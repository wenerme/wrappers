use crate::stats;
use chrono::Utc;
use hex;
use hmac::{Hmac, Mac};
use pgrx::pg_sys;
use pgrx::prelude::{TimestampWithTimeZone, to_timestamp};
use reqwest::{
    self,
    header::{HeaderMap, HeaderValue},
};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::{RetryTransientMiddleware, policies::ExponentialBackoff};
use serde_json::value::Value as JsonValue;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Duration;

use supabase_wrappers::prelude::*;

use super::{TencentClsFdwError, TencentClsFdwResult};

type HmacSha256 = Hmac<Sha256>;

const DEFAULT_MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024;
const DEFAULT_LIMIT: u64 = 100;

/// Microseconds between Unix epoch (1970-01-01) and PostgreSQL epoch (2000-01-01).
const PG_EPOCH_OFFSET_US: i64 = 946_684_800 * 1_000_000;

/// Convert a pgrx TimestampWithTimeZone (microseconds since PG epoch) to Unix milliseconds.
fn tstz_to_unix_ms(v: TimestampWithTimeZone) -> i64 {
    let us: i64 = v.into();
    (us + PG_EPOCH_OFFSET_US) / 1000
}

/// Convert Unix milliseconds to a pgrx TimestampWithTimeZone.
fn unix_ms_to_tstz(ms: i64) -> TimestampWithTimeZone {
    to_timestamp(ms as f64 / 1000.0)
}

// ---------------------------------------------------------------------------
// CQL pushdown: convert PostgreSQL quals to CQL search expression
// ---------------------------------------------------------------------------

/// Extract timestamp range from `ts` column quals, return (from_ms, to_ms)
/// and the remaining non-ts quals.
fn extract_ts_range(quals: &[Qual]) -> (i64, i64, Vec<&Qual>) {
    let now = Utc::now().timestamp_millis();
    let mut from_ms: i64 = now - 3600 * 1000; // default: 1 hour ago
    let mut to_ms: i64 = now;
    let mut rest = Vec::new();

    for qual in quals {
        if qual.field == "ts" {
            if let Value::Cell(Cell::Timestamptz(v)) = &qual.value {
                let ms = tstz_to_unix_ms(*v);
                match qual.operator.as_str() {
                    ">=" => from_ms = ms,
                    ">" => from_ms = ms + 1, // exclusive → inclusive
                    "<=" => to_ms = ms + 1,  // inclusive → exclusive (API To is exclusive)
                    "<" => to_ms = ms,
                    "=" => {
                        from_ms = ms;
                        to_ms = ms + 1;
                    }
                    _ => rest.push(qual),
                }
            } else {
                rest.push(qual);
            }
        } else {
            rest.push(qual);
        }
    }

    (from_ms, to_ms, rest)
}

/// Escape a string value for CQL (double-quote context).
fn cql_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Format a Cell value for CQL.
fn cell_to_cql_value(cell: &Cell) -> String {
    match cell {
        Cell::String(s) => format!("\"{}\"", cql_escape(s)),
        Cell::Bool(v) => format!("\"{v}\""), // CLS treats booleans as strings
        Cell::I8(v) => v.to_string(),
        Cell::I16(v) => v.to_string(),
        Cell::I32(v) => v.to_string(),
        Cell::I64(v) => v.to_string(),
        Cell::F32(v) => v.to_string(),
        Cell::F64(v) => v.to_string(),
        _ => format!("{cell}"),
    }
}

/// Convert non-ts quals to a CQL search expression.
/// Returns None for _query (handled separately), skips unsupported quals.
fn quals_to_cql(quals: &[&Qual]) -> String {
    let mut parts: Vec<String> = Vec::new();

    for qual in quals {
        // Skip _query pseudo-column (handled separately)
        if qual.field == "_query" {
            continue;
        }

        // "log.field_name" comes from log->>'field_name' JSONB extraction.
        // In CQL the field name is just "field_name" (CLS indexes LogJson fields at top level).
        let field_str;
        let field: &str = if let Some(key) = qual.field.strip_prefix("log.") {
            key
        } else {
            field_str = qual.field.clone();
            &field_str
        };

        // Handle NULL tests
        match qual.operator.as_str() {
            "is" => {
                if let Value::Cell(Cell::String(s)) = &qual.value
                    && s == "null"
                {
                    // field IS NULL → NOT field:*
                    parts.push(format!("NOT {field}:*"));
                    continue;
                }
            }
            "is not" => {
                if let Value::Cell(Cell::String(s)) = &qual.value
                    && s == "null"
                {
                    // field IS NOT NULL → field:*
                    parts.push(format!("{field}:*"));
                    continue;
                }
            }
            _ => {}
        }

        // Handle LIKE patterns
        match qual.operator.as_str() {
            "~~" => {
                if let Value::Cell(Cell::String(pattern)) = &qual.value {
                    let inner = pattern.trim_matches('%');
                    if field == "log" {
                        // log LIKE '%xxx%' → full text search
                        parts.push(format!("\"{}\"", cql_escape(inner)));
                    } else {
                        // field LIKE '%xxx%' → field:"xxx"
                        parts.push(format!("{field}:\"{}\"", cql_escape(inner)));
                    }
                }
                continue;
            }
            "!~~" => {
                if let Value::Cell(Cell::String(pattern)) = &qual.value {
                    let inner = pattern.trim_matches('%');
                    if field == "log" {
                        parts.push(format!("NOT \"{}\"", cql_escape(inner)));
                    } else {
                        parts.push(format!("NOT {field}:\"{}\"", cql_escape(inner)));
                    }
                }
                continue;
            }
            _ => {}
        }

        // Handle comparison operators
        if let Value::Cell(cell) = &qual.value {
            let val = cell_to_cql_value(cell);
            match qual.operator.as_str() {
                "=" => parts.push(format!("{field}:{val}")),
                "<>" | "!=" => parts.push(format!("NOT {field}:{val}")),
                ">" => parts.push(format!("{field}:>{val}")),
                ">=" => parts.push(format!("{field}:>={val}")),
                "<" => parts.push(format!("{field}:<{val}")),
                "<=" => parts.push(format!("{field}:<={val}")),
                _ => {} // skip unsupported operators
            }
        }
    }

    if parts.is_empty() {
        "*".to_string()
    } else {
        parts.join(" AND ")
    }
}

/// Extract _query override from quals if present.
fn extract_query_override(quals: &[Qual]) -> Option<String> {
    quals.iter().find_map(|q| {
        if q.field == "_query" {
            if let Value::Cell(Cell::String(v)) = &q.value {
                Some(v.clone())
            } else {
                None
            }
        } else {
            None
        }
    })
}

// ---------------------------------------------------------------------------
// TC3 signing and HTTP
// ---------------------------------------------------------------------------

/// TC3-HMAC-SHA256 signing for Tencent Cloud API v3
fn tc3_sign(
    secret_id: &str,
    secret_key: &str,
    service: &str,
    host: &str,
    timestamp: i64,
    payload: &str,
) -> String {
    let date = chrono::DateTime::from_timestamp(timestamp, 0)
        .unwrap()
        .format("%Y-%m-%d")
        .to_string();

    // Step 1: Canonical request
    let hashed_payload = hex::encode(Sha256::digest(payload.as_bytes()));
    let canonical_headers = format!("content-type:application/json\nhost:{host}\n");
    let signed_headers = "content-type;host";
    let canonical_request =
        format!("POST\n/\n\n{canonical_headers}\n{signed_headers}\n{hashed_payload}");

    // Step 2: String to sign
    let credential_scope = format!("{date}/{service}/tc3_request");
    let hashed_canonical = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let string_to_sign =
        format!("TC3-HMAC-SHA256\n{timestamp}\n{credential_scope}\n{hashed_canonical}");

    // Step 3: Signing key chain
    let k_date = hmac_sha256(format!("TC3{secret_key}").as_bytes(), date.as_bytes());
    let k_service = hmac_sha256(&k_date, service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"tc3_request");
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    // Step 4: Authorization header
    format!(
        "TC3-HMAC-SHA256 Credential={secret_id}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
    )
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn create_client() -> TencentClsFdwResult<ClientWithMiddleware> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()?;
    let retry_policy = ExponentialBackoff::builder().build_with_max_retries(3);
    Ok(ClientBuilder::new(client)
        .with(RetryTransientMiddleware::new_with_policy(retry_policy))
        .build())
}

// ---------------------------------------------------------------------------
// Data conversion
// ---------------------------------------------------------------------------

fn json_value_to_cell(tgt_col: &Column, v: &JsonValue) -> TencentClsFdwResult<Cell> {
    match tgt_col.type_oid {
        pg_sys::BOOLOID => v.as_bool().map(Cell::Bool),
        pg_sys::INT2OID => v
            .as_i64()
            .and_then(|s| i16::try_from(s).ok())
            .map(Cell::I16),
        pg_sys::INT4OID => v
            .as_i64()
            .and_then(|s| i32::try_from(s).ok())
            .map(Cell::I32),
        pg_sys::FLOAT8OID => v.as_f64().map(Cell::F64),
        pg_sys::INT8OID => v.as_i64().map(Cell::I64),
        pg_sys::TEXTOID => {
            if v.is_string() {
                v.as_str().map(|s| Cell::String(s.to_owned()))
            } else {
                Some(Cell::String(v.to_string()))
            }
        }
        _ => {
            return Err(TencentClsFdwError::UnsupportedColumnType(
                tgt_col.name.clone(),
            ));
        }
    }
    .ok_or(TencentClsFdwError::ColumnTypeNotMatch(tgt_col.name.clone()))
}

// ---------------------------------------------------------------------------
// FDW implementation
// ---------------------------------------------------------------------------

#[wrappers_fdw(
    version = "0.1.0",
    author = "Wener",
    website = "https://github.com/supabase/wrappers/tree/main/wrappers/src/fdw/tencent_cls_fdw",
    error_type = "TencentClsFdwError"
)]
pub(crate) struct TencentClsFdw {
    rt: Runtime,
    secret_id: String,
    secret_key: String,
    region: String,
    endpoint: String,
    client: Option<ClientWithMiddleware>,
    tgt_cols: Vec<Column>,
    scan_result: Vec<Row>,
    max_response_size: usize,
}

/// Check if a string looks like a CLS topic UUID (8-4-4-4-12 hex).
fn is_topic_id(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    s.bytes().enumerate().all(|(i, b)| match i {
        8 | 13 | 18 | 23 => b == b'-',
        _ => b.is_ascii_hexdigit(),
    })
}

impl TencentClsFdw {
    const FDW_NAME: &'static str = "TencentClsFdw";

    /// Resolve a topic name to a topic ID via DescribeTopics API.
    /// If the input is already a UUID, return it as-is.
    fn resolve_topic_id(&self, topic: &str) -> TencentClsFdwResult<String> {
        if is_topic_id(topic) {
            return Ok(topic.to_string());
        }

        let client = self
            .client
            .as_ref()
            .ok_or_else(|| TencentClsFdwError::MissingParameter("client".to_string()))?;

        let body = serde_json::json!({
            "Filters": [{"Key": "topicName", "Values": [topic]}],
            "PreciseSearch": 1,
            "Limit": 10
        });

        let payload = serde_json::to_string(&body)?;
        let timestamp = Utc::now().timestamp();
        let host = &self.endpoint;

        let authorization = tc3_sign(
            &self.secret_id,
            &self.secret_key,
            "cls",
            host,
            timestamp,
            &payload,
        );

        let url = format!("https://{host}/");
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&authorization).map_err(|e| {
                TencentClsFdwError::ApiError(format!("invalid Authorization header: {e}"))
            })?,
        );
        headers.insert("X-TC-Action", HeaderValue::from_static("DescribeTopics"));
        headers.insert("X-TC-Version", HeaderValue::from_static("2020-10-16"));
        headers.insert(
            "X-TC-Region",
            HeaderValue::from_str(&self.region).map_err(|e| {
                TencentClsFdwError::ApiError(format!("invalid X-TC-Region header: {e}"))
            })?,
        );
        headers.insert(
            "X-TC-Timestamp",
            HeaderValue::from_str(&timestamp.to_string()).map_err(|e| {
                TencentClsFdwError::ApiError(format!("invalid X-TC-Timestamp header: {e}"))
            })?,
        );

        let max_response_size = self.max_response_size;
        let resp_text: String = self.rt.block_on(async {
            let resp = client
                .post(&url)
                .headers(headers)
                .header("Content-Type", "application/json")
                .body(payload)
                .send()
                .await
                .map_err(TencentClsFdwError::RequestMiddlewareError)?;

            let text = resp
                .text()
                .await
                .map_err(TencentClsFdwError::RequestError)?;
            if text.len() > max_response_size {
                return Err(TencentClsFdwError::ResponseTooLarge(
                    text.len(),
                    max_response_size,
                ));
            }
            Ok::<_, TencentClsFdwError>(text)
        })?;

        let resp: JsonValue = serde_json::from_str(&resp_text)?;

        // Extract first matching topic ID
        if let Some(topics) = resp.pointer("/Response/Topics").and_then(|v| v.as_array())
            && let Some(first) = topics.first()
            && let Some(tid) = first.get("TopicId").and_then(|v| v.as_str())
        {
            return Ok(tid.to_string());
        }

        Err(TencentClsFdwError::ApiError(format!(
            "topic not found: '{topic}'"
        )))
    }

    #[allow(clippy::too_many_arguments)]
    fn search_log(
        &self,
        topic_id: &str,
        query: &str,
        from_ms: i64,
        to_ms: i64,
        limit: u64,
        syntax_rule: u8,
        context: &str,
    ) -> TencentClsFdwResult<JsonValue> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| TencentClsFdwError::MissingParameter("client".to_string()))?;

        let mut body = serde_json::json!({
            "TopicId": topic_id,
            "Query": query,
            "From": from_ms,
            "To": to_ms,
            "Limit": limit,
            "SyntaxRule": syntax_rule,
            "UseNewAnalysis": true,
        });
        if !context.is_empty() {
            body["Context"] = serde_json::json!(context);
        }

        let payload = serde_json::to_string(&body)?;
        let timestamp = Utc::now().timestamp();
        let host = &self.endpoint;

        let authorization = tc3_sign(
            &self.secret_id,
            &self.secret_key,
            "cls",
            host,
            timestamp,
            &payload,
        );

        let url = format!("https://{host}/");
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&authorization).map_err(|e| {
                TencentClsFdwError::ApiError(format!("invalid Authorization header: {e}"))
            })?,
        );
        headers.insert("X-TC-Action", HeaderValue::from_static("SearchLog"));
        headers.insert("X-TC-Version", HeaderValue::from_static("2020-10-16"));
        headers.insert(
            "X-TC-Region",
            HeaderValue::from_str(&self.region).map_err(|e| {
                TencentClsFdwError::ApiError(format!("invalid X-TC-Region header: {e}"))
            })?,
        );
        headers.insert(
            "X-TC-Timestamp",
            HeaderValue::from_str(&timestamp.to_string()).map_err(|e| {
                TencentClsFdwError::ApiError(format!("invalid X-TC-Timestamp header: {e}"))
            })?,
        );

        let max_response_size = self.max_response_size;
        let resp_text: String = self.rt.block_on(async {
            let resp = client
                .post(&url)
                .headers(headers)
                .header("Content-Type", "application/json")
                .body(payload)
                .send()
                .await
                .map_err(TencentClsFdwError::RequestMiddlewareError)?;

            let status = resp.status();
            let max_size = max_response_size;

            if let Some(content_len) = resp.content_length()
                && content_len as usize > max_size
            {
                return Err(TencentClsFdwError::ResponseTooLarge(
                    content_len as usize,
                    max_size,
                ));
            }

            let text = resp
                .text()
                .await
                .map_err(TencentClsFdwError::RequestError)?;

            if text.len() > max_size {
                return Err(TencentClsFdwError::ResponseTooLarge(text.len(), max_size));
            }

            if !status.is_success() {
                return Err(TencentClsFdwError::ApiError(format!(
                    "HTTP {}: {}",
                    status,
                    &text[..text.len().min(500)]
                )));
            }
            Ok::<_, TencentClsFdwError>(text)
        })?;

        let resp: JsonValue = serde_json::from_str(&resp_text)?;

        // Check for API error
        if let Some(error) = resp.pointer("/Response/Error").and_then(|e| e.as_object()) {
            let code = error
                .get("Code")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown");
            let message = error.get("Message").and_then(|v| v.as_str()).unwrap_or("");
            return Err(TencentClsFdwError::ApiError(format!("{code}: {message}")));
        }

        Ok(resp)
    }

    /// Convert CLS search results to FDW rows.
    fn resp_to_rows(&self, resp: &JsonValue, tgt_cols: &[Column]) -> TencentClsFdwResult<Vec<Row>> {
        let results = resp.pointer("/Response/Results").and_then(|v| v.as_array());

        let results = match results {
            Some(arr) => arr,
            None => return Ok(Vec::new()),
        };

        results
            .iter()
            .map(|record| {
                let mut row = Row::new();

                // Parse LogJson into a JSON object for field extraction
                let log_json: Option<JsonValue> = record
                    .get("LogJson")
                    .and_then(|v| v.as_str())
                    .and_then(|s| serde_json::from_str(s).ok());

                for tgt_col in tgt_cols {
                    let cell: Option<Cell> = match tgt_col.name.as_str() {
                        // ts: convert Time (milliseconds) to timestamptz
                        "ts" => record
                            .get("Time")
                            .and_then(|v| v.as_i64())
                            .map(unix_ms_to_tstz)
                            .map(Cell::Timestamptz),
                        // log: raw LogJson string
                        "log" => record
                            .get("LogJson")
                            .and_then(|v| v.as_str())
                            .map(|s| Cell::String(s.to_owned())),
                        // Meta column: full result JSON
                        "_result" => Some(Cell::String(record.to_string())),
                        // Standard CLS result fields
                        "source" => record
                            .get("Source")
                            .and_then(|v| v.as_str())
                            .map(|s| Cell::String(s.to_owned())),
                        "topic_id" => record
                            .get("TopicId")
                            .and_then(|v| v.as_str())
                            .map(|s| Cell::String(s.to_owned())),
                        "topic_name" => record
                            .get("TopicName")
                            .and_then(|v| v.as_str())
                            .map(|s| Cell::String(s.to_owned())),
                        "file_name" => record
                            .get("FileName")
                            .and_then(|v| v.as_str())
                            .map(|s| Cell::String(s.to_owned())),
                        "host_name" => record
                            .get("HostName")
                            .and_then(|v| v.as_str())
                            .map(|s| Cell::String(s.to_owned())),
                        // User-defined columns: extract from LogJson
                        _ => {
                            if let Some(ref lj) = log_json {
                                if let Some(v) = lj.get(&tgt_col.name) {
                                    json_value_to_cell(tgt_col, v).ok()
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        }
                    };
                    row.push(&tgt_col.name, cell);
                }
                Ok(row)
            })
            .collect()
    }

    /// Convert CLS SQL analysis results to FDW rows.
    /// With UseNewAnalysis=true, AnalysisRecords contains JSON strings.
    /// With UseNewAnalysis=false (legacy), AnalysisResults contains arrays.
    fn analysis_resp_to_rows(
        &self,
        resp: &JsonValue,
        tgt_cols: &[Column],
    ) -> TencentClsFdwResult<Vec<Row>> {
        // UseNewAnalysis=true: AnalysisRecords is array of JSON strings
        if let Some(records) = resp
            .pointer("/Response/AnalysisRecords")
            .and_then(|v| v.as_array())
        {
            return records
                .iter()
                .filter_map(|r| r.as_str())
                .map(|s| {
                    let record: JsonValue =
                        serde_json::from_str(s).unwrap_or(JsonValue::Object(Default::default()));
                    let mut row = Row::new();
                    for tgt_col in tgt_cols {
                        let cell: Option<Cell> = if let Some(v) = record.get(&tgt_col.name) {
                            json_value_to_cell(tgt_col, v).ok()
                        } else {
                            None
                        };
                        row.push(&tgt_col.name, cell);
                    }
                    Ok(row)
                })
                .collect();
        }

        // Fallback: AnalysisResults (legacy format, array of key-value arrays)
        if let Some(results) = resp
            .pointer("/Response/AnalysisResults")
            .and_then(|v| v.as_array())
        {
            let col_names: Vec<String> = resp
                .pointer("/Response/ColNames")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            return results
                .iter()
                .filter_map(|r| r.as_array())
                .map(|values| {
                    let mut row = Row::new();
                    for tgt_col in tgt_cols {
                        let cell: Option<Cell> = col_names
                            .iter()
                            .position(|n| n == &tgt_col.name)
                            .and_then(|idx| {
                                values
                                    .get(idx)
                                    .and_then(|v| json_value_to_cell(tgt_col, v).ok())
                            });
                        row.push(&tgt_col.name, cell);
                    }
                    Ok(row)
                })
                .collect();
        }

        Ok(Vec::new())
    }

    /// Build CLS SQL analysis query string: `<CQL> | SELECT ... GROUP BY ... LIMIT ...`
    fn build_analysis_query(
        cql: &str,
        aggregates: &[Aggregate],
        group_by: &[Column],
    ) -> String {
        let mut select_items: Vec<String> = Vec::new();

        // GROUP BY columns
        for col in group_by {
            select_items.push(col.name.clone());
        }

        // Aggregate expressions with aliases
        for agg in aggregates {
            let expr = match agg.kind {
                AggregateKind::Count => "count(*)".to_string(),
                AggregateKind::CountColumn => {
                    let col = agg.column.as_ref().map(|c| c.name.as_str()).unwrap_or("*");
                    if agg.distinct {
                        format!("count(distinct {col})")
                    } else {
                        format!("count({col})")
                    }
                }
                _ => {
                    let func = agg.kind.sql_name();
                    let col = agg.column.as_ref().map(|c| c.name.as_str()).unwrap_or("*");
                    format!("{func}({col})")
                }
            };
            select_items.push(format!("{expr} as {}", agg.alias));
        }

        let mut sql = format!("{cql} | SELECT {}", select_items.join(", "));

        if !group_by.is_empty() {
            let group_cols: Vec<&str> = group_by.iter().map(|c| c.name.as_str()).collect();
            sql.push_str(&format!(" GROUP BY {}", group_cols.join(", ")));
        }

        // CLS default max is 10000
        sql.push_str(" LIMIT 10000");

        sql
    }
}

impl ForeignDataWrapper<TencentClsFdwError> for TencentClsFdw {
    fn new(server: ForeignServer) -> TencentClsFdwResult<Self> {
        let secret_id = match server.options.get("secret_id") {
            Some(id) => id.to_owned(),
            None => {
                let id_key = require_option("secret_id_id", &server.options)?;
                get_vault_secret(id_key)
                    .ok_or_else(|| TencentClsFdwError::VaultSecretNotFound(id_key.to_string()))?
            }
        };
        let secret_key = match server.options.get("secret_key") {
            Some(key) => key.to_owned(),
            None => {
                let key_id = require_option("secret_key_id", &server.options)?;
                get_vault_secret(key_id)
                    .ok_or_else(|| TencentClsFdwError::VaultSecretNotFound(key_id.to_string()))?
            }
        };

        let region = server
            .options
            .get("region")
            .cloned()
            .unwrap_or_else(|| "ap-shanghai".to_string());

        let endpoint = server
            .options
            .get("endpoint")
            .cloned()
            .unwrap_or_else(|| format!("cls.{region}.tencentcloudapi.com"));

        let max_response_size = server
            .options
            .get("max_response_size")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(DEFAULT_MAX_RESPONSE_SIZE);

        let client = Some(create_client()?);

        stats::inc_stats(Self::FDW_NAME, stats::Metric::CreateTimes, 1);

        Ok(TencentClsFdw {
            rt: create_async_runtime()?,
            secret_id,
            secret_key,
            region,
            endpoint,
            client,
            tgt_cols: Vec::new(),
            scan_result: Vec::new(),
            max_response_size,
        })
    }

    fn begin_scan(
        &mut self,
        quals: &[Qual],
        columns: &[Column],
        _sorts: &[Sort],
        _limit: &Option<Limit>,
        options: &HashMap<String, String>,
    ) -> TencentClsFdwResult<()> {
        let topic =
            require_option("topic", options).or_else(|_| require_option("topic_id", options))?;
        let topic_id = self.resolve_topic_id(topic)?;
        let topic_id = topic_id.as_str();
        let base_query = options.get("query").map(|s| s.as_str()).unwrap_or("*");
        let syntax_rule: u8 = options
            .get("syntax_rule")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);
        let limit: u64 = options
            .get("limit")
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_LIMIT);

        self.tgt_cols = columns.to_vec();

        // Extract ts range and remaining quals
        let (from_ms, to_ms, rest_quals) = extract_ts_range(quals);

        // Build CQL from remaining quals, or use _query override if present
        let effective_query = if let Some(q) = extract_query_override(quals) {
            q
        } else {
            let cql = quals_to_cql(&rest_quals);
            // Combine with base query from table options
            if base_query != "*" && cql != "*" {
                format!("{base_query} AND {cql}")
            } else if base_query != "*" {
                base_query.to_string()
            } else {
                cql
            }
        };

        let resp = self.search_log(
            topic_id,
            &effective_query,
            from_ms,
            to_ms,
            limit,
            syntax_rule,
            "",
        )?;
        let result = self.resp_to_rows(&resp, columns)?;

        if !result.is_empty() {
            stats::inc_stats(Self::FDW_NAME, stats::Metric::RowsIn, result.len() as i64);
            stats::inc_stats(Self::FDW_NAME, stats::Metric::RowsOut, result.len() as i64);
        }
        self.scan_result = result;

        Ok(())
    }

    fn iter_scan(&mut self, row: &mut Row) -> TencentClsFdwResult<Option<()>> {
        if self.scan_result.is_empty() {
            Ok(None)
        } else {
            Ok(self
                .scan_result
                .drain(0..1)
                .next_back()
                .map(|src_row| row.replace_with(src_row)))
        }
    }

    fn re_scan(&mut self) -> TencentClsFdwResult<()> {
        Ok(())
    }

    fn end_scan(&mut self) -> TencentClsFdwResult<()> {
        self.scan_result.clear();
        Ok(())
    }

    fn supported_aggregates(&self) -> Vec<AggregateKind> {
        vec![
            AggregateKind::Count,
            AggregateKind::CountColumn,
            AggregateKind::Sum,
            AggregateKind::Avg,
            AggregateKind::Min,
            AggregateKind::Max,
        ]
    }

    fn supports_group_by(&self) -> bool {
        true
    }

    fn begin_aggregate_scan(
        &mut self,
        aggregates: &[Aggregate],
        group_by: &[Column],
        quals: &[Qual],
        options: &HashMap<String, String>,
    ) -> TencentClsFdwResult<()> {
        let topic =
            require_option("topic", options).or_else(|_| require_option("topic_id", options))?;
        let topic_id = self.resolve_topic_id(topic)?;
        let topic_id = topic_id.as_str();
        let base_query = options.get("query").map(|s| s.as_str()).unwrap_or("*");
        let syntax_rule: u8 = options
            .get("syntax_rule")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        // Build tgt_cols for aggregate output: group_by cols + agg aliases
        let mut tgt_cols = Vec::new();
        for col in group_by {
            tgt_cols.push(col.clone());
        }
        for agg in aggregates {
            tgt_cols.push(Column {
                name: agg.alias.clone(),
                num: 0,
                type_oid: agg.type_oid,
            });
        }
        self.tgt_cols = tgt_cols;

        // Extract ts range
        let (from_ms, to_ms, rest_quals) = extract_ts_range(quals);

        // Build CQL part
        let cql = if let Some(q) = extract_query_override(quals) {
            q
        } else {
            let cql = quals_to_cql(&rest_quals);
            if base_query != "*" && cql != "*" {
                format!("{base_query} AND {cql}")
            } else if base_query != "*" {
                base_query.to_string()
            } else {
                cql
            }
        };

        // Build full analysis query: CQL | SELECT ... GROUP BY ... LIMIT ...
        let query = Self::build_analysis_query(&cql, aggregates, group_by);

        // CLS analysis uses the same SearchLog API with SQL in the query
        let api_limit = 1000u64; // analysis returns aggregated rows, usually small
        let resp = self.search_log(topic_id, &query, from_ms, to_ms, api_limit, syntax_rule, "")?;

        let result = self.analysis_resp_to_rows(&resp, &self.tgt_cols.clone())?;

        if !result.is_empty() {
            stats::inc_stats(Self::FDW_NAME, stats::Metric::RowsIn, result.len() as i64);
            stats::inc_stats(Self::FDW_NAME, stats::Metric::RowsOut, result.len() as i64);
        }
        self.scan_result = result;

        Ok(())
    }

    fn validator(
        options: Vec<Option<String>>,
        catalog: Option<pg_sys::Oid>,
    ) -> TencentClsFdwResult<()> {
        if let Some(oid) = catalog
            && oid == FOREIGN_TABLE_RELATION_ID
        {
            // Accept either 'topic' (name or UUID) or legacy 'topic_id'
            let has_topic = check_options_contain(&options, "topic").is_ok();
            let has_topic_id = check_options_contain(&options, "topic_id").is_ok();
            if !has_topic && !has_topic_id {
                check_options_contain(&options, "topic")?; // will produce error
            }
        }
        Ok(())
    }
}
