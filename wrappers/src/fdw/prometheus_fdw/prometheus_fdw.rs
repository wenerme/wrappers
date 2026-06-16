use crate::stats;
use pgrx::{pg_sys, prelude::to_timestamp};
use serde_json::Value as JsonValue;
use std::collections::HashMap;

use supabase_wrappers::prelude::*;

/// Microseconds between Unix epoch (1970) and PG epoch (2000).
const PG_EPOCH_OFFSET_US: i64 = 946_684_800 * 1_000_000;

use super::{PrometheusFdwError, PrometheusFdwResult};

/// Escape a PromQL label value (backslash + double-quote).
fn promql_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Push a PromQL label matcher if the operator is supported.
fn push_label_matcher(
    matchers: &mut Vec<(String, String, String)>,
    label_key: &str,
    operator: &str,
    value: &Value,
) {
    if let Value::Cell(Cell::String(v)) = value {
        let promql_op = match operator {
            "=" => Some("="),
            "<>" | "!=" => Some("!="),
            "~" => Some("=~"),  // PG regex → PromQL =~
            "!~" => Some("!~"), // PG not regex → PromQL !~
            _ => None,
        };
        if let Some(op) = promql_op {
            matchers.push((label_key.to_string(), op.to_string(), v.clone()));
        }
    }
}

/// Build a PromQL selector string from label matchers, e.g.
/// `{job="kubelet", namespace=~"kube.*"}`.
fn build_label_selector(matchers: &[(&str, &str, &str)]) -> String {
    if matchers.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = matchers
        .iter()
        .map(|(k, op, v)| format!("{k}{op}\"{}\"", promql_escape(v)))
        .collect();
    format!("{{{}}}", parts.join(","))
}

#[wrappers_fdw(
    version = "0.1.0",
    author = "Wener",
    website = "https://github.com/supabase/wrappers/tree/main/wrappers/src/fdw/prometheus_fdw",
    error_type = "PrometheusFdwError"
)]
pub(crate) struct PrometheusFdw {
    rt: Runtime,
    base_url: String,
    bearer_token: Option<String>,
    username: Option<String>,
    password: Option<String>,
    scan_result: Vec<Row>,
    iter_idx: usize,
}

impl PrometheusFdw {
    const FDW_NAME: &'static str = "PrometheusFdw";

    fn api_get(&self, path: &str, params: &[(&str, &str)]) -> PrometheusFdwResult<JsonValue> {
        let url = format!("{}{path}", self.base_url.trim_end_matches('/'));

        let resp_text: String = self.rt.block_on(async {
            let client = reqwest::Client::new();
            let mut req = client.get(&url).query(params);

            if let Some(ref token) = self.bearer_token {
                req = req.bearer_auth(token);
            } else if let Some(ref user) = self.username {
                req = req.basic_auth(user, self.password.as_deref());
            }

            let resp = req.send().await?;
            resp.text().await
        })?;

        let resp: JsonValue = serde_json::from_str(&resp_text)?;

        if let Some(err_type) = resp.get("errorType").and_then(|v| v.as_str()) {
            let err_msg = resp
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            return Err(PrometheusFdwError::ApiError(format!(
                "{err_type}: {err_msg}"
            )));
        }

        Ok(resp)
    }

    fn resp_to_rows(&self, resp: &JsonValue, tgt_cols: &[Column], query_used: &str) -> Vec<Row> {
        let empty = Vec::new();
        let results = resp
            .pointer("/data/result")
            .and_then(|v| v.as_array())
            .unwrap_or(&empty);

        let is_matrix = resp.pointer("/data/resultType").and_then(|v| v.as_str()) == Some("matrix");

        let mut rows = Vec::new();

        for series in results {
            let metric = series.get("metric").cloned().unwrap_or(JsonValue::Null);
            let name = metric
                .get("__name__")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            // Labels without __name__
            let labels = if let Some(obj) = metric.as_object() {
                let filtered: serde_json::Map<String, JsonValue> = obj
                    .iter()
                    .filter(|(k, _)| k.as_str() != "__name__")
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                JsonValue::Object(filtered)
            } else {
                JsonValue::Null
            };

            let points: Vec<(f64, f64)> = if is_matrix {
                series
                    .get("values")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|p| {
                                let a = p.as_array()?;
                                let ts = a.first()?.as_f64()?;
                                let val: f64 = a.get(1)?.as_str()?.parse().ok()?;
                                Some((ts, val))
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            } else {
                series
                    .get("value")
                    .and_then(|v| v.as_array())
                    .and_then(|a| {
                        let ts = a.first()?.as_f64()?;
                        let val: f64 = a.get(1)?.as_str()?.parse().ok()?;
                        Some(vec![(ts, val)])
                    })
                    .unwrap_or_default()
            };

            for (ts, val) in points {
                let mut row = Row::new();
                for col in tgt_cols {
                    let cell = match col.name.as_str() {
                        "name" => Some(Cell::String(name.clone())),
                        "labels" => Some(Cell::Json(pgrx::JsonB(labels.clone()))),
                        "time" => Some(Cell::Timestamptz(to_timestamp(ts))),
                        "value" => Some(Cell::F64(val)),
                        // Echo _query back so PG's local filter passes
                        "_query" => Some(Cell::String(query_used.to_owned())),
                        // label_* columns: extract from labels object
                        col_name if col_name.starts_with("label_") => {
                            let label_key = &col_name["label_".len()..];
                            labels
                                .get(label_key)
                                .and_then(|v| v.as_str())
                                .map(|s| Cell::String(s.to_owned()))
                        }
                        _ => None,
                    };
                    row.push(&col.name, cell);
                }
                rows.push(row);
            }
        }

        rows
    }
}

impl ForeignDataWrapper<PrometheusFdwError> for PrometheusFdw {
    fn new(server: ForeignServer) -> PrometheusFdwResult<Self> {
        let base_url = require_option("base_url", &server.options)?.to_string();

        let bearer_token = server.options.get("bearer_token").cloned().or_else(|| {
            server
                .options
                .get("bearer_token_id")
                .and_then(|id| get_vault_secret(id))
        });

        stats::inc_stats(Self::FDW_NAME, stats::Metric::CreateTimes, 1);

        Ok(PrometheusFdw {
            rt: create_async_runtime()?,
            base_url,
            bearer_token,
            username: server.options.get("username").cloned(),
            password: server.options.get("password").cloned(),
            scan_result: Vec::new(),
            iter_idx: 0,
        })
    }

    fn begin_scan(
        &mut self,
        quals: &[Qual],
        columns: &[Column],
        _sorts: &[Sort],
        _limit: &Option<Limit>,
        options: &HashMap<String, String>,
    ) -> PrometheusFdwResult<()> {
        let step = options.get("step").map(|s| s.as_str()).unwrap_or("10m");
        self.iter_idx = 0;

        let mut metric_name: Option<String> = None;
        let mut raw_query: Option<String> = None; // _query: raw PromQL override
        let mut start_time: Option<i64> = None;
        let mut end_time: Option<i64> = None;
        // label matchers: (label_key, promql_op, value)
        let mut label_matchers: Vec<(String, String, String)> = Vec::new();

        for qual in quals {
            match qual.field.as_str() {
                "_query" if qual.operator == "=" => {
                    if let Value::Cell(Cell::String(v)) = &qual.value {
                        raw_query = Some(v.clone());
                    }
                }
                "name" if qual.operator == "=" => {
                    if let Value::Cell(Cell::String(v)) = &qual.value {
                        metric_name = Some(v.clone());
                    }
                }
                "time" => {
                    // Accept both Timestamptz (preferred) and I64 (legacy)
                    let ts_secs = match &qual.value {
                        Value::Cell(Cell::Timestamptz(v)) => {
                            let us: i64 = (*v).into();
                            Some((us + PG_EPOCH_OFFSET_US) / 1_000_000)
                        }
                        Value::Cell(Cell::I64(v)) => Some(*v),
                        _ => None,
                    };
                    if let Some(secs) = ts_secs {
                        match qual.operator.as_str() {
                            ">=" | ">" => start_time = Some(secs),
                            "<=" | "<" => end_time = Some(secs),
                            "=" => {
                                start_time = Some(secs);
                                end_time = Some(secs);
                            }
                            _ => {}
                        }
                    }
                }
                // label_* declared columns: push down as PromQL label matchers
                col_name if col_name.starts_with("label_") => {
                    let label_key = col_name["label_".len()..].to_string();
                    push_label_matcher(
                        &mut label_matchers,
                        &label_key,
                        &qual.operator,
                        &qual.value,
                    );
                }
                // labels->>'key' = 'val' pattern (field = "labels.key" from framework)
                col_name if col_name.starts_with("labels.") => {
                    let label_key = col_name["labels.".len()..].to_string();
                    push_label_matcher(
                        &mut label_matchers,
                        &label_key,
                        &qual.operator,
                        &qual.value,
                    );
                }
                _ => {}
            }
        }

        // _query overrides everything; otherwise build PromQL from name + label matchers
        let query = if let Some(q) = raw_query {
            q
        } else {
            let base = metric_name.ok_or_else(|| {
                PrometheusFdwError::MissingOption(
                    "WHERE name = '...' or WHERE _query = '...' is required".to_string(),
                )
            })?;
            let selector = build_label_selector(
                &label_matchers
                    .iter()
                    .map(|(k, op, v)| (k.as_str(), op.as_str(), v.as_str()))
                    .collect::<Vec<_>>(),
            );
            format!("{base}{selector}")
        };

        let resp = if start_time.is_some() || end_time.is_some() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let start = start_time.unwrap_or(now - 3600);
            let end = end_time.unwrap_or(now);
            let start_s = start.to_string();
            let end_s = end.to_string();
            self.api_get(
                "/api/v1/query_range",
                &[
                    ("query", query.as_str()),
                    ("start", &start_s),
                    ("end", &end_s),
                    ("step", step),
                ],
            )?
        } else {
            self.api_get("/api/v1/query", &[("query", query.as_str())])?
        };

        self.scan_result = self.resp_to_rows(&resp, columns, &query);

        stats::inc_stats(
            Self::FDW_NAME,
            stats::Metric::RowsIn,
            self.scan_result.len() as i64,
        );
        stats::inc_stats(
            Self::FDW_NAME,
            stats::Metric::RowsOut,
            self.scan_result.len() as i64,
        );

        Ok(())
    }

    fn iter_scan(&mut self, row: &mut Row) -> PrometheusFdwResult<Option<()>> {
        if self.iter_idx >= self.scan_result.len() {
            return Ok(None);
        }
        row.replace_with(self.scan_result[self.iter_idx].clone());
        self.iter_idx += 1;
        Ok(Some(()))
    }

    fn re_scan(&mut self) -> PrometheusFdwResult<()> {
        self.iter_idx = 0;
        Ok(())
    }

    fn end_scan(&mut self) -> PrometheusFdwResult<()> {
        self.scan_result.clear();
        Ok(())
    }

    fn validator(
        options: Vec<Option<String>>,
        catalog: Option<pg_sys::Oid>,
    ) -> PrometheusFdwResult<()> {
        if let Some(oid) = catalog
            && oid == FOREIGN_SERVER_RELATION_ID
        {
            check_options_contain(&options, "base_url")?;
        }
        Ok(())
    }
}
