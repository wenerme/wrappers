use crate::stats;
use chrono::{NaiveDate, NaiveDateTime};
use futures_util::stream::StreamExt;
use mysql_async::{Pool, Row as MySqlRow, prelude::*};
use pgrx::{PgBuiltInOids, PgOid, pg_sys, prelude::to_timestamp};
use std::collections::{HashMap, HashSet};
use std::sync::mpsc;
use std::time::Duration;

use supabase_wrappers::prelude::*;

use super::{MysqlFdwError, MysqlFdwResult};

// ---------------------------------------------------------------------------
// Row conversion helpers
// ---------------------------------------------------------------------------

fn get_col<T: FromValue>(src_row: &MySqlRow, col_name: &str) -> MysqlFdwResult<Option<T>> {
    match src_row.get_opt::<Option<T>, &str>(col_name) {
        Some(Ok(v)) => Ok(v),
        Some(Err(e)) => Err(MysqlFdwError::ConversionError(format!(
            "column '{col_name}': {e}"
        ))),
        None => Ok(None),
    }
}

fn field_to_cell(src_row: &MySqlRow, tgt_col: &Column) -> MysqlFdwResult<Option<Cell>> {
    let col_name = tgt_col.name.as_str();

    let ret = match PgOid::from(tgt_col.type_oid) {
        PgOid::BuiltIn(PgBuiltInOids::BOOLOID) => {
            get_col::<bool>(src_row, col_name)?.map(Cell::Bool)
        }
        PgOid::BuiltIn(PgBuiltInOids::CHAROID) => get_col::<i8>(src_row, col_name)?.map(Cell::I8),
        PgOid::BuiltIn(PgBuiltInOids::INT2OID) => get_col::<i16>(src_row, col_name)?.map(Cell::I16),
        PgOid::BuiltIn(PgBuiltInOids::FLOAT4OID) => {
            get_col::<f32>(src_row, col_name)?.map(Cell::F32)
        }
        PgOid::BuiltIn(PgBuiltInOids::INT4OID) => get_col::<i32>(src_row, col_name)?.map(Cell::I32),
        PgOid::BuiltIn(PgBuiltInOids::FLOAT8OID) => {
            get_col::<f64>(src_row, col_name)?.map(Cell::F64)
        }
        PgOid::BuiltIn(PgBuiltInOids::INT8OID) => get_col::<i64>(src_row, col_name)?.map(Cell::I64),
        PgOid::BuiltIn(PgBuiltInOids::NUMERICOID) => get_col::<f64>(src_row, col_name)?
            .map(pgrx::AnyNumeric::try_from)
            .transpose()?
            .map(Cell::Numeric),
        PgOid::BuiltIn(PgBuiltInOids::TEXTOID)
        | PgOid::BuiltIn(PgBuiltInOids::VARCHAROID)
        | PgOid::BuiltIn(PgBuiltInOids::BPCHAROID) => {
            get_col::<String>(src_row, col_name)?.map(Cell::String)
        }
        PgOid::BuiltIn(PgBuiltInOids::JSONBOID) => match get_col::<String>(src_row, col_name)? {
            Some(s) => {
                let v: serde_json::Value = serde_json::from_str(&s).map_err(|e| {
                    MysqlFdwError::ConversionError(format!("failed to parse json '{s}': {e}"))
                })?;
                Some(Cell::Json(pgrx::JsonB(v)))
            }
            None => None,
        },
        PgOid::BuiltIn(PgBuiltInOids::DATEOID) => match get_col::<String>(src_row, col_name)? {
            Some(s) => {
                let v = NaiveDate::parse_from_str(&s, "%Y-%m-%d").map_err(|e| {
                    MysqlFdwError::ConversionError(format!("failed to parse date '{s}': {e}"))
                })?;
                let epoch = NaiveDate::from_ymd_opt(1970, 1, 1).unwrap();
                let seconds_from_epoch = v.signed_duration_since(epoch).num_seconds();
                let ts = to_timestamp(seconds_from_epoch as f64);
                Some(Cell::Date(pgrx::prelude::Date::from(ts)))
            }
            None => None,
        },
        PgOid::BuiltIn(PgBuiltInOids::TIMESTAMPOID) => {
            match get_col::<String>(src_row, col_name)? {
                Some(s) => {
                    let v = parse_naive_datetime(&s)?;
                    let ts = to_timestamp(v.and_utc().timestamp() as f64);
                    Some(Cell::Timestamp(ts.to_utc()))
                }
                None => None,
            }
        }
        PgOid::BuiltIn(PgBuiltInOids::TIMESTAMPTZOID) => {
            match get_col::<String>(src_row, col_name)? {
                Some(s) => {
                    let v = parse_naive_datetime(&s)?;
                    let ts = to_timestamp(v.and_utc().timestamp() as f64);
                    Some(Cell::Timestamptz(ts))
                }
                None => None,
            }
        }
        _ => {
            return Err(MysqlFdwError::UnsupportedColumnType(tgt_col.name.clone()));
        }
    };

    Ok(ret)
}

fn parse_naive_datetime(s: &str) -> MysqlFdwResult<NaiveDateTime> {
    NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f")
        .or_else(|_| NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S"))
        .map_err(|e| MysqlFdwError::ConversionError(format!("failed to parse datetime '{s}': {e}")))
}

// ---------------------------------------------------------------------------
// Schema import helpers
// ---------------------------------------------------------------------------

/// Maps a MySQL column type to the corresponding PostgreSQL type string.
fn mysql_type_to_pg(
    data_type: &str,
    column_type: &str,
    numeric_precision: Option<u64>,
    numeric_scale: Option<u64>,
) -> Option<String> {
    match data_type.to_lowercase().as_str() {
        "boolean" | "bool" => Some("boolean".to_string()),
        "tinyint" => {
            if column_type.to_lowercase() == "tinyint(1)" {
                Some("boolean".to_string())
            } else {
                Some("smallint".to_string())
            }
        }
        "smallint" | "year" => Some("smallint".to_string()),
        "mediumint" | "int" | "integer" => Some("integer".to_string()),
        "bigint" => Some("bigint".to_string()),
        "float" => Some("real".to_string()),
        "double" | "double precision" => Some("double precision".to_string()),
        "decimal" | "numeric" => match (numeric_precision, numeric_scale) {
            (Some(p), Some(s)) => Some(format!("numeric({p},{s})")),
            _ => Some("numeric".to_string()),
        },
        "char" | "varchar" | "tinytext" | "text" | "mediumtext" | "longtext" | "enum" | "set" => {
            Some("text".to_string())
        }
        "date" => Some("date".to_string()),
        "datetime" | "timestamp" => Some("timestamp".to_string()),
        "time" => Some("time".to_string()),
        "json" => Some("jsonb".to_string()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// SQL building helpers
// ---------------------------------------------------------------------------

fn quote_ident(name: &str) -> String {
    format!("`{}`", name.replace('`', "``"))
}

fn deparse_qual(qual: &Qual, fmt: &mut MysqlCellFormatter) -> String {
    let field = quote_ident(&qual.field);
    if qual.use_or {
        match &qual.value {
            Value::Cell(_) => unreachable!(),
            Value::Array(cells) => {
                let conds: Vec<String> = cells
                    .iter()
                    .map(|cell| format!("{} {} {}", field, qual.operator, fmt.fmt_cell(cell)))
                    .collect();
                conds.join(" or ")
            }
        }
    } else {
        match &qual.value {
            Value::Cell(cell) => match qual.operator.as_str() {
                "is" | "is not" => match cell {
                    Cell::String(s) if s == "null" => {
                        format!("{} {} null", field, qual.operator)
                    }
                    _ => format!("{} {} {}", field, qual.operator, fmt.fmt_cell(cell)),
                },
                "~~" => format!("{} like {}", field, fmt.fmt_cell(cell)),
                "!~~" => format!("{} not like {}", field, fmt.fmt_cell(cell)),
                _ => format!("{} {} {}", field, qual.operator, fmt.fmt_cell(cell)),
            },
            Value::Array(_) => unreachable!(),
        }
    }
}

struct MysqlCellFormatter;

impl CellFormatter for MysqlCellFormatter {
    fn fmt_cell(&mut self, cell: &Cell) -> String {
        match cell {
            Cell::Bool(v) => format!("{}", *v as u8),
            Cell::String(v) => {
                format!("'{}'", v.replace('\\', "\\\\").replace('\'', "\\'"))
            }
            Cell::Json(v) => {
                let s = v.0.to_string();
                format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"))
            }
            _ => format!("{cell}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Worker thread protocol
// ---------------------------------------------------------------------------

/// Commands sent from the PG backend thread to the async worker thread.
enum WorkerCmd {
    /// Start streaming the given SQL query. Worker replies StreamReady or Err.
    Query {
        sql: String,
        reply: mpsc::SyncSender<WorkerReply>,
    },
    /// Fetch next row from the active stream. Worker replies Row, Done, or Err.
    Next {
        reply: mpsc::SyncSender<WorkerReply>,
    },
    /// Execute a non-SELECT statement (INSERT/UPDATE/DELETE). Worker replies Ok or Err.
    Execute {
        sql: String,
        reply: mpsc::SyncSender<WorkerReply>,
    },
    /// Run an `information_schema` query and return all rows. Worker replies Rows or Err.
    QueryAll {
        sql: String,
        reply: mpsc::SyncSender<WorkerReply>,
    },
    /// Gracefully shut down the worker.
    Disconnect,
}

/// Replies from the async worker thread back to the PG backend thread.
enum WorkerReply {
    StreamReady,
    Row(MySqlRow),
    Rows(Vec<MySqlRow>),
    Done,
    Ok,
    Err(mysql_async::Error),
}

/// Spawn the async worker thread. Returns a sender to communicate with it.
fn spawn_worker(conn_str: String) -> mpsc::SyncSender<WorkerCmd> {
    let (tx, rx) = mpsc::sync_channel::<WorkerCmd>(1);

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("mysql worker runtime");

        let pool = Pool::new(conn_str.as_str());

        // The stream must live for the lifetime of the worker loop.
        let mut stream: Option<
            mysql_async::ResultSetStream<
                'static,
                'static,
                'static,
                MySqlRow,
                mysql_async::TextProtocol,
            >,
        > = None;

        loop {
            match rx.recv() {
                Err(_) => break, // sender dropped, exit
                Ok(WorkerCmd::Disconnect) => {
                    drop(stream);
                    rt.block_on(async {
                        let _ = pool.disconnect().await;
                    });
                    break;
                }
                Ok(WorkerCmd::Query { sql, reply }) => {
                    stream = None; // drop any previous stream
                    let result = rt.block_on(async {
                        let conn = pool.get_conn().await?;
                        let s = sql.stream::<MySqlRow, _>(conn).await?;
                        Ok::<_, mysql_async::Error>(s)
                    });
                    match result {
                        Ok(s) => {
                            stream = Some(s);
                            let _ = reply.send(WorkerReply::StreamReady);
                        }
                        Err(e) => {
                            let _ = reply.send(WorkerReply::Err(e));
                        }
                    }
                }
                Ok(WorkerCmd::Next { reply }) => {
                    let r = if let Some(ref mut s) = stream {
                        rt.block_on(async {
                            match s.next().await {
                                None => WorkerReply::Done,
                                Some(Ok(row)) => WorkerReply::Row(row),
                                Some(Err(e)) => WorkerReply::Err(e),
                            }
                        })
                    } else {
                        WorkerReply::Done
                    };
                    let _ = reply.send(r);
                }
                Ok(WorkerCmd::Execute { sql, reply }) => {
                    let result = rt.block_on(async {
                        let mut conn = pool.get_conn().await?;
                        conn.query_drop(&sql).await?;
                        Ok::<_, mysql_async::Error>(())
                    });
                    let r = match result {
                        Ok(()) => WorkerReply::Ok,
                        Err(e) => WorkerReply::Err(e),
                    };
                    let _ = reply.send(r);
                }
                Ok(WorkerCmd::QueryAll { sql, reply }) => {
                    let result = rt.block_on(async {
                        let mut conn = pool.get_conn().await?;
                        let rows: Vec<MySqlRow> = conn.query(sql).await?;
                        conn.disconnect().await?;
                        Ok::<_, mysql_async::Error>(rows)
                    });
                    let r = match result {
                        Ok(rows) => WorkerReply::Rows(rows),
                        Err(e) => WorkerReply::Err(e),
                    };
                    let _ = reply.send(r);
                }
            }
        }
    });

    tx
}

// ---------------------------------------------------------------------------
// FDW struct
// ---------------------------------------------------------------------------

#[wrappers_fdw(
    version = "0.1.2",
    author = "Wener",
    website = "https://github.com/supabase/wrappers/tree/main/wrappers/src/fdw/mysql_fdw",
    error_type = "MysqlFdwError"
)]
pub(crate) struct MysqlFdw {
    /// Channel to the async worker thread (owns the runtime, pool, and stream).
    tx: mpsc::SyncSender<WorkerCmd>,
    table: String,
    rowid_col: String,
    tgt_cols: Vec<Column>,
    sql_query: String,
    scaned_row_cnt: usize,
    /// Per-operation wall-clock timeout. Worker runs independently in its own
    /// thread so this is a plain std::sync::mpsc recv_timeout — unaffected by
    /// PG signal handling. Defaults to 30 s; set via server option `timeout_secs`.
    timeout: Duration,
}

impl MysqlFdw {
    const FDW_NAME: &'static str = "MysqlFdw";

    /// Send a command (already containing the reply channel) and block until reply or timeout.
    fn send_cmd(
        &self,
        cmd: WorkerCmd,
        reply_rx: mpsc::Receiver<WorkerReply>,
    ) -> MysqlFdwResult<WorkerReply> {
        self.tx
            .send(cmd)
            .map_err(|_| MysqlFdwError::ConversionError("worker thread gone".into()))?;
        reply_rx
            .recv_timeout(self.timeout)
            .map_err(|_| MysqlFdwError::Timeout(self.timeout.as_secs()))
    }

    fn setup_streaming(&self) -> MysqlFdwResult<()> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        match self.send_cmd(
            WorkerCmd::Query {
                sql: self.sql_query.clone(),
                reply: reply_tx,
            },
            reply_rx,
        )? {
            WorkerReply::StreamReady => Ok(()),
            WorkerReply::Err(e) => Err(e.into()),
            _ => Err(MysqlFdwError::ConversionError(
                "unexpected worker reply".into(),
            )),
        }
    }

    fn execute_sql(&self, sql: String) -> MysqlFdwResult<()> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        match self.send_cmd(
            WorkerCmd::Execute {
                sql,
                reply: reply_tx,
            },
            reply_rx,
        )? {
            WorkerReply::Ok => {
                stats::inc_stats(Self::FDW_NAME, stats::Metric::RowsOut, 1);
                Ok(())
            }
            WorkerReply::Err(e) => Err(e.into()),
            _ => Err(MysqlFdwError::ConversionError(
                "unexpected worker reply".into(),
            )),
        }
    }

    fn deparse_aggregate(
        table: &str,
        aggregates: &[Aggregate],
        group_by: &[Column],
        quals: &[Qual],
        sorts: &[Sort],
        limit: &Option<Limit>,
    ) -> MysqlFdwResult<String> {
        let mut select_items: Vec<String> = Vec::new();

        for col in group_by {
            select_items.push(format!(
                "{} as {}",
                quote_ident(&col.name),
                quote_ident(&col.name)
            ));
        }

        for agg in aggregates {
            let expr = match agg.kind {
                AggregateKind::Count => "count(*)".to_string(),
                AggregateKind::CountColumn => {
                    let col_name = agg
                        .column
                        .as_ref()
                        .map(|c| quote_ident(&c.name))
                        .unwrap_or_default();
                    if agg.distinct {
                        format!("count(distinct {col_name})")
                    } else {
                        format!("count({col_name})")
                    }
                }
                _ => {
                    let func = agg.kind.sql_name();
                    let col_name = agg
                        .column
                        .as_ref()
                        .map(|c| quote_ident(&c.name))
                        .unwrap_or_default();
                    format!("{func}({col_name})")
                }
            };
            select_items.push(format!("{expr} as {}", quote_ident(&agg.alias)));
        }

        let mut sql = format!(
            "select {} from {}",
            select_items.join(", "),
            quote_ident(table)
        );

        if !quals.is_empty() {
            let mut fmt = MysqlCellFormatter;
            let cond = quals
                .iter()
                .map(|q| deparse_qual(q, &mut fmt))
                .collect::<Vec<String>>()
                .join(" and ");
            if !cond.is_empty() {
                sql.push_str(&format!(" where {cond}"));
            }
        }

        if !group_by.is_empty() {
            let group_cols = group_by
                .iter()
                .map(|c| quote_ident(&c.name))
                .collect::<Vec<String>>()
                .join(", ");
            sql.push_str(&format!(" group by {group_cols}"));
        }

        let valid_sort_fields: Vec<&str> = group_by
            .iter()
            .map(|c| c.name.as_str())
            .chain(aggregates.iter().map(|a| a.alias.as_str()))
            .collect();
        let valid_sorts: Vec<&Sort> = sorts
            .iter()
            .filter(|s| valid_sort_fields.contains(&s.field.as_str()))
            .collect();

        if !valid_sorts.is_empty() {
            let order_by = valid_sorts
                .iter()
                .map(|sort| {
                    let mut clause = quote_ident(&sort.field);
                    if sort.reversed {
                        clause.push_str(" desc");
                    } else {
                        clause.push_str(" asc");
                    }
                    clause
                })
                .collect::<Vec<String>>()
                .join(", ");
            sql.push_str(&format!(" order by {order_by}"));
        }

        if let Some(limit) = limit {
            let real_limit = limit.offset + limit.count;
            sql.push_str(&format!(" limit {real_limit}"));
        }

        Ok(sql)
    }

    fn deparse(
        table: &str,
        quals: &[Qual],
        columns: &[Column],
        sorts: &[Sort],
        limit: &Option<Limit>,
    ) -> MysqlFdwResult<String> {
        let tgts = if columns.is_empty() {
            "*".to_string()
        } else {
            columns
                .iter()
                .map(|c| quote_ident(&c.name))
                .collect::<Vec<String>>()
                .join(", ")
        };

        let tbl = if table.starts_with('(') && table.ends_with(')') {
            table.to_string()
        } else {
            quote_ident(table)
        };
        let mut sql = format!("select {tgts} from {tbl} as _wrappers_tbl");

        if !quals.is_empty() {
            let mut fmt = MysqlCellFormatter;
            let cond = quals
                .iter()
                .map(|q| deparse_qual(q, &mut fmt))
                .collect::<Vec<String>>()
                .join(" and ");
            if !cond.is_empty() {
                sql.push_str(&format!(" where {cond}"));
            }
        }

        if !sorts.is_empty() {
            let order_by = sorts
                .iter()
                .map(|sort| {
                    let mut clause = quote_ident(&sort.field);
                    if sort.reversed {
                        clause.push_str(" desc");
                    } else {
                        clause.push_str(" asc");
                    }
                    clause
                })
                .collect::<Vec<String>>()
                .join(", ");
            sql.push_str(&format!(" order by {order_by}"));
        }

        if let Some(limit) = limit {
            let real_limit = limit.offset + limit.count;
            sql.push_str(&format!(" limit {real_limit}"));
        }

        Ok(sql)
    }
}

// ---------------------------------------------------------------------------
// ForeignDataWrapper implementation
// ---------------------------------------------------------------------------

impl ForeignDataWrapper<MysqlFdwError> for MysqlFdw {
    fn new(server: ForeignServer) -> MysqlFdwResult<Self> {
        let conn_str = match server.options.get("conn_string") {
            Some(s) => s.to_owned(),
            None => {
                let id = require_option("conn_string_id", &server.options)?;
                get_vault_secret(id)
                    .ok_or_else(|| MysqlFdwError::VaultSecretNotFound(id.to_string()))?
            }
        };

        let timeout_secs = server
            .options
            .get("timeout_secs")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(30);

        stats::inc_stats(Self::FDW_NAME, stats::Metric::CreateTimes, 1);

        Ok(MysqlFdw {
            tx: spawn_worker(conn_str),
            table: String::default(),
            rowid_col: String::default(),
            tgt_cols: Vec::new(),
            sql_query: String::default(),
            scaned_row_cnt: 0,
            timeout: Duration::from_secs(timeout_secs),
        })
    }

    fn begin_scan(
        &mut self,
        quals: &[Qual],
        columns: &[Column],
        sorts: &[Sort],
        limit: &Option<Limit>,
        options: &HashMap<String, String>,
    ) -> MysqlFdwResult<()> {
        self.table = require_option("table", options)?.to_string();
        self.tgt_cols = columns.to_vec();
        self.scaned_row_cnt = 0;
        self.sql_query = Self::deparse(&self.table, quals, columns, sorts, limit)?;
        self.setup_streaming()
    }

    fn iter_scan(&mut self, row: &mut Row) -> MysqlFdwResult<Option<()>> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        match self.send_cmd(WorkerCmd::Next { reply: reply_tx }, reply_rx)? {
            WorkerReply::Done => {
                stats::inc_stats(
                    Self::FDW_NAME,
                    stats::Metric::RowsIn,
                    self.scaned_row_cnt as i64,
                );
                stats::inc_stats(
                    Self::FDW_NAME,
                    stats::Metric::RowsOut,
                    self.scaned_row_cnt as i64,
                );
                Ok(None)
            }
            WorkerReply::Row(src_row) => {
                let mut tgt_row = Row::new();
                for tgt_col in &self.tgt_cols {
                    let cell = field_to_cell(&src_row, tgt_col)?;
                    tgt_row.push(&tgt_col.name, cell);
                }
                row.replace_with(tgt_row);
                self.scaned_row_cnt += 1;
                Ok(Some(()))
            }
            WorkerReply::Err(e) => Err(e.into()),
            _ => Err(MysqlFdwError::ConversionError(
                "unexpected worker reply".into(),
            )),
        }
    }

    fn re_scan(&mut self) -> MysqlFdwResult<()> {
        self.setup_streaming()
    }

    fn end_scan(&mut self) -> MysqlFdwResult<()> {
        let _ = self.tx.send(WorkerCmd::Disconnect);
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
    ) -> MysqlFdwResult<()> {
        self.table = require_option("table", options)?.to_string();
        self.scaned_row_cnt = 0;

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

        self.sql_query =
            Self::deparse_aggregate(&self.table, aggregates, group_by, quals, &[], &None)?;
        self.setup_streaming()
    }

    fn begin_modify(&mut self, options: &HashMap<String, String>) -> MysqlFdwResult<()> {
        self.table = require_option("table", options)?.to_string();
        self.rowid_col = require_option("rowid_column", options)?.to_string();
        Ok(())
    }

    fn insert(&mut self, src: &Row) -> MysqlFdwResult<()> {
        let mut fmt = MysqlCellFormatter;
        let mut cols = Vec::new();
        let mut vals = Vec::new();

        for (col, cell) in src.iter() {
            cols.push(quote_ident(col));
            match cell {
                Some(cell) => vals.push(fmt.fmt_cell(cell)),
                None => vals.push("null".to_string()),
            }
        }

        self.execute_sql(format!(
            "insert into {} ({}) values ({})",
            quote_ident(&self.table),
            cols.join(", "),
            vals.join(", ")
        ))
    }

    fn update(&mut self, rowid: &Cell, new_row: &Row) -> MysqlFdwResult<()> {
        let mut fmt = MysqlCellFormatter;
        let mut sets = Vec::new();

        for (col, cell) in new_row.iter() {
            if col == &self.rowid_col {
                continue;
            }
            let value = match cell {
                Some(cell) => fmt.fmt_cell(cell),
                None => "null".to_string(),
            };
            sets.push(format!("{} = {}", quote_ident(col), value));
        }

        self.execute_sql(format!(
            "update {} set {} where {} = {}",
            quote_ident(&self.table),
            sets.join(", "),
            quote_ident(&self.rowid_col),
            fmt.fmt_cell(rowid)
        ))
    }

    fn delete(&mut self, rowid: &Cell) -> MysqlFdwResult<()> {
        let mut fmt = MysqlCellFormatter;
        self.execute_sql(format!(
            "delete from {} where {} = {}",
            quote_ident(&self.table),
            quote_ident(&self.rowid_col),
            fmt.fmt_cell(rowid)
        ))
    }

    fn end_modify(&mut self) -> MysqlFdwResult<()> {
        let _ = self.tx.send(WorkerCmd::Disconnect);
        Ok(())
    }

    fn import_foreign_schema(
        &mut self,
        stmt: ImportForeignSchemaStmt,
    ) -> MysqlFdwResult<Vec<String>> {
        let is_strict =
            require_option_or("strict", &stmt.options, "false").eq_ignore_ascii_case("true");

        let db = stmt.remote_schema.replace('\'', "\\'");
        let sql = format!(
            "select table_name, column_name, data_type, column_type, is_nullable, \
             numeric_precision, numeric_scale, column_key \
             from information_schema.columns \
             where table_schema = '{db}' \
             order by table_name, ordinal_position"
        );

        let rows = {
            let (reply_tx, reply_rx) = mpsc::sync_channel(1);
            match self.send_cmd(
                WorkerCmd::QueryAll {
                    sql,
                    reply: reply_tx,
                },
                reply_rx,
            )? {
                WorkerReply::Rows(r) => r,
                WorkerReply::Err(e) => return Err(e.into()),
                _ => {
                    return Err(MysqlFdwError::ConversionError(
                        "unexpected worker reply".into(),
                    ));
                }
            }
        };

        let mut table_names: Vec<String> = Vec::new();
        type TableColInfo =
            HashMap<String, Vec<(String, String, String, bool, Option<u64>, Option<u64>, bool)>>;
        let mut table_cols: TableColInfo = HashMap::new();

        for row in &rows {
            let table_name: String = row.get("TABLE_NAME").unwrap_or_default();
            let column_name: String = row.get("COLUMN_NAME").unwrap_or_default();
            let data_type: String = row.get("DATA_TYPE").unwrap_or_default();
            let column_type: String = row.get("COLUMN_TYPE").unwrap_or_default();
            let is_nullable: String = row.get("IS_NULLABLE").unwrap_or_default();
            let numeric_precision: Option<u64> =
                row.get::<Option<u64>, _>("NUMERIC_PRECISION").flatten();
            let numeric_scale: Option<u64> = row.get::<Option<u64>, _>("NUMERIC_SCALE").flatten();
            let column_key: String = row.get("COLUMN_KEY").unwrap_or_default();

            if !table_cols.contains_key(&table_name) {
                table_names.push(table_name.clone());
            }
            table_cols.entry(table_name).or_default().push((
                column_name,
                data_type,
                column_type,
                is_nullable.eq_ignore_ascii_case("YES"),
                numeric_precision,
                numeric_scale,
                column_key == "PRI",
            ));
        }

        let all_tables: HashSet<&str> = table_names.iter().map(|s| s.as_str()).collect();
        let table_list: HashSet<&str> = stmt.table_list.iter().map(|s| s.as_str()).collect();
        let selected: HashSet<&str> = match stmt.list_type {
            ImportSchemaType::FdwImportSchemaAll => all_tables,
            ImportSchemaType::FdwImportSchemaLimitTo => {
                all_tables.intersection(&table_list).copied().collect()
            }
            ImportSchemaType::FdwImportSchemaExcept => {
                all_tables.difference(&table_list).copied().collect()
            }
        };

        let mut ret: Vec<String> = Vec::new();

        for table_name in &table_names {
            if !selected.contains(table_name.as_str()) {
                continue;
            }
            let columns = match table_cols.get(table_name) {
                Some(c) => c,
                None => continue,
            };

            let mut fields: Vec<String> = Vec::new();
            let mut rowid_col: Option<String> = None;

            for (col_name, data_type, column_type, is_nullable, num_prec, num_scale, is_pk) in
                columns
            {
                match mysql_type_to_pg(data_type, column_type, *num_prec, *num_scale) {
                    Some(pg_type) => {
                        let not_null = if !is_nullable { " not null" } else { "" };
                        let quoted_col = pgrx::spi::quote_identifier(col_name);
                        fields.push(format!("{quoted_col} {pg_type}{not_null}"));
                        if *is_pk && rowid_col.is_none() {
                            rowid_col = Some(col_name.clone());
                        }
                    }
                    None => {
                        if is_strict {
                            return Err(MysqlFdwError::UnsupportedColumnType(format!(
                                "{table_name}.{col_name}"
                            )));
                        }
                    }
                }
            }

            if !fields.is_empty() {
                let rowid_opt = rowid_col
                    .map(|r| format!(", rowid_column '{}'", r.replace('\'', "''")))
                    .unwrap_or_default();
                let table_ident = pgrx::spi::quote_identifier(table_name);
                let table_opt = table_name.replace('\'', "''");
                ret.push(format!(
                    "create foreign table if not exists {table_ident} (\n    {}\n)\nserver {} options (table '{table_opt}'{rowid_opt})",
                    fields.join(",\n    "),
                    stmt.server_name,
                ));
            }
        }

        let _ = self.tx.send(WorkerCmd::Disconnect);
        Ok(ret)
    }

    fn validator(options: Vec<Option<String>>, catalog: Option<pg_sys::Oid>) -> MysqlFdwResult<()> {
        if let Some(oid) = catalog
            && oid == FOREIGN_TABLE_RELATION_ID
        {
            check_options_contain(&options, "table")?;
        }
        Ok(())
    }
}
