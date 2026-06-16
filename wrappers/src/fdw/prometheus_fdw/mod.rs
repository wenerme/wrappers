#![allow(clippy::module_inception)]
mod prometheus_fdw;
mod tests;

use pgrx::pg_sys::panic::ErrorReport;
use pgrx::prelude::PgSqlErrorCode;
use thiserror::Error;

use supabase_wrappers::prelude::sanitize_error_message;

#[derive(Error, Debug)]
enum PrometheusFdwError {
    #[error("{0}")]
    OptionsError(#[from] supabase_wrappers::prelude::OptionsError),

    #[error("{0}")]
    CreateRuntimeError(#[from] supabase_wrappers::prelude::CreateRuntimeError),

    #[error("request failed: {0}")]
    RequestError(#[from] reqwest::Error),

    #[error("Prometheus API error: {0}")]
    ApiError(String),

    #[error("JSON parse error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("missing required: {0}")]
    MissingOption(String),
}

impl From<PrometheusFdwError> for ErrorReport {
    fn from(value: PrometheusFdwError) -> Self {
        let msg = sanitize_error_message(&format!("{value}"));
        ErrorReport::new(PgSqlErrorCode::ERRCODE_FDW_ERROR, msg, "")
    }
}

type PrometheusFdwResult<T> = Result<T, PrometheusFdwError>;
