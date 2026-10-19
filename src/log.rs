//! Server-log helpers that never include a token or any part of one.

use pgrx::prelude::*;

/// Logs one `LOG_SERVER_ONLY` (= `COMMERROR`) line for a refused or undecided login.
/// Callers must never pass a token or any part of one.
pub fn refusal(reason: &str, detail: &str) {
    let message = if detail.is_empty() {
        format!("pg_oauth_rs: {reason}")
    } else {
        format!("pg_oauth_rs: {reason}: {detail}")
    };
    // Below ERROR, so this reports and returns; it never unwinds on its own.
    ereport!(
        PgLogLevel::LOG_SERVER_ONLY,
        PgSqlErrorCode::ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION,
        message
    );
}
