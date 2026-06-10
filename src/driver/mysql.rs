//! MySQL / MariaDB backend (they share a wire protocol and `SHOW GRANTS`
//! format, so one implementation covers both).
//!
//! Read-only fulfilment here is a *privilege assertion*: at startup we run
//! `SHOW GRANTS` and refuse to start unless every granted privilege is in a
//! tiny read-only allowlist. We use an allowlist, not a blocklist, on purpose —
//! a new server version adding a new writable privilege can never silently slip
//! past us.

use anyhow::{Context, Result, bail};
use mysql_async::consts::{ColumnFlags, ColumnType};
use mysql_async::prelude::*;
use mysql_async::{Column, Conn, Opts, OptsBuilder, SslOpts, Value};
use tokio::sync::Mutex;

use crate::config::NetConfig;
use crate::driver::{
    Driver, Limits, QueryOutput, ResultSet, cap_cell, estimate_bytes, float_to_json, to_hex,
};

/// Privileges that cannot modify data, schema, or other sessions. Anything not
/// in this set disqualifies the account from read-only mode.
const READ_ONLY_PRIVILEGES: &[&str] = &["SELECT", "SHOW VIEW", "USAGE"];

/// MySQL collation id 63 = the `binary` charset; it marks BLOB/VARBINARY/BIT
/// columns (as opposed to TEXT, which shares the same wire types but carries a
/// text collation).
const BINARY_CHARSET: u16 = 63;

const DEFAULT_PORT: u16 = 3306;

/// One persistent connection, not a pool: tool calls are serial, and a single
/// session keeps `USE`/`SET`/temp-table state stable across calls. `None`
/// means the previous call hit a fatal (connection-level) error; the next call
/// reconnects with a fresh session.
pub struct MySqlDriver {
    opts: Opts,
    conn: Mutex<Option<Conn>>,
    name: &'static str,
}

impl MySqlDriver {
    pub async fn connect(config: &NetConfig, name: &'static str) -> Result<Self> {
        let mut opts = OptsBuilder::default()
            .ip_or_hostname(config.host.clone())
            .tcp_port(config.port.unwrap_or(DEFAULT_PORT))
            .user(Some(config.user.clone()))
            .pass(Some(config.password.clone()))
            .db_name(config.database.clone());

        if config.tls {
            let mut ssl = SslOpts::default();
            if let Some(ca) = &config.tls_ca {
                ssl = ssl.with_root_certs(vec![ca.clone().into()]);
            }
            if config.tls_insecure {
                ssl = ssl
                    .with_danger_accept_invalid_certs(true)
                    .with_danger_skip_domain_validation(true);
            }
            opts = opts.ssl_opts(ssl);
        }

        let opts = Opts::from(opts);
        // Connect now so bad host/credentials surface at startup, not on the
        // first tool call.
        let conn = Conn::new(opts.clone())
            .await
            .context("failed to connect to the database")?;
        Ok(Self {
            opts,
            conn: Mutex::new(Some(conn)),
            name,
        })
    }
}

#[async_trait::async_trait]
impl Driver for MySqlDriver {
    fn name(&self) -> &'static str {
        self.name
    }

    fn introspection_hint(&self) -> &'static str {
        "SHOW TABLES, DESCRIBE <table>, SHOW CREATE TABLE <table>, and information_schema"
    }

    fn exec_notes(&self) -> &'static str {
        " Binary values use 0x hex."
    }

    async fn assert_read_only(&self) -> Result<()> {
        let mut guard = self.conn.lock().await;
        let conn = match guard.as_mut() {
            Some(conn) => conn,
            None => unreachable!("assert_read_only runs right after connect"),
        };
        let grants: Vec<String> = conn.query("SHOW GRANTS").await?;

        let mut violations = Vec::new();
        for line in &grants {
            if let Some(reason) = grant_violation(line) {
                violations.push(format!("  {line}\n      -> disqualifying: {reason}"));
            }
        }
        if !violations.is_empty() {
            bail!(
                "account is not read-only; the following grants permit mutation \
                 (or could not be verified):\n{}\n\n\
                 Grant this account only SELECT (and optionally SHOW VIEW), or run \
                 without --read-only.",
                violations.join("\n")
            );
        }
        Ok(())
    }

    async fn exec(&self, sql: &str, limits: Limits) -> Result<QueryOutput> {
        let mut guard = self.conn.lock().await;
        if guard.is_none() {
            *guard = Some(
                Conn::new(self.opts.clone())
                    .await
                    .context("reconnecting to the database")?,
            );
        }
        let conn = guard.as_mut().expect("connection established above");

        match run_query(conn, sql, limits).await {
            Ok(output) => Ok(output),
            Err(e) if e.is_fatal() => {
                // The connection is broken. Drop it so the next call gets a
                // fresh one; never silently retry the statement — if it was a
                // write, a retry could execute it twice.
                *guard = None;
                Err(anyhow::Error::new(e).context(
                    "database connection lost; it will be re-established on the next \
                     call with fresh session state (USE/SET/temp tables are gone)",
                ))
            }
            Err(e) => Err(e.into()),
        }
    }
}

/// Run one `sql_exec` payload and consume *every* result set before
/// returning. Leaving a set pending would hand its bytes — and, worse, any
/// buffered error packet — to the next tool call (`clean_dirty` propagates
/// such errors). Capped rows are still read off the wire and discarded; that
/// costs nothing extra, since the server has already sent them.
async fn run_query(conn: &mut Conn, sql: &str, limits: Limits) -> mysql_async::Result<QueryOutput> {
    // An error in the first statement surfaces here and fails the whole call.
    let mut result = conn.query_iter(sql).await?;

    let mut result_sets = Vec::new();
    let mut error = None;
    let mut spent_bytes: u64 = 0;

    // Outer loop: one iteration per result set. `result.next()` yields the
    // current set's rows and auto-advances to the next set at the boundary.
    loop {
        let columns: Vec<Column> = match result.columns() {
            Some(cols) => cols.to_vec(),
            None => Vec::new(),
        };
        let mut rows: Vec<Vec<serde_json::Value>> = Vec::new();
        let mut truncated = false;

        loop {
            match result.next().await {
                Ok(Some(row)) => {
                    if truncated {
                        continue; // draining: keep the protocol in sync, store nothing
                    }
                    if limits.max_rows != 0 && rows.len() as u64 >= limits.max_rows {
                        truncated = true;
                        continue;
                    }
                    let json_row: Vec<serde_json::Value> = columns
                        .iter()
                        .enumerate()
                        .map(|(i, col)| {
                            cap_cell(
                                value_to_json(row.as_ref(i).unwrap_or(&Value::NULL), col),
                                limits.max_cell_bytes,
                            )
                        })
                        .collect();
                    let row_bytes: u64 = json_row.iter().map(estimate_bytes).sum::<u64>() + 2;
                    if limits.max_response_bytes != 0
                        && spent_bytes + row_bytes > limits.max_response_bytes
                    {
                        truncated = true;
                        continue;
                    }
                    spent_bytes += row_bytes;
                    rows.push(json_row);
                }
                Ok(None) => break,
                Err(e) if e.is_fatal() => return Err(e),
                // A later statement (or a failure mid-set) — keep what
                // succeeded, report the error in-band. mysql_async has already
                // cleared the pending state, so the connection stays clean.
                Err(e) => {
                    error = Some(e.to_string());
                    break;
                }
            }
        }

        // A result set (SELECT/SHOW/…) reports rows; everything else reports
        // its write outcome. They are mutually exclusive in practice.
        let is_result_set = !columns.is_empty();
        result_sets.push(ResultSet {
            columns: columns.iter().map(|c| c.name_str().into_owned()).collect(),
            rows,
            rows_affected: if is_result_set {
                None
            } else {
                Some(result.affected_rows())
            },
            last_insert_id: result
                .last_insert_id()
                .filter(|&id| id != 0)
                .and_then(|id| i64::try_from(id).ok()),
            truncated,
        });

        if error.is_some() {
            break;
        }
        if result.is_empty() {
            // `is_empty()` lies when a later statement failed: mysql_async
            // *parks* that ERR packet in the connection (read_result_set →
            // set_pending_result_error) and reading it wiped the status flags,
            // so neither `has_rows` nor `more_results_exists` can see it. One
            // more `next()` surfaces the parked error — and, crucially,
            // *clears* it, so it can't poison the next call. On a truly empty
            // result this probe touches no I/O and returns Ok(None).
            match result.next().await {
                Ok(_) => {}
                Err(e) if e.is_fatal() => return Err(e),
                Err(e) => error = Some(e.to_string()),
            }
            break;
        }
    }

    Ok(QueryOutput { result_sets, error })
}

/// Map a MySQL value to JSON, preserving NULL vs string vs number, and keeping
/// binary data intact as hex.
///
/// `query_iter` uses the text protocol, so non-NULL values arrive as `Bytes`
/// regardless of declared type; we coerce numeric columns back to JSON numbers
/// using the column metadata. `DECIMAL`/`NEWDECIMAL` are deliberately left as
/// strings so their precision is never lost to a float. Columns in the
/// `binary` charset (BLOB/VARBINARY/BINARY/BIT/GEOMETRY) are hex-encoded as
/// `0x…` — lossy UTF-8 would silently corrupt them. The typed `Int`/`Double`
/// arms also handle the binary protocol, should a future path use it.
fn value_to_json(value: &Value, column: &Column) -> serde_json::Value {
    use serde_json::Value as J;
    let bytes = match value {
        Value::NULL => return J::Null,
        Value::Int(i) => return J::from(*i),
        Value::UInt(u) => return J::from(*u),
        // Round-trip through the f32's shortest decimal form instead of `as
        // f64`, which would surface noise digits (0.1f32 -> 0.10000000149…).
        Value::Float(f) => {
            return f
                .to_string()
                .parse::<f64>()
                .map(float_to_json)
                .unwrap_or_else(|_| J::String(f.to_string()));
        }
        Value::Double(d) => return float_to_json(*d),
        Value::Date(..) | Value::Time(..) => return J::String(format_temporal(value)),
        Value::Bytes(b) => b,
    };

    let unsigned = column.flags().contains(ColumnFlags::UNSIGNED_FLAG);
    match column.column_type() {
        ColumnType::MYSQL_TYPE_TINY
        | ColumnType::MYSQL_TYPE_SHORT
        | ColumnType::MYSQL_TYPE_INT24
        | ColumnType::MYSQL_TYPE_LONG
        | ColumnType::MYSQL_TYPE_LONGLONG
        | ColumnType::MYSQL_TYPE_YEAR => {
            let text = String::from_utf8_lossy(bytes);
            if unsigned {
                text.parse::<u64>().map(J::from)
            } else {
                text.parse::<i64>().map(J::from)
            }
            .unwrap_or_else(|_| J::String(text.into_owned()))
        }
        ColumnType::MYSQL_TYPE_FLOAT | ColumnType::MYSQL_TYPE_DOUBLE => {
            let text = String::from_utf8_lossy(bytes);
            text.parse::<f64>()
                .map(float_to_json)
                .unwrap_or_else(|_| J::String(text.into_owned()))
        }
        // Binary-charset string/blob types hold bytes, not text.
        ColumnType::MYSQL_TYPE_TINY_BLOB
        | ColumnType::MYSQL_TYPE_MEDIUM_BLOB
        | ColumnType::MYSQL_TYPE_LONG_BLOB
        | ColumnType::MYSQL_TYPE_BLOB
        | ColumnType::MYSQL_TYPE_STRING
        | ColumnType::MYSQL_TYPE_VAR_STRING
        | ColumnType::MYSQL_TYPE_VARCHAR
        | ColumnType::MYSQL_TYPE_BIT
        | ColumnType::MYSQL_TYPE_GEOMETRY
            if column.character_set() == BINARY_CHARSET =>
        {
            J::String(to_hex(bytes))
        }
        // DECIMAL, text strings, dates, JSON, enums, … stay as text.
        _ => J::String(String::from_utf8_lossy(bytes).into_owned()),
    }
}

/// Render a `DATE`/`DATETIME`/`TIMESTAMP` or `TIME` value as a string.
fn format_temporal(value: &Value) -> String {
    match value {
        Value::Date(y, mo, d, h, mi, s, us) => {
            let mut out = format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}");
            if *us > 0 {
                out.push_str(&format!(".{us:06}"));
            }
            out
        }
        Value::Time(neg, days, h, mi, s, us) => {
            let hours = (*days) * 24 + *h as u32;
            let sign = if *neg { "-" } else { "" };
            let mut out = format!("{sign}{hours:02}:{mi:02}:{s:02}");
            if *us > 0 {
                out.push_str(&format!(".{us:06}"));
            }
            out
        }
        _ => String::new(),
    }
}

/// Inspect one `SHOW GRANTS` line. Returns `Some(reason)` if it permits mutation
/// (or cannot be verified, e.g. a role grant), or `None` if it is read-only.
fn grant_violation(line: &str) -> Option<String> {
    let upper = line.trim().to_uppercase();

    // `WITH GRANT OPTION` lets the account grant itself anything later.
    if upper.contains("WITH GRANT OPTION") {
        return Some("WITH GRANT OPTION".to_string());
    }

    let rest = match upper.strip_prefix("GRANT ") {
        Some(r) => r,
        None => return Some("unrecognized grant statement".to_string()),
    };

    // Strip column-level lists like `SELECT (col1, col2)` *before* locating
    // the ` ON ` clause: a column name containing " on " would otherwise
    // truncate the privilege list early and hide later privileges from the
    // check. Doing it first also keeps the inner commas from breaking the
    // split below.
    let rest = strip_parens(rest);

    // No `ON` clause => a role grant (`GRANT rolename TO user`). MariaDB roles
    // aren't expanded by SHOW GRANTS, so we can't verify them — refuse.
    let privileges = match rest.find(" ON ") {
        Some(idx) => &rest[..idx],
        None => return Some(format!("role or unverifiable grant: {}", line.trim())),
    };

    for priv_name in privileges.split(',') {
        let priv_name = priv_name.trim();
        if priv_name.is_empty() {
            continue;
        }
        if !READ_ONLY_PRIVILEGES.contains(&priv_name) {
            return Some(priv_name.to_string());
        }
    }
    None
}

/// Remove parenthesized segments (column lists) from a privilege list.
fn strip_parens(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut depth = 0usize;
    for c in s.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::grant_violation;

    #[test]
    fn allows_read_only_grants() {
        assert!(grant_violation("GRANT USAGE ON *.* TO `ro`@`%`").is_none());
        assert!(grant_violation("GRANT SELECT ON `app`.* TO `ro`@`%`").is_none());
        assert!(grant_violation("GRANT SELECT, SHOW VIEW ON `app`.* TO `ro`@`%`").is_none());
        assert!(grant_violation("GRANT SELECT (id, name) ON `app`.`t` TO `ro`@`%`").is_none());
    }

    #[test]
    fn rejects_writable_grants() {
        assert!(grant_violation("GRANT ALL PRIVILEGES ON *.* TO `x`@`%`").is_some());
        assert!(grant_violation("GRANT SELECT, INSERT ON `app`.* TO `x`@`%`").is_some());
        assert!(grant_violation("GRANT SELECT, UPDATE (col) ON `app`.`t` TO `x`@`%`").is_some());
        assert!(grant_violation("GRANT DROP ON `app`.* TO `x`@`%`").is_some());
        assert!(grant_violation("GRANT PROCESS ON *.* TO `x`@`%`").is_some());
        assert!(grant_violation("GRANT FILE ON *.* TO `x`@`%`").is_some());
    }

    #[test]
    fn rejects_grant_option_and_roles() {
        assert!(grant_violation("GRANT SELECT ON *.* TO `x`@`%` WITH GRANT OPTION").is_some());
        assert!(grant_violation("GRANT `read_role` TO `x`@`%`").is_some());
    }

    #[test]
    fn column_name_containing_on_cannot_hide_privileges() {
        // The " on " inside the backquoted column name must not be mistaken
        // for the ON clause — the UPDATE after it has to be caught.
        assert!(
            grant_violation("GRANT SELECT (`a on b`), UPDATE (c) ON `app`.`t` TO `x`@`%`")
                .is_some()
        );
        // Same shape but genuinely read-only stays accepted.
        assert!(grant_violation("GRANT SELECT (`a on b`, c) ON `app`.`t` TO `x`@`%`").is_none());
    }
}
