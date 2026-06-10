//! SQLite backend — the zero-dependency onboarding path. The engine is
//! compiled into the binary (`rusqlite` with `bundled`), so pointing the
//! config at a file (or `":memory:"`) is all it takes.
//!
//! `rusqlite` is deliberately a *placeholder*: the plan is to swap to the
//! pure-Rust `turso` crate once it leaves beta and can meet this project's
//! read-only bar (today its read-only story is the SQL-flippable
//! `PRAGMA query_only`, `sqlite3_limit` is stubbed, and there is no
//! authorizer). The swap is contained to this file; the config surface,
//! tool semantics, and the test suite (which verifies the written file with
//! rusqlite independently) all stay put.
//!
//! Read-only here is enforced *below* the SQL layer, so
//! `enforces_read_only_at_connection()` is true and no account inspection
//! happens:
//!
//!   * the file is opened with `SQLITE_OPEN_READONLY`, and
//!   * `SQLITE_LIMIT_ATTACHED` is set to 0 (and verified), so a query cannot
//!     `ATTACH` a second, writable database file.
//!
//! We also never set `SQLITE_OPEN_URI`, so path strings — in the config and
//! in `ATTACH` — are literal filenames; `file:…?mode=rwc` tricks are inert.
//! Carve-out (analogous to MySQL's `GET_LOCK`): a read-only connection can
//! still `CREATE TEMP TABLE` — the temp database is session-private and
//! separate from the file; persistent state stays untouched.
//!
//! Unlike the MySQL driver there is no reconnect machinery: an in-process
//! handle cannot "drop".

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use rusqlite::fallible_iterator::FallibleIterator;
use rusqlite::limits::Limit;
use rusqlite::types::ValueRef;
use rusqlite::{Batch, Connection, OpenFlags};

use crate::config::SqliteConfig;
use crate::driver::{
    Driver, Limits, QueryOutput, ResultSet, cap_cell, estimate_bytes, float_to_json, to_hex,
};

pub struct SqliteDriver {
    /// `Connection` is `Send + !Sync`; the mutex serializes tool calls (they
    /// arrive serially anyway) and makes the handle shareable with the
    /// `spawn_blocking` closures that run the actual SQL.
    conn: Arc<Mutex<Connection>>,
}

impl SqliteDriver {
    pub fn connect(config: &SqliteConfig, read_only: bool) -> Result<Self> {
        // Never `OpenFlags::default()`: it includes SQLITE_OPEN_URI (config
        // paths must stay literal) and SQLITE_OPEN_CREATE (creation is the
        // operator's explicit, opted-in decision).
        let flags = if read_only {
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX
        } else if config.is_memory() || config.create {
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
        } else {
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX
        };

        // Friendly message only — the open below (without SQLITE_OPEN_CREATE)
        // is the real enforcement, so a race here degrades the message, never
        // the behavior.
        if !config.is_memory() && !config.create && !config.path.exists() {
            if read_only {
                bail!("database file {} does not exist", config.path.display());
            }
            bail!(
                "database file {} does not exist; add create = true to the config \
                 to create it",
                config.path.display()
            );
        }

        let conn = Connection::open_with_flags(&config.path, flags)
            .with_context(|| format!("failed to open database {}", config.path.display()))?;

        if read_only {
            conn.set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0)
                .context("failed to disable ATTACH for read-only mode")?;
            // Verify rather than assume: if anything clamped the limit above
            // zero, read-only would be weaker than promised.
            let attached = conn.limit(Limit::SQLITE_LIMIT_ATTACHED)?;
            if attached != 0 {
                bail!("could not disable ATTACH (limit is {attached}); refusing read-only mode");
            }
        }

        // Surface a corrupt or locked file at startup, not on the first call.
        conn.query_row("SELECT 1", [], |_| Ok(()))
            .with_context(|| format!("database {} failed a probe query", config.path.display()))?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }
}

#[async_trait::async_trait]
impl Driver for SqliteDriver {
    fn name(&self) -> &'static str {
        "sqlite"
    }

    fn introspection_hint(&self) -> &'static str {
        "SELECT name, sql FROM sqlite_master, PRAGMA table_info(<table>), \
         and PRAGMA database_list"
    }

    fn exec_notes(&self) -> &'static str {
        " Binary values use 0x hex."
    }

    fn enforces_read_only_at_connection(&self) -> bool {
        true
    }

    async fn assert_read_only(&self) -> Result<()> {
        // Never called: main.rs short-circuits on
        // `enforces_read_only_at_connection()`. Kept non-panicking on purpose.
        Ok(())
    }

    async fn exec(&self, sql: &str, limits: Limits) -> Result<QueryOutput> {
        let conn = Arc::clone(&self.conn);
        let sql = sql.to_owned();
        tokio::task::spawn_blocking(move || {
            // A poisoned mutex means a prior call panicked — that call already
            // failed loudly; the connection itself is still usable.
            let conn = conn.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            run_batch(&conn, &sql, limits)
        })
        .await
        .context("sqlite executor task failed")?
    }
}

/// Run one `sql_exec` payload: one `ResultSet` per statement, mirroring the
/// MySQL driver's observable semantics — a first-statement failure fails the
/// call, a later statement's failure is reported in-band with earlier results
/// intact (statements after the error never run; rusqlite's `Batch` mandates
/// stopping there).
fn run_batch(conn: &Connection, sql: &str, limits: Limits) -> Result<QueryOutput> {
    let mut result_sets: Vec<ResultSet> = Vec::new();
    let mut error = None;
    let mut spent_bytes: u64 = 0;

    let mut batch = Batch::new(conn, sql);
    loop {
        let mut stmt = match batch.next() {
            Ok(Some(stmt)) => stmt,
            Ok(None) => break,
            // Parse/prepare error. No recovery is possible mid-batch.
            Err(e) => {
                if result_sets.is_empty() {
                    return Err(e.into());
                }
                error = Some(e.to_string());
                break;
            }
        };

        if stmt.column_count() == 0 {
            // No result set: report the write outcome. `changes()` is stale
            // after DDL (it only tracks DML), so use a total_changes() delta —
            // CREATE TABLE correctly reports 0. The delta also counts
            // trigger/cascade changes, which is more honest anyway.
            let changes_before = conn.total_changes();
            let rowid_before = conn.last_insert_rowid();
            match stmt.raw_execute() {
                Ok(_) => {}
                Err(e) => {
                    drop(stmt);
                    if result_sets.is_empty() {
                        return Err(e.into());
                    }
                    error = Some(e.to_string());
                    break;
                }
            }
            let rows_affected = conn.total_changes() - changes_before;
            // last_insert_rowid() is sticky across statements: only report it
            // when this statement actually inserted and the rowid moved.
            // (Blind spot: consecutive inserts into different fresh tables can
            // produce identical rowids; acceptable.)
            let rowid_after = conn.last_insert_rowid();
            let last_insert_id =
                (rows_affected > 0 && rowid_after != rowid_before).then_some(rowid_after);
            result_sets.push(ResultSet {
                columns: Vec::new(),
                rows: Vec::new(),
                rows_affected: Some(rows_affected),
                last_insert_id,
                truncated: false,
            });
            continue;
        }

        // Row-returning statement: stream rows under the caps. Unlike MySQL
        // there is no wire protocol to drain — stepping further would *compute*
        // extra rows — so on truncation we simply stop and drop the statement.
        // Safe even for `INSERT … RETURNING`: SQLite applies all changes on
        // the first step and buffers the RETURNING rows.
        let columns: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
        let mut rows: Vec<Vec<serde_json::Value>> = Vec::new();
        let mut truncated = false;
        let column_count = columns.len();

        let mut rows_iter = stmt.raw_query();
        loop {
            match rows_iter.next() {
                Ok(Some(row)) => {
                    if limits.max_rows != 0 && rows.len() as u64 >= limits.max_rows {
                        truncated = true;
                        break;
                    }
                    let json_row: Vec<serde_json::Value> = (0..column_count)
                        .map(|i| {
                            let value = row
                                .get_ref(i)
                                .map(value_ref_to_json)
                                .unwrap_or(serde_json::Value::Null);
                            cap_cell(value, limits.max_cell_bytes)
                        })
                        .collect();
                    let row_bytes: u64 = json_row.iter().map(estimate_bytes).sum::<u64>() + 2;
                    if limits.max_response_bytes != 0
                        && spent_bytes + row_bytes > limits.max_response_bytes
                    {
                        truncated = true;
                        break;
                    }
                    spent_bytes += row_bytes;
                    rows.push(json_row);
                }
                Ok(None) => break,
                Err(e) => {
                    // Mid-set failure: keep the partial set, report in-band.
                    error = Some(e.to_string());
                    break;
                }
            }
        }

        result_sets.push(ResultSet {
            columns,
            rows,
            rows_affected: None,
            last_insert_id: None,
            truncated,
        });
        if error.is_some() {
            break;
        }
        // After truncation the loop continues with the next statement: the
        // model may have issued writes after a large SELECT, and those must
        // still run (same semantics as the MySQL driver).
    }

    Ok(QueryOutput { result_sets, error })
}

fn value_ref_to_json(value: ValueRef<'_>) -> serde_json::Value {
    use serde_json::Value as J;
    match value {
        ValueRef::Null => J::Null,
        ValueRef::Integer(i) => J::from(i),
        ValueRef::Real(f) => float_to_json(f),
        // SQLite TEXT is UTF-8 by contract; lossy handles the rare junk.
        ValueRef::Text(bytes) => J::String(String::from_utf8_lossy(bytes).into_owned()),
        ValueRef::Blob(bytes) => J::String(to_hex(bytes)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SqliteConfig;
    use crate::driver::Limits;

    fn memory_driver() -> SqliteDriver {
        let config: SqliteConfig = toml::from_str("path = \":memory:\"").unwrap();
        SqliteDriver::connect(&config, false).unwrap()
    }

    const NO_LIMITS: Limits = Limits {
        max_rows: 0,
        max_cell_bytes: 0,
        max_response_bytes: 0,
    };

    #[tokio::test]
    async fn ddl_reports_zero_rows_affected_and_insert_reports_rowid() {
        let driver = memory_driver();
        let out = driver
            .exec(
                "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT); \
                 INSERT INTO t (v) VALUES ('a'); \
                 UPDATE t SET v = 'b'",
                NO_LIMITS,
            )
            .await
            .unwrap();
        assert!(out.error.is_none());
        assert_eq!(out.result_sets.len(), 3);
        assert_eq!(out.result_sets[0].rows_affected, Some(0)); // DDL, not stale DML count
        assert_eq!(out.result_sets[1].rows_affected, Some(1));
        assert_eq!(out.result_sets[1].last_insert_id, Some(1));
        assert_eq!(out.result_sets[2].rows_affected, Some(1));
        assert_eq!(out.result_sets[2].last_insert_id, None); // UPDATE didn't insert
    }

    #[tokio::test]
    async fn later_statement_error_is_in_band_and_types_map() {
        let driver = memory_driver();
        let out = driver
            .exec(
                "SELECT 1 AS a, 0.5 AS b, x'deadbeef' AS c, NULL AS d; SELECT * FROM missing",
                NO_LIMITS,
            )
            .await
            .unwrap();
        assert_eq!(out.result_sets.len(), 1);
        assert_eq!(
            out.result_sets[0].rows[0],
            vec![
                serde_json::json!(1),
                serde_json::json!(0.5),
                serde_json::json!("0xdeadbeef"),
                serde_json::Value::Null,
            ]
        );
        assert!(out.error.as_deref().is_some_and(|e| e.contains("missing")));

        // First-statement failure fails the whole call.
        assert!(
            driver
                .exec("SELECT * FROM missing", NO_LIMITS)
                .await
                .is_err()
        );
        // And the connection is still healthy afterwards.
        let ok = driver.exec("SELECT 42", NO_LIMITS).await.unwrap();
        assert_eq!(ok.result_sets[0].rows[0][0], serde_json::json!(42));
    }

    #[tokio::test]
    async fn truncation_does_not_skip_later_statements() {
        let driver = memory_driver();
        driver
            .exec(
                "CREATE TABLE n (i INTEGER); \
                 INSERT INTO n VALUES (1),(2),(3),(4),(5)",
                NO_LIMITS,
            )
            .await
            .unwrap();
        let capped = Limits {
            max_rows: 2,
            max_cell_bytes: 0,
            max_response_bytes: 0,
        };
        let out = driver
            .exec("SELECT i FROM n; INSERT INTO n VALUES (6)", capped)
            .await
            .unwrap();
        assert!(out.result_sets[0].truncated);
        assert_eq!(out.result_sets[0].rows.len(), 2);
        // The INSERT after the truncated SELECT still ran.
        assert_eq!(out.result_sets[1].rows_affected, Some(1));
        let count = driver
            .exec("SELECT COUNT(*) FROM n", NO_LIMITS)
            .await
            .unwrap();
        assert_eq!(count.result_sets[0].rows[0][0], serde_json::json!(6));
    }
}
