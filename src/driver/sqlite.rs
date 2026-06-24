use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use rusqlite::fallible_iterator::FallibleIterator;
use rusqlite::limits::Limit;
use rusqlite::types::ValueRef;
use rusqlite::{Batch, Connection, OpenFlags};

use crate::config::SqliteConfig;
use crate::driver::{
    BackendProfile, Driver, Limits, QueryOutput, ResultSet, cap_cell, estimate_bytes,
    float_to_json, to_hex,
};

pub struct SqliteDriver {
    conn: Arc<Mutex<Connection>>,
    profile: &'static BackendProfile,
}

impl SqliteDriver {
    pub fn connect(
        config: &SqliteConfig,
        profile: &'static BackendProfile,
        read_only: bool,
        memory_uri: Option<&str>,
    ) -> Result<Self> {
        let shared_memory = if config.is_memory() { memory_uri } else { None };

        let mut flags = if read_only {
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX
        } else if config.is_memory() || config.create {
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
        } else {
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX
        };
        if shared_memory.is_some() {
            flags |= OpenFlags::SQLITE_OPEN_URI | OpenFlags::SQLITE_OPEN_SHARED_CACHE;
        }

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

        let (target, target_name): (&Path, String) = match shared_memory {
            Some(uri) => (Path::new(uri), format!("shared in-memory database {uri:?}")),
            None => (
                config.path.as_ref(),
                format!("database {}", config.path.display()),
            ),
        };
        let conn = Connection::open_with_flags(target, flags)
            .with_context(|| format!("failed to open {target_name}"))?;

        if read_only {
            conn.set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0)
                .context("failed to disable ATTACH for read-only mode")?;

            let attached = conn.limit(Limit::SQLITE_LIMIT_ATTACHED)?;
            if attached != 0 {
                bail!("could not disable ATTACH (limit is {attached}); refusing read-only mode");
            }
        }

        conn.query_row("SELECT 1", [], |_| Ok(()))
            .with_context(|| format!("{target_name} failed a probe query"))?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            profile,
        })
    }
}

#[async_trait::async_trait]
impl Driver for SqliteDriver {
    fn name(&self) -> &'static str {
        self.profile.name()
    }

    fn introspection_hint(&self) -> &'static str {
        self.profile.introspection_hint()
    }

    fn exec_notes(&self) -> &'static str {
        self.profile.exec_notes()
    }

    fn enforces_read_only_at_connection(&self) -> bool {
        true
    }

    async fn assert_read_only(&self) -> Result<()> {
        Ok(())
    }

    async fn exec(&self, sql: &str, limits: Limits) -> Result<QueryOutput> {
        let conn = Arc::clone(&self.conn);
        let sql = sql.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            run_batch(&conn, &sql, limits)
        })
        .await
        .context("sqlite executor task failed")?
    }
}

fn run_batch(conn: &Connection, sql: &str, limits: Limits) -> Result<QueryOutput> {
    let mut result_sets: Vec<ResultSet> = Vec::new();
    let mut error = None;
    let mut spent_bytes: u64 = 0;

    let mut batch = Batch::new(conn, sql);
    loop {
        let mut stmt = match batch.next() {
            Ok(Some(stmt)) => stmt,
            Ok(None) => break,

            Err(e) => {
                if result_sets.is_empty() {
                    return Err(e.into());
                }
                error = Some(e.to_string());
                break;
            }
        };

        if stmt.column_count() == 0 {
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
    }

    Ok(QueryOutput { result_sets, error })
}

fn value_ref_to_json(value: ValueRef<'_>) -> serde_json::Value {
    use serde_json::Value as J;
    match value {
        ValueRef::Null => J::Null,
        ValueRef::Integer(i) => J::from(i),
        ValueRef::Real(f) => float_to_json(f),

        ValueRef::Text(bytes) => J::String(String::from_utf8_lossy(bytes).into_owned()),
        ValueRef::Blob(bytes) => J::String(to_hex(bytes)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SqliteConfig;
    use crate::driver::{Limits, SQLITE_PROFILE};

    fn memory_driver() -> SqliteDriver {
        let config: SqliteConfig = toml::from_str("path = \":memory:\"").unwrap();
        SqliteDriver::connect(&config, &SQLITE_PROFILE, false, None).unwrap()
    }

    fn shared_memory_driver(uri: &str) -> SqliteDriver {
        let config: SqliteConfig = toml::from_str("path = \":memory:\"").unwrap();
        SqliteDriver::connect(&config, &SQLITE_PROFILE, false, Some(uri)).unwrap()
    }

    const NO_LIMITS: Limits = Limits {
        max_rows: 0,
        max_cell_bytes: 0,
        max_response_bytes: 0,
    };

    #[tokio::test]
    async fn shared_cache_memory_is_visible_across_connections() {
        let uri = "file:sqlmcp-test-share?mode=memory&cache=shared";
        let _keeper = shared_memory_driver(uri);
        let a = shared_memory_driver(uri);
        a.exec(
            "CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('hi')",
            NO_LIMITS,
        )
        .await
        .unwrap();
        let b = shared_memory_driver(uri);
        let out = b.exec("SELECT v FROM t", NO_LIMITS).await.unwrap();
        assert_eq!(out.result_sets[0].rows[0][0], serde_json::json!("hi"));
    }

    #[tokio::test]
    async fn keeper_keeps_memory_db_alive_across_session_churn() {
        let uri = "file:sqlmcp-test-keeper?mode=memory&cache=shared";
        let _keeper = shared_memory_driver(uri);
        {
            let session = shared_memory_driver(uri);
            session
                .exec(
                    "CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('x')",
                    NO_LIMITS,
                )
                .await
                .unwrap();
        }
        let next = shared_memory_driver(uri);
        let out = next.exec("SELECT v FROM t", NO_LIMITS).await.unwrap();
        assert_eq!(out.result_sets[0].rows[0][0], serde_json::json!("x"));
    }

    #[tokio::test]
    async fn without_keeper_memory_db_dies_with_last_connection() {
        let uri = "file:sqlmcp-test-nokeeper?mode=memory&cache=shared";
        {
            let only = shared_memory_driver(uri);
            only.exec("CREATE TABLE t (v TEXT)", NO_LIMITS)
                .await
                .unwrap();
        }
        let fresh = shared_memory_driver(uri);
        assert!(fresh.exec("SELECT v FROM t", NO_LIMITS).await.is_err());
    }

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
        assert_eq!(out.result_sets[0].rows_affected, Some(0));
        assert_eq!(out.result_sets[1].rows_affected, Some(1));
        assert_eq!(out.result_sets[1].last_insert_id, Some(1));
        assert_eq!(out.result_sets[2].rows_affected, Some(1));
        assert_eq!(out.result_sets[2].last_insert_id, None);
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

        assert!(
            driver
                .exec("SELECT * FROM missing", NO_LIMITS)
                .await
                .is_err()
        );

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

        assert_eq!(out.result_sets[1].rows_affected, Some(1));
        let count = driver
            .exec("SELECT COUNT(*) FROM n", NO_LIMITS)
            .await
            .unwrap();
        assert_eq!(count.result_sets[0].rows[0][0], serde_json::json!(6));
    }
}
