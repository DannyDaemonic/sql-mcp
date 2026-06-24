pub mod mysql;
pub mod postgres;
pub mod sqlite;

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::{Duration, Instant};

use anyhow::Result;
use serde::Serialize;
use tokio::sync::Mutex;

use crate::config::BackendConfig;
use crate::driver::mysql::MySqlDriver;
use crate::driver::postgres::PostgresDriver;
use crate::driver::sqlite::SqliteDriver;

const BINARY_EXEC_NOTES: &str = " Binary values use 0x hex.";

pub(crate) struct BackendMetadata {
    introspection_hint: &'static str,
    exec_notes: &'static str,
    read_only_state: &'static str,
    writable_state: &'static str,
}

pub(crate) struct BackendProfile {
    name: &'static str,
    metadata: &'static BackendMetadata,
}

impl BackendProfile {
    pub(crate) fn name(&self) -> &'static str {
        self.name
    }

    pub(crate) fn introspection_hint(&self) -> &'static str {
        self.metadata.introspection_hint
    }

    pub(crate) fn exec_notes(&self) -> &'static str {
        self.metadata.exec_notes
    }

    pub(crate) fn lost_state(&self, read_only: bool) -> String {
        let state = if read_only {
            self.metadata.read_only_state
        } else {
            self.metadata.writable_state
        };
        format!("connection-local state was lost ({state})")
    }

    pub(crate) fn connection_lost(&self, read_only: bool) -> String {
        format!(
            "database connection lost; it will be re-established on the next \
             call with fresh session state; {}",
            self.lost_state(read_only)
        )
    }
}

static MYSQL_METADATA: BackendMetadata = BackendMetadata {
    introspection_hint: "SHOW TABLES, DESCRIBE <table>, SHOW CREATE TABLE <table>, and information_schema",
    exec_notes: BINARY_EXEC_NOTES,
    read_only_state: "USE, SET/session variables, prepared statements, transactions, and session locks",
    writable_state: "USE, SET/session variables, prepared statements, temporary tables, transactions, and session locks",
};

static POSTGRES_METADATA: BackendMetadata = BackendMetadata {
    introspection_hint: "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public', and pg_catalog views such as pg_tables and pg_indexes",
    exec_notes: " Every value is returned as text (PostgreSQL renders it; bytea arrives as \\x-prefixed hex); cast or parse as needed; last_insert_id is never set, use INSERT ... RETURNING. All statements of one call run in a single transaction: if any statement fails, the whole call's effects are rolled back (explicit BEGIN/COMMIT overrides this). COPY FROM STDIN and COPY TO STDOUT are not supported; use INSERT and SELECT.",
    read_only_state: "SET/session parameters, prepared statements, transactions, LISTEN state, and session locks",
    writable_state: "SET/session parameters, prepared statements, temporary tables, transactions, LISTEN state, and session locks",
};

static SQLITE_METADATA: BackendMetadata = BackendMetadata {
    introspection_hint: "SELECT name, sql FROM sqlite_master, PRAGMA table_info(<table>), and PRAGMA database_list",
    exec_notes: BINARY_EXEC_NOTES,
    read_only_state: "temporary objects, connection-local PRAGMAs, and transactions",
    writable_state: "temporary objects, connection-local PRAGMAs, and transactions",
};

pub(crate) static MYSQL_PROFILE: BackendProfile = BackendProfile {
    name: "mysql",
    metadata: &MYSQL_METADATA,
};

pub(crate) static MARIADB_PROFILE: BackendProfile = BackendProfile {
    name: "mariadb",
    metadata: &MYSQL_METADATA,
};

pub(crate) static POSTGRES_PROFILE: BackendProfile = BackendProfile {
    name: "postgres",
    metadata: &POSTGRES_METADATA,
};

pub(crate) static SQLITE_PROFILE: BackendProfile = BackendProfile {
    name: "sqlite",
    metadata: &SQLITE_METADATA,
};

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_rows: u64,
    pub max_cell_bytes: u64,
    pub max_response_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct QueryOutput {
    pub result_sets: Vec<ResultSet>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ResultSet {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows_affected: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_insert_id: Option<i64>,

    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

#[async_trait::async_trait]
pub trait Driver: Send + Sync {
    fn name(&self) -> &'static str;

    fn introspection_hint(&self) -> &'static str;

    fn exec_notes(&self) -> &'static str;

    fn enforces_read_only_at_connection(&self) -> bool {
        false
    }

    async fn assert_read_only(&self) -> Result<()>;

    async fn exec(&self, sql: &str, limits: Limits) -> Result<QueryOutput>;
}

fn next_memory_uri() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    format!("file:sqlmcp-mem-{n}?mode=memory&cache=shared")
}

#[derive(Clone)]
pub struct DriverFactory {
    backend: BackendConfig,
    read_only: bool,
    profile: &'static BackendProfile,

    memory_uri: Option<String>,
}

impl DriverFactory {
    pub fn new(backend: BackendConfig, read_only: bool) -> Self {
        let profile = match &backend {
            BackendConfig::Mysql(_) => &MYSQL_PROFILE,
            BackendConfig::Mariadb(_) => &MARIADB_PROFILE,
            BackendConfig::Postgres(_) => &POSTGRES_PROFILE,
            BackendConfig::Sqlite(_) => &SQLITE_PROFILE,
        };
        let memory_uri = match &backend {
            BackendConfig::Sqlite(cfg) if cfg.is_memory() => Some(next_memory_uri()),
            _ => None,
        };
        Self {
            backend,
            read_only,
            profile,
            memory_uri,
        }
    }

    pub fn name(&self) -> &'static str {
        self.profile.name()
    }

    pub fn requires_lifetime_keeper(&self) -> bool {
        self.memory_uri.is_some()
    }

    pub async fn connect(&self) -> Result<Arc<dyn Driver>> {
        Ok(match &self.backend {
            BackendConfig::Mysql(net) | BackendConfig::Mariadb(net) => {
                Arc::new(MySqlDriver::connect(net, self.profile, self.read_only).await?)
            }
            BackendConfig::Postgres(net) => {
                Arc::new(PostgresDriver::connect(net, self.profile, self.read_only).await?)
            }
            BackendConfig::Sqlite(config) => Arc::new(SqliteDriver::connect(
                config,
                self.profile,
                self.read_only,
                self.memory_uri.as_deref(),
            )?),
        })
    }

    pub fn new_http_session(self: &Arc<Self>, pool: Arc<ConnectionPool>) -> Arc<dyn Driver> {
        SessionDriver::new(Arc::clone(self), pool)
    }

    fn introspection_hint(&self) -> &'static str {
        self.profile.introspection_hint()
    }

    fn exec_notes(&self) -> &'static str {
        self.profile.exec_notes()
    }

    fn lost_state(&self) -> String {
        self.profile.lost_state(self.read_only)
    }
}

pub struct ConnectionPool {
    max: usize,
    eviction_grace: Option<Duration>,
    next_id: std::sync::atomic::AtomicU64,
    entries: StdMutex<HashMap<u64, PoolEntry>>,
}

struct PoolEntry {
    session: Weak<SessionDriver>,
    connected: bool,
    busy: bool,
    last_used: Instant,
}

impl ConnectionPool {
    pub fn new(max: usize, eviction_grace: Option<Duration>) -> Arc<Self> {
        Arc::new(Self {
            max,
            eviction_grace,
            next_id: std::sync::atomic::AtomicU64::new(1),
            entries: StdMutex::new(HashMap::new()),
        })
    }

    fn allocate_id(&self) -> u64 {
        use std::sync::atomic::Ordering;

        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn register(&self, id: u64, session: Weak<SessionDriver>) {
        self.entries.lock().unwrap().insert(
            id,
            PoolEntry {
                session,
                connected: false,
                busy: false,
                last_used: Instant::now(),
            },
        );
    }

    fn reserve(&self, id: u64) -> Result<()> {
        let now = Instant::now();
        let mut entries = self.entries.lock().unwrap();
        entries.retain(|_, entry| entry.session.strong_count() != 0);
        let connected = entries.values().filter(|entry| entry.connected).count();
        if connected < self.max {
            let entry = entries.get_mut(&id).expect("registered HTTP session");
            entry.connected = true;
            entry.busy = true;
            return Ok(());
        }

        let mut candidates: Vec<(u64, Instant)> = self
            .eviction_grace
            .into_iter()
            .flat_map(|grace| {
                entries.iter().filter_map(move |(candidate_id, entry)| {
                    (*candidate_id != id
                        && entry.connected
                        && !entry.busy
                        && now.duration_since(entry.last_used) >= grace)
                        .then_some((*candidate_id, entry.last_used))
                })
            })
            .collect();
        candidates.sort_by_key(|(_, last_used)| *last_used);

        for (candidate_id, last_used) in candidates {
            let Some(session) = entries
                .get(&candidate_id)
                .and_then(|entry| entry.session.upgrade())
            else {
                continue;
            };
            if session.try_evict(now.duration_since(last_used)) {
                let victim = entries.get_mut(&candidate_id).expect("candidate entry");
                victim.connected = false;
                victim.busy = false;
                let entry = entries.get_mut(&id).expect("registered HTTP session");
                entry.connected = true;
                entry.busy = true;
                return Ok(());
            }
        }

        let retry_after = self.eviction_grace.and_then(|grace| {
            entries
                .values()
                .filter(|entry| entry.connected && !entry.busy)
                .map(|entry| grace.saturating_sub(now.duration_since(entry.last_used)))
                .min()
        });
        match (self.eviction_grace, retry_after) {
            (None, _) => anyhow::bail!(
                "database session unavailable: all {} sql-mcp connection slots are in use \
                 and pressure eviction is disabled; this statement was not executed, retry later",
                self.max
            ),
            (_, Some(wait)) => anyhow::bail!(
                "database session unavailable: all {} sql-mcp connection slots are in use; \
                 the oldest idle session becomes eligible for eviction in about {} seconds; \
                 this statement was not executed, retry later",
                self.max,
                wait.as_secs().max(1)
            ),
            (_, None) => anyhow::bail!(
                "database session unavailable: all {} sql-mcp connection slots are executing; \
                 this statement was not executed, retry later",
                self.max
            ),
        }
    }

    fn connected(&self, id: u64) {
        if let Some(entry) = self.entries.lock().unwrap().get_mut(&id) {
            entry.busy = true;
        }
    }

    fn idle(&self, id: u64) {
        if let Some(entry) = self.entries.lock().unwrap().get_mut(&id) {
            entry.busy = false;
            entry.last_used = Instant::now();
        }
    }

    fn release(&self, id: u64) {
        if let Some(entry) = self.entries.lock().unwrap().get_mut(&id) {
            entry.connected = false;
            entry.busy = false;
        }
    }

    fn unregister(&self, id: u64) {
        self.entries.lock().unwrap().remove(&id);
    }
}

struct PoolUse<'a> {
    pool: &'a ConnectionPool,
    id: u64,
    connected: bool,
}

impl Drop for PoolUse<'_> {
    fn drop(&mut self) {
        if self.connected {
            self.pool.idle(self.id);
        } else {
            self.pool.release(self.id);
        }
    }
}

enum SessionState {
    Empty,
    Connected(Arc<dyn Driver>),
    Lost(String),
}

struct SessionDriver {
    factory: Arc<DriverFactory>,
    pool: Arc<ConnectionPool>,
    id: u64,
    state: Mutex<SessionState>,
}

impl SessionDriver {
    fn new(factory: Arc<DriverFactory>, pool: Arc<ConnectionPool>) -> Arc<Self> {
        let id = pool.allocate_id();
        let session = Arc::new(Self {
            factory,
            pool,
            id,
            state: Mutex::new(SessionState::Empty),
        });
        session.pool.register(id, Arc::downgrade(&session));
        session
    }

    fn try_evict(&self, idle_for: Duration) -> bool {
        let Ok(mut state) = self.state.try_lock() else {
            return false;
        };
        if !matches!(*state, SessionState::Connected(_)) {
            return false;
        }
        *state = SessionState::Lost(format!(
            "database session was evicted after {} seconds idle to free connection capacity; \
             this statement was not executed; {}",
            idle_for.as_secs(),
            self.factory.lost_state()
        ));
        true
    }
}

impl Drop for SessionDriver {
    fn drop(&mut self) {
        self.pool.unregister(self.id);
    }
}

#[async_trait::async_trait]
impl Driver for SessionDriver {
    fn name(&self) -> &'static str {
        self.factory.name()
    }

    fn introspection_hint(&self) -> &'static str {
        self.factory.introspection_hint()
    }

    fn exec_notes(&self) -> &'static str {
        self.factory.exec_notes()
    }

    async fn assert_read_only(&self) -> Result<()> {
        Ok(())
    }

    async fn exec(&self, sql: &str, limits: Limits) -> Result<QueryOutput> {
        let mut state = self.state.lock().await;
        if let SessionState::Lost(message) = &*state {
            let message = message.clone();
            *state = SessionState::Empty;
            return Err(anyhow::anyhow!(
                "{message}; a fresh database session will be established on the next call"
            ));
        }
        let mut pool_use = PoolUse {
            pool: &self.pool,
            id: self.id,
            connected: false,
        };
        if matches!(*state, SessionState::Empty) {
            self.pool.reserve(self.id)?;
            match self.factory.connect().await {
                Ok(driver) => *state = SessionState::Connected(driver),
                Err(error) => return Err(error),
            }
        } else {
            self.pool.connected(self.id);
        }
        pool_use.connected = true;
        let SessionState::Connected(driver) = &*state else {
            unreachable!("session connected above")
        };
        driver.exec(sql, limits).await
    }
}

pub(crate) fn cap_cell(value: serde_json::Value, max_cell_bytes: u64) -> serde_json::Value {
    let serde_json::Value::String(s) = &value else {
        return value;
    };
    if max_cell_bytes == 0 || s.len() as u64 <= max_cell_bytes {
        return value;
    }
    let total = s.len();
    let mut end = max_cell_bytes as usize;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    serde_json::Value::String(format!(
        "{}\u{2026}[truncated; {total} bytes total]",
        &s[..end]
    ))
}

pub(crate) fn estimate_bytes(value: &serde_json::Value) -> u64 {
    use serde_json::Value as J;
    let len = match value {
        J::Null => 4,
        J::Bool(_) => 5,
        J::Number(n) => n.to_string().len(),
        J::String(s) => s.len() + 2,

        J::Array(_) | J::Object(_) => 16,
    };
    len as u64 + 1
}

pub(crate) fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub(crate) fn float_to_json(f: f64) -> serde_json::Value {
    serde_json::Number::from_f64(f)
        .map(serde_json::Value::Number)
        .unwrap_or_else(|| serde_json::Value::String(f.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{BackendConfig, DriverFactory, cap_cell};
    use crate::config::SqliteConfig;

    fn sqlite_factory(toml: &str) -> DriverFactory {
        let config: SqliteConfig = toml::from_str(toml).unwrap();
        DriverFactory::new(BackendConfig::Sqlite(config), false)
    }

    #[test]
    fn only_memory_sqlite_requires_a_keeper() {
        assert!(sqlite_factory("path = \":memory:\"").requires_lifetime_keeper());
        assert!(!sqlite_factory("path = \"/tmp/app.db\"").requires_lifetime_keeper());
    }

    #[test]
    fn each_memory_factory_resolves_a_distinct_shared_uri() {
        let a = sqlite_factory("path = \":memory:\"");
        let b = sqlite_factory("path = \":memory:\"");
        let (Some(ua), Some(ub)) = (&a.memory_uri, &b.memory_uri) else {
            panic!("memory factories must resolve a shared-cache uri");
        };

        assert_ne!(ua, ub);
        assert!(
            ua.contains("mode=memory") && ua.contains("cache=shared"),
            "{ua}"
        );
        assert!(
            sqlite_factory("path = \"/tmp/app.db\"")
                .memory_uri
                .is_none()
        );
    }

    #[test]
    fn cap_cell_truncates_at_char_boundary_and_marks() {
        let long = format!("{}\u{00E9} tail", "x".repeat(9));
        let capped = cap_cell(serde_json::Value::String(long.clone()), 10);
        let serde_json::Value::String(s) = capped else {
            panic!("expected string");
        };

        assert!(
            s.starts_with("xxxxxxxxx\u{2026}[truncated; 16 bytes total]"),
            "{s}"
        );

        let v = serde_json::Value::String("short".into());
        assert_eq!(cap_cell(v.clone(), 10), v);
        let big = serde_json::Value::String("y".repeat(100));
        assert_eq!(cap_cell(big.clone(), 0), big);
    }
}
