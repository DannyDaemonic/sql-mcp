//! Backend abstraction.
//!
//! Every backend exposes exactly what the single `sql_exec` tool needs: a way
//! to run arbitrary SQL, plus a way to *fulfil read-only mode*. Each driver
//! owns one persistent connection — MCP tool calls arrive serially, and a
//! single session means `USE db`, `SET @vars`, and temporary tables behave the
//! way the model expects from call to call (a pool would route consecutive
//! calls to different sessions). If the connection drops, the driver
//! reconnects on the next call with a *fresh* session and says so in the
//! error, rather than silently retrying the statement (a retry could
//! double-execute a write).
//!
//! A call may carry multiple statements (MySQL negotiates multi-statements at
//! the protocol level) and a statement may produce multiple result sets
//! (stored procedures). `exec` must consume *everything* before returning —
//! a result set left pending on the connection would surface, including any
//! buffered error, on the *next* tool call. Nothing is deferred: every byte
//! and every error belongs to the call that caused it.
//!
//! # Read-only
//!
//! Read-only is an intent expressed by the operator; each backend satisfies it
//! with the strongest mechanism it actually has. The contract: the account (or
//! connection) must be **incapable of mutating persistent state** — data,
//! schema, and privileges. Not filtered, not configured, incapable. Session
//! flags never count, because any flag reachable from SQL can be flipped back
//! by the very SQL we are about to run.
//!
//! What the contract deliberately does *not* cover: shared-state side effects
//! that require no privilege at all. A SELECT-only MySQL account can still call
//! `GET_LOCK()` (server-wide advisory locks), `SLEEP()`, or simply burn CPU
//! with an expensive query; PostgreSQL's `pg_advisory_lock()` is likewise
//! ungated. No privilege inspection can exclude those — they come with SQL
//! access itself, so we document the carve-out instead of pretending a grant
//! check covers it.
//!
//!   * Some backends enforce read-only below the SQL layer. For those,
//!     `enforces_read_only_at_connection()` is true and no account inspection
//!     is needed. SQLite does exactly this: the file is opened with
//!     `SQLITE_OPEN_READONLY` *and* `SQLITE_LIMIT_ATTACHED` is set to 0, so a
//!     query cannot `ATTACH` a second, writable file — the open-flag alone
//!     does not obviously cover attached databases, so we don't rely on it.
//!     (Carve-out, analogous to `GET_LOCK` above: a read-only connection can
//!     still `CREATE TEMP TABLE` — the temp database is session-private and
//!     separate from the file; persistent state stays untouched.)
//!   * MySQL/MariaDB cannot enforce read-only per connection, so the gate is
//!     proving the *account* can't write: `assert_read_only` inspects grants
//!     against an allowlist and refuses startup otherwise.
//!   * PostgreSQL takes the same account-assertion path, but the inspection is
//!     necessarily wider than MySQL's `SHOW GRANTS`: role attributes
//!     (superuser/createdb/createrole/replication/bypassrls) on every role the
//!     account can assume (attributes require `SET ROLE`; grants flow via
//!     INHERIT too), object *ownership* across every owned object class —
//!     relations, schemas, databases, functions, types, operators, text-search
//!     objects, FDWs/servers, languages, tablespaces, publications,
//!     subscriptions, extensions, … — since owners hold full rights with no
//!     ACL entry to see, and ACLs across every grantable class:
//!     relation/column/large-object, schema, database,
//!     type/language/FDW/server/tablespace, parameter, and default ACLs.
//!     That includes `CREATE` on schemas, `TEMP` on the database (revocable
//!     in PostgreSQL, so unlike SQLite no carve-out: `REVOKE TEMP ... FROM
//!     PUBLIC` is required to qualify), `USAGE` on FDWs/foreign servers
//!     (permits CREATE SERVER / CREATE USER MAPPING — catalog mutation), and
//!     `GRANT ALTER SYSTEM ON PARAMETER` (persistent server config; the
//!     session-local `SET` form is allowed) — plus memberships in predefined
//!     `pg_*` roles, whose powers are invisible to ACL scans. Any privilege
//!     held `WITH GRANT OPTION` and any membership held `WITH ADMIN OPTION`
//!     disqualify regardless of the underlying privilege: handing access
//!     onward is privilege mutation. Connecting to a hot standby is *not*
//!     accepted as connection-level enforcement: a standby can be promoted
//!     mid-session, at which point writes become possible.
//!
//!     The privilege half of the PostgreSQL contract is precisely *cannot
//!     escalate access*, not *cannot touch the privilege catalogs*: a role
//!     can always change its own password and per-role session defaults
//!     (`ALTER ROLE CURRENT_USER …` — MySQL's ungated self `SET PASSWORD` is
//!     the same carve-out), `ALTER DEFAULT PRIVILEGES` for objects it would
//!     create (a persistent catalog row, but inert here — a qualifying
//!     account cannot CREATE anything for the rule to apply to), and on
//!     PostgreSQL 15 and older grant membership in *itself* to another role.
//!     None of these extend what can be read or written beyond what was
//!     already granted.
//!     Carve-outs (analogous to `GET_LOCK`): `EXECUTE` is granted to `PUBLIC`
//!     by default, so a `SECURITY DEFINER` function can write with its
//!     owner's privileges, and large objects (`lo_create()`/`lo_from_bytea()`)
//!     persist data with no revocable privilege gating their *creation* —
//!     operators who care can `REVOKE EXECUTE` on the `lo_*` functions.
//!     Likewise `PREPARE TRANSACTION` (only when the server sets
//!     `max_prepared_transactions > 0`; default off) parks a transaction and
//!     its locks past disconnect with no gating privilege.

pub mod mysql;
pub mod postgres;
pub mod sqlite;

use anyhow::Result;
use serde::Serialize;

/// Output caps, set by the operator, enforced by every driver. Each guards a
/// failure mode the others can't see: `max_rows` bounds row count per result
/// set, `max_cell_bytes` stops one huge TEXT/BLOB value from eating the whole
/// budget, and `max_response_bytes` is the global backstop on the serialized
/// response. `0` disables a cap.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_rows: u64,
    pub max_cell_bytes: u64,
    pub max_response_bytes: u64,
}

/// The result of one `sql_exec` call: one entry per statement/result set, in
/// execution order.
#[derive(Debug, Serialize)]
pub struct QueryOutput {
    pub result_sets: Vec<ResultSet>,
    /// Set when a later statement (or result set) failed after earlier ones
    /// succeeded: the earlier `result_sets` are intact and this carries the
    /// failure. An error in the *first* statement fails the whole call
    /// instead. Either way the connection is left clean — errors never leak
    /// into the next call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One result set: `columns`/`rows` for row-returning statements
/// (SELECT/SHOW/…); for statements that return no rows, `columns`/`rows` are
/// empty and `rows_affected`/`last_insert_id` carry the outcome.
#[derive(Debug, Serialize)]
pub struct ResultSet {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows_affected: Option<u64>,
    /// `i64` (not the MySQL-native `u64`) so the field keeps one type across
    /// backends — SQLite rowids are signed; PostgreSQL has no equivalent and
    /// will simply never set it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_insert_id: Option<i64>,
    /// True when `max_rows` or `max_response_bytes` cut this result set short.
    /// The model is told to narrow with LIMIT/aggregation when it sees this.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

#[async_trait::async_trait]
pub trait Driver: Send + Sync {
    /// Human-readable backend name, used in instructions and log lines.
    fn name(&self) -> &'static str;

    /// Dialect-specific introspection examples, surfaced to the model in the
    /// tool description (e.g. `SHOW TABLES` vs `sqlite_master` vs
    /// `pg_catalog`). Keep it to one sentence.
    fn introspection_hint(&self) -> &'static str;

    /// Dialect-specific behavior notes appended to the tool description —
    /// things the model must know to use the backend correctly (how binary
    /// values are encoded, PostgreSQL's text-only values and
    /// one-transaction-per-call semantics). Sentences start with a space.
    fn exec_notes(&self) -> &'static str;

    /// True when the connection itself guarantees read-only (below the SQL
    /// layer), so `assert_read_only` is unnecessary. Defaults to false.
    fn enforces_read_only_at_connection(&self) -> bool {
        false
    }

    /// Prove the connecting account cannot mutate persistent state (data,
    /// schema, privileges). Return `Err` to refuse startup. Only called in
    /// read-only mode and only when `enforces_read_only_at_connection()` is
    /// false.
    async fn assert_read_only(&self) -> Result<()>;

    /// Execute SQL (possibly several statements) and return every result set,
    /// subject to `limits`. Enforcement is per-driver because only the driver
    /// can stop materializing rows mid-stream; capped data is still drained
    /// off the wire so the connection is clean for the next call.
    async fn exec(&self, sql: &str, limits: Limits) -> Result<QueryOutput>;
}

// ---- Helpers shared by all drivers ----

/// Truncate an oversized cell value at a UTF-8 boundary, marking the cut
/// in-band so the model can tell truncated data from real data.
pub(crate) fn cap_cell(value: serde_json::Value, max_cell_bytes: u64) -> serde_json::Value {
    let serde_json::Value::String(s) = &value else {
        return value; // numbers/null are always small
    };
    if max_cell_bytes == 0 || s.len() as u64 <= max_cell_bytes {
        return value;
    }
    let total = s.len();
    let mut end = max_cell_bytes as usize;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    serde_json::Value::String(format!("{}…[truncated; {total} bytes total]", &s[..end]))
}

/// Approximate serialized size of one cell (compact JSON), plus separator.
pub(crate) fn estimate_bytes(value: &serde_json::Value) -> u64 {
    use serde_json::Value as J;
    let len = match value {
        J::Null => 4,
        J::Bool(_) => 5,
        J::Number(n) => n.to_string().len(),
        J::String(s) => s.len() + 2,
        // We never produce nested values; charge something non-zero anyway.
        J::Array(_) | J::Object(_) => 16,
    };
    len as u64 + 1
}

/// Hex-encode binary data as `0x…` — lossy UTF-8 would silently corrupt it.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// JSON has no NaN/Infinity, so non-finite floats fall back to their string form.
pub(crate) fn float_to_json(f: f64) -> serde_json::Value {
    serde_json::Number::from_f64(f)
        .map(serde_json::Value::Number)
        .unwrap_or_else(|| serde_json::Value::String(f.to_string()))
}

#[cfg(test)]
mod tests {
    use super::cap_cell;

    #[test]
    fn cap_cell_truncates_at_char_boundary_and_marks() {
        let long = format!("{}é tail", "x".repeat(9)); // 'é' spans bytes 9..11
        let capped = cap_cell(serde_json::Value::String(long.clone()), 10);
        let serde_json::Value::String(s) = capped else {
            panic!("expected string");
        };
        // Cut lands inside 'é', so it backs up to byte 9.
        assert!(
            s.starts_with("xxxxxxxxx…[truncated; 16 bytes total]"),
            "{s}"
        );

        // Under the cap, and with the cap disabled: untouched.
        let v = serde_json::Value::String("short".into());
        assert_eq!(cap_cell(v.clone(), 10), v);
        let big = serde_json::Value::String("y".repeat(100));
        assert_eq!(cap_cell(big.clone(), 0), big);
    }
}
