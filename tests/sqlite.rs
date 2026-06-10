//! SQLite integration suite — no Docker required.
//!
//! Dogfooding by design: the database is created, populated, and queried
//! exclusively *through the sql-mcp binary*. Only the final verification
//! step opens the file independently (with rusqlite, i.e. canonical SQLite)
//! to prove what the binary wrote is a well-formed SQLite database with the
//! expected contents and column types. When the backend swaps from rusqlite
//! to the pure-Rust `turso`, that verifier becomes the file-format
//! compatibility proof — these tests should survive the swap unchanged.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde_json::json;
use tempfile::TempDir;

mod common;
use common::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_suite() -> Result<()> {
    let tmp = TempDir::new().context("create sqlite-test tempdir")?;
    let dir = tmp.path();
    let db = dir.join("app.db");
    let missing = dir.join("missing.db");

    let cfg = Configs::write(dir, &db, &missing)?;

    test_missing_file_refusals(&cfg)
        .await
        .context("missing-file refusals")?;
    test_description_and_banner(&cfg)
        .await
        .context("tool description and stderr banner")?;
    test_create_flow_and_typing(&cfg)
        .await
        .context("create flow and type mapping")?;
    test_multi_statement_and_poison(&cfg)
        .await
        .context("multi-statement and poison analog")?;
    test_caps(&cfg).await.context("output caps")?;
    test_temp_table_session(&cfg)
        .await
        .context("temp-table session persistence")?;
    test_read_only(&cfg, dir, &db)
        .await
        .context("read-only enforcement")?;
    test_memory_smoke(&cfg).await.context(":memory: smoke")?;
    test_config_rejections(&cfg)
        .await
        .context("config rejections")?;
    verify_file_with_canonical_sqlite(&db).context("independent rusqlite verification")?;
    Ok(())
}

struct Configs {
    create: PathBuf,
    plain: PathBuf,
    max_rows: PathBuf,
    read_only: PathBuf,
    missing_no_create: PathBuf,
    missing_read_only: PathBuf,
    memory: PathBuf,
    memory_read_only: PathBuf,
    net_key: PathBuf,
    typo_key: PathBuf,
}

impl Configs {
    fn write(dir: &Path, db: &Path, missing: &Path) -> Result<Self> {
        let base = format!("driver = \"sqlite\"\npath = {db:?}\n");
        let missing_base = format!("driver = \"sqlite\"\npath = {missing:?}\n");
        Ok(Self {
            create: write_cfg(
                dir,
                "create.toml",
                &(base.clone() + "create = true\n"),
                0o600,
            )?,
            plain: write_cfg(dir, "plain.toml", &base, 0o600)?,
            max_rows: write_cfg(
                dir,
                "max-rows.toml",
                &(base.clone() + "max_rows = 5\n"),
                0o600,
            )?,
            read_only: write_cfg(
                dir,
                "read-only.toml",
                &(base.clone() + "read_only = true\n"),
                0o600,
            )?,
            missing_no_create: write_cfg(dir, "missing.toml", &missing_base, 0o600)?,
            missing_read_only: write_cfg(
                dir,
                "missing-ro.toml",
                &(missing_base + "read_only = true\n"),
                0o600,
            )?,
            memory: write_cfg(
                dir,
                "memory.toml",
                "driver = \"sqlite\"\npath = \":memory:\"\n",
                0o600,
            )?,
            memory_read_only: write_cfg(
                dir,
                "memory-ro.toml",
                "driver = \"sqlite\"\npath = \":memory:\"\nread_only = true\n",
                0o600,
            )?,
            net_key: write_cfg(
                dir,
                "net-key.toml",
                &(base.clone() + "host = \"127.0.0.1\"\n"),
                0o600,
            )?,
            typo_key: write_cfg(
                dir,
                "typo-key.toml",
                "driver = \"sqlite\"\npth = \"/a.db\"\n",
                0o600,
            )?,
        })
    }
}

async fn test_missing_file_refusals(cfg: &Configs) -> Result<()> {
    // Without create: refused, and the message teaches the fix.
    let output = startup_with_config(&cfg.missing_no_create, &[], &[]).await?;
    ensure_refused(output, &["does not exist", "create = true"])?;

    // Read-only on a missing file: refused, but must NOT suggest create = true
    // (it contradicts read-only).
    let (code, stdout, stderr) = startup_with_config(&cfg.missing_read_only, &[], &[]).await?;
    let combined = stdout + &stderr;
    ensure!(code != 0, "expected refusal:\n{combined}");
    ensure!(combined.contains("does not exist"), "{combined}");
    ensure!(
        !combined.contains("create = true"),
        "read-only missing-file error must not suggest create = true:\n{combined}"
    );
    Ok(())
}

async fn test_description_and_banner(cfg: &Configs) -> Result<()> {
    let mut mcp = McpSession::start(&cfg.create).await?;
    let response = mcp.tools_list().await?;
    let stderr = mcp.close().await?;
    let description = response["result"]["tools"][0]["description"]
        .as_str()
        .context("tool description")?;
    for needle in [
        "configured sqlite database",
        "1000 rows per result set",
        "sqlite_master",
        "Multiple statements",
        "0x",
    ] {
        ensure!(
            description.contains(needle),
            "description missing {needle:?}: {description}"
        );
    }
    ensure!(stderr.contains("serving sql_exec for sqlite"), "{stderr}");
    Ok(())
}

async fn test_create_flow_and_typing(cfg: &Configs) -> Result<()> {
    let mut mcp = McpSession::start(&cfg.create).await?;
    let ddl = tool_payload(
        &mcp.call(
            "CREATE TABLE t (id INTEGER PRIMARY KEY, i INTEGER, r REAL, s TEXT, b BLOB, z TEXT)",
        )
        .await?,
    )?;
    let insert = tool_payload(
        &mcp.call("INSERT INTO t (i, r, s, b, z) VALUES (-42, 0.5, 'héllo', X'DEADBEEF', NULL)")
            .await?,
    )?;
    let select = tool_payload(&mcp.call("SELECT i, r, s, b, z FROM t").await?)?;
    mcp.close().await?;

    // DDL reports 0 (the total_changes delta fix — a stale DML count would be wrong).
    ensure_eq_json(
        &ddl["result_sets"][0],
        &json!({"columns": [], "rows": [], "rows_affected": 0}),
        "CREATE TABLE result shape",
    )?;
    ensure_eq_json(
        &insert["result_sets"][0],
        &json!({"columns": [], "rows": [], "rows_affected": 1, "last_insert_id": 1}),
        "INSERT result shape",
    )?;
    ensure_eq_json(
        &select["result_sets"][0]["rows"],
        &json!([[-42, 0.5, "héllo", "0xdeadbeef", null]]),
        "typed round-trip",
    )?;
    Ok(())
}

async fn test_multi_statement_and_poison(cfg: &Configs) -> Result<()> {
    let mut mcp = McpSession::start(&cfg.plain).await?;

    let two = tool_payload(&mcp.call("SELECT 1; SELECT 2,3").await?)?;
    ensure!(two["result_sets"][0]["rows"] == json!([[1]]));
    ensure!(two["result_sets"][1]["rows"] == json!([[2, 3]]));

    // Later-statement failure: in-band error, earlier set intact…
    let first = tool_payload(
        &mcp.call("SELECT 1 AS ok; SELECT * FROM nonexistent")
            .await?,
    )?;
    ensure!(first["result_sets"][0]["rows"] == json!([[1]]));
    ensure!(
        first["error"]
            .as_str()
            .is_some_and(|error| error.contains("nonexistent")),
        "missing in-band error: {first}"
    );
    // …and the next call must be clean.
    let second = tool_payload(&mcp.call("SELECT 42 AS fine").await?)?;
    ensure!(second["result_sets"][0]["rows"] == json!([[42]]));
    ensure!(second.get("error").is_none());

    // First-statement failure: tool error, next call clean.
    let bad = mcp.call("SELECT * FROM nonexistent").await?;
    ensure!(tool_is_error(&bad) && tool_text(&bad).contains("SQL error"));
    let after = tool_payload(&mcp.call("SELECT 7").await?)?;
    ensure!(after["result_sets"][0]["rows"] == json!([[7]]));

    mcp.close().await?;
    Ok(())
}

async fn test_caps(cfg: &Configs) -> Result<()> {
    // Seed ten rows through the binary.
    let mut mcp = McpSession::start(&cfg.plain).await?;
    tool_payload(
        &mcp.call(
            "CREATE TABLE ten (i INTEGER); \
             INSERT INTO ten VALUES (1),(2),(3),(4),(5),(6),(7),(8),(9),(10)",
        )
        .await?,
    )?;
    // Cell cap (default 16 KiB): SQLite has no REPEAT — hex(zeroblob(50000))
    // produces a 100000-char string.
    let big = tool_payload(&mcp.call("SELECT hex(zeroblob(50000)) AS big").await?)?;
    let value = big["result_sets"][0]["rows"][0][0]
        .as_str()
        .context("big cell")?;
    ensure!(
        value.ends_with("…[truncated; 100000 bytes total]"),
        "{value}"
    );
    ensure!((16_000..=17_000).contains(&value.len()));
    mcp.close().await?;

    // max_rows = 5: truncation, AND a write after the truncated SELECT in the
    // same call must still execute (no statement skipping after truncation).
    let mut mcp = McpSession::start(&cfg.max_rows).await?;
    let payload = tool_payload(
        &mcp.call("SELECT i FROM ten; INSERT INTO ten VALUES (11)")
            .await?,
    )?;
    ensure!(payload["result_sets"][0]["rows"].as_array().unwrap().len() == 5);
    ensure!(payload["result_sets"][0]["truncated"] == json!(true));
    ensure!(payload["result_sets"][1]["rows_affected"] == json!(1));
    let count = tool_payload(&mcp.call("SELECT COUNT(*) FROM ten").await?)?;
    ensure!(count["result_sets"][0]["rows"] == json!([[11]]));
    mcp.close().await?;
    Ok(())
}

async fn test_temp_table_session(cfg: &Configs) -> Result<()> {
    let mut mcp = McpSession::start(&cfg.plain).await?;
    tool_payload(&mcp.call("CREATE TEMP TABLE tt (a INTEGER)").await?)?;
    tool_payload(&mcp.call("INSERT INTO tt VALUES (7)").await?)?;
    let payload = tool_payload(&mcp.call("SELECT * FROM tt").await?)?;
    mcp.close().await?;
    ensure!(payload["result_sets"][0]["rows"] == json!([[7]]));
    Ok(())
}

async fn test_read_only(cfg: &Configs, dir: &Path, db: &Path) -> Result<()> {
    let bytes_before = fs::read(db)?;
    let entries_before = dir_entries(dir)?;

    let mut mcp = McpSession::start(&cfg.read_only).await?;

    // Reads work.
    let select = tool_payload(&mcp.call("SELECT i FROM t").await?)?;
    ensure!(select["result_sets"][0]["rows"] == json!([[-42]]));

    // Writes fail as tool errors (enforced below the SQL layer).
    for sql in [
        "INSERT INTO t (i) VALUES (1)",
        "CREATE TABLE w (a INTEGER)",
        "DROP TABLE t",
    ] {
        let response = mcp.call(sql).await?;
        ensure!(
            tool_is_error(&response) && tool_text(&response).to_lowercase().contains("readonly"),
            "write should fail readonly: {sql} -> {}",
            tool_text(&response)
        );
    }

    // ATTACH cannot open a second (writable) file: blocked by the ATTACH
    // limit, with the literal-path handling (no SQLITE_OPEN_URI) as backup.
    let evil = dir.join("evil.db");
    let attach_plain = mcp
        .call(&format!("ATTACH DATABASE '{}' AS w", evil.display()))
        .await?;
    ensure!(tool_is_error(&attach_plain), "{}", tool_text(&attach_plain));
    let evil2 = dir.join("evil2.db");
    let attach_uri = mcp
        .call(&format!(
            "ATTACH DATABASE 'file:{}?mode=rwc' AS w",
            evil2.display()
        ))
        .await?;
    ensure!(tool_is_error(&attach_uri), "{}", tool_text(&attach_uri));

    // The session must still be healthy afterwards.
    let after = tool_payload(&mcp.call("SELECT 1").await?)?;
    ensure!(after["result_sets"][0]["rows"] == json!([[1]]));
    let stderr = mcp.close().await?;
    ensure!(
        stderr.contains("enforces read-only at the connection"),
        "{stderr}"
    );

    // Nothing changed on disk: no new files (no evil.db, no literal
    // "file:…?mode=rwc" file), database bytes identical.
    ensure!(!evil.exists(), "evil.db was created");
    let entries_after = dir_entries(dir)?;
    ensure!(
        entries_after == entries_before,
        "read-only session changed the directory: before={entries_before:?} after={entries_after:?}"
    );
    ensure!(
        fs::read(db)? == bytes_before,
        "db file changed in read-only mode"
    );

    // create = true + --read-only: contradiction caught even when read-only
    // arrives via the CLI flag (post-merge validation).
    let output = startup_with_config(&cfg.create, &["--read-only"], &[]).await?;
    ensure_refused(output, &["create = true", "read-only"])?;
    Ok(())
}

async fn test_memory_smoke(cfg: &Configs) -> Result<()> {
    let mut mcp = McpSession::start(&cfg.memory).await?;
    tool_payload(&mcp.call("CREATE TABLE m (v TEXT)").await?)?;
    tool_payload(&mcp.call("INSERT INTO m VALUES ('hi')").await?)?;
    let payload = tool_payload(&mcp.call("SELECT v FROM m").await?)?;
    mcp.close().await?;
    ensure!(payload["result_sets"][0]["rows"] == json!([["hi"]]));

    let output = startup_with_config(&cfg.memory_read_only, &[], &[]).await?;
    ensure_refused(output, &[":memory:", "read-only"])?;
    Ok(())
}

async fn test_config_rejections(cfg: &Configs) -> Result<()> {
    let output = startup_with_config(&cfg.net_key, &[], &[]).await?;
    ensure_refused(output, &["unknown config key \"host\""])?;
    let output = startup_with_config(&cfg.typo_key, &[], &[]).await?;
    ensure_refused(output, &[r#"did you mean "path""#])?;
    Ok(())
}

/// Independent proof that the file sql-mcp wrote is a real SQLite database
/// with correctly typed contents — verified by canonical SQLite (rusqlite).
/// This stays when the backend swaps to turso, becoming the file-format
/// compatibility check.
fn verify_file_with_canonical_sqlite(db: &Path) -> Result<()> {
    let conn = rusqlite::Connection::open_with_flags(
        db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let row = conn.query_row(
        "SELECT i, typeof(i), r, typeof(r), s, typeof(s), hex(b), typeof(b), typeof(z) \
         FROM t",
        [],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, f64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
            ))
        },
    )?;
    ensure!(
        row == (
            -42,
            "integer".into(),
            0.5,
            "real".into(),
            "héllo".into(),
            "text".into(),
            "DEADBEEF".into(),
            "blob".into(),
            "null".into()
        ),
        "canonical SQLite sees different contents/types: {row:?}"
    );
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM ten", [], |r| r.get(0))?;
    ensure!(count == 11, "expected 11 rows in ten, got {count}");
    Ok(())
}

fn dir_entries(dir: &Path) -> Result<Vec<String>> {
    let mut entries: Vec<String> = fs::read_dir(dir)?
        .map(|e| Ok(e?.file_name().to_string_lossy().into_owned()))
        .collect::<Result<_>>()?;
    entries.sort();
    Ok(entries)
}
