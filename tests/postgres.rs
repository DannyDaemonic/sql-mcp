//! PostgreSQL live suite — drives the real binary over MCP stdio against a
//! testcontainers `postgres:17` (Docker required, like tests/live.rs).
//!
//! What this proves beyond the shared semantics: text-only values (the
//! simple-query protocol has no type info on the wire), the
//! one-implicit-transaction-per-call rollback behavior, and the wide
//! read-only assertion — role attributes, ownership, ACLs across catalogs,
//! predefined roles, and the REVOKE TEMP requirement.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};

mod common;
use common::*;
use serde_json::json;
use tempfile::TempDir;
use testcontainers::core::IntoContainerPort;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, CopyTargetOptions, GenericImage, ImageExt};
use tokio::time::{Instant, sleep};

const ROOT_PASSWORD: &str = "rootpw";
const DATABASE: &str = "app";
const INTERNAL_PG_PORT: u16 = 5432;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_live_suite() -> Result<()> {
    let tmp = TempDir::new().context("create postgres-test tempdir")?;
    let certs = write_test_certs(tmp.path(), "postgres-server")?;
    let init_script = write_ssl_init_script(tmp.path())?;

    let (main_started, plain_started) = tokio::try_join!(
        async {
            start_postgres(&certs, &init_script)
                .await
                .context("start PostgreSQL container")
        },
        async {
            start_plain_postgres()
                .await
                .context("start plain (no-SSL) PostgreSQL container")
        },
    )?;
    let (container, port) = main_started;
    let (plain_container, plain_port) = plain_started;

    seed(port).await.context("seed PostgreSQL")?;
    let cfg = write_configs(tmp.path(), port, plain_port, &certs)?;

    test_description_and_banner(&cfg)
        .await
        .context("test 1: tool description and banner")?;
    test_text_values(&cfg)
        .await
        .context("test 2: text values and NULL disambiguation")?;
    test_multi_statement(&cfg)
        .await
        .context("test 3: multi-statement result sets")?;
    test_rows_affected(&cfg)
        .await
        .context("test 4: rows_affected shape")?;
    test_returning(&cfg)
        .await
        .context("test 5: INSERT ... RETURNING is a row set")?;
    test_midbatch_error_rolls_back(&cfg)
        .await
        .context("test 6: mid-batch error rolls back and stays clean")?;
    test_first_statement_error(&cfg)
        .await
        .context("test 7: first-statement error isolation")?;
    test_copy_fails_one_call_and_recovers(&cfg)
        .await
        .context("test 7b: COPY costs one call and recovers")?;
    test_explicit_transaction_abort_is_reported(&cfg)
        .await
        .context("test 7c: aborted explicit transaction is reported with the fix")?;
    test_caps(&cfg).await.context("test 8: output caps")?;
    test_session_state(&cfg)
        .await
        .context("test 9: session state persistence")?;
    test_read_only_matrix(&cfg)
        .await
        .context("test 10: read-only assertion matrix")?;
    test_kill_reconnect(&cfg, port)
        .await
        .context("test 11: terminated backend reconnect")?;
    test_tls(&cfg)
        .await
        .context("test 12: TLS verification matrix")?;

    drop(plain_container);
    drop(container);
    Ok(())
}

// ---- containers ----

/// The init script runs as the postgres user (the entrypoint drops root
/// before initdb), so it can give the server key the 0600 postgres-owned
/// permissions the server demands — the file testcontainers copies in is
/// root-owned, which PostgreSQL would refuse. SSL is enabled by appending to
/// postgresql.conf rather than via CMD flags: the entrypoint passes CMD flags
/// to the *temporary* init-phase server too, which would die on the
/// not-yet-installed key, while the appended config is only read by the final
/// server that starts after init completes.
fn write_ssl_init_script(dir: &Path) -> Result<PathBuf> {
    let path = dir.join("10-ssl.sh");
    fs::write(
        &path,
        "#!/bin/sh\nset -e\n\
         cp /certs/server-key.pem /var/lib/postgresql/server-key.pem\n\
         chmod 600 /var/lib/postgresql/server-key.pem\n\
         cat >> \"$PGDATA/postgresql.conf\" <<EOF\n\
         ssl = on\n\
         ssl_cert_file = '/certs/server-cert.pem'\n\
         ssl_key_file = '/var/lib/postgresql/server-key.pem'\n\
         EOF\n",
    )?;
    Ok(path)
}

async fn start_postgres(
    certs: &CertPaths,
    init_script: &Path,
) -> Result<(ContainerAsync<GenericImage>, u16)> {
    // ssl=on serves both plaintext and TLS on the same port (pg_hba `host`
    // rules accept both), so one container covers the functional tests and
    // the tls/tls_ca/wrong-CA matrix.
    let container = GenericImage::new("postgres", "17")
        .with_env_var("POSTGRES_PASSWORD", ROOT_PASSWORD)
        .with_env_var("POSTGRES_DB", DATABASE)
        .with_copy_to(
            CopyTargetOptions::new("/certs/server-cert.pem").with_mode(0o644),
            certs.server_cert.as_path(),
        )
        .with_copy_to(
            CopyTargetOptions::new("/certs/server-key.pem").with_mode(0o644),
            certs.server_key.as_path(),
        )
        .with_copy_to(
            CopyTargetOptions::new("/docker-entrypoint-initdb.d/10-ssl.sh").with_mode(0o755),
            init_script,
        )
        .with_startup_timeout(Duration::from_secs(120))
        .start()
        .await?;
    let port = container
        .get_host_port_ipv4(INTERNAL_PG_PORT.tcp())
        .await
        .context("resolve PostgreSQL mapped port")?;
    wait_for_db(port, DATABASE).await?;
    Ok((container, port))
}

async fn start_plain_postgres() -> Result<(ContainerAsync<GenericImage>, u16)> {
    let container = GenericImage::new("postgres", "17")
        .with_env_var("POSTGRES_PASSWORD", ROOT_PASSWORD)
        .with_startup_timeout(Duration::from_secs(120))
        .start()
        .await?;
    let port = container
        .get_host_port_ipv4(INTERNAL_PG_PORT.tcp())
        .await
        .context("resolve plain PostgreSQL mapped port")?;
    wait_for_db(port, "postgres").await?;
    Ok((container, port))
}

async fn root_client(port: u16, db: &str) -> Result<tokio_postgres::Client> {
    let (client, connection) = tokio_postgres::Config::new()
        .host("127.0.0.1")
        .port(port)
        .user("postgres")
        .password(ROOT_PASSWORD)
        .dbname(db)
        .connect(tokio_postgres::NoTls)
        .await
        .with_context(|| format!("connect postgres root to 127.0.0.1:{port}/{db}"))?;
    tokio::spawn(connection);
    Ok(client)
}

/// The image's init phase serves only a unix socket, so a successful TCP
/// connection already means the final server; poll until queries answer.
async fn wait_for_db(port: u16, db: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut last: Option<anyhow::Error> = None;
    while Instant::now() < deadline {
        match root_client(port, db).await {
            Ok(client) => match client.simple_query("SELECT 1").await {
                Ok(_) => return Ok(()),
                Err(err) => last = Some(err.into()),
            },
            Err(err) => last = Some(err),
        }
        sleep(Duration::from_millis(500)).await;
    }
    Err(last.unwrap_or_else(|| anyhow!("PostgreSQL did not become ready")))
}

async fn seed(port: u16) -> Result<()> {
    let client = root_client(port, DATABASE).await?;
    let statements = [
        "CREATE TABLE ten_rows (i int)",
        "INSERT INTO ten_rows SELECT generate_series(1, 10)",
        "CREATE TABLE rollback_t (i int)",
        "CREATE TABLE types_t (id serial PRIMARY KEY, v text)",
        "CREATE SEQUENCE app_seq",
        "CREATE TABLE owned_t (i int)",
        // Lock the database down so a clean role *can* qualify: the implicit
        // default ACL grants PUBLIC CONNECT and TEMP; re-grant CONNECT only.
        "REVOKE TEMPORARY, CREATE ON DATABASE app FROM PUBLIC",
        // No-op on PG15+, where PUBLIC already lost CREATE on `public`.
        "REVOKE CREATE ON SCHEMA public FROM PUBLIC",
        // The read-only matrix, one role per disqualification path:
        "CREATE ROLE ro LOGIN PASSWORD 'ropw'",
        "GRANT SELECT ON ALL TABLES IN SCHEMA public TO ro",
        "CREATE ROLE writer LOGIN PASSWORD 'wpw'",
        "GRANT SELECT, INSERT ON ten_rows TO writer",
        // A name that needs quoting (capital + embedded quote): the refusal's
        // fix SQL must come out paste-safe via quote_ident.
        "CREATE TABLE \"Evil\"\"T\" (i int)",
        "GRANT INSERT ON \"Evil\"\"T\" TO writer",
        "CREATE ROLE owner_u LOGIN PASSWORD 'opw'",
        "ALTER TABLE owned_t OWNER TO owner_u",
        "CREATE ROLE member_u LOGIN PASSWORD 'mpw'",
        "GRANT writer TO member_u",
        "CREATE ROLE pgwrite_u LOGIN PASSWORD 'pgw'",
        "GRANT pg_write_all_data TO pgwrite_u",
        "CREATE ROLE seq_u LOGIN PASSWORD 'spw'",
        "GRANT USAGE ON SEQUENCE app_seq TO seq_u",
        "CREATE ROLE temp_u LOGIN PASSWORD 'tpw'",
        // Privilege-mutation paths: a grantable privilege, an admin option
        // on an otherwise harmless role, and ALTER SYSTEM on a parameter.
        "CREATE ROLE grantopt_u LOGIN PASSWORD 'gopw'",
        "GRANT SELECT ON ten_rows TO grantopt_u WITH GRANT OPTION",
        "CREATE ROLE harmless",
        "GRANT SELECT ON ten_rows TO harmless",
        "CREATE ROLE admin_u LOGIN PASSWORD 'apw'",
        "GRANT harmless TO admin_u WITH ADMIN OPTION",
        "CREATE ROLE altersys_u LOGIN PASSWORD 'aspw'",
        "GRANT ALTER SYSTEM ON PARAMETER work_mem TO altersys_u",
        // Precision check: an inert membership (no INHERIT, no SET ROLE) in a
        // writing role, plus session-local GRANT SET — both must be accepted.
        "CREATE ROLE setfalse_u LOGIN PASSWORD 'sfpw'",
        "GRANT writer TO setfalse_u WITH SET FALSE, INHERIT FALSE",
        "GRANT SET ON PARAMETER log_statement TO setfalse_u",
        // Ownership of a non-relation object class (a type), with the USAGE
        // grant on it being the harmless side `ro` is allowed to hold. The
        // domain over an array pins the auto-array-type filter: it has
        // typcategory 'A' like the noise types, but is a real owned object.
        "CREATE TYPE mood AS ENUM ('happy', 'sad')",
        "GRANT USAGE ON TYPE mood TO ro",
        "CREATE DOMAIN arrdom AS int[]",
        "CREATE ROLE typeowner_u LOGIN PASSWORD 'topw'",
        "ALTER TYPE mood OWNER TO typeowner_u",
        "ALTER DOMAIN arrdom OWNER TO typeowner_u",
        // FDW/foreign-server USAGE: catalog-mutation capability without any
        // table grant at all.
        "CREATE FOREIGN DATA WRAPPER dummy_fdw",
        "CREATE SERVER dummy_srv FOREIGN DATA WRAPPER dummy_fdw",
        "CREATE ROLE fdw_u LOGIN PASSWORD 'fpw'",
        "GRANT USAGE ON FOREIGN DATA WRAPPER dummy_fdw TO fdw_u",
        "GRANT USAGE ON FOREIGN SERVER dummy_srv TO fdw_u",
        // Attribute reachability: CREATEDB is exercisable only via SET ROLE,
        // so the inherit-only member must pass and the set-only member must
        // be refused.
        "CREATE ROLE attrholder CREATEDB",
        "CREATE ROLE inheritonly_u LOGIN PASSWORD 'inpw'",
        "GRANT attrholder TO inheritonly_u WITH SET FALSE, INHERIT TRUE",
        "CREATE ROLE setonly_u LOGIN PASSWORD 'sopw'",
        "GRANT attrholder TO setonly_u WITH SET TRUE, INHERIT FALSE",
        // tempdb keeps its implicit default ACL (PUBLIC TEMP) on purpose.
        "CREATE DATABASE tempdb",
    ];
    for statement in statements {
        client
            .simple_query(statement)
            .await
            .with_context(|| format!("seed statement failed: {statement}"))?;
    }
    Ok(())
}

// ---- configs ----

struct Configs {
    root: PathBuf,
    max_rows: PathBuf,
    max_response: PathBuf,
    ro: PathBuf,
    writer: PathBuf,
    owner: PathBuf,
    member: PathBuf,
    pgwrite: PathBuf,
    seq: PathBuf,
    temp: PathBuf,
    grantopt: PathBuf,
    admin: PathBuf,
    altersys: PathBuf,
    setfalse: PathBuf,
    typeowner: PathBuf,
    fdw: PathBuf,
    inheritonly: PathBuf,
    setonly: PathBuf,
    tls: PathBuf,
    tls_insecure: PathBuf,
    tls_ca: PathBuf,
    tls_wrong_ca: PathBuf,
    tls_against_plain: PathBuf,
}

fn pg_cfg(port: u16, user: &str, password: &str, db: &str, extra: &str) -> String {
    format!(
        "driver = \"postgres\"\nhost = \"127.0.0.1\"\nport = {port}\nuser = \"{user}\"\n\
         password = \"{password}\"\ndatabase = \"{db}\"\n{extra}"
    )
}

fn write_configs(dir: &Path, port: u16, plain_port: u16, certs: &CertPaths) -> Result<Configs> {
    let root = |extra: &str| pg_cfg(port, "postgres", ROOT_PASSWORD, DATABASE, extra);
    Ok(Configs {
        root: write_cfg(dir, "pg-root.toml", &root(""), 0o600)?,
        max_rows: write_cfg(dir, "pg-max-rows.toml", &root("max_rows = 5\n"), 0o600)?,
        max_response: write_cfg(
            dir,
            "pg-max-response.toml",
            &root("max_response_bytes = 2000\n"),
            0o600,
        )?,
        ro: write_cfg(
            dir,
            "pg-ro.toml",
            &pg_cfg(port, "ro", "ropw", DATABASE, ""),
            0o600,
        )?,
        writer: write_cfg(
            dir,
            "pg-writer.toml",
            &pg_cfg(port, "writer", "wpw", DATABASE, ""),
            0o600,
        )?,
        owner: write_cfg(
            dir,
            "pg-owner.toml",
            &pg_cfg(port, "owner_u", "opw", DATABASE, ""),
            0o600,
        )?,
        member: write_cfg(
            dir,
            "pg-member.toml",
            &pg_cfg(port, "member_u", "mpw", DATABASE, ""),
            0o600,
        )?,
        pgwrite: write_cfg(
            dir,
            "pg-pgwrite.toml",
            &pg_cfg(port, "pgwrite_u", "pgw", DATABASE, ""),
            0o600,
        )?,
        seq: write_cfg(
            dir,
            "pg-seq.toml",
            &pg_cfg(port, "seq_u", "spw", DATABASE, ""),
            0o600,
        )?,
        temp: write_cfg(
            dir,
            "pg-temp.toml",
            &pg_cfg(port, "temp_u", "tpw", "tempdb", ""),
            0o600,
        )?,
        grantopt: write_cfg(
            dir,
            "pg-grantopt.toml",
            &pg_cfg(port, "grantopt_u", "gopw", DATABASE, ""),
            0o600,
        )?,
        admin: write_cfg(
            dir,
            "pg-admin.toml",
            &pg_cfg(port, "admin_u", "apw", DATABASE, ""),
            0o600,
        )?,
        altersys: write_cfg(
            dir,
            "pg-altersys.toml",
            &pg_cfg(port, "altersys_u", "aspw", DATABASE, ""),
            0o600,
        )?,
        setfalse: write_cfg(
            dir,
            "pg-setfalse.toml",
            &pg_cfg(port, "setfalse_u", "sfpw", DATABASE, ""),
            0o600,
        )?,
        typeowner: write_cfg(
            dir,
            "pg-typeowner.toml",
            &pg_cfg(port, "typeowner_u", "topw", DATABASE, ""),
            0o600,
        )?,
        fdw: write_cfg(
            dir,
            "pg-fdw.toml",
            &pg_cfg(port, "fdw_u", "fpw", DATABASE, ""),
            0o600,
        )?,
        inheritonly: write_cfg(
            dir,
            "pg-inheritonly.toml",
            &pg_cfg(port, "inheritonly_u", "inpw", DATABASE, ""),
            0o600,
        )?,
        setonly: write_cfg(
            dir,
            "pg-setonly.toml",
            &pg_cfg(port, "setonly_u", "sopw", DATABASE, ""),
            0o600,
        )?,
        tls: write_cfg(dir, "pg-tls.toml", &root("tls = true\n"), 0o600)?,
        tls_insecure: write_cfg(
            dir,
            "pg-tls-insecure.toml",
            &root("tls = true\ntls_insecure = true\n"),
            0o600,
        )?,
        tls_ca: write_cfg(
            dir,
            "pg-tls-ca.toml",
            &format!("{}tls = true\ntls_ca = {:?}\n", root(""), certs.ca),
            0o600,
        )?,
        tls_wrong_ca: write_cfg(
            dir,
            "pg-tls-wrong-ca.toml",
            &format!("{}tls = true\ntls_ca = {:?}\n", root(""), certs.wrong_ca),
            0o600,
        )?,
        tls_against_plain: write_cfg(
            dir,
            "pg-tls-against-plain.toml",
            &pg_cfg(
                plain_port,
                "postgres",
                ROOT_PASSWORD,
                "postgres",
                "tls = true\n",
            ),
            0o600,
        )?,
    })
}

// ---- tests ----

async fn test_description_and_banner(cfg: &Configs) -> Result<()> {
    let mut mcp = McpSession::start(&cfg.root).await?;
    let response = mcp.tools_list().await?;
    let stderr = mcp.close().await?;
    let description = response["result"]["tools"][0]["description"]
        .as_str()
        .context("tool description")?;
    for needle in [
        "configured postgres database",
        "1000 rows per result set",
        "returned as text",
        "RETURNING",
        "single transaction",
        "information_schema",
        "pg_catalog",
    ] {
        ensure!(
            description.contains(needle),
            "description missing {needle:?}: {description}"
        );
    }
    ensure!(stderr.contains("serving sql_exec for postgres"), "{stderr}");
    Ok(())
}

async fn test_text_values(cfg: &Configs) -> Result<()> {
    let mut mcp = McpSession::start(&cfg.root).await?;
    let payload = tool_payload(
        &mcp.call(
            "SELECT NULL AS a, 'null' AS b, 1 AS c, 'héllo' AS d, \
             1.50::numeric AS p, decode('deadbeef', 'hex') AS bin",
        )
        .await?,
    )?;
    mcp.close().await?;
    ensure_eq_json(
        &payload["result_sets"][0]["columns"],
        &json!(["a", "b", "c", "d", "p", "bin"]),
        "columns",
    )?;
    // Everything is text — including the number — except real SQL NULL,
    // which stays JSON null (so it can never be confused with 'null').
    // numeric keeps its exact scale; bytea uses PostgreSQL's \x hex form.
    ensure_eq_json(
        &payload["result_sets"][0]["rows"],
        &json!([[null, "null", "1", "héllo", "1.50", "\\xdeadbeef"]]),
        "text values",
    )
}

async fn test_multi_statement(cfg: &Configs) -> Result<()> {
    let mut mcp = McpSession::start(&cfg.root).await?;
    let payload = tool_payload(&mcp.call("SELECT 1 AS a; SELECT 2 AS b, 3 AS c").await?)?;
    mcp.close().await?;
    let sets = payload["result_sets"].as_array().context("result_sets")?;
    ensure!(sets.len() == 2, "expected 2 result sets: {payload}");
    ensure_eq_json(&sets[0]["rows"], &json!([["1"]]), "first set")?;
    ensure_eq_json(&sets[1]["rows"], &json!([["2", "3"]]), "second set")?;
    ensure!(
        payload.get("error").is_none(),
        "unexpected error: {payload}"
    );
    Ok(())
}

async fn test_rows_affected(cfg: &Configs) -> Result<()> {
    let mut mcp = McpSession::start(&cfg.root).await?;

    let ddl = tool_payload(&mcp.call("CREATE TABLE t2 (i int)").await?)?;
    ensure_eq_json(
        &ddl["result_sets"][0]["rows_affected"],
        &json!(0),
        "DDL rows_affected",
    )?;
    ensure!(
        ddl["result_sets"][0].get("last_insert_id").is_none(),
        "postgres must never set last_insert_id: {ddl}"
    );

    let insert = tool_payload(&mcp.call("INSERT INTO t2 VALUES (1), (2)").await?)?;
    ensure_eq_json(
        &insert["result_sets"][0]["rows_affected"],
        &json!(2),
        "INSERT rows_affected",
    )?;
    ensure!(
        insert["result_sets"][0].get("last_insert_id").is_none(),
        "postgres must never set last_insert_id: {insert}"
    );

    let update = tool_payload(&mcp.call("UPDATE t2 SET i = i + 1").await?)?;
    ensure_eq_json(
        &update["result_sets"][0]["rows_affected"],
        &json!(2),
        "UPDATE rows_affected",
    )?;
    mcp.close().await?;
    Ok(())
}

async fn test_returning(cfg: &Configs) -> Result<()> {
    let mut mcp = McpSession::start(&cfg.root).await?;
    let payload = tool_payload(
        &mcp.call("INSERT INTO types_t (v) VALUES ('x') RETURNING id")
            .await?,
    )?;
    mcp.close().await?;
    let set = &payload["result_sets"][0];
    ensure_eq_json(&set["columns"], &json!(["id"]), "RETURNING columns")?;
    ensure_eq_json(&set["rows"], &json!([["1"]]), "RETURNING rows")?;
    // A row-returning statement reports rows, not a write outcome.
    ensure!(
        set.get("rows_affected").is_none(),
        "RETURNING must not set rows_affected: {payload}"
    );
    Ok(())
}

async fn test_midbatch_error_rolls_back(cfg: &Configs) -> Result<()> {
    let mut mcp = McpSession::start(&cfg.root).await?;
    let response = mcp
        .call("INSERT INTO rollback_t VALUES (1); SELECT * FROM missing_t")
        .await?;
    ensure!(
        !tool_is_error(&response),
        "mid-batch error must be in-band: {}",
        tool_text(&response)
    );
    let payload = tool_payload(&response)?;
    ensure_eq_json(
        &payload["result_sets"][0]["rows_affected"],
        &json!(1),
        "INSERT before the failure",
    )?;
    let error = payload["error"].as_str().context("in-band error")?;
    ensure!(
        error.contains("missing_t"),
        "error names the table: {error}"
    );
    ensure!(
        error.contains("rolled back"),
        "error carries the rollback note: {error}"
    );

    // The rollback is real: the INSERT's effect is gone…
    let count = tool_payload(&mcp.call("SELECT count(*) FROM rollback_t").await?)?;
    ensure_eq_json(
        &count["result_sets"][0]["rows"],
        &json!([["0"]]),
        "rolled back",
    )?;
    // …and the connection is clean (the poison analog).
    let clean = tool_payload(&mcp.call("SELECT 6 * 7 AS answer").await?)?;
    ensure_eq_json(
        &clean["result_sets"][0]["rows"],
        &json!([["42"]]),
        "clean follow-up",
    )?;
    mcp.close().await?;
    Ok(())
}

/// An explicit BEGIN opts out of the per-call implicit transaction: a failed
/// statement then leaves the session *aborted* across calls. The driver must
/// not roll back on the caller's behalf (that would destroy ROLLBACK TO
/// <savepoint> recovery), but every error along the way must say exactly how
/// to recover.
async fn test_explicit_transaction_abort_is_reported(cfg: &Configs) -> Result<()> {
    let mut mcp = McpSession::start(&cfg.root).await?;

    // Shape 1: BEGIN inside the failing batch — the in-band error carries
    // the aborted-transaction guidance.
    let response = mcp
        .call("BEGIN; INSERT INTO rollback_t VALUES (1); SELECT * FROM missing_t")
        .await?;
    ensure!(!tool_is_error(&response), "{}", tool_text(&response));
    let payload = tool_payload(&response)?;
    let error = payload["error"].as_str().context("in-band error")?;
    ensure!(error.contains("must run ROLLBACK"), "{error}");

    // The session is now aborted: ordinary statements fail, and the error
    // names the way out…
    let response = mcp.call("SELECT 1").await?;
    ensure!(
        tool_is_error(&response),
        "expected aborted-transaction error"
    );
    let text = tool_text(&response);
    ensure!(text.contains("current transaction is aborted"), "{text}");
    ensure!(text.contains("run ROLLBACK"), "{text}");

    // …and taking it recovers the session (shape 2: ROLLBACK from a later
    // call, proving the abort spanned calls).
    tool_payload(&mcp.call("ROLLBACK").await?)?;
    let clean = tool_payload(&mcp.call("SELECT 6 * 7 AS answer").await?)?;
    ensure_eq_json(
        &clean["result_sets"][0]["rows"],
        &json!([["42"]]),
        "clean after ROLLBACK",
    )?;
    // And the INSERT from the aborted transaction never committed.
    let count = tool_payload(&mcp.call("SELECT count(*) FROM rollback_t").await?)?;
    ensure_eq_json(
        &count["result_sets"][0]["rows"],
        &json!([["0"]]),
        "aborted work discarded",
    )?;
    mcp.close().await?;
    Ok(())
}

/// COPY FROM STDIN/TO STDOUT can't work over the simple-query transport;
/// tokio-postgres rejects the copy response and the connection dies. The
/// driver must announce that in the *same* call (dropping the dead client),
/// so recovery costs exactly one call.
async fn test_copy_fails_one_call_and_recovers(cfg: &Configs) -> Result<()> {
    let mut mcp = McpSession::start(&cfg.root).await?;
    for sql in ["COPY ten_rows FROM STDIN", "COPY ten_rows TO STDOUT"] {
        let response = mcp.call(sql).await?;
        ensure!(tool_is_error(&response), "{sql}: expected a tool error");
        let text = tool_text(&response);
        ensure!(
            text.contains("COPY FROM STDIN / TO STDOUT is not supported"),
            "{sql}: error must explain the COPY limitation: {text}"
        );
        // The very next call works — the dead client was discarded in the
        // failing call, not left to burn a second one.
        let payload = tool_payload(&mcp.call("SELECT 6 * 7 AS answer").await?)?;
        ensure_eq_json(
            &payload["result_sets"][0]["rows"],
            &json!([["42"]]),
            "recovery after COPY",
        )?;
    }
    mcp.close().await?;
    Ok(())
}

async fn test_first_statement_error(cfg: &Configs) -> Result<()> {
    let mut mcp = McpSession::start(&cfg.root).await?;

    let response = mcp.call("SELECT * FROM missing_t").await?;
    ensure!(tool_is_error(&response), "expected tool error");
    ensure!(tool_text(&response).contains("missing_t"));

    // First statement of a batch failing also fails the whole call: nothing
    // ran, nothing to report in-band.
    let response = mcp.call("SELECT * FROM missing_t; SELECT 1").await?;
    ensure!(tool_is_error(&response), "expected tool error for batch");

    let clean = tool_payload(&mcp.call("SELECT 1 AS one").await?)?;
    ensure_eq_json(
        &clean["result_sets"][0]["rows"],
        &json!([["1"]]),
        "clean follow-up",
    )?;
    mcp.close().await?;
    Ok(())
}

async fn test_caps(cfg: &Configs) -> Result<()> {
    // max_rows: 5 of 10, truncated, later statements still run.
    let mut mcp = McpSession::start(&cfg.max_rows).await?;
    let payload = tool_payload(
        &mcp.call("SELECT i FROM ten_rows ORDER BY i; SELECT count(*) FROM ten_rows")
            .await?,
    )?;
    let first = &payload["result_sets"][0];
    ensure!(
        first["rows"].as_array().map(Vec::len) == Some(5),
        "expected 5 rows: {payload}"
    );
    ensure_eq_json(&first["truncated"], &json!(true), "truncated flag")?;
    ensure_eq_json(
        &payload["result_sets"][1]["rows"],
        &json!([["10"]]),
        "statement after the truncated one still ran",
    )?;
    let clean = tool_payload(&mcp.call("SELECT 1 AS one").await?)?;
    ensure_eq_json(
        &clean["result_sets"][0]["rows"],
        &json!([["1"]]),
        "clean follow-up",
    )?;
    mcp.close().await?;

    // max_cell_bytes (default 16 KiB in the root config): one huge value is
    // cut with the in-band marker.
    let mut mcp = McpSession::start(&cfg.root).await?;
    let payload = tool_payload(&mcp.call("SELECT repeat('a', 100000) AS big").await?)?;
    let value = payload["result_sets"][0]["rows"][0][0]
        .as_str()
        .context("cell value")?;
    ensure!(
        value.ends_with("…[truncated; 100000 bytes total]"),
        "missing cell truncation marker: …{}",
        &value[value.len().saturating_sub(60)..]
    );
    ensure!(
        value.len() < 20_000,
        "cell not actually capped: {}",
        value.len()
    );
    mcp.close().await?;

    // max_response_bytes: the global budget truncates the set.
    let mut mcp = McpSession::start(&cfg.max_response).await?;
    let payload = tool_payload(
        &mcp.call("SELECT i, repeat('x', 500) FROM ten_rows ORDER BY i")
            .await?,
    )?;
    let set = &payload["result_sets"][0];
    let rows = set["rows"].as_array().context("rows")?;
    ensure!(
        !rows.is_empty() && rows.len() < 10,
        "expected a partial set under the response cap: {} rows",
        rows.len()
    );
    ensure_eq_json(&set["truncated"], &json!(true), "truncated flag")?;
    let clean = tool_payload(&mcp.call("SELECT 1 AS one").await?)?;
    ensure_eq_json(
        &clean["result_sets"][0]["rows"],
        &json!([["1"]]),
        "clean follow-up",
    )?;
    mcp.close().await?;
    Ok(())
}

async fn test_session_state(cfg: &Configs) -> Result<()> {
    let mut mcp = McpSession::start(&cfg.root).await?;
    // One persistent session: temp tables and SET survive across calls.
    // (TEMP was revoked from PUBLIC, but root is the superuser.)
    tool_payload(&mcp.call("CREATE TEMP TABLE session_t (i int)").await?)?;
    tool_payload(&mcp.call("INSERT INTO session_t VALUES (7)").await?)?;
    let payload = tool_payload(&mcp.call("SELECT i FROM session_t").await?)?;
    ensure_eq_json(
        &payload["result_sets"][0]["rows"],
        &json!([["7"]]),
        "temp table",
    )?;

    tool_payload(&mcp.call("SET application_name = 'sqlmcp_test'").await?)?;
    let payload = tool_payload(&mcp.call("SHOW application_name").await?)?;
    ensure_eq_json(
        &payload["result_sets"][0]["rows"],
        &json!([["sqlmcp_test"]]),
        "SET persists",
    )?;
    mcp.close().await?;
    Ok(())
}

async fn test_read_only_matrix(cfg: &Configs) -> Result<()> {
    // (a) The locked-down role passes, the connection works, writes are
    // refused by the server itself.
    let mut mcp = McpSession::start_with(&cfg.ro, &["--read-only"], &[]).await?;
    let payload = tool_payload(&mcp.call("SELECT count(*) FROM ten_rows").await?)?;
    ensure_eq_json(
        &payload["result_sets"][0]["rows"],
        &json!([["10"]]),
        "ro can read",
    )?;
    let response = mcp.call("INSERT INTO ten_rows VALUES (99)").await?;
    ensure!(tool_is_error(&response), "ro write must fail");
    ensure!(
        tool_text(&response).contains("permission denied"),
        "{}",
        tool_text(&response)
    );
    let stderr = mcp.close().await?;
    ensure!(
        stderr.contains("verified incapable of mutation"),
        "{stderr}"
    );

    // Precision counterparts (fail-closed must not become
    // reject-everything): a membership granted WITH SET FALSE, INHERIT FALSE
    // confers nothing usable and GRANT SET ON PARAMETER is session-local;
    // an inherit-only membership in a CREATEDB role never confers the
    // attribute (attributes require SET ROLE). Both accounts must pass —
    // `ro` itself additionally holds the harmless USAGE on a type.
    for (config, label) in [
        (&cfg.setfalse, "inert membership"),
        (
            &cfg.inheritonly,
            "inherit-only membership in a CREATEDB role",
        ),
    ] {
        let mut mcp = McpSession::start_with(config, &["--read-only"], &[]).await?;
        let payload = tool_payload(&mcp.call("SELECT 1 AS one").await?)?;
        ensure_eq_json(&payload["result_sets"][0]["rows"], &json!([["1"]]), label)?;
        let stderr = mcp.close().await?;
        ensure!(
            stderr.contains("verified incapable of mutation"),
            "{label}: {stderr}"
        );
    }

    // Each disqualification path refuses startup, names the finding, and
    // shows the fixing SQL.
    let refusals: [(&Path, &[&str]); 13] = [
        (
            &cfg.writer,
            &[
                "INSERT on public.ten_rows",
                "REVOKE INSERT",
                // quote_ident makes the fix paste-safe for hostile names.
                "REVOKE INSERT ON public.\"Evil\"\"T\" FROM writer;",
            ],
        ),
        (
            &cfg.owner,
            &["owned_t", "owned by reachable role owner_u", "OWNER TO"],
        ),
        // Reached through membership, not a direct grant.
        (
            &cfg.member,
            &["INSERT on public.ten_rows granted to writer"],
        ),
        (
            &cfg.pgwrite,
            &[
                "predefined role pg_write_all_data",
                "REVOKE pg_write_all_data",
            ],
        ),
        (
            &cfg.seq,
            &[
                "USAGE on public.app_seq",
                "nextval",
                "REVOKE USAGE ON SEQUENCE",
            ],
        ),
        (&cfg.temp, &["REVOKE TEMP ON DATABASE tempdb FROM PUBLIC"]),
        // A harmless privilege held WITH GRANT OPTION is privilege mutation…
        (
            &cfg.grantopt,
            &[
                "SELECT WITH GRANT OPTION on public.ten_rows",
                "REVOKE GRANT OPTION FOR SELECT",
            ],
        ),
        // …as is a harmless membership held WITH ADMIN OPTION…
        (
            &cfg.admin,
            &[
                "membership in harmless WITH ADMIN OPTION",
                "REVOKE ADMIN OPTION FOR harmless FROM admin_u",
            ],
        ),
        // …and ALTER SYSTEM writes persistent server configuration.
        (
            &cfg.altersys,
            &[
                "ALTER SYSTEM on parameter work_mem",
                "postgresql.auto.conf",
                "REVOKE ALTER SYSTEM ON PARAMETER work_mem",
            ],
        ),
        // Ownership of a non-relation object class (here a type) is still
        // schema-mutation power (ALTER TYPE … ADD VALUE, DROP TYPE) — and a
        // domain over an array must not hide behind the array-type filter.
        (
            &cfg.typeowner,
            &[
                "type public.mood is owned by reachable role typeowner_u",
                "ALTER TYPE public.mood OWNER TO",
                "domain public.arrdom is owned by reachable role typeowner_u",
                "ALTER DOMAIN public.arrdom OWNER TO",
            ],
        ),
        // FDW/foreign-server USAGE creates catalog state with no table grant
        // in sight.
        (
            &cfg.fdw,
            &[
                "USAGE on foreign data wrapper dummy_fdw",
                "CREATE SERVER",
                "USAGE on foreign server dummy_srv",
                "CREATE USER MAPPING",
            ],
        ),
        // A SET ROLE-able membership in an attribute-bearing role counts
        // (the inherit-only counterpart above passes).
        (
            &cfg.setonly,
            &["attrholder has the CREATEDB attribute", "NOCREATEDB"],
        ),
        (&cfg.root, &["SUPERUSER"]),
    ];
    for (config, needles) in refusals {
        let output = startup_with_config(config, &["--read-only"], &[]).await?;
        let mut expected = vec!["not read-only"];
        expected.extend_from_slice(needles);
        ensure_refused(output, &expected)
            .with_context(|| format!("read-only refusal for {}", config.display()))?;
    }
    Ok(())
}

async fn test_kill_reconnect(cfg: &Configs, port: u16) -> Result<()> {
    let mut mcp = McpSession::start(&cfg.root).await?;
    let payload = tool_payload(&mcp.call("SELECT pg_backend_pid()").await?)?;
    let backend_pid = payload["result_sets"][0]["rows"][0][0]
        .as_str()
        .context("backend pid")?
        .to_string();

    let admin = root_client(port, DATABASE).await?;
    admin
        .simple_query(&format!("SELECT pg_terminate_backend({backend_pid})"))
        .await
        .context("terminate backend")?;

    // The next call must *announce* the lost session (never silently retry
    // or reconnect); the call after that runs on a fresh connection.
    let mut informed = false;
    for _ in 0..20 {
        let response = mcp.call("SELECT 1").await?;
        if tool_is_error(&response) {
            let text = tool_text(&response);
            ensure!(
                text.contains("re-established on the next call"),
                "unexpected error after kill: {text}"
            );
            informed = true;
            break;
        }
        // The server may not have delivered the termination yet.
        sleep(Duration::from_millis(100)).await;
    }
    ensure!(informed, "connection loss was never surfaced");

    let payload = tool_payload(&mcp.call("SELECT 6 * 7 AS answer").await?)?;
    ensure_eq_json(
        &payload["result_sets"][0]["rows"],
        &json!([["42"]]),
        "fresh connection works",
    )?;
    mcp.close().await?;
    Ok(())
}

async fn test_tls(cfg: &Configs) -> Result<()> {
    // tls = true verifies against the built-in roots; the container's cert is
    // signed by the throwaway test CA, so startup must refuse.
    let output = startup_with_config(&cfg.tls, &[], &[]).await?;
    ensure_refused(output, &["failed to connect"]).context("unknown CA refused")?;

    // The wrong CA also fails verification…
    let output = startup_with_config(&cfg.tls_wrong_ca, &[], &[]).await?;
    ensure_refused(output, &["failed to connect"]).context("wrong CA refused")?;

    // …the right CA connects, with TLS actually on the wire…
    let mut mcp = McpSession::start(&cfg.tls_ca).await?;
    let payload = tool_payload(
        &mcp.call("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
            .await?,
    )?;
    ensure_eq_json(
        &payload["result_sets"][0]["rows"],
        &json!([["t"]]),
        "tls_ca on the wire",
    )?;
    mcp.close().await?;

    // …tls_insecure connects despite the unknown CA, still over TLS…
    let mut mcp = McpSession::start(&cfg.tls_insecure).await?;
    let payload = tool_payload(
        &mcp.call("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
            .await?,
    )?;
    ensure_eq_json(
        &payload["result_sets"][0]["rows"],
        &json!([["t"]]),
        "tls_insecure on the wire",
    )?;
    mcp.close().await?;

    // …and tls = true against a server without SSL fails loudly instead of
    // silently downgrading.
    let output = startup_with_config(&cfg.tls_against_plain, &[], &[]).await?;
    ensure_refused(output, &["failed to connect", "TLS"]).context("no-SSL server refused")?;
    Ok(())
}
