use std::collections::HashMap;
use std::future::Future;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};

mod common;
use common::*;
use mysql_async::prelude::*;
use mysql_async::{Conn, Opts, OptsBuilder};
use serde_json::json;
use tempfile::TempDir;
use testcontainers::core::IntoContainerPort;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, CopyTargetOptions, GenericImage, ImageExt};
use tokio::time::{Instant, sleep};

const ROOT_PASSWORD: &str = "rootpw";
const DATABASE: &str = "app";
const INTERNAL_MYSQL_PORT: u16 = 3306;
const CONTAINER_START_ATTEMPTS: usize = 5;
const BIG_DRAIN_TIMEOUT: Duration = Duration::from_secs(180);
const BIG_DRAIN_REASONABLE_TIME: Duration = Duration::from_secs(120);
const BIG_DRAIN_MAX_RSS_KB: u64 = 512 * 1024;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn testing_md_live_suite() -> Result<()> {
    let tmp = TempDir::new().context("create integration-test tempdir")?;
    let certs = write_test_certs(tmp.path(), "mysql-server")?;

    let (mysql_started, maria_started) = tokio::try_join!(
        async { start_mysql(&certs).await.context("start MySQL container") },
        async { start_mariadb().await.context("start MariaDB container") },
    )?;
    let (mysql_container, mysql) = mysql_started;
    let (maria_container, maria) = maria_started;

    tokio::try_join!(
        async {
            seed_database(&mysql, DbKind::Mysql)
                .await
                .context("seed MySQL")
        },
        async {
            seed_database(&maria, DbKind::Mariadb)
                .await
                .context("seed MariaDB")
        },
    )?;

    let cfg = write_configs(tmp.path(), mysql.port, maria.port, &certs)?;

    test_1_tool_description(&cfg.mysql_root, "mysql")
        .await
        .context("test 1: MySQL tool description")?;
    test_2_to_5_type_mapping(&cfg.mysql_root)
        .await
        .context("tests 2-5: MySQL type mapping")?;
    test_6_dml_shape_and_last_insert_id(&cfg.mysql_root)
        .await
        .context("test 6: DML result shape")?;
    test_7_multi_statement_success(&cfg.mysql_root)
        .await
        .context("test 7: multi-statement success")?;
    test_8_poison_check(&cfg.mysql_root)
        .await
        .context("critical test 8: MySQL poison check")?;
    test_9_first_statement_error_isolation(&cfg.mysql_root)
        .await
        .context("test 9: first-statement SQL error isolation")?;
    test_10_stored_procedure_multi_sets(&cfg.mysql_root)
        .await
        .context("test 10: stored procedure result sets")?;
    test_11_max_rows(&cfg.mysql_max_rows)
        .await
        .context("test 11: max_rows and follow-up")?;
    test_12_big_drain(&cfg.mysql_root)
        .await
        .context("test 12: big drain and follow-up")?;
    test_13_cell_caps(&cfg.mysql_root)
        .await
        .context("test 13: max_cell_bytes and UTF-8 boundary")?;
    test_14_response_cap(&cfg.mysql_max_response)
        .await
        .context("test 14: max_response_bytes shared budget")?;
    test_15_caps_zero(&cfg.mysql_caps_zero)
        .await
        .context("test 15: caps disabled")?;
    test_16_read_only_ro(&cfg.mysql_ro, "mysql")
        .await
        .context("test 16: read-only ro user")?;
    test_17_writer_refused(&cfg.mysql_writer)
        .await
        .context("test 17: writer refused in read-only mode")?;
    test_18_roleuser_refused(&cfg.mysql_roleuser)
        .await
        .context("test 18: roleuser refused")?;
    test_19_granter_refused(&cfg.mysql_granter)
        .await
        .context("test 19: grant-option user refused")?;
    test_20_mode_env_and_writer_normal(&cfg.mysql_writer)
        .await
        .context("test 20: SQL_MCP_MODE and writer normal mode")?;
    test_21_session_variable(&cfg.mysql_root)
        .await
        .context("test 21: session variable persistence")?;
    test_22_temp_table(&cfg.mysql_root)
        .await
        .context("test 22: temp table persistence")?;
    test_23_kill_reconnect(&cfg.mysql_root, &mysql)
        .await
        .context("test 23: killed connection reconnect")?;
    test_24_restart_reconnect(&cfg.mysql_root, &mysql_container, &mysql)
        .await
        .context("test 24: container restart reconnect")?;
    test_25_config_mode(&cfg.mysql_root)
        .await
        .context("test 25: config mode security")?;
    test_26_tls_config_validation(&cfg)
        .await
        .context("test 26: TLS config validation")?;
    test_27_unknown_config_and_cli(&cfg)
        .await
        .context("test 27: unknown config/CLI validation")?;
    test_28_tls_requires_verification(&cfg.mysql_tls)
        .await
        .context("test 28: tls=true refuses unknown CA")?;
    test_29_tls_insecure(&cfg.mysql_tls_insecure)
        .await
        .context("test 29: tls_insecure connects")?;
    test_30_tls_ca_and_wrong_ca(&cfg.mysql_tls_ca, &cfg.mysql_tls_wrong_ca)
        .await
        .context("test 30: tls_ca full verification and wrong-CA countercheck")?;
    test_31_mariadb_smoke(&cfg.maria_root, &cfg.maria_ro)
        .await
        .context("test 31: MariaDB smoke")?;

    drop(maria_container);
    drop(mysql_container);
    Ok(())
}

#[derive(Clone, Copy)]
enum DbKind {
    Mysql,
    Mariadb,
}

struct DbInstance {
    port: u16,
}

struct ConfigPaths {
    mysql_root: PathBuf,
    mysql_max_rows: PathBuf,
    mysql_max_response: PathBuf,
    mysql_caps_zero: PathBuf,
    mysql_ro: PathBuf,
    mysql_writer: PathBuf,
    mysql_roleuser: PathBuf,
    mysql_granter: PathBuf,
    mysql_tls: PathBuf,
    mysql_tls_insecure: PathBuf,
    mysql_tls_ca: PathBuf,
    mysql_tls_wrong_ca: PathBuf,
    maria_root: PathBuf,
    maria_ro: PathBuf,
    invalid_tls_insecure_without_tls: PathBuf,
    invalid_tls_ca_without_tls: PathBuf,
    invalid_tls_ca_and_insecure: PathBuf,
    invalid_unknown_key: PathBuf,
    invalid_missing_driver: PathBuf,
}

async fn start_mysql(certs: &CertPaths) -> Result<(ContainerAsync<GenericImage>, DbInstance)> {
    retry_container_start("MySQL", |host_port| async move {
        start_mysql_on_port(certs, host_port).await
    })
    .await
}

async fn start_mysql_on_port(
    certs: &CertPaths,
    host_port: u16,
) -> Result<(ContainerAsync<GenericImage>, DbInstance)> {
    let request = GenericImage::new("mysql", "8")
        .with_mapped_port(host_port, INTERNAL_MYSQL_PORT.tcp())
        .with_env_var("MYSQL_ROOT_PASSWORD", ROOT_PASSWORD)
        .with_env_var("MYSQL_DATABASE", DATABASE)
        .with_copy_to(
            CopyTargetOptions::new("/etc/mysql/ca.pem").with_mode(0o644),
            certs.ca.as_path(),
        )
        .with_copy_to(
            CopyTargetOptions::new("/etc/mysql/server-cert.pem").with_mode(0o644),
            certs.server_cert.as_path(),
        )
        .with_copy_to(
            CopyTargetOptions::new("/etc/mysql/server-key.pem").with_mode(0o644),
            certs.server_key.as_path(),
        )
        .with_cmd([
            "--ssl-ca=/etc/mysql/ca.pem",
            "--ssl-cert=/etc/mysql/server-cert.pem",
            "--ssl-key=/etc/mysql/server-key.pem",
        ])
        .with_startup_timeout(Duration::from_secs(120));

    let container = request.start().await?;
    let port = container
        .get_host_port_ipv4(INTERNAL_MYSQL_PORT.tcp())
        .await
        .context("resolve MySQL mapped port")?;
    let db = DbInstance { port };
    wait_for_db(&db).await?;
    Ok((container, db))
}

async fn start_mariadb() -> Result<(ContainerAsync<GenericImage>, DbInstance)> {
    retry_container_start("MariaDB", start_mariadb_on_port).await
}

async fn start_mariadb_on_port(
    host_port: u16,
) -> Result<(ContainerAsync<GenericImage>, DbInstance)> {
    let container = GenericImage::new("mariadb", "11")
        .with_mapped_port(host_port, INTERNAL_MYSQL_PORT.tcp())
        .with_env_var("MARIADB_ROOT_PASSWORD", ROOT_PASSWORD)
        .with_env_var("MARIADB_DATABASE", DATABASE)
        .with_startup_timeout(Duration::from_secs(120))
        .start()
        .await?;
    let port = container
        .get_host_port_ipv4(INTERNAL_MYSQL_PORT.tcp())
        .await
        .context("resolve MariaDB mapped port")?;
    let db = DbInstance { port };
    wait_for_db(&db).await?;
    Ok((container, db))
}

async fn retry_container_start<F, Fut>(
    name: &str,
    mut start: F,
) -> Result<(ContainerAsync<GenericImage>, DbInstance)>
where
    F: FnMut(u16) -> Fut,
    Fut: Future<Output = Result<(ContainerAsync<GenericImage>, DbInstance)>>,
{
    let mut last = None;
    for _ in 0..CONTAINER_START_ATTEMPTS {
        let host_port = free_host_port()?;
        match start(host_port).await {
            Ok(started) => return Ok(started),
            Err(err) if is_host_port_collision(&err) => {
                last = Some(err);
            }
            Err(err) => return Err(err),
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("{name} did not start")))
        .with_context(|| format!("{name} host-port allocation raced repeatedly"))
}

fn is_host_port_collision(err: &anyhow::Error) -> bool {
    // Walk the whole source chain: the Docker bind error usually sits below
    // the outermost context, which is all `err.to_string()` would render.
    err.chain().any(|cause| {
        let message = cause.to_string().to_ascii_lowercase();
        message.contains("port is already allocated")
            || message.contains("bind for")
            || message.contains("address already in use")
    })
}

fn free_host_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

async fn wait_for_db(db: &DbInstance) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut last = None;
    while Instant::now() < deadline {
        match root_conn(db, None).await {
            Ok(mut conn) => {
                conn.ping().await?;
                conn.disconnect().await?;
                return Ok(());
            }
            Err(err) => {
                last = Some(err);
                sleep(Duration::from_millis(500)).await;
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("database did not become ready")))
}

async fn root_conn(db: &DbInstance, schema: Option<&str>) -> Result<Conn> {
    let mut builder = OptsBuilder::default()
        .ip_or_hostname("127.0.0.1")
        .tcp_port(db.port)
        .user(Some("root"))
        .pass(Some(ROOT_PASSWORD));
    if let Some(schema) = schema {
        builder = builder.db_name(Some(schema));
    }
    Conn::new(Opts::from(builder))
        .await
        .with_context(|| format!("connect root to 127.0.0.1:{}", db.port))
}

async fn seed_database(db: &DbInstance, kind: DbKind) -> Result<()> {
    let mut conn = root_conn(db, None).await?;
    let default_role = match kind {
        DbKind::Mysql => "ALTER USER 'roleuser'@'%' DEFAULT ROLE r1",
        DbKind::Mariadb => "SET DEFAULT ROLE r1 FOR 'roleuser'@'%'",
    };
    let statements = [
        "DROP DATABASE IF EXISTS app",
        "DROP USER IF EXISTS 'ro'@'%'",
        "DROP USER IF EXISTS 'writer'@'%'",
        "DROP USER IF EXISTS 'roleuser'@'%'",
        "DROP USER IF EXISTS 'granter'@'%'",
        "DROP ROLE IF EXISTS r1",
        "CREATE DATABASE app CHARACTER SET utf8mb4",
        "USE app",
        r#"CREATE TABLE types_t (
  id INT AUTO_INCREMENT PRIMARY KEY,
  u INT UNSIGNED, n INT, dec_c DECIMAL(20,4), f FLOAT, d DOUBLE,
  txt TEXT, vb VARBINARY(64), bl BLOB, bits BIT(8),
  dt DATETIME(6), tm TIME, dte DATE, js JSON, en ENUM('a','b')
)"#,
        r#"INSERT INTO types_t (u,n,dec_c,f,d,txt,vb,bl,bits,dt,tm,dte,js,en) VALUES
 (4294967295,-42,12345.6789,0.1,0.1,CONVERT(UNHEX('68c3a96c6c6f2077c3b6726c64') USING utf8mb4),X'00FF41',X'DEADBEEF',b'10100101',
  '2026-06-10 12:34:56.789012','-25:10:05','2026-06-10','{"k":[1,2]}','b'),
 (NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)"#,
        "CREATE TABLE ten_rows (i INT)",
        "INSERT INTO ten_rows VALUES (1),(2),(3),(4),(5),(6),(7),(8),(9),(10)",
        "CREATE PROCEDURE two_sets() BEGIN SELECT 1 AS a; SELECT 2 AS b, 3 AS c; END",
        "CREATE USER 'ro'@'%' IDENTIFIED BY 'ropw'",
        "GRANT SELECT, SHOW VIEW ON app.* TO 'ro'@'%'",
        "CREATE USER 'writer'@'%' IDENTIFIED BY 'wpw'",
        "GRANT SELECT, INSERT ON app.* TO 'writer'@'%'",
        "CREATE USER 'roleuser'@'%' IDENTIFIED BY 'rpw'",
        "CREATE ROLE r1",
        "GRANT SELECT ON app.* TO r1",
        "GRANT r1 TO 'roleuser'@'%'",
        default_role,
        "CREATE USER 'granter'@'%' IDENTIFIED BY 'gpw'",
        "GRANT SELECT ON app.* TO 'granter'@'%' WITH GRANT OPTION",
        "GRANT EXECUTE ON app.* TO 'writer'@'%'",
    ];

    for statement in statements {
        conn.query_drop(statement)
            .await
            .with_context(|| format!("seed statement failed: {statement}"))?;
    }
    conn.disconnect().await?;
    Ok(())
}

fn write_configs(
    dir: &Path,
    mysql_port: u16,
    maria_port: u16,
    certs: &CertPaths,
) -> Result<ConfigPaths> {
    let mysql_base = format!(
        r#"driver = "mysql"
host = "127.0.0.1"
port = {mysql_port}
user = "root"
password = "{ROOT_PASSWORD}"
database = "{DATABASE}"
"#
    );
    let maria_base = format!(
        r#"driver = "mariadb"
host = "127.0.0.1"
port = {maria_port}
user = "root"
password = "{ROOT_PASSWORD}"
database = "{DATABASE}"
"#
    );

    Ok(ConfigPaths {
        mysql_root: write_cfg(dir, "mysql-root.toml", &mysql_base, 0o600)?,
        mysql_max_rows: write_cfg(
            dir,
            "mysql-max-rows.toml",
            &(mysql_base.clone() + "max_rows = 5\n"),
            0o600,
        )?,
        mysql_max_response: write_cfg(
            dir,
            "mysql-max-response.toml",
            &(mysql_base.clone() + "max_response_bytes = 2000\n"),
            0o600,
        )?,
        mysql_caps_zero: write_cfg(
            dir,
            "mysql-caps-zero.toml",
            &(mysql_base.clone() + "max_rows = 0\nmax_cell_bytes = 0\nmax_response_bytes = 0\n"),
            0o600,
        )?,
        mysql_ro: write_cfg(
            dir,
            "mysql-ro.toml",
            &mysql_base
                .replace(r#"user = "root""#, r#"user = "ro""#)
                .replace(
                    &format!(r#"password = "{ROOT_PASSWORD}""#),
                    r#"password = "ropw""#,
                ),
            0o600,
        )?,
        mysql_writer: write_cfg(
            dir,
            "mysql-writer.toml",
            &mysql_base
                .replace(r#"user = "root""#, r#"user = "writer""#)
                .replace(
                    &format!(r#"password = "{ROOT_PASSWORD}""#),
                    r#"password = "wpw""#,
                ),
            0o600,
        )?,
        mysql_roleuser: write_cfg(
            dir,
            "mysql-roleuser.toml",
            &mysql_base
                .replace(r#"user = "root""#, r#"user = "roleuser""#)
                .replace(
                    &format!(r#"password = "{ROOT_PASSWORD}""#),
                    r#"password = "rpw""#,
                ),
            0o600,
        )?,
        mysql_granter: write_cfg(
            dir,
            "mysql-granter.toml",
            &mysql_base
                .replace(r#"user = "root""#, r#"user = "granter""#)
                .replace(
                    &format!(r#"password = "{ROOT_PASSWORD}""#),
                    r#"password = "gpw""#,
                ),
            0o600,
        )?,
        mysql_tls: write_cfg(
            dir,
            "mysql-tls.toml",
            &(mysql_base.clone() + "tls = true\n"),
            0o600,
        )?,
        mysql_tls_insecure: write_cfg(
            dir,
            "mysql-tls-insecure.toml",
            &(mysql_base.clone() + "tls = true\ntls_insecure = true\n"),
            0o600,
        )?,
        mysql_tls_ca: write_cfg(
            dir,
            "mysql-tls-ca.toml",
            &format!("{mysql_base}tls = true\ntls_ca = {:?}\n", certs.ca),
            0o600,
        )?,
        mysql_tls_wrong_ca: write_cfg(
            dir,
            "mysql-tls-wrong-ca.toml",
            &format!("{mysql_base}tls = true\ntls_ca = {:?}\n", certs.wrong_ca),
            0o600,
        )?,
        maria_root: write_cfg(dir, "maria-root.toml", &maria_base, 0o600)?,
        maria_ro: write_cfg(
            dir,
            "maria-ro.toml",
            &maria_base
                .replace(r#"user = "root""#, r#"user = "ro""#)
                .replace(
                    &format!(r#"password = "{ROOT_PASSWORD}""#),
                    r#"password = "ropw""#,
                ),
            0o600,
        )?,
        invalid_tls_insecure_without_tls: write_cfg(
            dir,
            "invalid-tls-insecure-no-tls.toml",
            &(mysql_base.clone() + "tls_insecure = true\n"),
            0o600,
        )?,
        invalid_tls_ca_without_tls: write_cfg(
            dir,
            "invalid-tls-ca-no-tls.toml",
            &format!("{mysql_base}tls_ca = {:?}\n", certs.ca),
            0o600,
        )?,
        invalid_tls_ca_and_insecure: write_cfg(
            dir,
            "invalid-tls-ca-and-insecure.toml",
            &format!(
                "{mysql_base}tls = true\ntls_ca = {:?}\ntls_insecure = true\n",
                certs.ca
            ),
            0o600,
        )?,
        invalid_unknown_key: write_cfg(
            dir,
            "invalid-unknown-key.toml",
            &(mysql_base.clone() + "read_onyl = true\n"),
            0o600,
        )?,
        invalid_missing_driver: write_cfg(
            dir,
            "invalid-missing-driver.toml",
            &mysql_base
                .lines()
                .filter(|line| !line.starts_with("driver = "))
                .collect::<Vec<_>>()
                .join("\n"),
            0o600,
        )?,
    })
}

async fn test_1_tool_description(config: &Path, backend: &str) -> Result<()> {
    let mut mcp = McpSession::start(config).await?;
    let response = mcp.tools_list().await?;
    let stderr = mcp.close().await?;
    let description = response["result"]["tools"][0]["description"]
        .as_str()
        .context("tool description")?;
    for needle in [
        &format!("configured {backend} database"),
        "1000 rows per result set",
        "16384 bytes per value",
        "~262144 bytes per response",
        "Multiple statements",
        "0x",
        "SHOW TABLES",
        "DESCRIBE",
    ] {
        ensure!(
            description.contains(needle),
            "description missing {needle:?}: {description}"
        );
    }
    ensure!(stderr.contains(&format!("serving sql_exec for {backend}")));
    Ok(())
}

async fn test_2_to_5_type_mapping(config: &Path) -> Result<()> {
    let mut mcp = McpSession::start(config).await?;
    let payload = tool_payload(&mcp.call("SELECT * FROM types_t").await?)?;
    mcp.close().await?;

    let columns = payload["result_sets"][0]["columns"]
        .as_array()
        .context("columns")?
        .iter()
        .enumerate()
        .map(|(idx, value)| (value.as_str().unwrap().to_string(), idx))
        .collect::<HashMap<_, _>>();
    let rows = payload["result_sets"][0]["rows"]
        .as_array()
        .context("rows")?;
    let row1 = rows
        .first()
        .context("row 1")?
        .as_array()
        .context("row 1 array")?;
    let row2 = rows
        .get(1)
        .context("row 2")?
        .as_array()
        .context("row 2 array")?;
    let col = |name: &str| columns[name];

    ensure!(row1[col("u")] == json!(4294967295u64));
    ensure!(row1[col("n")] == json!(-42));
    ensure!(row1[col("dec_c")] == json!("12345.6789"));
    ensure!(row1[col("f")] == json!(0.1));
    ensure!(row1[col("txt")] == json!("héllo wörld"));
    ensure!(row1[col("vb")] == json!("0x00ff41"));
    ensure!(row1[col("bl")] == json!("0xdeadbeef"));
    ensure!(row1[col("bits")] == json!("0xa5"));
    ensure!(row1[col("dt")] == json!("2026-06-10 12:34:56.789012"));
    ensure!(row1[col("tm")] == json!("-25:10:05"));
    ensure!(row1[col("dte")] == json!("2026-06-10"));
    ensure!(row1[col("js")].is_string());
    ensure!(row1[col("en")] == json!("b"));
    for (idx, value) in row2.iter().enumerate() {
        if payload["result_sets"][0]["columns"][idx] != json!("id") {
            ensure!(value.is_null(), "row 2 value at {idx} was {value}");
        }
    }
    Ok(())
}

async fn test_6_dml_shape_and_last_insert_id(config: &Path) -> Result<()> {
    let mut mcp = McpSession::start(config).await?;
    let insert = tool_payload(&mcp.call("INSERT INTO ten_rows VALUES (11)").await?)?;
    let count = tool_payload(&mcp.call("SELECT COUNT(*) FROM ten_rows").await?)?;
    mcp.close().await?;

    ensure_eq_json(
        &insert["result_sets"][0],
        &json!({"columns":[],"rows":[],"rows_affected":1}),
        "insert result shape",
    )?;
    ensure!(first_rows(&count)[0] == json!([11]));

    let mut mcp = McpSession::start(config).await?;
    let insert = tool_payload(&mcp.call("INSERT INTO types_t (n) VALUES (1)").await?)?;
    mcp.close().await?;
    ensure!(
        insert["result_sets"][0]["last_insert_id"]
            .as_i64()
            .unwrap_or(0)
            > 0
    );
    Ok(())
}

async fn test_7_multi_statement_success(config: &Path) -> Result<()> {
    let mut mcp = McpSession::start(config).await?;
    let payload = tool_payload(&mcp.call("SELECT 1; SELECT 2,3").await?)?;
    mcp.close().await?;
    ensure!(payload.get("error").is_none());
    ensure!(payload["result_sets"][0]["rows"] == json!([[1]]));
    ensure!(payload["result_sets"][1]["rows"] == json!([[2, 3]]));
    Ok(())
}

async fn test_8_poison_check(config: &Path) -> Result<()> {
    let mut mcp = McpSession::start(config).await?;
    let first = tool_payload(
        &mcp.call("SELECT 1 AS ok; SELECT * FROM nonexistent")
            .await?,
    )?;
    let second_response = mcp.call("SELECT 42 AS fine").await?;
    let second = tool_payload(&second_response).with_context(|| {
        format!("critical: follow-up failed because of previous call; response={second_response}")
    })?;
    mcp.close().await?;

    ensure!(first["result_sets"][0]["rows"] == json!([[1]]));
    ensure!(
        first["error"]
            .as_str()
            .is_some_and(|error| error.contains("nonexistent")),
        "first response missing in-band nonexistent error: {first}"
    );
    ensure!(second["result_sets"][0]["rows"] == json!([[42]]));
    ensure!(second.get("error").is_none());
    Ok(())
}

async fn test_9_first_statement_error_isolation(config: &Path) -> Result<()> {
    let mut mcp = McpSession::start(config).await?;
    let first = mcp.call("SELECT * FROM nonexistent").await?;
    ensure!(
        tool_is_error(&first) && tool_text(&first).contains("SQL error"),
        "first call should be a tool error: {first}"
    );
    let second_response = mcp.call("SELECT 1").await?;
    let second = tool_payload(&second_response).with_context(|| {
        format!(
            "critical: follow-up failed because of previous SQL error; response={second_response}"
        )
    })?;
    mcp.close().await?;
    ensure!(second["result_sets"][0]["rows"] == json!([[1]]));
    Ok(())
}

async fn test_10_stored_procedure_multi_sets(config: &Path) -> Result<()> {
    let mut mcp = McpSession::start(config).await?;
    let payload = tool_payload(&mcp.call("CALL two_sets()").await?)?;
    mcp.close().await?;
    ensure!(payload["result_sets"][0]["columns"] == json!(["a"]));
    ensure!(payload["result_sets"][0]["rows"] == json!([[1]]));
    ensure!(payload["result_sets"][1]["columns"] == json!(["b", "c"]));
    ensure!(payload["result_sets"][1]["rows"] == json!([[2, 3]]));
    Ok(())
}

async fn test_11_max_rows(config: &Path) -> Result<()> {
    let mut mcp = McpSession::start(config).await?;
    let first = tool_payload(&mcp.call("SELECT * FROM ten_rows").await?)?;
    let second_response = mcp.call("SELECT 1").await?;
    let second = tool_payload(&second_response).with_context(|| {
        format!("critical: follow-up after max_rows truncation failed: {second_response}")
    })?;
    mcp.close().await?;
    ensure!(first["result_sets"][0]["rows"].as_array().unwrap().len() == 5);
    ensure!(first["result_sets"][0]["truncated"] == json!(true));
    ensure!(second["result_sets"][0]["rows"] == json!([[1]]));
    Ok(())
}

async fn test_12_big_drain(config: &Path) -> Result<()> {
    let mut mcp = McpSession::start(config).await?;
    let set_depth = mcp
        .call("SET SESSION cte_max_recursion_depth = 200000")
        .await?;
    ensure!(
        !tool_is_error(&set_depth),
        "SET failed: {}",
        tool_text(&set_depth)
    );

    let started = Instant::now();
    let (big_response, peak_rss) = mcp
        .call_with_rss(
            "WITH RECURSIVE n AS (SELECT 1 i UNION ALL SELECT i+1 FROM n WHERE i < 200000) SELECT i, REPEAT('x', 100) FROM n",
            BIG_DRAIN_TIMEOUT,
        )
        .await?;
    let big = tool_payload(&big_response)?;
    let follow_response = mcp.call("SELECT 1").await?;
    let follow = tool_payload(&follow_response).with_context(|| {
        format!("critical: follow-up after big drain failed: {follow_response}")
    })?;
    mcp.close().await?;

    let elapsed = started.elapsed();
    ensure!(
        elapsed < BIG_DRAIN_REASONABLE_TIME,
        "big drain took {elapsed:?}, expected under {BIG_DRAIN_REASONABLE_TIME:?}"
    );
    ensure!(
        peak_rss < BIG_DRAIN_MAX_RSS_KB,
        "peak RSS too high: {peak_rss} KiB"
    );
    ensure!(big["result_sets"][0]["truncated"] == json!(true));
    ensure!(follow["result_sets"][0]["rows"] == json!([[1]]));
    Ok(())
}

async fn test_13_cell_caps(config: &Path) -> Result<()> {
    let mut mcp = McpSession::start(config).await?;
    let ascii = tool_payload(&mcp.call("SELECT REPEAT('a', 100000) AS big").await?)?;
    let utf8 = tool_payload(&mcp.call("SELECT REPEAT('é', 20000) AS e").await?)?;
    mcp.close().await?;

    let ascii_value = ascii["result_sets"][0]["rows"][0][0].as_str().unwrap();
    ensure!((16_000..=17_000).contains(&ascii_value.len()));
    ensure!(ascii_value.ends_with("…[truncated; 100000 bytes total]"));

    let utf8_value = utf8["result_sets"][0]["rows"][0][0].as_str().unwrap();
    ensure!(!utf8_value.contains('\u{fffd}'));
    ensure!(utf8_value.ends_with("…[truncated; 40000 bytes total]"));
    Ok(())
}

async fn test_14_response_cap(config: &Path) -> Result<()> {
    let mut mcp = McpSession::start(config).await?;
    let payload = tool_payload(
        &mcp.call(
            "SELECT REPEAT('x',300) AS a FROM ten_rows; SELECT REPEAT('y',300) AS b FROM ten_rows",
        )
        .await?,
    )?;
    mcp.close().await?;
    let set1_rows = payload["result_sets"][0]["rows"].as_array().unwrap().len();
    let set2_rows = payload["result_sets"][1]["rows"].as_array().unwrap().len();
    ensure!((1..=7).contains(&set1_rows));
    ensure!(set2_rows == 0);
    ensure!(payload["result_sets"][0]["truncated"] == json!(true));
    ensure!(payload["result_sets"][1]["truncated"] == json!(true));
    Ok(())
}

async fn test_15_caps_zero(config: &Path) -> Result<()> {
    let mut mcp = McpSession::start(config).await?;
    let payload = tool_payload(&mcp.call("SELECT REPEAT('a', 100000) AS big").await?)?;
    mcp.close().await?;
    let value = payload["result_sets"][0]["rows"][0][0].as_str().unwrap();
    ensure!(value.len() == 100000);
    ensure!(!value.contains("[truncated"));
    Ok(())
}

async fn test_16_read_only_ro(config: &Path, backend: &str) -> Result<()> {
    let mut mcp = McpSession::start_with(config, &["--read-only"], &[]).await?;
    let _ = mcp.tools_list().await?;
    let stderr = mcp.close().await?;
    ensure!(
        stderr.contains("verified incapable of mutation"),
        "read-only verification log missing: {stderr}"
    );
    ensure!(stderr.contains(&format!("serving sql_exec for {backend}")));
    Ok(())
}

async fn test_17_writer_refused(config: &Path) -> Result<()> {
    let output = startup_with_config(config, &["--read-only"], &[]).await?;
    ensure_refused(output, &["INSERT", "EXECUTE"])
}

async fn test_18_roleuser_refused(config: &Path) -> Result<()> {
    let output = startup_with_config(config, &["--read-only"], &[]).await?;
    ensure_refused(output, &["role", "disqualifying"])
}

async fn test_19_granter_refused(config: &Path) -> Result<()> {
    let output = startup_with_config(config, &["--read-only"], &[]).await?;
    ensure_refused(output, &["WITH GRANT OPTION"])
}

async fn test_20_mode_env_and_writer_normal(config: &Path) -> Result<()> {
    let ro = startup_with_config(config, &[], &[("SQL_MCP_MODE", "ro")]).await?;
    ensure_refused(ro, &["INSERT"])?;

    let banana = startup_with_config(config, &[], &[("SQL_MCP_MODE", "banana")]).await?;
    ensure_refused(banana, &["valid values", "ro", "read-only"])?;

    let mut mcp = McpSession::start(config).await?;
    let payload = tool_payload(&mcp.call("SELECT 1").await?)?;
    mcp.close().await?;
    ensure!(payload["result_sets"][0]["rows"] == json!([[1]]));
    Ok(())
}

async fn test_21_session_variable(config: &Path) -> Result<()> {
    let mut mcp = McpSession::start(config).await?;
    let _ = tool_payload(&mcp.call("SET @x := 41").await?)?;
    let payload = tool_payload(&mcp.call("SELECT @x + 1 AS v").await?)?;
    mcp.close().await?;
    ensure!(payload["result_sets"][0]["rows"] == json!([[42]]));
    Ok(())
}

async fn test_22_temp_table(config: &Path) -> Result<()> {
    let mut mcp = McpSession::start(config).await?;
    let _ = tool_payload(&mcp.call("CREATE TEMPORARY TABLE tt (a INT)").await?)?;
    let _ = tool_payload(&mcp.call("INSERT INTO tt VALUES (7)").await?)?;
    let payload = tool_payload(&mcp.call("SELECT * FROM tt").await?)?;
    mcp.close().await?;
    ensure!(payload["result_sets"][0]["rows"] == json!([[7]]));
    Ok(())
}

async fn test_23_kill_reconnect(config: &Path, db: &DbInstance) -> Result<()> {
    let mut mcp = McpSession::start(config).await?;
    let id_payload = tool_payload(&mcp.call("SELECT CONNECTION_ID() AS id").await?)?;
    let id = id_payload["result_sets"][0]["rows"][0][0]
        .as_u64()
        .context("connection id")?;
    let mut killer = root_conn(db, Some(DATABASE)).await?;
    killer.query_drop(format!("KILL {id}")).await?;
    killer.disconnect().await?;

    let lost = mcp.call("SELECT 1").await?;
    ensure!(tool_is_error(&lost));
    ensure!(tool_text(&lost).contains("re-established on the next call"));
    let follow_response = mcp.call("SELECT 1").await?;
    let follow = tool_payload(&follow_response).with_context(|| {
        format!("critical: call after killed-connection advisory failed: {follow_response}")
    })?;
    mcp.close().await?;
    ensure!(follow["result_sets"][0]["rows"] == json!([[1]]));
    Ok(())
}

async fn test_24_restart_reconnect(
    config: &Path,
    container: &ContainerAsync<GenericImage>,
    db: &DbInstance,
) -> Result<()> {
    let mut mcp = McpSession::start(config).await?;
    container.stop().await.context("stop MySQL container")?;
    container.start().await.context("start MySQL container")?;
    wait_for_db(db).await?;

    let lost = mcp.call("SELECT 1").await?;
    ensure!(tool_is_error(&lost));
    ensure!(tool_text(&lost).contains("re-established on the next call"));
    let follow_response = mcp.call("SELECT 1").await?;
    let follow = tool_payload(&follow_response).with_context(|| {
        format!("critical: call after container restart advisory failed: {follow_response}")
    })?;
    mcp.close().await?;
    ensure!(follow["result_sets"][0]["rows"] == json!([[1]]));
    Ok(())
}

async fn test_25_config_mode(config: &Path) -> Result<()> {
    set_mode(config, 0o644)?;
    let result = startup_with_config(config, &[], &[]).await;
    set_mode(config, 0o600)?;
    let (code, stdout, stderr) = result?;
    let combined = stdout + &stderr;
    ensure!(code != 0);
    ensure!(combined.contains("644"));
    ensure!(combined.contains("chmod 600"));
    Ok(())
}

async fn test_26_tls_config_validation(cfg: &ConfigPaths) -> Result<()> {
    for (path, needle) in [
        (&cfg.invalid_tls_insecure_without_tls, "tls_insecure"),
        (&cfg.invalid_tls_ca_without_tls, "tls_ca"),
        (&cfg.invalid_tls_ca_and_insecure, "tls_ca"),
    ] {
        let output = startup_with_config(path, &[], &[]).await?;
        ensure_refused(output, &[needle])?;
    }
    Ok(())
}

async fn test_27_unknown_config_and_cli(cfg: &ConfigPaths) -> Result<()> {
    let unknown = startup_with_config(&cfg.invalid_unknown_key, &[], &[]).await?;
    ensure_refused(unknown, &[r#"did you mean "read_only""#])?;
    let missing = startup_with_config(&cfg.invalid_missing_driver, &[], &[]).await?;
    ensure_refused(missing, &["driver"])?;
    let output = run_startup(&["--definitely-unknown"], &[]).await?;
    ensure_refused(output, &["unknown"])?;
    Ok(())
}

async fn test_28_tls_requires_verification(config: &Path) -> Result<()> {
    let output = startup_with_config(config, &[], &[]).await?;
    ensure_refused(output, &["UnknownIssuer"])
}

async fn test_29_tls_insecure(config: &Path) -> Result<()> {
    let mut mcp = McpSession::start(config).await?;
    let payload = tool_payload(&mcp.call("SHOW STATUS LIKE 'Ssl_cipher'").await?)?;
    mcp.close().await?;
    let cipher = payload["result_sets"][0]["rows"][0][1]
        .as_str()
        .context("cipher")?;
    ensure!(!cipher.is_empty());
    Ok(())
}

async fn test_30_tls_ca_and_wrong_ca(good_config: &Path, wrong_config: &Path) -> Result<()> {
    let mut mcp = McpSession::start(good_config).await?;
    let payload = tool_payload(&mcp.call("SHOW STATUS LIKE 'Ssl_cipher'").await?)?;
    mcp.close().await?;
    let cipher = payload["result_sets"][0]["rows"][0][1]
        .as_str()
        .context("cipher")?;
    ensure!(!cipher.is_empty());

    let output = startup_with_config(wrong_config, &[], &[]).await?;
    ensure_refused(output, &["UnknownIssuer"])?;
    Ok(())
}

async fn test_31_mariadb_smoke(root_config: &Path, ro_config: &Path) -> Result<()> {
    test_1_tool_description(root_config, "mariadb").await?;
    test_2_to_5_type_mapping(root_config).await?;
    test_7_multi_statement_success(root_config).await?;
    test_8_poison_check(root_config).await?;
    test_16_read_only_ro(ro_config, "mariadb").await?;
    Ok(())
}
