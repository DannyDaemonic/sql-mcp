use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};
use futures_util::StreamExt;
use rustls::DigitallySignedStruct;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::sync::Mutex;
use tokio_postgres::config::SslMode;
use tokio_postgres::error::SqlState;
use tokio_postgres::{Client, SimpleQueryMessage};
use tokio_postgres_rustls::MakeRustlsConnect;

use crate::config::NetConfig;
use crate::driver::{
    BackendProfile, Driver, Limits, QueryOutput, ResultSet, cap_cell, estimate_bytes,
};

const DEFAULT_PORT: u16 = 5432;

const ROLLBACK_NOTE: &str = " (all statements of one call run in a single transaction: earlier \
     statements from this call were rolled back, unless the call issued its own BEGIN/COMMIT; \
     any explicit transaction left open is now aborted, and a later call must run ROLLBACK, or \
     ROLLBACK TO <savepoint>, to clear it)";

pub struct PostgresDriver {
    pg_config: tokio_postgres::Config,

    tls: Option<rustls::ClientConfig>,
    client: Mutex<Option<Client>>,
    profile: &'static BackendProfile,
    read_only: bool,
}

impl PostgresDriver {
    pub async fn connect(
        config: &NetConfig,
        profile: &'static BackendProfile,
        read_only: bool,
    ) -> Result<Self> {
        let mut pg_config = tokio_postgres::Config::new();
        pg_config
            .host(&config.host)
            .port(config.port.unwrap_or(DEFAULT_PORT))
            .user(&config.user)
            .password(&config.password);
        if let Some(db) = &config.database {
            pg_config.dbname(db);
        }

        pg_config.ssl_mode(if config.tls {
            SslMode::Require
        } else {
            SslMode::Disable
        });

        let tls = if config.tls {
            Some(build_tls(config)?)
        } else {
            None
        };

        let client = establish(&pg_config, &tls).await?;
        Ok(Self {
            pg_config,
            tls,
            client: Mutex::new(Some(client)),
            profile,
            read_only,
        })
    }
}

async fn establish(
    pg_config: &tokio_postgres::Config,
    tls: &Option<rustls::ClientConfig>,
) -> Result<Client> {
    Ok(match tls {
        Some(tls) => {
            let (client, connection) = pg_config
                .connect(MakeRustlsConnect::new(tls.clone()))
                .await
                .context("failed to connect to the database")?;
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("[sql-mcp] postgres connection ended: {e}");
                }
            });
            client
        }
        None => {
            let (client, connection) = pg_config
                .connect(tokio_postgres::NoTls)
                .await
                .context("failed to connect to the database")?;
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("[sql-mcp] postgres connection ended: {e}");
                }
            });
            client
        }
    })
}

#[async_trait::async_trait]
impl Driver for PostgresDriver {
    fn name(&self) -> &'static str {
        self.profile.name()
    }

    fn introspection_hint(&self) -> &'static str {
        self.profile.introspection_hint()
    }

    fn exec_notes(&self) -> &'static str {
        self.profile.exec_notes()
    }

    async fn assert_read_only(&self) -> Result<()> {
        let guard = self.client.lock().await;
        let client = match guard.as_ref() {
            Some(client) => client,
            None => unreachable!("assert_read_only runs right after connect"),
        };

        let version_rows =
            catalog_rows(client, "SELECT current_setting('server_version_num')").await?;
        let reach = Reach {
            version_num: version_rows
                .first()
                .map(|row| cell(row, 0))
                .unwrap_or_default()
                .parse()
                .context("parsing server_version_num")?,
        };

        let mut violations = Vec::new();
        scan_roles(client, &reach, &mut violations).await?;
        scan_admin_options(client, &reach, &mut violations).await?;
        scan_ownership(client, &reach, &mut violations).await?;
        scan_relation_acls(client, &reach, &mut violations).await?;
        scan_misc_acls(client, &reach, &mut violations).await?;
        scan_schema_acls(client, &reach, &mut violations).await?;
        scan_database_acl(client, &reach, &mut violations).await?;
        if reach.has_parameter_acl() {
            scan_parameter_acls(client, &reach, &mut violations).await?;
        }
        scan_default_acls(client, &reach, &mut violations).await?;

        if !violations.is_empty() {
            const MAX_LISTED: usize = 25;
            let total = violations.len();
            let mut listed = violations;
            if total > MAX_LISTED {
                listed.truncate(MAX_LISTED);
                listed.push(format!("  ... and {} more", total - MAX_LISTED));
            }
            bail!(
                "account is not read-only; the following permit mutation (or could \
                 not be verified):\n{}\n\n\
                 Give the account only SELECT on tables, USAGE on schemas, and CONNECT \
                 on the database (and run REVOKE TEMP ON DATABASE <db> FROM PUBLIC), or \
                 run without --read-only.",
                listed.join("\n")
            );
        }
        Ok(())
    }

    async fn exec(&self, sql: &str, limits: Limits) -> Result<QueryOutput> {
        let mut guard = self.client.lock().await;
        match guard.as_ref() {
            None => {
                *guard = Some(
                    establish(&self.pg_config, &self.tls)
                        .await
                        .context("reconnecting to the database")?,
                );
            }

            Some(client) if client.is_closed() => {
                *guard = None;
                bail!("{}", self.profile.connection_lost(self.read_only));
            }
            Some(_) => {}
        }
        let client = guard.as_ref().expect("connection established above");

        match run_query(client, sql, limits).await {
            Ok(output) => Ok(output),
            Err(e) if e.is_closed() => {
                *guard = None;
                Err(anyhow::Error::new(e).context(self.profile.connection_lost(self.read_only)))
            }

            Err(e) if e.as_db_error().is_none() => {
                *guard = None;
                Err(anyhow::Error::new(e).context(format!(
                    "the call failed at the protocol level (COPY FROM STDIN / TO STDOUT \
                     is not supported over this transport) and the connection was \
                     discarded; it will be re-established on the next call with fresh \
                     session state; {}",
                    self.profile.lost_state(self.read_only)
                )))
            }

            Err(e) => Err(anyhow::anyhow!(error_text(&e))),
        }
    }
}

fn error_text(e: &tokio_postgres::Error) -> String {
    if let Some(db) = e.as_db_error() {
        let mut text = db.to_string();

        if db.code() == &SqlState::IN_FAILED_SQL_TRANSACTION {
            text.push_str(
                " (an explicit transaction opened by an earlier call is in a failed state; \
                 run ROLLBACK, or ROLLBACK TO <savepoint>, to clear it)",
            );
        }
        return text;
    }
    let mut text = e.to_string();
    let mut source = std::error::Error::source(e);
    while let Some(cause) = source {
        text.push_str(&format!(": {cause}"));
        source = cause.source();
    }
    text
}

async fn run_query(
    client: &Client,
    sql: &str,
    limits: Limits,
) -> std::result::Result<QueryOutput, tokio_postgres::Error> {
    let stream = client.simple_query_raw(sql).await?;
    futures_util::pin_mut!(stream);

    let mut result_sets: Vec<ResultSet> = Vec::new();
    let mut error = None;
    let mut spent_bytes: u64 = 0;

    let mut current: Option<(Vec<String>, Vec<Vec<serde_json::Value>>, bool)> = None;

    while let Some(message) = stream.next().await {
        match message {
            Ok(SimpleQueryMessage::RowDescription(cols)) => {
                if let Some(set) = current.take() {
                    result_sets.push(finish_set(set));
                }
                current = Some((
                    cols.iter().map(|c| c.name().to_string()).collect(),
                    Vec::new(),
                    false,
                ));
            }
            Ok(SimpleQueryMessage::Row(row)) => {
                let Some((columns, rows, truncated)) = current.as_mut() else {
                    continue;
                };
                if *truncated {
                    continue;
                }
                if limits.max_rows != 0 && rows.len() as u64 >= limits.max_rows {
                    *truncated = true;
                    continue;
                }

                let json_row: Vec<serde_json::Value> = (0..columns.len())
                    .map(|i| {
                        cap_cell(
                            match row.get(i) {
                                Some(s) => serde_json::Value::String(s.to_owned()),
                                None => serde_json::Value::Null,
                            },
                            limits.max_cell_bytes,
                        )
                    })
                    .collect();
                let row_bytes: u64 = json_row.iter().map(estimate_bytes).sum::<u64>() + 2;
                if limits.max_response_bytes != 0
                    && spent_bytes + row_bytes > limits.max_response_bytes
                {
                    *truncated = true;
                    continue;
                }
                spent_bytes += row_bytes;
                rows.push(json_row);
            }
            Ok(SimpleQueryMessage::CommandComplete(n)) => match current.take() {
                Some(set) => result_sets.push(finish_set(set)),

                None => result_sets.push(ResultSet {
                    columns: Vec::new(),
                    rows: Vec::new(),
                    rows_affected: Some(n),
                    last_insert_id: None,
                    truncated: false,
                }),
            },

            Ok(_) => {}

            Err(e) if e.is_closed() || e.as_db_error().is_none() => return Err(e),
            Err(e) => {
                if let Some(set) = current.take() {
                    result_sets.push(finish_set(set));
                }
                if result_sets.is_empty() {
                    return Err(e);
                }
                error = Some(format!("{}{ROLLBACK_NOTE}", error_text(&e)));
                break;
            }
        }
    }
    if let Some(set) = current.take() {
        result_sets.push(finish_set(set));
    }
    Ok(QueryOutput { result_sets, error })
}

fn finish_set(
    (columns, rows, truncated): (Vec<String>, Vec<Vec<serde_json::Value>>, bool),
) -> ResultSet {
    ResultSet {
        columns,
        rows,
        rows_affected: None,
        last_insert_id: None,
        truncated,
    }
}

struct Reach {
    version_num: i32,
}

impl Reach {
    fn pred(&self, oid_expr: &str) -> String {
        if self.version_num >= 160000 {
            format!(
                "(pg_has_role(current_user, {oid_expr}, 'USAGE') \
                 OR pg_has_role(current_user, {oid_expr}, 'SET'))"
            )
        } else {
            format!("pg_has_role(current_user, {oid_expr}, 'MEMBER')")
        }
    }

    fn set_pred(&self, oid_expr: &str) -> String {
        if self.version_num >= 160000 {
            format!("pg_has_role(current_user, {oid_expr}, 'SET')")
        } else {
            format!("pg_has_role(current_user, {oid_expr}, 'MEMBER')")
        }
    }

    fn grantee_pred(&self) -> String {
        format!("(a.grantee = 0 OR {})", self.pred("a.grantee"))
    }

    fn has_parameter_acl(&self) -> bool {
        self.version_num >= 150000
    }
}

const SAFE_PREDEFINED_ROLES: &[&str] = &[
    "pg_read_all_data",
    "pg_read_all_settings",
    "pg_read_all_stats",
    "pg_stat_scan_tables",
    "pg_monitor",
];

fn violation(finding: impl AsRef<str>, reason: &str, fix: &str) -> String {
    format!(
        "  {}\n      -> disqualifying: {reason}\n      -> fix: {fix}",
        finding.as_ref()
    )
}

async fn catalog_rows(client: &Client, sql: &str) -> Result<Vec<Vec<Option<String>>>> {
    let messages = client
        .simple_query(sql)
        .await
        .context("inspecting catalogs for the read-only assertion")?;
    let mut rows = Vec::new();
    for message in messages {
        if let SimpleQueryMessage::Row(row) = message {
            rows.push(
                (0..row.len())
                    .map(|i| row.get(i).map(str::to_owned))
                    .collect(),
            );
        }
    }
    Ok(rows)
}

fn cell(row: &[Option<String>], i: usize) -> &str {
    row.get(i).and_then(|c| c.as_deref()).unwrap_or("")
}

async fn scan_roles(client: &Client, reach: &Reach, violations: &mut Vec<String>) -> Result<()> {
    let rows = catalog_rows(
        client,
        &format!(
            r#"
        SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls,
               {settable} AS settable, quote_ident(rolname)
        FROM pg_catalog.pg_roles
        WHERE {usable}
        ORDER BY rolname
        "#,
            settable = reach.set_pred("oid"),
            usable = reach.pred("oid"),
        ),
    )
    .await?;
    for row in &rows {
        let (role, qrole) = (cell(row, 0), cell(row, 7));

        if cell(row, 6) == "t" {
            const ATTRS: &[(usize, &str, &str)] = &[
                (1, "SUPERUSER", "bypasses every permission check"),
                (2, "CREATEDB", "can create databases"),
                (3, "CREATEROLE", "can create and grant roles"),
                (4, "REPLICATION", "can use the replication protocol"),
                (5, "BYPASSRLS", "bypasses row-level security"),
            ];
            for &(idx, attr, why) in ATTRS {
                if cell(row, idx) == "t" {
                    violations.push(violation(
                        format!("role {qrole} has the {attr} attribute (reachable via SET ROLE)"),
                        why,
                        &format!("ALTER ROLE {qrole} NO{attr}; or REVOKE {qrole} FROM <account>;"),
                    ));
                }
            }
        }

        if let Some(reason) = predefined_role_violation(role) {
            violations.push(violation(
                format!("membership in predefined role {qrole}"),
                &reason,
                &format!("REVOKE {qrole} FROM <account>;"),
            ));
        }
    }
    Ok(())
}

async fn scan_admin_options(
    client: &Client,
    reach: &Reach,
    violations: &mut Vec<String>,
) -> Result<()> {
    let rows = catalog_rows(
        client,
        &format!(
            r#"
        SELECT quote_ident(m.rolname), quote_ident(r.rolname)
        FROM pg_catalog.pg_auth_members am
        JOIN pg_catalog.pg_roles m ON m.oid = am.member
        JOIN pg_catalog.pg_roles r ON r.oid = am.roleid
        WHERE am.admin_option AND {}
        "#,
            reach.pred("am.member")
        ),
    )
    .await?;
    for row in &rows {
        let (member, role) = (cell(row, 0), cell(row, 1));
        violations.push(violation(
            format!("role {member} holds membership in {role} WITH ADMIN OPTION"),
            "permits granting this role onward (privilege mutation)",
            &format!("REVOKE ADMIN OPTION FOR {role} FROM {member};"),
        ));
    }
    Ok(())
}

async fn scan_ownership(
    client: &Client,
    reach: &Reach,
    violations: &mut Vec<String>,
) -> Result<()> {
    let mut sql = format!(
        r#"
        SELECT CASE c.relkind WHEN 'S' THEN 'SEQUENCE' WHEN 'v' THEN 'VIEW'
                              WHEN 'm' THEN 'MATERIALIZED VIEW'
                              WHEN 'f' THEN 'FOREIGN TABLE' ELSE 'TABLE' END,
               quote_ident(n.nspname) || '.' || quote_ident(c.relname),
               pg_get_userbyid(c.relowner)
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relkind IN ('r','p','v','m','S','f')
          AND {owner_rel}
        UNION ALL
        SELECT 'SCHEMA', quote_ident(n.nspname), pg_get_userbyid(n.nspowner)
        FROM pg_catalog.pg_namespace n
        WHERE {owner_nsp}
        UNION ALL
        SELECT 'DATABASE', quote_ident(d.datname), pg_get_userbyid(d.datdba)
        FROM pg_catalog.pg_database d
        WHERE {owner_db}
        UNION ALL
        SELECT CASE p.prokind WHEN 'p' THEN 'PROCEDURE'
                              WHEN 'a' THEN 'AGGREGATE' ELSE 'FUNCTION' END,
               quote_ident(n.nspname) || '.' || quote_ident(p.proname)
                 || '(' || pg_get_function_identity_arguments(p.oid) || ')',
               pg_get_userbyid(p.proowner)
        FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        WHERE {owner_proc}
        UNION ALL
        SELECT 'LARGE OBJECT', l.oid::text, pg_get_userbyid(l.lomowner)
        FROM pg_catalog.pg_largeobject_metadata l
        WHERE {owner_lo}
        UNION ALL
        SELECT CASE t.typtype WHEN 'd' THEN 'DOMAIN' ELSE 'TYPE' END,
               quote_ident(n.nspname) || '.' || quote_ident(t.typname),
               pg_get_userbyid(t.typowner)
        FROM pg_catalog.pg_type t
        JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
        WHERE {owner_type}
          -- An auto-generated array type is one some element type's typarray
          -- points at. (Filtering on typcategory = 'A' would also drop
          -- user-owned domains over arrays, which ARE alterable objects.)
          AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_type el
                          WHERE el.typarray = t.oid)
          AND NOT (t.typtype = 'c' AND t.typrelid <> 0 AND EXISTS (
                SELECT 1 FROM pg_catalog.pg_class rc
                WHERE rc.oid = t.typrelid
                  AND rc.relkind IN ('r','p','v','m','S','f')))
        UNION ALL
        SELECT 'EXTENSION', quote_ident(e.extname), pg_get_userbyid(e.extowner)
        FROM pg_catalog.pg_extension e
        WHERE {owner_ext}
        UNION ALL
        SELECT 'COLLATION', quote_ident(n.nspname) || '.' || quote_ident(co.collname),
               pg_get_userbyid(co.collowner)
        FROM pg_catalog.pg_collation co
        JOIN pg_catalog.pg_namespace n ON n.oid = co.collnamespace
        WHERE {owner_coll}
        UNION ALL
        SELECT 'CONVERSION', quote_ident(n.nspname) || '.' || quote_ident(cv.conname),
               pg_get_userbyid(cv.conowner)
        FROM pg_catalog.pg_conversion cv
        JOIN pg_catalog.pg_namespace n ON n.oid = cv.connamespace
        WHERE {owner_conv}
        UNION ALL
        SELECT 'OPERATOR',
               quote_ident(n.nspname) || '.' || o.oprname || ' ('
                 || CASE WHEN o.oprleft = 0 THEN 'NONE'
                         ELSE pg_catalog.format_type(o.oprleft, NULL) END
                 || ', '
                 || CASE WHEN o.oprright = 0 THEN 'NONE'
                         ELSE pg_catalog.format_type(o.oprright, NULL) END
                 || ')',
               pg_get_userbyid(o.oprowner)
        FROM pg_catalog.pg_operator o
        JOIN pg_catalog.pg_namespace n ON n.oid = o.oprnamespace
        WHERE {owner_opr}
        UNION ALL
        SELECT 'OPERATOR CLASS',
               quote_ident(n.nspname) || '.' || quote_ident(oc.opcname)
                 || ' USING ' || amc.amname,
               pg_get_userbyid(oc.opcowner)
        FROM pg_catalog.pg_opclass oc
        JOIN pg_catalog.pg_namespace n ON n.oid = oc.opcnamespace
        JOIN pg_catalog.pg_am amc ON amc.oid = oc.opcmethod
        WHERE {owner_opc}
        UNION ALL
        SELECT 'OPERATOR FAMILY',
               quote_ident(n.nspname) || '.' || quote_ident(og.opfname)
                 || ' USING ' || amf.amname,
               pg_get_userbyid(og.opfowner)
        FROM pg_catalog.pg_opfamily og
        JOIN pg_catalog.pg_namespace n ON n.oid = og.opfnamespace
        JOIN pg_catalog.pg_am amf ON amf.oid = og.opfmethod
        WHERE {owner_opf}
        UNION ALL
        SELECT 'TEXT SEARCH CONFIGURATION',
               quote_ident(n.nspname) || '.' || quote_ident(ts.cfgname),
               pg_get_userbyid(ts.cfgowner)
        FROM pg_catalog.pg_ts_config ts
        JOIN pg_catalog.pg_namespace n ON n.oid = ts.cfgnamespace
        WHERE {owner_tsc}
        UNION ALL
        SELECT 'TEXT SEARCH DICTIONARY',
               quote_ident(n.nspname) || '.' || quote_ident(td.dictname),
               pg_get_userbyid(td.dictowner)
        FROM pg_catalog.pg_ts_dict td
        JOIN pg_catalog.pg_namespace n ON n.oid = td.dictnamespace
        WHERE {owner_tsd}
        UNION ALL
        SELECT 'FOREIGN DATA WRAPPER', quote_ident(f.fdwname), pg_get_userbyid(f.fdwowner)
        FROM pg_catalog.pg_foreign_data_wrapper f
        WHERE {owner_fdw}
        UNION ALL
        SELECT 'SERVER', quote_ident(s.srvname), pg_get_userbyid(s.srvowner)
        FROM pg_catalog.pg_foreign_server s
        WHERE {owner_srv}
        UNION ALL
        SELECT 'LANGUAGE', quote_ident(l.lanname), pg_get_userbyid(l.lanowner)
        FROM pg_catalog.pg_language l
        WHERE {owner_lang}
        UNION ALL
        SELECT 'TABLESPACE', quote_ident(sp.spcname), pg_get_userbyid(sp.spcowner)
        FROM pg_catalog.pg_tablespace sp
        WHERE {owner_spc}
        UNION ALL
        SELECT 'PUBLICATION', quote_ident(pb.pubname), pg_get_userbyid(pb.pubowner)
        FROM pg_catalog.pg_publication pb
        WHERE {owner_pub}
        UNION ALL
        SELECT 'EVENT TRIGGER', quote_ident(ev.evtname), pg_get_userbyid(ev.evtowner)
        FROM pg_catalog.pg_event_trigger ev
        WHERE {owner_evt}
        UNION ALL
        SELECT 'STATISTICS', quote_ident(n.nspname) || '.' || quote_ident(sx.stxname),
               pg_get_userbyid(sx.stxowner)
        FROM pg_catalog.pg_statistic_ext sx
        JOIN pg_catalog.pg_namespace n ON n.oid = sx.stxnamespace
        WHERE {owner_stx}
        "#,
        owner_rel = reach.pred("c.relowner"),
        owner_nsp = reach.pred("n.nspowner"),
        owner_db = reach.pred("d.datdba"),
        owner_proc = reach.pred("p.proowner"),
        owner_lo = reach.pred("l.lomowner"),
        owner_type = reach.pred("t.typowner"),
        owner_ext = reach.pred("e.extowner"),
        owner_coll = reach.pred("co.collowner"),
        owner_conv = reach.pred("cv.conowner"),
        owner_opr = reach.pred("o.oprowner"),
        owner_opc = reach.pred("oc.opcowner"),
        owner_opf = reach.pred("og.opfowner"),
        owner_tsc = reach.pred("ts.cfgowner"),
        owner_tsd = reach.pred("td.dictowner"),
        owner_fdw = reach.pred("f.fdwowner"),
        owner_srv = reach.pred("s.srvowner"),
        owner_lang = reach.pred("l.lanowner"),
        owner_spc = reach.pred("sp.spcowner"),
        owner_pub = reach.pred("pb.pubowner"),
        owner_evt = reach.pred("ev.evtowner"),
        owner_stx = reach.pred("sx.stxowner"),
    );

    if reach.version_num >= 150000 {
        sql.push_str(&format!(
            r#"
        UNION ALL
        SELECT 'SUBSCRIPTION', quote_ident(sb.subname), pg_get_userbyid(sb.subowner)
        FROM pg_catalog.pg_subscription sb
        WHERE {}
        "#,
            reach.pred("sb.subowner")
        ));
    }
    let rows = catalog_rows(client, &sql).await?;
    for row in &rows {
        let (kind, name, owner) = (cell(row, 0), cell(row, 1), cell(row, 2));

        let fix = if kind == "EXTENSION" {
            format!(
                "DROP EXTENSION {name}; and reinstall it as an admin role \
                 (ALTER EXTENSION has no OWNER TO form)"
            )
        } else {
            format!("ALTER {kind} {name} OWNER TO <admin role>;")
        };
        violations.push(violation(
            format!(
                "{} {name} is owned by reachable role {owner}",
                kind.to_lowercase()
            ),
            "ownership implies full rights (ALTER/DROP/write) regardless of grants",
            &fix,
        ));
    }
    Ok(())
}

async fn scan_relation_acls(
    client: &Client,
    reach: &Reach,
    violations: &mut Vec<String>,
) -> Result<()> {
    let grantee = reach.grantee_pred();
    let rows = catalog_rows(
        client,
        &format!(
            r#"
        SELECT c.relkind, quote_ident(n.nspname) || '.' || quote_ident(c.relname),
               a.privilege_type, COALESCE(quote_ident(gr.rolname), 'PUBLIC'),
               a.is_grantable, NULL
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        CROSS JOIN LATERAL aclexplode(c.relacl) a
        LEFT JOIN pg_catalog.pg_roles gr ON gr.oid = a.grantee
        WHERE c.relacl IS NOT NULL AND {grantee}
        UNION ALL
        SELECT c.relkind, quote_ident(n.nspname) || '.' || quote_ident(c.relname),
               a.privilege_type, COALESCE(quote_ident(gr.rolname), 'PUBLIC'),
               a.is_grantable, quote_ident(att.attname)
        FROM pg_catalog.pg_attribute att
        JOIN pg_catalog.pg_class c ON c.oid = att.attrelid
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        CROSS JOIN LATERAL aclexplode(att.attacl) a
        LEFT JOIN pg_catalog.pg_roles gr ON gr.oid = a.grantee
        WHERE att.attacl IS NOT NULL AND {grantee}
        UNION ALL
        SELECT 'L', 'large object ' || l.oid::text, a.privilege_type,
               COALESCE(quote_ident(gr.rolname), 'PUBLIC'), a.is_grantable, NULL
        FROM pg_catalog.pg_largeobject_metadata l
        CROSS JOIN LATERAL aclexplode(l.lomacl) a
        LEFT JOIN pg_catalog.pg_roles gr ON gr.oid = a.grantee
        WHERE l.lomacl IS NOT NULL AND {grantee}
        "#
        ),
    )
    .await?;
    for row in &rows {
        let (relkind, name, privilege, grantee, column) = (
            cell(row, 0),
            cell(row, 1),
            cell(row, 2),
            cell(row, 3),
            cell(row, 5),
        );

        let (display, revoke) = if column.is_empty() {
            let target = if relkind == "S" {
                format!("SEQUENCE {name}")
            } else {
                name.to_string()
            };
            (name.to_string(), format!("{privilege} ON {target}"))
        } else {
            (
                format!("column {column} of {name}"),
                format!("{privilege} ({column}) ON {name}"),
            )
        };
        if let Some(reason) = relation_acl_violation(relkind, name, privilege) {
            violations.push(violation(
                format!("{privilege} on {display} granted to {grantee}"),
                &reason,
                &format!("REVOKE {revoke} FROM {grantee};"),
            ));
        }
        if cell(row, 4) == "t" {
            violations.push(grant_option_violation(
                privilege,
                &format!("{display} (held by {grantee})"),
                &format!("REVOKE GRANT OPTION FOR {revoke} FROM {grantee};"),
            ));
        }
    }
    Ok(())
}

async fn scan_misc_acls(
    client: &Client,
    reach: &Reach,
    violations: &mut Vec<String>,
) -> Result<()> {
    let grantee = reach.grantee_pred();
    let rows = catalog_rows(
        client,
        &format!(
            r#"
        SELECT 'TYPE', quote_ident(n.nspname) || '.' || quote_ident(t.typname),
               a.privilege_type,
               COALESCE(quote_ident(gr.rolname), 'PUBLIC'), a.is_grantable
        FROM pg_catalog.pg_type t
        JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
        CROSS JOIN LATERAL aclexplode(t.typacl) a
        LEFT JOIN pg_catalog.pg_roles gr ON gr.oid = a.grantee
        WHERE t.typacl IS NOT NULL AND {grantee}
        UNION ALL
        SELECT 'LANGUAGE', quote_ident(l.lanname), a.privilege_type,
               COALESCE(quote_ident(gr.rolname), 'PUBLIC'), a.is_grantable
        FROM pg_catalog.pg_language l
        CROSS JOIN LATERAL aclexplode(l.lanacl) a
        LEFT JOIN pg_catalog.pg_roles gr ON gr.oid = a.grantee
        WHERE l.lanacl IS NOT NULL AND {grantee}
        UNION ALL
        SELECT 'FOREIGN DATA WRAPPER', quote_ident(f.fdwname), a.privilege_type,
               COALESCE(quote_ident(gr.rolname), 'PUBLIC'), a.is_grantable
        FROM pg_catalog.pg_foreign_data_wrapper f
        CROSS JOIN LATERAL aclexplode(f.fdwacl) a
        LEFT JOIN pg_catalog.pg_roles gr ON gr.oid = a.grantee
        WHERE f.fdwacl IS NOT NULL AND {grantee}
        UNION ALL
        SELECT 'FOREIGN SERVER', quote_ident(s.srvname), a.privilege_type,
               COALESCE(quote_ident(gr.rolname), 'PUBLIC'), a.is_grantable
        FROM pg_catalog.pg_foreign_server s
        CROSS JOIN LATERAL aclexplode(s.srvacl) a
        LEFT JOIN pg_catalog.pg_roles gr ON gr.oid = a.grantee
        WHERE s.srvacl IS NOT NULL AND {grantee}
        UNION ALL
        SELECT 'TABLESPACE', quote_ident(sp.spcname), a.privilege_type,
               COALESCE(quote_ident(gr.rolname), 'PUBLIC'), a.is_grantable
        FROM pg_catalog.pg_tablespace sp
        CROSS JOIN LATERAL aclexplode(sp.spcacl) a
        LEFT JOIN pg_catalog.pg_roles gr ON gr.oid = a.grantee
        WHERE sp.spcacl IS NOT NULL AND {grantee}
        "#
        ),
    )
    .await?;
    for row in &rows {
        let (class, name, privilege, grantee) =
            (cell(row, 0), cell(row, 1), cell(row, 2), cell(row, 3));
        if let Some(reason) = misc_acl_violation(class, privilege) {
            violations.push(violation(
                format!(
                    "{privilege} on {} {name} granted to {grantee}",
                    class.to_lowercase()
                ),
                reason,
                &format!("REVOKE {privilege} ON {class} {name} FROM {grantee};"),
            ));
        }
        if cell(row, 4) == "t" {
            violations.push(grant_option_violation(
                privilege,
                &format!("{class} {name} (held by {grantee})"),
                &format!("REVOKE GRANT OPTION FOR {privilege} ON {class} {name} FROM {grantee};"),
            ));
        }
    }
    Ok(())
}

fn misc_acl_violation(class: &str, privilege: &str) -> Option<&'static str> {
    match (class, privilege) {
        ("TYPE", "USAGE") | ("LANGUAGE", "USAGE") => None,
        ("FOREIGN DATA WRAPPER", "USAGE") => {
            Some("permits CREATE SERVER (persistent catalog mutation)")
        }
        ("FOREIGN SERVER", "USAGE") => {
            Some("permits CREATE USER MAPPING (persistent catalog mutation)")
        }
        ("TABLESPACE", "CREATE") => Some("permits placing new objects in the tablespace"),
        _ => Some("not a recognized read-only privilege"),
    }
}

async fn scan_schema_acls(
    client: &Client,
    reach: &Reach,
    violations: &mut Vec<String>,
) -> Result<()> {
    let rows = catalog_rows(
        client,
        &format!(
            r#"
        SELECT quote_ident(n.nspname), a.privilege_type,
               COALESCE(quote_ident(gr.rolname), 'PUBLIC'), a.is_grantable
        FROM pg_catalog.pg_namespace n
        CROSS JOIN LATERAL aclexplode(n.nspacl) a
        LEFT JOIN pg_catalog.pg_roles gr ON gr.oid = a.grantee
        WHERE n.nspacl IS NOT NULL AND {}
        "#,
            reach.grantee_pred()
        ),
    )
    .await?;
    for row in &rows {
        let (schema, privilege, grantee) = (cell(row, 0), cell(row, 1), cell(row, 2));
        if privilege != "USAGE" {
            violations.push(violation(
                format!("{privilege} on schema {schema} granted to {grantee}"),
                "permits creating objects in the schema",
                &format!("REVOKE {privilege} ON SCHEMA {schema} FROM {grantee};"),
            ));
        }
        if cell(row, 3) == "t" {
            violations.push(grant_option_violation(
                privilege,
                &format!("schema {schema} (held by {grantee})"),
                &format!("REVOKE GRANT OPTION FOR {privilege} ON SCHEMA {schema} FROM {grantee};"),
            ));
        }
    }
    Ok(())
}

async fn scan_database_acl(
    client: &Client,
    reach: &Reach,
    violations: &mut Vec<String>,
) -> Result<()> {
    let rows = catalog_rows(
        client,
        &format!(
            r#"
        SELECT quote_ident(d.datname), d.datacl IS NULL, a.privilege_type,
               COALESCE(quote_ident(gr.rolname), 'PUBLIC'), a.is_grantable
        FROM pg_catalog.pg_database d
        LEFT JOIN LATERAL aclexplode(d.datacl) a ON true
        LEFT JOIN pg_catalog.pg_roles gr ON gr.oid = a.grantee
        WHERE d.datname = current_database()
          AND (d.datacl IS NULL OR {})
        "#,
            reach.grantee_pred()
        ),
    )
    .await?;
    for row in &rows {
        let (db, is_default, privilege, grantee) =
            (cell(row, 0), cell(row, 1), cell(row, 2), cell(row, 3));
        if is_default == "t" {
            violations.push(violation(
                format!("database {db} has the implicit default ACL"),
                "permits creating temp tables by default (PUBLIC TEMP)",
                &format!("REVOKE TEMP ON DATABASE {db} FROM PUBLIC;"),
            ));
            continue;
        }
        if privilege != "CONNECT" {
            violations.push(violation(
                format!("{privilege} on database {db} granted to {grantee}"),
                if privilege == "TEMPORARY" {
                    "permits creating temp tables (revocable in PostgreSQL, so required)"
                } else {
                    "permits creating schemas in the database"
                },
                &format!("REVOKE {privilege} ON DATABASE {db} FROM {grantee};"),
            ));
        }
        if cell(row, 4) == "t" {
            violations.push(grant_option_violation(
                privilege,
                &format!("database {db} (held by {grantee})"),
                &format!("REVOKE GRANT OPTION FOR {privilege} ON DATABASE {db} FROM {grantee};"),
            ));
        }
    }
    Ok(())
}

async fn scan_parameter_acls(
    client: &Client,
    reach: &Reach,
    violations: &mut Vec<String>,
) -> Result<()> {
    let rows = catalog_rows(
        client,
        &format!(
            r#"
        SELECT p.parname, a.privilege_type, COALESCE(quote_ident(gr.rolname), 'PUBLIC'), a.is_grantable
        FROM pg_catalog.pg_parameter_acl p
        CROSS JOIN LATERAL aclexplode(p.paracl) a
        LEFT JOIN pg_catalog.pg_roles gr ON gr.oid = a.grantee
        WHERE {}
        "#,
            reach.grantee_pred()
        ),
    )
    .await?;
    for row in &rows {
        let (param, privilege, grantee) = (cell(row, 0), cell(row, 1), cell(row, 2));
        if let Some(reason) = parameter_acl_violation(privilege) {
            violations.push(violation(
                format!("{privilege} on parameter {param} granted to {grantee}"),
                reason,
                &format!("REVOKE {privilege} ON PARAMETER {param} FROM {grantee};"),
            ));
        }
        if cell(row, 3) == "t" {
            violations.push(grant_option_violation(
                privilege,
                &format!("parameter {param} (held by {grantee})"),
                &format!(
                    "REVOKE GRANT OPTION FOR {privilege} ON PARAMETER {param} FROM {grantee};"
                ),
            ));
        }
    }
    Ok(())
}

async fn scan_default_acls(
    client: &Client,
    reach: &Reach,
    violations: &mut Vec<String>,
) -> Result<()> {
    let rows = catalog_rows(
        client,
        &format!(
            r#"
        SELECT d.defaclobjtype, COALESCE(quote_ident(n.nspname), '<all schemas>'),
               a.privilege_type, COALESCE(quote_ident(gr.rolname), 'PUBLIC'), a.is_grantable
        FROM pg_catalog.pg_default_acl d
        LEFT JOIN pg_catalog.pg_namespace n ON n.oid = d.defaclnamespace
        CROSS JOIN LATERAL aclexplode(d.defaclacl) a
        LEFT JOIN pg_catalog.pg_roles gr ON gr.oid = a.grantee
        WHERE {}
        "#,
            reach.grantee_pred()
        ),
    )
    .await?;
    for row in &rows {
        let (objtype, schema, privilege, grantee) =
            (cell(row, 0), cell(row, 1), cell(row, 2), cell(row, 3));
        if let Some(reason) = default_acl_violation(objtype, privilege) {
            violations.push(violation(
                format!(
                    "default ACL grants {privilege} (objects of type '{objtype}' in {schema}) \
                     to {grantee}"
                ),
                &reason,
                "ALTER DEFAULT PRIVILEGES ... REVOKE ...;",
            ));
        }
        if cell(row, 4) == "t" {
            violations.push(grant_option_violation(
                privilege,
                &format!("future objects of type '{objtype}' in {schema} (held by {grantee})"),
                "ALTER DEFAULT PRIVILEGES ... REVOKE GRANT OPTION FOR ...;",
            ));
        }
    }

    let rows = catalog_rows(
        client,
        &format!(
            r#"
        SELECT quote_ident(n.nspname) || '.' || quote_ident(p.proname), a.privilege_type,
               COALESCE(quote_ident(gr.rolname), 'PUBLIC'), a.is_grantable
        FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        CROSS JOIN LATERAL aclexplode(p.proacl) a
        LEFT JOIN pg_catalog.pg_roles gr ON gr.oid = a.grantee
        WHERE p.proacl IS NOT NULL
          AND {}
          AND (a.privilege_type <> 'EXECUTE' OR a.is_grantable)
        "#,
            reach.grantee_pred()
        ),
    )
    .await?;
    for row in &rows {
        let (func, privilege, grantee) = (cell(row, 0), cell(row, 1), cell(row, 2));
        if privilege != "EXECUTE" {
            violations.push(violation(
                format!("{privilege} on function {func} granted to {grantee}"),
                "not a recognized read-only privilege",
                &format!("REVOKE {privilege} ON FUNCTION {func} FROM {grantee};"),
            ));
        }
        if cell(row, 3) == "t" {
            violations.push(grant_option_violation(
                privilege,
                &format!("function {func} (held by {grantee})"),
                &format!("REVOKE GRANT OPTION FOR {privilege} ON FUNCTION {func} FROM {grantee};"),
            ));
        }
    }
    Ok(())
}

fn grant_option_violation(privilege: &str, target: &str, fix: &str) -> String {
    violation(
        format!("{privilege} WITH GRANT OPTION on {target}"),
        "the holder can grant the privilege to other roles (privilege mutation)",
        fix,
    )
}

fn parameter_acl_violation(privilege: &str) -> Option<&'static str> {
    match privilege {
        "SET" => None,
        "ALTER SYSTEM" => {
            Some("permits writing persistent server configuration (postgresql.auto.conf)")
        }
        _ => Some("not a recognized read-only privilege"),
    }
}

fn relation_acl_violation(relkind: &str, name: &str, privilege: &str) -> Option<String> {
    if privilege == "SELECT" {
        return None;
    }

    if relkind == "v" && name == "pg_catalog.pg_settings" && privilege == "UPDATE" {
        return None;
    }
    Some(match (relkind, privilege) {
        ("S", "USAGE") | ("S", "UPDATE") => format!(
            "{privilege} on a sequence permits nextval()/setval(), which mutate persistent state"
        ),
        ("L", _) => format!("{privilege} permits writing the large object's data"),
        _ => format!("{privilege} permits mutation"),
    })
}

fn default_acl_violation(objtype: &str, privilege: &str) -> Option<String> {
    match (objtype, privilege) {
        ("r", "SELECT") | ("S", "SELECT") | ("f", "EXECUTE") | ("n", "USAGE") | ("T", "USAGE") => {
            None
        }
        _ => Some(format!(
            "{privilege} would apply to future objects of this type"
        )),
    }
}

fn predefined_role_violation(rolname: &str) -> Option<String> {
    if !rolname.starts_with("pg_") || SAFE_PREDEFINED_ROLES.contains(&rolname) {
        return None;
    }
    Some(
        "predefined-role powers never appear in any ACL; only read-only ones \
         (pg_read_all_data, pg_monitor, ...) are allowed"
            .to_string(),
    )
}

fn build_tls(config: &NetConfig) -> Result<rustls::ClientConfig> {
    let builder = rustls::ClientConfig::builder();
    if config.tls_insecure {
        return Ok(builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert::default()))
            .with_no_client_auth());
    }
    let mut roots = rustls::RootCertStore::empty();
    if let Some(ca) = &config.tls_ca {
        let mut added = 0usize;
        for cert in CertificateDer::pem_file_iter(ca)
            .with_context(|| format!("reading tls_ca {}", ca.display()))?
        {
            let cert = cert.with_context(|| format!("parsing tls_ca {}", ca.display()))?;
            roots
                .add(cert)
                .with_context(|| format!("adding certificate from tls_ca {}", ca.display()))?;
            added += 1;
        }
        ensure!(
            added > 0,
            "tls_ca {} contains no certificates",
            ca.display()
        );
    } else {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    Ok(builder.with_root_certificates(roots).with_no_client_auth())
}

#[derive(Debug)]
struct AcceptAnyServerCert {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl Default for AcceptAnyServerCert {
    fn default() -> Self {
        Self {
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Reach, default_acl_violation, misc_acl_violation, parameter_acl_violation,
        predefined_role_violation, relation_acl_violation,
    };

    #[test]
    fn relation_acl_allows_only_select() {
        assert!(relation_acl_violation("r", "app.t", "SELECT").is_none());
        assert!(relation_acl_violation("S", "app.s", "SELECT").is_none());
        assert!(relation_acl_violation("v", "app.v", "SELECT").is_none());
        for privilege in [
            "INSERT",
            "UPDATE",
            "DELETE",
            "TRUNCATE",
            "REFERENCES",
            "TRIGGER",
        ] {
            assert!(
                relation_acl_violation("r", "app.t", privilege).is_some(),
                "{privilege}"
            );
        }

        assert!(relation_acl_violation("S", "app.s", "USAGE").is_some());
        assert!(relation_acl_violation("S", "app.s", "UPDATE").is_some());

        assert!(relation_acl_violation("L", "large object 1", "SELECT").is_none());
        assert!(relation_acl_violation("L", "large object 1", "UPDATE").is_some());

        assert!(relation_acl_violation("v", "pg_catalog.pg_settings", "UPDATE").is_none());
        assert!(relation_acl_violation("v", "pg_catalog.pg_settings", "INSERT").is_some());
        assert!(relation_acl_violation("r", "pg_catalog.pg_settings", "UPDATE").is_some());
        assert!(relation_acl_violation("v", "app.pg_settings", "UPDATE").is_some());
    }

    #[test]
    fn default_acl_allowlist() {
        assert!(default_acl_violation("r", "SELECT").is_none());
        assert!(default_acl_violation("S", "SELECT").is_none());
        assert!(default_acl_violation("f", "EXECUTE").is_none());
        assert!(default_acl_violation("n", "USAGE").is_none());
        assert!(default_acl_violation("T", "USAGE").is_none());
        assert!(default_acl_violation("r", "INSERT").is_some());
        assert!(default_acl_violation("S", "USAGE").is_some());
        assert!(default_acl_violation("n", "CREATE").is_some());
    }

    #[test]
    fn misc_acl_allows_only_passive_usage() {
        assert!(misc_acl_violation("TYPE", "USAGE").is_none());
        assert!(misc_acl_violation("LANGUAGE", "USAGE").is_none());

        assert!(misc_acl_violation("FOREIGN DATA WRAPPER", "USAGE").is_some());
        assert!(misc_acl_violation("FOREIGN SERVER", "USAGE").is_some());
        assert!(misc_acl_violation("TABLESPACE", "CREATE").is_some());

        assert!(misc_acl_violation("TYPE", "ALTER").is_some());
    }

    #[test]
    fn parameter_acl_allows_only_session_local_set() {
        assert!(parameter_acl_violation("SET").is_none());
        assert!(parameter_acl_violation("ALTER SYSTEM").is_some());

        assert!(parameter_acl_violation("CONFIGURE").is_some());
    }

    #[test]
    fn reachability_predicate_tracks_server_version() {
        let modern = Reach {
            version_num: 160000,
        };
        assert!(modern.pred("oid").contains("'USAGE'"));
        assert!(modern.pred("oid").contains("'SET'"));

        assert!(!modern.set_pred("oid").contains("'USAGE'"));
        assert!(modern.set_pred("oid").contains("'SET'"));

        let legacy = Reach {
            version_num: 150004,
        };
        assert_eq!(
            legacy.pred("oid"),
            "pg_has_role(current_user, oid, 'MEMBER')"
        );
        assert!(legacy.has_parameter_acl());
        assert!(
            !Reach {
                version_num: 140011
            }
            .has_parameter_acl()
        );
    }

    #[test]
    fn predefined_roles_allowlist() {
        assert!(predefined_role_violation("pg_read_all_data").is_none());
        assert!(predefined_role_violation("pg_monitor").is_none());
        assert!(predefined_role_violation("app_readers").is_none());
        assert!(predefined_role_violation("pg_write_all_data").is_some());
        assert!(predefined_role_violation("pg_maintain").is_some());
        assert!(predefined_role_violation("pg_write_server_files").is_some());
        assert!(predefined_role_violation("pg_execute_server_program").is_some());

        assert!(predefined_role_violation("pg_brand_new_power").is_some());
    }
}
