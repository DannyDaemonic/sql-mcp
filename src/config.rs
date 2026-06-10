use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(flatten)]
    pub backend: BackendConfig,

    #[serde(default)]
    pub read_only: bool,

    #[serde(default = "default_max_rows")]
    pub max_rows: u64,

    #[serde(default = "default_max_cell_bytes")]
    pub max_cell_bytes: u64,

    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: u64,

    #[serde(default)]
    http_listen: Option<String>,

    #[serde(default)]
    http_token: Option<String>,

    #[serde(default)]
    http_tokens: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct HttpConfig {
    pub listen: std::net::SocketAddr,
    pub tokens: Vec<String>,
}

impl Config {
    pub fn http(&self) -> Result<Option<HttpConfig>> {
        let mut tokens: Vec<String> = match (&self.http_token, &self.http_tokens) {
            (Some(_), Some(_)) => {
                bail!("http_token and http_tokens are both set; pick one")
            }
            (Some(token), None) => vec![token.clone()],
            (None, Some(list)) => list.clone(),
            (None, None) => Vec::new(),
        };

        let Some(listen) = &self.http_listen else {
            if !tokens.is_empty() {
                bail!(
                    "http_token(s) is set but http_listen is not; add \
                     http_listen = \"127.0.0.1:8650\" (or remove the token)"
                );
            }
            return Ok(None);
        };

        let listen: std::net::SocketAddr = listen.parse().with_context(|| {
            format!("http_listen {listen:?} is not an IP:port address (e.g. \"127.0.0.1:8650\")")
        })?;

        if tokens.is_empty() {
            bail!(
                "http_listen is set but no bearer token is configured; HTTP always \
                 requires auth (stdio is the no-auth local transport). Generate one: \
                 openssl rand -hex 32, then set http_token = \"<value>\""
            );
        }
        for token in &tokens {
            if token.len() < 16 {
                bail!(
                    "an http token is shorter than 16 characters; refusing a guessable \
                     credential (generate one: openssl rand -hex 32)"
                );
            }
        }
        let before = tokens.len();
        tokens.sort();
        tokens.dedup();
        if tokens.len() != before {
            bail!("http_tokens contains duplicates; each agent should get its own token");
        }

        Ok(Some(HttpConfig { listen, tokens }))
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "driver", rename_all = "lowercase")]
pub enum BackendConfig {
    Mysql(NetConfig),
    Mariadb(NetConfig),
    Postgres(NetConfig),
    Sqlite(SqliteConfig),
}

impl BackendConfig {
    pub fn name(&self) -> &'static str {
        match self {
            BackendConfig::Mysql(_) => "mysql",
            BackendConfig::Mariadb(_) => "mariadb",
            BackendConfig::Postgres(_) => "postgres",
            BackendConfig::Sqlite(_) => "sqlite",
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SqliteConfig {
    pub path: PathBuf,

    #[serde(default)]
    pub create: bool,
}

impl SqliteConfig {
    pub fn is_memory(&self) -> bool {
        self.path.as_os_str() == ":memory:"
    }

    fn validate(&self, read_only: bool) -> Result<()> {
        if self.create && read_only {
            bail!(
                "create = true contradicts read-only mode: a read-only connection \
                 cannot create a database; pick one"
            );
        }
        if self.is_memory() && read_only {
            bail!(
                "path = \":memory:\" contradicts read-only mode: a fresh in-memory \
                 database is empty, so a read-only connection to it can answer nothing"
            );
        }
        if self.is_memory() && self.create {
            bail!("create = true is meaningless with path = \":memory:\"; remove it");
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct NetConfig {
    pub host: String,

    #[serde(default)]
    pub port: Option<u16>,
    pub user: String,
    #[serde(default)]
    pub password: String,

    #[serde(default)]
    pub database: Option<String>,

    #[serde(default)]
    pub tls: bool,

    #[serde(default)]
    pub tls_ca: Option<PathBuf>,

    #[serde(default)]
    pub tls_insecure: bool,
}

impl NetConfig {
    fn validate(&self) -> Result<()> {
        if !self.tls && self.tls_ca.is_some() {
            bail!("tls_ca is set but tls = false; set tls = true (or remove tls_ca)");
        }
        if !self.tls && self.tls_insecure {
            bail!(
                "tls_insecure = true but tls = false: the connection would be plaintext, \
                 not insecure-TLS; set tls = true (or remove tls_insecure)"
            );
        }
        if self.tls_insecure && self.tls_ca.is_some() {
            bail!(
                "tls_ca and tls_insecure are mutually exclusive: tls_insecure skips the \
                 certificate verification tls_ca would configure; pick one"
            );
        }
        Ok(())
    }
}

fn default_max_rows() -> u64 {
    1000
}

fn default_max_cell_bytes() -> u64 {
    16 * 1024
}

fn default_max_response_bytes() -> u64 {
    256 * 1024
}

pub fn load() -> Result<Config> {
    let mut path: Option<PathBuf> = std::env::var_os("SQL_MCP_CONFIG").map(PathBuf::from);
    let mut force_read_only = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--read-only" | "--ro" => force_read_only = true,
            "-c" | "--config" => {
                let v = args.next().context("--config requires a path argument")?;
                path = Some(PathBuf::from(v));
            }
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other if other.starts_with("--config=") => {
                path = Some(PathBuf::from(&other["--config=".len()..]));
            }
            other => bail!("unknown argument: {other} (try --help)"),
        }
    }

    if let Ok(mode) = std::env::var("SQL_MCP_MODE") {
        match mode.as_str() {
            "ro" | "read-only" => force_read_only = true,
            other => bail!(
                "SQL_MCP_MODE has unrecognized value {other:?}; valid values are \
                 \"ro\" or \"read-only\" (refusing to guess what you meant)"
            ),
        }
    }

    let path = path.unwrap_or_else(|| PathBuf::from("sql-mcp.toml"));
    check_permissions(&path)?;

    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading config file {}", path.display()))?;
    let table: toml::Table =
        toml::from_str(&text).with_context(|| format!("parsing config file {}", path.display()))?;
    reject_unknown_keys(&table)
        .with_context(|| format!("validating config file {}", path.display()))?;
    let mut config: Config = toml::Value::Table(table)
        .try_into()
        .with_context(|| format!("parsing config file {}", path.display()))?;

    config.read_only = config.read_only || force_read_only;

    match &config.backend {
        BackendConfig::Mysql(net) | BackendConfig::Mariadb(net) | BackendConfig::Postgres(net) => {
            net.validate()?
        }
        BackendConfig::Sqlite(sqlite) => sqlite.validate(config.read_only)?,
    }

    config.http()?;

    Ok(config)
}

const COMMON_KEYS: &[&str] = &[
    "driver",
    "read_only",
    "max_rows",
    "max_cell_bytes",
    "max_response_bytes",
    "http_listen",
    "http_token",
    "http_tokens",
];

const NET_KEYS: &[&str] = &[
    "host",
    "port",
    "user",
    "password",
    "database",
    "tls",
    "tls_ca",
    "tls_insecure",
];

const SQLITE_KEYS: &[&str] = &["path", "create"];

fn reject_unknown_keys(table: &toml::Table) -> Result<()> {
    let driver = table.get("driver").and_then(|v| v.as_str()).context(
        "config is missing the required `driver` key (\"mysql\", \"mariadb\", \"postgres\", \
         or \"sqlite\")",
    )?;
    let backend_keys: &[&str] = match driver {
        "mysql" | "mariadb" | "postgres" => NET_KEYS,
        "sqlite" => SQLITE_KEYS,
        other => {
            bail!("unknown driver {other:?}; supported drivers: mysql, mariadb, postgres, sqlite")
        }
    };

    for key in table.keys() {
        let key = key.as_str();
        if COMMON_KEYS.contains(&key) || backend_keys.contains(&key) {
            continue;
        }
        let suggestion = COMMON_KEYS
            .iter()
            .chain(backend_keys)
            .min_by_key(|known| edit_distance(key, known))
            .filter(|known| edit_distance(key, known) <= 2)
            .map(|known| format!(" (did you mean {known:?}?)"))
            .unwrap_or_default();
        bail!(
            "unknown config key {key:?}{suggestion}; unknown keys are rejected so a \
             typo'd setting can never be silently ignored"
        );
    }
    Ok(())
}

fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut current = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            current.push((prev[j] + cost).min(prev[j + 1] + 1).min(current[j] + 1));
        }
        prev = current;
    }
    prev[b.len()]
}

#[cfg(unix)]
fn check_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let meta = std::fs::metadata(path)
        .with_context(|| format!("config file {} not found or unreadable", path.display()))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "config file {} is accessible by group/other (mode {:o}); it holds a password.\n\
             Fix it: chmod 600 {}",
            path.display(),
            mode,
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn print_help() {
    eprintln!(concat!(
        "sql-mcp: minimal MCP server exposing a single sql_exec(sql) tool.\n",
        "\n",
        "USAGE:\n",
        "    sql-mcp [--config <path>] [--read-only]\n",
        "\n",
        "OPTIONS:\n",
        "    -c, --config <path>   Path to the TOML config file.\n",
        "                          Default: ./sql-mcp.toml or $SQL_MCP_CONFIG.\n",
        "                          The file must be mode 0600.\n",
        "        --read-only       Refuse to start unless the DB account is provably\n",
        "                          incapable of mutation. Also via SQL_MCP_MODE=ro.\n",
        "    -h, --help            Show this help.\n",
        "\n",
        "The config file holds driver (mysql/mariadb/postgres/sqlite) plus its settings:\n",
        "host/port/user/password/database for network backends, or path (and optional\n",
        "create = true, or path = \":memory:\") for sqlite. Optional read_only = true and\n",
        "output caps (max_rows, max_cell_bytes, max_response_bytes; 0 disables). Unknown\n",
        "keys are an error. Credentials live only in this 0600 file, never in env vars.",
    ));
}

#[cfg(test)]
mod tests {
    use super::{BackendConfig, Config};

    #[test]
    fn parses_flat_toml_into_tagged_backend() {
        let config: Config = toml::from_str(
            r#"
            driver = "mariadb"
            host = "127.0.0.1"
            port = 3307
            user = "ro"
            password = "secret"
            database = "app"
            read_only = true
            max_rows = 50
            tls = true
            "#,
        )
        .unwrap();
        assert!(config.read_only);
        assert_eq!(config.max_rows, 50);
        let BackendConfig::Mariadb(net) = &config.backend else {
            panic!("wrong backend");
        };
        assert_eq!(net.port, Some(3307));
        assert!(net.tls);
        assert_eq!(net.database.as_deref(), Some("app"));
    }

    #[test]
    fn defaults_apply() {
        let config: Config =
            toml::from_str("driver = \"mysql\"\nhost = \"h\"\nuser = \"u\"").unwrap();
        assert!(!config.read_only);
        assert_eq!(config.max_rows, 1000);
        assert_eq!(config.max_cell_bytes, 16 * 1024);
        assert_eq!(config.max_response_bytes, 256 * 1024);
        let BackendConfig::Mysql(net) = &config.backend else {
            panic!("wrong backend");
        };
        assert_eq!(net.port, None);
        assert!(!net.tls);
    }

    #[test]
    fn parses_sqlite_config() {
        let config: Config =
            toml::from_str("driver = \"sqlite\"\npath = \"/tmp/app.db\"\ncreate = true").unwrap();
        let BackendConfig::Sqlite(sqlite) = &config.backend else {
            panic!("wrong backend");
        };
        assert_eq!(sqlite.path.to_str(), Some("/tmp/app.db"));
        assert!(sqlite.create);
        assert!(!sqlite.is_memory());

        let config: Config = toml::from_str("driver = \"sqlite\"\npath = \":memory:\"").unwrap();
        let BackendConfig::Sqlite(sqlite) = &config.backend else {
            panic!("wrong backend");
        };
        assert!(!sqlite.create);
        assert!(sqlite.is_memory());
    }

    #[test]
    fn parses_postgres_config() {
        let config: Config = toml::from_str(
            "driver = \"postgres\"\nhost = \"db.example\"\nuser = \"ro\"\ndatabase = \"app\"",
        )
        .unwrap();
        let BackendConfig::Postgres(net) = &config.backend else {
            panic!("wrong backend");
        };
        assert_eq!(net.port, None);
        assert_eq!(net.database.as_deref(), Some("app"));

        let table: toml::Table = toml::from_str(
            "driver = \"postgres\"\nhost = \"h\"\nuser = \"u\"\ntls = true\nport = 5433",
        )
        .unwrap();
        assert!(super::reject_unknown_keys(&table).is_ok());
        let table: toml::Table =
            toml::from_str("driver = \"postgres\"\nhost = \"h\"\nuser = \"u\"\npath = \"/a.db\"")
                .unwrap();
        let err = super::reject_unknown_keys(&table).unwrap_err().to_string();
        assert!(err.contains("\"path\""), "{err}");
    }

    #[test]
    fn sqlite_contradictions_are_rejected() {
        let sqlite = |s: &str| -> super::SqliteConfig { toml::from_str(s).unwrap() };
        assert!(
            sqlite("path = \"/a.db\"\ncreate = true")
                .validate(true)
                .is_err()
        );
        assert!(sqlite("path = \":memory:\"").validate(true).is_err());
        assert!(
            sqlite("path = \":memory:\"\ncreate = true")
                .validate(false)
                .is_err()
        );
        assert!(
            sqlite("path = \"/a.db\"\ncreate = true")
                .validate(false)
                .is_ok()
        );
        assert!(sqlite("path = \"/a.db\"").validate(true).is_ok());
    }

    #[test]
    fn backend_keys_do_not_leak_across_drivers() {
        let table: toml::Table =
            toml::from_str("driver = \"sqlite\"\npath = \"/a.db\"\nhost = \"127.0.0.1\"").unwrap();
        let err = super::reject_unknown_keys(&table).unwrap_err().to_string();
        assert!(err.contains("\"host\""), "{err}");

        let table: toml::Table =
            toml::from_str("driver = \"mysql\"\nhost = \"h\"\nuser = \"u\"\npath = \"/a.db\"")
                .unwrap();
        assert!(super::reject_unknown_keys(&table).is_err());

        let table: toml::Table = toml::from_str("driver = \"sqlite\"\npth = \"/a.db\"").unwrap();
        let err = super::reject_unknown_keys(&table).unwrap_err().to_string();
        assert!(err.contains("did you mean \"path\""), "{err}");
    }

    #[test]
    fn http_config_validation() {
        let cfg = |extra: &str| -> Config {
            toml::from_str(&format!("driver = \"sqlite\"\npath = \"/a.db\"\n{extra}")).unwrap()
        };
        let token = "0123456789abcdef0123456789abcdef";

        assert!(cfg("").http().unwrap().is_none());

        let http = cfg(&format!(
            "http_listen = \"127.0.0.1:8650\"\nhttp_token = \"{token}\""
        ))
        .http()
        .unwrap()
        .unwrap();
        assert_eq!(http.listen.port(), 8650);
        assert_eq!(http.tokens.len(), 1);
        let http = cfg(&format!(
            "http_listen = \"127.0.0.1:0\"\nhttp_tokens = [\"{token}\", \"{token}2\"]"
        ))
        .http()
        .unwrap()
        .unwrap();
        assert_eq!(http.tokens.len(), 2);

        let err = cfg("http_listen = \"127.0.0.1:8650\"")
            .http()
            .unwrap_err()
            .to_string();
        assert!(err.contains("openssl rand"), "{err}");

        assert!(cfg(&format!("http_token = \"{token}\"")).http().is_err());

        assert!(
            cfg(&format!(
                "http_listen = \"127.0.0.1:1\"\nhttp_token = \"{token}\"\nhttp_tokens = [\"{token}\"]"
            ))
            .http()
            .is_err()
        );

        assert!(
            cfg("http_listen = \"127.0.0.1:1\"\nhttp_token = \"short\"")
                .http()
                .is_err()
        );
        assert!(
            cfg(&format!(
                "http_listen = \"127.0.0.1:1\"\nhttp_tokens = [\"{token}\", \"{token}\"]"
            ))
            .http()
            .is_err()
        );
        assert!(
            cfg(&format!(
                "http_listen = \"localhost:8650\"\nhttp_token = \"{token}\""
            ))
            .http()
            .is_err()
        );
    }

    #[test]
    fn unknown_keys_are_rejected_with_suggestion() {
        let table: toml::Table =
            toml::from_str("driver = \"mysql\"\nhost = \"h\"\nuser = \"u\"\nread_onyl = true")
                .unwrap();
        let err = super::reject_unknown_keys(&table).unwrap_err().to_string();
        assert!(err.contains("read_onyl"), "{err}");
        assert!(err.contains("did you mean \"read_only\""), "{err}");

        let table: toml::Table =
            toml::from_str("driver = \"mysql\"\nhost = \"h\"\nuser = \"u\"\ntls_insecue = true")
                .unwrap();
        let err = super::reject_unknown_keys(&table).unwrap_err().to_string();
        assert!(err.contains("did you mean \"tls_insecure\""), "{err}");
    }

    #[test]
    fn known_keys_pass_and_missing_driver_fails() {
        let table: toml::Table = toml::from_str(
            "driver = \"mariadb\"\nhost = \"h\"\nuser = \"u\"\nmax_response_bytes = 1024\ntls = true",
        )
        .unwrap();
        assert!(super::reject_unknown_keys(&table).is_ok());

        let table: toml::Table = toml::from_str("host = \"h\"").unwrap();
        assert!(super::reject_unknown_keys(&table).is_err());
    }

    #[test]
    fn unknown_driver_is_rejected() {
        assert!(
            toml::from_str::<Config>("driver = \"oracle\"\nhost = \"h\"\nuser = \"u\"").is_err()
        );
    }

    #[test]
    fn contradictory_tls_is_rejected() {
        let net = |s: &str| -> super::NetConfig {
            toml::from_str(&format!("host = \"h\"\nuser = \"u\"\n{s}")).unwrap()
        };
        assert!(net("tls_insecure = true").validate().is_err());
        assert!(net("tls_ca = \"/ca.pem\"").validate().is_err());
        assert!(
            net("tls = true\ntls_ca = \"/ca.pem\"\ntls_insecure = true")
                .validate()
                .is_err()
        );
        assert!(net("tls = true\ntls_ca = \"/ca.pem\"").validate().is_ok());
        assert!(net("tls = true\ntls_insecure = true").validate().is_ok());
        assert!(net("").validate().is_ok());
    }
}
