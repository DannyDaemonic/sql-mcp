use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

fn secs_or_none(secs: u64) -> Option<Duration> {
    (secs != 0).then(|| Duration::from_secs(secs))
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub database: DatabaseConfig,

    #[serde(default)]
    http: Option<HttpInput>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
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
}

#[derive(Debug, Deserialize)]
struct HttpInput {
    listen: String,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    tokens: Option<Vec<String>>,
    #[serde(default = "default_max_sessions")]
    max_sessions: usize,
    #[serde(default = "default_session_idle_timeout")]
    session_idle_timeout: u64,
    #[serde(default = "default_eviction_grace")]
    eviction_grace: u64,
}

#[derive(Debug, Clone)]
pub struct HttpConfig {
    pub listen: std::net::SocketAddr,
    pub tokens: Vec<String>,
    pub max_sessions: usize,
    pub session_idle_timeout: Option<Duration>,
    pub eviction_grace: Option<Duration>,
}

impl Config {
    pub fn http(&self) -> Result<Option<HttpConfig>> {
        let Some(http) = &self.http else {
            return Ok(None);
        };
        let mut tokens: Vec<String> = match (&http.token, &http.tokens) {
            (Some(_), Some(_)) => {
                bail!("http.token and http.tokens are both set; pick one")
            }
            (Some(token), None) => vec![token.clone()],
            (None, Some(list)) => list.clone(),
            (None, None) => Vec::new(),
        };

        let listen: std::net::SocketAddr = http.listen.parse().with_context(|| {
            format!(
                "http.listen {:?} is not an IP:port address (e.g. \"127.0.0.1:8650\")",
                http.listen
            )
        })?;

        if tokens.is_empty() {
            bail!(
                "[http] is configured but no bearer token is configured; HTTP always \
                 requires auth (stdio is the no-auth local transport). Generate one: \
                 openssl rand -hex 32, then set token = \"<value>\""
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
            bail!("http.tokens contains duplicates; each agent should get its own token");
        }
        if http.max_sessions == 0 {
            bail!("http.max_sessions must be at least 1");
        }
        if http.session_idle_timeout == 0 && http.eviction_grace == 0 {
            bail!(
                "http.session_idle_timeout and http.eviction_grace cannot both be 0: idle sessions \
                 would never be reclaimed, locking out new sessions once max_sessions is full; set \
                 at least one nonzero"
            );
        }

        Ok(Some(HttpConfig {
            listen,
            tokens,
            max_sessions: http.max_sessions,
            session_idle_timeout: secs_or_none(http.session_idle_timeout),
            eviction_grace: secs_or_none(http.eviction_grace),
        }))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "driver", rename_all = "lowercase")]
pub enum BackendConfig {
    Mysql(NetConfig),
    Mariadb(NetConfig),
    Postgres(NetConfig),
    Sqlite(SqliteConfig),
}

#[derive(Debug, Clone, Deserialize)]
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
                "path = \":memory:\" contradicts read-only mode: this database is created \
                 empty when the process starts and is gone when it stops, so there is never \
                 any pre-existing data for a read-only connection to serve"
            );
        }
        if self.is_memory() && self.create {
            bail!("create = true is meaningless with path = \":memory:\"; remove it");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
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

fn default_max_sessions() -> usize {
    16
}

fn default_session_idle_timeout() -> u64 {
    28_800
}

fn default_eviction_grace() -> u64 {
    300
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

    config.database.read_only = config.database.read_only || force_read_only;

    match &config.database.backend {
        BackendConfig::Mysql(net) | BackendConfig::Mariadb(net) | BackendConfig::Postgres(net) => {
            net.validate()?
        }
        BackendConfig::Sqlite(sqlite) => sqlite.validate(config.database.read_only)?,
    }

    config.http()?;

    Ok(config)
}

const ROOT_KEYS: &[&str] = &["database", "http"];

const DATABASE_KEYS: &[&str] = &[
    "driver",
    "read_only",
    "max_rows",
    "max_cell_bytes",
    "max_response_bytes",
];

const HTTP_KEYS: &[&str] = &[
    "listen",
    "token",
    "tokens",
    "max_sessions",
    "session_idle_timeout",
    "eviction_grace",
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

#[derive(Clone, Copy, Eq, PartialEq)]
enum ConfigSection {
    Root,
    Database,
    Http,
}

impl ConfigSection {
    fn name(self) -> &'static str {
        match self {
            ConfigSection::Root => "config",
            ConfigSection::Database => "database",
            ConfigSection::Http => "http",
        }
    }

    fn destination(self, key: &str) -> String {
        match self {
            ConfigSection::Root => format!("the top level as [{key}]"),
            ConfigSection::Database => "[database]".to_string(),
            ConfigSection::Http => "[http]".to_string(),
        }
    }
}

const SECTIONS: &[(ConfigSection, &[&[&str]])] = &[
    (
        ConfigSection::Database,
        &[DATABASE_KEYS, NET_KEYS, SQLITE_KEYS],
    ),
    (ConfigSection::Http, &[HTTP_KEYS]),
    (ConfigSection::Root, &[ROOT_KEYS]),
];

fn reject_unknown_keys(table: &toml::Table) -> Result<()> {
    reject_keys(ConfigSection::Root, table, ROOT_KEYS)?;
    let Some(database_value) = table.get("database") else {
        bail!("config is missing the required [database] table");
    };
    let database = database_value.as_table().context(
        "top-level `database` must be a [database] table; if this is a database name, put \
         `database = ...` under [database]",
    )?;
    let driver = database.get("driver").and_then(|v| v.as_str()).context(
        "[database] is missing the required `driver` key (\"mysql\", \"mariadb\", \
         \"postgres\", or \"sqlite\")",
    )?;
    let backend_keys: &[&str] = match driver {
        "mysql" | "mariadb" | "postgres" => NET_KEYS,
        "sqlite" => SQLITE_KEYS,
        other => {
            bail!("unknown driver {other:?}; supported drivers: mysql, mariadb, postgres, sqlite")
        }
    };

    let allowed: Vec<&str> = DATABASE_KEYS.iter().chain(backend_keys).copied().collect();
    reject_keys(ConfigSection::Database, database, &allowed)?;
    if let Some(http) = table.get("http") {
        let http = http
            .as_table()
            .context("http must be a TOML table (`[http]`)")?;
        reject_keys(ConfigSection::Http, http, HTTP_KEYS)?;
    }
    Ok(())
}

fn reject_keys(section: ConfigSection, table: &toml::Table, known: &[&str]) -> Result<()> {
    for key in table.keys() {
        let key = key.as_str();
        if known.contains(&key) {
            continue;
        }
        if let Some(message) = misplaced_key_message(section, key) {
            bail!("{message}");
        }
        let suggestion = known
            .iter()
            .min_by_key(|known| edit_distance(key, known))
            .filter(|known| edit_distance(key, known) <= 2)
            .map(|known| format!(" (did you mean {known:?}?)"))
            .unwrap_or_default();
        bail!(
            "unknown {} key {key:?}{suggestion}; unknown keys are rejected so a typo'd \
             setting can never be silently ignored",
            section.name()
        );
    }
    Ok(())
}

fn misplaced_key_message(section: ConfigSection, key: &str) -> Option<String> {
    let belongs_here = |s: ConfigSection| {
        SECTIONS
            .iter()
            .find(|(candidate, _)| *candidate == s)
            .is_some_and(|(_, groups)| groups.iter().any(|group| group.contains(&key)))
    };
    if belongs_here(section) {
        return None;
    }

    let (home, _) = SECTIONS
        .iter()
        .find(|(s, groups)| *s != section && groups.iter().any(|group| group.contains(&key)))?;
    Some(format!(
        "`{key}` belongs under {}; move it there",
        home.destination(key)
    ))
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
        "The config file has a required [database] table holding driver\n",
        "(mysql/mariadb/postgres/sqlite) plus its settings:\n",
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
    fn parses_database_and_http_tables() {
        let config: Config = toml::from_str(
            r#"
            [database]
            driver = "mariadb"
            host = "127.0.0.1"
            port = 3307
            user = "ro"
            password = "secret"
            database = "app"
            read_only = true
            max_rows = 50
            tls = true

            [http]
            listen = "127.0.0.1:8650"
            token = "0123456789abcdef0123456789abcdef"
            "#,
        )
        .unwrap();
        assert!(config.database.read_only);
        assert_eq!(config.database.max_rows, 50);
        let BackendConfig::Mariadb(net) = &config.database.backend else {
            panic!("wrong backend");
        };
        assert_eq!(net.port, Some(3307));
        assert!(net.tls);
        assert_eq!(net.database.as_deref(), Some("app"));
        let http = config.http().unwrap().unwrap();
        assert_eq!(http.listen.port(), 8650);
        assert_eq!(http.max_sessions, 16);
        assert_eq!(http.session_idle_timeout.unwrap().as_secs(), 28_800);
        assert_eq!(http.eviction_grace.unwrap().as_secs(), 300);
    }

    #[test]
    fn defaults_apply() {
        let config: Config =
            toml::from_str("[database]\ndriver = \"mysql\"\nhost = \"h\"\nuser = \"u\"").unwrap();
        assert!(!config.database.read_only);
        assert_eq!(config.database.max_rows, 1000);
        assert_eq!(config.database.max_cell_bytes, 16 * 1024);
        assert_eq!(config.database.max_response_bytes, 256 * 1024);
        let BackendConfig::Mysql(net) = &config.database.backend else {
            panic!("wrong backend");
        };
        assert_eq!(net.port, None);
        assert!(!net.tls);
        assert!(config.http().unwrap().is_none());
    }

    #[test]
    fn parses_sqlite_config() {
        let config: Config = toml::from_str(
            "[database]\ndriver = \"sqlite\"\npath = \"/tmp/app.db\"\ncreate = true",
        )
        .unwrap();
        let BackendConfig::Sqlite(sqlite) = &config.database.backend else {
            panic!("wrong backend");
        };
        assert_eq!(sqlite.path.to_str(), Some("/tmp/app.db"));
        assert!(sqlite.create);
        assert!(!sqlite.is_memory());

        let config: Config =
            toml::from_str("[database]\ndriver = \"sqlite\"\npath = \":memory:\"").unwrap();
        let BackendConfig::Sqlite(sqlite) = &config.database.backend else {
            panic!("wrong backend");
        };
        assert!(!sqlite.create);
        assert!(sqlite.is_memory());
    }

    #[test]
    fn parses_postgres_config() {
        let config: Config = toml::from_str(
            "[database]\ndriver = \"postgres\"\nhost = \"db.example\"\nuser = \"ro\"\ndatabase = \"app\"",
        )
        .unwrap();
        let BackendConfig::Postgres(net) = &config.database.backend else {
            panic!("wrong backend");
        };
        assert_eq!(net.port, None);
        assert_eq!(net.database.as_deref(), Some("app"));

        let table: toml::Table = toml::from_str(
            "[database]\ndriver = \"postgres\"\nhost = \"h\"\nuser = \"u\"\ntls = true\nport = 5433",
        )
        .unwrap();
        assert!(super::reject_unknown_keys(&table).is_ok());
        let table: toml::Table = toml::from_str(
            "[database]\ndriver = \"postgres\"\nhost = \"h\"\nuser = \"u\"\npath = \"/a.db\"",
        )
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
        let table: toml::Table = toml::from_str(
            "[database]\ndriver = \"sqlite\"\npath = \"/a.db\"\nhost = \"127.0.0.1\"",
        )
        .unwrap();
        let err = super::reject_unknown_keys(&table).unwrap_err().to_string();
        assert!(err.contains("\"host\""), "{err}");

        let table: toml::Table =
            toml::from_str("[database]\ndriver = \"sqlite\"\npath = \"/a.db\"\ndatabase = \"app\"")
                .unwrap();
        let err = super::reject_unknown_keys(&table).unwrap_err().to_string();
        assert!(err.contains("unknown database key \"database\""), "{err}");

        let table: toml::Table = toml::from_str(
            "[database]\ndriver = \"mysql\"\nhost = \"h\"\nuser = \"u\"\npath = \"/a.db\"",
        )
        .unwrap();
        assert!(super::reject_unknown_keys(&table).is_err());

        let table: toml::Table =
            toml::from_str("[database]\ndriver = \"sqlite\"\npth = \"/a.db\"").unwrap();
        let err = super::reject_unknown_keys(&table).unwrap_err().to_string();
        assert!(err.contains("did you mean \"path\""), "{err}");
    }

    #[test]
    fn http_config_validation() {
        let cfg = |extra: &str| -> Config {
            toml::from_str(&format!(
                "[database]\ndriver = \"sqlite\"\npath = \"/a.db\"\n{extra}"
            ))
            .unwrap()
        };
        let token = "0123456789abcdef0123456789abcdef";

        assert!(cfg("").http().unwrap().is_none());

        let http = cfg(&format!(
            "[http]\nlisten = \"127.0.0.1:8650\"\ntoken = \"{token}\"\n\
             max_sessions = 3\nsession_idle_timeout = 0\neviction_grace = 300"
        ))
        .http()
        .unwrap()
        .unwrap();
        assert_eq!(http.listen.port(), 8650);
        assert_eq!(http.tokens.len(), 1);
        assert_eq!(http.max_sessions, 3);
        assert!(http.session_idle_timeout.is_none());
        assert_eq!(http.eviction_grace.unwrap().as_secs(), 300);

        let http = cfg(&format!(
            "[http]\nlisten = \"127.0.0.1:8650\"\ntoken = \"{token}\"\n\
             session_idle_timeout = 60\neviction_grace = 0"
        ))
        .http()
        .unwrap()
        .unwrap();
        assert_eq!(http.session_idle_timeout.unwrap().as_secs(), 60);
        assert!(http.eviction_grace.is_none());

        let err = cfg(&format!(
            "[http]\nlisten = \"127.0.0.1:8650\"\ntoken = \"{token}\"\n\
             session_idle_timeout = 0\neviction_grace = 0"
        ))
        .http()
        .unwrap_err()
        .to_string();
        assert!(err.contains("cannot both be 0"), "{err}");

        let http = cfg(&format!(
            "[http]\nlisten = \"127.0.0.1:0\"\ntokens = [\"{token}\", \"{token}2\"]"
        ))
        .http()
        .unwrap()
        .unwrap();
        assert_eq!(http.tokens.len(), 2);

        let err = cfg("[http]\nlisten = \"127.0.0.1:8650\"")
            .http()
            .unwrap_err()
            .to_string();
        assert!(err.contains("openssl rand"), "{err}");

        assert!(
            toml::from_str::<Config>(&format!(
                "[database]\ndriver = \"sqlite\"\npath = \"/a.db\"\n[http]\ntoken = \"{token}\""
            ))
            .is_err()
        );

        assert!(
            cfg(&format!(
                "[http]\nlisten = \"127.0.0.1:1\"\ntoken = \"{token}\"\ntokens = [\"{token}\"]"
            ))
            .http()
            .is_err()
        );

        assert!(
            cfg("[http]\nlisten = \"127.0.0.1:1\"\ntoken = \"short\"")
                .http()
                .is_err()
        );
        assert!(
            cfg(&format!(
                "[http]\nlisten = \"127.0.0.1:1\"\ntokens = [\"{token}\", \"{token}\"]"
            ))
            .http()
            .is_err()
        );
        assert!(
            cfg(&format!(
                "[http]\nlisten = \"localhost:8650\"\ntoken = \"{token}\""
            ))
            .http()
            .is_err()
        );
        assert!(
            cfg(&format!(
                "[http]\nlisten = \"127.0.0.1:1\"\ntoken = \"{token}\"\nmax_sessions = 0"
            ))
            .http()
            .is_err()
        );
    }

    #[test]
    fn unknown_keys_are_rejected_with_suggestion() {
        let table: toml::Table = toml::from_str(
            "[database]\ndriver = \"mysql\"\nhost = \"h\"\nuser = \"u\"\nread_onyl = true",
        )
        .unwrap();
        let err = super::reject_unknown_keys(&table).unwrap_err().to_string();
        assert!(err.contains("read_onyl"), "{err}");
        assert!(err.contains("did you mean \"read_only\""), "{err}");

        let table: toml::Table = toml::from_str(
            "[database]\ndriver = \"mysql\"\nhost = \"h\"\nuser = \"u\"\ntls_insecue = true",
        )
        .unwrap();
        let err = super::reject_unknown_keys(&table).unwrap_err().to_string();
        assert!(err.contains("did you mean \"tls_insecure\""), "{err}");

        let flat: toml::Table = toml::from_str("driver = \"sqlite\"\npath = \":memory:\"").unwrap();
        let err = super::reject_unknown_keys(&flat).unwrap_err().to_string();
        assert!(err.contains("`driver` belongs under [database]"), "{err}");
    }

    #[test]
    fn misplaced_keys_report_destination() {
        let err = |input: &str| -> String {
            let table: toml::Table = toml::from_str(input).unwrap();
            super::reject_unknown_keys(&table).unwrap_err().to_string()
        };

        let message = err("host = \"h\"");
        assert!(
            message.contains("`host` belongs under [database]"),
            "{message}"
        );

        let message = err(r#"
            [database]
            driver = "sqlite"
            path = ":memory:"
            token = "0123456789abcdef0123456789abcdef"
            "#);
        assert!(
            message.contains("`token` belongs under [http]"),
            "{message}"
        );

        let message = err(r#"
            [database]
            driver = "sqlite"
            path = ":memory:"

            [http]
            listen = "127.0.0.1:8650"
            host = "h"
            "#);
        assert!(
            message.contains("`host` belongs under [database]"),
            "{message}"
        );

        let message = err("database = \"app\"");
        assert!(
            message.contains("top-level `database` must be a [database] table"),
            "{message}"
        );

        let message = err(r#"
            [database]
            driver = "postgres"
            host = "h"
            user = "u"

            [http]
            listen = "127.0.0.1:8650"
            token = "0123456789abcdef0123456789abcdef"
            database = "app"
            "#);
        assert!(
            message.contains("`database` belongs under [database]"),
            "{message}"
        );
    }

    #[test]
    fn known_keys_pass_and_missing_driver_fails() {
        let table: toml::Table = toml::from_str(
            "[database]\ndriver = \"mariadb\"\nhost = \"h\"\nuser = \"u\"\nmax_response_bytes = 1024\ntls = true",
        )
        .unwrap();
        assert!(super::reject_unknown_keys(&table).is_ok());

        let table: toml::Table = toml::from_str("host = \"h\"").unwrap();
        assert!(super::reject_unknown_keys(&table).is_err());
    }

    #[test]
    fn unknown_driver_is_rejected() {
        assert!(
            toml::from_str::<Config>("[database]\ndriver = \"oracle\"\nhost = \"h\"\nuser = \"u\"")
                .is_err()
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
