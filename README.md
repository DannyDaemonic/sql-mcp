# sql-mcp

A deliberately tiny [MCP](https://modelcontextprotocol.io) server that exposes
**one** tool to your SQL database:

```
sql_exec(sql) -> { result_sets: [ {columns, rows} | {rows_affected, last_insert_id} ] }
```

That's the whole surface. No table-listing or schema-describing helper tools,
no embedded models — SQL already does all of that (`SHOW TABLES`, `DESCRIBE t`,
`sqlite_master`, `information_schema`). Credentials live in one `0600` file,
**never** in environment variables. The release binary is ~6 MB (TLS, a
complete SQLite engine, the MySQL and PostgreSQL drivers, and the HTTP
transport included); the Docker image is that binary on `scratch`.

Backends today: **MySQL**, **MariaDB**, **PostgreSQL**, and **SQLite**. MSSQL
is planned behind the same one-tool interface.

## Try it in 30 seconds (SQLite)

The SQLite engine is compiled into the binary — no server, no install, no
third-party service. Point at a file and go:

```sh
printf 'driver = "sqlite"\npath = "./app.db"\ncreate = true\n' > sql-mcp.toml
chmod 600 sql-mcp.toml
sql-mcp
```

Use `path = ":memory:"` for a throwaway scratch database (no `create` needed).
Without `create = true`, a missing file is a startup error — a typo'd path can
never silently become an empty database. See
[`examples/sqlite.toml`](examples/sqlite.toml) for all the options.

## Configure

Annotated example configs live in [`examples/`](examples/) — one per backend:

- [`examples/mariadb.toml`](examples/mariadb.toml) — MariaDB / MySQL (host,
  credentials, TLS)
- [`examples/postgres.toml`](examples/postgres.toml) — PostgreSQL (host,
  credentials, TLS, the text-values and transaction notes)
- [`examples/sqlite.toml`](examples/sqlite.toml) — SQLite (file path,
  `create`, `:memory:`)

Copy the one for your backend and lock it down:

```sh
cp examples/mariadb.toml sql-mcp.toml   # or examples/sqlite.toml
chmod 600 sql-mcp.toml          # required — sql-mcp refuses a group/world-readable config
$EDITOR sql-mcp.toml
```

```toml
driver   = "mariadb"   # or "mysql"
host     = "127.0.0.1"
port     = 3306         # optional; defaults to the backend's well-known port
user     = "readonly"
password = "..."
database = "app"        # optional default schema
# read_only = true            # optional; see below
# max_rows = 1000             # optional rows-per-result-set cap (default 1000, 0 = off)
# max_cell_bytes = 16384      # optional per-value byte cap (default 16 KiB, 0 = off)
# max_response_bytes = 262144 # optional whole-response byte cap (default 256 KiB, 0 = off)
# tls = true                  # optional; see TLS below
```

Misconfiguration is an **error, not a warning**: contradictory TLS settings
(e.g. `tls_insecure = true` with `tls = false`), an unrecognized
`SQL_MCP_MODE` value, an unknown flag, or an unknown config key (typos like
`read_onyl` get a "did you mean" hint) all refuse startup. A security tool
must never run with settings the operator merely *believes* are in effect.

Config file is found via `--config <path>`, else `$SQL_MCP_CONFIG`, else
`./sql-mcp.toml`.

## Run

```sh
sql-mcp --config /path/to/sql-mcp.toml
```

It speaks MCP over stdio. Point your client at it, e.g.:

```json
{
  "mcpServers": {
    "sql": { "command": "/path/to/sql-mcp", "args": ["--config", "/path/to/sql-mcp.toml"] }
  }
}
```

All logging goes to stderr; stdout is the protocol channel.

## Remote use (HTTP)

Set `http_listen` and a token, and sql-mcp serves MCP over streamable HTTP
instead of stdio:

```toml
http_listen = "127.0.0.1:8650"
http_token  = "<openssl rand -hex 32>"
# or, one per agent so each can be revoked independently:
# http_tokens = ["<token-for-claude>", "<token-for-ci>"]
```

Point an MCP client at it with an `Authorization` header:

```json
{
  "mcpServers": {
    "sql": {
      "type": "http",
      "url": "http://127.0.0.1:8650/",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

**HTTP always requires the bearer token — there is no localhost exemption.**
A no-auth local port would hand every local user the database access the
`0600` config file exists to protect, a reverse proxy in front would make
every request look local, and DNS-rebinded browser JavaScript can reach
`127.0.0.1`. Local no-auth use is what stdio is for. Tokens are compared in
constant time, live in the locked-down config like every other credential,
and must be at least 16 characters (`openssl rand -hex 32` is the suggested
shape). `http_listen` without a token is a startup error.

The token travels in cleartext over plain HTTP, so bind beyond loopback only
behind a TLS-terminating reverse proxy or inside a private network
(WireGuard/Tailscale).

Two things to know when several agents share one instance:

- All HTTP clients share **one database session** (the single persistent
  connection): `SET @vars` and temp tables are visible across clients. Same
  model as stdio — one server, one session.
- One sql-mcp instance serves **one database**. Serving two databases means
  two instances (two ports or two containers) — which is also the security
  boundary you want: each gets its own tokens, read-only mode, and caps.

## Read-only mode

Enable with `--read-only`, `SQL_MCP_MODE=ro`, or `read_only = true` in the config
(any one wins — read-only only ever tightens).

**What it is:** an *assertion about the connecting account*, not a query filter.
sql-mcp never inspects or rewrites your SQL. In read-only mode it refuses to
start unless the account is provably incapable of mutating **persistent state**
— data, schema, and privileges. The boundaries of that promise — what no
privilege system can gate — are collected in
[Caveats and compromises](#caveats-and-compromises).

**Why it works this way:** for MySQL/MariaDB there is no reliable per-connection
read-only switch, because the input *is* SQL — any session flag
(`SET SESSION TRANSACTION READ ONLY`) can be turned off by the very statement
we're about to run. The only real gate is an account that lacks write
privileges. So at startup sql-mcp runs `SHOW GRANTS` and verifies every granted
privilege is in a small read-only allowlist:

```
SELECT, SHOW VIEW, USAGE
```

Anything else — `INSERT`, `UPDATE`, `DELETE`, `CREATE`, `DROP`, `ALTER`,
`FILE`, `PROCESS`, `SUPER`, `GRANT OPTION`, `ALL PRIVILEGES`, … — makes it
refuse to start, naming the offending grant. It's an **allowlist**, so a future
server version adding a new writable privilege can't silently slip through.
Role grants (which `SHOW GRANTS` doesn't expand) are also treated as
unverifiable and rejected; grant the account `SELECT` directly instead.

For **PostgreSQL**, the assertion takes the same account-inspection path, but
it is necessarily wider than `SHOW GRANTS`, because PostgreSQL hides write
capability in more places. At startup sql-mcp inspects the catalogs and
refuses unless *all* of these come back clean — every refusal names the
finding and the exact `REVOKE`/`ALTER` that fixes it:

- **Role attributes** (`SUPERUSER`, `CREATEDB`, `CREATEROLE`, `REPLICATION`,
  `BYPASSRLS`) on the account *and on every role it can assume with
  `SET ROLE`* — attributes are never inherited, so an inherit-only
  membership in an attribute-bearing role doesn't count, and an inert
  membership (`WITH SET FALSE, INHERIT FALSE` on PostgreSQL 16+) confers
  nothing at all. Ordinary grants flow through both `INHERIT` and `SET ROLE`
  and are checked accordingly.
- **Object ownership, across every owned object class** — an owner has full
  rights with no ACL entry to see, so the account (and reachable roles) must
  own nothing: no tables, sequences, views, schemas, databases, functions,
  large objects, types/domains, operators, collations, conversions,
  text-search objects, foreign-data wrappers, foreign servers, languages,
  tablespaces, extensions, publications, subscriptions, event triggers, or
  statistics objects.
- **Relation, column, and large-object ACLs** — `SELECT` is the only allowed
  privilege. On sequences even `USAGE` disqualifies: it permits `nextval()`,
  which mutates persistent state.
- **Type, language, FDW, foreign-server, and tablespace ACLs** — `USAGE` on
  a type or language is passive and allowed; `USAGE` on a foreign-data
  wrapper or foreign server is not (it permits `CREATE SERVER` /
  `CREATE USER MAPPING` — catalog mutation), and `CREATE` on a tablespace
  disqualifies.
- **Schema ACLs** — `USAGE` only; `CREATE` on any schema is the gateway to DDL.
- **The database ACL** — `CONNECT` only: no `CREATE`, no `TEMP`. A stock
  database grants `PUBLIC` the `TEMP` privilege implicitly, so qualifying
  requires a one-time `REVOKE TEMP ON DATABASE <db> FROM PUBLIC;` (the
  refusal message says exactly this). Temp tables are revocable in
  PostgreSQL, so unlike SQLite they get no carve-out.
- **Parameter ACLs** (PostgreSQL 15+) — `GRANT ALTER SYSTEM ON PARAMETER`
  writes persistent server configuration (`postgresql.auto.conf`) and
  disqualifies; the session-local `GRANT SET` form is allowed.
- **Default ACLs** (standing rules granting privileges on *future* objects)
  and **predefined-role memberships** — `pg_read_all_data`, `pg_monitor`, and
  friends are fine; `pg_write_all_data`, `pg_maintain`, the file-access
  roles, or any unrecognized `pg_*` role disqualify, because predefined-role
  powers never appear in any ACL.
- **Grant and admin options** — any privilege held `WITH GRANT OPTION` and
  any role membership held `WITH ADMIN OPTION` disqualify, no matter how
  harmless the underlying privilege or role: being able to hand access
  onward is privilege mutation.

A hot-standby connection is deliberately *not* treated as connection-level
enforcement: a standby can be promoted mid-session, at which point writes
become possible.

For **SQLite**, read-only is enforced *below* the SQL layer instead — no
account inspection, because there are no accounts: the file is opened with
`SQLITE_OPEN_READONLY` **and** the attached-database limit is set to 0, so a
query can't `ATTACH` a second, writable file (URI filename processing is also
disabled, so `file:…?mode=rwc` strings are inert).

### Provisioning a dedicated read-only account

Use an account that exists *only* for sql-mcp — never one shared with an
application. The assertion examines everything the account can reach, so the
less it has, the easier it qualifies — and the less an extracted credential
is worth.

MySQL / MariaDB:

```sql
CREATE USER 'sql_mcp'@'%' IDENTIFIED BY '<long random password>';
GRANT SELECT, SHOW VIEW ON app.* TO 'sql_mcp'@'%';
```

PostgreSQL (run while connected to the target database):

```sql
CREATE ROLE sql_mcp LOGIN PASSWORD '<long random password>';
-- The implicit default ACL grants PUBLIC the TEMP privilege; read-only mode
-- requires it revoked (one-time, per database):
REVOKE TEMPORARY, CREATE ON DATABASE app FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;   -- PostgreSQL 14 and older
GRANT SELECT ON ALL TABLES IN SCHEMA public TO sql_mcp;
-- Cover tables created later (run as the role that creates them):
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO sql_mcp;
```

Then start sql-mcp with `read_only = true` — it verifies the result, and any
leftover capability is refused naming the exact `REVOKE`/`ALTER` that fixes
it.

## Caveats and compromises

The honest limits, collected in one place. Each is either something no client
can enforce, or a deliberate trade documented instead of hidden.

**All backends**

- Read-only is **asserted at startup**. Grants changed while sql-mcp is
  running aren't re-checked until restart.
- No privilege system gates *resource* side effects: any account can burn CPU
  with an expensive query. That's a server-side limit
  (`max_execution_time`, `statement_timeout`), not something a client can
  promise.

**MySQL / MariaDB**

- `GET_LOCK()` and `SLEEP()` require no privilege at all — a SELECT-only
  account can still take server-wide advisory locks that collide with your
  applications'.
- Role grants are rejected as unverifiable in read-only mode (`SHOW GRANTS`
  doesn't expand them); grant the account `SELECT` directly instead.
- Any account can change **its own password** (`SET PASSWORD` for yourself
  needs no grant), which no allowlist can exclude. The effect is staling the
  credential in sql-mcp's config — and, if the database port is reachable
  directly, a login that bypasses sql-mcp's output caps with the same
  read-only privileges.
- No "verify-ca" TLS mode (chain check without the hostname check): the
  upstream mysql_async flag for it can never take effect, so sql-mcp doesn't
  offer a security knob that doesn't work. See [TLS](#tls).

**SQLite**

- A read-only connection can still `CREATE TEMP TABLE`: the temp database is
  session-private and separate from the file, and SQLite has no way to revoke
  it below the SQL layer. Persistent state stays untouched.
- The engine is `rusqlite` (canonical SQLite, statically compiled) as a
  deliberate placeholder until a pure-Rust engine can meet the read-only
  enforcement bar; the file format is plain SQLite either way, and the test
  suite independently verifies it.

**PostgreSQL**

- **Values arrive as text** (`"42"`, not `42`): multi-statement support
  requires the simple-query protocol, which carries no type information on
  the wire. The server renders every type canonically — `numeric` keeps its
  exact scale, `bytea` arrives as `\x…` hex — and the tool description tells
  the model to cast or parse as needed. `last_insert_id` is never set; use
  `INSERT … RETURNING`.
- **One call is one transaction:** if any statement in a call fails, the
  whole call's effects are rolled back, and the in-band error says so.
  Explicit `BEGIN`/`COMMIT` in the SQL overrides this — a bare `BEGIN`
  leaves the session inside a transaction until a later call commits or
  rolls back, and if a statement fails inside it, the session stays
  *aborted*: every later call errors with `current transaction is aborted`
  until one runs `ROLLBACK` (each error says exactly that; sql-mcp never
  rolls back on its own, which would destroy `ROLLBACK TO <savepoint>`
  recovery).
- `COPY … FROM STDIN` / `TO STDOUT` are not supported — the transport has no
  copy channel, and the attempt costs the connection (it is dropped with an
  error saying so and re-established on the next call). The tool description
  steers the model to `INSERT`/`SELECT` instead.
- `pg_advisory_lock()` requires no privilege — the `GET_LOCK()` analog.
- Prepared transactions: if the server enables them
  (`max_prepared_transactions > 0`; the default is `0` = off), any connected
  role can `PREPARE TRANSACTION`, parking a transaction — including the
  locks it holds — that survives disconnect until the same role or a
  superuser runs `COMMIT`/`ROLLBACK PREPARED`. No per-role privilege gates
  it. A SELECT-only role still can't write through one, but it can pin locks
  and resources; leave the parameter at `0` unless you need two-phase
  commit.
- The privilege promise is precisely **no escalation**, not zero catalog
  writes: a handful of self-mutations need no grant and cannot be revoked.
  A role can always change **its own password**
  (`ALTER ROLE CURRENT_USER PASSWORD …` — staling the credential in
  sql-mcp's config, and permitting a direct login that bypasses sql-mcp's
  output caps if the server port is reachable), set **its own per-role
  session defaults** (`ALTER ROLE CURRENT_USER SET …`), and
  `ALTER DEFAULT PRIVILEGES` for objects it would create (inert under the
  checks above — a qualifying account can't `CREATE` anything for the rule
  to ever apply to); on PostgreSQL 15 and older it can also grant membership
  *in itself* to another existing role. None of these extend what can be
  read or written beyond what was already granted. One more reason the
  account should be
  [dedicated to sql-mcp](#provisioning-a-dedicated-read-only-account).
- `EXECUTE` is granted to `PUBLIC` by default on every function, so the
  read-only check cannot require zero `EXECUTE` — which means a
  `SECURITY DEFINER` function can write with its *owner's* privileges.
  Auditing those functions is the database owner's job; sql-mcp doesn't
  pretend the grant check covers them. `dblink`/`postgres_fdw` functions (if
  those extensions are installed) are a concrete instance: `dblink_exec()`
  opens a fresh server-side connection that can write through whatever
  credentials or permissive `pg_hba.conf` it reaches — operators who care
  can `REVOKE EXECUTE` on them, like the `lo_*` functions.
- Large objects: `lo_create()`/`lo_from_bytea()` persist data with no
  revocable privilege gating *creation* (they ride the `EXECUTE` carve-out).
  Operators who care can `REVOKE EXECUTE` on the `lo_*` functions.
- The `CREATE`/`TEMP` database check covers the **current database only**:
  SQL through this connection can't reach another database, and demanding a
  cluster-wide revoke would refuse virtually every stock cluster.

## TLS

TLS is compiled in (rustls + the `ring` provider — no OpenSSL, so the
static/scratch build is unaffected). `ring` is deliberately chosen over
`aws-lc-rs`, which produced a ~50% larger binary in testing. TLS is **off by
default**, since forcing it would break localhost and self-signed setups.
Enable per connection:

```toml
tls = true                     # require TLS; verify cert against system roots
# tls_ca = "/etc/ssl/db-ca.pem"  # trust this PEM CA bundle instead of the built-in roots
# tls_insecure = true            # accept invalid/self-signed certs, skip hostname check (dangerous)
```

With `tls = true` and no other options, sql-mcp refuses to connect if the
server certificate doesn't verify (e.g. a default self-signed MySQL cert →
`UnknownIssuer`). Point `tls_ca` at the signing CA, or set `tls_insecure = true`
on a trusted link, to proceed.

`tls_ca` and `tls_insecure` require `tls = true` and are mutually exclusive
with each other; any contradictory combination is a startup error.

One reality check for verified TLS: MySQL/MariaDB **auto-generated** server
certificates contain no subjectAltName, and rustls (correctly) refuses to
match a hostname against a SAN-less certificate — so `tls_ca` can never fully
verify a default install, even with the right CA. For verified TLS, issue the
server a certificate whose SAN covers the host you connect to. (A "verify-ca"
mode — chain check without the hostname check — is currently blocked by an
upstream mysql_async issue where its skip-hostname flag never takes effect;
until then the choices are real certificates or `tls_insecure`.)

## Build

```sh
cargo build --release          # -> target/release/sql-mcp (size-optimized profile)
cargo test                     # everything: unit + SQLite + Docker-backed MySQL/MariaDB/PostgreSQL
cargo test --test sqlite       # SQLite integration suite — no Docker needed
cargo test --test postgres     # PostgreSQL suite (Docker)
cargo test --bin sql-mcp       # unit tests only
```

The live MySQL/MariaDB and PostgreSQL tests use `testcontainers-rs` and start
disposable `mysql:8`, `mariadb:11`, and `postgres:17` containers. They seed
schema/users, drive sql-mcp over stdio, and cover multi-result draining, caps,
the read-only assertion matrices, reconnects, and TLS. The first run may pull
images.

The SQLite suite needs no Docker: the database is created, populated, and
queried entirely *through the sql-mcp binary*, then independently re-opened
with rusqlite to prove the file is a well-formed SQLite database with the
expected contents and types. (rusqlite is the backend today, so that's a
sanity loop — but the backend is planned to swap to the pure-Rust `turso`
crate once it can meet the read-only enforcement bar, and the same verifier
then becomes the canonical-SQLite file-format compatibility proof.)

### Docker

```sh
docker build -t sql-mcp .
docker run --rm -i -v "$PWD/sql-mcp.toml:/sql-mcp.toml:ro" sql-mcp
```

The image is a static musl binary on `scratch` — a few MB and nothing else: no
OS, no interpreter, no runtime.

## Notes / current limits

- A call may contain **multiple statements** (semicolon-separated) and
  statements may return multiple result sets (e.g. `CALL`); the response is one
  `result_sets` entry per statement/result set, in order. Everything is
  consumed within the call — if a later statement fails, the earlier results
  are returned together with an `"error"` field, and nothing (data *or*
  buffered errors) ever leaks into the next call. (On PostgreSQL the earlier
  statements' *effects* are also rolled back — see
  [Caveats](#caveats-and-compromises).)
- Three output caps, each guarding a failure mode the others can't see:
  `max_rows` per result set (default 1000), `max_cell_bytes` per value
  (default 16 KiB — one huge `TEXT` cell can blow the budget under any row
  cap), and `max_response_bytes` for the whole response (default 256 KiB, the
  global backstop). `0` disables a cap. Capped result sets carry
  `"truncated": true`; capped values end in `…[truncated; N bytes total]`; the
  caps are stated in the tool description so the model narrows with
  `LIMIT`/`SUBSTRING` instead of guessing. The caps protect memory and the
  model's context window; the database still executes the full query — only
  `LIMIT` in the SQL avoids that.
- For MySQL/MariaDB and SQLite, result values are typed where it's safe
  (integers → JSON numbers); `DECIMAL` and friends stay strings so precision
  is never lost to a float, and binary values (`BLOB`, `VARBINARY`, `BIT`,
  geometry) are hex-encoded as `0x…` rather than lossily decoded as UTF-8.
  PostgreSQL returns every value as text — see
  [Caveats](#caveats-and-compromises).
- The server holds **one persistent connection**, so session state (`USE`,
  `SET @vars`, temp tables) carries across calls. If the connection drops, the
  next call reconnects with a fresh session and the error says so; the failed
  statement is never silently retried (a retried write could execute twice).

## Why this exists

sql-mcp was built after evaluating an existing SQL MCP server that shipped as
a 5.2 GB Docker image — an embedded embedding model, a Python/ML runtime, and
a catalog of helper tools, each re-implementing something SQL already does.
This project is the counter-thesis: the model already speaks SQL, so the
server's job is a secure transport, not a toolbox. One tool, a ~6 MB static
binary, credentials in one locked-down file, and a read-only mode that is an
enforceable guarantee rather than a request.

## License

Licensed under either of the [Apache License, Version 2.0](LICENSE-APACHE) or
the [MIT license](LICENSE-MIT), at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
