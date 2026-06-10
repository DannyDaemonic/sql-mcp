//! HTTP transport integration suite — no Docker required.
//!
//! Spawns the real binary on an ephemeral port (sqlite `:memory:` backend)
//! and drives MCP over streamable HTTP with reqwest: bearer-auth rejections
//! first, then a full initialize → initialized → tools/call round-trip, for
//! each configured token.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use futures_util::StreamExt;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::timeout;

mod common;
use common::{ensure_refused, initialize_request, startup_with_config, write_cfg};

const TOKEN_A: &str = "test-token-aaaaaaaaaaaaaaaaaaaaaaaa";
const TOKEN_B: &str = "test-token-bbbbbbbbbbbbbbbbbbbbbbbb";
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_suite() -> Result<()> {
    let tmp = TempDir::new().context("create http-test tempdir")?;

    // Binary-level config refusal: listen without a token must never serve.
    let no_token = write_cfg(
        tmp.path(),
        "no-token.toml",
        "driver = \"sqlite\"\npath = \":memory:\"\nhttp_listen = \"127.0.0.1:0\"\n",
        0o600,
    )?;
    let output = startup_with_config(&no_token, &[], &[]).await?;
    ensure_refused(output, &["bearer token", "openssl rand"]).context("no-token refusal")?;

    let config = write_cfg(
        tmp.path(),
        "http.toml",
        &format!(
            "driver = \"sqlite\"\npath = \":memory:\"\nhttp_listen = \"127.0.0.1:0\"\n\
             http_tokens = [\"{TOKEN_A}\", \"{TOKEN_B}\"]\n"
        ),
        0o600,
    )?;
    let mut server = HttpServer::start(&config).await?;
    let client = reqwest::Client::new();

    test_auth_rejections(&client, &server.url)
        .await
        .context("bearer auth rejections")?;
    test_mcp_round_trip(&client, &server.url, TOKEN_A)
        .await
        .context("MCP round-trip with token A")?;
    test_mcp_round_trip(&client, &server.url, TOKEN_B)
        .await
        .context("MCP round-trip with token B")?;

    server.stop().await
}

async fn test_auth_rejections(client: &reqwest::Client, url: &str) -> Result<()> {
    // (header value, label)
    let cases: [(Option<String>, &str); 4] = [
        (None, "missing Authorization"),
        (Some(format!("Bearer {TOKEN_A}x")), "wrong token"),
        (
            Some(format!("Bearer {}", &TOKEN_A[..TOKEN_A.len() - 1])),
            "token prefix",
        ),
        (Some(format!("Basic {TOKEN_A}")), "wrong scheme"),
    ];
    for (auth, label) in cases {
        let mut request = client
            .post(url)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(initialize_request().to_string());
        if let Some(auth) = auth {
            request = request.header("authorization", auth);
        }
        let response = timeout(HTTP_TIMEOUT, request.send()).await??;
        ensure!(
            response.status() == reqwest::StatusCode::UNAUTHORIZED,
            "{label}: expected 401, got {}",
            response.status()
        );
    }
    // Auth applies to every method, not just POST.
    let response = timeout(HTTP_TIMEOUT, client.get(url).send()).await??;
    ensure!(response.status() == reqwest::StatusCode::UNAUTHORIZED);
    Ok(())
}

async fn test_mcp_round_trip(client: &reqwest::Client, url: &str, token: &str) -> Result<()> {
    let post = |body: Value, session: Option<String>| {
        let mut request = client
            .post(url)
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(body.to_string());
        if let Some(session) = session {
            request = request.header("mcp-session-id", session);
        }
        request.send()
    };

    let response = timeout(HTTP_TIMEOUT, post(initialize_request(), None)).await??;
    ensure!(
        response.status().is_success(),
        "initialize: {}",
        response.status()
    );
    let session = response
        .headers()
        .get("mcp-session-id")
        .context("missing mcp-session-id header")?
        .to_str()?
        .to_string();
    let init = response_payload(response, 1)
        .await
        .context("initialize response")?;
    ensure!(
        init["result"]["serverInfo"]["name"].is_string(),
        "unexpected initialize result: {init}"
    );

    let response = timeout(
        HTTP_TIMEOUT,
        post(
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            Some(session.clone()),
        ),
    )
    .await??;
    ensure!(
        response.status() == reqwest::StatusCode::ACCEPTED,
        "initialized notification: {}",
        response.status()
    );

    let response = timeout(
        HTTP_TIMEOUT,
        post(
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "sql_exec", "arguments": {"sql": "SELECT 6 * 7 AS answer"}},
            }),
            Some(session),
        ),
    )
    .await??;
    ensure!(
        response.status().is_success(),
        "tools/call: {}",
        response.status()
    );
    let call = response_payload(response, 2)
        .await
        .context("tools/call response")?;
    let text = call["result"]["content"][0]["text"]
        .as_str()
        .context("tool text content")?;
    let payload: Value = serde_json::from_str(text)?;
    ensure!(
        payload["result_sets"][0]["rows"] == json!([[42]]),
        "unexpected sql result: {payload}"
    );
    Ok(())
}

/// Extract the JSON-RPC response with the given id from a streamable-HTTP
/// response — either a plain JSON body or an SSE stream whose `data:` events
/// may include priming/keep-alive events before the actual response.
async fn response_payload(response: reqwest::Response, id: u64) -> Result<Value> {
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();

    if content_type.starts_with("application/json") {
        let value: Value = serde_json::from_slice(&response.bytes().await?)?;
        ensure!(value["id"] == json!(id), "unexpected response id: {value}");
        return Ok(value);
    }
    ensure!(
        content_type.starts_with("text/event-stream"),
        "unexpected content-type {content_type}"
    );

    let mut stream = response.bytes_stream();
    let mut buf = String::new();
    let deadline = tokio::time::Instant::now() + HTTP_TIMEOUT;
    loop {
        let chunk = timeout(deadline - tokio::time::Instant::now(), stream.next())
            .await
            .context("hang: SSE stream produced no response")?
            .context("SSE stream ended before the response")??;
        buf.push_str(&String::from_utf8_lossy(&chunk));

        // Scan complete lines only (a trailing partial line stays in `buf`).
        while let Some(newline) = buf.find('\n') {
            let line: String = buf.drain(..=newline).collect();
            let line = line.trim_end();
            if let Some(data) = line.strip_prefix("data: ")
                && let Ok(value) = serde_json::from_str::<Value>(data)
                && value["id"] == json!(id)
            {
                return Ok(value);
            }
        }
    }
}

struct HttpServer {
    child: Child,
    url: String,
}

impl HttpServer {
    /// Spawn the binary and parse the ephemeral port from its stderr banner.
    async fn start(config: &Path) -> Result<Self> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sql-mcp"))
            .arg("-c")
            .arg(config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .env_remove("SQL_MCP_MODE")
            .spawn()
            .context("spawn sql-mcp")?;
        let stderr = child.stderr.take().context("child stderr")?;
        let mut lines = BufReader::new(stderr).lines();

        let url = loop {
            let line = timeout(HTTP_TIMEOUT, lines.next_line())
                .await
                .context("hang: no http banner on stderr")??
                .context("sql-mcp exited before the http banner")?;
            if let Some(rest) = line.split("http listening on ").nth(1)
                && let Some(url) = rest.split_whitespace().next()
            {
                break url.to_string();
            }
        };

        // Keep draining stderr so the child never blocks on a full pipe.
        tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
        Ok(Self { child, url })
    }

    async fn stop(&mut self) -> Result<()> {
        if let Some(status) = self.child.try_wait()? {
            bail!("sql-mcp exited prematurely: {status}");
        }
        self.child.kill().await?;
        Ok(())
    }
}
