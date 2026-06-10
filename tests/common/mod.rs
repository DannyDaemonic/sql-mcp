//! Shared integration-test harness: drives the compiled sql-mcp binary over
//! stdio JSON-RPC. Used by every suite (`mod common;`), with and without
//! Docker — keep this file backend-agnostic.
#![allow(dead_code)] // each suite compiles its own copy; not all use every helper

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::time::{sleep, timeout};

pub const MCP_TIMEOUT: Duration = Duration::from_secs(30);

pub struct CertPaths {
    pub ca: PathBuf,
    pub server_cert: PathBuf,
    pub server_key: PathBuf,
    pub wrong_ca: PathBuf,
}

/// Generate a throwaway CA, a server certificate it signs (SANs: localhost
/// and 127.0.0.1, so rustls hostname verification passes against the test
/// container), and an unrelated "wrong CA" for negative verification tests.
pub fn write_test_certs(dir: &Path, server_cn: &str) -> Result<CertPaths> {
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "sqlmcp-test-ca");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let issuer = Issuer::new(ca_params, ca_key);

    let server_key = KeyPair::generate()?;
    let mut server_params =
        CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;
    server_params
        .distinguished_name
        .push(DnType::CommonName, server_cn);
    let server_cert = server_params.signed_by(&server_key, &issuer)?;

    let wrong_ca_key = KeyPair::generate()?;
    let mut wrong_ca_params = CertificateParams::new(Vec::<String>::new())?;
    wrong_ca_params
        .distinguished_name
        .push(DnType::CommonName, "wrong-ca");
    wrong_ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    wrong_ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let wrong_ca_cert = wrong_ca_params.self_signed(&wrong_ca_key)?;

    let ca = dir.join("ca.pem");
    let server_cert_path = dir.join("server-cert.pem");
    let server_key_path = dir.join("server-key.pem");
    let wrong_ca = dir.join("wrong-ca.pem");
    fs::write(&ca, ca_cert.pem())?;
    fs::write(&server_cert_path, server_cert.pem())?;
    fs::write(&server_key_path, server_key.serialize_pem())?;
    fs::write(&wrong_ca, wrong_ca_cert.pem())?;
    set_mode(&server_key_path, 0o600)?;

    Ok(CertPaths {
        ca,
        server_cert: server_cert_path,
        server_key: server_key_path,
        wrong_ca,
    })
}

pub fn write_cfg(dir: &Path, name: &str, contents: &str, mode: u32) -> Result<PathBuf> {
    let path = dir.join(name);
    fs::write(&path, contents)?;
    set_mode(&path, mode)?;
    Ok(path)
}

pub fn set_mode(path: &Path, mode: u32) -> Result<()> {
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(mode);
    fs::set_permissions(path, perms)?;
    Ok(())
}

pub struct McpSession {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Lines<BufReader<ChildStdout>>,
    stderr: Option<ChildStderr>,
    next_id: u64,
}

impl McpSession {
    pub async fn start(config: &Path) -> Result<Self> {
        Self::start_with(config, &[], &[]).await
    }

    pub async fn start_with(config: &Path, args: &[&str], envs: &[(&str, &str)]) -> Result<Self> {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_sql-mcp"));
        cmd.arg("-c")
            .arg(config)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_remove("SQL_MCP_MODE");
        for (key, value) in envs {
            cmd.env(key, value);
        }
        let mut child = cmd.spawn().context("spawn sql-mcp")?;
        let stdin = child.stdin.take().context("child stdin")?;
        let stdout = child.stdout.take().context("child stdout")?;
        let stderr = child.stderr.take().context("child stderr")?;
        let mut session = Self {
            child,
            stdin: Some(stdin),
            stdout: BufReader::new(stdout).lines(),
            stderr: Some(stderr),
            next_id: 2,
        };
        session.send(initialize_request()).await?;
        let response = session.read_response(MCP_TIMEOUT).await?;
        ensure!(
            response.get("error").is_none(),
            "initialize failed: {response}"
        );
        session
            .send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await?;
        Ok(session)
    }

    pub async fn send(&mut self, value: Value) -> Result<()> {
        let line = serde_json::to_string(&value)?;
        let stdin = self.stdin.as_mut().context("child stdin already closed")?;
        stdin.write_all(line.as_bytes()).await?;
        stdin.write_all(b"\n").await?;
        stdin.flush().await?;
        Ok(())
    }

    pub async fn request(&mut self, request: Value) -> Result<Value> {
        self.send(request).await?;
        self.read_response(MCP_TIMEOUT).await
    }

    pub async fn tools_list(&mut self) -> Result<Value> {
        self.request(json!({"jsonrpc":"2.0","id":self.next_id,"method":"tools/list"}))
            .await
    }

    pub async fn call(&mut self, sql: &str) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        self.request(json!({
            "jsonrpc":"2.0",
            "id":id,
            "method":"tools/call",
            "params":{"name":"sql_exec","arguments":{"sql":sql}},
        }))
        .await
    }

    pub async fn call_with_rss(
        &mut self,
        sql: &str,
        response_timeout: Duration,
    ) -> Result<(Value, u64)> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({
            "jsonrpc":"2.0",
            "id":id,
            "method":"tools/call",
            "params":{"name":"sql_exec","arguments":{"sql":sql}},
        }))
        .await?;

        let pid = self.child.id();
        let stop = Arc::new(AtomicBool::new(false));
        let peak = Arc::new(AtomicU64::new(0));
        let sampler = pid.map(|pid| {
            let stop = Arc::clone(&stop);
            let peak = Arc::clone(&peak);
            tokio::spawn(async move {
                while !stop.load(Ordering::Relaxed) {
                    if let Some(rss) = rss_kb(pid) {
                        peak.fetch_max(rss, Ordering::Relaxed);
                    }
                    sleep(Duration::from_millis(50)).await;
                }
            })
        });

        let response = self.read_response(response_timeout).await;
        stop.store(true, Ordering::Relaxed);
        if let Some(sampler) = sampler {
            let _ = sampler.await;
        }
        response.map(|value| (value, peak.load(Ordering::Relaxed)))
    }

    pub async fn read_response(&mut self, response_timeout: Duration) -> Result<Value> {
        let line = match timeout(response_timeout, self.stdout.next_line()).await {
            Ok(Ok(Some(line))) => line,
            Ok(Ok(None)) => {
                let stderr = self.finish_after_eof().await.unwrap_or_default();
                bail!("EOF before MCP response. stderr:\n{stderr}");
            }
            Ok(Err(err)) => return Err(err).context("read MCP stdout"),
            Err(_) => {
                self.kill().await?;
                bail!("hang: no MCP response within {response_timeout:?}");
            }
        };
        serde_json::from_str(&line).with_context(|| format!("invalid JSON-RPC response: {line}"))
    }

    pub async fn close(mut self) -> Result<String> {
        drop(self.stdin.take());
        let status = timeout(Duration::from_secs(10), self.child.wait())
            .await
            .context("hang: sql-mcp did not exit after stdin EOF")??;
        let mut stderr = String::new();
        if let Some(mut stream) = self.stderr.take() {
            stream.read_to_string(&mut stderr).await?;
        }
        ensure!(
            !stderr.to_lowercase().contains("panic"),
            "panic observed on stderr: {stderr}"
        );
        ensure!(
            status.success(),
            "sql-mcp exited with {status}; stderr:\n{stderr}"
        );
        Ok(stderr)
    }

    pub async fn finish_after_eof(&mut self) -> Result<String> {
        let _ = timeout(Duration::from_secs(5), self.child.wait()).await;
        let mut stderr = String::new();
        if let Some(mut stream) = self.stderr.take() {
            stream.read_to_string(&mut stderr).await?;
        }
        Ok(stderr)
    }

    pub async fn kill(&mut self) -> Result<()> {
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;
        Ok(())
    }
}

pub fn rss_kb(pid: u32) -> Option<u64> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status.lines().find_map(|line| {
        line.strip_prefix("VmRSS:").and_then(|value| {
            value
                .split_whitespace()
                .next()
                .and_then(|number| number.parse().ok())
        })
    })
}

pub async fn run_startup(args: &[&str], envs: &[(&str, &str)]) -> Result<(i32, String, String)> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sql-mcp"));
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("SQL_MCP_MODE");
    for (key, value) in envs {
        cmd.env(key, value);
    }
    let output = timeout(Duration::from_secs(20), cmd.output())
        .await
        .context("hang: sql-mcp startup did not exit")??;
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    ensure!(
        !stderr.to_lowercase().contains("panic"),
        "panic observed on stderr: {stderr}"
    );
    Ok((output.status.code().unwrap_or(-1), stdout, stderr))
}

pub fn initialize_request() -> Value {
    json!({
        "jsonrpc":"2.0",
        "id":1,
        "method":"initialize",
        "params":{
            "protocolVersion":"2025-06-18",
            "capabilities":{},
            "clientInfo":{"name":"rust-live-test","version":"0"},
        },
    })
}

pub fn tool_text(response: &Value) -> String {
    response
        .pointer("/result/content")
        .and_then(Value::as_array)
        .map(|content| {
            content
                .iter()
                .filter_map(|item| item.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_else(|| response.to_string())
}

pub fn tool_is_error(response: &Value) -> bool {
    response
        .pointer("/result/isError")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

pub fn tool_payload(response: &Value) -> Result<Value> {
    ensure!(
        !tool_is_error(response),
        "tool returned error: {}",
        tool_text(response)
    );
    serde_json::from_str(&tool_text(response)).context("parse tool JSON text")
}

pub fn first_rows(payload: &Value) -> &Vec<Value> {
    payload["result_sets"][0]["rows"]
        .as_array()
        .expect("rows array")
}

pub async fn startup_with_config(
    config: &Path,
    extra_args: &[&str],
    envs: &[(&str, &str)],
) -> Result<(i32, String, String)> {
    let config_arg = config
        .to_str()
        .with_context(|| format!("non-UTF-8 config path: {}", config.display()))?;
    let mut args = vec!["-c", config_arg];
    args.extend_from_slice(extra_args);
    run_startup(&args, envs).await
}

pub fn ensure_refused(output: (i32, String, String), needles: &[&str]) -> Result<()> {
    let (code, stdout, stderr) = output;
    let combined = stdout + &stderr;
    ensure!(
        code != 0,
        "expected refusal, got exit 0 and output:\n{combined}"
    );
    for needle in needles {
        ensure!(
            combined.contains(needle),
            "refusal output missing {needle:?}:\n{combined}"
        );
    }
    Ok(())
}

pub fn ensure_eq_json(actual: &Value, expected: &Value, label: &str) -> Result<()> {
    ensure!(
        actual == expected,
        "{label} mismatch:\nactual: {actual}\nexpected: {expected}"
    );
    Ok(())
}
