//! Streamable-HTTP transport with mandatory bearer auth.
//!
//! Every request must carry `Authorization: Bearer <token>` matching one of
//! the configured tokens (compared in constant time) *before* anything
//! reaches the MCP layer. There is deliberately no localhost exemption — see
//! `Config::http` for the rationale. Because auth gates every request,
//! rmcp's Host-header (DNS-rebinding) validation is redundant and disabled:
//! it would only reject legitimate remote hostnames.
//!
//! The bearer token travels in cleartext on the wire: bind beyond loopback
//! only behind a TLS-terminating proxy or inside a private network
//! (WireGuard/Tailscale). The README says the same.
//!
//! One deliberate semantic to know about: the driver holds a single database
//! connection, so all HTTP clients share one SQL session (`SET @x`, temp
//! tables are visible across clients) — the same model as stdio, where one
//! server is one session. Run one instance per agent if that isolation
//! matters.

use std::convert::Infallible;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use http::{Request, Response, StatusCode, header};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rmcp::transport::streamable_http_server::StreamableHttpServerConfig;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::tower::StreamableHttpService;
use subtle::ConstantTimeEq;
use tower_service::Service;

use crate::SqlServer;
use crate::config::HttpConfig;

pub async fn serve(server: SqlServer, http: HttpConfig) -> Result<()> {
    let tokens: Arc<Vec<String>> = Arc::new(http.tokens);
    let service = StreamableHttpService::new(
        move || Ok(server.clone()),
        Arc::new(LocalSessionManager::default()),
        // Bearer auth gates every request before this layer sees it, which
        // already defeats DNS rebinding; the Host allowlist would only break
        // legitimate remote hostnames.
        StreamableHttpServerConfig::default().disable_allowed_hosts(),
    );

    let listener = tokio::net::TcpListener::bind(http.listen)
        .await
        .with_context(|| format!("failed to bind {}", http.listen))?;
    // Resolve the actual address so `:0` (ephemeral port) logs something usable.
    let local = listener.local_addr().context("resolve bound address")?;
    eprintln!(
        "[sql-mcp] http listening on http://{local} (bearer auth, {} token{}).",
        tokens.len(),
        if tokens.len() == 1 { "" } else { "s" }
    );

    loop {
        let (stream, _peer) = listener.accept().await.context("accept connection")?;
        let io = TokioIo::new(stream);
        let service = service.clone();
        let tokens = Arc::clone(&tokens);
        tokio::spawn(async move {
            let hyper_service = service_fn(move |request: Request<Incoming>| {
                let mut service = service.clone();
                let tokens = Arc::clone(&tokens);
                async move {
                    if !authorized(request.headers(), &tokens) {
                        return Ok::<_, Infallible>(unauthorized());
                    }
                    // `poll_ready` is unconditionally Ready for this service.
                    service.call(request).await
                }
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, hyper_service)
                .await
            {
                eprintln!("[sql-mcp] http connection error: {e}");
            }
        });
    }
}

/// True when the request carries `Authorization: Bearer <t>` and `<t>`
/// matches one of the configured tokens. Comparison is constant-time per
/// candidate (length differences short-circuit, but token length is not a
/// secret).
fn authorized(headers: &http::HeaderMap, tokens: &[String]) -> bool {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return false;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    let Some(presented) = value.strip_prefix("Bearer ") else {
        return false;
    };
    tokens
        .iter()
        .any(|expected| bool::from(presented.as_bytes().ct_eq(expected.as_bytes())))
}

fn unauthorized() -> Response<BoxBody<Bytes, Infallible>> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::WWW_AUTHENTICATE, "Bearer")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(
            Full::new(Bytes::from_static(b"missing or invalid bearer token"))
                .map_err(|never| match never {})
                .boxed(),
        )
        .expect("static response")
}

#[cfg(test)]
mod tests {
    use super::authorized;
    use http::{HeaderMap, HeaderValue, header};

    fn headers(value: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(value) = value {
            headers.insert(header::AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    #[test]
    fn bearer_auth_matrix() {
        let tokens = vec![
            "correct-horse-battery".to_string(),
            "second-agent-token".to_string(),
        ];
        assert!(authorized(
            &headers(Some("Bearer correct-horse-battery")),
            &tokens
        ));
        assert!(authorized(
            &headers(Some("Bearer second-agent-token")),
            &tokens
        ));
        assert!(!authorized(&headers(None), &tokens));
        assert!(!authorized(&headers(Some("Bearer wrong")), &tokens));
        assert!(!authorized(
            &headers(Some("Bearer correct-horse-batter")),
            &tokens
        ));
        assert!(!authorized(
            &headers(Some("Bearer correct-horse-battery2")),
            &tokens
        ));
        assert!(!authorized(
            &headers(Some("correct-horse-battery")),
            &tokens
        )); // no scheme
        assert!(!authorized(
            &headers(Some("Basic correct-horse-battery")),
            &tokens
        ));
        assert!(!authorized(
            &headers(Some("bearer correct-horse-battery")),
            &tokens
        )); // case-sensitive scheme
    }
}
