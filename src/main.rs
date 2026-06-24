mod config;
mod driver;
mod http;

use std::sync::Arc;

use anyhow::{Context, Result};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::ToolCallContext;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::service::RequestContext;
use rmcp::transport::stdio;
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler, ServiceExt, schemars, tool, tool_router,
};
use serde::Deserialize;

use crate::driver::{ConnectionPool, Driver, DriverFactory, Limits};

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SqlExecArgs {
    sql: String,
}

#[derive(Clone)]
pub struct SqlServer {
    driver: Arc<dyn Driver>,
    read_only: bool,
    limits: Limits,
    tool_router: ToolRouter<Self>,
}

#[derive(Clone)]
pub struct SqlServerFactory {
    driver: Arc<DriverFactory>,
    pool: Arc<ConnectionPool>,
    read_only: bool,
    limits: Limits,
}

impl SqlServerFactory {
    fn new(
        driver: Arc<DriverFactory>,
        pool: Arc<ConnectionPool>,
        read_only: bool,
        limits: Limits,
    ) -> Self {
        Self {
            driver,
            pool,
            read_only,
            limits,
        }
    }

    fn new_session(&self) -> SqlServer {
        SqlServer::new(
            self.driver.new_http_session(Arc::clone(&self.pool)),
            self.read_only,
            self.limits,
        )
    }
}

#[tool_router]
impl SqlServer {
    fn new(driver: Arc<dyn Driver>, read_only: bool, limits: Limits) -> Self {
        Self {
            driver,
            read_only,
            limits,
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Execute SQL against the configured database.")]
    async fn sql_exec(
        &self,
        Parameters(args): Parameters<SqlExecArgs>,
    ) -> Result<CallToolResult, McpError> {
        match self.driver.exec(&args.sql, self.limits).await {
            Ok(output) => {
                let json = serde_json::to_string(&output).unwrap_or_else(|e| {
                    format!("{{\"error\":\"failed to serialize result: {e}\"}}")
                });
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }

            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "SQL error: {e}"
            ))])),
        }
    }

    fn tool_description(&self) -> String {
        let mut caps = Vec::new();
        if self.limits.max_rows != 0 {
            caps.push(format!("{} rows per result set", self.limits.max_rows));
        }
        if self.limits.max_cell_bytes != 0 {
            caps.push(format!(
                "{} bytes per value (cut values end in \u{2026}[truncated; N bytes total])",
                self.limits.max_cell_bytes
            ));
        }
        if self.limits.max_response_bytes != 0 {
            caps.push(format!(
                "~{} bytes per response",
                self.limits.max_response_bytes
            ));
        }
        let caps = if caps.is_empty() {
            String::new()
        } else {
            format!(
                " Limits: {}; truncated results include \"truncated\": true; cut strings \
                 end in \u{2026}[truncated; N bytes total].",
                caps.join(", ")
            )
        };
        format!(
            "Run SQL against the configured {} database. Multiple statements are allowed. \
             Returns JSON: {{\"result_sets\": [...]}}; each entry is {{columns, rows}} \
             or {{rows_affected, last_insert_id}}. Later statement errors are returned \
             as \"error\" with earlier results.{}{caps}.",
            self.driver.name(),
            self.driver.exec_notes(),
        )
    }
}

impl ServerHandler for SqlServer {
    fn get_info(&self) -> ServerInfo {
        let mode = if self.read_only {
            " Read-only mode is enabled."
        } else {
            ""
        };
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_instructions(format!(
                "Runs SQL against a {} database via the tool `sql_exec`. \
                 There are no schema tools; use SQL introspection directly, \
                 e.g. {}.{mode}",
                self.driver.name(),
                self.driver.introspection_hint(),
            ))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        self.tool_router
            .call(ToolCallContext::new(self, request, context))
            .await
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let mut tools = self.tool_router.list_all();
        for tool in &mut tools {
            if tool.name == "sql_exec" {
                tool.description = Some(self.tool_description().into());
            }
        }
        Ok(ListToolsResult {
            tools,
            ..Default::default()
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = config::load()?;

    let http = config.http()?;
    let database = config.database;
    let read_only = database.read_only;
    let limits = Limits {
        max_rows: database.max_rows,
        max_cell_bytes: database.max_cell_bytes,
        max_response_bytes: database.max_response_bytes,
    };
    let factory = Arc::new(DriverFactory::new(database.backend, read_only));
    let driver = factory
        .connect()
        .await
        .context("connecting to validate configuration")?;

    if read_only {
        if driver.enforces_read_only_at_connection() {
            eprintln!(
                "[sql-mcp] read-only mode: {} enforces read-only at the connection.",
                driver.name()
            );
        } else {
            driver
                .assert_read_only()
                .await
                .context("refusing to start in read-only mode")?;
            eprintln!(
                "[sql-mcp] read-only mode: {} account verified incapable of mutation.",
                driver.name()
            );
        }
    }

    let cap = |n: u64| {
        if n == 0 {
            "off".to_string()
        } else {
            n.to_string()
        }
    };
    eprintln!(
        "[sql-mcp] serving sql_exec for {} over {}{} (caps: {} rows/set, {} bytes/value, {} bytes/response).",
        factory.name(),
        if http.is_some() { "http" } else { "stdio" },
        if read_only { " (read-only)" } else { "" },
        cap(limits.max_rows),
        cap(limits.max_cell_bytes),
        cap(limits.max_response_bytes),
    );

    match http {
        Some(http) => {
            let pool = ConnectionPool::new(http.max_sessions, http.eviction_grace);
            let keep = factory.requires_lifetime_keeper();
            let servers = SqlServerFactory::new(factory, pool, read_only, limits);

            let _keeper = keep.then_some(driver);
            http::serve(servers, http).await?
        }
        None => {
            let server = SqlServer::new(driver, read_only, limits);
            let service = server
                .serve(stdio())
                .await
                .context("failed to start MCP server")?;
            service.waiting().await?;
        }
    }
    Ok(())
}
