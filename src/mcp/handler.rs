//! The MCP methods: tools and resources, each call answered by internal
//! REST requests with the caller's `Authorization` header.

use super::guard::{AuthProbe, Caller};
use super::internal::{Call, Internal, Reply};
use super::resources;
use super::tools::{self, Role, Switches};
use crate::engines::rel::MAX_STATEMENT_LEN;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{header, request::Parts, HeaderValue, StatusCode};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, ErrorData, Implementation, ListResourceTemplatesResult,
    ListResourcesResult, ListToolsResult, PaginatedRequestParams, ReadResourceRequestParams, ReadResourceResponse,
    ServerCapabilities, ServerConfig,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::ServerHandler;
use std::future::Future;
use std::net::SocketAddr;

#[derive(Clone)]
pub(crate) struct LuraMcp {
    pub(crate) internal: Internal,
    pub(crate) switches: Switches,
}

/// What a call carries over from its HTTP request.
struct Invocation {
    authorization: Option<HeaderValue>,
    peer: Option<SocketAddr>,
    probe: Option<AuthProbe>,
}

impl Invocation {
    fn of(context: &RequestContext<RoleServer>) -> Self {
        let parts = context.extensions.get::<Parts>();
        Self {
            authorization: parts.and_then(|p| p.headers.get(header::AUTHORIZATION)).cloned(),
            peer: parts.and_then(|p| p.extensions.get::<ConnectInfo<SocketAddr>>()).map(|info| info.0),
            probe: parts.and_then(|p| p.extensions.get::<AuthProbe>()).cloned(),
        }
    }

    fn report(&self, accepted: bool) {
        if let Some(probe) = &self.probe {
            probe.report(accepted);
        }
    }
}

/// Stands in for the result once the credential was refused: the response
/// becomes HTTP 401 before it leaves.
fn refused() -> ErrorData {
    ErrorData::invalid_request("Unauthorized", None)
}

impl LuraMcp {
    /// Runs `calls` in order, stopping at a 401; `None` when the credential
    /// was refused.
    async fn run(&self, invocation: &Invocation, calls: &[Call]) -> Option<Vec<Reply>> {
        let mut replies = Vec::with_capacity(calls.len());
        for call in calls {
            let reply = self.internal.run(call, invocation.authorization.as_ref(), invocation.peer).await;
            if reply.status == StatusCode::UNAUTHORIZED {
                invocation.report(false);
                return None;
            }
            replies.push(reply);
        }
        invocation.report(true);
        Some(replies)
    }

    /// Checks the credential of a call that runs no request of its own.
    async fn authorized(&self, invocation: &Invocation) -> bool {
        self.run(invocation, &[Call::get("/store-api/auth/whoami".into())]).await.is_some()
    }
}

impl ServerHandler for LuraMcp {
    fn get_info(&self) -> ServerConfig {
        let capabilities = ServerCapabilities::builder().enable_tools().enable_resources().build();
        ServerConfig::new(capabilities)
            .with_server_info(Implementation::new("luradb", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "LuraDB: key-value, JSON document and relational (LuraSQL) domains. Start with list_domains, \
                 then describe the domain, its tables or indexes. Every call runs with the permissions of the \
                 caller's API key.",
            )
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, ErrorData>> + Send + '_ {
        let role = context.extensions.get::<Parts>().and_then(|p| p.extensions.get::<Caller>()).map_or(Role::User, |c| c.0);
        std::future::ready(Ok(ListToolsResult::with_all_items(tools::listed(role, self.switches))))
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CallToolResponse, ErrorData>> + Send + '_ {
        async move {
            let invocation = Invocation::of(&context);
            let spec = tools::find(&request.name).filter(|spec| spec.offered(self.switches));
            let planned = spec.map(|spec| {
                tools::plan(spec, &request.arguments.clone().unwrap_or_default(), MAX_STATEMENT_LEN)
            });
            let plan = match planned {
                Some(Ok(plan)) => plan,
                // Nothing runs: the credential still has to be valid.
                Some(Err(refusal)) => {
                    return if self.authorized(&invocation).await { Ok(refusal.into_result().into()) } else { Err(refused()) };
                }
                None => {
                    return if self.authorized(&invocation).await {
                        Err(ErrorData::invalid_params(format!("tool '{}' is not available", request.name), None))
                    } else {
                        Err(refused())
                    };
                }
            };
            let replies = self.run(&invocation, &plan.calls).await.ok_or_else(refused)?;
            Ok(plan.result(&replies).into())
        }
    }

    fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListResourcesResult, ErrorData>> + Send + '_ {
        std::future::ready(Ok(ListResourcesResult::with_all_items(resources::listed())))
    }

    fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListResourceTemplatesResult, ErrorData>> + Send + '_ {
        std::future::ready(Ok(ListResourceTemplatesResult::with_all_items(resources::templates())))
    }

    fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ReadResourceResponse, ErrorData>> + Send + '_ {
        async move {
            let invocation = Invocation::of(&context);
            let read = match resources::read(&request.uri) {
                Ok(read) => read,
                Err(e) => return if self.authorized(&invocation).await { Err(e) } else { Err(refused()) },
            };
            let replies = self.run(&invocation, &read.calls()).await.ok_or_else(refused)?;
            read.result(&request.uri, &replies).map(Into::into)
        }
    }
}
