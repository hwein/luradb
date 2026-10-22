//! Built-in MCP server (Model Context Protocol, Streamable HTTP transport)
//! on a listener and a runtime of its own. Every tool call and resource read
//! becomes REST requests that run through the frontend layers and the bridge
//! like any REST request, with the caller's `Authorization` header: MCP
//! never grants more than the same API key does over REST.

mod guard;
mod handler;
mod internal;
mod oauth;
mod resources;
mod sql;
mod tools;

#[cfg(test)]
pub(crate) use internal::test_hook;

use crate::api::middleware::{proxy_fn, ParsedCidr};
use crate::config::LuraConfig;
use axum::middleware::from_fn_with_state;
use axum::Router;
use guard::Gate;
use handler::LuraMcp;
use internal::Internal;
use oauth::OAuth;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use std::sync::Arc;
use tokio::sync::watch;
use tools::Switches;

/// Worker threads of the MCP runtime. Its requests mostly wait for the
/// reader pool and the data shards, which do the work, so MCP clients and
/// their long-lived streams take no frontend worker.
pub const RUNTIME_WORKERS: usize = 1;

/// The router of the MCP listener; `internal` is the frontend layers in
/// front of the listener's own bridge. Must run on the MCP runtime: it ends
/// the open event streams once `shutdown` flips.
#[allow(clippy::disallowed_methods, reason = "runs on the MCP runtime")]
pub fn router(
    config: &LuraConfig,
    internal: Router,
    trusted_cidrs: Arc<Vec<ParsedCidr>>,
    mut shutdown: watch::Receiver<bool>,
) -> Router {
    let internal = Internal::new(internal);
    let handler = LuraMcp {
        internal: internal.clone(),
        switches: Switches { read_only: config.mcp.read_only, allow_ddl: config.mcp.allow_ddl },
    };
    // Origins are checked by `guard::check_origin`; any `Host` is accepted,
    // the listener may sit behind a proxy under any name.
    let sdk = StreamableHttpServerConfig::default().disable_allowed_hosts();
    let streams = sdk.cancellation_token.clone();
    tokio::spawn(async move {
        let _ = shutdown.changed().await;
        streams.cancel();
    });
    let service =
        StreamableHttpService::new(move || Ok(handler.clone()), Arc::new(LocalSessionManager::default()), sdk);

    let oauth_enabled = config.mcp.oauth_enabled;
    let gate = Arc::new(Gate {
        internal: internal.clone(),
        auth_enabled: config.auth.enabled,
        resource_metadata: oauth_enabled.then(|| OAuth::resource_metadata_url(&config.mcp.public_url)),
    });
    let origins = Arc::new(config.mcp.allowed_origins.clone());
    let mut app = Router::new()
        .route_service("/mcp", service)
        .route_layer(from_fn_with_state(gate, guard::authenticate))
        .route_layer(from_fn_with_state(origins, guard::check_origin));
    if oauth_enabled {
        app = app.merge(oauth::routes(Arc::new(OAuth::new(internal, &config.mcp.public_url))));
    }
    // Resolves the client IP behind trusted proxies, for the sign-in limit.
    app.layer(from_fn_with_state(trusted_cidrs, proxy_fn))
}
