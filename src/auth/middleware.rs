//! Auth middleware — validates Bearer tokens and enforces domain permissions.
//!
//! Sits before the existing middleware stack:
//!   Request → AuthMiddleware → DomainResolver → RateLimiter → Handler

use crate::auth::{AccessLevel, AuthCache};
use axum::{
    extract::Request,
    http::{header, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;

/// Marker set by the UDS accept loop for connections whose kernel-verified
/// peer UID is in `auth.trusted_uids`. Grants admin access.
/// Clients cannot forge request extensions, so its presence is trustworthy.
#[derive(Clone, Copy, Debug)]
pub struct TrustedPeer;

/// Marker the MCP listener sets on the internal requests it builds for its
/// tools, resources and OAuth endpoints; no network request carries it. Only
/// such requests may use an OAuth access token or reach the internal OAuth
/// routes.
#[derive(Clone, Copy, Debug)]
pub struct McpInternal;

/// Store type of a domain-scoped request — KV, JSON and rel domains are
/// separate permission namespaces.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum StoreType {
    Kv,
    Json,
    Rel,
}

/// Extracts `(store_type, domain, management)` from domain-scoped API paths:
///   /store-api/kv/{domain}/…             → (Kv, domain, false)
///   /store-api/json/{domain}/…           → (Json, domain, false)
///   /store-api/rel/{domain}/…            → (Rel, domain, false)
///   /store-api/domains/{domain}[/…]      → (Kv, domain, true)   KV domain management
///   /store-api/json/domains/{domain}     → (Json, domain, true) JSON domain management
///   /store-api/rel/domains/{domain}      → (Rel, domain, true)  rel domain management
///   /store-api/metrics/domains/{domain}  → (Kv, domain, false)  domain metrics
/// The domain listings (`/store-api/{,json/,rel/}domains`) and everything
/// else → None.
pub(crate) fn extract_domain(path: &str) -> Option<(StoreType, &str, bool)> {
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    match segments.as_slice() {
        ["store-api", "kv", domain, ..] if !domain.is_empty() => {
            Some((StoreType::Kv, domain, false))
        }
        ["store-api", "json", "domains", domain] if !domain.is_empty() => {
            Some((StoreType::Json, domain, true))
        }
        ["store-api", "json", "domains", ..] => None,
        ["store-api", "json", domain, ..] if !domain.is_empty() => {
            Some((StoreType::Json, domain, false))
        }
        ["store-api", "rel", "domains", domain] if !domain.is_empty() => {
            Some((StoreType::Rel, domain, true))
        }
        ["store-api", "rel", "domains", ..] => None,
        ["store-api", "rel", domain, ..] if !domain.is_empty() => {
            Some((StoreType::Rel, domain, false))
        }
        ["store-api", "domains", domain, ..] if !domain.is_empty() => {
            Some((StoreType::Kv, domain, true))
        }
        ["store-api", "metrics", "domains", domain, ..] if !domain.is_empty() => {
            Some((StoreType::Kv, domain, false))
        }
        _ => None,
    }
}

fn is_domain_listing(path: &str) -> bool {
    matches!(path, "/store-api/domains" | "/store-api/json/domains" | "/store-api/rel/domains")
}

/// POST counts as a write except for the read-only `/search` endpoint and
/// `/sql`: its required level depends on the statement, so the
/// handler enforces it after parsing — the middleware only demands `Read`.
fn is_write_request(method: &Method, path: &str) -> bool {
    match *method {
        Method::PUT | Method::DELETE | Method::PATCH => true,
        Method::POST => !(path.ends_with("/search") || path.ends_with("/sql")),
        _ => false,
    }
}

/// Permission-table key for a domain: JSON/rel domains live in their own
/// namespace (`json:{domain}` / `rel:{domain}`), plain names are KV permissions.
pub(crate) fn permission_domain(store_type: StoreType, domain: &str) -> String {
    match store_type {
        StoreType::Kv => domain.to_string(),
        StoreType::Json => format!("json:{domain}"),
        StoreType::Rel => format!("rel:{domain}"),
    }
}

/// Reverses `permission_domain`. Domain names never contain `:` (enforced by
/// each engine's domain-name validation at creation time), and
/// `permission_domain` is the only writer of these keys — so the prefix
/// match below is unambiguous and total, with no fallback branch needed.
pub(crate) fn split_permission_domain(stored: &str) -> (StoreType, &str) {
    if let Some(domain) = stored.strip_prefix("json:") {
        (StoreType::Json, domain)
    } else if let Some(domain) = stored.strip_prefix("rel:") {
        (StoreType::Rel, domain)
    } else {
        (StoreType::Kv, stored)
    }
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
}

fn forbidden() -> Response {
    (StatusCode::FORBIDDEN, "Forbidden").into_response()
}

/// Result of the middleware auth check for a domain-scoped request, handed to
/// handlers that need a finer check than the path allows (`/sql`).
/// Set by `auth_layer` into the request extensions.
#[derive(Clone, Copy, Debug)]
pub enum AuthOutcome {
    /// Admin key or trusted UDS peer — full access, no statement check.
    Full,
    /// Regular user; `level` is the granted level for the request's domain.
    Scoped(AccessLevel),
}

/// Username of a regular user, set into the request extensions alongside
/// `AuthOutcome::Scoped`, or alone on the domain listings. Additive —
/// `AuthOutcome` itself is unchanged (`backup.rs` depends on its exact shape).
/// Lets handlers that need a per-engine permission lookup (cross-engine link
/// authorization, domain listings) resolve the caller's username without
/// re-deriving it from the request.
#[derive(Clone, Debug)]
pub struct AuthUser(pub String);

/// Enforces the statement-exact level in the `/sql` handler.
/// `required` is mapped by the caller from `StatementClass`. `auth_enabled`
/// comes from `AppState`: a missing outcome may only pass when auth is
/// globally off — otherwise fail-closed (403), since a missing outcome while
/// auth is on would be a middleware bug that must never grant silent full access.
pub fn enforce_sql_level(
    auth_enabled: bool,
    outcome: Option<AuthOutcome>,
    required: AccessLevel,
) -> Result<(), Box<Response>> {
    match outcome {
        Some(AuthOutcome::Full) => Ok(()),
        Some(AuthOutcome::Scoped(level)) if level >= required => Ok(()),
        Some(AuthOutcome::Scoped(_)) => Err(Box::new(forbidden())),
        None if !auth_enabled => Ok(()), // auth globally off: nothing is checked anywhere
        None => Err(Box::new(forbidden())), // auth on, outcome missing: fail-closed
    }
}

/// Axum middleware function for auth enforcement.
///
/// Call with `axum::middleware::from_fn_with_state(state, auth_layer)`.
pub async fn auth_layer(
    axum::extract::State(cache): axum::extract::State<Arc<AuthCache>>,
    mut request: Request,
    next: Next,
) -> Response {
    // Public endpoints bypass auth entirely
    let path = request.uri().path().to_string();
    if path == "/health" {
        return next.run(request).await;
    }

    // The MCP listener's OAuth state: its client registrations and code
    // exchanges carry no user key, and for every other caller the routes
    // do not exist.
    let mcp_internal = request.extensions().get::<McpInternal>().is_some();
    if path.starts_with("/store-api/auth/oauth/") {
        return if mcp_internal { next.run(request).await } else { StatusCode::NOT_FOUND.into_response() };
    }

    // UDS peers with a trusted UID are authenticated by the kernel.
    if request.extensions().get::<TrustedPeer>().is_some() {
        request.extensions_mut().insert(AuthOutcome::Full);
        return next.run(request).await;
    }

    let user = match cache.resolve_bearer(request.headers(), mcp_internal, crate::auth::now_secs()).await {
        Some(u) => u,
        None => return unauthorized(),
    };

    // Whitelist (/version handshake, whoami): any valid
    // key passes for these paths, no domain permission or admin role
    // required. Must come after user resolution (so an invalid key still
    // 401s) but before the admin/domain logic below — extract_domain(…) is
    // None for both paths, which would otherwise 403 them.
    if path == "/version" || path == "/store-api/auth/whoami" {
        return next.run(request).await;
    }

    use crate::auth::UserRole;
    if user.role == UserRole::Admin {
        request.extensions_mut().insert(AuthOutcome::Full);
        return next.run(request).await;
    }

    // Domain listings are open to every user; the handler filters them by the
    // user's permissions. Creating a domain (POST) stays admin-only.
    if is_domain_listing(&path) && matches!(*request.method(), Method::GET | Method::HEAD) {
        request.extensions_mut().insert(AuthUser(user.name.clone()));
        return next.run(request).await;
    }

    // Regular user: check domain permission
    let (store_type, domain, management) = match extract_domain(&path) {
        Some(x) => x,
        None => {
            // Path doesn't include a domain (e.g. /auth/*, /metrics, /config).
            // Only admins can reach those.
            return forbidden();
        }
    };

    // Domain lifecycle (create/delete) is admin-only; GET on
    // management paths stays open to users with a permission on the domain.
    if management
        && matches!(
            *request.method(),
            Method::POST | Method::PUT | Method::DELETE | Method::PATCH
        )
    {
        return forbidden();
    }

    let perm_domain = permission_domain(store_type, domain);
    let perm = cache.get_permission(&user.name, &perm_domain).await;
    // Ddl > Write > Read: a higher grant covers path-based
    // writes too. `/sql` never requires more than Read here — the exact
    // statement level is the handler's job (`enforce_sql_level`).
    let required_min = if is_write_request(request.method(), &path) {
        AccessLevel::Write
    } else {
        AccessLevel::Read
    };
    match perm {
        Some(level) if level >= required_min => {
            request.extensions_mut().insert(AuthOutcome::Scoped(level));
            request.extensions_mut().insert(AuthUser(user.name.clone()));
            next.run(request).await
        }
        _ => forbidden(),
    }
}

/// Axum middleware for the OpenAPI/Swagger docs routes.
/// Applied only to the Swagger sub-router in `build_router` — never merged
/// into `create_router`'s route surface, which would trip the
/// router-contract coverage gate. Same "any valid key, no domain permission"
/// rule as the `/version` handshake in `auth_layer` above, since docs routes
/// aren't domain-scoped either.
pub async fn docs_auth_layer(
    axum::extract::State(cache): axum::extract::State<Arc<AuthCache>>,
    request: Request,
    next: Next,
) -> Response {
    if request.extensions().get::<TrustedPeer>().is_some() {
        return next.run(request).await;
    }
    let hash = match extract_bearer(request.headers()) {
        Some(h) => h,
        None => return unauthorized(),
    };
    if cache.get_user_by_key_hash(&hash).await.is_none() {
        return unauthorized();
    }
    next.run(request).await
}

pub(crate) fn extract_bearer(headers: &axum::http::HeaderMap) -> Option<String> {
    bearer_token(headers).map(crate::auth::hash_api_key)
}

/// The Bearer credential of `headers`, if any.
pub(crate) fn bearer_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    let token = headers.get(header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Bearer ")?;
    (!token.is_empty()).then_some(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_extraction() {
        assert_eq!(
            extract_domain("/store-api/kv/analytics/keys/foo"),
            Some((StoreType::Kv, "analytics", false))
        );
        assert_eq!(
            extract_domain("/store-api/json/users/documents/doc1"),
            Some((StoreType::Json, "users", false))
        );
        assert_eq!(
            extract_domain("/store-api/json/users/search"),
            Some((StoreType::Json, "users", false))
        );
        assert_eq!(extract_domain("/store-api/json/domains"), None);
        assert_eq!(
            extract_domain("/store-api/json/domains/users"),
            Some((StoreType::Json, "users", true))
        );
        assert_eq!(extract_domain("/store-api/json/domains/users/extra"), None);
        assert_eq!(extract_domain("/store-api/json/domains/"), None);
        assert_eq!(
            extract_domain("/store-api/rel/sales/sql"),
            Some((StoreType::Rel, "sales", false))
        );
        assert_eq!(
            extract_domain("/store-api/rel/sales/tables/orders/rows"),
            Some((StoreType::Rel, "sales", false))
        );
        assert_eq!(
            extract_domain("/store-api/rel/sales/tables/from-file"),
            Some((StoreType::Rel, "sales", false))
        );
        assert_eq!(extract_domain("/store-api/rel/domains"), None);
        assert_eq!(
            extract_domain("/store-api/rel/domains/sales"),
            Some((StoreType::Rel, "sales", true))
        );
        assert_eq!(extract_domain("/store-api/rel/domains/sales/extra"), None);
        assert_eq!(extract_domain("/store-api/rel/domains/"), None);
        assert_eq!(
            extract_domain("/store-api/domains/analytics"),
            Some((StoreType::Kv, "analytics", true))
        );
        assert_eq!(
            extract_domain("/store-api/metrics/domains/myapp"),
            Some((StoreType::Kv, "myapp", false))
        );
        assert_eq!(extract_domain("/store-api/auth/users"), None);
        assert_eq!(extract_domain("/store-api/domains"), None);
        assert_eq!(extract_domain("/health"), None);
    }

    #[test]
    fn write_detection() {
        assert!(is_write_request(&Method::PUT, "/store-api/json/d/documents/k"));
        assert!(is_write_request(&Method::DELETE, "/store-api/kv/d/keys/k"));
        assert!(is_write_request(&Method::POST, "/store-api/json/d/bulk"));
        assert!(is_write_request(&Method::POST, "/store-api/json/d/reindex"));
        assert!(is_write_request(&Method::POST, "/store-api/json/d/documents"));
        assert!(!is_write_request(&Method::POST, "/store-api/json/d/search"));
        assert!(!is_write_request(&Method::GET, "/store-api/json/d/documents"));
        assert!(!is_write_request(&Method::POST, "/store-api/rel/sales/sql"));
        assert!(is_write_request(&Method::POST, "/store-api/rel/sales/tables/t/rows"));
        assert!(!is_write_request(&Method::GET, "/store-api/rel/sales/tables/t/rows"));
        assert!(is_write_request(&Method::PUT, "/store-api/rel/sales/tables/t/rows/1"));
        assert!(is_write_request(&Method::DELETE, "/store-api/rel/sales/tables/t/rows/1"));
    }

    #[test]
    fn permission_domain_scoping() {
        assert_eq!(permission_domain(StoreType::Kv, "users"), "users");
        assert_eq!(permission_domain(StoreType::Json, "users"), "json:users");
        assert_eq!(permission_domain(StoreType::Rel, "sales"), "rel:sales");
    }

    #[test]
    fn split_permission_domain_roundtrip() {
        for (store_type, domain) in [
            (StoreType::Kv, "analytics"),
            (StoreType::Json, "users"),
            (StoreType::Rel, "sales"),
        ] {
            let stored = permission_domain(store_type, domain);
            assert_eq!(split_permission_domain(&stored), (store_type, domain));
        }
        // No prefix (pre-existing plain KV keys) -> Kv.
        assert_eq!(split_permission_domain("plain"), (StoreType::Kv, "plain"));
    }

    #[test]
    fn enforce_sql_level_matrix() {
        use AccessLevel::*;

        // Scoped(Read): only Read passes.
        assert!(enforce_sql_level(true, Some(AuthOutcome::Scoped(Read)), Read).is_ok());
        let err = enforce_sql_level(true, Some(AuthOutcome::Scoped(Read)), Write).unwrap_err();
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
        assert!(enforce_sql_level(true, Some(AuthOutcome::Scoped(Read)), Ddl).is_err());

        // Scoped(Write): Read/Write pass, Ddl doesn't.
        assert!(enforce_sql_level(true, Some(AuthOutcome::Scoped(Write)), Ddl).is_err());
        assert!(enforce_sql_level(true, Some(AuthOutcome::Scoped(Write)), Write).is_ok());
        assert!(enforce_sql_level(true, Some(AuthOutcome::Scoped(Write)), Read).is_ok());

        // Scoped(Ddl) covers everything.
        assert!(enforce_sql_level(true, Some(AuthOutcome::Scoped(Ddl)), Ddl).is_ok());

        // Full always passes, regardless of the required level.
        assert!(enforce_sql_level(true, Some(AuthOutcome::Full), Ddl).is_ok());

        // Missing outcome: only passes when auth is globally disabled
        // (fail-closed otherwise — a missing outcome with auth on is a bug).
        assert!(enforce_sql_level(false, None, Ddl).is_ok());
        assert!(enforce_sql_level(true, None, Ddl).is_err());
    }

    use axum::body::Body;
    use axum::http::Request;
    use tower::util::ServiceExt;
    use utoipa::OpenApi;

    /// Shared engine/state bootstrap for `make_app_with_auth` and
    /// `make_docs_app` below.
    async fn make_test_state(auth_enabled: bool) -> (crate::api::AppState, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let wal_path = dir.path().join("wal.log");
        let wal = Arc::new(crate::core::wal::WriteAheadLog::new(&wal_path).await.unwrap());
        let vlog_path = dir.path().join("vlog.log");
        let vlog = Arc::new(crate::storage::vlog::VLog::new(&vlog_path).await.unwrap());
        let fm = Arc::new(crate::storage::file_manager::FileManager::new(dir.path()).await.unwrap());
        let mm = Arc::new(crate::storage::manifest::ManifestManager::new(dir.path()));
        let engine = Arc::new(
            crate::engines::lsm::engine::LsmStorageEngine::new(
                wal, wal_path, vlog, vlog_path, fm, mm,
                crate::engines::lsm::engine::LsmEngineOptions::default(),
            )
            .await
            .unwrap(),
        );
        let metrics = crate::metrics::MetricsStore::new(crate::metrics::MetricsConfig::default());
        let registry = Arc::new(
            crate::engines::lsm::DomainRegistry::recover(
                engine,
                crate::engines::lsm::domain::DomainConfig::default(),
                Arc::clone(&metrics),
            )
            .await
            .unwrap(),
        );
        let bus = Arc::new(crate::core::events::GlobalEventBus::new(256, 1024));
        let (control, auth_cache) = crate::control::testing::start(dir.path(), Arc::clone(&registry), None, None, bus).await;
        let state = crate::api::AppState {
            registry,
            auth_cache,
            auth_enabled,
            metrics,
            json_engine: None,
            rel_engine: None,
            shm_manager: None,
            backup_manager: None,
            log_access: None,
            control,
            config: Arc::new(crate::config::LuraConfig::default()),
            config_path: "test.toml".to_string(),
            config_file_loaded: false,
        };
        (state, dir)
    }

    /// Same shape as `kv.rs`'s `make_app`, but with `auth_enabled: true` and
    /// no domain — /version and /health don't touch domains at all.
    async fn make_app_with_auth() -> (axum::Router, Arc<crate::auth::AuthCache>, tempfile::TempDir) {
        let (state, dir) = make_test_state(true).await;
        let auth_cache = Arc::clone(&state.auth_cache);
        let app = crate::api::router_inline(state, Arc::new(vec![]));
        (app, auth_cache, dir)
    }

    /// Builds the Swagger/docs sub-router + `docs_auth_layer`, merged with the
    /// regular API router — the docs part of the frontend router
    /// (`server::build_router`), without the engine bridge.
    async fn make_docs_app(auth_enabled: bool) -> (axum::Router, Arc<crate::auth::AuthCache>, tempfile::TempDir) {
        let (state, dir) = make_test_state(auth_enabled).await;
        let auth_cache = Arc::clone(&state.auth_cache);
        let mut docs_router = axum::Router::new().merge(
            utoipa_swagger_ui::SwaggerUi::new("/test-ui")
                .url("/api-docs/openapi.json", crate::api::ApiDoc::openapi()),
        );
        if auth_enabled {
            docs_router = docs_router.layer(axum::middleware::from_fn_with_state(
                Arc::clone(&auth_cache),
                docs_auth_layer,
            ));
        }
        let app = docs_router.merge(crate::api::router_inline(state, Arc::new(vec![])));
        (app, auth_cache, dir)
    }

    #[test]
    fn version_requires_valid_key_any_role() {
        crate::core::engine_runtime::block_on(async {
            let (app, auth_cache, _dir) = make_app_with_auth().await;

            // No token -> 401.
            let resp = app
                .clone()
                .oneshot(Request::builder().uri("/version").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

            // Non-admin key, no domain permission at all -> still passes /version.
            let key = "lura_test_version_key";
            auth_cache
                .upsert_user(crate::auth::UserRecord {
                    name: "worker".to_string(),
                    api_key_hash: crate::auth::hash_api_key(key),
                    role: crate::auth::UserRole::User,
                    created_at: 0,
                })
                .await
                .unwrap();
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/version")
                        .header("authorization", format!("Bearer {key}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);

            // Regression: /health stays reachable without a token.
            let resp = app
                .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        })
    }

    // Regression-critical: /store-api/config carries no `{domain}` segment, so
    // its admin-only protection is entirely implicit -- it falls out of
    // extract_domain's None branch above, same as /metrics, /events,
    // /backups*. A future path refactor that accidentally gave it a domain
    // segment would silently open it to any user holding some permission.
    #[test]
    fn config_endpoint_is_admin_only() {
        crate::core::engine_runtime::block_on(async {
            let (app, auth_cache, _dir) = make_app_with_auth().await;

            // Non-admin key, even with a domain permission -> 403 (no {domain}
            // segment in this path for that permission to apply to).
            let key = "lura_test_config_key";
            auth_cache
                .upsert_user(crate::auth::UserRecord {
                    name: "worker".to_string(),
                    api_key_hash: crate::auth::hash_api_key(key),
                    role: crate::auth::UserRole::User,
                    created_at: 0,
                })
                .await
                .unwrap();
            auth_cache
                .set_permission(crate::auth::DomainPermission {
                    username: "worker".to_string(),
                    domain: "shop".to_string(),
                    access: AccessLevel::Ddl,
                })
                .await
                .unwrap();
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/store-api/config")
                        .header("authorization", format!("Bearer {key}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);

            // Admin key -> 200.
            let admin_key = "lura_test_config_admin_key";
            auth_cache
                .upsert_user(crate::auth::UserRecord {
                    name: "admin".to_string(),
                    api_key_hash: crate::auth::hash_api_key(admin_key),
                    role: crate::auth::UserRole::Admin,
                    created_at: 0,
                })
                .await
                .unwrap();
            let resp = app
                .oneshot(
                    Request::builder()
                        .uri("/store-api/config")
                        .header("authorization", format!("Bearer {admin_key}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        })
    }

    #[test]
    fn docs_routes_require_key_when_auth_enabled() {
        crate::core::engine_runtime::block_on(async {
            let (app, _auth_cache, _dir) = make_docs_app(true).await;

            // openapi.json, the bare swagger_url (redirects to .../), and an
            // asset sub-path under it — the `{*rest}` wildcard SwaggerUi
            // registers for its own static assets is part of the same
            // sub-router, so it's covered by the same layer too, no path list
            // needed.
            for uri in ["/api-docs/openapi.json", "/test-ui", "/test-ui/does-not-exist.js"] {
                let resp = app
                    .clone()
                    .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{uri}");
            }

            // /health is untouched by this change.
            let resp = app
                .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        })
    }

    #[test]
    fn docs_routes_accept_any_valid_key_no_domain_permission() {
        crate::core::engine_runtime::block_on(async {
            let (app, auth_cache, _dir) = make_docs_app(true).await;

            // Non-admin key with no domain permission at all -> still 200, same
            // "any valid key" rule as /version (not 403 from the extract_domain
            // fallback that `auth_layer` would otherwise apply).
            let key = "lura_test_docs_key";
            auth_cache
                .upsert_user(crate::auth::UserRecord {
                    name: "worker".to_string(),
                    api_key_hash: crate::auth::hash_api_key(key),
                    role: crate::auth::UserRole::User,
                    created_at: 0,
                })
                .await
                .unwrap();

            for uri in ["/api-docs/openapi.json", "/test-ui/"] {
                let resp = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .uri(uri)
                            .header("authorization", format!("Bearer {key}"))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK, "{uri}");
            }
        })
    }

    #[test]
    fn docs_routes_accept_admin_key() {
        crate::core::engine_runtime::block_on(async {
            let (app, auth_cache, _dir) = make_docs_app(true).await;

            let key = "lura_test_docs_admin_key";
            auth_cache
                .upsert_user(crate::auth::UserRecord {
                    name: "admin".to_string(),
                    api_key_hash: crate::auth::hash_api_key(key),
                    role: crate::auth::UserRole::Admin,
                    created_at: 0,
                })
                .await
                .unwrap();

            let resp = app
                .oneshot(
                    Request::builder()
                        .uri("/api-docs/openapi.json")
                        .header("authorization", format!("Bearer {key}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        })
    }

    #[test]
    fn docs_routes_open_without_key_when_auth_disabled() {
        crate::core::engine_runtime::block_on(async {
            let (app, _auth_cache, _dir) = make_docs_app(false).await;

            for uri in ["/api-docs/openapi.json", "/test-ui/"] {
                let resp = app
                    .clone()
                    .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK, "{uri}");
            }
        })
    }
}
