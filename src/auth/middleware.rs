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
/// peer UID is in `auth.trusted_uids` (spec perf/001). Grants admin access.
/// Clients cannot forge request extensions, so its presence is trustworthy.
#[derive(Clone, Copy, Debug)]
pub struct TrustedPeer;

/// Store type of a domain-scoped request — KV, JSON and rel domains are
/// separate permission namespaces (spec json/012, rel/011).
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
///   /store-api/metrics/domains/{domain}  → (Kv, domain, false)  domain metrics
/// `/store-api/json/domains/…`, `/store-api/rel/domains/…` and everything
/// else → None (admin-only).
fn extract_domain(path: &str) -> Option<(StoreType, &str, bool)> {
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    match segments.as_slice() {
        ["store-api", "kv", domain, ..] if !domain.is_empty() => {
            Some((StoreType::Kv, domain, false))
        }
        ["store-api", "json", "domains", ..] => None,
        ["store-api", "json", domain, ..] if !domain.is_empty() => {
            Some((StoreType::Json, domain, false))
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

/// POST counts as a write except for the read-only `/search` endpoint and
/// `/sql` (rel/011 §4): its required level depends on the statement, so the
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
/// handlers that need a finer check than the path allows (rel/009 `/sql`).
/// Set by `auth_layer` into the request extensions.
#[derive(Clone, Copy, Debug)]
pub enum AuthOutcome {
    /// Admin key or trusted UDS peer — full access, no statement check.
    Full,
    /// Regular user; `level` is the granted level for the request's domain.
    Scoped(AccessLevel),
}

/// Username of a Scoped user, set into the request extensions alongside
/// `AuthOutcome::Scoped` (spec rel/016). Additive — `AuthOutcome` itself is
/// unchanged (`backup.rs` depends on its exact shape). Lets handlers that
/// need a per-engine permission lookup (cross-engine link authorization)
/// resolve the caller's username without re-deriving it from the request.
#[derive(Clone, Debug)]
pub struct AuthUser(pub String);

/// Enforces the statement-exact level in the `/sql` handler (rel/011 §4).
/// `required` is mapped by the caller from `StatementClass`. `auth_enabled`
/// comes from `AppState`: a missing outcome may only pass when auth is
/// globally off — otherwise fail-closed (403), since a missing outcome while
/// auth is on would be a middleware bug that must never grant silent full access.
pub fn enforce_sql_level(
    auth_enabled: bool,
    outcome: Option<AuthOutcome>,
    required: AccessLevel,
) -> Result<(), Response> {
    match outcome {
        Some(AuthOutcome::Full) => Ok(()),
        Some(AuthOutcome::Scoped(level)) if level >= required => Ok(()),
        Some(AuthOutcome::Scoped(_)) => Err(forbidden()),
        None if !auth_enabled => Ok(()), // auth globally off: nothing is checked anywhere
        None => Err(forbidden()),        // auth on, outcome missing: fail-closed
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

    // UDS peers with a trusted UID are authenticated by the kernel (perf/001).
    if request.extensions().get::<TrustedPeer>().is_some() {
        request.extensions_mut().insert(AuthOutcome::Full);
        return next.run(request).await;
    }

    let hash = match extract_bearer(request.headers()) {
        Some(h) => h,
        None => return unauthorized(),
    };

    let user = match cache.get_user_by_key_hash(&hash).await {
        Some(u) => u,
        None => return unauthorized(),
    };

    // Whitelist (spec 004 §7 for /version, general/016 for whoami): any valid
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

    // Regular user: check domain permission
    let (store_type, domain, management) = match extract_domain(&path) {
        Some(x) => x,
        None => {
            // Path doesn't include a domain (e.g. /auth/* or /json/domains/*
            // management routes). Only admins can reach those.
            return forbidden();
        }
    };

    // Domain lifecycle (create/delete) is admin-only (spec kv/012); GET on
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
    // Ddl > Write > Read (spec rel/011 §3): a higher grant covers path-based
    // writes too. `/sql` never requires more than Read here — the exact
    // statement level is the handler's job (`enforce_sql_level`, §4).
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

/// Axum middleware for the OpenAPI/Swagger docs routes (spec general/014).
/// Applied only to the Swagger sub-router in `build_router` — never merged
/// into `create_router`'s route surface, which would trip the general/009
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
    let value = headers.get(header::AUTHORIZATION)?;
    let s = value.to_str().ok()?;
    let token = s.strip_prefix("Bearer ")?;
    if token.is_empty() {
        return None;
    }
    Some(crate::auth::hash_api_key(token))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

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
        assert_eq!(extract_domain("/store-api/json/domains/users"), None);
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
        assert_eq!(extract_domain("/store-api/rel/domains/sales"), None);
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

    // ── HTTP-level: /version handshake + /health regression (spec 004 §7) ──

    use axum::body::Body;
    use axum::http::Request;
    use tower::util::ServiceExt;
    use utoipa::OpenApi;

    /// Shared engine/state bootstrap for `make_app_with_auth` and
    /// `make_docs_app` below (spec general/014).
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
        let auth_cache = Arc::new(crate::auth::AuthCache::new(Arc::clone(&engine)));
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
            event_bus: Arc::new(crate::core::events::GlobalEventBus::new(256, 1024)),
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
        let app = crate::api::create_router(state, Arc::new(vec![]));
        (app, auth_cache, dir)
    }

    /// Builds the Swagger/docs sub-router + `docs_auth_layer`, merged with the
    /// regular API router — mirrors `build_router` in `main.rs` (spec
    /// general/014). Can't call `build_router` itself: it's private to the
    /// binary crate, and this test module also compiles under the library
    /// crate (`src/lib.rs` declares the same `pub mod` tree).
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
        let app = docs_router.merge(crate::api::create_router(state, Arc::new(vec![])));
        (app, auth_cache, dir)
    }

    #[tokio::test]
    async fn version_requires_valid_key_any_role() {
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
    }

    // ── /store-api/config admin-only (spec general/022) ──────────────────────

    // Regression-critical: /store-api/config carries no `{domain}` segment, so
    // its admin-only protection is entirely implicit -- it falls out of
    // extract_domain's None branch above, same as /metrics, /events,
    // /backups*. A future path refactor that accidentally gave it a domain
    // segment would silently open it to any user holding some permission.
    #[tokio::test]
    async fn config_endpoint_is_admin_only() {
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
    }

    // ── Docs routes behind auth (spec general/014) ──────────────────────────

    #[tokio::test]
    async fn docs_routes_require_key_when_auth_enabled() {
        let (app, _auth_cache, _dir) = make_docs_app(true).await;

        // openapi.json, the bare swagger_url (redirects to .../), and an
        // asset sub-path under it (spec general/014: asset sub-paths under
        // swagger_url) — the `*rest` wildcard SwaggerUi registers for its own
        // static assets is part of the same sub-router, so it's covered by
        // the same layer too, no path list needed.
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
    }

    #[tokio::test]
    async fn docs_routes_accept_any_valid_key_no_domain_permission() {
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
    }

    #[tokio::test]
    async fn docs_routes_accept_admin_key() {
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
    }

    #[tokio::test]
    async fn docs_routes_open_without_key_when_auth_disabled() {
        let (app, _auth_cache, _dir) = make_docs_app(false).await;

        for uri in ["/api-docs/openapi.json", "/test-ui/"] {
            let resp = app
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
        }
    }
}
