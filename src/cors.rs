//! CORS layer for browser clients (spec general/020). Opt-in via `[cors]` —
//! `build_layer` returns `None` when disabled, so the router carries no
//! `CorsLayer` at all and behavior is unchanged from before this module
//! existed.

use crate::config::CorsConfig;
use axum::http::{header, HeaderName, HeaderValue, Method};
use tower_http::cors::{AllowOrigin, CorsLayer};

/// Builds the `CorsLayer` from config, or `None` when `cors.enabled = false`.
/// Methods/headers/max_age are fixed (spec general/020 §Feste Layer-Defaults)
/// — not configurable, since they follow from the API surface, not from
/// operations. `allowed_origins` is assumed already validated by
/// `CorsConfig::validate` (called at startup): every entry parses as a
/// `HeaderValue`, and `"*"` never appears mixed with concrete origins.
pub fn build_layer(cfg: &CorsConfig) -> Option<CorsLayer> {
    if !cfg.enabled {
        return None;
    }

    // "*" must become `AllowOrigin::any()`, never `AllowOrigin::list` — the
    // latter panics if the wildcard is among its entries.
    let allow_origin = if cfg.allowed_origins.iter().any(|o| o == "*") {
        AllowOrigin::any()
    } else {
        let origins: Vec<HeaderValue> = cfg
            .allowed_origins
            .iter()
            .map(|o| HeaderValue::from_str(o).expect("cors.allowed_origins validated at startup"))
            .collect();
        AllowOrigin::list(origins)
    };

    Some(
        CorsLayer::new()
            .allow_origin(allow_origin)
            .allow_methods([
                Method::GET,
                Method::HEAD,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
            ])
            .allow_headers([
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
                header::IF_MATCH,
                header::IF_NONE_MATCH,
                HeaderName::from_static("last-event-id"),
            ])
            .expose_headers([header::ETAG, HeaderName::from_static("x-expires-at")])
            .max_age(std::time::Duration::from_secs(3600)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::AppState;
    use crate::core::wal::WriteAheadLog;
    use crate::engines::lsm::{DomainRegistry, LsmStorageEngine};
    use crate::storage::file_manager::FileManager;
    use crate::storage::manifest::ManifestManager;
    use crate::storage::vlog::VLog;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::Arc;
    use tower::util::ServiceExt;

    fn cors_cfg(origins: &[&str]) -> CorsConfig {
        CorsConfig {
            enabled: true,
            allowed_origins: origins.iter().map(|s| s.to_string()).collect(),
        }
    }

    // ── build_layer (Test 2) ────────────────────────────────────────────────

    #[test]
    fn disabled_yields_no_layer() {
        assert!(build_layer(&CorsConfig::default()).is_none());
    }

    #[test]
    fn wildcard_does_not_panic() {
        // AllowOrigin::list panics on "*" — this proves any() is used instead.
        let _ = build_layer(&cors_cfg(&["*"])).expect("enabled config yields a layer");
    }

    // ── HTTP-level (Tests 3-9) ───────────────────────────────────────────────

    async fn make_state(auth_enabled: bool) -> (AppState, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let wal_path = dir.path().join("wal.log");
        let wal = Arc::new(WriteAheadLog::new(&wal_path).await.unwrap());
        let vlog_path = dir.path().join("vlog.log");
        let vlog = Arc::new(VLog::new(&vlog_path).await.unwrap());
        let fm = Arc::new(FileManager::new(dir.path()).await.unwrap());
        let mm = Arc::new(ManifestManager::new(dir.path()));
        let engine = Arc::new(
            LsmStorageEngine::new(
                wal, wal_path, vlog, vlog_path, fm, mm,
                crate::engines::lsm::engine::LsmEngineOptions::default(),
            )
            .await
            .unwrap(),
        );
        let auth_cache = Arc::new(crate::auth::AuthCache::new(Arc::clone(&engine)));
        let metrics = crate::metrics::MetricsStore::new(crate::metrics::MetricsConfig::default());
        let registry = Arc::new(
            DomainRegistry::recover(engine, crate::engines::lsm::domain::DomainConfig::default(), Arc::clone(&metrics))
                .await
                .unwrap(),
        );
        registry.create_domain("testdom").await.unwrap();
        let state = AppState {
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

    // Mirrors `build_router` in main.rs: the CorsLayer goes on top of the
    // fully merged router (spec general/020 §Platzierung), not inside
    // `create_router` — this is what puts it outside `auth_layer`.
    async fn make_app(
        cors: CorsConfig,
        auth_enabled: bool,
    ) -> (axum::Router, Arc<crate::auth::AuthCache>, tempfile::TempDir) {
        let (state, dir) = make_state(auth_enabled).await;
        let auth_cache = Arc::clone(&state.auth_cache);
        let mut app = crate::api::create_router(state, Arc::new(vec![]));
        if let Some(layer) = build_layer(&cors) {
            app = app.layer(layer);
        }
        (app, auth_cache, dir)
    }

    fn acao<B>(resp: &axum::http::Response<B>) -> Option<&str> {
        resp.headers().get("access-control-allow-origin")?.to_str().ok()
    }

    // Test 3: preflight bypasses auth entirely, even with no Authorization —
    // it never reaches auth_layer because the CORS layer is outside it.
    #[tokio::test]
    async fn preflight_bypasses_auth() {
        let (app, _auth_cache, _dir) = make_app(cors_cfg(&["https://console.example.com"]), true).await;

        let resp = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/store-api/kv/testdom/keys/foo")
                    .header("origin", "https://console.example.com")
                    .header("access-control-request-method", "DELETE")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(acao(&resp), Some("https://console.example.com"));
        let allow_methods = resp.headers().get("access-control-allow-methods").unwrap().to_str().unwrap();
        assert!(allow_methods.contains("DELETE") && allow_methods.contains("PATCH"), "{allow_methods}");
        let allow_headers = resp.headers().get("access-control-allow-headers").unwrap().to_str().unwrap();
        assert!(allow_headers.contains("authorization"), "{allow_headers}");
        assert!(resp.headers().get("access-control-max-age").is_some());
    }

    // Test 4: an origin not on the list gets no ACAO — the browser blocks
    // the response itself once it sees that.
    #[tokio::test]
    async fn disallowed_origin_gets_no_header() {
        let (app, _auth_cache, _dir) = make_app(cors_cfg(&["https://console.example.com"]), false).await;

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header("origin", "https://evil.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(acao(&resp).is_none());
    }

    // Test 5: no Origin header (curl, server-to-server) -> no ACAO, but the
    // request-independent Expose-Headers/Vary headers still ride along.
    #[tokio::test]
    async fn no_origin_header_gets_no_acao_but_keeps_static_headers() {
        let (app, _auth_cache, _dir) = make_app(cors_cfg(&["https://console.example.com"]), false).await;

        let resp = app
            .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert!(acao(&resp).is_none());
        assert!(resp.headers().get("access-control-expose-headers").is_some());
        assert!(resp.headers().get("vary").is_some());
    }

    // Test 6: an error response (401, no API key) still carries the CORS
    // header — otherwise the browser hides the real status behind a CORS error.
    #[tokio::test]
    async fn error_response_carries_cors_header() {
        let (app, _auth_cache, _dir) = make_app(cors_cfg(&["https://console.example.com"]), true).await;

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/store-api/kv/testdom/keys")
                    .header("origin", "https://console.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(acao(&resp), Some("https://console.example.com"));
    }

    // Test 7: Expose-Headers carries `etag` on a normal response, but is
    // absent from a preflight response (which only gets
    // allow_methods/allow_headers/max_age).
    #[tokio::test]
    async fn expose_headers_only_on_normal_responses() {
        let (app, _auth_cache, _dir) = make_app(cors_cfg(&["https://console.example.com"]), false).await;

        let normal = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header("origin", "https://console.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let expose = normal.headers().get("access-control-expose-headers").unwrap().to_str().unwrap();
        assert!(expose.contains("etag"), "{expose}");

        let preflight = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/health")
                    .header("origin", "https://console.example.com")
                    .header("access-control-request-method", "GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(preflight.headers().get("access-control-expose-headers").is_none());
    }

    // Test 8: the SSE watch response carries the CORS header too —
    // EventSource can't send an Authorization header, and fetch-based
    // browser clients reading the stream need it just the same.
    #[tokio::test]
    async fn watch_sse_response_carries_cors_header() {
        let (app, _auth_cache, _dir) = make_app(cors_cfg(&["https://console.example.com"]), false).await;

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/store-api/kv/testdom/watch")
                    .header("origin", "https://console.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(acao(&resp), Some("https://console.example.com"));
    }

    // Test 9: wildcard operation — ACAO: * regardless of the request's
    // Origin, including when there is none; Allow-Credentials never sent.
    #[tokio::test]
    async fn wildcard_allows_any_origin_and_no_origin_without_credentials() {
        let (app, _auth_cache, _dir) = make_app(cors_cfg(&["*"]), false).await;

        let with_origin = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header("origin", "https://anything.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(acao(&with_origin), Some("*"));
        assert!(with_origin.headers().get("access-control-allow-credentials").is_none());

        let without_origin = app
            .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(acao(&without_origin), Some("*"));
        assert!(without_origin.headers().get("access-control-allow-credentials").is_none());
    }
}
