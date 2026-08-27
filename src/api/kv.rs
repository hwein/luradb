//! Domain-scoped KV REST handlers.
//!
//! PUT    /store-api/kv/{domain}/keys/{key}          → put_key   (200 | 429 | 400)
//! PUT    /store-api/kv/{domain}/keys/{key}?ttl=N    → put_key   (TTL variant)
//! GET    /store-api/kv/{domain}/keys/{key}          → get_key   (200 | 204 | 404 | 429)
//! DELETE /store-api/kv/{domain}/keys/{key}          → delete_key (204 | 429)
//! PATCH  /store-api/kv/{domain}/keys/{key}/null     → set_null  (200 | 429)
//! GET    /store-api/kv/{domain}/keys/{key}/meta     → get_key_meta (200 | 400 | 404 | 410 | 429)
//! GET    /store-api/kv/{domain}/keys?prefix={p}     → scan_keys (200 | 429)
//! GET    /store-api/kv/{domain}/watch?prefix={p}    → watch     (SSE stream)

use crate::api::{middleware::ApiError, AppState};
use crate::engines::lsm::{GetResult, OpType};
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Json, Response,
    },
};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use utoipa::ToSchema;

// ── Query param types ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct TtlParams {
    pub ttl: Option<u64>,
}

#[derive(Deserialize)]
pub struct ScanParams {
    pub prefix: Option<String>,
}

#[derive(Deserialize)]
pub struct WatchParams {
    pub prefix: Option<String>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn resolve(
    state: &AppState,
    domain: &str,
) -> Result<crate::engines::lsm::DomainStore, ApiError> {
    state.registry.store(domain).await.map_err(ApiError::from)
}

// ── Handlers ─────────────────────────────────────────────────────────────────

#[utoipa::path(
    put,
    path = "/store-api/kv/{domain}/keys/{key}",
    params(
        ("domain" = String, Path, description = "Domain name"),
        ("key"    = String, Path, description = "Key (valid UTF-8, max 256 bytes)"),
        ("ttl"    = Option<u64>, Query, description = "TTL in seconds (optional)"),
    ),
    request_body(content = String, content_type = "text/plain"),
    responses(
        (status = 200, description = "Key upserted"),
        (status = 429, description = "Rate limit exceeded", headers(("Retry-After" = u64))),
        (status = 400, description = "Invalid key"),
        (status = 404, description = "Domain not found"),
        (status = 410, description = "Domain is being deleted"),
    ),
    tag = "Key-Value Store"
)]
/// Inserts or updates a value for the given key (upsert semantics).
/// The optional `ttl` query parameter sets an expiry in seconds; omitting it stores the key indefinitely.
pub async fn put_key(
    State(state): State<AppState>,
    Path((domain, key)): Path<(String, String)>,
    Query(params): Query<TtlParams>,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let store = resolve(&state, &domain).await?;
    match params.ttl {
        Some(ttl) => {
            store.put_with_ttl(key.as_bytes(), &body, ttl).await.map_err(ApiError::from)?
        }
        None => store.put(key.as_bytes(), &body).await.map_err(ApiError::from)?,
    }
    Ok(StatusCode::OK)
}

#[utoipa::path(
    get,
    path = "/store-api/kv/{domain}/keys/{key}",
    params(
        ("domain" = String, Path, description = "Domain name"),
        ("key"    = String, Path, description = "Key (valid UTF-8, max 256 bytes)"),
    ),
    responses(
        (status = 200, description = "Value (raw bytes; an empty value yields an empty body). The `X-Expires-At` header (absolute Unix seconds) is present only when the key has a TTL.", content_type = "application/octet-stream", headers(("X-Expires-At" = u64))),
        (status = 204, description = "Key exists in the explicit null state (set via PATCH …/null)"),
        (status = 404, description = "Key or domain not found"),
        (status = 429, description = "Rate limit exceeded", headers(("Retry-After" = u64))),
        (status = 400, description = "Invalid key"),
        (status = 410, description = "Domain is being deleted"),
    ),
    tag = "Key-Value Store"
)]
/// Retrieves the raw byte value for a key. Returns 204 for a key in the null state and 404 if the key does not exist or has expired.
/// When the key has a TTL, the response carries an `X-Expires-At` header with the absolute Unix-seconds expiry.
pub async fn get_key(
    State(state): State<AppState>,
    Path((domain, key)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let store = resolve(&state, &domain).await?;
    let (result, expire_at) = store.get_with_expiry(key.as_bytes()).await.map_err(ApiError::from)?;
    match result {
        GetResult::Present(value) => {
            let mut resp = Bytes::from(value).into_response();
            if expire_at != 0 {
                resp.headers_mut().insert("x-expires-at", expire_at.to_string().parse().unwrap());
            }
            Ok(resp)
        }
        GetResult::Null => Ok(StatusCode::NO_CONTENT.into_response()),
        GetResult::Absent => Err(ApiError::from(anyhow::anyhow!(
            "404 Not Found: key '{}' not found",
            key
        ))),
    }
}

// ── KeyMetaResponse DTO ────────────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct KeyMetaResponse {
    /// Absolute Unix-seconds TTL expiry; `null` when the key has no TTL. Equal to the `X-Expires-At` header when present.
    pub expires_at: Option<u64>,
    /// Unix-milliseconds write time of the newest visible version (PUT, or PATCH …/null) — not a creation timestamp; every overwrite advances it.
    pub last_modified_at: u64,
}

#[utoipa::path(
    get,
    path = "/store-api/kv/{domain}/keys/{key}/meta",
    params(
        ("domain" = String, Path, description = "Domain name"),
        ("key"    = String, Path, description = "Key (valid UTF-8, max 256 bytes)"),
    ),
    responses(
        (status = 200, description = "Key metadata", body = KeyMetaResponse),
        (status = 400, description = "Invalid key"),
        (status = 404, description = "Key or domain not found"),
        (status = 410, description = "Domain is being deleted"),
        (status = 429, description = "Rate limit exceeded", headers(("Retry-After" = u64))),
    ),
    tag = "Key-Value Store"
)]
/// Returns a key's TTL expiry and last-modified time without reading its value (no VLog dereference).
/// `last_modified_at` is the write time of the newest visible version (PUT, or PATCH …/null) — not a
/// creation timestamp; every overwrite advances it.
pub async fn get_key_meta(
    State(state): State<AppState>,
    Path((domain, key)): Path<(String, String)>,
) -> Result<Json<KeyMetaResponse>, ApiError> {
    let store = resolve(&state, &domain).await?;
    let meta = store
        .get_meta(key.as_bytes())
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::from(anyhow::anyhow!("404 Not Found: key '{}' not found", key)))?;
    Ok(Json(KeyMetaResponse {
        expires_at: if meta.expire_at == 0 { None } else { Some(meta.expire_at) },
        last_modified_at: meta.last_modified_ms,
    }))
}

#[utoipa::path(
    delete,
    path = "/store-api/kv/{domain}/keys/{key}",
    params(
        ("domain" = String, Path, description = "Domain name"),
        ("key"    = String, Path, description = "Key (valid UTF-8, max 256 bytes)"),
    ),
    responses(
        (status = 204, description = "Key deleted"),
        (status = 429, description = "Rate limit exceeded", headers(("Retry-After" = u64))),
        (status = 400, description = "Invalid key"),
        (status = 410, description = "Domain is being deleted"),
    ),
    tag = "Key-Value Store"
)]
/// Permanently removes a key from the domain. The operation is idempotent; deleting a non-existent key still returns 204.
pub async fn delete_key(
    State(state): State<AppState>,
    Path((domain, key)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let store = resolve(&state, &domain).await?;
    store.delete(key.as_bytes()).await.map_err(ApiError::from)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    patch,
    path = "/store-api/kv/{domain}/keys/{key}/null",
    params(
        ("domain" = String, Path, description = "Domain name"),
        ("key"    = String, Path, description = "Key (valid UTF-8, max 256 bytes)"),
    ),
    responses(
        (status = 200, description = "Key set to the null value state"),
        (status = 429, description = "Rate limit exceeded", headers(("Retry-After" = u64))),
        (status = 400, description = "Invalid key"),
        (status = 410, description = "Domain is being deleted"),
    ),
    tag = "Key-Value Store"
)]
/// Sets the key to an explicit null value (upsert): the key stays registered and appears in scans,
/// but carries no data — GET answers 204. A write like any other; it resets a previously set TTL.
pub async fn set_null(
    State(state): State<AppState>,
    Path((domain, key)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let store = resolve(&state, &domain).await?;
    store.set_null(key.as_bytes()).await.map_err(ApiError::from)?;
    Ok(StatusCode::OK)
}

#[utoipa::path(
    get,
    path = "/store-api/kv/{domain}/keys",
    params(
        ("domain" = String, Path, description = "Domain name"),
        ("prefix" = Option<String>, Query, description = "Key prefix filter"),
    ),
    responses(
        (status = 200, description = "List of matching keys", body = Vec<String>),
        (status = 429, description = "Rate limit exceeded", headers(("Retry-After" = u64))),
        (status = 410, description = "Domain is being deleted"),
    ),
    tag = "Key-Value Store"
)]
/// Lists all keys in the domain, optionally filtered by a prefix. Returns an empty array if no keys match.
pub async fn scan_keys(
    State(state): State<AppState>,
    Path(domain): Path<String>,
    Query(params): Query<ScanParams>,
) -> Result<Json<Vec<String>>, ApiError> {
    let store = resolve(&state, &domain).await?;
    let prefix = params.prefix.unwrap_or_default();
    let raw = store.scan_keys(prefix.as_bytes()).await.map_err(ApiError::from)?;
    let keys: Vec<String> =
        raw.into_iter().map(|k| String::from_utf8_lossy(&k).into_owned()).collect();
    Ok(Json(keys))
}

#[utoipa::path(
    get,
    path = "/store-api/kv/{domain}/watch",
    params(
        ("domain" = String, Path, description = "Domain name"),
        ("prefix" = Option<String>, Query, description = "Key prefix filter"),
    ),
    responses(
        (status = 200, description = "SSE stream of key change events", content_type = "text/event-stream"),
        (status = 410, description = "Domain is being deleted"),
    ),
    tag = "Key-Value Store"
)]
/// Opens a Server-Sent Events stream that delivers real-time change events (`set` / `delete`) for keys matching the optional prefix.
/// The connection stays open until the client disconnects; a keep-alive ping is sent automatically.
pub async fn watch(
    State(state): State<AppState>,
    Path(domain): Path<String>,
    Query(params): Query<WatchParams>,
) -> Result<
    Sse<impl futures::Stream<Item = Result<Event, Infallible>> + Send + 'static>,
    ApiError,
> {
    let store = resolve(&state, &domain).await?;
    let prefix_bytes: Vec<u8> = params.prefix.unwrap_or_default().into_bytes();
    let rx = store.watch();

    let stream = futures::stream::unfold(
        (rx, prefix_bytes),
        |(mut rx, prefix)| async move {
            loop {
                match rx.recv().await {
                    Ok(event) if event.key.starts_with(&prefix) => {
                        let op_str = match event.op {
                            OpType::Set => "set",
                            OpType::Delete => "delete",
                        };
                        let key_str = String::from_utf8_lossy(&event.key).into_owned();
                        let sse = Event::default().event(op_str).data(key_str);
                        return Some((Ok::<Event, Infallible>(sse), (rx, prefix)));
                    }
                    Ok(_) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                }
            }
        },
    );

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::AppState;
    use crate::engines::lsm::{DomainRegistry, LsmStorageEngine};
    use crate::core::wal::WriteAheadLog;
    use crate::storage::vlog::VLog;
    use crate::storage::file_manager::FileManager;
    use crate::storage::manifest::ManifestManager;
    use axum::body::{to_bytes, Body};
    use axum::http::{Method, Request};
    use axum::response::IntoResponse;
    use std::sync::Arc;
    use tower::util::ServiceExt; // requires tower feature "util"

    async fn make_app() -> (axum::Router, tempfile::TempDir) {
        make_app_with_config(crate::engines::lsm::domain::DomainConfig::default()).await
    }

    // Spec kv/022 test 10 needs a domain with a near-zero read quota to
    // force a 429 without hundreds of requests; every other test keeps
    // using the default-quota `make_app` above.
    async fn make_app_with_config(config: crate::engines::lsm::domain::DomainConfig) -> (axum::Router, tempfile::TempDir) {
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
        let registry = Arc::new(DomainRegistry::recover(engine, config, Arc::clone(&metrics)).await.unwrap());
        registry.create_domain("testdom").await.unwrap();
        let state = AppState {
            registry,
            auth_cache,
            auth_enabled: false,
            metrics,
            json_engine: None,
            rel_engine: None,
            shm_manager: None,
            backup_manager: None,
            log_access: None,
        };
        let app = crate::api::create_router(state, Arc::new(vec![]));
        (app, dir)
    }

    // Test 5: PUT + GET roundtrip over HTTP.
    #[tokio::test]
    async fn test_put_get_roundtrip() {
        let (app, _dir) = make_app().await;

        let put_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/store-api/kv/testdom/keys/hello")
                    .body(Body::from("world"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put_resp.status(), StatusCode::OK);

        let get_resp = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/store-api/kv/testdom/keys/hello")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get_resp.status(), StatusCode::OK);
        let body = to_bytes(get_resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body.as_ref(), b"world");
    }

    // ── Spec kv/018: REST contract for the NULL value state ─────────────────

    async fn send(app: &axum::Router, method: Method, uri: &str, body: Body) -> axum::http::Response<Body> {
        app.clone()
            .oneshot(Request::builder().method(method).uri(uri).body(body).unwrap())
            .await
            .unwrap()
    }

    // PATCH …/null → 200; GET → 204 (empty body); key appears in the scan;
    // DELETE → 204; GET → 404.
    #[tokio::test]
    async fn test_set_null_rest_lifecycle() {
        let (app, _dir) = make_app().await;
        let uri = "/store-api/kv/testdom/keys/nkey";

        let resp = send(&app, Method::PATCH, "/store-api/kv/testdom/keys/nkey/null", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = send(&app, Method::GET, uri, Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT, "null state must read as 204");
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert!(body.is_empty());

        let resp = send(&app, Method::GET, "/store-api/kv/testdom/keys", Body::empty()).await;
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let keys: Vec<String> = serde_json::from_slice(&body).unwrap();
        assert!(keys.iter().any(|k| k == "nkey"), "null key must appear in scans, got {keys:?}");

        let resp = send(&app, Method::DELETE, uri, Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let resp = send(&app, Method::GET, uri, Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "deleted key must be 404");
    }

    // A 0-byte PUT is an empty value — 200 with an empty body, distinct from 204.
    #[tokio::test]
    async fn test_empty_value_reads_as_200_not_204() {
        let (app, _dir) = make_app().await;
        let uri = "/store-api/kv/testdom/keys/ekey";

        let resp = send(&app, Method::PUT, uri, Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = send(&app, Method::GET, uri, Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK, "empty value is 200, not 204");
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert!(body.is_empty());
    }

    // set_null on a non-existent key creates it in the null state (upsert).
    #[tokio::test]
    async fn test_set_null_upserts_missing_key() {
        let (app, _dir) = make_app().await;
        let resp = send(&app, Method::PATCH, "/store-api/kv/testdom/keys/fresh/null", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = send(&app, Method::GET, "/store-api/kv/testdom/keys/fresh", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    // Test 6: Domain isolation — PUT in A, GET in B → 404.
    #[tokio::test]
    async fn test_domain_isolation_via_api() {
        let (app, _dir) = make_app().await;

        // Create a second domain via POST /store-api/domains.
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/store-api/domains")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name":"other"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        // PUT into testdom.
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/store-api/kv/testdom/keys/secret")
                    .body(Body::from("value-a"))
                    .unwrap(),
            )
            .await
            .unwrap();

        // GET from other domain → 404.
        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/store-api/kv/other/keys/secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // Test 7: Rate limit → 429 + Retry-After header (verified via ApiError).
    #[tokio::test]
    async fn test_rate_limit_returns_429_with_retry_after() {
        use crate::engines::lsm::rate_limiter::TokenBucket;

        // Verify token bucket exhaustion produces 429 semantics.
        let bucket = TokenBucket::new(1);
        assert!(bucket.try_consume(), "first request ok");
        assert!(!bucket.try_consume(), "second must fail");

        // Verify ApiError maps 429 + adds Retry-After header.
        let err = ApiError::from(anyhow::anyhow!("429 Too Many Requests: test"));
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(
            resp.headers().contains_key(axum::http::header::RETRY_AFTER),
            "429 must include Retry-After header"
        );
    }

    // ── Spec general/007 test 3: REST roundtrip with a UTF-8 key ────────────

    /// Percent-encodes every non-unreserved byte — enough to embed an arbitrary
    /// UTF-8 key (umlaut, emoji) in a URL path segment for tests.
    fn percent_encode(s: &str) -> String {
        let mut out = String::new();
        for b in s.as_bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    out.push(*b as char)
                }
                _ => out.push_str(&format!("%{:02X}", b)),
            }
        }
        out
    }

    // Test 3: PUT/GET/scan_keys with a percent-encoded umlaut+emoji key — scan
    // returns exactly the stored string, no U+FFFD.
    #[tokio::test]
    async fn test_rest_roundtrip_utf8_umlaut_emoji_key() {
        let (app, _dir) = make_app().await;
        let key = "börek-🎉";
        let uri = format!("/store-api/kv/testdom/keys/{}", percent_encode(key));

        let put_resp = app
            .clone()
            .oneshot(
                Request::builder().method(Method::PUT).uri(&uri).body(Body::from("world")).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put_resp.status(), StatusCode::OK);

        let get_resp = app
            .clone()
            .oneshot(Request::builder().method(Method::GET).uri(&uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(get_resp.status(), StatusCode::OK);
        let body = to_bytes(get_resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body.as_ref(), b"world");

        let scan_resp = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/store-api/kv/testdom/keys")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(scan_resp.status(), StatusCode::OK);
        let body = to_bytes(scan_resp.into_body(), usize::MAX).await.unwrap();
        let keys: Vec<String> = serde_json::from_slice(&body).unwrap();
        assert!(
            keys.iter().any(|k| k == key),
            "scan must return the exact stored string {key:?}, got {keys:?}"
        );
        assert!(
            !keys.iter().any(|k| k.contains('\u{FFFD}')),
            "no U+FFFD replacement char expected, got {keys:?}"
        );
    }

    // ── Spec kv/022: TTL observability & key metadata ────────────────────────

    async fn body_json(body: Body) -> serde_json::Value {
        let bytes = to_bytes(body, usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    // Test 1: PUT ?ttl=60 -> GET carries X-Expires-At, value within
    // [now+60, now+63] (second granularity + the +1 from expire_at_from_ttl,
    // plus a little slack for scheduling jitter between the two timestamps).
    #[tokio::test]
    async fn test_get_with_ttl_returns_expires_at_header() {
        let (app, _dir) = make_app().await;
        let uri = "/store-api/kv/testdom/keys/ttlkey";
        let before = crate::engines::lsm::domain::now_secs();

        let resp = send(&app, Method::PUT, &format!("{uri}?ttl=60"), Body::from("v")).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = send(&app, Method::GET, uri, Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let header = resp.headers().get("x-expires-at").expect("X-Expires-At must be present");
        let expires_at: u64 = header.to_str().unwrap().parse().unwrap();
        assert!(
            (before + 60..=before + 63).contains(&expires_at),
            "expected expires_at in [{}, {}], got {}",
            before + 60,
            before + 63,
            expires_at
        );
    }

    // Test 2: PUT without ttl -> GET carries no X-Expires-At.
    #[tokio::test]
    async fn test_get_without_ttl_has_no_expires_at_header() {
        let (app, _dir) = make_app().await;
        let uri = "/store-api/kv/testdom/keys/plainkey";
        send(&app, Method::PUT, uri, Body::from("v")).await;

        let resp = send(&app, Method::GET, uri, Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get("x-expires-at").is_none());
    }

    // Test 3: an already-expired TTL (ttl=0) -> GET 404 with no header;
    // …/meta 404 too.
    #[tokio::test]
    async fn test_expired_ttl_key_get_and_meta_404() {
        let (app, _dir) = make_app().await;
        let uri = "/store-api/kv/testdom/keys/expiredkey";
        send(&app, Method::PUT, &format!("{uri}?ttl=0"), Body::from("v")).await;

        let resp = send(&app, Method::GET, uri, Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(resp.headers().get("x-expires-at").is_none());

        let resp = send(&app, Method::GET, &format!("{uri}/meta"), Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // Test 4: PATCH …/null -> GET 204 without X-Expires-At; …/meta 200 with
    // expires_at: null (set_null never carries a TTL, kv/018 §3.8).
    #[tokio::test]
    async fn test_null_key_meta_has_null_expires_at() {
        let (app, _dir) = make_app().await;
        let uri = "/store-api/kv/testdom/keys/nullmeta";
        let resp = send(&app, Method::PATCH, &format!("{uri}/null"), Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = send(&app, Method::GET, uri, Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert!(resp.headers().get("x-expires-at").is_none());

        let resp = send(&app, Method::GET, &format!("{uri}/meta"), Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let meta = body_json(resp.into_body()).await;
        assert!(meta["expires_at"].is_null(), "expected null expires_at, got {meta:?}");
    }

    // Test 5: …/meta's expires_at is value-equal to the X-Expires-At header.
    #[tokio::test]
    async fn test_meta_expires_at_matches_header() {
        let (app, _dir) = make_app().await;
        let uri = "/store-api/kv/testdom/keys/matchkey";
        send(&app, Method::PUT, &format!("{uri}?ttl=60"), Body::from("v")).await;

        let get_resp = send(&app, Method::GET, uri, Body::empty()).await;
        let header_val: u64 =
            get_resp.headers().get("x-expires-at").unwrap().to_str().unwrap().parse().unwrap();

        let meta_resp = send(&app, Method::GET, &format!("{uri}/meta"), Body::empty()).await;
        assert_eq!(meta_resp.status(), StatusCode::OK);
        let meta = body_json(meta_resp.into_body()).await;
        assert_eq!(meta["expires_at"].as_u64().unwrap(), header_val);
    }

    // Test 6: last_modified_at sits near the write time, and a second PUT on
    // the same key must INCREASE it — proof it tracks the newest version,
    // not a creation time, and a regression guard against reading the
    // sstable's inverted on-disk timestamp verbatim (spec kv/022 §4.3).
    #[tokio::test]
    async fn test_last_modified_at_near_write_time_and_increases_on_overwrite() {
        let (app, _dir) = make_app().await;
        let uri = "/store-api/kv/testdom/keys/lmkey";
        let before_ms =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;

        send(&app, Method::PUT, uri, Body::from("v1")).await;
        let resp = send(&app, Method::GET, &format!("{uri}/meta"), Body::empty()).await;
        let meta = body_json(resp.into_body()).await;
        let first_lm = meta["last_modified_at"].as_u64().unwrap();
        assert!(
            first_lm >= before_ms,
            "last_modified_at must be at/after the write, got {first_lm} vs {before_ms}"
        );

        // Guarantee the HLC physical (millisecond) component advances between
        // the two writes; without it two same-millisecond PUTs could tie.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        send(&app, Method::PUT, uri, Body::from("v2")).await;
        let resp = send(&app, Method::GET, &format!("{uri}/meta"), Body::empty()).await;
        let meta = body_json(resp.into_body()).await;
        let second_lm = meta["last_modified_at"].as_u64().unwrap();

        assert!(
            second_lm > first_lm,
            "a second PUT must increase last_modified_at, got {second_lm} <= {first_lm}"
        );
    }

    // Test 7: …/meta on an unknown key -> 404.
    #[tokio::test]
    async fn test_meta_unknown_key_404() {
        let (app, _dir) = make_app().await;
        let resp = send(&app, Method::GET, "/store-api/kv/testdom/keys/ghost/meta", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // Test 8: DELETE a key -> …/meta afterwards is 404 (tombstone == absent).
    #[tokio::test]
    async fn test_meta_404_after_delete() {
        let (app, _dir) = make_app().await;
        let uri = "/store-api/kv/testdom/keys/delkey";
        send(&app, Method::PUT, uri, Body::from("v")).await;
        let resp = send(&app, Method::DELETE, uri, Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let resp = send(&app, Method::GET, &format!("{uri}/meta"), Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // Test 9: …/meta with an invalid key (longer than max_user_key_length)
    // -> 400. (An empty :key path segment never reaches the handler — axum's
    // router itself 404s before validate_user_key runs, same as GET …/{key}.)
    #[tokio::test]
    async fn test_meta_invalid_key_too_long_400() {
        let (app, _dir) = make_app().await;
        let long_key = "a".repeat(300); // > default max_user_key_length (256)
        let uri = format!("/store-api/kv/testdom/keys/{long_key}/meta");
        let resp = send(&app, Method::GET, &uri, Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // Test 10: …/meta runs into the read rate limit (429 + Retry-After) —
    // proof the admin backup bypass (get_with_snapshot, which skips the
    // limiter) is not what backs this endpoint.
    #[tokio::test]
    async fn test_meta_rate_limit_429_with_retry_after() {
        let mut config = crate::engines::lsm::domain::DomainConfig::default();
        config.default_read_iops = 1;
        let (app, _dir) = make_app_with_config(config).await;
        let uri = "/store-api/kv/testdom/keys/ratekey";
        send(&app, Method::PUT, uri, Body::from("v")).await;

        let resp = send(&app, Method::GET, &format!("{uri}/meta"), Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK, "first read must consume the single token");

        let resp = send(&app, Method::GET, &format!("{uri}/meta"), Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(
            resp.headers().contains_key(axum::http::header::RETRY_AFTER),
            "429 must include Retry-After header"
        );
    }
}
