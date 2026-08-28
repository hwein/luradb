//! Domain-scoped KV REST handlers.
//!
//! PUT    /store-api/kv/{domain}/keys/{key}          → put_key   (200 | 429 | 400)
//! PUT    /store-api/kv/{domain}/keys/{key}?ttl=N    → put_key   (TTL variant)
//! GET    /store-api/kv/{domain}/keys/{key}          → get_key   (200 | 204 | 404 | 429)
//! DELETE /store-api/kv/{domain}/keys/{key}          → delete_key (204 | 429)
//! PATCH  /store-api/kv/{domain}/keys/{key}/null     → set_null  (200 | 429)
//! GET    /store-api/kv/{domain}/keys/{key}/meta     → get_key_meta (200 | 400 | 404 | 410 | 429)
//! GET    /store-api/kv/{domain}/keys?prefix={p}&contains={s}&limit={n}&offset={o} → scan_keys (200 | 429)
//! DELETE /store-api/kv/{domain}/keys?prefix={p}&contains={s} → delete_keys_by_prefix (200 | 400 | 413 | 429 | 404 | 410)
//! GET    /store-api/kv/{domain}/count?prefix={p}    → count_keys (200 | 429)
//! GET    /store-api/kv/{domain}/watch?prefix={p}    → watch     (SSE stream)

use crate::api::{middleware::ApiError, AppState, CountResponse};
use crate::core::events::{format_event_id, stream_epoch, ResetReason, Resume};
use crate::engines::lsm::{GetResult, OpType, WalEvent, WatchMessage, WatchStart, WATCH_TAG};
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Json, Response,
    },
};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use tokio::sync::broadcast;
use utoipa::ToSchema;

// Caps the wire response of a keys scan (spec kv/028); the underlying scan
// itself stays unbounded — same server cost as today, documented at
// `count_keys`. `count_keys` keeps using `ScanParams` unchanged.
const DEFAULT_SCAN_LIMIT: usize = 1000;
const MAX_SCAN_LIMIT: usize = 10_000;

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
pub struct KeyScanParams {
    pub prefix: Option<String>,
    /// Case-sensitive substring filter on the user key, applied before `total`/offset/limit (kv/023 §2 semantics).
    pub contains: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// `prefix` is required and rejected empty-string (spec kv/023 §2) — plain
/// `String`, not `Option`, so a missing `?prefix=` is an axum `Query`
/// rejection (400) before the handler ever runs.
#[derive(Deserialize)]
pub struct BulkDeleteParams {
    pub prefix: String,
    pub contains: Option<String>,
}

#[derive(Deserialize)]
pub struct WatchParams {
    pub prefix: Option<String>,
    /// Fallback resume id for callers that cannot set headers (e.g. `curl`,
    /// or a `fetch`-based reader); the `Last-Event-ID` header wins when both
    /// are present (spec kv/024 §4.1).
    pub last_event_id: Option<String>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn resolve(
    state: &AppState,
    domain: &str,
) -> Result<crate::engines::lsm::DomainStore, ApiError> {
    state.registry.store(domain).await.map_err(ApiError::from)
}

/// Resolves the effective `Last-Event-ID` (spec kv/024 §4.1): the header —
/// what a native `EventSource`'s auto-reconnect sets — wins when both the
/// header and `?last_event_id=` are present.
fn resolve_last_event_id(headers: &HeaderMap, params: &WatchParams) -> Option<String> {
    headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| params.last_event_id.clone())
}

/// A decided SSE item, before axum-specific rendering — kept as plain data
/// (rather than `axum::response::sse::Event` directly) so the decision logic
/// below is unit-testable by inspecting fields, without depending on
/// `Event`'s internal representation (it exposes no accessors of its own).
struct SseItem {
    id: String,
    event: &'static str,
    data: String,
}

fn render_sse_item(item: SseItem) -> Event {
    Event::default().id(item.id).event(item.event).data(item.data)
}

fn watch_event_item(event: &WalEvent, epoch: u64) -> SseItem {
    let op_str = match event.op {
        OpType::Set => "set",
        OpType::Delete => "delete",
    };
    let key_str = String::from_utf8_lossy(&event.key).into_owned();
    SseItem { id: format_event_id(WATCH_TAG, epoch, event.seq), event: op_str, data: key_str }
}

/// Builds `event: reset` (spec kv/024 §5): `id:` carries the current
/// sequence head, so a reconnect right after a reset resumes gaplessly from
/// there; `data:` is JSON (not plain text) so the reason vocabulary can grow
/// without breaking the wire format. Serialized manually (`serde_json`
/// rather than `Event::json_data`) since the latter needs axum's `json`
/// cargo feature, which this project does not enable.
fn reset_item(reason: ResetReason, epoch: u64, head: u64) -> SseItem {
    let data = serde_json::to_string(&serde_json::json!({ "reason": reason }))
        .expect("ResetReason serializes infallibly");
    SseItem { id: format_event_id(WATCH_TAG, epoch, head), event: "reset", data }
}

enum WatchStep {
    Emit(SseItem),
    Skip,
    Stop,
}

/// Maps one raw relay receive to a live-stream outcome (spec kv/024 §4.3,
/// §6): suppresses `seq <= suppress_upto` (the overlap between an initial
/// replay's snapshot and the live relay picking up), and turns a `Gap` or
/// the receiver's own `Lagged` into `reset(lagged)` — never a silent
/// `continue`, which is exactly the defect this spec fixes. Pure (no I/O),
/// so every branch is unit-testable without real timing.
fn watch_item(
    msg: Result<WatchMessage, broadcast::error::RecvError>,
    prefix: &[u8],
    epoch: u64,
    suppress_upto: Option<u64>,
    head: u64,
) -> WatchStep {
    match msg {
        Ok(WatchMessage::Event(event)) => {
            if !event.key.starts_with(prefix) {
                return WatchStep::Skip;
            }
            if suppress_upto.is_some_and(|upto| event.seq <= upto) {
                return WatchStep::Skip;
            }
            WatchStep::Emit(watch_event_item(&event, epoch))
        }
        Ok(WatchMessage::Gap) => WatchStep::Emit(reset_item(ResetReason::Lagged, epoch, head)),
        Err(broadcast::error::RecvError::Lagged(_)) => {
            WatchStep::Emit(reset_item(ResetReason::Lagged, epoch, head))
        }
        Err(broadcast::error::RecvError::Closed) => WatchStep::Stop,
    }
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
        (status = 429, description = "Rate limit exceeded", body = String, content_type = "text/plain", headers(("Retry-After" = u64))),
        (status = 400, description = "Invalid key", body = String, content_type = "text/plain"),
        (status = 404, description = "Domain not found", body = String, content_type = "text/plain"),
        (status = 410, description = "Domain is being deleted", body = String, content_type = "text/plain"),
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
        (status = 404, description = "Key or domain not found", body = String, content_type = "text/plain"),
        (status = 429, description = "Rate limit exceeded", body = String, content_type = "text/plain", headers(("Retry-After" = u64))),
        (status = 400, description = "Invalid key", body = String, content_type = "text/plain"),
        (status = 410, description = "Domain is being deleted", body = String, content_type = "text/plain"),
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
        (status = 400, description = "Invalid key", body = String, content_type = "text/plain"),
        (status = 404, description = "Key or domain not found", body = String, content_type = "text/plain"),
        (status = 410, description = "Domain is being deleted", body = String, content_type = "text/plain"),
        (status = 429, description = "Rate limit exceeded", body = String, content_type = "text/plain", headers(("Retry-After" = u64))),
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
        (status = 429, description = "Rate limit exceeded", body = String, content_type = "text/plain", headers(("Retry-After" = u64))),
        (status = 400, description = "Invalid key", body = String, content_type = "text/plain"),
        (status = 410, description = "Domain is being deleted", body = String, content_type = "text/plain"),
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
        (status = 429, description = "Rate limit exceeded", body = String, content_type = "text/plain", headers(("Retry-After" = u64))),
        (status = 400, description = "Invalid key", body = String, content_type = "text/plain"),
        (status = 410, description = "Domain is being deleted", body = String, content_type = "text/plain"),
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

// ── KeyScanResponse DTO ──────────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct KeyScanResponse {
    /// The page, in scan order (sorted).
    pub keys: Vec<String>,
    /// Matches after `prefix`/`contains` filtering, before `offset`/`limit`.
    pub total: u64,
    /// Effective offset applied.
    pub offset: usize,
    /// Effective limit applied (after capping to the maximum).
    pub limit: usize,
}

#[utoipa::path(
    get,
    path = "/store-api/kv/{domain}/keys",
    params(
        ("domain" = String, Path, description = "Domain name"),
        ("prefix" = Option<String>, Query, description = "Key prefix filter"),
        ("contains" = Option<String>, Query, description = "Case-sensitive substring filter on the user key, applied before total/offset/limit"),
        ("limit" = Option<usize>, Query, description = "Page size (default 1000, max 10000; over-max is silently capped)"),
        ("offset" = Option<usize>, Query, description = "Keys to skip"),
    ),
    responses(
        (status = 200, description = "One page of matching keys", body = KeyScanResponse),
        (status = 429, description = "Rate limit exceeded", body = String, content_type = "text/plain", headers(("Retry-After" = u64))),
        (status = 410, description = "Domain is being deleted", body = String, content_type = "text/plain"),
    ),
    tag = "Key-Value Store"
)]
/// Lists one page of keys in the domain, optionally filtered by a prefix and/or a case-sensitive `contains` substring.
/// `total` counts matches after filtering, before `offset`/`limit` are applied; an out-of-range `offset` yields an empty `keys` array with `total` unchanged.
pub async fn scan_keys(
    State(state): State<AppState>,
    Path(domain): Path<String>,
    Query(params): Query<KeyScanParams>,
) -> Result<Json<KeyScanResponse>, ApiError> {
    let store = resolve(&state, &domain).await?;
    let prefix = params.prefix.unwrap_or_default();
    let limit = params.limit.unwrap_or(DEFAULT_SCAN_LIMIT).min(MAX_SCAN_LIMIT);
    let offset = params.offset.unwrap_or(0);
    let (raw, total) = store
        .scan_keys_page(prefix.as_bytes(), params.contains.as_deref(), offset, limit)
        .await
        .map_err(ApiError::from)?;
    let keys: Vec<String> =
        raw.into_iter().map(|k| String::from_utf8_lossy(&k).into_owned()).collect();
    Ok(Json(KeyScanResponse { keys, total, offset, limit }))
}

// ── BulkDeleteResponse DTO ───────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct BulkDeleteResponse {
    pub deleted: usize,
}

#[utoipa::path(
    delete,
    path = "/store-api/kv/{domain}/keys",
    params(
        ("domain" = String, Path, description = "Domain name"),
        ("prefix" = String, Query, description = "Key prefix — required, must not be empty. A domain-emptying request needs the admin-only DELETE /store-api/domains/{name} instead."),
        ("contains" = Option<String>, Query, description = "Case-sensitive substring filter on the user key, applied to the prefix scan's results before the cap check"),
    ),
    responses(
        (status = 200, description = "Matched keys deleted atomically (one write batch); an empty selection is a no-op", body = BulkDeleteResponse),
        (status = 400, description = "Missing or empty prefix", body = String, content_type = "text/plain"),
        (status = 413, description = "The selection exceeds max_bulk_delete_keys; no key was deleted", body = String, content_type = "text/plain"),
        (status = 429, description = "Rate limit exceeded", body = String, content_type = "text/plain", headers(("Retry-After" = u64))),
        (status = 404, description = "Domain not found", body = String, content_type = "text/plain"),
        (status = 410, description = "Domain is being deleted", body = String, content_type = "text/plain"),
    ),
    tag = "Key-Value Store"
)]
/// Deletes every live key whose raw form starts with `prefix`, optionally narrowed by a case-sensitive
/// `contains` substring filter on the key — the same selection `GET …/keys?prefix=&contains=` would show.
/// Atomic: either every matched key is gone, or (a 413) none is. Returns the number of keys deleted.
pub async fn delete_keys_by_prefix(
    State(state): State<AppState>,
    Path(domain): Path<String>,
    Query(params): Query<BulkDeleteParams>,
) -> Result<Json<BulkDeleteResponse>, ApiError> {
    let store = resolve(&state, &domain).await?;
    let deleted = store
        .delete_by_prefix(params.prefix.as_bytes(), params.contains.as_deref())
        .await
        .map_err(ApiError::from)?;
    Ok(Json(BulkDeleteResponse { deleted }))
}

#[utoipa::path(
    get,
    path = "/store-api/kv/{domain}/count",
    params(
        ("domain" = String, Path, description = "Domain name"),
        ("prefix" = Option<String>, Query, description = "Key prefix filter"),
    ),
    responses(
        (status = 200, description = "Number of live keys matching the prefix. A full key scan under the hood (same cost as the equivalent `keys?prefix=` call) — cost grows linearly with domain size, so this is meant for on-demand use, not high-frequency polling.", body = CountResponse),
        (status = 429, description = "Rate limit exceeded", body = String, content_type = "text/plain", headers(("Retry-After" = u64))),
        (status = 410, description = "Domain is being deleted", body = String, content_type = "text/plain"),
    ),
    tag = "Key-Value Store"
)]
/// Counts live keys in the domain, optionally filtered by a prefix — the same
/// semantics as `GET …/keys?prefix=`, without transferring the keys themselves.
pub async fn count_keys(
    State(state): State<AppState>,
    Path(domain): Path<String>,
    Query(params): Query<ScanParams>,
) -> Result<Json<CountResponse>, ApiError> {
    let store = resolve(&state, &domain).await?;
    let prefix = params.prefix.unwrap_or_default();
    let count = store.count_keys(prefix.as_bytes()).await.map_err(ApiError::from)?;
    Ok(Json(CountResponse { count }))
}

#[utoipa::path(
    get,
    path = "/store-api/kv/{domain}/watch",
    params(
        ("domain" = String, Path, description = "Domain name"),
        ("prefix" = Option<String>, Query, description = "Key prefix filter"),
        ("last_event_id" = Option<String>, Query, description = "Resume id from a previous `id:` (or `event: reset`) — for callers that cannot set headers. Ignored when the `Last-Event-ID` header is present."),
        ("Last-Event-ID" = Option<String>, Header, description = "Resume id from a previous `id:` (or `event: reset`); set automatically by a native `EventSource`'s auto-reconnect. Takes precedence over `?last_event_id=`."),
    ),
    responses(
        (status = 200, description = "SSE stream of key change events. Every event carries an `id:`. Event types: `set` / `delete` (data: the key) and `reset` (data: `{\"reason\": ...}`, emitted whenever gapless resume cannot be guaranteed — the client should re-read the domain, then keep applying events normally).", content_type = "text/event-stream"),
        (status = 410, description = "Domain is being deleted", body = String, content_type = "text/plain"),
    ),
    tag = "Key-Value Store"
)]
/// Opens a Server-Sent Events stream that delivers real-time change events (`set` / `delete`) for keys matching the optional prefix.
/// The connection stays open until the client disconnects; a keep-alive ping is sent automatically.
///
/// A `Last-Event-ID` (header or `?last_event_id=`, spec kv/024) resumes gaplessly from an in-memory
/// replay ring when possible; otherwise the server emits `event: reset` before continuing live. A
/// client that ignores `id:`/`reset` behaves exactly as before this was added.
pub async fn watch(
    State(state): State<AppState>,
    Path(domain): Path<String>,
    Query(params): Query<WatchParams>,
    headers: HeaderMap,
) -> Result<
    Sse<impl futures::Stream<Item = Result<Event, Infallible>> + Send + 'static>,
    ApiError,
> {
    let store = resolve(&state, &domain).await?;
    let last_event_id = resolve_last_event_id(&headers, &params);
    let prefix_bytes: Vec<u8> = params.prefix.unwrap_or_default().into_bytes();

    let WatchStart { resume, rx } = store.watch_from(last_event_id.as_deref());
    let epoch = stream_epoch();

    // Leading items served up front (never through the relay channel, see
    // spec kv/024 §4.3): 0 or 1 `reset`, or a domain-/prefix-filtered replay.
    // `suppress_upto` carries the replay's `head` so the live loop below can
    // discard the live re-deliveries of what was just replayed (the
    // subscribe-before-snapshot ordering guarantees overlap, never a gap).
    let (leading, suppress_upto): (Vec<Event>, Option<u64>) = match resume {
        Resume::Live => (Vec::new(), None),
        Resume::Reset { reason, head } => (vec![render_sse_item(reset_item(reason, epoch, head))], None),
        Resume::Replay { events, head } => {
            let items = events
                .iter()
                .filter(|e| e.key.starts_with(&prefix_bytes))
                .map(|e| render_sse_item(watch_event_item(e, epoch)))
                .collect();
            (items, Some(head))
        }
    };
    let leading_stream = futures::stream::iter(leading.into_iter().map(Ok::<Event, Infallible>));

    let live_stream = futures::stream::unfold(
        (rx, prefix_bytes, suppress_upto, store),
        move |(mut rx, prefix, suppress_upto, store)| async move {
            loop {
                let msg = rx.recv().await;
                // A `parking_lot::Mutex` lock, cheap enough to pay on every
                // message rather than special-case the two branches that
                // actually need it (Gap/Lagged) — keeps `watch_item` pure.
                let head = store.watch_head();
                match watch_item(msg, &prefix, epoch, suppress_upto, head) {
                    WatchStep::Emit(item) => {
                        return Some((Ok::<Event, Infallible>(render_sse_item(item)), (rx, prefix, suppress_upto, store)))
                    }
                    WatchStep::Skip => continue,
                    WatchStep::Stop => return None,
                }
            }
        },
    );

    Ok(Sse::new(leading_stream.chain(live_stream)).keep_alive(KeepAlive::default()))
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

    // For tests that need a non-default quota (the large-volume count test
    // raises the write quota); every other test keeps using the
    // default-quota `make_app` above.
    async fn make_app_with_config(config: crate::engines::lsm::domain::DomainConfig) -> (axum::Router, tempfile::TempDir) {
        let (state, dir) = make_state(config, false).await;
        let app = crate::api::create_router(state, Arc::new(vec![]));
        (app, dir)
    }

    // Spec general/017 test 10 (auth scoping) needs `auth_enabled: true` and
    // a live handle to `auth_cache` before the state is consumed by
    // `create_router` — factored out of `make_app_with_config` for that.
    async fn make_state(
        config: crate::engines::lsm::domain::DomainConfig,
        auth_enabled: bool,
    ) -> (AppState, tempfile::TempDir) {
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

    // Spec general/026 test 2 (kv sample): a real 404 carries a non-empty
    // plaintext body — schema (text/plain string) and reality agree.
    #[tokio::test]
    async fn test_get_missing_key_404_has_nonempty_plaintext_body() {
        let (app, _dir) = make_app().await;
        let resp = send(&app, Method::GET, "/store-api/kv/testdom/keys/ghost", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let content_type =
            resp.headers().get(axum::http::header::CONTENT_TYPE).unwrap().to_str().unwrap().to_string();
        assert!(content_type.starts_with("text/plain"), "{content_type}");
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8_lossy(&bytes);
        assert!(!body.is_empty(), "404 body must not be empty");
        assert!(
            serde_json::from_str::<serde_json::Value>(&body).is_err(),
            "body must be plain text, not JSON: {body}"
        );
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
        let body = body_json(resp.into_body()).await;
        let keys: Vec<String> = serde_json::from_value(body["keys"].clone()).unwrap();
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
        let body = body_json(scan_resp.into_body()).await;
        let keys: Vec<String> = serde_json::from_value(body["keys"].clone()).unwrap();
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

    // Test 1: PUT ?ttl=60 -> GET carries X-Expires-At. The stamp is
    // put-time + 60 + 1 (second granularity + the +1 from
    // expire_at_from_ttl); bracketing the PUT between `before`/`after`
    // bounds it exactly (±1 truncation margin) however slowly the test runs.
    #[tokio::test]
    async fn test_get_with_ttl_returns_expires_at_header() {
        let (app, _dir) = make_app().await;
        let uri = "/store-api/kv/testdom/keys/ttlkey";
        let before = crate::engines::lsm::domain::now_secs();

        let resp = send(&app, Method::PUT, &format!("{uri}?ttl=60"), Body::from("v")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let after = crate::engines::lsm::domain::now_secs();

        let resp = send(&app, Method::GET, uri, Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let header = resp.headers().get("x-expires-at").expect("X-Expires-At must be present");
        let expires_at: u64 = header.to_str().unwrap().parse().unwrap();
        assert!(
            (before + 60..=after + 62).contains(&expires_at),
            "expected expires_at in [{}, {}], got {}",
            before + 60,
            after + 62,
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
    // limiter) is not what backs this endpoint. The bucket is drained and
    // locked (no refill race) instead of racing a 1-IOPS refill window.
    #[tokio::test]
    async fn test_meta_rate_limit_429_with_retry_after() {
        let (state, _dir) = make_state(crate::engines::lsm::domain::DomainConfig::default(), false).await;
        let store = state.registry.store("testdom").await.unwrap();
        let app = crate::api::create_router(state, Arc::new(vec![]));
        let uri = "/store-api/kv/testdom/keys/ratekey";
        send(&app, Method::PUT, uri, Body::from("v")).await;

        let resp = send(&app, Method::GET, &format!("{uri}/meta"), Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK, "read must succeed before the budget is drained");

        store.drain_read_budget_for_test();
        let resp = send(&app, Method::GET, &format!("{uri}/meta"), Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(
            resp.headers().contains_key(axum::http::header::RETRY_AFTER),
            "429 must include Retry-After header"
        );
    }

    // ── Spec general/017: KV object-count endpoint ───────────────────────────

    // Tests 1-3: empty domain -> 0; a mix of prefixed/unprefixed keys counts
    // exactly, with and without a `prefix` filter, cross-checked against the
    // exact key list `scan_keys` returns for the same prefix (spec §1: same
    // codepath, so count == keys.len()); a deleted key stops counting, a
    // NULL-state key keeps counting (it's still visible to a scan, kv/018).
    #[tokio::test]
    async fn test_count_keys_basic_prefix_and_liveness() {
        let (app, _dir) = make_app().await;
        let uri = "/store-api/kv/testdom/count";

        let resp = send(&app, Method::GET, uri, Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp.into_body()).await["count"].as_u64().unwrap(), 0);

        for i in 0..7 {
            send(&app, Method::PUT, &format!("/store-api/kv/testdom/keys/b:{i}"), Body::from("v")).await;
        }
        for i in 0..3 {
            send(&app, Method::PUT, &format!("/store-api/kv/testdom/keys/a:{i}"), Body::from("v")).await;
        }
        let resp = send(&app, Method::GET, uri, Body::empty()).await;
        assert_eq!(body_json(resp.into_body()).await["count"].as_u64().unwrap(), 10);

        let resp = send(&app, Method::GET, &format!("{uri}?prefix=a:"), Body::empty()).await;
        assert_eq!(body_json(resp.into_body()).await["count"].as_u64().unwrap(), 3);

        let resp = send(&app, Method::GET, "/store-api/kv/testdom/keys?prefix=a:", Body::empty()).await;
        let body = body_json(resp.into_body()).await;
        let keys: Vec<String> = serde_json::from_value(body["keys"].clone()).unwrap();
        assert_eq!(keys.len(), 3, "count?prefix=a: must match keys?prefix=a:'s length exactly");

        // A deleted key stops counting; a NULL-state key keeps counting —
        // net effect here is unchanged (10 - 1 deleted + 1 null-state = 10).
        send(&app, Method::DELETE, "/store-api/kv/testdom/keys/b:0", Body::empty()).await;
        send(&app, Method::PATCH, "/store-api/kv/testdom/keys/nullkey/null", Body::empty()).await;
        let resp = send(&app, Method::GET, uri, Body::empty()).await;
        assert_eq!(body_json(resp.into_body()).await["count"].as_u64().unwrap(), 10);
    }

    // Test 4: unknown domain -> 404; domain in deletion -> 410.
    #[tokio::test]
    async fn test_count_keys_domain_not_found_and_deleting() {
        let (app, _dir) = make_app().await;

        let resp = send(&app, Method::GET, "/store-api/kv/ghost/count", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/store-api/domains")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name":"gone"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let resp = send(&app, Method::DELETE, "/store-api/domains/gone", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let resp = send(&app, Method::GET, "/store-api/kv/gone/count", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::GONE);
    }

    // Test 4 (rate limit): exhausted read budget -> 429 + Retry-After, same
    // drained-and-locked bucket mechanism as the …/meta rate-limit test.
    #[tokio::test]
    async fn test_count_keys_rate_limit_429_with_retry_after() {
        let (state, _dir) = make_state(crate::engines::lsm::domain::DomainConfig::default(), false).await;
        let store = state.registry.store("testdom").await.unwrap();
        let app = crate::api::create_router(state, Arc::new(vec![]));
        let uri = "/store-api/kv/testdom/count";

        let resp = send(&app, Method::GET, uri, Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK, "count must succeed before the budget is drained");

        store.drain_read_budget_for_test();
        let resp = send(&app, Method::GET, uri, Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(
            resp.headers().contains_key(axum::http::header::RETRY_AFTER),
            "429 must include Retry-After header"
        );
    }

    // Test 5 (shadow counter-proof, spec §2): a key literally named "count"
    // stays reachable via GET …/keys/count — proof that the count endpoint
    // lives a level above `keys`, not as a `keys/count` sibling of `{key}`.
    #[tokio::test]
    async fn test_count_route_does_not_shadow_key_named_count() {
        let (app, _dir) = make_app().await;
        let resp = send(&app, Method::PUT, "/store-api/kv/testdom/keys/count", Body::from("42")).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = send(&app, Method::GET, "/store-api/kv/testdom/keys/count", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK, "a key named 'count' must stay readable via GET .../keys/{{key}}");
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body.as_ref(), b"42");
    }

    // Test 10: a Read grant on the domain allows the count; no grant -> 403
    // (the generic domain-scoped auth path, spec general/007 — exercised here
    // for the new route specifically).
    #[tokio::test]
    async fn test_count_keys_auth_scoping() {
        use crate::auth::{hash_api_key, AccessLevel, DomainPermission, UserRecord, UserRole};

        let (state, _dir) = make_state(crate::engines::lsm::domain::DomainConfig::default(), true).await;
        let cache = Arc::clone(&state.auth_cache);
        let app = crate::api::create_router(state, Arc::new(vec![]));

        cache
            .upsert_user(UserRecord {
                name: "worker".to_string(),
                api_key_hash: hash_api_key("lura_test_worker_key"),
                role: UserRole::User,
                created_at: 0,
            })
            .await
            .unwrap();

        let req = || {
            Request::builder()
                .method(Method::GET)
                .uri("/store-api/kv/testdom/count")
                .header("authorization", "Bearer lura_test_worker_key")
                .body(Body::empty())
                .unwrap()
        };

        let resp = app.clone().oneshot(req()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "no permission on testdom yet");

        cache
            .set_permission(DomainPermission {
                username: "worker".to_string(),
                domain: "testdom".to_string(),
                access: AccessLevel::Read,
            })
            .await
            .unwrap();
        let resp = app.clone().oneshot(req()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "Read grant must allow the count");
    }

    // Test 11: 10,000 keys -> count = 10,000; only the number crosses the
    // wire. Seeded concurrently (not one PUT at a time) so the WAL's
    // group-commit (core::wal::run_committer) batches the writes into a
    // handful of fsyncs instead of one per key; needs a raised write quota
    // since the concurrent burst would otherwise trip the default 500/s.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_count_keys_large_volume() {
        let mut config = crate::engines::lsm::domain::DomainConfig::default();
        config.default_write_iops = 20_000;
        let (app, _dir) = make_app_with_config(config).await;

        let app_ref = &app;
        let puts = (0..10_000u32).map(|i| async move {
            let uri = format!("/store-api/kv/testdom/keys/k{i:05}");
            send(app_ref, Method::PUT, &uri, Body::from("v")).await
        });
        futures::future::join_all(puts).await;

        let resp = send(&app, Method::GET, "/store-api/kv/testdom/count", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp.into_body()).await["count"].as_u64().unwrap(), 10_000);
    }

    // ── Spec kv/023: prefix bulk-delete ──────────────────────────────────────

    // Test 1: 5 keys sharing a prefix + 2 foreign keys -> deleting the prefix
    // removes exactly the 5, the 2 foreign keys stay reachable via GET.
    #[tokio::test]
    async fn test_bulk_delete_by_prefix_deletes_matching_keeps_foreign() {
        let (app, _dir) = make_app().await;
        for i in 0..5 {
            send(&app, Method::PUT, &format!("/store-api/kv/testdom/keys/del:{i}"), Body::from("v")).await;
        }
        send(&app, Method::PUT, "/store-api/kv/testdom/keys/keep:1", Body::from("v")).await;
        send(&app, Method::PUT, "/store-api/kv/testdom/keys/keep:2", Body::from("v")).await;

        let resp = send(&app, Method::DELETE, "/store-api/kv/testdom/keys?prefix=del:", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp.into_body()).await["deleted"].as_u64().unwrap(), 5);

        for i in 0..5 {
            let resp = send(&app, Method::GET, &format!("/store-api/kv/testdom/keys/del:{i}"), Body::empty()).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        }
        for k in ["keep:1", "keep:2"] {
            let resp = send(&app, Method::GET, &format!("/store-api/kv/testdom/keys/{k}"), Body::empty()).await;
            assert_eq!(resp.status(), StatusCode::OK, "{k} must survive the prefix delete");
        }
    }

    // Test 2: `contains` is case-sensitive — `contains=Log` matches
    // `app:Log:1`, not `app:log:2`.
    #[tokio::test]
    async fn test_bulk_delete_contains_filter_is_case_sensitive() {
        let (app, _dir) = make_app().await;
        send(&app, Method::PUT, "/store-api/kv/testdom/keys/app:Log:1", Body::from("v")).await;
        send(&app, Method::PUT, "/store-api/kv/testdom/keys/app:log:2", Body::from("v")).await;

        let resp =
            send(&app, Method::DELETE, "/store-api/kv/testdom/keys?prefix=app:&contains=Log", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp.into_body()).await["deleted"].as_u64().unwrap(), 1);

        let resp = send(&app, Method::GET, "/store-api/kv/testdom/keys/app:Log:1", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let resp = send(&app, Method::GET, "/store-api/kv/testdom/keys/app:log:2", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK, "lowercase key must survive a case-sensitive contains=Log");
    }

    // Test 3: an empty prefix is rejected (400) and the domain is unchanged —
    // proof the endpoint can never be used to empty a whole domain.
    #[tokio::test]
    async fn test_bulk_delete_empty_prefix_400_domain_unchanged() {
        let (app, _dir) = make_app().await;
        send(&app, Method::PUT, "/store-api/kv/testdom/keys/k1", Body::from("v")).await;

        let resp = send(&app, Method::DELETE, "/store-api/kv/testdom/keys?prefix=", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp = send(&app, Method::GET, "/store-api/kv/testdom/keys", Body::empty()).await;
        let body = body_json(resp.into_body()).await;
        let keys: Vec<String> = serde_json::from_value(body["keys"].clone()).unwrap();
        assert_eq!(keys, vec!["k1".to_string()], "domain must be unchanged after a rejected empty-prefix delete");
    }

    // Test 4: a missing `prefix` query param is an axum `Query` rejection (400).
    #[tokio::test]
    async fn test_bulk_delete_missing_prefix_400() {
        let (app, _dir) = make_app().await;
        let resp = send(&app, Method::DELETE, "/store-api/kv/testdom/keys", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // Test 5: no matches -> 200 with deleted: 0 (no WAL record, idempotent).
    #[tokio::test]
    async fn test_bulk_delete_no_matches_returns_zero() {
        let (app, _dir) = make_app().await;
        let resp = send(&app, Method::DELETE, "/store-api/kv/testdom/keys?prefix=ghost:", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp.into_body()).await["deleted"].as_u64().unwrap(), 0);
    }

    // Test 6: a selection over the configured cap -> 413 with both the match
    // count and the limit in the error text, and nothing gets deleted.
    #[tokio::test]
    async fn test_bulk_delete_over_cap_413_nothing_deleted() {
        let mut config = crate::engines::lsm::domain::DomainConfig::default();
        config.max_bulk_delete_keys = 3;
        let (app, _dir) = make_app_with_config(config).await;
        for i in 0..5 {
            send(&app, Method::PUT, &format!("/store-api/kv/testdom/keys/cap:{i}"), Body::from("v")).await;
        }

        let resp = send(&app, Method::DELETE, "/store-api/kv/testdom/keys?prefix=cap:", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains('5') && text.contains('3'), "expected both counts in the error, got {text}");

        for i in 0..5 {
            let resp = send(&app, Method::GET, &format!("/store-api/kv/testdom/keys/cap:{i}"), Body::empty()).await;
            assert_eq!(resp.status(), StatusCode::OK, "cap:{i} must survive a rejected over-cap delete");
        }
    }

    // Test 7: exactly `cap` matches -> success, not 413.
    #[tokio::test]
    async fn test_bulk_delete_exactly_at_cap_succeeds() {
        let mut config = crate::engines::lsm::domain::DomainConfig::default();
        config.max_bulk_delete_keys = 3;
        let (app, _dir) = make_app_with_config(config).await;
        for i in 0..3 {
            send(&app, Method::PUT, &format!("/store-api/kv/testdom/keys/edge:{i}"), Body::from("v")).await;
        }

        let resp = send(&app, Method::DELETE, "/store-api/kv/testdom/keys?prefix=edge:", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp.into_body()).await["deleted"].as_u64().unwrap(), 3);
    }

    // Test 8: the cap is checked AFTER the `contains` filter — more raw
    // prefix hits than the cap, but the filtered set fits -> success, not a
    // false 413.
    #[tokio::test]
    async fn test_bulk_delete_cap_checked_after_contains_filter() {
        let mut config = crate::engines::lsm::domain::DomainConfig::default();
        config.max_bulk_delete_keys = 2;
        let (app, _dir) = make_app_with_config(config).await;
        send(&app, Method::PUT, "/store-api/kv/testdom/keys/f:x1", Body::from("v")).await;
        send(&app, Method::PUT, "/store-api/kv/testdom/keys/f:x2", Body::from("v")).await;
        send(&app, Method::PUT, "/store-api/kv/testdom/keys/f:y1", Body::from("v")).await;
        send(&app, Method::PUT, "/store-api/kv/testdom/keys/f:y2", Body::from("v")).await;

        let resp =
            send(&app, Method::DELETE, "/store-api/kv/testdom/keys?prefix=f:&contains=x", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK, "raw prefix hits exceed the cap, but the filtered set does not");
        assert_eq!(body_json(resp.into_body()).await["deleted"].as_u64().unwrap(), 2);
    }

    // Test 9 (spec §3.2 order): the write token is checked before the scan
    // runs. `read_iops = 1` makes this provable — draining only the write
    // bucket must 429 the bulk-delete without ever touching the sole read
    // token, so a GET right after must still succeed.
    #[tokio::test]
    async fn test_bulk_delete_checks_write_token_before_scanning() {
        let mut config = crate::engines::lsm::domain::DomainConfig::default();
        config.default_read_iops = 1;
        let (state, _dir) = make_state(config, false).await;
        let store = state.registry.store("testdom").await.unwrap();
        let app = crate::api::create_router(state, Arc::new(vec![]));

        send(&app, Method::PUT, "/store-api/kv/testdom/keys/ord:1", Body::from("v")).await;

        store.drain_write_budget_for_test();
        let resp = send(&app, Method::DELETE, "/store-api/kv/testdom/keys?prefix=ord:", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS, "write check must run before the scan");

        let resp = send(&app, Method::GET, "/store-api/kv/testdom/keys/ord:1", Body::empty()).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the sole read token must be untouched -- a scan-first bug would have consumed it"
        );
    }

    // Test 10: a watch subscriber gets one `delete` event per deleted key —
    // the same stream N individual DELETEs would have produced.
    #[tokio::test]
    async fn test_bulk_delete_fires_one_delete_event_per_key() {
        let (app, _dir) = make_app().await;
        send(&app, Method::PUT, "/store-api/kv/testdom/keys/w:1", Body::from("v")).await;
        send(&app, Method::PUT, "/store-api/kv/testdom/keys/w:2", Body::from("v")).await;

        let watch_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/store-api/kv/testdom/watch?prefix=w:")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(watch_resp.status(), StatusCode::OK);

        let resp = send(&app, Method::DELETE, "/store-api/kv/testdom/keys?prefix=w:", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp.into_body()).await["deleted"].as_u64().unwrap(), 2);

        // 2 delete events x 3 SSE fields each (id/event/data).
        let fields = read_sse_fields(watch_resp.into_body(), 6, std::time::Duration::from_secs(5)).await;
        let delete_count = fields.iter().filter(|(f, v)| f == "event" && v == "delete").count();
        assert_eq!(delete_count, 2, "expected exactly 2 delete events, got {fields:?}");
        let data_values: Vec<&str> = fields.iter().filter(|(f, _)| f == "data").map(|(_, v)| v.as_str()).collect();
        assert!(data_values.contains(&"w:1") && data_values.contains(&"w:2"), "got {fields:?}");
    }

    // Test 12: a key in the NULL state (kv/018) is a live key -- it appears
    // in the scan and gets deleted like any other; afterward it reads 404
    // (deleted), never 204 (NULL-but-present).
    #[tokio::test]
    async fn test_bulk_delete_includes_null_state_keys() {
        let (app, _dir) = make_app().await;
        send(&app, Method::PATCH, "/store-api/kv/testdom/keys/n:1/null", Body::empty()).await;
        send(&app, Method::PUT, "/store-api/kv/testdom/keys/n:2", Body::from("v")).await;

        let resp = send(&app, Method::DELETE, "/store-api/kv/testdom/keys?prefix=n:", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp.into_body()).await["deleted"].as_u64().unwrap(), 2);

        let resp = send(&app, Method::GET, "/store-api/kv/testdom/keys/n:1", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "a deleted NULL-state key must read as 404, not 204");
    }

    // Test 13: auth scoping -- a Read-only grant is not enough (403), a
    // Write grant is (200), and an admin passes regardless (200). DELETE is
    // unconditionally a write per `is_write_request` (spec §5).
    #[tokio::test]
    async fn test_bulk_delete_auth_scoping() {
        use crate::auth::{hash_api_key, AccessLevel, DomainPermission, UserRecord, UserRole};

        let (state, _dir) = make_state(crate::engines::lsm::domain::DomainConfig::default(), true).await;
        let cache = Arc::clone(&state.auth_cache);
        let app = crate::api::create_router(state, Arc::new(vec![]));

        cache
            .upsert_user(UserRecord {
                name: "reader".to_string(),
                api_key_hash: hash_api_key("lura_test_bulk_reader"),
                role: UserRole::User,
                created_at: 0,
            })
            .await
            .unwrap();
        cache
            .set_permission(DomainPermission {
                username: "reader".to_string(),
                domain: "testdom".to_string(),
                access: AccessLevel::Read,
            })
            .await
            .unwrap();

        cache
            .upsert_user(UserRecord {
                name: "writer".to_string(),
                api_key_hash: hash_api_key("lura_test_bulk_writer"),
                role: UserRole::User,
                created_at: 0,
            })
            .await
            .unwrap();
        cache
            .set_permission(DomainPermission {
                username: "writer".to_string(),
                domain: "testdom".to_string(),
                access: AccessLevel::Write,
            })
            .await
            .unwrap();

        cache
            .upsert_user(UserRecord {
                name: "admin".to_string(),
                api_key_hash: hash_api_key("lura_test_bulk_admin"),
                role: UserRole::Admin,
                created_at: 0,
            })
            .await
            .unwrap();

        let req = |key: &str| {
            Request::builder()
                .method(Method::DELETE)
                .uri("/store-api/kv/testdom/keys?prefix=a")
                .header("authorization", format!("Bearer {key}"))
                .body(Body::empty())
                .unwrap()
        };

        let resp = app.clone().oneshot(req("lura_test_bulk_reader")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "a read-only grant must not allow bulk delete");

        let resp = app.clone().oneshot(req("lura_test_bulk_writer")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "a write grant must allow bulk delete");

        let resp = app.clone().oneshot(req("lura_test_bulk_admin")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "admin must always be allowed");
    }

    // ── Spec kv/024: watch event ids, resume & gap signal ───────────────────

    // Test 2: the Last-Event-ID header wins over `?last_event_id=` when both
    // are present; either one alone is used as-is.
    #[test]
    fn test_resolve_last_event_id_header_wins_over_query() {
        let params = |q: Option<&str>| WatchParams { prefix: None, last_event_id: q.map(str::to_string) };

        let mut headers = HeaderMap::new();
        headers.insert("last-event-id", "w-1-1".parse().unwrap());
        assert_eq!(
            resolve_last_event_id(&headers, &params(Some("w-2-2"))),
            Some("w-1-1".to_string()),
            "header must win when both are set"
        );

        let empty_headers = HeaderMap::new();
        assert_eq!(resolve_last_event_id(&empty_headers, &params(Some("w-2-2"))), Some("w-2-2".to_string()));
        assert_eq!(resolve_last_event_id(&headers, &params(None)), Some("w-1-1".to_string()));
        assert_eq!(resolve_last_event_id(&empty_headers, &params(None)), None);
    }

    // watch_item: the pure per-message mapping the live loop uses (spec
    // kv/024 §4.3/§6) — every branch, without any real timing. Asserts on
    // `SseItem`'s plain fields rather than the rendered `axum::sse::Event`
    // (which exposes no accessors of its own).
    mod watch_item_tests {
        use super::*;

        fn set_event(seq: u64, key: &[u8]) -> WalEvent {
            WalEvent { seq, key: key.to_vec(), op: OpType::Set }
        }

        #[test]
        fn test_matching_prefix_emits_a_data_event() {
            let step = watch_item(Ok(WatchMessage::Event(set_event(5, b"user:1"))), b"user:", 42, None, 0);
            match step {
                WatchStep::Emit(item) => {
                    assert_eq!(item.id, format_event_id(WATCH_TAG, 42, 5));
                    assert_eq!(item.event, "set");
                    assert_eq!(item.data, "user:1");
                }
                _ => panic!("expected Emit"),
            }
        }

        #[test]
        fn test_delete_op_maps_to_delete_event_name() {
            let event = WalEvent { seq: 1, key: b"k".to_vec(), op: OpType::Delete };
            let step = watch_item(Ok(WatchMessage::Event(event)), b"", 1, None, 0);
            match step {
                WatchStep::Emit(item) => assert_eq!(item.event, "delete"),
                _ => panic!("expected Emit"),
            }
        }

        #[test]
        fn test_non_matching_prefix_is_skipped() {
            let step = watch_item(Ok(WatchMessage::Event(set_event(1, b"other:1"))), b"user:", 42, None, 0);
            assert!(matches!(step, WatchStep::Skip));
        }

        // seq <= suppress_upto is a re-delivery of the initial replay; seq >
        // suppress_upto is new and must be emitted (spec kv/024 §4.3).
        #[test]
        fn test_suppress_upto_boundary() {
            let msg = || Ok(WatchMessage::Event(set_event(10, b"k")));
            assert!(matches!(watch_item(msg(), b"", 1, Some(10), 0), WatchStep::Skip));
            assert!(matches!(watch_item(msg(), b"", 1, Some(9), 0), WatchStep::Emit(_)));
            assert!(matches!(watch_item(msg(), b"", 1, None, 0), WatchStep::Emit(_)));
        }

        #[test]
        fn test_gap_emits_reset_lagged_with_head_as_id() {
            let step = watch_item(Ok(WatchMessage::Gap), b"", 7, None, 99);
            match step {
                WatchStep::Emit(item) => {
                    assert_eq!(item.event, "reset");
                    assert_eq!(item.data, r#"{"reason":"lagged"}"#);
                    assert_eq!(item.id, format_event_id(WATCH_TAG, 7, 99));
                }
                _ => panic!("expected Emit"),
            }
        }

        #[test]
        fn test_receiver_lagged_also_emits_reset_lagged() {
            let step = watch_item(Err(broadcast::error::RecvError::Lagged(3)), b"", 7, None, 99);
            match step {
                WatchStep::Emit(item) => assert_eq!(item.data, r#"{"reason":"lagged"}"#),
                _ => panic!("expected Emit"),
            }
        }

        #[test]
        fn test_closed_stops() {
            let step = watch_item(Err(broadcast::error::RecvError::Closed), b"", 1, None, 0);
            assert!(matches!(step, WatchStep::Stop));
        }
    }

    /// Splits one SSE line into (field, value), tolerating an optional space
    /// after the colon — axum's exact spacing isn't part of the contract, so
    /// tests must not hardcode it. `split_once` only touches the *first*
    /// colon, so a `data:` value that itself contains a colon (e.g. a key
    /// like `user:1`) is preserved intact.
    fn parse_sse_field(line: &str) -> Option<(&str, &str)> {
        let (field, rest) = line.split_once(':')?;
        Some((field, rest.strip_prefix(' ').unwrap_or(rest)))
    }

    /// Reads SSE lines (as parsed (field, value) pairs) from a streaming
    /// response body, waiting up to `timeout` per chunk -- avoids hanging on
    /// a stream that (by design) never completes on its own. Blank
    /// (keep-alive comment) lines are dropped.
    async fn read_sse_fields(
        body: Body,
        min_fields: usize,
        timeout: std::time::Duration,
    ) -> Vec<(String, String)> {
        let mut stream = body.into_data_stream();
        let mut buf = String::new();
        let mut fields = Vec::new();
        while fields.len() < min_fields {
            let chunk = tokio::time::timeout(timeout, stream.next())
                .await
                .expect("timed out waiting for an SSE chunk")
                .expect("stream ended before min_fields was reached")
                .expect("chunk read error");
            buf.push_str(&String::from_utf8_lossy(&chunk));
            while let Some(pos) = buf.find('\n') {
                let line = buf[..pos].trim_end_matches('\r').to_string();
                buf = buf[pos + 1..].to_string();
                if let Some((field, value)) = parse_sse_field(&line) {
                    fields.push((field.to_string(), value.to_string()));
                }
            }
        }
        fields
    }

    // Test 6 (additive) + wire format: a fresh connect (no Last-Event-ID)
    // gets no reset, and the `set` event it does see carries a real `id:`.
    #[tokio::test]
    async fn test_watch_sse_wire_format_has_id_and_no_reset_when_fresh() {
        let (app, _dir) = make_app().await;
        let watch_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/store-api/kv/testdom/watch")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(watch_resp.status(), StatusCode::OK);

        send(&app, Method::PUT, "/store-api/kv/testdom/keys/watched", Body::from("v")).await;

        let fields = read_sse_fields(watch_resp.into_body(), 3, std::time::Duration::from_secs(5)).await;
        assert!(
            fields.iter().any(|(f, v)| f == "id" && v.starts_with("w-")),
            "expected an id: w-... field, got {fields:?}"
        );
        assert!(fields.contains(&("event".to_string(), "set".to_string())), "got {fields:?}");
        assert!(fields.contains(&("data".to_string(), "watched".to_string())), "got {fields:?}");
        assert!(
            !fields.iter().any(|(f, v)| f == "event" && v == "reset"),
            "a fresh connect must never reset, got {fields:?}"
        );
    }

    // Test 10: `?prefix=` applies identically to the replay list and the
    // live stream -- a non-matching key is invisible on both sides of the
    // same connection.
    #[tokio::test]
    async fn test_watch_prefix_filter_applies_to_replay_and_live_identically() {
        let (app, _dir) = make_app().await;
        send(&app, Method::PUT, "/store-api/kv/testdom/keys/user:1", Body::from("v")).await;
        send(&app, Method::PUT, "/store-api/kv/testdom/keys/item:1", Body::from("v")).await;

        // Resume from seq 0 ("from the beginning") so both pre-existing
        // writes are replayed, exercising the replay-side filter.
        let id0 = format_event_id(WATCH_TAG, stream_epoch(), 0);
        let watch_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/store-api/kv/testdom/watch?prefix=user:&last_event_id={id0}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(watch_resp.status(), StatusCode::OK);

        // A live write outside the prefix must also stay invisible.
        send(&app, Method::PUT, "/store-api/kv/testdom/keys/item:2", Body::from("v")).await;
        send(&app, Method::PUT, "/store-api/kv/testdom/keys/user:2", Body::from("v")).await;

        // 2 full events (user:1 replayed, user:2 live) x 3 fields each
        // (id/event/data) -- read enough to capture both completely.
        let fields = read_sse_fields(watch_resp.into_body(), 6, std::time::Duration::from_secs(5)).await;
        let data_values: Vec<&str> = fields.iter().filter(|(f, _)| f == "data").map(|(_, v)| v.as_str()).collect();
        assert_eq!(data_values, vec!["user:1", "user:2"], "item:* must never appear, got {fields:?}");
    }

    // ── Spec kv/028: GET …/keys pagination & contains filter ────────────────

    // Test 1: 25 keys, limit=10 -> page 1 (offset=0) and page 2 (offset=10)
    // are disjoint, each in sorted scan order, `total=25` on every page;
    // page 3 (offset=20) holds the remaining 5; offset=30 is past the end
    // -> empty `keys`, `total` unchanged, still 200.
    #[tokio::test]
    async fn test_scan_keys_pagination_pages_are_disjoint_and_sorted() {
        let (app, _dir) = make_app().await;
        for i in 0..25 {
            send(&app, Method::PUT, &format!("/store-api/kv/testdom/keys/p:{i:02}"), Body::from("v")).await;
        }
        let expected: Vec<String> = (0..25).map(|i| format!("p:{i:02}")).collect();
        let page = |offset: usize| format!("/store-api/kv/testdom/keys?prefix=p:&limit=10&offset={offset}");

        for (offset, start, end) in [(0usize, 0usize, 10usize), (10, 10, 20), (20, 20, 25)] {
            let resp = send(&app, Method::GET, &page(offset), Body::empty()).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = body_json(resp.into_body()).await;
            let keys: Vec<String> = serde_json::from_value(body["keys"].clone()).unwrap();
            assert_eq!(keys, expected[start..end].to_vec(), "offset={offset}");
            assert_eq!(body["total"].as_u64().unwrap(), 25);
        }

        let resp = send(&app, Method::GET, &page(30), Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        let keys: Vec<String> = serde_json::from_value(body["keys"].clone()).unwrap();
        assert!(keys.is_empty(), "offset past the end must yield an empty page");
        assert_eq!(body["total"].as_u64().unwrap(), 25);
    }

    // Test 2: no `limit` -> default 1000; with > 1000 matches, exactly 1000
    // keys come back, the envelope's `limit` reads 1000, and `total` is the
    // full match count. Seeded concurrently (see test_count_keys_large_volume)
    // with a raised write quota so the burst doesn't trip the default 500/s.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_scan_keys_default_limit_is_1000() {
        let mut config = crate::engines::lsm::domain::DomainConfig::default();
        config.default_write_iops = 5_000;
        let (app, _dir) = make_app_with_config(config).await;

        let app_ref = &app;
        let puts = (0..1_100u32).map(|i| async move {
            let uri = format!("/store-api/kv/testdom/keys/d:{i:05}");
            send(app_ref, Method::PUT, &uri, Body::from("v")).await
        });
        futures::future::join_all(puts).await;

        let resp = send(&app, Method::GET, "/store-api/kv/testdom/keys?prefix=d:", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        let keys: Vec<String> = serde_json::from_value(body["keys"].clone()).unwrap();
        assert_eq!(keys.len(), 1000, "default page size must be 1000");
        assert_eq!(body["limit"].as_u64().unwrap(), 1000);
        assert_eq!(body["total"].as_u64().unwrap(), 1_100);
    }

    // Test 3: `limit` above the maximum is silently capped -- the envelope
    // reports the effective value (10000), no 400. A real 10001-key page
    // isn't needed to prove this: the take() logic itself is already
    // covered by test 1's pagination.
    #[tokio::test]
    async fn test_scan_keys_limit_above_max_is_capped_in_envelope() {
        let (app, _dir) = make_app().await;
        send(&app, Method::PUT, "/store-api/kv/testdom/keys/only", Body::from("v")).await;

        let resp = send(&app, Method::GET, "/store-api/kv/testdom/keys?limit=999999", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        assert_eq!(body["limit"].as_u64().unwrap(), 10_000, "limit must be capped to the maximum in the envelope");
    }

    // Test 4: `contains` is case-sensitive and counts toward `total` -- same
    // scenario as the bulk-delete contains filter (kv/023 test 2):
    // `contains=Log` matches `app:Log:1`, not `app:log:2`.
    #[tokio::test]
    async fn test_scan_keys_contains_filter_is_case_sensitive_and_counts_in_total() {
        let (app, _dir) = make_app().await;
        send(&app, Method::PUT, "/store-api/kv/testdom/keys/app:Log:1", Body::from("v")).await;
        send(&app, Method::PUT, "/store-api/kv/testdom/keys/app:log:2", Body::from("v")).await;

        let resp =
            send(&app, Method::GET, "/store-api/kv/testdom/keys?prefix=app:&contains=Log", Body::empty()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        let keys: Vec<String> = serde_json::from_value(body["keys"].clone()).unwrap();
        assert_eq!(keys, vec!["app:Log:1".to_string()]);
        assert_eq!(body["total"].as_u64().unwrap(), 1, "total must reflect the filtered count");
    }

    // Test 5: prefix + contains + offset/limit combined -- filtering happens
    // before pagination (more raw prefix hits than the filtered count, which
    // itself fits under `limit`): the page holds every filtered match,
    // `total` is the filtered count, and a follow-up offset slices that same
    // filtered set rather than the raw prefix hits.
    #[tokio::test]
    async fn test_scan_keys_prefix_contains_offset_limit_combined() {
        let (app, _dir) = make_app().await;
        for k in ["f:x1", "f:x2", "f:x3", "f:y1", "f:y2"] {
            send(&app, Method::PUT, &format!("/store-api/kv/testdom/keys/{k}"), Body::from("v")).await;
        }

        let resp = send(
            &app,
            Method::GET,
            "/store-api/kv/testdom/keys?prefix=f:&contains=x&limit=4",
            Body::empty(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp.into_body()).await;
        let keys: Vec<String> = serde_json::from_value(body["keys"].clone()).unwrap();
        assert_eq!(keys, vec!["f:x1".to_string(), "f:x2".to_string(), "f:x3".to_string()]);
        assert_eq!(body["total"].as_u64().unwrap(), 3, "total must be the filtered count, not the 5 raw prefix hits");

        let resp = send(
            &app,
            Method::GET,
            "/store-api/kv/testdom/keys?prefix=f:&contains=x&limit=4&offset=1",
            Body::empty(),
        )
        .await;
        let body = body_json(resp.into_body()).await;
        let keys: Vec<String> = serde_json::from_value(body["keys"].clone()).unwrap();
        assert_eq!(keys, vec!["f:x2".to_string(), "f:x3".to_string()], "offset must slice the filtered set");
        assert_eq!(body["total"].as_u64().unwrap(), 3);
    }
}
