//! Global lifecycle/DDL event stream (spec general/018).
//!
//! GET /store-api/events → get_events (SSE stream, admin-only — see auth::middleware::extract_domain:
//! a path with no `{domain}` segment is admin-only, no auth code needed here)

use crate::api::AppState;
use crate::core::events::{format_event_id, stream_epoch, GlobalEvent, ResetReason, Resume, EVENTS_TAG};
use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::sse::{Event, KeepAlive, Sse},
};
use futures::StreamExt;
use serde::Deserialize;
use std::convert::Infallible;
use tokio::sync::broadcast;

// ── Query param types ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct EventsParams {
    /// Fallback resume id for callers that cannot set headers (e.g. `curl`,
    /// or a `fetch`-based reader); the `Last-Event-ID` header wins when both
    /// are present (spec general/018 §5, kv/024 §4.1).
    pub last_event_id: Option<String>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Resolves the effective `Last-Event-ID` (spec general/018 §5, kv/024
/// §4.1): the header — what a native `EventSource`'s auto-reconnect sets —
/// wins when both the header and `?last_event_id=` are present.
fn resolve_last_event_id(headers: &HeaderMap, params: &EventsParams) -> Option<String> {
    headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| params.last_event_id.clone())
}

/// A decided SSE item, before axum-specific rendering (kv/024 pattern: kept
/// as plain data so the decision logic is unit-testable without depending on
/// `Event`'s internal representation, which exposes no accessors of its own).
struct SseItem {
    id: String,
    event: &'static str,
    data: String,
}

fn render_sse_item(item: SseItem) -> Event {
    Event::default().id(item.id).event(item.event).data(item.data)
}

fn global_event_item(event: &GlobalEvent, epoch: u64) -> SseItem {
    let data = serde_json::to_string(event).expect("GlobalEvent serializes infallibly");
    SseItem { id: format_event_id(EVENTS_TAG, epoch, event.seq), event: event.kind, data }
}

/// Builds `event: reset` (spec general/018 §5, kv/024 §5): `id:` carries the
/// current sequence head, so a reconnect right after a reset resumes
/// gaplessly from there.
fn reset_item(reason: ResetReason, epoch: u64, head: u64) -> SseItem {
    let data = serde_json::to_string(&serde_json::json!({ "reason": reason }))
        .expect("ResetReason serializes infallibly");
    SseItem { id: format_event_id(EVENTS_TAG, epoch, head), event: "reset", data }
}

enum EventStep {
    Emit(SseItem),
    Skip,
    Stop,
}

/// Maps one raw bus receive to a live-stream outcome (spec general/018 §5,
/// kv/024 §4.3/§6). Unlike kv/024's per-domain `watch_item`, there is no
/// relay task and no domain/prefix filter here (§5: the handler subscribes to
/// the bus directly) — so there is no `Gap` message, only the receiver's own
/// `Lagged`, mapped straight to `reset(lagged)`, never a silent `continue`.
/// Pure (no I/O), so every branch is unit-testable without real timing.
fn global_live_item(
    msg: Result<GlobalEvent, broadcast::error::RecvError>,
    epoch: u64,
    suppress_upto: Option<u64>,
    head: u64,
) -> EventStep {
    match msg {
        Ok(event) => {
            if suppress_upto.is_some_and(|upto| event.seq <= upto) {
                return EventStep::Skip;
            }
            EventStep::Emit(global_event_item(&event, epoch))
        }
        Err(broadcast::error::RecvError::Lagged(_)) => {
            EventStep::Emit(reset_item(ResetReason::Lagged, epoch, head))
        }
        Err(broadcast::error::RecvError::Closed) => EventStep::Stop,
    }
}

// ── Handler ───────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/store-api/events",
    params(
        ("last_event_id" = Option<String>, Query, description = "Resume id from a previous `id:` (or `event: reset`) — for callers that cannot set headers. Ignored when the `Last-Event-ID` header is present."),
        ("Last-Event-ID" = Option<String>, Header, description = "Resume id from a previous `id:` (or `event: reset`); set automatically by a native `EventSource`'s auto-reconnect. Takes precedence over `?last_event_id=`."),
    ),
    responses(
        (status = 200, description = "SSE stream of lifecycle/DDL events across the KV, JSON and relational engines: domains created/deleted/purged, and (rel) table/view/index DDL, (json) index DDL. No per-key data events — use a domain's `watch` for those. Every event carries an `id:`; `event:` matches its `type` field (e.g. `domain_created`, `table_altered`). `data:` is JSON `{engine, type, domain, object?, ts}` — `object` is the table/view/index/field name, absent for domain events. `event: reset` (`data: {\"reason\": ...}`) is emitted whenever gapless resume cannot be guaranteed.", content_type = "text/event-stream"),
        (status = 401, description = "Missing or invalid API key"),
        (status = 403, description = "Non-admin caller — this endpoint has no `{domain}` segment, so it is admin-only"),
    ),
    tag = "Events"
)]
/// Opens a Server-Sent Events stream of global lifecycle/DDL events: domains created, deleted and
/// purged across all three engines, plus relational table/view/index DDL and JSON index DDL.
/// Admin-only — the path carries no domain segment, so the standard auth middleware rejects any
/// non-admin caller (spec general/018 §3).
///
/// A `Last-Event-ID` (header or `?last_event_id=`, header wins) resumes gaplessly from an in-memory
/// replay ring when possible; otherwise the server emits `event: reset` before continuing live. This
/// stream has its own tag (`g`) and sequence, entirely independent of `GET /store-api/kv/{domain}/watch`'s
/// (`w`) — an id from one stream is `unknown_id` at the other.
pub async fn get_events(
    State(state): State<AppState>,
    Query(params): Query<EventsParams>,
    headers: HeaderMap,
) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>> + Send + 'static> {
    let last_event_id = resolve_last_event_id(&headers, &params);
    let epoch = stream_epoch();

    // subscribe() before the ring snapshot (spec §5, kv/024 §4.3): nothing
    // published between them can be lost — only re-delivered, which the live
    // loop below discards via `suppress_upto`.
    let rx = state.event_bus.subscribe();
    let resume = state.event_bus.decide_resume(last_event_id.as_deref());

    let (leading, suppress_upto): (Vec<Event>, Option<u64>) = match resume {
        Resume::Live => (Vec::new(), None),
        Resume::Reset { reason, head } => (vec![render_sse_item(reset_item(reason, epoch, head))], None),
        Resume::Replay { events, head } => {
            let items = events.iter().map(|e| render_sse_item(global_event_item(e, epoch))).collect();
            (items, Some(head))
        }
    };
    let leading_stream = futures::stream::iter(leading.into_iter().map(Ok::<Event, Infallible>));

    let bus = state.event_bus;
    let live_stream = futures::stream::unfold((rx, suppress_upto, bus), move |(mut rx, suppress_upto, bus)| async move {
        loop {
            let msg = rx.recv().await;
            let head = bus.head();
            match global_live_item(msg, epoch, suppress_upto, head) {
                EventStep::Emit(item) => {
                    return Some((Ok::<Event, Infallible>(render_sse_item(item)), (rx, suppress_upto, bus)))
                }
                EventStep::Skip => continue,
                EventStep::Stop => return None,
            }
        }
    });

    Sse::new(leading_stream.chain(live_stream)).keep_alive(KeepAlive::default())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{JsonStoreConfig, RelStoreConfig};
    use crate::core::events::GlobalEventBus;
    use crate::engines::json::JsonEngine;
    use crate::engines::lsm::{DomainRegistry, LsmStorageEngine};
    use crate::engines::rel::{CrossEngineResolver, RelEngine};
    use crate::core::wal::WriteAheadLog;
    use crate::storage::file_manager::FileManager;
    use crate::storage::manifest::ManifestManager;
    use crate::storage::vlog::VLog;
    use axum::body::{to_bytes, Body};
    use axum::http::{Method, Request, StatusCode};
    use std::sync::Arc;
    use tower::util::ServiceExt;

    /// Full three-engine test app, admin key pre-provisioned, bus wired to
    /// all three engines before the router is built (mirrors main.rs's
    /// startup order, spec §1).
    struct TestApp {
        app: axum::Router,
        admin_key: String,
    }

    async fn make_app() -> (TestApp, tempfile::TempDir) {
        make_app_with(256, 1024).await
    }

    async fn make_app_with(channel_capacity: usize, replay_buffer_size: usize) -> (TestApp, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();

        let wal = Arc::new(WriteAheadLog::new(&dir.path().join("wal.log")).await.unwrap());
        let vlog = Arc::new(VLog::new(&dir.path().join("vlog.log")).await.unwrap());
        let fm = Arc::new(FileManager::new(dir.path()).await.unwrap());
        let mm = Arc::new(ManifestManager::new(dir.path()));
        let engine = Arc::new(
            LsmStorageEngine::new(
                wal, dir.path().join("wal.log"), vlog, dir.path().join("vlog.log"), fm, mm,
                crate::engines::lsm::engine::LsmEngineOptions::default(),
            )
            .await
            .unwrap(),
        );
        let metrics = crate::metrics::MetricsStore::new(crate::metrics::MetricsConfig::default());
        let registry = Arc::new(
            DomainRegistry::recover(Arc::clone(&engine), crate::engines::lsm::domain::DomainConfig::default(), Arc::clone(&metrics))
                .await
                .unwrap(),
        );

        let json_engine = JsonEngine::bootstrap(&JsonStoreConfig {
            wal_path: dir.path().join("json.wal").to_string_lossy().into_owned(),
            vlog_path: dir.path().join("json.vlog").to_string_lossy().into_owned(),
            sstable_dir: dir.path().join("json_sstables").to_string_lossy().into_owned(),
            ..JsonStoreConfig::default()
        })
        .await
        .unwrap();

        let cross_engine = CrossEngineResolver::disabled(Arc::clone(&metrics));
        let rel_engine = RelEngine::bootstrap(
            &RelStoreConfig {
                wal_path: dir.path().join("rel.wal").to_string_lossy().into_owned(),
                vlog_path: dir.path().join("rel.vlog").to_string_lossy().into_owned(),
                sstable_dir: dir.path().join("rel_sstables").to_string_lossy().into_owned(),
                ..RelStoreConfig::default()
            },
            Arc::clone(&metrics),
            cross_engine,
        )
        .await
        .unwrap();

        let bus = Arc::new(GlobalEventBus::new(channel_capacity, replay_buffer_size));
        registry.attach_event_bus(Arc::clone(&bus)); // attach before anything runs, spec §1
        json_engine.attach_event_bus(Arc::clone(&bus));
        rel_engine.attach_event_bus(Arc::clone(&bus));

        let auth_cache = Arc::new(crate::auth::AuthCache::new(Arc::clone(&engine)));
        let admin_key = "lura_test_events_admin".to_string();
        auth_cache
            .upsert_user(crate::auth::UserRecord {
                name: "admin".to_string(),
                api_key_hash: crate::auth::hash_api_key(&admin_key),
                role: crate::auth::UserRole::Admin,
                created_at: 0,
            })
            .await
            .unwrap();

        let state = AppState {
            registry,
            auth_cache,
            auth_enabled: true,
            metrics,
            json_engine: Some(json_engine),
            rel_engine: Some(rel_engine),
            shm_manager: None,
            backup_manager: None,
            log_access: None,
            event_bus: bus,
        };
        let app = crate::api::create_router(state, Arc::new(vec![]));
        (TestApp { app, admin_key }, dir)
    }

    async fn admin_req(app: &axum::Router, uri: &str, admin_key: &str) -> axum::http::Response<Body> {
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(uri)
                    .header("authorization", format!("Bearer {admin_key}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    /// Splits one SSE line into (field, value) — see kv.rs's identical helper.
    fn parse_sse_field(line: &str) -> Option<(&str, &str)> {
        let (field, rest) = line.split_once(':')?;
        Some((field, rest.strip_prefix(' ').unwrap_or(rest)))
    }

    /// Reads SSE lines from a streaming response body until at least
    /// `min_fields` have been parsed, waiting up to `timeout` per chunk.
    async fn read_sse_fields(body: Body, min_fields: usize, timeout: std::time::Duration) -> Vec<(String, String)> {
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

    // Test 6: no key -> 401; valid non-admin key -> 403; admin key -> 200
    // with text/event-stream. Pins the path-shape admin-only property (§3).
    #[tokio::test]
    async fn test_auth_no_key_401_non_admin_403_admin_200() {
        let (t, _dir) = make_app().await;

        let resp = t
            .app
            .clone()
            .oneshot(Request::builder().method(Method::GET).uri("/store-api/events").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // A non-admin key, created via the real API (no domain permission
        // whatsoever — irrelevant here anyway, since this path has no domain
        // segment for a permission to attach to).
        let create_resp = t
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/store-api/auth/users")
                    .header("authorization", format!("Bearer {}", t.admin_key))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name":"worker"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_resp.status(), StatusCode::CREATED);
        let body = to_bytes(create_resp.into_body(), usize::MAX).await.unwrap();
        let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let worker_key = created["api_key"].as_str().unwrap().to_string();

        let resp = t
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/store-api/events")
                    .header("authorization", format!("Bearer {worker_key}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "non-admin, no domain segment -> 403");

        let resp = admin_req(&t.app, "/store-api/events", &t.admin_key).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(axum::http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()),
            Some("text/event-stream")
        );
    }

    // Wire-format smoke test: a fresh connect gets no reset, and a real
    // lifecycle event carries id/event/data with the right shape.
    #[tokio::test]
    async fn test_sse_wire_format_has_id_and_no_reset_when_fresh() {
        let (t, _dir) = make_app().await;
        let resp = admin_req(&t.app, "/store-api/events", &t.admin_key).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let create_resp = t
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/store-api/domains")
                    .header("authorization", format!("Bearer {}", t.admin_key))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name":"sales"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_resp.status(), StatusCode::CREATED);

        let fields = read_sse_fields(resp.into_body(), 3, std::time::Duration::from_secs(5)).await;
        assert!(fields.iter().any(|(f, v)| f == "id" && v.starts_with("g-")), "got {fields:?}");
        assert!(fields.contains(&("event".to_string(), "domain_created".to_string())), "got {fields:?}");
        let data = fields.iter().find(|(f, _)| f == "data").map(|(_, v)| v.clone()).expect("data field");
        let json: serde_json::Value = serde_json::from_str(&data).unwrap();
        assert_eq!(json["engine"], "kv");
        assert_eq!(json["type"], "domain_created");
        assert_eq!(json["domain"], "sales");
        assert!(json.get("object").is_none());
        assert!(json["ts"].as_u64().unwrap() > 0);
        assert!(
            !fields.iter().any(|(f, v)| f == "event" && v == "reset"),
            "a fresh connect must never reset, got {fields:?}"
        );
    }

    // Test 7: disconnect after event 3, reconnect with its id -> exactly the
    // following events, no reset. Connects (Resume::Live, spec §5) *before*
    // the writes happen -- with no id presented, only events published after
    // the subscribe are ever seen, exactly as for a fresh domain watch.
    #[tokio::test]
    async fn test_resume_gapless_after_reconnect() {
        let (t, _dir) = make_app().await;
        let resp = admin_req(&t.app, "/store-api/events", &t.admin_key).await;

        for i in 0..5 {
            let resp = t
                .app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri("/store-api/domains")
                        .header("authorization", format!("Bearer {}", t.admin_key))
                        .header("content-type", "application/json")
                        .body(Body::from(format!(r#"{{"name":"d{i}"}}"#)))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::CREATED);
        }

        let fields = read_sse_fields(resp.into_body(), 15, std::time::Duration::from_secs(5)).await; // 5 events x 3 fields
        let third_id = fields
            .iter()
            .enumerate()
            .filter(|(_, (f, _))| f == "id")
            .nth(2)
            .map(|(_, (_, v))| v.clone())
            .expect("third id");

        let resumed = t
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/store-api/events?last_event_id={third_id}"))
                    .header("authorization", format!("Bearer {}", t.admin_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let resumed_fields = read_sse_fields(resumed.into_body(), 6, std::time::Duration::from_secs(5)).await; // events 4,5
        let domains: Vec<String> = resumed_fields
            .iter()
            .filter(|(f, _)| f == "data")
            .map(|(_, v)| serde_json::from_str::<serde_json::Value>(v).unwrap()["domain"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(domains, vec!["d3", "d4"], "expected exactly the events after the third, got {resumed_fields:?}");
        assert!(
            !resumed_fields.iter().any(|(f, v)| f == "event" && v == "reset"),
            "a gapless resume must never reset, got {resumed_fields:?}"
        );
    }

    // Test 8: a tiny replay_buffer_size gets overrun -> reset(window_exceeded).
    #[tokio::test]
    async fn test_window_exceeded_resets() {
        let (t, _dir) = make_app_with(256, 2).await;
        for i in 0..5 {
            let resp = t
                .app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri("/store-api/domains")
                        .header("authorization", format!("Bearer {}", t.admin_key))
                        .header("content-type", "application/json")
                        .body(Body::from(format!(r#"{{"name":"d{i}"}}"#)))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::CREATED);
        }

        let epoch = stream_epoch();
        let stale_id = format_event_id(EVENTS_TAG, epoch, 1);
        let resp = t
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/store-api/events?last_event_id={stale_id}"))
                    .header("authorization", format!("Bearer {}", t.admin_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let fields = read_sse_fields(resp.into_body(), 3, std::time::Duration::from_secs(5)).await;
        assert!(fields.contains(&("event".to_string(), "reset".to_string())), "got {fields:?}");
        let data = fields.iter().find(|(f, _)| f == "data").map(|(_, v)| v.clone()).unwrap();
        assert_eq!(serde_json::from_str::<serde_json::Value>(&data).unwrap()["reason"], "window_exceeded");
    }

    // Test 9: a resume id from a different epoch -> reset(restart).
    #[tokio::test]
    async fn test_restart_epoch_mismatch_resets() {
        let (t, _dir) = make_app().await;
        let fake_epoch = stream_epoch().wrapping_add(1);
        let id = format_event_id(EVENTS_TAG, fake_epoch, 1);
        let resp = t
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/store-api/events?last_event_id={id}"))
                    .header("authorization", format!("Bearer {}", t.admin_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let fields = read_sse_fields(resp.into_body(), 3, std::time::Duration::from_secs(5)).await;
        let data = fields.iter().find(|(f, _)| f == "data").map(|(_, v)| v.clone()).unwrap();
        assert_eq!(serde_json::from_str::<serde_json::Value>(&data).unwrap()["reason"], "restart");
    }

    // Test 10: a tiny channel_capacity plus a burst makes a blocked consumer
    // lag -> reset(lagged), after which events flow again.
    #[tokio::test]
    async fn test_lagged_consumer_resets_then_events_flow_again() {
        let (t, _dir) = make_app_with(2, 1024).await;
        let resp = admin_req(&t.app, "/store-api/events", &t.admin_key).await;
        let mut stream = resp.into_body().into_data_stream();

        // Burst well past the tiny channel capacity without draining.
        for i in 0..20 {
            let r = t
                .app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri("/store-api/domains")
                        .header("authorization", format!("Bearer {}", t.admin_key))
                        .header("content-type", "application/json")
                        .body(Body::from(format!(r#"{{"name":"d{i}"}}"#)))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::CREATED);
        }

        let mut buf = String::new();
        let mut fields = Vec::new();
        let mut saw_reset = false;
        let mut saw_event_after_reset = false;
        while fields.len() < 200 {
            let chunk = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
                .await
                .expect("timed out waiting for an SSE chunk")
                .expect("stream ended early")
                .expect("chunk read error");
            buf.push_str(&String::from_utf8_lossy(&chunk));
            while let Some(pos) = buf.find('\n') {
                let line = buf[..pos].trim_end_matches('\r').to_string();
                buf = buf[pos + 1..].to_string();
                if let Some((field, value)) = parse_sse_field(&line) {
                    if field == "event" && value == "reset" {
                        saw_reset = true;
                    } else if field == "event" && value != "reset" && saw_reset {
                        saw_event_after_reset = true;
                    }
                    fields.push((field.to_string(), value.to_string()));
                }
            }
            if saw_event_after_reset {
                break;
            }
        }
        assert!(saw_reset, "a burst past channel capacity must lag a non-draining consumer, got {fields:?}");
        assert!(saw_event_after_reset, "events must keep flowing after a lagged reset, got {fields:?}");
    }

    // Test 11: a watch id (kv/024's "w") at /store-api/events -> reset(unknown_id).
    #[tokio::test]
    async fn test_foreign_watch_tag_is_unknown_id() {
        let (t, _dir) = make_app().await;
        let id = format_event_id("w", stream_epoch(), 1);
        let resp = t
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/store-api/events?last_event_id={id}"))
                    .header("authorization", format!("Bearer {}", t.admin_key))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let fields = read_sse_fields(resp.into_body(), 3, std::time::Duration::from_secs(5)).await;
        let data = fields.iter().find(|(f, _)| f == "data").map(|(_, v)| v.clone()).unwrap();
        assert_eq!(serde_json::from_str::<serde_json::Value>(&data).unwrap()["reason"], "unknown_id");
    }

    // ── Pure global_live_item branches (mirrors kv.rs's watch_item_tests) ────

    mod global_live_item_tests {
        use super::*;

        fn event(seq: u64) -> GlobalEvent {
            GlobalEvent { seq, engine: "kv", kind: "domain_created", domain: "d".to_string(), object: None, ts: 1 }
        }

        #[test]
        fn test_new_event_emits() {
            let step = global_live_item(Ok(event(5)), 42, None, 0);
            match step {
                EventStep::Emit(item) => {
                    assert_eq!(item.id, format_event_id(EVENTS_TAG, 42, 5));
                    assert_eq!(item.event, "domain_created");
                }
                _ => panic!("expected Emit"),
            }
        }

        #[test]
        fn test_suppress_upto_boundary() {
            assert!(matches!(global_live_item(Ok(event(10)), 1, Some(10), 0), EventStep::Skip));
            assert!(matches!(global_live_item(Ok(event(10)), 1, Some(9), 0), EventStep::Emit(_)));
            assert!(matches!(global_live_item(Ok(event(10)), 1, None, 0), EventStep::Emit(_)));
        }

        #[test]
        fn test_lagged_emits_reset_lagged_with_head_as_id() {
            let step = global_live_item(Err(broadcast::error::RecvError::Lagged(3)), 7, None, 99);
            match step {
                EventStep::Emit(item) => {
                    assert_eq!(item.event, "reset");
                    assert_eq!(item.data, r#"{"reason":"lagged"}"#);
                    assert_eq!(item.id, format_event_id(EVENTS_TAG, 7, 99));
                }
                _ => panic!("expected Emit"),
            }
        }

        #[test]
        fn test_closed_stops() {
            assert!(matches!(global_live_item(Err(broadcast::error::RecvError::Closed), 1, None, 0), EventStep::Stop));
        }
    }

    // Test 2: resolve_last_event_id header-wins-over-query, mirrored from kv.rs.
    #[test]
    fn test_resolve_last_event_id_header_wins_over_query() {
        let params = |q: Option<&str>| EventsParams { last_event_id: q.map(str::to_string) };

        let mut headers = HeaderMap::new();
        headers.insert("last-event-id", "g-1-1".parse().unwrap());
        assert_eq!(
            resolve_last_event_id(&headers, &params(Some("g-2-2"))),
            Some("g-1-1".to_string()),
            "header must win when both are set"
        );

        let empty_headers = HeaderMap::new();
        assert_eq!(resolve_last_event_id(&empty_headers, &params(Some("g-2-2"))), Some("g-2-2".to_string()));
        assert_eq!(resolve_last_event_id(&headers, &params(None)), Some("g-1-1".to_string()));
        assert_eq!(resolve_last_event_id(&empty_headers, &params(None)), None);
    }
}
