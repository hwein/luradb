//! REST handlers for Spec 013 — Metrics & Heartbeat.
//!
//! GET /health                             → heartbeat, no auth
//! GET /store-api/metrics                  → system + all domain metrics, Admin only
//! GET /store-api/metrics/domains/{name}   → single domain metrics, Admin or domain user

use crate::api::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use serde_json::{json, Value};
use std::sync::atomic::Ordering;

/// `GET /health` — public heartbeat endpoint.
///
/// Returns a JSON snapshot of system vitals. No authentication required.
#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "System is healthy"),
    ),
    security(()),
    tag = "Metrics"
)]
pub async fn health(State(state): State<AppState>) -> Json<Value> {
    let engine_data = state.registry.engine().heartbeat_data();
    let domain_count = state
        .registry
        .list_domains()
        .await
        .map(|d| d.len())
        .unwrap_or(0);
    let hb = state.metrics.heartbeat(&engine_data, domain_count);
    Json(serde_json::to_value(hb).unwrap_or_else(|_| json!({"status": "ok"})))
}

#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct VersionResponse {
    /// Server version (CARGO_PKG_VERSION).
    pub server_version: String,
    /// API contract version — identical to the contract's `info.version`.
    pub api_version: String,
}

/// `GET /version` — version handshake. Requires any valid API key.
#[utoipa::path(
    get,
    path = "/version",
    responses(
        (status = 200, description = "Server and API contract version", body = VersionResponse),
        (status = 401, description = "Unauthorized — a valid API key is required"),
    ),
    security(("bearer_auth" = [])),
    tag = "Metrics"
)]
pub async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        server_version: env!("CARGO_PKG_VERSION").to_string(),
        api_version: crate::api::API_VERSION.to_string(),
    })
}

/// `GET /config` — effective configuration of the running process. Admin only.
///
/// The path carries no `{domain}` segment, so `extract_domain` returns `None`
/// and the auth layer's None-branch requires an admin role (spec
/// general/022). The admin API key never appears in the body — redaction
/// happens at the field level (`AdminEntry.api_key`'s `#[serde(skip_serializing)]`
/// in config.rs), not in this handler.
#[utoipa::path(
    get,
    path = "/store-api/config",
    responses(
        (status = 200, description = "config_path (resolved path, always set), config_file_loaded (whether a file existed there), and config (the effective LuraConfig — see config.rs for field docs)", body = Object),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden — Admin only"),
    ),
    security(("bearer_auth" = [])),
    tag = "Metrics"
)]
pub async fn get_config(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "config_path": state.config_path,
        "config_file_loaded": state.config_file_loaded,
        "config": &*state.config,
    }))
}

/// `GET /metrics` — system + all domain metrics. Admin only.
///
/// `engines` (spec general/019) is an additive block, one entry per storage
/// engine (`kv`/`json`/`rel`), each with the same nine fields: `read_ops`,
/// `write_ops`, `read_latency_us_p50/p95/p99`, `write_latency_us_p50/p95/p99`,
/// `window_secs`. Clients compute `read_ops / window_secs` for ops/s — the
/// rate is a `window_secs`-wide average, not an instantaneous value, since
/// `read_ops`/`write_ops` only count fully ticked seconds (the running
/// second is excluded). A disabled engine still gets its block, all zero —
/// `0` for a latency percentile means no op landed in the window, not an
/// unmeasurably fast one.
//
// The `system` block is KV-only: `compaction_runs`, `janitor_runs` and
// `memtable_size_bytes` come from the KV engine's LSM instance — json/rel
// run their own instances, not reflected here (spec general/024). Plain
// `//` on purpose: a `///` line would enter the OpenAPI description and
// change the pinned contract file.
#[utoipa::path(
    get,
    path = "/store-api/metrics",
    responses(
        (status = 200, description = "Metrics snapshot"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden — Admin only"),
    ),
    security(("bearer_auth" = [])),
    tag = "Metrics"
)]
pub async fn get_metrics(State(state): State<AppState>) -> Json<Value> {
    let sys = &state.metrics.system;
    let engine = state.registry.engine();
    let system = json!({
        "total_reads":       sys.total_reads.load(Ordering::Relaxed),
        "total_writes":      sys.total_writes.load(Ordering::Relaxed),
        "compaction_runs":   engine.compaction_runs(),
        "janitor_runs":      engine.janitor_runs(),
        "memtable_size_bytes": engine.stats().memtable_size as u64,
    });
    let domains = state.metrics.get_all_domain_metrics();
    let [kv_metrics, json_metrics, rel_metrics] = state.metrics.engine_metrics();
    let engines = json!({ "kv": kv_metrics, "json": json_metrics, "rel": rel_metrics });

    let bc = state.registry.engine().block_cache_metrics();
    let block_cache = json!({
        "hits":             bc.hits.load(Ordering::Relaxed),
        "misses":           bc.misses.load(Ordering::Relaxed),
        "small_hits":       bc.small_hits.load(Ordering::Relaxed),
        "main_hits":        bc.main_hits.load(Ordering::Relaxed),
        "small_evictions":  bc.small_evictions.load(Ordering::Relaxed),
        "main_evictions":   bc.main_evictions.load(Ordering::Relaxed),
        "current_bytes":    bc.current_bytes.load(Ordering::Relaxed),
    });

    // Backup block (spec general/006 metrics section) — null when backup.enabled = false.
    let backup = state.backup_manager.as_ref().map(|m| {
        let snap = m.metrics_snapshot();
        let running = m
            .running_job()
            .filter(|j| j.kind == crate::backup::JobKind::Backup)
            .map(|j| json!({ "id": j.id, "scope": j.scope, "started_at": j.started_at }));
        json!({
            "last_success_at": snap.last_success_at,
            "last_success_at_by_schedule": snap.last_success_at_by_schedule,
            "last_duration_ms": snap.last_duration_ms,
            "last_size_bytes": snap.last_size_bytes,
            "running": running,
            "failed_total": snap.failed_total,
        })
    });

    Json(json!({
        "system": system,
        "domains": domains,
        "engines": engines,
        "block_cache": block_cache,
        "backup": backup
    }))
}

/// `GET /metrics/domains/{name}` — metrics for one domain. Admin or domain user.
#[utoipa::path(
    get,
    path = "/store-api/metrics/domains/{name}",
    params(("name" = String, Path, description = "Domain name")),
    responses(
        (status = 200, description = "Domain metrics snapshot"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Domain not found or no metrics yet"),
    ),
    security(("bearer_auth" = [])),
    tag = "Metrics"
)]
pub async fn get_domain_metrics(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    match state.metrics.get_domain_metrics(&name) {
        Some(m) => Ok(Json(serde_json::to_value(m).unwrap_or_else(|_| json!({})))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::wal::WriteAheadLog;
    use crate::engines::lsm::domain::{DomainConfig, DomainRegistry};
    use crate::engines::lsm::engine::LsmStorageEngine;
    use crate::storage::{file_manager::FileManager, manifest::ManifestManager, vlog::VLog};
    use std::sync::Arc;

    // Spec 004 §Output item 4: handler reports the two constants verbatim.
    #[tokio::test]
    async fn version_handler_reports_constants() {
        let Json(resp) = version().await;
        assert_eq!(resp.server_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(resp.api_version, crate::api::API_VERSION);
    }

    // ── Spec general/019: per-engine metrics, HTTP level ─────────────────────

    // Minimal KV-only AppState (json_engine/rel_engine disabled) -- enough to
    // exercise get_metrics's engines block, which is always present
    // regardless of which engines are actually wired up.
    async fn make_state() -> (AppState, tempfile::TempDir) {
        make_state_with_config(crate::config::LuraConfig::default(), "test.toml".to_string(), false).await
    }

    // Parameterized variant for the config-endpoint tests below (spec
    // general/022), which need to control the config/path/loaded-flag triple.
    async fn make_state_with_config(
        config: crate::config::LuraConfig,
        config_path: String,
        config_file_loaded: bool,
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
        let registry = Arc::new(
            DomainRegistry::recover(engine, DomainConfig::default(), Arc::clone(&metrics))
                .await
                .unwrap(),
        );
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
            event_bus: Arc::new(crate::core::events::GlobalEventBus::new(256, 1024)),
            config: Arc::new(config),
            config_path,
            config_file_loaded,
        };
        (state, dir)
    }

    // Test 9: engines.kv/.json/.rel are present with all nine fields;
    // domains[] keeps exactly its eight known fields, unchanged.
    #[tokio::test]
    async fn test_engines_block_present_with_all_fields_domains_unchanged() {
        let (state, _dir) = make_state().await;
        state.registry.create_domain("shop").await.unwrap();
        state.registry.store("shop").await.unwrap().put(b"k", b"v").await.unwrap();
        state.registry.store("shop").await.unwrap().get(b"k").await.unwrap();
        state.metrics.tick_all();

        let Json(body) = get_metrics(State(state)).await;
        for engine in ["kv", "json", "rel"] {
            let block = &body["engines"][engine];
            for field in [
                "read_ops", "write_ops",
                "read_latency_us_p50", "read_latency_us_p95", "read_latency_us_p99",
                "write_latency_us_p50", "write_latency_us_p95", "write_latency_us_p99",
                "window_secs",
            ] {
                assert!(block.get(field).is_some(), "engines.{engine}.{field} missing");
            }
        }

        let domain = body["domains"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["domain"] == "shop")
            .expect("shop must appear in domains[]");
        let mut fields: Vec<&str> = domain.as_object().unwrap().keys().map(|s| s.as_str()).collect();
        fields.sort();
        let mut expected = vec![
            "domain", "read_ops", "write_ops", "read_latency_us_p50", "read_latency_us_p99",
            "cache_hit_rate", "rate_limit_rejections", "window_secs",
        ];
        expected.sort();
        assert_eq!(fields, expected, "domains[] must keep exactly its eight known fields");
    }

    // Test 10: a disabled JSON engine (json_engine: None in AppState) still
    // yields a complete, all-zero engines.json block.
    #[tokio::test]
    async fn test_disabled_json_engine_yields_zeroed_block() {
        let (state, _dir) = make_state().await;
        assert!(state.json_engine.is_none());

        let Json(body) = get_metrics(State(state)).await;
        let json_block = &body["engines"]["json"];
        assert_eq!(json_block["read_ops"], 0);
        assert_eq!(json_block["write_ops"], 0);
        assert_eq!(json_block["read_latency_us_p50"], 0);
        assert_eq!(json_block["write_latency_us_p50"], 0);
    }

    // Test 11: deleting a domain removes it from domains[], but
    // engines.kv.read_ops (the engine aggregate) stays put.
    #[tokio::test]
    async fn test_domain_delete_keeps_engine_aggregate() {
        let (state, _dir) = make_state().await;
        state.registry.create_domain("gone").await.unwrap();
        state.registry.store("gone").await.unwrap().put(b"k", b"v").await.unwrap();
        state.registry.store("gone").await.unwrap().get(b"k").await.unwrap();
        state.metrics.tick_all();
        let before = state.metrics.engine_metrics()[0].read_ops;
        assert!(before > 0);

        state.registry.delete_domain("gone").await.unwrap();
        // delete_domain only marks the domain Deleting -- the domain purger
        // removes its metrics window on finalize (kv/013). Call it directly
        // rather than spinning up a full purger cycle in this HTTP-level test.
        state.metrics.remove_domain("gone");

        let Json(body) = get_metrics(State(state)).await;
        assert!(
            body["domains"].as_array().unwrap().iter().all(|d| d["domain"] != "gone"),
            "deleted domain must be gone from domains[]"
        );
        assert_eq!(
            body["engines"]["kv"]["read_ops"].as_u64().unwrap(),
            before,
            "engine aggregate must survive domain deletion"
        );
    }

    // ── Spec general/024: compaction_runs/janitor_runs/memtable_size_bytes ───

    // Test 3: memtable_size_bytes is a live gauge read from the engine's
    // active MemTable, not a maintained counter -- grows after a write, and
    // shrinks back once flush_all_memtables drains it (approximate, so no
    // exact post-flush value is asserted).
    #[tokio::test]
    async fn test_memtable_size_bytes_reflects_live_memtable() {
        let (state, _dir) = make_state().await;
        state.registry.create_domain("shop").await.unwrap();
        state.registry.store("shop").await.unwrap().put(b"k", b"v").await.unwrap();

        let Json(body) = get_metrics(State(state.clone())).await;
        let before = body["system"]["memtable_size_bytes"].as_u64().unwrap();
        assert!(before > 0, "memtable_size_bytes must be > 0 after a PUT");

        state.registry.engine().flush_all_memtables().await.unwrap();

        let Json(body) = get_metrics(State(state)).await;
        let after = body["system"]["memtable_size_bytes"].as_u64().unwrap();
        assert!(after < before, "memtable_size_bytes must shrink after a full flush");
    }

    // Test 4 (regression): the system block keeps exactly its five known
    // fields, all numeric -- rewiring three of them to the engine must not
    // drop or rename a field.
    #[tokio::test]
    async fn test_system_block_keeps_exactly_five_numeric_fields() {
        let (state, _dir) = make_state().await;
        let Json(body) = get_metrics(State(state)).await;
        let system = body["system"].as_object().unwrap();

        let mut fields: Vec<&str> = system.keys().map(|s| s.as_str()).collect();
        fields.sort();
        let mut expected =
            vec!["total_reads", "total_writes", "compaction_runs", "janitor_runs", "memtable_size_bytes"];
        expected.sort();
        assert_eq!(fields, expected, "system block must keep exactly its five known fields");

        for field in expected {
            assert!(system[field].is_number(), "system.{field} must be numeric");
        }
    }

    // ── GET /store-api/config (spec general/022) ─────────────────────────────

    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::util::ServiceExt;

    async fn body_string(resp: axum::http::Response<Body>) -> String {
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    async fn config_response(state: AppState) -> axum::http::Response<Body> {
        let app = crate::api::create_router(state, Arc::new(vec![]));
        app.oneshot(Request::builder().uri("/store-api/config").body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    // Tests 1+2: the admin api_key is redacted by construction
    // (`#[serde(skip_serializing)]` on `AdminEntry::api_key`), verified as a
    // plain string search over the whole wire body -- stays valid even if the
    // key moves to a nested location later. Redaction is field-exact: the
    // admin name next to it must survive.
    #[tokio::test]
    async fn config_endpoint_redacts_admin_api_key_but_keeps_name() {
        let mut config = crate::config::LuraConfig::default();
        config.auth.admins = vec![crate::config::AdminEntry {
            name: "root".to_string(),
            api_key: "MARKER_SECRET".to_string(),
        }];
        let (state, _dir) = make_state_with_config(config, "test.toml".to_string(), false).await;
        let resp = config_response(state).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(!body.contains("MARKER_SECRET"), "admin api_key leaked into the response body");
        assert!(body.contains("root"), "admin name must stay visible");
    }

    // Test 3 (admin-only enforcement) lives in auth/middleware.rs, next to
    // the other auth-layer HTTP tests -- see config_endpoint_is_admin_only.

    // Test 4: LuraConfig::default() with config_file_loaded: false -> 200,
    // flag false, config_path still set, config fully populated.
    #[tokio::test]
    async fn config_endpoint_defaults_operation() {
        let (state, _dir) = make_state_with_config(
            crate::config::LuraConfig::default(),
            "/etc/luradb/luradb.toml".to_string(),
            false,
        )
        .await;
        let resp = config_response(state).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["config_file_loaded"], false);
        assert_eq!(body["config_path"], "/etc/luradb/luradb.toml");
        assert!(body["config"]["server"].is_object());
        assert!(body["config"]["storage"].is_object());
    }

    // Test 5: config_path passes through unchanged; config_file_loaded: true
    // distinguishes the "file was loaded" case from test 4's defaults case.
    #[tokio::test]
    async fn config_endpoint_path_passthrough_when_loaded() {
        let (state, _dir) = make_state_with_config(
            crate::config::LuraConfig::default(),
            "/etc/luradb/luradb.toml".to_string(),
            true,
        )
        .await;
        let resp = config_response(state).await;
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["config_path"], "/etc/luradb/luradb.toml");
        assert_eq!(body["config_file_loaded"], true);
    }

    // Test 6: the `config` key-set matches LuraConfig's field names exactly --
    // no fixed count/list here on purpose, so this stays valid as sections
    // are added (the endpoint's own promise: "effective configuration").
    #[tokio::test]
    async fn config_endpoint_config_keys_match_luraconfig_fields() {
        let (state, _dir) =
            make_state_with_config(crate::config::LuraConfig::default(), "test.toml".to_string(), false).await;
        let resp = config_response(state).await;
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();

        let mut got: Vec<String> = body["config"].as_object().unwrap().keys().cloned().collect();
        got.sort();
        let expected_value = serde_json::to_value(crate::config::LuraConfig::default()).unwrap();
        let mut expected: Vec<String> = expected_value.as_object().unwrap().keys().cloned().collect();
        expected.sort();
        assert_eq!(got, expected);
    }

    // Test 7: a TOML-loaded config with a non-default value (server.port)
    // comes back with that exact value -- proof the *loaded* instance is
    // serialized, not a fresh default one.
    #[tokio::test]
    async fn config_endpoint_reflects_loaded_values_not_defaults() {
        let toml_str = r#"
            [server]
            port = 4242
        "#;
        let config: crate::config::LuraConfig = toml::from_str(toml_str).unwrap();
        assert_ne!(config.server.port, crate::config::ServerConfig::default().port);
        let (state, _dir) = make_state_with_config(config, "test.toml".to_string(), true).await;
        let resp = config_response(state).await;
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["config"]["server"]["port"], 4242);
    }
}
