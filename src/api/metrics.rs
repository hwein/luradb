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

/// `GET /metrics` — system + all domain metrics. Admin only.
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
    let system = json!({
        "total_reads":       sys.total_reads.load(Ordering::Relaxed),
        "total_writes":      sys.total_writes.load(Ordering::Relaxed),
        "compaction_runs":   sys.compaction_runs.load(Ordering::Relaxed),
        "janitor_runs":      sys.janitor_runs.load(Ordering::Relaxed),
        "memtable_size_bytes": sys.memtable_size_bytes.load(Ordering::Relaxed),
    });
    let domains = state.metrics.get_all_domain_metrics();

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

    Json(json!({ "system": system, "domains": domains, "block_cache": block_cache, "backup": backup }))
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

    // Spec 004 §Output item 4: handler reports the two constants verbatim.
    #[tokio::test]
    async fn version_handler_reports_constants() {
        let Json(resp) = version().await;
        assert_eq!(resp.server_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(resp.api_version, crate::api::API_VERSION);
    }
}
