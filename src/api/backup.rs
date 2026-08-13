//! Backup & Restore REST handlers (spec general/006).
//!
//! Admin-only: `/store-api/backups*` and `/store-api/restores*` carry no
//! domain segment, so `extract_domain` (`src/auth/middleware.rs`) falls
//! through to `None` -- non-admins get 403 automatically; nothing here
//! needs to enforce it (the router-coverage test below only anchors the
//! behavior for these new routes).
//!
//! Errors follow the project-wide plaintext `ApiError` convention
//! (`src/api/middleware.rs`; general/005 decisions 1+2: plaintext
//! `"NNN Reason: Detail"` bodies, 503 when the feature is disabled). The
//! `{"error":"…"}` / 404-disabled examples in general/006 cite that spec's
//! superseded draft state and no longer apply.

use crate::api::{middleware::ApiError, AppState};
use crate::backup::{
    restore, writer, BackupError, BackupManager, BackupScope, BackupState, JobKind, RestoreState, RestoreStatus,
    RunningJobInfo,
};
use axum::{
    body::Body,
    extract::{Path, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Json, Response},
};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tower::ServiceExt;
use tower_http::services::ServeFile;
use utoipa::ToSchema;

// ── Error mapping ────────────────────────────────────────────────────────────

/// Maps every `BackupError` variant to its spec general/006 HTTP status and
/// a plaintext `ApiError` body (project-wide convention, general/005
/// decisions 1+2). Matched by variant, not by parsing `Display`, so
/// wire text stays independent of `BackupError`'s internal `Display`.
impl From<BackupError> for ApiError {
    fn from(e: BackupError) -> Self {
        match e {
            BackupError::Busy => {
                ApiError::new(StatusCode::CONFLICT, "409 Conflict: a backup or restore job is already running")
            }
            BackupError::NotFound => ApiError::new(StatusCode::NOT_FOUND, "404 Not Found: backup not found"),
            BackupError::RestoreNotFound => {
                ApiError::new(StatusCode::NOT_FOUND, "404 Not Found: restore not found")
            }
            BackupError::DomainNotFound(domain) => {
                ApiError::new(StatusCode::NOT_FOUND, format!("404 Not Found: domain '{domain}' not found"))
            }
            BackupError::BackupRunning => ApiError::new(
                StatusCode::CONFLICT,
                "409 Conflict: the backup job for this id is still running",
            ),
            BackupError::InvalidBackupFile(reason) => ApiError::new(
                StatusCode::BAD_REQUEST,
                format!("400 Bad Request: invalid backup file: {reason}"),
            ),
            BackupError::RemapRequiresSingleDomain => ApiError::new(
                StatusCode::BAD_REQUEST,
                "400 Bad Request: into_domain requires a backup with exactly one domain",
            ),
            BackupError::DomainExists(domain) => {
                ApiError::new(StatusCode::CONFLICT, format!("409 Conflict: domain '{domain}' already exists"))
            }
            BackupError::UnsupportedFormatVersion(v) => ApiError::new(
                StatusCode::BAD_REQUEST,
                format!("400 Bad Request: unsupported backup format version {v}"),
            ),
            // Mirrors json.rs's convention for the same underlying condition
            // (json.enabled = false) on regular JSON endpoints.
            BackupError::JsonEngineDisabled => ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "503 Service Unavailable: scope requires the JSON engine, which is disabled (json.enabled = false)",
            ),
            BackupError::InvalidId(id) => {
                ApiError::new(StatusCode::BAD_REQUEST, format!("400 Bad Request: invalid backup id '{id}'"))
            }
            BackupError::Other(inner) => {
                tracing::error!("[Backup API] internal error: {inner:#}");
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "500 Internal Server Error: internal error")
            }
        }
    }
}

/// Resolves the backup manager or fails with 503 (spec general/005
/// decision 1: "feature disabled" answers 503 project-wide, same as
/// the JSON/rel engine guards -- routes are always registered).
fn backup_manager(state: &AppState) -> Result<&Arc<BackupManager>, ApiError> {
    state.backup_manager.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "503 Service Unavailable: backup is disabled (backup.enabled = false)",
        )
    })
}

// ── Audit logging (spec general/006 "exfiltration awareness") ──────────────

/// Best-effort caller identity for the audit log. Independently resolves the
/// same Bearer key the auth middleware already validated this request
/// against: the middleware only forwards a coarse `AuthOutcome` (Full /
/// Scoped) into request extensions, never the resolved `UserRecord`
/// (`src/auth/middleware.rs`), so there is nothing to read from there.
/// Trusted UDS peers and auth-disabled deployments have no bearer key at
/// all, so those log without a name.
async fn admin_name(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let hash = crate::auth::middleware::extract_bearer(headers)?;
    state.auth_cache.get_user_by_key_hash(&hash).await.map(|u| u.name)
}

fn log_audit(admin: &Option<String>, action: &str, backup_id: &str) {
    match admin {
        Some(name) => tracing::info!(admin = %name, backup_id = %backup_id, "{action}"),
        None => tracing::info!(backup_id = %backup_id, "{action}"),
    }
}

// ── DTOs ─────────────────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct CreateBackupRequest {
    /// `all` | `kv` | `json` | `kv:<domain>` | `json:<domain>` | `domain:<name>`.
    /// Covers the KV and JSON engines only — relational data is never included.
    pub scope: String,
    /// Only effective for `all`/`kv` scopes (auth records live in the KV instance).
    #[serde(default)]
    pub include_auth: bool,
}

#[derive(Serialize, ToSchema)]
pub struct BackupAcceptedResponse {
    pub id: String,
    pub state: String,
}

#[derive(Serialize, ToSchema)]
pub struct BackupSummaryResponse {
    pub id: String,
    pub state: String,
    pub scope: String,
    pub created_at: u64,
    pub size_bytes: u64,
    pub schedule: Option<String>,
    pub format_version: u32,
}

impl From<crate::backup::BackupSummary> for BackupSummaryResponse {
    fn from(s: crate::backup::BackupSummary) -> Self {
        Self {
            id: s.id,
            state: backup_state_str(s.state).to_string(),
            scope: s.scope,
            created_at: s.created_at,
            size_bytes: s.size_bytes,
            schedule: s.schedule,
            format_version: s.format_version,
        }
    }
}

#[derive(Serialize, ToSchema)]
pub struct RunningBackupInfo {
    pub id: String,
    pub scope: String,
    pub started_at: u64,
}

impl From<RunningJobInfo> for RunningBackupInfo {
    fn from(j: RunningJobInfo) -> Self {
        Self { id: j.id, scope: j.scope, started_at: j.started_at }
    }
}

#[derive(Serialize, ToSchema)]
pub struct BackupListResponse {
    pub backups: Vec<BackupSummaryResponse>,
    pub running: Option<RunningBackupInfo>,
}

/// Manifest fields + state + size (spec general/006 GET /backups/{id} and
/// POST /backups/upload). Everything but `id`/`state`/`scope` is optional:
/// the currently-running-job shape (`running`) only fills `started_at`; the
/// complete/incomplete shape fills the rest instead.
#[derive(Serialize, ToSchema)]
pub struct BackupDetailResponse {
    pub id: String,
    pub state: String,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format_version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub luradb_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_auth: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kv_snapshot_ts: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json_snapshot_ts: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<u64>,
}

impl BackupDetailResponse {
    fn running(job: &RunningJobInfo) -> Self {
        Self {
            id: job.id.clone(),
            state: "running".to_string(),
            scope: job.scope.clone(),
            created_at: None,
            size_bytes: None,
            schedule: None,
            format_version: None,
            luradb_version: None,
            include_auth: None,
            kv_snapshot_ts: None,
            json_snapshot_ts: None,
            encoding: None,
            started_at: Some(job.started_at),
        }
    }

    fn from_manifest(id: String, state: BackupState, size_bytes: u64, manifest: writer::ManifestLine) -> Self {
        Self {
            id,
            state: backup_state_str(state).to_string(),
            scope: manifest.scope,
            created_at: Some(manifest.created_at),
            size_bytes: Some(size_bytes),
            schedule: manifest.schedule,
            format_version: Some(manifest.format_version),
            luradb_version: Some(manifest.luradb_version),
            include_auth: Some(manifest.include_auth),
            kv_snapshot_ts: Some(manifest.kv_snapshot_ts),
            json_snapshot_ts: Some(manifest.json_snapshot_ts),
            encoding: Some(manifest.encoding),
            started_at: None,
        }
    }
}

fn backup_state_str(s: BackupState) -> &'static str {
    match s {
        BackupState::Complete => "complete",
        BackupState::Incomplete => "incomplete",
    }
}

#[derive(Deserialize, ToSchema)]
pub struct RestoreRequest {
    /// `"fail_if_exists"` (default) or `"replace"`.
    #[serde(default)]
    pub mode: Option<String>,
    /// Only legal when the archive contains exactly one domain name
    /// (`kv:*`/`json:*`/`domain:*` scopes).
    pub into_domain: Option<String>,
    /// Apply auth-user/auth-perm lines from the archive (upsert). Default false.
    #[serde(default)]
    pub include_auth: bool,
}

#[derive(Serialize, ToSchema)]
pub struct RestoreAcceptedResponse {
    pub restore_id: String,
    pub state: String,
}

#[derive(Serialize, ToSchema)]
pub struct RestoreErrorEntry {
    pub key: String,
    pub error: String,
}

#[derive(Serialize, ToSchema)]
pub struct RestoreStatusResponse {
    pub restore_id: String,
    pub backup_id: String,
    pub state: String,
    pub imported: u64,
    pub skipped: u64,
    pub failed: u64,
    pub errors: Vec<RestoreErrorEntry>,
    pub started_at: u64,
    pub finished_at: Option<u64>,
}

impl From<RestoreStatus> for RestoreStatusResponse {
    fn from(s: RestoreStatus) -> Self {
        Self {
            restore_id: s.restore_id,
            backup_id: s.backup_id,
            state: match s.state {
                RestoreState::Running => "running",
                RestoreState::Complete => "complete",
                RestoreState::Failed => "failed",
            }
            .to_string(),
            imported: s.imported,
            skipped: s.skipped,
            failed: s.failed,
            errors: s.errors.into_iter().map(|(key, error)| RestoreErrorEntry { key, error }).collect(),
            started_at: s.started_at,
            finished_at: s.finished_at,
        }
    }
}

fn parse_restore_mode(s: &str) -> Result<restore::RestoreMode, ApiError> {
    match s {
        "fail_if_exists" => Ok(restore::RestoreMode::FailIfExists),
        "replace" => Ok(restore::RestoreMode::Replace),
        _ => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("400 Bad Request: invalid restore mode '{s}' (fail_if_exists|replace)"),
        )),
    }
}

// ── Handlers ─────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/store-api/backups",
    request_body = CreateBackupRequest,
    responses(
        (status = 202, description = "Backup job started", body = BackupAcceptedResponse),
        (status = 400, description = "Invalid scope"),
        (status = 404, description = "Scope targets a missing domain"),
        (status = 409, description = "A backup or restore job is already running"),
        (status = 503, description = "Backup is disabled, or scope requires the JSON engine, which is disabled"),
    ),
    tag = "Backup"
)]
/// Starts an on-demand backup job (spec general/006 scope syntax for `scope`).
pub async fn create_backup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateBackupRequest>,
) -> Result<(StatusCode, Json<BackupAcceptedResponse>), ApiError> {
    let manager = backup_manager(&state)?;
    let scope = BackupScope::parse(&body.scope).map_err(|_| {
        ApiError::new(StatusCode::BAD_REQUEST, format!("400 Bad Request: invalid scope '{}'", body.scope))
    })?;
    let (id, _handle) = manager.start_backup(scope, body.include_auth, None).await?;
    log_audit(&admin_name(&state, &headers).await, "backup created", &id);
    Ok((StatusCode::ACCEPTED, Json(BackupAcceptedResponse { id, state: "running".to_string() })))
}

#[utoipa::path(
    get,
    path = "/store-api/backups",
    responses(
        (status = 200, description = "Backup list", body = BackupListResponse),
        (status = 503, description = "Backup is disabled"),
    ),
    tag = "Backup"
)]
/// Lists every backup archive in `backup.dir`, plus the currently running
/// backup job (if any) separately in `running`.
pub async fn list_backups(State(state): State<AppState>) -> Result<Json<BackupListResponse>, ApiError> {
    let manager = backup_manager(&state)?;
    let backups = manager.list_backups()?.into_iter().map(Into::into).collect();
    let running = manager.running_job().filter(|j| j.kind == JobKind::Backup).map(Into::into);
    Ok(Json(BackupListResponse { backups, running }))
}

#[utoipa::path(
    get,
    path = "/store-api/backups/{id}",
    params(("id" = String, Path, description = "Backup id")),
    responses(
        (status = 200, description = "Backup details", body = BackupDetailResponse),
        (status = 400, description = "Invalid backup id"),
        (status = 404, description = "Backup not found"),
        (status = 503, description = "Backup is disabled"),
    ),
    tag = "Backup"
)]
/// Manifest fields + state + size for one backup. A backup whose job is
/// still running (no `.ndjson` file yet, only `.part`) reports `state:
/// "running"` from the in-RAM job slot instead of 404.
pub async fn get_backup(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<BackupDetailResponse>, ApiError> {
    let manager = backup_manager(&state)?;
    if let Some(job) = manager.running_job().filter(|j| j.kind == JobKind::Backup && j.id == id) {
        return Ok(Json(BackupDetailResponse::running(&job)));
    }
    let (manifest, state, size_bytes) = manager.get_backup_manifest(&id)?;
    Ok(Json(BackupDetailResponse::from_manifest(id, state, size_bytes, manifest)))
}

#[utoipa::path(
    get,
    path = "/store-api/backups/{id}/download",
    params(("id" = String, Path, description = "Backup id")),
    responses(
        (status = 200, description = "Full NDJSON archive", content_type = "application/x-ndjson"),
        (status = 206, description = "Partial content (Range request)", content_type = "application/x-ndjson"),
        (status = 400, description = "Invalid backup id"),
        (status = 404, description = "Backup not found"),
        (status = 409, description = "The backup job for this id is still running"),
        (status = 503, description = "Backup is disabled"),
    ),
    tag = "Backup"
)]
/// Streams the archive (`ServeFile`/tower-http `fs`) with HTTP Range support
/// for resumable downloads (spec general/006).
pub async fn download_backup(
    State(state): State<AppState>,
    Path(id): Path<String>,
    request: Request,
) -> Result<Response, ApiError> {
    let manager = backup_manager(&state)?;
    crate::backup::validate_backup_id(&id)?;
    if manager.running_job().is_some_and(|j| j.id == id) {
        return Err(BackupError::BackupRunning.into());
    }
    let path = manager.ndjson_path(&id);
    if !path.exists() {
        return Err(BackupError::NotFound.into());
    }

    let admin = admin_name(&state, request.headers()).await;
    let response = ServeFile::new(&path).oneshot(request).await.unwrap();
    let mut response = response.map(Body::new);
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/x-ndjson"));
    log_audit(&admin, "backup downloaded", &id);
    Ok(response)
}

#[utoipa::path(
    delete,
    path = "/store-api/backups/{id}",
    params(("id" = String, Path, description = "Backup id")),
    responses(
        (status = 204, description = "Backup deleted"),
        (status = 400, description = "Invalid backup id"),
        (status = 404, description = "Backup not found"),
        (status = 409, description = "The backup job for this id is still running"),
        (status = 503, description = "Backup is disabled"),
    ),
    tag = "Backup"
)]
/// Deletes a backup archive file. Refuses while the id is the currently
/// running job (or a stale `.part` leftover still exists for it).
pub async fn delete_backup(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let manager = backup_manager(&state)?;
    manager.delete_backup(&id)?;
    log_audit(&admin_name(&state, &headers).await, "backup deleted", &id);
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/store-api/backups/upload",
    request_body(content = String, description = "NDJSON backup archive, raw bytes streamed to disk (no multipart)"),
    responses(
        (status = 201, description = "Archive accepted", body = BackupDetailResponse),
        (status = 400, description = "Invalid backup file — checksum/manifest verification failed"),
        (status = 503, description = "Backup is disabled"),
    ),
    tag = "Backup"
)]
/// Streams the request body to `backup.dir`, verifies its checksum and
/// manifest, then assigns it a fresh server-side id (`bk_..._upload[_N]`) —
/// the id in the manifest is never adopted. Invalid archives are discarded.
pub async fn upload_backup(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> Result<(StatusCode, Json<BackupDetailResponse>), ApiError> {
    let manager = backup_manager(&state)?;
    let mut scratch = ScratchGuard { path: manager.upload_scratch_path(), keep: false };

    stream_body_to_file(&scratch.path, body).await?;

    let manifest = match restore::verify_and_scan(&scratch.path).await {
        Ok(scan) => scan.manifest,
        // Typed failures (unsupported version, malformed line, checksum
        // mismatch) keep their own status and message; anything untyped is
        // a client-side parse problem.
        Err(e) => {
            return Err(match e.downcast::<BackupError>() {
                Ok(typed) => typed.into(),
                Err(_) => ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "400 Bad Request: invalid backup file: checksum or manifest verification failed",
                ),
            });
        }
    };

    let id = manager.finalize_upload(&scratch.path)?;
    scratch.keep = true;

    log_audit(&admin_name(&state, &headers).await, "backup uploaded", &id);
    let (_, backup_state, size_bytes) = manager.get_backup_manifest(&id)?;
    Ok((StatusCode::CREATED, Json(BackupDetailResponse::from_manifest(id, backup_state, size_bytes, manifest))))
}

/// Deletes the upload scratch file on every exit path, including the handler
/// future being dropped mid-stream (client disconnect) — no error arm sees
/// that one. Defused once `finalize_upload` renamed the file away. `Drop`
/// cannot await, hence the blocking remove.
struct ScratchGuard {
    path: std::path::PathBuf,
    keep: bool,
}

impl Drop for ScratchGuard {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Writes the request body to `path` as it arrives — no full-body buffering
/// (spec general/006: no RAM copy).
async fn stream_body_to_file(path: &std::path::Path, body: Body) -> Result<(), ApiError> {
    let mut file = tokio::fs::File::create(path).await.map_err(|e| BackupError::Other(e.into()))?;
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| {
            ApiError::new(StatusCode::BAD_REQUEST, "400 Bad Request: invalid backup file: error reading upload body")
        })?;
        file.write_all(&chunk).await.map_err(|e| BackupError::Other(e.into()))?;
    }
    file.flush().await.map_err(|e| BackupError::Other(e.into()))?;
    file.sync_all().await.map_err(|e| BackupError::Other(e.into()))?;
    Ok(())
}

#[utoipa::path(
    post,
    path = "/store-api/backups/{id}/restore",
    params(("id" = String, Path, description = "Backup id to restore from")),
    request_body = RestoreRequest,
    responses(
        (status = 202, description = "Restore job started", body = RestoreAcceptedResponse),
        (status = 400, description = "Invalid id/mode, remap requires a single domain, unsupported format version, or invalid backup file"),
        (status = 404, description = "Backup not found, or scope targets a missing domain"),
        (status = 409, description = "A backup or restore job is already running"),
        (status = 503, description = "Backup is disabled"),
    ),
    tag = "Backup"
)]
/// Starts a restore job from an existing backup archive. The single-domain
/// remap and format-version checks happen synchronously here; a domain
/// already existing (`fail_if_exists`) only surfaces asynchronously via
/// `GET /restores/{id}`.
pub async fn restore_backup(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<RestoreRequest>,
) -> Result<(StatusCode, Json<RestoreAcceptedResponse>), ApiError> {
    let manager = backup_manager(&state)?;
    let mode = parse_restore_mode(body.mode.as_deref().unwrap_or("fail_if_exists"))?;

    // Synchronous pre-checks (orchestrator hint 1 / spec general/006):
    // start_restore itself only validates id/existence/slot synchronously.
    let summary = manager.get_backup(&id)?;
    if summary.format_version != writer::FORMAT_VERSION {
        return Err(BackupError::UnsupportedFormatVersion(summary.format_version).into());
    }
    if summary.state == BackupState::Incomplete {
        return Err(BackupError::InvalidBackupFile(
            "backup archive is incomplete (missing checksum line)".to_string(),
        )
        .into());
    }
    if body.into_domain.is_some() {
        let single_domain =
            summary.scope.starts_with("kv:") || summary.scope.starts_with("json:") || summary.scope.starts_with("domain:");
        if !single_domain {
            return Err(BackupError::RemapRequiresSingleDomain.into());
        }
    }

    let (restore_id, handle) = manager.start_restore(&id, mode, body.into_domain, body.include_auth).await?;

    // Post-completion hook (orchestrator hint 2): a successful include_auth
    // restore must refresh the in-RAM AuthCache, or restored users stay
    // invisible until a process restart.
    if body.include_auth {
        let auth_cache = Arc::clone(&state.auth_cache);
        let manager_for_reload = Arc::clone(manager);
        let reload_restore_id = restore_id.clone();
        tokio::spawn(async move {
            let _ = handle.await;
            let completed = manager_for_reload
                .get_restore_status(&reload_restore_id)
                .map(|s| s.state == RestoreState::Complete)
                .unwrap_or(false);
            if completed {
                if let Err(e) = auth_cache.load_from_engine().await {
                    tracing::warn!(
                        "[Backup API] auth cache reload after restore '{reload_restore_id}' failed: {e:#}"
                    );
                }
            }
        });
    }

    log_audit(&admin_name(&state, &headers).await, "backup restore started", &id);
    Ok((StatusCode::ACCEPTED, Json(RestoreAcceptedResponse { restore_id, state: "running".to_string() })))
}

#[utoipa::path(
    get,
    path = "/store-api/restores/{id}",
    params(("id" = String, Path, description = "Restore id")),
    responses(
        (status = 200, description = "Restore status", body = RestoreStatusResponse),
        (status = 404, description = "Restore not found"),
        (status = 503, description = "Backup is disabled"),
    ),
    tag = "Backup"
)]
/// Live status of a restore job. Lives in RAM only (spec general/006) — gone
/// after a restart; the outcome is also in the log.
pub async fn get_restore_status(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<RestoreStatusResponse>, ApiError> {
    let manager = backup_manager(&state)?;
    let status = manager
        .get_restore_status(&id)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "404 Not Found: restore not found"))?;
    Ok(Json(status.into()))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BackupConfig;
    use crate::engines::lsm::domain::now_secs;
    use axum::body::to_bytes;
    use axum::http::Method;
    use axum::Router;
    use serde_json::json;

    fn enabled_backup_config() -> BackupConfig {
        BackupConfig { enabled: true, dir: "unused".to_string(), scan_batch_size: 500, scan_pause_ms: 0, schedule: Vec::new() }
    }

    fn slow_backup_config() -> BackupConfig {
        BackupConfig { enabled: true, dir: "unused".to_string(), scan_batch_size: 1, scan_pause_ms: 300, schedule: Vec::new() }
    }

    /// `backup_config = None` -> `backup_manager: None`; `Some(cfg)` -> enabled,
    /// with `cfg.dir` always redirected into this call's own temp dir.
    async fn make_state(backup_config: Option<BackupConfig>, auth_enabled: bool) -> (AppState, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let kv_dir = dir.path().join("kv");
        std::fs::create_dir_all(&kv_dir).unwrap();
        let wal_path = kv_dir.join("wal.log");
        let wal = Arc::new(crate::core::wal::WriteAheadLog::new(&wal_path).await.unwrap());
        let vlog_path = kv_dir.join("vlog.log");
        let vlog = Arc::new(crate::storage::vlog::VLog::new(&vlog_path).await.unwrap());
        let fm = Arc::new(crate::storage::file_manager::FileManager::new(&kv_dir).await.unwrap());
        let mm = Arc::new(crate::storage::manifest::ManifestManager::new(&kv_dir));
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
                Arc::clone(&engine),
                crate::engines::lsm::domain::DomainConfig::default(),
                Arc::clone(&metrics),
            )
            .await
            .unwrap(),
        );

        let backup_manager = match backup_config {
            None => None,
            Some(cfg) => {
                let cfg = BackupConfig { dir: dir.path().join("backups").to_string_lossy().into_owned(), ..cfg };
                Some(BackupManager::new(&cfg, Arc::clone(&registry), None).unwrap())
            }
        };

        let state = AppState {
            registry,
            auth_cache,
            auth_enabled,
            metrics,
            json_engine: None,
            rel_engine: None,
            shm_manager: None,
            backup_manager,
            log_access: None,
        };
        (state, dir)
    }

    async fn make_app(backup_config: Option<BackupConfig>) -> (Router, tempfile::TempDir) {
        let (state, dir) = make_state(backup_config, false).await;
        (crate::api::create_router(state, Arc::new(vec![])), dir)
    }

    async fn make_admin(cache: &crate::auth::AuthCache, key: &str) {
        cache
            .upsert_user(crate::auth::UserRecord {
                name: "boss".to_string(),
                api_key_hash: crate::auth::hash_api_key(key),
                role: crate::auth::UserRole::Admin,
                created_at: 0,
            })
            .await
            .unwrap();
    }

    async fn make_user(cache: &crate::auth::AuthCache, name: &str, key: &str) {
        cache
            .upsert_user(crate::auth::UserRecord {
                name: name.to_string(),
                api_key_hash: crate::auth::hash_api_key(key),
                role: crate::auth::UserRole::User,
                created_at: 0,
            })
            .await
            .unwrap();
    }

    async fn request(
        app: &Router,
        method: Method,
        uri: &str,
        body: Option<&str>,
        bearer: Option<&str>,
    ) -> (StatusCode, String) {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(b) = bearer {
            builder = builder.header("authorization", format!("Bearer {b}"));
        }
        let req = if let Some(b) = body {
            builder = builder.header("content-type", "application/json");
            builder.body(Body::from(b.to_string())).unwrap()
        } else {
            builder.body(Body::empty()).unwrap()
        };
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    fn all_routes() -> [(Method, &'static str, Option<&'static str>); 8] {
        [
            (Method::POST, "/store-api/backups", Some(r#"{"scope":"all"}"#)),
            (Method::GET, "/store-api/backups", None),
            (Method::GET, "/store-api/backups/bk_x", None),
            (Method::GET, "/store-api/backups/bk_x/download", None),
            (Method::DELETE, "/store-api/backups/bk_x", None),
            (Method::POST, "/store-api/backups/upload", None),
            (Method::POST, "/store-api/backups/bk_x/restore", Some(r#"{"mode":"fail_if_exists"}"#)),
            (Method::GET, "/store-api/restores/rs_x", None),
        ]
    }

    // 9. backup.enabled=false -> every new route answers 503 (spec
    // general/005 decision 1: "feature disabled" is 503 project-wide).
    #[tokio::test]
    async fn test_backup_disabled_returns_503_on_all_routes() {
        let (app, _dir) = make_app(None).await;
        for (method, uri, body) in all_routes() {
            let (status, resp_body) = request(&app, method.clone(), uri, body, None).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{method} {uri}: {resp_body}");
            assert!(resp_body.contains("backup is disabled"), "{method} {uri}: unexpected body {resp_body}");
        }
    }

    // 9b. Mandatory test (spec general/006 authorization section): every
    // new route rejects non-admins with 403, regardless of method or
    // permissions held elsewhere -- extract_domain has no match arm for
    // backups*/restores*.
    #[tokio::test]
    async fn test_all_backup_routes_require_admin() {
        let (state, _dir) = make_state(Some(enabled_backup_config()), true).await;
        let cache = Arc::clone(&state.auth_cache);
        let app = crate::api::create_router(state, Arc::new(vec![]));

        let worker_key = "lura_test_backup_worker_key";
        make_user(&cache, "worker", worker_key).await;

        for (method, uri, body) in all_routes() {
            let (status, resp_body) = request(&app, method.clone(), uri, body, Some(worker_key)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}: {resp_body}");
        }

        // No key at all -> 401 (regression guard, not the focus of this test).
        let (status, _) = request(&app, Method::GET, "/store-api/backups", None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // An admin key passes the auth layer (proves the 403s above are a
        // real admin-only gate, not an accidental global lockout).
        let admin_key = "lura_test_backup_admin_key";
        make_admin(&cache, admin_key).await;
        let (status, body) = request(&app, Method::GET, "/store-api/backups", None, Some(admin_key)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    // 10. ID validation: traversal-flavored / malformed ids -> 400 invalid backup id.
    #[tokio::test]
    async fn test_invalid_backup_id_rejected() {
        let (app, _dir) = make_app(Some(enabled_backup_config())).await;
        for uri in [
            "/store-api/backups/not-bk-prefixed",
            "/store-api/backups/bk_..",
            "/store-api/backups/bk_has%20space",
        ] {
            let (status, body) = request(&app, Method::GET, uri, None, None).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}: {body}");
            assert!(body.contains("invalid backup id"), "{uri}: {body}");

            let (status, body) = request(&app, Method::DELETE, uri, None, None).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}: {body}");
        }
    }

    // 11a. A second POST /backups while one is running -> 409 (job slot busy).
    #[tokio::test]
    async fn test_second_backup_conflicts_with_running_job() {
        let (state, _dir) = make_state(Some(slow_backup_config()), false).await;
        let store = state.registry.store("default").await.unwrap();
        for i in 0..5 {
            store.put(format!("k{i}").as_bytes(), b"v").await.unwrap();
        }
        let app = crate::api::create_router(state, Arc::new(vec![]));

        let (status1, body1) = request(&app, Method::POST, "/store-api/backups", Some(r#"{"scope":"all"}"#), None).await;
        assert_eq!(status1, StatusCode::ACCEPTED, "{body1}");

        let (status2, body2) = request(&app, Method::POST, "/store-api/backups", Some(r#"{"scope":"all"}"#), None).await;
        assert_eq!(status2, StatusCode::CONFLICT, "{body2}");
        assert!(body2.contains("already running"), "{body2}");
    }

    // 11b. POST /backups/{id}/restore while a backup job is running -> 409
    // (job slot busy), rejected synchronously before any file is even read.
    #[tokio::test]
    async fn test_restore_conflicts_with_running_job() {
        let (state, dir) = make_state(Some(slow_backup_config()), false).await;
        let backup_dir = dir.path().join("backups");
        write_fake_backup(&backup_dir, "bk_fake", "all", now_secs(), None, true);
        let store = state.registry.store("default").await.unwrap();
        for i in 0..5 {
            store.put(format!("k{i}").as_bytes(), b"v").await.unwrap();
        }
        let app = crate::api::create_router(state, Arc::new(vec![]));

        let (status, body) = request(&app, Method::POST, "/store-api/backups", Some(r#"{"scope":"all"}"#), None).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");

        let (status, body) = request(
            &app,
            Method::POST,
            "/store-api/backups/bk_fake/restore",
            Some(r#"{"mode":"fail_if_exists"}"#),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(body.contains("already running"), "{body}");
    }

    // 11c. Download/DELETE of the currently-running backup's id -> 409 (this
    // backup is still running); GET (detail) of the same id reports
    // state="running" from the job slot instead of 404 (orchestrator hint 3).
    #[tokio::test]
    async fn test_download_and_delete_conflict_while_backup_running() {
        let (state, _dir) = make_state(Some(slow_backup_config()), false).await;
        let store = state.registry.store("default").await.unwrap();
        for i in 0..5 {
            store.put(format!("k{i}").as_bytes(), b"v").await.unwrap();
        }
        let app = crate::api::create_router(state, Arc::new(vec![]));

        let (status, body) = request(&app, Method::POST, "/store-api/backups", Some(r#"{"scope":"all"}"#), None).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"].as_str().unwrap().to_string();

        let (detail_status, detail_body) =
            request(&app, Method::GET, &format!("/store-api/backups/{id}"), None, None).await;
        assert_eq!(detail_status, StatusCode::OK, "{detail_body}");
        let detail: serde_json::Value = serde_json::from_str(&detail_body).unwrap();
        assert_eq!(detail["state"], json!("running"));
        assert_eq!(detail["id"], json!(id));

        let (dl_status, dl_body) =
            request(&app, Method::GET, &format!("/store-api/backups/{id}/download"), None, None).await;
        assert_eq!(dl_status, StatusCode::CONFLICT, "{dl_body}");
        assert!(dl_body.contains("still running"), "{dl_body}");

        let (del_status, del_body) = request(&app, Method::DELETE, &format!("/store-api/backups/{id}"), None, None).await;
        assert_eq!(del_status, StatusCode::CONFLICT, "{del_body}");
        assert!(del_body.contains("still running"), "{del_body}");
    }

    // 11d. A running *restore* occupies the same job slot but is not a
    // backup: GET /backups/{restore_id} must reject the id like every other
    // route does, and the restored-from backup keeps reporting its own
    // manifest (regression: the slot early-return ignored the job kind).
    #[tokio::test]
    async fn test_get_backup_ignores_running_restore_job() {
        let (state, _dir) = make_state(Some(slow_backup_config()), false).await;
        state.registry.create_domain("shop").await.unwrap();
        let store = state.registry.store("shop").await.unwrap();
        for i in 0..3 {
            store.put(format!("order:{i}").as_bytes(), b"v").await.unwrap();
        }
        let app = crate::api::create_router(state, Arc::new(vec![]));

        let (status, body) =
            request(&app, Method::POST, "/store-api/backups", Some(r#"{"scope":"kv:shop"}"#), None).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"].as_str().unwrap().to_string();
        wait_for_backup_completion(&app, &id).await;

        // The slow config throttles the restore, so it is still running for
        // every assertion below.
        let (status, body) = request(
            &app,
            Method::POST,
            &format!("/store-api/backups/{id}/restore"),
            Some(r#"{"mode":"fail_if_exists","into_domain":"shop-restored"}"#),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let restore_id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["restore_id"]
            .as_str()
            .unwrap()
            .to_string();

        let (status, body) = request(&app, Method::GET, &format!("/store-api/restores/{restore_id}"), None, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap()["state"], json!("running"), "{body}");

        let (status, body) = request(&app, Method::GET, &format!("/store-api/backups/{restore_id}"), None, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.contains("invalid backup id"), "{body}");

        let (status, body) = request(&app, Method::GET, "/store-api/backups", None, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap()["running"], serde_json::Value::Null);

        let (status, body) = request(&app, Method::GET, &format!("/store-api/backups/{id}"), None, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap()["state"], json!("complete"), "{body}");
    }

    // Happy-path wiring proof: create -> list -> detail -> download
    // (Content-Type + Range/206) -> delete -> 404 afterward. Roundtrip
    // *content* correctness (hex/null/ttl/checksum/etc.) is already covered
    // by backup::writer/restore's own test suites; this only proves the
    // HTTP layer forwards things correctly.
    #[tokio::test]
    async fn test_create_list_get_download_delete_roundtrip() {
        let (state, _dir) = make_state(Some(enabled_backup_config()), false).await;
        let store = state.registry.store("default").await.unwrap();
        store.put(b"k1", b"v1").await.unwrap();
        let app = crate::api::create_router(state, Arc::new(vec![]));

        let (status, body) =
            request(&app, Method::POST, "/store-api/backups", Some(r#"{"scope":"kv:default"}"#), None).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"].as_str().unwrap().to_string();

        let detail = wait_for_backup_completion(&app, &id).await;
        assert_eq!(detail["state"], json!("complete"), "{detail}");
        assert_eq!(detail["scope"], json!("kv:default"));
        assert_eq!(detail["format_version"], json!(1));

        let (status, body) = request(&app, Method::GET, "/store-api/backups", None, None).await;
        assert_eq!(status, StatusCode::OK);
        let list: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(list["backups"].as_array().unwrap().iter().any(|b| b["id"] == json!(id)));
        assert_eq!(list["running"], serde_json::Value::Null);

        // Content-Type + Range support (spec general/006 download).
        let req = Request::builder().uri(format!("/store-api/backups/{id}/download")).body(Body::empty()).unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(header::CONTENT_TYPE).unwrap(), "application/x-ndjson");
        let full_bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();

        let req = Request::builder()
            .uri(format!("/store-api/backups/{id}/download"))
            .header(header::RANGE, "bytes=0-4")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        let partial_bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&partial_bytes[..], &full_bytes[0..5]);

        let (status, _) = request(&app, Method::DELETE, &format!("/store-api/backups/{id}"), None, None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        let (status, body) = request(&app, Method::GET, &format!("/store-api/backups/{id}"), None, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    }

    // Metrics wiring (spec general/006 metrics section): the /store-api/metrics
    // "backup" block is null when disabled, and reflects a completed backup
    // (last_success_at/last_duration_ms/last_size_bytes/failed_total) plus
    // `running` for an in-progress one when enabled.
    #[tokio::test]
    async fn test_metrics_backup_block() {
        let (app, _dir) = make_app(None).await;
        let (status, body) = request(&app, Method::GET, "/store-api/metrics", None, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["backup"], serde_json::Value::Null, "disabled backup must report a null block");

        let (state, _dir) = make_state(Some(slow_backup_config()), false).await;
        let store = state.registry.store("default").await.unwrap();
        for i in 0..5 {
            store.put(format!("k{i}").as_bytes(), b"v").await.unwrap();
        }
        let app = crate::api::create_router(state, Arc::new(vec![]));

        let (status, body) = request(&app, Method::POST, "/store-api/backups", Some(r#"{"scope":"all"}"#), None).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"].as_str().unwrap().to_string();

        // While running: failed_total/last_success_at still at defaults, but
        // `running` reflects the in-progress job.
        let (status, body) = request(&app, Method::GET, "/store-api/metrics", None, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["backup"]["running"]["id"], json!(id));
        assert_eq!(value["backup"]["failed_total"], json!(0));

        wait_for_backup_completion(&app, &id).await;

        let (status, body) = request(&app, Method::GET, "/store-api/metrics", None, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(value["backup"]["last_success_at"].as_u64().unwrap() > 0);
        assert!(value["backup"]["last_size_bytes"].as_u64().unwrap() > 0);
        assert_eq!(value["backup"]["running"], serde_json::Value::Null);
    }

    // Happy-path wiring proof: upload a real archive's exact bytes back in,
    // as a raw streamed body (spec: no multipart, no RAM copy) -> 201 with a
    // fresh server-assigned id, distinct from the archive's own manifest id.
    #[tokio::test]
    async fn test_upload_roundtrip() {
        let (state, _dir) = make_state(Some(enabled_backup_config()), false).await;
        let store = state.registry.store("default").await.unwrap();
        store.put(b"k1", b"v1").await.unwrap();
        let manager = Arc::clone(state.backup_manager.as_ref().unwrap());
        let app = crate::api::create_router(state, Arc::new(vec![]));

        let (source_id, handle) = manager.start_backup(BackupScope::All, false, None).await.unwrap();
        handle.await.unwrap();
        let bytes = tokio::fs::read(manager.ndjson_path(&source_id)).await.unwrap();

        let req =
            Request::builder().method(Method::POST).uri("/store-api/backups/upload").body(Body::from(bytes)).unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let uploaded_id = value["id"].as_str().unwrap().to_string();
        assert!(uploaded_id.ends_with("_upload"), "got id '{uploaded_id}'");
        assert_ne!(uploaded_id, source_id, "the server must assign a fresh id, not adopt the manifest's own id");
        assert_eq!(value["format_version"], json!(1));

        let (status, list_body) = request(&app, Method::GET, "/store-api/backups", None, None).await;
        assert_eq!(status, StatusCode::OK);
        let list: serde_json::Value = serde_json::from_str(&list_body).unwrap();
        assert!(list["backups"].as_array().unwrap().iter().any(|b| b["id"] == json!(uploaded_id)));
    }

    // Invalid uploads are rejected and leave nothing behind (spec: the file
    // is discarded).
    #[tokio::test]
    async fn test_upload_invalid_archive_rejected_and_discarded() {
        let (state, dir) = make_state(Some(enabled_backup_config()), false).await;
        let app = crate::api::create_router(state, Arc::new(vec![]));

        let req = Request::builder()
            .method(Method::POST)
            .uri("/store-api/backups/upload")
            .body(Body::from("not a valid backup file\n"))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("invalid backup file"));

        let backup_dir = dir.path().join("backups");
        let leftovers: Vec<_> = std::fs::read_dir(&backup_dir).unwrap().collect();
        assert!(leftovers.is_empty(), "an invalid upload must not leave any file behind");
    }

    // Spec general/006 explicitly calls out that uploads have no body-limit
    // problem: a body past axum's usual 2 MB `Bytes`/`Json` default must
    // still reach the handler (and get a normal 400, not a framework-level
    // rejection) -- proves `body: Body` (raw, streamed) really does bypass
    // that default rather than just being documented to.
    #[tokio::test]
    async fn test_upload_accepts_body_larger_than_default_2mb_limit() {
        let (state, _dir) = make_state(Some(enabled_backup_config()), false).await;
        let app = crate::api::create_router(state, Arc::new(vec![]));

        let oversized = vec![b'x'; 3 * 1024 * 1024]; // 3 MiB > axum's 2 MiB Bytes/Json default
        let req = Request::builder()
            .method(Method::POST)
            .uri("/store-api/backups/upload")
            .body(Body::from(oversized))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        // Not 413/other framework rejection -- the handler ran its own
        // checksum/manifest validation and correctly called it invalid.
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("invalid backup file"));
    }

    // A client that vanishes mid-upload drops the handler future at the body
    // stream's await -- no error arm ever runs there, so only the scratch
    // guard's Drop can discard the half-written file (regression).
    #[tokio::test]
    async fn test_aborted_upload_leaves_no_scratch_file() {
        let (state, dir) = make_state(Some(enabled_backup_config()), false).await;
        let app = crate::api::create_router(state, Arc::new(vec![]));
        let backup_dir = dir.path().join("backups");

        // One chunk, then a body that never yields again and never ends.
        let stream = futures::stream::once(async {
            Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"partial upload"))
        })
        .chain(futures::stream::pending());
        let req = Request::builder()
            .method(Method::POST)
            .uri("/store-api/backups/upload")
            .body(Body::from_stream(stream))
            .unwrap();
        let task = tokio::spawn(async move { app.oneshot(req).await });

        assert!(wait_for_dir_entries(&backup_dir, 1).await, "the handler never streamed into a scratch file");
        task.abort();
        assert!(wait_for_dir_entries(&backup_dir, 0).await, "an aborted upload must not leave a scratch file behind");
    }

    // Typed archive failures keep their own status and message instead of
    // collapsing into the generic verification-failed 400 (regression).
    #[tokio::test]
    async fn test_upload_unsupported_format_version_keeps_its_message() {
        let (state, _dir) = make_state(Some(enabled_backup_config()), false).await;
        let app = crate::api::create_router(state, Arc::new(vec![]));

        let manifest = json!({
            "t": "manifest", "format_version": 99, "id": "bk_x", "created_at": now_secs(),
            "luradb_version": "test", "scope": "all", "include_auth": false,
            "kv_snapshot_ts": 0, "json_snapshot_ts": 0, "encoding": "hex", "schedule": null
        });
        let req = Request::builder()
            .method(Method::POST)
            .uri("/store-api/backups/upload")
            .body(Body::from(format!("{manifest}\n")))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("unsupported backup format version 99"), "{body}");
    }

    // Happy-path wiring proof: restore with into_domain remap -> status
    // polling reaches "complete" with the expected counts.
    #[tokio::test]
    async fn test_restore_roundtrip_with_remap() {
        let (state, _dir) = make_state(Some(enabled_backup_config()), false).await;
        state.registry.create_domain("shop").await.unwrap();
        let store = state.registry.store("shop").await.unwrap();
        store.put(b"order:1", b"hello").await.unwrap();
        let app = crate::api::create_router(state, Arc::new(vec![]));

        let (status, body) = request(&app, Method::POST, "/store-api/backups", Some(r#"{"scope":"kv:shop"}"#), None).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"].as_str().unwrap().to_string();
        wait_for_backup_completion(&app, &id).await;

        let (status, body) = request(
            &app,
            Method::POST,
            &format!("/store-api/backups/{id}/restore"),
            Some(r#"{"mode":"fail_if_exists","into_domain":"shop-restored"}"#),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let restore_id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["restore_id"]
            .as_str()
            .unwrap()
            .to_string();

        let status_value = wait_for_restore_completion(&app, &restore_id).await;
        assert_eq!(status_value["state"], json!("complete"), "{status_value}");
        assert_eq!(status_value["backup_id"], json!(id));
        assert_eq!(status_value["imported"], json!(1));
    }

    // Synchronous restore pre-checks (orchestrator hint 1): all three must
    // be rejected before any job/slot is ever touched.
    #[tokio::test]
    async fn test_restore_synchronous_prechecks() {
        let (state, dir) = make_state(Some(enabled_backup_config()), false).await;
        let backup_dir = dir.path().join("backups");
        write_fake_backup(&backup_dir, "bk_multi", "all", now_secs(), None, true);
        write_fake_backup(&backup_dir, "bk_incomplete", "kv:shop", now_secs(), None, false);
        write_fake_backup_bad_version(&backup_dir, "bk_badversion");
        let app = crate::api::create_router(state, Arc::new(vec![]));

        let (status, body) = request(
            &app,
            Method::POST,
            "/store-api/backups/bk_multi/restore",
            Some(r#"{"mode":"fail_if_exists","into_domain":"x"}"#),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.contains("requires a backup with exactly one domain"), "{body}");

        let (status, body) = request(
            &app,
            Method::POST,
            "/store-api/backups/bk_incomplete/restore",
            Some(r#"{"mode":"fail_if_exists"}"#),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.contains("invalid backup file"), "{body}");

        let (status, body) = request(
            &app,
            Method::POST,
            "/store-api/backups/bk_badversion/restore",
            Some(r#"{"mode":"fail_if_exists"}"#),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.contains("unsupported backup format version"), "{body}");
    }

    /// Polls `GET /backups/{id}` until it is no longer "running" (bounded,
    /// direction-stable -- spec general/008 style, not a tight timing window).
    async fn wait_for_backup_completion(app: &Router, id: &str) -> serde_json::Value {
        for _ in 0..200 {
            let (status, body) = request(app, Method::GET, &format!("/store-api/backups/{id}"), None, None).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let value: serde_json::Value = serde_json::from_str(&body).unwrap();
            if value["state"] != json!("running") {
                return value;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("backup '{id}' did not finish within the poll budget");
    }

    async fn wait_for_restore_completion(app: &Router, restore_id: &str) -> serde_json::Value {
        for _ in 0..200 {
            let (status, body) =
                request(app, Method::GET, &format!("/store-api/restores/{restore_id}"), None, None).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let value: serde_json::Value = serde_json::from_str(&body).unwrap();
            if value["state"] != json!("running") {
                return value;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("restore '{restore_id}' did not finish within the poll budget");
    }

    /// Bounded poll for exactly `count` entries in `dir` -- an upload scratch
    /// file appears and vanishes on the handler task's schedule, not the
    /// test's.
    async fn wait_for_dir_entries(dir: &std::path::Path, count: usize) -> bool {
        for _ in 0..100 {
            if std::fs::read_dir(dir).unwrap().count() == count {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        false
    }

    /// Writes a minimal, well-formed-enough (but NOT checksum-verified)
    /// NDJSON backup file directly -- mirrors `backup::mod::manager_tests`'
    /// helper of the same shape; duplicated since that one is private to its
    /// module. Fine for testing the synchronous pre-checks, which never read
    /// past the manifest/cheap-completeness peek.
    fn write_fake_backup(dir: &std::path::Path, id: &str, scope: &str, created_at: u64, schedule: Option<&str>, complete: bool) {
        let manifest = writer::ManifestLine {
            t: "manifest".to_string(),
            format_version: writer::FORMAT_VERSION,
            id: id.to_string(),
            created_at,
            luradb_version: "test".to_string(),
            scope: scope.to_string(),
            include_auth: false,
            kv_snapshot_ts: 0,
            json_snapshot_ts: 0,
            encoding: "hex".to_string(),
            schedule: schedule.map(|s| s.to_string()),
        };
        let mut content = serde_json::to_string(&manifest).unwrap();
        content.push('\n');
        if complete {
            let checksum = writer::ChecksumLine { t: "checksum".to_string(), sha256: "deadbeef".to_string(), lines: 1 };
            content.push_str(&serde_json::to_string(&checksum).unwrap());
            content.push('\n');
        }
        std::fs::write(dir.join(format!("{id}.ndjson")), content).unwrap();
    }

    fn write_fake_backup_bad_version(dir: &std::path::Path, id: &str) {
        let manifest = json!({
            "t": "manifest", "format_version": 99, "id": id, "created_at": now_secs(),
            "luradb_version": "test", "scope": "all", "include_auth": false,
            "kv_snapshot_ts": 0, "json_snapshot_ts": 0, "encoding": "hex", "schedule": null
        });
        let mut content = manifest.to_string();
        content.push('\n');
        let checksum = json!({"t": "checksum", "sha256": "deadbeef", "lines": 1});
        content.push_str(&checksum.to_string());
        content.push('\n');
        std::fs::write(dir.join(format!("{id}.ndjson")), content).unwrap();
    }
}
