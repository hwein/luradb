//! Log Access REST handlers (spec general/005): read-only tail + file
//! listing over the log directory. Admin-only — `extract_domain`
//! (`src/auth/middleware.rs`) has no match arm for `/store-api/logs*`, so
//! non-admins get 403 from the existing auth middleware automatically.
//!
//! Opt-in: `AppState.log_access` is `None` unless `log.http_access = true`,
//! in which case both handlers answer 503 (spec general/005 decision 1: a
//! disabled feature is 503 project-wide, same as the JSON/rel/backup
//! guards). Routes are always registered so "disabled" (503) stays
//! distinguishable from "wrong URL / old server" (404).

use crate::api::{middleware::ApiError, AppState};
use crate::config::LogFormat;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
use tokio::io::{AsyncReadExt, AsyncSeekExt, SeekFrom};
use utoipa::ToSchema;

/// `AppState.log_access` payload — the log directory and format to read
/// from. `None` in `AppState` when `log.http_access = false`.
#[derive(Clone)]
pub struct LogAccessState {
    pub dir: PathBuf,
    pub format: LogFormat,
}

const MAX_SCAN_BYTES: usize = 4 * 1024 * 1024;
const CHUNK_SIZE: usize = 64 * 1024;

// ── DTOs ─────────────────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct LogQuery {
    /// Tail line count from the file end (default 100, capped at 1000). `0` is rejected.
    pub lines: Option<usize>,
    /// Case-sensitive substring filter; only matching lines count toward `lines`.
    pub q: Option<String>,
    /// Name of a file listed by `GET /logs/files`. Defaults to the newest `luradb.log*` file.
    pub file: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct LogResponse {
    /// Name of the file actually read, without a path.
    pub file: String,
    /// Mirrors `log.format` ("json" | "text") — the client parses `lines` itself.
    pub format: String,
    /// Chronologically ascending (oldest first), like `tail`.
    pub lines: Vec<String>,
    /// `true` iff the scan budget was exhausted before `lines` matches and before file start.
    pub truncated: bool,
}

#[derive(Serialize, ToSchema)]
pub struct LogFileInfo {
    pub file: String,
    pub size: u64,
    pub modified: u64,
}

#[derive(Serialize, ToSchema)]
pub struct LogFilesResponse {
    pub files: Vec<LogFileInfo>,
}

fn format_str(format: &LogFormat) -> &'static str {
    match format {
        LogFormat::Json => "json",
        LogFormat::Text => "text",
    }
}

/// Resolves the log-access state or fails with 503 (spec general/005
/// decision 1: "feature disabled" answers 503 project-wide) when
/// `log.http_access = false`.
fn log_access_state(state: &AppState) -> Result<&LogAccessState, ApiError> {
    state.log_access.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "503 Service Unavailable: log access is disabled (log.http_access = false)",
        )
    })
}

// ── Handlers ─────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/store-api/logs",
    params(
        ("lines" = Option<usize>, Query, description = "Tail line count from file end (default 100, capped at 1000). 0 is rejected."),
        ("q" = Option<String>, Query, description = "Case-sensitive substring filter; only matching lines count toward `lines`."),
        ("file" = Option<String>, Query, description = "Name of a file listed by GET /logs/files. Defaults to the newest luradb.log* file."),
    ),
    responses(
        (status = 200, description = "Tail of the selected log file", body = LogResponse),
        (status = 400, description = "lines = 0, or invalid file name"),
        (status = 404, description = "file does not exist"),
        (status = 500, description = "log directory unreadable, no luradb.log* file found, or read failed"),
        (status = 503, description = "Log HTTP access is disabled"),
    ),
    tag = "Logs"
)]
/// Reads the last N lines of a log file (spec general/005).
pub async fn get_logs(
    State(state): State<AppState>,
    Query(query): Query<LogQuery>,
) -> Result<Json<LogResponse>, ApiError> {
    let access = log_access_state(&state)?;

    let requested_lines = query.lines.unwrap_or(100);
    if requested_lines == 0 {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "400 Bad Request: lines must be >= 1"));
    }
    let capped_lines = requested_lines.min(1000);

    let file_name = match &query.file {
        Some(name) => {
            if !is_valid_file_name(name) {
                return Err(ApiError::new(StatusCode::BAD_REQUEST, "400 Bad Request: invalid file name"));
            }
            name.clone()
        }
        None => {
            let files = list_log_files(&access.dir).await.map_err(|_| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "500 Internal Server Error: log directory unreadable",
                )
            })?;
            files.into_iter().next().map(|f| f.file).ok_or_else(|| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "500 Internal Server Error: no luradb.log* file found",
                )
            })?
        }
    };

    let path = access.dir.join(&file_name);
    let result = tail_lines(&path, capped_lines, query.q.as_deref()).await.map_err(|e| {
        // Only the explicit `file` param distinguishes "not found" from a
        // generic read failure -- the no-param path already confirmed
        // existence via `list_log_files` just above.
        if query.file.is_some() && e.kind() == io::ErrorKind::NotFound {
            ApiError::new(StatusCode::NOT_FOUND, "404 Not Found: log file not found")
        } else {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "500 Internal Server Error: log file read failed")
        }
    })?;

    Ok(Json(LogResponse {
        file: file_name,
        format: format_str(&access.format).to_string(),
        lines: result.lines,
        truncated: result.truncated,
    }))
}

#[utoipa::path(
    get,
    path = "/store-api/logs/files",
    responses(
        (status = 200, description = "All luradb.log* files, newest first", body = LogFilesResponse),
        (status = 500, description = "log directory unreadable"),
        (status = 503, description = "Log HTTP access is disabled"),
    ),
    tag = "Logs"
)]
/// Lists every `luradb.log*` file in the log directory (spec general/005).
/// `files[0]` is exactly the file `GET /logs` reads without a `file` param.
pub async fn list_files(State(state): State<AppState>) -> Result<Json<LogFilesResponse>, ApiError> {
    let access = log_access_state(&state)?;
    let files = list_log_files(&access.dir).await.map_err(|_| {
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "500 Internal Server Error: log directory unreadable")
    })?;
    Ok(Json(LogFilesResponse { files }))
}

// ── File listing & selection ────────────────────────────────────────────────

/// Whitelist for the `file` query param: must start with `luradb.log` and
/// stay a single path segment -- structurally excludes traversal (spec
/// general/005 "Sicherheit"). Same prefix rule as `LogJanitor`.
fn is_valid_file_name(name: &str) -> bool {
    name.starts_with("luradb.log") && !name.contains('/') && !name.contains('\\')
}

/// All `luradb.log*` files in `dir`, newest first (mtime descending, name
/// descending on a tie -- deterministic). Covers rotation "none"
/// (`luradb.log`) and daily/hourly (`luradb.log.<date>`).
async fn list_log_files(dir: &Path) -> io::Result<Vec<LogFileInfo>> {
    let mut entries = tokio::fs::read_dir(dir).await?;
    let mut files = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with("luradb.log") {
            continue;
        }
        let Ok(metadata) = entry.metadata().await else { continue };
        if !metadata.is_file() {
            continue;
        }
        let modified = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        files.push(LogFileInfo { file: name, size: metadata.len(), modified });
    }
    files.sort_by(|a, b| b.modified.cmp(&a.modified).then_with(|| b.file.cmp(&a.file)));
    Ok(files)
}

// ── Backward tail ────────────────────────────────────────────────────────────

struct TailResult {
    lines: Vec<String>,
    truncated: bool,
}

/// Reads `path` backwards in `CHUNK_SIZE` chunks, collecting up to `lines`
/// lines (optionally only `q` substring matches), stopping at `lines`
/// matches, the start of the file, or `MAX_SCAN_BYTES` scanned -- whichever
/// comes first (spec general/005 "Sicherheit": resource caps). Returns
/// lines in chronological (oldest-first) order, like `tail`.
async fn tail_lines(path: &Path, lines: usize, q: Option<&str>) -> io::Result<TailResult> {
    let mut file = tokio::fs::File::open(path).await?;
    let file_len = file.metadata().await?.len() as usize;

    // A single trailing '\n' at EOF must not produce an empty-line artifact
    // (spec): scan as if the file ended right before it.
    let mut pos = file_len;
    if pos > 0 {
        let mut last = [0u8; 1];
        file.seek(SeekFrom::Start((pos - 1) as u64)).await?;
        file.read_exact(&mut last).await?;
        if last[0] == b'\n' {
            pos -= 1;
        }
    }

    // Bytes read so far that precede the earliest newline found yet -- a
    // still-incomplete line prefix, carried into the next (earlier) chunk.
    let mut leftover: Vec<u8> = Vec::new();
    // Matched lines, newest first; reversed into chronological order at the end.
    let mut matched_rev: Vec<String> = Vec::new();
    let mut scanned: usize = 0;
    let mut truncated = false;

    loop {
        if matched_rev.len() >= lines {
            break;
        }
        if pos == 0 {
            // File start reached: any remaining leftover is itself the
            // file's first, complete line.
            if !leftover.is_empty() {
                push_if_match(&leftover, q, &mut matched_rev);
            }
            break;
        }
        if scanned >= MAX_SCAN_BYTES {
            // Budget exhausted -- the leftover is a partially scanned oldest
            // line and must be discarded, not emitted.
            truncated = true;
            break;
        }

        let budget_left = MAX_SCAN_BYTES - scanned;
        let chunk_len = CHUNK_SIZE.min(pos).min(budget_left);
        let new_pos = pos - chunk_len;
        let mut chunk = vec![0u8; chunk_len];
        file.seek(SeekFrom::Start(new_pos as u64)).await?;
        file.read_exact(&mut chunk).await?;
        scanned += chunk_len;
        chunk.extend_from_slice(&leftover);
        let combined = chunk;
        pos = new_pos;

        match combined.iter().position(|&b| b == b'\n') {
            None => {
                // No newline in this window yet -- still one (possibly
                // incomplete) line spanning this chunk and the next.
                leftover = combined;
            }
            Some(first_nl) => {
                leftover = combined[..first_nl].to_vec();
                let rest = &combined[first_nl + 1..];
                let mut segments: Vec<&[u8]> = Vec::new();
                let mut segment_start = 0usize;
                for (i, &b) in rest.iter().enumerate() {
                    if b == b'\n' {
                        segments.push(&rest[segment_start..i]);
                        segment_start = i + 1;
                    }
                }
                segments.push(&rest[segment_start..]);

                for seg in segments.iter().rev() {
                    if matched_rev.len() >= lines {
                        break;
                    }
                    push_if_match(seg, q, &mut matched_rev);
                }
            }
        }
    }

    matched_rev.reverse();
    Ok(TailResult { lines: matched_rev, truncated })
}

/// Byte-buffer-to-line UTF-8 conversion happens per assembled line, never
/// per chunk (spec: chunk boundaries must not split multi-byte sequences).
fn push_if_match(bytes: &[u8], q: Option<&str>, out: &mut Vec<String>) {
    let line = String::from_utf8_lossy(bytes).into_owned();
    let matches = match q {
        Some(needle) => line.contains(needle),
        None => true,
    };
    if matches {
        out.push(line);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{Method, Request};
    use std::sync::Arc;
    use tower::util::ServiceExt;

    async fn make_state(log_access: Option<LogAccessState>, auth_enabled: bool) -> (AppState, tempfile::TempDir) {
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
        let state = AppState {
            registry,
            auth_cache,
            auth_enabled,
            metrics,
            json_engine: None,
            rel_engine: None,
            shm_manager: None,
            backup_manager: None,
            log_access,
        };
        (state, dir)
    }

    async fn make_app(log_access: Option<LogAccessState>) -> (axum::Router, tempfile::TempDir) {
        let (state, dir) = make_state(log_access, false).await;
        (crate::api::create_router(state, Arc::new(vec![])), dir)
    }

    fn text_access(dir: &Path) -> LogAccessState {
        LogAccessState { dir: dir.to_path_buf(), format: LogFormat::Text }
    }

    async fn request(app: &axum::Router, uri: &str, bearer: Option<&str>) -> (StatusCode, String) {
        let mut builder = Request::builder().method(Method::GET).uri(uri);
        if let Some(b) = bearer {
            builder = builder.header("authorization", format!("Bearer {b}"));
        }
        let resp = app.clone().oneshot(builder.body(Body::empty()).unwrap()).await.unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    fn set_mtime_secs_ago(path: &Path, secs_ago: u64) {
        use std::os::unix::ffi::OsStrExt;
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let past = std::time::SystemTime::now()
            .checked_sub(std::time::Duration::from_secs(secs_ago))
            .unwrap_or(UNIX_EPOCH);
        let secs = past.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let times = [
            libc::timeval { tv_sec: secs as libc::time_t, tv_usec: 0 },
            libc::timeval { tv_sec: secs as libc::time_t, tv_usec: 0 },
        ];
        unsafe { libc::utimes(c_path.as_ptr(), times.as_ptr()) };
    }

    // 1. http_access = false -> both routes 503.
    #[tokio::test]
    async fn test_log_access_disabled_returns_503_on_both_routes() {
        let (app, _dir) = make_app(None).await;
        for uri in ["/store-api/logs", "/store-api/logs/files"] {
            let (status, body) = request(&app, uri, None).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{uri}: {body}");
            assert!(body.contains("log access is disabled"), "{uri}: {body}");
        }
    }

    // 3. Mandatory test: non-admin -> 403 on both routes, admin -> 200.
    #[tokio::test]
    async fn test_both_routes_require_admin() {
        let log_dir = tempfile::TempDir::new().unwrap();
        std::fs::write(log_dir.path().join("luradb.log"), "a line\n").unwrap();
        let (state, _dir) = make_state(Some(text_access(log_dir.path())), true).await;
        let cache = Arc::clone(&state.auth_cache);
        let app = crate::api::create_router(state, Arc::new(vec![]));

        let worker_key = "lura_test_logs_worker_key";
        cache
            .upsert_user(crate::auth::UserRecord {
                name: "worker".to_string(),
                api_key_hash: crate::auth::hash_api_key(worker_key),
                role: crate::auth::UserRole::User,
                created_at: 0,
            })
            .await
            .unwrap();
        for uri in ["/store-api/logs", "/store-api/logs/files"] {
            let (status, body) = request(&app, uri, Some(worker_key)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{uri}: {body}");
        }

        let admin_key = "lura_test_logs_admin_key";
        cache
            .upsert_user(crate::auth::UserRecord {
                name: "boss".to_string(),
                api_key_hash: crate::auth::hash_api_key(admin_key),
                role: crate::auth::UserRole::Admin,
                created_at: 0,
            })
            .await
            .unwrap();
        for uri in ["/store-api/logs", "/store-api/logs/files"] {
            let (status, body) = request(&app, uri, Some(admin_key)).await;
            assert_eq!(status, StatusCode::OK, "{uri}: {body}");
        }
    }

    // 4. Tail correctness: last N lines, chronologically ascending.
    #[tokio::test]
    async fn test_tail_returns_last_n_lines_chronological() {
        let log_dir = tempfile::TempDir::new().unwrap();
        let content = (1..=10).map(|i| format!("line{i}")).collect::<Vec<_>>().join("\n") + "\n";
        std::fs::write(log_dir.path().join("luradb.log"), content).unwrap();
        let (app, _dir) = make_app(Some(text_access(log_dir.path()))).await;

        let (status, body) = request(&app, "/store-api/logs?lines=3", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["lines"], serde_json::json!(["line8", "line9", "line10"]));
        assert_eq!(value["truncated"], serde_json::json!(false));
        assert_eq!(value["file"], serde_json::json!("luradb.log"));
        assert_eq!(value["format"], serde_json::json!("text"));
    }

    // 5. Chunk boundaries: a line far longer than CHUNK_SIZE necessarily
    // spans multiple 64-KiB reads and must reassemble intact.
    #[tokio::test]
    async fn test_line_spanning_chunk_boundary_reassembled_intact() {
        let log_dir = tempfile::TempDir::new().unwrap();
        let huge = "X".repeat(150_000);
        let content = format!("before\n{huge}\nafter\n");
        std::fs::write(log_dir.path().join("luradb.log"), content).unwrap();
        let (app, _dir) = make_app(Some(text_access(log_dir.path()))).await;

        let (status, body) = request(&app, "/store-api/logs?lines=10", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["lines"], serde_json::json!(["before", huge, "after"]));
        assert_eq!(value["truncated"], serde_json::json!(false));
    }

    // 6. q filter: only matches, counted toward `lines`.
    #[tokio::test]
    async fn test_q_filter_only_matching_lines() {
        let log_dir = tempfile::TempDir::new().unwrap();
        let content = "INFO one\nWARN two\nINFO three\nWARN four\nINFO five\n";
        std::fs::write(log_dir.path().join("luradb.log"), content).unwrap();
        let (app, _dir) = make_app(Some(text_access(log_dir.path()))).await;

        let (status, body) = request(&app, "/store-api/logs?lines=10&q=WARN", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["lines"], serde_json::json!(["WARN two", "WARN four"]));
    }

    // 7. Without `file`, the newest file by mtime is read (LogJanitor-style utimes).
    #[tokio::test]
    async fn test_tail_without_file_param_reads_newest_by_mtime() {
        let log_dir = tempfile::TempDir::new().unwrap();
        let old = log_dir.path().join("luradb.log.2026-08-11");
        std::fs::write(&old, "old\n").unwrap();
        set_mtime_secs_ago(&old, 200);
        let new = log_dir.path().join("luradb.log.2026-08-12");
        std::fs::write(&new, "new\n").unwrap();
        set_mtime_secs_ago(&new, 10);
        let (app, _dir) = make_app(Some(text_access(log_dir.path()))).await;

        let (status, body) = request(&app, "/store-api/logs", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["file"], serde_json::json!("luradb.log.2026-08-12"));
        assert_eq!(value["lines"], serde_json::json!(["new"]));
    }

    // 8. Files listing: sorted newest first, files[0] matches the tail
    // default; empty directory -> 200 {"files": []}.
    #[tokio::test]
    async fn test_list_files_sorted_newest_first_and_empty_dir() {
        let log_dir = tempfile::TempDir::new().unwrap();
        let (app, _dir) = make_app(Some(text_access(log_dir.path()))).await;

        let (status, body) = request(&app, "/store-api/logs/files", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({"files": []})
        );

        let a = log_dir.path().join("luradb.log.a");
        std::fs::write(&a, "1234").unwrap();
        set_mtime_secs_ago(&a, 100);
        let b = log_dir.path().join("luradb.log.b");
        std::fs::write(&b, "12345678").unwrap();
        set_mtime_secs_ago(&b, 10);

        let (status, body) = request(&app, "/store-api/logs/files", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        let files = value["files"].as_array().unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0]["file"], serde_json::json!("luradb.log.b"));
        assert_eq!(files[0]["size"], serde_json::json!(8));
        assert_eq!(files[1]["file"], serde_json::json!("luradb.log.a"));

        let (status, body) = request(&app, "/store-api/logs", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let tail: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(tail["file"], files[0]["file"]);
    }

    // 9. file param: selects a listed archive file; invalid names -> 400;
    // validated-but-missing -> 404.
    #[tokio::test]
    async fn test_file_param_selects_listed_file_and_validates() {
        let log_dir = tempfile::TempDir::new().unwrap();
        std::fs::write(log_dir.path().join("luradb.log"), "current\n").unwrap();
        std::fs::write(log_dir.path().join("luradb.log.old"), "archived\n").unwrap();
        let (app, _dir) = make_app(Some(text_access(log_dir.path()))).await;

        let (status, body) = request(&app, "/store-api/logs?file=luradb.log.old", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["file"], serde_json::json!("luradb.log.old"));
        assert_eq!(value["lines"], serde_json::json!(["archived"]));

        for bad in ["evil.txt", "luradb.log%2F..%2Fx", "..%2Fluradb.log"] {
            let (status, body) = request(&app, &format!("/store-api/logs?file={bad}"), None).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {body}");
            assert!(body.contains("invalid file name"), "{bad}: {body}");
        }

        let (status, body) = request(&app, "/store-api/logs?file=luradb.log.missing", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert!(body.contains("log file not found"), "{body}");
    }

    // 10a. Caps: lines=5000 is capped to 1000.
    #[tokio::test]
    async fn test_lines_param_capped_at_1000() {
        let log_dir = tempfile::TempDir::new().unwrap();
        let content = (1..=1200).map(|i| format!("l{i}")).collect::<Vec<_>>().join("\n") + "\n";
        std::fs::write(log_dir.path().join("luradb.log"), content).unwrap();
        let (app, _dir) = make_app(Some(text_access(log_dir.path()))).await;

        let (status, body) = request(&app, "/store-api/logs?lines=5000", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        let lines = value["lines"].as_array().unwrap();
        assert_eq!(lines.len(), 1000);
        assert_eq!(lines[0], serde_json::json!("l201"));
        assert_eq!(lines[999], serde_json::json!("l1200"));
    }

    // 10b. Budget stop -> truncated = true, fewer than the capped count returned.
    #[tokio::test]
    async fn test_scan_budget_exhausted_sets_truncated() {
        let log_dir = tempfile::TempDir::new().unwrap();
        // ~4.5 KB/line * 2000 lines ~= 9 MB, well over the 4 MiB scan budget;
        // 1000 matches would need ~4.5 MB, past the budget too.
        let line = "x".repeat(4500);
        let mut content = String::new();
        for _ in 0..2000 {
            content.push_str(&line);
            content.push('\n');
        }
        std::fs::write(log_dir.path().join("luradb.log"), &content).unwrap();
        let (app, _dir) = make_app(Some(text_access(log_dir.path()))).await;

        let (status, body) = request(&app, "/store-api/logs?lines=5000", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["truncated"], serde_json::json!(true));
        assert!(value["lines"].as_array().unwrap().len() < 1000);
    }

    // 11. Fewer lines than requested -> all lines, truncated = false.
    #[tokio::test]
    async fn test_fewer_lines_than_requested_returns_all_not_truncated() {
        let log_dir = tempfile::TempDir::new().unwrap();
        std::fs::write(log_dir.path().join("luradb.log"), "only one line\n").unwrap();
        let (app, _dir) = make_app(Some(text_access(log_dir.path()))).await;

        let (status, body) = request(&app, "/store-api/logs?lines=50", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["lines"], serde_json::json!(["only one line"]));
        assert_eq!(value["truncated"], serde_json::json!(false));
    }

    // lines = 0 -> 400.
    #[tokio::test]
    async fn test_lines_zero_rejected() {
        let log_dir = tempfile::TempDir::new().unwrap();
        std::fs::write(log_dir.path().join("luradb.log"), "x\n").unwrap();
        let (app, _dir) = make_app(Some(text_access(log_dir.path()))).await;

        let (status, body) = request(&app, "/store-api/logs?lines=0", None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.contains("lines must be"), "{body}");
    }
}
