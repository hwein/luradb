//! Logical backup & restore (spec general/006).
//!
//! `BackupManager` owns the global backup/restore job slot, ID assignment,
//! the on-disk backup listing, retention, and the in-RAM restore-status
//! registry. The actual NDJSON export/import pipelines live in `writer`/
//! `restore`; the cron subset lives in `cron`. HTTP handlers, the scheduler
//! task and `main.rs` wiring are a later step.

pub mod cron;
pub mod restore;
pub mod writer;

use crate::config::BackupConfig;
use crate::engines::json::JsonEngine;
use crate::engines::lsm::domain::{now_secs, DomainRegistry};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;

/// Which data a backup covers (spec general/006 "Scope-Syntax"). Parsing is
/// syntax-only — domain existence is checked when a backup job actually runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackupScope {
    /// Both engines, all active domains.
    All,
    /// KV engine, all KV domains.
    Kv,
    /// JSON engine, all JSON domains (incl. index definitions).
    Json,
    /// A single KV domain.
    KvDomain(String),
    /// A single JSON domain.
    JsonDomain(String),
    /// The KV **and** JSON domain of this name (whichever engine has it).
    Domain(String),
}

impl BackupScope {
    /// Parses a scope string: `all`, `kv`, `json`, `kv:<domain>`,
    /// `json:<domain>`, or `domain:<name>`.
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "all" => return Ok(Self::All),
            "kv" => return Ok(Self::Kv),
            "json" => return Ok(Self::Json),
            _ => {}
        }
        if let Some(domain) = s.strip_prefix("kv:") {
            return Ok(Self::KvDomain(validate_scope_domain(domain)?.to_string()));
        }
        if let Some(domain) = s.strip_prefix("json:") {
            return Ok(Self::JsonDomain(validate_scope_domain(domain)?.to_string()));
        }
        if let Some(domain) = s.strip_prefix("domain:") {
            return Ok(Self::Domain(validate_scope_domain(domain)?.to_string()));
        }
        anyhow::bail!(
            "invalid backup scope '{s}': expected 'all', 'kv', 'json', 'kv:<domain>', 'json:<domain>', or 'domain:<name>'"
        );
    }
}

impl BackupScope {
    /// Canonical string form — the inverse of [`Self::parse`]; stored in the
    /// backup manifest's `scope` field.
    pub fn as_string(&self) -> String {
        match self {
            Self::All => "all".to_string(),
            Self::Kv => "kv".to_string(),
            Self::Json => "json".to_string(),
            Self::KvDomain(d) => format!("kv:{d}"),
            Self::JsonDomain(d) => format!("json:{d}"),
            Self::Domain(d) => format!("domain:{d}"),
        }
    }

    /// Filesystem/ID-safe slug used in `bk_<timestamp>_<slug>` when no
    /// schedule name overrides it (spec general/006 backup IDs).
    pub fn slug(&self) -> String {
        self.as_string().replace(':', "-")
    }
}

/// Syntax check only (matches the `[a-zA-Z0-9_-]` domain-name charset used
/// elsewhere in the repo) — no existence check, no engine access.
fn validate_scope_domain(name: &str) -> anyhow::Result<&str> {
    anyhow::ensure!(!name.is_empty(), "invalid backup scope: domain name must not be empty");
    anyhow::ensure!(
        name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
        "invalid backup scope: domain name '{name}' contains invalid characters (only [a-zA-Z0-9_-] allowed)"
    );
    Ok(name)
}

// ── Errors ───────────────────────────────────────────────────────────────

/// Typed errors the HTTP layer (later step) maps to specific status codes.
/// Anything not worth a dedicated variant collapses into `Other`.
#[derive(Debug, Error)]
pub enum BackupError {
    #[error("backup_busy")]
    Busy,
    #[error("backup_not_found")]
    NotFound,
    #[error("restore_not_found")]
    RestoreNotFound,
    #[error("domain_not_found: {0}")]
    DomainNotFound(String),
    #[error("backup_running")]
    BackupRunning,
    #[error("invalid_backup_file: {0}")]
    InvalidBackupFile(String),
    #[error("remap_requires_single_domain")]
    RemapRequiresSingleDomain,
    #[error("domain_exists: {0}")]
    DomainExists(String),
    #[error("unsupported_format_version: {0}")]
    UnsupportedFormatVersion(u32),
    #[error("json_engine_disabled")]
    JsonEngineDisabled,
    #[error("invalid backup id '{0}'")]
    InvalidId(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Validates the client-facing backup id charset (`^bk_[A-Za-z0-9_-]+$`) —
/// the only input that ever turns into a path under `backup.dir`, so this is
/// the traversal guard (spec general/006, "no path from client data").
pub(crate) fn validate_backup_id(id: &str) -> Result<(), BackupError> {
    let valid = id.len() > 3
        && id.starts_with("bk_")
        && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if valid {
        Ok(())
    } else {
        Err(BackupError::InvalidId(id.to_string()))
    }
}

// ── Job slot ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobKind {
    Backup,
    Restore,
}

#[derive(Debug, Clone)]
pub struct RunningJobInfo {
    pub id: String,
    pub kind: JobKind,
    pub scope: String,
    pub started_at: u64,
}

/// Clears the global job slot when the spawned job task ends, on every exit
/// path (success, error, or panic) — the busy check in `start_backup`/
/// `start_restore` would otherwise wedge forever after a job panics.
struct SlotGuard(Arc<BackupManager>);

impl Drop for SlotGuard {
    fn drop(&mut self) {
        *self.0.slot.lock() = None;
    }
}

// ── Backup listing ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupState {
    Complete,
    Incomplete,
}

#[derive(Debug, Clone)]
pub struct BackupSummary {
    pub id: String,
    pub state: BackupState,
    pub scope: String,
    pub created_at: u64,
    pub size_bytes: u64,
    pub schedule: Option<String>,
    pub format_version: u32,
}

// ── Restore status registry ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreState {
    Running,
    Complete,
    Failed,
}

#[derive(Debug, Clone)]
pub struct RestoreStatus {
    pub restore_id: String,
    pub backup_id: String,
    pub state: RestoreState,
    pub imported: u64,
    pub skipped: u64,
    pub failed: u64,
    pub errors: Vec<(String, String)>,
    pub started_at: u64,
    pub finished_at: Option<u64>,
}

// ── BackupManager ────────────────────────────────────────────────────────

/// Owns the global backup/restore job slot, ID assignment, the on-disk
/// backup listing/retention, and the RAM restore-status registry.
///
/// Job-starting methods take `self: &Arc<Self>`: they validate synchronously
/// (job slot, and for backups the scope) and spawn the actual work via
/// `tokio::spawn`, returning the id and a `JoinHandle` immediately — the
/// handle lets tests (and later, the scheduler) await completion.
pub struct BackupManager {
    dir: PathBuf,
    scan_batch_size: usize,
    scan_pause_ms: u64,
    kv_registry: Arc<DomainRegistry>,
    json_engine: Option<Arc<JsonEngine>>,
    slot: parking_lot::Mutex<Option<RunningJobInfo>>,
    restores: parking_lot::RwLock<HashMap<String, RestoreStatus>>,
}

impl BackupManager {
    /// Creates the manager and ensures `config.dir` exists.
    pub fn new(
        config: &BackupConfig,
        kv_registry: Arc<DomainRegistry>,
        json_engine: Option<Arc<JsonEngine>>,
    ) -> anyhow::Result<Arc<Self>> {
        let dir = PathBuf::from(&config.dir);
        std::fs::create_dir_all(&dir)?;
        Ok(Arc::new(Self {
            dir,
            scan_batch_size: config.scan_batch_size,
            scan_pause_ms: config.scan_pause_ms,
            kv_registry,
            json_engine,
            slot: parking_lot::Mutex::new(None),
            restores: parking_lot::RwLock::new(HashMap::new()),
        }))
    }

    /// The currently running job, if any (backup list's `running` field and
    /// the busy check share this).
    pub fn running_job(&self) -> Option<RunningJobInfo> {
        self.slot.lock().clone()
    }

    // ── Backup jobs ─────────────────────────────────────────────────────

    /// Validates the scope, allocates an id, marks the slot busy, and spawns
    /// the export. Scope validation is synchronous (unlike restore) because
    /// a rejected backup never produces any artifact or status entry — this
    /// is the only chance to tell the caller why.
    pub async fn start_backup(
        self: &Arc<Self>,
        scope: BackupScope,
        include_auth: bool,
        schedule: Option<String>,
    ) -> Result<(String, tokio::task::JoinHandle<()>), BackupError> {
        let resolved = writer::resolve_scope(&scope, &self.kv_registry, &self.json_engine).await?;

        let id = {
            let mut slot = self.slot.lock();
            if slot.is_some() {
                return Err(BackupError::Busy);
            }
            let suffix = schedule.clone().unwrap_or_else(|| scope.slug());
            let id = self.allocate_backup_id(&suffix);
            *slot = Some(RunningJobInfo {
                id: id.clone(),
                kind: JobKind::Backup,
                scope: scope.as_string(),
                started_at: now_secs(),
            });
            id
        };

        let manager = Arc::clone(self);
        let job_id = id.clone();
        let handle = tokio::spawn(async move {
            let _guard = SlotGuard(Arc::clone(&manager));
            let params = writer::BackupParams {
                dir: &manager.dir,
                id: &job_id,
                scope: &scope,
                include_auth,
                schedule: schedule.as_deref(),
                resolved: &resolved,
                kv_registry: &manager.kv_registry,
                json_engine: &manager.json_engine,
                scan_batch_size: manager.scan_batch_size,
                scan_pause_ms: manager.scan_pause_ms,
            };
            match writer::run_backup(params).await {
                Ok(()) => tracing::info!("[Backup] job '{job_id}' completed"),
                Err(e) => tracing::warn!("[Backup] job '{job_id}' failed: {e:#}"),
            }
        });

        Ok((id, handle))
    }

    fn allocate_backup_id(&self, suffix: &str) -> String {
        let base = format!("bk_{}_{suffix}", cron::format_utc_timestamp(now_secs()));
        if !self.backup_id_taken(&base) {
            return base;
        }
        for n in 2.. {
            let candidate = format!("{base}_{n}");
            if !self.backup_id_taken(&candidate) {
                return candidate;
            }
        }
        unreachable!("directories are finite")
    }

    fn backup_id_taken(&self, id: &str) -> bool {
        self.dir.join(format!("{id}.ndjson")).exists() || self.dir.join(format!("{id}.ndjson.part")).exists()
    }

    // ── Restore jobs ─────────────────────────────────────────────────────

    /// Marks the slot busy, records a `running` status entry, and spawns the
    /// restore. Beyond "does the backup file exist", validation (checksum,
    /// remap, domain-exists) happens inside the job and surfaces only via
    /// [`Self::get_restore_status`] — matching the spec's restore response,
    /// which is always `202 running`.
    pub async fn start_restore(
        self: &Arc<Self>,
        backup_id: &str,
        mode: restore::RestoreMode,
        into_domain: Option<String>,
        include_auth: bool,
    ) -> Result<(String, tokio::task::JoinHandle<()>), BackupError> {
        validate_backup_id(backup_id)?;
        if !self.dir.join(format!("{backup_id}.ndjson")).exists() {
            return Err(BackupError::NotFound);
        }

        let restore_id = {
            let mut slot = self.slot.lock();
            if slot.is_some() {
                return Err(BackupError::Busy);
            }
            let id = self.allocate_restore_id();
            *slot = Some(RunningJobInfo {
                id: id.clone(),
                kind: JobKind::Restore,
                scope: backup_id.to_string(),
                started_at: now_secs(),
            });
            id
        };

        let started_at = now_secs();
        self.restores.write().insert(
            restore_id.clone(),
            RestoreStatus {
                restore_id: restore_id.clone(),
                backup_id: backup_id.to_string(),
                state: RestoreState::Running,
                imported: 0,
                skipped: 0,
                failed: 0,
                errors: Vec::new(),
                started_at,
                finished_at: None,
            },
        );

        let manager = Arc::clone(self);
        let job_restore_id = restore_id.clone();
        let job_backup_id = backup_id.to_string();
        let handle = tokio::spawn(async move {
            let _guard = SlotGuard(Arc::clone(&manager));
            let params = restore::RestoreParams {
                dir: &manager.dir,
                backup_id: &job_backup_id,
                mode,
                into_domain: into_domain.as_deref(),
                include_auth,
                kv_registry: &manager.kv_registry,
                json_engine: &manager.json_engine,
                scan_batch_size: manager.scan_batch_size,
                scan_pause_ms: manager.scan_pause_ms,
            };
            let result = restore::run_restore(params).await;
            let mut restores = manager.restores.write();
            if let Some(status) = restores.get_mut(&job_restore_id) {
                status.finished_at = Some(now_secs());
                match result {
                    Ok(outcome) => {
                        status.imported = outcome.imported;
                        status.skipped = outcome.skipped;
                        status.failed = outcome.failed;
                        status.errors = outcome.errors;
                        status.state = RestoreState::Complete;
                        tracing::info!(
                            "[Restore] job '{job_restore_id}' completed (backup '{job_backup_id}')"
                        );
                    }
                    Err(e) => {
                        status.errors.push(("_restore_".to_string(), e.to_string()));
                        status.state = RestoreState::Failed;
                        tracing::warn!("[Restore] job '{job_restore_id}' failed: {e:#}");
                    }
                }
            }
        });

        Ok((restore_id, handle))
    }

    fn allocate_restore_id(&self) -> String {
        let base = format!("rs_{}", cron::format_utc_timestamp(now_secs()));
        let restores = self.restores.read();
        if !restores.contains_key(&base) {
            return base;
        }
        for n in 2.. {
            let candidate = format!("{base}_{n}");
            if !restores.contains_key(&candidate) {
                return candidate;
            }
        }
        unreachable!("the restore registry is finite")
    }

    /// Snapshot of a restore job's status (spec general/006 `GET /restores/{id}`).
    pub fn get_restore_status(&self, restore_id: &str) -> Option<RestoreStatus> {
        self.restores.read().get(restore_id).cloned()
    }

    // ── Listing, detail, deletion ────────────────────────────────────────

    fn ndjson_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.ndjson"))
    }

    /// Directory scan for `GET /backups`: every `bk_*.ndjson` file (never
    /// `.part` — an in-progress job is reported separately via
    /// [`Self::running_job`]), reading only the manifest line plus a cheap
    /// tail-peek for the checksum line per file.
    pub fn list_backups(&self) -> anyhow::Result<Vec<BackupSummary>> {
        let mut out = Vec::new();
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with("bk_") || !name.ends_with(".ndjson") {
                continue;
            }
            match read_backup_summary(&entry.path()) {
                Ok(summary) => out.push(summary),
                Err(e) => tracing::warn!(
                    "[Backup] skipping unreadable backup file {}: {e}",
                    entry.path().display()
                ),
            }
        }
        Ok(out)
    }

    /// `GET /backups/{id}` data lookup.
    pub fn get_backup(&self, id: &str) -> Result<BackupSummary, BackupError> {
        validate_backup_id(id)?;
        let path = self.ndjson_path(id);
        if !path.exists() {
            return Err(BackupError::NotFound);
        }
        read_backup_summary(&path).map_err(BackupError::Other)
    }

    /// `DELETE /backups/{id}`. Refuses while the id is the active job (or a
    /// `.part` file for it still exists, e.g. a stale leftover) — spec
    /// general/006 `backup_running`.
    pub fn delete_backup(&self, id: &str) -> Result<(), BackupError> {
        validate_backup_id(id)?;
        if self.slot.lock().as_ref().is_some_and(|j| j.id == id) {
            return Err(BackupError::BackupRunning);
        }
        if self.dir.join(format!("{id}.ndjson.part")).exists() {
            return Err(BackupError::BackupRunning);
        }
        let path = self.ndjson_path(id);
        if !path.exists() {
            return Err(BackupError::NotFound);
        }
        std::fs::remove_file(&path).map_err(|e| BackupError::Other(e.into()))
    }

    /// Retention (spec general/006 Scheduler step 3): keeps the `keep_last`
    /// most recent **complete** backups of `schedule_name`, deletes the
    /// rest. On-demand/upload backups (`schedule = null`) are never touched
    /// — the caller-supplied name can never match `None`. Not wired to any
    /// scheduler here; the follow-up scheduler task calls this after a
    /// successful scheduled run.
    pub fn apply_retention(&self, schedule_name: &str, keep_last: usize) -> anyhow::Result<usize> {
        let mut matching: Vec<BackupSummary> = self
            .list_backups()?
            .into_iter()
            .filter(|b| b.state == BackupState::Complete && b.schedule.as_deref() == Some(schedule_name))
            .collect();
        matching.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        let mut deleted = 0;
        for old in matching.into_iter().skip(keep_last) {
            match std::fs::remove_file(self.ndjson_path(&old.id)) {
                Ok(()) => deleted += 1,
                Err(e) => tracing::warn!("[Backup] retention: cannot delete '{}': {e}", old.id),
            }
        }
        Ok(deleted)
    }
}

/// Reads a backup's manifest line (first line) plus a cheap tail-peek to
/// classify it `Complete`/`Incomplete` without a full SHA-256 pass (spec
/// general/006: the real verification runs only in the restore/upload path).
fn read_backup_summary(path: &Path) -> anyhow::Result<BackupSummary> {
    let metadata = std::fs::metadata(path)?;
    let first = read_first_line(path)?
        .ok_or_else(|| anyhow::anyhow!("empty backup file {}", path.display()))?;
    let manifest: writer::ManifestLine = serde_json::from_str(&first)?;

    let is_complete = read_last_line(path)?
        .and_then(|last| serde_json::from_str::<serde_json::Value>(&last).ok())
        .and_then(|v| v.get("t").and_then(|t| t.as_str()).map(|t| t == "checksum"))
        .unwrap_or(false);

    // The file name, not the manifest, is a backup's identity: an uploaded
    // archive keeps its original manifest id (rewriting it would break the
    // checksum) but is addressed by its fresh server-assigned name.
    let id = path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow::anyhow!("backup file {} has no valid name stem", path.display()))?
        .to_string();

    Ok(BackupSummary {
        id,
        state: if is_complete { BackupState::Complete } else { BackupState::Incomplete },
        scope: manifest.scope,
        created_at: manifest.created_at,
        size_bytes: metadata.len(),
        schedule: manifest.schedule,
        format_version: manifest.format_version,
    })
}

fn read_first_line(path: &Path) -> std::io::Result<Option<String>> {
    use std::io::BufRead;
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let mut line = String::new();
    let n = reader.read_line(&mut line)?;
    if n == 0 {
        return Ok(None);
    }
    Ok(Some(line.trim_end().to_string()))
}

/// Reads the last non-empty line of `path` from a bounded tail window
/// (avoids a full read for the incomplete-check on potentially large files).
fn read_last_line(path: &Path) -> std::io::Result<Option<String>> {
    use std::io::{Read, Seek, SeekFrom};
    const TAIL: u64 = 8192;
    let mut file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(None);
    }
    file.seek(SeekFrom::Start(len.saturating_sub(TAIL)))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    let text = String::from_utf8_lossy(&buf);
    Ok(text.lines().rev().find(|l| !l.trim().is_empty()).map(|s| s.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_fixed_scopes() {
        assert_eq!(BackupScope::parse("all").unwrap(), BackupScope::All);
        assert_eq!(BackupScope::parse("kv").unwrap(), BackupScope::Kv);
        assert_eq!(BackupScope::parse("json").unwrap(), BackupScope::Json);
    }

    #[test]
    fn test_parse_domain_scopes() {
        assert_eq!(
            BackupScope::parse("kv:shop").unwrap(),
            BackupScope::KvDomain("shop".to_string())
        );
        assert_eq!(
            BackupScope::parse("json:shop").unwrap(),
            BackupScope::JsonDomain("shop".to_string())
        );
        assert_eq!(
            BackupScope::parse("domain:shop").unwrap(),
            BackupScope::Domain("shop".to_string())
        );
    }

    #[test]
    fn test_parse_domain_name_allows_underscore_and_hyphen() {
        assert_eq!(
            BackupScope::parse("kv:my-domain_1").unwrap(),
            BackupScope::KvDomain("my-domain_1".to_string())
        );
    }

    #[test]
    fn test_parse_rejects_unknown_scope() {
        assert!(BackupScope::parse("").is_err());
        assert!(BackupScope::parse("unknown").is_err());
        assert!(BackupScope::parse("Kv").is_err()); // case-sensitive
        assert!(BackupScope::parse("kv:shop:extra").is_err());
    }

    #[test]
    fn test_parse_rejects_empty_domain_name() {
        assert!(BackupScope::parse("kv:").is_err());
        assert!(BackupScope::parse("json:").is_err());
        assert!(BackupScope::parse("domain:").is_err());
    }

    #[test]
    fn test_parse_rejects_invalid_domain_characters() {
        assert!(BackupScope::parse("kv:sh op").is_err());
        assert!(BackupScope::parse("domain:sh/op").is_err());
        assert!(BackupScope::parse("json:sh.op").is_err());
    }

    // ── as_string / slug ─────────────────────────────────────────────────

    #[test]
    fn test_as_string_round_trips_through_parse() {
        for s in ["all", "kv", "json", "kv:shop", "json:shop", "domain:shop"] {
            let scope = BackupScope::parse(s).unwrap();
            assert_eq!(scope.as_string(), s);
        }
    }

    #[test]
    fn test_slug_replaces_colon_with_hyphen() {
        assert_eq!(BackupScope::KvDomain("shop".to_string()).slug(), "kv-shop");
        assert_eq!(BackupScope::Domain("shop".to_string()).slug(), "domain-shop");
        assert_eq!(BackupScope::All.slug(), "all");
    }

    #[test]
    fn test_validate_backup_id() {
        assert!(validate_backup_id("bk_20260712T030000Z_all").is_ok());
        assert!(validate_backup_id("bk_x").is_ok());
        assert!(validate_backup_id("bk_").is_err(), "must have at least one char after the prefix");
        assert!(validate_backup_id("../../etc/passwd").is_err());
        assert!(validate_backup_id("bk_../x").is_err());
        assert!(validate_backup_id("not_bk_prefixed").is_err());
        assert!(validate_backup_id("bk_has space").is_err());
    }
}

#[cfg(test)]
mod manager_tests {
    use super::*;
    use crate::engines::lsm::domain::DomainConfig;
    use crate::engines::lsm::engine::{LsmEngineOptions, LsmStorageEngine};
    use crate::metrics::{MetricsConfig, MetricsStore};
    use crate::storage::file_manager::FileManager;
    use crate::storage::manifest::ManifestManager;
    use crate::storage::vlog::VLog;
    use crate::core::wal::WriteAheadLog;

    async fn make_manager() -> (Arc<BackupManager>, tempfile::TempDir, tempfile::TempDir) {
        let engine_dir = tempfile::TempDir::new().unwrap();
        let wal_path = engine_dir.path().join("wal.log");
        let wal = Arc::new(WriteAheadLog::new(&wal_path).await.unwrap());
        let vlog_path = engine_dir.path().join("vlog.log");
        let vlog = Arc::new(VLog::new(&vlog_path).await.unwrap());
        let fm = Arc::new(FileManager::new(engine_dir.path()).await.unwrap());
        let mm = Arc::new(ManifestManager::new(engine_dir.path()));
        let engine = Arc::new(
            LsmStorageEngine::new(wal, wal_path, vlog, vlog_path, fm, mm, LsmEngineOptions::default())
                .await
                .unwrap(),
        );
        let metrics = MetricsStore::new(MetricsConfig::default());
        let registry =
            Arc::new(DomainRegistry::recover(Arc::clone(&engine), DomainConfig::default(), metrics).await.unwrap());

        let backup_dir = tempfile::TempDir::new().unwrap();
        let config = BackupConfig {
            enabled: true,
            dir: backup_dir.path().to_string_lossy().into_owned(),
            scan_batch_size: 500,
            scan_pause_ms: 0,
            schedule: Vec::new(),
        };
        let manager = BackupManager::new(&config, registry, None).unwrap();
        (manager, engine_dir, backup_dir)
    }

    /// Writes a minimal, well-formed-enough NDJSON backup file directly
    /// (bypassing `writer::run_backup`) so tests can control `created_at`/
    /// `schedule` precisely without running a real export.
    fn write_fake_backup(dir: &Path, id: &str, scope: &str, created_at: u64, schedule: Option<&str>, complete: bool) {
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

    // 1. Job slot: a second backup while one is running -> Busy.
    #[tokio::test]
    async fn test_start_backup_busy_while_running() {
        let (manager, _e, _b) = make_manager().await;
        let (_id1, handle1) =
            manager.start_backup(BackupScope::All, false, None).await.expect("first backup must start");
        let err = manager.start_backup(BackupScope::All, false, None).await.unwrap_err();
        assert!(matches!(err, BackupError::Busy));
        handle1.await.unwrap();
        // Slot freed after completion -> a new backup can start.
        let (_id2, handle2) = manager.start_backup(BackupScope::All, false, None).await.unwrap();
        handle2.await.unwrap();
    }

    // 2. The slot is shared between backup and restore.
    #[tokio::test]
    async fn test_backup_and_restore_share_one_slot() {
        let (manager, _e, backup_dir) = make_manager().await;
        write_fake_backup(backup_dir.path(), "bk_shared", "all", now_secs(), None, true);
        // Manually mark the slot busy (as if a backup were running) instead
        // of racing a real one -- deterministic and instant.
        *manager.slot.lock() = Some(RunningJobInfo {
            id: "bk_shared".to_string(),
            kind: JobKind::Backup,
            scope: "all".to_string(),
            started_at: now_secs(),
        });
        let err = manager
            .start_restore("bk_shared", restore::RestoreMode::FailIfExists, None, false)
            .await
            .unwrap_err();
        assert!(matches!(err, BackupError::Busy));
    }

    // 3. ID collision -> "_2" suffix.
    #[tokio::test]
    async fn test_backup_id_collision_gets_suffix() {
        let (manager, _e, backup_dir) = make_manager().await;
        // Occupy the base id for this second AND the next, so the assertion
        // holds even when the wall clock rolls over between this now_secs()
        // call and the one inside allocate_backup_id (spec general/008:
        // no time-flaky tests).
        let now = now_secs();
        for ts in [now, now + 1] {
            let base_id = format!("bk_{}_kv", cron::format_utc_timestamp(ts));
            write_fake_backup(backup_dir.path(), &base_id, "kv", ts, None, true);
        }

        let (id, handle) = manager.start_backup(BackupScope::Kv, false, None).await.unwrap();
        assert!(id.ends_with("_2"), "colliding id must get a _2 suffix, got '{id}'");
        handle.await.unwrap();
    }

    // 4. Restore id collision also gets a suffix.
    #[tokio::test]
    async fn test_restore_id_collision_gets_suffix() {
        let (manager, _e, backup_dir) = make_manager().await;
        write_fake_backup(backup_dir.path(), "bk_x", "all", now_secs(), None, true);
        let ts = cron::format_utc_timestamp(now_secs());
        let base_id = format!("rs_{ts}");
        manager.restores.write().insert(
            base_id.clone(),
            RestoreStatus {
                restore_id: base_id.clone(),
                backup_id: "bk_x".to_string(),
                state: RestoreState::Running,
                imported: 0,
                skipped: 0,
                failed: 0,
                errors: Vec::new(),
                started_at: now_secs(),
                finished_at: None,
            },
        );

        let (id, handle) =
            manager.start_restore("bk_x", restore::RestoreMode::FailIfExists, None, false).await.unwrap();
        assert_eq!(id, format!("{base_id}_2"));
        handle.await.unwrap();
    }

    // 5. start_backup on an invalid/missing domain scope fails synchronously
    //    (no job slot ever gets taken).
    #[tokio::test]
    async fn test_start_backup_domain_not_found_is_synchronous() {
        let (manager, _e, _b) = make_manager().await;
        let err = manager
            .start_backup(BackupScope::KvDomain("nope".to_string()), false, None)
            .await
            .unwrap_err();
        assert!(matches!(err, BackupError::DomainNotFound(_)));
        assert!(manager.running_job().is_none(), "a rejected backup must never take the slot");
    }

    // 6. start_restore on an unknown backup id -> NotFound, synchronously.
    #[tokio::test]
    async fn test_start_restore_missing_backup_not_found() {
        let (manager, _e, _b) = make_manager().await;
        let err = manager
            .start_restore("bk_does_not_exist", restore::RestoreMode::FailIfExists, None, false)
            .await
            .unwrap_err();
        assert!(matches!(err, BackupError::NotFound));
    }

    // 7. get_restore_status reflects the completed job's outcome.
    #[tokio::test]
    async fn test_restore_status_reflects_completion() {
        let (manager, _e, backup_dir) = make_manager().await;
        write_fake_backup(backup_dir.path(), "bk_status", "all", now_secs(), None, true);
        let (id, handle) =
            manager.start_restore("bk_status", restore::RestoreMode::FailIfExists, None, false).await.unwrap();
        // The fake file's checksum won't verify -> the job fails, but the
        // status registry must still observe a terminal state.
        handle.await.unwrap();
        let status = manager.get_restore_status(&id).unwrap();
        assert_eq!(status.state, RestoreState::Failed);
        assert!(status.finished_at.is_some());
        assert!(!status.errors.is_empty());
    }

    // 8. list_backups: only `*.ndjson` files are listed (never `.part`), and
    //    complete vs incomplete is detected from the checksum tail-peek.
    #[tokio::test]
    async fn test_list_backups_complete_vs_incomplete() {
        let (manager, _e, backup_dir) = make_manager().await;
        write_fake_backup(backup_dir.path(), "bk_ok", "all", 1000, None, true);
        write_fake_backup(backup_dir.path(), "bk_bad", "all", 2000, None, false);
        std::fs::write(backup_dir.path().join("bk_running.ndjson.part"), "{}\n").unwrap();

        let mut list = manager.list_backups().unwrap();
        list.sort_by(|a, b| a.id.cmp(&b.id));
        assert_eq!(list.len(), 2, ".part files must never appear in the list");
        assert_eq!(list[0].id, "bk_bad");
        assert_eq!(list[0].state, BackupState::Incomplete);
        assert_eq!(list[1].id, "bk_ok");
        assert_eq!(list[1].state, BackupState::Complete);
    }

    // 9. get_backup / delete_backup basics: not-found, id validation, and
    //    busy-while-running.
    #[tokio::test]
    async fn test_get_and_delete_backup() {
        let (manager, _e, backup_dir) = make_manager().await;
        write_fake_backup(backup_dir.path(), "bk_del", "all", 1000, None, true);

        let summary = manager.get_backup("bk_del").unwrap();
        assert_eq!(summary.state, BackupState::Complete);

        assert!(matches!(manager.get_backup("bk_missing").unwrap_err(), BackupError::NotFound));
        assert!(matches!(manager.get_backup("../etc/passwd").unwrap_err(), BackupError::InvalidId(_)));

        *manager.slot.lock() = Some(RunningJobInfo {
            id: "bk_del".to_string(),
            kind: JobKind::Backup,
            scope: "all".to_string(),
            started_at: now_secs(),
        });
        assert!(matches!(manager.delete_backup("bk_del").unwrap_err(), BackupError::BackupRunning));
        *manager.slot.lock() = None;

        manager.delete_backup("bk_del").unwrap();
        assert!(matches!(manager.delete_backup("bk_del").unwrap_err(), BackupError::NotFound));
    }

    // 9b. The file name wins over the manifest id (upload case: the server
    //     assigns a fresh name; the archive keeps its original manifest id).
    #[tokio::test]
    async fn test_backup_identity_is_the_file_name_not_the_manifest_id() {
        let (manager, _e, backup_dir) = make_manager().await;
        write_fake_backup(backup_dir.path(), "bk_original", "all", 1000, None, true);
        std::fs::rename(
            backup_dir.path().join("bk_original.ndjson"),
            backup_dir.path().join("bk_uploaded.ndjson"),
        )
        .unwrap();

        let summary = manager.get_backup("bk_uploaded").unwrap();
        assert_eq!(summary.id, "bk_uploaded");
        let list = manager.list_backups().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "bk_uploaded");
        assert!(matches!(manager.get_backup("bk_original").unwrap_err(), BackupError::NotFound));
    }

    // 10. delete_backup refuses a backup whose id only has a lingering
    //     `.part` file (e.g. after a crash) even with a free slot.
    #[tokio::test]
    async fn test_delete_backup_refuses_lingering_part_file() {
        let (manager, _e, backup_dir) = make_manager().await;
        write_fake_backup(backup_dir.path(), "bk_p", "all", 1000, None, true);
        std::fs::write(backup_dir.path().join("bk_p.ndjson.part"), "{}\n").unwrap();
        assert!(matches!(manager.delete_backup("bk_p").unwrap_err(), BackupError::BackupRunning));
    }

    // 11. Retention keeps only the newest `keep_last` COMPLETE backups of one
    //     schedule; on-demand (`schedule = null`) backups are never touched,
    //     regardless of count, and other schedules are untouched.
    #[tokio::test]
    async fn test_retention_keeps_newest_per_schedule_only() {
        let (manager, _e, backup_dir) = make_manager().await;
        for (i, ts) in [1000u64, 2000, 3000, 4000].into_iter().enumerate() {
            write_fake_backup(backup_dir.path(), &format!("bk_nightly_{i}"), "all", ts, Some("nightly"), true);
        }
        write_fake_backup(backup_dir.path(), "bk_other_1", "all", 5000, Some("other-schedule"), true);
        write_fake_backup(backup_dir.path(), "bk_ondemand_1", "all", 6000, None, true);
        write_fake_backup(backup_dir.path(), "bk_ondemand_2", "all", 7000, None, true);
        // An incomplete "nightly" backup must not count toward keep_last nor be deleted by retention.
        write_fake_backup(backup_dir.path(), "bk_nightly_incomplete", "all", 8000, Some("nightly"), false);

        let deleted = manager.apply_retention("nightly", 2).unwrap();
        assert_eq!(deleted, 2, "must delete the two oldest complete 'nightly' backups");

        let remaining: std::collections::HashSet<String> =
            manager.list_backups().unwrap().into_iter().map(|b| b.id).collect();
        assert!(remaining.contains("bk_nightly_2"));
        assert!(remaining.contains("bk_nightly_3"));
        assert!(!remaining.contains("bk_nightly_0"));
        assert!(!remaining.contains("bk_nightly_1"));
        assert!(remaining.contains("bk_nightly_incomplete"), "incomplete backups are never touched by retention");
        assert!(remaining.contains("bk_other_1"), "other schedules must be untouched");
        assert!(remaining.contains("bk_ondemand_1"), "on-demand backups (schedule=null) are never touched");
        assert!(remaining.contains("bk_ondemand_2"));
    }

    #[test]
    fn test_civil_time_helper_reexported_for_scheduler_reuse() {
        // Smoke test that the shared helper (used for ID timestamps here,
        // and for cron minute-matching in the scheduler follow-up) is
        // reachable from this module.
        let t = cron::civil_from_unix(0);
        assert_eq!(t.year, 1970);
    }
}
