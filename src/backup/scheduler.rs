//! Backup scheduler (spec general/006 "Scheduler"): a tokio task that ticks
//! once a minute, matches every configured schedule's cron expression against
//! the current UTC minute, and starts a backup job on a match. Retention runs
//! after a scheduled job completes successfully.
//!
//! Follows the `DomainPurger`/`JsonDomainPurger` pattern (`src/engines/lsm/domain.rs`):
//! a thin `run` loop (sleep + tick) around a pure, directly-testable `tick`.

use super::cron::CronSchedule;
use super::{cron, BackupError, BackupManager, BackupScope, BackupState};
use crate::config::BackupScheduleConfig;
use crate::engines::lsm::domain::now_secs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// One `[[backup.schedule]]` entry, pre-parsed at scheduler construction
/// (config was already validated at startup — `BackupConfig::validate` — so
/// parsing here cannot fail in practice; it is still propagated, not
/// unwrapped, to avoid a panic on any future validation gap).
struct SchedulerEntry {
    name: String,
    cron: CronSchedule,
    scope: BackupScope,
    include_auth: bool,
    keep_last: usize,
}

impl SchedulerEntry {
    fn from_config(cfg: &BackupScheduleConfig) -> anyhow::Result<Self> {
        Ok(Self {
            name: cfg.name.clone(),
            cron: CronSchedule::parse(&cfg.cron)?,
            scope: BackupScope::parse(&cfg.scope)?,
            include_auth: cfg.include_auth,
            keep_last: cfg.keep_last,
        })
    }
}

pub struct BackupScheduler {
    manager: Arc<BackupManager>,
    entries: Vec<SchedulerEntry>,
    shutdown: Arc<AtomicBool>,
}

impl BackupScheduler {
    pub fn new(
        manager: Arc<BackupManager>,
        schedules: &[BackupScheduleConfig],
        shutdown: Arc<AtomicBool>,
    ) -> anyhow::Result<Self> {
        let entries = schedules.iter().map(SchedulerEntry::from_config).collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Self { manager, entries, shutdown })
    }

    /// Runs the tick loop until `shutdown` is set (fire-and-forget, matching
    /// the purger tasks — not joined during graceful shutdown).
    pub async fn run(self: Arc<Self>) {
        while !self.shutdown.load(Ordering::Relaxed) {
            // Sleep to the next minute boundary before ticking, like classic
            // cron: ticks only ever land on a boundary, so a start inside an
            // already-matching minute does not re-fire that slot (no
            // catch-up). Sleeping to the boundary instead of a flat 60s also
            // avoids drifting by the tick's own duration each round.
            let sleep_secs = 60 - (now_secs() % 60);
            tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }
            self.tick(now_secs()).await;
        }
    }

    /// One minute tick: evaluates every schedule's cron against `now`'s UTC
    /// calendar fields (spec general/006 "Scheduler" — match against the
    /// current minute, not next-fire computation; no catch-up of missed
    /// ticks). Pure/callable so tests can drive it directly without a real
    /// 60s sleep loop.
    pub async fn tick(&self, now: u64) {
        let t = cron::civil_from_unix(now);
        for entry in &self.entries {
            if !entry.cron.matches(t.minute, t.hour, t.day, t.month, t.weekday) {
                continue;
            }
            match self.manager.start_backup(entry.scope.clone(), entry.include_auth, Some(entry.name.clone())).await
            {
                Ok((id, handle)) => {
                    tokio::spawn(retain_after_success(
                        Arc::clone(&self.manager),
                        id,
                        entry.name.clone(),
                        entry.keep_last,
                        handle,
                    ));
                }
                // Spec step 1: slot busy -> skip this tick, warn, no catch-up.
                Err(BackupError::Busy) => {
                    tracing::warn!(
                        "[Backup Scheduler] job slot busy, skipping this tick for schedule '{}'",
                        entry.name
                    );
                }
                // A schedule pointing at a missing domain (or any other
                // synchronous rejection) fails at runtime and is logged —
                // spec general/006 startup validation — the scheduler
                // itself must never abort on one bad schedule.
                Err(e) => {
                    tracing::warn!("[Backup Scheduler] schedule '{}' failed to start: {e}", entry.name);
                }
            }
        }
    }
}

/// Waits for a scheduled backup job to finish, then applies retention
/// (spec general/006 Scheduler step 3) if — and only if — it actually
/// produced a complete backup. Split out from `tick` so tests can await it
/// directly instead of racing a detached `tokio::spawn`.
async fn retain_after_success(
    manager: Arc<BackupManager>,
    id: String,
    schedule_name: String,
    keep_last: usize,
    handle: tokio::task::JoinHandle<()>,
) {
    let _ = handle.await;
    let succeeded = manager.get_backup(&id).is_ok_and(|b| b.state == BackupState::Complete);
    if succeeded {
        if let Err(e) = manager.apply_retention(&schedule_name, keep_last) {
            tracing::warn!("[Backup Scheduler] retention for '{schedule_name}' failed: {e:#}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::{JobKind, RunningJobInfo};
    use crate::config::BackupConfig;
    use crate::engines::lsm::domain::{DomainConfig, DomainRegistry};
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

    fn always_matching_schedule(name: &str) -> BackupScheduleConfig {
        BackupScheduleConfig {
            name: name.to_string(),
            cron: "* * * * *".to_string(),
            scope: "all".to_string(),
            include_auth: false,
            keep_last: 2,
        }
    }

    fn never_matching_schedule(name: &str) -> BackupScheduleConfig {
        // The test drives tick() with a fixed `now` (the Unix epoch,
        // 1970-01-01T00:00:00Z) that this cron can never match: minute 0 != 5.
        BackupScheduleConfig {
            name: name.to_string(),
            cron: "5 0 1 1 0".to_string(),
            scope: "all".to_string(),
            include_auth: false,
            keep_last: 2,
        }
    }

    // 1. Tick skips a matching schedule while the job slot is busy (spec
    //    general/006 Scheduler step 1) -- the pre-existing running job must
    //    be left completely undisturbed.
    #[tokio::test]
    async fn test_tick_skips_matching_schedule_when_slot_busy() {
        let (manager, _e, _b) = make_manager().await;
        *manager.slot.lock() = Some(RunningJobInfo {
            id: "bk_manual".to_string(),
            kind: JobKind::Backup,
            scope: "all".to_string(),
            started_at: now_secs(),
        });

        let scheduler =
            BackupScheduler::new(Arc::clone(&manager), &[always_matching_schedule("nightly")], Arc::new(AtomicBool::new(false)))
                .unwrap();
        scheduler.tick(now_secs()).await;

        let job = manager.running_job().expect("the pre-existing job must still be there");
        assert_eq!(job.id, "bk_manual", "tick must not have started (and overwritten) a new job");
        assert!(manager.list_backups().unwrap().is_empty(), "no backup file must have been produced");
    }

    // 2. Tick starts a backup when a schedule's cron matches and the slot is
    //    free (spec general/006 Scheduler step 2).
    #[tokio::test]
    async fn test_tick_starts_backup_when_cron_matches_and_slot_free() {
        let (manager, _e, _b) = make_manager().await;
        let scheduler =
            BackupScheduler::new(Arc::clone(&manager), &[always_matching_schedule("nightly")], Arc::new(AtomicBool::new(false)))
                .unwrap();

        scheduler.tick(now_secs()).await;

        let job = manager.running_job().expect("a matching schedule with a free slot must start a job");
        assert_eq!(job.kind, JobKind::Backup);
        assert_eq!(job.scope, "all");
    }

    // 3. A schedule whose cron does not match `now` never touches the slot.
    #[tokio::test]
    async fn test_tick_skips_non_matching_cron() {
        let (manager, _e, _b) = make_manager().await;
        let scheduler = BackupScheduler::new(
            Arc::clone(&manager),
            &[never_matching_schedule("rare")],
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();

        // Use a `now` that is guaranteed not to be 00:05:00 UTC on a Sunday
        // Jan 1st -- the Unix epoch itself (1970-01-01T00:00:00Z, minute 0).
        scheduler.tick(0).await;

        assert!(manager.running_job().is_none());
    }

    // 4. Two schedules matching the same tick: the first takes the slot, the
    //    second's start_backup synchronously observes Busy and is skipped
    //    (not a panic, not an error propagated to the caller).
    #[tokio::test]
    async fn test_tick_second_matching_schedule_in_same_tick_gets_busy() {
        let (manager, _e, _b) = make_manager().await;
        let scheduler = BackupScheduler::new(
            Arc::clone(&manager),
            &[always_matching_schedule("first"), always_matching_schedule("second")],
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap();

        scheduler.tick(now_secs()).await;

        let job = manager.running_job().expect("the first schedule must have started a job");
        // ID suffix carries the schedule name (spec: "ID-Suffix = Schedule-Name").
        assert!(job.id.ends_with("_first"), "the first schedule must have won the slot, got id '{}'", job.id);
    }

    // 5. retain_after_success applies retention only for its own schedule
    //    after a successful run; on-demand backups are untouched (wiring
    //    test -- apply_retention's own scope-filtering is covered in
    //    backup::mod's unit tests already).
    #[tokio::test]
    async fn test_retain_after_success_applies_retention_for_own_schedule_only() {
        let (manager, _e, backup_dir) = make_manager().await;
        // Two pre-existing complete "nightly" backups plus keep_last=2 means
        // a third successful run must push the retention count to "delete 1".
        for (i, ts) in [1000u64, 2000].into_iter().enumerate() {
            write_fake_backup(backup_dir.path(), &format!("bk_nightly_{i}"), "all", ts, Some("nightly"), true);
        }
        write_fake_backup(backup_dir.path(), "bk_ondemand", "all", 3000, None, true);

        let (id, handle) = manager.start_backup(BackupScope::All, false, Some("nightly".to_string())).await.unwrap();
        retain_after_success(Arc::clone(&manager), id.clone(), "nightly".to_string(), 2, handle).await;

        let remaining: std::collections::HashSet<String> =
            manager.list_backups().unwrap().into_iter().map(|b| b.id).collect();
        assert!(remaining.contains(&id), "the just-completed run must survive its own retention pass");
        assert!(remaining.contains("bk_nightly_1"), "newest of the two pre-existing backups must survive");
        assert!(!remaining.contains("bk_nightly_0"), "oldest pre-existing backup must be pruned (keep_last=2)");
        assert!(remaining.contains("bk_ondemand"), "on-demand backups (schedule=null) are never touched");
    }

    // 6. retain_after_success is a no-op when the job failed -- nothing gets
    //    deleted (a failed run must never trigger retention on a schedule's
    //    otherwise-healthy backup history).
    #[tokio::test]
    async fn test_retain_after_success_skips_retention_on_failed_job() {
        let (manager, _e, backup_dir) = make_manager().await;
        write_fake_backup(backup_dir.path(), "bk_nightly_0", "all", 1000, Some("nightly"), true);
        write_fake_backup(backup_dir.path(), "bk_nightly_1", "all", 2000, Some("nightly"), true);

        // A restore against a nonexistent backup id fails synchronously
        // (BackupError::NotFound) -- simulate the "job never produced a file"
        // case directly against retain_after_success with a fabricated id
        // and an already-finished no-op handle.
        let handle = tokio::spawn(async {});
        retain_after_success(Arc::clone(&manager), "bk_never_existed".to_string(), "nightly".to_string(), 1, handle)
            .await;

        let remaining: std::collections::HashSet<String> =
            manager.list_backups().unwrap().into_iter().map(|b| b.id).collect();
        assert!(remaining.contains("bk_nightly_0"), "retention must not run when the job produced no backup");
        assert!(remaining.contains("bk_nightly_1"));
    }

    // 7. run() must not tick while shutting down: it returns without starting
    //    a backup even though the schedule matches every minute.
    #[tokio::test]
    async fn test_run_does_not_tick_when_shutdown_is_set() {
        let (manager, _e, _b) = make_manager().await;
        let scheduler = Arc::new(
            BackupScheduler::new(
                Arc::clone(&manager),
                &[always_matching_schedule("nightly")],
                Arc::new(AtomicBool::new(true)),
            )
            .unwrap(),
        );

        scheduler.run().await;

        assert!(manager.running_job().is_none(), "a shutting-down scheduler must not start a backup");
    }

    /// Mirrors `backup::mod::manager_tests::write_fake_backup` -- duplicated
    /// (not exported) since it is a tiny test-only fixture and the source
    /// module's test helpers are private to it.
    fn write_fake_backup(dir: &std::path::Path, id: &str, scope: &str, created_at: u64, schedule: Option<&str>, complete: bool) {
        use crate::backup::writer;
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
}
