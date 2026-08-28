//! `ttl_sweeper` module
//!
//! Background task that removes TTL-expired keys proactively instead of
//! waiting for a compaction to happen over them (spec kv/025). Each removed
//! key gets a real tombstone plus the `delete` event of the ordinary write
//! path — the KV instance only, since JSON and rel never write an `expire_at`.

use crate::engines::lsm::engine::LsmStorageEngine;
use crate::engines::lsm::key::Timestamp;
use crate::storage::format::VersionState;
use anyhow::Result;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

/// Periodic TTL sweeper over one KV engine.
pub struct TtlSweeper {
    engine: Arc<LsmStorageEngine>,
    /// Candidates *checked* per tick — discarded ones count too (spec §6).
    batch_size: usize,
    interval: Duration,
    shutdown: Arc<AtomicBool>,
    /// Scan cursor kept across ticks, not persisted (spec kv/025 §3): the
    /// largest key checked last tick. It is what guarantees progress — a chunk
    /// consisting purely of false positives still moves it forward instead of
    /// blocking the lid for good. Empty means "start from the beginning".
    cursor: Mutex<Vec<u8>>,
}

impl TtlSweeper {
    pub fn new(
        engine: Arc<LsmStorageEngine>,
        shutdown: Arc<AtomicBool>,
        batch_size: usize,
        interval_secs: u64,
    ) -> Self {
        Self {
            engine,
            batch_size,
            interval: Duration::from_secs(interval_secs),
            shutdown,
            cursor: Mutex::new(Vec::new()),
        }
    }

    /// Runs the sweep loop until `shutdown` is set.
    pub async fn run(self: Arc<Self>) {
        while !self.shutdown.load(Ordering::Relaxed) {
            if let Err(e) = self.sweep_tick().await {
                eprintln!("[TtlSweeper] Error: {e}");
            }
            sleep(self.interval).await;
        }
    }

    /// One sweep cycle (spec kv/025 §3).
    pub async fn sweep_tick(&self) -> Result<()> {
        // 1./2. One freeze check, then pin — after this the tick never causes
        // a freeze itself, so no tombstone can land in a newer source than a
        // concurrent write to the same key (§4.2).
        self.engine.maybe_freeze_memtable().await?;
        let memtable = self.engine.pin_memtable();

        // 3. Candidate scan above the cursor (superset, no vLog access).
        let after = self.cursor.lock().clone();
        let candidates = self.engine.scan_expired(&after, self.batch_size).await?;

        // A short chunk means the end of the round was reached — wrap around.
        let next_cursor = if candidates.len() < self.batch_size {
            Vec::new()
        } else {
            candidates.last().cloned().unwrap_or_default()
        };

        let mut written = 0usize;
        for key in &candidates {
            // 4. Authoritative re-check: `Live`, `Tombstone` and "absent"
            // discard the candidate without write and without event (§5).
            if let Some((ts, VersionState::Expired)) = self.engine.newest_version(key).await? {
                // 5. Dated on the *re-check* stamp, never the scan's: the
                // smallest value above the version it displaces, so every
                // other write of this key beats it (§4.1). `Timestamp: Ord` is
                // inverted — arithmetic goes through `as_u64` only.
                let tombstone_ts = Timestamp::new(ts.as_u64() + 1);
                self.engine.write_tombstone_at(&memtable, key, tombstone_ts).await?;
                written += 1;
            }
        }

        *self.cursor.lock() = next_cursor;
        tracing::debug!(
            candidates = candidates.len(),
            written,
            skipped = candidates.len() - written,
            "TTL sweep tick"
        );
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::wal::WriteAheadLog;
    use crate::engines::lsm::engine::LsmEngineOptions;
    use crate::engines::lsm::reader::GetResult;
    use crate::engines::lsm::watcher::{OpType, WalEvent};
    use crate::engines::StorageEngine;
    use crate::storage::file_manager::FileManager;
    use crate::storage::manifest::ManifestManager;
    use crate::storage::vlog::VLog;
    use tokio::sync::broadcast::error::TryRecvError;

    async fn make_engine() -> (Arc<LsmStorageEngine>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let wal_path = dir.path().join("wal.log");
        let wal = Arc::new(WriteAheadLog::new(&wal_path).await.unwrap());
        let vlog_path = dir.path().join("vlog.log");
        let vlog = Arc::new(VLog::new(&vlog_path).await.unwrap());
        let file_manager = Arc::new(FileManager::new(dir.path()).await.unwrap());
        let manifest_manager = Arc::new(ManifestManager::new(dir.path()));
        let engine = LsmStorageEngine::new(
            wal, wal_path, vlog, vlog_path, file_manager, manifest_manager,
            LsmEngineOptions::default(),
        )
        .await
        .unwrap();
        (Arc::new(engine), dir)
    }

    fn sweeper(engine: &Arc<LsmStorageEngine>, batch_size: usize) -> TtlSweeper {
        TtlSweeper::new(
            Arc::clone(engine),
            Arc::new(AtomicBool::new(false)),
            batch_size,
            60,
        )
    }

    /// Drains the delete events currently queued on `rx` (the sweeper writes
    /// them synchronously inside the tick, so nothing is in flight afterwards).
    fn drained_deletes(rx: &mut tokio::sync::broadcast::Receiver<WalEvent>) -> Vec<Vec<u8>> {
        let mut keys = Vec::new();
        loop {
            match rx.try_recv() {
                Ok(event) => {
                    if matches!(event.op, OpType::Delete) {
                        keys.push(event.key);
                    }
                }
                Err(TryRecvError::Empty) | Err(TryRecvError::Closed) => return keys,
                Err(TryRecvError::Lagged(_)) => continue,
            }
        }
    }

    async fn state_of(engine: &LsmStorageEngine, key: &[u8]) -> Option<VersionState> {
        engine.newest_version(key).await.unwrap().map(|(_, state)| state)
    }

    // 1. Expiry -> delete event + a real tombstone (not just lazily filtered).
    #[tokio::test]
    async fn test_expired_key_yields_event_and_tombstone() {
        let (engine, _dir) = make_engine().await;
        engine.put_with_ttl(b"k", b"v", 0).await.unwrap();
        let mut rx = engine.watch_subscribe();

        sweeper(&engine, 500).sweep_tick().await.unwrap();

        assert_eq!(drained_deletes(&mut rx), vec![b"k".to_vec()]);
        assert_eq!(engine.get(b"k").await.unwrap(), None);
        assert_eq!(state_of(&engine, b"k").await, Some(VersionState::Tombstone));
    }

    // 2. Mechanism A without the sweeper: a tombstone dated on the expired
    // version loses against a newer write, in the MemTable ...
    #[tokio::test]
    async fn test_dated_tombstone_loses_against_newer_write() {
        let (engine, _dir) = make_engine().await;
        engine.put_with_ttl(b"k", b"old", 0).await.unwrap();
        let (observed, _) = engine.newest_version(b"k").await.unwrap().unwrap();

        engine.put(b"k", b"fresh").await.unwrap();
        let memtable = engine.pin_memtable();
        engine
            .write_tombstone_at(&memtable, b"k", Timestamp::new(observed.as_u64() + 1))
            .await
            .unwrap();

        assert_eq!(engine.get(b"k").await.unwrap(), Some(b"fresh".to_vec()));
    }

    // ... and across a flush plus compaction of the same sequence.
    #[tokio::test]
    async fn test_dated_tombstone_loses_against_newer_write_after_compaction() {
        let (engine, _dir) = make_engine().await;
        engine.put_with_ttl(b"k", b"old", 0).await.unwrap();
        let (observed, _) = engine.newest_version(b"k").await.unwrap().unwrap();

        engine.put(b"k", b"fresh").await.unwrap();
        let memtable = engine.pin_memtable();
        engine
            .write_tombstone_at(&memtable, b"k", Timestamp::new(observed.as_u64() + 1))
            .await
            .unwrap();

        engine.freeze_active_memtable();
        engine.flush_memtable().await.unwrap();
        engine.compact().await.unwrap();

        assert_eq!(engine.get(b"k").await.unwrap(), Some(b"fresh".to_vec()));
    }

    // 3. Mechanism B: the tombstone goes into the pinned (now immutable)
    // MemTable while the client value lands in the new active one — the freeze
    // inversion the pin rules out.
    #[tokio::test]
    async fn test_tombstone_in_pinned_memtable_loses_against_newer_source() {
        let (engine, _dir) = make_engine().await;
        engine.put_with_ttl(b"k", b"old", 0).await.unwrap();
        let (observed, _) = engine.newest_version(b"k").await.unwrap().unwrap();

        let memtable = engine.pin_memtable();
        engine.freeze_active_memtable();
        engine.put(b"k", b"client").await.unwrap();
        engine
            .write_tombstone_at(&memtable, b"k", Timestamp::new(observed.as_u64() + 1))
            .await
            .unwrap();

        assert_eq!(engine.get(b"k").await.unwrap(), Some(b"client".to_vec()));
    }

    // 4. A candidate revived with a live value between scan and re-check gets
    // neither a tombstone nor an event — the scan still lists it (its expired
    // old version is physically there), the re-check drops it.
    #[tokio::test]
    async fn test_recheck_suppresses_write_and_event() {
        let (engine, _dir) = make_engine().await;
        engine.put_with_ttl(b"k", b"old", 0).await.unwrap();
        engine.put(b"k", b"alive").await.unwrap();
        assert_eq!(engine.scan_expired(b"", 500).await.unwrap(), vec![b"k".to_vec()]);
        let mut rx = engine.watch_subscribe();

        sweeper(&engine, 500).sweep_tick().await.unwrap();

        assert!(drained_deletes(&mut rx).is_empty());
        assert_eq!(engine.get(b"k").await.unwrap(), Some(b"alive".to_vec()));
        assert_eq!(state_of(&engine, b"k").await, Some(VersionState::Live));
    }

    // 5. Replaced by an equally expired version: the tombstone is dated on the
    // re-check stamp, so it takes effect in this tick — no second one needed.
    #[tokio::test]
    async fn test_tombstone_dates_on_the_recheck_version() {
        let (engine, _dir) = make_engine().await;
        engine.put_with_ttl(b"k", b"first", 0).await.unwrap();
        engine.put_with_ttl(b"k", b"second", 0).await.unwrap();

        sweeper(&engine, 500).sweep_tick().await.unwrap();

        assert_eq!(engine.get(b"k").await.unwrap(), None);
        assert_eq!(state_of(&engine, b"k").await, Some(VersionState::Tombstone));
    }

    // 6. Idempotent without a flush of the pinned MemTable in between: the
    // second tick still sees the candidate but writes nothing and stays silent.
    #[tokio::test]
    async fn test_second_tick_writes_nothing_and_stays_silent() {
        let (engine, _dir) = make_engine().await;
        engine.put_with_ttl(b"k", b"v", 0).await.unwrap();
        let sweeper = sweeper(&engine, 500);
        sweeper.sweep_tick().await.unwrap();
        let mut rx = engine.watch_subscribe();

        sweeper.sweep_tick().await.unwrap();

        assert!(drained_deletes(&mut rx).is_empty());
        assert_eq!(state_of(&engine, b"k").await, Some(VersionState::Tombstone));
    }

    // 7. Disabled sweeper = today's behavior: `main.rs` starts no task, so the
    // key stays physically present and is invisible through the lazy filter only.
    #[tokio::test]
    async fn test_without_a_tick_the_expired_key_stays_physically_present() {
        let (engine, _dir) = make_engine().await;
        engine.put_with_ttl(b"k", b"v", 0).await.unwrap();

        assert_eq!(engine.get(b"k").await.unwrap(), None);
        assert_eq!(state_of(&engine, b"k").await, Some(VersionState::Expired));
        assert!(crate::config::TtlSweeperCfg::default().enabled);
    }

    // 8. Keys without a TTL, NULL keys (kv/018) and already tombstoned ones
    // are never candidates.
    #[tokio::test]
    async fn test_no_candidates_without_expiry() {
        let (engine, _dir) = make_engine().await;
        engine.put(b"plain", b"v").await.unwrap();
        engine.set_null(b"null").await.unwrap();
        engine.put(b"gone", b"v").await.unwrap();
        engine.delete(b"gone").await.unwrap();
        let mut rx = engine.watch_subscribe();

        assert!(engine.scan_expired(b"", 500).await.unwrap().is_empty());
        sweeper(&engine, 500).sweep_tick().await.unwrap();

        assert!(drained_deletes(&mut rx).is_empty());
        assert_eq!(engine.get(b"plain").await.unwrap(), Some(b"v".to_vec()));
        assert_eq!(state_of(&engine, b"null").await, Some(VersionState::Live));
    }

    // 9. Chunk boundary: the first tick clears exactly `batch_size` keys, the
    // second one the rest.
    #[tokio::test]
    async fn test_chunk_boundary_splits_over_two_ticks() {
        let (engine, _dir) = make_engine().await;
        for i in 0..7u32 {
            engine.put_with_ttl(format!("k{i}").as_bytes(), b"v", 0).await.unwrap();
        }
        let sweeper = sweeper(&engine, 5);
        let mut rx = engine.watch_subscribe();

        sweeper.sweep_tick().await.unwrap();
        assert_eq!(drained_deletes(&mut rx).len(), 5);

        sweeper.sweep_tick().await.unwrap();
        assert_eq!(drained_deletes(&mut rx).len(), 2);
        for i in 0..7u32 {
            let key = format!("k{i}");
            assert_eq!(state_of(&engine, key.as_bytes()).await, Some(VersionState::Tombstone));
        }
    }

    // 10. Cursor progress (blocker regression): more false positives than
    // `batch_size` sort ahead of the one genuinely expired key. Without the
    // cursor that key would stay behind forever.
    #[tokio::test]
    async fn test_cursor_advances_past_false_positives() {
        let (engine, _dir) = make_engine().await;
        for i in 0..6u32 {
            let key = format!("a{i}");
            engine.put_with_ttl(key.as_bytes(), b"old", 0).await.unwrap();
            engine.put(key.as_bytes(), b"alive").await.unwrap();
        }
        engine.put_with_ttl(b"z", b"v", 0).await.unwrap();
        let sweeper = sweeper(&engine, 5);
        let mut rx = engine.watch_subscribe();

        sweeper.sweep_tick().await.unwrap();
        assert!(drained_deletes(&mut rx).is_empty(), "all five candidates are false positives");
        assert_eq!(*sweeper.cursor.lock(), b"a4".to_vec());

        sweeper.sweep_tick().await.unwrap();
        assert_eq!(drained_deletes(&mut rx), vec![b"z".to_vec()]);
        assert_eq!(state_of(&engine, b"z").await, Some(VersionState::Tombstone));
        assert!(sweeper.cursor.lock().is_empty(), "a short chunk wraps the cursor around");
    }

    // The candidate scan sees expired versions in SSTables too, not just in
    // MemTables — otherwise a flushed key would never be swept.
    #[tokio::test]
    async fn test_sweeps_expired_key_from_sstable() {
        let (engine, _dir) = make_engine().await;
        engine.put_with_ttl(b"k", b"v", 0).await.unwrap();
        engine.freeze_active_memtable();
        engine.flush_memtable().await.unwrap();

        sweeper(&engine, 500).sweep_tick().await.unwrap();

        assert_eq!(state_of(&engine, b"k").await, Some(VersionState::Tombstone));
    }

    // The re-check reports state, not just presence: expired and absent are
    // distinguishable, which `get_with_metadata` cannot do (spec kv/025 §3.1).
    #[tokio::test]
    async fn test_newest_version_distinguishes_expired_from_absent() {
        let (engine, _dir) = make_engine().await;
        engine.put_with_ttl(b"k", b"v", 0).await.unwrap();
        let snapshot = engine.snapshot();

        assert_eq!(state_of(&engine, b"k").await, Some(VersionState::Expired));
        assert_eq!(state_of(&engine, b"missing").await, None);
        assert_eq!(engine.get_with_metadata(b"k", snapshot.snapshot()).await.unwrap(), None);
        assert_eq!(
            engine.get_with_metadata(b"missing", snapshot.snapshot()).await.unwrap(),
            None
        );
        assert_eq!(
            engine.get_with_snapshot(b"k", snapshot.snapshot()).await.unwrap(),
            GetResult::Absent
        );
    }
}
