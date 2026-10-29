//! `ttl_sweeper` module
//!
//! Background task that removes TTL-expired keys proactively instead of
//! waiting for a compaction to happen over them. Each removed
//! key gets a real tombstone plus the `delete` event of the ordinary write
//! path — the KV instance only, since JSON and rel never write an `expire_at`.

use crate::engines::lsm::engine::LsmStorageEngine;
use crate::engines::lsm::key::Timestamp;
use crate::storage::format::VersionState;
use anyhow::Result;
use parking_lot::Mutex;
use std::sync::Arc;

/// Periodic TTL sweeper over one KV engine.
pub struct TtlSweeper {
    engine: Arc<LsmStorageEngine>,
    /// Candidates *checked* per tick — discarded ones count too.
    batch_size: usize,
    /// Scan cursor kept across ticks, not persisted: the
    /// largest key settled last tick. It is what guarantees progress — a chunk
    /// consisting purely of false positives still moves it forward instead of
    /// blocking the lid for good. Empty means "start from the beginning".
    cursor: Mutex<Vec<u8>>,
}

impl TtlSweeper {
    pub fn new(engine: Arc<LsmStorageEngine>, batch_size: usize) -> Self {
        Self { engine, batch_size, cursor: Mutex::new(Vec::new()) }
    }

    /// One sweep cycle.
    pub async fn sweep_tick(&self) -> Result<()> {
        // 1./2. One freeze check, then pin — after this the tick never causes
        // a freeze itself, so no tombstone can land in a newer source than a
        // concurrent write to the same key.
        self.engine.maybe_freeze_memtable().await?;
        let memtable = self.engine.pin_memtable();

        // 3. Candidate scan above the cursor (superset, no vLog access).
        let after = self.cursor.lock().clone();
        let candidates = self.engine.scan_expired(&after, self.batch_size).await?;

        // A short chunk means the end of the round was reached — wrap around.
        let mut next_cursor = if candidates.len() < self.batch_size {
            Vec::new()
        } else {
            candidates.last().cloned().unwrap_or_default()
        };

        let mut written = 0usize;
        for (i, key) in candidates.iter().enumerate() {
            // Read before the re-check: a checkpoint counted after it drops
            // the tombstone.
            let checkpoint = self.engine.checkpoint_count();
            // 4. Authoritative re-check: `Live`, `Tombstone` and "absent"
            // discard the candidate without write and without event.
            if let Some((ts, VersionState::Expired)) = self.engine.newest_version(key).await? {
                #[cfg(test)]
                if let Some(hook) = &self.engine.hooks.after_sweep_recheck {
                    hook.pause().await;
                }
                // 5. Dated on the *re-check* stamp, never the scan's: the
                // smallest value above the version it displaces, so every
                // other write of this key beats it. `Timestamp: Ord` is
                // inverted — arithmetic goes through `as_u64` only.
                let tombstone_ts = Timestamp::new(ts.as_u64() + 1);
                if !self.engine.write_tombstone_at(&memtable, key, tombstone_ts, checkpoint).await? {
                    // A checkpoint came between: end the tick so the next
                    // one checks this key again.
                    next_cursor = if i == 0 { after } else { candidates[i - 1].clone() };
                    break;
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::storage_thread::{TestHub, WalTarget};
    use crate::core::wal::WriteAheadLog;
    use crate::engines::lsm::engine::{LsmEngineOptions, TestHook, TestHooks};
    use crate::engines::lsm::hlc::HLCTimestamp;
    use crate::engines::lsm::reader::{GetResult, Snapshot};
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
        TtlSweeper::new(Arc::clone(engine), batch_size)
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
    #[test]
    fn test_expired_key_yields_event_and_tombstone() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put_expired_for_test(b"k", b"v").await.unwrap();
            let mut rx = engine.watch_subscribe();

            sweeper(&engine, 500).sweep_tick().await.unwrap();

            assert_eq!(drained_deletes(&mut rx), vec![b"k".to_vec()]);
            assert_eq!(engine.get(b"k").await.unwrap(), None);
            assert_eq!(state_of(&engine, b"k").await, Some(VersionState::Tombstone));
        })
    }

    // 2. Without the sweeper: a tombstone dated on the expired
    // version loses against a newer write, in the MemTable ...
    #[test]
    fn test_dated_tombstone_loses_against_newer_write() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put_expired_for_test(b"k", b"old").await.unwrap();
            let (observed, _) = engine.newest_version(b"k").await.unwrap().unwrap();

            engine.put(b"k", b"fresh").await.unwrap();
            let memtable = engine.pin_memtable();
            engine
                .write_tombstone_at(&memtable, b"k", Timestamp::new(observed.as_u64() + 1), engine.checkpoint_count())
                .await
                .unwrap();

            assert_eq!(engine.get(b"k").await.unwrap(), Some(b"fresh".to_vec()));
        })
    }

    // ... and across a flush plus compaction of the same sequence.
    #[test]
    fn test_dated_tombstone_loses_against_newer_write_after_compaction() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put_expired_for_test(b"k", b"old").await.unwrap();
            let (observed, _) = engine.newest_version(b"k").await.unwrap().unwrap();

            engine.put(b"k", b"fresh").await.unwrap();
            let memtable = engine.pin_memtable();
            engine
                .write_tombstone_at(&memtable, b"k", Timestamp::new(observed.as_u64() + 1), engine.checkpoint_count())
                .await
                .unwrap();

            engine.freeze_active_memtable();
            engine.flush_memtable().await.unwrap();
            engine.compact().await.unwrap();

            assert_eq!(engine.get(b"k").await.unwrap(), Some(b"fresh".to_vec()));
        })
    }

    // 3. The tombstone goes into the pinned (now immutable)
    // MemTable while the client value lands in the new active one — the freeze
    // inversion the pin rules out.
    #[test]
    fn test_tombstone_in_pinned_memtable_loses_against_newer_source() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put_expired_for_test(b"k", b"old").await.unwrap();
            let (observed, _) = engine.newest_version(b"k").await.unwrap().unwrap();

            let memtable = engine.pin_memtable();
            engine.freeze_active_memtable();
            engine.put(b"k", b"client").await.unwrap();
            engine
                .write_tombstone_at(&memtable, b"k", Timestamp::new(observed.as_u64() + 1), engine.checkpoint_count())
                .await
                .unwrap();

            assert_eq!(engine.get(b"k").await.unwrap(), Some(b"client".to_vec()));
        })
    }

    // 4. A candidate revived with a live value between scan and re-check gets
    // neither a tombstone nor an event — the scan still lists it (its expired
    // old version is physically there), the re-check drops it.
    #[test]
    fn test_recheck_suppresses_write_and_event() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put_expired_for_test(b"k", b"old").await.unwrap();
            engine.put(b"k", b"alive").await.unwrap();
            assert_eq!(engine.scan_expired(b"", 500).await.unwrap(), vec![b"k".to_vec()]);
            let mut rx = engine.watch_subscribe();

            sweeper(&engine, 500).sweep_tick().await.unwrap();

            assert!(drained_deletes(&mut rx).is_empty());
            assert_eq!(engine.get(b"k").await.unwrap(), Some(b"alive".to_vec()));
            assert_eq!(state_of(&engine, b"k").await, Some(VersionState::Live));
        })
    }

    // 5. Replaced by an equally expired version: the tombstone is dated on the
    // re-check stamp, so it takes effect in this tick — no second one needed.
    #[test]
    fn test_tombstone_dates_on_the_recheck_version() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put_expired_for_test(b"k", b"first").await.unwrap();
            engine.put_expired_for_test(b"k", b"second").await.unwrap();

            sweeper(&engine, 500).sweep_tick().await.unwrap();

            assert_eq!(engine.get(b"k").await.unwrap(), None);
            assert_eq!(state_of(&engine, b"k").await, Some(VersionState::Tombstone));
        })
    }

    // 6. Idempotent without a flush of the pinned MemTable in between: the
    // second tick still sees the candidate but writes nothing and stays silent.
    #[test]
    fn test_second_tick_writes_nothing_and_stays_silent() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put_expired_for_test(b"k", b"v").await.unwrap();
            let sweeper = sweeper(&engine, 500);
            sweeper.sweep_tick().await.unwrap();
            let mut rx = engine.watch_subscribe();

            sweeper.sweep_tick().await.unwrap();

            assert!(drained_deletes(&mut rx).is_empty());
            assert_eq!(state_of(&engine, b"k").await, Some(VersionState::Tombstone));
        })
    }

    // 7. Disabled sweeper = today's behavior: `main.rs` starts no task, so the
    // key stays physically present and is invisible through the lazy filter only.
    #[test]
    fn test_without_a_tick_the_expired_key_stays_physically_present() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put_expired_for_test(b"k", b"v").await.unwrap();

            assert_eq!(engine.get(b"k").await.unwrap(), None);
            assert_eq!(state_of(&engine, b"k").await, Some(VersionState::Expired));
            assert!(crate::config::TtlSweeperCfg::default().enabled);
        })
    }

    // 8. Keys without a TTL, NULL keys and already tombstoned ones
    // are never candidates.
    #[test]
    fn test_no_candidates_without_expiry() {
        crate::core::engine_runtime::block_on(async {
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
        })
    }

    // 9. Chunk boundary: the first tick clears exactly `batch_size` keys, the
    // second one the rest.
    #[test]
    fn test_chunk_boundary_splits_over_two_ticks() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            for i in 0..7u32 {
                engine.put_expired_for_test(format!("k{i}").as_bytes(), b"v").await.unwrap();
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
        })
    }

    // 10. Cursor progress (blocker regression): more false positives than
    // `batch_size` sort ahead of the one genuinely expired key. Without the
    // cursor that key would stay behind forever.
    #[test]
    fn test_cursor_advances_past_false_positives() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            for i in 0..6u32 {
                let key = format!("a{i}");
                engine.put_expired_for_test(key.as_bytes(), b"old").await.unwrap();
                engine.put(key.as_bytes(), b"alive").await.unwrap();
            }
            engine.put_expired_for_test(b"z", b"v").await.unwrap();
            let sweeper = sweeper(&engine, 5);
            let mut rx = engine.watch_subscribe();

            sweeper.sweep_tick().await.unwrap();
            assert!(drained_deletes(&mut rx).is_empty(), "all five candidates are false positives");
            assert_eq!(*sweeper.cursor.lock(), b"a4".to_vec());

            sweeper.sweep_tick().await.unwrap();
            assert_eq!(drained_deletes(&mut rx), vec![b"z".to_vec()]);
            assert_eq!(state_of(&engine, b"z").await, Some(VersionState::Tombstone));
            assert!(sweeper.cursor.lock().is_empty(), "a short chunk wraps the cursor around");
        })
    }

    // The candidate scan sees expired versions in SSTables too, not just in
    // MemTables — otherwise a flushed key would never be swept.
    #[test]
    fn test_sweeps_expired_key_from_sstable() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put_expired_for_test(b"k", b"v").await.unwrap();
            engine.freeze_active_memtable();
            engine.flush_memtable().await.unwrap();

            sweeper(&engine, 500).sweep_tick().await.unwrap();

            assert_eq!(state_of(&engine, b"k").await, Some(VersionState::Tombstone));
        })
    }

    // The re-check reports state, not just presence: expired and absent are
    // distinguishable, which `get_with_metadata` cannot do.
    #[test]
    fn test_newest_version_distinguishes_expired_from_absent() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put_expired_for_test(b"k", b"v").await.unwrap();
            let snapshot = engine.snapshot().await;

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
        })
    }

    // A client write that drew the tombstone's stamp
    // (`ts + 1`) and landed first keeps its entry; tombstone and event drop.
    #[test]
    fn test_tombstone_on_identical_internal_key_keeps_client_value() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put(b"k", b"client").await.unwrap();
            let (client_ts, _) = engine.newest_version(b"k").await.unwrap().unwrap();
            let memtable = engine.pin_memtable();
            let mut rx = engine.watch_subscribe();

            engine.write_tombstone_at(&memtable, b"k", client_ts, engine.checkpoint_count()).await.unwrap();

            assert!(drained_deletes(&mut rx).is_empty());
            assert_eq!(engine.get(b"k").await.unwrap(), Some(b"client".to_vec()));
        })
    }

    // Regression: the tombstone landed first, the client
    // write with the same stamp replaces it.
    #[test]
    fn test_client_write_replaces_tombstone_on_identical_internal_key() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            // Far ahead of the wall clock: the next stamp is exactly `seed + 1`.
            let seed = HLCTimestamp::from_components(1 << 47, 0).as_u64();
            engine.hlc().seed(seed);
            let tie = Timestamp::new(seed + 1);
            let memtable = engine.pin_memtable();

            engine.write_tombstone_at(&memtable, b"k", tie, engine.checkpoint_count()).await.unwrap();
            engine.put(b"k", b"client").await.unwrap();

            let (newest_ts, _) = engine.newest_version(b"k").await.unwrap().unwrap();
            assert_eq!(newest_ts.as_u64(), tie.as_u64(), "the client write must tie with the tombstone");
            assert_eq!(engine.get(b"k").await.unwrap(), Some(b"client".to_vec()));
        })
    }

    // The same tie across sources: the tombstone sits in the pinned, older
    // MemTable, the client write in the newer one. Reads take the newer
    // source, and a compaction of both flushed tables must decide the same.
    #[test]
    fn test_tie_across_sources_keeps_the_client_value_through_compaction() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            // Far ahead of the wall clock: the next stamp is exactly `seed + 1`.
            let seed = HLCTimestamp::from_components(1 << 47, 0).as_u64();
            engine.hlc().seed(seed);
            let tie = Timestamp::new(seed + 1);
            let pinned = engine.pin_memtable();
            engine.freeze_active_memtable();

            engine.put(b"k", b"client").await.unwrap();
            engine.write_tombstone_at(&pinned, b"k", tie, engine.checkpoint_count()).await.unwrap();
            let (newest_ts, _) = engine.newest_version(b"k").await.unwrap().unwrap();
            assert_eq!(newest_ts.as_u64(), tie.as_u64(), "the client write must tie with the tombstone");
            assert_eq!(engine.get(b"k").await.unwrap(), Some(b"client".to_vec()));

            engine.freeze_active_memtable();
            engine.flush_memtable().await.unwrap();
            engine.flush_memtable().await.unwrap();
            engine.compact().await.unwrap();

            assert_eq!(engine.get(b"k").await.unwrap(), Some(b"client".to_vec()));
        })
    }

    // The same tie above the low watermark: a snapshot registered below it
    // keeps every version the tie holds, yet the compaction writes each
    // internal key once -- the newer source's entry, the one reads see. A
    // second entry could open the next data block, where a read at the tie
    // would find the tombstone.
    #[test]
    fn test_tie_above_the_watermark_leaves_one_entry_after_compaction() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let below = engine.snapshot().await;
            // Far ahead of the wall clock: the next stamp is exactly `seed + 1`.
            let seed = HLCTimestamp::from_components(1 << 47, 0).as_u64();
            engine.hlc().seed(seed);
            let tie = Timestamp::new(seed + 1);
            assert!(below.snapshot().timestamp().as_u64() < tie.as_u64());
            let pinned = engine.pin_memtable();
            engine.freeze_active_memtable();

            engine.put(b"k", b"client").await.unwrap();
            engine.write_tombstone_at(&pinned, b"k", tie, engine.checkpoint_count()).await.unwrap();
            engine.freeze_active_memtable();
            engine.flush_memtable().await.unwrap();
            engine.flush_memtable().await.unwrap();
            engine.compact().await.unwrap();

            let entries: usize = engine.version().level(1).iter().map(|t| t.iter().count()).sum();
            assert_eq!(entries, 1, "one entry per internal key");
            assert_eq!(
                engine.get_with_snapshot(b"k", &Snapshot::new(tie)).await.unwrap(),
                GetResult::Present(b"client".to_vec())
            );
            drop(below);
        })
    }

    // The dropped tombstone adds no bytes to the MemTable size.
    #[test]
    fn test_dropped_tombstone_adds_no_bytes() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put(b"k", b"client").await.unwrap();
            let (client_ts, _) = engine.newest_version(b"k").await.unwrap().unwrap();
            let memtable = engine.pin_memtable();

            engine.write_tombstone_at(&memtable, b"k", client_ts, engine.checkpoint_count()).await.unwrap();

            // The client entry only: 1-byte user key + 8-byte stamp + 6 value bytes.
            assert_eq!(memtable.size_bytes(), 1 + 8 + 6);
        })
    }

    /// A key-value engine with `hooks` on the log `<dir>/wal` of `hub`; it
    /// replays the log when it opens.
    async fn engine_on_hub(dir: &std::path::Path, hub: &TestHub, hooks: TestHooks) -> Arc<LsmStorageEngine> {
        let (wal_path, vlog_path) = (dir.join("wal"), dir.join("vlog.log"));
        let wal = Arc::new(hub.wal(WalTarget::Kv));
        let vlog = Arc::new(VLog::new(&vlog_path).await.unwrap());
        let file_manager = Arc::new(FileManager::new(dir).await.unwrap());
        let manifest_manager = Arc::new(ManifestManager::new(dir));
        let options = LsmEngineOptions::default();
        let mut engine =
            LsmStorageEngine::new(wal, wal_path, vlog, vlog_path, file_manager, manifest_manager, options).await.unwrap();
        engine.hooks = hooks;
        Arc::new(engine)
    }

    /// An engine on a hub of its own over `<dir>/wal`, with `hooks`.
    async fn start(dir: &std::path::Path, hooks: TestHooks) -> (Arc<LsmStorageEngine>, TestHub) {
        let hub = TestHub::start(&[(WalTarget::Kv, &dir.join("wal"))]);
        (engine_on_hub(dir, &hub, hooks).await, hub)
    }

    /// Drops `engine` and its hub without a flush or a cut, as a crash does,
    /// and opens the engine again on the files left behind.
    async fn crash(dir: &std::path::Path, engine: Arc<LsmStorageEngine>, hub: TestHub) -> (Arc<LsmStorageEngine>, TestHub) {
        drop(engine);
        drop(hub);
        start(dir, TestHooks::default()).await
    }

    /// An engine whose sweeps park at `hook` after a re-check found a key expired.
    async fn parking_sweeps(dir: &std::path::Path, hook: &Arc<TestHook>) -> (Arc<LsmStorageEngine>, TestHub) {
        start(dir, TestHooks { after_sweep_recheck: Some(Arc::clone(hook)), ..TestHooks::default() }).await
    }

    fn spawn_sweep(engine: &Arc<LsmStorageEngine>) -> compio::runtime::JoinHandle<Result<()>> {
        spawn_tick(&Arc::new(sweeper(engine, 500)))
    }

    fn spawn_tick(sweeper: &Arc<TtlSweeper>) -> compio::runtime::JoinHandle<Result<()>> {
        let sweeper = Arc::clone(sweeper);
        compio::runtime::spawn(async move { sweeper.sweep_tick().await })
    }

    // A sweep whose re-check saw the expired value before a newer write and
    // a whole checkpoint writes no tombstone after the checkpoint's mark:
    // no record, no event, and after a crash the newer value is there. The
    // next tick checks the key again and finds it fresh, even with a chunk
    // that would have moved past it.
    #[test]
    fn test_a_tombstone_checked_before_a_checkpoint_is_not_written_after_it() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let hook = Arc::new(TestHook::default());
            let (engine, hub) = parking_sweeps(dir.path(), &hook).await;
            engine.put_expired_for_test(b"k", b"old").await.unwrap();
            let mut rx = engine.watch_subscribe();
            let sweeper = Arc::new(sweeper(&engine, 1));
            let sweep = spawn_tick(&sweeper);
            hook.reached.notified().await;

            engine.put(b"k", b"fresh").await.unwrap();
            engine.checkpoint().await.unwrap();
            let log = std::fs::read(dir.path().join("wal")).unwrap();
            hook.release.notify_one();
            sweep.await.unwrap().unwrap();
            assert_eq!(std::fs::read(dir.path().join("wal")).unwrap(), log, "the sweep wrote a record");
            assert!(drained_deletes(&mut rx).is_empty());
            assert!(sweeper.cursor.lock().is_empty(), "the next tick starts before the key");

            sweeper.sweep_tick().await.unwrap();
            assert_eq!(std::fs::read(dir.path().join("wal")).unwrap(), log, "the next tick wrote a record");
            assert!(drained_deletes(&mut rx).is_empty());

            let (engine, _hub) = crash(dir.path(), engine, hub).await;
            assert_eq!(engine.get(b"k").await.unwrap(), Some(b"fresh".to_vec()));
        })
    }

    // A key whose tombstone a checkpoint dropped is still expired: the next
    // tick checks it again and writes exactly one tombstone, even with a
    // chunk that would have moved past it.
    #[test]
    fn test_a_tombstone_dropped_for_a_checkpoint_is_written_by_the_next_tick() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let hook = Arc::new(TestHook::default());
            let (engine, _hub) = parking_sweeps(dir.path(), &hook).await;
            engine.put_expired_for_test(b"k", b"old").await.unwrap();
            let mut rx = engine.watch_subscribe();
            let sweeper = Arc::new(sweeper(&engine, 1));
            let sweep = spawn_tick(&sweeper);
            hook.reached.notified().await;
            engine.checkpoint().await.unwrap();
            hook.release.notify_one();
            sweep.await.unwrap().unwrap();
            assert!(drained_deletes(&mut rx).is_empty());
            assert!(sweeper.cursor.lock().is_empty(), "the next tick starts before the key");

            let sweep = spawn_tick(&sweeper);
            hook.reached.notified().await;
            hook.release.notify_one();
            sweep.await.unwrap().unwrap();

            assert_eq!(drained_deletes(&mut rx), [b"k".to_vec()]);
            assert_eq!(state_of(&engine, b"k").await, Some(VersionState::Tombstone));
        })
    }

    // A tombstone lost in a pinned MemTable flushed before the write is cut
    // with the log by the next checkpoint: after a crash the key stays
    // invisible, and the next sweep removes it with one event.
    #[test]
    fn test_a_tombstone_lost_before_a_checkpoint_is_written_by_the_next_sweep() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let hook = Arc::new(TestHook::default());
            let (engine, hub) = parking_sweeps(dir.path(), &hook).await;
            engine.put_expired_for_test(b"k", b"old").await.unwrap();
            let sweep = spawn_sweep(&engine);
            hook.reached.notified().await;
            engine.freeze_active_memtable();
            engine.flush_memtable().await.unwrap();
            hook.release.notify_one();
            sweep.await.unwrap().unwrap();
            engine.checkpoint().await.unwrap();

            let (engine, _hub) = crash(dir.path(), engine, hub).await;
            assert_eq!(engine.get(b"k").await.unwrap(), None);
            let mut rx = engine.watch_subscribe();
            sweeper(&engine, 500).sweep_tick().await.unwrap();
            assert_eq!(drained_deletes(&mut rx), [b"k".to_vec()]);
        })
    }

    // A tombstone and a newer write both after a checkpoint's mark replay
    // together after a crash: the newer write wins.
    #[test]
    fn test_a_tombstone_and_a_newer_write_after_the_mark_keep_the_newer_write() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let hook = Arc::new(TestHook::default());
            let (engine, hub) = parking_sweeps(dir.path(), &hook).await;
            engine.put_expired_for_test(b"k", b"old").await.unwrap();
            engine.checkpoint().await.unwrap();
            let sweep = spawn_sweep(&engine);
            hook.reached.notified().await;
            engine.put(b"k", b"fresh").await.unwrap();
            hook.release.notify_one();
            sweep.await.unwrap().unwrap();

            let (engine, _hub) = crash(dir.path(), engine, hub).await;
            assert_eq!(engine.get(b"k").await.unwrap(), Some(b"fresh".to_vec()));
        })
    }

    // A tombstone written before a checkpoint is persisted by it: after a
    // crash the key stays removed.
    #[test]
    fn test_a_tombstone_before_a_checkpoint_survives_a_crash() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let (engine, hub) = start(dir.path(), TestHooks::default()).await;
            engine.put_expired_for_test(b"k", b"old").await.unwrap();
            sweeper(&engine, 500).sweep_tick().await.unwrap();
            engine.checkpoint().await.unwrap();
            assert_eq!(std::fs::read(dir.path().join("wal")).unwrap(), crate::core::wal::WAL_MAGIC);

            let (engine, _hub) = crash(dir.path(), engine, hub).await;
            assert_eq!(engine.get(b"k").await.unwrap(), None);
            assert_eq!(state_of(&engine, b"k").await, Some(VersionState::Tombstone));
        })
    }
}
