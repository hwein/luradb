//! `engine` module
//!
//! The `LsmStorageEngine` orchestrates all LSM-Tree subsystems:
//! MemTable, WAL, VLog, SSTable levels, compaction, and the Janitor GC.

use crate::config::BlockCacheConfig;
use crate::control::resources::{Resources, SpaceWait, REPEAT_TICKS};
use crate::engines::lsm::block_cache::StripedBlockCache;
use crate::engines::lsm::memtable::{MemTable, Value};
use crate::engines::lsm::reader::{
    is_applying, GetResult, LsmReader, RawEntry, RawValue, RegistrySnapshot, Snapshot, SnapshotRegistry,
    ValueWithMetadata,
};
use crate::engines::lsm::key::{InternalKey, Timestamp};
use crate::engines::lsm::version::{Version, VersionCell};
use crate::engines::lsm::compaction::{
    CompactionConfig, CompactionJob, select_sstables_for_level_compaction,
    select_level_to_compact, should_compact,
};
use crate::engines::lsm::janitor::{FlushBarrier, Janitor, JanitorConfig};
use crate::engines::lsm::hlc::{HLCTimestamp, HybridLogicalClock};
use crate::engines::lsm::watcher::{OpType, WalEvent, WATCH_TAG};
use crate::engines::StorageEngine;
use crate::core::coop::YieldEvery;
use crate::core::events::{stream_epoch, Resume, SeqRing};
use crate::core::io_engine::IoEngine;
use crate::core::wal::{WalEntry, WriteAheadLog};
use crate::storage::vlog::{discover_generations, generation_path, VLog, VLogError};
use crate::storage::sstable::{SSTableBuilder, SSTableReader};
use crate::storage::format::VersionState;
use crate::storage::file_manager::FileManager;
use crate::storage::manifest::{Manifest, ManifestManager, SSTableMetadata};
use crate::storage::write_failures::{WriteError, WriteFailures};
use anyhow::{Context, Result};
use parking_lot::{Mutex, RwLock};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}};
use compio::time::sleep;
use std::time::Duration;
use tokio::sync::{broadcast, watch, Notify};

// Default limits — kept as constants so tests can reference them directly.
const MAX_KEY_LENGTH: usize = 256;
const MAX_VALUE_SIZE_LIMIT: usize = 512 * 1024;

/// Per-instance tuning parameters for the LSM storage engine.
#[derive(Debug, Clone)]
pub struct LsmEngineConfig {
    /// Values >= this threshold are offloaded to the vLog (WiscKey).
    pub vlog_inline_threshold: usize,
    /// MemTable size in bytes at which it is frozen and queued for flushing.
    pub memtable_size_threshold: usize,
    /// Maximum key length in bytes.
    pub max_key_length: usize,
    /// Maximum value size in bytes; larger values are rejected.
    pub max_value_size: usize,
    /// Polling interval of the background flush loop.
    pub flush_check_interval_ms: u64,
    /// Polling interval of the background compaction loop.
    pub compaction_check_interval_ms: u64,
    /// Capacity of the WAL-event broadcast channel.
    pub wal_event_channel_capacity: usize,
    /// Access SSTables via mmap instead of loading them fully.
    pub use_mmap: bool,
    /// Capacity of the KV watch replay ring. `0` disables
    /// resume (every reconnect with a `Last-Event-ID` gets `reset`), but
    /// `id:` fields are still assigned. json/rel set this to `0` — they have
    /// no watch endpoint.
    pub watch_replay_buffer_size: usize,
}

impl Default for LsmEngineConfig {
    fn default() -> Self {
        Self {
            vlog_inline_threshold: 1024,
            memtable_size_threshold: 4 * 1024 * 1024,
            max_key_length: MAX_KEY_LENGTH,
            max_value_size: MAX_VALUE_SIZE_LIMIT,
            flush_check_interval_ms: 100,
            compaction_check_interval_ms: 1_000,
            wal_event_channel_capacity: 256,
            use_mmap: true,
            watch_replay_buffer_size: 1024,
        }
    }
}

/// Grouped configuration for [`LsmStorageEngine::new`] — a flat parameter
/// object that keeps the constructor within the argument-count limit.
#[derive(Default)]
pub struct LsmEngineOptions {
    pub engine: LsmEngineConfig,
    pub compaction: CompactionConfig,
    pub janitor: JanitorConfig,
    pub block_cache: BlockCacheConfig,
    pub recovery: Recovery,
    /// The data shard the instance belongs to; its watch stream's epoch
    /// carries it.
    pub shard: u16,
    /// Refuses the client writes while disk space or memory runs short, and
    /// says how much space compaction and value log cleanup find. The system
    /// store keeps the default, so its writes, sign-ins and keys, go on.
    pub resources: Resources,
}

/// Where a new engine's unflushed writes come from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Recovery {
    /// Replays its own write-ahead log, flushes what it read and truncates
    /// the log.
    #[default]
    Internal,
    /// Replays nothing; [`LsmStorageEngine::replay_wal`] hands it its share
    /// of a log several instances write, which their owner truncates.
    External,
}

fn validate_key(key: &[u8], max_len: usize) -> Result<()> {
    anyhow::ensure!(!key.is_empty(), "Key must not be empty");
    anyhow::ensure!(
        key.len() <= max_len,
        "Key length {} exceeds maximum of {} bytes",
        key.len(),
        max_len
    );
    Ok(())
}

fn validate_value(value: &[u8], max_size: usize) -> Result<()> {
    anyhow::ensure!(
        value.len() <= max_size,
        "Value length {} exceeds maximum of {} bytes",
        value.len(),
        max_size
    );
    Ok(())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Scans one MemTable for keys starting with `prefix`.
///
/// Encoded keys lead with the user key, so a prefix's entries are contiguous:
/// the scan starts at `prefix` and ends at the first encoded key without it.
/// Inside, the user key is still checked — a shorter one plus its stamp bytes
/// can start with `prefix`.
///
/// Callers process sources newest-first, so the first version seen for a
/// user-key anywhere is its newest and decides for good (`decided`): live
/// versions land in `live`, tombstoned or TTL-expired ones suppress the key.
/// A version of the batch `applying_batch` names does not decide; the next
/// older one does. Stops early once `live` holds `limit` keys.
///
/// `snapshot` of `None` matches every version (today's `scan_keys`
/// behavior); `Some` skips versions newer than the snapshot instead of
/// deciding the key, so an older, visible version further along can still
/// decide it (backup export).
///
/// `coop` counts across all sources of one scan.
async fn scan_memtable_for_prefix(
    mt: &MemTable,
    prefix: &[u8],
    now: u64,
    limit: usize,
    snapshot: Option<&Snapshot>,
    applying_batch: &AtomicU64,
    live: &mut BTreeSet<Vec<u8>>,
    decided: &mut BTreeSet<Vec<u8>>,
    coop: &mut YieldEvery,
) {
    for (encoded_key, value) in mt.iter_from(prefix) {
        coop.tick().await;
        if live.len() >= limit || !encoded_key.starts_with(prefix) {
            return;
        }
        if let Some(user_key) = InternalKey::extract_user_key(&encoded_key) {
            if !user_key.starts_with(prefix) || decided.contains(user_key) {
                continue;
            }
            let ts = InternalKey::extract_timestamp(&encoded_key);
            if let Some(snap) = snapshot {
                let visible = ts.map(|ts| snap.is_visible(ts)).unwrap_or(false);
                if !visible {
                    continue;
                }
            }
            if ts.is_some_and(|ts| is_applying(applying_batch, ts)) {
                continue;
            }
            decided.insert(user_key.to_vec());
            if is_live_version(&value, now) {
                live.insert(user_key.to_vec());
            }
            coop.tick().await;
        }
    }
}

/// Appends `value` to the active vLog generation, returning `(generation id,
/// offset)` read from the *same* reference so the pointer can never mix ids.
///
/// A `Sealed` error means the Janitor swapped the active generation between the
/// lookup and the append; it publishes the new generation before sealing the
/// old one, so a single retry converges. A failed write counts in `failures`
/// and may stop the server.
async fn append_to_active(versions: &VersionCell, value: &[u8], failures: &WriteFailures) -> Result<(u32, u64)> {
    loop {
        let active = Arc::clone(&versions.get().active_vlog);
        match active.append(value).await {
            Ok(offset) => {
                failures.succeeded();
                return Ok((active.id(), offset));
            }
            Err(VLogError::Sealed { id }) => anyhow::ensure!(
                versions.get().active_vlog.id() != id,
                "active value log generation {id} is sealed"
            ),
            Err(VLogError::Io(e)) if failures.stops_for(active.path(), &e) => {
                return Err(crate::storage::fatal_write_error(active.path(), &e));
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Counts the failures in a row of a background job: the first and every
/// 60th after it get a log line.
#[derive(Default)]
struct FailureLog(AtomicU64);

impl FailureLog {
    /// Counts a failure; whether it gets a log line.
    fn failed(&self) -> bool {
        self.0.fetch_add(1, Ordering::Relaxed).is_multiple_of(REPEAT_TICKS)
    }

    /// The job succeeded: the next failure starts a new row.
    fn succeeded(&self) {
        self.0.store(0, Ordering::Relaxed);
    }
}

/// True if `value` is neither TTL-expired at `now` nor a tombstone.
fn is_live_version(value: &Value, now: u64) -> bool {
    value.version_state(now) == VersionState::Live
}

/// Ticks between two yield points of a prefix scan: one per visited entry,
/// one more per decided key, which copies the key into the result sets; the
/// result's collection and the release of the decided set tick once per key.
const SCAN_KEYS_YIELD_INTERVAL: u32 = 1024;

/// Entries the expiry scan checks between two yield points.
const SCAN_EXPIRED_YIELD_INTERVAL: usize = 1024;

/// Counts one checked entry and hands the worker back every
/// [`SCAN_EXPIRED_YIELD_INTERVAL`] entries — the SSTable
/// phase is synchronous and would otherwise block a worker for a whole file.
async fn scan_expired_yield(checked: &mut usize) {
    *checked += 1;
    if (*checked).is_multiple_of(SCAN_EXPIRED_YIELD_INTERVAL) {
        tokio::task::yield_now().await;
    }
}

/// Adds `key` and drops the largest entry once the set exceeds `limit`, so it
/// always holds the `limit` smallest candidates seen — independent of the
/// order the sources deliver them in. Memory is
/// O(`batch_size`), never O(keys of the instance).
fn push_expired_candidate(candidates: &mut BTreeSet<Vec<u8>>, limit: usize, key: Vec<u8>) {
    candidates.insert(key);
    if candidates.len() > limit {
        candidates.pop_last();
    }
}

/// A batch's resolved ops reduced to each key's last one, in batch order —
/// the state that applying all of them in order leaves, as WAL replay does.
/// Phase 2 inserts each key once: a reader on another thread
/// that found a key's first insert might load the batch slot only after the
/// batch and keep the superseded value.
fn last_op_per_key(ops: Vec<(Vec<u8>, Value)>) -> impl Iterator<Item = (Vec<u8>, Value)> {
    let last: Vec<bool> = {
        let mut seen = HashSet::with_capacity(ops.len());
        ops.iter().rev().map(|(key, _)| seen.insert(key.as_slice())).collect()
    };
    ops.into_iter().zip(last.into_iter().rev()).filter_map(|(op, last)| last.then_some(op))
}

/// Sweeps one SSTable for keys with `prefix` (see [`scan_memtable_for_prefix`]
/// for the newest-first decision protocol and the `snapshot` contract).
/// Returns `true` once `live` holds `limit` keys so the caller can stop.
async fn scan_sstable_for_prefix(
    sstable: &SSTableReader,
    prefix: &[u8],
    limit: usize,
    snapshot: Option<&Snapshot>,
    live: &mut BTreeSet<Vec<u8>>,
    decided: &mut BTreeSet<Vec<u8>>,
    coop: &mut YieldEvery,
) -> Result<bool> {
    let entries: Box<dyn Iterator<Item = Result<(Vec<u8>, bool)>> + Send + '_> = match snapshot {
        Some(snap) => Box::new(sstable.keys_with_prefix_at(prefix, snap.timestamp().inverted())),
        None => Box::new(sstable.keys_with_prefix(prefix)),
    };
    for entry in entries {
        coop.tick().await;
        if live.len() >= limit {
            return Ok(true);
        }
        let (user_key, is_live) = entry?;
        if decided.contains(&user_key) {
            continue;
        }
        if is_live {
            live.insert(user_key.clone());
        }
        decided.insert(user_key);
        coop.tick().await;
    }
    Ok(false)
}

/// Test-only rendezvous for the install-window tests: the
/// paused path signals `reached`, then waits for `release`.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestHook {
    pub reached: Notify,
    pub release: Notify,
}

#[cfg(test)]
impl TestHook {
    /// Signals arrival and parks until the test releases it.
    pub async fn pause(&self) {
        self.reached.notify_one();
        self.release.notified().await;
    }
}

/// Test-only rendezvous for a synchronous path on a thread of its own: the
/// first `pause` sends its thread's id on `reached`, then blocks until
/// `release` is sent.
#[cfg(test)]
pub(crate) struct ThreadHook {
    ends: Mutex<Option<(std::sync::mpsc::Sender<std::thread::ThreadId>, std::sync::mpsc::Receiver<()>)>>,
}

#[cfg(test)]
impl ThreadHook {
    /// The hook plus the test's ends: `reached` receives the id of the
    /// parked thread, a send on `release` lets it go on.
    pub fn new() -> (Arc<Self>, std::sync::mpsc::Receiver<std::thread::ThreadId>, std::sync::mpsc::Sender<()>) {
        let (reached_tx, reached_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        (Arc::new(Self { ends: Mutex::new(Some((reached_tx, release_rx))) }), reached_rx, release_tx)
    }

    /// Parks the first caller only; later calls pass straight through.
    pub fn pause(&self) {
        let Some((reached, release)) = self.ends.lock().take() else { return };
        reached.send(std::thread::current().id()).unwrap();
        release.recv().unwrap();
    }
}

/// Test-only pause points inside the engine — set before
/// the engine is shared, never in a release build.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestHooks {
    /// Parks `flush_memtable` between its claim and the SSTable write.
    pub before_flush_write: Option<Arc<TestHook>>,
    /// Parks `rebuild_levels_from_manifest` between opening the new readers
    /// and installing them.
    pub before_level_install: Option<Arc<TestHook>>,
    /// Parks `snapshot` right after it drew its stamp.
    pub snapshot_stamp_drawn: Option<Arc<ThreadHook>>,
    /// Parks `write_batch` in Phase 2 right after its first MemTable insert.
    pub batch_first_applied: Option<Arc<ThreadHook>>,
    /// Parks `scan_with_metadata` before it reads.
    pub before_scan: Option<Arc<ThreadHook>>,
    /// Parks `write_kv_pair` of this key under its in-flight guard, right
    /// before the MemTable insert.
    pub before_kv_pair_apply: Option<(Vec<u8>, Arc<TestHook>)>,
    /// Parks `compact_level` between its manifest change in memory and its
    /// own save of the manifest.
    pub before_compaction_save: Option<Arc<TestHook>>,
    /// Parks `flush_memtable` between its manifest change in memory and its
    /// own save of the manifest.
    pub before_flush_save: Option<Arc<TestHook>>,
    /// Parks a TTL sweep between the re-check of a candidate that found it
    /// expired and the write of its tombstone.
    pub after_sweep_recheck: Option<Arc<TestHook>>,
}

/// LSM-Tree Storage Engine with MVCC and background maintenance.
///
/// All long-lived background tasks (flush, compaction, Janitor GC) are spawned
/// via [`start_background_tasks`] and stopped gracefully via [`shutdown`].
pub struct LsmStorageEngine {
    /// MemTables, SSTable levels and vLog generations as one value: readers
    /// clone it, every change installs a successor.
    /// Shared with the Janitor, which installs its GC results itself.
    version: Arc<VersionCell>,

    wal: Arc<WriteAheadLog>,

    /// Canonical vLog path (generation 1) — base for every later generation.
    vlog_path: PathBuf,

    file_manager: Arc<FileManager>,
    manifest: Arc<RwLock<Manifest>>,
    manifest_manager: Arc<ManifestManager>,
    compaction_config: CompactionConfig,
    engine_config: LsmEngineConfig,
    janitor_config: JanitorConfig,
    hlc: Arc<HybridLogicalClock>,

    /// Registry of active MVCC snapshots — drives the compaction low watermark.
    snapshot_registry: Arc<SnapshotRegistry>,

    /// Broadcast channel for WAL-confirmed write events (Watch feature).
    change_tx: broadcast::Sender<WalEvent>,

    /// Sequences every `change_tx` event and keeps a bounded replay ring for
    /// the KV watch resume protocol.
    watch_log: SeqRing<WalEvent>,
    /// Epoch of the watch stream's event ids: [`stream_epoch`] of the shard.
    watch_epoch: u64,

    /// Signals background tasks to stop.
    shutdown: Arc<AtomicBool>,

    /// Wakes background loops immediately on shutdown instead of leaving them
    /// to sleep out their poll interval — `watch::Receiver::changed` has
    /// no lost-wakeup between a loop's flag check and going to sleep, unlike
    /// `Notify::notify_waiters`.
    shutdown_tx: watch::Sender<bool>,

    /// Handles of the three background loops; joined by [`Self::shutdown`]
    /// before it touches MemTables/WAL.
    background_tasks: Mutex<Vec<compio::runtime::JoinHandle<()>>>,

    /// S3-FIFO block cache shared across all read operations, striped.
    block_cache: Arc<StripedBlockCache>,

    /// Number of successfully completed `compact_next_level` calls since
    /// process start -- `/metrics` system block.
    compaction_runs: AtomicU64,

    /// Number of Janitor GC cycles that actually ran (`GcStats::ran == true`)
    /// since process start -- `/metrics` system block.
    /// `Arc` because the Janitor is built as its own object and carries this
    /// counter into its background task.
    janitor_runs: Arc<AtomicU64>,

    /// Notified after every MemTable flush — an extra tick of the SHM snapshot
    /// publisher besides its interval.
    flush_notify: Arc<Notify>,

    /// Raised after every visible change: each MemTable write and each domain
    /// create/delete. Flush, compaction and vLog GC leave
    /// it alone.
    change_epoch: AtomicU64,

    /// In-flight guard for the client write sequence. Every client write path
    /// holds the `read()` side from before its
    /// timestamp through `memtable.set`; every production MemTable rotation
    /// drains by taking `write()` and holding it across the swap. Two
    /// guarantees follow: no vLog pointer into a generation the Janitor just
    /// sealed is still on its way into a MemTable, and no rotation
    /// falls between a writer's stamp and its apply, which would strand an
    /// older stamp in the newer MemTable. `tokio::sync::RwLock` is
    /// task-fair (write-preferring), so a drain waits only for guards already
    /// in flight, never for ones started after it — no starvation under
    /// sustained write load, and no deadlock: the drain holds no other lock a
    /// writer needs while it waits, and no write path drains while holding its
    /// own read guard. `Arc` because the Janitor drains around its switch of
    /// the active vLog generation.
    in_flight_writes: Arc<tokio::sync::RwLock<()>>,

    /// Stamp of the batch whose Phase 2 is applying it to the MemTable, 0
    /// when none: readers skip MemTable versions with this
    /// stamp, so a reader on another thread sees a batch whole or not at
    /// all. One slot suffices — Phase 2 is await-free and only the owner
    /// thread runs it.
    applying_batch: AtomicU64,

    /// Highest LSN of a WAL record whose write reached the MemTable; after
    /// recovery the log's highest one. Never decreases.
    last_applied_lsn: Arc<AtomicU64>,

    /// Held by a flush from its claim to its install, so L0 and the manifest
    /// carry the SSTables in MemTable age order and whoever takes this lock
    /// knows that no flush claimed before it is still in flight. Lock order
    /// is `flush_lock` → `manifest` / `version`, never the other way round;
    /// `Arc` because the Janitor's GC install takes it too.
    flush_lock: Arc<tokio::sync::Mutex<()>>,

    /// Held by a whole GC cycle and by a whole compaction, so neither of the
    /// two jobs that rewrite entire levels enters the manifest while the other
    /// is running. Lock order is `maintenance_lock` →
    /// `flush_lock`; the flush path never takes it, so a GC cycle cannot stall
    /// a write.
    maintenance_lock: Arc<tokio::sync::Mutex<()>>,

    /// Refuses the client writes while disk space or memory runs short.
    resources: Resources,
    /// Compactions skipped for want of disk space.
    compaction_space: SpaceWait,
    /// The value log appends and the flushes' SSTable writes that failed in
    /// a row, reported where the WAL reports its own.
    vlog_failures: WriteFailures,
    flush_failures: WriteFailures,
    /// Failed flushes and compactions in a row, for their log lines.
    flush_errors: FailureLog,
    compaction_errors: FailureLog,

    /// The largest the active MemTable grew during the replay.
    #[cfg(test)]
    pub(crate) replay_peak: std::sync::atomic::AtomicUsize,
    /// The watermark of each rotation during the replay, in order.
    #[cfg(test)]
    pub(crate) replay_watermarks: Mutex<Vec<u64>>,

    #[cfg(test)]
    pub(crate) hooks: TestHooks,
}

impl LsmStorageEngine {
    /// Creates a new LSM storage engine, recovering state from disk.
    pub async fn new(
        wal: Arc<WriteAheadLog>,
        wal_path: PathBuf,
        vlog: Arc<VLog>,
        vlog_path: PathBuf,
        file_manager: Arc<FileManager>,
        manifest_manager: Arc<ManifestManager>,
        options: LsmEngineOptions,
    ) -> Result<Self> {
        let LsmEngineOptions {
            engine: engine_config,
            compaction: compaction_config,
            janitor: janitor_config,
            block_cache: block_cache_config,
            recovery,
            shard,
            resources,
        } = options;

        let mut version = Self::discover_vlog_generations(vlog, &vlog_path).await?;

        let manifest = manifest_manager.load().await?;

        // High-water mark of everything already persisted (seeds the HLC).
        let manifest_max_ts = manifest
            .levels
            .iter()
            .flatten()
            .map(|meta| meta.max_timestamp)
            .max()
            .unwrap_or(0);

        // Then, recover SSTable levels from the manifest.
        let levels = Self::recover_sstables(&manifest, &file_manager, engine_config.use_mmap).await?;
        version = version.with_levels(levels);

        let (change_tx, _) = broadcast::channel(engine_config.wal_event_channel_capacity);
        let watch_log = SeqRing::new(engine_config.watch_replay_buffer_size);

        let block_cache = Arc::new(StripedBlockCache::new(
            block_cache_config.capacity_bytes,
            block_cache_config.small_ratio,
            block_cache_config.ghost_capacity,
        ));

        let (shutdown_tx, _) = watch::channel(false);
        let (vlog_failures, flush_failures) =
            (WriteFailures::new(wal.io_failures()), WriteFailures::new(wal.io_failures()));
        let engine = Self {
            version: Arc::new(VersionCell::new(version)),
            wal,
            vlog_path,
            file_manager,
            manifest: Arc::new(RwLock::new(manifest)),
            manifest_manager,
            compaction_config,
            engine_config,
            janitor_config,
            hlc: Arc::new(HybridLogicalClock::new()),
            snapshot_registry: Arc::new(SnapshotRegistry::new()),
            change_tx,
            watch_log,
            watch_epoch: stream_epoch(shard),
            shutdown: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
            background_tasks: Mutex::new(Vec::new()),
            block_cache,
            compaction_runs: AtomicU64::new(0),
            janitor_runs: Arc::new(AtomicU64::new(0)),
            flush_notify: Arc::new(Notify::new()),
            change_epoch: AtomicU64::new(0),
            in_flight_writes: Arc::new(tokio::sync::RwLock::new(())),
            applying_batch: AtomicU64::new(0),
            last_applied_lsn: Arc::new(AtomicU64::new(0)),
            flush_lock: Arc::new(tokio::sync::Mutex::new(())),
            maintenance_lock: Arc::new(tokio::sync::Mutex::new(())),
            resources,
            compaction_space: SpaceWait::default(),
            vlog_failures,
            flush_failures,
            flush_errors: FailureLog::default(),
            compaction_errors: FailureLog::default(),
            #[cfg(test)]
            replay_peak: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            replay_watermarks: Mutex::new(Vec::new()),
            #[cfg(test)]
            hooks: TestHooks::default(),
        };

        // A fresh HLC only reads the wall clock, so after a
        // backwards clock step every snapshot would be older than the data on
        // disk and hide it. Seeding from recovered state fixes the read side
        // and keeps new writes above existing versions. Must happen before
        // any timestamp can be issued; the replay raises it to the stamps of
        // the log.
        engine.hlc.seed(manifest_max_ts);

        if recovery == Recovery::Internal {
            Self::replay_wal(&wal_path, std::slice::from_ref(&engine), |_, _| Ok(0)).await?;
            engine.wal.truncate().await?;
        }

        Ok(engine)
    }

    /// Replays the log at `path` onto `instances`, which share it, before
    /// any write: each entry above its owner's flushed LSN, one at a time; a
    /// MemTable at the size threshold is flushed at once. A log of an
    /// earlier format goes in whole, ahead of the segments that replaced
    /// it. On return every instance has flushed what it took, its flushed
    /// LSN is the log's last and the next write continues the log's LSNs;
    /// the caller truncates the log.
    pub(crate) async fn replay_wal(
        path: &Path,
        instances: &[Self],
        owner: impl Fn(u64, &WalEntry) -> Result<usize>,
    ) -> Result<()> {
        let mut replayed = vec![false; instances.len()];
        // `done` is the LSN of the last record read in full: every instance
        // has applied all of its entries up to it.
        let (mut done, mut current, mut max_lsn) = (0, 0, 0);
        for mut log in crate::core::wal::recover_path(path).await? {
            let flushed: Vec<Option<u64>> =
                instances.iter().map(|instance| log.lsns_continue().then(|| instance.flushed_lsn())).collect();
            while let Some(next) = log.next().await {
                let (lsn, entry) = next?;
                if lsn != current {
                    (done, current) = (current, lsn);
                }
                let index = owner(lsn, &entry)?;
                let instance = &instances[index];
                if flushed[index].is_some_and(|flushed| lsn <= flushed) {
                    instance.hlc.seed(entry.timestamp());
                    continue;
                }
                instance.replay_entry(entry, done).await?;
                replayed[index] = true;
            }
            max_lsn = max_lsn.max(log.max_lsn());
        }
        if let Some(first) = instances.first() {
            // Before the first append: new records continue the LSNs of the
            // log and of the tables, which a log of an earlier format may
            // not reach.
            let flushed = instances.iter().map(Self::flushed_lsn).max().unwrap_or(0);
            first.wal.set_lsn_start(max_lsn.max(flushed)).await?;
        }
        for (instance, replayed) in instances.iter().zip(replayed) {
            // One without records here saves its manifest alone.
            instance.raise_flushed_lsn(max_lsn).await?;
            if replayed {
                instance.sync_vlog_and_dirs().await?;
            }
            instance.last_applied_lsn.fetch_max(max_lsn, Ordering::Release);
        }
        Ok(())
    }

    /// Applies one replayed entry; a MemTable at the size threshold is
    /// first rotated out with `done`, the LSN up to which this instance has
    /// applied all of its entries, and flushed.
    async fn replay_entry(&self, entry: WalEntry, done: u64) -> Result<()> {
        if self.version().memtable.size_bytes() >= self.engine_config.memtable_size_threshold {
            #[cfg(test)]
            self.replay_watermarks.lock().push(done);
            self.install(|v| v.rotated(done));
            self.flush_memtable().await?;
        }
        self.apply_entry(entry).await?;
        #[cfg(test)]
        self.replay_peak.fetch_max(self.version().memtable.size_bytes(), Ordering::Relaxed);
        Ok(())
    }

    /// Writes `entry` into the active MemTable under its own stamp, its value
    /// into the vLog from `vlog_inline_threshold` on, and raises the clock to
    /// the stamp. Ops of one batch share a stamp and go in in order, the
    /// later one wins. A single DELETE goes in only while no version of its
    /// key stamped at or after it is known: a sweeper tombstone is dated
    /// below the value it expires, and a newer write of the key may stand
    /// before it in the log, but in an SSTable, where the MemTable would
    /// hide it.
    async fn apply_entry(&self, entry: WalEntry) -> Result<()> {
        let memtable = Arc::clone(&self.version().memtable);
        self.hlc.seed(entry.timestamp());
        match entry {
            WalEntry::Set { timestamp, key, value, expire_at } => {
                let expire_at = if expire_at == 0 { None } else { Some(expire_at) };
                let resolved = if value.len() >= self.engine_config.vlog_inline_threshold {
                    let (file_id, offset) = append_to_active(&self.version, &value, &self.vlog_failures).await?;
                    Value::Pointer { file_id, offset, len: value.len(), expire_at }
                } else {
                    Value::Inline(value, expire_at)
                };
                memtable.set(key, Timestamp::new(timestamp), resolved);
            }
            WalEntry::Delete { timestamp, key, in_batch: true } => {
                memtable.set(key, Timestamp::new(timestamp), Value::Tombstone);
            }
            WalEntry::Delete { timestamp, key, in_batch: false } => {
                if !self.holds_version_since(&key, timestamp).await? {
                    memtable.set(key, Timestamp::new(timestamp), Value::Tombstone);
                }
            }
            WalEntry::SetNull { timestamp, key } => {
                memtable.set(key, Timestamp::new(timestamp), Value::Null);
            }
        }
        Ok(())
    }

    /// Whether the newest version of `key` a read finds is stamped
    /// `timestamp` or later.
    async fn holds_version_since(&self, key: &[u8], timestamp: u64) -> Result<bool> {
        let newest = self.build_reader().newest_version(key, &Snapshot::new(Timestamp::new(u64::MAX))).await?;
        Ok(newest.is_some_and(|(stamp, _)| stamp.as_u64() >= timestamp))
    }

    /// Writes `entries` under their own stamps and expiries, raises the clock
    /// to the newest stamp and flushes them; the flushed LSN stays. Built
    /// with [`Recovery::External`], the instance must take no other write
    /// until the last batch is in.
    pub async fn import_raw(&self, entries: Vec<RawEntry>) -> Result<()> {
        for RawEntry { key, stamp: timestamp, value, expire_at } in entries {
            let entry = match value {
                RawValue::Bytes(value) => WalEntry::Set { timestamp, key, value, expire_at },
                RawValue::Null => WalEntry::SetNull { timestamp, key },
                RawValue::Tombstone => WalEntry::Delete { timestamp, key, in_batch: true },
            };
            self.apply_entry(entry).await?;
        }
        if self.version().memtable.is_empty() {
            return Ok(());
        }
        self.install(|v| v.rotated(0));
        self.flush_memtable().await?;
        self.sync_vlog_and_dirs().await
    }

    /// Syncs every vLog generation of the current version, then the
    /// directories of the SSTables, the manifest and the vLog; a failed
    /// sync stops the server.
    async fn sync_vlog_and_dirs(&self) -> Result<()> {
        self.sync_vlog_generations().await?;
        let vlog_dir = self.vlog_path.parent().unwrap_or(Path::new(""));
        crate::storage::sync_dirs_or_stop(&[self.file_manager.dir(), self.manifest_manager.dir(), vlog_dir]).await
    }

    /// Syncs every vLog generation of the current version: a frozen MemTable
    /// may point into a generation the Janitor sealed without a sync. A
    /// failed sync stops the server: a second one of the same file proves
    /// nothing.
    async fn sync_vlog_generations(&self) -> Result<()> {
        let version = self.version();
        let mut generations: Vec<&Arc<VLog>> = version.vlog.values().collect();
        generations.sort_by_key(|vlog| vlog.id());
        for vlog in generations {
            if let Err(e) = vlog.sync().await {
                return Err(crate::storage::fatal_sync_error(vlog.path(), &e));
            }
        }
        Ok(())
    }

    /// A version over every vLog generation that exists next to `vlog_path`;
    /// the highest id becomes the active one. `vlog` is the
    /// caller's handle on the canonical path, which is generation 1 — a store
    /// without further generations therefore starts exactly as before.
    async fn discover_vlog_generations(vlog: Arc<VLog>, vlog_path: &Path) -> Result<Version> {
        let mut version = Version::new(vlog);
        for id in discover_generations(vlog_path).await? {
            if id > 1 {
                let generation = Arc::new(VLog::open(generation_path(vlog_path, id), id).await?);
                Arc::make_mut(&mut version.vlog).insert(id, Arc::clone(&generation));
                version.active_vlog = generation;
            }
        }
        Ok(version)
    }

    /// Opens an SSTable reader for `file_id` — memory-mapped when `use_mmap`
    /// is on, fully loaded otherwise — and stamps the block-cache file id.
    pub(crate) async fn open_sstable_reader(
        file_manager: &FileManager,
        file_id: u64,
        use_mmap: bool,
    ) -> Result<SSTableReader> {
        let mut reader = if use_mmap {
            SSTableReader::open_mmap(&file_manager.file_path(file_id))?
        } else {
            let data = file_manager.read_sstable(file_id).await?;
            SSTableReader::open(data)?
        };
        reader.set_file_id(file_id);
        Ok(reader)
    }

    /// Serving readers for `metas`: the instance `current` holds for a file,
    /// a new one only for a file it lacks. One instance per file, so
    /// [`SSTableReader::retire`] marks it for every version that holds it.
    pub(crate) async fn level_readers(
        file_manager: &FileManager,
        current: &Version,
        metas: &[SSTableMetadata],
        use_mmap: bool,
    ) -> Result<Vec<Arc<SSTableReader>>> {
        let held: HashMap<u64, &Arc<SSTableReader>> =
            current.levels.iter().flatten().map(|t| (t.file_id, t)).collect();
        let mut readers = Vec::with_capacity(metas.len());
        for meta in metas {
            readers.push(match held.get(&meta.file_id) {
                Some(reader) => Arc::clone(reader),
                None => Arc::new(Self::open_sstable_reader(file_manager, meta.file_id, use_mmap).await?),
            });
        }
        Ok(readers)
    }

    /// An unopenable SSTable that the manifest still lists is a startup
    /// error, not a warning: silently installing a partial
    /// level would start the database without a part of its data.
    async fn recover_sstables(
        manifest: &Manifest,
        file_manager: &Arc<FileManager>,
        use_mmap: bool,
    ) -> Result<Vec<(usize, Vec<Arc<SSTableReader>>)>> {
        let mut levels = Vec::new();
        for (level_idx, level_metas) in manifest.levels.iter().enumerate() {
            let mut sstables = Vec::new();
            for meta in level_metas {
                let reader = Self::open_sstable_reader(file_manager, meta.file_id, use_mmap)
                    .await
                    .with_context(|| format!("cannot open SSTable {} at L{level_idx}", meta.file_id))?;
                sstables.push(Arc::new(reader));
            }
            if !sstables.is_empty() {
                levels.push((level_idx, sstables));
            }
        }
        Ok(levels)
    }

    /// Starts the flush loop, compaction loop, and Janitor GC loop, keeping
    /// their `JoinHandle`s so [`Self::shutdown`] can join them.
    pub fn start_background_tasks(self: &Arc<Self>) {
        let mut tasks = self.background_tasks.lock();

        // Flush loop
        let engine = Arc::clone(self);
        tasks.push(compio::runtime::spawn(async move { engine.background_flush_loop().await }));

        // Compaction loop
        let engine = Arc::clone(self);
        tasks.push(compio::runtime::spawn(async move { engine.background_compaction_loop().await }));

        // Janitor (vLog GC) loop
        let janitor = Arc::new(self.build_janitor(self.janitor_config.clone()));
        let shutdown_rx = self.shutdown_tx.subscribe();
        tasks.push(compio::runtime::spawn(async move { janitor.run_background(shutdown_rx).await }));
    }

    /// Builds a Janitor over this engine's state, wired with the flush barrier
    /// its GC needs before the SSTables are the complete live set.
    pub(crate) fn build_janitor(self: &Arc<Self>, config: JanitorConfig) -> Janitor {
        let engine = Arc::clone(self);
        let flush_barrier: FlushBarrier = Arc::new(move || {
            let engine = Arc::clone(&engine);
            Box::pin(async move { engine.flush_all_memtables().await })
        });
        Janitor::new(
            Arc::clone(&self.version),
            self.vlog_path.clone(),
            Arc::clone(&self.manifest),
            Arc::clone(&self.manifest_manager),
            Arc::clone(&self.file_manager),
            Arc::clone(&self.block_cache),
            Arc::clone(&self.snapshot_registry),
            config,
            self.engine_config.use_mmap,
            Arc::clone(&self.shutdown),
            Arc::clone(&self.janitor_runs),
            Some(flush_barrier),
            Some(Arc::clone(&self.flush_lock)),
            Some(Arc::clone(&self.maintenance_lock)),
            Some((Arc::clone(&self.in_flight_writes), Arc::clone(&self.last_applied_lsn))),
            self.resources.clone(),
        )
    }

    async fn background_flush_loop(&self) {
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        while !self.shutdown.load(Ordering::Relaxed) {
            let wait = self.flush_turn().await;
            // Woken immediately on shutdown instead of sleeping out the
            // full interval; `changed()` cannot miss a signal sent while this
            // loop was doing the work above (no lost-wakeup, unlike Notify).
            tokio::select! {
                _ = sleep(wait) => {}
                _ = shutdown_rx.changed() => {}
            }
        }
    }

    /// Flushes the oldest immutable MemTable, if there is one, and returns
    /// how long the flush loop waits for its next turn: after a failure the
    /// compaction interval, so a failing disk is not tried ten times a
    /// second.
    async fn flush_turn(&self) -> Duration {
        if !self.version().immutables.is_empty() {
            match self.flush_memtable().await {
                Ok(_) => self.flush_errors.succeeded(),
                Err(e) => {
                    if self.flush_errors.failed() {
                        eprintln!("[Engine] Flush error: {e}");
                    }
                    return Duration::from_millis(self.engine_config.compaction_check_interval_ms);
                }
            }
        }
        Duration::from_millis(self.engine_config.flush_check_interval_ms)
    }

    async fn background_compaction_loop(&self) {
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        while !self.shutdown.load(Ordering::Relaxed) {
            let needs = {
                let manifest = self.manifest.read();
                should_compact(&manifest, &self.compaction_config)
            };
            if needs {
                match self.compact_next_level().await {
                    Ok(_) => self.compaction_errors.succeeded(),
                    Err(e) => {
                        if self.compaction_errors.failed() {
                            eprintln!("[Engine] Compaction error: {e}");
                        }
                    }
                }
            }
            tokio::select! {
                _ = sleep(Duration::from_millis(self.engine_config.compaction_check_interval_ms)) => {}
                _ = shutdown_rx.changed() => {}
            }
        }
    }

    /// Freezes the active MemTable and flushes every immutable one, leaving no
    /// vLog pointer MemTable-resident. Used by the Janitor's flush barrier.
    pub async fn flush_all_memtables(&self) -> Result<()> {
        // Drain. Order anchor: Seal (Janitor, before it calls this
        // barrier) -> Drain (here) -> Freeze/Flush (below). The write side waits
        // out every write that acquired its read guard before this point -- each
        // has, by the time it releases the guard, already applied its
        // `memtable.set`. Combined with the preceding seal (no *new* pointer
        // into the sealed generations can appear), every live pointer into a
        // sealed generation is now MemTable-resident and gets picked up by the
        // freeze/flush below.
        //
        // Held across the rotation instead of dropped right after the wait:
        // a writer admitted in between could draw its stamp
        // before the swap and apply it after, stranding an older stamp in the
        // new MemTable. Everything below the guard is synchronous -- no await.
        {
            let _drain = self.in_flight_writes.write().await;
            self.install(|v| v.rotated(self.last_applied_lsn()));
        }
        self.flush_immutables().await
    }

    /// Raises the manifest's flushed LSN to `lsn`, which must be durable in
    /// the write-ahead log: rotates the active MemTable out with `lsn` as its
    /// watermark, flushes every frozen MemTable, then saves the raised LSN.
    /// An instance without unflushed writes only saves its manifest.
    pub async fn raise_flushed_lsn(&self, lsn: u64) -> Result<()> {
        {
            let _drain = self.in_flight_writes.write().await;
            self.install(|v| v.rotated(lsn));
        }
        self.flush_immutables().await?;
        // Every record of this instance up to `lsn` applied before the drain
        // and is in an SSTable now; later records carry higher LSNs.
        self.manifest.write().raise_flushed_lsn(lsn);
        let snap = self.manifest.read().clone();
        self.manifest_manager.save(&snap).await
    }

    /// The manifest's flushed LSN: every record of this instance up to it
    /// is in an SSTable.
    pub fn flushed_lsn(&self) -> u64 {
        self.manifest.read().flushed_lsn
    }

    /// Flushes every frozen MemTable, the ones handed back by a failed flush
    /// included.
    async fn flush_immutables(&self) -> Result<()> {
        loop {
            while !self.version().immutables.is_empty() {
                self.flush_memtable().await?;
            }
            // The barrier: `flush_lock` is free only once every flush claimed
            // before this point has installed its SSTable or, failed, handed
            // its MemTable back to the immutables. Acquired
            // after the drain loop, never around it — `flush_memtable` takes
            // the same lock and `tokio::sync::Mutex` is not reentrant. The
            // check belongs under the guard: released first, the flush loop
            // could claim the next MemTable before it runs. A MemTable handed
            // back is drained again.
            let _flush = self.flush_lock.lock().await;
            let version = self.version();
            debug_assert!(version.flushing.is_empty());
            if version.immutables.is_empty() {
                return Ok(());
            }
        }
    }

    /// [`Self::shutdown_flush`], then truncates the WAL — for an engine that
    /// writes its WAL alone. Idempotent: a second call finds no handles left
    /// to join and flushes/truncates an already-clean state.
    ///
    /// A failed flush, save or sync skips the truncate: the WAL is then the
    /// only durable copy of the data, and the next startup replays it. The
    /// failure stays an `eprintln!`, not just `tracing::error!`: no tracing
    /// subscriber runs under `cargo test`, so this line is the only surviving
    /// evidence in a captured test log. Callers take no `Result` from this
    /// method, so a log line like "LSM engine shutdown complete." right after
    /// it only means the shutdown sequence ran to completion, not that the
    /// flush succeeded.
    pub async fn shutdown(&self) {
        if let Err(e) = self.shutdown_flush().await {
            eprintln!("[Engine] {e:#}");
            return;
        }

        // All data is now durable in SSTables — WAL entries are redundant.
        // Clear it so the next startup finds an empty WAL and skips
        // the unnecessary MemTable-to-SSTable flush cycle.
        if let Err(e) = self.wal.truncate().await {
            eprintln!("[Engine] Shutdown WAL truncate error: {e}");
        }
    }

    /// Signals background tasks to stop, joins them, then
    /// [`Self::persist_all`]; leaves the WAL alone.
    pub async fn shutdown_flush(&self) -> Result<()> {
        // Joined before touching MemTables below.
        self.stop_background_tasks().await;
        self.persist_all().await
    }

    /// Flushes every MemTable, saves the manifest, then syncs every vLog
    /// generation and the directories of SSTables, manifest and vLog. `Ok`
    /// means every write applied before the call is durable in an SSTable the
    /// saved manifest lists, its vLog bytes included, so the WAL may go. The
    /// syncs may follow the save: until the WAL goes, it covers everything
    /// the manifest names.
    ///
    /// A failed `flush_memtable` puts its MemTable back among the immutables,
    /// but nothing persisted its data. A failed manifest save after an
    /// earlier flush installed its SSTable leaves the table in L0 and in no
    /// MANIFEST on disk, where the next startup would not find it. Either way
    /// the WAL is the only durable copy, and this fails. A failed sync stops
    /// the server, which leaves the WAL to the next start as well.
    pub async fn persist_all(&self) -> Result<()> {
        self.flush_all_memtables().await.context("Flush error")?;
        // A no-op unless a flush's own save failed: the manifest carries the
        // version already on disk then.
        let snap = self.manifest.read().clone();
        self.manifest_manager.save(&snap).await.context("Manifest save error")?;
        self.sync_vlog_and_dirs().await.context("Sync error")
    }

    /// The LSN of the last record durable in this engine's WAL.
    pub async fn wal_head_lsn(&self) -> Result<u64> {
        Ok(self.wal.head_lsn().await?)
    }

    /// Signals the background tasks to stop and joins them, without the
    /// flush and WAL truncate of [`Self::shutdown`].
    pub(crate) async fn stop_background_tasks(&self) {
        // Flag for cheap sync checks + watch send to wake any loop that is
        // sleeping instead of leaving it to poll.
        self.shutdown.store(true, Ordering::Relaxed);
        let _ = self.shutdown_tx.send(true);

        // The lock cannot be held across the awaits in the loop, so the
        // handles are taken first.
        let handles = {
            let mut tasks = self.background_tasks.lock();
            std::mem::take(&mut *tasks)
        };
        for handle in handles {
            if let Err(e) = handle.await {
                eprintln!("[Engine] Background task join error: {e}");
            }
        }
    }

    /// The current sources as one value; holding it costs no lock.
    pub(crate) fn version(&self) -> Arc<Version> {
        self.version.get()
    }

    /// Installs the successor `f` builds from the current version — one
    /// install per change, synchronous, see [`VersionCell::install`].
    pub(crate) fn install(&self, f: impl FnOnce(&Version) -> Version) {
        self.version.install(f)
    }

    /// Draws the next stamp. While the clock's logical counter is saturated,
    /// yields to the runtime until the wall clock moves on.
    async fn next_timestamp(&self) -> Timestamp {
        loop {
            if let Some(stamp) = self.hlc.try_now() {
                return Timestamp::new(stamp.as_u64());
            }
            tokio::task::yield_now().await;
        }
    }

    /// Stamp of a point read: the last one the clock issued, raised to the
    /// wall clock, without issuing one. A confirmed write
    /// drew its stamp before its confirmation, so every later read sees it;
    /// the wall clock covers stored stamps no seed knows of (a manifest
    /// written before `max_timestamp`), as a drawn stamp did.
    fn read_timestamp(&self) -> Timestamp {
        let wall = HLCTimestamp::from_components(self.hlc.wall(), 0);
        Timestamp::new(self.hlc.peek().max(wall).as_u64())
    }

    /// Creates an MVCC snapshot and registers it with the [`SnapshotRegistry`].
    ///
    /// The returned guard deregisters itself when dropped, automatically
    /// advancing the low watermark used by the compaction filter.
    ///
    /// Unlike a point read, it draws a stamp of its own: one per snapshot,
    /// under the registry lock (see [`SnapshotRegistry::acquire_at`]).
    pub async fn snapshot(&self) -> RegistrySnapshot {
        self.snapshot_registry
            .acquire_at(|| {
                let stamp = self.hlc.try_now()?;
                #[cfg(test)]
                if let Some(hook) = &self.hooks.snapshot_stamp_drawn {
                    hook.pause();
                }
                Some(Timestamp::new(stamp.as_u64()))
            })
            .await
    }

    /// Test-only: the registry `snapshot` registers in.
    #[cfg(test)]
    pub(crate) fn snapshot_registry(&self) -> &SnapshotRegistry {
        &self.snapshot_registry
    }

    pub fn hlc(&self) -> &Arc<HybridLogicalClock> {
        &self.hlc
    }

    /// Handle to the flush-notification. The SHM snapshot
    /// publisher awaits it as an extra tick right after a MemTable flush.
    pub fn flush_notify(&self) -> Arc<Notify> {
        Arc::clone(&self.flush_notify)
    }

    /// Monotonic change epoch. Every change counted in a
    /// loaded value is visible to reads started after the load.
    pub fn change_epoch(&self) -> u64 {
        self.change_epoch.load(Ordering::Acquire)
    }

    /// Counts one change; call only once readers can see it.
    pub(super) fn raise_change_epoch(&self) {
        self.change_epoch.fetch_add(1, Ordering::Release);
    }

    /// Reader over the current version.
    pub(crate) fn build_reader(&self) -> LsmReader<'_> {
        LsmReader::new(self.version(), Arc::clone(&self.block_cache), &self.applying_batch)
    }

    /// Reader and snapshot of an unregistered point read at the current
    /// state. The version is taken before the stamp: compaction
    /// and GC only drop what every registered snapshot sees as shadowed, and
    /// the reader keeps its own sources as `Arc`s, so they still hold the
    /// newest version of every key at that stamp. A stamp taken first could
    /// meet a version whose compaction already dropped what the stamp sees.
    fn latest_view(&self) -> (LsmReader<'_>, Snapshot) {
        let reader = self.build_reader();
        (reader, Snapshot::new(self.read_timestamp()))
    }

    /// Point read at the current state, with `expire_at` (0 = no TTL) — the
    /// KV `get` path. Registers no snapshot, see [`Self::latest_view`].
    pub async fn get_latest_with_expiry(&self, key: &[u8]) -> Result<(GetResult, u64)> {
        let (reader, snapshot) = self.latest_view();
        reader.get_with_expiry(key, &snapshot).await
    }

    /// [`Self::get_latest_with_expiry`] plus the write stamp of the version
    /// read (0 = absent) — the KV `get` path, which serves it as `ETag`.
    pub async fn get_latest_with_stamp(&self, key: &[u8]) -> Result<(GetResult, u64, u64)> {
        let (reader, snapshot) = self.latest_view();
        reader.get_with_stamp(key, &snapshot).await
    }

    /// Metadata point read at the current state — the KV `meta` path; never
    /// dereferences the vLog. Registers no snapshot, see
    /// [`Self::latest_view`].
    pub async fn get_latest_with_metadata(&self, key: &[u8]) -> Result<Option<ValueWithMetadata>> {
        let (reader, snapshot) = self.latest_view();
        reader.get_with_metadata(key, &snapshot).await
    }

    /// MVCC-aware point read. Three-valued: a live value, an
    /// explicit NULL (`set_null`), or absent.
    pub async fn get_with_snapshot(
        &self,
        key: &[u8],
        snapshot: &Snapshot,
    ) -> Result<GetResult> {
        self.build_reader().get(key, snapshot).await
    }

    /// MVCC-aware point read returning value + metadata without dereferencing
    /// the VLog. Additive to [`Self::get_with_snapshot`].
    pub async fn get_with_metadata(
        &self,
        key: &[u8],
        snapshot: &Snapshot,
    ) -> Result<Option<ValueWithMetadata>> {
        self.build_reader().get_with_metadata(key, snapshot).await
    }

    /// Like [`Self::get_with_snapshot`], but also returns `expire_at`
    /// (absolute Unix seconds, 0 = no TTL) — for the backup export,
    /// which needs the remaining TTL alongside the value. Unlike
    /// [`Self::get_with_metadata`], VLog pointers are dereferenced.
    pub async fn get_with_expiry(
        &self,
        key: &[u8],
        snapshot: &Snapshot,
    ) -> Result<(GetResult, u64)> {
        self.build_reader().get_with_expiry(key, snapshot).await
    }

    /// Newest version of `key` as (write stamp, liveness) — the TTL sweeper's
    /// authoritative re-check. Takes no snapshot argument:
    /// the sweeper always wants the current state, so it is pulled internally
    /// and cannot accidentally be a stale one. It draws a fresh stamp instead
    /// of peeking: the sweeper dates its tombstone one above
    /// the version found, and the draw keeps that date within the clock.
    pub(super) async fn newest_version(&self, key: &[u8]) -> Result<Option<(Timestamp, VersionState)>> {
        let reader = self.build_reader();
        let snapshot = Snapshot::new(self.next_timestamp().await);
        reader.newest_version(key, &snapshot).await
    }

    /// Collects the `limit` smallest user-keys above `after` that carry *some*
    /// expired version. Deliberately a superset: no
    /// cross-source newest-first resolution happens here (no `decided` set
    /// over all keys) — [`Self::newest_version`] decides authoritatively.
    /// Key-only, no vLog I/O.
    pub(super) async fn scan_expired(&self, after: &[u8], limit: usize) -> Result<Vec<Vec<u8>>> {
        let mut candidates: BTreeSet<Vec<u8>> = BTreeSet::new();
        let now = now_secs();
        let mut checked = 0usize;

        let version = self.version();
        for mt in version.memtables_newest_first() {
            for (encoded_key, value) in mt.iter() {
                scan_expired_yield(&mut checked).await;
                let Some(user_key) = InternalKey::extract_user_key(&encoded_key) else {
                    continue;
                };
                if user_key <= after || value.version_state(now) != VersionState::Expired {
                    continue;
                }
                push_expired_candidate(&mut candidates, limit, user_key.to_vec());
            }
        }

        for level_sstables in &version.levels {
            for sstable in level_sstables {
                for entry in sstable.prefix_entries(&[], None) {
                    scan_expired_yield(&mut checked).await;
                    let (user_key, _ts, state) = entry?;
                    if state != VersionState::Expired || user_key.as_slice() <= after {
                        continue;
                    }
                    push_expired_candidate(&mut candidates, limit, user_key);
                }
                tokio::task::yield_now().await;
            }
        }

        Ok(candidates.into_iter().collect())
    }

    /// Block cache counters summed over its stripes, for the `/metrics`
    /// endpoint.
    pub fn block_cache_metrics(&self) -> Arc<crate::engines::lsm::block_cache::BlockCacheMetrics> {
        self.block_cache.metrics()
    }

    /// Rotates the active MemTable once it reached the size threshold.
    ///
    /// Drains in-flight writes first and holds the drain across the swap:
    /// every writer that already drew its stamp has applied it before
    /// the rotation, every later one stamps after it. Otherwise a slow writer
    /// could apply its older stamp into the fresh MemTable — a newer source
    /// holding an older version, which the source-ordered read path resolves
    /// the wrong way round. Must never run under this engine's own
    /// `in_flight_writes` read guard (self-deadlock); the write paths therefore
    /// call it before acquiring theirs.
    pub(super) async fn maybe_freeze_memtable(&self) -> Result<()> {
        let threshold = self.engine_config.memtable_size_threshold;
        if self.version().memtable.size_bytes() >= threshold {
            let _drain = self.in_flight_writes.write().await;
            self.install(|v| {
                if v.memtable.size_bytes() >= threshold {
                    v.rotated(self.last_applied_lsn())
                } else {
                    v.clone()
                }
            });
        }
        Ok(())
    }

    /// Returns once every write that already holds its in-flight guard has
    /// applied; writes admitted later are not waited for.
    pub(crate) async fn quiesce_writes(&self) {
        drop(self.in_flight_writes.write().await);
    }

    /// Like [`Self::quiesce_writes`], but keeps every later write out until
    /// the returned guard drops.
    pub(crate) async fn drain_writes(&self) -> tokio::sync::RwLockWriteGuard<'_, ()> {
        self.in_flight_writes.write().await
    }

    /// A write in flight, as far as [`Self::quiesce_writes`] can tell.
    #[cfg(test)]
    pub(crate) async fn in_flight_write_for_test(&self) -> tokio::sync::RwLockReadGuard<'_, ()> {
        self.in_flight_writes.read().await
    }

    /// Whether the client writes are refused for want of disk space or
    /// memory; the background writers that only write tombstones wait then.
    pub fn writes_refused(&self) -> bool {
        self.resources.check_write().is_err()
    }

    #[cfg(test)]
    pub(crate) fn resources(&self) -> &Resources {
        &self.resources
    }

    /// Highest LSN of a WAL record whose write reached the MemTable.
    pub fn last_applied_lsn(&self) -> u64 {
        self.last_applied_lsn.load(Ordering::Acquire)
    }

    /// Records that the write of WAL record `lsn` reached the MemTable;
    /// writes apply in any order, the highest LSN stays.
    fn applied(&self, lsn: u64) {
        self.last_applied_lsn.fetch_max(lsn, Ordering::Release);
    }

    /// Assigns the next watch-stream sequence, rings it, and broadcasts it
    /// — the single choke point every non-batch write path
    /// goes through. Every caller invokes this only after its own
    /// `memtable.set`: a crash between the two now drops the
    /// event instead of describing a write a replay might still undo.
    fn publish_change(&self, key: &[u8], op: OpType) {
        self.watch_log.publish(&self.change_tx, |seq| WalEvent { seq, key: key.to_vec(), op });
    }

    /// Appends a SET entry to the WAL and inserts the value into the MemTable.
    ///
    /// Large values (>= `MAX_VALUE_LENGTH`) are offloaded to the vLog; smaller
    /// ones are stored inline. `expire_at` is an absolute Unix timestamp (seconds)
    /// for TTL; `None` or `0` means no expiry.
    pub(super) async fn write_kv_pair(&self, key: &[u8], value: &[u8], expire_at: Option<u64>) -> Result<()> {
        self.write_kv_pair_admitted(key, value, expire_at, || Ok(())).await
    }

    /// [`Self::write_kv_pair`] that first runs `admit` under the in-flight
    /// guard; an error from it refuses the write before the stamp and the WAL,
    /// as does a shortage of disk space or memory. A write that holds the
    /// guard when the shortage begins goes through.
    pub(super) async fn write_kv_pair_admitted(
        &self,
        key: &[u8],
        value: &[u8],
        expire_at: Option<u64>,
        admit: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        // Freeze check first: its drain takes the write side of
        // `in_flight_writes`, which would deadlock under the guard below.
        self.maybe_freeze_memtable().await?;

        // In-flight guard: held from before
        // the stamp through `memtable.set`, so no rotation can fall into that
        // window and no pointer into a generation the Janitor just sealed is
        // still on its way into a MemTable. Inline values carry no generation
        // but need the guard all the same — the stamp ordering applies to
        // every write.
        let _guard = self.in_flight_writes.read().await;
        self.resources.check_write()?;
        admit()?;

        // Reserve, then stamp: a full WAL queue and a saturated clock are
        // waited out before the stamp. From the stamp to `send` no `.await` —
        // `send` fixes the record's LSN, so the stamps follow the LSNs.
        let permit = self.wal.reserve().await?;
        let timestamp = self.next_timestamp().await;
        let expire_at_val = expire_at.unwrap_or(0);

        // WAL entry: [type=1][ts:u64][key_len:u32][key][value_len:u32][value][expire_at:u64]
        let mut log_entry = Vec::new();
        log_entry.push(1u8);
        log_entry.extend_from_slice(&timestamp.as_u64().to_be_bytes());
        log_entry.extend_from_slice(&(key.len() as u32).to_be_bytes());
        log_entry.extend_from_slice(key);
        log_entry.extend_from_slice(&(value.len() as u32).to_be_bytes());
        log_entry.extend_from_slice(value);
        log_entry.extend_from_slice(&expire_at_val.to_be_bytes());
        let (_, lsn) = permit.send(log_entry).await?;

        let resolved = if value.len() >= self.engine_config.vlog_inline_threshold {
            let (file_id, offset) = append_to_active(&self.version, value, &self.vlog_failures).await?;
            Value::Pointer { file_id, offset, len: value.len(), expire_at }
        } else {
            Value::Inline(value.to_vec(), expire_at)
        };
        #[cfg(test)]
        if let Some((hooked, hook)) = &self.hooks.before_kv_pair_apply {
            if hooked.as_slice() == key {
                hook.pause().await;
            }
        }
        self.version().memtable.set(key.to_vec(), timestamp, resolved);
        self.applied(lsn);
        self.raise_change_epoch();

        // Broadcast after the apply is visible, not just WAL-durable: closes
        // the window where a racing delete's event could describe a state
        // that never becomes visible.
        self.publish_change(key, OpType::Set);
        Ok(())
    }

    /// Serialises one DELETE record (WAL type 2): [type=2][ts:u64][key_len:u32][key].
    /// Shared by the client delete path and the TTL sweeper.
    fn encode_tombstone_wal_record(timestamp: Timestamp, key: &[u8]) -> Vec<u8> {
        let mut log_entry = Vec::new();
        log_entry.push(2u8);
        log_entry.extend_from_slice(&timestamp.as_u64().to_be_bytes());
        log_entry.extend_from_slice(&(key.len() as u32).to_be_bytes());
        log_entry.extend_from_slice(key);
        log_entry
    }

    /// Appends a DELETE entry to the WAL and inserts a tombstone into the MemTable.
    pub(super) async fn write_tombstone(&self, key: &[u8]) -> Result<()> {
        self.write_tombstone_admitted(key, || Ok(())).await
    }

    /// [`Self::write_tombstone`], admitted like [`Self::write_kv_pair_admitted`].
    pub(super) async fn write_tombstone_admitted(&self, key: &[u8], admit: impl FnOnce() -> Result<()>) -> Result<()> {
        // Freeze check before the guard, then guard before the stamp — see
        // `write_kv_pair_admitted`.
        self.maybe_freeze_memtable().await?;
        let _guard = self.in_flight_writes.read().await;
        self.resources.check_write()?;
        admit()?;

        // Reserve, then stamp, no `.await` up to `send` — see `write_kv_pair_admitted`.
        let permit = self.wal.reserve().await?;
        let timestamp = self.next_timestamp().await;
        let (_, lsn) = permit.send(Self::encode_tombstone_wal_record(timestamp, key)).await?;

        // Still pinned after the WAL append; the guard above now closes the
        // inversion window this placement only narrowed.
        self.version().memtable.set(key.to_vec(), timestamp, Value::Tombstone);
        self.applied(lsn);
        self.raise_change_epoch();

        // Broadcast after the apply is visible — see `write_kv_pair_admitted`.
        self.publish_change(key, OpType::Delete);
        Ok(())
    }

    /// Pins the active MemTable — every tombstone of one sweep tick goes into
    /// exactly this one, never a newer one.
    pub(super) fn pin_memtable(&self) -> Arc<MemTable> {
        Arc::clone(&self.version().memtable)
    }

    /// Writes a tombstone dated `timestamp` into the *given* MemTable — the
    /// TTL sweeper's pinned one — while it is still the active one.
    /// Deliberately without `maybe_freeze_memtable`: a tombstone that ends
    /// up in a newer source than the value it dates against would win
    /// despite its older stamp. A write that drew the same stamp and is
    /// already in that MemTable keeps its entry; the tombstone and its event
    /// are then dropped.
    /// Sweeper-exclusive — [`Self::write_tombstone`] does not delegate here.
    /// Holds the in-flight guard like every other WAL writer, so a drain
    /// waits for it.
    ///
    /// Has a rotation frozen the pinned MemTable since the re-check that
    /// found the key expired, a newer value may sit in a source that a flush
    /// puts below the flushed LSN, while this record would be replayed above
    /// it after a crash: nothing is written, no event goes out, and `false`
    /// tells the sweeper to check the key again next tick.
    pub(super) async fn write_tombstone_at(
        &self,
        memtable: &Arc<MemTable>,
        key: &[u8],
        timestamp: Timestamp,
    ) -> Result<bool> {
        let _guard = self.in_flight_writes.read().await;
        // Every rotation takes the write side of the guard held here.
        if !Arc::ptr_eq(memtable, &self.version().memtable) {
            return Ok(false);
        }
        let permit = self.wal.reserve().await?;
        let (_, lsn) = permit.send(Self::encode_tombstone_wal_record(timestamp, key)).await?;

        let inserted = memtable.set_if_absent(key.to_vec(), timestamp, Value::Tombstone);
        self.applied(lsn);
        if !inserted {
            return Ok(true);
        }
        self.raise_change_epoch();

        // Broadcast after the apply is visible — see `write_kv_pair_admitted`.
        self.publish_change(key, OpType::Delete);
        Ok(true)
    }

    /// Appends a SET_NULL entry to the WAL and inserts a NULL marker into the
    /// MemTable: an update, not a delete — the key stays
    /// visible and overwrites older versions like a Put. Writes without
    /// expiry (`set_null` never carries a TTL).
    pub(super) async fn write_null(&self, key: &[u8]) -> Result<()> {
        self.write_null_admitted(key, || Ok(())).await
    }

    /// [`Self::write_null`], admitted like [`Self::write_kv_pair_admitted`].
    pub(super) async fn write_null_admitted(&self, key: &[u8], admit: impl FnOnce() -> Result<()>) -> Result<()> {
        // Freeze check before the guard, then guard before the stamp — see
        // `write_kv_pair_admitted`.
        self.maybe_freeze_memtable().await?;
        let _guard = self.in_flight_writes.read().await;
        self.resources.check_write()?;
        admit()?;

        // Reserve, then stamp, no `.await` up to `send` — see `write_kv_pair_admitted`.
        let permit = self.wal.reserve().await?;
        let timestamp = self.next_timestamp().await;

        // WAL entry: [type=4][ts:u64][key_len:u32][key] — type 3 is already
        // the batch record, so SetNull uses 4.
        let mut log_entry = Vec::new();
        log_entry.push(4u8);
        log_entry.extend_from_slice(&timestamp.as_u64().to_be_bytes());
        log_entry.extend_from_slice(&(key.len() as u32).to_be_bytes());
        log_entry.extend_from_slice(key);
        let (_, lsn) = permit.send(log_entry).await?;

        self.version().memtable.set(key.to_vec(), timestamp, Value::Null);
        self.applied(lsn);
        self.raise_change_epoch();

        // set_null is an update — a Set event, not Delete.
        // Broadcast after the apply is visible — see `write_kv_pair_admitted`.
        self.publish_change(key, OpType::Set);
        Ok(())
    }

    fn validate_batch_ops(&self, ops: &[BatchOp]) -> Result<()> {
        for op in ops {
            match op {
                BatchOp::Put { key, value } => {
                    validate_key(key, self.engine_config.max_key_length)?;
                    validate_value(value, self.engine_config.max_value_size)?;
                }
                BatchOp::Delete { key } => validate_key(key, self.engine_config.max_key_length)?,
            }
        }
        Ok(())
    }

    /// Serialises `ops` into one type-3 WAL record sharing `timestamp`.
    fn encode_batch_wal_record(timestamp: Timestamp, ops: &[BatchOp]) -> Vec<u8> {
        let mut log_entry = Vec::new();
        log_entry.push(3u8);
        log_entry.extend_from_slice(&timestamp.as_u64().to_be_bytes());
        log_entry.extend_from_slice(&(ops.len() as u32).to_be_bytes());
        for op in ops {
            match op {
                BatchOp::Put { key, value } => {
                    log_entry.push(1u8);
                    log_entry.extend_from_slice(&(key.len() as u32).to_be_bytes());
                    log_entry.extend_from_slice(key);
                    log_entry.extend_from_slice(&(value.len() as u32).to_be_bytes());
                    log_entry.extend_from_slice(value);
                    log_entry.extend_from_slice(&0u64.to_be_bytes());
                }
                BatchOp::Delete { key } => {
                    log_entry.push(2u8);
                    log_entry.extend_from_slice(&(key.len() as u32).to_be_bytes());
                    log_entry.extend_from_slice(key);
                }
            }
        }
        log_entry
    }

    /// Assigns `ops.len()` consecutive sequences in one lock section
    /// (`publish_many`), so a concurrent single-op write can never
    /// interleave into the middle of this batch's stream slice. Called only
    /// after the batch's MemTable apply, on `events` pre-extracted from the
    /// ops before `resolve_batch_values` consumes them — see `write_batch`.
    fn broadcast_batch_events(&self, events: &[(Vec<u8>, OpType)]) {
        let mut events = events.iter();
        self.watch_log.publish_many(&self.change_tx, events.len(), |seq| {
            let (key, op) = events.next().expect("publish_many calls `make` exactly `n` times");
            WalEvent { seq, key: key.clone(), op: op.clone() }
        });
    }

    /// Phase 1 of [`Self::write_batch`]: offloads large values to the vLog,
    /// yielding the MemTable-ready `(key, value)` pairs. Re-reads the vLog per
    /// op so a concurrent Janitor swap is observed.
    async fn resolve_batch_values(&self, ops: Vec<BatchOp>) -> Result<Vec<(Vec<u8>, Value)>> {
        let mut resolved = Vec::with_capacity(ops.len());
        for op in ops {
            resolved.push(match op {
                BatchOp::Put { key, value } => {
                    if value.len() >= self.engine_config.vlog_inline_threshold {
                        let (file_id, offset) = append_to_active(&self.version, &value, &self.vlog_failures).await?;
                        (key, Value::Pointer { file_id, offset, len: value.len(), expire_at: None })
                    } else {
                        (key, Value::Inline(value, None))
                    }
                }
                BatchOp::Delete { key } => (key, Value::Tombstone),
            });
        }
        Ok(resolved)
    }

    /// Writes all `ops` as ONE WAL record (type 3, single fsync) sharing one
    /// timestamp, then applies them to the MemTable. Recovery replays the
    /// record all-or-nothing, so the batch is atomic; while
    /// the apply runs, `applying_batch` hides it from readers on other
    /// threads.
    pub async fn write_batch(&self, ops: Vec<BatchOp>) -> Result<()> {
        self.write_batch_admitted(ops, || Ok(())).await
    }

    /// [`Self::write_batch`], admitted like [`Self::write_kv_pair_admitted`];
    /// an empty batch writes nothing and is not checked.
    pub(super) async fn write_batch_admitted(
        &self,
        ops: Vec<BatchOp>,
        admit: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        if ops.is_empty() {
            return Ok(());
        }
        self.validate_batch_ops(&ops)?;

        // Freeze check before the guard — see `write_kv_pair_admitted`.
        self.maybe_freeze_memtable().await?;

        // In-flight guard, held across the
        // whole batch: batches are bounded, so one guard per batch is simpler
        // than tracking which individual ops end up pointer-creating. Acquired
        // before the shared stamp and held through every `memtable.set` in
        // Phase 2 below.
        let _guard = self.in_flight_writes.read().await;
        self.resources.check_write()?;
        admit()?;

        // Reserve, then stamp, no `.await` up to `send` — see `write_kv_pair_admitted`.
        let permit = self.wal.reserve().await?;
        let timestamp = self.next_timestamp().await;
        let (_, lsn) = permit.send(Self::encode_batch_wal_record(timestamp, &ops)).await?;

        // Captured before `resolve_batch_values` below consumes `ops` — the
        // broadcast itself waits until after the Phase 2 apply.
        let batch_events: Vec<(Vec<u8>, OpType)> = ops
            .iter()
            .map(|op| match op {
                BatchOp::Put { key, .. } => (key.clone(), OpType::Set),
                BatchOp::Delete { key } => (key.clone(), OpType::Delete),
            })
            .collect();

        // Phase 1 (fallible): offload large values to the vLog BEFORE any
        // MemTable mutation — a vLog error must not leave the batch
        // half-applied (the WAL replays it fully after restart).
        let resolved = self.resolve_batch_values(ops).await?;

        // Phase 2 (infallible): apply the whole batch to the MemTable. The
        // slot is set before the first insert and cleared before the batch
        // counts as visible.
        let applied = last_op_per_key(resolved);
        let memtable = Arc::clone(&self.version().memtable);
        self.applying_batch.store(timestamp.as_u64(), Ordering::SeqCst);
        for (key, value) in applied {
            memtable.set(key, timestamp, value);
            #[cfg(test)]
            if let Some(hook) = &self.hooks.batch_first_applied {
                hook.pause();
            }
        }
        self.applying_batch.store(0, Ordering::Release);
        self.applied(lsn);
        self.raise_change_epoch();

        // Broadcast after the apply is visible — see `write_kv_pair_admitted`.
        self.broadcast_batch_events(&batch_events);
        Ok(())
    }

    /// Validated upsert without TTL.
    pub fn put<'a>(
        &'a self,
        key: &'a [u8],
        value: &'a [u8],
    ) -> impl std::future::Future<Output = Result<()>> + Send + 'a {
        async move {
            validate_key(key, self.engine_config.max_key_length)?;
            validate_value(value, self.engine_config.max_value_size)?;
            self.write_kv_pair(key, value, None).await
        }
    }

    /// Validated upsert with a TTL in seconds.
    ///
    /// The entry stays visible for at least `ttl_secs` and becomes invisible
    /// (treated as a tombstone) within a second after that.
    pub fn put_with_ttl<'a>(
        &'a self,
        key: &'a [u8],
        value: &'a [u8],
        ttl_secs: u64,
    ) -> impl std::future::Future<Output = Result<()>> + Send + 'a {
        async move {
            validate_key(key, self.engine_config.max_key_length)?;
            validate_value(value, self.engine_config.max_value_size)?;
            let expire_at = super::domain::expire_at_from_ttl(ttl_secs);
            self.write_kv_pair(key, value, Some(expire_at)).await
        }
    }

    /// Test-only: an already-expired entry (`expire_at = 1`) via the path of
    /// [`Self::put_with_ttl`]; unlike ttl 0 it survives wall-clock steps.
    #[cfg(test)]
    pub fn put_expired_for_test<'a>(
        &'a self,
        key: &'a [u8],
        value: &'a [u8],
    ) -> impl std::future::Future<Output = Result<()>> + Send + 'a {
        async move {
            validate_key(key, self.engine_config.max_key_length)?;
            validate_value(value, self.engine_config.max_value_size)?;
            self.write_kv_pair(key, value, Some(1)).await
        }
    }

    /// Sets `key` to the technical NULL state: an update, not a
    /// delete. Upserts a non-existent key into the NULL state.
    pub fn set_null<'a>(
        &'a self,
        key: &'a [u8],
    ) -> impl std::future::Future<Output = Result<()>> + Send + 'a {
        async move {
            validate_key(key, self.engine_config.max_key_length)?;
            self.write_null(key).await
        }
    }

    /// Returns all live (non-expired, non-tombstoned) user-keys that start with
    /// `prefix`, scanning only SSTable index/data blocks and the MemTables —
    /// no vLog I/O is performed.
    ///
    /// MVCC-correct: sources are visited newest-first (active MemTable,
    /// immutables newest-to-oldest, L0 newest-to-oldest, then L1..Ln) and per
    /// user-key the first version seen decides — a tombstone or expired entry
    /// as newest version suppresses all older ones.
    pub async fn scan_keys(&self, prefix: &[u8]) -> Result<Vec<Vec<u8>>> {
        self.scan_keys_limited(prefix, usize::MAX).await
    }

    /// Like [`Self::scan_keys`], but stops once `limit` live keys were found.
    /// The result is a sorted subset of the live keys (not necessarily the
    /// lexicographically smallest ones); an empty result means no live key
    /// with `prefix` exists.
    pub async fn scan_keys_limited(&self, prefix: &[u8], limit: usize) -> Result<Vec<Vec<u8>>> {
        self.scan_keys_inner(prefix, limit, None).await
    }

    /// Like [`Self::scan_keys`], but against an externally supplied MVCC
    /// `snapshot` instead of "now" (backup export): a write
    /// committed after the snapshot was acquired never appears, matching
    /// [`Self::get_with_snapshot`]'s consistency guarantee for point reads.
    pub async fn scan_keys_with_snapshot(&self, prefix: &[u8], snapshot: &Snapshot) -> Result<Vec<Vec<u8>>> {
        self.scan_keys_inner(prefix, usize::MAX, Some(snapshot)).await
    }

    /// Combines [`Self::scan_keys_limited`] and [`Self::scan_keys_with_snapshot`]:
    /// stops once `limit` keys visible under `snapshot` were found (rel
    /// SELECT fast-limit path). A key that only starts existing
    /// after `snapshot` never counts toward the cap, so it can never
    /// displace a snapshot-visible key the way it could under the
    /// unsnapshotted [`Self::scan_keys_limited`]. Like that method, the
    /// result is a sorted subset of the visible keys (not necessarily the
    /// lexicographically smallest ones) — LIMIT without ORDER BY accepts
    /// any subset, matching today's fast-path semantics.
    pub async fn scan_keys_limited_with_snapshot(
        &self,
        prefix: &[u8],
        limit: usize,
        snapshot: &Snapshot,
    ) -> Result<Vec<Vec<u8>>> {
        self.scan_keys_inner(prefix, limit, Some(snapshot)).await
    }

    /// Hands every live entry under `prefix` visible at `snapshot`, with value
    /// and metadata, to `emit` until it breaks, in one pass over the current
    /// sources (see [`LsmReader::scan_with_metadata`]) — the SHM snapshot
    /// builder's read. It blocks for the whole pass: call it off the engine
    /// thread.
    pub fn scan_with_metadata(
        &self,
        prefix: &[u8],
        snapshot: &Snapshot,
        emit: impl FnMut(&[u8], ValueWithMetadata) -> ControlFlow<()>,
    ) -> Result<()> {
        #[cfg(test)]
        if let Some(hook) = &self.hooks.before_scan {
            hook.pause();
        }
        self.build_reader().scan_with_metadata(prefix, snapshot, emit)
    }

    /// Shared implementation for [`Self::scan_keys_limited`]/
    /// [`Self::scan_keys_with_snapshot`]: `snapshot` of `None` matches every
    /// version currently live (today's `scan_keys` behavior).
    async fn scan_keys_inner(
        &self,
        prefix: &[u8],
        limit: usize,
        snapshot: Option<&Snapshot>,
    ) -> Result<Vec<Vec<u8>>> {
        let mut live: BTreeSet<Vec<u8>> = BTreeSet::new();
        // User keys already decided by a newer version (live OR dead).
        let mut decided: BTreeSet<Vec<u8>> = BTreeSet::new();
        let now = now_secs();
        let mut coop = YieldEvery::new(SCAN_KEYS_YIELD_INTERVAL);

        // One version for the whole scan: its yields hold an `Arc`, no guard,
        // and every source comes from the same state.
        let version = self.version();
        for mt in version.memtables_newest_first() {
            scan_memtable_for_prefix(
                mt,
                prefix,
                now,
                limit,
                snapshot,
                &self.applying_batch,
                &mut live,
                &mut decided,
                &mut coop,
            )
            .await;
        }
        for sstable in version.sstables_newest_first() {
            if scan_sstable_for_prefix(sstable, prefix, limit, snapshot, &mut live, &mut decided, &mut coop)
                .await?
            {
                break;
            }
        }

        // Collecting and releasing are O(keys) too; they tick like the sources.
        let mut keys = Vec::with_capacity(live.len());
        for key in live {
            coop.tick().await;
            keys.push(key);
        }
        while decided.pop_first().is_some() {
            coop.tick().await;
        }
        Ok(keys)
    }

    /// Returns a receiver that is notified for every WAL-confirmed write.
    ///
    /// Each event carries the key, operation type (`Set` / `Delete`), and its
    /// watch-stream sequence. The caller is responsible
    /// for filtering by prefix if needed. Events may be dropped if the
    /// receiver is too slow (lagged) — use [`Self::watch_decide_resume`] to
    /// recover from that via the replay ring.
    pub fn watch_subscribe(&self) -> broadcast::Receiver<WalEvent> {
        self.change_tx.subscribe()
    }

    /// Capacity of the live WAL-event broadcast (and of every per-domain
    /// relay channel too).
    pub fn wal_event_channel_capacity(&self) -> usize {
        self.engine_config.wal_event_channel_capacity
    }

    /// Current head of the watch-stream sequence — the `id:` a `reset`
    /// event carries.
    pub fn watch_head(&self) -> u64 {
        self.watch_log.head()
    }

    /// Full resume decision for the KV watch from a raw
    /// `Last-Event-ID`/`?last_event_id=` value, against [`Self::watch_epoch`]:
    /// a cursor of another shard or an earlier run resets.
    pub fn watch_decide_resume(&self, raw_id: Option<&str>) -> Resume<WalEvent> {
        self.watch_log.decide_resume(raw_id, WATCH_TAG, self.watch_epoch)
    }

    /// The epoch of this instance's watch event ids.
    pub fn watch_epoch(&self) -> u64 {
        self.watch_epoch
    }

    /// Test-only: freezes the active MemTable so `flush_memtable` persists it.
    /// Deliberately without the in-flight drain every production rotation runs
    /// — it is the lever tests use to
    /// build the stranded-stamp state the drain now prevents.
    #[cfg(test)]
    pub fn freeze_active_memtable(&self) {
        self.install(|v| {
            let mut next = v.clone();
            v.memtable.set_lsn_watermark(self.last_applied_lsn());
            next.immutables.push(Arc::clone(&v.memtable));
            next.memtable = Arc::new(MemTable::new());
            next
        });
    }

    /// Flushes the oldest immutable MemTable, returning the new SSTable's
    /// `file_id` (or `None` when there was nothing to flush).
    ///
    /// The claim moves the MemTable from the immutables into the flush slot
    /// in one install: the removal still keeps concurrent callers from
    /// flushing it twice, while readers keep seeing it until its SSTable is
    /// installed.
    ///
    /// [`Self::flush_lock`] spans claim and install, so the SSTables enter L0
    /// and the manifest in MemTable age order.
    pub async fn flush_memtable(&self) -> Result<Option<u64>> {
        let _flush = self.flush_lock.lock().await;
        let mut claimed = None;
        self.install(|v| {
            let mut next = v.clone();
            if !next.immutables.is_empty() {
                let memtable = next.immutables.remove(0);
                next.flushing.push(Arc::clone(&memtable));
                claimed = Some(memtable);
            }
            next
        });
        let Some(memtable_to_flush) = claimed else { return Ok(None) };

        match self.write_memtable_to_l0(&memtable_to_flush).await {
            Ok(file_id) => Ok(Some(file_id)),
            Err(e) => {
                self.abort_flush(&memtable_to_flush);
                Err(e)
            }
        }
    }

    /// Returns a failed flush's MemTable to the head of the immutables, so the
    /// next call is its retry. A no-op once the SSTable was installed — the
    /// flush slot no longer holds it then.
    fn abort_flush(&self, memtable: &Arc<MemTable>) {
        self.install(|v| {
            let mut next = v.clone();
            let claimed = next.flushing.len();
            next.flushing.retain(|m| !Arc::ptr_eq(m, memtable));
            if next.flushing.len() < claimed {
                next.immutables.insert(0, Arc::clone(memtable));
            }
            next
        });
    }

    /// Builds the SSTable of an already-claimed MemTable, installs it in L0 and
    /// persists the manifest. Any error leaves the claim to [`Self::abort_flush`].
    async fn write_memtable_to_l0(&self, memtable_to_flush: &Arc<MemTable>) -> Result<u64> {
        let mut builder = SSTableBuilder::new(memtable_to_flush.len());
        let mut smallest_key: Option<Vec<u8>> = None;
        let mut largest_key: Option<Vec<u8>> = None;
        let mut max_timestamp = 0u64;

        for (encoded_key, value) in memtable_to_flush.iter() {
            if smallest_key.is_none() || encoded_key < *smallest_key.as_ref().unwrap() {
                smallest_key = Some(encoded_key.clone());
            }
            if largest_key.is_none() || encoded_key > *largest_key.as_ref().unwrap() {
                largest_key = Some(encoded_key.clone());
            }
            // Raw value, not `Timestamp::cmp` — that one sorts newest first.
            if let Some(ts) = InternalKey::extract_timestamp(&encoded_key) {
                max_timestamp = max_timestamp.max(ts.as_u64());
            }

            match value {
                Value::Inline(data, expire_at) => {
                    // Small values are stored directly in the SSTable DataBlock —
                    // no VLog write needed.
                    builder.add_inline(
                        encoded_key,
                        data,
                        expire_at.unwrap_or(0),
                    );
                }
                Value::Pointer { file_id, offset, len, expire_at } => {
                    builder.add(
                        encoded_key,
                        crate::storage::format::ValuePointer {
                            file_id,
                            value_offset: offset,
                            value_len: len as u32,
                            expire_at: expire_at.unwrap_or(0),
                        },
                    );
                }
                Value::Null => {
                    builder.add(
                        encoded_key,
                        crate::storage::format::ValuePointer {
                            file_id: 0,
                            value_offset: crate::storage::format::NULL_OFFSET,
                            value_len: 0,
                            expire_at: 0,
                        },
                    );
                }
                Value::Tombstone => {
                    builder.add(
                        encoded_key,
                        crate::storage::format::ValuePointer {
                            file_id: 0,
                            value_offset: crate::storage::format::TOMBSTONE_OFFSET,
                            value_len: 0,
                            expire_at: 0,
                        },
                    );
                }
            }
        }

        let sstable_data = builder.finish()?;
        let file_size = sstable_data.len() as u64;
        let file_id = self.file_manager.allocate_file_id();

        #[cfg(test)]
        if let Some(hook) = &self.hooks.before_flush_write {
            hook.pause().await;
        }

        // The bytes come back, so the non-mmap reader below needs no copy.
        let sstable_data = match self.file_manager.write_sstable(file_id, sstable_data).await {
            Ok(data) => {
                self.flush_failures.succeeded();
                data
            }
            Err(e) => {
                return Err(match e.downcast_ref::<WriteError>() {
                    Some(failed) if self.flush_failures.stops_for(&failed.path, &failed.error) => {
                        crate::storage::fatal_write_error(&failed.path, &failed.error)
                    }
                    _ => e,
                });
            }
        };
        // Before the manifest changes in memory, not just before its save: a
        // compaction or GC cycle may save the shared manifest from then on,
        // and a saved manifest must name only files whose names are on disk.
        // A failed sync stops the server.
        crate::storage::sync_dirs_or_stop(&[self.file_manager.dir()]).await?;
        // The watermark the save below raises covers this MemTable's values.
        self.sync_vlog_generations().await?;

        let mut sstable = if self.engine_config.use_mmap {
            SSTableReader::open_mmap(&self.file_manager.file_path(file_id))?
        } else {
            SSTableReader::open(sstable_data)?
        };
        sstable.set_file_id(file_id);
        let sstable = Arc::new(sstable);
        // One install: the SSTable enters L0 as the MemTable leaves the flush
        // slot.
        self.install(|v| {
            let mut next = v.clone();
            if next.levels.is_empty() {
                next.levels.push(Vec::new());
            }
            next.levels[0].push(sstable);
            next.flushing.retain(|m| !Arc::ptr_eq(m, memtable_to_flush));
            next
        });

        {
            let mut manifest = self.manifest.write();
            manifest.add_sstable(SSTableMetadata {
                file_id,
                level: 0,
                smallest_key: smallest_key.unwrap_or_default(),
                largest_key: largest_key.unwrap_or_default(),
                file_size,
                max_timestamp,
            });
            manifest.raise_flushed_lsn(memtable_to_flush.lsn_watermark());
        }

        #[cfg(test)]
        if let Some(hook) = &self.hooks.before_flush_save {
            hook.pause().await;
        }

        let snap = self.manifest.read().clone();
        self.manifest_manager.save(&snap).await?;

        // Event trigger for the SHM snapshot publisher: a
        // stored permit means a flush that races the publisher is not missed.
        self.flush_notify.notify_one();
        Ok(file_id)
    }

    // `IoEngine` is not on the hot path yet and cannot be
    // stored as a field here: it is `!Send`/`!Sync` (its buffers and files
    // are confined to the engine thread's ring), while `LsmStorageEngine` is
    // shared via `Arc` with the reader pool. These
    // methods are additive and only run where a caller has direct, unspawned
    // access to both -- startup recovery here, and explicit calls from tests
    // or the storage thread.

    /// Registers every currently loaded SSTable with `io_engine` -- called
    /// once at startup, after recovery.
    pub async fn register_sstables_with_io_engine(&self, io_engine: &mut IoEngine) -> Result<()> {
        let version = self.version();
        for readers in &version.levels {
            for r in readers {
                let path = self.file_manager.file_path(r.file_id);
                if let Err(e) = io_engine.register_file(r.file_id, &path).await {
                    eprintln!("[Engine] Warning: cannot register SSTable {} with IoEngine: {e}", r.file_id);
                }
            }
        }
        Ok(())
    }

    /// Flushes the oldest immutable MemTable (see [`Self::flush_memtable`])
    /// and registers the resulting SSTable with `io_engine`.
    pub async fn flush_memtable_and_register(&self, io_engine: &mut IoEngine) -> Result<()> {
        if let Some(file_id) = self.flush_memtable().await? {
            let path = self.file_manager.file_path(file_id);
            io_engine.register_file(file_id, &path).await?;
        }
        Ok(())
    }

    /// Compacts the level that most urgently needs it.
    pub async fn compact_next_level(&self) -> Result<()> {
        let source_level = {
            let manifest = self.manifest.read();
            match select_level_to_compact(&manifest, &self.compaction_config) {
                Some(l) => l,
                None => return Ok(()),
            }
        };

        // Only a level that actually got compacted counts -- mirrors the
        // Janitor's `GcStats::ran` distinction so this stays an activity
        // signal instead of a poll-interval counter.
        if !self.compact_level(source_level).await?.is_empty() {
            self.compaction_runs.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Compacts `source_level` into `source_level + 1`, returning the file ids
    /// removed from the working set (the merged source + target inputs) so the
    /// caller can deregister exactly those from the `IoEngine`. Waits, with
    /// nothing removed, while the SSTable volume has less free space than its
    /// inputs take, the most its output can take.
    pub async fn compact_level(&self, source_level: usize) -> Result<Vec<u64>> {
        // Whole run under the maintenance lock: a GC cycle either sees this
        // compaction's output from its start or not at all, so it can neither
        // orphan the vLog pointers the output copied nor re-enter the SSTables
        // it merged away.
        let _maintenance = self.maintenance_lock.lock().await;

        // Inject the current low watermark so tombstones below it can be GC'd.
        let mut config = self.compaction_config.clone();
        config.low_watermark = self.snapshot_registry.low_watermark();

        let target_level = source_level + 1;
        let (src_metas, tgt_metas) = {
            let manifest = self.manifest.read();
            // Levels below the target stay as read here: flushes only add to
            // L0, compaction and GC hold the maintenance lock.
            config.bottommost = manifest.levels.iter().skip(target_level + 1).all(Vec::is_empty);
            select_sstables_for_level_compaction(source_level, &manifest)
        };

        if src_metas.is_empty() {
            return Ok(Vec::new());
        }
        let inputs: u64 = src_metas.iter().chain(&tgt_metas).map(|meta| meta.file_size).sum();
        let dir = self.file_manager.dir();
        if let Some(free) = self.resources.free_space(dir).filter(|&free| free < inputs) {
            if self.compaction_space.skipped() {
                tracing::warn!(
                    "Compaction of level {source_level} waits for disk space: {free} bytes free in {}, \
                     its inputs take {inputs}.",
                    dir.display()
                );
            }
            return Ok(Vec::new());
        }
        self.compaction_space.ran();

        // Load SSTables from disk.
        let use_mmap = self.engine_config.use_mmap;
        let src_sstables = self.open_sstable_readers(&src_metas, use_mmap).await?;
        let tgt_sstables = self.open_sstable_readers(&tgt_metas, use_mmap).await?;

        let job = CompactionJob::new(src_sstables, tgt_sstables, config);
        let new_metas = self.write_compacted_sstables(&job, target_level).await?;

        // Before the manifest changes in memory, not just before its save: a
        // flush may save the shared manifest from then on, and a saved
        // manifest must name only files whose names are on disk.
        crate::storage::sync_dirs(&[self.file_manager.dir()]).await?;

        // Atomically update manifest.
        {
            let mut manifest = self.manifest.write();
            for meta in &src_metas { manifest.remove_sstable(source_level, meta.file_id); }
            for meta in &tgt_metas { manifest.remove_sstable(target_level, meta.file_id); }
            for meta in &new_metas  { manifest.add_sstable(meta.clone()); }
        }

        let retired = {
            // Under the flush lock the manifest cannot gain an L0 table
            // between the rebuild's read and its swap, which would drop that
            // table from the read path.
            let _flush = self.flush_lock.lock().await;
            self.rebuild_levels_from_manifest([source_level, target_level], use_mmap).await?
        };

        #[cfg(test)]
        if let Some(hook) = &self.hooks.before_compaction_save {
            hook.pause().await;
        }

        // Persist manifest.
        let snap = self.manifest.read().clone();
        self.manifest_manager.save(&snap).await?;

        // The inputs go only once the manifest without them survives a power
        // loss.
        if let Err(e) = crate::storage::sync_dirs(&[self.manifest_manager.dir()]).await {
            let inputs: Vec<u64> = src_metas.iter().chain(&tgt_metas).map(|meta| meta.file_id).collect();
            eprintln!("[Engine] Warning: compacted SSTables {inputs:?} stay on disk: {e:#}");
            return Err(e);
        }

        self.retire_compacted_sstables(&retired, &src_metas, &tgt_metas).await;

        Ok(crate::engines::lsm::compaction::deleted_file_ids(&src_metas, &tgt_metas))
    }

    /// Opens serving readers for every `metas` entry (see
    /// [`Self::open_sstable_reader`]).
    async fn open_sstable_readers(
        &self,
        metas: &[SSTableMetadata],
        use_mmap: bool,
    ) -> Result<Vec<Arc<SSTableReader>>> {
        let mut sstables = Vec::new();
        for meta in metas {
            sstables.push(Arc::new(
                Self::open_sstable_reader(&self.file_manager, meta.file_id, use_mmap).await?,
            ));
        }
        Ok(sstables)
    }

    /// Writes and syncs `job`'s output SSTables one at a time and returns
    /// their target-level metadata. On an error it deletes the files it
    /// wrote, the unfinished one included: no manifest names them yet.
    async fn write_compacted_sstables(
        &self,
        job: &CompactionJob,
        target_level: usize,
    ) -> Result<Vec<SSTableMetadata>> {
        let mut written = Vec::new();
        let result = async {
            let mut run = job.compact()?;
            let mut new_metas = Vec::new();
            // A temporary file only once an entry for it is known.
            while run.has_next()? {
                let file_id = self.file_manager.allocate_file_id();
                let mut writer = self.file_manager.begin_sstable(file_id).await?;
                let summary = match run.next_sstable(&mut writer).await {
                    Ok(Some(summary)) => summary,
                    Ok(None) => {
                        writer.abort().await;
                        break;
                    }
                    Err(e) => {
                        writer.abort().await;
                        return Err(e);
                    }
                };
                writer.finish().await?;
                written.push(file_id);

                new_metas.push(SSTableMetadata {
                    file_id,
                    level: target_level,
                    smallest_key: summary.smallest_key,
                    largest_key: summary.largest_key,
                    file_size: summary.file_size,
                    max_timestamp: summary.max_timestamp,
                });
            }
            Ok(new_metas)
        }
        .await;

        if result.is_err() {
            for file_id in written {
                if let Err(e) = self.file_manager.delete_sstable(file_id).await {
                    eprintln!("[Engine] Warning: cannot delete compaction output {file_id}: {e}");
                }
            }
        }
        result
    }

    /// Smallest/largest encoded key in `sstable` (empty vecs when it has none)
    /// plus its highest raw MVCC timestamp (`SSTableMetadata::max_timestamp`).
    #[cfg(test)]
    pub(crate) fn sstable_key_range(sstable: &SSTableReader) -> Result<(Vec<u8>, Vec<u8>, u64)> {
        let mut smallest_key: Option<Vec<u8>> = None;
        let mut largest_key: Option<Vec<u8>> = None;
        let mut max_timestamp = 0u64;
        for entry in sstable.iter() {
            let (key, _) = entry?;
            if smallest_key.is_none() || key < smallest_key.as_ref().unwrap().as_slice() {
                smallest_key = Some(key.to_vec());
            }
            if largest_key.is_none() || key > largest_key.as_ref().unwrap().as_slice() {
                largest_key = Some(key.to_vec());
            }
            // Raw value, not `Timestamp::cmp` — that one sorts newest first.
            if let Some(ts) = InternalKey::extract_timestamp(key) {
                max_timestamp = max_timestamp.max(ts.as_u64());
            }
        }
        Ok((smallest_key.unwrap_or_default(), largest_key.unwrap_or_default(), max_timestamp))
    }

    /// Rebuilds `levels`' readers from the manifest (post manifest-swap) and
    /// returns the readers the install dropped; a table the version already
    /// holds keeps its reader (see [`Self::level_readers`]).
    ///
    /// Both levels keep their old readers until every new one is open, then
    /// change in one install.
    async fn rebuild_levels_from_manifest(
        &self,
        levels: [usize; 2],
        use_mmap: bool,
    ) -> Result<Vec<Arc<SSTableReader>>> {
        let current = self.version();
        let mut updates = Vec::with_capacity(levels.len());
        for lvl in levels {
            let metas = self.manifest.read().get_level(lvl).to_vec();
            updates.push((lvl, Self::level_readers(&self.file_manager, &current, &metas, use_mmap).await?));
        }

        #[cfg(test)]
        if let Some(hook) = &self.hooks.before_level_install {
            hook.pause().await;
        }

        let mut dropped = Vec::new();
        self.install(|v| {
            let next = v.with_levels(updates);
            dropped = v.sstables_dropped_by(&next);
            next
        });
        Ok(dropped)
    }

    /// Retires the dropped readers, invalidates cached blocks of the merged
    /// inputs, then deletes their files.
    async fn retire_compacted_sstables(
        &self,
        retired: &[Arc<SSTableReader>],
        src: &[SSTableMetadata],
        tgt: &[SSTableMetadata],
    ) {
        for reader in retired {
            reader.retire();
        }
        for meta in src.iter().chain(tgt.iter()) {
            self.block_cache.invalidate_file(meta.file_id);
        }

        for meta in src.iter().chain(tgt.iter()) {
            if let Err(e) = self.file_manager.delete_sstable(meta.file_id).await {
                eprintln!("[Engine] Warning: cannot delete SSTable {}: {e}", meta.file_id);
            }
        }
    }

    /// Compacts `source_level` (see [`Self::compact_level`]) and deregisters
    /// the deleted source/target SSTables from `io_engine` (scaffolding --
    /// see the note above [`Self::register_sstables_with_io_engine`]).
    pub async fn compact_level_and_deregister(
        &self,
        source_level: usize,
        io_engine: &mut IoEngine,
    ) -> Result<()> {
        // Deregister exactly what the compaction deleted -- selecting again here
        // could race a concurrent flush and diverge from the real deletions,
        // leaking IoEngine handles.
        for file_id in self.compact_level(source_level).await? {
            io_engine.unregister_file(file_id)?;
        }
        Ok(())
    }

    /// Legacy entry-point kept for compatibility (compacts L0 → L1).
    pub async fn compact(&self) -> Result<()> {
        self.compact_level(0).await?;
        Ok(())
    }

    /// Returns the data needed for the `/health` heartbeat response.
    pub fn heartbeat_data(&self) -> EngineHeartbeatData {
        let version = self.version();
        // A flush in flight is still MemTable-resident.
        let memtable_keys: u64 = version.memtables_newest_first().map(|m| m.len() as u64).sum();
        EngineHeartbeatData {
            estimated_memtable_keys: memtable_keys,
            vlog_size_bytes: version.vlog_size(),
            l0_sstable_count: version.level(0).len(),
        }
    }

    /// Number of successfully completed `compact_next_level` calls since
    /// process start.
    pub fn compaction_runs(&self) -> u64 {
        self.compaction_runs.load(Ordering::Relaxed)
    }

    /// Number of Janitor GC cycles that actually ran since process start.
    pub fn janitor_runs(&self) -> u64 {
        self.janitor_runs.load(Ordering::Relaxed)
    }

    pub fn stats(&self) -> EngineStats {
        let version = self.version();
        EngineStats {
            memtable_size: version.memtable.size_bytes(),
            // A flush in flight is still MemTable-resident.
            num_immutable_memtables: version.immutables.len() + version.flushing.len(),
            num_levels: version.levels.len(),
            total_sstables: version.levels.iter().map(Vec::len).sum(),
        }
    }
}

pub struct EngineHeartbeatData {
    pub estimated_memtable_keys: u64,
    pub vlog_size_bytes: u64,
    pub l0_sstable_count: usize,
}

#[derive(Debug)]
pub struct EngineStats {
    pub memtable_size: usize,
    pub num_immutable_memtables: usize,
    pub num_levels: usize,
    pub total_sstables: usize,
}

/// A single operation inside an atomic [`LsmStorageEngine::write_batch`].
#[derive(Debug, Clone)]
pub enum BatchOp {
    Put { key: Vec<u8>, value: Vec<u8> },
    Delete { key: Vec<u8> },
}

impl StorageEngine for LsmStorageEngine {
    // Generic two-valued contract (shared with the unrelated `KvStore` engine):
    // collapses `Null` into `None`, like every caller outside the KV engine.
    // Callers that must distinguish Null use `get_with_snapshot`.
    fn get(&self, key: &[u8]) -> impl std::future::Future<Output = Result<Option<Vec<u8>>>> + Send {
        async move { Ok(self.get_latest_with_expiry(key).await?.0.into_option()) }
    }

    fn set(&self, key: &[u8], value: &[u8]) -> impl std::future::Future<Output = Result<()>> + Send {
        async move {
            validate_key(key, self.engine_config.max_key_length)?;
            validate_value(value, self.engine_config.max_value_size)?;
            self.write_kv_pair(key, value, None).await
        }
    }

    fn delete(&self, key: &[u8]) -> impl std::future::Future<Output = Result<()>> + Send {
        async move {
            validate_key(key, self.engine_config.max_key_length)?;
            self.write_tombstone(key).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::wal::WriteAheadLog;
    use crate::core::storage_thread::{TestHub, WalTarget};
    use crate::storage::vlog::VLog;
    use crate::storage::file_manager::FileManager;
    use crate::storage::manifest::ManifestManager;
    use crate::engines::StorageEngine;
    use crate::engines::lsm::block_cache::BlockCacheKey;
    use crate::engines::lsm::hlc::HLCTimestamp;
    use crate::engines::lsm::watcher::OpType;
    use crate::storage::test_fault;

    // The JSON and rel instances run on these defaults, so they must stay
    // this fixed tuning.
    #[test]
    fn test_defaults_match_fixed_json_and_rel_tuning() {
        let engine = LsmEngineConfig::default();
        assert_eq!(engine.vlog_inline_threshold, 1024);
        assert_eq!(engine.memtable_size_threshold, 4 * 1024 * 1024);
        assert_eq!(engine.flush_check_interval_ms, 100);
        assert_eq!(engine.compaction_check_interval_ms, 1000);
        assert_eq!(engine.wal_event_channel_capacity, 256);
        assert!(engine.use_mmap);

        let compaction = CompactionConfig::default();
        assert_eq!(compaction.l0_compaction_threshold, 4);
        assert_eq!(compaction.l1_max_size, 100 * 1024 * 1024);
        assert_eq!(compaction.level_size_ratio, 10);
        assert_eq!(compaction.max_sstable_size, 64 * 1024 * 1024);
        assert!(compaction.low_watermark.is_none());

        let janitor = JanitorConfig::default();
        assert_eq!(janitor.check_interval_secs, 60);
        assert_eq!(janitor.dead_bytes_threshold, 0.30);
        assert_eq!(janitor.min_vlog_size_bytes, 64 * 1024 * 1024);

        let block_cache = BlockCacheConfig::default();
        assert_eq!(block_cache.capacity_bytes, 64 * 1024 * 1024);
        assert_eq!(block_cache.small_ratio, 0.10);
        assert_eq!(block_cache.ghost_capacity, 10_000);
    }

    async fn make_engine() -> (LsmStorageEngine, tempfile::TempDir) {
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
        (engine, dir)
    }

    async fn engine_on(dir: &tempfile::TempDir) -> LsmStorageEngine {
        let wal_path = dir.path().join("wal.log");
        let wal = Arc::new(WriteAheadLog::new(&wal_path).await.unwrap());
        let vlog_path = dir.path().join("vlog.log");
        let vlog = Arc::new(VLog::new(&vlog_path).await.unwrap());
        let file_manager = Arc::new(FileManager::new(dir.path()).await.unwrap());
        let manifest_manager = Arc::new(ManifestManager::new(dir.path()));
        LsmStorageEngine::new(
            wal, wal_path, vlog, vlog_path, file_manager, manifest_manager,
            LsmEngineOptions::default(),
        )
        .await
        .unwrap()
    }

    /// [`engine_on`] with the WAL at `<dir>/wal.log` written through `hub`.
    async fn engine_on_hub(dir: &tempfile::TempDir, hub: &TestHub) -> LsmStorageEngine {
        let wal_path = dir.path().join("wal.log");
        let vlog_path = dir.path().join("vlog.log");
        let vlog = Arc::new(VLog::new(&vlog_path).await.unwrap());
        let file_manager = Arc::new(FileManager::new(dir.path()).await.unwrap());
        let manifest_manager = Arc::new(ManifestManager::new(dir.path()));
        LsmStorageEngine::new(
            Arc::new(hub.wal(WalTarget::Kv)), wal_path, vlog, vlog_path, file_manager, manifest_manager,
            LsmEngineOptions::default(),
        )
        .await
        .unwrap()
    }

    /// Like `engine_on`, but with the SSTable directory split out from `dir`
    /// so a test can make it unwritable (fault injection)
    /// without touching the WAL/manifest paths too.
    async fn engine_with_sstable_dir(dir: &tempfile::TempDir, sstable_dir: &Path) -> LsmStorageEngine {
        let wal_path = dir.path().join("wal.log");
        let wal = Arc::new(WriteAheadLog::new(&wal_path).await.unwrap());
        let vlog_path = dir.path().join("vlog.log");
        let vlog = Arc::new(VLog::new(&vlog_path).await.unwrap());
        let file_manager = Arc::new(FileManager::new(sstable_dir).await.unwrap());
        let manifest_manager = Arc::new(ManifestManager::new(dir.path()));
        LsmStorageEngine::new(
            wal, wal_path, vlog, vlog_path, file_manager, manifest_manager,
            LsmEngineOptions::default(),
        )
        .await
        .unwrap()
    }

    /// Like `engine_on`, but with a custom MemTable freeze threshold in bytes
    /// (freeze and size-accounting tests). Every entry counts at least its
    /// 8-byte stamp, so a threshold of 1 rotates on every write after the first.
    async fn engine_with_threshold(dir: &tempfile::TempDir, threshold: usize) -> LsmStorageEngine {
        let wal_path = dir.path().join("wal.log");
        let wal = Arc::new(WriteAheadLog::new(&wal_path).await.unwrap());
        let vlog_path = dir.path().join("vlog.log");
        let vlog = Arc::new(VLog::new(&vlog_path).await.unwrap());
        let file_manager = Arc::new(FileManager::new(dir.path()).await.unwrap());
        let manifest_manager = Arc::new(ManifestManager::new(dir.path()));
        LsmStorageEngine::new(
            wal, wal_path, vlog, vlog_path, file_manager, manifest_manager,
            LsmEngineOptions {
                engine: LsmEngineConfig { memtable_size_threshold: threshold, ..Default::default() },
                ..Default::default()
            },
        )
        .await
        .unwrap()
    }

    /// Builds an engine on `dir` with `options`, wraps it in `Arc`, and
    /// starts its background tasks -- the shape every real bootstrap path
    /// uses (`main.rs`, `JsonEngine::bootstrap`, `RelEngine::bootstrap`).
    async fn boot_with_tasks(dir: &tempfile::TempDir, options: LsmEngineOptions) -> Arc<LsmStorageEngine> {
        let wal_path = dir.path().join("wal.log");
        let wal = Arc::new(WriteAheadLog::new(&wal_path).await.unwrap());
        let vlog_path = dir.path().join("vlog.log");
        let vlog = Arc::new(VLog::new(&vlog_path).await.unwrap());
        let file_manager = Arc::new(FileManager::new(dir.path()).await.unwrap());
        let manifest_manager = Arc::new(ManifestManager::new(dir.path()));
        let engine = Arc::new(
            LsmStorageEngine::new(wal, wal_path, vlog, vlog_path, file_manager, manifest_manager, options)
                .await
                .unwrap(),
        );
        engine.start_background_tasks();
        engine
    }

    // Wake + join: without the shutdown wake-up the Janitor's default 60s
    // sleep would blow this timeout; without the join nothing here would
    // prove the loops actually stopped. Bound chosen generously on purpose
    // (no tight time windows).
    #[test]
    fn test_shutdown_wakes_and_joins_background_tasks_promptly() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let engine = boot_with_tasks(&dir, LsmEngineOptions::default()).await;

            compio::time::timeout(Duration::from_secs(10), engine.shutdown())
                .await
                .expect("shutdown must be woken, not wait out the 60s Janitor interval");
        })
    }

    // Restart determinism: the test_disabled_smoke
    // pattern at the LSM level, now overlap-free by construction -- a
    // shutdown that returns before its tasks fully stop would let the old
    // instance's flush/compaction/GC race the new instance's recovery on the
    // same directory.
    #[test]
    fn test_restart_determinism_with_background_tasks() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            // Short poll intervals raise the odds that a loop is doing real work
            // (not just sleeping) at the moment shutdown() fires each iteration.
            let opts = || LsmEngineOptions {
                engine: LsmEngineConfig {
                    flush_check_interval_ms: 5,
                    compaction_check_interval_ms: 5,
                    ..Default::default()
                },
                ..Default::default()
            };

            let mut engine = boot_with_tasks(&dir, opts()).await;
            for i in 0..10u32 {
                let key = format!("k{i}").into_bytes();
                let value = format!("v{i}").into_bytes();
                engine.put(&key, &value).await.unwrap();
                engine.shutdown().await;

                engine = boot_with_tasks(&dir, opts()).await;
                assert_eq!(engine.get(&key).await.unwrap(), Some(value), "iteration {i}");
            }
            engine.shutdown().await;
        })
    }

    // Idempotency: a second shutdown() finds an
    // empty handle list and an already-flushed, already-truncated WAL --
    // must not panic or return an error.
    #[test]
    fn test_shutdown_is_idempotent() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let engine = boot_with_tasks(&dir, LsmEngineOptions::default()).await;
            engine.put(b"k", b"v").await.unwrap();

            engine.shutdown().await;
            engine.shutdown().await; // must not panic
        })
    }

    // No task leak: shutdown's mem::take leaves no
    // dangling JoinHandles behind -- checkable directly since the field is
    // private to this module.
    #[test]
    fn test_shutdown_leaves_no_task_handles() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let engine = boot_with_tasks(&dir, LsmEngineOptions::default()).await;

            engine.shutdown().await;

            assert!(engine.background_tasks.lock().is_empty());
        })
    }

    // A failed SSTable write persists nothing (the MemTable
    // goes back among the immutables), so the WAL is
    // the only durable copy -- shutdown() must not truncate it in that case.
    // The SSTable directory is split out from the WAL/manifest one so the
    // fault fails only the flush, not the truncate that would otherwise
    // follow it.
    #[test]
    fn test_shutdown_skips_wal_truncate_after_failed_flush() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let sstable_dir = dir.path().join("sstables");
            std::fs::create_dir_all(&sstable_dir).unwrap();
            let wal_path = dir.path().join("wal.log");

            let engine = engine_with_sstable_dir(&dir, &sstable_dir).await;
            engine.put(b"crash-key", b"crash-value").await.unwrap();

            test_fault::fail_writes_in(&sstable_dir);
            engine.shutdown().await;
            test_fault::allow_writes_in(&sstable_dir);

            assert!(
                std::fs::read(&wal_path).unwrap().len() as u64 > crate::core::wal::WAL_HEADER_LEN,
                "a failed shutdown flush must leave the WAL in place"
            );

            // Re-open replays the WAL and recovers the data.
            let engine2 = engine_with_sstable_dir(&dir, &sstable_dir).await;
            assert_eq!(engine2.get(b"crash-key").await.unwrap(), Some(b"crash-value".to_vec()));

            // Success case unchanged: a normal shutdown flush still truncates.
            engine2.put(b"post-recovery", b"v2").await.unwrap();
            engine2.shutdown().await;
            assert_eq!(
                std::fs::read(&wal_path).unwrap(),
                crate::core::wal::wal_header(engine2.last_applied_lsn()),
                "a successful shutdown flush still truncates the WAL"
            );
        })
    }

    // A flush whose manifest save fails after its install leaves the table
    // in L0 but in no MANIFEST on disk: shutdown must save the manifest
    // before it truncates the WAL, or the next start loses those writes.
    // With the SSTable directory split out, a fault in `dir` fails only the
    // manifest save.
    #[test]
    fn test_shutdown_saves_the_manifest_a_failed_flush_left_unsaved() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let sstable_dir = dir.path().join("sstables");
            std::fs::create_dir_all(&sstable_dir).unwrap();

            let engine = engine_with_sstable_dir(&dir, &sstable_dir).await;
            engine.put(b"k", b"v").await.unwrap();
            engine.freeze_active_memtable();
            test_fault::fail_writes_in(dir.path());
            let flushed = engine.flush_memtable().await;
            test_fault::allow_writes_in(dir.path());
            assert!(flushed.is_err(), "the manifest save must fail");
            assert_eq!(engine.version().level(0).len(), 1, "the table was installed before the save");

            engine.shutdown().await;
            drop(engine);

            let engine2 = engine_with_sstable_dir(&dir, &sstable_dir).await;
            assert_eq!(engine2.get(b"k").await.unwrap(), Some(b"v".to_vec()));
        })
    }

    // Batch: all ops visible after write, and WAL replay (record type 3)
    // restores them all-or-nothing after a restart without flush.
    #[test]
    fn test_write_batch_atomic_and_recovered() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let engine = engine_on(&dir).await;
            engine.put(b"pre", b"old").await.unwrap();
            engine
                .write_batch(vec![
                    BatchOp::Put { key: b"batch-a".to_vec(), value: b"1".to_vec() },
                    BatchOp::Put { key: b"batch-b".to_vec(), value: b"2".to_vec() },
                    BatchOp::Delete { key: b"pre".to_vec() },
                ])
                .await
                .unwrap();
            assert_eq!(engine.get(b"batch-a").await.unwrap(), Some(b"1".to_vec()));
            assert_eq!(engine.get(b"batch-b").await.unwrap(), Some(b"2".to_vec()));
            assert_eq!(engine.get(b"pre").await.unwrap(), None);
            drop(engine);

            let engine2 = engine_on(&dir).await;
            assert_eq!(engine2.get(b"batch-a").await.unwrap(), Some(b"1".to_vec()));
            assert_eq!(engine2.get(b"batch-b").await.unwrap(), Some(b"2".to_vec()));
            assert_eq!(engine2.get(b"pre").await.unwrap(), None);
        })
    }

    // A sweeper DELETE record sharing a client write's
    // stamp replays as it applied live — the client value stays.
    #[test]
    fn test_replayed_sweeper_tombstone_keeps_identical_internal_key() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let engine = engine_on(&dir).await;
            engine.put(b"k", b"client").await.unwrap();
            let (client_ts, _) = engine.newest_version(b"k").await.unwrap().unwrap();
            let memtable = engine.pin_memtable();
            engine.write_tombstone_at(&memtable, b"k", client_ts).await.unwrap();
            assert_eq!(engine.get(b"k").await.unwrap(), Some(b"client".to_vec()));
            drop(engine);

            let engine2 = engine_on(&dir).await;
            assert_eq!(engine2.get(b"k").await.unwrap(), Some(b"client".to_vec()));
        })
    }

    // Regression: a batch Delete still replaces the Put
    // of the same batch (shared stamp) on replay — the later op wins.
    #[test]
    fn test_replayed_batch_delete_replaces_put_of_same_batch() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let engine = engine_on(&dir).await;
            engine
                .write_batch(vec![
                    BatchOp::Put { key: b"k".to_vec(), value: b"v".to_vec() },
                    BatchOp::Delete { key: b"k".to_vec() },
                ])
                .await
                .unwrap();
            assert_eq!(engine.get(b"k").await.unwrap(), None);
            drop(engine);

            let engine2 = engine_on(&dir).await;
            assert_eq!(engine2.get(b"k").await.unwrap(), None);
        })
    }

    // A vLog failure mid-batch must not leave the batch half-applied to the
    // MemTable; the WAL still holds it, so replay applies it fully on restart.
    #[test]
    fn test_write_batch_vlog_error_is_atomic() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let engine = engine_on(&dir).await;
            engine.put(b"idx", b"old").await.unwrap();

            // Writes to /dev/full fail with ENOSPC: the batch's vLog appends fail.
            let full = Arc::new(VLog::new("/dev/full").await.unwrap());
            engine.install(|v| v.with_active_vlog(full, engine.last_applied_lsn()));
            let big = vec![b'x'; 4096]; // >= vlog_inline_threshold → vLog append
            let res = engine
                .write_batch(vec![
                    BatchOp::Delete { key: b"idx".to_vec() },
                    BatchOp::Put { key: b"doc1".to_vec(), value: big.clone() },
                    BatchOp::Put { key: b"doc2".to_vec(), value: big.clone() },
                ])
                .await;
            assert!(res.is_err(), "vLog failure must fail the batch");

            // No op of the failed batch may be visible, not even the leading Delete.
            assert_eq!(engine.get(b"idx").await.unwrap(), Some(b"old".to_vec()));
            assert_eq!(engine.get(b"doc1").await.unwrap(), None);
            assert_eq!(engine.get(b"doc2").await.unwrap(), None);
            drop(engine);

            // WAL replay restores the full batch.
            let engine2 = engine_on(&dir).await;
            assert_eq!(engine2.get(b"idx").await.unwrap(), None);
            assert_eq!(engine2.get(b"doc1").await.unwrap(), Some(big.clone()));
            assert_eq!(engine2.get(b"doc2").await.unwrap(), Some(big));
        })
    }

    // Recovery must persist WAL data before truncating the WAL: even if the
    // recovering engine never reaches shutdown (startup failure), a later
    // engine on the same paths must still see the data.
    #[test]
    fn test_recovered_data_survives_without_shutdown() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let engine = engine_on(&dir).await;
            engine.put(b"crash-key", b"v1").await.unwrap();
            drop(engine); // crash: data only in the WAL

            // Recovers the WAL, then is dropped without shutdown.
            let engine2 = engine_on(&dir).await;
            assert_eq!(engine2.get(b"crash-key").await.unwrap(), Some(b"v1".to_vec()));
            drop(engine2);

            let engine3 = engine_on(&dir).await;
            assert_eq!(engine3.get(b"crash-key").await.unwrap(), Some(b"v1".to_vec()));
        })
    }

    // An SSTable the manifest still lists but that can no
    // longer be opened must fail `new()` instead of silently installing a
    // partial level.
    #[test]
    fn test_new_fails_when_manifest_sstable_is_missing() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let engine = engine_on(&dir).await;
            engine.put(b"k", b"v").await.unwrap();
            engine.flush_all_memtables().await.unwrap();
            drop(engine);

            async fn try_reopen(dir: &tempfile::TempDir) -> Result<LsmStorageEngine> {
                let wal_path = dir.path().join("wal.log");
                let wal = Arc::new(WriteAheadLog::new(&wal_path).await.unwrap());
                let vlog_path = dir.path().join("vlog.log");
                let vlog = Arc::new(VLog::new(&vlog_path).await.unwrap());
                let file_manager = Arc::new(FileManager::new(dir.path()).await.unwrap());
                let manifest_manager = Arc::new(ManifestManager::new(dir.path()));
                LsmStorageEngine::new(
                    wal, wal_path, vlog, vlog_path, file_manager, manifest_manager,
                    LsmEngineOptions::default(),
                )
                .await
            }

            // Success case unchanged: the SSTable is intact, re-open succeeds.
            let engine2 = try_reopen(&dir).await.unwrap();
            assert_eq!(engine2.get(b"k").await.unwrap(), Some(b"v".to_vec()));
            drop(engine2);

            let sst_path = std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .find(|p| p.extension().and_then(|e| e.to_str()) == Some("sst"))
                .expect("flush must have produced an SSTable file");
            std::fs::remove_file(&sst_path).unwrap();

            let result = try_reopen(&dir).await;
            assert!(result.is_err(), "new() must fail when a manifested SSTable cannot be opened");
        })
    }

    // A backwards step of the system clock, reproduced deterministically: the
    // HLC is pushed ahead of the wall clock before the writes, so a restarted
    // engine seeding its clock from nothing would take snapshots older than
    // every stored version and read back nothing. No wall clock is touched.

    const HLC_SKEW_MS: u64 = 5_000;

    fn advance_hlc(engine: &LsmStorageEngine) {
        let ahead = engine.hlc().try_now().unwrap().physical() + HLC_SKEW_MS;
        engine.hlc().update(HLCTimestamp::from_components(ahead, 0)).unwrap();
    }

    // Every key's newest version moves to another instance under its own
    // stamp and expiry — overwritten, value-log, NULL, deleted and expired
    // ones alike, from SSTables and the MemTable — and that instance's clock,
    // behind the stamps here, issues its next stamp above all of them.
    #[test]
    fn test_export_raw_moves_every_newest_version_and_import_raw_stamps_above_it() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let source = engine_on(&dir).await;
            advance_hlc(&source);
            let large = vec![7u8; 2048];
            source.put(b"a", b"old").await.unwrap();
            source.put(b"a", b"new").await.unwrap();
            source.put(b"big", &large).await.unwrap();
            source.put(b"gone", b"v").await.unwrap();
            source.freeze_active_memtable();
            source.flush_memtable().await.unwrap();
            source.delete(b"gone").await.unwrap();
            source.set_null(b"nulled").await.unwrap();
            source.put_expired_for_test(b"expired", b"v").await.unwrap();
            source.put_with_ttl(b"ttl", "clé".as_bytes(), 3600).await.unwrap();

            let snapshot = source.snapshot().await;
            let reader = source.build_reader();
            let exported: Vec<RawEntry> = reader.export_raw(snapshot.snapshot()).unwrap().map(Result::unwrap).collect();
            let keys: Vec<&[u8]> = exported.iter().map(|entry| entry.key.as_slice()).collect();
            assert_eq!(keys, [&b"a"[..], b"big", b"expired", b"gone", b"nulled", b"ttl"]);
            let by_key = |key: &[u8]| exported.iter().find(|entry| entry.key == key).unwrap().clone();
            assert_eq!(by_key(b"a").value, RawValue::Bytes(b"new".to_vec()));
            assert_eq!(by_key(b"big").value, RawValue::Bytes(large.clone()));
            assert_eq!(by_key(b"gone").value, RawValue::Tombstone);
            assert_eq!(by_key(b"nulled").value, RawValue::Null);
            assert_eq!((by_key(b"expired").value, by_key(b"expired").expire_at), (RawValue::Bytes(b"v".to_vec()), 1));
            assert!(by_key(b"ttl").expire_at > 1);
            for key in [&b"a"[..], b"big", b"nulled", b"ttl"] {
                assert_eq!(by_key(key).stamp, source.get_latest_with_stamp(key).await.unwrap().2);
            }
            let newest = exported.iter().map(|entry| entry.stamp).max().unwrap();

            let other = tempfile::TempDir::new().unwrap();
            let wal_path = other.path().join("wal.log");
            let wal = Arc::new(WriteAheadLog::new(&wal_path).await.unwrap());
            let vlog_path = other.path().join("vlog.log");
            let vlog = Arc::new(VLog::new(&vlog_path).await.unwrap());
            let file_manager = Arc::new(FileManager::new(other.path()).await.unwrap());
            let manifest_manager = Arc::new(ManifestManager::new(other.path()));
            let options = LsmEngineOptions { recovery: Recovery::External, ..LsmEngineOptions::default() };
            let target =
                LsmStorageEngine::new(wal, wal_path, vlog, vlog_path, file_manager, manifest_manager, options).await.unwrap();
            assert!(target.hlc().peek().as_u64() < newest, "the target's clock starts behind the stamps");
            target.import_raw(exported.clone()).await.unwrap();

            let snapshot = target.snapshot().await;
            let reader = target.build_reader();
            let imported: Vec<RawEntry> = reader.export_raw(snapshot.snapshot()).unwrap().map(Result::unwrap).collect();
            assert_eq!(imported, exported);
            for key in [&b"a"[..], b"big", b"nulled", b"ttl", b"gone", b"expired"] {
                let (source_read, target_read) =
                    (source.get_latest_with_stamp(key).await.unwrap(), target.get_latest_with_stamp(key).await.unwrap());
                assert_eq!(source_read, target_read, "{}", String::from_utf8_lossy(key));
            }
            target.put(b"after", b"v").await.unwrap();
            assert!(target.get_latest_with_stamp(b"after").await.unwrap().2 > newest);
        })
    }

    /// `engine` on a clock that reads `now`, its logical counter saturated
    /// at `now`'s millisecond.
    fn saturate_clock(engine: &mut LsmStorageEngine, now: &Arc<AtomicU64>) {
        let read = Arc::clone(now);
        engine.hlc = Arc::new(HybridLogicalClock::with_clock(move || read.load(Ordering::SeqCst)));
        engine.hlc.seed(HLCTimestamp::from_components(now.load(Ordering::SeqCst), u16::MAX).as_u64());
        assert_eq!(engine.hlc.try_now(), None);
    }

    // A saturated clock parks a write and a snapshot on the runtime instead
    // of the thread: other tasks keep running — this one moves the clock —
    // and both draw their stamp once the wall clock has moved on.
    #[test]
    fn test_a_saturated_clock_parks_writes_and_snapshots_without_blocking_the_thread() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let mut engine = engine_on(&dir).await;
            let now = Arc::new(AtomicU64::new(1_700_000_000_000));
            saturate_clock(&mut engine, &now);
            let engine = Arc::new(engine);

            let put = compio::runtime::spawn({
                let engine = Arc::clone(&engine);
                async move { engine.put(b"k", b"v").await }
            });
            let snapshot = compio::runtime::spawn({
                let engine = Arc::clone(&engine);
                async move { engine.snapshot().await.snapshot().timestamp().as_u64() }
            });
            for _ in 0..100 {
                tokio::task::yield_now().await;
            }
            assert!(!put.is_finished(), "the write waits for the clock");
            assert!(!snapshot.is_finished(), "the snapshot waits for the clock");

            now.fetch_add(1, Ordering::SeqCst);
            put.await.unwrap().unwrap();
            let snapshot = HLCTimestamp::new(snapshot.await.unwrap());
            let (_, _, stamp) = engine.get_latest_with_stamp(b"k").await.unwrap();
            let moved_on = now.load(Ordering::SeqCst);
            assert_eq!(HLCTimestamp::new(stamp).physical(), moved_on);
            assert_eq!(snapshot.physical(), moved_on);
        })
    }

    async fn put_range(engine: &LsmStorageEngine, range: std::ops::Range<u32>) {
        for i in range {
            engine.put(format!("k{i}").as_bytes(), b"v").await.unwrap();
        }
    }

    async fn assert_all_readable(engine: &LsmStorageEngine, range: std::ops::Range<u32>) {
        for i in range {
            assert_eq!(
                engine.get(format!("k{i}").as_bytes()).await.unwrap(),
                Some(b"v".to_vec()),
                "k{i} must be visible after the restart"
            );
        }
    }

    // Test 1: crash variant — the WAL still holds the advanced stamps.
    #[test]
    fn test_crash_restart_sees_data_written_ahead_of_the_wall_clock() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let engine = engine_on(&dir).await;
            advance_hlc(&engine);
            put_range(&engine, 0..20).await;
            drop(engine); // crash: the data lives only in the WAL

            let engine2 = engine_on(&dir).await;
            assert_all_readable(&engine2, 0..20).await;
        })
    }

    // Test 2: clean-shutdown variant — the WAL holds only its header
    // afterwards, so only the manifest high-water mark can carry the clock
    // across the restart.
    #[test]
    fn test_clean_shutdown_restart_sees_data_written_ahead_of_the_wall_clock() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let engine = engine_on(&dir).await;
            advance_hlc(&engine);
            put_range(&engine, 0..20).await;
            engine.shutdown().await;
            drop(engine);

            assert_eq!(
                std::fs::read(dir.path().join("wal.log")).unwrap(),
                crate::core::wal::wal_header(20),
                "a clean shutdown leaves no WAL record to seed from"
            );

            let engine2 = engine_on(&dir).await;
            assert_all_readable(&engine2, 0..20).await;
        })
    }

    // Test 3: a re-put after the restart must outrank the stored version.
    // The compaction is the discriminator — it keeps only the highest-stamped
    // version of a key, so a re-put stamped below the stored one is not
    // merely invisible for a while, it is dropped for good.
    #[test]
    fn test_reput_after_restart_outranks_the_stored_version() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let engine = engine_on(&dir).await;
            advance_hlc(&engine);
            engine.put(b"k", b"old").await.unwrap();
            engine.shutdown().await;
            drop(engine);

            let engine2 = engine_on(&dir).await;
            engine2.put(b"k", b"new").await.unwrap();
            assert_eq!(engine2.get(b"k").await.unwrap(), Some(b"new".to_vec()));

            // Both versions now meet in one merged SSTable.
            engine2.flush_all_memtables().await.unwrap();
            engine2.compact_level(0).await.unwrap();
            assert_eq!(
                engine2.get(b"k").await.unwrap(),
                Some(b"new".to_vec()),
                "the compaction must keep the re-put value, not the older-stamped one"
            );
            engine2.shutdown().await;
            drop(engine2);

            let engine3 = engine_on(&dir).await;
            assert_eq!(
                engine3.get(b"k").await.unwrap(),
                Some(b"new".to_vec()),
                "the re-put value must survive a further restart"
            );
        })
    }

    // Test 4: an older manifest has no `max_timestamp` field; it
    // must still load (serde default 0) with the WAL seed doing the work.
    #[test]
    fn test_manifest_without_max_timestamp_loads_and_wal_seed_applies() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let engine = engine_on(&dir).await;
            advance_hlc(&engine);
            put_range(&engine, 0..5).await;
            engine.flush_all_memtables().await.unwrap();
            put_range(&engine, 5..10).await;
            drop(engine); // crash: the WAL still holds every key

            // Rewrite the manifest in the older format.
            let manifest_path = dir.path().join("MANIFEST");
            let mut json: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
            for level in json["levels"].as_array_mut().unwrap() {
                for meta in level.as_array_mut().unwrap() {
                    assert!(meta.as_object_mut().unwrap().remove("max_timestamp").is_some());
                }
            }
            std::fs::write(&manifest_path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();

            let loaded = ManifestManager::new(dir.path()).load().await.unwrap();
            let meta = loaded.get_level(0).first().expect("the flush must have produced an SSTable");
            assert_eq!(meta.max_timestamp, 0, "an old manifest reads as 0, without a migration run");

            let engine2 = engine_on(&dir).await;
            assert_all_readable(&engine2, 0..10).await;
        })
    }

    // Point reads peek at the clock, raised to the wall
    // clock. A store whose manifest predates `max_timestamp` and whose WAL
    // is empty seeds nothing, yet once the wall clock has passed its data,
    // reads before the first write see every key, as a drawn stamp did.
    #[test]
    fn test_reads_before_the_first_write_see_a_store_without_max_timestamp() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let engine = engine_on(&dir).await;
            put_range(&engine, 0..5).await;
            let newest = engine.hlc().peek();
            engine.shutdown().await;
            drop(engine);

            let manifest_path = dir.path().join("MANIFEST");
            let mut json: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
            for level in json["levels"].as_array_mut().unwrap() {
                for meta in level.as_array_mut().unwrap() {
                    assert!(meta.as_object_mut().unwrap().remove("max_timestamp").is_some());
                }
            }
            std::fs::write(&manifest_path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();

            let engine2 = engine_on(&dir).await;
            assert_eq!(engine2.hlc().peek().as_u64(), 0, "nothing seeds the clock");
            // The last write may share the current millisecond; the wall clock's
            // `(ms, 0)` covers it once that millisecond is over.
            while HybridLogicalClock::physical_time() <= newest.physical() {
                compio::time::sleep(Duration::from_millis(1)).await;
            }
            assert_all_readable(&engine2, 0..5).await;
        })
    }

    #[test]
    fn test_put_get_basic() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put(b"key1", b"value1").await.unwrap();
            let result = engine.get(b"key1").await.unwrap();
            assert_eq!(result, Some(b"value1".to_vec()));
        })
    }

    #[test]
    fn test_put_upsert() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put(b"key1", b"value1").await.unwrap();
            engine.put(b"key1", b"value2").await.unwrap();
            let result = engine.get(b"key1").await.unwrap();
            assert_eq!(result, Some(b"value2".to_vec()));
        })
    }

    #[test]
    fn test_delete_returns_none() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put(b"key1", b"value1").await.unwrap();
            engine.delete(b"key1").await.unwrap();
            let result = engine.get(b"key1").await.unwrap();
            assert_eq!(result, None);
        })
    }

    #[test]
    fn test_resurrection() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put(b"key1", b"value1").await.unwrap();
            engine.delete(b"key1").await.unwrap();
            engine.put(b"key1", b"value3").await.unwrap();
            let result = engine.get(b"key1").await.unwrap();
            assert_eq!(result, Some(b"value3".to_vec()));
        })
    }

    #[test]
    fn test_set_null_is_update_not_delete() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put(b"key1", b"value1").await.unwrap();
            engine.set_null(b"key1").await.unwrap();
            let snap = engine.snapshot().await;
            assert_eq!(engine.get_with_snapshot(b"key1", snap.snapshot()).await.unwrap(), GetResult::Null);
        })
    }

    #[test]
    fn test_put_after_set_null_overwrites() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.set_null(b"key1").await.unwrap();
            engine.put(b"key1", b"value1").await.unwrap();
            assert_eq!(engine.get(b"key1").await.unwrap(), Some(b"value1".to_vec()));
        })
    }

    #[test]
    fn test_delete_after_set_null_is_absent() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.set_null(b"key1").await.unwrap();
            engine.delete(b"key1").await.unwrap();
            let snap = engine.snapshot().await;
            assert_eq!(engine.get_with_snapshot(b"key1", snap.snapshot()).await.unwrap(), GetResult::Absent);
        })
    }

    #[test]
    fn test_set_null_on_nonexistent_key_creates_it() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let snap = engine.snapshot().await;
            assert_eq!(engine.get_with_snapshot(b"ghost", snap.snapshot()).await.unwrap(), GetResult::Absent);

            engine.set_null(b"ghost").await.unwrap();
            let snap = engine.snapshot().await;
            assert_eq!(engine.get_with_snapshot(b"ghost", snap.snapshot()).await.unwrap(), GetResult::Null);
        })
    }

    // empty (0-byte Put) and NULL are distinct value states.
    #[test]
    fn test_empty_value_distinct_from_null() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put(b"empty", b"").await.unwrap();
            engine.set_null(b"null_key").await.unwrap();

            let snap = engine.snapshot().await;
            assert_eq!(
                engine.get_with_snapshot(b"empty", snap.snapshot()).await.unwrap(),
                GetResult::Present(Vec::new())
            );
            assert_eq!(engine.get_with_snapshot(b"null_key", snap.snapshot()).await.unwrap(), GetResult::Null);
        })
    }

    #[test]
    fn test_scan_keys_includes_null() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.set_null(b"user:1").await.unwrap();
            let keys = engine.scan_keys(b"user:").await.unwrap();
            assert!(keys.contains(&b"user:1".to_vec()), "NULL keys must appear in scans");
        })
    }

    // NULL must survive a MemTable flush to SSTable and a subsequent
    // compaction — never garbage-collected like a tombstone.
    #[test]
    fn test_set_null_survives_flush_and_compaction() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.set_null(b"n").await.unwrap();
            freeze_and_flush(&engine).await;
            let snap = engine.snapshot().await;
            assert_eq!(engine.get_with_snapshot(b"n", snap.snapshot()).await.unwrap(), GetResult::Null);

            // A second L0 table forces an L0 -> L1 compaction that must preserve it.
            engine.put(b"other", b"v").await.unwrap();
            freeze_and_flush(&engine).await;
            engine.compact_level(0).await.unwrap();

            let snap = engine.snapshot().await;
            assert_eq!(engine.get_with_snapshot(b"n", snap.snapshot()).await.unwrap(), GetResult::Null);
            assert!(engine.scan_keys(b"n").await.unwrap().contains(&b"n".to_vec()));
        })
    }

    // NULL written but never flushed must survive a WAL replay after restart.
    #[test]
    fn test_set_null_survives_wal_recovery() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let engine = engine_on(&dir).await;
            engine.set_null(b"n").await.unwrap();
            drop(engine); // crash: data only in the WAL

            let engine2 = engine_on(&dir).await;
            let snap = engine2.snapshot().await;
            assert_eq!(engine2.get_with_snapshot(b"n", snap.snapshot()).await.unwrap(), GetResult::Null);
        })
    }

    #[test]
    fn test_empty_key_rejected() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let err = engine.set(b"", b"value").await;
            assert!(err.is_err(), "empty key must be rejected");
        })
    }

    #[test]
    fn test_key_too_long_rejected() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let long_key = vec![b'x'; MAX_KEY_LENGTH + 1];
            let err = engine.set(&long_key, b"value").await;
            assert!(err.is_err(), "key exceeding MAX_KEY_LENGTH must be rejected");
        })
    }

    #[test]
    fn test_value_too_large_rejected() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let large_value = vec![0u8; MAX_VALUE_SIZE_LIMIT + 1];
            let err = engine.set(b"key", &large_value).await;
            assert!(err.is_err(), "value exceeding MAX_VALUE_SIZE_LIMIT must be rejected");
        })
    }

    #[test]
    fn test_ttl_key_readable_before_expiry() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            // Large TTL (1h): this test only checks immediate readability, not
            // expiry, so the window must stay open regardless of suite load.
            engine.put_with_ttl(b"ttl_key", b"value", 3600).await.unwrap();
            let result = engine.get(b"ttl_key").await.unwrap();
            assert_eq!(result, Some(b"value".to_vec()));
        })
    }

    #[test]
    fn test_ttl_key_expires() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            // Immediate readability is covered by test_ttl_key_readable_before_expiry.
            engine.put_expired_for_test(b"ttl_key", b"value").await.unwrap();
            assert!(engine.get(b"ttl_key").await.unwrap().is_none());
        })
    }

    // Worst case for the stamp: written at second W.95, read 1.1 s later in
    // second W + 2.
    #[test]
    fn test_ttl_holds_for_the_full_ttl_span() {
        const WRITE_SECS: u64 = 1_700_000_000;
        const TTL_SECS: u64 = 2;
        let expire_at = crate::engines::lsm::domain::expire_at_from(WRITE_SECS, TTL_SECS);
        assert!(!crate::storage::format::is_expired(expire_at, WRITE_SECS + 2), "a 2s TTL must survive 1.1s");
    }

    // format::is_expired treats `Some(0)` as "no TTL",
    // not "expired" -- this only stays correct because no write path ever
    // produces it. Covers all three write paths: `put` (None),
    // `put_with_ttl` (including ttl_secs == 0), and WAL replay.
    #[test]
    fn test_ttl_paths_never_produce_some_zero_expire_at() {
        crate::core::engine_runtime::block_on(async {
            let (engine, dir) = make_engine().await;
            engine.put(b"no_ttl", b"v").await.unwrap();
            engine.put_with_ttl(b"expired_now", b"v", 0).await.unwrap();
            engine.put_with_ttl(b"future", b"v", 60).await.unwrap();

            fn assert_no_some_zero(value: &Value) {
                let expire_at = match value {
                    Value::Inline(_, expire_at) => *expire_at,
                    Value::Pointer { expire_at, .. } => *expire_at,
                    Value::Null | Value::Tombstone => None,
                };
                assert_ne!(expire_at, Some(0), "no write path may produce Some(0)");
            }

            for (_, value) in engine.version().memtable.iter() {
                assert_no_some_zero(&value);
            }

            // WAL replay: the live engine hasn't truncated its WAL yet, so
            // applying its entries to another engine reflects exactly what a
            // restart would see.
            let wal_path = dir.path().join("wal.log");
            let (replayed, _replayed_dir) = make_engine().await;
            for (_, entry) in crate::core::wal::recover_all(&wal_path).await.unwrap().entries {
                replayed.apply_entry(entry).await.unwrap();
            }
            for (_, value) in replayed.version().memtable.iter() {
                assert_no_some_zero(&value);
            }
        })
    }

    #[test]
    fn test_scan_keys_prefix() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put(b"user:1", b"alice").await.unwrap();
            engine.put(b"user:2", b"bob").await.unwrap();
            engine.put(b"item:1", b"thing").await.unwrap();
            let keys = engine.scan_keys(b"user:").await.unwrap();
            assert_eq!(keys.len(), 2);
            assert!(keys.contains(&b"user:1".to_vec()));
            assert!(keys.contains(&b"user:2".to_vec()));
        })
    }

    #[test]
    fn test_scan_keys_excludes_tombstoned() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put(b"user:1", b"alice").await.unwrap();
            engine.put(b"user:2", b"bob").await.unwrap();
            engine.delete(b"user:1").await.unwrap();
            let keys = engine.scan_keys(b"user:").await.unwrap();
            assert!(!keys.contains(&b"user:1".to_vec()));
            assert!(keys.contains(&b"user:2".to_vec()));
        })
    }

    // Regression: a delete must stay effective once the live version — and
    // later the tombstone itself — reside in SSTables.
    #[test]
    fn test_scan_keys_excludes_tombstoned_after_flush() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put(b"user:1", b"alice").await.unwrap();
            engine.put(b"user:2", b"bob").await.unwrap();
            freeze_and_flush(&engine).await; // live versions now in an SSTable
            engine.delete(b"user:1").await.unwrap();

            let keys = engine.scan_keys(b"user:").await.unwrap();
            assert_eq!(keys, vec![b"user:2".to_vec()]);

            // Tombstone flushed to a second SSTable — still suppressed.
            freeze_and_flush(&engine).await;
            let keys = engine.scan_keys(b"user:").await.unwrap();
            assert_eq!(keys, vec![b"user:2".to_vec()]);
        })
    }

    // Regression: an older tombstone in a frozen MemTable must not hide a
    // newer re-creation of the same key in the active MemTable.
    #[test]
    fn test_scan_keys_sees_recreation_after_frozen_tombstone() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put(b"user:1", b"alice").await.unwrap();
            engine.delete(b"user:1").await.unwrap();
            engine.freeze_active_memtable(); // tombstone now in an immutable MemTable
            engine.put(b"user:1", b"alice2").await.unwrap();

            let keys = engine.scan_keys(b"user:").await.unwrap();
            assert_eq!(keys, vec![b"user:1".to_vec()]);
        })
    }

    #[test]
    fn test_scan_keys_limited() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            for i in 0..10 {
                engine.put(format!("user:{i}").as_bytes(), b"v").await.unwrap();
            }
            engine.delete(b"user:3").await.unwrap();

            let keys = engine.scan_keys_limited(b"user:", 4).await.unwrap();
            assert_eq!(keys.len(), 4);
            assert!(!keys.contains(&b"user:3".to_vec()));

            let all = engine.scan_keys_limited(b"user:", 100).await.unwrap();
            assert_eq!(all.len(), 9);
        })
    }

    // Note: the limit break in the SSTable sweep is only reachable once
    // keys live in an SSTable (unflushed keys hit the MemTable path). Flush
    // first, then trip the limit during the sweep.
    #[test]
    fn test_scan_keys_limited_stops_in_sstable_sweep() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            for i in 0..10 {
                engine.put(format!("user:{i}").as_bytes(), b"v").await.unwrap();
            }
            freeze_and_flush(&engine).await;
            let keys = engine.scan_keys_limited(b"user:", 4).await.unwrap();
            assert_eq!(keys.len(), 4);
        })
    }

    // Note: the TTL-expiry branch of scan_memtable_for_prefix is otherwise
    // only covered by `get`. An expired key must not appear in scan_keys.
    #[test]
    fn test_scan_keys_excludes_ttl_expired() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put_expired_for_test(b"user:1", b"alice").await.unwrap();
            engine.put(b"user:2", b"bob").await.unwrap();
            let keys = engine.scan_keys(b"user:").await.unwrap();
            assert!(!keys.contains(&b"user:1".to_vec()));
            assert!(keys.contains(&b"user:2".to_vec()));
        })
    }

    // Writes after the snapshot (put, delete, set_null) must not change what
    // the pinned scan sees, while the unpinned scan_keys sees the new state.
    #[test]
    fn test_scan_keys_with_snapshot_hides_later_writes() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put(b"user:1", b"alice").await.unwrap();
            engine.put(b"user:2", b"bob").await.unwrap();
            let snap = engine.snapshot().await;

            engine.put(b"user:3", b"carol").await.unwrap(); // new key after snapshot
            engine.delete(b"user:1").await.unwrap(); // delete after snapshot
            engine.set_null(b"user:2").await.unwrap(); // set_null after snapshot

            let pinned = engine.scan_keys_with_snapshot(b"user:", snap.snapshot()).await.unwrap();
            assert_eq!(pinned, vec![b"user:1".to_vec(), b"user:2".to_vec()]);

            let live = engine.scan_keys(b"user:").await.unwrap();
            assert_eq!(live, vec![b"user:2".to_vec(), b"user:3".to_vec()]);
        })
    }

    // Same guarantee once the pre-snapshot data has been flushed to SSTables
    // and the post-snapshot write lands in a newer SSTable: a key tombstoned
    // as of the snapshot and later resurrected must stay invisible.
    #[test]
    fn test_scan_keys_with_snapshot_respects_flushed_versions() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put(b"user:1", b"v1").await.unwrap();
            freeze_and_flush(&engine).await; // SSTable 1: user:1 = v1
            engine.delete(b"user:1").await.unwrap();
            freeze_and_flush(&engine).await; // SSTable 2: user:1 tombstoned

            let snap = engine.snapshot().await;

            engine.put(b"user:1", b"v2").await.unwrap(); // resurrection after snapshot
            freeze_and_flush(&engine).await; // SSTable 3: user:1 = v2

            let pinned = engine.scan_keys_with_snapshot(b"user:", snap.snapshot()).await.unwrap();
            assert!(pinned.is_empty(), "key tombstoned as of the snapshot must not appear");

            let live = engine.scan_keys(b"user:").await.unwrap();
            assert_eq!(live, vec![b"user:1".to_vec()], "current state must show the resurrection");
        })
    }

    // NULL keys count as live under a pinned snapshot too.
    #[test]
    fn test_scan_keys_with_snapshot_includes_null() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.set_null(b"user:1").await.unwrap();
            let snap = engine.snapshot().await;
            let keys = engine.scan_keys_with_snapshot(b"user:", snap.snapshot()).await.unwrap();
            assert_eq!(keys, vec![b"user:1".to_vec()]);
        })
    }

    // Expiry uses wall-clock time, not the snapshot timestamp -- an entry
    // written before the snapshot that is expired now must not appear
    // (matches every other read path).
    #[test]
    fn test_scan_keys_with_snapshot_excludes_expired() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put_expired_for_test(b"user:1", b"alice").await.unwrap();
            let snap = engine.snapshot().await;
            let keys = engine.scan_keys_with_snapshot(b"user:", snap.snapshot()).await.unwrap();
            assert!(keys.is_empty(), "TTL-expired entry must not appear even under an older snapshot");
        })
    }

    // Test 1 (the core case): a key that only starts existing after the
    // snapshot must never occupy one of the capped slots, even when it sorts
    // ahead of the pre-snapshot keys. Counterproof alongside: today's
    // unsnapshotted scan_keys_limited IS displaced by such a ghost -- the
    // difference this method fixes.
    #[test]
    fn test_scan_keys_limited_with_snapshot_excludes_ghosts_from_cap() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            for i in 0..10 {
                engine.put(format!("z:m{i}").as_bytes(), b"v").await.unwrap();
            }
            let snap = engine.snapshot().await;
            // Ghosts: written after the snapshot, and sort ahead of "z:m*".
            for i in 0..5 {
                engine.put(format!("z:a{i}").as_bytes(), b"v").await.unwrap();
            }

            let keys = engine.scan_keys_limited_with_snapshot(b"z:", 5, snap.snapshot()).await.unwrap();
            assert_eq!(keys.len(), 5, "cap must be filled entirely by pre-snapshot keys");
            assert!(keys.iter().all(|k| k.starts_with(b"z:m")), "no ghost key may occupy a cap slot");

            let unsnapshotted = engine.scan_keys_limited(b"z:", 5).await.unwrap();
            assert!(
                unsnapshotted.iter().any(|k| k.starts_with(b"z:a")),
                "today's unsnapshotted cap must be displaced by ghosts, or this is no longer a counterproof"
            );
        })
    }

    // Test 2: a key deleted after the snapshot was taken still counts toward
    // the cap and appears in the result (point-in-time consistency).
    #[test]
    fn test_scan_keys_limited_with_snapshot_keeps_deleted_after_snapshot() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put(b"user:1", b"v").await.unwrap();
            let snap = engine.snapshot().await;
            engine.delete(b"user:1").await.unwrap();

            let keys = engine.scan_keys_limited_with_snapshot(b"user:", 10, snap.snapshot()).await.unwrap();
            assert_eq!(keys, vec![b"user:1".to_vec()]);
        })
    }

    // Test 3: once the cap is filled while scanning a newer source, an older
    // source's further snapshot-visible keys are never reached -- still a
    // correct (if not minimal) subset, exactly `limit` entries (same
    // "subset, not necessarily smallest" semantics as the unsnapshotted
    // test_scan_keys_limited_stops_in_sstable_sweep above).
    #[test]
    fn test_scan_keys_limited_with_snapshot_stops_at_cap_across_sources() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            for i in 0..5 {
                engine.put(format!("user:{i}").as_bytes(), b"v").await.unwrap();
            }
            freeze_and_flush(&engine).await; // SSTable: user:0..4
            for i in 5..10 {
                engine.put(format!("user:{i}").as_bytes(), b"v").await.unwrap();
            }
            let snap = engine.snapshot().await; // all 10 visible: 5 in the SSTable, 5 in the active MemTable

            let full = engine.scan_keys_limited_with_snapshot(b"user:", 100, snap.snapshot()).await.unwrap();
            assert_eq!(full.len(), 10, "sanity: all 10 must be snapshot-visible when uncapped");

            let keys = engine.scan_keys_limited_with_snapshot(b"user:", 4, snap.snapshot()).await.unwrap();
            assert_eq!(
                keys.len(),
                4,
                "must stop exactly at the cap even though 6 more visible keys remain in the older SSTable"
            );
        })
    }

    // Test 4a: a TTL-expired key must not occupy a cap slot even though it
    // was written -- and became snapshot-visible -- before the snapshot;
    // wall-clock expiry still applies under a capped snapshot scan, same as
    // the uncapped scan_keys_with_snapshot. A cap of 1 makes the assertion
    // discriminating: if the expired key ("user:1", sorting first) wrongly
    // held the one slot, the live "user:2" would never appear.
    #[test]
    fn test_scan_keys_limited_with_snapshot_excludes_expired_from_cap() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put_expired_for_test(b"user:1", b"alice").await.unwrap();
            engine.put(b"user:2", b"bob").await.unwrap();
            let snap = engine.snapshot().await;
            let keys = engine.scan_keys_limited_with_snapshot(b"user:", 1, snap.snapshot()).await.unwrap();
            assert_eq!(
                keys,
                vec![b"user:2".to_vec()],
                "an expired key must not occupy the cap slot ahead of a live one"
            );
        })
    }

    // Test 4b: a NULL key (present, not deleted) counts as live and
    // does occupy a cap slot.
    #[test]
    fn test_scan_keys_limited_with_snapshot_includes_null() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.set_null(b"user:1").await.unwrap();
            let snap = engine.snapshot().await;
            let keys = engine.scan_keys_limited_with_snapshot(b"user:", 10, snap.snapshot()).await.unwrap();
            assert_eq!(keys, vec![b"user:1".to_vec()]);
        })
    }

    // All keys stay in the active MemTable (no flush).

    // Test 1: keys before, inside and behind the range, one a prefix of others.
    #[test]
    fn test_scan_keys_memtable_range_returns_exactly_the_prefix_keys() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let keys: [&[u8]; 6] = [b"aa", b"ab", b"abc", b"abd", b"ac", b"b"];
            for key in keys {
                engine.put(key, b"v").await.unwrap();
            }

            let scanned = engine.scan_keys(b"ab").await.unwrap();
            assert_eq!(scanned, vec![b"ab".to_vec(), b"abc".to_vec(), b"abd".to_vec()]);
        })
    }

    // Test 2: several versions per key in the range — the newest decides.
    #[test]
    fn test_scan_keys_memtable_range_newest_version_decides() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put(b"ab:1", b"v1").await.unwrap();
            engine.put(b"ab:1", b"v2").await.unwrap();
            engine.delete(b"ab:1").await.unwrap();
            engine.put(b"ab:2", b"v1").await.unwrap();
            engine.delete(b"ab:2").await.unwrap();
            engine.put(b"ab:2", b"v2").await.unwrap();
            engine.put(b"ac", b"v").await.unwrap();

            let scanned = engine.scan_keys(b"ab").await.unwrap();
            assert_eq!(scanned, vec![b"ab:2".to_vec()]);
        })
    }

    // Test 3: `limit` stops after exactly `limit` hits; keys around the range
    // never count.
    #[test]
    fn test_scan_keys_limited_memtable_range_stops_at_limit() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put(b"aa", b"v").await.unwrap();
            for i in 0..10 {
                engine.put(format!("ab:{i}").as_bytes(), b"v").await.unwrap();
            }
            engine.put(b"ac", b"v").await.unwrap();

            let scanned = engine.scan_keys_limited(b"ab", 3).await.unwrap();
            assert_eq!(scanned.len(), 3);
            assert!(scanned.iter().all(|k| k.starts_with(b"ab:")));
        })
    }

    // Test 4: an empty prefix still reads the whole MemTable.
    #[test]
    fn test_scan_keys_empty_prefix_returns_all_live_keys() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let keys: [&[u8]; 5] = [b"\x00k", b"ab", b"b", b"zz", b"\xffk"];
            for key in keys {
                engine.put(key, b"v").await.unwrap();
            }
            engine.delete(b"b").await.unwrap();

            let scanned = engine.scan_keys(b"").await.unwrap();
            assert_eq!(scanned, vec![b"\x00k".to_vec(), b"ab".to_vec(), b"zz".to_vec(), b"\xffk".to_vec()]);
        })
    }

    // Test 5: under a snapshot, newer versions in the range stay invisible and
    // the older visible version decides.
    #[test]
    fn test_scan_keys_with_snapshot_memtable_range_older_version_decides() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put(b"ab:1", b"v1").await.unwrap();
            engine.put(b"ab:2", b"v1").await.unwrap();
            engine.delete(b"ab:2").await.unwrap();
            engine.put(b"ac", b"v1").await.unwrap();
            let snap = engine.snapshot().await;
            engine.delete(b"ab:1").await.unwrap();
            engine.put(b"ab:2", b"v2").await.unwrap();
            engine.put(b"ab:3", b"v1").await.unwrap();

            let scanned = engine.scan_keys_with_snapshot(b"ab", snap.snapshot()).await.unwrap();
            assert_eq!(scanned, vec![b"ab:1".to_vec()]);
        })
    }

    // A shorter user key plus its stamp bytes can start with the prefix: it
    // must neither be returned nor end the range before a real match.
    #[test]
    fn test_scan_keys_skips_shorter_key_whose_stamp_starts_with_prefix() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put(b"k", b"v").await.unwrap();
            let (ts, _) = engine.newest_version(b"k").await.unwrap().unwrap();
            let mut prefix = b"k".to_vec();
            prefix.push(ts.to_be_bytes()[0]);
            // All-0xFF tail: sorts behind the encoded "k" plus stamp.
            let mut matching = prefix.clone();
            matching.resize(1 + 8, 0xFF);
            engine.put(&matching, b"v").await.unwrap();

            let scanned = engine.scan_keys(&prefix).await.unwrap();
            assert_eq!(scanned, vec![matching]);
        })
    }

    // Regression: with two overlapping L0 tables, get must return the newest
    // version, not the one in the oldest (first-flushed) table.
    #[test]
    fn test_get_newest_version_across_l0_tables() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put(b"k", b"v1").await.unwrap();
            freeze_and_flush(&engine).await; // L0 table 1: k=v1
            engine.put(b"k", b"v2").await.unwrap();
            freeze_and_flush(&engine).await; // L0 table 2: k=v2

            assert_eq!(engine.get(b"k").await.unwrap(), Some(b"v2".to_vec()));
        })
    }

    // Regression: a tombstone in a newer L0 table must suppress the live
    // version in an older L0 table (no resurrection).
    #[test]
    fn test_get_tombstone_in_newer_l0_table_wins() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put(b"k", b"v1").await.unwrap();
            freeze_and_flush(&engine).await;
            engine.delete(b"k").await.unwrap();
            freeze_and_flush(&engine).await;

            assert_eq!(engine.get(b"k").await.unwrap(), None);
        })
    }

    // A snapshot taken between the two versions must skip the (invisible)
    // newer L0 table and still find the old version in the older one.
    #[test]
    fn test_get_snapshot_between_l0_versions_sees_old() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put(b"k", b"v1").await.unwrap();
            freeze_and_flush(&engine).await;
            let snap = engine.snapshot().await;
            engine.put(b"k", b"v2").await.unwrap();
            freeze_and_flush(&engine).await;

            assert_eq!(
                engine.get_with_snapshot(b"k", snap.snapshot()).await.unwrap(),
                GetResult::Present(b"v1".to_vec())
            );
            assert_eq!(engine.get(b"k").await.unwrap(), Some(b"v2".to_vec()));
        })
    }

    // Regression: with two frozen (unflushed) MemTables, get must serve the
    // newest version — frozen tables are pushed to the back of the list.
    #[test]
    fn test_get_newest_version_across_immutable_memtables() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put(b"k", b"v1").await.unwrap();
            engine.freeze_active_memtable();
            engine.put(b"k", b"v2").await.unwrap();
            engine.freeze_active_memtable();

            assert_eq!(engine.get(b"k").await.unwrap(), Some(b"v2".to_vec()));
        })
    }

    // expire_at is 0 for a plain put, and the absolute TTL deadline for
    // put_with_ttl -- both against an externally acquired snapshot.
    #[test]
    fn test_get_with_expiry_reports_ttl_and_zero() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put(b"plain", b"v").await.unwrap();
            engine.put_with_ttl(b"ttl", b"v", 3600).await.unwrap();
            let snap = engine.snapshot().await;

            let (result, expire_at) = engine.get_with_expiry(b"plain", snap.snapshot()).await.unwrap();
            assert_eq!(result, GetResult::Present(b"v".to_vec()));
            assert_eq!(expire_at, 0);

            let (result, expire_at) = engine.get_with_expiry(b"ttl", snap.snapshot()).await.unwrap();
            assert_eq!(result, GetResult::Present(b"v".to_vec()));
            assert!(expire_at > now_secs(), "expire_at must be an absolute future timestamp");
        })
    }

    // A NULL entry is reported distinctly, with expire_at 0 (set_null never
    // carries a TTL).
    #[test]
    fn test_get_with_expiry_distinguishes_null() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.set_null(b"n").await.unwrap();
            let snap = engine.snapshot().await;
            assert_eq!(
                engine.get_with_expiry(b"n", snap.snapshot()).await.unwrap(),
                (GetResult::Null, 0)
            );
        })
    }

    // A missing key reports Absent with expire_at 0.
    #[test]
    fn test_get_with_expiry_absent_for_missing_key() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let snap = engine.snapshot().await;
            assert_eq!(
                engine.get_with_expiry(b"ghost", snap.snapshot()).await.unwrap(),
                (GetResult::Absent, 0)
            );
        })
    }

    // Snapshot isolation holds for the expiry-carrying read too, including
    // across a flush to SSTable and a VLog-backed (large) value.
    #[test]
    fn test_get_with_expiry_snapshot_consistency_across_flush() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let big = vec![b'x'; 4096]; // >= vlog_inline_threshold -> VLog pointer
            engine.put(b"k", &big).await.unwrap();
            freeze_and_flush(&engine).await;
            let snap = engine.snapshot().await;

            engine.put(b"k", b"newer").await.unwrap();
            freeze_and_flush(&engine).await;

            let (result, expire_at) = engine.get_with_expiry(b"k", snap.snapshot()).await.unwrap();
            assert_eq!(result, GetResult::Present(big));
            assert_eq!(expire_at, 0);
            assert_eq!(engine.get(b"k").await.unwrap(), Some(b"newer".to_vec()));
        })
    }

    #[test]
    fn test_watcher_receives_set_event() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let mut rx = engine.watch_subscribe();
            engine.put(b"watch_key", b"val").await.unwrap();
            let event = rx.recv().await.unwrap();
            assert_eq!(event.key, b"watch_key");
            assert!(matches!(event.op, OpType::Set));
        })
    }

    // set_null is an update — watchers receive a Set event.
    #[test]
    fn test_watcher_receives_set_event_on_set_null() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let mut rx = engine.watch_subscribe();
            engine.set_null(b"null_key").await.unwrap();
            let event = rx.recv().await.unwrap();
            assert_eq!(event.key, b"null_key");
            assert!(matches!(event.op, OpType::Set));
        })
    }

    #[test]
    fn test_watcher_receives_delete_event() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put(b"del_key", b"v").await.unwrap();
            let mut rx = engine.watch_subscribe();
            engine.delete(b"del_key").await.unwrap();
            let event = rx.recv().await.unwrap();
            assert_eq!(event.key, b"del_key");
            assert!(matches!(event.op, OpType::Delete));
        })
    }

    #[test]
    fn test_small_value_flush_no_vlog_growth() {
        crate::core::engine_runtime::block_on(async {
            let (engine, dir) = make_engine().await;
            let vlog_path = dir.path().join("vlog.log");

            // Write a small value (< MAX_VALUE_LENGTH = 1024 bytes)
            engine.put(b"small_key", b"tiny_value").await.unwrap();

            // Small values are stored inline in the MemTable — VLog must still be empty.
            let vlog_size_before = std::fs::metadata(&vlog_path)
                .map(|m| m.len())
                .unwrap_or(0);

            // Freeze the active MemTable and flush it to an SSTable.
            engine.freeze_active_memtable();
            engine.flush_memtable().await.unwrap();

            // VLog must not have grown — inline values go directly into the SSTable DataBlock.
            let vlog_size_after = std::fs::metadata(&vlog_path)
                .map(|m| m.len())
                .unwrap_or(0);
            assert_eq!(
                vlog_size_before,
                vlog_size_after,
                "VLog must not grow when flushing small (inline) values"
            );

            // The value must still be readable from the SSTable.
            let result = engine.get(b"small_key").await.unwrap();
            assert_eq!(result, Some(b"tiny_value".to_vec()));
        })
    }

    async fn freeze_and_flush(engine: &LsmStorageEngine) {
        engine.freeze_active_memtable();
        engine.flush_memtable().await.unwrap();
    }

    /// Every installed reader must carry the file id of its manifest entry —
    /// unstamped (id-0) readers collide in the block cache across tables.
    fn assert_readers_match_manifest(engine: &LsmStorageEngine) {
        let manifest = engine.manifest.read();
        for (lvl, readers) in engine.version().levels.iter().enumerate() {
            let mut reader_ids: Vec<u64> = readers.iter().map(|r| r.file_id).collect();
            let mut manifest_ids: Vec<u64> =
                manifest.get_level(lvl).iter().map(|m| m.file_id).collect();
            reader_ids.sort_unstable();
            manifest_ids.sort_unstable();
            assert_eq!(
                reader_ids, manifest_ids,
                "L{lvl} readers must be stamped with their manifest file ids"
            );
        }
    }

    #[test]
    fn test_compaction_rebuild_stamps_reader_file_ids() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put(b"a", b"1").await.unwrap();
            freeze_and_flush(&engine).await;
            engine.put(b"b", b"2").await.unwrap();
            freeze_and_flush(&engine).await;

            // Compacts both L0 tables (ids 0, 1) into a new L1 table (id 2).
            engine.compact_level(0).await.unwrap();

            assert_readers_match_manifest(&engine);
            let l1_ids: Vec<u64> = engine
                .manifest
                .read()
                .get_level(1)
                .iter()
                .map(|m| m.file_id)
                .collect();
            assert!(!l1_ids.is_empty() && l1_ids.iter().all(|id| *id != 0));

            assert_eq!(engine.get(b"a").await.unwrap(), Some(b"1".to_vec()));
            assert_eq!(engine.get(b"b").await.unwrap(), Some(b"2".to_vec()));
        })
    }

    // Regression: flush_memtable returns the flushed
    // SSTable's own file_id (not a positional guess into L0), and None when
    // there is nothing to flush -- so registration can't pick the wrong table.
    #[test]
    fn test_flush_memtable_returns_flushed_file_id() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            assert_eq!(engine.flush_memtable().await.unwrap(), None, "nothing to flush");

            engine.put(b"k", b"v").await.unwrap();
            engine.freeze_active_memtable();
            let id = engine.flush_memtable().await.unwrap().expect("a table was flushed");

            let version = engine.version();
            let l0 = version.level(0);
            assert_eq!(l0.len(), 1);
            assert_eq!(l0[0].file_id, id, "returned id must be the flushed table's id");
        })
    }

    // Regression: compact_level returns exactly the file
    // ids it deleted (merged source + target), so deregistration deregisters
    // the real deletions instead of a separately-selected, racy guess.
    #[test]
    fn test_compact_level_returns_deleted_file_ids() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put(b"a", b"1").await.unwrap();
            freeze_and_flush(&engine).await;
            engine.put(b"b", b"2").await.unwrap();
            freeze_and_flush(&engine).await;

            // Two L0 tables, L1 empty -> both source tables are deleted, no targets.
            let mut expected: Vec<u64> =
                engine.version().level(0).iter().map(|r| r.file_id).collect();
            expected.sort_unstable();

            let mut deleted = engine.compact_level(0).await.unwrap();
            deleted.sort_unstable();
            assert_eq!(deleted, expected, "must report exactly the compacted-away ids");
        })
    }

    // Note: every other compaction test targets an empty L1; this drives
    // the non-empty-target branch (open, drop from manifest, delete). A key
    // inside the existing L1 range forces overlapping-target selection.
    #[test]
    fn test_compaction_into_nonempty_target_level() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put(b"a", b"1").await.unwrap();
            freeze_and_flush(&engine).await;
            engine.put(b"z", b"26").await.unwrap();
            freeze_and_flush(&engine).await;
            engine.compact_level(0).await.unwrap(); // L1 now spans [a, z]

            engine.put(b"m", b"13").await.unwrap();
            freeze_and_flush(&engine).await;
            engine.compact_level(0).await.unwrap(); // compacts [m] into non-empty L1

            assert_eq!(engine.get(b"a").await.unwrap(), Some(b"1".to_vec()));
            assert_eq!(engine.get(b"m").await.unwrap(), Some(b"13".to_vec()));
            assert_eq!(engine.get(b"z").await.unwrap(), Some(b"26".to_vec()));
        })
    }

    // compaction_runs counts successfully
    // completed compact_next_level calls -- 0 before any compaction runs,
    // >= 1 once should_compact's own trigger condition (L0 at the default
    // threshold of 4) has actually been acted on.
    #[test]
    fn test_compaction_runs_counter_increments_on_real_compaction() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            assert_eq!(engine.compaction_runs(), 0);

            engine.put(b"a", b"1").await.unwrap();
            freeze_and_flush(&engine).await;
            engine.put(b"b", b"2").await.unwrap();
            freeze_and_flush(&engine).await;
            engine.put(b"c", b"3").await.unwrap();
            freeze_and_flush(&engine).await;
            engine.put(b"d", b"4").await.unwrap();
            freeze_and_flush(&engine).await;
            assert!(should_compact(&engine.manifest.read(), &engine.compaction_config));

            engine.compact_next_level().await.unwrap();
            assert_eq!(engine.compaction_runs(), 1, "a real compaction must increment compaction_runs");
        })
    }

    /// GC config that fires on any non-empty vLog.
    fn gc_always() -> JanitorConfig {
        JanitorConfig {
            check_interval_secs: 3600,
            dead_bytes_threshold: 0.0,
            min_vlog_size_bytes: 0,
        }
    }

    #[test]
    fn test_janitor_gc_stamps_reader_file_ids_and_invalidates_cache() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let engine = Arc::new(engine);
            let big = vec![b'x'; 4096]; // >= vlog_inline_threshold → vLog pointer
            engine.put(b"big", &big).await.unwrap();
            engine.put(b"small", b"v").await.unwrap();
            freeze_and_flush(&engine).await;

            // Populate the block cache under the pre-GC file id (first table = 0).
            assert_eq!(engine.get(b"small").await.unwrap(), Some(b"v".to_vec()));
            let pre_gc_key = BlockCacheKey { file_id: 0, block_offset: 0 };
            assert!(engine.block_cache.stripe(&pre_gc_key).get(&pre_gc_key).is_some());

            let stats = engine.build_janitor(gc_always()).run_gc().await.unwrap();
            assert!(stats.ran);

            assert_readers_match_manifest(&engine);
            assert!(
                engine.version().levels.iter().flatten().all(|r| r.file_id != 0),
                "rebuilt readers must carry the new (non-zero) file ids"
            );
            // Cached blocks of the deleted pre-GC table must be invalidated.
            assert!(engine.block_cache.stripe(&pre_gc_key).get(&pre_gc_key).is_none());

            // Data reads correctly through rebuilt readers and the new vLog.
            assert_eq!(engine.get(b"big").await.unwrap(), Some(big));
            assert_eq!(engine.get(b"small").await.unwrap(), Some(b"v".to_vec()));
        })
    }

    /// vLog generation ids stamped into the pointers of all L0 SSTables.
    fn l0_pointer_generations(engine: &LsmStorageEngine) -> Vec<u32> {
        let mut ids = Vec::new();
        for sstable in engine.version().level(0) {
            for entry in sstable.iter() {
                if let (_, crate::storage::format::DataBlockValue::Pointer(vp)) = entry.unwrap() {
                    if vp.file_id != 0 {
                        ids.push(vp.file_id);
                    }
                }
            }
        }
        ids
    }

    /// Every vLog-pointer `file_id` reachable from any MemTable (active,
    /// immutable, flushing) or any SSTable at any level — a full scan,
    /// not just a read-back, so a dangling pointer into a
    /// retired generation would show up here even if no test happens to read
    /// that key.
    fn all_pointer_generations(engine: &LsmStorageEngine) -> Vec<u32> {
        let mut ids = Vec::new();
        let version = engine.version();

        for mt in version.memtables_newest_first() {
            for (_, value) in mt.iter() {
                if let Value::Pointer { file_id, .. } = value {
                    ids.push(file_id);
                }
            }
        }

        for level in &version.levels {
            for sstable in level {
                for entry in sstable.iter() {
                    if let (_, crate::storage::format::DataBlockValue::Pointer(vp)) = entry.unwrap() {
                        if vp.file_id != 0 {
                            ids.push(vp.file_id);
                        }
                    }
                }
            }
        }

        ids
    }

    // A large value whose pointer lives only in
    // the active MemTable — no flush ran — must survive a GC cycle.
    #[test]
    fn test_gc_preserves_memtable_resident_vlog_value() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let engine = Arc::new(engine);
            let big = vec![b'x'; 4096]; // >= vlog_inline_threshold → vLog pointer
            engine.put(b"big", &big).await.unwrap();
            // Deliberately no flush: the pointer exists only in the MemTable.

            let stats = engine.build_janitor(gc_always()).run_gc().await.unwrap();
            assert!(stats.ran);
            assert_eq!(stats.live_bytes, 4096, "the MemTable pointer counts as live");

            assert_eq!(engine.get(b"big").await.unwrap(), Some(big));
        })
    }

    // Write path: with the old generation sealed and a
    // new one published, a write lands in — and is stamped with — the new one.
    #[test]
    fn test_write_after_generation_swap_uses_new_generation() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let gen1 = Arc::clone(&engine.version().active_vlog);
            let gen2 =
                Arc::new(VLog::open(generation_path(&engine.vlog_path, 2), 2).await.unwrap());
            engine.install(|v| v.with_active_vlog(gen2, engine.last_applied_lsn()));
            gen1.seal();

            let big = vec![b'y'; 4096];
            engine.put(b"big", &big).await.unwrap();

            assert_eq!(gen1.size(), 0, "the sealed generation must not grow");
            assert_eq!(engine.version().active_vlog.size(), 4096);
            assert_eq!(engine.get(b"big").await.unwrap(), Some(big.clone()));

            freeze_and_flush(&engine).await;
            assert_eq!(l0_pointer_generations(&engine), vec![2]);
            assert_eq!(engine.get(b"big").await.unwrap(), Some(big));
        })
    }

    // Values written while the GC runs must all
    // survive — the seal makes racing appends retry against the new generation.
    // The writers interleave with the GC at their await points, as they do on
    // the engine thread.
    #[test]
    fn test_gc_keeps_values_written_concurrently() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let engine = Arc::new(engine);
            let big = vec![b'w'; 2048];
            engine.put(b"pre", &big).await.unwrap();

            let writers: Vec<_> = (0..4u32)
                .map(|w| {
                    let engine = Arc::clone(&engine);
                    let value = big.clone();
                    compio::runtime::spawn(async move {
                        for i in 0..25u32 {
                            engine.put(format!("k{w}-{i:02}").as_bytes(), &value).await.unwrap();
                        }
                    })
                })
                .collect();

            engine.build_janitor(gc_always()).run_gc().await.unwrap();
            for writer in writers {
                writer.await.unwrap();
            }

            assert_eq!(engine.get(b"pre").await.unwrap(), Some(big.clone()));
            for w in 0..4u32 {
                for i in 0..25u32 {
                    assert_eq!(
                        engine.get(format!("k{w}-{i:02}").as_bytes()).await.unwrap(),
                        Some(big.clone()),
                        "value k{w}-{i:02} written during the GC must survive"
                    );
                }
            }
        })
    }

    // A held writer guard blocks the barrier's drain step;
    // dropping it unblocks immediately. Exercises the guard mechanism directly
    // (not the public write path) since the real race window is instruction-
    // width and cannot be hit deterministically. Timeout-guarded so a bug that
    // makes the drain hang fails the test instead of the suite.
    #[test]
    fn test_drain_waits_for_held_writer_guard_then_proceeds() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;

            // Simulates a write in flight: it has fetched the active generation
            // and is somewhere before its `memtable.set`.
            let guard = engine.in_flight_writes.read().await;

            let blocked = compio::time::timeout(Duration::from_millis(200), engine.flush_all_memtables()).await;
            assert!(blocked.is_err(), "drain must block while a writer guard is held");

            drop(guard);

            compio::time::timeout(Duration::from_millis(200), engine.flush_all_memtables())
                .await
                .expect("drain must complete promptly once the guard is released")
                .unwrap();
        })
    }

    /// Highest-stamped version of `user_key` across the active and all
    /// immutable MemTables -- the stamp-ordered oracle the source-ordered read
    /// path has to agree with. Inline values only; its callers
    /// write no pointers.
    fn newest_memtable_version(engine: &LsmStorageEngine, user_key: &[u8]) -> Option<(u64, Vec<u8>)> {
        let version = engine.version();
        let sources = std::iter::once(&version.memtable).chain(version.immutables.iter());

        let mut newest: Option<(u64, Vec<u8>)> = None;
        for memtable in sources {
            for (encoded_key, value) in memtable.iter() {
                if InternalKey::extract_user_key(&encoded_key) != Some(user_key) {
                    continue;
                }
                let Some(stamp) = InternalKey::extract_timestamp(&encoded_key) else { continue };
                let stamp = stamp.as_u64();
                let beats = match &newest {
                    Some((best, _)) => stamp > *best,
                    None => true,
                };
                if beats {
                    if let Value::Inline(bytes, _) = value {
                        newest = Some((stamp, bytes));
                    }
                }
            }
        }
        newest
    }

    // Without the write barrier: the point read resolves by source, not
    // by stamp, so an older stamp in the newer MemTable wins over the newer
    // version below it. Built with the test-only rotation lever (the one
    // rotation without a drain) because no production path can produce this
    // state any more -- it pins down exactly what the write barrier prevents.
    #[test]
    fn test_older_stamp_in_newer_memtable_wins_by_source_order() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;

            // Writer B: newer stamp, applied into the MemTable that is frozen next.
            let newer = engine.next_timestamp().await;
            engine.version().memtable.set(b"k".to_vec(), newer, Value::Inline(b"newer".to_vec(), None));

            engine.freeze_active_memtable();

            // Writer A: stamp drawn before the rotation, applied after it.
            let older = Timestamp::new(newer.as_u64() - 1);
            engine.version().memtable.set(b"k".to_vec(), older, Value::Inline(b"older".to_vec(), None));

            assert_eq!(
                engine.get(b"k").await.unwrap(),
                Some(b"older".to_vec()),
                "first hit decides: the newer source wins even with the older stamp"
            );
        })
    }

    // With the write barrier: concurrent writers on one key with a
    // threshold that rotates on nearly every write. The read must always
    // resolve to the newest stamp the engine holds -- what the source-ordered
    // read path can only deliver while the freeze barrier holds.
    #[test]
    fn test_concurrent_writes_across_freezes_never_strand_an_older_stamp() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let engine = Arc::new(engine_with_threshold(&dir, 1).await);

            for round in 0..20u32 {
                let key = format!("k{round}");
                let writers: Vec<_> = (0..4u32)
                    .map(|w| {
                        let engine = Arc::clone(&engine);
                        let key = key.clone();
                        compio::runtime::spawn(async move {
                            engine.put(key.as_bytes(), format!("v{w}").as_bytes()).await.unwrap();
                        })
                    })
                    .collect();
                for writer in writers {
                    writer.await.unwrap();
                }

                let (stamp, newest) = newest_memtable_version(&engine, key.as_bytes())
                    .expect("every round writes its key into a MemTable");
                assert_eq!(
                    engine.get(key.as_bytes()).await.unwrap(),
                    Some(newest),
                    "round {round}: the read must return the version stamped {stamp}"
                );
            }
        })
    }

    // A held writer guard blocks the freeze until the
    // in-flight apply is through; afterwards the rotation goes ahead. Same
    // shape as the drain test above, now for the regular freeze path.
    #[test]
    fn test_freeze_waits_for_held_writer_guard_then_rotates() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let engine = engine_with_threshold(&dir, 1).await;
            engine.put(b"k", b"v").await.unwrap();
            assert!(engine.version().immutables.is_empty(), "the first write does not rotate");

            // Simulates a write that has drawn its stamp and not applied it yet.
            let guard = engine.in_flight_writes.read().await;

            let blocked = compio::time::timeout(Duration::from_millis(200), engine.maybe_freeze_memtable()).await;
            assert!(blocked.is_err(), "the freeze must wait while a writer guard is held");
            assert!(engine.version().immutables.is_empty(), "nothing rotated under the held guard");

            drop(guard);

            compio::time::timeout(Duration::from_millis(200), engine.maybe_freeze_memtable())
                .await
                .expect("the freeze must proceed once the guard is released")
                .unwrap();
            assert_eq!(engine.version().immutables.len(), 1, "the rotation happened after the drain");
            assert!(engine.version().memtable.is_empty(), "the active MemTable is fresh");
        })
    }

    // Each entry contributes its encoded internal key
    // (user key + 8-byte stamp) plus its stored value bytes; TTL is not counted.
    #[test]
    fn test_memtable_size_is_the_sum_of_entry_bytes() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            assert_eq!(engine.stats().memtable_size, 0, "a fresh MemTable holds no bytes");

            engine.put(b"alpha", b"12345").await.unwrap(); // 5 + 8 + 5 = 18
            engine.put("clé".as_bytes(), "clé".as_bytes()).await.unwrap(); // 4 + 8 + 4 = 16
            engine.put_with_ttl(b"beta", b"xyz", 3600).await.unwrap(); // 4 + 8 + 3 = 15
            engine.set_null(b"gamma").await.unwrap(); // 5 + 8 + 0 = 13
            engine
                .write_batch(vec![BatchOp::Put { key: b"delta".to_vec(), value: b"batched".to_vec() }])
                .await
                .unwrap(); // 5 + 8 + 7 = 20

            assert_eq!(engine.stats().memtable_size, 18 + 16 + 15 + 13 + 20);
        })
    }

    // Every write is its own version, and each one
    // counts on its own.
    #[test]
    fn test_memtable_size_counts_every_version_of_a_key() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;

            engine.put(b"k", b"v1").await.unwrap(); // 1 + 8 + 2 = 11
            engine.put(b"k", b"v22").await.unwrap(); // 1 + 8 + 3 = 12
            engine.put(b"k", b"v333").await.unwrap(); // 1 + 8 + 4 = 13

            assert_eq!(engine.stats().memtable_size, 11 + 12 + 13);
        })
    }

    // A tombstone contributes only its internal key.
    #[test]
    fn test_memtable_size_counts_a_tombstone_by_its_internal_key() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;

            engine.delete(b"gone").await.unwrap(); // 4 + 8 + 0

            assert_eq!(engine.stats().memtable_size, 12);
        })
    }

    // The freeze trigger compares real bytes, not an
    // entry count. The check runs before each write, so the write
    // that crosses the threshold still lands in the active MemTable and the
    // next write rotates it.
    #[test]
    fn test_memtable_freezes_on_the_write_after_its_bytes_cross_the_threshold() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let engine = engine_with_threshold(&dir, 1000).await;
            let value = [b'x'; 20]; // 2-byte keys: 2 + 8 + 20 = 30 bytes per entry

            for i in 0..33 {
                engine.put(format!("{i:02}").as_bytes(), &value).await.unwrap();
            }
            let stats = engine.stats();
            assert_eq!(stats.memtable_size, 990);
            assert_eq!(stats.num_immutable_memtables, 0, "33 small entries stay below 1000 bytes");

            engine.put(b"33", &value).await.unwrap();
            let stats = engine.stats();
            assert_eq!(stats.memtable_size, 1020, "the crossing write lands in the active MemTable");
            assert_eq!(stats.num_immutable_memtables, 0, "the check ran before that write");

            engine.put(b"34", &value).await.unwrap();
            let stats = engine.stats();
            assert_eq!(stats.num_immutable_memtables, 1, "the next write rotates first");
            assert_eq!(stats.memtable_size, 30, "and lands in the fresh MemTable");
        })
    }

    // Large values: the same threshold is crossed
    // after a few entries. 600 bytes stay inline (below vlog_inline_threshold).
    #[test]
    fn test_large_inline_values_freeze_after_fewer_entries() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let engine = engine_with_threshold(&dir, 1000).await;
            let value = vec![b'x'; 600]; // 1 + 8 + 600 = 609 bytes per entry

            engine.put(b"a", &value).await.unwrap(); // 609
            engine.put(b"b", &value).await.unwrap(); // 1218: crosses, no rotation yet
            assert_eq!(engine.stats().num_immutable_memtables, 0);

            engine.put(b"c", &value).await.unwrap();
            assert_eq!(engine.stats().num_immutable_memtables, 1, "the third write rotates");
        })
    }

    // An offloaded value counts with its vLog pointer,
    // the only part of it held in memory.
    #[test]
    fn test_memtable_size_counts_an_offloaded_value_by_its_pointer() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let big = vec![b'x'; 4096]; // >= vlog_inline_threshold → vLog pointer

            engine.put(b"big", &big).await.unwrap();

            let pointer = std::mem::size_of::<crate::storage::format::ValuePointer>();
            assert_eq!(engine.stats().memtable_size, 3 + 8 + pointer);
        })
    }

    // The MemTable created by a freeze starts at 0,
    // so it reports only the writes that land in it.
    #[test]
    fn test_memtable_size_starts_at_zero_after_a_freeze() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let engine = engine_with_threshold(&dir, 1).await;
            engine.put(b"k", b"v").await.unwrap(); // 1 + 8 + 1 = 10

            engine.put(b"k2", b"v22").await.unwrap(); // rotates first; 2 + 8 + 3 = 13

            let stats = engine.stats();
            assert_eq!(stats.num_immutable_memtables, 1);
            assert_eq!(stats.memtable_size, 13, "the fresh MemTable counts only the new write");
        })
    }

    // A batch shares one stamp, so [Delete k, Put k v]
    // resolves to one insert of the Put, which counts once.
    #[test]
    fn test_memtable_size_counts_a_key_written_twice_in_a_batch_once() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;

            engine
                .write_batch(vec![
                    BatchOp::Delete { key: b"k".to_vec() },
                    BatchOp::Put { key: b"k".to_vec(), value: b"val".to_vec() },
                ])
                .await
                .unwrap();

            assert_eq!(engine.stats().memtable_size, 1 + 8 + 3);
        })
    }

    // Sharpens test_gc_keeps_values_written_concurrently
    // for the in-flight guard -- that test is left
    // unchanged and must stay green on its own. Adds two properties the guard
    // must not break: the GC cycle terminates under concurrent write load
    // instead of deadlocking against the drain, and once everything has
    // settled, no stored pointer names a generation the GC retired -- checked
    // via a full MemTable/SSTable scan, not just successful reads.
    #[test]
    fn test_gc_drain_no_deadlock_and_no_dangling_pointers_under_load() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let engine = Arc::new(engine);
            let big = vec![b'w'; 2048];
            engine.put(b"pre", &big).await.unwrap();

            let writers: Vec<_> = (0..4u32)
                .map(|w| {
                    let engine = Arc::clone(&engine);
                    let value = big.clone();
                    compio::runtime::spawn(async move {
                        for i in 0..25u32 {
                            engine.put(format!("k{w}-{i:02}").as_bytes(), &value).await.unwrap();
                        }
                    })
                })
                .collect();

            // A stuck drain (guard never released, or a deadlock against the
            // writers) fails the test instead of hanging the suite.
            compio::time::timeout(Duration::from_secs(10), engine.build_janitor(gc_always()).run_gc())
                .await
                .expect("GC must not deadlock against concurrent writers")
                .unwrap();

            for writer in writers {
                writer.await.unwrap();
            }

            assert_eq!(engine.get(b"pre").await.unwrap(), Some(big.clone()));
            for w in 0..4u32 {
                for i in 0..25u32 {
                    assert_eq!(
                        engine.get(format!("k{w}-{i:02}").as_bytes()).await.unwrap(),
                        Some(big.clone()),
                        "value k{w}-{i:02} written during the GC must survive"
                    );
                }
            }

            let live_ids = engine.version().vlog_ids();
            for id in all_pointer_generations(&engine) {
                assert!(
                    live_ids.contains(&id),
                    "pointer references retired generation {id}, live={live_ids:?}"
                );
            }
        })
    }

    // A generation that stays sealed (no swap) must fail the write cleanly
    // instead of spinning in the retry loop.
    #[test]
    fn test_append_to_permanently_sealed_generation_fails() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.version().active_vlog.seal();

            let err = engine.put(b"big", &vec![b'x'; 4096]).await.unwrap_err();
            assert!(err.to_string().contains("sealed"), "unexpected error: {err}");
        })
    }

    // Values from before and after a GC are both readable,
    // and a reference to the retired generation taken before the GC keeps
    // reading correctly from its already-open descriptor.
    #[test]
    fn test_reads_span_vlog_generations() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let engine = Arc::new(engine);
            let before = vec![b'1'; 4096];
            engine.put(b"before", &before).await.unwrap();
            let gen1 = Arc::clone(&engine.version().active_vlog);

            engine.build_janitor(gc_always()).run_gc().await.unwrap();
            assert_eq!(engine.version().active_vlog.id(), 2);
            assert_eq!(engine.version().vlog_ids(), vec![2], "generation 1 is retired");

            let after = vec![b'2'; 4096];
            engine.put(b"after", &after).await.unwrap();

            assert_eq!(engine.get(b"before").await.unwrap(), Some(before.clone()));
            assert_eq!(engine.get(b"after").await.unwrap(), Some(after));
            assert_eq!(gen1.read(0, 4096).unwrap(), before);
        })
    }

    // Startup registers every generation found on disk and
    // activates the highest id; a store with only the canonical file starts as
    // generation 1, and an orphaned empty generation does not disturb it.
    #[test]
    fn test_startup_registers_all_generations() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let vlog_path = dir.path().join("vlog.log");

            let engine = engine_on(&dir).await;
            assert_eq!(engine.version().vlog_ids(), vec![1], "legacy store is generation 1");
            assert_eq!(engine.version().active_vlog.id(), 1);
            drop(engine);

            std::fs::write(generation_path(&vlog_path, 2), b"generation-2").unwrap();
            let engine = engine_on(&dir).await;
            assert_eq!(engine.version().vlog_ids(), vec![1, 2]);
            assert_eq!(engine.version().active_vlog.id(), 2);
            assert_eq!(engine.version().vlog[&2].read(0, 12).unwrap(), b"generation-2");
            drop(engine);

            std::fs::write(generation_path(&vlog_path, 3), b"").unwrap(); // orphan
            let engine = engine_on(&dir).await;
            assert_eq!(engine.version().vlog_ids(), vec![1, 2, 3]);
            assert_eq!(engine.version().active_vlog.id(), 3);
            let big = vec![b'o'; 4096];
            engine.put(b"k", &big).await.unwrap();
            assert_eq!(engine.get(b"k").await.unwrap(), Some(big));
        })
    }

    // Startup with an active generation > 1 and the WAL on the storage hub:
    // appends go to that generation's file, after its existing bytes, and
    // generation 1 stays readable.
    #[test]
    fn test_startup_appends_to_an_active_generation_above_one() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let wal_path = dir.path().join("wal.log");
            let vlog_path = dir.path().join("vlog.log");
            std::fs::write(&vlog_path, b"generation-1").unwrap();
            std::fs::write(generation_path(&vlog_path, 2), b"generation-2").unwrap();

            let hub = TestHub::start(&[(WalTarget::Kv, &wal_path)]);
            let engine = engine_on_hub(&dir, &hub).await;

            let active = Arc::clone(&engine.version().active_vlog);
            assert_eq!(active.id(), 2, "generation 2 is the highest on disk");
            let off = active.append(b"-added").await.unwrap();
            assert_eq!(off, 12, "cursor seeded from generation 2's on-disk length");
            assert_eq!(std::fs::read(generation_path(&engine.vlog_path, 2)).unwrap(), b"generation-2-added");
            assert_eq!(active.read(off, 6).unwrap(), b"-added");
            assert_eq!(engine.version().vlog[&1].read(0, 12).unwrap(), b"generation-1");

            let big = vec![b'g'; 4096];
            engine.put(b"big", &big).await.unwrap();
            assert_eq!(engine.get(b"big").await.unwrap(), Some(big));
            assert_eq!(std::fs::metadata(generation_path(&engine.vlog_path, 2)).unwrap().len(), 18 + 4096);
        })
    }

    // Writes of an engine dropped without a shutdown -- no flush, no
    // truncate -- come back from the WAL the storage hub wrote; the restart
    // then flushes them and truncates the WAL through the hub.
    #[test]
    fn test_unflushed_writes_come_back_from_the_hub_written_wal() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let wal_path = dir.path().join("wal.log");
            let big = vec![b'w'; 4096];
            {
                let hub = TestHub::start(&[(WalTarget::Kv, &wal_path)]);
                let engine = engine_on_hub(&dir, &hub).await;
                engine.put(b"small", "clé ✓".as_bytes()).await.unwrap();
                engine.put(b"big", &big).await.unwrap();
                engine.put(b"gone", b"x").await.unwrap();
                engine.delete(b"gone").await.unwrap();
            }
            let (header, segment) = (crate::core::wal::WAL_HEADER_LEN, crate::core::wal::segment_path(&wal_path, 1));
            assert!(std::fs::metadata(&segment).unwrap().len() > header, "the writes are only in the WAL");

            let hub = TestHub::start(&[(WalTarget::Kv, &wal_path)]);
            let engine = engine_on_hub(&dir, &hub).await;
            assert_eq!(engine.get(b"small").await.unwrap(), Some("clé ✓".as_bytes().to_vec()));
            assert_eq!(engine.get(b"big").await.unwrap(), Some(big));
            assert_eq!(engine.get(b"gone").await.unwrap(), None);
            assert_eq!(std::fs::metadata(&segment).unwrap().len(), header);
        })
    }

    // A WAL of the earlier format: the start replays it, flushes it and
    // replaces it with a segment directory that holds the header alone; the
    // writes after it are LSN-framed, and the next start reads them back.
    #[test]
    fn test_start_upgrades_a_wal_of_the_earlier_format() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let wal_path = dir.path().join("wal.log");
            std::fs::write(&wal_path, include_bytes!("../../../tests/fixtures/wal/v1.wal")).unwrap();
            {
                let hub = TestHub::start(&[(WalTarget::Kv, &wal_path)]);
                let engine = engine_on_hub(&dir, &hub).await;
                let segment = crate::core::wal::segment_path(&wal_path, 1);
                assert_eq!(std::fs::read(segment).unwrap(), crate::core::wal::wal_header(5));
                assert!(!dir.path().join("wal.log.migrating").exists());
                assert_eq!(engine.last_applied_lsn(), 5, "the five records of the old WAL");
                engine.put(b"after", b"upgrade").await.unwrap();
                assert_eq!(engine.last_applied_lsn(), 6);
            }
            let recovered = crate::core::wal::recover_all(&wal_path).await.unwrap();
            assert_eq!(recovered.entries.len(), 1);
            assert_eq!(recovered.max_lsn, 6);

            let hub = TestHub::start(&[(WalTarget::Kv, &wal_path)]);
            let engine = engine_on_hub(&dir, &hub).await;
            assert_eq!(engine.get(b"alpha").await.unwrap(), None);
            assert_eq!(engine.get(b"beta").await.unwrap(), None);
            let snap = engine.snapshot().await;
            assert_eq!(engine.get_with_snapshot(b"gamma", snap.snapshot()).await.unwrap(), GetResult::Null);
            assert_eq!(engine.get("clé".as_bytes()).await.unwrap(), Some("🦀".as_bytes().to_vec()));
            assert_eq!(engine.get(b"after").await.unwrap(), Some(b"upgrade".to_vec()));
            assert_eq!(engine.last_applied_lsn(), 6);
        })
    }

    // Every write path applies one WAL record and reports its LSN; a batch is
    // one record, however many ops it holds.
    #[test]
    fn test_last_applied_lsn_follows_every_write_and_a_batch_takes_one() {
        crate::core::engine_runtime::block_on(async {
            let (engine, dir) = make_engine().await;
            assert_eq!(engine.last_applied_lsn(), 0);
            engine.put(b"a", b"1").await.unwrap();
            assert_eq!(engine.last_applied_lsn(), 1);
            engine.put_with_ttl(b"b", b"2", 3600).await.unwrap();
            assert_eq!(engine.last_applied_lsn(), 2);
            engine.delete(b"a").await.unwrap();
            assert_eq!(engine.last_applied_lsn(), 3);
            engine.set_null(b"c").await.unwrap();
            assert_eq!(engine.last_applied_lsn(), 4);
            let batch = vec![
                BatchOp::Put { key: b"d".to_vec(), value: b"4".to_vec() },
                BatchOp::Put { key: b"e".to_vec(), value: b"5".to_vec() },
                BatchOp::Delete { key: b"b".to_vec() },
            ];
            engine.write_batch(batch).await.unwrap();
            assert_eq!(engine.last_applied_lsn(), 5);
            let memtable = engine.pin_memtable();
            engine.write_tombstone_at(&memtable, b"c", Timestamp::new(1)).await.unwrap();
            assert_eq!(engine.last_applied_lsn(), 6);

            let recovered = crate::core::wal::recover_all(dir.path().join("wal.log")).await.unwrap();
            let lsns: Vec<u64> = recovered.entries.iter().map(|(lsn, _)| *lsn).collect();
            assert_eq!(lsns, [1, 2, 3, 4, 5, 5, 5, 6]);
            assert_eq!(recovered.max_lsn, engine.last_applied_lsn());
        })
    }

    // Concurrent writers apply in whatever order their vLog appends finish;
    // the applied LSN never goes back and ends at the last record's.
    #[test]
    fn test_last_applied_lsn_never_decreases_under_concurrent_writes() {
        crate::core::engine_runtime::block_on(async {
            let (engine, dir) = make_engine().await;
            let engine = Arc::new(engine);
            let seen = Arc::new(Mutex::new(Vec::new()));
            let writers: Vec<_> = (0..20u32)
                .map(|i| {
                    let (engine, seen) = (Arc::clone(&engine), Arc::clone(&seen));
                    let value = if i % 2 == 0 { vec![b'v'; 4096] } else { b"small".to_vec() };
                    compio::runtime::spawn(async move {
                        engine.put(format!("k{i}").as_bytes(), &value).await.unwrap();
                        seen.lock().push(engine.last_applied_lsn());
                    })
                })
                .collect();
            for writer in writers {
                writer.await.unwrap();
            }

            let seen = seen.lock().clone();
            assert!(seen.windows(2).all(|pair| pair[0] <= pair[1]), "{seen:?}");
            assert_eq!(seen.last(), Some(&20));
            assert_eq!(crate::core::wal::recover_all(dir.path().join("wal.log")).await.unwrap().max_lsn, 20);
        })
    }

    // A restart continues the LSNs of the WAL it recovers: with k records in
    // it, the first write after the start carries k + 1 — on a local
    // committer and on a fresh hub.
    #[test]
    fn test_restart_continues_the_lsns_of_the_recovered_wal() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let wal_path = dir.path().join("wal.log");
            {
                let engine = engine_on(&dir).await;
                for i in 0..3u32 {
                    engine.put(format!("local-{i}").as_bytes(), b"v").await.unwrap();
                }
            }
            let engine = engine_on(&dir).await;
            assert_eq!(engine.last_applied_lsn(), 3);
            engine.put(b"local-next", b"v").await.unwrap();
            assert_eq!(engine.last_applied_lsn(), 4);
            assert_eq!(crate::core::wal::recover_all(&wal_path).await.unwrap().max_lsn, 4);

            let dir = tempfile::TempDir::new().unwrap();
            let wal_path = dir.path().join("wal.log");
            {
                let hub = TestHub::start(&[(WalTarget::Kv, &wal_path)]);
                let engine = engine_on_hub(&dir, &hub).await;
                for i in 0..3u32 {
                    engine.put(format!("hub-{i}").as_bytes(), b"v").await.unwrap();
                }
            }
            let hub = TestHub::start(&[(WalTarget::Kv, &wal_path)]);
            let engine = engine_on_hub(&dir, &hub).await;
            assert_eq!(engine.last_applied_lsn(), 3);
            engine.put(b"hub-next", b"v").await.unwrap();
            assert_eq!(engine.last_applied_lsn(), 4);
            drop(hub);
            assert_eq!(crate::core::wal::recover_all(&wal_path).await.unwrap().max_lsn, 4);
        })
    }

    // The LSNs go on across a clean stop, whose log keeps its header alone,
    // across the drop of a segment and across the truncate of a start; a
    // crash after each loses no write.
    #[test]
    fn test_the_lsns_go_on_across_a_stop_a_dropped_segment_and_a_start() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let wal_path = dir.path().join("wal.log");
            let segment = |n| crate::core::wal::segment_path(&wal_path, n);
            let start = || async {
                let hub = TestHub::start(&[(WalTarget::Kv, &wal_path)]);
                (engine_on_hub(&dir, &hub).await, hub)
            };
            async fn put(engine: &LsmStorageEngine, i: u64) {
                engine.put(format!("k{i}").as_bytes(), b"v").await.unwrap();
            }

            let (engine, hub) = start().await;
            for i in 1..=50 {
                put(&engine, i).await;
            }
            engine.shutdown().await;
            drop((engine, hub));
            assert_eq!(std::fs::read(segment(1)).unwrap(), crate::core::wal::wal_header(50));

            let (engine, hub) = start().await;
            put(&engine, 51).await;
            assert_eq!(engine.last_applied_lsn(), 51);
            engine.wal.rotate().await.unwrap();
            engine.raise_flushed_lsn(51).await.unwrap();
            let segments = engine.wal.segments().await.unwrap();
            engine.wal.drop_segments_before(&segments.dir, segments.active().segment).await.unwrap();
            assert!(!segment(1).exists());
            assert_eq!(std::fs::read(segment(2)).unwrap(), crate::core::wal::wal_header(51));
            drop((engine, hub)); // crash

            let (engine, hub) = start().await;
            put(&engine, 52).await;
            assert_eq!(engine.last_applied_lsn(), 52);
            drop((engine, hub)); // crash

            let (engine, hub) = start().await;
            assert_eq!(std::fs::read(segment(2)).unwrap(), crate::core::wal::wal_header(52));
            put(&engine, 53).await;
            assert_eq!(engine.last_applied_lsn(), 53);
            drop((engine, hub)); // crash

            let (engine, _hub) = start().await;
            for i in 1..=53 {
                assert_eq!(engine.get(format!("k{i}").as_bytes()).await.unwrap(), Some(b"v".to_vec()), "k{i}");
            }
            assert_eq!(engine.last_applied_lsn(), 53);
        })
    }

    // A TTL-sweeper tombstone write holds the in-flight guard from before its
    // WAL append through its MemTable insert: a drain started meanwhile
    // returns only once the tombstone is in.
    #[test]
    fn test_quiesce_waits_for_a_sweeper_tombstone_write_in_flight() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let wal_path = dir.path().join("wal.log");
            let wal = Arc::new(WriteAheadLog::with_capacity(&wal_path, 1).await.unwrap());
            let vlog_path = dir.path().join("vlog.log");
            let vlog = Arc::new(VLog::new(&vlog_path).await.unwrap());
            let file_manager = Arc::new(FileManager::new(dir.path()).await.unwrap());
            let manifest_manager = Arc::new(ManifestManager::new(dir.path()));
            let engine = Arc::new(
                LsmStorageEngine::new(
                    Arc::clone(&wal), wal_path, vlog, vlog_path, file_manager, manifest_manager,
                    LsmEngineOptions::default(),
                )
                .await
                .unwrap(),
            );
            let memtable = engine.pin_memtable();
            let tombstone_in = |memtable: &MemTable| {
                memtable.iter().any(|(encoded, value)| {
                    InternalKey::extract_user_key(&encoded) == Some(b"k".as_slice()) && matches!(value, Value::Tombstone)
                })
            };

            // The queue's one slot is taken: the sweeper's write waits for it.
            let slot = wal.reserve().await.unwrap();
            let sweeper = compio::runtime::spawn({
                let (engine, memtable) = (Arc::clone(&engine), Arc::clone(&memtable));
                async move { engine.write_tombstone_at(&memtable, b"k", Timestamp::new(1)).await.unwrap() }
            });
            for _ in 0..100 {
                if engine.in_flight_writes.try_write().is_err() {
                    break;
                }
                tokio::task::yield_now().await;
            }
            assert!(engine.in_flight_writes.try_write().is_err(), "the sweeper write holds the in-flight guard");

            let mut drain = std::pin::pin!(engine.quiesce_writes());
            assert!(futures::poll!(drain.as_mut()).is_pending(), "the drain waits for the sweeper write");
            assert!(!tombstone_in(&memtable));
            drop(slot);
            drain.await;
            assert!(tombstone_in(&memtable), "the drain returned before the tombstone was in");
            sweeper.await.unwrap();
        })
    }

    // Runs on the engine runtime's test harness: `IoEngine` registers its
    // buffers with that runtime's ring.

    // 8. Integration: SSTable flush -> file is automatically registered.
    // Compaction deletion -> file is deregistered.
    #[test]
    fn test_flush_registers_and_compaction_deregisters_sstable() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let engine = engine_on(&dir).await;
            let mut io_engine = IoEngine::new(4, 4096).unwrap();

            engine.put(b"a", b"1").await.unwrap();
            engine.freeze_active_memtable();
            engine.flush_memtable_and_register(&mut io_engine).await.unwrap();
            let first_id = engine.version().level(0)[0].file_id;
            assert!(io_engine.get_file(first_id).is_some(), "flushed SSTable must be registered");

            engine.put(b"b", b"2").await.unwrap();
            engine.freeze_active_memtable();
            engine.flush_memtable_and_register(&mut io_engine).await.unwrap();
            let second_id = engine.version().level(0)[1].file_id;
            assert!(io_engine.get_file(second_id).is_some(), "second flushed SSTable must be registered");

            engine.compact_level_and_deregister(0, &mut io_engine).await.unwrap();
            assert!(io_engine.get_file(first_id).is_none(), "compacted-away SSTable must be deregistered");
            assert!(io_engine.get_file(second_id).is_none(), "compacted-away SSTable must be deregistered");

            // Data still reads correctly through the post-compaction L1 table.
            assert_eq!(engine.get(b"a").await.unwrap(), Some(b"1".to_vec()));
            assert_eq!(engine.get(b"b").await.unwrap(), Some(b"2".to_vec()));
        });
    }

    // Recovery must register every already-existing SSTable with the IoEngine.
    #[test]
    fn test_recovery_registers_existing_sstables() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            {
                let engine = engine_on(&dir).await;
                engine.put(b"k", b"v").await.unwrap();
                freeze_and_flush(&engine).await;
            }

            // Fresh engine instance recovers the SSTable written above.
            let engine2 = engine_on(&dir).await;
            let file_id = engine2.version().level(0)[0].file_id;

            let mut io_engine = IoEngine::new(4, 4096).unwrap();
            engine2.register_sstables_with_io_engine(&mut io_engine).await.unwrap();
            assert!(io_engine.get_file(file_id).is_some());
        });
    }

    // Test 7: put, delete, set_null (-> Set) and write_batch all
    // publish through the same choke point (`publish_change`/`publish_many`)
    // -> sequences are gapless and non-decreasing across every write path.
    #[test]
    fn test_watch_seq_monotonic_across_all_write_paths() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let mut rx = engine.watch_subscribe();

            engine.put(b"a", b"1").await.unwrap(); // Set
            engine.delete(b"a").await.unwrap(); // Delete
            engine.set_null(b"b").await.unwrap(); // Set (an update, not a delete)
            engine
                .write_batch(vec![
                    BatchOp::Put { key: b"c".to_vec(), value: b"1".to_vec() },
                    BatchOp::Put { key: b"d".to_vec(), value: b"2".to_vec() },
                ])
                .await
                .unwrap();

            let mut seqs = Vec::new();
            for _ in 0..5 {
                seqs.push(rx.recv().await.unwrap().seq);
            }
            assert_eq!(seqs, vec![1, 2, 3, 4, 5], "sequences must be gapless and in write order: {seqs:?}");
        })
    }

    // Test 8: a batch's N ops get N consecutive sequences (`publish_many`),
    // and a concurrent single-op write lands fully before or after the
    // batch's slice, never interleaved into it.
    #[test]
    fn test_watch_batch_is_contiguous_against_concurrent_single_write() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let engine = Arc::new(engine);
            let mut rx = engine.watch_subscribe();

            let batch_ops: Vec<BatchOp> = (0..20)
                .map(|i| BatchOp::Put { key: format!("batch{i}").into_bytes(), value: b"v".to_vec() })
                .collect();

            let e1 = Arc::clone(&engine);
            let batch_handle = compio::runtime::spawn(async move { e1.write_batch(batch_ops).await.unwrap() });
            let e2 = Arc::clone(&engine);
            let single_handle = compio::runtime::spawn(async move { e2.put(b"single", b"v").await.unwrap() });
            batch_handle.await.unwrap();
            single_handle.await.unwrap();

            let mut batch_seqs = Vec::new();
            let mut single_seq = None;
            for _ in 0..21 {
                let event = rx.recv().await.unwrap();
                if event.key == b"single" {
                    single_seq = Some(event.seq);
                } else {
                    batch_seqs.push(event.seq);
                }
            }
            batch_seqs.sort_unstable();
            let (min, max) = (*batch_seqs.first().unwrap(), *batch_seqs.last().unwrap());
            assert_eq!(
                max - min + 1,
                batch_seqs.len() as u64,
                "batch sequences must be contiguous: {batch_seqs:?}"
            );
            let single_seq = single_seq.expect("the concurrent single write must have published an event");
            assert!(
                single_seq < min || single_seq > max,
                "the concurrent single write must land fully before or after the batch: {single_seq} vs [{min},{max}]"
            );
        })
    }

    // A Set/Delete race on one key. Before the fix, `publish_change` ran right
    // after the WAL fsync, before `memtable.set` -- a subscriber could receive
    // an event for a write that was not yet applied (and, on a crash, might
    // never be). After the fix, every write path
    // calls `memtable.set` before `publish_change` with no `.await` between
    // them, and the broadcast channel's send/recv synchronizes with that
    // apply -- so a read taken right after receiving any event from this
    // round must already see a state newer than the pre-race baseline.
    // Deterministic on purpose, not a hit-rate sample: this ordering is
    // unconditional, unlike the residual stream-vs-timestamp ordering gap
    // between two different writers that stays open and is
    // not exercised here.
    #[test]
    fn test_watch_event_is_never_seen_before_its_own_apply() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let engine = Arc::new(engine);

            for round in 0..50u32 {
                let key = format!("race{round}");
                engine.put(key.as_bytes(), b"baseline").await.unwrap();
                let (baseline_ts, _) = engine.newest_version(key.as_bytes()).await.unwrap().unwrap();
                let mut rx = engine.watch_subscribe();

                let e1 = Arc::clone(&engine);
                let k1 = key.clone();
                let set_handle = compio::runtime::spawn(async move { e1.put(k1.as_bytes(), b"updated").await.unwrap() });
                let e2 = Arc::clone(&engine);
                let k2 = key.clone();
                let del_handle = compio::runtime::spawn(async move { e2.delete(k2.as_bytes()).await.unwrap() });

                for _ in 0..2 {
                    let event = rx.recv().await.unwrap();
                    assert_eq!(event.key, key.as_bytes());
                    let (seen_ts, _) = engine.newest_version(key.as_bytes()).await.unwrap().unwrap();
                    assert!(
                        seen_ts.as_u64() > baseline_ts.as_u64(),
                        "round {round}: {:?} event observed before its own apply became visible",
                        event.op
                    );
                }

                set_handle.await.unwrap();
                del_handle.await.unwrap();
            }
        })
    }

    /// Parks the next `flush_memtable` right before its SSTable write.
    fn hook_flush_write(engine: &mut LsmStorageEngine) -> Arc<TestHook> {
        let hook = Arc::new(TestHook::default());
        engine.hooks.before_flush_write = Some(Arc::clone(&hook));
        hook
    }

    // A MemTable claimed by a flush in flight stays
    // readable. Task B reads while the flush is parked between its claim and
    // the SSTable write -- before the fix the MemTable was in neither the
    // immutables nor L0, so every key read as absent.
    #[test]
    fn test_reads_see_flushing_memtable_during_the_install_window() {
        crate::core::engine_runtime::block_on(async {
            let (mut engine, _dir) = make_engine().await;
            let hook = hook_flush_write(&mut engine);
            let engine = Arc::new(engine);

            for i in 0..1000u32 {
                engine.put(format!("k{i:04}").as_bytes(), b"v").await.unwrap();
            }
            engine.freeze_active_memtable();

            let flusher = {
                let engine = Arc::clone(&engine);
                compio::runtime::spawn(async move { engine.flush_memtable().await })
            };
            hook.reached.notified().await;
            assert!(engine.version().immutables.is_empty(), "the claim removed it");
            assert_eq!(engine.version().flushing.len(), 1, "the claim parked it in the slot");

            for i in 0..1000u32 {
                assert_eq!(
                    engine.get(format!("k{i:04}").as_bytes()).await.unwrap(),
                    Some(b"v".to_vec()),
                    "k{i:04} must stay readable while its MemTable is being flushed"
                );
            }
            assert_eq!(engine.scan_keys(b"k").await.unwrap().len(), 1000);

            hook.release.notify_one();
            let file_id = flusher.await.unwrap().unwrap();
            assert!(file_id.is_some(), "the flush must have produced an SSTable");

            assert!(engine.version().flushing.is_empty());
            assert!(engine.version().immutables.is_empty());
            assert_eq!(engine.version().level(0).len(), 1);
            assert_eq!(engine.get(b"k0000").await.unwrap(), Some(b"v".to_vec()));
            assert_eq!(engine.scan_keys(b"k").await.unwrap().len(), 1000);
        })
    }

    // A failed flush hands its MemTable back to the
    // immutables and leaves the flush slot empty, so the next call
    // is its retry -- the keys stay readable throughout and end up in exactly
    // one L0 file. The fault in the SSTable directory fails the write before
    // the install.
    #[test]
    fn test_failed_flush_returns_its_memtable_for_the_retry() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let sstable_dir = dir.path().join("sstables");
            std::fs::create_dir_all(&sstable_dir).unwrap();
            let engine = engine_with_sstable_dir(&dir, &sstable_dir).await;
            engine.put(b"a", b"1").await.unwrap();
            engine.put(b"b", b"2").await.unwrap();
            engine.freeze_active_memtable();

            test_fault::fail_writes_in(&sstable_dir);
            assert!(engine.flush_memtable().await.is_err(), "the SSTable write must fail");
            test_fault::allow_writes_in(&sstable_dir);

            assert!(engine.version().flushing.is_empty(), "a failed flush claims nothing");
            assert_eq!(engine.version().immutables.len(), 1, "its MemTable is back");
            assert_eq!(engine.get(b"a").await.unwrap(), Some(b"1".to_vec()));
            assert_eq!(engine.get(b"b").await.unwrap(), Some(b"2".to_vec()));

            assert!(engine.flush_memtable().await.unwrap().is_some(), "the retry succeeds");
            assert_eq!(engine.version().level(0).len(), 1, "exactly one L0 file");
            assert!(engine.version().immutables.is_empty());
            assert!(engine.version().flushing.is_empty());
            assert_eq!(engine.get(b"a").await.unwrap(), Some(b"1".to_vec()));
            assert_eq!(engine.get(b"b").await.unwrap(), Some(b"2".to_vec()));
        })
    }

    // The claim stays exclusive -- a second call
    // never flushes the same MemTable, and only one L0 file results. It
    // waits for the flush lock instead of returning right
    // away, so it runs as its own task.
    #[test]
    fn test_concurrent_flush_calls_claim_the_memtable_once() {
        crate::core::engine_runtime::block_on(async {
            let (mut engine, _dir) = make_engine().await;
            let hook = hook_flush_write(&mut engine);
            let engine = Arc::new(engine);

            engine.put(b"a", b"1").await.unwrap();
            engine.freeze_active_memtable();

            let flusher = {
                let engine = Arc::clone(&engine);
                compio::runtime::spawn(async move { engine.flush_memtable().await })
            };
            hook.reached.notified().await;

            let second = {
                let engine = Arc::clone(&engine);
                compio::runtime::spawn(async move { engine.flush_memtable().await })
            };
            yield_repeatedly().await;
            assert!(!second.is_finished(), "the second call waits for the flush in flight");

            hook.release.notify_one();
            assert!(flusher.await.unwrap().unwrap().is_some());
            assert!(
                second.await.unwrap().unwrap().is_none(),
                "the second call must find the MemTable already flushed"
            );
            assert_eq!(engine.version().level(0).len(), 1, "exactly one L0 file");
            assert!(engine.version().flushing.is_empty());
            assert_eq!(engine.get(b"a").await.unwrap(), Some(b"1".to_vec()));
        })
    }

    // A compaction installs both levels at once. Task
    // B reads while the compaction is parked after opening its new readers --
    // before the fix the source level was already emptied while the target
    // level still carried the old versions, so `a` and `b` read as `old`.
    #[test]
    fn test_reads_see_newest_versions_while_a_compaction_installs() {
        crate::core::engine_runtime::block_on(async {
            let (mut engine, _dir) = make_engine().await;

            // L1 keeps the old versions, L0 two files with the newer ones.
            engine.put(b"a", b"old").await.unwrap();
            engine.put(b"b", b"old").await.unwrap();
            freeze_and_flush(&engine).await;
            engine.compact_level(0).await.unwrap();
            assert_eq!(engine.version().level(1).len(), 1);
            engine.put(b"a", b"new").await.unwrap();
            freeze_and_flush(&engine).await;
            engine.put(b"b", b"new").await.unwrap();
            freeze_and_flush(&engine).await;
            assert_eq!(engine.version().level(0).len(), 2);

            // Armed only now: the setup compaction above must not park.
            let hook = Arc::new(TestHook::default());
            engine.hooks.before_level_install = Some(Arc::clone(&hook));
            let engine = Arc::new(engine);

            let compactor = {
                let engine = Arc::clone(&engine);
                compio::runtime::spawn(async move { engine.compact_level(0).await })
            };
            hook.reached.notified().await;

            assert_eq!(engine.get(b"a").await.unwrap(), Some(b"new".to_vec()));
            assert_eq!(engine.get(b"b").await.unwrap(), Some(b"new".to_vec()));
            assert_eq!(
                engine.scan_keys(b"").await.unwrap(),
                vec![b"a".to_vec(), b"b".to_vec()],
                "no key may disappear while the compaction installs"
            );

            hook.release.notify_one();
            compactor.await.unwrap().unwrap();

            assert_eq!(engine.get(b"a").await.unwrap(), Some(b"new".to_vec()));
            assert_eq!(engine.get(b"b").await.unwrap(), Some(b"new".to_vec()));
            assert!(engine.version().level(0).is_empty());
            assert_readers_match_manifest(&engine);
        })
    }

    // The Janitor installs every rebuilt level at
    // once. Task B reads across both levels while the GC is parked after
    // opening its new readers -- level by level, a reader could otherwise
    // catch a mix of rebuilt and retired ones.
    #[test]
    fn test_reads_see_every_key_while_the_janitor_installs() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let engine = Arc::new(engine);
            let big = vec![b'x'; 4096]; // >= vlog_inline_threshold → vLog pointer

            engine.put(b"a", &big).await.unwrap();
            freeze_and_flush(&engine).await;
            engine.compact_level(0).await.unwrap(); // "a" moves down to L1
            engine.put(b"b", &big).await.unwrap();
            freeze_and_flush(&engine).await;
            assert_eq!(engine.version().level(0).len(), 1);
            assert_eq!(engine.version().level(1).len(), 1);

            let hook = Arc::new(TestHook::default());
            let mut janitor = engine.build_janitor(gc_always());
            janitor.set_install_hook(Arc::clone(&hook));
            let janitor = Arc::new(janitor);

            let gc = {
                let janitor = Arc::clone(&janitor);
                compio::runtime::spawn(async move { janitor.run_gc().await })
            };
            hook.reached.notified().await;

            assert_eq!(engine.get(b"a").await.unwrap(), Some(big.clone()));
            assert_eq!(engine.get(b"b").await.unwrap(), Some(big.clone()));
            assert_eq!(
                engine.scan_keys(b"").await.unwrap(),
                vec![b"a".to_vec(), b"b".to_vec()],
                "no key may disappear while the GC installs its rebuilt levels"
            );

            hook.release.notify_one();
            assert!(gc.await.unwrap().unwrap().ran);

            assert_eq!(engine.get(b"a").await.unwrap(), Some(big.clone()));
            assert_eq!(engine.get(b"b").await.unwrap(), Some(big));
            assert_readers_match_manifest(&engine);
        })
    }

    use crate::core::coop::completion_order;

    /// 20 000 keys under `k:` in one batch — enough scan work that a missing
    /// yield point is unmistakable, small enough to stay in the MemTable.
    async fn fill_scan_keys(engine: &LsmStorageEngine) {
        let ops: Vec<BatchOp> = (0..20_000u32)
            .map(|i| BatchOp::Put { key: format!("k:{i:05}").into_bytes(), value: b"v".to_vec() })
            .collect();
        engine.write_batch(ops).await.unwrap();
    }

    // MemTable branch: a 20 000-key `scan_keys` hands
    // the thread back, so a point `get` spawned after it answers first.
    #[test]
    fn test_scan_keys_interleaves_with_get_in_memtable() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let engine = Arc::new(engine);
            fill_scan_keys(&engine).await;

            let scanner = Arc::clone(&engine);
            let reader = Arc::clone(&engine);
            let order = completion_order(
                async move { assert_eq!(scanner.scan_keys(b"k:").await.unwrap().len(), 20_000) },
                async move { assert!(reader.get(b"k:00001").await.unwrap().is_some()) },
            )
            .await;
            assert_eq!(order, ["small", "long"]);
        })
    }

    // SSTable branch: same, with the keys flushed to
    // L0 so the scan runs through `scan_sstable_for_prefix`.
    #[test]
    fn test_scan_keys_interleaves_with_get_in_sstable() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let engine = Arc::new(engine);
            fill_scan_keys(&engine).await;
            engine.freeze_active_memtable();
            engine.flush_memtable().await.unwrap().expect("a MemTable was frozen");

            let scanner = Arc::clone(&engine);
            let reader = Arc::clone(&engine);
            let order = completion_order(
                async move { assert_eq!(scanner.scan_keys(b"k:").await.unwrap().len(), 20_000) },
                async move { assert!(reader.get(b"k:00001").await.unwrap().is_some()) },
            )
            .await;
            assert_eq!(order, ["small", "long"]);
        })
    }

    // A MemTable rotation runs while the scan sits
    // in a yield *inside its frozen-list iteration* — where a read guard on
    // the frozen list used to be held. No `parking_lot` guard survives a
    // yield, so the rotation gets its write lock instead of deadlocking the
    // one thread, and the scan still returns every key it started with.
    #[test]
    fn test_scan_keys_survives_memtable_rotation_mid_scan() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let engine = Arc::new(engine);
            // The bulk goes to the frozen list without a flush; the active
            // MemTable keeps far fewer keys than one yield interval, so the scan's
            // first yield can only fall into the frozen-list iteration.
            fill_scan_keys(&engine).await;
            engine.freeze_active_memtable();
            for i in 0..4u32 {
                let key = format!("k:9000{i}");
                engine.set(key.as_bytes(), b"v").await.unwrap();
            }

            let scanner = Arc::clone(&engine);
            let scan = compio::runtime::spawn(async move { scanner.scan_keys(b"k:").await.unwrap() });
            let rotator = Arc::clone(&engine);
            let rotate = compio::runtime::spawn(async move {
                rotator.freeze_active_memtable();
                rotator.set(b"k:99999", b"v").await.unwrap();
            });

            let scanned = scan.await.unwrap();
            rotate.await.unwrap();
            assert_eq!(scanned.len(), 20_004, "the rotation must not cost the scan a key");
            assert_eq!(engine.scan_keys(b"k:").await.unwrap().len(), 20_005);
        })
    }

    /// 600 keys under `a:` among 20 000 under `b:` — fewer `a:` entries than
    /// one yield interval, yet enough work that the scan must yield.
    async fn fill_dense_range_among_foreign_keys(engine: &LsmStorageEngine) {
        let ops: Vec<BatchOp> = (0..600u32)
            .map(|i| format!("a:{i:03}"))
            .chain((0..20_000u32).map(|i| format!("b:{i:05}")))
            .map(|key| BatchOp::Put { key: key.into_bytes(), value: b"v".to_vec() })
            .collect();
        engine.write_batch(ops).await.unwrap();
    }

    /// Completion order of a scan over `a:` (long) and a point `get` (small).
    async fn dense_range_scan_order(engine: Arc<LsmStorageEngine>) -> Vec<&'static str> {
        let reader = Arc::clone(&engine);
        completion_order(
            async move { assert_eq!(engine.scan_keys(b"a:").await.unwrap().len(), 600) },
            async move { assert!(reader.get(b"b:00001").await.unwrap().is_some()) },
        )
        .await
    }

    // MemTable branch: the range seek skips the foreign keys, so
    // every visited entry but the last is a decided key and ticks twice.
    #[test]
    fn test_scan_keys_yields_within_a_dense_range_in_memtable() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            fill_dense_range_among_foreign_keys(&engine).await;

            assert_eq!(dense_range_scan_order(Arc::new(engine)).await, ["small", "long"]);
        })
    }

    // SSTable branch: the same keys flushed to L0, decided by the sweep.
    #[test]
    fn test_scan_keys_yields_within_a_dense_range_in_sstable() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            fill_dense_range_among_foreign_keys(&engine).await;
            engine.freeze_active_memtable();
            engine.flush_memtable().await.unwrap().expect("a MemTable was frozen");

            assert_eq!(dense_range_scan_order(Arc::new(engine)).await, ["small", "long"]);
        })
    }

    // 300 keys only in the active MemTable tick 600 times in the source loop,
    // under one yield interval: only collecting the result (300) and draining
    // the decided set (300) reaches it.
    #[test]
    fn test_scan_keys_yields_while_materializing_the_result() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let ops: Vec<BatchOp> = (0..300u32)
                .map(|i| BatchOp::Put { key: format!("m:{i:03}").into_bytes(), value: b"v".to_vec() })
                .collect();
            engine.write_batch(ops).await.unwrap();
            let engine = Arc::new(engine);

            let reader = Arc::clone(&engine);
            let order = completion_order(
                async move { assert_eq!(engine.scan_keys(b"m:").await.unwrap().len(), 300) },
                async move { assert!(reader.get(b"m:001").await.unwrap().is_some()) },
            )
            .await;
            assert_eq!(order, ["small", "long"]);
        })
    }

    /// The plain, limited and snapshot scans of `prefix`.
    async fn scan_results(
        engine: &LsmStorageEngine,
        snapshot: &Snapshot,
        prefix: &[u8],
    ) -> [Vec<Vec<u8>>; 3] {
        [
            engine.scan_keys(prefix).await.unwrap(),
            engine.scan_keys_limited(prefix, 50).await.unwrap(),
            engine.scan_keys_with_snapshot(prefix, snapshot).await.unwrap(),
        ]
    }

    // 2 100 keys span several data blocks. Deletes and overwrites before and
    // after the snapshot leave several versions per key: the flushed table
    // must answer every scan as the MemTable did.
    #[test]
    fn test_scan_keys_over_a_flushed_table_matches_the_memtable_scan() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let put = |key: String| BatchOp::Put { key: key.into_bytes(), value: b"v".to_vec() };
            let delete = |key: String| BatchOp::Delete { key: key.into_bytes() };
            let initial: Vec<BatchOp> = ["a:", "b:", "c:"]
                .into_iter()
                .flat_map(|group| (0..700u32).map(move |i| format!("{group}{i:04}")))
                .map(put)
                .collect();
            engine.write_batch(initial).await.unwrap();
            engine
                .write_batch((0..700u32).step_by(5).map(|i| delete(format!("b:{i:04}"))).collect())
                .await
                .unwrap();
            let snap = engine.snapshot().await;
            let mut later: Vec<BatchOp> = (0..700u32).step_by(3).map(|i| delete(format!("b:{i:04}"))).collect();
            later.extend((1..700u32).step_by(3).map(|i| put(format!("b:{i:04}"))));
            later.push(put("b:9999".to_string()));
            engine.write_batch(later).await.unwrap();

            let prefixes: [&[u8]; 5] = [b"a:", b"b:", b"b:00", b"c:", b""];
            let mut in_memtable = Vec::new();
            for prefix in prefixes {
                in_memtable.push(scan_results(&engine, snap.snapshot(), prefix).await);
            }
            assert_eq!(in_memtable[3][0].len(), 700, "an untouched group stays complete");
            assert!(
                in_memtable[1][2].len() > in_memtable[1][0].len(),
                "the snapshot still sees keys deleted after it"
            );

            engine.freeze_active_memtable();
            engine.flush_memtable().await.unwrap().expect("a MemTable was frozen");
            let mut in_sstable = Vec::new();
            for prefix in prefixes {
                in_sstable.push(scan_results(&engine, snap.snapshot(), prefix).await);
            }
            assert_eq!(in_sstable, in_memtable);
        })
    }

    /// Gives every other task room to run, without ever asserting on
    /// wall-clock time: a fixed yield budget, no deadline.
    async fn yield_repeatedly() {
        for _ in 0..1000 {
            tokio::task::yield_now().await;
        }
    }

    // The flush barrier must not return while a
    // flush claimed before it is still in flight -- the GC behind it would
    // otherwise scan a manifest that is missing that MemTable's SSTable.
    #[test]
    fn test_barrier_waits_for_a_flush_in_flight() {
        crate::core::engine_runtime::block_on(async {
            let (mut engine, _dir) = make_engine().await;
            let hook = hook_flush_write(&mut engine);
            let engine = Arc::new(engine);

            let big = vec![b'x'; 4096]; // >= vlog_inline_threshold → vLog pointer
            engine.put(b"parked", &big).await.unwrap();
            engine.freeze_active_memtable();

            let flusher = {
                let engine = Arc::clone(&engine);
                compio::runtime::spawn(async move { engine.flush_memtable().await })
            };
            hook.reached.notified().await;
            assert_eq!(engine.version().flushing.len(), 1, "the flush claimed the MemTable");
            assert!(
                engine.version().immutables.is_empty(),
                "the barrier finds an empty queue and must still wait"
            );

            let barrier = {
                let engine = Arc::clone(&engine);
                compio::runtime::spawn(async move { engine.flush_all_memtables().await })
            };
            yield_repeatedly().await;
            assert!(!barrier.is_finished(), "the barrier must wait for the flush in flight");

            hook.release.notify_one();
            barrier.await.unwrap().unwrap();
            assert!(flusher.await.unwrap().unwrap().is_some());
            assert!(engine.version().flushing.is_empty(), "no flush is left in flight");
            assert_eq!(engine.get(b"parked").await.unwrap(), Some(big));
        })
    }

    // A GC cycle must not retire the generation
    // a flush in flight still points into -- before the fix its barrier
    // returned early, the live scan missed that SSTable, and the key came back
    // as a pointer into a deleted generation.
    #[test]
    fn test_gc_waits_for_a_flush_in_flight_before_it_scans() {
        crate::core::engine_runtime::block_on(async {
            let (mut engine, _dir) = make_engine().await;
            let hook = hook_flush_write(&mut engine);
            let engine = Arc::new(engine);

            let big = vec![b'x'; 4096];
            engine.put(b"parked", &big).await.unwrap();
            engine.freeze_active_memtable();

            let flusher = {
                let engine = Arc::clone(&engine);
                compio::runtime::spawn(async move { engine.flush_memtable().await })
            };
            hook.reached.notified().await;

            let janitor = Arc::new(engine.build_janitor(gc_always()));
            let gc = {
                let janitor = Arc::clone(&janitor);
                compio::runtime::spawn(async move { janitor.run_gc().await })
            };
            yield_repeatedly().await;
            assert!(!gc.is_finished(), "the GC must not scan past a flush in flight");
            assert!(engine.version().vlog.contains_key(&1), "its source generation is still live");

            hook.release.notify_one();
            assert!(flusher.await.unwrap().unwrap().is_some());
            assert!(gc.await.unwrap().unwrap().ran);

            assert_eq!(engine.get(b"parked").await.unwrap(), Some(big));
            assert_readers_match_manifest(&engine);
        })
    }

    // Same wait, but the parked flush fails and hands its MemTable back to
    // the immutables. The barrier must not report success while that
    // MemTable still points into the generation the GC is about to retire:
    // the cycle fails instead, generation 1 stays, and the next cycle, with
    // the SSTable directory writable again, carries the value over.
    #[test]
    fn test_gc_keeps_the_generation_a_failed_flush_hands_back() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let sstable_dir = dir.path().join("sstables");
            std::fs::create_dir_all(&sstable_dir).unwrap();
            let mut engine = engine_with_sstable_dir(&dir, &sstable_dir).await;
            let hook = hook_flush_write(&mut engine);
            let engine = Arc::new(engine);

            let big = vec![b'x'; 4096];
            engine.put(b"parked", &big).await.unwrap();
            engine.freeze_active_memtable();

            let flusher = {
                let engine = Arc::clone(&engine);
                compio::runtime::spawn(async move { engine.flush_memtable().await })
            };
            hook.reached.notified().await;

            let janitor = Arc::new(engine.build_janitor(gc_always()));
            let gc = {
                let janitor = Arc::clone(&janitor);
                compio::runtime::spawn(async move { janitor.run_gc().await })
            };
            // Generation 2 is active once the GC is past its switch; from there
            // to the barrier's wait on the flush lock nothing yields.
            while engine.version().active_vlog.id() != 2 {
                assert!(!gc.is_finished(), "the GC ended before its switch");
                tokio::task::yield_now().await;
            }

            test_fault::fail_writes_in(&sstable_dir);
            // Lets the parked flush go on, and every later one that parks.
            let releaser = {
                let hook = Arc::clone(&hook);
                compio::runtime::spawn(async move {
                    loop {
                        hook.release.notify_one();
                        hook.reached.notified().await;
                    }
                })
            };
            assert!(flusher.await.unwrap().is_err(), "the parked SSTable write must fail");
            let cycle = gc.await.unwrap();
            test_fault::allow_writes_in(&sstable_dir);

            assert!(cycle.is_err(), "the GC must not go on past a MemTable its barrier left behind");
            assert!(engine.version().vlog.contains_key(&1), "generation 1 stays live");
            assert_eq!(engine.get(b"parked").await.unwrap(), Some(big.clone()));

            assert!(janitor.run_gc().await.unwrap().ran);
            assert!(!engine.version().vlog.contains_key(&1));
            assert_eq!(engine.get(b"parked").await.unwrap(), Some(big));
            drop(releaser);
        })
    }

    // L0 follows claim order, not completion
    // order. A second flush cannot claim while the first is in flight, so the
    // older MemTable's SSTable always lands first -- before the fix both ran
    // at once and whoever finished last counted as the newest source.
    #[test]
    fn test_l0_follows_claim_order_not_completion_order() {
        crate::core::engine_runtime::block_on(async {
            let (mut engine, _dir) = make_engine().await;
            let hook = hook_flush_write(&mut engine);
            let engine = Arc::new(engine);

            engine.put(b"k", b"old").await.unwrap();
            engine.freeze_active_memtable();
            engine.put(b"k", b"new").await.unwrap();
            engine.freeze_active_memtable();
            assert_eq!(engine.version().immutables.len(), 2);

            let older = {
                let engine = Arc::clone(&engine);
                compio::runtime::spawn(async move { engine.flush_memtable().await })
            };
            hook.reached.notified().await;

            let newer = {
                let engine = Arc::clone(&engine);
                compio::runtime::spawn(async move { engine.flush_memtable().await })
            };
            yield_repeatedly().await;
            assert_eq!(engine.version().flushing.len(), 1, "only one flush may be in flight");
            assert_eq!(
                engine.version().immutables.len(),
                1,
                "the younger MemTable stays queued until the older one is installed"
            );
            assert!(!newer.is_finished(), "it waits for the flush lock instead of claiming");

            hook.release.notify_one();
            let older_id = older.await.unwrap().unwrap().unwrap();
            hook.reached.notified().await;
            hook.release.notify_one();
            let newer_id = newer.await.unwrap().unwrap().unwrap();

            let l0: Vec<u64> = engine.version().level(0).iter().map(|r| r.file_id).collect();
            assert_eq!(l0, vec![older_id, newer_id], "L0 lists the SSTables oldest first");
            let manifest_l0: Vec<u64> =
                engine.manifest.read().get_level(0).iter().map(|m| m.file_id).collect();
            assert_eq!(manifest_l0, l0, "the manifest keeps that order across a restart");
            assert_eq!(engine.get(b"k").await.unwrap(), Some(b"new".to_vec()));
        })
    }

    // No flush may install while the GC swaps
    // manifest and levels -- before the fix one could, and the GC then rebuilt
    // every level from its own snapshot, so that SSTable kept its manifest
    // entry but lost its reader and every key with it.
    #[test]
    fn test_gc_install_keeps_a_concurrently_flushed_sstable() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let engine = Arc::new(engine);
            let big = vec![b'x'; 4096]; // >= vlog_inline_threshold → vLog pointer

            engine.put(b"a", &big).await.unwrap();
            freeze_and_flush(&engine).await;

            let hook = Arc::new(TestHook::default());
            let mut janitor = engine.build_janitor(gc_always());
            janitor.set_install_hook(Arc::clone(&hook));
            let janitor = Arc::new(janitor);

            let gc = {
                let janitor = Arc::clone(&janitor);
                compio::runtime::spawn(async move { janitor.run_gc().await })
            };
            hook.reached.notified().await;

            engine.put(b"b", b"2").await.unwrap();
            engine.freeze_active_memtable();
            let flusher = {
                let engine = Arc::clone(&engine);
                compio::runtime::spawn(async move { engine.flush_memtable().await })
            };
            yield_repeatedly().await;
            assert!(engine.version().flushing.is_empty(), "the GC install holds the flush lock");
            assert_eq!(
                engine.version().immutables.len(),
                1,
                "the flush waits for the install instead of landing inside it"
            );

            hook.release.notify_one();
            assert!(gc.await.unwrap().unwrap().ran);
            assert!(flusher.await.unwrap().unwrap().is_some());

            assert_readers_match_manifest(&engine);
            assert_eq!(engine.get(b"a").await.unwrap(), Some(big));
            assert_eq!(engine.get(b"b").await.unwrap(), Some(b"2".to_vec()));
        })
    }

    // The wider window: a flush that completes
    // between the GC's manifest snapshot and its install must survive that
    // install -- with its reader, because the reload reads the current
    // manifest and not the snapshot, and as the newest L0 source, because
    // every rebuild carries snapshot content and belongs in front of it.
    #[test]
    fn test_gc_install_adopts_an_sstable_flushed_since_its_snapshot() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let engine = Arc::new(engine);
            let old = vec![b'x'; 4096]; // >= vlog_inline_threshold → vLog pointer
            let new = vec![b'y'; 4096];

            engine.put(b"shared", &old).await.unwrap();
            freeze_and_flush(&engine).await;

            let hook = Arc::new(TestHook::default());
            let mut janitor = engine.build_janitor(gc_always());
            janitor.set_before_manifest_swap_hook(Arc::clone(&hook));
            let janitor = Arc::new(janitor);

            let gc = {
                let janitor = Arc::clone(&janitor);
                compio::runtime::spawn(async move { janitor.run_gc().await })
            };
            hook.reached.notified().await;

            // The whole flush fits into the window: it overwrites a key the
            // snapshot table carries and enters the manifest the GC never saw.
            engine.put(b"shared", &new).await.unwrap();
            engine.put(b"late", &new).await.unwrap();
            engine.freeze_active_memtable();
            let flushed_id = engine.flush_memtable().await.unwrap().unwrap();

            hook.release.notify_one();
            let stats = gc.await.unwrap().unwrap();
            assert_eq!(stats.sstables_rebuilt, 1, "only the snapshot table was rebuilt");

            assert_readers_match_manifest(&engine);
            assert_eq!(engine.get(b"late").await.unwrap(), Some(new.clone()));
            assert_eq!(
                engine.get(b"shared").await.unwrap(),
                Some(new),
                "the rebuild carries the version the flush replaced"
            );

            let l0: Vec<u64> = engine.version().level(0).iter().map(|r| r.file_id).collect();
            assert_eq!(l0.len(), 2);
            assert_eq!(l0[1], flushed_id, "the rebuild is older and goes in front of the flush");
            let manifest_l0: Vec<u64> =
                engine.manifest.read().get_level(0).iter().map(|m| m.file_id).collect();
            assert_eq!(manifest_l0, l0, "the manifest keeps that order across a restart");
        })
    }

    // The same for a compaction install -- it
    // reads its levels from the manifest, so a flush landing in L0 between
    // that read and the swap would be replaced away.
    #[test]
    fn test_compaction_install_keeps_a_concurrently_flushed_sstable() {
        crate::core::engine_runtime::block_on(async {
            let (mut engine, _dir) = make_engine().await;
            engine.put(b"a", b"1").await.unwrap();
            freeze_and_flush(&engine).await;
            engine.put(b"b", b"2").await.unwrap();
            freeze_and_flush(&engine).await;

            let hook = Arc::new(TestHook::default());
            engine.hooks.before_level_install = Some(Arc::clone(&hook));
            let engine = Arc::new(engine);

            let compactor = {
                let engine = Arc::clone(&engine);
                compio::runtime::spawn(async move { engine.compact_level(0).await })
            };
            hook.reached.notified().await;

            engine.put(b"c", b"3").await.unwrap();
            engine.freeze_active_memtable();
            let flusher = {
                let engine = Arc::clone(&engine);
                compio::runtime::spawn(async move { engine.flush_memtable().await })
            };
            yield_repeatedly().await;
            assert!(engine.version().flushing.is_empty(), "the compaction install holds the flush lock");
            assert_eq!(
                engine.version().immutables.len(),
                1,
                "the flush waits for the install instead of landing inside it"
            );

            hook.release.notify_one();
            compactor.await.unwrap().unwrap();
            assert!(flusher.await.unwrap().unwrap().is_some());

            assert_readers_match_manifest(&engine);
            assert_eq!(engine.get(b"a").await.unwrap(), Some(b"1".to_vec()));
            assert_eq!(engine.get(b"b").await.unwrap(), Some(b"2".to_vec()));
            assert_eq!(engine.get(b"c").await.unwrap(), Some(b"3".to_vec()));
        })
    }

    /// A level below L0 must be free of overlaps: the read path iterates it in
    /// undefined order, so one user key in two of its SSTables makes the
    /// winning version a coin toss.
    fn assert_levels_below_l0_are_disjoint(engine: &LsmStorageEngine) {
        for (lvl, readers) in engine.version().levels.iter().enumerate().skip(1) {
            let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
            for reader in readers {
                let mut keys: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
                for entry in reader.iter() {
                    let (key, _) = entry.unwrap();
                    if let Some(user_key) = InternalKey::extract_user_key(key) {
                        keys.insert(user_key.to_vec());
                    }
                }
                for key in keys {
                    assert!(
                        seen.insert(key.clone()),
                        "L{lvl} carries {} in two SSTables",
                        String::from_utf8_lossy(&key)
                    );
                }
            }
        }
    }

    // A compaction must not run inside a GC
    // cycle -- it would copy vLog pointers into the generations the cycle is
    // about to delete, and its manifest swap would make the GC re-enter the
    // very SSTables the compaction merged away.
    #[test]
    fn test_compaction_waits_for_the_gc_cycle() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let engine = Arc::new(engine);
            let big = vec![b'x'; 4096]; // >= vlog_inline_threshold → vLog pointer
            let keys: [&[u8]; 5] = [b"a", b"b", b"c", b"d", b"e"];

            engine.put(keys[0], &big).await.unwrap();
            freeze_and_flush(&engine).await;
            engine.compact_level(0).await.unwrap(); // "a" moves down to L1
            for key in &keys[1..] {
                engine.put(key, &big).await.unwrap();
                freeze_and_flush(&engine).await;
            }
            assert_eq!(engine.version().level(0).len(), 4);
            assert_eq!(engine.version().level(1).len(), 1);

            let hook = Arc::new(TestHook::default());
            let mut janitor = engine.build_janitor(gc_always());
            janitor.set_install_hook(Arc::clone(&hook));
            let janitor = Arc::new(janitor);

            let gc = {
                let janitor = Arc::clone(&janitor);
                compio::runtime::spawn(async move { janitor.run_gc().await })
            };
            hook.reached.notified().await;

            let compactor = {
                let engine = Arc::clone(&engine);
                compio::runtime::spawn(async move { engine.compact_level(0).await })
            };
            // The second one would find L2 empty and return without touching a
            // file, so its "not finished" says the lock spans the whole run and
            // not merely the I/O the first one happens to be busy with.
            let idle = {
                let engine = Arc::clone(&engine);
                compio::runtime::spawn(async move { engine.compact_level(2).await })
            };
            yield_repeatedly().await;
            assert!(!compactor.is_finished(), "a compaction must not run inside a GC cycle");
            assert!(!idle.is_finished(), "not even one that has nothing to compact");
            assert_eq!(
                engine.manifest.read().get_level(0).len(),
                4,
                "and none of them may swap the GC's tables out of the manifest"
            );

            hook.release.notify_one();
            assert!(gc.await.unwrap().unwrap().ran);
            compactor.await.unwrap().unwrap();
            assert!(idle.await.unwrap().unwrap().is_empty());

            assert_readers_match_manifest(&engine);
            assert_levels_below_l0_are_disjoint(&engine);
            for key in keys {
                assert_eq!(engine.get(key).await.unwrap(), Some(big.clone()), "key must survive");
            }
        })
    }

    async fn assert_raises_change_epoch<T>(
        engine: &LsmStorageEngine,
        write: impl std::future::Future<Output = Result<T>>,
    ) {
        let before = engine.change_epoch();
        write.await.unwrap();
        assert!(engine.change_epoch() > before, "the write must raise the change epoch");
    }

    #[test]
    fn test_write_kv_pair_raises_change_epoch() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            assert_raises_change_epoch(&engine, engine.write_kv_pair(b"k", b"v", None)).await;
        })
    }

    #[test]
    fn test_write_tombstone_raises_change_epoch() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            assert_raises_change_epoch(&engine, engine.write_tombstone(b"k")).await;
        })
    }

    #[test]
    fn test_write_tombstone_at_raises_change_epoch() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let memtable = engine.pin_memtable();
            let stamp = engine.next_timestamp().await;
            assert_raises_change_epoch(&engine, engine.write_tombstone_at(&memtable, b"k", stamp)).await;
        })
    }

    #[test]
    fn test_write_null_raises_change_epoch() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            assert_raises_change_epoch(&engine, engine.write_null(b"k")).await;
        })
    }

    #[test]
    fn test_write_batch_raises_change_epoch() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let ops = vec![
                BatchOp::Put { key: b"a".to_vec(), value: b"v".to_vec() },
                BatchOp::Delete { key: b"b".to_vec() },
            ];
            assert_raises_change_epoch(&engine, engine.write_batch(ops)).await;
        })
    }

    /// Sources a reader over `version` searches: MemTables plus SSTables.
    fn source_count(version: &Version) -> usize {
        version.memtables_newest_first().count() + version.sstables_newest_first().count()
    }

    // An install is one swap. While an install is parked
    // mid-build -- the claimed MemTable already out of the immutables, not
    // yet in the flush slot -- a reader holding the old version still reads
    // it whole; after the swap the new version is whole. No reader can meet
    // the mix the builder holds.
    #[test]
    fn test_install_swaps_the_whole_version_at_once() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let engine = Arc::new(engine);
            for i in 0..100u32 {
                engine.put(format!("k{i:03}").as_bytes(), b"v").await.unwrap();
            }
            engine.freeze_active_memtable();
            let before = engine.version();
            assert_eq!((before.immutables.len(), before.flushing.len()), (1, 0));
            assert_eq!(source_count(&before), 2);

            let (reached_tx, reached_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            let installer = {
                let engine = Arc::clone(&engine);
                std::thread::spawn(move || {
                    engine.install(|v| {
                        let mut next = v.clone();
                        let claimed = next.immutables.remove(0);
                        reached_tx.send(()).unwrap();
                        release_rx.recv().unwrap();
                        next.flushing.push(claimed);
                        next
                    });
                })
            };
            reached_rx.recv().unwrap();

            assert_eq!(source_count(&before), 2, "the old version is untouched mid-install");
            let reader = LsmReader::new(Arc::clone(&before), Arc::clone(&engine.block_cache), &engine.applying_batch);
            let snapshot = Snapshot::new(engine.next_timestamp().await);
            for i in 0..100u32 {
                assert_eq!(
                    reader.get(format!("k{i:03}").as_bytes(), &snapshot).await.unwrap(),
                    GetResult::Present(b"v".to_vec()),
                    "k{i:03} reads from the old version while the install is parked"
                );
            }

            release_tx.send(()).unwrap();
            installer.join().unwrap();
            let after = engine.version();
            assert_eq!((after.immutables.len(), after.flushing.len()), (0, 1));
            assert_eq!(source_count(&after), 2);
        })
    }

    // Point reads peek at the clock instead of advancing
    // it -- a thousand of them leave it where it was -- while each registered
    // snapshot draws a stamp of its own; a write confirmed on one thread is
    // visible to a read that follows on another.
    #[test]
    fn test_reads_peek_at_the_clock_and_see_confirmed_writes() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let engine = Arc::new(engine);
            engine.put(b"k", b"v").await.unwrap();

            let before = engine.hlc().peek();
            for _ in 0..1_000 {
                assert_eq!(engine.get(b"k").await.unwrap(), Some(b"v".to_vec()));
                assert!(engine.get_latest_with_metadata(b"k").await.unwrap().is_some());
            }
            assert_eq!(engine.hlc().peek(), before, "point reads must not draw stamps");

            let first = engine.snapshot().await;
            let second = engine.snapshot().await;
            assert!(first.snapshot().timestamp().as_u64() > before.as_u64());
            assert!(
                second.snapshot().timestamp().as_u64() > first.snapshot().timestamp().as_u64(),
                "every registered snapshot has a stamp of its own"
            );
            assert_eq!(engine.get_with_snapshot(b"k", second.snapshot()).await.unwrap(), GetResult::Present(b"v".to_vec()));

            // Thread A writes, then hands over to thread B, which reads.
            let (confirmed_tx, confirmed_rx) = std::sync::mpsc::channel();
            let writer = {
                let engine = Arc::clone(&engine);
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
                    rt.block_on(engine.put(b"handover", b"from-a")).unwrap();
                    confirmed_tx.send(()).unwrap();
                })
            };
            let reader = {
                let engine = Arc::clone(&engine);
                std::thread::spawn(move || {
                    confirmed_rx.recv().unwrap();
                    let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
                    rt.block_on(engine.get(b"handover")).unwrap()
                })
            };
            // Joined off the test runtime: the WAL committer runs on it.
            let read = tokio::task::spawn_blocking(move || {
                writer.join().unwrap();
                reader.join().unwrap()
            })
            .await
            .unwrap();
            assert_eq!(read, Some(b"from-a".to_vec()));
        })
    }

    // Point reads leave the snapshot registry alone; a
    // scan pinned to a registered snapshot keeps exactly that one entry while
    // it yields, a point read in between adds none, and the entry leaves with
    // the guard.
    #[test]
    fn test_point_reads_register_nothing_and_a_scan_holds_one_snapshot() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let engine = Arc::new(engine);
            fill_scan_keys(&engine).await;
            let registry = Arc::clone(&engine.snapshot_registry);
            let acquired = registry.acquire_count();

            assert!(engine.get(b"k:00001").await.unwrap().is_some());
            assert!(engine.get_latest_with_expiry(b"k:00001").await.unwrap().0 != GetResult::Absent);
            assert!(engine.get_latest_with_metadata(b"k:00001").await.unwrap().is_some());
            assert_eq!(registry.acquire_count(), acquired, "point reads must not register");
            assert_eq!(registry.active_count(), 0);

            let scanner = {
                let engine = Arc::clone(&engine);
                compio::runtime::spawn(async move {
                    let guard = engine.snapshot().await;
                    engine.scan_keys_with_snapshot(b"k:", guard.snapshot()).await.unwrap().len()
                })
            };
            let mut checks = 0;
            loop {
                tokio::task::yield_now().await;
                if scanner.is_finished() {
                    break;
                }
                assert_eq!(registry.active_count(), 1, "exactly the scan's snapshot is registered");
                assert!(engine.get(b"k:00002").await.unwrap().is_some());
                assert_eq!(registry.active_count(), 1, "a point read mid-scan registers nothing");
                checks += 1;
            }
            assert!(checks > 0, "the scan must have yielded at least once");
            assert_eq!(scanner.await.unwrap(), 20_000);
            assert_eq!(registry.active_count(), 0, "the guard deregisters on drop");
        })
    }

    // A registered snapshot draws its stamp under the lock a compaction's
    // low watermark takes: parked on another thread right after the draw,
    // the reader still holds it, so no compaction can choose its inputs
    // between the stamp and its registration. The version the stamp sees
    // then survives an overwrite and the compaction that merges both.
    #[test]
    fn test_registered_snapshot_reads_the_key_a_compaction_rewrote_meanwhile() {
        crate::core::engine_runtime::block_on(async {
            let (mut engine, _dir) = make_engine().await;
            let (hook, reached, release) = ThreadHook::new();
            engine.hooks.snapshot_stamp_drawn = Some(hook);
            let engine = Arc::new(engine);
            // `a` and `z` widen the L1 table's range, so the later compaction
            // merges the new L0 table with it.
            for key in [b"a", b"k", b"z"] {
                engine.put(key, b"old").await.unwrap();
            }
            freeze_and_flush(&engine).await;
            engine.compact_level(0).await.unwrap();

            let reader = {
                let engine = Arc::clone(&engine);
                std::thread::spawn(move || futures::executor::block_on(engine.snapshot()))
            };
            reached.recv().unwrap();
            assert!(engine.snapshot_registry().is_locked(), "the stamp is drawn under the registry lock");
            engine.put(b"k", b"new").await.unwrap();
            freeze_and_flush(&engine).await;
            release.send(()).unwrap();
            let registered = tokio::task::spawn_blocking(move || reader.join().unwrap()).await.unwrap();

            engine.compact_level(0).await.unwrap();
            assert_eq!(engine.version().level(1).len(), 1, "the compaction merged both versions");
            assert_eq!(
                engine.get_with_snapshot(b"k", registered.snapshot()).await.unwrap(),
                GetResult::Present(b"old".to_vec()),
                "the compaction keeps the version the snapshot reads"
            );
            assert_eq!(engine.get(b"k").await.unwrap(), Some(b"new".to_vec()));
        })
    }

    // A version holding a retired generation keeps its
    // file -- a reader on it still gets the value -- until the version is
    // dropped; the Janitor's next run deletes the file.
    #[test]
    fn test_retired_generation_lives_until_the_last_version_drops() {
        crate::core::engine_runtime::block_on(async {
            let (engine, dir) = make_engine().await;
            let engine = Arc::new(engine);
            let big = vec![b'r'; 4096]; // >= vlog_inline_threshold → vLog pointer
            engine.put(b"held", &big).await.unwrap();
            let held = engine.version();
            let gen1_path = dir.path().join("vlog.log");
            let janitor = engine.build_janitor(gc_always());

            assert!(janitor.run_gc().await.unwrap().ran);
            assert!(!engine.version().vlog.contains_key(&1), "generation 1 is retired");
            assert!(gen1_path.exists(), "a version still holds generation 1");
            let reader = LsmReader::new(Arc::clone(&held), Arc::clone(&engine.block_cache), &engine.applying_batch);
            let snapshot = Snapshot::new(engine.read_timestamp());
            assert_eq!(reader.get(b"held", &snapshot).await.unwrap(), GetResult::Present(big.clone()));

            drop(reader);
            drop(held);
            assert!(gen1_path.exists(), "the Janitor deletes it, not the drop");
            janitor.run_gc().await.unwrap();
            assert!(!gen1_path.exists(), "the next run deletes the released generation");
            assert_eq!(engine.get(b"held").await.unwrap(), Some(big));
        })
    }

    // A reader still on the version from before a compaction or a GC probes
    // a table that job retired: it reads through the table's own mapping, but
    // no block of it goes back into the cache, where it would keep the deleted
    // file allocated.
    #[test]
    fn test_reads_on_an_old_version_cache_no_block_of_a_retired_sstable() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let engine = Arc::new(engine);
            engine.put(b"k", b"v").await.unwrap();
            freeze_and_flush(&engine).await;

            let before_compaction = engine.version();
            engine.compact_level(0).await.unwrap();
            let before_gc = engine.version();
            assert!(engine.build_janitor(gc_always()).run_gc().await.unwrap().ran);

            for (version, job) in [(before_compaction, "compaction"), (before_gc, "GC")] {
                let retired = version.sstables_newest_first().next().unwrap().file_id;
                let reader = LsmReader::new(Arc::clone(&version), Arc::clone(&engine.block_cache), &engine.applying_batch);
                let snapshot = Snapshot::new(engine.read_timestamp());
                assert_eq!(reader.get(b"k", &snapshot).await.unwrap(), GetResult::Present(b"v".to_vec()));
                let block = BlockCacheKey { file_id: retired, block_offset: 0 };
                assert!(
                    engine.block_cache.stripe(&block).get(&block).is_none(),
                    "no block of the table the {job} retired may be cached again"
                );
            }
        })
    }

    // The same for a reader two maintenance installs behind: the compaction
    // in between keeps the reader's table, and the GC after it retires the
    // table for that reader's version too.
    #[test]
    fn test_reads_two_installs_behind_cache_no_block_of_a_retired_sstable() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let engine = Arc::new(engine);
            engine.put(b"a", b"v").await.unwrap();
            freeze_and_flush(&engine).await;
            engine.compact_level(0).await.unwrap();
            let held = engine.version();
            let table = held.level(1)[0].file_id;

            // `z` lies beyond the L1 table's range, so the compaction keeps it.
            engine.put(b"z", b"v").await.unwrap();
            freeze_and_flush(&engine).await;
            engine.compact_level(0).await.unwrap();
            assert!(engine.version().level(1).iter().any(|t| t.file_id == table), "the compaction kept the table");
            assert!(engine.build_janitor(gc_always()).run_gc().await.unwrap().ran);
            assert!(engine.version().level(1).iter().all(|t| t.file_id != table), "the GC retired the table");

            let reader = LsmReader::new(Arc::clone(&held), Arc::clone(&engine.block_cache), &engine.applying_batch);
            let snapshot = Snapshot::new(engine.read_timestamp());
            assert_eq!(reader.get(b"a", &snapshot).await.unwrap(), GetResult::Present(b"v".to_vec()));
            let block = BlockCacheKey { file_id: table, block_offset: 0 };
            assert!(
                engine.block_cache.stripe(&block).get(&block).is_none(),
                "no block of the retired table may be cached again"
            );
        })
    }

    const STRESS_KEYS: u64 = 20_000;
    /// Keys every phase after the first overwrites.
    const STRESS_OVERWRITES: u64 = 5_000;

    fn stress_key(i: u64) -> Vec<u8> {
        format!("s{i:05}").into_bytes()
    }

    /// Key `i`'s value in write phase `phase`: phase and key up front, the
    /// rest padding above the inline threshold, so every value lives in the
    /// vLog.
    fn stress_value(i: u64, phase: u64) -> Vec<u8> {
        let mut value = format!("{phase}:{i:05}:").into_bytes();
        value.resize(1_100, b'x');
        value
    }

    /// The phase `value` was written in; panics unless it is a value of key `i`.
    fn stress_phase(i: u64, value: &[u8]) -> u64 {
        let text = std::str::from_utf8(&value[..value.len().min(16)]).unwrap_or("");
        let mut fields = text.split(':');
        let phase = fields.next().and_then(|p| p.parse().ok());
        match (phase, fields.next()) {
            (Some(phase), Some(key)) if key == format!("{i:05}") => phase,
            _ => panic!("key {i} read a foreign value"),
        }
    }

    /// Keys the writer has confirmed at `mark` (`phase << 32 | keys confirmed
    /// in that phase`): phase 0 writes every key, each later phase overwrites
    /// the first [`STRESS_OVERWRITES`].
    fn stress_known(mark: u64) -> u64 {
        if mark >> 32 == 0 { mark & u64::from(u32::MAX) } else { STRESS_KEYS }
    }

    /// Oldest phase a read of confirmed key `i` may return at `mark`.
    fn stress_least_phase(mark: u64, i: u64) -> u64 {
        let (phase, upto) = (mark >> 32, mark & u64::from(u32::MAX));
        if i < upto {
            phase
        } else if i < STRESS_OVERWRITES {
            phase - 1
        } else {
            0
        }
    }

    /// `keys`, a sorted scan result, lists the first `known` keys.
    fn assert_lists_known_keys(keys: &[Vec<u8>], known: u64) {
        assert!(keys.len() as u64 >= known, "a scan lost confirmed keys");
        for (n, key) in keys.iter().take(known as usize).enumerate() {
            assert_eq!(key, &stress_key(n as u64), "a scan lost confirmed key {n}");
        }
    }

    fn next_random(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    /// Sets its flag when dropped -- on an unwind too, so the stress readers
    /// stop when the writer fails.
    struct SetOnDrop(Arc<AtomicBool>);

    impl Drop for SetOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    /// One reader thread of the stress test: its own current-thread runtime,
    /// random point reads of confirmed keys with a full scan every 2 000
    /// reads, until `done`. A read returns at least the phase confirmed for
    /// its key before it started.
    fn spawn_stress_reader(
        engine: Arc<LsmStorageEngine>,
        mark: Arc<AtomicU64>,
        done: Arc<AtomicBool>,
        started: Arc<std::sync::Barrier>,
        seed: u64,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            rt.block_on(async move {
                let mut rng = 0x9E37_79B9_7F4A_7C15u64 ^ seed;
                let mut reads = 0u64;
                started.wait();
                loop {
                    let finished = done.load(Ordering::Acquire);
                    let at = mark.load(Ordering::Acquire);
                    let known = stress_known(at);
                    if known == 0 {
                        if finished {
                            break;
                        }
                        std::thread::yield_now();
                        continue;
                    }
                    let i = next_random(&mut rng) % known;
                    let least = stress_least_phase(at, i);
                    match engine.get(&stress_key(i)).await {
                        Ok(Some(value)) => {
                            let phase = stress_phase(i, &value);
                            assert!(phase >= least, "key {i} read phase {phase}, below the confirmed {least}");
                        }
                        Ok(None) => panic!("confirmed key {i} read as absent"),
                        Err(e) => panic!("read of confirmed key {i} failed: {e}"),
                    }
                    reads += 1;
                    if reads.is_multiple_of(2_000) || finished {
                        assert_lists_known_keys(&engine.scan_keys(b"s").await.unwrap(), known);
                    }
                    if finished {
                        break;
                    }
                    if reads.is_multiple_of(64) {
                        std::thread::sleep(Duration::from_micros(200));
                    }
                }
            });
        })
    }

    /// The stress test's reader on registered snapshots: each is held while
    /// the writer moves on, and its point reads and scans keep seeing what
    /// they saw first -- no confirmed key missing, no key back at an older
    /// phase than its first read at that stamp.
    fn spawn_pinned_stress_reader(
        engine: Arc<LsmStorageEngine>,
        mark: Arc<AtomicU64>,
        done: Arc<AtomicBool>,
        started: Arc<std::sync::Barrier>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            rt.block_on(async move {
                let mut rng = 0x2545_F491_4F6C_DD1Du64;
                started.wait();
                while !done.load(Ordering::Acquire) {
                    let at = mark.load(Ordering::Acquire);
                    let known = stress_known(at);
                    if known == 0 {
                        std::thread::yield_now();
                        continue;
                    }
                    let pinned = engine.snapshot().await;
                    let snapshot = pinned.snapshot();
                    let sample: Vec<u64> = (0..32).map(|_| next_random(&mut rng) % known).collect();
                    let mut first = Vec::with_capacity(sample.len());
                    for round in 0..4 {
                        assert_lists_known_keys(&engine.scan_keys_with_snapshot(b"s", snapshot).await.unwrap(), known);
                        for (n, &i) in sample.iter().enumerate() {
                            let phase = match engine.get_with_snapshot(&stress_key(i), snapshot).await {
                                Ok(GetResult::Present(value)) => stress_phase(i, &value),
                                other => panic!("confirmed key {i} read {other:?} at a pinned stamp"),
                            };
                            if round == 0 {
                                assert!(phase >= stress_least_phase(at, i), "key {i} read below its confirmed phase");
                                first.push(phase);
                            } else {
                                assert!(phase >= first[n], "key {i} went back to an older phase at a pinned stamp");
                            }
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            });
        })
    }

    // Four reader threads, each on its own runtime, read
    // while the engine runtime writes 20 000 vLog-sized keys, then
    // overwrites the first 5 000 in two more phases, through forced rotations,
    // flushes, compactions and a vLog GC. A read of a confirmed key always
    // returns a value of at least the phase confirmed for it -- never absent,
    // never an error such as an unknown generation -- and a scan always lists
    // every confirmed key. A fifth reader holds registered snapshots across
    // the writer's progress, so compactions meet a watermark, and checks that
    // each stays consistent. A fixed amount of writes, no clock.
    #[test]
    fn test_readers_on_other_threads_never_miss_a_confirmed_key() {
        crate::core::engine_runtime::block_on(async {
            const PHASES: u64 = 3;
            const BATCH: u64 = 100;
            let dir = tempfile::TempDir::new().unwrap();
            let engine = Arc::new(engine_with_threshold(&dir, 64 * 1024).await);
            let janitor = engine.build_janitor(gc_always());
            let mark = Arc::new(AtomicU64::new(0));
            let done = Arc::new(AtomicBool::new(false));
            let started = Arc::new(std::sync::Barrier::new(6));

            let mut readers: Vec<_> = (0..4)
                .map(|t| {
                    spawn_stress_reader(
                        Arc::clone(&engine),
                        Arc::clone(&mark),
                        Arc::clone(&done),
                        Arc::clone(&started),
                        t + 1,
                    )
                })
                .collect();
            readers.push(spawn_pinned_stress_reader(
                Arc::clone(&engine),
                Arc::clone(&mark),
                Arc::clone(&done),
                Arc::clone(&started),
            ));
            let stop_readers = SetOnDrop(Arc::clone(&done));
            started.wait();

            for phase in 0..PHASES {
                let batches = if phase == 0 { STRESS_KEYS } else { STRESS_OVERWRITES } / BATCH;
                for batch in 0..batches {
                    let first = batch * BATCH;
                    let ops = (first..first + BATCH)
                        .map(|i| BatchOp::Put { key: stress_key(i), value: stress_value(i, phase) })
                        .collect();
                    engine.write_batch(ops).await.unwrap();
                    mark.store(phase << 32 | (first + BATCH), Ordering::Release);

                    let written = batch + 1;
                    if written % 25 == 0 {
                        engine.flush_all_memtables().await.unwrap();
                    }
                    if written == batches / 2 {
                        engine.compact_level(0).await.unwrap();
                    }
                    if phase == 0 && written == batches * 3 / 4 {
                        assert!(janitor.run_gc().await.unwrap().ran);
                    }
                }
                engine.compact_level(0).await.unwrap();
            }
            drop(stop_readers);

            for reader in readers {
                reader.join().unwrap();
            }
            assert!(engine.version().vlog.keys().all(|id| *id > 1), "the GC retired generation 1");
            assert_eq!(engine.scan_keys(b"s").await.unwrap().len() as u64, STRESS_KEYS);
            for i in 0..STRESS_KEYS {
                let phase = if i < STRESS_OVERWRITES { PHASES - 1 } else { 0 };
                assert_eq!(engine.get(&stress_key(i)).await.unwrap(), Some(stress_value(i, phase)));
            }
        })
    }

    // A new active generation comes with a fresh MemTable, so
    // a version taken before the switch never meets a pointer into the new
    // generation -- the write after it lands in a MemTable that version does
    // not hold.
    #[test]
    fn test_version_before_a_generation_switch_never_sees_its_pointers() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let big = vec![b'n'; 4096]; // >= vlog_inline_threshold → vLog pointer
            let before = engine.version();
            let gen2 = Arc::new(VLog::open(generation_path(&engine.vlog_path, 2), 2).await.unwrap());
            engine.install(|v| v.with_active_vlog(gen2, engine.last_applied_lsn()));
            engine.put(b"late", &big).await.unwrap();

            let reader = LsmReader::new(before, Arc::clone(&engine.block_cache), &engine.applying_batch);
            let snapshot = Snapshot::new(engine.read_timestamp());
            assert_eq!(reader.get(b"late", &snapshot).await.unwrap(), GetResult::Absent);
            assert_eq!(engine.get(b"late").await.unwrap(), Some(big));
        })
    }

    // A pointer is resolved through the reader's own version only: a
    // generation the version does not know is a clean error, never a read
    // from some other file.
    #[test]
    fn test_pointer_into_an_unknown_generation_is_a_clean_error() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let stamp = engine.next_timestamp().await;
            let dangling = Value::Pointer { file_id: 7, offset: 0, len: 4, expire_at: None };
            engine.version().memtable.set(b"k".to_vec(), stamp, dangling);

            let err = engine.get(b"k").await.unwrap_err();
            assert!(err.to_string().contains("Unknown value log generation 7"), "{err}");
        })
    }

    /// Writes `key` and moves it down to L2, leaving L0 and L1 empty.
    async fn put_into_l2(engine: &LsmStorageEngine, key: &[u8], value: &[u8]) {
        engine.put(key, value).await.unwrap();
        freeze_and_flush(engine).await;
        engine.compact_level(0).await.unwrap();
        engine.compact_level(1).await.unwrap();
        assert!(engine.version().level(1).is_empty());
        assert_eq!(engine.version().level(2).len(), 1);
    }

    // Dropping the expired version on its way to L1
    // would bring back the older one in L2.
    #[test]
    fn test_compaction_keeps_expired_value_over_an_older_one_below() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            put_into_l2(&engine, b"k", b"v1").await;
            engine.put_expired_for_test(b"k", b"v2").await.unwrap();
            freeze_and_flush(&engine).await;

            engine.compact_level(0).await.unwrap();

            assert_eq!(engine.get(b"k").await.unwrap(), None);
        })
    }

    // The same for a tombstone below the watermark of a
    // registered snapshot.
    #[test]
    fn test_compaction_keeps_tombstone_over_an_older_version_below() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            put_into_l2(&engine, b"k", b"v1").await;
            engine.delete(b"k").await.unwrap();
            freeze_and_flush(&engine).await;
            let snap = engine.snapshot().await; // stamped above the tombstone

            engine.compact_level(0).await.unwrap();

            assert_eq!(engine.get(b"k").await.unwrap(), None);
            assert_eq!(engine.get_with_snapshot(b"k", snap.snapshot()).await.unwrap(), GetResult::Absent);
        })
    }

    // With no level below the target, both still go.
    #[test]
    fn test_bottommost_compaction_drops_tombstone_and_expired_value() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put_expired_for_test(b"e", b"v").await.unwrap();
            engine.delete(b"d").await.unwrap();
            freeze_and_flush(&engine).await;
            let _snap = engine.snapshot().await; // stamped above the tombstone

            engine.compact_level(0).await.unwrap();

            assert!(engine.version().level(0).is_empty(), "L0 was compacted away");
            assert!(engine.version().level(1).is_empty(), "nothing is left to write to L1");
        })
    }

    // The L1 table starts with an older version of the
    // L0 selection's largest user key, which sorts behind the selection's
    // largest internal key; it must join the job all the same.
    #[test]
    fn test_compaction_merges_target_table_starting_with_older_version_of_largest_key() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            engine.put(b"k", b"v1").await.unwrap();
            engine.put(b"z", b"26").await.unwrap();
            freeze_and_flush(&engine).await;
            engine.compact_level(0).await.unwrap(); // L1 spans [k@t1, z]

            engine.put(b"a", b"1").await.unwrap();
            engine.put(b"k", b"v2").await.unwrap();
            freeze_and_flush(&engine).await; // L0 spans [a, k@t2]

            engine.compact_level(0).await.unwrap();

            assert_levels_below_l0_are_disjoint(&engine);
            assert_eq!(engine.get(b"k").await.unwrap(), Some(b"v2".to_vec()));
        })
    }

    /// Ends of a hook that parks `write_batch` after its first MemTable insert.
    type BatchHook = (std::sync::mpsc::Receiver<std::thread::ThreadId>, std::sync::mpsc::Sender<()>);

    /// Engine whose `write_batch` parks after its first MemTable insert.
    async fn engine_with_batch_hook() -> (Arc<LsmStorageEngine>, BatchHook, tempfile::TempDir) {
        let (mut engine, dir) = make_engine().await;
        let (hook, reached, release) = ThreadHook::new();
        engine.hooks.batch_first_applied = Some(hook);
        (Arc::new(engine), (reached, release), dir)
    }

    /// Writes `ops` as one batch; while its Phase 2 is parked, `read` runs on
    /// a thread of its own with its own runtime. Returns what `read` saw.
    async fn read_mid_batch<T, F>(
        engine: &Arc<LsmStorageEngine>,
        (reached, release): BatchHook,
        ops: Vec<BatchOp>,
        read: impl FnOnce(Arc<LsmStorageEngine>) -> F + Send + 'static,
    ) -> T
    where
        T: Send + 'static,
        F: std::future::Future<Output = T>,
    {
        let reader = {
            let engine = Arc::clone(engine);
            std::thread::spawn(move || {
                reached.recv().unwrap();
                let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
                let seen = rt.block_on(read(engine));
                release.send(()).unwrap();
                seen
            })
        };
        engine.write_batch(ops).await.unwrap();
        tokio::task::spawn_blocking(move || reader.join().unwrap()).await.unwrap()
    }

    fn put_op(key: &[u8], value: &[u8]) -> BatchOp {
        BatchOp::Put { key: key.to_vec(), value: value.to_vec() }
    }

    // Phase 2 parked after `a` -- a reader on another
    // thread reads `a` and `b` old through the point-read entries, although a
    // reader blind to the batch slot already meets the new `a`; once the
    // batch is through, both are new.
    #[test]
    fn test_point_reads_on_another_thread_see_a_batch_whole_or_not_at_all() {
        crate::core::engine_runtime::block_on(async {
            let (engine, hook, _dir) = engine_with_batch_hook().await;
            for key in [b"a", b"b"] {
                engine.put(key, b"old").await.unwrap();
            }

            let ops = vec![put_op(b"a", b"new"), put_op(b"b", b"new")];
            let seen = read_mid_batch(&engine, hook, ops, |engine| async move {
                let no_batch = AtomicU64::new(0);
                let blind = LsmReader::new(engine.version(), Arc::clone(&engine.block_cache), &no_batch);
                let registered = engine.snapshot().await;
                let mut seen = Vec::new();
                for key in [b"a", b"b"] {
                    seen.push((
                        engine.get_latest_with_expiry(key).await.unwrap().0,
                        engine.get_latest_with_metadata(key).await.unwrap().map(|m| m.data),
                        engine.get_with_snapshot(key, registered.snapshot()).await.unwrap(),
                        blind.get(key, registered.snapshot()).await.unwrap(),
                    ));
                }
                seen
            })
            .await;

            let old = || GetResult::Present(b"old".to_vec());
            let new = || GetResult::Present(b"new".to_vec());
            assert_eq!(
                seen,
                vec![(old(), Some(b"old".to_vec()), old(), new()), (old(), Some(b"old".to_vec()), old(), old())]
            );
            for key in [b"a", b"b"] {
                assert_eq!(engine.get(key).await.unwrap(), Some(b"new".to_vec()));
            }
        })
    }

    // The batch of a prefix delete -- three tombstones,
    // parked after the first -- leaves all three keys present for a reader
    // on another thread; once it is through, all three are gone.
    #[test]
    fn test_a_prefix_delete_batch_is_whole_or_not_at_all_for_another_thread() {
        crate::core::engine_runtime::block_on(async {
            let (engine, hook, _dir) = engine_with_batch_hook().await;
            let keys = [b"p:1", b"p:2", b"p:3"];
            for key in keys {
                engine.put(key, b"v").await.unwrap();
            }

            let ops = keys.iter().map(|key| BatchOp::Delete { key: key.to_vec() }).collect();
            let seen = read_mid_batch(&engine, hook, ops, move |engine| async move {
                let mut seen = Vec::new();
                for key in keys {
                    seen.push(engine.get_latest_with_expiry(key).await.unwrap().0);
                }
                seen
            })
            .await;

            assert_eq!(seen, vec![GetResult::Present(b"v".to_vec()); 3]);
            for key in keys {
                assert_eq!(engine.get_latest_with_expiry(key).await.unwrap().0, GetResult::Absent);
            }
        })
    }

    // A key the batch writes twice never shows its first
    // value -- neither to a reader while Phase 2 is parked nor to one blind
    // to the slot, which stands for a reader that found the key mid-batch but
    // loaded the slot only after the batch.
    #[test]
    fn test_a_key_written_twice_in_a_batch_never_shows_its_first_value() {
        crate::core::engine_runtime::block_on(async {
            let (engine, hook, _dir) = engine_with_batch_hook().await;
            engine.put(b"k", b"old").await.unwrap();

            let ops = vec![put_op(b"k", b"first"), put_op(b"k", b"last")];
            let seen = read_mid_batch(&engine, hook, ops, |engine| async move {
                let no_batch = AtomicU64::new(0);
                let blind = LsmReader::new(engine.version(), Arc::clone(&engine.block_cache), &no_batch);
                (
                    engine.get_latest_with_expiry(b"k").await.unwrap().0,
                    blind.get(b"k", &Snapshot::new(engine.read_timestamp())).await.unwrap(),
                )
            })
            .await;

            assert_eq!(seen, (GetResult::Present(b"old".to_vec()), GetResult::Present(b"last".to_vec())));
            assert_eq!(engine.get(b"k").await.unwrap(), Some(b"last".to_vec()));
        })
    }

    // A scan on another thread while Phase 2 is parked
    // after its first insert -- `p:new`, or the tombstone of `p:old` -- lists
    // `p:old` and not `p:new`, with and without a snapshot; once the batch is
    // through, it lists only `p:new`.
    #[test]
    fn test_scans_on_another_thread_skip_a_batch_being_applied() {
        crate::core::engine_runtime::block_on(async {
            let put_new = || put_op(b"p:new", b"v");
            let delete_old = || BatchOp::Delete { key: b"p:old".to_vec() };
            let mut seen = Vec::new();
            for ops in [vec![put_new(), delete_old()], vec![delete_old(), put_new()]] {
                // The hook parks only once: one engine per order.
                let (engine, hook, _dir) = engine_with_batch_hook().await;
                engine.put(b"p:old", b"v").await.unwrap();

                let (unregistered, registered) = read_mid_batch(&engine, hook, ops, |engine| async move {
                    let registered = engine.snapshot().await;
                    (
                        engine.scan_keys(b"p:").await.unwrap(),
                        engine.scan_keys_with_snapshot(b"p:", registered.snapshot()).await.unwrap(),
                    )
                })
                .await;
                seen.push((unregistered, registered, engine.scan_keys(b"p:").await.unwrap()));
            }

            let (old, new) = (vec![b"p:old".to_vec()], vec![b"p:new".to_vec()]);
            assert_eq!(seen, vec![(old.clone(), old, new); 2], "per order: scans mid-batch, scan after");
        })
    }

    // A batch confirmed on thread A is whole for the
    // point reads and the scan that follow on thread B -- the slot no longer
    // names it once the batch is confirmed.
    #[test]
    fn test_a_batch_confirmed_on_one_thread_is_whole_for_reads_on_another() {
        crate::core::engine_runtime::block_on(async {
            let (engine, _dir) = make_engine().await;
            let engine = Arc::new(engine);

            let (confirmed_tx, confirmed_rx) = std::sync::mpsc::channel();
            let writer = {
                let engine = Arc::clone(&engine);
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
                    rt.block_on(engine.write_batch(vec![put_op(b"a", b"v"), put_op(b"b", b"v")])).unwrap();
                    confirmed_tx.send(()).unwrap();
                })
            };
            let reader = {
                let engine = Arc::clone(&engine);
                std::thread::spawn(move || {
                    confirmed_rx.recv().unwrap();
                    let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
                    rt.block_on(async {
                        (
                            engine.get(b"a").await.unwrap(),
                            engine.get(b"b").await.unwrap(),
                            engine.scan_keys(b"").await.unwrap(),
                        )
                    })
                })
            };
            // Joined off the test runtime: the WAL committer runs on it.
            let read = tokio::task::spawn_blocking(move || {
                writer.join().unwrap();
                reader.join().unwrap()
            })
            .await
            .unwrap();

            assert_eq!(read, (Some(b"v".to_vec()), Some(b"v".to_vec()), vec![b"a".to_vec(), b"b".to_vec()]));
        })
    }

    use crate::storage::test_trace;

    /// An engine on `dir` laid out as a data shard is: the WAL on top, the
    /// vLog in `vlog/`, SSTables and manifest in `sst/`.
    async fn engine_split(dir: &Path) -> Result<LsmStorageEngine> {
        engine_split_with(dir, LsmEngineOptions::default()).await
    }

    /// [`engine_split`] with `options`.
    async fn engine_split_with(dir: &Path, options: LsmEngineOptions) -> Result<LsmStorageEngine> {
        let wal_path = dir.join("wal.log");
        let wal = Arc::new(WriteAheadLog::new(&wal_path).await?);
        let vlog_path = dir.join("vlog").join("vlog.log");
        std::fs::create_dir_all(dir.join("vlog"))?;
        let vlog = Arc::new(VLog::new(&vlog_path).await?);
        let file_manager = Arc::new(FileManager::new(dir.join("sst")).await?);
        let manifest_manager = Arc::new(ManifestManager::new(dir.join("sst")));
        LsmStorageEngine::new(wal, wal_path, vlog, vlog_path, file_manager, manifest_manager, options).await
    }

    /// A value the vLog takes.
    fn vlog_value(fill: u8) -> Vec<u8> {
        vec![fill; 4096]
    }

    /// Freezes and flushes the active MemTable; the new SSTable's file id.
    async fn flush_new_table(engine: &LsmStorageEngine) -> u64 {
        engine.freeze_active_memtable();
        engine.flush_memtable().await.unwrap().unwrap()
    }

    // Test 4: of 180 failures in a row, the first and every 60th get a log
    // line; a success starts a new row.
    #[test]
    fn test_failures_in_a_row_log_the_first_and_every_60th() {
        let log = FailureLog::default();
        let logged: Vec<u32> = (0..180).filter(|_| log.failed()).collect();
        assert_eq!(logged, [0, 60, 120]);
        log.succeeded();
        assert!(log.failed());
    }

    // Test 4: after a failed flush the flush loop waits a compaction
    // interval, otherwise a flush interval.
    #[test]
    fn test_a_failed_flush_retries_at_the_compaction_interval() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let engine = engine_split(dir.path()).await.unwrap();
            let flush = Duration::from_millis(engine.engine_config.flush_check_interval_ms);
            let compaction = Duration::from_millis(engine.engine_config.compaction_check_interval_ms);
            assert_ne!(flush, compaction);
            assert_eq!(engine.flush_turn().await, flush, "nothing to flush");

            engine.put(b"k", b"v").await.unwrap();
            engine.freeze_active_memtable();
            test_fault::fail_next_writes(&dir.path().join("sst"), libc::ENOSPC, 180);
            for _ in 0..180 {
                assert_eq!(engine.flush_turn().await, compaction);
            }
            assert_eq!(engine.flush_turn().await, flush);
            assert!(engine.version().immutables.is_empty());
        })
    }

    // Test 1: a value log append failing on a read-only file system stops
    // the server at once, naming the value log; another I/O error at the
    // third failure in a row, a success in between starts the row anew; a
    // full file system never.
    #[test]
    fn test_failed_value_log_appends_stop_on_a_read_only_file_system_or_the_third_in_a_row() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let vlog_path = dir.path().join("vlog").join("vlog.log");
            let engine = engine_split(dir.path()).await.unwrap();
            for (errno, failures) in [(libc::ENOSPC, 4), (libc::EIO, 2), (libc::EIO, 0), (libc::EIO, 2)] {
                if failures == 0 {
                    engine.put(b"k", &vlog_value(b'k')).await.unwrap();
                    continue;
                }
                test_fault::fail_next_writes(&vlog_path, errno, failures);
                for _ in 0..failures {
                    assert!(engine.put(b"k", &vlog_value(b'k')).await.is_err());
                }
            }
            assert!(test_fault::stops_under(dir.path()).is_empty(), "a success starts the row anew");

            test_fault::fail_next_writes(&vlog_path, libc::EIO, 1);
            let err = engine.put(b"k", &vlog_value(b'k')).await.unwrap_err();
            assert!(format!("{err:#}").contains("data write failed on"), "{err:#}");
            assert_eq!(test_fault::stops_under(dir.path()), std::slice::from_ref(&vlog_path));

            test_fault::fail_next_writes(&vlog_path, libc::EROFS, 1);
            assert!(engine.put(b"k", &vlog_value(b'k')).await.is_err());
            assert_eq!(test_fault::stops_under(dir.path()), [vlog_path.clone(), vlog_path]);
        })
    }

    // Test 1: a flush whose SSTable cannot be written on a read-only file
    // system stops the server at once, naming the file; another I/O error at
    // the third failed flush in a row; a full file system never.
    #[test]
    fn test_failed_flush_writes_stop_on_a_read_only_file_system_or_the_third_in_a_row() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let sst = dir.path().join("sst");
            let engine = engine_split(dir.path()).await.unwrap();
            engine.put(b"k", b"v").await.unwrap();
            engine.freeze_active_memtable();
            for errno in [libc::ENOSPC, libc::ENOSPC, libc::ENOSPC, libc::EIO, libc::EIO] {
                test_fault::fail_next_writes(&sst, errno, 1);
                assert!(engine.flush_memtable().await.is_err());
            }
            assert!(test_fault::stops_under(dir.path()).is_empty());

            test_fault::fail_next_writes(&sst, libc::EIO, 1);
            let err = engine.flush_memtable().await.unwrap_err();
            assert!(format!("{err:#}").contains("data write failed on"), "{err:#}");
            test_fault::fail_next_writes(&sst, libc::EROFS, 1);
            assert!(engine.flush_memtable().await.is_err());
            let stops = test_fault::stops_under(dir.path());
            assert_eq!(stops.len(), 2, "{stops:?}");
            assert!(stops.iter().all(|stop| stop.parent() == Some(sst.as_path())), "{stops:?}");

            assert!(engine.flush_memtable().await.unwrap().is_some(), "the flush goes on once it can write");
            assert_eq!(engine.get(b"k").await.unwrap().as_deref(), Some(&b"v"[..]));
        })
    }

    // persist_all saves the manifest a flush changed, then syncs every vLog
    // generation and the SSTable and vLog directories; a failed sync of a
    // generation or a directory stops the server, naming it.
    #[test]
    fn test_persist_all_saves_the_manifest_then_syncs_generations_and_directories() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let gen2 = generation_path(&dir.path().join("vlog").join("vlog.log"), 2);
            std::fs::create_dir_all(dir.path().join("vlog")).unwrap();
            std::fs::write(&gen2, b"").unwrap();
            let engine = engine_split(dir.path()).await.unwrap();
            assert_eq!(engine.version().vlog_ids(), vec![1, 2]);

            engine.put(b"a", &vlog_value(b'a')).await.unwrap();
            test_trace::watch(dir.path());
            engine.persist_all().await.unwrap();
            assert_eq!(
                test_trace::steps(dir.path()),
                [
                    "sync sst",
                    "sync vlog/vlog.log",
                    "sync vlog/vlog.log.2",
                    "save sst/MANIFEST",
                    "sync vlog/vlog.log",
                    "sync vlog/vlog.log.2",
                    "sync sst",
                    "sync vlog"
                ]
            );

            let unsyncables = [gen2, dir.path().join("vlog")];
            for unsyncable in &unsyncables {
                engine.put(b"b", &vlog_value(b'b')).await.unwrap();
                test_fault::fail_syncs_of(unsyncable);
                let persisted = engine.persist_all().await;
                test_fault::allow_syncs_of(unsyncable);
                assert!(persisted.is_err(), "a failed sync of {} fails it", unsyncable.display());
            }
            assert_eq!(test_fault::stops_under(dir.path()), unsyncables);
        })
    }

    // A stop truncates the WAL only after the syncs; with the SSTable
    // directory unsyncable it leaves the WAL byte for byte, and a start after
    // a crash finds every value.
    #[test]
    fn test_shutdown_truncates_the_wal_only_after_the_syncs() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let wal_path = dir.path().join("wal.log");
            let engine = engine_split(dir.path()).await.unwrap();
            engine.put(b"a", &vlog_value(b'a')).await.unwrap();
            test_trace::watch(dir.path());
            engine.shutdown().await;
            assert_eq!(
                test_trace::steps(dir.path()),
                [
                    "sync sst",
                    "sync vlog/vlog.log",
                    "save sst/MANIFEST",
                    "sync vlog/vlog.log",
                    "sync sst",
                    "sync vlog",
                    "truncate wal.log"
                ]
            );
            drop(engine);

            let engine = engine_split(dir.path()).await.unwrap();
            engine.put(b"b", &vlog_value(b'b')).await.unwrap();
            let wal = std::fs::read(&wal_path).unwrap();
            let sst = dir.path().join("sst");
            test_fault::fail_syncs_of(&sst);
            engine.shutdown().await;
            test_fault::allow_syncs_of(&sst);
            assert_eq!(test_fault::stops_under(dir.path()), [sst], "a failed sync stops the server");
            assert_eq!(std::fs::read(&wal_path).unwrap(), wal, "a failed sync leaves the WAL as it was");
            drop(engine); // crash

            let engine = engine_split(dir.path()).await.unwrap();
            assert_eq!(engine.get(b"a").await.unwrap(), Some(vlog_value(b'a')));
            assert_eq!(engine.get(b"b").await.unwrap(), Some(vlog_value(b'b')));
        })
    }

    // A start syncs what its recovery flush wrote, the values the replay
    // appended to the vLog included, before it truncates the WAL; a failed
    // sync stops the start with the WAL untouched, and the next start
    // recovers every value.
    #[test]
    fn test_start_truncates_the_wal_only_after_the_recovery_sync() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let wal_path = dir.path().join("wal.log");
            let vlog_path = dir.path().join("vlog").join("vlog.log");
            let engine = engine_split(dir.path()).await.unwrap();
            engine.put(b"a", &vlog_value(b'a')).await.unwrap();
            drop(engine); // crash: the value is only in the WAL
            let wal = std::fs::read(&wal_path).unwrap();

            test_trace::watch(dir.path());
            test_fault::fail_syncs_of(&vlog_path);
            let started = engine_split(dir.path()).await;
            test_fault::allow_syncs_of(&vlog_path);
            assert!(started.is_err(), "a failed sync stops the start");
            assert_eq!(test_fault::stops_under(dir.path()), std::slice::from_ref(&vlog_path));
            assert_eq!(std::fs::read(&wal_path).unwrap(), wal, "the WAL stays as it was");
            assert_eq!(test_trace::steps(dir.path()), ["sync sst"]);
            drop(started);

            test_trace::watch(dir.path());
            let engine = engine_split(dir.path()).await.unwrap();
            assert_eq!(
                test_trace::steps(dir.path()),
                [
                    "sync sst",
                    "sync vlog/vlog.log",
                    "save sst/MANIFEST",
                    "sync vlog/vlog.log",
                    "sync sst",
                    "sync vlog",
                    "truncate wal.log"
                ]
            );
            assert_eq!(engine.get(b"a").await.unwrap(), Some(vlog_value(b'a')));
        })
    }

    // A GC cycle syncs its new generation and the vLog and SSTable
    // directories before it changes the manifest in memory, so a flush that
    // saves the changed manifest before the cycle does comes after those
    // syncs; after the save it syncs the SSTable directory again, and only
    // then deletes the old table and generation.
    #[test]
    fn test_gc_syncs_before_a_flush_can_save_its_manifest_and_before_it_deletes() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let engine = Arc::new(engine_split(dir.path()).await.unwrap());
            engine.put(b"a", &vlog_value(b'a')).await.unwrap();
            let old_table = flush_new_table(&engine).await;

            let hook = Arc::new(TestHook::default());
            let mut janitor = engine.build_janitor(gc_always());
            janitor.set_before_manifest_save_hook(Arc::clone(&hook));
            let janitor = Arc::new(janitor);
            test_trace::watch(dir.path());
            let gc = {
                let janitor = Arc::clone(&janitor);
                compio::runtime::spawn(async move { janitor.run_gc().await })
            };
            hook.reached.notified().await;
            let at_hook = test_trace::steps(dir.path());
            assert_eq!(at_hook, ["sync vlog/vlog.log.2", "sync vlog", "sync sst"]);

            // Saves the manifest the GC changed in memory.
            engine.put(b"b", &vlog_value(b'b')).await.unwrap();
            flush_new_table(&engine).await;
            hook.release.notify_one();
            assert!(gc.await.unwrap().unwrap().ran);

            let steps = test_trace::steps(dir.path());
            assert_eq!(
                steps[at_hook.len()..],
                [
                    "sync sst".to_string(),
                    "sync vlog/vlog.log".to_string(),
                    "sync vlog/vlog.log.2".to_string(),
                    "save sst/MANIFEST".to_string(),
                    "sync sst".to_string(),
                    format!("delete sst/sstable_{old_table:06}.sst"),
                    "delete vlog/vlog.log".to_string(),
                ]
            );
            assert_eq!(engine.get(b"a").await.unwrap(), Some(vlog_value(b'a')));
            assert_eq!(engine.get(b"b").await.unwrap(), Some(vlog_value(b'b')));
        })
    }

    // A GC cycle whose new generation does not sync fails before the
    // manifest changes and deletes nothing; a start after a crash reads
    // every value.
    #[test]
    fn test_gc_with_an_unsyncable_new_generation_changes_nothing() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let manifest_path = dir.path().join("sst").join("MANIFEST");
            let vlog_path = dir.path().join("vlog").join("vlog.log");
            let engine = Arc::new(engine_split(dir.path()).await.unwrap());
            engine.put(b"a", &vlog_value(b'a')).await.unwrap();
            let old_table = flush_new_table(&engine).await;
            let manifest = std::fs::read(&manifest_path).unwrap();

            let gen2 = generation_path(&vlog_path, 2);
            test_fault::fail_syncs_of(&gen2);
            let collected = engine.build_janitor(gc_always()).run_gc().await;
            test_fault::allow_syncs_of(&gen2);
            assert!(collected.is_err());
            assert_eq!(std::fs::read(&manifest_path).unwrap(), manifest, "the manifest on disk is unchanged");
            let level0: Vec<u64> = engine.manifest.read().get_level(0).iter().map(|m| m.file_id).collect();
            assert_eq!(level0, vec![old_table], "the manifest in memory is unchanged");
            assert!(engine.file_manager.file_path(old_table).exists());
            assert!(vlog_path.exists());
            drop(engine); // crash

            let engine = engine_split(dir.path()).await.unwrap();
            assert_eq!(engine.get(b"a").await.unwrap(), Some(vlog_value(b'a')));
        })
    }

    // A GC cycle whose SSTable directory does not sync after its manifest
    // save fails and keeps the old table and generation; a start after a
    // crash reads every value.
    #[test]
    fn test_gc_with_a_failed_sync_after_its_save_deletes_nothing() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let sst = dir.path().join("sst");
            let engine = Arc::new(engine_split(dir.path()).await.unwrap());
            engine.put(b"a", &vlog_value(b'a')).await.unwrap();
            let old_table = flush_new_table(&engine).await;

            let hook = Arc::new(TestHook::default());
            let mut janitor = engine.build_janitor(gc_always());
            janitor.set_before_manifest_save_hook(Arc::clone(&hook));
            let janitor = Arc::new(janitor);
            test_trace::watch(dir.path());
            let gc = {
                let janitor = Arc::clone(&janitor);
                compio::runtime::spawn(async move { janitor.run_gc().await })
            };
            hook.reached.notified().await;
            test_fault::fail_syncs_of(&sst);
            hook.release.notify_one();
            let collected = gc.await.unwrap();
            test_fault::allow_syncs_of(&sst);

            assert!(collected.is_err());
            let steps = test_trace::steps(dir.path());
            assert!(steps.contains(&"save sst/MANIFEST".to_string()), "{steps:?}");
            assert!(!steps.iter().any(|step| step.starts_with("delete")), "{steps:?}");
            assert!(engine.file_manager.file_path(old_table).exists());
            assert!(dir.path().join("vlog").join("vlog.log").exists());
            drop((janitor, engine)); // crash

            let engine = engine_split(dir.path()).await.unwrap();
            assert_eq!(engine.get(b"a").await.unwrap(), Some(vlog_value(b'a')));
        })
    }

    // A compaction syncs the SSTable directory before it changes the
    // manifest in memory, so a flush that saves the changed manifest before
    // the compaction does comes after that sync; after the save it syncs
    // again, and only then deletes its inputs.
    #[test]
    fn test_compaction_syncs_before_a_flush_can_save_its_manifest_and_before_it_deletes() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let mut engine = engine_split(dir.path()).await.unwrap();
            engine.put(b"a", b"1").await.unwrap();
            let first = flush_new_table(&engine).await;
            engine.put(b"b", b"2").await.unwrap();
            let second = flush_new_table(&engine).await;

            let hook = Arc::new(TestHook::default());
            engine.hooks.before_compaction_save = Some(Arc::clone(&hook));
            let engine = Arc::new(engine);
            test_trace::watch(dir.path());
            let compactor = {
                let engine = Arc::clone(&engine);
                compio::runtime::spawn(async move { engine.compact_level(0).await })
            };
            hook.reached.notified().await;
            let at_hook = test_trace::steps(dir.path());
            assert_eq!(at_hook, ["sync sst"]);

            // Saves the manifest the compaction changed in memory.
            engine.put(b"c", b"3").await.unwrap();
            flush_new_table(&engine).await;
            hook.release.notify_one();
            compactor.await.unwrap().unwrap();

            let steps = test_trace::steps(dir.path());
            assert_eq!(
                steps[at_hook.len()..],
                [
                    "sync sst".to_string(),
                    "sync vlog/vlog.log".to_string(),
                    "save sst/MANIFEST".to_string(),
                    "sync sst".to_string(),
                    format!("delete sst/sstable_{first:06}.sst"),
                    format!("delete sst/sstable_{second:06}.sst"),
                ]
            );
            for (key, value) in [(b"a", b"1"), (b"b", b"2"), (b"c", b"3")] {
                assert_eq!(engine.get(key).await.unwrap(), Some(value.to_vec()));
            }
        })
    }

    // A compaction whose SSTable directory does not sync after its manifest
    // save fails and keeps its inputs; a start after a crash reads every
    // value.
    #[test]
    fn test_compaction_with_a_failed_sync_after_its_save_keeps_its_inputs() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let sst = dir.path().join("sst");
            let mut engine = engine_split(dir.path()).await.unwrap();
            engine.put(b"a", &vlog_value(b'a')).await.unwrap();
            let first = flush_new_table(&engine).await;
            engine.put(b"b", b"2").await.unwrap();
            let second = flush_new_table(&engine).await;

            let hook = Arc::new(TestHook::default());
            engine.hooks.before_compaction_save = Some(Arc::clone(&hook));
            let engine = Arc::new(engine);
            let compactor = {
                let engine = Arc::clone(&engine);
                compio::runtime::spawn(async move { engine.compact_level(0).await })
            };
            hook.reached.notified().await;
            test_fault::fail_syncs_of(&sst);
            hook.release.notify_one();
            let compacted = compactor.await.unwrap();
            test_fault::allow_syncs_of(&sst);

            assert!(compacted.is_err());
            assert!(engine.file_manager.file_path(first).exists());
            assert!(engine.file_manager.file_path(second).exists());
            drop(engine); // crash

            let engine = engine_split(dir.path()).await.unwrap();
            assert_eq!(engine.get(b"a").await.unwrap(), Some(vlog_value(b'a')));
            assert_eq!(engine.get(b"b").await.unwrap(), Some(b"2".to_vec()));
        })
    }

    /// File ids of the level-0 tables the manifest on disk below `dir` names.
    async fn saved_level0(dir: &Path) -> Vec<u64> {
        let saved = ManifestManager::new(dir.join("sst")).load().await.unwrap();
        saved.get_level(0).iter().map(|m| m.file_id).collect()
    }

    // A flush syncs the SSTable directory before it adds its table to the
    // shared manifest, so a compaction that saves that manifest before the
    // flush does comes after the sync.
    #[test]
    fn test_flush_syncs_its_directory_before_a_compaction_can_save_its_table() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let mut engine = engine_split(dir.path()).await.unwrap();
            engine.put(b"a", b"1").await.unwrap();
            let first = flush_new_table(&engine).await;
            engine.put(b"b", b"2").await.unwrap();
            let second = flush_new_table(&engine).await;

            let compaction_hook = Arc::new(TestHook::default());
            let flush_hook = Arc::new(TestHook::default());
            engine.hooks.before_compaction_save = Some(Arc::clone(&compaction_hook));
            engine.hooks.before_flush_save = Some(Arc::clone(&flush_hook));
            let engine = Arc::new(engine);
            let compactor = {
                let engine = Arc::clone(&engine);
                compio::runtime::spawn(async move { engine.compact_level(0).await })
            };
            compaction_hook.reached.notified().await;

            engine.put(b"c", b"3").await.unwrap();
            engine.freeze_active_memtable();
            test_trace::watch(dir.path());
            let flusher = {
                let engine = Arc::clone(&engine);
                compio::runtime::spawn(async move { engine.flush_memtable().await })
            };
            flush_hook.reached.notified().await;
            assert_eq!(test_trace::steps(dir.path()), ["sync sst", "sync vlog/vlog.log"]);

            // Saves the manifest that already names the flushed table.
            compaction_hook.release.notify_one();
            compactor.await.unwrap().unwrap();
            flush_hook.release.notify_one();
            let third = flusher.await.unwrap().unwrap().unwrap();

            assert_eq!(
                test_trace::steps(dir.path()),
                [
                    "sync sst".to_string(),
                    "sync vlog/vlog.log".to_string(),
                    "save sst/MANIFEST".to_string(),
                    "sync sst".to_string(),
                    format!("delete sst/sstable_{first:06}.sst"),
                    format!("delete sst/sstable_{second:06}.sst"),
                ]
            );
            assert_eq!(saved_level0(dir.path()).await, vec![third]);
            for (key, value) in [(b"a", b"1"), (b"b", b"2"), (b"c", b"3")] {
                assert_eq!(engine.get(key).await.unwrap(), Some(value.to_vec()));
            }
        })
    }

    // A flush syncs the SSTable directory before it adds its table to the
    // shared manifest, so a GC cycle that saves that manifest before the
    // flush does comes after the sync.
    #[test]
    fn test_flush_syncs_its_directory_before_a_gc_cycle_can_save_its_table() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let mut engine = engine_split(dir.path()).await.unwrap();
            engine.put(b"a", &vlog_value(b'a')).await.unwrap();
            let old_table = flush_new_table(&engine).await;

            let flush_hook = Arc::new(TestHook::default());
            engine.hooks.before_flush_save = Some(Arc::clone(&flush_hook));
            let engine = Arc::new(engine);
            let gc_hook = Arc::new(TestHook::default());
            let mut janitor = engine.build_janitor(gc_always());
            janitor.set_before_manifest_save_hook(Arc::clone(&gc_hook));
            let janitor = Arc::new(janitor);
            let gc = {
                let janitor = Arc::clone(&janitor);
                compio::runtime::spawn(async move { janitor.run_gc().await })
            };
            gc_hook.reached.notified().await;

            engine.put(b"b", &vlog_value(b'b')).await.unwrap();
            engine.freeze_active_memtable();
            test_trace::watch(dir.path());
            let flusher = {
                let engine = Arc::clone(&engine);
                compio::runtime::spawn(async move { engine.flush_memtable().await })
            };
            flush_hook.reached.notified().await;
            assert_eq!(test_trace::steps(dir.path()), ["sync sst", "sync vlog/vlog.log", "sync vlog/vlog.log.2"]);

            // Saves the manifest that already names the flushed table.
            gc_hook.release.notify_one();
            assert!(gc.await.unwrap().unwrap().ran);
            flush_hook.release.notify_one();
            let new_table = flusher.await.unwrap().unwrap().unwrap();

            assert_eq!(
                test_trace::steps(dir.path()),
                [
                    "sync sst".to_string(),
                    "sync vlog/vlog.log".to_string(),
                    "sync vlog/vlog.log.2".to_string(),
                    "save sst/MANIFEST".to_string(),
                    "sync sst".to_string(),
                    format!("delete sst/sstable_{old_table:06}.sst"),
                    "delete vlog/vlog.log".to_string(),
                ]
            );
            assert!(saved_level0(dir.path()).await.contains(&new_table));
            assert_eq!(engine.get(b"a").await.unwrap(), Some(vlog_value(b'a')));
            assert_eq!(engine.get(b"b").await.unwrap(), Some(vlog_value(b'b')));
        })
    }

    // A flush whose SSTable directory does not sync stops the server before
    // the manifest names its table, naming the directory; the start after
    // the stop reads every value back from the WAL.
    #[test]
    fn test_flush_with_an_unsyncable_directory_stops_the_server() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let sst = dir.path().join("sst");
            let manifest_path = sst.join("MANIFEST");
            let engine = engine_split(dir.path()).await.unwrap();
            engine.put(b"a", &vlog_value(b'a')).await.unwrap();
            let first = flush_new_table(&engine).await;
            let manifest = std::fs::read(&manifest_path).unwrap();

            engine.put(b"b", &vlog_value(b'b')).await.unwrap();
            engine.freeze_active_memtable();
            test_fault::fail_syncs_of(&sst);
            let flushed = engine.flush_memtable().await;
            test_fault::allow_syncs_of(&sst);

            assert!(flushed.unwrap_err().to_string().starts_with("data sync failed on"));
            assert_eq!(test_fault::stops_under(dir.path()), [sst]);
            let level0: Vec<u64> = engine.manifest.read().get_level(0).iter().map(|m| m.file_id).collect();
            assert_eq!(level0, vec![first], "the manifest in memory is unchanged");
            assert_eq!(std::fs::read(&manifest_path).unwrap(), manifest, "the manifest on disk is unchanged");
            drop(engine); // the stop

            let engine = engine_split(dir.path()).await.unwrap();
            assert_eq!(engine.get(b"a").await.unwrap(), Some(vlog_value(b'a')));
            assert_eq!(engine.get(b"b").await.unwrap(), Some(vlog_value(b'b')));
        })
    }

    /// The flushed LSN of the manifest on disk below `dir`.
    async fn saved_flushed_lsn(dir: &Path) -> u64 {
        ManifestManager::new(dir.join("sst")).load().await.unwrap().flushed_lsn
    }

    // Each rotation gives its MemTable the last applied LSN as watermark,
    // and its flush saves that as the flushed LSN: a rotation at the size
    // threshold, one by `flush_all_memtables` and one by a switch of the
    // value log generation.
    #[test]
    fn test_a_flush_saves_the_watermark_of_its_rotation_as_the_flushed_lsn() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            // Five entries of a 2-byte key, its 8-byte stamp and a 1-byte value.
            let options = LsmEngineOptions {
                engine: LsmEngineConfig { memtable_size_threshold: 5 * 11, ..Default::default() },
                ..Default::default()
            };
            let engine = Arc::new(engine_split_with(dir.path(), options).await.unwrap());
            for i in 1..=8 {
                engine.put(format!("k{i}").as_bytes(), b"v").await.unwrap();
            }
            assert_eq!(engine.version().immutables.len(), 1, "the sixth write rotated");
            engine.flush_memtable().await.unwrap().unwrap();
            assert_eq!(saved_flushed_lsn(dir.path()).await, 5);
            engine.flush_all_memtables().await.unwrap();
            assert_eq!(saved_flushed_lsn(dir.path()).await, 8);

            engine.put(b"k9", &vlog_value(b'9')).await.unwrap();
            assert!(engine.build_janitor(gc_always()).run_gc().await.unwrap().ran);
            assert_eq!(saved_flushed_lsn(dir.path()).await, 9);
            assert_eq!(engine.flushed_lsn(), 9);
        })
    }

    // An instance without unflushed writes raises its flushed LSN without a
    // table; one with writes rotates them out under that LSN and flushes them.
    #[test]
    fn test_raise_flushed_lsn_flushes_only_what_waits() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let engine = engine_split(dir.path()).await.unwrap();
            engine.raise_flushed_lsn(42).await.unwrap();
            assert_eq!(saved_flushed_lsn(dir.path()).await, 42);
            assert!(saved_level0(dir.path()).await.is_empty());

            engine.wal.set_lsn_start(42).await.unwrap();
            engine.put(b"k", b"v").await.unwrap();
            assert_eq!(engine.last_applied_lsn(), 43);
            engine.raise_flushed_lsn(43).await.unwrap();
            assert_eq!(saved_flushed_lsn(dir.path()).await, 43);
            assert_eq!(saved_level0(dir.path()).await.len(), 1);
            assert!(engine.version().memtable.is_empty());
        })
    }

    // A flush syncs every value log generation before it saves the manifest
    // that raises the flushed LSN: the one generation, and both while a
    // cleanup has a second one open.
    #[test]
    fn test_a_flush_syncs_every_generation_before_its_manifest_save() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let engine = engine_split(dir.path()).await.unwrap();
            engine.put(b"a", &vlog_value(b'a')).await.unwrap();
            test_trace::watch(dir.path());
            flush_new_table(&engine).await;
            assert_eq!(test_trace::steps(dir.path()), ["sync sst", "sync vlog/vlog.log", "save sst/MANIFEST"]);
            drop(engine);

            let gen2 = generation_path(&dir.path().join("vlog").join("vlog.log"), 2);
            std::fs::write(&gen2, b"").unwrap();
            let engine = engine_split(dir.path()).await.unwrap();
            engine.put(b"b", &vlog_value(b'b')).await.unwrap();
            test_trace::watch(dir.path());
            flush_new_table(&engine).await;
            assert_eq!(
                test_trace::steps(dir.path()),
                ["sync sst", "sync vlog/vlog.log", "sync vlog/vlog.log.2", "save sst/MANIFEST"]
            );
        })
    }

    // A generation that fails to sync fails the flush and leaves the
    // manifest unchanged, on disk and in memory; the next flush writes a
    // table of a new id.
    #[test]
    fn test_a_failed_generation_sync_fails_the_flush_and_leaves_the_manifest() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let vlog_path = dir.path().join("vlog").join("vlog.log");
            let gen2 = generation_path(&vlog_path, 2);
            std::fs::create_dir_all(dir.path().join("vlog")).unwrap();
            std::fs::write(&gen2, b"").unwrap();
            let engine = engine_split(dir.path()).await.unwrap();
            engine.put(b"a", &vlog_value(b'a')).await.unwrap();
            let first = flush_new_table(&engine).await;
            let manifest = std::fs::read(dir.path().join("sst").join("MANIFEST")).unwrap();
            let tables = || {
                let mut names: Vec<_> = std::fs::read_dir(dir.path().join("sst"))
                    .unwrap()
                    .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                    .filter(|name| name.ends_with(".sst"))
                    .collect();
                names.sort();
                names
            };

            engine.put(b"b", &vlog_value(b'b')).await.unwrap();
            engine.freeze_active_memtable();
            let before = tables();
            test_fault::fail_syncs_of(&gen2);
            let flushed = engine.flush_memtable().await;
            test_fault::allow_syncs_of(&gen2);
            assert!(flushed.is_err());
            assert_eq!(test_fault::stops_under(dir.path()), std::slice::from_ref(&gen2), "the failed sync stops the server");
            assert_eq!(std::fs::read(dir.path().join("sst").join("MANIFEST")).unwrap(), manifest);
            let level0: Vec<u64> = engine.manifest.read().get_level(0).iter().map(|m| m.file_id).collect();
            assert_eq!(level0, [first]);
            assert_eq!(engine.flushed_lsn(), 1);
            let orphan: Vec<_> = tables().into_iter().filter(|name| !before.contains(name)).collect();
            assert_eq!(orphan.len(), 1, "the failed flush wrote its table");

            let second = engine.flush_memtable().await.unwrap().unwrap();
            assert_ne!(format!("sstable_{second:06}.sst"), orphan[0]);
            assert_eq!(saved_level0(dir.path()).await, [first, second]);
            assert_eq!(saved_flushed_lsn(dir.path()).await, 2);
            assert_eq!(engine.get(b"b").await.unwrap(), Some(vlog_value(b'b')));
        })
    }

    // Test 5: while writes are refused, every client write of an instance
    // fails with the refusal before the WAL; an instance on its own state,
    // the system store's case, writes on; after the block, writes go in.
    #[test]
    fn test_client_writes_are_refused_while_resources_run_short() {
        use crate::control::resources::{Resources, WriteBlocked};
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let resources = Resources::default();
            let options = LsmEngineOptions { resources: resources.clone(), ..Default::default() };
            let engine = engine_split_with(dir.path(), options).await.unwrap();
            engine.put(b"kept", b"v").await.unwrap();
            let lsn = engine.last_applied_lsn();

            resources.block_for_test(false, false);
            assert!(engine.writes_refused());
            let refusals = [
                engine.put(b"k", b"v").await,
                engine.put_with_ttl(b"k", b"v", 60).await,
                engine.set_null(b"k").await,
                StorageEngine::set(&engine, b"k", b"v").await,
                StorageEngine::delete(&engine, b"kept").await,
                engine.write_batch(vec![BatchOp::Delete { key: b"kept".to_vec() }]).await,
            ];
            for refused in refusals {
                let err = refused.unwrap_err();
                assert!(WriteBlocked::in_chain(&err).is_some(), "{err}");
            }
            assert_eq!(engine.last_applied_lsn(), lsn, "nothing reached the WAL");
            assert_eq!(engine.get(b"kept").await.unwrap(), Some(b"v".to_vec()));

            let other = tempfile::TempDir::new().unwrap();
            engine_split(other.path()).await.unwrap().put(b"k", b"v").await.unwrap();

            resources.unblock_for_test();
            engine.put(b"k", b"v").await.unwrap();
        })
    }

    // Test 6: while writes are refused, a flush still writes the MemTable
    // filled before as an SSTable and raises the flushed LSN.
    #[test]
    fn test_a_flush_runs_while_writes_are_refused() {
        use crate::control::resources::Resources;
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let resources = Resources::default();
            let options = LsmEngineOptions { resources: resources.clone(), ..Default::default() };
            let engine = engine_split_with(dir.path(), options).await.unwrap();
            engine.put(b"a", b"1").await.unwrap();
            engine.put(b"b", &vlog_value(b'b')).await.unwrap();
            assert_eq!(engine.flushed_lsn(), 0);

            resources.block_for_test(false, false);
            let table = flush_new_table(&engine).await;
            assert_eq!(saved_level0(dir.path()).await, [table]);
            assert_eq!((engine.flushed_lsn(), saved_flushed_lsn(dir.path()).await), (2, 2));
            assert_eq!(engine.get(b"b").await.unwrap(), Some(vlog_value(b'b')));
        })
    }

    // Test 4: a write past the gate when the block begins goes through; the
    // next one is refused.
    #[test]
    fn test_a_write_past_the_gate_when_the_block_begins_goes_through() {
        use crate::control::resources::Resources;
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let resources = Resources::default();
            let options = LsmEngineOptions { resources: resources.clone(), ..Default::default() };
            let mut engine = engine_split_with(dir.path(), options).await.unwrap();
            let hook = Arc::new(TestHook::default());
            engine.hooks = TestHooks { before_kv_pair_apply: Some((b"held".to_vec(), Arc::clone(&hook))), ..Default::default() };
            let engine = Arc::new(engine);
            let writer = {
                let engine = Arc::clone(&engine);
                compio::runtime::spawn(async move { engine.put(b"held", b"v").await })
            };
            hook.reached.notified().await;
            resources.block_for_test(false, false);
            hook.release.notify_one();
            writer.await.unwrap().unwrap();
            assert!(engine.put(b"late", b"v").await.is_err());
            assert_eq!(engine.get(b"held").await.unwrap(), Some(b"v".to_vec()));
        })
    }

    // Test 6: a compaction waits while the SSTable volume has less free
    // space than its inputs take, and runs once it has.
    #[test]
    fn test_compaction_waits_for_room_for_its_inputs() {
        use crate::control::resources::tests::{FakeProbe, GB};
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let probe = FakeProbe::new();
            probe.mount(dir.path(), 100 * GB, 10);
            let resources = crate::control::resources::Resources::with_probe(probe.clone());
            let engine = engine_split_with(dir.path(), LsmEngineOptions { resources, ..Default::default() }).await.unwrap();
            engine.put(b"a", b"1").await.unwrap();
            flush_new_table(&engine).await;
            engine.put(b"b", b"2").await.unwrap();
            flush_new_table(&engine).await;

            assert!(engine.compact_level(0).await.unwrap().is_empty(), "waits for room");
            assert_eq!(engine.manifest.read().get_level(0).len(), 2);

            probe.set_free(dir.path(), 50 * GB);
            assert_eq!(engine.compact_level(0).await.unwrap().len(), 2);
            assert!(engine.manifest.read().get_level(0).is_empty());
            assert_eq!(engine.get(b"a").await.unwrap(), Some(b"1".to_vec()));
        })
    }

    /// Engine options whose compactions cut their files at `max_sstable_size`.
    fn compaction_file_size(max_sstable_size: usize) -> LsmEngineOptions {
        LsmEngineOptions {
            compaction: CompactionConfig { max_sstable_size, ..Default::default() },
            ..Default::default()
        }
    }

    /// Puts `key-00..key-39` with 100-byte values into two overlapping L0
    /// tables, the second one overwriting the first five keys; their file ids.
    async fn two_overlapping_tables(engine: &LsmStorageEngine) -> [u64; 2] {
        for i in (0..40).step_by(2) {
            engine.put(format!("key-{i:02}").as_bytes(), &[b'a'; 100]).await.unwrap();
        }
        let first = flush_new_table(engine).await;
        for i in (1..40).step_by(2).chain(0..5) {
            engine.put(format!("key-{i:02}").as_bytes(), &[b'b'; 100]).await.unwrap();
        }
        [first, flush_new_table(engine).await]
    }

    // Each output file holds what the in-memory compaction put there, and
    // its manifest entry the file's size, key range and newest stamp.
    #[test]
    fn test_compaction_writes_the_files_and_metadata_of_the_in_memory_compaction() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let engine = engine_split_with(dir.path(), compaction_file_size(2000)).await.unwrap();
            let inputs = two_overlapping_tables(&engine).await;
            let readers = inputs
                .iter()
                .map(|id| Arc::new(SSTableReader::open_mmap(&engine.file_manager.file_path(*id)).unwrap()))
                .collect();
            let job = CompactionJob::new(readers, vec![], engine.compaction_config.clone());
            let expected = crate::engines::lsm::compaction::tests::compact_in_memory(&job).unwrap();
            assert_eq!(expected.len(), 3, "inputs of about 2.5 file sizes");

            engine.compact_level(0).await.unwrap();

            let written = engine.manifest.read().get_level(1).to_vec();
            assert_eq!(written.len(), expected.len());
            for (meta, bytes) in written.iter().zip(&expected) {
                assert_eq!(&std::fs::read(engine.file_manager.file_path(meta.file_id)).unwrap(), bytes);
                let keys: Vec<Vec<u8>> = SSTableReader::open(bytes.clone())
                    .unwrap()
                    .iter()
                    .map(|entry| entry.unwrap().0.to_vec())
                    .collect();
                let newest = keys.iter().map(|key| InternalKey::extract_timestamp(key).unwrap().as_u64()).max();
                assert_eq!(meta.file_size, bytes.len() as u64);
                assert_eq!(meta.smallest_key, keys[0]);
                assert_eq!(&meta.largest_key, keys.last().unwrap());
                assert_eq!(Some(meta.max_timestamp), newest);
            }
            assert_eq!(engine.get(b"key-00").await.unwrap(), Some(vec![b'b'; 100]));
            assert_eq!(engine.get(b"key-38").await.unwrap(), Some(vec![b'a'; 100]));
        })
    }

    // A compaction whose second output file cannot be created deletes the
    // first one, keeps its inputs and leaves the manifest as it was.
    #[test]
    fn test_compaction_failing_on_its_second_file_deletes_the_first() {
        compaction_failing_on_its_second_file("sst.tmp", test_fault::fail_writes_of, test_fault::allow_writes_of);
    }

    // Likewise when the second file is written but cannot be synced, and
    // its temporary file goes too.
    #[test]
    fn test_compaction_failing_to_sync_its_second_file_deletes_both() {
        compaction_failing_on_its_second_file("sst.tmp", test_fault::fail_syncs_of, test_fault::allow_syncs_of);
    }

    // Likewise when the second file cannot be renamed into place.
    #[test]
    fn test_compaction_failing_to_rename_its_second_file_deletes_both() {
        compaction_failing_on_its_second_file("sst", test_fault::fail_writes_of, test_fault::allow_writes_of);
    }

    /// Compacts two tables into three files while `fail` holds for the
    /// second file's name with `extension`; the compaction fails without a
    /// file of its own left.
    fn compaction_failing_on_its_second_file(extension: &str, fail: fn(&Path), allow: fn(&Path)) {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let sst = dir.path().join("sst");
            let engine = engine_split_with(dir.path(), compaction_file_size(2000)).await.unwrap();
            let inputs = two_overlapping_tables(&engine).await;
            let first_output = inputs[1] + 1;
            let second_output = sst.join(format!("sstable_{:06}.{extension}", first_output + 1));

            test_trace::watch(dir.path());
            fail(&second_output);
            let compacted = engine.compact_level(0).await;
            allow(&second_output);

            assert!(compacted.is_err());
            assert_eq!(test_trace::steps(dir.path()), [format!("delete sst/sstable_{first_output:06}.sst")]);
            let mut tables: Vec<String> = std::fs::read_dir(&sst)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .filter(|name| name.starts_with("sstable_"))
                .collect();
            tables.sort();
            assert_eq!(tables, inputs.map(|id| format!("sstable_{id:06}.sst")));
            assert_eq!(saved_level0(dir.path()).await, inputs);
            {
                let manifest = engine.manifest.read();
                let level0: Vec<u64> = manifest.get_level(0).iter().map(|meta| meta.file_id).collect();
                assert_eq!(level0, inputs);
                assert!(manifest.get_level(1).is_empty());
            }
            assert_eq!(engine.get(b"key-00").await.unwrap(), Some(vec![b'b'; 100]));
            assert_eq!(engine.get(b"key-39").await.unwrap(), Some(vec![b'b'; 100]));
        })
    }

    // Test 6: a GC cycle waits while the value log's volume has less free
    // space than the live values take, and runs once it has.
    #[test]
    fn test_gc_waits_for_room_for_its_live_values() {
        use crate::control::resources::tests::{FakeProbe, GB};
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let probe = FakeProbe::new();
            probe.mount(dir.path(), 100 * GB, 4095);
            let resources = crate::control::resources::Resources::with_probe(probe.clone());
            let engine = Arc::new(engine_split_with(dir.path(), LsmEngineOptions { resources, ..Default::default() }).await.unwrap());
            engine.put(b"a", &vlog_value(b'a')).await.unwrap();
            flush_new_table(&engine).await;

            assert!(!engine.build_janitor(gc_always()).run_gc().await.unwrap().ran, "waits for room");
            probe.set_free(dir.path(), 4096);
            assert!(engine.build_janitor(gc_always()).run_gc().await.unwrap().ran);
            assert_eq!(engine.get(b"a").await.unwrap(), Some(vlog_value(b'a')));
        })
    }

    /// A SET record of `key` and `value` stamped `timestamp`, without expiry.
    fn set_record(timestamp: u64, key: &[u8], value: &[u8]) -> Vec<u8> {
        let mut record = vec![1u8];
        record.extend_from_slice(&timestamp.to_be_bytes());
        record.extend_from_slice(&(key.len() as u32).to_be_bytes());
        record.extend_from_slice(key);
        record.extend_from_slice(&(value.len() as u32).to_be_bytes());
        record.extend_from_slice(value);
        record.extend_from_slice(&0u64.to_be_bytes());
        record
    }

    // A log of the previous format, as an earlier version writes it after a
    // way back, numbers its records from 1 again, below the flushed LSN the
    // manifests kept: the start replays all of it and goes on above both.
    #[test]
    fn test_a_log_of_the_previous_format_is_replayed_whole_above_a_higher_flushed_lsn() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let wal_path = dir.path().join("wal.log");
            let engine = engine_split(dir.path()).await.unwrap();
            for i in 1..=50 {
                engine.put(format!("k{i}").as_bytes(), b"v").await.unwrap();
            }
            engine.shutdown().await;
            assert_eq!(engine.flushed_lsn(), 50);
            let stamp = engine.hlc().peek().as_u64();
            drop(engine);

            let mut log = b"LURAWAL\x02".to_vec();
            let records = [
                set_record(stamp + 1, b"after-the-way-back", &vlog_value(b'w')),
                LsmStorageEngine::encode_tombstone_wal_record(Timestamp::new(stamp + 2), b"k1"),
            ];
            for (lsn, record) in (1u64..).zip(&records) {
                log.extend_from_slice(&lsn.to_be_bytes());
                log.extend_from_slice(record);
            }
            std::fs::write(&wal_path, &log).unwrap();

            let engine = engine_split(dir.path()).await.unwrap();
            assert_eq!(engine.get(b"after-the-way-back").await.unwrap(), Some(vlog_value(b'w')));
            assert_eq!(engine.get(b"k1").await.unwrap(), None);
            assert_eq!(engine.get(b"k2").await.unwrap(), Some(b"v".to_vec()));
            assert_eq!(std::fs::read(&wal_path).unwrap(), crate::core::wal::wal_header(50));
            engine.put(b"next", b"v").await.unwrap();
            assert_eq!(engine.last_applied_lsn(), 51);
        })
    }

    /// The active vLog generation swapped for one on `/dev/full` while `write`
    /// runs: a large value's append fails after its record went into the log.
    async fn with_a_failing_vlog<F: std::future::Future>(engine: &LsmStorageEngine, write: F) -> F::Output {
        let active = Arc::clone(&engine.version().active_vlog);
        let full = Arc::new(VLog::new("/dev/full").await.unwrap());
        engine.install(|v| v.with_active_vlog(full, engine.last_applied_lsn()));
        let written = write.await;
        engine.install(|v| v.with_active_vlog(active, engine.last_applied_lsn()));
        written
    }

    // A write whose value failed to go into the vLog after its record went
    // into the log was never confirmed: below the flushed LSN of a flush
    // after it, a crash drops it; above the last flush, the replay applies
    // it. Either outcome is allowed.
    #[test]
    fn test_a_record_without_apply_is_dropped_below_the_flushed_lsn_and_replayed_above_it() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let engine = engine_split(dir.path()).await.unwrap();
            let failed = with_a_failing_vlog(&engine, engine.put(b"failed", &vlog_value(b'f'))).await;
            assert!(failed.is_err());
            engine.put(b"kept", &vlog_value(b'k')).await.unwrap();
            engine.flush_all_memtables().await.unwrap();
            assert_eq!(engine.flushed_lsn(), 2, "the flush covers the record without apply");
            drop(engine); // crash

            let engine = engine_split(dir.path()).await.unwrap();
            assert_eq!(engine.get(b"failed").await.unwrap(), None);
            assert_eq!(engine.get(b"kept").await.unwrap(), Some(vlog_value(b'k')));
            engine.shutdown().await;
            drop(engine);

            let engine = engine_split(dir.path()).await.unwrap();
            engine.put(b"flushed", b"v").await.unwrap();
            engine.flush_all_memtables().await.unwrap();
            let failed = with_a_failing_vlog(&engine, engine.put(b"late", &vlog_value(b'l'))).await;
            assert!(failed.is_err());
            assert!(engine.flushed_lsn() < engine.wal_head_lsn().await.unwrap());
            drop(engine); // crash

            let engine = engine_split(dir.path()).await.unwrap();
            assert_eq!(engine.get(b"late").await.unwrap(), Some(vlog_value(b'l')));
            assert_eq!(engine.get(b"flushed").await.unwrap(), Some(b"v".to_vec()));
        })
    }
}
