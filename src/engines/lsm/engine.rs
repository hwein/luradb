//! `engine` module
//!
//! The `LsmStorageEngine` orchestrates all LSM-Tree subsystems:
//! MemTable, WAL, VLog, SSTable levels, compaction, and the Janitor GC.

use crate::config::BlockCacheConfig;
use crate::engines::lsm::block_cache::BlockCache;
use crate::engines::lsm::memtable::{MemTable, Value};
use crate::engines::lsm::reader::{GetResult, LsmReader, RegistrySnapshot, Snapshot, SnapshotRegistry, ValueWithMetadata};
use crate::engines::lsm::key::{InternalKey, Timestamp};
use crate::engines::lsm::levels::LevelManager;
use crate::engines::lsm::compaction::{
    CompactionConfig, CompactionJob, select_sstables_for_level_compaction,
    select_level_to_compact, should_compact,
};
use crate::engines::lsm::janitor::{FlushBarrier, Janitor, JanitorConfig};
use crate::engines::lsm::hlc::HybridLogicalClock;
use crate::engines::lsm::watcher::{OpType, WalEvent};
use crate::engines::StorageEngine;
use crate::core::io_engine::IoEngine;
use crate::core::storage_thread::StorageHandle;
use crate::core::wal::WriteAheadLog;
use crate::storage::vlog::{discover_generations, generation_path, VLog, VLogError, VLogRegistry};
use crate::storage::sstable::{SSTableBuilder, SSTableReader};
use crate::storage::file_manager::FileManager;
use crate::storage::manifest::{Manifest, ManifestManager, SSTableMetadata};
use anyhow::Result;
use parking_lot::{Mutex, RwLock};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use tokio::sync::{broadcast, Notify};
use tokio::time::{sleep, Duration};

// Default limits — kept as constants so tests can reference them directly.
const MAX_KEY_LENGTH: usize = 256;
const MAX_VALUE_SIZE_LIMIT: usize = 512 * 1024;

// ── Engine configuration ─────────────────────────────────────────────────────

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
    /// Access SSTables via mmap instead of loading them fully (perf/003).
    pub use_mmap: bool,
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
/// Callers process sources newest-first, so the first version seen for a
/// user-key anywhere is its newest and decides for good (`decided`): live
/// versions land in `live`, tombstoned or TTL-expired ones suppress the key.
/// Stops early once `live` holds `limit` keys.
///
/// `snapshot` of `None` matches every version (today's `scan_keys`
/// behavior); `Some` skips versions newer than the snapshot instead of
/// deciding the key, so an older, visible version further along can still
/// decide it (spec general/006 backup export).
fn scan_memtable_for_prefix(
    mt: &MemTable,
    prefix: &[u8],
    now: u64,
    limit: usize,
    snapshot: Option<&Snapshot>,
    live: &mut BTreeSet<Vec<u8>>,
    decided: &mut BTreeSet<Vec<u8>>,
) {
    for (encoded_key, value) in mt.iter() {
        if live.len() >= limit {
            return;
        }
        if let Some(user_key) = InternalKey::extract_user_key(&encoded_key) {
            if !user_key.starts_with(prefix) || decided.contains(user_key) {
                continue;
            }
            if let Some(snap) = snapshot {
                let visible = InternalKey::extract_timestamp(&encoded_key)
                    .map(|ts| snap.is_visible(ts))
                    .unwrap_or(false);
                if !visible {
                    continue;
                }
            }
            decided.insert(user_key.to_vec());
            if is_live_version(&value, now) {
                live.insert(user_key.to_vec());
            }
        }
    }
}

/// Appends `value` to the active vLog generation, returning `(generation id,
/// offset)` read from the *same* reference so the pointer can never mix ids.
///
/// A `Sealed` error means the Janitor swapped the active generation between the
/// lookup and the append; it publishes the new generation before sealing the
/// old one, so a single retry converges (spec kv/017).
async fn append_to_active(vlog: &VLogRegistry, value: &[u8]) -> Result<(u32, u64)> {
    loop {
        let active = vlog.active();
        match active.append(value).await {
            Ok(offset) => return Ok((active.id(), offset)),
            Err(VLogError::Sealed { id }) => anyhow::ensure!(
                vlog.active().id() != id,
                "active value log generation {id} is sealed"
            ),
            Err(e) => return Err(e.into()),
        }
    }
}

/// True if `value` is neither TTL-expired at `now` nor a tombstone.
fn is_live_version(value: &Value, now: u64) -> bool {
    let expired = match value {
        Value::Inline(_, Some(exp)) => *exp <= now,
        Value::Pointer { expire_at: Some(exp), .. } => *exp <= now,
        _ => false,
    };
    !expired && !matches!(value, Value::Tombstone)
}

/// Sweeps one SSTable for keys with `prefix` (see [`scan_memtable_for_prefix`]
/// for the newest-first decision protocol and the `snapshot` contract).
/// Returns `true` once `live` holds `limit` keys so the caller can stop.
fn scan_sstable_for_prefix(
    sstable: &SSTableReader,
    prefix: &[u8],
    limit: usize,
    snapshot: Option<&Snapshot>,
    live: &mut BTreeSet<Vec<u8>>,
    decided: &mut BTreeSet<Vec<u8>>,
) -> Result<bool> {
    let entries: Box<dyn Iterator<Item = Result<(Vec<u8>, bool)>> + '_> = match snapshot {
        Some(snap) => Box::new(sstable.keys_with_prefix_at(prefix, snap.timestamp().inverted())),
        None => Box::new(sstable.keys_with_prefix(prefix)),
    };
    for entry in entries {
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
    }
    Ok(false)
}

/// LSM-Tree Storage Engine with MVCC and background maintenance.
///
/// All long-lived background tasks (flush, compaction, Janitor GC) are spawned
/// via [`start_background_tasks`] and stopped gracefully via [`shutdown`].
pub struct LsmStorageEngine {
    /// Active (writable) MemTable.
    memtable: Arc<RwLock<Arc<MemTable>>>,

    /// Frozen MemTables waiting to be flushed to L0.
    immutable_memtables: Arc<RwLock<Vec<Arc<MemTable>>>>,

    /// Hierarchical SSTable levels.
    level_manager: Arc<LevelManager>,

    wal: Arc<WriteAheadLog>,

    /// All live vLog generations; the active one takes new appends.
    vlog: Arc<VLogRegistry>,

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

    /// Signals background tasks to stop.
    shutdown: Arc<AtomicBool>,

    /// S3-FIFO block cache shared across all read operations.
    block_cache: Arc<Mutex<BlockCache>>,

    /// Storage thread handle (perf/005). When set, `flush_memtable` writes
    /// SSTables through it and the Janitor reopens the VLog through it after GC.
    storage_handle: Option<StorageHandle>,

    /// Notified after every MemTable flush — the SHM snapshot publisher
    /// (spec perf/009 §4) rebuilds on this event in addition to its interval.
    flush_notify: Arc<Notify>,

    /// In-flight guard for the vLog-pointer-creating write sequence (spec
    /// kv/020). Writers hold the `read()` side from the active-generation
    /// fetch through `memtable.set`; the Janitor's flush barrier drains by
    /// taking `write()` once and dropping it immediately. `tokio::sync::RwLock`
    /// is task-fair (write-preferring), so the drain waits only for guards
    /// already in flight, never for ones started after it — no starvation
    /// under sustained write load, and no deadlock: the drain holds no other
    /// lock a writer needs while it waits.
    in_flight_writes: tokio::sync::RwLock<()>,
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
        } = options;

        let vlog = Self::build_vlog_registry(vlog, &vlog_path).await?;

        // Recover the MemTable from the WAL first.
        let recovered = Self::recover_from_wal(&wal_path, &vlog, engine_config.vlog_inline_threshold).await?;

        let level_manager = Arc::new(LevelManager::new());
        let manifest = manifest_manager.load().await?;

        // Then, recover SSTable levels from the manifest.
        Self::recover_sstables(&manifest, &file_manager, &level_manager, engine_config.use_mmap)
            .await?;

        let (change_tx, _) = broadcast::channel(engine_config.wal_event_channel_capacity);

        let block_cache = Arc::new(Mutex::new(BlockCache::new(
            block_cache_config.capacity_bytes,
            block_cache_config.small_ratio,
            block_cache_config.ghost_capacity,
        )));

        let engine = Self {
            memtable: Arc::new(RwLock::new(Arc::new(MemTable::new()))),
            immutable_memtables: Arc::new(RwLock::new(Vec::new())),
            level_manager,
            wal,
            vlog,
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
            shutdown: Arc::new(AtomicBool::new(false)),
            block_cache,
            storage_handle: None,
            flush_notify: Arc::new(Notify::new()),
            in_flight_writes: tokio::sync::RwLock::new(()),
        };

        // Recovered WAL data is RAM-only: flush it to an SSTable BEFORE
        // truncating the WAL, so no later startup failure can lose it.
        if !recovered.is_empty() {
            engine.immutable_memtables.write().push(Arc::new(recovered));
            engine.flush_memtable().await?;
        }
        engine.wal.truncate().await?;

        Ok(engine)
    }

    /// Attaches the storage thread handle (perf/005). Call once at startup,
    /// before the engine is wrapped in an `Arc` and shared.
    pub fn set_storage_handle(&mut self, handle: StorageHandle) {
        self.storage_handle = Some(handle);
    }

    /// Points the storage thread at the vLog generation that startup
    /// discovered as active and swaps in a handle-backed `VLog` for it, so
    /// its I/O takes the io_uring path instead of bypassing it until the
    /// next GC cycle (spec perf/013). A no-op when the active generation is
    /// already 1 — the thread already owns that file, since it always spawns
    /// on the canonical path (see `main.rs`).
    ///
    /// Must run after `recover_from_wal` has completed; `LsmStorageEngine::new`
    /// already awaits that internally, so calling this once `new` has
    /// returned is always safe. Reopening earlier would race WAL recovery,
    /// which still appends locally while the handle-backed `VLog` seeds its
    /// cursor from the file length.
    ///
    /// The thread's single fd can back only one generation at a time, so
    /// generation 1 — no longer thread-owned once this swap runs — is
    /// reopened locally afterward; every other generation was already local
    /// (`build_vlog_registry` opens ids > 1 via `tokio::fs`).
    pub async fn route_active_vlog_to_thread(&self, handle: &StorageHandle) -> Result<()> {
        let active = self.vlog.active();
        let id = active.id();
        if id <= 1 {
            return Ok(());
        }
        let path = active.path().to_path_buf();
        handle.vlog_reopen(path.clone(), id).await?;
        self.vlog.set_active(Arc::new(VLog::with_storage_handle(path, handle.clone(), id)));

        let gen1 = VLog::open(&self.vlog_path, 1).await?;
        self.vlog.register(Arc::new(gen1));
        Ok(())
    }

    // ── Recovery ────────────────────────────────────────────────────────────

    /// Registers every vLog generation that exists next to `vlog_path`; the
    /// highest id becomes the active one (spec kv/017). `vlog` is the caller's
    /// handle on the canonical path, which is generation 1 — a store without
    /// further generations therefore starts exactly as before.
    async fn build_vlog_registry(vlog: Arc<VLog>, vlog_path: &Path) -> Result<Arc<VLogRegistry>> {
        let registry = VLogRegistry::new(vlog);
        for id in discover_generations(vlog_path).await? {
            if id > 1 {
                registry.set_active(Arc::new(VLog::open(generation_path(vlog_path, id), id).await?));
            }
        }
        Ok(Arc::new(registry))
    }

    /// Recovers the MemTable state from the WAL.
    ///
    /// Does NOT truncate the WAL — [`Self::new`] first flushes the recovered
    /// data to an SSTable, so an interrupted startup never loses it.
    async fn recover_from_wal(
        wal_path: &PathBuf,
        vlog: &VLogRegistry,
        vlog_inline_threshold: usize,
    ) -> Result<MemTable> {
        let memtable = MemTable::new();
        let entries = crate::core::wal::recover(wal_path).await?;
        let mut max_ts = 0;

        for entry in entries {
            match entry {
                crate::core::wal::WalEntry::Set { timestamp, key, value, expire_at } => {
                    max_ts = max_ts.max(timestamp);
                    let ts = Timestamp::new(timestamp);
                    let expire_at_opt = if expire_at == 0 { None } else { Some(expire_at) };
                    if value.len() >= vlog_inline_threshold {
                        let (file_id, offset) = append_to_active(vlog, &value).await?;
                        memtable.set(key, ts, Value::Pointer { file_id, offset, len: value.len(), expire_at: expire_at_opt });
                    } else {
                        memtable.set(key, ts, Value::Inline(value, expire_at_opt));
                    }
                }
                crate::core::wal::WalEntry::Delete { timestamp, key } => {
                    max_ts = max_ts.max(timestamp);
                    let ts = Timestamp::new(timestamp);
                    memtable.set(key, ts, Value::Tombstone);
                }
                crate::core::wal::WalEntry::SetNull { timestamp, key } => {
                    max_ts = max_ts.max(timestamp);
                    let ts = Timestamp::new(timestamp);
                    memtable.set(key, ts, Value::Null);
                }
            }
        }

        Ok(memtable)
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

    async fn recover_sstables(
        manifest: &Manifest,
        file_manager: &Arc<FileManager>,
        level_manager: &Arc<LevelManager>,
        use_mmap: bool,
    ) -> Result<()> {
        for (level_idx, level_metas) in manifest.levels.iter().enumerate() {
            let mut sstables = Vec::new();
            for meta in level_metas {
                match Self::open_sstable_reader(file_manager, meta.file_id, use_mmap).await {
                    Ok(reader) => sstables.push(Arc::new(reader)),
                    Err(e) => eprintln!(
                        "Warning: cannot open SSTable {} at L{level_idx}: {e}",
                        meta.file_id
                    ),
                }
            }
            if !sstables.is_empty() {
                level_manager.replace_level(level_idx, sstables);
            }
        }
        Ok(())
    }

    // ── Background tasks ────────────────────────────────────────────────────

    /// Starts the flush loop, compaction loop, and Janitor GC loop.
    pub fn start_background_tasks(self: &Arc<Self>) {
        // Flush loop
        let engine = Arc::clone(self);
        tokio::spawn(async move { engine.background_flush_loop().await });

        // Compaction loop
        let engine = Arc::clone(self);
        tokio::spawn(async move { engine.background_compaction_loop().await });

        // Janitor (vLog GC) loop
        let janitor = Arc::new(self.build_janitor(self.janitor_config.clone()));
        tokio::spawn(async move { janitor.run_background().await });
    }

    /// Builds a Janitor over this engine's state, wired with the flush barrier
    /// its GC needs before the SSTables are the complete live set (kv/017).
    pub(crate) fn build_janitor(self: &Arc<Self>, config: JanitorConfig) -> Janitor {
        let engine = Arc::clone(self);
        let flush_barrier: FlushBarrier = Arc::new(move || {
            let engine = Arc::clone(&engine);
            Box::pin(async move { engine.flush_all_memtables().await })
        });
        Janitor::new(
            Arc::clone(&self.vlog),
            self.vlog_path.clone(),
            Arc::clone(&self.level_manager),
            Arc::clone(&self.manifest),
            Arc::clone(&self.manifest_manager),
            Arc::clone(&self.file_manager),
            Arc::clone(&self.block_cache),
            Arc::clone(&self.snapshot_registry),
            config,
            self.engine_config.use_mmap,
            Arc::clone(&self.shutdown),
            self.storage_handle.clone(),
            Some(flush_barrier),
        )
    }

    async fn background_flush_loop(&self) {
        while !self.shutdown.load(Ordering::Relaxed) {
            let has_immutable = !self.immutable_memtables.read().is_empty();
            if has_immutable {
                if let Err(e) = self.flush_memtable().await {
                    eprintln!("[Engine] Flush error: {e}");
                }
            }
            sleep(Duration::from_millis(self.engine_config.flush_check_interval_ms)).await;
        }
    }

    async fn background_compaction_loop(&self) {
        while !self.shutdown.load(Ordering::Relaxed) {
            let needs = {
                let manifest = self.manifest.read();
                should_compact(&manifest, &self.compaction_config)
            };
            if needs {
                if let Err(e) = self.compact_next_level().await {
                    eprintln!("[Engine] Compaction error: {e}");
                }
            }
            sleep(Duration::from_millis(self.engine_config.compaction_check_interval_ms)).await;
        }
    }

    /// Freezes the active MemTable and flushes every immutable one, leaving no
    /// vLog pointer MemTable-resident. Used by the Janitor's flush barrier.
    pub async fn flush_all_memtables(&self) -> Result<()> {
        // Drain (spec kv/020). Order anchor: Seal (Janitor, before it calls this
        // barrier) -> Drain (here) -> Freeze/Flush (below). Taking and instantly
        // dropping the write side waits out every pointer-write that acquired
        // its read guard before this point -- each has, by the time it releases
        // the guard, already applied its `memtable.set`. Combined with the
        // preceding seal (no *new* pointer into the sealed generations can
        // appear), every live pointer into a sealed generation is now
        // MemTable-resident and gets picked up by the freeze/flush below.
        drop(self.in_flight_writes.write().await);

        let frozen = {
            let mut mt = self.memtable.write();
            std::mem::replace(&mut *mt, Arc::new(MemTable::new()))
        };
        if !frozen.is_empty() {
            self.immutable_memtables.write().push(frozen);
        }
        while !self.immutable_memtables.read().is_empty() {
            self.flush_memtable().await?;
        }
        Ok(())
    }

    /// Shuts down all background tasks and flushes remaining MemTables.
    pub async fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);

        if let Err(e) = self.flush_all_memtables().await {
            eprintln!("[Engine] Shutdown flush error: {e}");
        }

        // All data is now in SSTables — WAL entries are redundant.
        // Clear it so the next startup finds an empty WAL and skips
        // the unnecessary MemTable-to-SSTable flush cycle.
        if let Err(e) = self.wal.truncate().await {
            eprintln!("[Engine] Shutdown WAL truncate error: {e}");
        }
    }

    // ── MVCC helpers ────────────────────────────────────────────────────────

    fn next_timestamp(&self) -> Timestamp {
        Timestamp::new(self.hlc.now().as_u64())
    }

    /// Creates an MVCC snapshot and registers it with the [`SnapshotRegistry`].
    ///
    /// The returned guard deregisters itself when dropped, automatically
    /// advancing the low watermark used by the compaction filter.
    pub fn snapshot(&self) -> RegistrySnapshot {
        let ts = self.next_timestamp();
        self.snapshot_registry.acquire(ts)
    }

    /// Returns a plain (unregistered) snapshot for internal use.
    fn snapshot_unregistered(&self) -> Snapshot {
        Snapshot::new(self.next_timestamp())
    }

    pub fn hlc(&self) -> &Arc<HybridLogicalClock> {
        &self.hlc
    }

    /// Handle to the flush-notification (spec perf/009 §4). The SHM snapshot
    /// publisher awaits it to rebuild right after a MemTable flush.
    pub fn flush_notify(&self) -> Arc<Notify> {
        Arc::clone(&self.flush_notify)
    }

    // ── Read path ───────────────────────────────────────────────────────────

    /// Reader over the current MemTable, immutables and levels. Every guard is
    /// released before it returns, so no lock is held across an await.
    fn build_reader(&self) -> LsmReader {
        let memtable = { Arc::clone(&*self.memtable.read()) };

        let mut reader = LsmReader::new(memtable, Arc::clone(&self.vlog), Arc::clone(&self.block_cache));
        {
            let imm = self.immutable_memtables.read();
            reader.set_immutable_memtables(imm.clone());
        }
        reader.set_sstables(self.level_manager.get_all_levels());
        reader
    }

    /// MVCC-aware point read. Three-valued (spec kv/018): a live value, an
    /// explicit NULL (`set_null`), or absent.
    pub async fn get_with_snapshot(
        &self,
        key: &[u8],
        snapshot: &Snapshot,
    ) -> Result<GetResult> {
        self.build_reader().get(key, snapshot).await
    }

    /// MVCC-aware point read returning value + metadata without dereferencing
    /// the VLog (spec perf/009 §3). Additive to [`Self::get_with_snapshot`];
    /// used by the SHM snapshot builder.
    pub async fn get_with_metadata(
        &self,
        key: &[u8],
        snapshot: &Snapshot,
    ) -> Result<Option<ValueWithMetadata>> {
        self.build_reader().get_with_metadata(key, snapshot).await
    }

    /// Like [`Self::get_with_snapshot`], but also returns `expire_at`
    /// (absolute Unix seconds, 0 = no TTL) — spec general/006 backup export,
    /// which needs the remaining TTL alongside the value. Unlike
    /// [`Self::get_with_metadata`], VLog pointers are dereferenced.
    pub async fn get_with_expiry(
        &self,
        key: &[u8],
        snapshot: &Snapshot,
    ) -> Result<(GetResult, u64)> {
        self.build_reader().get_with_expiry(key, snapshot).await
    }

    /// Returns a handle to the block cache metrics for the `/metrics` endpoint.
    pub fn block_cache_metrics(&self) -> Arc<crate::engines::lsm::block_cache::BlockCacheMetrics> {
        self.block_cache.lock().metrics()
    }

    // ── Write path helpers ──────────────────────────────────────────────────

    fn maybe_freeze_memtable(&self) -> Result<()> {
        let threshold = self.engine_config.memtable_size_threshold;
        let size = { self.memtable.read().approximate_size() };
        if size >= threshold {
            let mut mt = self.memtable.write();
            let mut imm = self.immutable_memtables.write();
            if mt.approximate_size() >= threshold {
                imm.push(Arc::clone(&*mt));
                *mt = Arc::new(MemTable::new());
            }
        }
        Ok(())
    }

    // ── Core write helpers ───────────────────────────────────────────────────

    /// Appends a SET entry to the WAL and inserts the value into the MemTable.
    ///
    /// Large values (>= `MAX_VALUE_LENGTH`) are offloaded to the vLog; smaller
    /// ones are stored inline. `expire_at` is an absolute Unix timestamp (seconds)
    /// for TTL; `None` or `0` means no expiry.
    pub(super) async fn write_kv_pair(&self, key: &[u8], value: &[u8], expire_at: Option<u64>) -> Result<()> {
        let timestamp = self.next_timestamp();
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
        self.wal.append(&log_entry).await?;

        // Broadcast after WAL is durable (sync_all already called inside wal.append).
        let _ = self.change_tx.send(WalEvent { key: key.to_vec(), op: OpType::Set });

        self.maybe_freeze_memtable()?;

        // Resolve the value before touching the MemTable (like `write_batch`):
        // a MemTable captured *before* the vLog append could be frozen and
        // flushed meanwhile, which would drop the entry.
        //
        // In-flight guard (spec kv/020): held from the active-generation fetch
        // through `memtable.set` below, so the Janitor's flush-barrier drain
        // cannot complete while a pointer into a generation it just sealed is
        // still on its way into a MemTable. Inline values carry no generation,
        // so they need no guard.
        let (resolved, _guard) = if value.len() >= self.engine_config.vlog_inline_threshold {
            let guard = self.in_flight_writes.read().await;
            let (file_id, offset) = append_to_active(&self.vlog, value).await?;
            (Value::Pointer { file_id, offset, len: value.len(), expire_at }, Some(guard))
        } else {
            (Value::Inline(value.to_vec(), expire_at), None)
        };
        let memtable = Arc::clone(&*self.memtable.read());
        memtable.set(key.to_vec(), timestamp, resolved);
        Ok(())
    }

    /// Appends a DELETE entry to the WAL and inserts a tombstone into the MemTable.
    pub(super) async fn write_tombstone(&self, key: &[u8]) -> Result<()> {
        let timestamp = self.next_timestamp();

        let mut log_entry = Vec::new();
        log_entry.push(2u8);
        log_entry.extend_from_slice(&timestamp.as_u64().to_be_bytes());
        log_entry.extend_from_slice(&(key.len() as u32).to_be_bytes());
        log_entry.extend_from_slice(key);
        self.wal.append(&log_entry).await?;

        // Broadcast after WAL is durable.
        let _ = self.change_tx.send(WalEvent { key: key.to_vec(), op: OpType::Delete });

        self.maybe_freeze_memtable()?;

        let memtable = Arc::clone(&*self.memtable.read());
        memtable.set(key.to_vec(), timestamp, Value::Tombstone);
        Ok(())
    }

    /// Appends a SET_NULL entry to the WAL and inserts a NULL marker into the
    /// MemTable (spec kv/018): an update, not a delete — the key stays
    /// visible and overwrites older versions like a Put. Writes without
    /// expiry (`set_null` never carries a TTL).
    pub(super) async fn write_null(&self, key: &[u8]) -> Result<()> {
        let timestamp = self.next_timestamp();

        // WAL entry: [type=4][ts:u64][key_len:u32][key] — type 3 is already
        // the batch record (json/005), so SetNull uses 4.
        let mut log_entry = Vec::new();
        log_entry.push(4u8);
        log_entry.extend_from_slice(&timestamp.as_u64().to_be_bytes());
        log_entry.extend_from_slice(&(key.len() as u32).to_be_bytes());
        log_entry.extend_from_slice(key);
        self.wal.append(&log_entry).await?;

        // set_null is an Update (spec kv/018 §1/§2) — a Set-Event, not Delete.
        let _ = self.change_tx.send(WalEvent { key: key.to_vec(), op: OpType::Set });

        self.maybe_freeze_memtable()?;

        let memtable = Arc::clone(&*self.memtable.read());
        memtable.set(key.to_vec(), timestamp, Value::Null);
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

    fn broadcast_batch_events(&self, ops: &[BatchOp]) {
        for op in ops {
            let (key, op_type) = match op {
                BatchOp::Put { key, .. } => (key, OpType::Set),
                BatchOp::Delete { key } => (key, OpType::Delete),
            };
            let _ = self.change_tx.send(WalEvent { key: key.clone(), op: op_type });
        }
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
                        let (file_id, offset) = append_to_active(&self.vlog, &value).await?;
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
    /// record all-or-nothing, so the batch is atomic (spec json/005).
    pub async fn write_batch(&self, ops: Vec<BatchOp>) -> Result<()> {
        if ops.is_empty() {
            return Ok(());
        }
        self.validate_batch_ops(&ops)?;
        let timestamp = self.next_timestamp();

        let log_entry = Self::encode_batch_wal_record(timestamp, &ops);
        self.wal.append(&log_entry).await?;

        self.broadcast_batch_events(&ops);

        self.maybe_freeze_memtable()?;

        // In-flight guard (spec kv/020), held across the whole batch: batches
        // are bounded, so one guard per batch is simpler than tracking which
        // individual ops end up pointer-creating. Acquired before Phase 1's
        // first `vlog.active()` fetch and held through every `memtable.set`
        // in Phase 2 below.
        let _guard = self.in_flight_writes.read().await;

        // Phase 1 (fallible): offload large values to the vLog BEFORE any
        // MemTable mutation — a vLog error must not leave the batch
        // half-applied (the WAL replays it fully after restart).
        let resolved = self.resolve_batch_values(ops).await?;

        // Phase 2 (infallible): apply the whole batch to the MemTable.
        let memtable = Arc::clone(&*self.memtable.read());
        for (key, value) in resolved {
            memtable.set(key, timestamp, value);
        }
        Ok(())
    }

    // ── Public high-level API ────────────────────────────────────────────────

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
    /// The entry becomes invisible (treated as a tombstone) once
    /// `now() + ttl_secs` is reached.
    pub fn put_with_ttl<'a>(
        &'a self,
        key: &'a [u8],
        value: &'a [u8],
        ttl_secs: u64,
    ) -> impl std::future::Future<Output = Result<()>> + Send + 'a {
        async move {
            validate_key(key, self.engine_config.max_key_length)?;
            validate_value(value, self.engine_config.max_value_size)?;
            let expire_at = now_secs() + ttl_secs;
            self.write_kv_pair(key, value, Some(expire_at)).await
        }
    }

    /// Sets `key` to the technical NULL state (spec kv/018): an update, not a
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

    // ── Discovery ────────────────────────────────────────────────────────────

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
    /// `snapshot` instead of "now" (spec general/006 backup export): a write
    /// committed after the snapshot was acquired never appears, matching
    /// [`Self::get_with_snapshot`]'s consistency guarantee for point reads.
    pub async fn scan_keys_with_snapshot(&self, prefix: &[u8], snapshot: &Snapshot) -> Result<Vec<Vec<u8>>> {
        self.scan_keys_inner(prefix, usize::MAX, Some(snapshot)).await
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

        let memtable = { Arc::clone(&*self.memtable.read()) };
        scan_memtable_for_prefix(&memtable, prefix, now, limit, snapshot, &mut live, &mut decided);

        {
            let imm = self.immutable_memtables.read();
            // Frozen MemTables are pushed to the back — iterate newest-first.
            for mt in imm.iter().rev() {
                scan_memtable_for_prefix(mt, prefix, now, limit, snapshot, &mut live, &mut decided);
            }
        }

        let mut levels = self.level_manager.get_all_levels();
        if let Some(l0) = levels.first_mut() {
            // L0 tables are appended in flush order — newest last.
            l0.reverse();
        }
        for level_sstables in levels {
            for sstable in level_sstables {
                if scan_sstable_for_prefix(&sstable, prefix, limit, snapshot, &mut live, &mut decided)? {
                    return Ok(live.into_iter().collect());
                }
            }
        }

        Ok(live.into_iter().collect())
    }

    // ── Watch ────────────────────────────────────────────────────────────────

    /// Returns a receiver that is notified for every WAL-confirmed write.
    ///
    /// Each event carries the key and operation type (`Set` / `Delete`).
    /// The caller is responsible for filtering by prefix if needed.
    /// Events may be dropped if the receiver is too slow (lagged).
    pub fn watch_subscribe(&self) -> broadcast::Receiver<WalEvent> {
        self.change_tx.subscribe()
    }

    // ── Flush ───────────────────────────────────────────────────────────────

    /// Test-only: freezes the active MemTable so `flush_memtable` persists it.
    #[cfg(test)]
    pub fn freeze_active_memtable(&self) {
        let mut mt = self.memtable.write();
        let mut imm = self.immutable_memtables.write();
        let old = std::mem::replace(&mut *mt, Arc::new(MemTable::new()));
        imm.push(old);
    }

    /// Flushes the oldest immutable MemTable, returning the new SSTable's
    /// `file_id` (or `None` when there was nothing to flush).
    pub async fn flush_memtable(&self) -> Result<Option<u64>> {
        let memtable_to_flush = {
            let mut imm = self.immutable_memtables.write();
            if imm.is_empty() { return Ok(None); }
            imm.remove(0)
        };

        let mut builder = SSTableBuilder::new();
        let mut smallest_key: Option<Vec<u8>> = None;
        let mut largest_key: Option<Vec<u8>> = None;

        for (encoded_key, value) in memtable_to_flush.iter() {
            if smallest_key.is_none() || encoded_key < *smallest_key.as_ref().unwrap() {
                smallest_key = Some(encoded_key.clone());
            }
            if largest_key.is_none() || encoded_key > *largest_key.as_ref().unwrap() {
                largest_key = Some(encoded_key.clone());
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

        // With the storage thread active, route the SSTable write through it
        // (crash-safe temp + fsync + rename); it hands the bytes back so the
        // non-mmap reader below needs no extra copy.
        let sstable_data = match &self.storage_handle {
            Some(handle) => {
                handle.sstable_write(self.file_manager.file_path(file_id), sstable_data).await?
            }
            None => {
                self.file_manager.write_sstable(file_id, &sstable_data).await?;
                sstable_data
            }
        };

        let mut sstable = if self.engine_config.use_mmap {
            SSTableReader::open_mmap(&self.file_manager.file_path(file_id))?
        } else {
            SSTableReader::open(sstable_data)?
        };
        sstable.set_file_id(file_id);
        let sstable = Arc::new(sstable);
        self.level_manager.add_sstable(0, Arc::clone(&sstable));

        {
            let mut manifest = self.manifest.write();
            manifest.add_sstable(SSTableMetadata {
                file_id,
                level: 0,
                smallest_key: smallest_key.unwrap_or_default(),
                largest_key: largest_key.unwrap_or_default(),
                file_size,
            });
        }

        let snap = self.manifest.read().clone();
        self.manifest_manager.save(&snap).await?;

        // Event trigger for the SHM snapshot publisher (spec perf/009 §4): a
        // stored permit means a flush that races the publisher is not missed.
        self.flush_notify.notify_one();
        Ok(Some(file_id))
    }

    // ── IoEngine registration (spec perf/004 scaffolding) ────────────────────
    //
    // `IoEngine` is not on the hot path yet (see spec perf/004) and cannot be
    // stored as a field here: `FixedBufPool` is `!Send`/`!Sync` (tokio-uring
    // resources are confined to their driver thread), while `LsmStorageEngine`
    // is shared via `Arc` across `tokio::spawn`ed background tasks. These
    // methods are additive and only run where a caller has direct, unspawned
    // access to both -- startup recovery here, and explicit calls from tests
    // or (in spec 005) the dedicated Storage Thread.

    /// Registers every currently loaded SSTable with `io_engine` -- called
    /// once at startup, after recovery.
    pub async fn register_sstables_with_io_engine(&self, io_engine: &mut IoEngine) -> Result<()> {
        for readers in self.level_manager.get_all_levels() {
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

    // ── Compaction ──────────────────────────────────────────────────────────

    /// Compacts the level that most urgently needs it.
    pub async fn compact_next_level(&self) -> Result<()> {
        let source_level = {
            let manifest = self.manifest.read();
            match select_level_to_compact(&manifest, &self.compaction_config) {
                Some(l) => l,
                None => return Ok(()),
            }
        };

        self.compact_level(source_level).await?;
        Ok(())
    }

    /// Compacts `source_level` into `source_level + 1`, returning the file ids
    /// removed from the working set (the merged source + target inputs) so the
    /// caller can deregister exactly those from the `IoEngine` (perf/004).
    pub async fn compact_level(&self, source_level: usize) -> Result<Vec<u64>> {
        // Inject the current low watermark so tombstones below it can be GC'd.
        let mut config = self.compaction_config.clone();
        config.low_watermark = self.snapshot_registry.low_watermark();

        let (src_metas, tgt_metas) = {
            let manifest = self.manifest.read();
            select_sstables_for_level_compaction(source_level, &manifest)
        };

        if src_metas.is_empty() {
            return Ok(Vec::new());
        }

        let target_level = source_level + 1;

        // Load SSTables from disk.
        let use_mmap = self.engine_config.use_mmap;
        let src_sstables = self.open_sstable_readers(&src_metas, use_mmap).await?;
        let tgt_sstables = self.open_sstable_readers(&tgt_metas, use_mmap).await?;

        let job = CompactionJob::new(src_sstables, tgt_sstables, config);
        let compacted = job.compact()?;

        let new_metas = self.write_compacted_sstables(compacted, target_level, use_mmap).await?;

        // Atomically update manifest.
        {
            let mut manifest = self.manifest.write();
            for meta in &src_metas { manifest.remove_sstable(source_level, meta.file_id); }
            for meta in &tgt_metas { manifest.remove_sstable(target_level, meta.file_id); }
            for meta in &new_metas  { manifest.add_sstable(meta.clone()); }
        }

        self.rebuild_levels_from_manifest([source_level, target_level], use_mmap).await?;

        // Persist manifest.
        let snap = self.manifest.read().clone();
        self.manifest_manager.save(&snap).await?;

        self.retire_compacted_sstables(&src_metas, &tgt_metas).await;

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

    /// Persists each compacted SSTable and returns its target-level metadata.
    async fn write_compacted_sstables(
        &self,
        compacted: Vec<Vec<u8>>,
        target_level: usize,
        use_mmap: bool,
    ) -> Result<Vec<SSTableMetadata>> {
        let mut new_metas = Vec::new();
        for sstable_data in compacted {
            let file_id = self.file_manager.allocate_file_id();
            let file_size = sstable_data.len() as u64;
            self.file_manager.write_sstable(file_id, &sstable_data).await?;

            // Transient reader for the key range only; serving readers are
            // opened in the rebuild below.
            let sstable = if use_mmap {
                SSTableReader::open_mmap(&self.file_manager.file_path(file_id))?
            } else {
                SSTableReader::open(sstable_data)?
            };
            let (smallest_key, largest_key) = Self::sstable_key_range(&sstable)?;

            new_metas.push(SSTableMetadata {
                file_id,
                level: target_level,
                smallest_key,
                largest_key,
                file_size,
            });
        }
        Ok(new_metas)
    }

    /// Smallest/largest encoded key in `sstable` (empty vecs when it has none).
    fn sstable_key_range(sstable: &SSTableReader) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut smallest_key: Option<Vec<u8>> = None;
        let mut largest_key: Option<Vec<u8>> = None;
        for entry in sstable.iter() {
            let (key, _) = entry?;
            if smallest_key.is_none() || key < smallest_key.as_ref().unwrap().as_slice() {
                smallest_key = Some(key.to_vec());
            }
            if largest_key.is_none() || key > largest_key.as_ref().unwrap().as_slice() {
                largest_key = Some(key.to_vec());
            }
        }
        Ok((smallest_key.unwrap_or_default(), largest_key.unwrap_or_default()))
    }

    /// Rebuilds `levels`' readers from the manifest (post manifest-swap).
    async fn rebuild_levels_from_manifest(&self, levels: [usize; 2], use_mmap: bool) -> Result<()> {
        for lvl in levels {
            let metas = self.manifest.read().get_level(lvl).to_vec();
            let sstables = self.open_sstable_readers(&metas, use_mmap).await?;
            self.level_manager.replace_level(lvl, sstables);
        }
        Ok(())
    }

    /// Invalidates cached blocks of the retired inputs, then deletes their files.
    async fn retire_compacted_sstables(&self, src: &[SSTableMetadata], tgt: &[SSTableMetadata]) {
        {
            let mut cache = self.block_cache.lock();
            for meta in src.iter().chain(tgt.iter()) {
                cache.invalidate_file(meta.file_id);
            }
        }

        for meta in src.iter().chain(tgt.iter()) {
            if let Err(e) = self.file_manager.delete_sstable(meta.file_id).await {
                eprintln!("[Engine] Warning: cannot delete SSTable {}: {e}", meta.file_id);
            }
        }
    }

    /// Compacts `source_level` (see [`Self::compact_level`]) and deregisters
    /// the deleted source/target SSTables from `io_engine` (spec perf/004
    /// scaffolding -- see the note above [`Self::register_sstables_with_io_engine`]).
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

    // ── Heartbeat data ───────────────────────────────────────────────────────

    /// Returns the data needed for the `/health` heartbeat response.
    pub fn heartbeat_data(&self) -> EngineHeartbeatData {
        let mt_len = self.memtable.read().len() as u64;
        let imm_len: u64 = self.immutable_memtables.read().iter().map(|m| m.len() as u64).sum();
        let vlog_bytes = self.vlog.total_size();
        let l0_count = self.level_manager.get_level(0).len();
        EngineHeartbeatData {
            estimated_memtable_keys: mt_len + imm_len,
            vlog_size_bytes: vlog_bytes,
            l0_sstable_count: l0_count,
        }
    }

    // ── Stats ────────────────────────────────────────────────────────────────

    #[allow(dead_code)]
    pub fn stats(&self) -> EngineStats {
        let memtable = self.memtable.read();
        let imm = self.immutable_memtables.read();
        EngineStats {
            memtable_size: memtable.approximate_size(),
            num_immutable_memtables: imm.len(),
            num_levels: self.level_manager.num_levels(),
            total_sstables: self.level_manager.total_sstables(),
        }
    }
}

pub struct EngineHeartbeatData {
    pub estimated_memtable_keys: u64,
    pub vlog_size_bytes: u64,
    pub l0_sstable_count: usize,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct EngineStats {
    pub memtable_size: usize,
    pub num_immutable_memtables: usize,
    pub num_levels: usize,
    pub total_sstables: usize,
}

// ── Batch operations (spec json/005) ─────────────────────────────────────────

/// A single operation inside an atomic [`LsmStorageEngine::write_batch`].
#[derive(Debug, Clone)]
pub enum BatchOp {
    Put { key: Vec<u8>, value: Vec<u8> },
    Delete { key: Vec<u8> },
}

// ── StorageEngine trait ──────────────────────────────────────────────────────

impl StorageEngine for LsmStorageEngine {
    // Generic two-valued contract (shared with the unrelated `KvStore` engine):
    // collapses `Null` into `None`, like every caller outside the KV engine
    // (spec kv/018). Callers that must distinguish Null use `get_with_snapshot`.
    fn get(&self, key: &[u8]) -> impl std::future::Future<Output = Result<Option<Vec<u8>>>> + Send {
        async move {
            let snapshot = self.snapshot_unregistered();
            Ok(self.get_with_snapshot(key, &snapshot).await?.into_option())
        }
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

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::wal::WriteAheadLog;
    use crate::core::storage_thread::{StorageThread, StorageThreadConfig};
    use crate::storage::vlog::VLog;
    use crate::storage::file_manager::FileManager;
    use crate::storage::manifest::ManifestManager;
    use crate::engines::StorageEngine;
    use crate::engines::lsm::block_cache::BlockCacheKey;
    use crate::engines::lsm::watcher::OpType;

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

    // Batch: all ops visible after write, and WAL replay (record type 3)
    // restores them all-or-nothing after a restart without flush.
    #[tokio::test]
    async fn test_write_batch_atomic_and_recovered() {
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
    }

    // A vLog failure mid-batch must not leave the batch half-applied to the
    // MemTable; the WAL still holds it, so replay applies it fully on restart.
    #[tokio::test]
    async fn test_write_batch_vlog_error_is_atomic() {
        let dir = tempfile::TempDir::new().unwrap();
        let engine = engine_on(&dir).await;
        engine.put(b"idx", b"old").await.unwrap();

        // Writes to /dev/full fail with ENOSPC. tokio buffers file writes,
        // so the error surfaces on the NEXT vLog op — hence two large Puts.
        engine.vlog.set_active(Arc::new(VLog::new("/dev/full").await.unwrap()));
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
    }

    // Recovery must persist WAL data before truncating the WAL: even if the
    // recovering engine never reaches shutdown (startup failure), a later
    // engine on the same paths must still see the data.
    #[tokio::test]
    async fn test_recovered_data_survives_without_shutdown() {
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
    }

    // ── Lifecycle tests ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_put_get_basic() {
        let (engine, _dir) = make_engine().await;
        engine.put(b"key1", b"value1").await.unwrap();
        let result = engine.get(b"key1").await.unwrap();
        assert_eq!(result, Some(b"value1".to_vec()));
    }

    #[tokio::test]
    async fn test_put_upsert() {
        let (engine, _dir) = make_engine().await;
        engine.put(b"key1", b"value1").await.unwrap();
        engine.put(b"key1", b"value2").await.unwrap();
        let result = engine.get(b"key1").await.unwrap();
        assert_eq!(result, Some(b"value2".to_vec()));
    }

    #[tokio::test]
    async fn test_delete_returns_none() {
        let (engine, _dir) = make_engine().await;
        engine.put(b"key1", b"value1").await.unwrap();
        engine.delete(b"key1").await.unwrap();
        let result = engine.get(b"key1").await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_resurrection() {
        let (engine, _dir) = make_engine().await;
        engine.put(b"key1", b"value1").await.unwrap();
        engine.delete(b"key1").await.unwrap();
        engine.put(b"key1", b"value3").await.unwrap();
        let result = engine.get(b"key1").await.unwrap();
        assert_eq!(result, Some(b"value3".to_vec()));
    }

    // ── set_null semantics (spec kv/018 §1): an Update, never a delete ───────

    #[tokio::test]
    async fn test_set_null_is_update_not_delete() {
        let (engine, _dir) = make_engine().await;
        engine.put(b"key1", b"value1").await.unwrap();
        engine.set_null(b"key1").await.unwrap();
        let snap = engine.snapshot();
        assert_eq!(engine.get_with_snapshot(b"key1", snap.snapshot()).await.unwrap(), GetResult::Null);
    }

    #[tokio::test]
    async fn test_put_after_set_null_overwrites() {
        let (engine, _dir) = make_engine().await;
        engine.set_null(b"key1").await.unwrap();
        engine.put(b"key1", b"value1").await.unwrap();
        assert_eq!(engine.get(b"key1").await.unwrap(), Some(b"value1".to_vec()));
    }

    #[tokio::test]
    async fn test_delete_after_set_null_is_absent() {
        let (engine, _dir) = make_engine().await;
        engine.set_null(b"key1").await.unwrap();
        engine.delete(b"key1").await.unwrap();
        let snap = engine.snapshot();
        assert_eq!(engine.get_with_snapshot(b"key1", snap.snapshot()).await.unwrap(), GetResult::Absent);
    }

    #[tokio::test]
    async fn test_set_null_on_nonexistent_key_creates_it() {
        let (engine, _dir) = make_engine().await;
        let snap = engine.snapshot();
        assert_eq!(engine.get_with_snapshot(b"ghost", snap.snapshot()).await.unwrap(), GetResult::Absent);

        engine.set_null(b"ghost").await.unwrap();
        let snap = engine.snapshot();
        assert_eq!(engine.get_with_snapshot(b"ghost", snap.snapshot()).await.unwrap(), GetResult::Null);
    }

    // empty (0-byte Put) and NULL are distinct value states.
    #[tokio::test]
    async fn test_empty_value_distinct_from_null() {
        let (engine, _dir) = make_engine().await;
        engine.put(b"empty", b"").await.unwrap();
        engine.set_null(b"null_key").await.unwrap();

        let snap = engine.snapshot();
        assert_eq!(
            engine.get_with_snapshot(b"empty", snap.snapshot()).await.unwrap(),
            GetResult::Present(Vec::new())
        );
        assert_eq!(engine.get_with_snapshot(b"null_key", snap.snapshot()).await.unwrap(), GetResult::Null);
    }

    #[tokio::test]
    async fn test_scan_keys_includes_null() {
        let (engine, _dir) = make_engine().await;
        engine.set_null(b"user:1").await.unwrap();
        let keys = engine.scan_keys(b"user:").await.unwrap();
        assert!(keys.contains(&b"user:1".to_vec()), "NULL keys must appear in scans");
    }

    // NULL must survive a MemTable flush to SSTable and a subsequent
    // compaction — never garbage-collected like a tombstone.
    #[tokio::test]
    async fn test_set_null_survives_flush_and_compaction() {
        let (engine, _dir) = make_engine().await;
        engine.set_null(b"n").await.unwrap();
        freeze_and_flush(&engine).await;
        let snap = engine.snapshot();
        assert_eq!(engine.get_with_snapshot(b"n", snap.snapshot()).await.unwrap(), GetResult::Null);

        // A second L0 table forces an L0 -> L1 compaction that must preserve it.
        engine.put(b"other", b"v").await.unwrap();
        freeze_and_flush(&engine).await;
        engine.compact_level(0).await.unwrap();

        let snap = engine.snapshot();
        assert_eq!(engine.get_with_snapshot(b"n", snap.snapshot()).await.unwrap(), GetResult::Null);
        assert!(engine.scan_keys(b"n").await.unwrap().contains(&b"n".to_vec()));
    }

    // NULL written but never flushed must survive a WAL replay after restart.
    #[tokio::test]
    async fn test_set_null_survives_wal_recovery() {
        let dir = tempfile::TempDir::new().unwrap();
        let engine = engine_on(&dir).await;
        engine.set_null(b"n").await.unwrap();
        drop(engine); // crash: data only in the WAL

        let engine2 = engine_on(&dir).await;
        let snap = engine2.snapshot();
        assert_eq!(engine2.get_with_snapshot(b"n", snap.snapshot()).await.unwrap(), GetResult::Null);
    }

    // ── Validation tests ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_empty_key_rejected() {
        let (engine, _dir) = make_engine().await;
        let err = engine.set(b"", b"value").await;
        assert!(err.is_err(), "empty key must be rejected");
    }

    #[tokio::test]
    async fn test_key_too_long_rejected() {
        let (engine, _dir) = make_engine().await;
        let long_key = vec![b'x'; MAX_KEY_LENGTH + 1];
        let err = engine.set(&long_key, b"value").await;
        assert!(err.is_err(), "key exceeding MAX_KEY_LENGTH must be rejected");
    }

    #[tokio::test]
    async fn test_value_too_large_rejected() {
        let (engine, _dir) = make_engine().await;
        let large_value = vec![0u8; MAX_VALUE_SIZE_LIMIT + 1];
        let err = engine.set(b"key", &large_value).await;
        assert!(err.is_err(), "value exceeding MAX_VALUE_SIZE_LIMIT must be rejected");
    }

    // ── TTL tests ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_ttl_key_readable_before_expiry() {
        let (engine, _dir) = make_engine().await;
        // Large TTL (1h): this test only checks immediate readability, not
        // expiry, so the window must stay open regardless of suite load.
        engine.put_with_ttl(b"ttl_key", b"value", 3600).await.unwrap();
        let result = engine.get(b"ttl_key").await.unwrap();
        assert_eq!(result, Some(b"value".to_vec()));
    }

    #[tokio::test]
    async fn test_ttl_key_expires() {
        let (engine, _dir) = make_engine().await;
        // Immediate readability is covered by test_ttl_key_readable_before_expiry.
        engine.put_with_ttl(b"ttl_key", b"value", 1).await.unwrap();
        // Wait 1.1 seconds for the 1s TTL to expire.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        // Must be None after expiry
        assert!(engine.get(b"ttl_key").await.unwrap().is_none());
    }

    // ── scan_keys tests ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_scan_keys_prefix() {
        let (engine, _dir) = make_engine().await;
        engine.put(b"user:1", b"alice").await.unwrap();
        engine.put(b"user:2", b"bob").await.unwrap();
        engine.put(b"item:1", b"thing").await.unwrap();
        let keys = engine.scan_keys(b"user:").await.unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&b"user:1".to_vec()));
        assert!(keys.contains(&b"user:2".to_vec()));
    }

    #[tokio::test]
    async fn test_scan_keys_excludes_tombstoned() {
        let (engine, _dir) = make_engine().await;
        engine.put(b"user:1", b"alice").await.unwrap();
        engine.put(b"user:2", b"bob").await.unwrap();
        engine.delete(b"user:1").await.unwrap();
        let keys = engine.scan_keys(b"user:").await.unwrap();
        assert!(!keys.contains(&b"user:1".to_vec()));
        assert!(keys.contains(&b"user:2".to_vec()));
    }

    // Regression: a delete must stay effective once the live version — and
    // later the tombstone itself — reside in SSTables.
    #[tokio::test]
    async fn test_scan_keys_excludes_tombstoned_after_flush() {
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
    }

    // Regression: an older tombstone in a frozen MemTable must not hide a
    // newer re-creation of the same key in the active MemTable.
    #[tokio::test]
    async fn test_scan_keys_sees_recreation_after_frozen_tombstone() {
        let (engine, _dir) = make_engine().await;
        engine.put(b"user:1", b"alice").await.unwrap();
        engine.delete(b"user:1").await.unwrap();
        engine.freeze_active_memtable(); // tombstone now in an immutable MemTable
        engine.put(b"user:1", b"alice2").await.unwrap();

        let keys = engine.scan_keys(b"user:").await.unwrap();
        assert_eq!(keys, vec![b"user:1".to_vec()]);
    }

    #[tokio::test]
    async fn test_scan_keys_limited() {
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
    }

    // Note: the limit break in the SSTable sweep is only reachable once
    // keys live in an SSTable (unflushed keys hit the MemTable path). Flush
    // first, then trip the limit during the sweep.
    #[tokio::test]
    async fn test_scan_keys_limited_stops_in_sstable_sweep() {
        let (engine, _dir) = make_engine().await;
        for i in 0..10 {
            engine.put(format!("user:{i}").as_bytes(), b"v").await.unwrap();
        }
        freeze_and_flush(&engine).await;
        let keys = engine.scan_keys_limited(b"user:", 4).await.unwrap();
        assert_eq!(keys.len(), 4);
    }

    // Note: the TTL-expiry branch of scan_memtable_for_prefix is otherwise
    // only covered by `get`. An expired key must not appear in scan_keys.
    #[tokio::test]
    async fn test_scan_keys_excludes_ttl_expired() {
        let (engine, _dir) = make_engine().await;
        engine.put_with_ttl(b"user:1", b"alice", 1).await.unwrap();
        engine.put(b"user:2", b"bob").await.unwrap();
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let keys = engine.scan_keys(b"user:").await.unwrap();
        assert!(!keys.contains(&b"user:1".to_vec()));
        assert!(keys.contains(&b"user:2".to_vec()));
    }

    // ── scan_keys_with_snapshot tests (spec general/006 backup export) ──────

    // Writes after the snapshot (put, delete, set_null) must not change what
    // the pinned scan sees, while the unpinned scan_keys sees the new state.
    #[tokio::test]
    async fn test_scan_keys_with_snapshot_hides_later_writes() {
        let (engine, _dir) = make_engine().await;
        engine.put(b"user:1", b"alice").await.unwrap();
        engine.put(b"user:2", b"bob").await.unwrap();
        let snap = engine.snapshot();

        engine.put(b"user:3", b"carol").await.unwrap(); // new key after snapshot
        engine.delete(b"user:1").await.unwrap(); // delete after snapshot
        engine.set_null(b"user:2").await.unwrap(); // set_null after snapshot

        let pinned = engine.scan_keys_with_snapshot(b"user:", snap.snapshot()).await.unwrap();
        assert_eq!(pinned, vec![b"user:1".to_vec(), b"user:2".to_vec()]);

        let live = engine.scan_keys(b"user:").await.unwrap();
        assert_eq!(live, vec![b"user:2".to_vec(), b"user:3".to_vec()]);
    }

    // Same guarantee once the pre-snapshot data has been flushed to SSTables
    // and the post-snapshot write lands in a newer SSTable: a key tombstoned
    // as of the snapshot and later resurrected must stay invisible.
    #[tokio::test]
    async fn test_scan_keys_with_snapshot_respects_flushed_versions() {
        let (engine, _dir) = make_engine().await;
        engine.put(b"user:1", b"v1").await.unwrap();
        freeze_and_flush(&engine).await; // SSTable 1: user:1 = v1
        engine.delete(b"user:1").await.unwrap();
        freeze_and_flush(&engine).await; // SSTable 2: user:1 tombstoned

        let snap = engine.snapshot();

        engine.put(b"user:1", b"v2").await.unwrap(); // resurrection after snapshot
        freeze_and_flush(&engine).await; // SSTable 3: user:1 = v2

        let pinned = engine.scan_keys_with_snapshot(b"user:", snap.snapshot()).await.unwrap();
        assert!(pinned.is_empty(), "key tombstoned as of the snapshot must not appear");

        let live = engine.scan_keys(b"user:").await.unwrap();
        assert_eq!(live, vec![b"user:1".to_vec()], "current state must show the resurrection");
    }

    // NULL keys count as live under a pinned snapshot too (kv/018).
    #[tokio::test]
    async fn test_scan_keys_with_snapshot_includes_null() {
        let (engine, _dir) = make_engine().await;
        engine.set_null(b"user:1").await.unwrap();
        let snap = engine.snapshot();
        let keys = engine.scan_keys_with_snapshot(b"user:", snap.snapshot()).await.unwrap();
        assert_eq!(keys, vec![b"user:1".to_vec()]);
    }

    // Expiry uses wall-clock time, not the snapshot timestamp -- an entry
    // that was live when the snapshot was acquired but has since expired
    // must not appear (matches every other read path).
    #[tokio::test]
    async fn test_scan_keys_with_snapshot_excludes_expired() {
        let (engine, _dir) = make_engine().await;
        engine.put_with_ttl(b"user:1", b"alice", 1).await.unwrap();
        let snap = engine.snapshot();
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let keys = engine.scan_keys_with_snapshot(b"user:", snap.snapshot()).await.unwrap();
        assert!(keys.is_empty(), "TTL-expired entry must not appear even under an older snapshot");
    }

    // ── Point-read MVCC ordering tests (overlapping L0 / frozen MemTables) ───

    // Regression: with two overlapping L0 tables, get must return the newest
    // version, not the one in the oldest (first-flushed) table.
    #[tokio::test]
    async fn test_get_newest_version_across_l0_tables() {
        let (engine, _dir) = make_engine().await;
        engine.put(b"k", b"v1").await.unwrap();
        freeze_and_flush(&engine).await; // L0 table 1: k=v1
        engine.put(b"k", b"v2").await.unwrap();
        freeze_and_flush(&engine).await; // L0 table 2: k=v2

        assert_eq!(engine.get(b"k").await.unwrap(), Some(b"v2".to_vec()));
    }

    // Regression: a tombstone in a newer L0 table must suppress the live
    // version in an older L0 table (no resurrection).
    #[tokio::test]
    async fn test_get_tombstone_in_newer_l0_table_wins() {
        let (engine, _dir) = make_engine().await;
        engine.put(b"k", b"v1").await.unwrap();
        freeze_and_flush(&engine).await;
        engine.delete(b"k").await.unwrap();
        freeze_and_flush(&engine).await;

        assert_eq!(engine.get(b"k").await.unwrap(), None);
    }

    // A snapshot taken between the two versions must skip the (invisible)
    // newer L0 table and still find the old version in the older one.
    #[tokio::test]
    async fn test_get_snapshot_between_l0_versions_sees_old() {
        let (engine, _dir) = make_engine().await;
        engine.put(b"k", b"v1").await.unwrap();
        freeze_and_flush(&engine).await;
        let snap = engine.snapshot();
        engine.put(b"k", b"v2").await.unwrap();
        freeze_and_flush(&engine).await;

        assert_eq!(
            engine.get_with_snapshot(b"k", snap.snapshot()).await.unwrap(),
            GetResult::Present(b"v1".to_vec())
        );
        assert_eq!(engine.get(b"k").await.unwrap(), Some(b"v2".to_vec()));
    }

    // Regression: with two frozen (unflushed) MemTables, get must serve the
    // newest version — frozen tables are pushed to the back of the list.
    #[tokio::test]
    async fn test_get_newest_version_across_immutable_memtables() {
        let (engine, _dir) = make_engine().await;
        engine.put(b"k", b"v1").await.unwrap();
        engine.freeze_active_memtable();
        engine.put(b"k", b"v2").await.unwrap();
        engine.freeze_active_memtable();

        assert_eq!(engine.get(b"k").await.unwrap(), Some(b"v2".to_vec()));
    }

    // ── get_with_expiry tests (spec general/006 backup export) ──────────────

    // expire_at is 0 for a plain put, and the absolute TTL deadline for
    // put_with_ttl -- both against an externally acquired snapshot.
    #[tokio::test]
    async fn test_get_with_expiry_reports_ttl_and_zero() {
        let (engine, _dir) = make_engine().await;
        engine.put(b"plain", b"v").await.unwrap();
        engine.put_with_ttl(b"ttl", b"v", 3600).await.unwrap();
        let snap = engine.snapshot();

        let (result, expire_at) = engine.get_with_expiry(b"plain", snap.snapshot()).await.unwrap();
        assert_eq!(result, GetResult::Present(b"v".to_vec()));
        assert_eq!(expire_at, 0);

        let (result, expire_at) = engine.get_with_expiry(b"ttl", snap.snapshot()).await.unwrap();
        assert_eq!(result, GetResult::Present(b"v".to_vec()));
        assert!(expire_at > now_secs(), "expire_at must be an absolute future timestamp");
    }

    // A NULL entry is reported distinctly, with expire_at 0 (set_null never
    // carries a TTL).
    #[tokio::test]
    async fn test_get_with_expiry_distinguishes_null() {
        let (engine, _dir) = make_engine().await;
        engine.set_null(b"n").await.unwrap();
        let snap = engine.snapshot();
        assert_eq!(
            engine.get_with_expiry(b"n", snap.snapshot()).await.unwrap(),
            (GetResult::Null, 0)
        );
    }

    // A missing key reports Absent with expire_at 0.
    #[tokio::test]
    async fn test_get_with_expiry_absent_for_missing_key() {
        let (engine, _dir) = make_engine().await;
        let snap = engine.snapshot();
        assert_eq!(
            engine.get_with_expiry(b"ghost", snap.snapshot()).await.unwrap(),
            (GetResult::Absent, 0)
        );
    }

    // Snapshot isolation holds for the expiry-carrying read too, including
    // across a flush to SSTable and a VLog-backed (large) value.
    #[tokio::test]
    async fn test_get_with_expiry_snapshot_consistency_across_flush() {
        let (engine, _dir) = make_engine().await;
        let big = vec![b'x'; 4096]; // >= vlog_inline_threshold -> VLog pointer
        engine.put(b"k", &big).await.unwrap();
        freeze_and_flush(&engine).await;
        let snap = engine.snapshot();

        engine.put(b"k", b"newer").await.unwrap();
        freeze_and_flush(&engine).await;

        let (result, expire_at) = engine.get_with_expiry(b"k", snap.snapshot()).await.unwrap();
        assert_eq!(result, GetResult::Present(big));
        assert_eq!(expire_at, 0);
        assert_eq!(engine.get(b"k").await.unwrap(), Some(b"newer".to_vec()));
    }

    // ── Watcher tests ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_watcher_receives_set_event() {
        let (engine, _dir) = make_engine().await;
        let mut rx = engine.watch_subscribe();
        engine.put(b"watch_key", b"val").await.unwrap();
        let event = rx.recv().await.unwrap();
        assert_eq!(event.key, b"watch_key");
        assert!(matches!(event.op, OpType::Set));
    }

    // kv/018 §2: set_null is an update — watchers receive a Set event.
    #[tokio::test]
    async fn test_watcher_receives_set_event_on_set_null() {
        let (engine, _dir) = make_engine().await;
        let mut rx = engine.watch_subscribe();
        engine.set_null(b"null_key").await.unwrap();
        let event = rx.recv().await.unwrap();
        assert_eq!(event.key, b"null_key");
        assert!(matches!(event.op, OpType::Set));
    }

    #[tokio::test]
    async fn test_watcher_receives_delete_event() {
        let (engine, _dir) = make_engine().await;
        engine.put(b"del_key", b"v").await.unwrap();
        let mut rx = engine.watch_subscribe();
        engine.delete(b"del_key").await.unwrap();
        let event = rx.recv().await.unwrap();
        assert_eq!(event.key, b"del_key");
        assert!(matches!(event.op, OpType::Delete));
    }

    // ── Inline-value flush test ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_small_value_flush_no_vlog_growth() {
        let (engine, dir) = make_engine().await;
        let vlog_path = dir.path().join("vlog.log");

        // Write a small value (< MAX_VALUE_LENGTH = 1024 bytes)
        engine.put(b"small_key", b"tiny_value").await.unwrap();

        // Small values are stored inline in the MemTable — VLog must still be empty.
        let vlog_size_before = std::fs::metadata(&vlog_path)
            .map(|m| m.len())
            .unwrap_or(0);

        // Freeze the active MemTable and flush it to an SSTable.
        {
            let old_mt = {
                let mut mt = engine.memtable.write();
                std::mem::replace(&mut *mt, Arc::new(MemTable::new()))
            };
            engine.immutable_memtables.write().push(old_mt);
        }
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
    }

    // ── Block-cache file-id stamping (compaction / Janitor rebuild) ──────────

    async fn freeze_and_flush(engine: &LsmStorageEngine) {
        engine.freeze_active_memtable();
        engine.flush_memtable().await.unwrap();
    }

    /// Every installed reader must carry the file id of its manifest entry —
    /// unstamped (id-0) readers collide in the block cache across tables.
    fn assert_readers_match_manifest(engine: &LsmStorageEngine) {
        let manifest = engine.manifest.read();
        for (lvl, readers) in engine.level_manager.get_all_levels().iter().enumerate() {
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

    #[tokio::test]
    async fn test_compaction_rebuild_stamps_reader_file_ids() {
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
    }

    // Regression (perf/004 finding 3): flush_memtable returns the flushed
    // SSTable's own file_id (not a positional guess into L0), and None when
    // there is nothing to flush -- so registration can't pick the wrong table.
    #[tokio::test]
    async fn test_flush_memtable_returns_flushed_file_id() {
        let (engine, _dir) = make_engine().await;
        assert_eq!(engine.flush_memtable().await.unwrap(), None, "nothing to flush");

        engine.put(b"k", b"v").await.unwrap();
        engine.freeze_active_memtable();
        let id = engine.flush_memtable().await.unwrap().expect("a table was flushed");

        let l0 = engine.level_manager.get_level(0);
        assert_eq!(l0.len(), 1);
        assert_eq!(l0[0].file_id, id, "returned id must be the flushed table's id");
    }

    // Regression (perf/004 finding 2): compact_level returns exactly the file
    // ids it deleted (merged source + target), so deregistration deregisters
    // the real deletions instead of a separately-selected, racy guess.
    #[tokio::test]
    async fn test_compact_level_returns_deleted_file_ids() {
        let (engine, _dir) = make_engine().await;
        engine.put(b"a", b"1").await.unwrap();
        freeze_and_flush(&engine).await;
        engine.put(b"b", b"2").await.unwrap();
        freeze_and_flush(&engine).await;

        // Two L0 tables, L1 empty -> both source tables are deleted, no targets.
        let mut expected: Vec<u64> =
            engine.level_manager.get_level(0).iter().map(|r| r.file_id).collect();
        expected.sort_unstable();

        let mut deleted = engine.compact_level(0).await.unwrap();
        deleted.sort_unstable();
        assert_eq!(deleted, expected, "must report exactly the compacted-away ids");
    }

    // Note: every other compaction test targets an empty L1; this drives
    // the non-empty-target branch (open, drop from manifest, delete). A key
    // inside the existing L1 range forces overlapping-target selection.
    #[tokio::test]
    async fn test_compaction_into_nonempty_target_level() {
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
    }

    /// GC config that fires on any non-empty vLog.
    fn gc_always() -> JanitorConfig {
        JanitorConfig {
            check_interval_secs: 3600,
            dead_bytes_threshold: 0.0,
            min_vlog_size_bytes: 0,
        }
    }

    #[tokio::test]
    async fn test_janitor_gc_stamps_reader_file_ids_and_invalidates_cache() {
        let (engine, _dir) = make_engine().await;
        let engine = Arc::new(engine);
        let big = vec![b'x'; 4096]; // >= vlog_inline_threshold → vLog pointer
        engine.put(b"big", &big).await.unwrap();
        engine.put(b"small", b"v").await.unwrap();
        freeze_and_flush(&engine).await;

        // Populate the block cache under the pre-GC file id (first table = 0).
        assert_eq!(engine.get(b"small").await.unwrap(), Some(b"v".to_vec()));
        let pre_gc_key = BlockCacheKey { file_id: 0, block_offset: 0 };
        assert!(engine.block_cache.lock().get(&pre_gc_key).is_some());

        let stats = engine.build_janitor(gc_always()).run_gc().await.unwrap();
        assert!(stats.ran);

        assert_readers_match_manifest(&engine);
        assert!(
            engine
                .level_manager
                .get_all_levels()
                .iter()
                .flatten()
                .all(|r| r.file_id != 0),
            "rebuilt readers must carry the new (non-zero) file ids"
        );
        // Cached blocks of the deleted pre-GC table must be invalidated.
        assert!(engine.block_cache.lock().get(&pre_gc_key).is_none());

        // Data reads correctly through rebuilt readers and the new vLog.
        assert_eq!(engine.get(b"big").await.unwrap(), Some(big));
        assert_eq!(engine.get(b"small").await.unwrap(), Some(b"v".to_vec()));
    }

    /// vLog generation ids stamped into the pointers of all L0 SSTables.
    fn l0_pointer_generations(engine: &LsmStorageEngine) -> Vec<u32> {
        let mut ids = Vec::new();
        for sstable in engine.level_manager.get_level(0) {
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

    /// Every vLog-pointer `file_id` reachable from any MemTable (active +
    /// immutable) or any SSTable at any level — a full scan (spec kv/020 test
    /// 3), not just a read-back, so a dangling pointer into a retired
    /// generation would show up here even if no test happens to read that key.
    fn all_pointer_generations(engine: &LsmStorageEngine) -> Vec<u32> {
        let mut ids = Vec::new();

        let active = engine.memtable.read();
        for (_, value) in active.iter() {
            if let Value::Pointer { file_id, .. } = value {
                ids.push(file_id);
            }
        }
        drop(active);

        for mt in engine.immutable_memtables.read().iter() {
            for (_, value) in mt.iter() {
                if let Value::Pointer { file_id, .. } = value {
                    ids.push(file_id);
                }
            }
        }

        for level in engine.level_manager.get_all_levels() {
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

    // Spec kv/017 test 1 (window A): a large value whose pointer lives only in
    // the active MemTable — no flush ran — must survive a GC cycle.
    #[tokio::test]
    async fn test_gc_preserves_memtable_resident_vlog_value() {
        let (engine, _dir) = make_engine().await;
        let engine = Arc::new(engine);
        let big = vec![b'x'; 4096]; // >= vlog_inline_threshold → vLog pointer
        engine.put(b"big", &big).await.unwrap();
        // Deliberately no flush: the pointer exists only in the MemTable.

        let stats = engine.build_janitor(gc_always()).run_gc().await.unwrap();
        assert!(stats.ran);
        assert_eq!(stats.live_bytes, 4096, "the MemTable pointer counts as live");

        assert_eq!(engine.get(b"big").await.unwrap(), Some(big));
    }

    // Spec kv/017 test 2 (write path): with the old generation sealed and a
    // new one published, a write lands in — and is stamped with — the new one.
    #[tokio::test]
    async fn test_write_after_generation_swap_uses_new_generation() {
        let (engine, _dir) = make_engine().await;
        let gen1 = engine.vlog.active();
        let gen2 =
            Arc::new(VLog::open(generation_path(&engine.vlog_path, 2), 2).await.unwrap());
        engine.vlog.set_active(gen2);
        gen1.seal();

        let big = vec![b'y'; 4096];
        engine.put(b"big", &big).await.unwrap();

        assert_eq!(gen1.size(), 0, "the sealed generation must not grow");
        assert_eq!(engine.vlog.active().size(), 4096);
        assert_eq!(engine.get(b"big").await.unwrap(), Some(big.clone()));

        freeze_and_flush(&engine).await;
        assert_eq!(l0_pointer_generations(&engine), vec![2]);
        assert_eq!(engine.get(b"big").await.unwrap(), Some(big));
    }

    // Spec kv/017 test 3 (window B): values written while the GC runs must all
    // survive — the seal makes racing appends retry against the new generation.
    // Multi-threaded on purpose: the seal/append race needs real parallelism.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_gc_keeps_values_written_concurrently() {
        let (engine, _dir) = make_engine().await;
        let engine = Arc::new(engine);
        let big = vec![b'w'; 2048];
        engine.put(b"pre", &big).await.unwrap();

        let writers: Vec<_> = (0..4u32)
            .map(|w| {
                let engine = Arc::clone(&engine);
                let value = big.clone();
                tokio::spawn(async move {
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
    }

    // Spec kv/020 test 1: a held writer guard blocks the barrier's drain step;
    // dropping it unblocks immediately. Exercises the guard mechanism directly
    // (not the public write path) since the real race window is instruction-
    // width and cannot be hit deterministically. Timeout-guarded so a bug that
    // makes the drain hang fails the test instead of the suite.
    #[tokio::test]
    async fn test_drain_waits_for_held_writer_guard_then_proceeds() {
        let (engine, _dir) = make_engine().await;

        // Simulates a write in flight: it has fetched the active generation
        // and is somewhere before its `memtable.set`.
        let guard = engine.in_flight_writes.read().await;

        let blocked = tokio::time::timeout(Duration::from_millis(200), engine.flush_all_memtables()).await;
        assert!(blocked.is_err(), "drain must block while a writer guard is held");

        drop(guard);

        tokio::time::timeout(Duration::from_millis(200), engine.flush_all_memtables())
            .await
            .expect("drain must complete promptly once the guard is released")
            .unwrap();
    }

    // Spec kv/020 tests 2+3: sharpens test_gc_keeps_values_written_concurrently
    // (kv/017) for the in-flight guard introduced here -- that test is left
    // unchanged and must stay green on its own. Adds two properties the guard
    // must not break: (2) the GC cycle terminates under concurrent write load
    // instead of deadlocking against the drain, and (3) once everything has
    // settled, no stored pointer names a generation the GC retired -- checked
    // via a full MemTable/SSTable scan, not just successful reads.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_gc_drain_no_deadlock_and_no_dangling_pointers_under_load() {
        let (engine, _dir) = make_engine().await;
        let engine = Arc::new(engine);
        let big = vec![b'w'; 2048];
        engine.put(b"pre", &big).await.unwrap();

        let writers: Vec<_> = (0..4u32)
            .map(|w| {
                let engine = Arc::clone(&engine);
                let value = big.clone();
                tokio::spawn(async move {
                    for i in 0..25u32 {
                        engine.put(format!("k{w}-{i:02}").as_bytes(), &value).await.unwrap();
                    }
                })
            })
            .collect();

        // A stuck drain (guard never released, or a deadlock against the
        // writers) fails the test instead of hanging the suite.
        tokio::time::timeout(Duration::from_secs(10), engine.build_janitor(gc_always()).run_gc())
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

        let live_ids = engine.vlog.ids();
        for id in all_pointer_generations(&engine) {
            assert!(
                live_ids.contains(&id),
                "pointer references retired generation {id}, live={live_ids:?}"
            );
        }
    }

    // A generation that stays sealed (no swap) must fail the write cleanly
    // instead of spinning in the retry loop.
    #[tokio::test]
    async fn test_append_to_permanently_sealed_generation_fails() {
        let (engine, _dir) = make_engine().await;
        engine.vlog.active().seal();

        let err = engine.put(b"big", &vec![b'x'; 4096]).await.unwrap_err();
        assert!(err.to_string().contains("sealed"), "unexpected error: {err}");
    }

    // Spec kv/017 test 4: values from before and after a GC are both readable,
    // and a reference to the retired generation taken before the GC keeps
    // reading correctly from its already-open descriptor.
    #[tokio::test]
    async fn test_reads_span_vlog_generations() {
        let (engine, _dir) = make_engine().await;
        let engine = Arc::new(engine);
        let before = vec![b'1'; 4096];
        engine.put(b"before", &before).await.unwrap();
        let gen1 = engine.vlog.active();

        engine.build_janitor(gc_always()).run_gc().await.unwrap();
        assert_eq!(engine.vlog.active().id(), 2);
        assert_eq!(engine.vlog.ids(), vec![2], "generation 1 is retired");

        let after = vec![b'2'; 4096];
        engine.put(b"after", &after).await.unwrap();

        assert_eq!(engine.get(b"before").await.unwrap(), Some(before.clone()));
        assert_eq!(engine.get(b"after").await.unwrap(), Some(after));
        assert_eq!(gen1.read(0, 4096).await.unwrap(), before);
    }

    // Spec kv/017 test 5: startup registers every generation found on disk and
    // activates the highest id; a store with only the canonical file starts as
    // generation 1, and an orphaned empty generation does not disturb it.
    #[tokio::test]
    async fn test_startup_registers_all_generations() {
        let dir = tempfile::TempDir::new().unwrap();
        let vlog_path = dir.path().join("vlog.log");

        let engine = engine_on(&dir).await;
        assert_eq!(engine.vlog.ids(), vec![1], "legacy store is generation 1");
        assert_eq!(engine.vlog.active().id(), 1);
        drop(engine);

        std::fs::write(generation_path(&vlog_path, 2), b"generation-2").unwrap();
        let engine = engine_on(&dir).await;
        assert_eq!(engine.vlog.ids(), vec![1, 2]);
        assert_eq!(engine.vlog.active().id(), 2);
        assert_eq!(engine.vlog.read(2, 0, 12).await.unwrap(), b"generation-2");
        drop(engine);

        std::fs::write(generation_path(&vlog_path, 3), b"").unwrap(); // orphan
        let engine = engine_on(&dir).await;
        assert_eq!(engine.vlog.ids(), vec![1, 2, 3]);
        assert_eq!(engine.vlog.active().id(), 3);
        let big = vec![b'o'; 4096];
        engine.put(b"k", &big).await.unwrap();
        assert_eq!(engine.get(b"k").await.unwrap(), Some(big));
    }

    // Spec perf/013 test 3: startup with an active generation > 1 and a live
    // storage thread repoints the thread at that generation instead of
    // leaving it on the canonical file until the next GC. Generation 1 (no
    // longer thread-owned) stays correctly readable through a local handle.
    #[tokio::test]
    async fn test_startup_routes_active_generation_through_thread() {
        let dir = tempfile::TempDir::new().unwrap();
        let wal_path = dir.path().join("wal.log");
        let vlog_path = dir.path().join("vlog.log");
        std::fs::write(&vlog_path, b"generation-1").unwrap();
        std::fs::write(generation_path(&vlog_path, 2), b"generation-2").unwrap();

        let st_config = StorageThreadConfig {
            sqpoll_enabled: false,
            sqpoll_idle_ms: 500,
            ring_depth: 64,
            channel_capacity: 64,
            cpu: -1,
        };
        let (mut st, handle) =
            StorageThread::new(st_config, wal_path.clone(), vlog_path.clone()).unwrap();

        let wal = Arc::new(WriteAheadLog::with_storage_handle(handle.clone()));
        let vlog = Arc::new(VLog::with_storage_handle(&vlog_path, handle.clone(), 1));
        let file_manager = Arc::new(FileManager::new(dir.path()).await.unwrap());
        let manifest_manager = Arc::new(ManifestManager::new(dir.path()));
        let engine = LsmStorageEngine::new(
            wal,
            wal_path,
            vlog,
            vlog_path,
            file_manager,
            manifest_manager,
            LsmEngineOptions::default(),
        )
        .await
        .unwrap();

        // Before the repoint: registry-only bookkeeping, thread still on gen 1.
        assert_eq!(engine.vlog.active().id(), 2, "generation 2 is the highest on disk");

        engine.route_active_vlog_to_thread(&handle).await.unwrap();

        let active = engine.vlog.active();
        assert_eq!(active.id(), 2, "active reference is handle-backed generation 2");
        let off = active.append(b"-added").await.unwrap();
        assert_eq!(off, 12, "cursor seeded from generation 2's on-disk length");
        assert_eq!(
            handle.vlog_read(off, 6, 2).await.unwrap(),
            b"-added",
            "the append routed through the thread's own fd"
        );

        // Generation 1 is no longer thread-owned but stays correctly readable.
        assert_eq!(engine.vlog.read(1, 0, 12).await.unwrap(), b"generation-1");

        st.shutdown();
    }

    // ── IoEngine integration (spec perf/004) ─────────────────────────────────
    //
    // Runs inside `tokio_uring::start` (not `#[tokio::test]`): registering
    // files with `IoEngine` requires a tokio-uring runtime context, and the
    // engine's own WAL/VLog/SSTable I/O (plain `tokio::fs`) works fine inside
    // one too (this is exactly how `main.rs` already runs the whole server).

    // 8. Integration: SSTable flush -> file is automatically registered.
    // Compaction deletion -> file is deregistered.
    #[test]
    fn test_flush_registers_and_compaction_deregisters_sstable() {
        tokio_uring::start(async {
            let dir = tempfile::TempDir::new().unwrap();
            let engine = engine_on(&dir).await;
            let mut io_engine = IoEngine::new(4, 4096).unwrap();

            engine.put(b"a", b"1").await.unwrap();
            engine.freeze_active_memtable();
            engine.flush_memtable_and_register(&mut io_engine).await.unwrap();
            let first_id = engine.level_manager.get_level(0)[0].file_id;
            assert!(io_engine.get_file(first_id).is_some(), "flushed SSTable must be registered");

            engine.put(b"b", b"2").await.unwrap();
            engine.freeze_active_memtable();
            engine.flush_memtable_and_register(&mut io_engine).await.unwrap();
            let second_id = engine.level_manager.get_level(0)[1].file_id;
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
        tokio_uring::start(async {
            let dir = tempfile::TempDir::new().unwrap();
            {
                let engine = engine_on(&dir).await;
                engine.put(b"k", b"v").await.unwrap();
                freeze_and_flush(&engine).await;
            }

            // Fresh engine instance recovers the SSTable written above.
            let engine2 = engine_on(&dir).await;
            let file_id = engine2.level_manager.get_level(0)[0].file_id;

            let mut io_engine = IoEngine::new(4, 4096).unwrap();
            engine2.register_sstables_with_io_engine(&mut io_engine).await.unwrap();
            assert!(io_engine.get_file(file_id).is_some());
        });
    }
}
