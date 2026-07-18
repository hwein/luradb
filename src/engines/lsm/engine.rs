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
use crate::engines::lsm::janitor::{Janitor, JanitorConfig};
use crate::engines::lsm::hlc::HybridLogicalClock;
use crate::engines::lsm::watcher::{OpType, WalEvent};
use crate::engines::StorageEngine;
use crate::core::io_engine::IoEngine;
use crate::core::storage_thread::StorageHandle;
use crate::core::wal::WriteAheadLog;
use crate::storage::vlog::VLog;
use crate::storage::sstable::{SSTableBuilder, SSTableReader};
use crate::storage::file_manager::FileManager;
use crate::storage::manifest::{Manifest, ManifestManager, SSTableMetadata};
use anyhow::Result;
use parking_lot::{Mutex, RwLock};
use std::collections::BTreeSet;
use std::path::PathBuf;
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
fn scan_memtable_for_prefix(
    mt: &MemTable,
    prefix: &[u8],
    now: u64,
    limit: usize,
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
            decided.insert(user_key.to_vec());
            if is_live_version(&value, now) {
                live.insert(user_key.to_vec());
            }
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
/// for the newest-first decision protocol). Returns `true` once `live` holds
/// `limit` keys so the caller can stop.
fn scan_sstable_for_prefix(
    sstable: &SSTableReader,
    prefix: &[u8],
    limit: usize,
    live: &mut BTreeSet<Vec<u8>>,
    decided: &mut BTreeSet<Vec<u8>>,
) -> Result<bool> {
    for entry in sstable.keys_with_prefix(prefix) {
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

    /// Shared vLog reference — swapped atomically by the Janitor after GC.
    vlog: Arc<RwLock<Arc<VLog>>>,

    /// Filesystem path of the vLog (needed to initialise the Janitor).
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
            vlog: Arc::new(RwLock::new(vlog)),
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

    // ── Recovery ────────────────────────────────────────────────────────────

    /// Recovers the MemTable state from the WAL.
    ///
    /// Does NOT truncate the WAL — [`Self::new`] first flushes the recovered
    /// data to an SSTable, so an interrupted startup never loses it.
    async fn recover_from_wal(
        wal_path: &PathBuf,
        vlog: &Arc<VLog>,
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
                        let offset = vlog.append(&value).await?;
                        memtable.set(key, ts, Value::Pointer { offset, len: value.len(), expire_at: expire_at_opt });
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
        let janitor = Arc::new(Janitor::new(
            Arc::clone(&self.vlog),
            self.vlog_path.clone(),
            Arc::clone(&self.level_manager),
            Arc::clone(&self.manifest),
            Arc::clone(&self.manifest_manager),
            Arc::clone(&self.file_manager),
            Arc::clone(&self.block_cache),
            Arc::clone(&self.snapshot_registry),
            self.janitor_config.clone(),
            self.engine_config.use_mmap,
            Arc::clone(&self.shutdown),
            self.storage_handle.clone(),
        ));
        tokio::spawn(async move { janitor.run_background().await });
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

    /// Shuts down all background tasks and flushes remaining MemTables.
    pub async fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);

        // Freeze the active memtable if it's not empty.
        let old_memtable = {
            let mut mt = self.memtable.write();
            // Swap the active memtable with a new, empty one.
            std::mem::replace(&mut *mt, Arc::new(MemTable::new()))
        };

        // If the old memtable had data, add it to the immutable list to be flushed.
        if old_memtable.approximate_size() > 0 {
            self.immutable_memtables.write().push(old_memtable);
        }

        // Flush all immutable memtables.
        while !self.immutable_memtables.read().is_empty() {
            if let Err(e) = self.flush_memtable().await {
                eprintln!("[Engine] Shutdown flush error: {e}");
                break;
            }
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

    /// MVCC-aware point read. Three-valued (spec kv/018): a live value, an
    /// explicit NULL (`set_null`), or absent.
    pub async fn get_with_snapshot(
        &self,
        key: &[u8],
        snapshot: &Snapshot,
    ) -> Result<GetResult> {
        let memtable = { Arc::clone(&*self.memtable.read()) };
        let vlog = { self.vlog.read().clone() };

        let mut reader = LsmReader::new(memtable, vlog, Arc::clone(&self.block_cache));
        {
            let imm = self.immutable_memtables.read();
            reader.set_immutable_memtables(imm.clone());
        }
        reader.set_sstables(self.level_manager.get_all_levels());
        reader.get(key, snapshot).await
    }

    /// MVCC-aware point read returning value + metadata without dereferencing
    /// the VLog (spec perf/009 §3). Additive to [`Self::get_with_snapshot`];
    /// used by the SHM snapshot builder.
    pub async fn get_with_metadata(
        &self,
        key: &[u8],
        snapshot: &Snapshot,
    ) -> Result<Option<ValueWithMetadata>> {
        let memtable = { Arc::clone(&*self.memtable.read()) };
        let vlog = { self.vlog.read().clone() };

        let mut reader = LsmReader::new(memtable, vlog, Arc::clone(&self.block_cache));
        {
            let imm = self.immutable_memtables.read();
            reader.set_immutable_memtables(imm.clone());
        }
        reader.set_sstables(self.level_manager.get_all_levels());
        reader.get_with_metadata(key, snapshot).await
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

        let memtable = Arc::clone(&*self.memtable.read());
        if value.len() >= self.engine_config.vlog_inline_threshold {
            let vlog = self.vlog.read().clone();
            let offset = vlog.append(value).await?;
            memtable.set(key.to_vec(), timestamp, Value::Pointer { offset, len: value.len(), expire_at });
        } else {
            memtable.set(key.to_vec(), timestamp, Value::Inline(value.to_vec(), expire_at));
        }
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
                        let vlog = self.vlog.read().clone();
                        let offset = vlog.append(&value).await?;
                        (key, Value::Pointer { offset, len: value.len(), expire_at: None })
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
        let mut live: BTreeSet<Vec<u8>> = BTreeSet::new();
        // User keys already decided by a newer version (live OR dead).
        let mut decided: BTreeSet<Vec<u8>> = BTreeSet::new();
        let now = now_secs();

        let memtable = { Arc::clone(&*self.memtable.read()) };
        scan_memtable_for_prefix(&memtable, prefix, now, limit, &mut live, &mut decided);

        {
            let imm = self.immutable_memtables.read();
            // Frozen MemTables are pushed to the back — iterate newest-first.
            for mt in imm.iter().rev() {
                scan_memtable_for_prefix(mt, prefix, now, limit, &mut live, &mut decided);
            }
        }

        let mut levels = self.level_manager.get_all_levels();
        if let Some(l0) = levels.first_mut() {
            // L0 tables are appended in flush order — newest last.
            l0.reverse();
        }
        for level_sstables in levels {
            for sstable in level_sstables {
                if scan_sstable_for_prefix(&sstable, prefix, limit, &mut live, &mut decided)? {
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
                Value::Pointer { offset, len, expire_at } => {
                    builder.add(
                        encoded_key,
                        crate::storage::format::ValuePointer {
                            file_id: 1,
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
        let vlog_bytes = self.vlog.read().size_bytes();
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
        *engine.vlog.write() = Arc::new(VLog::new("/dev/full").await.unwrap());
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

    // Vorarbeit: the limit break in the SSTable sweep is only reachable once
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

    // Vorarbeit: the TTL-expiry branch of scan_memtable_for_prefix is otherwise
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

    // Vorarbeit: every other compaction test targets an empty L1; this drives
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

    #[tokio::test]
    async fn test_janitor_gc_stamps_reader_file_ids_and_invalidates_cache() {
        let (engine, _dir) = make_engine().await;
        let big = vec![b'x'; 4096]; // >= vlog_inline_threshold → vLog pointer
        engine.put(b"big", &big).await.unwrap();
        engine.put(b"small", b"v").await.unwrap();
        freeze_and_flush(&engine).await;

        // Populate the block cache under the pre-GC file id (first table = 0).
        assert_eq!(engine.get(b"small").await.unwrap(), Some(b"v".to_vec()));
        let pre_gc_key = BlockCacheKey { file_id: 0, block_offset: 0 };
        assert!(engine.block_cache.lock().get(&pre_gc_key).is_some());

        let janitor = Janitor::new(
            Arc::clone(&engine.vlog),
            engine.vlog_path.clone(),
            Arc::clone(&engine.level_manager),
            Arc::clone(&engine.manifest),
            Arc::clone(&engine.manifest_manager),
            Arc::clone(&engine.file_manager),
            Arc::clone(&engine.block_cache),
            Arc::clone(&engine.snapshot_registry),
            JanitorConfig {
                check_interval_secs: 1,
                dead_bytes_threshold: 0.0,
                min_vlog_size_bytes: 0,
            },
            engine.engine_config.use_mmap,
            Arc::clone(&engine.shutdown),
            None,
        );
        let stats = janitor.run_gc().await.unwrap();
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

    // ── IoEngine integration (spec perf/004) ─────────────────────────────────
    //
    // Runs inside `tokio_uring::start` (not `#[tokio::test]`): registering
    // files with `IoEngine` requires a tokio-uring runtime context, and the
    // engine's own WAL/VLog/SSTable I/O (plain `tokio::fs`) works fine inside
    // one too (this is exactly how `main.rs` already runs the whole server).

    // 8. Integration: SSTable-Flush -> File wird automatisch registriert.
    // Compaction-Deletion -> File wird deregistriert.
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
