//! Value Log Garbage Collector — the Janitor.
//!
//! The vLog is append-only: deleted and overwritten values accumulate as *dead*
//! bytes that are never reclaimed by the compaction process (which only rewrites
//! the SSTable index, not the vLog payloads).
//!
//! The Janitor runs as a background Tokio task and periodically reclaims dead
//! space using the following algorithm:
//!
//! 1. Collect all live `(value_offset, value_len)` pointers by iterating every
//!    SSTable in every level (cross-referencing the LSM index).
//! 2. Compute `dead_ratio = 1 − live_bytes / vlog_size`.
//! 3. If `dead_ratio < threshold`, skip this cycle.
//! 4. Otherwise, write live values to a new vLog file (`vlog_gc.bin`) and
//!    record the `old_offset → new_offset` mapping.
//! 5. Rebuild every SSTable at every level with remapped pointers.
//! 6. Atomically swap the engine's vLog reference and update the manifest.
//! 7. Delete the old vLog file and rename the GC file to the canonical path.
//!
//! All steps are performed without holding any write-path locks for extended
//! periods, so normal reads and writes are never stalled.

use crate::core::storage_thread::StorageHandle;
use crate::engines::lsm::block_cache::BlockCache;
use crate::engines::lsm::engine::LsmStorageEngine;
use crate::engines::lsm::levels::LevelManager;
use crate::engines::lsm::reader::SnapshotRegistry;
use crate::storage::file_manager::FileManager;
use crate::storage::format::DataBlockValue;
use crate::storage::manifest::{Manifest, ManifestManager, SSTableMetadata};
use crate::storage::sstable::{SSTableBuilder, SSTableReader};
use crate::storage::vlog::VLog;
use anyhow::Result;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use tokio::time::{sleep, Duration};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Tuning parameters for the Janitor background task.
#[derive(Debug, Clone)]
pub struct JanitorConfig {
    /// How often to check whether a GC cycle is needed (seconds).
    pub check_interval_secs: u64,

    /// Fraction of dead bytes in the vLog that triggers a full GC pass (0–1).
    ///
    /// For example, `0.3` means GC runs when ≥ 30 % of vLog space is dead.
    pub dead_bytes_threshold: f64,

    /// Minimum vLog size (bytes) below which GC is skipped regardless of ratio.
    ///
    /// Avoids unnecessary work when the database is small.
    pub min_vlog_size_bytes: u64,
}

impl Default for JanitorConfig {
    fn default() -> Self {
        Self {
            check_interval_secs: 60,
            dead_bytes_threshold: 0.30, // 30 %
            min_vlog_size_bytes: 64 * 1024 * 1024, // 64 MB
        }
    }
}

// ---------------------------------------------------------------------------
// GC statistics
// ---------------------------------------------------------------------------

/// Outcome of a single Janitor GC cycle.
#[derive(Debug, Default)]
pub struct GcStats {
    /// Whether a GC pass was actually performed.
    pub ran: bool,
    /// Number of live bytes copied to the new vLog.
    pub live_bytes: u64,
    /// Number of dead bytes reclaimed.
    pub reclaimed_bytes: u64,
    /// Number of SSTables rebuilt with updated pointers.
    pub sstables_rebuilt: usize,
}

impl GcStats {
    fn skipped() -> Self {
        Self { ran: false, ..Default::default() }
    }
}

// ---------------------------------------------------------------------------
// Janitor
// ---------------------------------------------------------------------------

/// Background garbage collector for the Value Log.
pub struct Janitor {
    /// Shared vLog reference — swapped atomically after GC completes.
    vlog: Arc<RwLock<Arc<VLog>>>,

    /// Canonical (non-GC) filesystem path for the vLog.
    vlog_base_path: PathBuf,

    level_manager: Arc<LevelManager>,
    manifest: Arc<RwLock<Manifest>>,
    manifest_manager: Arc<ManifestManager>,
    file_manager: Arc<FileManager>,

    /// Shared block cache — entries of SSTables replaced by GC are invalidated.
    block_cache: Arc<Mutex<BlockCache>>,

    /// Used to check whether a GC cycle is safe (e.g. no active readers that
    /// might hold stale vLog offsets).  Currently informational only — the GC
    /// is safe because it rebuilds SSTables atomically before deleting the old
    /// vLog; active readers will finish against the old vLog via their Arc.
    #[allow(dead_code)]
    snapshot_registry: Arc<SnapshotRegistry>,

    config: JanitorConfig,

    /// Mirrors `LsmEngineConfig::use_mmap` for reopening rebuilt SSTables.
    use_mmap: bool,

    shutdown: Arc<AtomicBool>,

    /// Storage thread handle (perf/005). When set, the vLog is reopened through
    /// the thread after GC so remote I/O survives the swap.
    storage_handle: Option<StorageHandle>,
}

impl Janitor {
    /// Creates a new Janitor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vlog: Arc<RwLock<Arc<VLog>>>,
        vlog_base_path: PathBuf,
        level_manager: Arc<LevelManager>,
        manifest: Arc<RwLock<Manifest>>,
        manifest_manager: Arc<ManifestManager>,
        file_manager: Arc<FileManager>,
        block_cache: Arc<Mutex<BlockCache>>,
        snapshot_registry: Arc<SnapshotRegistry>,
        config: JanitorConfig,
        use_mmap: bool,
        shutdown: Arc<AtomicBool>,
        storage_handle: Option<StorageHandle>,
    ) -> Self {
        Self {
            vlog,
            vlog_base_path,
            level_manager,
            manifest,
            manifest_manager,
            file_manager,
            block_cache,
            snapshot_registry,
            config,
            use_mmap,
            shutdown,
            storage_handle,
        }
    }

    // -----------------------------------------------------------------------
    // Background loop
    // -----------------------------------------------------------------------

    /// Runs the Janitor's periodic GC loop.
    ///
    /// Intended to be spawned as a Tokio task via `tokio::spawn`.
    pub async fn run_background(self: Arc<Self>) {
        let interval = Duration::from_secs(self.config.check_interval_secs);
        while !self.shutdown.load(Ordering::Relaxed) {
            sleep(interval).await;

            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }

            if let Err(e) = self.run_gc().await {
                eprintln!("[Janitor] GC cycle failed: {e}");
            }
        }
    }

    // -----------------------------------------------------------------------
    // GC cycle
    // -----------------------------------------------------------------------

    /// Runs one GC cycle.
    ///
    /// Returns [`GcStats`] describing what happened.  If the dead-byte ratio
    /// is below the threshold the cycle is a no-op.
    pub async fn run_gc(&self) -> Result<GcStats> {
        // ── Take a consistent snapshot of the current vLog and manifest ──
        let current_vlog = self.vlog.read().clone();
        let vlog_size = current_vlog.size();
        let manifest_snapshot = self.manifest.read().clone();

        let mut live = self.collect_live_pointers(&manifest_snapshot).await?;

        // ── Decide whether to run ────────────────────────────────────────
        let live_bytes: u64 = live.iter().map(|(_, len)| *len as u64).sum();
        let dead_bytes = vlog_size.saturating_sub(live_bytes);
        let dead_ratio = if vlog_size > 0 {
            dead_bytes as f64 / vlog_size as f64
        } else {
            0.0
        };

        if vlog_size < self.config.min_vlog_size_bytes
            || dead_ratio < self.config.dead_bytes_threshold
        {
            return Ok(GcStats::skipped());
        }

        eprintln!(
            "[Janitor] Starting GC: vlog_size={vlog_size}, live={live_bytes}, dead={dead_bytes} ({:.1}%)",
            dead_ratio * 100.0
        );

        // ── Sort live pointers by offset for sequential I/O ──────────────
        live.sort_unstable_by_key(|(offset, _)| *offset);
        // Deduplicate — the same offset can appear if SSTables haven't been
        // compacted yet (same value referenced from L0 and an immutable MemTable
        // flush that hasn't been cleaned up).
        live.dedup_by_key(|(offset, _)| *offset);

        let gc_path = self.vlog_base_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("vlog_gc.bin");

        let (new_vlog, remap) = self.write_live_values(&current_vlog, &live, &gc_path).await?;

        let (new_level_metas, old_file_ids) =
            self.rebuild_all_sstables(&manifest_snapshot, &remap).await?;
        let sstables_rebuilt = old_file_ids.len();

        // ── Swap vLog reference atomically ────────────────────────────────
        //
        // After this point new writes go to new_vlog.  Old readers still hold
        // an Arc to current_vlog and will finish gracefully — Rust's Arc
        // guarantees the file stays open until the last reference is dropped.
        //
        // Storage-thread mode defers the swap to the reopen step below: the
        // thread owns the fd and must reopen the canonical path (after the
        // rename) before we hand out a handle-backed VLog.
        let old_vlog_path = current_vlog.path().to_path_buf();
        if self.storage_handle.is_none() {
            *self.vlog.write() = new_vlog;
        }

        self.apply_manifest_update(&old_file_ids, &new_level_metas);
        self.reload_level_readers(&new_level_metas).await?;

        // ── Persist manifest ───────────────────────────────────────────────
        let manifest_for_save = self.manifest.read().clone();
        self.manifest_manager.save(&manifest_for_save).await?;

        self.retire_old_sstables(&old_file_ids).await;

        // ── Replace old vLog file with GC file ─────────────────────────────
        //
        // We rename gc_path → canonical path so the next crash-recovery finds
        // the correct file.  The old file is removed only after the rename so
        // there is always at least one valid vLog file on disk.
        tokio::fs::rename(&gc_path, &old_vlog_path).await?;

        // ── Storage-thread mode: reopen the VLog on the canonical path ─────
        //
        // The thread closes the stale (renamed-away) inode's fd — fixing the
        // leak — points at the fresh GC file, refreshes fixed-file slot 1, then
        // we swap in a handle-backed VLog so I/O keeps flowing through the
        // thread instead of silently reverting to tokio::fs.
        if let Some(handle) = &self.storage_handle {
            handle.vlog_reopen(old_vlog_path.clone()).await?;
            *self.vlog.write() = Arc::new(VLog::with_storage_handle(&old_vlog_path, handle.clone()));
        }

        eprintln!(
            "[Janitor] GC complete: reclaimed={dead_bytes} bytes, rebuilt={sstables_rebuilt} SSTables"
        );

        Ok(GcStats {
            ran: true,
            live_bytes,
            reclaimed_bytes: dead_bytes,
            sstables_rebuilt,
        })
    }

    // -----------------------------------------------------------------------
    // GC phases (helpers of run_gc)
    // -----------------------------------------------------------------------

    /// Collects all live value pointers `(offset, len)` from every SSTable.
    ///
    /// Unreadable tables are skipped so a single bad file cannot stall GC forever.
    async fn collect_live_pointers(&self, manifest: &Manifest) -> Result<Vec<(u64, u32)>> {
        let mut live: Vec<(u64, u32)> = Vec::new();

        for level_idx in 0..manifest.levels.len() {
            for meta in manifest.get_level(level_idx) {
                let data = match self.file_manager.read_sstable(meta.file_id).await {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("[Janitor] Cannot read SSTable {}: {e}", meta.file_id);
                        continue;
                    }
                };
                let reader = SSTableReader::open(data)?;
                Self::collect_table_pointers(&reader, &mut live)?;
            }
        }

        Ok(live)
    }

    /// Collects the live vLog pointers of one SSTable into `live`.
    fn collect_table_pointers(reader: &SSTableReader, live: &mut Vec<(u64, u32)>) -> Result<()> {
        for entry in reader.iter() {
            let (_, dbv) = entry?;
            // Only Pointer entries reference the vLog; Inline entries do not.
            if let DataBlockValue::Pointer(vp) = dbv {
                // Skip the tombstone/NULL sentinels (both file_id == 0, kv/018)
                // — neither references vLog bytes.
                if vp.file_id != 0 && vp.value_offset != u64::MAX && vp.value_len > 0 {
                    live.push((vp.value_offset, vp.value_len));
                }
            }
        }
        Ok(())
    }

    /// Writes all live values to a fresh vLog at `gc_path`; returns it together
    /// with the old-offset → new-offset mapping.
    async fn write_live_values(
        &self,
        current_vlog: &VLog,
        live: &[(u64, u32)],
        gc_path: &Path,
    ) -> Result<(Arc<VLog>, HashMap<u64, u64>)> {
        // Remove any stale GC file from a previous crashed run.
        let _ = tokio::fs::remove_file(gc_path).await;

        let new_vlog = Arc::new(VLog::new(gc_path).await?);
        let mut remap: HashMap<u64, u64> = HashMap::with_capacity(live.len());

        for (old_offset, len) in live {
            let value = current_vlog.read(*old_offset, *len as usize).await?;
            let new_offset = new_vlog.append(&value).await?;
            remap.insert(*old_offset, new_offset);
        }

        Ok((new_vlog, remap))
    }

    /// Rebuilds one SSTable with pointers remapped to the new vLog.
    async fn rebuild_sstable(
        &self,
        meta: &SSTableMetadata,
        level_idx: usize,
        remap: &HashMap<u64, u64>,
    ) -> Result<SSTableMetadata> {
        let data = self.file_manager.read_sstable(meta.file_id).await?;
        let reader = SSTableReader::open(data)?;

        let mut builder = SSTableBuilder::new();
        let mut smallest_key: Option<Vec<u8>> = None;
        let mut largest_key: Option<Vec<u8>> = None;

        for entry in reader.iter() {
            let (key, dbv) = entry?;
            let key_vec = key.to_vec();

            if smallest_key.is_none() {
                smallest_key = Some(key_vec.clone());
            }
            largest_key = Some(key_vec.clone());

            match dbv {
                DataBlockValue::Pointer(mut vp) => {
                    // Remap non-tombstone pointers to their new vLog offset.
                    if let Some(&new_offset) = remap.get(&vp.value_offset) {
                        vp.value_offset = new_offset;
                    }
                    builder.add(key_vec, vp);
                }
                DataBlockValue::Inline { data, expire_at } => {
                    // Inline values have no vLog reference — copy as-is.
                    builder.add_inline(key_vec, data, expire_at);
                }
            }
        }

        let sstable_data = builder.finish()?;
        let new_file_id = self.file_manager.allocate_file_id();
        self.file_manager.write_sstable(new_file_id, &sstable_data).await?;

        Ok(SSTableMetadata {
            file_id: new_file_id,
            level: level_idx,
            smallest_key: smallest_key.unwrap_or_default(),
            largest_key: largest_key.unwrap_or_default(),
            file_size: sstable_data.len() as u64,
        })
    }

    /// Rebuilds every SSTable at every level; returns the new per-level
    /// metadata and the replaced `(level, file_id)` pairs.
    async fn rebuild_all_sstables(
        &self,
        manifest: &Manifest,
        remap: &HashMap<u64, u64>,
    ) -> Result<(Vec<Vec<SSTableMetadata>>, Vec<(usize, u64)>)> {
        let num_levels = manifest.levels.len();
        let mut new_level_metas: Vec<Vec<SSTableMetadata>> = Vec::with_capacity(num_levels);
        let mut old_file_ids: Vec<(usize, u64)> = Vec::new();

        for level_idx in 0..num_levels {
            let mut new_level: Vec<SSTableMetadata> = Vec::new();
            for meta in manifest.get_level(level_idx) {
                new_level.push(self.rebuild_sstable(meta, level_idx, remap).await?);
                old_file_ids.push((level_idx, meta.file_id));
            }
            new_level_metas.push(new_level);
        }

        Ok((new_level_metas, old_file_ids))
    }

    /// Applies the GC result to the shared manifest (sync — no await under the lock).
    fn apply_manifest_update(
        &self,
        old_file_ids: &[(usize, u64)],
        new_level_metas: &[Vec<SSTableMetadata>],
    ) {
        let mut manifest = self.manifest.write();
        for (level, file_id) in old_file_ids {
            manifest.remove_sstable(*level, *file_id);
        }
        for level_metas in new_level_metas {
            for meta in level_metas {
                manifest.add_sstable(meta.clone());
            }
        }
    }

    /// Reopens the rebuilt SSTables and swaps them into the level manager.
    async fn reload_level_readers(&self, new_level_metas: &[Vec<SSTableMetadata>]) -> Result<()> {
        for (level_idx, new_metas) in new_level_metas.iter().enumerate() {
            let mut sstables = Vec::new();
            for meta in new_metas {
                sstables.push(Arc::new(
                    LsmStorageEngine::open_sstable_reader(
                        &self.file_manager,
                        meta.file_id,
                        self.use_mmap,
                    )
                    .await?,
                ));
            }
            self.level_manager.replace_level(level_idx, sstables);
        }
        Ok(())
    }

    /// Invalidates cached blocks of the replaced SSTables, then deletes the files.
    async fn retire_old_sstables(&self, old_file_ids: &[(usize, u64)]) {
        // Cache lock scope ends before the await-ing deletes (invalidate before delete).
        {
            let mut cache = self.block_cache.lock();
            for (_, file_id) in old_file_ids {
                cache.invalidate_file(*file_id);
            }
        }
        for (_, file_id) in old_file_ids {
            if let Err(e) = self.file_manager.delete_sstable(*file_id).await {
                eprintln!("[Janitor] Warning: could not delete SSTable {file_id}: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BlockCacheConfig;
    use crate::core::storage_thread::{StorageThread, StorageThreadConfig};
    use crate::storage::format::ValuePointer;

    fn st_config() -> StorageThreadConfig {
        StorageThreadConfig {
            sqpoll_enabled: false,
            sqpoll_idle_ms: 500,
            ring_depth: 64,
            channel_capacity: 256,
            cpu: -1,
        }
    }

    // Finding 3: a GC pass with an active storage thread must leave the vLog
    // reachable *through the thread* — remote append/read keep working after the
    // swap and the reclaimed offsets line up.
    #[tokio::test]
    async fn test_gc_survives_with_storage_thread() {
        let dir = tempfile::TempDir::new().unwrap();
        let wal_path = dir.path().join("wal");
        let vlog_path = dir.path().join("vlog");
        let (mut st, handle) =
            StorageThread::new(st_config(), wal_path, vlog_path.clone()).unwrap();

        // vLog routed through the thread: one live + one dead value (900/1000 dead).
        let vlog = Arc::new(VLog::with_storage_handle(&vlog_path, handle.clone()));
        let live_val = vec![b'L'; 100];
        let live_off = vlog.append(&live_val).await.unwrap();
        vlog.append(&vec![b'D'; 900]).await.unwrap();
        assert_eq!(live_off, 0);
        assert_eq!(vlog.size(), 1000);

        // One SSTable references only the live value.
        let file_manager = Arc::new(FileManager::new(dir.path()).await.unwrap());
        let file_id = file_manager.allocate_file_id();
        let mut builder = SSTableBuilder::new();
        builder.add(
            b"live-key".to_vec(),
            ValuePointer { file_id: 1, value_offset: live_off, value_len: 100, expire_at: 0 },
        );
        let sst = builder.finish().unwrap();
        file_manager.write_sstable(file_id, &sst).await.unwrap();

        let mut manifest = Manifest::new();
        manifest.add_sstable(SSTableMetadata {
            file_id,
            level: 0,
            smallest_key: b"live-key".to_vec(),
            largest_key: b"live-key".to_vec(),
            file_size: sst.len() as u64,
        });
        let manifest = Arc::new(RwLock::new(manifest));

        let level_manager = Arc::new(LevelManager::new());
        level_manager.replace_level(
            0,
            vec![Arc::new(
                LsmStorageEngine::open_sstable_reader(&file_manager, file_id, false)
                    .await
                    .unwrap(),
            )],
        );

        let bc = BlockCacheConfig::default();
        let block_cache = Arc::new(Mutex::new(BlockCache::new(
            bc.capacity_bytes,
            bc.small_ratio,
            bc.ghost_capacity,
        )));
        let vlog_shared = Arc::new(RwLock::new(vlog));

        let janitor = Janitor::new(
            Arc::clone(&vlog_shared),
            vlog_path.clone(),
            level_manager,
            manifest,
            Arc::new(ManifestManager::new(dir.path())),
            file_manager,
            block_cache,
            Arc::new(SnapshotRegistry::new()),
            JanitorConfig { check_interval_secs: 3600, dead_bytes_threshold: 0.3, min_vlog_size_bytes: 1 },
            false,
            Arc::new(AtomicBool::new(false)),
            Some(handle.clone()),
        );

        let stats = janitor.run_gc().await.unwrap();
        assert!(stats.ran, "900/1000 dead bytes must trigger GC");
        assert_eq!(stats.reclaimed_bytes, 900);

        // A handle-backed vLog on the canonical path was swapped in; the live
        // value survives at its remapped offset (0 — first value copied).
        let swapped = vlog_shared.read().clone();
        assert_eq!(swapped.path(), vlog_path.as_path());
        assert_eq!(swapped.read(0, 100).await.unwrap(), live_val);

        // Remote append still routes through the thread and lands after the
        // compacted data; the storage-thread handle sees the same bytes.
        let new_off = swapped.append(b"AFTER-GC").await.unwrap();
        assert_eq!(new_off, 100);
        assert_eq!(swapped.read(new_off, 8).await.unwrap(), b"AFTER-GC");
        assert_eq!(handle.vlog_read(0, 100).await.unwrap(), live_val);

        st.shutdown();
    }

    /// Builds a tokio-fs-path Janitor (no storage thread) over the given fixtures.
    fn build_janitor(
        dir: &std::path::Path,
        vlog_shared: Arc<RwLock<Arc<VLog>>>,
        vlog_path: PathBuf,
        level_manager: Arc<LevelManager>,
        manifest: Arc<RwLock<Manifest>>,
        file_manager: Arc<FileManager>,
        config: JanitorConfig,
    ) -> Janitor {
        let bc = BlockCacheConfig::default();
        Janitor::new(
            vlog_shared,
            vlog_path,
            level_manager,
            manifest,
            Arc::new(ManifestManager::new(dir)),
            file_manager,
            Arc::new(Mutex::new(BlockCache::new(
                bc.capacity_bytes,
                bc.small_ratio,
                bc.ghost_capacity,
            ))),
            Arc::new(SnapshotRegistry::new()),
            config,
            false,
            Arc::new(AtomicBool::new(false)),
            None,
        )
    }

    /// Writes an SSTable of vLog pointers; `entries` = (key, value_offset, value_len), sorted.
    async fn write_pointer_sstable(
        file_manager: &Arc<FileManager>,
        entries: &[(&[u8], u64, u32)],
        level: usize,
    ) -> SSTableMetadata {
        let file_id = file_manager.allocate_file_id();
        let mut builder = SSTableBuilder::new();
        for (key, off, len) in entries {
            builder.add(
                key.to_vec(),
                ValuePointer { file_id: 1, value_offset: *off, value_len: *len, expire_at: 0 },
            );
        }
        let sst = builder.finish().unwrap();
        file_manager.write_sstable(file_id, &sst).await.unwrap();
        SSTableMetadata {
            file_id,
            level,
            smallest_key: entries.first().unwrap().0.to_vec(),
            largest_key: entries.last().unwrap().0.to_vec(),
            file_size: sst.len() as u64,
        }
    }

    // Skip gate: below min size OR below dead-ratio threshold → no-op, nothing touched.
    #[tokio::test]
    async fn test_gc_skips_below_thresholds() {
        let dir = tempfile::TempDir::new().unwrap();
        let vlog_path = dir.path().join("vlog");
        let vlog = Arc::new(VLog::new(&vlog_path).await.unwrap());
        let live_off = vlog.append(&vec![b'L'; 100]).await.unwrap();
        vlog.append(&vec![b'D'; 900]).await.unwrap(); // dead_ratio = 0.9

        let file_manager = Arc::new(FileManager::new(dir.path()).await.unwrap());
        let meta = write_pointer_sstable(&file_manager, &[(b"live-key", live_off, 100)], 0).await;
        let mut manifest = Manifest::new();
        manifest.add_sstable(meta.clone());
        let manifest = Arc::new(RwLock::new(manifest));
        let level_manager = Arc::new(LevelManager::new());
        level_manager.replace_level(
            0,
            vec![Arc::new(
                LsmStorageEngine::open_sstable_reader(&file_manager, meta.file_id, false)
                    .await
                    .unwrap(),
            )],
        );
        let vlog_shared = Arc::new(RwLock::new(vlog));
        let before = vlog_shared.read().clone();

        // (a) vLog smaller than min_vlog_size_bytes.
        let janitor = build_janitor(
            dir.path(),
            Arc::clone(&vlog_shared),
            vlog_path.clone(),
            Arc::clone(&level_manager),
            Arc::clone(&manifest),
            Arc::clone(&file_manager),
            JanitorConfig { check_interval_secs: 3600, dead_bytes_threshold: 0.3, min_vlog_size_bytes: 10_000 },
        );
        let stats = janitor.run_gc().await.unwrap();
        assert!(!stats.ran, "vlog below min size must skip");

        // (b) dead ratio below threshold.
        let janitor = build_janitor(
            dir.path(),
            Arc::clone(&vlog_shared),
            vlog_path.clone(),
            level_manager,
            Arc::clone(&manifest),
            Arc::clone(&file_manager),
            JanitorConfig { check_interval_secs: 3600, dead_bytes_threshold: 0.95, min_vlog_size_bytes: 1 },
        );
        let stats = janitor.run_gc().await.unwrap();
        assert!(!stats.ran, "dead ratio below threshold must skip");
        assert_eq!(stats.sstables_rebuilt, 0);

        // Nothing was touched: same vLog Arc, no GC file, SSTable intact.
        let after = vlog_shared.read().clone();
        assert!(Arc::ptr_eq(&before, &after));
        assert!(!dir.path().join("vlog_gc.bin").exists());
        assert_eq!(manifest.read().get_level(0)[0].file_id, meta.file_id);
        assert!(file_manager.read_sstable(meta.file_id).await.is_ok());
    }

    // Collect-phase read errors are non-fatal: the table is skipped, the cycle continues.
    #[tokio::test]
    async fn test_gc_unreadable_sstable_skipped_not_fatal() {
        let dir = tempfile::TempDir::new().unwrap();
        let vlog_path = dir.path().join("vlog");
        let vlog = Arc::new(VLog::new(&vlog_path).await.unwrap());
        vlog.append(&vec![b'D'; 100]).await.unwrap();

        let file_manager = Arc::new(FileManager::new(dir.path()).await.unwrap());
        let mut manifest = Manifest::new();
        manifest.add_sstable(SSTableMetadata {
            file_id: 999, // no such file on disk
            level: 0,
            smallest_key: b"a".to_vec(),
            largest_key: b"z".to_vec(),
            file_size: 1,
        });

        let janitor = build_janitor(
            dir.path(),
            Arc::new(RwLock::new(vlog)),
            vlog_path,
            Arc::new(LevelManager::new()),
            Arc::new(RwLock::new(manifest)),
            file_manager,
            JanitorConfig { check_interval_secs: 3600, dead_bytes_threshold: 0.3, min_vlog_size_bytes: 10_000 },
        );

        // With `?` instead of `continue` in the collect phase this would be Err.
        let stats = janitor.run_gc().await.unwrap();
        assert!(!stats.ran);
    }

    // Full cycle on the tokio-fs path: multi-level rebuild + duplicate-offset dedup.
    #[tokio::test]
    async fn test_gc_rebuilds_multiple_levels_and_dedups_offsets() {
        let dir = tempfile::TempDir::new().unwrap();
        let vlog_path = dir.path().join("vlog");
        let vlog = Arc::new(VLog::new(&vlog_path).await.unwrap());
        let val_a = vec![b'A'; 100];
        let val_b = vec![b'B'; 100];
        let off_a = vlog.append(&val_a).await.unwrap();
        let off_b = vlog.append(&val_b).await.unwrap();
        vlog.append(&vec![b'D'; 800]).await.unwrap(); // dead
        assert_eq!(vlog.size(), 1000);

        let file_manager = Arc::new(FileManager::new(dir.path()).await.unwrap());
        let l0 = write_pointer_sstable(&file_manager, &[(b"ka", off_a, 100), (b"kb", off_b, 100)], 0).await;
        // L1 references the same off_b → dedup must copy it only once.
        let l1 = write_pointer_sstable(&file_manager, &[(b"kb", off_b, 100)], 1).await;

        let mut manifest = Manifest::new();
        manifest.add_sstable(l0.clone());
        manifest.add_sstable(l1.clone());
        let manifest = Arc::new(RwLock::new(manifest));

        let level_manager = Arc::new(LevelManager::new());
        for meta in [&l0, &l1] {
            level_manager.replace_level(
                meta.level,
                vec![Arc::new(
                    LsmStorageEngine::open_sstable_reader(&file_manager, meta.file_id, false)
                        .await
                        .unwrap(),
                )],
            );
        }
        let vlog_shared = Arc::new(RwLock::new(vlog));

        let janitor = build_janitor(
            dir.path(),
            Arc::clone(&vlog_shared),
            vlog_path.clone(),
            level_manager,
            Arc::clone(&manifest),
            Arc::clone(&file_manager),
            JanitorConfig { check_interval_secs: 3600, dead_bytes_threshold: 0.3, min_vlog_size_bytes: 1 },
        );

        let stats = janitor.run_gc().await.unwrap();
        assert!(stats.ran);
        assert_eq!(stats.sstables_rebuilt, 2);

        // Deduped copy: A at 0, B at 100, nothing else.
        let swapped = vlog_shared.read().clone();
        assert_eq!(swapped.size(), 200);
        assert_eq!(swapped.read(0, 100).await.unwrap(), val_a);
        assert_eq!(swapped.read(100, 100).await.unwrap(), val_b);

        // Both levels rebuilt with remapped pointers; old files deleted.
        let m = manifest.read().clone();
        let expectations: [(usize, &SSTableMetadata, Vec<(Vec<u8>, u64)>); 2] = [
            (0, &l0, vec![(b"ka".to_vec(), 0), (b"kb".to_vec(), 100)]),
            (1, &l1, vec![(b"kb".to_vec(), 100)]),
        ];
        for (level, old, expected) in expectations {
            let metas = m.get_level(level);
            assert_eq!(metas.len(), 1);
            assert_ne!(metas[0].file_id, old.file_id);
            let data = file_manager.read_sstable(metas[0].file_id).await.unwrap();
            let reader = SSTableReader::open(data).unwrap();
            let mut got: Vec<(Vec<u8>, u64)> = Vec::new();
            for entry in reader.iter() {
                let (key, dbv) = entry.unwrap();
                match dbv {
                    DataBlockValue::Pointer(vp) => got.push((key.to_vec(), vp.value_offset)),
                    _ => panic!("Expected Pointer variant"),
                }
            }
            assert_eq!(got, expected);
            assert!(
                file_manager.read_sstable(old.file_id).await.is_err(),
                "old SSTable must be deleted"
            );
        }

        // GC file renamed onto the canonical path.
        assert!(!dir.path().join("vlog_gc.bin").exists());
        assert!(vlog_path.exists());
    }
}
