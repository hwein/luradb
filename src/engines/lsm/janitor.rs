//! Value Log Garbage Collector — the Janitor.
//!
//! The vLog is append-only: deleted and overwritten values accumulate as *dead*
//! bytes that are never reclaimed by the compaction process (which only rewrites
//! the SSTable index, not the vLog payloads).
//!
//! The Janitor runs as a background Tokio task and reclaims dead space by
//! rolling the vLog forward one *generation* per cycle (spec kv/017):
//!
//! 1. Gate on the estimated dead-byte ratio; below the threshold, skip.
//! 2. Open generation `N+1` and publish it as the active append target,
//!    together with a fresh MemTable.
//! 3. Seal every generation `<= N`, so no new pointer into them can appear.
//! 4. Flush barrier: freeze and flush all MemTables, so every remaining
//!    pointer into `<= N` resides in an SSTable.
//! 5. Snapshot the manifest and collect the live `(file_id, offset, len)` set.
//! 6. Copy those values into `N+1`, recording the remap.
//! 7. Rebuild every snapshot SSTable with the remapped pointers.
//! 8. Install a version without the old generations; each file is deleted
//!    once no version holds its generation any more (spec kv/031 A5).
//! 9. With a storage thread, roll one more generation that the thread owns, so
//!    thread and local writers never append to the same file.
//!
//! All steps are performed without holding any write-path locks for extended
//! periods, so normal reads and writes are never stalled.

use crate::core::storage_thread::StorageHandle;
use crate::engines::lsm::block_cache::StripedBlockCache;
use crate::engines::lsm::engine::LsmStorageEngine;
#[cfg(test)]
use crate::engines::lsm::engine::TestHook;
use crate::engines::lsm::reader::SnapshotRegistry;
use crate::engines::lsm::version::VersionCell;
use crate::storage::file_manager::FileManager;
use crate::storage::format::DataBlockValue;
use crate::storage::manifest::{Manifest, ManifestManager, SSTableMetadata};
use crate::storage::sstable::{SSTableBuilder, SSTableReader};
use crate::storage::vlog::{generation_path, VLog};
use anyhow::Result;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}};
use tokio::sync::watch;
use tokio::time::{sleep, Duration};

/// Engine callback that freezes and flushes every MemTable. Injected at
/// construction because the Janitor knows nothing about MemTables.
pub type FlushBarrier =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>;

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
    /// Number of live bytes copied to the new generation.
    pub live_bytes: u64,
    /// Live bytes copied out of each source generation.
    pub live_bytes_by_generation: Vec<(u32, u64)>,
    /// Number of dead bytes reclaimed by dropping the source generations.
    pub reclaimed_bytes: u64,
    /// Number of SSTables rebuilt with updated pointers.
    pub sstables_rebuilt: usize,
    /// Generation the live values were copied into.
    pub new_generation: u32,
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
    /// The engine's version: the GC reads the vLog generations from it and
    /// installs every change it makes (spec kv/031 A1).
    version: Arc<VersionCell>,

    /// Canonical vLog path — generation 1 and base for every later generation.
    vlog_base_path: PathBuf,

    manifest: Arc<RwLock<Manifest>>,
    manifest_manager: Arc<ManifestManager>,
    file_manager: Arc<FileManager>,

    /// Shared block cache — entries of SSTables replaced by GC are invalidated.
    block_cache: Arc<StripedBlockCache>,

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

    /// Incremented once per GC cycle that actually ran (`GcStats::ran ==
    /// true`) -- shared with `LsmStorageEngine::janitor_runs` for the
    /// `/metrics` system block (spec general/024).
    janitor_runs: Arc<AtomicU64>,

    /// Drains all MemTables before the live scan. `None` only for fixtures
    /// that have no MemTables at all.
    flush_barrier: Option<FlushBarrier>,

    /// The engine's flush lock: held over the manifest swap and the level
    /// install, it keeps a flush from installing an SSTable the reload would
    /// not see (spec general/029). `None` only for fixtures without an engine.
    flush_lock: Option<Arc<tokio::sync::Mutex<()>>>,

    /// The engine's maintenance lock: held over a whole GC cycle, it keeps a
    /// compaction from entering the manifest between the live scan and the
    /// retire (spec general/029). `None` only for fixtures without an engine.
    maintenance_lock: Option<Arc<tokio::sync::Mutex<()>>>,

    /// The engine's write drain (`in_flight_writes`): held while a new active
    /// generation and its fresh MemTable are installed, so no writer sits
    /// between its stamp and its apply across that rotation (spec kv/029).
    /// `None` only for fixtures without writers.
    write_drain: Option<Arc<tokio::sync::RwLock<()>>>,

    /// Generations already out of the current version whose files wait until
    /// no older version holds them (spec kv/031 A5).
    retired: Mutex<Vec<Arc<VLog>>>,

    /// Test-only pause point between opening the rebuilt readers and
    /// installing them (spec general/028).
    #[cfg(test)]
    install_hook: Option<Arc<TestHook>>,

    /// Test-only pause point after the rebuild and before the flush lock —
    /// the window a whole flush fits into (spec general/029).
    #[cfg(test)]
    before_manifest_swap_hook: Option<Arc<TestHook>>,
}

impl Janitor {
    /// Creates a new Janitor.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        version: Arc<VersionCell>,
        vlog_base_path: PathBuf,
        manifest: Arc<RwLock<Manifest>>,
        manifest_manager: Arc<ManifestManager>,
        file_manager: Arc<FileManager>,
        block_cache: Arc<StripedBlockCache>,
        snapshot_registry: Arc<SnapshotRegistry>,
        config: JanitorConfig,
        use_mmap: bool,
        shutdown: Arc<AtomicBool>,
        storage_handle: Option<StorageHandle>,
        janitor_runs: Arc<AtomicU64>,
        flush_barrier: Option<FlushBarrier>,
        flush_lock: Option<Arc<tokio::sync::Mutex<()>>>,
        maintenance_lock: Option<Arc<tokio::sync::Mutex<()>>>,
        write_drain: Option<Arc<tokio::sync::RwLock<()>>>,
    ) -> Self {
        Self {
            version,
            vlog_base_path,
            manifest,
            manifest_manager,
            file_manager,
            block_cache,
            snapshot_registry,
            config,
            use_mmap,
            shutdown,
            storage_handle,
            janitor_runs,
            flush_barrier,
            flush_lock,
            maintenance_lock,
            write_drain,
            retired: Mutex::new(Vec::new()),
            #[cfg(test)]
            install_hook: None,
            #[cfg(test)]
            before_manifest_swap_hook: None,
        }
    }

    /// Parks the next [`Self::reload_level_readers`] right before it installs
    /// the rebuilt levels (spec general/028).
    #[cfg(test)]
    pub(crate) fn set_install_hook(&mut self, hook: Arc<TestHook>) {
        self.install_hook = Some(hook);
    }

    /// Parks the next [`Self::run_gc`] after its rebuild, before it takes the
    /// flush lock — a flush released here reaches the manifest in full, which
    /// the snapshot the rebuild worked on never listed (spec general/029).
    #[cfg(test)]
    pub(crate) fn set_before_manifest_swap_hook(&mut self, hook: Arc<TestHook>) {
        self.before_manifest_swap_hook = Some(hook);
    }

    // -----------------------------------------------------------------------
    // Background loop
    // -----------------------------------------------------------------------

    /// Runs the Janitor's periodic GC loop.
    ///
    /// Intended to be spawned as a Tokio task via `tokio::spawn`. `shutdown_rx`
    /// wakes the loop immediately on shutdown (spec general/023 M2) instead of
    /// sleeping out the full `check_interval_secs`, which defaults to 60s.
    pub async fn run_background(self: Arc<Self>, mut shutdown_rx: watch::Receiver<bool>) {
        let interval = Duration::from_secs(self.config.check_interval_secs);
        while !self.shutdown.load(Ordering::Relaxed) {
            tokio::select! {
                _ = sleep(interval) => {}
                _ = shutdown_rx.changed() => {}
            }

            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }

            if let Err(e) = self.run_gc().await {
                eprintln!("[Janitor] GC cycle failed: {e}");
            }
        }

        // The rest goes now; a reader still holding one keeps reading from its
        // open descriptor.
        self.delete_retired_generations(true).await;
    }

    // -----------------------------------------------------------------------
    // GC cycle
    // -----------------------------------------------------------------------

    /// Runs one GC cycle.
    ///
    /// Returns [`GcStats`] describing what happened.  If the dead-byte ratio
    /// is below the threshold the cycle is a no-op. Every run, a skipped one
    /// included, first deletes the retired generations no version holds any
    /// more.
    pub async fn run_gc(&self) -> Result<GcStats> {
        self.delete_retired_generations(false).await;

        let (source_ids, vlog_size) = {
            let version = self.version.get();
            (version.vlog_ids(), version.vlog_size())
        };

        // ── Decide whether to run ────────────────────────────────────────
        //
        // Trigger heuristic only: values that are still MemTable-resident count
        // as dead here, which can make the GC run earlier but never costs data
        // (the authoritative live set is collected after the barrier below).
        let probe = self.manifest.read().clone();
        let probe_live: u64 = self
            .collect_live_pointers(&probe)
            .await?
            .iter()
            .map(|(_, _, len)| *len as u64)
            .sum();
        let dead_bytes = vlog_size.saturating_sub(probe_live);
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
            "[Janitor] Starting GC: generations={source_ids:?}, vlog_size={vlog_size}, dead(est)={dead_bytes} ({:.1}%)",
            dead_ratio * 100.0
        );

        // Whole cycle under the maintenance lock, barrier included: no
        // compaction can enter the manifest between the live scan below and
        // the retire at the end, so nothing the scan never saw survives into
        // the generations this cycle deletes (spec general/029). Taken before
        // the flush lock, never after it.
        let _maintenance = match &self.maintenance_lock {
            Some(lock) => Some(lock.lock().await),
            None => None,
        };

        // ── Roll forward to a fresh generation ───────────────────────────
        //
        // New writes land here from now on; `u32` overflow needs 4 billion GC
        // cycles on one store and is unreachable in practice.
        let new_id = source_ids.iter().max().copied().unwrap_or(0) + 1;
        let new_path = generation_path(&self.vlog_base_path, new_id);
        let new_vlog = Arc::new(VLog::open(&new_path, new_id).await?);
        self.activate(Arc::clone(&new_vlog)).await;

        // Invariant 1: seal AFTER publishing N+1 and BEFORE the flush barrier.
        // A racing append then fails with `Sealed` and retries against N+1, so
        // the set of pointers into the old generations is closed from here on.
        {
            let version = self.version.get();
            for id in &source_ids {
                if let Some(vlog) = version.vlog.get(id) {
                    vlog.seal();
                }
            }
        }

        // Flush barrier: drains every MemTable-resident pointer into an
        // SSTable — without it the live scan below would miss them.
        if let Some(barrier) = &self.flush_barrier {
            barrier().await?;
        }

        // Invariant 2: snapshot the manifest AFTER the barrier — a snapshot
        // taken earlier would not list the tables the barrier just wrote.
        let manifest_snapshot = self.manifest.read().clone();
        let mut live = self.collect_live_pointers(&manifest_snapshot).await?;
        // Pointers already in N+1 (a concurrent flush can have landed them in a
        // snapshot table) stay untouched.
        live.retain(|(file_id, _, _)| source_ids.contains(file_id));
        live.sort_unstable();
        // Deduplicate — the same value can be referenced from several SSTables.
        live.dedup_by_key(|(file_id, offset, _)| (*file_id, *offset));

        let remap = self.copy_live_values(&live, &new_vlog).await?;

        let (new_level_metas, old_file_ids) =
            self.rebuild_all_sstables(&manifest_snapshot, &remap, new_id).await?;
        let sstables_rebuilt = old_file_ids.len();

        #[cfg(test)]
        if let Some(hook) = &self.before_manifest_swap_hook {
            hook.pause().await;
        }

        let retired = {
            // Manifest swap and level install under the flush lock: what the
            // reload reads from the manifest is exactly what the read path
            // ends up with, an SSTable flushed since the snapshot included
            // (spec general/029).
            let _flush = match &self.flush_lock {
                Some(lock) => Some(lock.lock().await),
                None => None,
            };
            self.apply_manifest_update(&old_file_ids, &new_level_metas);
            self.reload_level_readers().await?
        };

        // ── Persist manifest ───────────────────────────────────────────────
        let manifest_for_save = self.manifest.read().clone();
        self.manifest_manager.save(&manifest_for_save).await?;

        self.retire_old_sstables(&retired, &old_file_ids).await;

        // ── Drop the source generations ────────────────────────────────────
        //
        // No SSTable references them anymore. A reader's version that still
        // holds one keeps its file until that version is dropped.
        let live_bytes_by_generation = live_bytes_per_generation(&source_ids, &live);
        let live_bytes: u64 = live_bytes_by_generation.iter().map(|(_, b)| *b).sum();
        let reclaimed_bytes = self.retire_generations(&source_ids).await.saturating_sub(live_bytes);

        // ── Storage-thread mode (perf/005) ─────────────────────────────────
        //
        // The thread owns a single vLog fd, still pointing at a retired
        // generation. It must not take over `N+1`: writers append there through
        // a local cursor, while the thread seeds its own cursor from the file
        // length at reopen time — everything written after that stat would be
        // overwritten. Roll one more generation that only the thread writes.
        // Reads never use the thread's fd (spec kv/031 A5), so the reopen
        // leaves every reader of a source generation on its own descriptor.
        if let Some(handle) = &self.storage_handle {
            let thread_id = new_id + 1;
            let thread_path = generation_path(&self.vlog_base_path, thread_id);
            handle.vlog_reopen(thread_path.clone(), thread_id).await?;
            self.activate(Arc::new(VLog::with_storage_handle(&thread_path, handle.clone(), thread_id)?))
                .await;
            // Invariant 1 again: seal only after publishing. In-flight appends
            // past the seal check finish alone in the local file, later fetches
            // retry against `N+2`. `N+1` stays registered and readable; the next
            // cycle collects it.
            new_vlog.seal();
        }

        eprintln!(
            "[Janitor] GC complete: generation {new_id} took over {live_bytes} live bytes \
             {live_bytes_by_generation:?}, reclaimed={reclaimed_bytes} bytes, \
             rebuilt={sstables_rebuilt} SSTables"
        );

        // Counts actually-run cycles only (mirrors `GcStats::ran`), not
        // threshold checks that skipped -- otherwise this would be an uptime
        // counter instead of an activity signal (spec general/024). Placed
        // here rather than only in the background loop so direct `run_gc`
        // callers (tests, future triggers) count too.
        self.janitor_runs.fetch_add(1, Ordering::Relaxed);

        Ok(GcStats {
            ran: true,
            live_bytes,
            live_bytes_by_generation,
            reclaimed_bytes,
            sstables_rebuilt,
            new_generation: new_id,
        })
    }

    // -----------------------------------------------------------------------
    // GC phases (helpers of run_gc)
    // -----------------------------------------------------------------------

    /// Installs `vlog` as the active generation with a fresh MemTable, under
    /// the engine's write drain (see [`Self::write_drain`]).
    async fn activate(&self, vlog: Arc<VLog>) {
        let _drain = match &self.write_drain {
            Some(drain) => Some(drain.write().await),
            None => None,
        };
        self.version.install(|v| v.with_active_vlog(vlog));
    }

    /// Collects all live value pointers `(file_id, offset, len)` from every
    /// SSTable.
    ///
    /// Unreadable tables are skipped so a single bad file cannot stall GC forever.
    async fn collect_live_pointers(&self, manifest: &Manifest) -> Result<Vec<(u32, u64, u32)>> {
        let mut live: Vec<(u32, u64, u32)> = Vec::new();

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
    fn collect_table_pointers(reader: &SSTableReader, live: &mut Vec<(u32, u64, u32)>) -> Result<()> {
        for entry in reader.iter() {
            let (_, dbv) = entry?;
            // Only Pointer entries reference the vLog; Inline entries do not.
            if let DataBlockValue::Pointer(vp) = dbv {
                // Skip the tombstone/NULL sentinels (both file_id == 0, kv/018)
                // — neither references vLog bytes.
                if vp.file_id != 0 && vp.value_offset != u64::MAX && vp.value_len > 0 {
                    live.push((vp.file_id, vp.value_offset, vp.value_len));
                }
            }
        }
        Ok(())
    }

    /// Copies every live value into `target`, returning the
    /// `(source generation, old offset) → new offset` remap. Keying on the
    /// generation makes the remap collision-free against pointers that already
    /// live in the target generation.
    async fn copy_live_values(
        &self,
        live: &[(u32, u64, u32)],
        target: &Arc<VLog>,
    ) -> Result<HashMap<(u32, u64), u64>> {
        let mut remap: HashMap<(u32, u64), u64> = HashMap::with_capacity(live.len());
        let version = self.version.get();
        for (file_id, old_offset, len) in live {
            let source = version.vlog.get(file_id).ok_or_else(|| {
                anyhow::anyhow!("live pointer references unknown vLog generation {file_id}")
            })?;
            // On the blocking pool: the values a GC copies are mostly cold.
            let (source, offset, len) = (Arc::clone(source), *old_offset, *len as usize);
            let value = tokio::task::spawn_blocking(move || source.read(offset, len)).await??;
            let new_offset = target.append(&value).await?;
            remap.insert((*file_id, *old_offset), new_offset);
        }
        Ok(remap)
    }

    /// Installs a version without the source generations and queues them for
    /// deletion; returns the total number of bytes they held.
    async fn retire_generations(&self, source_ids: &[u32]) -> u64 {
        let mut retired = Vec::new();
        self.version.install(|v| {
            let mut next = v.clone();
            let generations = Arc::make_mut(&mut next.vlog);
            retired.extend(source_ids.iter().filter_map(|id| generations.remove(id)));
            next
        });
        let removed_bytes = retired.iter().map(|vlog| vlog.size()).sum();
        self.retired.lock().extend(retired);
        self.delete_retired_generations(false).await;
        removed_bytes
    }

    /// Deletes the files of retired generations. Without `held_too`, only
    /// those the queue holds the last reference to: a reader's version that
    /// still names one keeps it.
    async fn delete_retired_generations(&self, held_too: bool) {
        let doomed: Vec<Arc<VLog>> = {
            let mut retired = self.retired.lock();
            let (doomed, kept) = retired.drain(..).partition(|vlog| held_too || Arc::strong_count(vlog) == 1);
            *retired = kept;
            doomed
        };
        for vlog in doomed {
            if let Err(e) = tokio::fs::remove_file(vlog.path()).await {
                eprintln!("[Janitor] Warning: could not delete vLog generation {}: {e}", vlog.id());
            }
        }
    }

    /// Rebuilds one SSTable with pointers remapped into generation `new_id`.
    async fn rebuild_sstable(
        &self,
        meta: &SSTableMetadata,
        level_idx: usize,
        remap: &HashMap<(u32, u64), u64>,
        new_id: u32,
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
                    // Only pointers into a collected generation move; sentinels
                    // and pointers already in `new_id` miss the remap key.
                    if let Some(&new_offset) = remap.get(&(vp.file_id, vp.value_offset)) {
                        vp.value_offset = new_offset;
                        vp.file_id = new_id;
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
            // Same entries, only their vLog pointers move.
            max_timestamp: meta.max_timestamp,
        })
    }

    /// Rebuilds every SSTable at every level; returns the new per-level
    /// metadata and the replaced `(level, file_id)` pairs.
    async fn rebuild_all_sstables(
        &self,
        manifest: &Manifest,
        remap: &HashMap<(u32, u64), u64>,
        new_id: u32,
    ) -> Result<(Vec<Vec<SSTableMetadata>>, Vec<(usize, u64)>)> {
        let num_levels = manifest.levels.len();
        let mut new_level_metas: Vec<Vec<SSTableMetadata>> = Vec::with_capacity(num_levels);
        let mut old_file_ids: Vec<(usize, u64)> = Vec::new();

        for level_idx in 0..num_levels {
            let mut new_level: Vec<SSTableMetadata> = Vec::new();
            for meta in manifest.get_level(level_idx) {
                new_level.push(self.rebuild_sstable(meta, level_idx, remap, new_id).await?);
                old_file_ids.push((level_idx, meta.file_id));
            }
            new_level_metas.push(new_level);
        }

        Ok((new_level_metas, old_file_ids))
    }

    /// Applies the GC result to the shared manifest (sync — no await under the lock).
    ///
    /// Every rebuild carries the content of a snapshot table and is therefore
    /// older than anything flushed since; L0 is read newest-last, so they go in
    /// front of what the level gained meanwhile (spec general/029).
    fn apply_manifest_update(
        &self,
        old_file_ids: &[(usize, u64)],
        new_level_metas: &[Vec<SSTableMetadata>],
    ) {
        let mut manifest = self.manifest.write();
        for (level, file_id) in old_file_ids {
            manifest.remove_sstable(*level, *file_id);
        }
        for (level, level_metas) in new_level_metas.iter().enumerate() {
            manifest.prepend_sstables(level, level_metas.clone());
        }
    }

    /// Swaps in readers for every level of the current manifest — the rebuilt
    /// tables plus whatever else the manifest gained meanwhile — and returns
    /// the readers the install dropped. A table the version already holds
    /// keeps its reader (see [`LsmStorageEngine::level_readers`]).
    ///
    /// Every level keeps its old readers until all new ones are open, then
    /// they change in one install (spec general/028, kv/031 A1).
    async fn reload_level_readers(&self) -> Result<Vec<Arc<SSTableReader>>> {
        let current = self.version.get();
        let num_levels = self.manifest.read().levels.len();
        let mut updates = Vec::with_capacity(num_levels);
        for level_idx in 0..num_levels {
            let metas = self.manifest.read().get_level(level_idx).to_vec();
            let sstables =
                LsmStorageEngine::level_readers(&self.file_manager, &current, &metas, self.use_mmap).await?;
            updates.push((level_idx, sstables));
        }

        #[cfg(test)]
        if let Some(hook) = &self.install_hook {
            hook.pause().await;
        }

        let mut dropped = Vec::new();
        self.version.install(|v| {
            let next = v.with_levels(updates);
            dropped = v.sstables_dropped_by(&next);
            next
        });
        Ok(dropped)
    }

    /// Retires the dropped readers, invalidates cached blocks of the replaced
    /// SSTables, then deletes the files.
    async fn retire_old_sstables(&self, retired: &[Arc<SSTableReader>], old_file_ids: &[(usize, u64)]) {
        for reader in retired {
            reader.retire();
        }
        for (_, file_id) in old_file_ids {
            self.block_cache.invalidate_file(*file_id);
        }
        for (_, file_id) in old_file_ids {
            if let Err(e) = self.file_manager.delete_sstable(*file_id).await {
                eprintln!("[Janitor] Warning: could not delete SSTable {file_id}: {e}");
            }
        }
    }
}

/// Live bytes per source generation, one entry per generation (0 when nothing
/// of it survived).
fn live_bytes_per_generation(source_ids: &[u32], live: &[(u32, u64, u32)]) -> Vec<(u32, u64)> {
    source_ids
        .iter()
        .map(|id| {
            let bytes = live
                .iter()
                .filter(|(file_id, _, _)| file_id == id)
                .map(|(_, _, len)| *len as u64)
                .sum();
            (*id, bytes)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BlockCacheConfig;
    use crate::core::storage_thread::{StorageThread, StorageThreadConfig};
    use crate::engines::lsm::version::Version;
    use crate::storage::format::ValuePointer;
    use crate::storage::vlog::VLogError;

    /// The engine-less fixtures' state: `vlog` as the only generation, plus
    /// `levels`.
    fn version_over(vlog: Arc<VLog>, levels: Vec<(usize, Vec<Arc<SSTableReader>>)>) -> Arc<VersionCell> {
        Arc::new(VersionCell::new(Version::new(vlog).with_levels(levels)))
    }

    fn st_config() -> StorageThreadConfig {
        StorageThreadConfig {
            sqpoll_enabled: false,
            sqpoll_idle_ms: 500,
            ring_depth: 64,
            channel_capacity: 256,
            cpu: -1,
        }
    }

    /// Everything a storage-thread GC test needs; `st` must be shut down last.
    struct StFixture {
        st: StorageThread,
        vlog_path: PathBuf,
        version: Arc<VersionCell>,
        janitor: Janitor,
        live_val: Vec<u8>,
    }

    /// Generation 1 routed through the storage thread with one live (100 B) and
    /// one dead (900 B) value, plus one SSTable naming the live one.
    async fn storage_thread_fixture(dir: &std::path::Path) -> StFixture {
        let vlog_path = dir.join("vlog");
        let (st, handle) =
            StorageThread::new(st_config(), dir.join("wal"), vlog_path.clone()).unwrap();

        let vlog = Arc::new(VLog::with_storage_handle(&vlog_path, handle.clone(), 1).unwrap());
        let live_val = vec![b'L'; 100];
        let live_off = vlog.append(&live_val).await.unwrap();
        vlog.append(&vec![b'D'; 900]).await.unwrap();
        assert_eq!(live_off, 0);
        assert_eq!(vlog.size(), 1000);

        let file_manager = Arc::new(FileManager::new(dir).await.unwrap());
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
            max_timestamp: 0,
        });
        let manifest = Arc::new(RwLock::new(manifest));

        let reader = LsmStorageEngine::open_sstable_reader(&file_manager, file_id, false).await.unwrap();
        let version = version_over(vlog, vec![(0, vec![Arc::new(reader)])]);

        let bc = BlockCacheConfig::default();
        let block_cache = Arc::new(StripedBlockCache::new(bc.capacity_bytes, bc.small_ratio, bc.ghost_capacity));

        let janitor = Janitor::new(
            Arc::clone(&version),
            vlog_path.clone(),
            manifest,
            Arc::new(ManifestManager::new(dir)),
            file_manager,
            block_cache,
            Arc::new(SnapshotRegistry::new()),
            JanitorConfig { check_interval_secs: 3600, dead_bytes_threshold: 0.3, min_vlog_size_bytes: 1 },
            false,
            Arc::new(AtomicBool::new(false)),
            Some(handle.clone()),
            Arc::new(AtomicU64::new(0)),
            None,
            None,
            None,
            None,
        );

        StFixture { st, vlog_path, version, janitor, live_val }
    }

    // Finding 3: a GC pass with an active storage thread must leave the vLog
    // reachable *through the thread* — remote append/read keep working after the
    // swap and the reclaimed offsets line up.
    #[tokio::test]
    async fn test_gc_survives_with_storage_thread() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut fx = storage_thread_fixture(dir.path()).await;

        let stats = fx.janitor.run_gc().await.unwrap();
        assert!(stats.ran, "900/1000 dead bytes must trigger GC");
        assert_eq!(stats.reclaimed_bytes, 900);
        assert_eq!(stats.new_generation, 2, "live values were copied into 2");

        // The thread rolled a further generation instead of taking over the
        // copy target; both stay registered.
        let version = fx.version.get();
        let swapped = Arc::clone(&version.active_vlog);
        assert_eq!(swapped.id(), 3);
        assert_eq!(swapped.path(), generation_path(&fx.vlog_path, 3));
        assert_eq!(version.vlog_ids(), vec![2, 3]);

        // The live value survives at its remapped offset (0 — first value
        // copied) in the copy generation, which is sealed.
        assert_eq!(version.vlog[&2].read(0, 100).unwrap(), fx.live_val);
        assert!(version.vlog[&2].is_sealed());

        // Remote append still routes through the thread and starts at 0 in the
        // fresh generation, the thread's own file.
        let new_off = swapped.append(b"AFTER-GC").await.unwrap();
        assert_eq!(new_off, 0);
        assert_eq!(swapped.read(new_off, 8).unwrap(), b"AFTER-GC");
        assert_eq!(std::fs::read(generation_path(&fx.vlog_path, 3)).unwrap(), b"AFTER-GC");

        fx.st.shutdown();
    }

    // Spec kv/031 test 7 (storage thread): reads never go through the thread,
    // so a source generation held across the GC still reads its own file,
    // which stays on disk until the holder lets go.
    #[tokio::test]
    async fn test_gc_keeps_a_held_source_generation_readable_until_released() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut fx = storage_thread_fixture(dir.path()).await;
        let held = Arc::clone(&fx.version.get().vlog[&1]);

        assert!(fx.janitor.run_gc().await.unwrap().ran);
        assert!(!fx.version.get().vlog.contains_key(&1), "generation 1 is retired");
        assert_eq!(held.read(0, 100).unwrap(), fx.live_val, "the thread has moved on to generation 3");
        assert!(fx.vlog_path.exists(), "a holder keeps the file");

        drop(held);
        assert!(!fx.janitor.run_gc().await.unwrap().ran, "nothing left to collect");
        assert!(!fx.vlog_path.exists(), "the next run deletes the released generation");

        fx.st.shutdown();
    }

    // The two writers of a GC cycle never share a file: the thread owns its own
    // generation, so its appends cannot land on top of the copy target.
    #[tokio::test]
    async fn test_gc_storage_thread_generation_is_disjoint_from_copy_target() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut fx = storage_thread_fixture(dir.path()).await;
        assert!(fx.janitor.run_gc().await.unwrap().ran);

        // A late writer still holding the copy generation is bounced to the
        // active one instead of writing a second cursor into that file.
        let version = fx.version.get();
        let copy_gen = Arc::clone(&version.vlog[&2]);
        let active = Arc::clone(&version.active_vlog);
        assert_ne!(copy_gen.path(), active.path());
        assert!(matches!(copy_gen.append(b"late").await, Err(VLogError::Sealed { id: 2 })));

        let copy_len = std::fs::metadata(copy_gen.path()).unwrap().len();
        assert_eq!(copy_len, 100);

        // Thread appends fill the fresh generation from offset 0 and leave the
        // copy generation byte-identical.
        for i in 0..4u64 {
            assert_eq!(active.append(&[b'T'; 10]).await.unwrap(), i * 10);
        }
        assert_eq!(std::fs::metadata(active.path()).unwrap().len(), 40);
        assert_eq!(std::fs::metadata(copy_gen.path()).unwrap().len(), copy_len);
        assert_eq!(copy_gen.read(0, 100).unwrap(), fx.live_val);

        fx.st.shutdown();
    }

    /// Builds a tokio-fs-path Janitor (no storage thread) over the given
    /// fixtures. No flush barrier: these fixtures have no MemTables.
    /// `janitor_runs` is passed straight through, so a caller that wants to
    /// inspect it keeps its own clone.
    fn build_janitor(
        dir: &std::path::Path,
        version: Arc<VersionCell>,
        vlog_path: PathBuf,
        manifest: Arc<RwLock<Manifest>>,
        file_manager: Arc<FileManager>,
        config: JanitorConfig,
        janitor_runs: Arc<AtomicU64>,
    ) -> Janitor {
        let bc = BlockCacheConfig::default();
        Janitor::new(
            version,
            vlog_path,
            manifest,
            Arc::new(ManifestManager::new(dir)),
            file_manager,
            Arc::new(StripedBlockCache::new(bc.capacity_bytes, bc.small_ratio, bc.ghost_capacity)),
            Arc::new(SnapshotRegistry::new()),
            config,
            false,
            Arc::new(AtomicBool::new(false)),
            None,
            janitor_runs,
            None,
            None,
            None,
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
            max_timestamp: 0,
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
        let reader = LsmStorageEngine::open_sstable_reader(&file_manager, meta.file_id, false).await.unwrap();
        let version = version_over(vlog, vec![(0, vec![Arc::new(reader)])]);
        let before = Arc::clone(&version.get().active_vlog);
        let janitor_runs = Arc::new(AtomicU64::new(0));

        // (a) vLog smaller than min_vlog_size_bytes.
        let janitor = build_janitor(
            dir.path(),
            Arc::clone(&version),
            vlog_path.clone(),
            Arc::clone(&manifest),
            Arc::clone(&file_manager),
            JanitorConfig { check_interval_secs: 3600, dead_bytes_threshold: 0.3, min_vlog_size_bytes: 10_000 },
            Arc::clone(&janitor_runs),
        );
        let stats = janitor.run_gc().await.unwrap();
        assert!(!stats.ran, "vlog below min size must skip");

        // (b) dead ratio below threshold.
        let janitor = build_janitor(
            dir.path(),
            Arc::clone(&version),
            vlog_path.clone(),
            Arc::clone(&manifest),
            Arc::clone(&file_manager),
            JanitorConfig { check_interval_secs: 3600, dead_bytes_threshold: 0.95, min_vlog_size_bytes: 1 },
            Arc::clone(&janitor_runs),
        );
        let stats = janitor.run_gc().await.unwrap();
        assert!(!stats.ran, "dead ratio below threshold must skip");
        assert_eq!(stats.sstables_rebuilt, 0);
        assert_eq!(janitor_runs.load(Ordering::Relaxed), 0, "skip cycles (ran == false) must not increment janitor_runs");

        // Nothing was touched: same vLog Arc, no new generation, SSTable intact.
        let after = Arc::clone(&version.get().active_vlog);
        assert!(Arc::ptr_eq(&before, &after));
        assert!(!generation_path(&vlog_path, 2).exists());
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
            max_timestamp: 0,
        });

        let janitor = build_janitor(
            dir.path(),
            version_over(vlog, Vec::new()),
            vlog_path,
            Arc::new(RwLock::new(manifest)),
            file_manager,
            JanitorConfig { check_interval_secs: 3600, dead_bytes_threshold: 0.3, min_vlog_size_bytes: 10_000 },
            Arc::new(AtomicU64::new(0)),
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

        let mut levels = Vec::new();
        for meta in [&l0, &l1] {
            let reader = LsmStorageEngine::open_sstable_reader(&file_manager, meta.file_id, false).await.unwrap();
            levels.push((meta.level, vec![Arc::new(reader)]));
        }
        let version = version_over(vlog, levels);
        let janitor_runs = Arc::new(AtomicU64::new(0));

        let janitor = build_janitor(
            dir.path(),
            Arc::clone(&version),
            vlog_path.clone(),
            Arc::clone(&manifest),
            Arc::clone(&file_manager),
            JanitorConfig { check_interval_secs: 3600, dead_bytes_threshold: 0.3, min_vlog_size_bytes: 1 },
            Arc::clone(&janitor_runs),
        );

        let stats = janitor.run_gc().await.unwrap();
        assert!(stats.ran);
        assert_eq!(stats.sstables_rebuilt, 2);
        assert_eq!(stats.live_bytes_by_generation, vec![(1, 200)]);
        assert_eq!(janitor_runs.load(Ordering::Relaxed), 1, "a ran == true cycle must increment janitor_runs");

        // Deduped copy: A at 0, B at 100, nothing else.
        let swapped = Arc::clone(&version.get().active_vlog);
        assert_eq!(swapped.size(), 200);
        assert_eq!(swapped.read(0, 100).unwrap(), val_a);
        assert_eq!(swapped.read(100, 100).unwrap(), val_b);

        // Both levels rebuilt with pointers remapped into generation 2; old
        // files deleted.
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
                    DataBlockValue::Pointer(vp) => {
                        assert_eq!(vp.file_id, 2, "rebuilt pointers name the new generation");
                        got.push((key.to_vec(), vp.value_offset));
                    }
                    _ => panic!("Expected Pointer variant"),
                }
            }
            assert_eq!(got, expected);
            assert!(
                file_manager.read_sstable(old.file_id).await.is_err(),
                "old SSTable must be deleted"
            );
        }

        // The source generation is gone, the new one carries the live values.
        assert!(!vlog_path.exists());
        assert!(generation_path(&vlog_path, 2).exists());
        assert_eq!(version.get().vlog_ids(), vec![2]);
    }
}
