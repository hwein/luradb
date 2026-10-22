//! RCU read snapshots published into the SHM double buffer (spec perf/009).
//!
//! [`SnapshotBuilder`] reads the current engine state into a compact,
//! rkyv-serialized [`ShmSnapshot`] (a per-domain, key-sorted index of the live
//! inline values); [`SnapshotPublisher`] pushes it through the spec 007
//! [`SnapshotWriter`] whenever its content may have changed, checked on an
//! interval and after every MemTable flush (spec perf/028). Local
//! clients (spec 010) read it lock-free via `SnapshotGuard` — for VLog-backed
//! values the entry carries only a `is_vlog_pointer` flag and the client falls
//! back to a command-ring GET.

use crate::engines::lsm::domain::now_secs;
use crate::engines::lsm::{Domain, DomainRegistry, LsmStorageEngine, Snapshot, ValueWithMetadata};
use crate::metrics::MetricsStore;
use crate::storage::format::is_expired;
use anyhow::{Context, Result};
use rkyv::util::AlignedVec;
use rkyv::{rancor, Archive, Deserialize, Serialize};
use std::ops::ControlFlow;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{oneshot, watch, Notify};

use super::{PublishOutcome, ReaderRegistry, ShmManager, SnapshotWriter, StateHeader};

/// Per-entry byte estimate on top of key+value: covers rkyv relative pointers,
/// length fields, the fixed `ShmEntry` fields and alignment padding. Kept
/// generous so the accumulation budget stays conservative.
const PER_ENTRY_OVERHEAD: usize = 64;

/// Warn on every N-th consecutive skipped publish (spec perf/012 §9) — about
/// once a second at the default interval.
const SKIP_WARN_EVERY: u32 = 10;

// ── SHM snapshot format (spec §1) ──────────────────────────────────────────────

/// Root of the SHM snapshot. rkyv-serialized into the active data buffer and
/// read back by clients via a validated pointer-cast (`rkyv::access`).
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
pub struct ShmSnapshot {
    /// Monotonic snapshot version (HLC value at build time).
    pub version: u64,
    /// Snapshot timestamp (HLC value at build time).
    pub timestamp: u64,
    /// Active domains, sorted by name (allows the client a binary search).
    pub domains: Vec<ShmDomainIndex>,
}

/// One domain's key index inside the snapshot.
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
pub struct ShmDomainIndex {
    /// User-facing domain name.
    pub name: String,
    /// Key-value entries, sorted by user key (`key`).
    pub entries: Vec<ShmEntry>,
}

/// A single key-value entry in the snapshot.
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
pub struct ShmEntry {
    /// User key (domain prefix stripped).
    pub key: Vec<u8>,
    /// Inline value bytes; empty when `is_vlog_pointer` (spec §1 approach a).
    pub value: Vec<u8>,
    /// Unix seconds after which the entry expires; 0 = no expiry.
    pub expire_at: u64,
    /// Value lives in the VLog (`value` empty); client falls back to a GET.
    pub is_vlog_pointer: bool,
    /// Key exists in the explicit NULL state (spec kv/018): `value` empty,
    /// never a VLog pointer.
    pub is_null: bool,
}

fn serialize_snapshot(snapshot: &ShmSnapshot) -> AlignedVec {
    rkyv::to_bytes::<rancor::Error>(snapshot)
        .expect("rkyv serialization is infallible for in-memory values")
}

/// Earliest `expire_at > 0` among the snapshot's entries (spec perf/028 A2).
fn earliest_expiry(snapshot: &ShmSnapshot) -> Option<u64> {
    snapshot.domains.iter().flat_map(|d| &d.entries).map(|e| e.expire_at).filter(|&at| at > 0).min()
}

/// Result of [`SnapshotBuilder::build`].
pub struct BuiltSnapshot {
    /// rkyv-serialized [`ShmSnapshot`].
    pub bytes: AlignedVec,
    /// Earliest `expire_at > 0` among the included entries; reaching it
    /// makes the publisher rebuild (spec perf/028 A2).
    pub earliest_expiry: Option<u64>,
}

// ── SnapshotBuilder (spec §2, §3, §6) ──────────────────────────────────────────

/// Builds an [`ShmSnapshot`] from the current engine state.
///
/// Reads go straight through the engine (not `DomainStore`) so the system
/// rebuild is not charged against per-domain read rate limits.
pub struct SnapshotBuilder {
    registry: Arc<DomainRegistry>,
    engine: Arc<LsmStorageEngine>,
    /// Data-buffer capacity (bytes); the accumulation budget is a fraction of it.
    max_snapshot_size: usize,
}

impl SnapshotBuilder {
    pub fn new(
        registry: Arc<DomainRegistry>,
        engine: Arc<LsmStorageEngine>,
        max_snapshot_size: usize,
    ) -> Self {
        Self { registry, engine, max_snapshot_size }
    }

    /// Builds the snapshot and returns the rkyv-serialized bytes plus the
    /// earliest entry expiry.
    ///
    /// One MVCC snapshot pins a consistent point-in-time across all domains.
    /// Only taking it and listing the domains run on the calling thread; the
    /// reads and the serialization run on a thread of their own, so the engine
    /// thread serves requests meanwhile. Accumulation stops once a
    /// conservative budget (7/8 of the buffer) is hit; the truncated result is
    /// logged and still published. Whether it fits after serialization is the
    /// final call of [`SnapshotWriter::publish`].
    pub async fn build(&self) -> Result<BuiltSnapshot> {
        let snap = self.engine.snapshot().await;

        // Active domains only (list_domains filters Deleting), sorted by name so
        // truncation is deterministic.
        let mut domains = self.registry.list_domains().await?;
        domains.sort_by(|a, b| a.name.cmp(&b.name));

        let engine = Arc::clone(&self.engine);
        let max_snapshot_size = self.max_snapshot_size;
        let (built_tx, built_rx) = oneshot::channel();
        // `snap` moves along and keeps the read point pinned until the end.
        std::thread::Builder::new()
            .name("luradb-shm".into())
            .spawn(move || {
                let _ = built_tx.send(build_at(&engine, &domains, snap.snapshot(), max_snapshot_size));
            })
            .context("failed to start the SHM snapshot build thread")?;
        built_rx.await.context("the SHM snapshot build thread ended without a result")?
    }
}

/// The blocking part of [`SnapshotBuilder::build`], run on its own thread:
/// reads `domains` at `read_point` against the byte budget and serializes the
/// result.
fn build_at(
    engine: &LsmStorageEngine,
    domains: &[Domain],
    read_point: &Snapshot,
    max_snapshot_size: usize,
) -> Result<BuiltSnapshot> {
    // Point-in-time stamp of this snapshot = its MVCC read timestamp.
    let ts = read_point.timestamp().as_u64();
    let budget = max_snapshot_size / 8 * 7;
    let mut running = 0usize;
    // On truncation: (domain where the budget ran out, count of later domains omitted).
    let mut truncation: Option<(String, usize)> = None;

    let mut domain_indices = Vec::with_capacity(domains.len());
    for (idx, domain) in domains.iter().enumerate() {
        let (entries, truncated) = collect_domain_entries(engine, domain, read_point, budget, &mut running)?;
        domain_indices.push(ShmDomainIndex { name: domain.name.clone(), entries });
        if truncated {
            // Remaining name-sorted domains are dropped entirely.
            truncation = Some((domain.name.clone(), domains.len() - idx - 1));
            break;
        }
    }

    if let Some((domain, omitted)) = &truncation {
        tracing::warn!(
            "SHM snapshot truncated in domain '{domain}' ({omitted} later domain(s) omitted): \
             accumulated size exceeded budget of {} bytes (buffer {})",
            budget,
            max_snapshot_size
        );
    }

    let snapshot = ShmSnapshot { version: ts, timestamp: ts, domains: domain_indices };
    Ok(BuiltSnapshot { earliest_expiry: earliest_expiry(&snapshot), bytes: serialize_snapshot(&snapshot) })
}

/// Collects one domain's entries against the shared byte budget, reading no
/// further than the first entry that would exceed it. Returns the entries,
/// sorted by key, and whether this domain was truncated. `read_point` is the
/// single MVCC read point (passed through, never re-taken); `running`
/// accumulates across domains.
fn collect_domain_entries(
    engine: &LsmStorageEngine,
    domain: &Domain,
    read_point: &Snapshot,
    budget: usize,
    running: &mut usize,
) -> Result<(Vec<ShmEntry>, bool)> {
    let prefix_len = domain.system_prefix.len();
    let mut entries = Vec::new();
    let mut truncated = false;
    engine.scan_with_metadata(&domain.system_prefix, read_point, |raw_key, meta| {
        let user_key = &raw_key[prefix_len..];
        let cost = user_key.len() + meta.data.len() + PER_ENTRY_OVERHEAD;
        if *running + cost > budget {
            truncated = true;
            return ControlFlow::Break(());
        }
        *running += cost;
        entries.push(to_entry(user_key.to_vec(), meta));
        ControlFlow::Continue(())
    })?;
    // The scan can put a key after its extensions; clients binary-search by key.
    entries.sort_by(|a, b| a.key.cmp(&b.key));
    Ok((entries, truncated))
}

/// Builds an entry, flagging VLog-backed values (empty `value`, client falls
/// back to a GET), NULL keys (kv/018), and inline values.
fn to_entry(user_key: Vec<u8>, meta: ValueWithMetadata) -> ShmEntry {
    let (value, is_vlog_pointer) =
        if meta.from_vlog { (Vec::new(), true) } else { (meta.data, false) };
    ShmEntry { key: user_key, value, expire_at: meta.expire_at, is_vlog_pointer, is_null: meta.is_null }
}

// ── SnapshotPublisher (spec §4, §7) ─────────────────────────────────────────────

/// Counts consecutive skipped publishes so the livelock guard (spec perf/012
/// §9) can log without a wall clock — and stays testable without log capture.
#[derive(Default)]
struct SkipTracker {
    consecutive: u32,
}

impl SkipTracker {
    /// Records a skip; true on every `SKIP_WARN_EVERY`-th one in a row.
    fn on_skipped(&mut self) -> bool {
        self.consecutive += 1;
        self.consecutive.is_multiple_of(SKIP_WARN_EVERY)
    }

    /// Records a successful publish; `Some(n)` if it ended a run of `n` skips.
    fn on_published(&mut self) -> Option<u32> {
        let skipped = std::mem::take(&mut self.consecutive);
        (skipped > 0).then_some(skipped)
    }
}

/// Times a run of skipped publishes against the kick threshold. Measured in
/// time, not skips: skips come from the interval and from flushes alike, so a
/// skip count would depend on the write load.
struct KickTracker {
    /// `Duration::ZERO` = never kick.
    after: Duration,
    /// Start of the current run, or of its measurement since the last kick.
    since: Option<Instant>,
}

impl KickTracker {
    fn new(after: Duration) -> Self {
        Self { after, since: None }
    }

    /// Records a skip at `now`; true once the run has lasted longer than the
    /// threshold, which also restarts the measurement — one kick, no storm
    /// while the disconnects are still being processed.
    fn on_skipped(&mut self, now: Instant) -> bool {
        if self.after.is_zero() {
            return false;
        }
        let since = *self.since.get_or_insert(now);
        if now.saturating_duration_since(since) <= self.after {
            return false;
        }
        self.since = Some(now);
        true
    }

    fn on_published(&mut self) {
        self.since = None;
    }
}

/// What one publisher step did (spec perf/028 A2).
#[derive(Debug, PartialEq, Eq)]
enum Tick {
    /// Content unchanged since the last publish: no build, only the header
    /// timestamp confirmed.
    Idle,
    /// Rebuilt and handed to the writer.
    Rebuilt(PublishOutcome),
    /// Build or publish failed (logged); the next step rebuilds.
    Failed,
}

/// The publisher's loop body plus the state it carries between ticks.
struct PublishLoop<'w> {
    builder: SnapshotBuilder,
    writer: SnapshotWriter<'w>,
    readers: Arc<ReaderRegistry>,
    metrics: Arc<MetricsStore>,
    skips: SkipTracker,
    kicks: KickTracker,
    /// Change epoch of the last publish; `None` before the first.
    published_epoch: Option<u64>,
    /// Earliest `expire_at > 0` among the last published entries.
    earliest_expiry: Option<u64>,
}

impl<'w> PublishLoop<'w> {
    /// `kick_after`: how long a skip run may last before its blockers are
    /// disconnected; `Duration::ZERO` = never.
    fn new(
        builder: SnapshotBuilder,
        writer: SnapshotWriter<'w>,
        readers: Arc<ReaderRegistry>,
        metrics: Arc<MetricsStore>,
        kick_after: Duration,
    ) -> Self {
        Self {
            builder,
            writer,
            readers,
            metrics,
            skips: SkipTracker::default(),
            kicks: KickTracker::new(kick_after),
            published_epoch: None,
            earliest_expiry: None,
        }
    }

    /// One tick: rebuilds and publishes only if the snapshot content may have
    /// changed since the last publish, else just confirms the header
    /// timestamp. `now` is the Unix time in seconds checked against the
    /// earliest published expiry; `at` times a skipped publish against the
    /// kick threshold.
    async fn step(&mut self, now: u64, at: Instant) -> Tick {
        // Read before `build` takes its MVCC snapshot: a write in between
        // leaves the epoch behind and triggers the next rebuild.
        let epoch = self.builder.engine.change_epoch();
        let expired = self.earliest_expiry.is_some_and(|expiry| is_expired(expiry, now));
        if self.published_epoch == Some(epoch) && !expired {
            self.writer.confirm_unchanged();
            return Tick::Idle;
        }
        let built = match self.builder.build().await {
            Ok(built) => built,
            Err(e) => {
                tracing::error!("SHM snapshot build failed: {e}");
                return Tick::Failed;
            }
        };
        let outcome = match self.writer.publish(&built.bytes) {
            Ok(outcome) => outcome,
            Err(e) => {
                tracing::error!("SHM snapshot publish failed: {e}");
                return Tick::Failed;
            }
        };
        match outcome {
            PublishOutcome::Published => {
                // Only a publish moves the comparison state.
                self.published_epoch = Some(epoch);
                self.earliest_expiry = built.earliest_expiry;
                self.metrics.record_shm_publish();
                self.kicks.on_published();
                if let Some(n) = self.skips.on_published() {
                    tracing::info!("SHM snapshot publishing resumed after {n} skipped publishes");
                }
            }
            // No force-flip: a pinned buffer is never overwritten. The state
            // is made visible and, past the kick threshold, the clients
            // pinning it are disconnected.
            PublishOutcome::SkippedBusy { buffer } => {
                self.metrics.record_shm_publish_skip();
                if self.skips.on_skipped() {
                    tracing::warn!(
                        "SHM snapshot stale: {} consecutive publishes skipped, buffer {buffer} \
                         still pinned by (client_id, readers) {:?}",
                        self.skips.consecutive,
                        self.readers.blockers(buffer)
                    );
                }
                if self.kicks.on_skipped(at) {
                    self.kick_blockers(buffer);
                }
            }
        }
        Tick::Rebuilt(outcome)
    }

    /// Disconnects every client pinning `buffer` the way its own EOF would;
    /// its reads still in flight may see the buffer overwritten.
    fn kick_blockers(&self, buffer: u32) {
        let blockers = self.readers.blockers(buffer);
        if blockers.is_empty() {
            return;
        }
        for &(client_id, _) in &blockers {
            self.readers.kick(client_id);
            self.metrics.record_shm_client_kicked();
        }
        tracing::warn!(
            "SHM snapshot blocked longer than the kick threshold: disconnecting \
             (client_id, readers) {blockers:?} pinning buffer {buffer}"
        );
    }
}

/// Background task that publishes snapshots into the SHM double buffer.
///
/// Runs as a task of the engine thread's compio runtime: it holds a `!Send`
/// [`SnapshotWriter`] (raw pointers into the mapped buffers) across `.await`
/// points, which the thread-local executor permits.
pub struct SnapshotPublisher {
    builder: SnapshotBuilder,
    manager: Arc<ShmManager>,
    interval: Duration,
    wait_timeout_us: u64,
    /// Reader slots of the registered clients; scanned before every flip.
    readers: Arc<ReaderRegistry>,
    /// Notified after each MemTable flush — an extra tick.
    flush_notify: Arc<Notify>,
    /// Receives the publish and kick counters.
    metrics: Arc<MetricsStore>,
    /// How long a run of skipped publishes may last before the clients
    /// blocking it are disconnected; `Duration::ZERO` = never.
    kick_after: Duration,
    /// Set to true at shutdown to stop the loop.
    shutdown: watch::Receiver<bool>,
}

impl SnapshotPublisher {
    pub fn new(
        builder: SnapshotBuilder,
        manager: Arc<ShmManager>,
        interval: Duration,
        wait_timeout_us: u64,
        readers: Arc<ReaderRegistry>,
        flush_notify: Arc<Notify>,
        metrics: Arc<MetricsStore>,
        kick_after: Duration,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self { builder, manager, interval, wait_timeout_us, readers, flush_notify, metrics, kick_after, shutdown }
    }

    /// Runs until the shutdown signal fires. The loop always survives build and
    /// publish errors (logged and retried on the next tick) — spec §4.
    pub async fn run(self) {
        let SnapshotPublisher {
            builder,
            manager,
            interval,
            wait_timeout_us,
            readers,
            flush_notify,
            metrics,
            kick_after,
            mut shutdown,
        } = self;

        // Build the writer inside the task body from the live segments; `manager`
        // (moved in) keeps the mappings alive for the whole task.
        let (state, data_a, data_b) =
            match (manager.get_segment("state"), manager.get_segment("data_a"), manager.get_segment("data_b")) {
                (Some(s), Some(a), Some(b)) => (s, a, b),
                _ => {
                    tracing::error!("SHM snapshot publisher: state/data segments missing; not starting");
                    return;
                }
            };
        // Safe: the state segment is >= StateHeader::SIZE (checked at startup)
        // and only ever accessed through StateHeader.
        let header = unsafe { StateHeader::from_ptr(state.as_ptr(), state.len()) };
        // Safe: this task is the single writer; the two data buffers are
        // distinct mappings of `buf_len` bytes that live as long as `manager`.
        let writer = unsafe {
            SnapshotWriter::new(
                header,
                data_a.as_ptr() as *mut u8,
                data_b.as_ptr() as *mut u8,
                data_a.len(),
                wait_timeout_us,
                Arc::clone(&readers),
            )
        };
        let mut publish = PublishLoop::new(builder, writer, readers, metrics, kick_after);

        loop {
            if *shutdown.borrow() {
                break;
            }
            publish.step(now_secs(), Instant::now()).await;

            tokio::select! {
                _ = compio::time::sleep(interval) => {}
                _ = flush_notify.notified() => {}
                _ = shutdown.changed() => break,
            }
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::wal::WriteAheadLog;
    use crate::engines::lsm::domain::DomainConfig;
    use crate::engines::lsm::engine::{LsmEngineConfig, LsmEngineOptions, TestHooks, ThreadHook};
    use crate::ipc::{ReaderSlot, ReaderSlotHandle, ReaderSlotLease, SnapshotGuard, PUBLISH_WAIT_TIMEOUT_US};
    use crate::metrics::{MetricsConfig, MetricsStore};
    use crate::storage::file_manager::FileManager;
    use crate::storage::manifest::ManifestManager;
    use crate::storage::vlog::VLog;
    use futures::FutureExt;
    use rkyv::Archived;
    use std::sync::atomic::Ordering;

    async fn make_setup() -> (Arc<LsmStorageEngine>, Arc<DomainRegistry>, tempfile::TempDir) {
        make_setup_with(LsmEngineOptions::default()).await
    }

    async fn make_setup_with(
        options: LsmEngineOptions,
    ) -> (Arc<LsmStorageEngine>, Arc<DomainRegistry>, tempfile::TempDir) {
        make_setup_with_hooks(options, TestHooks::default()).await
    }

    async fn make_setup_with_hooks(
        options: LsmEngineOptions,
        hooks: TestHooks,
    ) -> (Arc<LsmStorageEngine>, Arc<DomainRegistry>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let wal_path = dir.path().join("wal.log");
        let wal = Arc::new(WriteAheadLog::new(&wal_path).await.unwrap());
        let vlog_path = dir.path().join("vlog.log");
        let vlog = Arc::new(VLog::new(&vlog_path).await.unwrap());
        let fm = Arc::new(FileManager::new(dir.path()).await.unwrap());
        let mm = Arc::new(ManifestManager::new(dir.path()));
        let mut engine = LsmStorageEngine::new(wal, wal_path, vlog, vlog_path, fm, mm, options).await.unwrap();
        engine.hooks = hooks;
        let engine = Arc::new(engine);
        let metrics = MetricsStore::new(MetricsConfig::default());
        let registry = Arc::new(
            DomainRegistry::recover(Arc::clone(&engine), DomainConfig::default(), metrics).await.unwrap(),
        );
        (engine, registry, dir)
    }

    fn builder(registry: &Arc<DomainRegistry>, engine: &Arc<LsmStorageEngine>, max: usize) -> SnapshotBuilder {
        SnapshotBuilder::new(Arc::clone(registry), Arc::clone(engine), max)
    }

    /// Deserializes (and validates) a serialized snapshot the way a client would.
    fn decode(bytes: &[u8]) -> ShmSnapshot {
        let mut aligned: AlignedVec = AlignedVec::with_capacity(bytes.len());
        aligned.extend_from_slice(bytes);
        let archived =
            rkyv::access::<Archived<ShmSnapshot>, rancor::Error>(aligned.as_slice()).unwrap();
        rkyv::deserialize::<ShmSnapshot, rancor::Error>(archived).unwrap()
    }

    fn find<'a>(snap: &'a ShmSnapshot, name: &str) -> Option<&'a ShmDomainIndex> {
        snap.domains.iter().find(|d| d.name == name)
    }

    /// Engine options under which the MemTable never rotates on its own, so
    /// the test alone decides where the keys live.
    fn unrotated() -> LsmEngineOptions {
        LsmEngineOptions {
            engine: LsmEngineConfig { memtable_size_threshold: usize::MAX, ..LsmEngineConfig::default() },
            ..LsmEngineOptions::default()
        }
    }

    /// Writes the keys `c000000..` (`n` of them, 64-byte values) under
    /// `prefix`, split evenly over `sstables` flushed SSTables; 0 leaves them
    /// all in the MemTable.
    async fn seed(engine: &LsmStorageEngine, prefix: &[u8], n: u32, sstables: u32) {
        use crate::engines::lsm::engine::BatchOp;
        let parts = sstables.max(1);
        for part in 0..parts {
            let (from, to) = (n / parts * part, n / parts * (part + 1));
            for start in (from..to).step_by(1024) {
                let ops = (start..(start + 1024).min(to))
                    .map(|i| BatchOp::Put {
                        key: [prefix, format!("c{i:06}").as_bytes()].concat(),
                        value: vec![b'v'; 64],
                    })
                    .collect();
                engine.write_batch(ops).await.unwrap();
            }
            if sstables > 0 {
                engine.flush_all_memtables().await.unwrap();
            }
        }
    }

    // A build over keys in SSTables reads them on another thread while the
    // engine thread answers a write: the build holds the engine thread only to
    // take its read point, its first scan stays parked until the write returned.
    #[test]
    fn test_sources_are_read_off_the_engine_thread_while_it_answers_a_write() {
        crate::core::engine_runtime::block_on(async {
            let (hook, reached, release) = ThreadHook::new();
            let hooks = TestHooks { before_scan: Some(hook), ..TestHooks::default() };
            let (engine, registry, _dir) = make_setup_with_hooks(unrotated(), hooks).await;
            let domain = registry.create_domain("shm").await.unwrap();
            seed(&engine, &domain.system_prefix, 2_048, 2).await;
            let engine_thread = std::thread::current().id();
            let builder = builder(&registry, &engine, ARENA_LEN);
            let build = compio::runtime::spawn(async move { builder.build().await.unwrap() });
            // Waits off the engine thread and lets a scan parked on the engine
            // thread itself go at once, so that case fails instead of hanging.
            let (scan_thread, release) = tokio::task::spawn_blocking(move || {
                let scan_thread = reached.recv().unwrap();
                if scan_thread == engine_thread {
                    release.send(()).unwrap();
                }
                (scan_thread, release)
            })
            .await
            .unwrap();
            assert_ne!(scan_thread, engine_thread, "the build read its sources on the engine thread");

            registry.store("shm").await.unwrap().put(b"late", b"v").await.unwrap();
            release.send(()).unwrap();
            let snap = decode(&build.await.unwrap().bytes);
            let dom = find(&snap, "shm").unwrap();
            assert_eq!(dom.entries.len(), 2_048);
            assert!(!dom.entries.iter().any(|e| e.key == b"late"), "the write came after the build's read point");
        })
    }

    // Diagnosis, asserts no timing: prints how long one build takes against
    // the key count, with the keys in the MemTable, in one SSTable, or split
    // over two. Run it in release:
    // `cargo test --release -- --ignored --nocapture snapshot_build_cost`
    #[test]
    #[ignore = "diagnosis: prints build durations"]
    fn snapshot_build_cost_by_key_count_and_layout() {
        for n in [50_000u32, 100_000, 200_000, 400_000] {
            for sstables in [0, 1, 2] {
                let elapsed = crate::core::engine_runtime::block_on(async {
                    let (engine, registry, _dir) = make_setup_with(unrotated()).await;
                    let domain = registry.create_domain("shm").await.unwrap();
                    seed(&engine, &domain.system_prefix, n, sstables).await;
                    let builder = builder(&registry, &engine, 1 << 30);
                    let start = Instant::now();
                    let built = builder.build().await.unwrap();
                    let elapsed = start.elapsed();
                    assert_eq!(find(&decode(&built.bytes), "shm").unwrap().entries.len(), n as usize);
                    elapsed
                });
                println!("build: {n:>7} keys, {sstables} SSTable(s): {elapsed:?}");
            }
        }
    }

    // 1. ShmSnapshot serialize/deserialize roundtrip.
    #[test]
    fn test_snapshot_roundtrip() {
        let snap = ShmSnapshot {
            version: 42,
            timestamp: 99,
            domains: vec![ShmDomainIndex {
                name: "default".into(),
                entries: vec![
                    ShmEntry { key: b"a".to_vec(), value: b"1".to_vec(), expire_at: 0, is_vlog_pointer: false, is_null: false },
                    ShmEntry { key: b"b".to_vec(), value: Vec::new(), expire_at: 7, is_vlog_pointer: true, is_null: false },
                    ShmEntry { key: b"c".to_vec(), value: Vec::new(), expire_at: 0, is_vlog_pointer: false, is_null: true },
                ],
            }],
        };
        let bytes = serialize_snapshot(&snap);
        assert_eq!(decode(&bytes), snap);
    }

    // 2. Empty database → snapshot has the (empty) default domain.
    #[test]
    fn test_build_empty_db() {
        crate::core::engine_runtime::block_on(async {
            let (engine, registry, _dir) = make_setup().await;
            let bytes = builder(&registry, &engine, 1 << 20).build().await.unwrap().bytes;
            let snap = decode(&bytes);
            let default = find(&snap, "default").expect("default domain present");
            assert!(default.entries.is_empty(), "no user keys written");
        })
    }

    // 3. 100 keys across 2 domains → all present, sorted per domain.
    #[test]
    fn test_build_many_keys_sorted() {
        crate::core::engine_runtime::block_on(async {
            let (engine, registry, _dir) = make_setup().await;
            registry.create_domain("alpha").await.unwrap();
            registry.create_domain("beta").await.unwrap();
            let a = registry.store("alpha").await.unwrap();
            let b = registry.store("beta").await.unwrap();
            for i in 0..50u32 {
                a.put(format!("key{i:03}").as_bytes(), format!("va{i}").as_bytes()).await.unwrap();
                b.put(format!("key{i:03}").as_bytes(), format!("vb{i}").as_bytes()).await.unwrap();
            }

            let snap = decode(&builder(&registry, &engine, 1 << 20).build().await.unwrap().bytes);
            for name in ["alpha", "beta"] {
                let dom = find(&snap, name).unwrap();
                assert_eq!(dom.entries.len(), 50, "{name} entry count");
                assert!(dom.entries.windows(2).all(|w| w[0].key <= w[1].key), "{name} sorted");
            }
            // Domains themselves are name-sorted.
            assert!(snap.domains.windows(2).all(|w| w[0].name <= w[1].name));
        })
    }

    // 4. VLog-backed value → is_vlog_pointer = true, value empty.
    #[test]
    fn test_build_vlog_pointer() {
        crate::core::engine_runtime::block_on(async {
            let (engine, registry, _dir) = make_setup().await;
            let store = registry.default_store().await.unwrap();
            let big = vec![b'x'; 2048]; // >= vlog_inline_threshold (1024)
            store.put(b"large", &big).await.unwrap();

            let snap = decode(&builder(&registry, &engine, 1 << 20).build().await.unwrap().bytes);
            let dom = find(&snap, "default").unwrap();
            let entry = dom.entries.iter().find(|e| e.key == b"large").unwrap();
            assert!(entry.is_vlog_pointer);
            assert!(entry.value.is_empty(), "VLog value must not be embedded");
        })
    }

    // 5. Inline value → is_vlog_pointer = false, value carries the data.
    #[test]
    fn test_build_inline_value() {
        crate::core::engine_runtime::block_on(async {
            let (engine, registry, _dir) = make_setup().await;
            let store = registry.default_store().await.unwrap();
            store.put(b"small", b"hello").await.unwrap();

            let snap = decode(&builder(&registry, &engine, 1 << 20).build().await.unwrap().bytes);
            let dom = find(&snap, "default").unwrap();
            let entry = dom.entries.iter().find(|e| e.key == b"small").unwrap();
            assert!(!entry.is_vlog_pointer);
            assert!(!entry.is_null);
            assert_eq!(entry.value, b"hello");
        })
    }

    // kv/018: a NULL key exists in the snapshot, marked is_null, empty value.
    #[test]
    fn test_build_null_key_included_and_flagged() {
        crate::core::engine_runtime::block_on(async {
            let (engine, registry, _dir) = make_setup().await;
            let store = registry.default_store().await.unwrap();
            store.set_null(b"nulled").await.unwrap();

            let snap = decode(&builder(&registry, &engine, 1 << 20).build().await.unwrap().bytes);
            let dom = find(&snap, "default").unwrap();
            let entry = dom.entries.iter().find(|e| e.key == b"nulled").expect("NULL key present");
            assert!(entry.is_null);
            assert!(!entry.is_vlog_pointer);
            assert!(entry.value.is_empty());
        })
    }

    // 6. Over-budget snapshot is truncated (fewer entries than written).
    #[test]
    fn test_build_truncates_over_budget() {
        crate::core::engine_runtime::block_on(async {
            let (engine, registry, _dir) = make_setup().await;
            let store = registry.default_store().await.unwrap();
            for i in 0..200u32 {
                store.put(format!("key{i:04}").as_bytes(), b"val").await.unwrap();
            }
            // Tiny budget forces truncation.
            let snap = decode(&builder(&registry, &engine, 2048).build().await.unwrap().bytes);
            let total: usize = snap.domains.iter().map(|d| d.entries.len()).sum();
            assert!(total > 0, "at least one entry fits");
            assert!(total < 200, "snapshot must be truncated, got {total}");
        })
    }

    // A domain four times the budget is read only up to the budget: the build
    // stops reading its sources at the first entry that no longer fits.
    #[test]
    fn test_build_of_a_domain_over_budget_stops_reading_at_the_budget() {
        use crate::engines::lsm::engine::BatchOp;
        use crate::engines::lsm::reader::scanned_versions;
        crate::core::engine_runtime::block_on(async {
            let (engine, registry, _dir) = make_setup_with(unrotated()).await;
            let domain = registry.create_domain("shm").await.unwrap();
            let max_snapshot_size = 1 << 16;
            // Every entry costs the same: a 7-byte key, a 64-byte value, the overhead.
            let fits = (max_snapshot_size / 8 * 7) / (7 + 64 + PER_ENTRY_OVERHEAD);
            let n = 4 * fits;
            // The keys interleave over three sources: two SSTables and the MemTable.
            for source in 0..3 {
                let ops = (source..n)
                    .step_by(3)
                    .map(|i| BatchOp::Put {
                        key: [domain.system_prefix.as_slice(), format!("k{i:06}").as_bytes()].concat(),
                        value: vec![b'v'; 64],
                    })
                    .collect();
                engine.write_batch(ops).await.unwrap();
                if source < 2 {
                    engine.flush_all_memtables().await.unwrap();
                }
            }

            let read_point = engine.snapshot().await;
            let before = scanned_versions();
            let built =
                build_at(&engine, std::slice::from_ref(&domain), read_point.snapshot(), max_snapshot_size).unwrap();
            let read = scanned_versions() - before;

            let snap = decode(&built.bytes);
            let dom = find(&snap, "shm").unwrap();
            let keys: Vec<Vec<u8>> = dom.entries.iter().map(|e| e.key.clone()).collect();
            let smallest: Vec<Vec<u8>> = (0..fits).map(|i| format!("k{i:06}").into_bytes()).collect();
            assert_eq!(keys, smallest);
            // Lead: the entry that no longer fit, plus one queued version per source.
            assert!(read <= (fits + 1 + 3) as u64, "read {read} versions to publish {fits}");
        })
    }

    // A key sorts before the keys it is a prefix of, wherever each one lives.
    #[test]
    fn test_build_sorts_a_key_before_its_extensions() {
        crate::core::engine_runtime::block_on(async {
            let (engine, registry, _dir) = make_setup_with(unrotated()).await;
            let store = registry.default_store().await.unwrap();
            store.put(b"ab", b"2").await.unwrap();
            engine.flush_all_memtables().await.unwrap();
            store.put(b"a", b"1").await.unwrap();
            store.put(b"abc", b"3").await.unwrap();

            let snap = decode(&builder(&registry, &engine, 1 << 20).build().await.unwrap().bytes);
            let dom = find(&snap, "default").unwrap();
            let keys: Vec<&[u8]> = dom.entries.iter().map(|e| e.key.as_slice()).collect();
            assert_eq!(keys, [b"a".as_slice(), b"ab", b"abc"]);
        })
    }

    // 7 & 8. End-to-end: build → publish into an SHM arena → client reads via
    // SnapshotGuard + rkyv::access, incl. the zero-copy value view and a
    // binary search over the sorted entries.
    #[test]
    fn test_publisher_end_to_end_client_read() {
        crate::core::engine_runtime::block_on(async {
            let (engine, registry, _dir) = make_setup().await;
            let store = registry.default_store().await.unwrap();
            store.put(b"alpha", b"1").await.unwrap();
            store.put(b"beta", b"2").await.unwrap();

            let bytes = builder(&registry, &engine, 1 << 20).build().await.unwrap().bytes;

            // Arena models the SHM state header + two data buffers (page-aligned in
            // production; here we copy into an AlignedVec before validating), plus
            // the registered client's reader slot.
            let header = Box::new(StateHeader::zeroed());
            header.init();
            let slot = Arc::new(ReaderSlot::zeroed());
            let readers = Arc::new(ReaderRegistry::new());
            // Safe: the pointer targets the slot inside `slot`, whose `Arc` clone the
            // handle keeps alive.
            let handle = unsafe {
                ReaderSlotHandle::new(
                    1,
                    Arc::as_ptr(&slot),
                    Arc::clone(&slot) as Arc<dyn std::any::Any + Send + Sync>,
                    Arc::default(),
                )
            };
            let _lease = readers.register(handle);

            let len = 1 << 20;
            let mut buf_a = vec![0u8; len];
            let mut buf_b = vec![0u8; len];
            // Safe: single writer, two distinct buffers of `len` bytes, header valid.
            let writer = unsafe {
                SnapshotWriter::new(
                    &header,
                    buf_a.as_mut_ptr(),
                    buf_b.as_mut_ptr(),
                    len,
                    PUBLISH_WAIT_TIMEOUT_US,
                    Arc::clone(&readers),
                )
            };
            assert_eq!(writer.publish(&bytes).unwrap(), PublishOutcome::Published);
            drop(writer);

            let guard = SnapshotGuard::acquire(&header, &slot, &buf_a, &buf_b).expect("snapshot available");

            // Client side: validate, then read zero-copy from the mapped bytes.
            let mut aligned: AlignedVec = AlignedVec::with_capacity(guard.data().len());
            aligned.extend_from_slice(guard.data());
            let archived =
                rkyv::access::<Archived<ShmSnapshot>, rancor::Error>(aligned.as_slice()).unwrap();
            let dom = archived.domains.iter().find(|d| d.name == "default").unwrap();
            // entries are sorted → binary search, then a zero-copy value slice.
            let idx = dom.entries.binary_search_by(|e| e.key.as_slice().cmp(b"alpha".as_ref())).unwrap();
            assert_eq!(dom.entries[idx].value.as_slice(), b"1");
            assert!(!dom.entries[idx].is_vlog_pointer);

            // Full owned view for the remaining assertions.
            let snap = rkyv::deserialize::<ShmSnapshot, rancor::Error>(archived).unwrap();
            let dom = find(&snap, "default").unwrap();
            assert_eq!(dom.entries.iter().find(|e| e.key == b"beta").unwrap().value, b"2");
        })
    }

    // 9. Expired-TTL key does not appear in the snapshot.
    #[test]
    fn test_expired_ttl_absent() {
        crate::core::engine_runtime::block_on(async {
            let (engine, registry, _dir) = make_setup().await;
            let store = registry.default_store().await.unwrap();
            store.put(b"stays", b"v").await.unwrap();
            // Already expired regardless of the wall clock (spec general/033).
            store.put_expired_for_test(b"gone", b"v").await.unwrap();

            let snap = decode(&builder(&registry, &engine, 1 << 20).build().await.unwrap().bytes);
            let dom = find(&snap, "default").unwrap();
            assert!(dom.entries.iter().any(|e| e.key == b"stays"));
            assert!(!dom.entries.iter().any(|e| e.key == b"gone"), "expired key must be absent");
        })
    }

    // Keys in SSTables come out as their newest version: an overwrite in the
    // newer table wins, a tombstone or an expiry hides the key, and the NULL
    // and vLog flags survive the flush.
    #[test]
    fn test_build_reads_the_newest_version_from_sstables() {
        crate::core::engine_runtime::block_on(async {
            let (engine, registry, _dir) = make_setup_with(unrotated()).await;
            let store = registry.default_store().await.unwrap();
            store.put(b"kept", b"1").await.unwrap();
            store.put(b"overwritten", b"old").await.unwrap();
            store.put(b"deleted", b"v").await.unwrap();
            store.put(b"large", &vec![b'x'; 2048]).await.unwrap();
            store.set_null(b"nulled").await.unwrap();
            store.put_expired_for_test(b"gone", b"v").await.unwrap();
            engine.flush_all_memtables().await.unwrap();
            store.put(b"overwritten", b"new").await.unwrap();
            store.delete(b"deleted").await.unwrap();
            engine.flush_all_memtables().await.unwrap();

            let snap = decode(&builder(&registry, &engine, 1 << 20).build().await.unwrap().bytes);
            let dom = find(&snap, "default").unwrap();
            let keys: Vec<&[u8]> = dom.entries.iter().map(|e| e.key.as_slice()).collect();
            assert_eq!(keys, [b"kept".as_slice(), b"large", b"nulled", b"overwritten"]);
            assert_eq!(default_entry(&snap, b"kept").unwrap().value, b"1");
            assert_eq!(default_entry(&snap, b"overwritten").unwrap().value, b"new");
            let large = default_entry(&snap, b"large").unwrap();
            assert!(large.is_vlog_pointer && large.value.is_empty());
            let nulled = default_entry(&snap, b"nulled").unwrap();
            assert!(nulled.is_null && !nulled.is_vlog_pointer && nulled.value.is_empty());
        })
    }

    // Spec perf/012 test 10: the livelock guard's counting logic — warn on every
    // K-th consecutive skip, report and reset the run on the next publish.
    #[test]
    fn test_skip_tracker_warns_every_k_and_resets() {
        let mut t = SkipTracker::default();
        assert_eq!(t.on_published(), None, "no skips yet");

        for i in 1..=(2 * SKIP_WARN_EVERY) {
            let warn = t.on_skipped();
            assert_eq!(warn, i % SKIP_WARN_EVERY == 0, "skip {i} warn flag");
        }
        assert_eq!(t.on_published(), Some(2 * SKIP_WARN_EVERY));
        assert_eq!(t.on_published(), None, "counter reset");
        assert!(!t.on_skipped(), "counting restarts after a publish");
    }

    const KICK_AFTER: Duration = Duration::from_secs(30);
    const SEC: Duration = Duration::from_secs(1);

    // Instants are computed, never awaited: no wall clock decides the outcome.
    #[test]
    fn test_kick_tracker_fires_once_past_threshold_then_restarts() {
        let mut t = KickTracker::new(KICK_AFTER);
        let t0 = Instant::now();
        assert!(!t.on_skipped(t0), "the first skip starts the run");
        assert!(!t.on_skipped(t0 + KICK_AFTER), "at the threshold, not past it");
        let kicked_at = t0 + KICK_AFTER + SEC;
        assert!(t.on_skipped(kicked_at), "past the threshold");
        assert!(!t.on_skipped(kicked_at + SEC), "the measurement restarts at the kick");
        assert!(t.on_skipped(kicked_at + KICK_AFTER + SEC), "a run still blocked kicks again");
    }

    #[test]
    fn test_kick_tracker_resets_on_publish() {
        let mut t = KickTracker::new(KICK_AFTER);
        let t0 = Instant::now();
        assert!(!t.on_skipped(t0));
        t.on_published();
        let t1 = t0 + KICK_AFTER + SEC;
        assert!(!t.on_skipped(t1), "a publish ends the run, this skip starts a new one");
        assert!(!t.on_skipped(t1 + KICK_AFTER));
    }

    #[test]
    fn test_kick_tracker_with_zero_threshold_never_kicks() {
        let mut t = KickTracker::new(Duration::ZERO);
        let t0 = Instant::now();
        for secs in [0, 1, 3600, 365 * 86_400] {
            assert!(!t.on_skipped(t0 + Duration::from_secs(secs)), "kicked after {secs} s");
        }
    }

    // 10. A domain in Deleting state does not appear in the snapshot.
    #[test]
    fn test_deleting_domain_absent() {
        crate::core::engine_runtime::block_on(async {
            let (engine, registry, _dir) = make_setup().await;
            registry.create_domain("temp").await.unwrap();
            registry.store("temp").await.unwrap().put(b"k", b"v").await.unwrap();
            registry.delete_domain("temp").await.unwrap();

            let snap = decode(&builder(&registry, &engine, 1 << 20).build().await.unwrap().bytes);
            assert!(find(&snap, "temp").is_none(), "deleting domain must be absent");
            assert!(find(&snap, "default").is_some(), "active domain still present");
        })
    }

    // ── Spec perf/028: publisher step ─────────────────────────────────────────────

    const ARENA_LEN: usize = 1 << 20;

    /// Step time for tests without TTL entries.
    const BEFORE_ANY_EXPIRY: u64 = 0;

    /// SHM stand-in for the step tests: state header, two data buffers, one
    /// registered client slot and the metrics the publisher records into.
    struct Arena {
        header: Box<StateHeader>,
        slot: Arc<ReaderSlot>,
        /// The registered client's disconnect signal; nobody acts on it here.
        kick: Arc<Notify>,
        metrics: Arc<MetricsStore>,
        readers: Arc<ReaderRegistry>,
        _lease: ReaderSlotLease,
        buf_a: Vec<u8>,
        buf_b: Vec<u8>,
        /// Write pointers into the buffers, taken once: heap buffers never move.
        ptr_a: *mut u8,
        ptr_b: *mut u8,
    }

    impl Arena {
        fn new() -> Self {
            let header = Box::new(StateHeader::zeroed());
            header.init();
            let slot = Arc::new(ReaderSlot::zeroed());
            let kick = Arc::new(Notify::new());
            let readers = Arc::new(ReaderRegistry::new());
            // Safe: the pointer targets the slot inside `slot`, whose `Arc`
            // clone the handle keeps alive.
            let handle = unsafe {
                ReaderSlotHandle::new(
                    1,
                    Arc::as_ptr(&slot),
                    Arc::clone(&slot) as Arc<dyn std::any::Any + Send + Sync>,
                    Arc::clone(&kick),
                )
            };
            let _lease = readers.register(handle);
            let (mut buf_a, mut buf_b) = (vec![0u8; ARENA_LEN], vec![0u8; ARENA_LEN]);
            let (ptr_a, ptr_b) = (buf_a.as_mut_ptr(), buf_b.as_mut_ptr());
            let metrics = MetricsStore::new(MetricsConfig::default());
            Self { header, slot, kick, metrics, readers, _lease, buf_a, buf_b, ptr_a, ptr_b }
        }

        /// Publisher loop writing into this arena — its only writer — that
        /// never kicks.
        fn publish_loop(&self, builder: SnapshotBuilder) -> PublishLoop<'_> {
            self.kicking_publish_loop(builder, Duration::ZERO)
        }

        fn kicking_publish_loop(&self, builder: SnapshotBuilder, kick_after: Duration) -> PublishLoop<'_> {
            // Safe: single writer; two distinct buffers of ARENA_LEN bytes that
            // live as long as `self`.
            let writer = unsafe {
                SnapshotWriter::new(
                    &self.header,
                    self.ptr_a,
                    self.ptr_b,
                    ARENA_LEN,
                    PUBLISH_WAIT_TIMEOUT_US,
                    Arc::clone(&self.readers),
                )
            };
            PublishLoop::new(builder, writer, Arc::clone(&self.readers), Arc::clone(&self.metrics), kick_after)
        }

        /// `[publishes, skips, current skip run, kicked clients]`.
        fn shm_counters(&self) -> [u64; 4] {
            let sys = &self.metrics.system;
            [
                &sys.shm_snapshot_publishes_total,
                &sys.shm_snapshot_publish_skips_total,
                &sys.shm_snapshot_consecutive_skips,
                &sys.shm_clients_kicked_total,
            ]
            .map(|c| c.load(Ordering::Relaxed))
        }

        /// Whether the registered client was kicked since the last call.
        fn take_kick(&self) -> bool {
            self.kick.notified().now_or_never().is_some()
        }

        /// The registered client starts a read of buffer `idx` and holds it.
        fn hold(&self, idx: usize) {
            self.slot.counter(idx).fetch_add(1, Ordering::AcqRel);
        }

        fn release(&self, idx: usize) {
            self.slot.counter(idx).fetch_sub(1, Ordering::AcqRel);
        }

        fn version(&self) -> u64 {
            self.header.version.load(Ordering::Acquire)
        }

        /// Pins the active buffer like a client read in progress.
        fn pin(&self) -> SnapshotGuard<'_> {
            SnapshotGuard::acquire(&self.header, &self.slot, &self.buf_a, &self.buf_b).expect("snapshot available")
        }

        /// The active snapshot, read the way a client does.
        fn read(&self) -> ShmSnapshot {
            decode(self.pin().data())
        }
    }

    /// `key`'s entry in the default domain.
    fn default_entry<'a>(snap: &'a ShmSnapshot, key: &[u8]) -> Option<&'a ShmEntry> {
        find(snap, "default")?.entries.iter().find(|e| e.key == key)
    }

    // Spec perf/028 test 1: without a write, the next step is idle — no build,
    // no flip.
    #[test]
    fn test_step_without_write_is_idle() {
        crate::core::engine_runtime::block_on(async {
            let (engine, registry, _dir) = make_setup().await;
            let arena = Arena::new();
            let mut publish = arena.publish_loop(builder(&registry, &engine, ARENA_LEN));
            assert_eq!(publish.step(BEFORE_ANY_EXPIRY, Instant::now()).await, Tick::Rebuilt(PublishOutcome::Published));
            let version = arena.version();

            assert_eq!(publish.step(BEFORE_ANY_EXPIRY, Instant::now()).await, Tick::Idle);
            assert_eq!(arena.version(), version, "an idle step must not flip");
        })
    }

    // Spec perf/028 test 6: an idle step confirms the unchanged snapshot by
    // refreshing `last_update_ns`; `version` stays.
    #[test]
    fn test_idle_step_refreshes_last_update_ns() {
        crate::core::engine_runtime::block_on(async {
            let (engine, registry, _dir) = make_setup().await;
            let arena = Arena::new();
            let mut publish = arena.publish_loop(builder(&registry, &engine, ARENA_LEN));
            publish.step(BEFORE_ANY_EXPIRY, Instant::now()).await;
            let version = arena.version();
            arena.header.last_update_ns.store(0, Ordering::Relaxed);

            assert_eq!(publish.step(BEFORE_ANY_EXPIRY, Instant::now()).await, Tick::Idle);
            assert_ne!(arena.header.last_update_ns.load(Ordering::Relaxed), 0, "idle step must refresh it");
            assert_eq!(arena.version(), version);
        })
    }

    // Spec perf/028 test 2: a write between two steps makes the second one
    // rebuild, and the new value is in the snapshot.
    #[test]
    fn test_step_after_write_rebuilds_with_new_value() {
        crate::core::engine_runtime::block_on(async {
            let (engine, registry, _dir) = make_setup().await;
            let store = registry.default_store().await.unwrap();
            let arena = Arena::new();
            let mut publish = arena.publish_loop(builder(&registry, &engine, ARENA_LEN));
            publish.step(BEFORE_ANY_EXPIRY, Instant::now()).await;

            store.put(b"k", b"new").await.unwrap();
            assert_eq!(publish.step(BEFORE_ANY_EXPIRY, Instant::now()).await, Tick::Rebuilt(PublishOutcome::Published));
            assert_eq!(default_entry(&arena.read(), b"k").expect("written key published").value, b"new");
        })
    }

    fn domain_names(snap: &ShmSnapshot) -> Vec<&str> {
        snap.domains.iter().map(|d| d.name.as_str()).collect()
    }

    // Spec perf/028 test 3: creating and then deleting a domain each make the
    // next step rebuild with the matching domain list.
    #[test]
    fn test_step_after_domain_create_and_delete_rebuilds() {
        crate::core::engine_runtime::block_on(async {
            let (engine, registry, _dir) = make_setup().await;
            let arena = Arena::new();
            let mut publish = arena.publish_loop(builder(&registry, &engine, ARENA_LEN));
            publish.step(BEFORE_ANY_EXPIRY, Instant::now()).await;

            registry.create_domain("fresh").await.unwrap();
            assert_eq!(publish.step(BEFORE_ANY_EXPIRY, Instant::now()).await, Tick::Rebuilt(PublishOutcome::Published));
            assert_eq!(domain_names(&arena.read()), ["default", "fresh"]);

            registry.delete_domain("fresh").await.unwrap();
            assert_eq!(publish.step(BEFORE_ANY_EXPIRY, Instant::now()).await, Tick::Rebuilt(PublishOutcome::Published));
            assert_eq!(domain_names(&arena.read()), ["default"]);
        })
    }

    // Spec perf/028 test 5: a skipped publish keeps the comparison state, so
    // the next step rebuilds without a write and publishes once the pin is gone.
    #[test]
    fn test_step_after_skipped_publish_rebuilds_without_write() {
        crate::core::engine_runtime::block_on(async {
            let (engine, registry, _dir) = make_setup().await;
            let store = registry.default_store().await.unwrap();
            let arena = Arena::new();
            let mut publish = arena.publish_loop(builder(&registry, &engine, ARENA_LEN));
            publish.step(BEFORE_ANY_EXPIRY, Instant::now()).await;
            // Pins buffer B, the target of the publish after next.
            let guard = arena.pin();
            store.put(b"k", b"1").await.unwrap();
            assert_eq!(publish.step(BEFORE_ANY_EXPIRY, Instant::now()).await, Tick::Rebuilt(PublishOutcome::Published));
            store.put(b"k", b"2").await.unwrap();
            assert_eq!(
                publish.step(BEFORE_ANY_EXPIRY, Instant::now()).await,
                Tick::Rebuilt(PublishOutcome::SkippedBusy { buffer: 1 })
            );

            drop(guard);
            assert_eq!(publish.step(BEFORE_ANY_EXPIRY, Instant::now()).await, Tick::Rebuilt(PublishOutcome::Published));
            assert_eq!(default_entry(&arena.read(), b"k").expect("key published").value, b"2");
        })
    }

    // Spec perf/028 test 4, trigger: the step idles before the earliest
    // published `expire_at` and rebuilds from it on. Stamps an hour out keep
    // every entry published, so only the step time decides.
    #[test]
    fn test_step_rebuilds_from_earliest_expiry_on() {
        crate::core::engine_runtime::block_on(async {
            let (engine, registry, _dir) = make_setup().await;
            let store = registry.default_store().await.unwrap();
            let soon = now_secs() + 3600;
            store.put(b"plain", b"v").await.unwrap();
            store.put_unthrottled(b"late", b"v", Some(soon + 3600)).await.unwrap();
            store.put_unthrottled(b"soon", b"v", Some(soon)).await.unwrap();
            let arena = Arena::new();
            let mut publish = arena.publish_loop(builder(&registry, &engine, ARENA_LEN));
            publish.step(BEFORE_ANY_EXPIRY, Instant::now()).await;

            assert_eq!(publish.step(soon - 1, Instant::now()).await, Tick::Idle);
            assert_eq!(publish.step(soon, Instant::now()).await, Tick::Rebuilt(PublishOutcome::Published));
        })
    }

    // Spec perf/028 test 4, removal: once the wall clock reached the stamp, the
    // step at that time drops the expired entry.
    #[test]
    fn test_step_at_expiry_drops_the_expired_entry() {
        crate::core::engine_runtime::block_on(async {
            let (engine, registry, _dir) = make_setup().await;
            let store = registry.default_store().await.unwrap();
            let expire_at = now_secs() + 2;
            store.put_unthrottled(b"ttl", b"v", Some(expire_at)).await.unwrap();
            let arena = Arena::new();
            let mut publish = arena.publish_loop(builder(&registry, &engine, ARENA_LEN));
            publish.step(BEFORE_ANY_EXPIRY, Instant::now()).await;

            // The engine hides expired entries by wall clock: poll it, a fixed
            // sleep could be cut short by a backwards clock step.
            while now_secs() < expire_at {
                compio::time::sleep(Duration::from_millis(50)).await;
            }
            publish.step(expire_at, Instant::now()).await;
            // Absence only: whether the first build still saw the entry depends
            // on scheduling; the trigger itself is the test above.
            assert!(default_entry(&arena.read(), b"ttl").is_none(), "expired entry must be gone");
        })
    }

    // ── Publish metrics and the kick of blocking clients ─────────────────────────

    const SKIPPED_ON_B: Tick = Tick::Rebuilt(PublishOutcome::SkippedBusy { buffer: 1 });

    // Each step feeds the publish counters; with kicking off (the default) a
    // year-long skip run disconnects nobody.
    #[test]
    fn test_step_records_publish_metrics_and_never_kicks_when_off() {
        crate::core::engine_runtime::block_on(async {
            let (engine, registry, _dir) = make_setup().await;
            let arena = Arena::new();
            let mut publish = arena.publish_loop(builder(&registry, &engine, ARENA_LEN));
            // Buffer B is the first publish's target.
            arena.hold(1);
            let t0 = Instant::now();

            assert_eq!(publish.step(BEFORE_ANY_EXPIRY, t0).await, SKIPPED_ON_B);
            assert_eq!(publish.step(BEFORE_ANY_EXPIRY, t0 + 365 * 86_400 * SEC).await, SKIPPED_ON_B);
            assert_eq!(arena.shm_counters(), [0, 2, 2, 0]);
            assert!(!arena.take_kick());

            arena.release(1);
            let published = publish.step(BEFORE_ANY_EXPIRY, t0 + 365 * 86_400 * SEC + SEC).await;
            assert_eq!(published, Tick::Rebuilt(PublishOutcome::Published));
            assert_eq!(arena.shm_counters(), [1, 2, 0, 0], "a publish ends the run");
        })
    }

    // Past the threshold the clients pinning the blocked buffer are kicked and
    // counted once; the measurement restarts, so a client still holding on is
    // not kicked again by the very next skip.
    #[test]
    fn test_step_kicks_blockers_once_past_threshold() {
        crate::core::engine_runtime::block_on(async {
            let (engine, registry, _dir) = make_setup().await;
            let arena = Arena::new();
            let mut publish = arena.kicking_publish_loop(builder(&registry, &engine, ARENA_LEN), KICK_AFTER);
            arena.hold(1);
            let t0 = Instant::now();

            assert_eq!(publish.step(BEFORE_ANY_EXPIRY, t0).await, SKIPPED_ON_B);
            assert_eq!(publish.step(BEFORE_ANY_EXPIRY, t0 + KICK_AFTER).await, SKIPPED_ON_B);
            assert!(!arena.take_kick(), "not past the threshold yet");

            let kicked_at = t0 + KICK_AFTER + SEC;
            assert_eq!(publish.step(BEFORE_ANY_EXPIRY, kicked_at).await, SKIPPED_ON_B);
            assert!(arena.take_kick(), "the blocking client is kicked");
            assert_eq!(arena.shm_counters()[3], 1);

            // This stand-in client ignores the kick and keeps its read.
            assert_eq!(publish.step(BEFORE_ANY_EXPIRY, kicked_at + SEC).await, SKIPPED_ON_B);
            assert!(!arena.take_kick(), "no second kick right after the first");
            assert_eq!(arena.shm_counters(), [0, 4, 4, 1]);
        })
    }
}
