//! RCU read snapshots published into the SHM double buffer.
//!
//! [`SnapshotBuilder`] reads a consistent cut through the key-value engines of
//! all data shards into a compact, rkyv-serialized [`ShmSnapshot`] (a
//! per-domain, key-sorted index of the live inline values);
//! [`SnapshotPublisher`] pushes it through the [`SnapshotWriter`] whenever its
//! content may have changed, checked on an interval and after every MemTable
//! flush. Local clients read it lock-free via `SnapshotGuard` — for
//! VLog-backed values the entry carries only a `is_vlog_pointer` flag and the
//! client falls back to a command-ring GET.

use crate::control::{slots, ControlPlane, Engine, Lifecycle};
use crate::engines::lsm::domain::now_secs;
use crate::engines::lsm::{Domain, LsmStorageEngine, Snapshot, ValueWithMetadata};
use crate::metrics::MetricsStore;
use crate::storage::format::is_expired;
use anyhow::{Context, Result};
use futures::FutureExt;
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

/// Warn on every N-th consecutive skipped publish — about once a second at
/// the default interval.
const SKIP_WARN_EVERY: u32 = 10;

/// Root of the SHM snapshot. rkyv-serialized into the active data buffer and
/// read back by clients via a validated pointer-cast (`rkyv::access`).
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
pub struct ShmSnapshot {
    /// Position in the key-value write-ahead log up to which every record is
    /// in the snapshot; never decreases from one snapshot to the next.
    pub version: u64,
    /// Newest stamp among the shards' read snapshots.
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
    /// Inline value bytes; empty when `is_vlog_pointer`.
    pub value: Vec<u8>,
    /// Unix seconds after which the entry expires; 0 = no expiry.
    pub expire_at: u64,
    /// Value lives in the VLog (`value` empty); client falls back to a GET.
    pub is_vlog_pointer: bool,
    /// Key exists in the explicit NULL state: `value` empty,
    /// never a VLog pointer.
    pub is_null: bool,
}

fn serialize_snapshot(snapshot: &ShmSnapshot) -> AlignedVec {
    rkyv::to_bytes::<rancor::Error>(snapshot)
        .expect("rkyv serialization is infallible for in-memory values")
}

/// Earliest `expire_at > 0` among the snapshot's entries.
fn earliest_expiry(snapshot: &ShmSnapshot) -> Option<u64> {
    snapshot.domains.iter().flat_map(|d| &d.entries).map(|e| e.expire_at).filter(|&at| at > 0).min()
}

/// Where the data a snapshot reflects stands: the key-value write-ahead log
/// and the domain directory. A snapshot built at equal marks holds the same
/// data, unless an entry expired in between.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangeMarks {
    lsn: u64,
    directory: u64,
}

/// Result of [`SnapshotBuilder::build`].
pub struct BuiltSnapshot {
    /// rkyv-serialized [`ShmSnapshot`].
    pub bytes: AlignedVec,
    /// Earliest `expire_at > 0` among the included entries; reaching it
    /// makes the publisher rebuild.
    pub earliest_expiry: Option<u64>,
    /// The marks the snapshot holds the data of.
    pub marks: ChangeMarks,
}

/// Builds an [`ShmSnapshot`] from a consistent cut through the key-value
/// engines of all data shards.
///
/// Reads go straight through the engines (not `DomainStore`) so the system
/// rebuild is not charged against per-domain read rate limits.
pub struct SnapshotBuilder {
    control: Arc<ControlPlane>,
    /// Data-buffer capacity (bytes); the accumulation budget is a fraction of it.
    max_snapshot_size: usize,
}

/// A domain to read: the instance of its owner shard and the read point the
/// cut took there.
struct Source<'a> {
    engine: &'a LsmStorageEngine,
    domain: &'a Domain,
    read_point: &'a Snapshot,
}

impl SnapshotBuilder {
    pub fn new(control: Arc<ControlPlane>, max_snapshot_size: usize) -> Self {
        Self { control, max_snapshot_size }
    }

    /// The current marks, without a cut: where the write-ahead log stands
    /// and the directory's generation.
    async fn marks(&self) -> Result<ChangeMarks> {
        let directory = self.control.directory().generation();
        let shard_0 = self.control.shard_owners().next().context("no data shard runs")?;
        Ok(ChangeMarks { lsn: shard_0.kv.engine().wal_head_lsn().await?, directory })
    }

    /// Builds the snapshot and returns the rkyv-serialized bytes, the
    /// earliest entry expiry and the marks it holds the data of.
    ///
    /// The active key-value domains come from the directory, sorted by name
    /// across all shards; each is read on its owner's instance at the read
    /// snapshot of one consistent cut, which stays pinned until the end. Only
    /// the cut runs on the calling thread; the reads and the serialization
    /// run on a thread of their own. Accumulation stops once a conservative
    /// budget (7/8 of the buffer) is hit; the domains after that one are left
    /// out, the truncated result is logged and still published. Whether it
    /// fits after serialization is the final call of
    /// [`SnapshotWriter::publish`].
    pub async fn build(&self) -> Result<BuiltSnapshot> {
        let directory = self.control.directory();
        let registries: Vec<_> = self.control.shard_owners().map(|owners| Arc::clone(&owners.kv)).collect();
        let shards = u16::try_from(registries.len()).context("too many data shards")?;
        let mut domains = Vec::new();
        for entry in directory.domains(Engine::Kv).filter(|entry| entry.state == Lifecycle::Active) {
            let shard = usize::from(slots::shard_of(entry.slot, shards));
            // `None`: deleted since the directory was read.
            if let Some(domain) = registries[shard].get_domain(&entry.name).await? {
                domains.push((shard, domain));
            }
        }
        let cut = self.control.consistent_cut(Engine::Kv).await?;
        let marks = ChangeMarks { lsn: cut.s, directory: directory.generation() };

        let max_snapshot_size = self.max_snapshot_size;
        let (built_tx, built_rx) = oneshot::channel();
        std::thread::Builder::new()
            .name("luradb-shm".into())
            .spawn(move || {
                let sources: Vec<Source> = domains
                    .iter()
                    .map(|(shard, domain)| Source {
                        engine: registries[*shard].engine(),
                        domain,
                        read_point: cut.reads[*shard].1.snapshot(),
                    })
                    .collect();
                let timestamp = cut.reads.iter().map(|(_, read)| read.snapshot().timestamp().as_u64()).max();
                let built = build_at(&sources, marks, timestamp.unwrap_or_default(), max_snapshot_size);
                drop(sources);
                drop(cut);
                let _ = built_tx.send(built);
            })
            .context("failed to start the SHM snapshot build thread")?;
        built_rx.await.context("the SHM snapshot build thread ended without a result")?
    }
}

/// The blocking part of [`SnapshotBuilder::build`], run on its own thread:
/// reads `sources` in order against the byte budget and serializes the result.
fn build_at(
    sources: &[Source<'_>],
    marks: ChangeMarks,
    timestamp: u64,
    max_snapshot_size: usize,
) -> Result<BuiltSnapshot> {
    let budget = max_snapshot_size / 8 * 7;
    let mut running = 0usize;
    // On truncation: (domain where the budget ran out, count of later domains omitted).
    let mut truncation: Option<(String, usize)> = None;

    let mut domain_indices = Vec::with_capacity(sources.len());
    for (idx, source) in sources.iter().enumerate() {
        let Source { engine, domain, read_point } = source;
        let (entries, truncated) = collect_domain_entries(engine, domain, read_point, budget, &mut running)?;
        domain_indices.push(ShmDomainIndex { name: domain.name.clone(), entries });
        if truncated {
            truncation = Some((domain.name.clone(), sources.len() - idx - 1));
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

    let snapshot = ShmSnapshot { version: marks.lsn, timestamp, domains: domain_indices };
    Ok(BuiltSnapshot { earliest_expiry: earliest_expiry(&snapshot), bytes: serialize_snapshot(&snapshot), marks })
}

/// Collects one domain's entries against the shared byte budget, reading no
/// further than the first entry that would exceed it. Returns the entries,
/// sorted by key, and whether this domain was truncated. `read_point` is the
/// cut's read point on the domain's shard (passed through, never re-taken);
/// `running` accumulates across domains.
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
/// back to a GET), NULL keys, and inline values.
fn to_entry(user_key: Vec<u8>, meta: ValueWithMetadata) -> ShmEntry {
    let (value, is_vlog_pointer) =
        if meta.from_vlog { (Vec::new(), true) } else { (meta.data, false) };
    ShmEntry { key: user_key, value, expire_at: meta.expire_at, is_vlog_pointer, is_null: meta.is_null }
}

/// Counts consecutive skipped publishes so the livelock guard can log without
/// a wall clock — and stays testable without log capture.
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

/// What one publisher step did.
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
    /// Marks of the last publish; `None` before the first.
    published: Option<ChangeMarks>,
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
            published: None,
            earliest_expiry: None,
        }
    }

    /// One tick: rebuilds and publishes only if the snapshot content may have
    /// changed since the last publish, else just confirms the header
    /// timestamp. `now` is the Unix time in seconds checked against the
    /// earliest published expiry; `at` times a skipped publish against the
    /// kick threshold.
    async fn step(&mut self, now: u64, at: Instant) -> Tick {
        let marks = match self.builder.marks().await {
            Ok(marks) => marks,
            Err(e) => {
                tracing::error!("SHM snapshot change check failed: {e:#}");
                return Tick::Failed;
            }
        };
        let expired = self.earliest_expiry.is_some_and(|expiry| is_expired(expiry, now));
        if self.published == Some(marks) && !expired {
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
                self.published = Some(built.marks);
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

/// The MemTable flush notifications of every shard's key-value instance as
/// one: a wait ends at the first and takes those already pending with it,
/// so the flushes of one interval add one publisher step.
struct Flushes(Vec<Arc<Notify>>);

impl Flushes {
    fn of(control: &ControlPlane) -> Self {
        Self(control.shard_owners().map(|owners| owners.kv.engine().flush_notify()).collect())
    }

    async fn wait(&self) {
        let _ = futures::future::select_all(self.0.iter().map(|flush| Box::pin(flush.notified()))).await;
        for flush in &self.0 {
            let _ = flush.notified().now_or_never();
        }
    }
}

/// Background task that publishes snapshots into the SHM double buffer.
///
/// Runs as a task of the control-plane thread's compio runtime: it holds a
/// `!Send` [`SnapshotWriter`] (raw pointers into the mapped buffers) across
/// `.await` points, which the thread-local executor permits.
pub struct SnapshotPublisher {
    builder: SnapshotBuilder,
    manager: Arc<ShmManager>,
    interval: Duration,
    wait_timeout_us: u64,
    /// Reader slots of the registered clients; scanned before every flip.
    readers: Arc<ReaderRegistry>,
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
        metrics: Arc<MetricsStore>,
        kick_after: Duration,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self { builder, manager, interval, wait_timeout_us, readers, metrics, kick_after, shutdown }
    }

    /// Runs until the shutdown signal fires; a step is due every interval and
    /// after MemTable flushes. The loop always survives build and publish
    /// errors (logged and retried on the next tick).
    pub async fn run(self) {
        let SnapshotPublisher {
            builder,
            manager,
            interval,
            wait_timeout_us,
            readers,
            metrics,
            kick_after,
            mut shutdown,
        } = self;
        let flushes = Flushes::of(&builder.control);

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
                _ = flushes.wait() => {}
                _ = shutdown.changed() => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::wal::WriteAheadLog;
    use crate::engines::lsm::domain::DomainConfig;
    use crate::engines::lsm::engine::{LsmEngineConfig, LsmEngineOptions, TestHooks, ThreadHook};
    use crate::engines::lsm::DomainRegistry;
    use crate::ipc::{ReaderSlot, ReaderSlotHandle, ReaderSlotLease, SnapshotGuard, PUBLISH_WAIT_TIMEOUT_US};
    use crate::metrics::{MetricsConfig, MetricsStore};
    use crate::storage::file_manager::FileManager;
    use crate::storage::manifest::ManifestManager;
    use crate::storage::vlog::VLog;
    use rkyv::Archived;
    use std::sync::atomic::Ordering;

    /// The control plane over the test's data shards, and the directory
    /// everything lives in.
    struct Fixture {
        control: Arc<ControlPlane>,
        _dir: tempfile::TempDir,
    }

    async fn make_setup() -> (Arc<LsmStorageEngine>, Arc<DomainRegistry>, Fixture) {
        make_setup_with(LsmEngineOptions::default()).await
    }

    async fn make_setup_with(options: LsmEngineOptions) -> (Arc<LsmStorageEngine>, Arc<DomainRegistry>, Fixture) {
        make_setup_with_hooks(options, TestHooks::default()).await
    }

    /// One data shard with its own log.
    async fn make_setup_with_hooks(
        options: LsmEngineOptions,
        hooks: TestHooks,
    ) -> (Arc<LsmStorageEngine>, Arc<DomainRegistry>, Fixture) {
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
        let bus = Arc::new(crate::core::events::GlobalEventBus::new(64, 64));
        let (control, _) = crate::control::testing::start(dir.path(), Arc::clone(&registry), None, None, bus).await;
        (engine, registry, Fixture { control, _dir: dir })
    }

    /// `n` data shards writing one log through `hub`, `tune` applied to
    /// engine `k`; their registries by shard index.
    async fn shards_with(
        n: u16,
        hub: &crate::core::storage_thread::TestHub,
        dir: tempfile::TempDir,
        tune: impl FnMut(usize, &mut LsmStorageEngine),
    ) -> (Vec<Arc<DomainRegistry>>, Fixture) {
        let shards = crate::control::testing::kv_shards(dir.path(), hub, n, tune).await;
        let registries = shards.iter().map(|shard| Arc::clone(&shard.kv)).collect();
        let bus = Arc::new(crate::core::events::GlobalEventBus::new(64, 64));
        let (control, _) = crate::control::testing::start_shards(dir.path(), shards, bus).await;
        (registries, Fixture { control, _dir: dir })
    }

    /// A hub writing the key-value log under `dir`.
    fn hub_in(dir: &tempfile::TempDir) -> crate::core::storage_thread::TestHub {
        use crate::core::storage_thread::{TestHub, WalTarget};
        TestHub::start(&[(WalTarget::Kv, &dir.path().join("kv.wal"))])
    }

    fn builder(fx: &Fixture, max: usize) -> SnapshotBuilder {
        SnapshotBuilder::new(Arc::clone(&fx.control), max)
    }

    /// Creates the key-value domain `name` through the control plane, on
    /// the shard of `registry`, its owner.
    async fn create(fx: &Fixture, registry: &DomainRegistry, name: &str) -> Domain {
        fx.control.create_domain(Engine::Kv, name, false).await.unwrap();
        registry.get_domain(name).await.unwrap().expect("created on its owner")
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
            let (engine, registry, fx) = make_setup_with_hooks(unrotated(), hooks).await;
            let domain = create(&fx, &registry, "shm").await;
            seed(&engine, &domain.system_prefix, 2_048, 2).await;
            let engine_thread = std::thread::current().id();
            let builder = builder(&fx, ARENA_LEN);
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
                    let (engine, registry, fx) = make_setup_with(unrotated()).await;
                    let domain = create(&fx, &registry, "shm").await;
                    seed(&engine, &domain.system_prefix, n, sstables).await;
                    let builder = builder(&fx, 1 << 30);
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
            let (_, _, fx) = make_setup().await;
            let bytes = builder(&fx, 1 << 20).build().await.unwrap().bytes;
            let snap = decode(&bytes);
            let default = find(&snap, "default").expect("default domain present");
            assert!(default.entries.is_empty(), "no user keys written");
        })
    }

    // 3. 100 keys across 2 domains → all present, sorted per domain.
    #[test]
    fn test_build_many_keys_sorted() {
        crate::core::engine_runtime::block_on(async {
            let (_, registry, fx) = make_setup().await;
            create(&fx, &registry, "alpha").await;
            create(&fx, &registry, "beta").await;
            let a = registry.store("alpha").await.unwrap();
            let b = registry.store("beta").await.unwrap();
            for i in 0..50u32 {
                a.put(format!("key{i:03}").as_bytes(), format!("va{i}").as_bytes()).await.unwrap();
                b.put(format!("key{i:03}").as_bytes(), format!("vb{i}").as_bytes()).await.unwrap();
            }

            let snap = decode(&builder(&fx, 1 << 20).build().await.unwrap().bytes);
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
            let (_, registry, fx) = make_setup().await;
            let store = registry.default_store().await.unwrap();
            let big = vec![b'x'; 2048]; // >= vlog_inline_threshold (1024)
            store.put(b"large", &big).await.unwrap();

            let snap = decode(&builder(&fx, 1 << 20).build().await.unwrap().bytes);
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
            let (_, registry, fx) = make_setup().await;
            let store = registry.default_store().await.unwrap();
            store.put(b"small", b"hello").await.unwrap();

            let snap = decode(&builder(&fx, 1 << 20).build().await.unwrap().bytes);
            let dom = find(&snap, "default").unwrap();
            let entry = dom.entries.iter().find(|e| e.key == b"small").unwrap();
            assert!(!entry.is_vlog_pointer);
            assert!(!entry.is_null);
            assert_eq!(entry.value, b"hello");
        })
    }

    // A NULL key exists in the snapshot, marked is_null, empty value.
    #[test]
    fn test_build_null_key_included_and_flagged() {
        crate::core::engine_runtime::block_on(async {
            let (_, registry, fx) = make_setup().await;
            let store = registry.default_store().await.unwrap();
            store.set_null(b"nulled").await.unwrap();

            let snap = decode(&builder(&fx, 1 << 20).build().await.unwrap().bytes);
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
            let (_, registry, fx) = make_setup().await;
            let store = registry.default_store().await.unwrap();
            for i in 0..200u32 {
                store.put(format!("key{i:04}").as_bytes(), b"val").await.unwrap();
            }
            // Tiny budget forces truncation.
            let snap = decode(&builder(&fx, 2048).build().await.unwrap().bytes);
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
            let (engine, registry, fx) = make_setup_with(unrotated()).await;
            let domain = create(&fx, &registry, "shm").await;
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
            let source = Source { engine: &engine, domain: &domain, read_point: read_point.snapshot() };
            let marks = ChangeMarks { lsn: 0, directory: 0 };
            let before = scanned_versions();
            let built = build_at(std::slice::from_ref(&source), marks, 0, max_snapshot_size).unwrap();
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
            let (engine, registry, fx) = make_setup_with(unrotated()).await;
            let store = registry.default_store().await.unwrap();
            store.put(b"ab", b"2").await.unwrap();
            engine.flush_all_memtables().await.unwrap();
            store.put(b"a", b"1").await.unwrap();
            store.put(b"abc", b"3").await.unwrap();

            let snap = decode(&builder(&fx, 1 << 20).build().await.unwrap().bytes);
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
            let (_, registry, fx) = make_setup().await;
            let store = registry.default_store().await.unwrap();
            store.put(b"alpha", b"1").await.unwrap();
            store.put(b"beta", b"2").await.unwrap();

            let bytes = builder(&fx, 1 << 20).build().await.unwrap().bytes;

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
            let (_, registry, fx) = make_setup().await;
            let store = registry.default_store().await.unwrap();
            store.put(b"stays", b"v").await.unwrap();
            // Already expired regardless of the wall clock.
            store.put_expired_for_test(b"gone", b"v").await.unwrap();

            let snap = decode(&builder(&fx, 1 << 20).build().await.unwrap().bytes);
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
            let (engine, registry, fx) = make_setup_with(unrotated()).await;
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

            let snap = decode(&builder(&fx, 1 << 20).build().await.unwrap().bytes);
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

    // The livelock guard's counting logic — warn on every
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
            let (_, registry, fx) = make_setup().await;
            create(&fx, &registry, "temp").await;
            registry.store("temp").await.unwrap().put(b"k", b"v").await.unwrap();
            fx.control.delete_domain(Engine::Kv, "temp").await.unwrap();

            let snap = decode(&builder(&fx, 1 << 20).build().await.unwrap().bytes);
            assert!(find(&snap, "temp").is_none(), "deleting domain must be absent");
            assert!(find(&snap, "default").is_some(), "active domain still present");
        })
    }

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

    // Without a write, the next step is idle — no build,
    // no flip.
    #[test]
    fn test_step_without_write_is_idle() {
        crate::core::engine_runtime::block_on(async {
            let (_, _, fx) = make_setup().await;
            let arena = Arena::new();
            let mut publish = arena.publish_loop(builder(&fx, ARENA_LEN));
            assert_eq!(publish.step(BEFORE_ANY_EXPIRY, Instant::now()).await, Tick::Rebuilt(PublishOutcome::Published));
            let version = arena.version();

            assert_eq!(publish.step(BEFORE_ANY_EXPIRY, Instant::now()).await, Tick::Idle);
            assert_eq!(arena.version(), version, "an idle step must not flip");
        })
    }

    // An idle step confirms the unchanged snapshot by
    // refreshing `last_update_ns`; `version` stays.
    #[test]
    fn test_idle_step_refreshes_last_update_ns() {
        crate::core::engine_runtime::block_on(async {
            let (_, _, fx) = make_setup().await;
            let arena = Arena::new();
            let mut publish = arena.publish_loop(builder(&fx, ARENA_LEN));
            publish.step(BEFORE_ANY_EXPIRY, Instant::now()).await;
            let version = arena.version();
            arena.header.last_update_ns.store(0, Ordering::Relaxed);

            assert_eq!(publish.step(BEFORE_ANY_EXPIRY, Instant::now()).await, Tick::Idle);
            assert_ne!(arena.header.last_update_ns.load(Ordering::Relaxed), 0, "idle step must refresh it");
            assert_eq!(arena.version(), version);
        })
    }

    // A write between two steps makes the second one
    // rebuild, and the new value is in the snapshot.
    #[test]
    fn test_step_after_write_rebuilds_with_new_value() {
        crate::core::engine_runtime::block_on(async {
            let (_, registry, fx) = make_setup().await;
            let store = registry.default_store().await.unwrap();
            let arena = Arena::new();
            let mut publish = arena.publish_loop(builder(&fx, ARENA_LEN));
            publish.step(BEFORE_ANY_EXPIRY, Instant::now()).await;

            store.put(b"k", b"new").await.unwrap();
            assert_eq!(publish.step(BEFORE_ANY_EXPIRY, Instant::now()).await, Tick::Rebuilt(PublishOutcome::Published));
            assert_eq!(default_entry(&arena.read(), b"k").expect("written key published").value, b"new");
        })
    }

    fn domain_names(snap: &ShmSnapshot) -> Vec<&str> {
        snap.domains.iter().map(|d| d.name.as_str()).collect()
    }

    // Creating and then deleting a domain each make the
    // next step rebuild with the matching domain list.
    #[test]
    fn test_step_after_domain_create_and_delete_rebuilds() {
        crate::core::engine_runtime::block_on(async {
            let (_, registry, fx) = make_setup().await;
            let arena = Arena::new();
            let mut publish = arena.publish_loop(builder(&fx, ARENA_LEN));
            publish.step(BEFORE_ANY_EXPIRY, Instant::now()).await;

            create(&fx, &registry, "fresh").await;
            assert_eq!(publish.step(BEFORE_ANY_EXPIRY, Instant::now()).await, Tick::Rebuilt(PublishOutcome::Published));
            assert_eq!(domain_names(&arena.read()), ["default", "fresh"]);

            fx.control.delete_domain(Engine::Kv, "fresh").await.unwrap();
            assert_eq!(publish.step(BEFORE_ANY_EXPIRY, Instant::now()).await, Tick::Rebuilt(PublishOutcome::Published));
            assert_eq!(domain_names(&arena.read()), ["default"]);
        })
    }

    // A skipped publish keeps the comparison state, so
    // the next step rebuilds without a write and publishes once the pin is gone.
    #[test]
    fn test_step_after_skipped_publish_rebuilds_without_write() {
        crate::core::engine_runtime::block_on(async {
            let (_, registry, fx) = make_setup().await;
            let store = registry.default_store().await.unwrap();
            let arena = Arena::new();
            let mut publish = arena.publish_loop(builder(&fx, ARENA_LEN));
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

    // Expiry trigger: the step idles before the earliest
    // published `expire_at` and rebuilds from it on. Stamps an hour out keep
    // every entry published, so only the step time decides.
    #[test]
    fn test_step_rebuilds_from_earliest_expiry_on() {
        crate::core::engine_runtime::block_on(async {
            let (_, registry, fx) = make_setup().await;
            let store = registry.default_store().await.unwrap();
            let soon = now_secs() + 3600;
            store.put(b"plain", b"v").await.unwrap();
            store.put_unthrottled(b"late", b"v", Some(soon + 3600)).await.unwrap();
            store.put_unthrottled(b"soon", b"v", Some(soon)).await.unwrap();
            let arena = Arena::new();
            let mut publish = arena.publish_loop(builder(&fx, ARENA_LEN));
            publish.step(BEFORE_ANY_EXPIRY, Instant::now()).await;

            assert_eq!(publish.step(soon - 1, Instant::now()).await, Tick::Idle);
            assert_eq!(publish.step(soon, Instant::now()).await, Tick::Rebuilt(PublishOutcome::Published));
        })
    }

    // Expiry removal: once the wall clock reached the stamp, the
    // step at that time drops the expired entry.
    #[test]
    fn test_step_at_expiry_drops_the_expired_entry() {
        crate::core::engine_runtime::block_on(async {
            let (_, registry, fx) = make_setup().await;
            let store = registry.default_store().await.unwrap();
            let expire_at = now_secs() + 2;
            store.put_unthrottled(b"ttl", b"v", Some(expire_at)).await.unwrap();
            let arena = Arena::new();
            let mut publish = arena.publish_loop(builder(&fx, ARENA_LEN));
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

    const SKIPPED_ON_B: Tick = Tick::Rebuilt(PublishOutcome::SkippedBusy { buffer: 1 });

    // Each step feeds the publish counters; with kicking off (the default) a
    // year-long skip run disconnects nobody.
    #[test]
    fn test_step_records_publish_metrics_and_never_kicks_when_off() {
        crate::core::engine_runtime::block_on(async {
            let (_, _, fx) = make_setup().await;
            let arena = Arena::new();
            let mut publish = arena.publish_loop(builder(&fx, ARENA_LEN));
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
            let (_, _, fx) = make_setup().await;
            let arena = Arena::new();
            let mut publish = arena.kicking_publish_loop(builder(&fx, ARENA_LEN), KICK_AFTER);
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

    /// Creates a domain on shard `k` of two for each `(k, seed)`, with
    /// `keys` 64-byte entries; the names sort in the order given.
    async fn domains_on(
        fx: &Fixture,
        registries: &[Arc<DomainRegistry>],
        placement: &[(u16, u64)],
        keys: u32,
    ) -> Vec<String> {
        let mut names = Vec::new();
        for &(k, name_seed) in placement {
            let name = slots::domain_name_for_shard(k, 2, name_seed);
            let registry = &registries[usize::from(k)];
            let domain = create(fx, registry, &name).await;
            seed(registry.engine(), &domain.system_prefix, keys, 0).await;
            names.push(name);
        }
        names
    }

    /// Shards 0, 1, 0, 1 in name order.
    const ALTERNATING: [(u16, u64); 4] = [(0, 1), (1, 2), (0, 3), (1, 4)];

    // With two data shards, the snapshot holds the domains of both, the
    // default domain once, sorted by name across the shards, each with its
    // own entries.
    #[test]
    fn test_build_holds_the_domains_of_both_shards_sorted_by_name() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let hub = hub_in(&dir);
            let (registries, fx) = shards_with(2, &hub, dir, |_, _| {}).await;
            let names = domains_on(&fx, &registries, &ALTERNATING, 3).await;
            let k = slots::domain_name_for_shard(1, 2, 5);
            create(&fx, &registries[1], &k).await;
            registries[1].store(&k).await.unwrap().put(b"key", "clé".as_bytes()).await.unwrap();

            let snap = decode(&builder(&fx, ARENA_LEN).build().await.unwrap().bytes);
            let mut expected: Vec<&str> = names.iter().map(String::as_str).chain([k.as_str(), "default"]).collect();
            expected.sort_unstable();
            assert_eq!(domain_names(&snap), expected);
            for name in &names {
                let keys: Vec<&[u8]> = find(&snap, name).unwrap().entries.iter().map(|e| e.key.as_slice()).collect();
                assert_eq!(keys, [b"c000000".as_slice(), b"c000001", b"c000002"], "{name}");
            }
            let entry = &find(&snap, &k).unwrap().entries[0];
            assert_eq!((entry.key.as_slice(), entry.value.as_slice()), (b"key".as_slice(), "clé".as_bytes()));
        })
    }

    // Truncation runs over the domains in name order across the shards: two
    // builds of unchanged data both stop in the same domain, after the same
    // entry, and leave out the same domains.
    #[test]
    fn test_truncation_stops_in_the_same_domain_across_shards_every_build() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let hub = hub_in(&dir);
            let (registries, fx) = shards_with(2, &hub, dir, |_, _| {}).await;
            let names = domains_on(&fx, &registries, &ALTERNATING, 20).await;
            // 49 entries of 7-byte keys and 64-byte values fit: 20, 20, then 9.
            let max_snapshot_size = 7714;
            let builder = builder(&fx, max_snapshot_size);

            let first = decode(&builder.build().await.unwrap().bytes);
            let second = decode(&builder.build().await.unwrap().bytes);
            let counts = |snap: &ShmSnapshot| -> Vec<(String, usize)> {
                snap.domains.iter().map(|d| (d.name.clone(), d.entries.len())).collect()
            };
            assert_eq!(counts(&first), [(names[0].clone(), 20), (names[1].clone(), 20), (names[2].clone(), 9)]);
            assert_eq!(counts(&second), counts(&first));
        })
    }

    // A writer confirms a key on shard 0, then the same key on shard 1, over
    // and over, while snapshots are built after a seeded number of yields:
    // every snapshot that holds a key on shard 1 holds it on shard 0.
    #[test]
    fn test_every_snapshot_with_a_write_on_shard_1_holds_the_one_confirmed_before_on_shard_0() {
        const PAIRS: usize = 200;
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let hub = hub_in(&dir);
            let (registries, fx) = shards_with(2, &hub, dir, |_, _| {}).await;
            let names = domains_on(&fx, &registries, &ALTERNATING[..2], 0).await;
            let mut targets = Vec::new();
            for (registry, name) in registries.iter().zip(&names) {
                let prefix = registry.get_domain(name).await.unwrap().unwrap().system_prefix;
                targets.push((Arc::clone(registry.engine()), prefix));
            }
            let writer = compio::runtime::spawn(async move {
                for i in 0..PAIRS {
                    for (engine, prefix) in &targets {
                        engine.put(&[prefix.as_slice(), format!("k{i:04}").as_bytes()].concat(), b"v").await.unwrap();
                    }
                }
            });
            let builder = builder(&fx, ARENA_LEN);
            let keys = |snap: &ShmSnapshot, name: &str| -> Vec<Vec<u8>> {
                find(snap, name).unwrap().entries.iter().map(|e| e.key.clone()).collect()
            };
            let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
            let mut built = 0;
            while !writer.is_finished() {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                for _ in 0..state % 16 {
                    tokio::task::yield_now().await;
                }
                let snap = decode(&builder.build().await.unwrap().bytes);
                let on_0 = keys(&snap, &names[0]);
                let on_1 = keys(&snap, &names[1]);
                assert!(on_1.iter().all(|key| on_0.contains(key)), "{on_1:?} on shard 1, {on_0:?} on shard 0");
                built += 1;
            }
            writer.await.unwrap();
            let snap = decode(&builder.build().await.unwrap().bytes);
            assert_eq!((keys(&snap, &names[0]).len(), keys(&snap, &names[1]).len()), (PAIRS, PAIRS));
            assert!(built > 0, "no snapshot built while the writer ran");
        })
    }

    // Over publications with writes on both shards between them, `version`
    // never falls and rises with every write; without a write the step is
    // idle and the version stays.
    #[test]
    fn test_version_never_falls_and_rises_with_every_write_on_any_shard() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let hub = hub_in(&dir);
            let (registries, fx) = shards_with(2, &hub, dir, |_, _| {}).await;
            let names = domains_on(&fx, &registries, &ALTERNATING[..2], 0).await;
            let arena = Arena::new();
            let mut publish = arena.publish_loop(builder(&fx, ARENA_LEN));
            publish.step(BEFORE_ANY_EXPIRY, Instant::now()).await;
            let mut version = arena.read().version;

            for i in 0..6usize {
                let (registry, name) = (&registries[i % 2], &names[i % 2]);
                registry.store(name).await.unwrap().put(format!("k{i}").as_bytes(), b"v").await.unwrap();
                assert_eq!(publish.step(BEFORE_ANY_EXPIRY, Instant::now()).await, Tick::Rebuilt(PublishOutcome::Published));
                let next = arena.read().version;
                assert!(next > version, "write {i} on shard {}: {next} after {version}", i % 2);
                version = next;
            }
            assert_eq!(publish.step(BEFORE_ANY_EXPIRY, Instant::now()).await, Tick::Idle);
            assert_eq!(arena.read().version, version);
        })
    }

    // Three flushes over both shards before the publisher waits end one
    // wait, not three: the next wait finds nothing pending.
    #[test]
    fn test_flushes_on_every_shard_before_a_wait_end_one_wait() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let hub = hub_in(&dir);
            let (registries, fx) = shards_with(2, &hub, dir, |_, _| {}).await;
            let flushes = Flushes::of(&fx.control);
            for (i, k) in [0, 1, 0].into_iter().enumerate() {
                let engine = registries[k].engine();
                engine.put(format!("flush-{i}").as_bytes(), b"v").await.unwrap();
                engine.flush_all_memtables().await.unwrap();
            }

            let mut waits = 0;
            while flushes.wait().now_or_never().is_some() {
                waits += 1;
            }
            assert_eq!(waits, 1);
        })
    }

    // Diagnosis, asserts no timing: what one publication costs — the cut,
    // with a drain on every shard, alone and with the reads and the
    // serialization — by shard count and domain count, 100 keys per domain.
    // All shards serve on one thread here. Run it in release:
    // `cargo test --release --lib -- --ignored --nocapture publication_cost`
    //
    // Measured once, 2026-10-22, release build on WSL2, every shard a task on
    // one idle thread (a lower bound, no write stall), 50 builds each, 100 keys
    // per domain — cut (pin, drain, register) / whole publication (cut, read,
    // serialize):
    //
    // | shards | domains | cut      | whole publication |
    // |--------|---------|----------|-------------------|
    // | 1      | 10      | 49 µs    | 353 µs            |
    // | 1      | 100     | 59 µs    | 3.58 ms           |
    // | 2      | 10      | 53 µs    | 329 µs            |
    // | 2      | 100     | 67 µs    | 3.35 ms           |
    // | 4      | 10      | 49 µs    | 349 µs            |
    // | 4      | 100     | 53 µs    | 3.34 ms           |
    #[test]
    #[ignore = "diagnosis: prints publication costs"]
    fn publication_cost_by_shard_and_domain_count() {
        const RUNS: u32 = 50;
        for shards in [1u16, 2, 4] {
            for domains in [10usize, 100] {
                let (cut, build) = crate::core::engine_runtime::block_on(async {
                    let dir = tempfile::TempDir::new().unwrap();
                    let hub = hub_in(&dir);
                    let (registries, fx) = shards_with(shards, &hub, dir, |_, _| {}).await;
                    for i in 0..domains {
                        let name = format!("m{i:03}");
                        let owner = &registries[usize::from(slots::shard_of_domain(&name, shards))];
                        let domain = create(&fx, owner, &name).await;
                        seed(owner.engine(), &domain.system_prefix, 100, 0).await;
                    }
                    let builder = builder(&fx, 1 << 30);
                    builder.build().await.unwrap();
                    let start = Instant::now();
                    for _ in 0..RUNS {
                        drop(fx.control.consistent_cut(Engine::Kv).await.unwrap());
                    }
                    let cut = start.elapsed() / RUNS;
                    let start = Instant::now();
                    for _ in 0..RUNS {
                        builder.build().await.unwrap();
                    }
                    (cut, start.elapsed() / RUNS)
                });
                println!("publication: {shards} shard(s), {domains:>3} domains: cut {cut:?}, build {build:?}");
            }
        }
    }
}
