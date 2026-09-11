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

use crate::core::coop::{self, YieldEvery};
use crate::engines::lsm::domain::now_secs;
use crate::engines::lsm::{Domain, DomainRegistry, LsmStorageEngine, RegistrySnapshot, ValueWithMetadata};
use crate::storage::format::is_expired;
use anyhow::Result;
use rkyv::util::AlignedVec;
use rkyv::{rancor, Archive, Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{watch, Notify};

use super::{PublishOutcome, ReaderRegistry, ShmManager, SnapshotWriter, StateHeader};

/// Per-entry byte estimate on top of key+value: covers rkyv relative pointers,
/// length fields, the fixed `ShmEntry` fields and alignment padding. Kept
/// generous so the accumulation budget stays conservative.
const PER_ENTRY_OVERHEAD: usize = 64;

/// Warn on every N-th consecutive skipped publish (spec perf/012 §9) — about
/// once a second at the default interval.
const SKIP_WARN_EVERY: u32 = 10;

/// Entries collected between two yields (spec perf/017 A2).
const ENTRY_YIELD_INTERVAL: u32 = 1024;

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
    /// Accumulation stops once a conservative budget (7/8 of the buffer) is hit;
    /// the truncated result is logged and still published. Whether it fits after
    /// serialization is the final call of [`SnapshotWriter::publish`].
    pub async fn build(&self) -> Result<BuiltSnapshot> {
        let snap = self.engine.snapshot();
        // Point-in-time stamp of this snapshot = its MVCC read timestamp.
        let ts = snap.snapshot().timestamp().as_u64();

        // Active domains only (list_domains filters Deleting), sorted by name so
        // truncation is deterministic (spec §6 first-come-first-served).
        let mut domains = self.registry.list_domains().await?;
        domains.sort_by(|a, b| a.name.cmp(&b.name));

        let budget = self.max_snapshot_size / 8 * 7;
        let mut running = 0usize;
        // On truncation: (domain where the budget ran out, count of later domains omitted).
        let mut truncation: Option<(String, usize)> = None;

        let mut domain_indices = Vec::with_capacity(domains.len());
        for (idx, domain) in domains.iter().enumerate() {
            let (entries, truncated) =
                self.collect_domain_entries(domain, &snap, budget, &mut running).await?;
            domain_indices.push(ShmDomainIndex { name: domain.name.clone(), entries });
            if truncated {
                // Remaining name-sorted domains are dropped entirely (spec §6 FCFS).
                truncation = Some((domain.name.clone(), domains.len() - idx - 1));
                break;
            }
        }

        if let Some((domain, omitted)) = &truncation {
            tracing::warn!(
                "SHM snapshot truncated in domain '{domain}' ({omitted} later domain(s) omitted): \
                 accumulated size exceeded budget of {} bytes (buffer {})",
                budget,
                self.max_snapshot_size
            );
        }

        let snapshot = ShmSnapshot { version: ts, timestamp: ts, domains: domain_indices };
        // Serialization and the expiry scan are pure CPU work over an owned
        // value — they run on the blocking pool (spec perf/017 A4).
        Ok(coop::offload(move || BuiltSnapshot {
            earliest_expiry: earliest_expiry(&snapshot),
            bytes: serialize_snapshot(&snapshot),
        })
        .await)
    }

    /// Collects one domain's entries against the shared byte budget, stopping at
    /// the first entry that would exceed it. Returns the entries and whether this
    /// domain was truncated. `snap` is the single MVCC read point (passed
    /// through, never re-taken); `running` accumulates across domains.
    async fn collect_domain_entries(
        &self,
        domain: &Domain,
        snap: &RegistrySnapshot,
        budget: usize,
        running: &mut usize,
    ) -> Result<(Vec<ShmEntry>, bool)> {
        let prefix_len = domain.system_prefix.len();
        let raw_keys = self.engine.scan_keys(&domain.system_prefix).await?;
        let mut entries = Vec::new();
        let mut truncated = false;
        let mut coop = YieldEvery::new(ENTRY_YIELD_INTERVAL);
        for raw_key in raw_keys {
            coop.tick().await;
            let meta = match self.engine.get_with_metadata(&raw_key, snap.snapshot()).await? {
                Some(m) => m,
                None => continue, // vanished or expired between scan and read
            };
            let user_key = raw_key[prefix_len..].to_vec();
            let cost = user_key.len() + meta.data.len() + PER_ENTRY_OVERHEAD;
            if *running + cost > budget {
                truncated = true;
                break;
            }
            *running += cost;
            entries.push(to_entry(user_key, meta));
        }
        Ok((entries, truncated))
    }
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
        self.consecutive % SKIP_WARN_EVERY == 0
    }

    /// Records a successful publish; `Some(n)` if it ended a run of `n` skips.
    fn on_published(&mut self) -> Option<u32> {
        let skipped = std::mem::take(&mut self.consecutive);
        (skipped > 0).then_some(skipped)
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
    skips: SkipTracker,
    /// Change epoch of the last publish; `None` before the first.
    published_epoch: Option<u64>,
    /// Earliest `expire_at > 0` among the last published entries.
    earliest_expiry: Option<u64>,
}

impl<'w> PublishLoop<'w> {
    fn new(builder: SnapshotBuilder, writer: SnapshotWriter<'w>, readers: Arc<ReaderRegistry>) -> Self {
        Self {
            builder,
            writer,
            readers,
            skips: SkipTracker::default(),
            published_epoch: None,
            earliest_expiry: None,
        }
    }

    /// One tick (spec perf/028 A2): rebuilds and publishes only if the
    /// snapshot content may have changed since the last publish, else just
    /// confirms the header timestamp (A3). `now` is the Unix time in seconds
    /// checked against the earliest published expiry.
    async fn step(&mut self, now: u64) -> Tick {
        // Read before `build` takes its MVCC snapshot: a write in between
        // leaves the epoch behind and triggers the next rebuild.
        let epoch = self.builder.engine.change_epoch();
        let expired = self.earliest_expiry.is_some_and(|at| is_expired(at, now));
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
                // Only a publish moves the comparison state (A2.4).
                self.published_epoch = Some(epoch);
                self.earliest_expiry = built.earliest_expiry;
                if let Some(n) = self.skips.on_published() {
                    tracing::info!("SHM snapshot publishing resumed after {n} skipped publishes");
                }
            }
            // No force-flip (spec perf/012 §9): a pinned buffer is never
            // overwritten, the state is only made visible.
            PublishOutcome::SkippedBusy { buffer } => {
                if self.skips.on_skipped() {
                    tracing::warn!(
                        "SHM snapshot stale: {} consecutive publishes skipped, buffer {buffer} \
                         still pinned by (client_id, readers) {:?}",
                        self.skips.consecutive,
                        self.readers.blockers(buffer)
                    );
                }
            }
        }
        Tick::Rebuilt(outcome)
    }
}

/// Background task that publishes snapshots into the SHM double buffer.
///
/// Runs via `tokio_uring::spawn`: it holds a `!Send` [`SnapshotWriter`] (raw
/// pointers into the mapped buffers) across `.await` points, which the
/// tokio-uring local executor permits.
pub struct SnapshotPublisher {
    builder: SnapshotBuilder,
    manager: Arc<ShmManager>,
    interval: Duration,
    wait_timeout_us: u64,
    /// Reader slots of the registered clients; scanned before every flip.
    readers: Arc<ReaderRegistry>,
    /// Notified after each MemTable flush — an extra tick (spec §4b).
    flush_notify: Arc<Notify>,
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
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self { builder, manager, interval, wait_timeout_us, readers, flush_notify, shutdown }
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
        let mut publish = PublishLoop::new(builder, writer, readers);

        loop {
            if *shutdown.borrow() {
                break;
            }
            publish.step(now_secs()).await;

            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
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
    use crate::engines::lsm::engine::LsmEngineOptions;
    use crate::ipc::{ReaderSlot, ReaderSlotHandle, ReaderSlotLease, SnapshotGuard, PUBLISH_WAIT_TIMEOUT_US};
    use crate::metrics::{MetricsConfig, MetricsStore};
    use crate::storage::file_manager::FileManager;
    use crate::storage::manifest::ManifestManager;
    use crate::storage::vlog::VLog;
    use rkyv::Archived;
    use std::sync::atomic::Ordering;

    async fn make_setup() -> (Arc<LsmStorageEngine>, Arc<DomainRegistry>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let wal_path = dir.path().join("wal.log");
        let wal = Arc::new(WriteAheadLog::new(&wal_path).await.unwrap());
        let vlog_path = dir.path().join("vlog.log");
        let vlog = Arc::new(VLog::new(&vlog_path).await.unwrap());
        let fm = Arc::new(FileManager::new(dir.path()).await.unwrap());
        let mm = Arc::new(ManifestManager::new(dir.path()));
        let engine = Arc::new(
            LsmStorageEngine::new(
                wal,
                wal_path,
                vlog,
                vlog_path,
                fm,
                mm,
                LsmEngineOptions::default(),
            )
            .await
            .unwrap(),
        );
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

    // Spec perf/017 test 7: a 20 000-key snapshot build hands the thread
    // back, so a point `get` spawned after it answers first.
    #[tokio::test]
    async fn test_snapshot_build_interleaves_with_get() {
        use crate::engines::lsm::engine::BatchOp;
        use crate::engines::StorageEngine;

        let (engine, registry, _dir) = make_setup().await;
        let domain = registry.create_domain("shm").await.unwrap();
        let ops: Vec<BatchOp> = (0..20_000u32)
            .map(|i| BatchOp::Put {
                key: [domain.system_prefix.as_slice(), format!("k:{i:05}").as_bytes()].concat(),
                value: b"v".to_vec(),
            })
            .collect();
        engine.write_batch(ops).await.unwrap();

        let builder = builder(&registry, &engine, 32 * 1024 * 1024);
        let reader = Arc::clone(&engine);
        let probe_key = [domain.system_prefix.as_slice(), b"k:00001".as_slice()].concat();
        let order = crate::core::coop::completion_order(
            async move {
                let bytes = builder.build().await.unwrap().bytes;
                let snapshot = decode(bytes.as_slice());
                assert_eq!(find(&snapshot, "shm").unwrap().entries.len(), 20_000);
            },
            async move {
                assert!(reader.get(&probe_key).await.unwrap().is_some());
            },
        )
        .await;
        assert_eq!(order, ["small", "long"]);
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
    #[tokio::test]
    async fn test_build_empty_db() {
        let (engine, registry, _dir) = make_setup().await;
        let bytes = builder(&registry, &engine, 1 << 20).build().await.unwrap().bytes;
        let snap = decode(&bytes);
        let default = find(&snap, "default").expect("default domain present");
        assert!(default.entries.is_empty(), "no user keys written");
    }

    // 3. 100 keys across 2 domains → all present, sorted per domain.
    #[tokio::test]
    async fn test_build_many_keys_sorted() {
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
    }

    // 4. VLog-backed value → is_vlog_pointer = true, value empty.
    #[tokio::test]
    async fn test_build_vlog_pointer() {
        let (engine, registry, _dir) = make_setup().await;
        let store = registry.default_store().await.unwrap();
        let big = vec![b'x'; 2048]; // >= vlog_inline_threshold (1024)
        store.put(b"large", &big).await.unwrap();

        let snap = decode(&builder(&registry, &engine, 1 << 20).build().await.unwrap().bytes);
        let dom = find(&snap, "default").unwrap();
        let entry = dom.entries.iter().find(|e| e.key == b"large").unwrap();
        assert!(entry.is_vlog_pointer);
        assert!(entry.value.is_empty(), "VLog value must not be embedded");
    }

    // 5. Inline value → is_vlog_pointer = false, value carries the data.
    #[tokio::test]
    async fn test_build_inline_value() {
        let (engine, registry, _dir) = make_setup().await;
        let store = registry.default_store().await.unwrap();
        store.put(b"small", b"hello").await.unwrap();

        let snap = decode(&builder(&registry, &engine, 1 << 20).build().await.unwrap().bytes);
        let dom = find(&snap, "default").unwrap();
        let entry = dom.entries.iter().find(|e| e.key == b"small").unwrap();
        assert!(!entry.is_vlog_pointer);
        assert!(!entry.is_null);
        assert_eq!(entry.value, b"hello");
    }

    // kv/018: a NULL key exists in the snapshot, marked is_null, empty value.
    #[tokio::test]
    async fn test_build_null_key_included_and_flagged() {
        let (engine, registry, _dir) = make_setup().await;
        let store = registry.default_store().await.unwrap();
        store.set_null(b"nulled").await.unwrap();

        let snap = decode(&builder(&registry, &engine, 1 << 20).build().await.unwrap().bytes);
        let dom = find(&snap, "default").unwrap();
        let entry = dom.entries.iter().find(|e| e.key == b"nulled").expect("NULL key present");
        assert!(entry.is_null);
        assert!(!entry.is_vlog_pointer);
        assert!(entry.value.is_empty());
    }

    // 6. Over-budget snapshot is truncated (fewer entries than written).
    #[tokio::test]
    async fn test_build_truncates_over_budget() {
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
    }

    // 7 & 8. End-to-end: build → publish into an SHM arena → client reads via
    // SnapshotGuard + rkyv::access, incl. the zero-copy value view and a
    // binary search over the sorted entries.
    #[tokio::test]
    async fn test_publisher_end_to_end_client_read() {
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
            )
        };
        let _lease = readers.register(handle);

        let len = 1 << 20;
        let mut buf_a = vec![0u8; len];
        let mut buf_b = vec![0u8; len];
        // Safe: single writer, two distinct buffers of `len` bytes, header valid.
        let writer = unsafe {
            SnapshotWriter::new(
                &*header,
                buf_a.as_mut_ptr(),
                buf_b.as_mut_ptr(),
                len,
                PUBLISH_WAIT_TIMEOUT_US,
                Arc::clone(&readers),
            )
        };
        assert_eq!(writer.publish(&bytes).unwrap(), PublishOutcome::Published);
        drop(writer);

        let guard = SnapshotGuard::acquire(&*header, &slot, &buf_a, &buf_b).expect("snapshot available");

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
    }

    // 9. Expired-TTL key does not appear in the snapshot.
    #[tokio::test]
    async fn test_expired_ttl_absent() {
        let (engine, registry, _dir) = make_setup().await;
        let store = registry.default_store().await.unwrap();
        store.put(b"stays", b"v").await.unwrap();
        // Already expired regardless of the wall clock (spec general/033).
        store.put_expired_for_test(b"gone", b"v").await.unwrap();

        let snap = decode(&builder(&registry, &engine, 1 << 20).build().await.unwrap().bytes);
        let dom = find(&snap, "default").unwrap();
        assert!(dom.entries.iter().any(|e| e.key == b"stays"));
        assert!(!dom.entries.iter().any(|e| e.key == b"gone"), "expired key must be absent");
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

    // 10. A domain in Deleting state does not appear in the snapshot.
    #[tokio::test]
    async fn test_deleting_domain_absent() {
        let (engine, registry, _dir) = make_setup().await;
        registry.create_domain("temp").await.unwrap();
        registry.store("temp").await.unwrap().put(b"k", b"v").await.unwrap();
        registry.delete_domain("temp").await.unwrap();

        let snap = decode(&builder(&registry, &engine, 1 << 20).build().await.unwrap().bytes);
        assert!(find(&snap, "temp").is_none(), "deleting domain must be absent");
        assert!(find(&snap, "default").is_some(), "active domain still present");
    }

    // ── Spec perf/028: publisher step ─────────────────────────────────────────────

    const ARENA_LEN: usize = 1 << 20;

    /// Step time for tests without TTL entries.
    const BEFORE_ANY_EXPIRY: u64 = 0;

    /// SHM stand-in for the step tests: state header, two data buffers and one
    /// registered client slot.
    struct Arena {
        header: Box<StateHeader>,
        slot: Arc<ReaderSlot>,
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
            let readers = Arc::new(ReaderRegistry::new());
            // Safe: the pointer targets the slot inside `slot`, whose `Arc`
            // clone the handle keeps alive.
            let handle = unsafe {
                ReaderSlotHandle::new(
                    1,
                    Arc::as_ptr(&slot),
                    Arc::clone(&slot) as Arc<dyn std::any::Any + Send + Sync>,
                )
            };
            let _lease = readers.register(handle);
            let (mut buf_a, mut buf_b) = (vec![0u8; ARENA_LEN], vec![0u8; ARENA_LEN]);
            let (ptr_a, ptr_b) = (buf_a.as_mut_ptr(), buf_b.as_mut_ptr());
            Self { header, slot, readers, _lease, buf_a, buf_b, ptr_a, ptr_b }
        }

        /// Publisher loop writing into this arena — its only writer.
        fn publish_loop(&self, builder: SnapshotBuilder) -> PublishLoop<'_> {
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
            PublishLoop::new(builder, writer, Arc::clone(&self.readers))
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
    #[tokio::test]
    async fn test_step_without_write_is_idle() {
        let (engine, registry, _dir) = make_setup().await;
        let arena = Arena::new();
        let mut publish = arena.publish_loop(builder(&registry, &engine, ARENA_LEN));
        assert_eq!(publish.step(BEFORE_ANY_EXPIRY).await, Tick::Rebuilt(PublishOutcome::Published));
        let version = arena.version();

        assert_eq!(publish.step(BEFORE_ANY_EXPIRY).await, Tick::Idle);
        assert_eq!(arena.version(), version, "an idle step must not flip");
    }

    // Spec perf/028 test 6: an idle step confirms the unchanged snapshot by
    // refreshing `last_update_ns`; `version` stays.
    #[tokio::test]
    async fn test_idle_step_refreshes_last_update_ns() {
        let (engine, registry, _dir) = make_setup().await;
        let arena = Arena::new();
        let mut publish = arena.publish_loop(builder(&registry, &engine, ARENA_LEN));
        publish.step(BEFORE_ANY_EXPIRY).await;
        let version = arena.version();
        arena.header.last_update_ns.store(0, Ordering::Relaxed);

        assert_eq!(publish.step(BEFORE_ANY_EXPIRY).await, Tick::Idle);
        assert_ne!(arena.header.last_update_ns.load(Ordering::Relaxed), 0, "idle step must refresh it");
        assert_eq!(arena.version(), version);
    }

    // Spec perf/028 test 2: a write between two steps makes the second one
    // rebuild, and the new value is in the snapshot.
    #[tokio::test]
    async fn test_step_after_write_rebuilds_with_new_value() {
        let (engine, registry, _dir) = make_setup().await;
        let store = registry.default_store().await.unwrap();
        let arena = Arena::new();
        let mut publish = arena.publish_loop(builder(&registry, &engine, ARENA_LEN));
        publish.step(BEFORE_ANY_EXPIRY).await;

        store.put(b"k", b"new").await.unwrap();
        assert_eq!(publish.step(BEFORE_ANY_EXPIRY).await, Tick::Rebuilt(PublishOutcome::Published));
        assert_eq!(default_entry(&arena.read(), b"k").expect("written key published").value, b"new");
    }

    fn domain_names(snap: &ShmSnapshot) -> Vec<&str> {
        snap.domains.iter().map(|d| d.name.as_str()).collect()
    }

    // Spec perf/028 test 3: creating and then deleting a domain each make the
    // next step rebuild with the matching domain list.
    #[tokio::test]
    async fn test_step_after_domain_create_and_delete_rebuilds() {
        let (engine, registry, _dir) = make_setup().await;
        let arena = Arena::new();
        let mut publish = arena.publish_loop(builder(&registry, &engine, ARENA_LEN));
        publish.step(BEFORE_ANY_EXPIRY).await;

        registry.create_domain("fresh").await.unwrap();
        assert_eq!(publish.step(BEFORE_ANY_EXPIRY).await, Tick::Rebuilt(PublishOutcome::Published));
        assert_eq!(domain_names(&arena.read()), ["default", "fresh"]);

        registry.delete_domain("fresh").await.unwrap();
        assert_eq!(publish.step(BEFORE_ANY_EXPIRY).await, Tick::Rebuilt(PublishOutcome::Published));
        assert_eq!(domain_names(&arena.read()), ["default"]);
    }

    // Spec perf/028 test 5: a skipped publish keeps the comparison state, so
    // the next step rebuilds without a write and publishes once the pin is gone.
    #[tokio::test]
    async fn test_step_after_skipped_publish_rebuilds_without_write() {
        let (engine, registry, _dir) = make_setup().await;
        let store = registry.default_store().await.unwrap();
        let arena = Arena::new();
        let mut publish = arena.publish_loop(builder(&registry, &engine, ARENA_LEN));
        publish.step(BEFORE_ANY_EXPIRY).await;
        // Pins buffer B, the target of the publish after next.
        let guard = arena.pin();
        store.put(b"k", b"1").await.unwrap();
        assert_eq!(publish.step(BEFORE_ANY_EXPIRY).await, Tick::Rebuilt(PublishOutcome::Published));
        store.put(b"k", b"2").await.unwrap();
        assert_eq!(
            publish.step(BEFORE_ANY_EXPIRY).await,
            Tick::Rebuilt(PublishOutcome::SkippedBusy { buffer: 1 })
        );

        drop(guard);
        assert_eq!(publish.step(BEFORE_ANY_EXPIRY).await, Tick::Rebuilt(PublishOutcome::Published));
        assert_eq!(default_entry(&arena.read(), b"k").expect("key published").value, b"2");
    }

    // Spec perf/028 test 4, trigger: the step idles before the earliest
    // published `expire_at` and rebuilds from it on. Stamps an hour out keep
    // every entry published, so only the step time decides.
    #[tokio::test]
    async fn test_step_rebuilds_from_earliest_expiry_on() {
        let (engine, registry, _dir) = make_setup().await;
        let store = registry.default_store().await.unwrap();
        let soon = now_secs() + 3600;
        store.put(b"plain", b"v").await.unwrap();
        store.put_unthrottled(b"late", b"v", Some(soon + 3600)).await.unwrap();
        store.put_unthrottled(b"soon", b"v", Some(soon)).await.unwrap();
        let arena = Arena::new();
        let mut publish = arena.publish_loop(builder(&registry, &engine, ARENA_LEN));
        publish.step(BEFORE_ANY_EXPIRY).await;

        assert_eq!(publish.step(soon - 1).await, Tick::Idle);
        assert_eq!(publish.step(soon).await, Tick::Rebuilt(PublishOutcome::Published));
    }

    // Spec perf/028 test 4, removal: once the wall clock reached the stamp, the
    // step at that time drops the expired entry.
    #[tokio::test]
    async fn test_step_at_expiry_drops_the_expired_entry() {
        let (engine, registry, _dir) = make_setup().await;
        let store = registry.default_store().await.unwrap();
        let expire_at = now_secs() + 2;
        store.put_unthrottled(b"ttl", b"v", Some(expire_at)).await.unwrap();
        let arena = Arena::new();
        let mut publish = arena.publish_loop(builder(&registry, &engine, ARENA_LEN));
        publish.step(BEFORE_ANY_EXPIRY).await;

        // The engine hides expired entries by wall clock: poll it, a fixed
        // sleep could be cut short by a backwards clock step.
        while now_secs() < expire_at {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        publish.step(expire_at).await;
        // Absence only: whether the first build still saw the entry depends
        // on scheduling; the trigger itself is the test above.
        assert!(default_entry(&arena.read(), b"ttl").is_none(), "expired entry must be gone");
    }
}
