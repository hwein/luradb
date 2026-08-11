//! RCU read snapshots published into the SHM double buffer (spec perf/009).
//!
//! [`SnapshotBuilder`] reads the current engine state into a compact,
//! rkyv-serialized [`ShmSnapshot`] (a per-domain, key-sorted index of the live
//! inline values); [`SnapshotPublisher`] pushes it through the spec 007
//! [`SnapshotWriter`] on an interval and after every MemTable flush. Local
//! clients (spec 010) read it lock-free via `SnapshotGuard` — for VLog-backed
//! values the entry carries only a `is_vlog_pointer` flag and the client falls
//! back to a command-ring GET.

use crate::engines::lsm::{Domain, DomainRegistry, LsmStorageEngine, RegistrySnapshot, ValueWithMetadata};
use anyhow::Result;
use rkyv::util::AlignedVec;
use rkyv::{rancor, Archive, Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{watch, Notify};

use super::{PublishOutcome, ShmManager, SnapshotWriter, StateHeader};

/// Per-entry byte estimate on top of key+value: covers rkyv relative pointers,
/// length fields, the fixed `ShmEntry` fields and alignment padding. Kept
/// generous so the accumulation budget stays conservative.
const PER_ENTRY_OVERHEAD: usize = 64;

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

// ── SnapshotBuilder (spec §2, §3, §6) ──────────────────────────────────────────

/// Builds an [`ShmSnapshot`] from the current engine state.
///
/// Reads go straight through the engine (not `DomainStore`) so the periodic
/// system rebuild is not charged against per-domain read rate limits.
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

    /// Builds the snapshot and returns the rkyv-serialized bytes.
    ///
    /// One MVCC snapshot pins a consistent point-in-time across all domains.
    /// Accumulation stops once a conservative budget (7/8 of the buffer) is hit;
    /// the truncated result is logged and still published. Whether it fits after
    /// serialization is the final call of [`SnapshotWriter::publish`].
    pub async fn build(&self) -> Result<AlignedVec> {
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
        Ok(serialize_snapshot(&snapshot))
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
        for raw_key in raw_keys {
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
    /// Notified after each MemTable flush — an extra rebuild trigger (spec §4b).
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
        flush_notify: Arc<Notify>,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self { builder, manager, interval, wait_timeout_us, flush_notify, shutdown }
    }

    /// Runs until the shutdown signal fires. The loop always survives build and
    /// publish errors (logged and retried on the next tick) — spec §4.
    pub async fn run(self) {
        let SnapshotPublisher { builder, manager, interval, wait_timeout_us, flush_notify, mut shutdown } =
            self;

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
            )
        };

        loop {
            if *shutdown.borrow() {
                break;
            }
            match builder.build().await {
                Ok(bytes) => match writer.publish(&bytes) {
                    Ok(PublishOutcome::Published) | Ok(PublishOutcome::SkippedBusy) => {}
                    Err(e) => tracing::error!("SHM snapshot publish failed: {e}"),
                },
                Err(e) => tracing::error!("SHM snapshot build failed: {e}"),
            }

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
    use crate::ipc::{SnapshotGuard, PUBLISH_WAIT_TIMEOUT_US};
    use crate::metrics::{MetricsConfig, MetricsStore};
    use crate::storage::file_manager::FileManager;
    use crate::storage::manifest::ManifestManager;
    use crate::storage::vlog::VLog;
    use rkyv::Archived;

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
        let bytes = builder(&registry, &engine, 1 << 20).build().await.unwrap();
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

        let snap = decode(&builder(&registry, &engine, 1 << 20).build().await.unwrap());
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

        let snap = decode(&builder(&registry, &engine, 1 << 20).build().await.unwrap());
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

        let snap = decode(&builder(&registry, &engine, 1 << 20).build().await.unwrap());
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

        let snap = decode(&builder(&registry, &engine, 1 << 20).build().await.unwrap());
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
        let snap = decode(&builder(&registry, &engine, 2048).build().await.unwrap());
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

        let bytes = builder(&registry, &engine, 1 << 20).build().await.unwrap();

        // Arena models the SHM state header + two data buffers (page-aligned in
        // production; here we copy into an AlignedVec before validating).
        let header = Box::new(StateHeader::zeroed());
        header.init();
        let len = 1 << 20;
        let mut buf_a = vec![0u8; len];
        let mut buf_b = vec![0u8; len];
        // Safe: single writer, two distinct buffers of `len` bytes, header valid.
        let writer = unsafe {
            SnapshotWriter::new(&*header, buf_a.as_mut_ptr(), buf_b.as_mut_ptr(), len, PUBLISH_WAIT_TIMEOUT_US)
        };
        assert_eq!(writer.publish(&bytes).unwrap(), PublishOutcome::Published);
        drop(writer);

        let guard = SnapshotGuard::acquire(&*header, &buf_a, &buf_b).expect("snapshot available");

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
        // ttl 0 → expire_at = now, already expired at build time (no sleep).
        store.put_with_ttl(b"gone", b"v", 0).await.unwrap();

        let snap = decode(&builder(&registry, &engine, 1 << 20).build().await.unwrap());
        let dom = find(&snap, "default").unwrap();
        assert!(dom.entries.iter().any(|e| e.key == b"stays"));
        assert!(!dom.entries.iter().any(|e| e.key == b"gone"), "expired key must be absent");
    }

    // 10. A domain in Deleting state does not appear in the snapshot.
    #[tokio::test]
    async fn test_deleting_domain_absent() {
        let (engine, registry, _dir) = make_setup().await;
        registry.create_domain("temp").await.unwrap();
        registry.store("temp").await.unwrap().put(b"k", b"v").await.unwrap();
        registry.delete_domain("temp").await.unwrap();

        let snap = decode(&builder(&registry, &engine, 1 << 20).build().await.unwrap());
        assert!(find(&snap, "temp").is_none(), "deleting domain must be absent");
        assert!(find(&snap, "default").is_some(), "active domain still present");
    }
}
