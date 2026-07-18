//! Read-path implementation with MVCC support.
//!
//! This module implements the read logic for the LSM-Tree with snapshot isolation.
//! It searches through multiple levels: MemTable → Immutable MemTables → SSTables.

use crate::engines::lsm::block_cache::BlockCache;
use crate::engines::lsm::key::{InternalKey, Timestamp};
use crate::engines::lsm::memtable::{MemTable, Value};
use crate::storage::format::CachedValue;
use crate::storage::sstable::SSTableReader;
use crate::storage::vlog::VLog;
use anyhow::Result;
use parking_lot::Mutex;
use std::sync::Arc;
use std::collections::{BinaryHeap, BTreeSet};
use std::cmp::Ordering;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn is_expired(expire_at: Option<u64>) -> bool {
    expire_at.map(|exp| exp <= now_secs()).unwrap_or(false)
}

/// A snapshot for MVCC reads.
///
/// A snapshot captures a consistent view of the database at a specific point in time.
/// All reads within this snapshot will only see data that was committed before the
/// snapshot timestamp.
#[derive(Debug, Clone)]
pub struct Snapshot {
    timestamp: Timestamp,
}

impl Snapshot {
    /// Creates a new snapshot with the given timestamp.
    pub fn new(timestamp: Timestamp) -> Self {
        Self { timestamp }
    }

    /// Returns the snapshot timestamp.
    pub fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    /// Checks if a given timestamp is visible in this snapshot.
    ///
    /// A timestamp is visible if it is less than or equal to the snapshot timestamp.
    pub fn is_visible(&self, ts: Timestamp) -> bool {
        ts.as_u64() <= self.timestamp.as_u64()
    }
}

/// Reader for the LSM-Tree with MVCC support.
///
/// This reader performs point lookups and scans across multiple levels of the LSM-Tree,
/// applying MVCC filtering to return only the appropriate version for a given snapshot.
pub struct LsmReader {
    /// Active MemTable (currently being written to)
    memtable: Arc<MemTable>,

    /// Immutable MemTables (not yet flushed to disk)
    immutable_memtables: Vec<Arc<MemTable>>,

    /// SSTables organized by level (L0, L1, ..., Ln)
    sstables: Vec<Vec<Arc<SSTableReader>>>,

    /// Value log for dereferencing large values
    vlog: Arc<VLog>,

    /// Shared S3-FIFO block cache — checked before every SSTable block read.
    cache: Arc<Mutex<BlockCache>>,
}

/// Three-valued result of a KV point read (spec kv/018): a live value, an
/// explicit NULL (key present, no bytes), or nothing at all. Replaces the
/// former `Option<Vec<u8>>` returned by `get`/`get_with_snapshot` — `Null` is
/// only ever produced inside the KV engine (via `set_null`); every caller
/// outside it treats `Null` defensively like `Absent` via
/// [`GetResult::into_option`].
#[derive(Debug, Clone, PartialEq)]
pub enum GetResult {
    Absent,
    Null,
    Present(Vec<u8>),
}

impl GetResult {
    /// Collapses `Null` into `Absent` — for callers where a NULL version can
    /// never occur (JSON/rel never write it; only the KV engine's `set_null` does).
    pub fn into_option(self) -> Option<Vec<u8>> {
        match self {
            GetResult::Present(v) => Some(v),
            GetResult::Null | GetResult::Absent => None,
        }
    }
}

/// A value plus the metadata the SHM snapshot builder needs (spec perf/009 §3).
///
/// Unlike [`LsmReader::get`], a VLog-backed value is *not* dereferenced: the
/// pointer is only flagged via `from_vlog` and `data` is left empty. Callers
/// that need the actual bytes of a VLog value fall back to a normal read.
#[derive(Debug, Clone, PartialEq)]
pub struct ValueWithMetadata {
    pub data: Vec<u8>,
    pub expire_at: u64,
    pub from_vlog: bool,
    /// Key is explicitly NULL (kv/018): `data` is empty, `from_vlog` is false.
    pub is_null: bool,
}

impl LsmReader {
    /// Creates a new LSM reader.
    pub fn new(
        memtable: Arc<MemTable>,
        vlog: Arc<VLog>,
        cache: Arc<Mutex<BlockCache>>,
    ) -> Self {
        Self {
            memtable,
            immutable_memtables: Vec::new(),
            sstables: Vec::new(),
            vlog,
            cache,
        }
    }

    /// Sets the immutable MemTables for this reader.
    pub fn set_immutable_memtables(&mut self, tables: Vec<Arc<MemTable>>) {
        self.immutable_memtables = tables;
    }

    /// Sets the SSTables for this reader.
    pub fn set_sstables(&mut self, sstables: Vec<Vec<Arc<SSTableReader>>>) {
        self.sstables = sstables;
    }

    /// MemTables newest-first: active, then immutables newest-to-oldest.
    fn memtables_newest_first(&self) -> impl Iterator<Item = &MemTable> + '_ {
        std::iter::once(&*self.memtable)
            .chain(self.immutable_memtables.iter().rev().map(|m| &**m))
    }

    /// SSTables newest-first: L0 newest-to-oldest (flush order, newest last),
    /// then L1..Ln (key-disjoint, order irrelevant).
    fn sstables_newest_first(&self) -> impl Iterator<Item = &Arc<SSTableReader>> + '_ {
        self.sstables
            .first()
            .into_iter()
            .flat_map(|l0| l0.iter().rev())
            .chain(self.sstables.iter().skip(1).flatten())
    }

    /// Performs a point lookup with MVCC support.
    ///
    /// Sources are searched newest-first (see [`Self::memtables_newest_first`]
    /// then [`Self::sstables_newest_first`]); each yields its newest version
    /// <= snapshot timestamp, so the first hit decides for good. Returns None
    /// if the key is absent or that version is a tombstone.
    pub async fn get(&self, user_key: &[u8], snapshot: &Snapshot) -> Result<GetResult> {
        for memtable in self.memtables_newest_first() {
            if let Some(result) = self.get_from_memtable(memtable, user_key, snapshot).await? {
                return Ok(result);
            }
        }
        for sstable in self.sstables_newest_first() {
            if let Some(result) = self.get_from_sstable(sstable, user_key, snapshot).await? {
                return Ok(result);
            }
        }
        Ok(GetResult::Absent)
    }

    /// Gets a value from a MemTable with MVCC filtering.
    async fn get_from_memtable(
        &self,
        memtable: &MemTable,
        user_key: &[u8],
        snapshot: &Snapshot,
    ) -> Result<Option<GetResult>> {
        match memtable.get(user_key, snapshot.timestamp()) {
            Some(value) => {
                match value {
                    Value::Inline(v, expire_at) => {
                        if is_expired(expire_at) { return Ok(Some(GetResult::Absent)); }
                        Ok(Some(GetResult::Present(v)))
                    }
                    Value::Pointer { offset, len, expire_at } => {
                        if is_expired(expire_at) { return Ok(Some(GetResult::Absent)); }
                        let v = self.vlog.read(offset, len).await?;
                        Ok(Some(GetResult::Present(v)))
                    }
                    Value::Null => Ok(Some(GetResult::Null)),
                    Value::Tombstone => Ok(Some(GetResult::Absent)),
                }
            }
            None => Ok(None),
        }
    }

    /// Gets a value from an SSTable with MVCC filtering.
    ///
    /// Checks the block cache before reading from the SSTable's in-memory data.
    /// Handles both inline entries (no VLog access) and pointer entries (VLog read).
    async fn get_from_sstable(
        &self,
        sstable: &SSTableReader,
        user_key: &[u8],
        snapshot: &Snapshot,
    ) -> Result<Option<GetResult>> {
        let search_key = InternalKey::new(user_key.to_vec(), snapshot.timestamp());
        let encoded_key = search_key.encode();

        let maybe_value = {
            let mut cache = self.cache.lock();
            sstable.get_with_cache(&encoded_key, &mut *cache)?
        };

        // Zero-copy until here (spec perf/002): the value is materialized
        // exactly once, after the visible version has been found.
        match maybe_value {
            None => Ok(None),
            Some(CachedValue::Tombstone) => Ok(Some(GetResult::Absent)),
            Some(CachedValue::Null) => Ok(Some(GetResult::Null)),
            Some(CachedValue::VLogPointer { value_offset, value_len, expire_at, .. }) => {
                if expire_at != 0 && expire_at <= now_secs() {
                    return Ok(Some(GetResult::Absent));
                }
                let value = self.vlog.read(value_offset, value_len as usize).await?;
                Ok(Some(GetResult::Present(value)))
            }
            Some(value) => {
                let expire_at = value.expire_at();
                if expire_at != 0 && expire_at <= now_secs() {
                    return Ok(Some(GetResult::Absent));
                }
                Ok(Some(GetResult::Present(value.to_owned_bytes())))
            }
        }
    }

    /// Like [`Self::get`], but returns the newest visible value with metadata
    /// (VLog status, expiry) and never dereferences the VLog (spec perf/009 §3).
    ///
    /// Same newest-first source order and MVCC/TTL/tombstone semantics as
    /// `get`; a VLog hit yields `from_vlog = true` with empty `data`.
    pub async fn get_with_metadata(
        &self,
        user_key: &[u8],
        snapshot: &Snapshot,
    ) -> Result<Option<ValueWithMetadata>> {
        for memtable in self.memtables_newest_first() {
            if let Some(result) = self.meta_from_memtable(memtable, user_key, snapshot)? {
                return Ok(result);
            }
        }
        for sstable in self.sstables_newest_first() {
            if let Some(result) = self.meta_from_sstable(sstable, user_key, snapshot)? {
                return Ok(result);
            }
        }
        Ok(None)
    }

    /// MemTable variant of the metadata lookup. Sync (no VLog read); outer
    /// `Some` = key present in this source, inner `None` = tombstone/expired.
    fn meta_from_memtable(
        &self,
        memtable: &MemTable,
        user_key: &[u8],
        snapshot: &Snapshot,
    ) -> Result<Option<Option<ValueWithMetadata>>> {
        match memtable.get(user_key, snapshot.timestamp()) {
            Some(Value::Inline(v, expire_at)) => {
                if is_expired(expire_at) { return Ok(Some(None)); }
                Ok(Some(Some(ValueWithMetadata { data: v, expire_at: expire_at.unwrap_or(0), from_vlog: false, is_null: false })))
            }
            Some(Value::Pointer { expire_at, .. }) => {
                if is_expired(expire_at) { return Ok(Some(None)); }
                Ok(Some(Some(ValueWithMetadata { data: Vec::new(), expire_at: expire_at.unwrap_or(0), from_vlog: true, is_null: false })))
            }
            Some(Value::Null) => {
                Ok(Some(Some(ValueWithMetadata { data: Vec::new(), expire_at: 0, from_vlog: false, is_null: true })))
            }
            Some(Value::Tombstone) => Ok(Some(None)),
            None => Ok(None),
        }
    }

    /// SSTable variant of the metadata lookup. Sync (no VLog read); a VLog
    /// pointer is flagged, not resolved.
    fn meta_from_sstable(
        &self,
        sstable: &SSTableReader,
        user_key: &[u8],
        snapshot: &Snapshot,
    ) -> Result<Option<Option<ValueWithMetadata>>> {
        let search_key = InternalKey::new(user_key.to_vec(), snapshot.timestamp());
        let encoded_key = search_key.encode();

        let maybe_value = {
            let mut cache = self.cache.lock();
            sstable.get_with_cache(&encoded_key, &mut *cache)?
        };

        match maybe_value {
            None => Ok(None),
            Some(CachedValue::Tombstone) => Ok(Some(None)),
            Some(CachedValue::Null) => {
                Ok(Some(Some(ValueWithMetadata { data: Vec::new(), expire_at: 0, from_vlog: false, is_null: true })))
            }
            Some(CachedValue::VLogPointer { expire_at, .. }) => {
                if expire_at != 0 && expire_at <= now_secs() {
                    return Ok(Some(None));
                }
                Ok(Some(Some(ValueWithMetadata { data: Vec::new(), expire_at, from_vlog: true, is_null: false })))
            }
            Some(value) => {
                let expire_at = value.expire_at();
                if expire_at != 0 && expire_at <= now_secs() {
                    return Ok(Some(None));
                }
                Ok(Some(Some(ValueWithMetadata { data: value.to_owned_bytes(), expire_at, from_vlog: false, is_null: false })))
            }
        }
    }

    /// Adds an SSTable to a specific level.
    ///
    /// This is used during flush and compaction operations.
    #[allow(dead_code)]
    pub fn add_sstable(&mut self, level: usize, sstable: Arc<SSTableReader>) {
        while self.sstables.len() <= level {
            self.sstables.push(Vec::new());
        }
        self.sstables[level].push(sstable);
    }

    /// Adds an immutable MemTable.
    ///
    /// Called when the active MemTable is frozen and a new one is created.
    #[allow(dead_code)]
    pub fn add_immutable_memtable(&mut self, memtable: Arc<MemTable>) {
        self.immutable_memtables.push(memtable);
    }
}

/// A versioned entry in the LSM-Tree.
///
/// This represents a single version of a key-value pair with its timestamp.
#[derive(Debug, Clone)]
pub struct VersionedEntry {
    pub key: Vec<u8>,
    pub timestamp: Timestamp,
    pub value: Option<Vec<u8>>, // None for tombstones
}

impl VersionedEntry {
    /// Creates a new versioned entry.
    pub fn new(key: Vec<u8>, timestamp: Timestamp, value: Option<Vec<u8>>) -> Self {
        Self { key, timestamp, value }
    }

    /// Returns true if this entry is a tombstone.
    pub fn is_tombstone(&self) -> bool {
        self.value.is_none()
    }

    /// Returns the internal key for this entry.
    pub fn internal_key(&self) -> InternalKey {
        InternalKey::new(self.key.clone(), self.timestamp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_visibility() {
        let snapshot = Snapshot::new(Timestamp::new(100));

        assert!(snapshot.is_visible(Timestamp::new(50)));
        assert!(snapshot.is_visible(Timestamp::new(100)));
        assert!(!snapshot.is_visible(Timestamp::new(150)));
    }

    #[test]
    fn test_versioned_entry() {
        let entry = VersionedEntry::new(
            b"key1".to_vec(),
            Timestamp::new(100),
            Some(b"value1".to_vec()),
        );

        assert!(!entry.is_tombstone());
        assert_eq!(entry.internal_key().user_key(), b"key1");

        let tombstone = VersionedEntry::new(
            b"key2".to_vec(),
            Timestamp::new(200),
            None,
        );

        assert!(tombstone.is_tombstone());
    }
}

/// A merge iterator that combines multiple sorted iterators into a single
/// deduplicated stream, respecting MVCC visibility rules.
///
/// This iterator:
/// 1. Merges entries from multiple sources (MemTables, SSTables)
/// 2. Ensures entries are emitted in sorted order (by InternalKey)
/// 3. Deduplicates entries with the same user key (emits only the newest visible version)
/// 4. Filters entries based on snapshot visibility
pub struct MergeIterator<I>
where
    I: Iterator<Item = Result<(Vec<u8>, Timestamp, Option<Vec<u8>>)>>,
{
    /// Min-heap of iterators with their current entry
    /// We use Reverse to make BinaryHeap a min-heap
    heap: BinaryHeap<std::cmp::Reverse<HeapEntry<I>>>,

    /// Snapshot for MVCC filtering
    snapshot: Snapshot,

    /// Last emitted user key (for deduplication)
    last_user_key: Option<Vec<u8>>,
}

/// An entry in the merge heap, containing an iterator and its current value.
struct HeapEntry<I>
where
    I: Iterator<Item = Result<(Vec<u8>, Timestamp, Option<Vec<u8>>)>>,
{
    /// The current entry from this iterator
    current: (Vec<u8>, Timestamp, Option<Vec<u8>>),

    /// The iterator itself
    iterator: I,

    /// Source priority (lower is higher priority)
    /// Used to break ties when keys are equal: prefer newer sources
    source_priority: usize,
}

impl<I> PartialEq for HeapEntry<I>
where
    I: Iterator<Item = Result<(Vec<u8>, Timestamp, Option<Vec<u8>>)>>,
{
    fn eq(&self, other: &Self) -> bool {
        self.current.0 == other.current.0 && self.current.1 == other.current.1
    }
}

impl<I> Eq for HeapEntry<I>
where
    I: Iterator<Item = Result<(Vec<u8>, Timestamp, Option<Vec<u8>>)>>,
{
}

impl<I> PartialOrd for HeapEntry<I>
where
    I: Iterator<Item = Result<(Vec<u8>, Timestamp, Option<Vec<u8>>)>>,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<I> Ord for HeapEntry<I>
where
    I: Iterator<Item = Result<(Vec<u8>, Timestamp, Option<Vec<u8>>)>>,
{
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare by internal key (user_key + timestamp)
        let self_key = InternalKey::new(self.current.0.clone(), self.current.1);
        let other_key = InternalKey::new(other.current.0.clone(), other.current.1);

        match self_key.cmp(&other_key) {
            Ordering::Equal => {
                // If keys are equal, use source priority (lower is better/newer)
                self.source_priority.cmp(&other.source_priority)
            }
            other => other,
        }
    }
}

impl<I> MergeIterator<I>
where
    I: Iterator<Item = Result<(Vec<u8>, Timestamp, Option<Vec<u8>>)>>,
{
    /// Creates a new merge iterator.
    ///
    /// # Arguments
    /// * `iterators` - A vector of (iterator, source_priority) pairs
    /// * `snapshot` - The snapshot for MVCC visibility
    pub fn new(iterators: Vec<(I, usize)>, snapshot: Snapshot) -> Result<Self> {
        let mut heap = BinaryHeap::new();

        for (mut iterator, source_priority) in iterators {
            if let Some(result) = iterator.next() {
                let current = result?;
                heap.push(std::cmp::Reverse(HeapEntry {
                    current,
                    iterator,
                    source_priority,
                }));
            }
        }

        Ok(Self {
            heap,
            snapshot,
            last_user_key: None,
        })
    }

    /// Advances `entry`'s source, returning the prior head. Re-heaps on a new
    /// item; drops the entry on end-of-source or error (the error propagates,
    /// no re-heap).
    fn advance_source(
        &mut self,
        mut entry: HeapEntry<I>,
    ) -> Result<(Vec<u8>, Timestamp, Option<Vec<u8>>)> {
        match entry.iterator.next() {
            Some(Ok(current)) => {
                let prev = std::mem::replace(&mut entry.current, current);
                self.heap.push(std::cmp::Reverse(entry));
                Ok(prev)
            }
            Some(Err(e)) => Err(e),
            None => Ok(entry.current),
        }
    }

    /// Advances the iterator and returns the next unique, visible entry.
    ///
    /// Pops the smallest entry, filters by MVCC visibility, deduplicates by
    /// user key, then advances the source (see [`Self::advance_source`]).
    pub fn next(&mut self) -> Option<Result<VersionedEntry>> {
        while let Some(std::cmp::Reverse(entry)) = self.heap.pop() {
            // Skip entries not visible in this snapshot.
            if !self.snapshot.is_visible(entry.current.1) {
                match self.advance_source(entry) {
                    Ok(_) => continue,
                    Err(e) => return Some(Err(e)),
                }
            }

            // Skip a user key already emitted (its newest version won).
            if self.last_user_key.as_ref() == Some(&entry.current.0) {
                match self.advance_source(entry) {
                    Ok(_) => continue,
                    Err(e) => return Some(Err(e)),
                }
            }

            // New user key: record it BEFORE advancing (observable on error),
            // then emit the prior head (tombstones included).
            self.last_user_key = Some(entry.current.0.clone());
            return match self.advance_source(entry) {
                Ok((user_key, timestamp, value)) => {
                    Some(Ok(VersionedEntry::new(user_key, timestamp, value)))
                }
                Err(e) => Some(Err(e)),
            };
        }

        None
    }
}

impl<I> Iterator for MergeIterator<I>
where
    I: Iterator<Item = Result<(Vec<u8>, Timestamp, Option<Vec<u8>>)>>,
{
    type Item = Result<VersionedEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next()
    }
}

#[cfg(test)]
mod merge_iterator_tests {
    use super::*;

    /// Helper to create a simple iterator from a vec
    fn vec_iter(
        data: Vec<(Vec<u8>, u64, Option<Vec<u8>>)>,
    ) -> impl Iterator<Item = Result<(Vec<u8>, Timestamp, Option<Vec<u8>>)>> {
        data.into_iter()
            .map(|(k, ts, v)| Ok((k, Timestamp::new(ts), v)))
    }

    #[test]
    fn test_merge_iterator_basic() -> Result<()> {
        // Two iterators with non-overlapping keys
        let iter1 = vec_iter(vec![
            (b"key1".to_vec(), 100, Some(b"value1".to_vec())),
            (b"key3".to_vec(), 100, Some(b"value3".to_vec())),
        ]);

        let iter2 = vec_iter(vec![
            (b"key2".to_vec(), 100, Some(b"value2".to_vec())),
            (b"key4".to_vec(), 100, Some(b"value4".to_vec())),
        ]);

        let snapshot = Snapshot::new(Timestamp::new(150));
        let mut merge_iter = MergeIterator::new(vec![(iter1, 0), (iter2, 1)], snapshot)?;

        // Should get all keys in sorted order
        let entry1 = merge_iter.next().unwrap()?;
        assert_eq!(entry1.key, b"key1");

        let entry2 = merge_iter.next().unwrap()?;
        assert_eq!(entry2.key, b"key2");

        let entry3 = merge_iter.next().unwrap()?;
        assert_eq!(entry3.key, b"key3");

        let entry4 = merge_iter.next().unwrap()?;
        assert_eq!(entry4.key, b"key4");

        assert!(merge_iter.next().is_none());

        Ok(())
    }

    #[test]
    fn test_merge_iterator_deduplication() -> Result<()> {
        // Two iterators with overlapping keys - should deduplicate
        let iter1 = vec_iter(vec![
            (b"key1".to_vec(), 200, Some(b"newer".to_vec())), // Newer version
        ]);

        let iter2 = vec_iter(vec![
            (b"key1".to_vec(), 100, Some(b"older".to_vec())), // Older version
        ]);

        let snapshot = Snapshot::new(Timestamp::new(250));
        let mut merge_iter = MergeIterator::new(vec![(iter1, 0), (iter2, 1)], snapshot)?;

        // Should only get the newer version
        let entry = merge_iter.next().unwrap()?;
        assert_eq!(entry.key, b"key1");
        assert_eq!(entry.value, Some(b"newer".to_vec()));

        assert!(merge_iter.next().is_none());

        Ok(())
    }

    #[test]
    fn test_merge_iterator_mvcc_filtering() -> Result<()> {
        let iter1 = vec_iter(vec![
            (b"key1".to_vec(), 100, Some(b"v1".to_vec())),
            (b"key2".to_vec(), 200, Some(b"v2".to_vec())), // Not visible
        ]);

        let snapshot = Snapshot::new(Timestamp::new(150));
        let mut merge_iter = MergeIterator::new(vec![(iter1, 0)], snapshot)?;

        // Should only get key1 (key2's timestamp is beyond snapshot)
        let entry = merge_iter.next().unwrap()?;
        assert_eq!(entry.key, b"key1");

        assert!(merge_iter.next().is_none());

        Ok(())
    }

    #[test]
    fn test_merge_iterator_tombstone() -> Result<()> {
        let iter1 = vec_iter(vec![
            (b"key1".to_vec(), 100, None), // Tombstone
        ]);

        let snapshot = Snapshot::new(Timestamp::new(150));
        let mut merge_iter = MergeIterator::new(vec![(iter1, 0)], snapshot)?;

        let entry = merge_iter.next().unwrap()?;
        assert_eq!(entry.key, b"key1");
        assert!(entry.is_tombstone());

        Ok(())
    }

    // Vorarbeit: advancing a source onto an Err must propagate it without
    // re-inserting the entry into the heap (the block moved into advance_source).
    #[test]
    fn test_merge_iterator_propagates_error() -> Result<()> {
        let iter = vec![
            Ok((b"key1".to_vec(), Timestamp::new(100), Some(b"v1".to_vec()))),
            Err(anyhow::anyhow!("boom")),
        ]
        .into_iter();

        let snapshot = Snapshot::new(Timestamp::new(150));
        let mut merge_iter = MergeIterator::new(vec![(iter, 0)], snapshot)?;

        assert!(merge_iter.next().expect("must yield a result").is_err());
        Ok(())
    }

    // Vorarbeit: same user key AND timestamp in two sources — the lower
    // source_priority (newer source) wins the tiebreak.
    #[test]
    fn test_merge_iterator_source_priority_tiebreak() -> Result<()> {
        let iter_new = vec_iter(vec![(b"k".to_vec(), 100, Some(b"new".to_vec()))]);
        let iter_old = vec_iter(vec![(b"k".to_vec(), 100, Some(b"old".to_vec()))]);

        let snapshot = Snapshot::new(Timestamp::new(150));
        let mut merge_iter = MergeIterator::new(vec![(iter_new, 0), (iter_old, 1)], snapshot)?;

        let entry = merge_iter.next().unwrap()?;
        assert_eq!(entry.key, b"k");
        assert_eq!(entry.value, Some(b"new".to_vec()));
        assert!(merge_iter.next().is_none());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Snapshot Registry
// ---------------------------------------------------------------------------

/// Tracks active MVCC snapshots to compute the compaction low watermark.
///
/// The *low watermark* is the timestamp of the oldest active snapshot.
/// A tombstone whose timestamp is strictly less than the low watermark can be
/// safely garbage-collected: every currently active snapshot already observes
/// the key as deleted, so the tombstone entry is no longer needed.
#[derive(Clone, Debug, Default)]
pub struct SnapshotRegistry {
    active: Arc<parking_lot::Mutex<BTreeSet<u64>>>,
}

impl SnapshotRegistry {
    /// Creates a new, empty registry.
    pub fn new() -> Self {
        Self {
            active: Arc::new(parking_lot::Mutex::new(BTreeSet::new())),
        }
    }

    /// Registers a snapshot at timestamp  and returns an RAII guard.
    ///
    /// The snapshot is automatically deregistered when the guard is dropped,
    /// ensuring the low watermark always reflects the true oldest active reader.
    pub fn acquire(&self, ts: Timestamp) -> RegistrySnapshot {
        self.active.lock().insert(ts.as_u64());
        RegistrySnapshot {
            active: Arc::clone(&self.active),
            ts_raw: ts.as_u64(),
            inner: Snapshot::new(ts),
        }
    }

    /// Returns the timestamp of the oldest active snapshot, or  when no
    /// snapshots are currently registered.
    ///
    /// This value is used by the compaction filter: tombstones with a timestamp
    /// strictly below the low watermark are safe to drop.
    pub fn low_watermark(&self) -> Option<Timestamp> {
        self.active
            .lock()
            .iter()
            .next()
            .copied()
            .map(Timestamp::new)
    }
}

/// RAII guard for a snapshot registered in [].
///
/// Automatically deregisters the snapshot on drop.
pub struct RegistrySnapshot {
    active: Arc<parking_lot::Mutex<BTreeSet<u64>>>,
    ts_raw: u64,
    inner: Snapshot,
}

impl RegistrySnapshot {
    /// Returns a reference to the underlying [] for MVCC reads.
    pub fn snapshot(&self) -> &Snapshot {
        &self.inner
    }
}

impl Drop for RegistrySnapshot {
    fn drop(&mut self) {
        self.active.lock().remove(&self.ts_raw);
    }
}

#[cfg(test)]
mod snapshot_registry_tests {
    use super::*;

    #[test]
    fn test_low_watermark_empty() {
        let reg = SnapshotRegistry::new();
        assert!(reg.low_watermark().is_none());
    }

    #[test]
    fn test_low_watermark_single() {
        let reg = SnapshotRegistry::new();
        let _s = reg.acquire(Timestamp::new(42));
        assert_eq!(reg.low_watermark().unwrap().as_u64(), 42);
    }

    #[test]
    fn test_low_watermark_multiple() {
        let reg = SnapshotRegistry::new();
        let _s1 = reg.acquire(Timestamp::new(100));
        let _s2 = reg.acquire(Timestamp::new(50));
        let _s3 = reg.acquire(Timestamp::new(200));
        assert_eq!(reg.low_watermark().unwrap().as_u64(), 50);
    }

    #[test]
    fn test_deregistration_on_drop() {
        let reg = SnapshotRegistry::new();
        {
            let _s = reg.acquire(Timestamp::new(77));
            assert_eq!(reg.low_watermark().unwrap().as_u64(), 77);
        }
        assert!(reg.low_watermark().is_none());
    }

    #[test]
    fn test_low_watermark_advances_after_oldest_drops() {
        let reg = SnapshotRegistry::new();
        let s1 = reg.acquire(Timestamp::new(10));
        let _s2 = reg.acquire(Timestamp::new(20));
        assert_eq!(reg.low_watermark().unwrap().as_u64(), 10);
        drop(s1);
        assert_eq!(reg.low_watermark().unwrap().as_u64(), 20);
    }
}
