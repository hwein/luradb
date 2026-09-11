//! `memtable` module
//!
//! The `memtable` is the in-memory component of the LSM-Tree. It stores
//! recent writes in a sorted, lock-free data structure with MVCC support.

use crate::engines::lsm::key::{InternalKey, Timestamp};
use crate::storage::format::{is_expired, ValuePointer, VersionState};
use crossbeam_skiplist::SkipMap;
use std::cell::Cell;
use std::ops::Bound;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Counted size of a vLog-offloaded value: its on-disk vLog pointer (spec
/// general/032).
const POINTER_SIZE: usize = std::mem::size_of::<ValuePointer>();

/// Represents a value stored in the MemTable.
/// It can either be the full value (for small values) or a pointer
/// to the value's location in the value log (for large values).
///
/// Both live variants carry an optional TTL expiry timestamp (Unix seconds).
/// `None` means the entry does not expire.
#[derive(Debug, Clone)]
pub enum Value {
    Inline(Vec<u8>, Option<u64>), // data, expire_at
    /// vLog pointer + TTL. `file_id` is the vLog generation the value was
    /// appended to (spec kv/017).
    Pointer { file_id: u32, offset: u64, len: usize, expire_at: Option<u64> },
    /// Key explicitly set to NULL (kv/018): present, no bytes, no TTL — an
    /// update, not a delete.
    Null,
    Tombstone,
}

impl Value {
    /// Classifies this version's liveness at `now` (spec kv/025 §2): mirrors
    /// `DataBlockValue`/`CachedValue` in `storage::format` for the
    /// MemTable's own value representation.
    pub fn version_state(&self, now: u64) -> VersionState {
        match self {
            Value::Tombstone => VersionState::Tombstone,
            Value::Null => VersionState::Live,
            // invariant: no write path ever produces Some(0) (put/put_with_ttl/
            // WAL replay) -- unwrap_or(0) safely means "no TTL" here.
            Value::Inline(_, expire_at) => {
                if is_expired(expire_at.unwrap_or(0), now) { VersionState::Expired } else { VersionState::Live }
            }
            Value::Pointer { expire_at, .. } => {
                if is_expired(expire_at.unwrap_or(0), now) { VersionState::Expired } else { VersionState::Live }
            }
        }
    }

    /// Counted value bytes (spec general/032): inline data without its TTL,
    /// an offloaded value as its vLog pointer.
    fn stored_size(&self) -> usize {
        match self {
            Value::Inline(data, _) => data.len(),
            Value::Pointer { .. } => POINTER_SIZE,
            Value::Null | Value::Tombstone => 0,
        }
    }
}

/// The MemTable is a sorted, in-memory data structure that holds recent
/// key-value writes with MVCC support.
///
/// Keys are stored as InternalKey (user_key + timestamp), allowing multiple
/// versions of the same key to coexist. The SkipMap stores encoded InternalKeys
/// as bytes, which are sorted lexicographically (user_key ascending, timestamp descending).
pub struct MemTable {
    /// SkipMap with encoded InternalKey as the key
    map: Arc<SkipMap<Vec<u8>, Value>>,
    /// Encoded internal keys plus counted value bytes of all entries.
    size_bytes: AtomicUsize,
}

impl MemTable {
    /// Creates a new, empty `MemTable`.
    pub fn new() -> Self {
        Self {
            map: Arc::new(SkipMap::new()),
            size_bytes: AtomicUsize::new(0),
        }
    }

    /// Inserts a key-value pair with a timestamp (MVCC).
    ///
    /// # Arguments
    /// * `user_key` - The user-facing key
    /// * `timestamp` - The MVCC timestamp for this version
    /// * `value` - The `Value` enum, containing either the inlined value or a pointer
    pub fn set(&self, user_key: Vec<u8>, timestamp: Timestamp, value: Value) {
        let internal_key = InternalKey::new(user_key, timestamp);
        let encoded_key = internal_key.encode();
        let key_len = encoded_key.len();
        self.size_bytes.fetch_add(key_len + value.stored_size(), Ordering::Relaxed);

        // An identical internal key (a batch shares one stamp) replaces the
        // entry, so its bytes leave the count. compare_insert may call the
        // closure more than once: overwrite, never add.
        let replaced = Cell::new(0);
        self.map.compare_insert(encoded_key, value, |old| {
            replaced.set(key_len + old.stored_size());
            true
        });
        self.size_bytes.fetch_sub(replaced.get(), Ordering::Relaxed);
    }

    /// Like [`Self::set`], but keeps an existing entry with the identical
    /// internal key (spec kv/032). Returns whether `value` was inserted.
    pub fn set_if_absent(&self, user_key: Vec<u8>, timestamp: Timestamp, value: Value) -> bool {
        let encoded_key = InternalKey::new(user_key, timestamp).encode();
        let size = encoded_key.len() + value.stored_size();
        // Counted up front like `set`, so a racing replace of this entry
        // never subtracts bytes that were not added yet.
        self.size_bytes.fetch_add(size, Ordering::Relaxed);

        // compare_insert calls the closure only for an existing identical key
        // (possibly more than once); `false` keeps that entry.
        let existed = Cell::new(false);
        self.map.compare_insert(encoded_key, value, |_| {
            existed.set(true);
            false
        });
        if existed.get() {
            self.size_bytes.fetch_sub(size, Ordering::Relaxed);
        }
        !existed.get()
    }

    /// Retrieves the latest version of a key visible to the given snapshot.
    pub fn get(&self, user_key: &[u8], snapshot_ts: Timestamp) -> Option<Value> {
        self.get_with_ts(user_key, snapshot_ts).map(|(v, _)| v)
    }

    /// Like [`Self::get`], but also returns the version's write timestamp
    /// (spec kv/022 `last_modified_at`) — decoded straight from the encoded
    /// key, so already un-inverted.
    ///
    /// # Arguments
    /// * `user_key` - The user-facing key to look up
    /// * `snapshot_ts` - The snapshot timestamp (only return versions <= this)
    ///
    /// # Returns
    /// * `Some((Value, Timestamp))` if a visible version is found
    /// * `None` if no visible version exists
    pub fn get_with_ts(&self, user_key: &[u8], snapshot_ts: Timestamp) -> Option<(Value, Timestamp)> {
        // Build the search key: UserKey + SnapshotTimestamp
        let search_key = InternalKey::new(user_key.to_vec(), snapshot_ts);
        let encoded_search_key = search_key.encode();

        // CORRECTION: We use `encoded_search_key..` (RangeFrom), not `..=`.
        // Since we sort "Newest First" (inverted TS), a higher timestamp
        // means a smaller numeric value.
        // We're looking for entries whose timestamp is <= SnapshotTimestamp.
        // In inverted space that means: EntryKey >= SearchKey.
        // So we start at SearchKey and move forward.
        for entry in self.map.range(encoded_search_key..) {
            let key_bytes = entry.key();
            let value = entry.value();

            if let Some(entry_user_key) = InternalKey::extract_user_key(key_bytes.as_slice()) {
                if entry_user_key == user_key {
                    let ts = InternalKey::extract_timestamp(key_bytes.as_slice()).unwrap_or(snapshot_ts);
                    return Some((value.clone(), ts));
                } else {
                    // As soon as the UserKey no longer matches, we can stop,
                    // since the map is sorted by UserKey.
                    break;
                }
            }
        }
        None
    }

    /// Retrieves all versions of a key (for debugging/testing).
    ///
    /// # Arguments
    /// * `user_key` - The user-facing key to look up
    ///
    /// # Returns
    /// A vector of (Timestamp, Value) pairs for all versions of this key
    #[allow(dead_code)]
    pub fn get_all_versions(&self, user_key: &[u8]) -> Vec<(Timestamp, Value)> {
        let mut versions = Vec::new();

        for entry in self.map.iter() {
            let key_bytes = entry.key();
            let value = entry.value();

            if let Some(entry_user_key) = InternalKey::extract_user_key(key_bytes.as_slice()) {
                if entry_user_key == user_key {
                    if let Some(ts) = InternalKey::extract_timestamp(key_bytes.as_slice()) {
                        versions.push((ts, value.clone()));
                    }
                }
            }
        }

        versions
    }

    /// Returns an iterator over all entries in the MemTable.
    ///
    /// Useful for flushing to SSTable.
    pub fn iter(&self) -> impl Iterator<Item = (Vec<u8>, Value)> + '_ {
        self.map.iter().map(|entry| {
            (entry.key().clone(), entry.value().clone())
        })
    }

    /// Like [`Self::iter`], but starting at the first encoded key `>= start`
    /// (spec perf/029).
    pub fn iter_from<'a>(&'a self, start: &'a [u8]) -> impl Iterator<Item = (Vec<u8>, Value)> + 'a {
        self.map
            .range::<[u8], _>((Bound::Included(start), Bound::Unbounded))
            .map(|entry| (entry.key().clone(), entry.value().clone()))
    }

    /// Payload bytes of all entries (spec general/032).
    pub fn size_bytes(&self) -> usize {
        self.size_bytes.load(Ordering::Relaxed)
    }

    /// Returns true if the MemTable is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Returns the number of entries in the MemTable.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.map.len()
    }
}

impl Default for MemTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memtable_mvcc_basic() {
        let memtable = MemTable::new();

        // Insert multiple versions of the same key
        memtable.set(b"key1".to_vec(), Timestamp::new(100), Value::Inline(b"v1".to_vec(), None));
        memtable.set(b"key1".to_vec(), Timestamp::new(200), Value::Inline(b"v2".to_vec(), None));
        memtable.set(b"key1".to_vec(), Timestamp::new(300), Value::Inline(b"v3".to_vec(), None));

        // Read at different snapshots
        let v1 = memtable.get(b"key1", Timestamp::new(150));
        assert!(matches!(v1, Some(Value::Inline(ref v, _)) if v == b"v1"));

        let v2 = memtable.get(b"key1", Timestamp::new(250));
        assert!(matches!(v2, Some(Value::Inline(ref v, _)) if v == b"v2"));

        let v3 = memtable.get(b"key1", Timestamp::new(350));
        assert!(matches!(v3, Some(Value::Inline(ref v, _)) if v == b"v3"));
    }

    #[test]
    fn test_memtable_tombstone() {
        let memtable = MemTable::new();

        memtable.set(b"key1".to_vec(), Timestamp::new(100), Value::Inline(b"v1".to_vec(), None));
        memtable.set(b"key1".to_vec(), Timestamp::new(200), Value::Tombstone);

        // At timestamp 150, should get v1
        let v1 = memtable.get(b"key1", Timestamp::new(150));
        assert!(matches!(v1, Some(Value::Inline(ref v, _)) if v == b"v1"));

        // At timestamp 250, should get tombstone
        let tombstone = memtable.get(b"key1", Timestamp::new(250));
        assert!(matches!(tombstone, Some(Value::Tombstone)));
    }

    #[test]
    fn test_memtable_get_all_versions() {
        let memtable = MemTable::new();

        memtable.set(b"key1".to_vec(), Timestamp::new(100), Value::Inline(b"v1".to_vec(), None));
        memtable.set(b"key1".to_vec(), Timestamp::new(200), Value::Inline(b"v2".to_vec(), None));
        memtable.set(b"key1".to_vec(), Timestamp::new(300), Value::Inline(b"v3".to_vec(), None));

        let versions = memtable.get_all_versions(b"key1");
        assert_eq!(versions.len(), 3);
    }

    // Spec general/032: re-inserting an identical internal key replaces the
    // entry, so its old contribution is subtracted.
    #[test]
    fn test_memtable_set_on_identical_internal_key_replaces_its_bytes() {
        let memtable = MemTable::new();

        memtable.set(b"key".to_vec(), Timestamp::new(100), Value::Inline(b"old-value".to_vec(), None));
        memtable.set(b"key".to_vec(), Timestamp::new(100), Value::Inline(b"new".to_vec(), None));

        assert_eq!(memtable.size_bytes(), 3 + 8 + 3);
    }
}
