//! `memtable` module
//!
//! The `memtable` is the in-memory component of the LSM-Tree. It stores
//! recent writes in a sorted, lock-free data structure with MVCC support.

use crate::engines::lsm::key::{InternalKey, Timestamp};
use crossbeam_skiplist::SkipMap;
use std::sync::Arc;

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

/// The MemTable is a sorted, in-memory data structure that holds recent
/// key-value writes with MVCC support.
///
/// Keys are stored as InternalKey (user_key + timestamp), allowing multiple
/// versions of the same key to coexist. The SkipMap stores encoded InternalKeys
/// as bytes, which are sorted lexicographically (user_key ascending, timestamp descending).
pub struct MemTable {
    /// SkipMap with encoded InternalKey as the key
    map: Arc<SkipMap<Vec<u8>, Value>>,
}

impl MemTable {
    /// Creates a new, empty `MemTable`.
    pub fn new() -> Self {
        Self {
            map: Arc::new(SkipMap::new()),
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
        self.map.insert(encoded_key, value);
    }

    /// Retrieves the latest version of a key visible to the given snapshot.
    ///
    /// # Arguments
    /// * `user_key` - The user-facing key to look up
    /// * `snapshot_ts` - The snapshot timestamp (only return versions <= this)
    ///
    /// # Returns
    /// * `Some(Value)` if a visible version is found
    /// * `None` if no visible version exists
    pub fn get(&self, user_key: &[u8], snapshot_ts: Timestamp) -> Option<Value> {
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
                    return Some(value.clone());
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

    /// Returns the approximate size of the MemTable in bytes.
    ///
    /// This is used to determine when to freeze and flush the MemTable.
    #[allow(dead_code)]
    pub fn approximate_size(&self) -> usize {
        // Rough estimate: count entries and assume average size
        // A more accurate implementation would track actual memory usage
        self.map.len() * 256 // Rough estimate
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
}
