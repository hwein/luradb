//! MVCC Key structures for LSM-Tree
//!
//! This module implements the internal key representation for MVCC support.
//! Physical keys in the LSM are composed of: UserKey + Timestamp (inverted).

use std::cmp::Ordering;

/// A timestamp used for MVCC.
/// Internally stored as u64, but inverted for sorting (newest first).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp(u64);

impl Timestamp {
    /// Creates a new timestamp from a raw u64 value.
    pub fn new(ts: u64) -> Self {
        Self(ts)
    }

    /// Returns the raw timestamp value.
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    /// Returns the inverted timestamp for storage (newest first in sort order).
    pub fn inverted(&self) -> u64 {
        u64::MAX - self.0
    }

    /// Creates a timestamp from an inverted value (as stored on disk).
    pub fn from_inverted(inverted: u64) -> Self {
        Self(u64::MAX - inverted)
    }

    /// Encodes the timestamp as big-endian bytes (inverted for sorting).
    pub fn to_be_bytes(&self) -> [u8; 8] {
        self.inverted().to_be_bytes()
    }

    /// Decodes a timestamp from big-endian bytes (inverted).
    pub fn from_be_bytes(bytes: [u8; 8]) -> Self {
        let inverted = u64::from_be_bytes(bytes);
        Self::from_inverted(inverted)
    }
}

impl PartialOrd for Timestamp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Timestamp {
    fn cmp(&self, other: &Self) -> Ordering {
        // When comparing timestamps, newer (larger) timestamps come first
        // This is achieved by comparing the inverted values in reverse
        other.0.cmp(&self.0)
    }
}

/// Internal key representation: UserKey + Timestamp.
///
/// The physical layout on disk is: [user_key_bytes][inverted_timestamp_be]
/// This ensures that for the same user key, newer versions appear first in sort order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternalKey {
    user_key: Vec<u8>,
    timestamp: Timestamp,
}

impl InternalKey {
    /// Creates a new internal key.
    pub fn new(user_key: Vec<u8>, timestamp: Timestamp) -> Self {
        Self { user_key, timestamp }
    }

    /// Returns the user key portion.
    pub fn user_key(&self) -> &[u8] {
        &self.user_key
    }

    /// Returns the timestamp.
    pub fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    /// Encodes the internal key into a byte vector.
    /// Format: [user_key][timestamp_inverted_be]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(self.user_key.len() + 8);
        encoded.extend_from_slice(&self.user_key);
        encoded.extend_from_slice(&self.timestamp.to_be_bytes());
        encoded
    }

    /// Decodes an internal key from a byte slice.
    /// Returns None if the slice is too short.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }

        let ts_offset = bytes.len() - 8;
        let user_key = bytes[..ts_offset].to_vec();
        let ts_bytes: [u8; 8] = bytes[ts_offset..].try_into().ok()?;
        let timestamp = Timestamp::from_be_bytes(ts_bytes);

        Some(Self { user_key, timestamp })
    }

    /// Extracts the user key from an encoded internal key without allocating.
    pub fn extract_user_key(encoded: &[u8]) -> Option<&[u8]> {
        if encoded.len() < 8 {
            return None;
        }
        Some(&encoded[..encoded.len() - 8])
    }

    /// Extracts the timestamp from an encoded internal key.
    pub fn extract_timestamp(encoded: &[u8]) -> Option<Timestamp> {
        if encoded.len() < 8 {
            return None;
        }
        let ts_bytes: [u8; 8] = encoded[encoded.len() - 8..].try_into().ok()?;
        Some(Timestamp::from_be_bytes(ts_bytes))
    }
}

impl PartialOrd for InternalKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for InternalKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // First compare user keys lexicographically
        match self.user_key.cmp(&other.user_key) {
            Ordering::Equal => {
                // For the same user key, newer timestamps come first
                self.timestamp.cmp(&other.timestamp)
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_inversion() {
        let ts1 = Timestamp::new(100);
        let ts2 = Timestamp::new(200);

        // Newer timestamp should compare as "less" (comes first)
        assert!(ts2 < ts1);

        // Inverted values should sort correctly
        assert!(ts1.inverted() > ts2.inverted());
    }

    #[test]
    fn test_timestamp_encoding() {
        let ts = Timestamp::new(12345);
        let bytes = ts.to_be_bytes();
        let decoded = Timestamp::from_be_bytes(bytes);
        assert_eq!(ts, decoded);
    }

    #[test]
    fn test_internal_key_encoding() {
        let key = InternalKey::new(b"user_key".to_vec(), Timestamp::new(100));
        let encoded = key.encode();
        let decoded = InternalKey::decode(&encoded).unwrap();

        assert_eq!(key, decoded);
        assert_eq!(key.user_key(), b"user_key");
        assert_eq!(key.timestamp(), Timestamp::new(100));
    }

    #[test]
    fn test_internal_key_ordering() {
        let key1 = InternalKey::new(b"key_a".to_vec(), Timestamp::new(100));
        let key2 = InternalKey::new(b"key_a".to_vec(), Timestamp::new(200));
        let key3 = InternalKey::new(b"key_b".to_vec(), Timestamp::new(100));

        // Same user key, newer timestamp comes first
        assert!(key2 < key1);

        // Different user keys
        assert!(key1 < key3);
    }

    #[test]
    fn test_extract_user_key() {
        let key = InternalKey::new(b"test_key".to_vec(), Timestamp::new(42));
        let encoded = key.encode();

        let extracted = InternalKey::extract_user_key(&encoded).unwrap();
        assert_eq!(extracted, b"test_key");
    }

    #[test]
    fn test_extract_timestamp() {
        let key = InternalKey::new(b"test_key".to_vec(), Timestamp::new(42));
        let encoded = key.encode();

        let extracted = InternalKey::extract_timestamp(&encoded).unwrap();
        assert_eq!(extracted, Timestamp::new(42));
    }
}
