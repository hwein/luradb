//! Bloom Filter implementation for fast negative lookups in SSTables.
//!
//! A Bloom filter is a space-efficient probabilistic data structure that
//! can test whether an element is a member of a set. False positives are
//! possible, but false negatives are not.

use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

/// A simple Bloom filter implementation.
///
/// This filter uses multiple hash functions (derived from two base hashes)
/// to achieve the desired false positive rate.
#[derive(Clone, Debug)]
pub struct BloomFilter {
    /// Bit array for the filter
    bits: Vec<u8>,

    /// Number of hash functions
    num_hashes: u32,

    /// Number of bits in the filter
    num_bits: u64,
}

impl BloomFilter {
    /// Creates a new Bloom filter.
    ///
    /// # Arguments
    /// * `num_items` - Expected number of items to be inserted
    /// * `false_positive_rate` - Desired false positive rate (e.g., 0.01 for 1%)
    ///
    /// # Returns
    /// A new Bloom filter sized appropriately for the given parameters
    pub fn new(num_items: usize, false_positive_rate: f64) -> Self {
        // Calculate optimal number of bits: m = -n * ln(p) / (ln(2)^2)
        // Round up to the nearest multiple of 8 so that num_bits == bits.len() * 8
        // exactly.  This is critical for round-trip serialisation: from_bytes()
        // reconstructs num_bits as bits.len() * 8, so unless num_bits was already
        // a multiple of 8 the hash positions used by contains() would differ from
        // those used during insert(), producing false negatives.
        let num_bits = ((-(num_items as f64) * false_positive_rate.ln()
            / (std::f64::consts::LN_2.powi(2))).ceil() as u64 + 7) & !7;

        // Calculate optimal number of hash functions: k = m / n * ln(2)
        let num_hashes = ((num_bits as f64 / num_items as f64)
            * std::f64::consts::LN_2).ceil() as u32;

        let num_bytes = ((num_bits + 7) / 8) as usize;

        Self {
            bits: vec![0u8; num_bytes],
            num_hashes,
            num_bits,
        }
    }

    /// Creates a Bloom filter from raw data.
    ///
    /// Used when deserializing from disk.
    ///
    /// An empty `bits` (num_bits == 0) would make `hash()` divide by zero;
    /// forcing `num_hashes` to 0 in that case degrades the filter to
    /// "always contains" instead, which is a safe false positive.
    pub fn from_bytes(bits: Vec<u8>, num_hashes: u32) -> Self {
        let num_bits = (bits.len() * 8) as u64;
        let num_hashes = if num_bits == 0 { 0 } else { num_hashes };
        Self {
            bits,
            num_hashes,
            num_bits,
        }
    }

    /// Inserts an item into the Bloom filter.
    pub fn insert(&mut self, item: &[u8]) {
        for i in 0..self.num_hashes {
            let bit_pos = self.hash(item, i);
            self.set_bit(bit_pos);
        }
    }

    /// Checks if an item might be in the Bloom filter.
    ///
    /// # Returns
    /// * `true` - The item might be in the set (could be false positive)
    /// * `false` - The item is definitely not in the set
    pub fn contains(&self, item: &[u8]) -> bool {
        for i in 0..self.num_hashes {
            let bit_pos = self.hash(item, i);
            if !self.get_bit(bit_pos) {
                return false;
            }
        }
        true
    }

    /// Returns the raw bit array.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bits
    }

    /// Returns the number of hash functions.
    pub fn num_hashes(&self) -> u32 {
        self.num_hashes
    }

    /// Computes the i-th hash value for the given item.
    ///
    /// Uses double hashing: h(i) = h1 + i * h2
    fn hash(&self, item: &[u8], i: u32) -> u64 {
        let hash1 = self.hash_fn1(item);
        let hash2 = self.hash_fn2(item);

        // Double hashing to generate multiple hash values
        (hash1.wrapping_add((i as u64).wrapping_mul(hash2))) % self.num_bits
    }

    /// First hash function.
    fn hash_fn1(&self, item: &[u8]) -> u64 {
        let mut hasher = DefaultHasher::new();
        item.hash(&mut hasher);
        hasher.finish()
    }

    /// Second hash function.
    fn hash_fn2(&self, item: &[u8]) -> u64 {
        let mut hasher = DefaultHasher::new();
        // Add a seed to differentiate from hash_fn1
        0x517cc1b727220a95u64.hash(&mut hasher);
        item.hash(&mut hasher);
        hasher.finish()
    }

    /// Sets a bit at the given position.
    fn set_bit(&mut self, pos: u64) {
        let byte_idx = (pos / 8) as usize;
        let bit_idx = (pos % 8) as u8;
        self.bits[byte_idx] |= 1 << bit_idx;
    }

    /// Gets a bit at the given position.
    fn get_bit(&self, pos: u64) -> bool {
        let byte_idx = (pos / 8) as usize;
        let bit_idx = (pos % 8) as u8;
        (self.bits[byte_idx] & (1 << bit_idx)) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_filter_basic() {
        let mut filter = BloomFilter::new(1000, 0.01);

        // Insert some items
        filter.insert(b"key1");
        filter.insert(b"key2");
        filter.insert(b"key3");

        // Check for inserted items (should all be true)
        assert!(filter.contains(b"key1"));
        assert!(filter.contains(b"key2"));
        assert!(filter.contains(b"key3"));

        // Check for non-inserted items (should mostly be false)
        // Note: Small chance of false positives
        assert!(!filter.contains(b"key999"));
    }

    #[test]
    fn test_bloom_filter_false_positive_rate() {
        let num_items = 10000;
        let false_positive_rate = 0.01;
        let mut filter = BloomFilter::new(num_items, false_positive_rate);

        // Insert items
        for i in 0..num_items {
            filter.insert(format!("key{}", i).as_bytes());
        }

        // Test false positive rate with items not in the filter
        let test_size = 10000;
        let mut false_positives = 0;

        for i in num_items..(num_items + test_size) {
            if filter.contains(format!("key{}", i).as_bytes()) {
                false_positives += 1;
            }
        }

        let actual_fp_rate = false_positives as f64 / test_size as f64;

        // Allow some tolerance (actual FP rate should be close to target)
        assert!(actual_fp_rate < false_positive_rate * 2.0);
    }

    #[test]
    fn test_bloom_filter_serialization() {
        let mut filter = BloomFilter::new(100, 0.01);

        filter.insert(b"test1");
        filter.insert(b"test2");

        // Serialize
        let bytes = filter.as_bytes().to_vec();
        let num_hashes = filter.num_hashes();

        // Deserialize
        let restored = BloomFilter::from_bytes(bytes, num_hashes);

        // Check that restored filter works
        assert!(restored.contains(b"test1"));
        assert!(restored.contains(b"test2"));
        assert!(!restored.contains(b"nonexistent"));
    }

    // kv/021: from_bytes(empty, num_hashes >= 1) must not panic (division by
    // zero in hash()) -- degrades to "always contains" instead.
    #[test]
    fn test_from_bytes_empty_bits_does_not_panic() {
        let filter = BloomFilter::from_bytes(Vec::new(), 3);
        assert!(filter.contains(b"x"));
    }
}
