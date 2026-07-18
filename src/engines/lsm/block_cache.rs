//! Block Cache — Spec 015.
//!
//! Implements an S3-FIFO (Simple, Scalable, Scan-resistant FIFO) block cache
//! that sits between MemTable misses and SSTable I/O.
//!
//! # S3-FIFO structure
//! - **Small Queue** (~10 % of capacity): newly inserted blocks.
//! - **Main Queue** (~90 % of capacity): blocks promoted after ≥ 2 accesses.
//! - **Ghost Buffer** (metadata only): tracks recently evicted block IDs so
//!   that re-requested blocks skip the Small Queue and land directly in Main.
//!
//! # Eviction rules
//! 1. New block → Small Queue.
//! 2. Small Queue block accessed again → promoted to Main Queue on next eviction.
//! 3. Small Queue full → oldest item evicted; if freq > 0 → Main Queue,
//!    else → Ghost Buffer.
//! 4. Main Queue full → oldest item evicted; if freq > 1 → freq--, re-insert
//!    at tail (one CLOCK-like chance); if freq ≤ 1 → permanent eviction.
//! 5. Ghost Buffer hit on insert → block goes directly to Main Queue.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

// ── Public types ─────────────────────────────────────────────────────────────

/// Cache key: identifies a data block by its SSTable file and byte offset.
#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
pub struct BlockCacheKey {
    pub file_id: u64,
    pub block_offset: u64,
}

/// A cached data block — zero-copy view into a memory-mapped SSTable or
/// owned aligned bytes. Defined in the storage layer (spec perf/003).
pub use crate::storage::format::CachedBlock;

// ── Metrics ──────────────────────────────────────────────────────────────────

pub struct BlockCacheMetrics {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub small_hits: AtomicU64,
    pub main_hits: AtomicU64,
    pub small_evictions: AtomicU64,
    pub main_evictions: AtomicU64,
    /// Snapshot of current_bytes, updated on every insert/evict.
    pub current_bytes: AtomicU64,
}

impl Default for BlockCacheMetrics {
    fn default() -> Self {
        Self {
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            small_hits: AtomicU64::new(0),
            main_hits: AtomicU64::new(0),
            small_evictions: AtomicU64::new(0),
            main_evictions: AtomicU64::new(0),
            current_bytes: AtomicU64::new(0),
        }
    }
}

// ── Internal index entry ──────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Debug)]
enum Location {
    Small,
    Main,
}

struct IndexEntry {
    location: Location,
    /// Access frequency counter, capped at 3.
    freq: u8,
    block: CachedBlock,
    block_size: usize,
}

// ── BlockCache ────────────────────────────────────────────────────────────────

/// S3-FIFO block cache.
///
/// **Not thread-safe.** Wrap in `parking_lot::Mutex<BlockCache>` for concurrent
/// access.
pub struct BlockCache {
    /// Insertion-order queues (keys only; data lives in `index`).
    small: VecDeque<BlockCacheKey>,
    main: VecDeque<BlockCacheKey>,
    /// Ghost buffer: key-only, tracks recently evicted block identifiers.
    ghost: VecDeque<BlockCacheKey>,

    /// Authoritative state: location, frequency, and block data.
    index: HashMap<BlockCacheKey, IndexEntry>,
    /// O(1) ghost membership test.
    ghost_set: HashSet<BlockCacheKey>,

    current_bytes: usize,
    small_bytes: usize,
    capacity_bytes: usize,
    small_ratio: f32,
    ghost_capacity: usize,

    pub metrics: Arc<BlockCacheMetrics>,
}

impl BlockCache {
    pub fn new(capacity_bytes: usize, small_ratio: f32, ghost_capacity: usize) -> Self {
        Self {
            small: VecDeque::new(),
            main: VecDeque::new(),
            ghost: VecDeque::new(),
            index: HashMap::new(),
            ghost_set: HashSet::new(),
            current_bytes: 0,
            small_bytes: 0,
            capacity_bytes,
            small_ratio,
            ghost_capacity,
            metrics: Arc::new(BlockCacheMetrics::default()),
        }
    }

    pub fn metrics(&self) -> Arc<BlockCacheMetrics> {
        Arc::clone(&self.metrics)
    }

    // ── Read ─────────────────────────────────────────────────────────────────

    /// Looks up a block. Returns the cached bytes on hit, `None` on miss.
    ///
    /// Increments the access frequency of the entry (capped at 3) so that hot
    /// blocks are promoted / retained on the next eviction pass.
    pub fn get(&mut self, key: &BlockCacheKey) -> Option<CachedBlock> {
        match self.index.get_mut(key) {
            None => {
                self.metrics.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
            Some(entry) => {
                entry.freq = entry.freq.saturating_add(1).min(3);
                let block = entry.block.clone();
                match entry.location {
                    Location::Small => {
                        self.metrics.hits.fetch_add(1, Ordering::Relaxed);
                        self.metrics.small_hits.fetch_add(1, Ordering::Relaxed);
                    }
                    Location::Main => {
                        self.metrics.hits.fetch_add(1, Ordering::Relaxed);
                        self.metrics.main_hits.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Some(block)
            }
        }
    }

    // ── Write ─────────────────────────────────────────────────────────────────

    /// Inserts a block into the cache.
    ///
    /// - If the block is already cached, the call is a no-op.
    /// - If the key is in the Ghost Buffer, the block is inserted directly
    ///   into the Main Queue (bypassing Small).
    /// - Otherwise the block enters the Small Queue.
    ///
    /// After insertion the eviction policy is applied to enforce capacity limits.
    pub fn insert(&mut self, key: BlockCacheKey, block: CachedBlock) {
        if self.index.contains_key(&key) {
            return;
        }

        let block_size = block.len();
        let is_ghost = self.ghost_set.contains(&key);

        if is_ghost {
            // Ghost hit → bypass Small, insert directly to Main with freq = 1.
            self.remove_from_ghost(&key);
            self.main.push_back(key);
            self.index.insert(key, IndexEntry {
                location: Location::Main,
                freq: 1,
                block,
                block_size,
            });
            self.current_bytes += block_size;
        } else {
            // Fresh insert → Small Queue.
            self.small.push_back(key);
            self.index.insert(key, IndexEntry {
                location: Location::Small,
                freq: 0,
                block,
                block_size,
            });
            self.current_bytes += block_size;
            self.small_bytes += block_size;
        }

        self.metrics.current_bytes.store(self.current_bytes as u64, Ordering::Relaxed);
        self.enforce_capacity();
    }

    // ── Invalidation ─────────────────────────────────────────────────────────

    /// Removes all cache entries (Small, Main, and Ghost) that belong to
    /// `file_id`. Called after an SSTable file is deleted by compaction.
    pub fn invalidate_file(&mut self, file_id: u64) {
        let to_remove: Vec<BlockCacheKey> = self
            .index
            .keys()
            .filter(|k| k.file_id == file_id)
            .copied()
            .collect();

        for key in &to_remove {
            if let Some(entry) = self.index.remove(key) {
                match entry.location {
                    Location::Small => {
                        self.current_bytes -= entry.block_size;
                        self.small_bytes -= entry.block_size;
                    }
                    Location::Main => {
                        self.current_bytes -= entry.block_size;
                    }
                }
            }
            self.ghost_set.remove(key);
        }

        // Purge stale keys from ordering deques (linear scan, but infrequent).
        self.small.retain(|k| k.file_id != file_id);
        self.main.retain(|k| k.file_id != file_id);
        self.ghost.retain(|k| k.file_id != file_id);

        self.metrics.current_bytes.store(self.current_bytes as u64, Ordering::Relaxed);
    }

    // ── Eviction helpers ──────────────────────────────────────────────────────

    fn enforce_capacity(&mut self) {
        let small_cap = (self.capacity_bytes as f32 * self.small_ratio) as usize;

        // Keep Small within its ratio share.
        while self.small_bytes > small_cap && !self.small.is_empty() {
            self.evict_from_small();
        }

        // Keep total within overall capacity.
        while self.current_bytes > self.capacity_bytes {
            if !self.main.is_empty() {
                self.evict_from_main();
            } else if !self.small.is_empty() {
                self.evict_from_small();
            } else {
                break;
            }
        }

        self.metrics.current_bytes.store(self.current_bytes as u64, Ordering::Relaxed);
    }

    /// Evicts one item from the Small Queue.
    ///
    /// - freq > 0 → promote to Main Queue.
    /// - freq == 0 → evict permanently; key goes to Ghost Buffer.
    fn evict_from_small(&mut self) {
        while let Some(key) = self.small.pop_front() {
            let entry = match self.index.remove(&key) {
                Some(e) => e,
                None => continue, // Stale deque entry — skip.
            };

            self.current_bytes -= entry.block_size;
            self.small_bytes -= entry.block_size;

            if entry.freq > 0 {
                // Promote to Main.
                self.main.push_back(key);
                self.index.insert(key, IndexEntry {
                    location: Location::Main,
                    freq: entry.freq,
                    block: entry.block,
                    block_size: entry.block_size,
                });
                self.current_bytes += entry.block_size;
                // (Not counted in small_bytes — now in Main.)
            } else {
                // Evict to Ghost.
                self.metrics.small_evictions.fetch_add(1, Ordering::Relaxed);
                self.add_to_ghost(key);
            }
            return;
        }
    }

    /// Permanently removes a Main-queue entry (index, byte accounting, metric).
    fn remove_main_entry(&mut self, key: &BlockCacheKey) {
        if let Some(entry) = self.index.remove(key) {
            self.current_bytes -= entry.block_size;
            self.metrics.main_evictions.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Evicts one item from the Main Queue.
    ///
    /// Items with freq > 1 are given one CLOCK-like extra chance (freq--, moved
    /// to tail). The first item with freq ≤ 1 is evicted permanently.
    fn evict_from_main(&mut self) {
        let initial_len = self.main.len();
        let mut checked = 0;

        while checked < initial_len {
            let Some(key) = self.main.pop_front() else {
                return;
            };
            let Some(freq) = self.index.get(&key).map(|e| e.freq) else {
                return; // Stale entry — aborts the round.
            };

            if freq <= 1 {
                self.remove_main_entry(&key);
                return;
            }

            // Give one more chance: decrement freq and re-insert at tail.
            if let Some(e) = self.index.get_mut(&key) {
                e.freq -= 1;
            }
            self.main.push_back(key);
            checked += 1;
        }

        // All items had freq > 1 — force-evict the front item.
        if let Some(key) = self.main.pop_front() {
            self.remove_main_entry(&key);
        }
    }

    // ── Ghost Buffer helpers ──────────────────────────────────────────────────

    fn add_to_ghost(&mut self, key: BlockCacheKey) {
        // Trim ghost to its capacity (evict oldest active ghost entry first).
        while self.ghost_set.len() >= self.ghost_capacity {
            match self.ghost.pop_front() {
                Some(k) if self.ghost_set.contains(&k) => {
                    self.ghost_set.remove(&k);
                    break;
                }
                Some(_) => continue, // Stale deque entry.
                None => break,
            }
        }

        if !self.ghost_set.contains(&key) {
            self.ghost.push_back(key);
            self.ghost_set.insert(key);
        }
    }

    /// Removes `key` from the ghost set (lazy: deque entry becomes stale).
    fn remove_from_ghost(&mut self, key: &BlockCacheKey) {
        self.ghost_set.remove(key);
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rkyv::util::AlignedVec;

    fn make_block(n: usize, size: usize) -> (BlockCacheKey, CachedBlock) {
        let key = BlockCacheKey { file_id: 1, block_offset: n as u64 };
        let mut av = AlignedVec::with_capacity(size);
        av.extend_from_slice(&vec![n as u8; size]);
        (key, CachedBlock::Owned(Arc::new(av)))
    }

    // Test 1: insert + get → Cache Hit, metric incremented.
    #[test]
    fn test_insert_and_get_hit() {
        let mut cache = BlockCache::new(1024 * 1024, 0.10, 100);
        let (key, block) = make_block(0, 64);
        cache.insert(key, block.clone());

        let result = cache.get(&key);
        assert!(result.is_some());
        assert_eq!(result.unwrap().as_bytes(), block.as_bytes());
        assert_eq!(cache.metrics.hits.load(Ordering::Relaxed), 1);
        assert_eq!(cache.metrics.small_hits.load(Ordering::Relaxed), 1);
        assert_eq!(cache.metrics.misses.load(Ordering::Relaxed), 0);
    }

    // Test 2: Capacity exceeded → eviction from Small Queue, Ghost Buffer filled.
    #[test]
    fn test_capacity_eviction_fills_ghost() {
        // 3 blocks of 400 bytes each; capacity = 1000 bytes, small = 100 bytes.
        let block_size = 400;
        let capacity = 1000;
        let mut cache = BlockCache::new(capacity, 0.10, 100); // small_cap = 100 bytes

        // Insert first block → Small (small_bytes=400 > small_cap=100, evict)
        let (k0, b0) = make_block(0, block_size);
        cache.insert(k0, b0);
        // k0 should have been moved to ghost (freq=0, evicted from small)
        assert!(cache.ghost_set.contains(&k0));
        assert_eq!(cache.metrics.small_evictions.load(Ordering::Relaxed), 1);

        // Insert second block
        let (k1, b1) = make_block(1, block_size);
        cache.insert(k1, b1);
        // k1 also evicted to ghost
        assert!(cache.ghost_set.contains(&k1));

        assert!(cache.metrics.small_evictions.load(Ordering::Relaxed) >= 2);
    }

    // Test 3: Evicted block re-requested → Ghost Buffer hit → directly into Main.
    #[test]
    fn test_ghost_hit_promotes_to_main() {
        let block_size = 400;
        let mut cache = BlockCache::new(1000, 0.10, 100); // small_cap = 100

        // Insert and let k0 be evicted to ghost (freq=0 → ghost).
        let (k0, b0) = make_block(0, block_size);
        cache.insert(k0, b0.clone());
        assert!(cache.ghost_set.contains(&k0));

        // Re-insert the same block → ghost hit → Main Queue.
        cache.insert(k0, b0.clone());
        assert!(!cache.ghost_set.contains(&k0));
        let entry = cache.index.get(&k0).expect("should be in index");
        assert_eq!(entry.location, Location::Main);
    }

    // Test 4: Large scan (many single-access blocks) → Main Queue stays stable.
    #[test]
    fn test_scan_resistance() {
        let block_size = 1024;
        let capacity = 100 * block_size; // room for 100 blocks
        let mut cache = BlockCache::new(capacity, 0.10, 1000);

        // Fill Main Queue with 90 "hot" blocks (accessed twice).
        for i in 0..90usize {
            let (k, b) = make_block(i, block_size);
            cache.insert(k, b);
            // Access again to bump freq.
            cache.get(&k);
        }

        let main_len_before = cache.main.len();

        // Simulate a large scan: 200 unique blocks accessed only once.
        for i in 1000..1200usize {
            let (k, b) = make_block(i, block_size);
            cache.insert(k, b);
            // No second access — these stay in Small and get evicted.
        }

        // Main Queue should not have been completely evicted.
        let hot_still_in_main = cache
            .main
            .iter()
            .filter(|k| k.file_id == 1 && (k.block_offset as usize) < 90)
            .count();

        assert!(
            hot_still_in_main > 0,
            "Hot blocks should survive a large scan (main_before={main_len_before})",
        );
    }

    fn make_aligned(byte: u8, size: usize) -> CachedBlock {
        let mut av = AlignedVec::with_capacity(size);
        av.extend_from_slice(&vec![byte; size]);
        CachedBlock::Owned(Arc::new(av))
    }

    // Test 5: invalidate_file removes all entries for that file_id.
    #[test]
    fn test_invalidate_file() {
        let mut cache = BlockCache::new(1024 * 1024, 0.10, 100);

        for i in 0..5usize {
            let key = BlockCacheKey { file_id: 1, block_offset: i as u64 };
            cache.insert(key, make_aligned(0, 64));
        }
        for i in 0..3usize {
            let key = BlockCacheKey { file_id: 2, block_offset: i as u64 };
            cache.insert(key, make_aligned(0, 64));
        }

        assert!(!cache.index.is_empty());

        cache.invalidate_file(1);

        // All file_id=1 entries gone.
        for i in 0..5usize {
            let key = BlockCacheKey { file_id: 1, block_offset: i as u64 };
            assert!(!cache.index.contains_key(&key));
            assert!(!cache.ghost_set.contains(&key));
        }

        // file_id=2 entries remain.
        let file2_count = cache.index.keys().filter(|k| k.file_id == 2).count();
        assert_eq!(file2_count, 3);
    }

    // Test 6: Cache miss recorded; second access is a hit.
    #[test]
    fn test_miss_then_hit() {
        let mut cache = BlockCache::new(1024 * 1024, 0.10, 100);
        let key = BlockCacheKey { file_id: 1, block_offset: 0 };

        // Miss on empty cache.
        assert!(cache.get(&key).is_none());
        assert_eq!(cache.metrics.misses.load(Ordering::Relaxed), 1);

        // Insert and hit.
        let block = make_aligned(42, 128);
        cache.insert(key, block.clone());
        let got = cache.get(&key).expect("should be cached");
        assert_eq!(got.as_bytes(), block.as_bytes());
        assert_eq!(cache.metrics.hits.load(Ordering::Relaxed), 1);
    }

    /// Puts a block into Main via the ghost-hit route (insert → small-evict →
    /// ghost → re-insert). Requires `size` > small_cap so the first insert is
    /// evicted from Small immediately.
    fn insert_into_main(cache: &mut BlockCache, n: usize, size: usize) -> BlockCacheKey {
        let (key, block) = make_block(n, size);
        cache.insert(key, block.clone());
        assert!(cache.ghost_set.contains(&key));
        cache.insert(key, block);
        assert_eq!(cache.index.get(&key).unwrap().location, Location::Main);
        key
    }

    // Test 7: freq > 1 gets one CLOCK second chance (decrement + tail re-insert).
    #[test]
    fn test_main_eviction_clock_second_chance() {
        let mut cache = BlockCache::new(1000, 0.10, 100); // small_cap = 100
        let hot = insert_into_main(&mut cache, 0, 400);
        let cold = insert_into_main(&mut cache, 1, 400);
        cache.get(&hot); // freq 1 → 2

        cache.evict_from_main();

        assert!(cache.index.contains_key(&hot), "hot block must survive the round");
        assert!(!cache.index.contains_key(&cold), "cold block must be evicted");
        assert_eq!(cache.index.get(&hot).unwrap().freq, 1, "second chance decrements freq");
        assert_eq!(cache.metrics.main_evictions.load(Ordering::Relaxed), 1);
    }

    // Test 8: all items hot → the front item is force-evicted anyway.
    #[test]
    fn test_main_eviction_force_evicts_front_when_all_hot() {
        let mut cache = BlockCache::new(1000, 0.10, 100);
        let front = insert_into_main(&mut cache, 0, 400);
        let back = insert_into_main(&mut cache, 1, 400);
        cache.get(&front); // freq 2
        cache.get(&back); // freq 2

        cache.evict_from_main();

        assert!(!cache.index.contains_key(&front), "front must be force-evicted when all are hot");
        assert!(cache.index.contains_key(&back));
        assert_eq!(cache.metrics.main_evictions.load(Ordering::Relaxed), 1);
    }

    // Test 9: a stale main-deque key (no index entry) aborts the whole round.
    #[test]
    fn test_main_eviction_stale_entry_aborts_round() {
        let mut cache = BlockCache::new(1000, 0.10, 100);
        let live = insert_into_main(&mut cache, 0, 400);
        let stale = BlockCacheKey { file_id: 9, block_offset: 999 };
        cache.main.push_front(stale); // deque entry without index entry

        cache.evict_from_main();

        assert!(cache.index.contains_key(&live), "round aborts before touching live entries");
        assert_eq!(cache.metrics.main_evictions.load(Ordering::Relaxed), 0);
        assert!(!cache.main.contains(&stale), "stale key is consumed");
    }
}
