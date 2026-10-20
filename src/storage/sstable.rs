use crate::core::coop;
use crate::engines::lsm::block_cache::{BlockCacheKey, CachedBlock, StripedBlockCache};
use crate::engines::lsm::key::Timestamp;
use crate::storage::format::{
    ArchivedDataBlockValue, BlockHandle, BloomFilter, CachedValue, DataBlock, DataBlockValue,
    IndexBlock, NULL_OFFSET, SSTableFooter, TOMBSTONE_OFFSET, ValuePointer, VersionState,
};
use crate::storage::bloom::BloomFilter as BloomFilterImpl;
use rkyv::util::AlignedVec;
use rkyv::{rancor, Archived};
use anyhow::{Result, bail};
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};

const BLOCK_SIZE_TARGET: usize = 4096; // 4KB target for data blocks

/// True until `key` lies behind the run of keys that start with `prefix`.
#[inline]
fn not_behind_prefix_run(key: &[u8], prefix: &[u8]) -> bool {
    key < prefix || key.starts_with(prefix)
}

/// Returns the user-key portion of an encoded MVCC key.
///
/// MVCC keys have the layout `[user_key][inv_timestamp_be_8_bytes]`.
/// For non-MVCC keys (len < 8), the key is returned as-is.
#[inline]
fn mvcc_user_key(key: &[u8]) -> &[u8] {
    if key.len() >= 8 { &key[..key.len() - 8] } else { key }
}

/// Returns the inverted timestamp (big-endian u64) from an encoded MVCC key.
/// Returns `0` for keys shorter than 8 bytes.
#[inline]
fn mvcc_inv_ts(key: &[u8]) -> u64 {
    if key.len() >= 8 {
        u64::from_be_bytes(key[key.len() - 8..].try_into().unwrap_or([0u8; 8]))
    } else {
        0
    }
}

pub struct SSTableBuilder {
    data_blocks: Vec<DataBlock>,
    current_block: DataBlock,
    // (last_key, block_handle)
    index: IndexBlock,
    // Bloom filter keyed on user_key (MVCC timestamp stripped)
    bloom_filter: BloomFilterImpl,
    total_keys: usize,
}

impl SSTableBuilder {
    pub fn new() -> Self {
        let initial_bloom_size = 10000;
        Self {
            data_blocks: Vec::new(),
            current_block: DataBlock {
                entries: Vec::new(),
            },
            index: IndexBlock {
                entries: Vec::new(),
            },
            bloom_filter: BloomFilterImpl::new(initial_bloom_size, 0.01),
            total_keys: 0,
        }
    }

    /// Adds a key-value pointer pair (large value in VLog) to the SSTable.
    /// Keys must be added in sorted order.
    pub fn add(&mut self, key: Vec<u8>, value_pointer: ValuePointer) {
        // Bloom filter keyed on user_key so that MVCC snapshot reads hit correctly.
        self.bloom_filter.insert(mvcc_user_key(&key));
        self.total_keys += 1;
        self.current_block
            .entries
            .push((key, DataBlockValue::Pointer(value_pointer)));
        if self.current_block.entries.len() * 16 > BLOCK_SIZE_TARGET {
            self.finish_block();
        }
    }

    /// Adds a key with inline value data (small value, no VLog) to the SSTable.
    /// Keys must be added in sorted order.
    pub fn add_inline(&mut self, key: Vec<u8>, data: Vec<u8>, expire_at: u64) {
        self.bloom_filter.insert(mvcc_user_key(&key));
        self.total_keys += 1;
        self.current_block
            .entries
            .push((key, DataBlockValue::Inline { data, expire_at }));
        if self.current_block.entries.len() * 16 > BLOCK_SIZE_TARGET {
            self.finish_block();
        }
    }

    fn finish_block(&mut self) {
        if self.current_block.entries.is_empty() {
            return;
        }
        let block = std::mem::replace(
            &mut self.current_block,
            DataBlock {
                entries: Vec::new(),
            },
        );

        if let Some((first_key, _)) = block.entries.first() {
            let handle = BlockHandle { offset: 0, size: 0 };
            self.index
                .entries
                .push((first_key.clone(), handle));
        }
        self.data_blocks.push(block);
    }

    /// Serializes the SSTable to a byte vector.
    pub fn finish(mut self) -> anyhow::Result<Vec<u8>> {
        self.finish_block();

        let mut buf = AlignedVec::new();

        fn pad_to_align8(buf: &mut AlignedVec) {
            let misalign = buf.len() % 8;
            if misalign != 0 {
                buf.extend_from_slice(&[0u8; 8][..8 - misalign]);
            }
        }

        for (i, data_block) in self.data_blocks.iter().enumerate() {
            let block_bytes = rkyv::to_bytes::<rancor::Error>(data_block)?;

            let block_offset = buf.len() as u64;
            let block_len = block_bytes.len() as u64;
            self.index.entries[i].1.offset = block_offset;
            self.index.entries[i].1.size = block_len;

            buf.extend_from_slice(&block_bytes);
            pad_to_align8(&mut buf);
        }

        let index_bytes = rkyv::to_bytes::<rancor::Error>(&self.index)?;
        let index_handle = BlockHandle {
            offset: buf.len() as u64,
            size: index_bytes.len() as u64,
        };
        buf.extend_from_slice(&index_bytes);
        pad_to_align8(&mut buf);

        let bloom_filter = BloomFilter {
            data: self.bloom_filter.as_bytes().to_vec(),
            num_hashes: self.bloom_filter.num_hashes(),
        };
        let bloom_bytes = rkyv::to_bytes::<rancor::Error>(&bloom_filter)?;
        let bloom_filter_handle = BlockHandle {
            offset: buf.len() as u64,
            size: bloom_bytes.len() as u64,
        };
        buf.extend_from_slice(&bloom_bytes);
        pad_to_align8(&mut buf);

        let footer = SSTableFooter {
            index_handle,
            bloom_filter_handle,
            checksum: 0,
        };
        let footer_bytes = rkyv::to_bytes::<rancor::Error>(&footer)?;
        let footer_offset = buf.len() as u64;
        buf.extend_from_slice(&footer_bytes);

        buf.extend_from_slice(&footer_offset.to_le_bytes());

        Ok(buf.into_vec())
    }
}

/// Backing storage of an SSTable: fully loaded bytes (fallback, freshly
/// built tables) or a memory-mapped file (spec perf/003).
enum SSTableData {
    Owned(AlignedVec),
    Mapped(std::sync::Arc<memmap2::Mmap>),
}

impl SSTableData {
    fn as_slice(&self) -> &[u8] {
        match self {
            SSTableData::Owned(vec) => vec.as_slice(),
            SSTableData::Mapped(mmap) => &mmap[..],
        }
    }

    fn len(&self) -> usize {
        self.as_slice().len()
    }
}

pub struct SSTableReader {
    data: SSTableData,
    #[allow(dead_code)]
    footer: &'static Archived<SSTableFooter>,
    index: &'static Archived<IndexBlock>,
    bloom_filter: BloomFilterImpl,
    /// SSTable file identifier used as part of the block cache key.
    /// Set to 0 by default; call `set_file_id` after opening to assign the
    /// correct ID from the manifest.
    pub file_id: u64,
    retired: AtomicBool,
    #[cfg(test)]
    blocks_read: std::sync::atomic::AtomicUsize,
}

impl SSTableReader {
    /// Loads an SSTable fully into memory (non-mmap fallback; also used for
    /// freshly built tables whose bytes are already in RAM).
    pub fn open(raw: Vec<u8>) -> Result<Self> {
        let mut data = AlignedVec::with_capacity(raw.len());
        data.extend_from_slice(&raw);
        drop(raw);
        Self::from_data(SSTableData::Owned(data))
    }

    /// Memory-maps an SSTable file and advises the kernel to pre-fault its
    /// pages (spec perf/003). The `unsafe` map is sound: SSTables are
    /// immutable, and an unlinked file stays mapped for every version still
    /// holding its reader.
    pub fn open_mmap(path: &std::path::Path) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        let mmap = unsafe { memmap2::MmapOptions::new().map(&file)? };
        if let Err(e) = mmap.advise(memmap2::Advice::WillNeed) {
            tracing::debug!("madvise(WillNeed) failed for {}: {e}", path.display());
        }
        Self::from_data(SSTableData::Mapped(std::sync::Arc::new(mmap)))
    }

    fn from_data(data: SSTableData) -> Result<Self> {
        let bytes = data.as_slice();
        if bytes.len() < 8 {
            bail!("SSTable data too short");
        }

        let footer_offset_bytes: [u8; 8] = bytes[bytes.len() - 8..]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to read footer offset"))?;
        let footer_offset = u64::from_le_bytes(footer_offset_bytes) as usize;

        let footer_end = bytes.len() - 8;
        if footer_offset > footer_end {
            bail!("Invalid footer offset");
        }

        let footer_slice = &bytes[footer_offset..footer_end];
        let footer = rkyv::access::<Archived<SSTableFooter>, rancor::Error>(footer_slice)
            .map_err(|e| anyhow::anyhow!("Footer validation failed: {}", e))?;

        let footer: &'static Archived<SSTableFooter> = unsafe {
            std::mem::transmute(footer)
        };

        let index_offset = u64::from(footer.index_handle.offset) as usize;
        let index_size = u64::from(footer.index_handle.size) as usize;

        let index_end = index_offset
            .checked_add(index_size)
            .filter(|&end| end <= bytes.len())
            .ok_or_else(|| anyhow::anyhow!("Invalid index block offset/size"))?;

        let index_slice = &bytes[index_offset..index_end];
        let index = rkyv::access::<Archived<IndexBlock>, rancor::Error>(index_slice)
            .map_err(|e| anyhow::anyhow!("Index validation failed: {}", e))?;

        let index: &'static Archived<IndexBlock> = unsafe {
            std::mem::transmute(index)
        };

        let bloom_offset = u64::from(footer.bloom_filter_handle.offset) as usize;
        let bloom_size = u64::from(footer.bloom_filter_handle.size) as usize;

        let bloom_end = bloom_offset
            .checked_add(bloom_size)
            .filter(|&end| end <= bytes.len())
            .ok_or_else(|| anyhow::anyhow!("Invalid bloom filter offset/size"))?;

        let bloom_slice = &bytes[bloom_offset..bloom_end];
        let bloom_archived = rkyv::access::<Archived<BloomFilter>, rancor::Error>(bloom_slice)
            .map_err(|e| anyhow::anyhow!("Bloom filter validation failed: {}", e))?;

        // kv/021: an empty bit array paired with num_hashes >= 1 would divide
        // by zero on every lookup (BloomFilter::hash). A legitimate writer
        // never produces this combination (see SSTableBuilder::new), so it
        // only occurs on corrupted/torn/crafted bytes -- reject it here.
        if bloom_archived.data.is_empty() && u32::from(bloom_archived.num_hashes) >= 1 {
            bail!("Invalid bloom filter: empty bit array with non-zero hash count");
        }

        let bloom_filter = BloomFilterImpl::from_bytes(
            bloom_archived.data.to_vec(),
            u32::from(bloom_archived.num_hashes),
        );

        Ok(Self {
            data,
            footer,
            index,
            bloom_filter,
            file_id: 0,
            retired: AtomicBool::new(false),
            #[cfg(test)]
            blocks_read: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// Sets the file ID used as part of the block cache key.
    pub fn set_file_id(&mut self, file_id: u64) {
        self.file_id = file_id;
    }

    /// Marks the table as out of every current version: readers on an older
    /// one still read it, but its blocks no longer enter the cache. Call
    /// before the cache invalidates the file.
    pub fn retire(&self) {
        self.retired.store(true, Ordering::Release);
    }

    /// Point lookup that checks and populates the block cache.
    ///
    /// Semantics are identical to [`get`] but every data block read is
    /// first looked up in `cache`; on a miss the raw block bytes are stored
    /// in the cache for future reads, except inside [`coop::inline_read`],
    /// where a miss on a mapped table ends the lookup with an error.
    pub fn get_with_cache(
        &self,
        key: &[u8],
        cache: &StripedBlockCache,
    ) -> Result<Option<CachedValue>> {
        Ok(self.get_with_cache_and_ts(key, cache)?.map(|(v, _)| v))
    }

    /// Like [`Self::get_with_cache`], but also returns the matched entry's
    /// write timestamp, un-inverted back to HLC form (spec kv/022
    /// `last_modified_at`) — the encoded key stores it inverted
    /// (`Timestamp::inverted`) for newest-first sort order.
    pub fn get_with_cache_and_ts(
        &self,
        key: &[u8],
        cache: &StripedBlockCache,
    ) -> Result<Option<(CachedValue, Timestamp)>> {
        let bloom_key = mvcc_user_key(key);
        if !self.bloom_filter.contains(bloom_key) {
            return Ok(None);
        }

        // ── 1. Exact-match path ───────────────────────────────────────────────
        let block_idx = self.find_block(key)?;
        if let Some(idx) = block_idx {
            let block_handle = &self.index.entries[idx].1;
            let block_offset = u64::from(block_handle.offset);
            let cache_key = BlockCacheKey { file_id: self.file_id, block_offset };

            let raw = self.get_or_cache_block(block_handle, &cache_key, cache)?;
            let data_block = rkyv::access::<Archived<DataBlock>, rancor::Error>(raw.as_bytes())
                .map_err(|e| anyhow::anyhow!("DataBlock validation failed: {}", e))?;

            for entry in data_block.entries.iter() {
                if entry.0.as_slice() == key {
                    let ts = Timestamp::from_inverted(mvcc_inv_ts(entry.0.as_slice()));
                    return Ok(Some((cached_value_from_archived(&raw, &entry.1), ts)));
                }
            }
        }

        // ── 2. MVCC fallback ──────────────────────────────────────────────────
        if key.len() >= 8 {
            return self.get_mvcc_prefix_cached(key, cache);
        }

        Ok(None)
    }

    /// MVCC prefix scan with block cache integration; also returns the
    /// matched entry's un-inverted write timestamp (see
    /// [`Self::get_with_cache_and_ts`]).
    fn get_mvcc_prefix_cached(
        &self,
        key: &[u8],
        cache: &StripedBlockCache,
    ) -> Result<Option<(CachedValue, Timestamp)>> {
        let search_user_key = mvcc_user_key(key);
        let search_inv_ts = mvcc_inv_ts(key);

        let start_idx = self.find_block_by_user_key(search_user_key)?.map_or(0, |i| i.saturating_sub(1));

        for bi in start_idx..self.index.entries.len() {
            let block_handle = &self.index.entries[bi].1;
            let block_offset = u64::from(block_handle.offset);
            let cache_key = BlockCacheKey { file_id: self.file_id, block_offset };

            let raw = self.get_or_cache_block(block_handle, &cache_key, cache)?;
            let data_block = rkyv::access::<Archived<DataBlock>, rancor::Error>(raw.as_bytes())
                .map_err(|e| anyhow::anyhow!("DataBlock validation failed: {}", e))?;

            let mut passed_user_key = false;

            for entry in data_block.entries.iter() {
                let bk = entry.0.as_slice();
                let bk_user = mvcc_user_key(bk);

                if bk_user != search_user_key {
                    if passed_user_key {
                        return Ok(None);
                    }
                    continue;
                }

                passed_user_key = true;
                let stored_inv_ts = mvcc_inv_ts(bk);

                if stored_inv_ts >= search_inv_ts {
                    let ts = Timestamp::from_inverted(stored_inv_ts);
                    return Ok(Some((cached_value_from_archived(&raw, &entry.1), ts)));
                }
            }

            // User key seen in this block but no visible version yet —
            // might continue into the next block.
        }

        Ok(None)
    }

    /// Returns the raw bytes of a data block, using the cache when available.
    ///
    /// On a cache miss the block is taken from the table's data and, unless
    /// the table is retired, inserted into the cache before being returned.
    /// Inside [`coop::inline_read`] a miss on a mapped table fails instead.
    /// Only the block's own stripe is locked.
    fn get_or_cache_block(
        &self,
        handle: &Archived<BlockHandle>,
        cache_key: &BlockCacheKey,
        cache: &StripedBlockCache,
    ) -> Result<CachedBlock> {
        let mut stripe = cache.stripe(cache_key);
        if let Some(cached) = stripe.get(cache_key) {
            return Ok(cached);
        }

        let offset = u64::from(handle.offset) as usize;
        let size = u64::from(handle.size) as usize;

        let end = offset
            .checked_add(size)
            .filter(|&end| end <= self.data.len())
            .ok_or_else(|| anyhow::anyhow!("Invalid data block offset/size"))?;

        let block = match &self.data {
            SSTableData::Mapped(mmap) => {
                // The mapping's pages may still be on disk.
                if coop::would_block() {
                    bail!("data block not cached: reading it may wait for the disk");
                }
                // Zero-copy: the cache entry references the shared mapping.
                CachedBlock::Mapped {
                    mmap: std::sync::Arc::clone(mmap),
                    offset,
                    len: size,
                }
            }
            SSTableData::Owned(_) => {
                let mut aligned = AlignedVec::with_capacity(size);
                aligned.extend_from_slice(&self.data.as_slice()[offset..end]);
                CachedBlock::Owned(std::sync::Arc::new(aligned))
            }
        };
        debug_assert_eq!(
            block.as_bytes().as_ptr() as usize % 8,
            0,
            "data block must be 8-byte aligned for rkyv"
        );
        // Under the stripe guard, which `invalidate_file` takes after
        // `retire`: an insert either precedes that invalidation or sees the mark.
        if !self.retired.load(Ordering::Acquire) {
            stripe.insert(*cache_key, block.clone());
        }
        Ok(block)
    }

    /// Performs a point lookup for a given key.
    ///
    /// Supports both exact key lookup (non-MVCC) and MVCC-aware lookup where the
    /// search key carries a snapshot timestamp that may differ from the stored
    /// write timestamp.  For MVCC keys (len >= 8), the method falls back to a
    /// user-key prefix scan if the exact match misses.
    pub fn get(&self, key: &[u8]) -> Result<Option<DataBlockValue>> {
        // Bloom filter is keyed on user_key (timestamp stripped) so check accordingly.
        let bloom_key = mvcc_user_key(key);
        if !self.bloom_filter.contains(bloom_key) {
            return Ok(None);
        }

        // ── 1. Exact-match path (works when snapshot timestamp == write timestamp) ──
        let block_idx = self.find_block(key)?;
        if let Some(idx) = block_idx {
            let block_handle = &self.index.entries[idx].1;
            let data_block = self.read_data_block(block_handle)?;
            for entry in data_block.entries.iter() {
                if entry.0.as_slice() == key {
                    return Ok(Some(archived_to_owned_dbv(&entry.1)));
                }
            }
        }

        // ── 2. MVCC-fallback (snapshot timestamp differs from write timestamp) ─────
        // Keys >= 8 bytes are treated as MVCC-encoded: [user_key][inv_ts_be_8_bytes].
        // A snapshot taken AFTER the write has a smaller inv_ts than the stored key,
        // so the exact block search misses. We search by user_key prefix instead.
        if key.len() >= 8 {
            return self.get_mvcc_prefix(key);
        }

        Ok(None)
    }

    /// MVCC-aware lookup: find the most recent version of user_key that is
    /// visible under the given snapshot timestamp.
    ///
    /// `key` must be an MVCC-encoded key: `[user_key][inv_snapshot_ts_be_8_bytes]`.
    /// An entry is visible iff `stored_inv_ts >= search_inv_ts`
    /// (equivalent to `T_stored <= T_snapshot`).
    fn get_mvcc_prefix(&self, key: &[u8]) -> Result<Option<DataBlockValue>> {
        let search_user_key = mvcc_user_key(key);
        let search_inv_ts = mvcc_inv_ts(key);

        // Find the last block whose first user_key <= search_user_key.
        // Start one block earlier to cover entries that span block boundaries.
        let start_idx = self.find_block_by_user_key(search_user_key)?.map_or(0, |i| i.saturating_sub(1));

        for bi in start_idx..self.index.entries.len() {
            let block_handle = &self.index.entries[bi].1;
            let data_block = self.read_data_block(block_handle)?;
            let mut passed_user_key = false;

            for entry in data_block.entries.iter() {
                let bk = entry.0.as_slice();
                let bk_user = mvcc_user_key(bk);

                if bk_user != search_user_key {
                    if passed_user_key {
                        // We've iterated past all versions of this user_key.
                        return Ok(None);
                    }
                    continue;
                }

                passed_user_key = true;
                let stored_inv_ts = mvcc_inv_ts(bk);

                // stored_inv_ts >= search_inv_ts  ↔  T_stored <= T_snapshot (visible)
                if stored_inv_ts >= search_inv_ts {
                    return Ok(Some(archived_to_owned_dbv(&entry.1)));
                }
                // stored_inv_ts < search_inv_ts  ↔  T_stored > T_snapshot (too new)
                // Keep iterating — next entries are older versions.
            }
        }

        Ok(None)
    }

    /// Binary search: returns the index of the last block whose first full key
    /// is ≤ `key`.  Used for exact-match lookups.
    fn find_block(&self, key: &[u8]) -> Result<Option<usize>> {
        if self.index.entries.is_empty() {
            return Ok(None);
        }

        let mut left = 0;
        let mut right = self.index.entries.len();
        let mut result = None;

        while left < right {
            let mid = left + (right - left) / 2;
            let block_first_key = &self.index.entries[mid].0;

            if block_first_key.as_slice() <= key {
                result = Some(mid);
                left = mid + 1;
            } else {
                right = mid;
            }
        }

        Ok(result)
    }

    /// Binary search: returns the index of the last block whose first
    /// **user_key** (MVCC timestamp stripped) is ≤ `user_key`.
    fn find_block_by_user_key(&self, user_key: &[u8]) -> Result<Option<usize>> {
        if self.index.entries.is_empty() {
            return Ok(None);
        }

        let mut left = 0;
        let mut right = self.index.entries.len();
        let mut result = None;

        while left < right {
            let mid = left + (right - left) / 2;
            let bfk = &self.index.entries[mid].0;
            let bfk_user = mvcc_user_key(bfk.as_slice());

            if bfk_user <= user_key {
                result = Some(mid);
                left = mid + 1;
            } else {
                right = mid;
            }
        }

        Ok(result)
    }

    fn read_data_block(&self, handle: &Archived<BlockHandle>) -> Result<&Archived<DataBlock>> {
        #[cfg(test)]
        self.blocks_read.fetch_add(1, Ordering::Relaxed);
        let offset = u64::from(handle.offset) as usize;
        let size = u64::from(handle.size) as usize;

        let end = offset
            .checked_add(size)
            .filter(|&end| end <= self.data.len())
            .ok_or_else(|| anyhow::anyhow!("Invalid data block offset/size"))?;

        let block_slice = &self.data.as_slice()[offset..end];
        rkyv::access::<Archived<DataBlock>, rancor::Error>(block_slice)
            .map_err(|e| anyhow::anyhow!("DataBlock validation failed: {}", e))
    }

    /// Iterates all versions whose user-key starts with `prefix`, without
    /// touching the vLog. Yields `(user_key, live)` in key order (newest
    /// version first per user-key); `live` is `false` for tombstones and
    /// TTL-expired entries so callers can suppress older versions.
    pub fn keys_with_prefix<'a>(
        &'a self,
        prefix: &'a [u8],
    ) -> impl Iterator<Item = Result<(Vec<u8>, bool)>> + 'a {
        self.prefix_entries(prefix, None)
            .map(|entry| entry.map(|(user_key, _ts, state)| (user_key, state == VersionState::Live)))
    }

    /// Like [`Self::keys_with_prefix`], but only considers versions visible
    /// under an MVCC snapshot ceiling (spec general/006 backup export):
    /// `max_inv_ts` is the snapshot timestamp in *inverted* form
    /// (`Timestamp::inverted()`). Entries newer than the snapshot are
    /// skipped instead of deciding the key, so an older, visible version
    /// further along can still decide it.
    pub fn keys_with_prefix_at<'a>(
        &'a self,
        prefix: &'a [u8],
        max_inv_ts: u64,
    ) -> impl Iterator<Item = Result<(Vec<u8>, bool)>> + 'a {
        self.prefix_entries(prefix, Some(max_inv_ts))
            .map(|entry| entry.map(|(user_key, _ts, state)| (user_key, state == VersionState::Live)))
    }

    /// Shared implementation for [`Self::keys_with_prefix`]/
    /// [`Self::keys_with_prefix_at`]: `max_inv_ts` of `None` matches every
    /// version (today's `keys_with_prefix` behavior). Returns each version's
    /// write timestamp and liveness classification (spec kv/025 §2) — the
    /// callers above collapse it to today's `(user_key, bool)`, the TTL
    /// sweeper's expiry scan uses it directly.
    pub(crate) fn prefix_entries<'a>(
        &'a self,
        prefix: &'a [u8],
        max_inv_ts: Option<u64>,
    ) -> impl Iterator<Item = Result<(Vec<u8>, Timestamp, VersionState)>> + 'a {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // The start block may open before the range: those entries pass here
        // and fall to the filter below. Behind the range, none match.
        let range_entries = self.iter_blocks(self.prefix_blocks(prefix)).take_while(move |entry| match entry {
            Ok((key, _)) => not_behind_prefix_run(key, prefix),
            Err(_) => true,
        });

        range_entries.filter_map(move |entry| {
            let (encoded_key, dbv) = match entry {
                Ok(e) => e,
                Err(e) => return Some(Err(e)),
            };
            if encoded_key.len() < 8 {
                return None;
            }
            let user_key = &encoded_key[..encoded_key.len() - 8];
            if !user_key.starts_with(prefix) {
                return None;
            }
            let inv_ts = mvcc_inv_ts(encoded_key);
            if let Some(ceiling) = max_inv_ts {
                if inv_ts < ceiling {
                    return None; // newer than the snapshot -- not decisive
                }
            }
            let state = dbv.version_state(now);
            Some(Ok((user_key.to_vec(), Timestamp::from_inverted(inv_ts), state)))
        })
    }

    /// Blocks that can hold keys with `prefix`. Every such encoded key starts
    /// with the prefix, so they form one run in key order: it begins in the
    /// last block whose first key is `<= prefix` (block 0 if none) and ends
    /// before the first block that opens behind the run.
    fn prefix_blocks(&self, prefix: &[u8]) -> Range<usize> {
        let firsts = &self.index.entries;
        let start = firsts
            .partition_point(|entry| entry.0.as_slice() <= prefix)
            .saturating_sub(1);
        let end = firsts.partition_point(|entry| not_behind_prefix_run(entry.0.as_slice(), prefix));
        start..end
    }

    /// Returns an iterator over all entries in the SSTable.
    pub fn iter(&self) -> SSTableIterator<'_> {
        self.iter_blocks(0..self.index.entries.len())
    }

    fn iter_blocks(&self, blocks: Range<usize>) -> SSTableIterator<'_> {
        SSTableIterator {
            reader: self,
            block_idx: blocks.start,
            end_block: blocks.end,
            entry_idx: 0,
            current_block: None,
        }
    }
}

/// Builds a `CachedValue` for a matched entry inside a cached block without
/// copying value bytes (spec perf/002). Inline values become zero-copy
/// offsets into the block's `Arc<AlignedVec>` allocation — sound because the
/// `Arc` pins the allocation and the archived bytes live inside it. The
/// tombstone (file_id == 0, offset == TOMBSTONE_OFFSET) and NULL (file_id ==
/// 0, offset == NULL_OFFSET) sentinels are resolved here (spec kv/018).
fn cached_value_from_archived(block: &CachedBlock, value: &ArchivedDataBlockValue) -> CachedValue {
    match value {
        ArchivedDataBlockValue::Pointer(avp) => {
            let file_id = u32::from(avp.file_id);
            let value_offset = u64::from(avp.value_offset);
            if file_id == 0 && value_offset == TOMBSTONE_OFFSET {
                CachedValue::Tombstone
            } else if file_id == 0 && value_offset == NULL_OFFSET {
                CachedValue::Null
            } else {
                CachedValue::VLogPointer {
                    file_id,
                    value_offset,
                    value_len: u32::from(avp.value_len),
                    expire_at: u64::from(avp.expire_at),
                }
            }
        }
        ArchivedDataBlockValue::Inline { data, expire_at } => {
            let offset = data.as_slice().as_ptr() as usize - block.as_bytes().as_ptr() as usize;
            CachedValue::Cached {
                block: block.clone(),
                offset,
                len: data.len(),
                expire_at: u64::from(*expire_at),
            }
        }
    }
}

/// Converts an archived `DataBlockValue` to an owned `DataBlockValue`.
/// Still used by the iterator (compaction needs owned values) and by the
/// cache-less [`SSTableReader::get`]; removed from the cached hot path.
fn archived_to_owned_dbv(archived: &ArchivedDataBlockValue) -> DataBlockValue {
    match archived {
        ArchivedDataBlockValue::Pointer(avp) => DataBlockValue::Pointer(ValuePointer {
            file_id: u32::from(avp.file_id),
            value_offset: u64::from(avp.value_offset),
            value_len: u32::from(avp.value_len),
            expire_at: u64::from(avp.expire_at),
        }),
        ArchivedDataBlockValue::Inline { data, expire_at } => DataBlockValue::Inline {
            data: data.to_vec(),
            expire_at: u64::from(*expire_at),
        },
    }
}

/// Iterator over the entries of an SSTable's blocks `block_idx..end_block`.
pub struct SSTableIterator<'a> {
    reader: &'a SSTableReader,
    block_idx: usize,
    end_block: usize,
    entry_idx: usize,
    current_block: Option<&'a Archived<DataBlock>>,
}

impl<'a> Iterator for SSTableIterator<'a> {
    type Item = Result<(&'a [u8], DataBlockValue)>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.current_block.is_none() {
                if self.block_idx >= self.end_block {
                    return None;
                }

                let handle = &self.reader.index.entries[self.block_idx].1;
                match self.reader.read_data_block(handle) {
                    Ok(block) => {
                        self.current_block = Some(block);
                        self.entry_idx = 0;
                    }
                    Err(e) => return Some(Err(e)),
                }
            }

            if let Some(block) = self.current_block {
                if self.entry_idx < block.entries.len() {
                    let entry = &block.entries[self.entry_idx];
                    let key = entry.0.as_slice();
                    let dbv = archived_to_owned_dbv(&entry.1);
                    self.entry_idx += 1;
                    return Some(Ok((key, dbv)));
                } else {
                    self.block_idx += 1;
                    self.current_block = None;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engines::lsm::key::InternalKey;
    use crate::storage::format::ArchivedDataBlockValue;
    use rkyv::Archived;

    // Zero-copy lookups (spec perf/002): inline values reference the cached
    // block; pointers and the tombstone sentinel map to their variants.
    #[test]
    fn test_get_with_cache_returns_cached_value_variants() -> anyhow::Result<()> {
        let mut builder = SSTableBuilder::new();
        builder.add_inline(b"inline-key".to_vec(), b"hello-inline".to_vec(), 99);
        builder.add(
            b"pointer-key".to_vec(),
            ValuePointer { file_id: 3, value_offset: 1234, value_len: 56, expire_at: 7 },
        );
        builder.add(
            b"tombstone-key".to_vec(),
            ValuePointer { file_id: 0, value_offset: u64::MAX, value_len: 0, expire_at: 0 },
        );
        builder.add(
            b"null-key".to_vec(),
            ValuePointer { file_id: 0, value_offset: NULL_OFFSET, value_len: 0, expire_at: 0 },
        );
        let bytes = builder.finish()?;
        let reader = SSTableReader::open(bytes)?;
        let cache = StripedBlockCache::new(1024 * 1024, 0.1, 100);

        match reader.get_with_cache(b"inline-key", &cache)? {
            Some(CachedValue::Cached { ref block, offset, len, expire_at }) => {
                assert_eq!(expire_at, 99);
                assert_eq!(len, b"hello-inline".len());
                assert_eq!(&block.as_bytes()[offset..offset + len], b"hello-inline");
            }
            other => panic!("expected Cached, got {other:?}"),
        }

        match reader.get_with_cache(b"pointer-key", &cache)? {
            Some(CachedValue::VLogPointer { file_id, value_offset, value_len, expire_at }) => {
                assert_eq!((file_id, value_offset, value_len, expire_at), (3, 1234, 56, 7));
            }
            other => panic!("expected VLogPointer, got {other:?}"),
        }

        match reader.get_with_cache(b"tombstone-key", &cache)? {
            Some(CachedValue::Tombstone) => {}
            other => panic!("expected Tombstone, got {other:?}"),
        }

        // kv/018: the NULL sentinel is distinct from the tombstone sentinel.
        match reader.get_with_cache(b"null-key", &cache)? {
            Some(CachedValue::Null) => {}
            other => panic!("expected Null, got {other:?}"),
        }

        assert!(reader.get_with_cache(b"missing-key", &cache)?.is_none());
        Ok(())
    }

    // kv/022 regression: get_with_cache_and_ts must return the un-inverted
    // write timestamp. The encoded key stores it inverted (newest-first sort
    // order); a naive read of the raw bytes would report a NEWER write as a
    // SMALLER timestamp, decreasing `last_modified_at` on every overwrite.
    #[test]
    fn test_get_with_cache_and_ts_uninverts_timestamp() -> anyhow::Result<()> {
        use crate::engines::lsm::key::InternalKey;

        let mut builder = SSTableBuilder::new();
        // Same user key, two versions. Encoded order is newest-first (the
        // inverted timestamp of the larger raw value sorts smaller), so the
        // ts=2000 entry must be added before the ts=1000 one.
        let newer = InternalKey::new(b"k".to_vec(), Timestamp::new(2000)).encode();
        let older = InternalKey::new(b"k".to_vec(), Timestamp::new(1000)).encode();
        builder.add_inline(newer, b"v2".to_vec(), 0);
        builder.add_inline(older, b"v1".to_vec(), 0);
        let bytes = builder.finish()?;
        let reader = SSTableReader::open(bytes)?;
        let cache = StripedBlockCache::new(1024 * 1024, 0.1, 100);

        // Exact-match path: the search key equals the stored newer key.
        let search_key = InternalKey::new(b"k".to_vec(), Timestamp::new(2000)).encode();
        let (_, ts) = reader.get_with_cache_and_ts(&search_key, &cache)?.expect("must find entry");
        assert_eq!(ts, Timestamp::new(2000), "must report the write timestamp, not its inverted on-disk form");

        // MVCC-fallback path: a snapshot newer than both writes must resolve
        // to the newest version (2000) and report its un-inverted timestamp.
        let snapshot_key = InternalKey::new(b"k".to_vec(), Timestamp::new(9999)).encode();
        let (_, ts) = reader.get_with_cache_and_ts(&snapshot_key, &cache)?.expect("must find entry");
        assert_eq!(ts, Timestamp::new(2000));

        Ok(())
    }

    // mmap-backed reads (spec perf/003): same lookup semantics, zero-copy
    // blocks referencing the mapping.
    #[test]
    fn test_open_mmap_roundtrip() -> anyhow::Result<()> {
        let mut builder = SSTableBuilder::new();
        builder.add_inline(b"mkey".to_vec(), b"mval".to_vec(), 0);
        builder.add(
            b"pkey".to_vec(),
            ValuePointer { file_id: 2, value_offset: 9, value_len: 3, expire_at: 0 },
        );
        let bytes = builder.finish()?;
        let dir = tempfile::TempDir::new()?;
        let path = dir.path().join("table.sst");
        std::fs::write(&path, &bytes)?;

        let reader = SSTableReader::open_mmap(&path)?;
        let cache = StripedBlockCache::new(1024 * 1024, 0.1, 100);
        match reader.get_with_cache(b"mkey", &cache)? {
            Some(CachedValue::Cached { ref block, offset, len, .. }) => {
                assert!(matches!(block, CachedBlock::Mapped { .. }), "block must be mmap-backed");
                assert_eq!(&block.as_bytes()[offset..offset + len], b"mval");
            }
            other => panic!("expected mmap-backed Cached, got {other:?}"),
        }
        match reader.get_with_cache(b"pkey", &cache)? {
            Some(CachedValue::VLogPointer { file_id: 2, .. }) => {}
            other => panic!("expected VLogPointer, got {other:?}"),
        }
        // The uncached path reads from the mapping as well.
        assert!(reader.get(b"mkey")?.is_some());
        Ok(())
    }

    // An uncached data block of a mapped table may still be on disk: an
    // inline read gives up on it and says so, any other read caches it, and
    // inline reads hit it from then on. An owned table sits in memory.
    #[tokio::test]
    async fn test_inline_read_gives_up_on_an_uncached_mapped_block() -> anyhow::Result<()> {
        let mut builder = SSTableBuilder::new();
        builder.add_inline(b"mkey".to_vec(), b"mval".to_vec(), 0);
        let bytes = builder.finish()?;
        let dir = tempfile::TempDir::new()?;
        let path = dir.path().join("table.sst");
        std::fs::write(&path, &bytes)?;

        let mapped = SSTableReader::open_mmap(&path)?;
        let cache = StripedBlockCache::new(1024 * 1024, 0.1, 100);
        let (cold, gave_up) = coop::inline_read(async { mapped.get_with_cache(b"mkey", &cache) }).await;
        assert!(cold.is_err() && gave_up);
        assert!(mapped.get_with_cache(b"mkey", &cache)?.is_some());
        let (warm, gave_up) = coop::inline_read(async { mapped.get_with_cache(b"mkey", &cache) }).await;
        assert!(warm?.is_some() && !gave_up);

        let owned = SSTableReader::open(bytes)?;
        let cache = StripedBlockCache::new(1024 * 1024, 0.1, 100);
        let (read, gave_up) = coop::inline_read(async { owned.get_with_cache(b"mkey", &cache) }).await;
        assert!(read?.is_some() && !gave_up);
        Ok(())
    }

    #[test]
    fn test_build_and_read_sstable() -> anyhow::Result<()> {
        let mut builder = SSTableBuilder::new();
        builder.add(
            b"key1".to_vec(),
            ValuePointer { file_id: 1, value_offset: 100, value_len: 10, expire_at: 0 },
        );
        for i in 2..200 {
            builder.add(
                format!("key{:03}", i).into_bytes(),
                ValuePointer {
                    file_id: 1,
                    value_offset: 100 + (i as u64 * 10),
                    value_len: 10,
                    expire_at: 0,
                },
            );
        }
        builder.add(
            b"key999".to_vec(),
            ValuePointer { file_id: 1, value_offset: 9990, value_len: 10, expire_at: 0 },
        );

        let buf = builder.finish()?;

        let footer_offset_bytes: [u8; 8] = buf[buf.len() - 8..].try_into()?;
        let footer_offset = u64::from_le_bytes(footer_offset_bytes);

        let footer_size = std::mem::size_of::<Archived<SSTableFooter>>();
        let footer_end = footer_offset as usize + footer_size;
        let footer_slice = &buf[footer_offset as usize..footer_end];

        let footer = rkyv::access::<Archived<SSTableFooter>, rancor::Error>(footer_slice)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        assert_eq!(u64::from(footer.checksum), 0);

        let index_handle = &footer.index_handle;
        let index_offset = u64::from(index_handle.offset) as usize;
        let index_size = u64::from(index_handle.size) as usize;
        let index_slice = &buf[index_offset..index_offset + index_size];
        let index_block = rkyv::access::<Archived<IndexBlock>, rancor::Error>(index_slice)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;

        assert!(!index_block.entries.is_empty());

        let (first_key, first_block_handle) = (&index_block.entries[0].0, &index_block.entries[0].1);
        assert_eq!(first_key.as_slice(), b"key1");

        let data_offset = u64::from(first_block_handle.offset) as usize;
        let data_size = u64::from(first_block_handle.size) as usize;
        let data_slice = &buf[data_offset..data_offset + data_size];
        let data_block = rkyv::access::<Archived<DataBlock>, rancor::Error>(data_slice)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;

        let (key, dbv) = (&data_block.entries[0].0, &data_block.entries[0].1);
        assert_eq!(key.as_slice(), b"key1");
        match dbv {
            ArchivedDataBlockValue::Pointer(avp) => {
                assert_eq!(u32::from(avp.file_id), 1);
                assert_eq!(u64::from(avp.value_offset), 100);
            }
            _ => panic!("Expected Pointer variant"),
        }

        Ok(())
    }

    #[test]
    fn test_sstable_reader() -> anyhow::Result<()> {
        let mut builder = SSTableBuilder::new();
        for i in 1..=100 {
            builder.add(
                format!("key{:03}", i).into_bytes(),
                ValuePointer { file_id: 1, value_offset: i * 100, value_len: 50, expire_at: 0 },
            );
        }
        let buf = builder.finish()?;

        let reader = SSTableReader::open(buf)?;

        let result = reader.get(b"key050")?;
        assert!(result.is_some());
        match result.unwrap() {
            DataBlockValue::Pointer(vp) => {
                assert_eq!(vp.file_id, 1);
                assert_eq!(vp.value_offset, 5000);
                assert_eq!(vp.value_len, 50);
            }
            _ => panic!("Expected Pointer variant"),
        }

        let result = reader.get(b"key999")?;
        assert!(result.is_none());

        let mut count = 0;
        for item in reader.iter() {
            let (_key, _dbv) = item?;
            count += 1;
        }
        assert_eq!(count, 100);

        Ok(())
    }

    #[test]
    fn test_inline_entry_read_without_vlog() -> anyhow::Result<()> {
        let mut builder = SSTableBuilder::new();
        let inline_data = b"small_value".to_vec();
        builder.add_inline(b"inline_key".to_vec(), inline_data.clone(), 0);
        let buf = builder.finish()?;

        let reader = SSTableReader::open(buf)?;
        let result = reader.get(b"inline_key")?;
        assert!(result.is_some(), "Inline entry must be found");
        match result.unwrap() {
            DataBlockValue::Inline { data, expire_at } => {
                assert_eq!(data, inline_data);
                assert_eq!(expire_at, 0);
            }
            DataBlockValue::Pointer(_) => panic!("Expected Inline variant, got Pointer"),
        }
        Ok(())
    }

    // kv/019: a corrupted footer whose index_handle overflows `offset + size`
    // must be rejected with an `Err`, not panic (untrusted on-disk bytes).
    #[test]
    fn test_from_data_rejects_overflowing_index_handle() -> anyhow::Result<()> {
        let mut builder = SSTableBuilder::new();
        builder.add(
            b"key1".to_vec(),
            ValuePointer { file_id: 1, value_offset: 1, value_len: 1, expire_at: 0 },
        );
        let mut buf = builder.finish()?;

        let footer_offset_bytes: [u8; 8] = buf[buf.len() - 8..].try_into()?;
        let footer_offset = u64::from_le_bytes(footer_offset_bytes) as usize;
        let footer_end = buf.len() - 8;
        let footer = rkyv::access::<Archived<SSTableFooter>, rancor::Error>(&buf[footer_offset..footer_end])
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let bloom_filter_handle = BlockHandle {
            offset: u64::from(footer.bloom_filter_handle.offset),
            size: u64::from(footer.bloom_filter_handle.size),
        };

        let corrupt_footer = SSTableFooter {
            index_handle: BlockHandle { offset: u64::MAX, size: 8 },
            bloom_filter_handle,
            checksum: 0,
        };
        let corrupt_footer_bytes = rkyv::to_bytes::<rancor::Error>(&corrupt_footer)?;
        buf[footer_offset..footer_end].copy_from_slice(&corrupt_footer_bytes);

        let result = SSTableReader::open(buf);
        assert!(result.is_err(), "overflowing index_handle must be rejected, not panic");
        Ok(())
    }

    // kv/019: analog for bloom_filter_handle.
    #[test]
    fn test_from_data_rejects_overflowing_bloom_filter_handle() -> anyhow::Result<()> {
        let mut builder = SSTableBuilder::new();
        builder.add(
            b"key1".to_vec(),
            ValuePointer { file_id: 1, value_offset: 1, value_len: 1, expire_at: 0 },
        );
        let mut buf = builder.finish()?;

        let footer_offset_bytes: [u8; 8] = buf[buf.len() - 8..].try_into()?;
        let footer_offset = u64::from_le_bytes(footer_offset_bytes) as usize;
        let footer_end = buf.len() - 8;
        let footer = rkyv::access::<Archived<SSTableFooter>, rancor::Error>(&buf[footer_offset..footer_end])
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let index_handle = BlockHandle {
            offset: u64::from(footer.index_handle.offset),
            size: u64::from(footer.index_handle.size),
        };

        let corrupt_footer = SSTableFooter {
            index_handle,
            bloom_filter_handle: BlockHandle { offset: u64::MAX, size: 8 },
            checksum: 0,
        };
        let corrupt_footer_bytes = rkyv::to_bytes::<rancor::Error>(&corrupt_footer)?;
        buf[footer_offset..footer_end].copy_from_slice(&corrupt_footer_bytes);

        let result = SSTableReader::open(buf);
        assert!(result.is_err(), "overflowing bloom_filter_handle must be rejected, not panic");
        Ok(())
    }

    // kv/019: builds a valid single-block SSTable whose IndexBlock entry
    // points at an overflowing BlockHandle, to exercise the read path
    // (as opposed to the footer handles covered above).
    fn build_sstable_with_corrupt_block_handle() -> anyhow::Result<Vec<u8>> {
        let mut builder = SSTableBuilder::new();
        builder.add(
            b"key1".to_vec(),
            ValuePointer { file_id: 1, value_offset: 1, value_len: 1, expire_at: 0 },
        );
        let valid_bytes = builder.finish()?;

        let footer_offset_bytes: [u8; 8] = valid_bytes[valid_bytes.len() - 8..].try_into()?;
        let footer_offset = u64::from_le_bytes(footer_offset_bytes) as usize;
        let footer_end = valid_bytes.len() - 8;
        let footer = rkyv::access::<Archived<SSTableFooter>, rancor::Error>(
            &valid_bytes[footer_offset..footer_end],
        )
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let index_offset = u64::from(footer.index_handle.offset) as usize;

        // Keep the data-block bytes (and their alignment padding) verbatim;
        // rebuild index/bloom/footer around a corrupted BlockHandle.
        let mut buf = AlignedVec::new();
        buf.extend_from_slice(&valid_bytes[..index_offset]);

        fn pad_to_align8(buf: &mut AlignedVec) {
            let misalign = buf.len() % 8;
            if misalign != 0 {
                buf.extend_from_slice(&[0u8; 8][..8 - misalign]);
            }
        }

        let index = IndexBlock {
            entries: vec![(b"key1".to_vec(), BlockHandle { offset: u64::MAX - 4, size: 8 })],
        };
        let index_bytes = rkyv::to_bytes::<rancor::Error>(&index)?;
        let index_handle = BlockHandle { offset: buf.len() as u64, size: index_bytes.len() as u64 };
        buf.extend_from_slice(&index_bytes);
        pad_to_align8(&mut buf);

        let mut bloom_filter = BloomFilterImpl::new(10, 0.01);
        bloom_filter.insert(b"key1");
        let bloom_filter_fmt = BloomFilter {
            data: bloom_filter.as_bytes().to_vec(),
            num_hashes: bloom_filter.num_hashes(),
        };
        let bloom_bytes = rkyv::to_bytes::<rancor::Error>(&bloom_filter_fmt)?;
        let bloom_filter_handle = BlockHandle { offset: buf.len() as u64, size: bloom_bytes.len() as u64 };
        buf.extend_from_slice(&bloom_bytes);
        pad_to_align8(&mut buf);

        let footer = SSTableFooter { index_handle, bloom_filter_handle, checksum: 0 };
        let footer_bytes = rkyv::to_bytes::<rancor::Error>(&footer)?;
        let footer_offset = buf.len() as u64;
        buf.extend_from_slice(&footer_bytes);
        buf.extend_from_slice(&footer_offset.to_le_bytes());

        Ok(buf.into_vec())
    }

    // kv/019: get_with_cache → get_or_cache_block must return an `Err` for an
    // overflowing block handle instead of panicking.
    #[test]
    fn test_get_or_cache_block_rejects_overflowing_block_handle() -> anyhow::Result<()> {
        let buf = build_sstable_with_corrupt_block_handle()?;
        let reader = SSTableReader::open(buf)?;
        let cache = StripedBlockCache::new(1024 * 1024, 0.1, 100);
        let result = reader.get_with_cache(b"key1", &cache);
        assert!(result.is_err(), "overflowing block handle must be rejected, not panic");
        Ok(())
    }

    // kv/019: get → read_data_block must return an `Err` for an overflowing
    // block handle instead of panicking.
    #[test]
    fn test_read_data_block_rejects_overflowing_block_handle() -> anyhow::Result<()> {
        let buf = build_sstable_with_corrupt_block_handle()?;
        let reader = SSTableReader::open(buf)?;
        let result = reader.get(b"key1");
        assert!(result.is_err(), "overflowing block handle must be rejected, not panic");
        Ok(())
    }

    // kv/021: builds a valid SSTable whose bloom filter block is structurally
    // valid (rkyv::access succeeds) but carries an empty bit array combined
    // with `num_hashes`, to exercise the from_data fail-fast check on a
    // corrupted/crafted bloom block (as opposed to bloom.rs's own unit test
    // for the from_bytes/hash defense-in-depth layer).
    fn build_sstable_with_empty_bloom_block(num_hashes: u32) -> anyhow::Result<Vec<u8>> {
        let mut builder = SSTableBuilder::new();
        builder.add(
            b"key1".to_vec(),
            ValuePointer { file_id: 1, value_offset: 1, value_len: 1, expire_at: 0 },
        );
        let valid_bytes = builder.finish()?;

        let footer_offset_bytes: [u8; 8] = valid_bytes[valid_bytes.len() - 8..].try_into()?;
        let footer_offset = u64::from_le_bytes(footer_offset_bytes) as usize;
        let footer_end = valid_bytes.len() - 8;
        let footer = rkyv::access::<Archived<SSTableFooter>, rancor::Error>(
            &valid_bytes[footer_offset..footer_end],
        )
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let bloom_offset = u64::from(footer.bloom_filter_handle.offset) as usize;
        let index_handle = BlockHandle {
            offset: u64::from(footer.index_handle.offset),
            size: u64::from(footer.index_handle.size),
        };

        // Keep the data-block and index-block bytes (and their alignment
        // padding) verbatim; rebuild only the bloom block and footer.
        let mut buf = AlignedVec::new();
        buf.extend_from_slice(&valid_bytes[..bloom_offset]);

        fn pad_to_align8(buf: &mut AlignedVec) {
            let misalign = buf.len() % 8;
            if misalign != 0 {
                buf.extend_from_slice(&[0u8; 8][..8 - misalign]);
            }
        }

        let bloom_filter_fmt = BloomFilter { data: Vec::new(), num_hashes };
        let bloom_bytes = rkyv::to_bytes::<rancor::Error>(&bloom_filter_fmt)?;
        let bloom_filter_handle = BlockHandle { offset: buf.len() as u64, size: bloom_bytes.len() as u64 };
        buf.extend_from_slice(&bloom_bytes);
        pad_to_align8(&mut buf);

        let footer = SSTableFooter { index_handle, bloom_filter_handle, checksum: 0 };
        let footer_bytes = rkyv::to_bytes::<rancor::Error>(&footer)?;
        let footer_offset = buf.len() as u64;
        buf.extend_from_slice(&footer_bytes);
        buf.extend_from_slice(&footer_offset.to_le_bytes());

        Ok(buf.into_vec())
    }

    // kv/021: an empty bloom bit array combined with num_hashes >= 1 can only
    // come from corrupted/torn/crafted bytes (a real writer never produces
    // it, see SSTableBuilder::new) -- from_data must reject it, not panic.
    #[test]
    fn test_from_data_rejects_empty_bloom_block_with_nonzero_hashes() -> anyhow::Result<()> {
        let buf = build_sstable_with_empty_bloom_block(3)?;
        let result = SSTableReader::open(buf);
        assert!(
            result.is_err(),
            "empty bloom bit array with num_hashes >= 1 must be rejected, not panic"
        );
        Ok(())
    }

    // kv/021: num_hashes == 0 is what BloomFilter::new(0, p) legitimately
    // produces (NaN-cast); the fail-fast must not reject this combination.
    #[test]
    fn test_from_data_accepts_empty_bloom_block_with_zero_hashes() -> anyhow::Result<()> {
        let buf = build_sstable_with_empty_bloom_block(0)?;
        let result = SSTableReader::open(buf);
        assert!(
            result.is_ok(),
            "empty bloom bit array with num_hashes == 0 must still be accepted"
        );
        Ok(())
    }

    // ── Spec perf/032: prefix scans seek through the block index ─────────────

    /// The builder closes a data block at this many entries.
    const ENTRIES_PER_BLOCK: usize = BLOCK_SIZE_TARGET / 16 + 1;

    /// One stored version: user key, write timestamp, `false` for a tombstone.
    type Version = (Vec<u8>, u64, bool);

    fn version(user_key: &str, ts: u64, live: bool) -> Version {
        (user_key.as_bytes().to_vec(), ts, live)
    }

    /// `count` live keys `{prefix}0000`, `{prefix}0001`, ... written at ts 10.
    fn numbered(prefix: &str, count: usize) -> Vec<Version> {
        (0..count).map(|i| version(&format!("{prefix}{i:04}"), 10, true)).collect()
    }

    fn encode(user_key: &[u8], ts: u64) -> Vec<u8> {
        InternalKey::new(user_key.to_vec(), Timestamp::new(ts)).encode()
    }

    fn build_table(versions: Vec<Version>) -> anyhow::Result<SSTableReader> {
        let mut stored: Vec<(Vec<u8>, bool)> = versions
            .into_iter()
            .map(|(user_key, ts, live)| (encode(&user_key, ts), live))
            .collect();
        stored.sort();
        let mut builder = SSTableBuilder::new();
        for (key, live) in stored {
            if live {
                builder.add_inline(key, b"v".to_vec(), 0);
            } else {
                builder.add(
                    key,
                    ValuePointer { file_id: 0, value_offset: TOMBSTONE_OFFSET, value_len: 0, expire_at: 0 },
                );
            }
        }
        SSTableReader::open(builder.finish()?)
    }

    fn scan(reader: &SSTableReader, prefix: &[u8]) -> anyhow::Result<Vec<(Vec<u8>, bool)>> {
        reader.keys_with_prefix(prefix).collect()
    }

    fn live_keys(prefix: &str, count: usize) -> Vec<(Vec<u8>, bool)> {
        (0..count).map(|i| (format!("{prefix}{i:04}").into_bytes(), true)).collect()
    }

    /// 600 keys before, 300 inside and 600 behind the range `m:`: the range
    /// crosses a block boundary, with whole blocks on both sides.
    fn table_around_range() -> anyhow::Result<SSTableReader> {
        let mut versions = numbered("a:", 600);
        versions.extend(numbered("m:", 300));
        versions.extend(numbered("z:", 600));
        let reader = build_table(versions)?;
        assert_eq!(reader.index.entries.len(), 6, "layout precondition");
        Ok(reader)
    }

    // Test 1: keys before, inside and behind the range -> exactly the hits.
    #[test]
    fn test_prefix_scan_returns_exactly_the_range_across_blocks() -> anyhow::Result<()> {
        let reader = table_around_range()?;
        assert_eq!(scan(&reader, b"m:")?, live_keys("m:", 300));
        Ok(())
    }

    // Test 2: a prefix that is itself a key, a prefix below the first key, a
    // prefix above the last key. The stamp's 0xFF sorts a key behind its own
    // extensions, so the result order is abc, abd, ab.
    #[test]
    fn test_prefix_scan_nested_and_out_of_table_prefixes() -> anyhow::Result<()> {
        let mut versions = numbered("a:", 600);
        for key in ["ab", "abc", "abd", "ac"] {
            versions.push(version(key, 10, true));
        }
        versions.extend(numbered("z:", 600));
        let reader = build_table(versions)?;

        let entry = |key: &str| (key.as_bytes().to_vec(), true);
        assert_eq!(scan(&reader, b"ab")?, [entry("abc"), entry("abd"), entry("ab")]);
        assert_eq!(scan(&reader, b"ac")?, [entry("ac")]);
        let mut below_first_key = live_keys("a:", 600);
        below_first_key.extend(["abc", "abd", "ab", "ac"].map(entry));
        assert_eq!(scan(&reader, b"a")?, below_first_key);
        assert!(scan(&reader, b"0")?.is_empty());
        assert!(scan(&reader, b"zz")?.is_empty());
        Ok(())
    }

    // The block holding `ab` starts at that key although `abc` and `abd`,
    // which sort before it, end the block before: the scan must start there.
    #[test]
    fn test_prefix_scan_starts_before_a_block_that_opens_with_the_prefix_key() -> anyhow::Result<()> {
        let mut versions = numbered("aa", ENTRIES_PER_BLOCK - 2);
        for key in ["abc", "abd", "ab", "ac"] {
            versions.push(version(key, 10, true));
        }
        versions.extend(numbered("z:", ENTRIES_PER_BLOCK));
        let reader = build_table(versions)?;
        assert_eq!(reader.index.entries[1].0.as_slice(), encode(b"ab", 10), "layout precondition");

        let entry = |key: &str| (key.as_bytes().to_vec(), true);
        assert_eq!(scan(&reader, b"ab")?, [entry("abc"), entry("abd"), entry("ab")]);
        Ok(())
    }

    // A shorter user key plus its stamp bytes can start with the prefix: it
    // must neither be returned nor end the range before a real match.
    #[test]
    fn test_prefix_scan_skips_shorter_key_whose_stamp_starts_with_prefix() -> anyhow::Result<()> {
        let mut prefix = b"k".to_vec();
        prefix.push(Timestamp::new(10).to_be_bytes()[0]);
        // All-0xFF tail: sorts behind the encoded "k" plus stamp.
        let mut matching = prefix.clone();
        matching.resize(1 + 8, 0xFF);
        let reader = build_table(vec![
            version("j", 10, true),
            version("k", 10, true),
            (matching.clone(), 10, true),
        ])?;

        assert_eq!(scan(&reader, &prefix)?, [(matching, true)]);
        Ok(())
    }

    // Test 3: versions newer than the snapshot ceiling stay invisible, an older
    // visible version is delivered.
    #[test]
    fn test_prefix_scan_at_snapshot_skips_newer_versions() -> anyhow::Result<()> {
        let mut versions = numbered("a:", 600);
        for i in 0..300 {
            let key = format!("m:{i:04}");
            match i % 3 {
                // Newer tombstone over an older live version.
                0 => versions.extend([version(&key, 30, false), version(&key, 10, true)]),
                1 => versions.push(version(&key, 10, true)),
                // Written only after the snapshot.
                _ => versions.push(version(&key, 30, true)),
            }
        }
        versions.extend(numbered("z:", 600));
        let reader = build_table(versions)?;

        let ceiling = Timestamp::new(20).inverted();
        let visible: anyhow::Result<Vec<_>> = reader.keys_with_prefix_at(b"m:", ceiling).collect();
        let expected: Vec<_> = live_keys("m:", 300)
            .into_iter()
            .enumerate()
            .filter(|(i, _)| i % 3 != 2)
            .map(|(_, entry)| entry)
            .collect();
        assert_eq!(visible?, expected);
        Ok(())
    }

    // Test 4: an empty prefix reads the whole table.
    #[test]
    fn test_prefix_scan_with_empty_prefix_returns_every_entry() -> anyhow::Result<()> {
        let reader = table_around_range()?;
        let mut expected = live_keys("a:", 600);
        expected.extend(live_keys("m:", 300));
        expected.extend(live_keys("z:", 600));
        assert_eq!(scan(&reader, b"")?, expected);
        Ok(())
    }

    // Test 5: the scan reads the blocks of its range, not the table.
    #[test]
    fn test_prefix_scan_in_last_block_reads_at_most_two_blocks() -> anyhow::Result<()> {
        let mut versions = numbered("a:", 1000);
        versions.extend(numbered("t:", 20));
        let reader = build_table(versions)?;
        assert_eq!(reader.index.entries.len(), 4, "layout precondition");

        assert_eq!(scan(&reader, b"t:")?, live_keys("t:", 20));
        assert!(reader.blocks_read.load(Ordering::Relaxed) <= 2);
        Ok(())
    }

    #[test]
    fn test_prefix_scan_between_two_blocks_reads_at_most_one_block() -> anyhow::Result<()> {
        let mut versions = numbered("a:", ENTRIES_PER_BLOCK);
        versions.extend(numbered("c:", ENTRIES_PER_BLOCK));
        versions.extend(numbered("e:", ENTRIES_PER_BLOCK));
        let reader = build_table(versions)?;
        assert_eq!(reader.index.entries.len(), 3, "layout precondition");

        assert!(scan(&reader, b"b:")?.is_empty());
        assert!(reader.blocks_read.load(Ordering::Relaxed) <= 1);
        Ok(())
    }

    // A block that cannot be read is reported, not skipped.
    #[test]
    fn test_prefix_scan_reports_a_corrupt_block() -> anyhow::Result<()> {
        let reader = SSTableReader::open(build_sstable_with_corrupt_block_handle()?)?;
        let first = reader.keys_with_prefix(b"key1").next();
        assert!(first.is_some_and(|entry| entry.is_err()));
        Ok(())
    }
}
