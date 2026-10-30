use crate::core::coop;
use crate::engines::lsm::block_cache::{BlockCacheKey, CachedBlock, StripedBlockCache};
use crate::engines::lsm::key::{InternalKey, Timestamp};
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
const BLOOM_FALSE_POSITIVE_RATE: f64 = 0.01;

/// True until `key` lies behind the run of keys that start with `prefix`.
#[inline]
fn not_behind_prefix_run(key: &[u8], prefix: &[u8]) -> bool {
    key < prefix || key.starts_with(prefix)
}

/// Inside [`coop::inline_read`], gives the read up if a page of `bytes`, a
/// slice of a mapped table, is not in memory. Anywhere else asks nothing.
fn give_up_unless_resident(bytes: &[u8], what: &str) -> Result<()> {
    if coop::in_inline_scope() && !coop::resident(bytes) {
        coop::would_block();
        bail!("{what} not in memory: reading it may wait for the disk");
    }
    Ok(())
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

/// What a finished SSTable holds, known without reading it back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SSTableSummary {
    pub file_size: u64,
    /// Smallest and largest encoded key, empty without entries.
    pub smallest_key: Vec<u8>,
    pub largest_key: Vec<u8>,
    /// Highest raw MVCC timestamp of the keys.
    pub max_timestamp: u64,
    pub total_keys: usize,
}

/// Builds an SSTable of keys added in sorted order. [`Self::take_encoded`]
/// encodes the full data blocks and hands their bytes over, so that the
/// builder keeps only the open block, the index and the Bloom filter.
pub struct SSTableBuilder {
    current_block: DataBlock,
    /// Full blocks the next `take_encoded` or `finish` encodes.
    full_blocks: Vec<DataBlock>,
    index: IndexBlock,
    /// Encoded bytes not handed over yet; they end at file offset `offset`.
    encoded: Vec<u8>,
    offset: u64,
    filter: BloomFilterImpl,
    total_keys: usize,
    largest_key: Vec<u8>,
    max_timestamp: u64,
}

impl SSTableBuilder {
    /// A builder whose Bloom filter is sized for `filter_capacity` keys; more
    /// keys raise its false positive rate.
    pub fn new(filter_capacity: usize) -> Self {
        Self {
            current_block: DataBlock { entries: Vec::new() },
            full_blocks: Vec::new(),
            index: IndexBlock { entries: Vec::new() },
            encoded: Vec::new(),
            offset: 0,
            filter: BloomFilterImpl::new(filter_capacity, BLOOM_FALSE_POSITIVE_RATE),
            total_keys: 0,
            largest_key: Vec::new(),
            max_timestamp: 0,
        }
    }

    /// Adds a key-value pointer pair (large value in VLog) to the SSTable.
    /// Keys must be added in sorted order.
    pub fn add(&mut self, key: Vec<u8>, value_pointer: ValuePointer) {
        self.push(key, DataBlockValue::Pointer(value_pointer));
    }

    /// Adds a key with inline value data (small value, no VLog) to the SSTable.
    /// Keys must be added in sorted order.
    pub fn add_inline(&mut self, key: Vec<u8>, data: Vec<u8>, expire_at: u64) {
        self.push(key, DataBlockValue::Inline { data, expire_at });
    }

    fn push(&mut self, key: Vec<u8>, value: DataBlockValue) {
        // Keyed on the user key so that reads at any snapshot timestamp hit.
        self.filter.insert(mvcc_user_key(&key));
        self.total_keys += 1;
        // Raw value, not `Timestamp::cmp` — that one sorts newest first.
        if let Some(ts) = InternalKey::extract_timestamp(&key) {
            self.max_timestamp = self.max_timestamp.max(ts.as_u64());
        }
        self.current_block.entries.push((key, value));
        if self.current_block.entries.len() * 16 > BLOCK_SIZE_TARGET {
            self.finish_block();
        }
    }

    fn finish_block(&mut self) {
        if self.current_block.entries.is_empty() {
            return;
        }
        let block = std::mem::replace(&mut self.current_block, DataBlock { entries: Vec::new() });
        self.full_blocks.push(block);
    }

    /// Encodes the full blocks and hands over the bytes not handed over yet;
    /// they continue the file where the last call's bytes ended.
    pub fn take_encoded(&mut self) -> Result<Vec<u8>> {
        self.encode_full_blocks()?;
        Ok(std::mem::take(&mut self.encoded))
    }

    fn encode_full_blocks(&mut self) -> Result<()> {
        for block in std::mem::take(&mut self.full_blocks) {
            let bytes = rkyv::to_bytes::<rancor::Error>(&block)?;
            let handle = BlockHandle { offset: self.offset, size: bytes.len() as u64 };
            if let (Some((first_key, _)), Some((last_key, _))) = (block.entries.first(), block.entries.last()) {
                self.index.entries.push((first_key.clone(), handle));
                self.largest_key.clone_from(last_key);
            }
            self.append(&bytes);
            self.pad_to_align8();
        }
        Ok(())
    }

    fn append(&mut self, bytes: &[u8]) {
        self.encoded.extend_from_slice(bytes);
        self.offset += bytes.len() as u64;
    }

    fn pad_to_align8(&mut self) {
        let misalign = (self.offset % 8) as usize;
        if misalign != 0 {
            self.append(&[0u8; 8][..8 - misalign]);
        }
    }

    /// Serializes the SSTable: every byte [`Self::take_encoded`] has not
    /// handed over, the whole table if it was never called.
    pub fn finish(self) -> Result<Vec<u8>> {
        Ok(self.finish_with_summary()?.0)
    }

    /// [`Self::finish`] plus the summary of the whole table.
    pub fn finish_with_summary(mut self) -> Result<(Vec<u8>, SSTableSummary)> {
        self.finish_block();
        self.encode_full_blocks()?;

        let index_bytes = rkyv::to_bytes::<rancor::Error>(&self.index)?;
        let index_handle = BlockHandle { offset: self.offset, size: index_bytes.len() as u64 };
        self.append(&index_bytes);
        self.pad_to_align8();

        let bloom_filter = BloomFilter {
            data: self.filter.as_bytes().to_vec(),
            num_hashes: self.filter.num_hashes(),
        };
        let bloom_bytes = rkyv::to_bytes::<rancor::Error>(&bloom_filter)?;
        let bloom_filter_handle = BlockHandle { offset: self.offset, size: bloom_bytes.len() as u64 };
        self.append(&bloom_bytes);
        self.pad_to_align8();

        let footer = SSTableFooter {
            index_handle,
            bloom_filter_handle,
            checksum: 0,
        };
        let footer_bytes = rkyv::to_bytes::<rancor::Error>(&footer)?;
        let footer_offset = self.offset;
        self.append(&footer_bytes);
        self.append(&footer_offset.to_le_bytes());

        let summary = SSTableSummary {
            file_size: self.offset,
            smallest_key: self.index.entries.first().map(|(key, _)| key.clone()).unwrap_or_default(),
            largest_key: self.largest_key,
            max_timestamp: self.max_timestamp,
            total_keys: self.total_keys,
        };
        Ok((self.encoded, summary))
    }

    /// Entries the builder holds unencoded.
    #[cfg(test)]
    pub(crate) fn held_entries(&self) -> usize {
        self.full_blocks.iter().chain([&self.current_block]).map(|block| block.entries.len()).sum()
    }
}

/// Backing storage of an SSTable: fully loaded bytes (fallback, freshly
/// built tables) or a memory-mapped file.
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
    footer: &'static Archived<SSTableFooter>,
    index: &'static Archived<IndexBlock>,
    bloom_filter: BloomFilterImpl,
    /// SSTable file identifier used as part of the block cache key.
    /// Set to 0 by default; call `set_file_id` after opening to assign the
    /// correct ID from the manifest.
    pub file_id: u64,
    retired: AtomicBool,
    #[cfg(test)]
    pub(crate) blocks_read: std::sync::atomic::AtomicUsize,
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
    /// pages. The `unsafe` map is sound: SSTables are
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

        // An empty bit array paired with num_hashes >= 1 would divide by zero
        // on every lookup (BloomFilter::hash). A legitimate writer never
        // produces this combination (see SSTableBuilder::finish), so it only
        // occurs on corrupted/torn/crafted bytes -- reject it here.
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

    /// The most keys the table's Bloom filter was sized for.
    pub fn bloom_capacity(&self) -> usize {
        self.bloom_filter.capacity(BLOOM_FALSE_POSITIVE_RATE)
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
    /// where a miss on a mapped table, or index or block pages of it that are
    /// not in memory, end the lookup with an error.
    pub fn get_with_cache(
        &self,
        key: &[u8],
        cache: &StripedBlockCache,
    ) -> Result<Option<CachedValue>> {
        Ok(self.get_with_cache_and_ts(key, cache)?.map(|(v, _)| v))
    }

    /// Like [`Self::get_with_cache`], but also returns the matched entry's
    /// write timestamp, un-inverted back to HLC form (the encoded key stores
    /// it inverted for newest-first sort order).
    pub fn get_with_cache_and_ts(
        &self,
        key: &[u8],
        cache: &StripedBlockCache,
    ) -> Result<Option<(CachedValue, Timestamp)>> {
        let bloom_key = mvcc_user_key(key);
        if !self.bloom_filter.contains(bloom_key) {
            return Ok(None);
        }
        if let SSTableData::Mapped(mmap) = &self.data {
            // The whole index section, not just the rkyv root at its end.
            let offset = u64::from(self.footer.index_handle.offset) as usize;
            let size = u64::from(self.footer.index_handle.size) as usize;
            give_up_unless_resident(&mmap[offset..offset + size], "index")?;
        }

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

        if key.len() >= 8 {
            return self.newest_visible_version(
                key,
                |handle| {
                    let cache_key = BlockCacheKey { file_id: self.file_id, block_offset: u64::from(handle.offset) };
                    self.get_or_cache_block(handle, &cache_key, cache)
                },
                |raw| {
                    rkyv::access::<Archived<DataBlock>, rancor::Error>(raw.as_bytes())
                        .map_err(|e| anyhow::anyhow!("DataBlock validation failed: {}", e))
                },
                |raw, value, ts| (cached_value_from_archived(raw, value), ts),
            );
        }

        Ok(None)
    }

    /// The newest version of `key`'s user key `u` visible at `key`'s
    /// timestamp. Every visible version of `u` is encoded at or after `key`
    /// and at most `u‖FF…FF`; longer keys between them are skipped. `load`
    /// fetches a block, `view` opens it, `hit` maps the matching entry.
    fn newest_visible_version<B, R>(
        &self,
        key: &[u8],
        mut load: impl FnMut(&Archived<BlockHandle>) -> Result<B>,
        view: impl Fn(&B) -> Result<&Archived<DataBlock>>,
        hit: impl FnOnce(&B, &ArchivedDataBlockValue, Timestamp) -> R,
    ) -> Result<Option<R>> {
        let user_key = mvcc_user_key(key);
        let search_inv_ts = mvcc_inv_ts(key);
        let hi = [user_key, [0xFF; 8].as_slice()].concat();

        let start = self.find_block(key)?.unwrap_or(0);
        for (first_key, handle) in self.index.entries[start..].iter().map(|entry| (&entry.0, &entry.1)) {
            if first_key.as_slice() > hi.as_slice() {
                break;
            }
            let block = load(handle)?;
            for entry in view(&block)?.entries.iter() {
                let entry_key = entry.0.as_slice();
                if entry_key > hi.as_slice() {
                    return Ok(None);
                }
                if mvcc_user_key(entry_key) != user_key {
                    continue;
                }
                // Inverted: at least the search stamp means written at or before the snapshot.
                let inv_ts = mvcc_inv_ts(entry_key);
                if inv_ts >= search_inv_ts {
                    return Ok(Some(hit(&block, &entry.1, Timestamp::from_inverted(inv_ts))));
                }
            }
        }

        Ok(None)
    }

    /// Returns the raw bytes of a data block, using the cache when available.
    ///
    /// On a cache miss the block is taken from the table's data and, unless
    /// the table is retired, inserted into the cache before being returned.
    /// Inside [`coop::inline_read`] a miss on a mapped table fails instead,
    /// and so does a hit on a mapped block whose pages are not in memory.
    /// Only the block's own stripe is locked.
    fn get_or_cache_block(
        &self,
        handle: &Archived<BlockHandle>,
        cache_key: &BlockCacheKey,
        cache: &StripedBlockCache,
    ) -> Result<CachedBlock> {
        let mut stripe = cache.stripe(cache_key);
        if let Some(cached) = stripe.get(cache_key) {
            drop(stripe);
            if matches!(cached, CachedBlock::Mapped { .. }) {
                give_up_unless_resident(cached.as_bytes(), "data block")?;
            }
            return Ok(cached);
        }
        #[cfg(test)]
        self.blocks_read.fetch_add(1, Ordering::Relaxed);

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
    /// write timestamp.  For MVCC keys (len >= 8), the method falls back to
    /// the newest version visible at the snapshot if the exact match misses.
    pub fn get(&self, key: &[u8]) -> Result<Option<DataBlockValue>> {
        // Bloom filter is keyed on user_key (timestamp stripped) so check accordingly.
        let bloom_key = mvcc_user_key(key);
        if !self.bloom_filter.contains(bloom_key) {
            return Ok(None);
        }

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

        // Keys >= 8 bytes are treated as MVCC-encoded: [user_key][inv_ts_be_8_bytes].
        // A snapshot taken AFTER the write has a smaller inv_ts than the stored key,
        // so the exact block search misses.
        if key.len() >= 8 {
            return self.newest_visible_version(
                key,
                |handle| self.read_data_block(handle),
                |block| Ok(*block),
                |_, value, _| archived_to_owned_dbv(value),
            );
        }

        Ok(None)
    }

    /// Binary search: returns the index of the last block whose first full key
    /// is ≤ `key`.
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
    /// under an MVCC snapshot ceiling (backup export):
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
    /// [`Self::keys_with_prefix_at`]: [`Self::prefix_versions`] with each
    /// version's liveness at the current time in place of its value — the
    /// callers above collapse it to `(user_key, bool)`, the TTL sweeper's
    /// expiry scan uses it directly.
    pub(crate) fn prefix_entries<'a>(
        &'a self,
        prefix: &'a [u8],
        max_inv_ts: Option<u64>,
    ) -> impl Iterator<Item = Result<(Vec<u8>, Timestamp, VersionState)>> + 'a {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.prefix_versions(prefix, max_inv_ts)
            .map(move |version| version.map(|(user_key, ts, value)| (user_key, ts, value.version_state(now))))
    }

    /// Every version whose user key starts with `prefix`, in key order
    /// (newest first per user key), with its write timestamp and stored
    /// value. `max_inv_ts` of `None` matches every version; `Some` is a
    /// snapshot timestamp in inverted form and skips the versions newer than
    /// that snapshot.
    pub(crate) fn prefix_versions<'a>(
        &'a self,
        prefix: &'a [u8],
        max_inv_ts: Option<u64>,
    ) -> impl Iterator<Item = Result<(Vec<u8>, Timestamp, DataBlockValue)>> + 'a {
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
            Some(Ok((user_key.to_vec(), Timestamp::from_inverted(inv_ts), dbv)))
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
/// copying value bytes. Inline values become zero-copy
/// offsets into the block's `Arc<AlignedVec>` allocation — sound because the
/// `Arc` pins the allocation and the archived bytes live inside it. The
/// tombstone (file_id == 0, offset == TOMBSTONE_OFFSET) and NULL (file_id ==
/// 0, offset == NULL_OFFSET) sentinels are resolved here.
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

    // Zero-copy lookups: inline values reference the cached
    // block; pointers and the tombstone sentinel map to their variants.
    #[test]
    fn test_get_with_cache_returns_cached_value_variants() -> anyhow::Result<()> {
        let mut builder = SSTableBuilder::new(4);
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

        // The NULL sentinel is distinct from the tombstone sentinel.
        match reader.get_with_cache(b"null-key", &cache)? {
            Some(CachedValue::Null) => {}
            other => panic!("expected Null, got {other:?}"),
        }

        assert!(reader.get_with_cache(b"missing-key", &cache)?.is_none());
        Ok(())
    }

    // Regression: get_with_cache_and_ts must return the un-inverted
    // write timestamp. The encoded key stores it inverted (newest-first sort
    // order); a naive read of the raw bytes would report a NEWER write as a
    // SMALLER timestamp, decreasing `last_modified_at` on every overwrite.
    #[test]
    fn test_get_with_cache_and_ts_uninverts_timestamp() -> anyhow::Result<()> {
        use crate::engines::lsm::key::InternalKey;

        let mut builder = SSTableBuilder::new(2);
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

    // mmap-backed reads: same lookup semantics, zero-copy
    // blocks referencing the mapping.
    #[test]
    fn test_open_mmap_roundtrip() -> anyhow::Result<()> {
        let mut builder = SSTableBuilder::new(2);
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
        let mut builder = SSTableBuilder::new(1);
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

    /// A mapped table holding `mkey`, its block cached, and that block's bytes.
    fn mapped_table_with_a_cached_block(
        dir: &tempfile::TempDir,
    ) -> anyhow::Result<(SSTableReader, StripedBlockCache, CachedBlock)> {
        let mut builder = SSTableBuilder::new(1);
        builder.add_inline(b"mkey".to_vec(), b"mval".to_vec(), 0);
        let path = dir.path().join("table.sst");
        std::fs::write(&path, builder.finish()?)?;
        let mapped = SSTableReader::open_mmap(&path)?;
        let cache = StripedBlockCache::new(1024 * 1024, 0.1, 100);
        let Some(CachedValue::Cached { block, .. }) = mapped.get_with_cache(b"mkey", &cache)? else {
            bail!("expected a cached value");
        };
        Ok((mapped, cache, block))
    }

    // The kernel may have evicted the pages of a cached block of a mapped
    // table: an inline read gives up on it as on an uncached block.
    #[tokio::test]
    async fn test_inline_read_gives_up_on_a_cached_mapped_block_whose_pages_are_evicted() -> anyhow::Result<()> {
        let dir = tempfile::TempDir::new()?;
        let (mapped, cache, block) = mapped_table_with_a_cached_block(&dir)?;
        let block_start = block.as_bytes().as_ptr();
        coop::set_residency(Some(Box::new(move |bytes| bytes.as_ptr() != block_start)));

        let (read, gave_up) = coop::inline_read(async { mapped.get_with_cache(b"mkey", &cache) }).await;
        coop::set_residency(None);
        assert!(read.is_err() && gave_up);
        assert!(mapped.get_with_cache(b"mkey", &cache)?.is_some());
        Ok(())
    }

    // So may the pages of the index: an inline read asks about the whole index
    // section first and gives up before it looks at the index or a block.
    #[tokio::test]
    async fn test_inline_read_gives_up_when_the_index_pages_are_evicted() -> anyhow::Result<()> {
        let dir = tempfile::TempDir::new()?;
        let (mapped, cache, block) = mapped_table_with_a_cached_block(&dir)?;
        let block_start = block.as_bytes().as_ptr();
        let asked = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let log = std::rc::Rc::clone(&asked);
        coop::set_residency(Some(Box::new(move |bytes| {
            log.borrow_mut().push(bytes.to_vec());
            bytes.as_ptr() == block_start
        })));

        let (read, gave_up) = coop::inline_read(async { mapped.get_with_cache(b"mkey", &cache) }).await;
        coop::set_residency(None);
        assert!(read.is_err() && gave_up);
        let asked = asked.borrow();
        assert_eq!(asked.len(), 1);
        let mut index_section = AlignedVec::<16>::new();
        index_section.extend_from_slice(&asked[0]);
        let index = rkyv::access::<Archived<IndexBlock>, rancor::Error>(&index_section)?;
        assert_eq!(index.entries[0].0.as_slice(), b"mkey");
        Ok(())
    }

    // Resident pages keep a hit inline. Only an inline read of a mapped table
    // asks; an owned table and a read outside an inline read never do.
    #[tokio::test]
    async fn test_only_an_inline_read_of_a_mapped_table_asks_whether_pages_are_resident() -> anyhow::Result<()> {
        let dir = tempfile::TempDir::new()?;
        let (mapped, cache, _) = mapped_table_with_a_cached_block(&dir)?;
        let mut builder = SSTableBuilder::new(1);
        builder.add_inline(b"mkey".to_vec(), b"mval".to_vec(), 0);
        let owned = SSTableReader::open(builder.finish()?)?;
        let owned_cache = StripedBlockCache::new(1024 * 1024, 0.1, 100);
        assert!(owned.get_with_cache(b"mkey", &owned_cache)?.is_some());
        let asked = std::rc::Rc::new(std::cell::Cell::new(0));
        let count = std::rc::Rc::clone(&asked);
        coop::set_residency(Some(Box::new(move |_| {
            count.set(count.get() + 1);
            true
        })));

        let (read, gave_up) = coop::inline_read(async { mapped.get_with_cache(b"mkey", &cache) }).await;
        assert!(read?.is_some() && !gave_up);
        assert_eq!(asked.get(), 2, "the index and the block");
        assert!(mapped.get_with_cache(b"mkey", &cache)?.is_some());
        let (read, gave_up) = coop::inline_read(async { owned.get_with_cache(b"mkey", &owned_cache) }).await;
        assert!(read?.is_some() && !gave_up);
        coop::set_residency(None);
        assert_eq!(asked.get(), 2);
        Ok(())
    }

    #[test]
    fn test_build_and_read_sstable() -> anyhow::Result<()> {
        let mut builder = SSTableBuilder::new(200);
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
        let mut builder = SSTableBuilder::new(100);
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
        let mut builder = SSTableBuilder::new(1);
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

    // A corrupted footer whose index_handle overflows `offset + size`
    // must be rejected with an `Err`, not panic (untrusted on-disk bytes).
    #[test]
    fn test_from_data_rejects_overflowing_index_handle() -> anyhow::Result<()> {
        let mut builder = SSTableBuilder::new(1);
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

    // Analog for bloom_filter_handle.
    #[test]
    fn test_from_data_rejects_overflowing_bloom_filter_handle() -> anyhow::Result<()> {
        let mut builder = SSTableBuilder::new(1);
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

    // Builds a valid single-block SSTable whose IndexBlock entry
    // points at an overflowing BlockHandle, to exercise the read path
    // (as opposed to the footer handles covered above).
    fn build_sstable_with_corrupt_block_handle() -> anyhow::Result<Vec<u8>> {
        let mut builder = SSTableBuilder::new(1);
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

    // get_with_cache → get_or_cache_block must return an `Err` for an
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

    // get → read_data_block must return an `Err` for an overflowing
    // block handle instead of panicking.
    #[test]
    fn test_read_data_block_rejects_overflowing_block_handle() -> anyhow::Result<()> {
        let buf = build_sstable_with_corrupt_block_handle()?;
        let reader = SSTableReader::open(buf)?;
        let result = reader.get(b"key1");
        assert!(result.is_err(), "overflowing block handle must be rejected, not panic");
        Ok(())
    }

    // Builds a valid SSTable whose bloom filter block is structurally
    // valid (rkyv::access succeeds) but carries an empty bit array combined
    // with `num_hashes`, to exercise the from_data fail-fast check on a
    // corrupted/crafted bloom block (as opposed to bloom.rs's own unit test
    // for the from_bytes/hash defense-in-depth layer).
    fn build_sstable_with_empty_bloom_block(num_hashes: u32) -> anyhow::Result<Vec<u8>> {
        let mut builder = SSTableBuilder::new(1);
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

    // An empty bloom bit array combined with num_hashes >= 1 can only come
    // from corrupted/torn/crafted bytes (a real writer never produces it, see
    // SSTableBuilder::finish) -- from_data must reject it, not panic.
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

    // num_hashes == 0 is what BloomFilter::new(0, p) legitimately
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
        let mut builder = SSTableBuilder::new(stored.len());
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

    fn spaced_key(n: usize) -> Vec<u8> {
        format!("k:{n:07}").into_bytes()
    }

    /// `count` keys `spaced_key(first)`, `spaced_key(first + step)`, ... written at `ts`.
    fn spaced_table(first: usize, step: usize, count: usize, ts: u64) -> anyhow::Result<SSTableReader> {
        let mut builder = SSTableBuilder::new(count);
        for i in 0..count {
            builder.add_inline(encode(&spaced_key(first + i * step), ts), b"v".to_vec(), 0);
        }
        SSTableReader::open(builder.finish()?)
    }

    #[test]
    fn test_filter_of_a_large_table_rejects_absent_keys() -> anyhow::Result<()> {
        let reader = spaced_table(0, 2, 200_000, 10)?;
        let rejected = (0..10_000)
            .filter(|i| !reader.bloom_filter.contains(&spaced_key(2 * i + 1)))
            .count();
        assert!(rejected >= 9_700, "only {rejected} of 10 000 absent keys rejected");
        Ok(())
    }

    // An absent key the filter lets through: the read ends at the first key
    // behind it instead of running to the end of the table.
    #[test]
    fn test_point_read_of_an_absent_key_reads_at_most_two_blocks() -> anyhow::Result<()> {
        let reader = spaced_table(0, 2, 50_000, 10)?;
        let absent = (0..50_000)
            .map(|i| spaced_key(2 * i + 1))
            .find(|key| reader.bloom_filter.contains(key))
            .expect("some absent key passes the filter");
        let cache = StripedBlockCache::new(64 * 1024 * 1024, 0.1, 100);

        assert!(reader.get_with_cache_and_ts(&encode(&absent, 30), &cache)?.is_none());
        let blocks_read = reader.blocks_read.load(Ordering::Relaxed);
        assert!(blocks_read <= 2, "read {blocks_read} blocks");
        Ok(())
    }

    // The newer `ab` sorts before the older `a` and opens the block holding
    // it: neither the entry nor the block may end the read of `a`.
    #[test]
    fn test_point_read_passes_a_longer_key_that_sorts_first() -> anyhow::Result<()> {
        let mut versions = numbered("0", ENTRIES_PER_BLOCK);
        versions.extend([version("ab", 20, true), version("a", 10, true)]);
        let reader = build_table(versions)?;
        assert_eq!(reader.index.entries[1].0.as_slice(), encode(b"ab", 20), "layout precondition");
        assert!(encode(b"ab", 20) < encode(b"a", 10), "layout precondition");
        let cache = StripedBlockCache::new(1024 * 1024, 0.1, 100);

        let (_, ts) = reader.get_with_cache_and_ts(&encode(b"a", 15), &cache)?.expect("a@10 is visible at 15");
        assert_eq!(ts, Timestamp::new(10));
        Ok(())
    }

    // The only version visible at the snapshot lies in the block after the
    // newer ones.
    #[test]
    fn test_point_read_follows_versions_into_the_next_block() -> anyhow::Result<()> {
        let mut versions = numbered("a:", 10);
        versions.extend((1..=ENTRIES_PER_BLOCK as u64).map(|i| version("m", 10 * i, true)));
        versions.extend(numbered("z:", 10));
        let reader = build_table(versions)?;
        assert_eq!(reader.index.entries.len(), 2, "layout precondition");
        assert_eq!(mvcc_user_key(reader.index.entries[1].0.as_slice()), b"m", "layout precondition");
        let cache = StripedBlockCache::new(1024 * 1024, 0.1, 100);

        let (_, ts) = reader.get_with_cache_and_ts(&encode(b"m", 15), &cache)?.expect("m@10 is visible at 15");
        assert_eq!(ts, Timestamp::new(10));
        Ok(())
    }

    /// `ab@20` ends the first block and the older `ab@10`, a tombstone, opens
    /// the second; the third opens with `a`, which sorts behind both.
    fn table_with_versions_across_a_block_boundary() -> anyhow::Result<SSTableReader> {
        let mut versions = numbered("aa", ENTRIES_PER_BLOCK - 1);
        versions.extend([version("ab", 20, true), version("ab", 10, false)]);
        versions.extend(numbered("ac", ENTRIES_PER_BLOCK - 1));
        versions.push(version("a", 10, true));
        let reader = build_table(versions)?;
        assert_eq!(reader.index.entries.len(), 3, "layout precondition");
        assert_eq!(reader.index.entries[1].0.as_slice(), encode(b"ab", 10), "layout precondition");
        assert_eq!(reader.index.entries[2].0.as_slice(), encode(b"a", 10), "layout precondition");
        Ok(reader)
    }

    #[test]
    fn test_point_read_finds_the_newest_visible_version_in_an_earlier_block() -> anyhow::Result<()> {
        let reader = table_with_versions_across_a_block_boundary()?;
        let cache = StripedBlockCache::new(1024 * 1024, 0.1, 100);

        let (_, ts) = reader.get_with_cache_and_ts(&encode(b"ab", 25), &cache)?.expect("ab@20 is visible at 25");
        assert_eq!(ts, Timestamp::new(20));
        Ok(())
    }

    #[test]
    fn test_uncached_point_read_finds_the_newest_visible_version_in_an_earlier_block() -> anyhow::Result<()> {
        let reader = table_with_versions_across_a_block_boundary()?;

        let value = reader.get(&encode(b"ab", 25))?;
        assert_eq!(value, Some(DataBlockValue::Inline { data: b"v".to_vec(), expire_at: 0 }));
        Ok(())
    }

    /// Two versions of `a` with stamps whose inverted form starts with 0xFE,
    /// and a longer key `a\xFE\x80` that sorts between them. Returns the
    /// reader and the older version's timestamp.
    fn table_with_a_longer_key_between_versions() -> anyhow::Result<(SSTableReader, u64)> {
        let newer = Timestamp::from_inverted(0xFE10_0000_0000_0000).as_u64();
        let older = Timestamp::from_inverted(0xFEF0_0000_0000_0000).as_u64();
        let longer = b"a\xFE\x80".to_vec();
        assert!(encode(b"a", newer) < encode(&longer, 10), "layout precondition");
        assert!(encode(&longer, 10) < encode(b"a", older), "layout precondition");
        let reader = build_table(vec![
            version("a", newer, true),
            version("a", older, true),
            (longer, 10, true),
        ])?;
        Ok((reader, older))
    }

    #[test]
    fn test_point_read_passes_a_longer_key_between_two_versions() -> anyhow::Result<()> {
        let (reader, older) = table_with_a_longer_key_between_versions()?;
        let cache = StripedBlockCache::new(1024 * 1024, 0.1, 100);

        let (_, ts) = reader
            .get_with_cache_and_ts(&encode(b"a", older + 1), &cache)?
            .expect("the older version is visible");
        assert_eq!(ts, Timestamp::new(older));
        Ok(())
    }

    #[test]
    fn test_uncached_point_read_passes_a_longer_key_between_two_versions() -> anyhow::Result<()> {
        let (reader, older) = table_with_a_longer_key_between_versions()?;

        assert!(reader.get(&encode(b"a", older + 1))?.is_some(), "the older version is visible");
        Ok(())
    }

    #[test]
    fn test_point_read_of_a_key_in_the_older_table_skips_the_newer_one() -> anyhow::Result<()> {
        let mut older = spaced_table(0, 2, 100_000, 10)?;
        older.set_file_id(1);
        let mut newer = spaced_table(1, 2, 100_000, 20)?;
        newer.set_file_id(2);
        let cache = StripedBlockCache::new(64 * 1024 * 1024, 0.1, 100);
        let key = encode(&spaced_key(2_000), 30);

        assert!(newer.get_with_cache_and_ts(&key, &cache)?.is_none());
        assert!(older.get_with_cache_and_ts(&key, &cache)?.is_some());
        let blocks_read = newer.blocks_read.load(Ordering::Relaxed);
        assert!(blocks_read <= 1, "read {blocks_read} blocks of the newer table");
        Ok(())
    }

    /// The builder as it was before it streamed: every block stays in memory
    /// until `finish` encodes the whole file.
    struct InMemoryBuilder {
        data_blocks: Vec<DataBlock>,
        current_block: DataBlock,
        index: IndexBlock,
        filter_capacity: usize,
    }

    impl InMemoryBuilder {
        fn new(filter_capacity: usize) -> Self {
            Self {
                data_blocks: Vec::new(),
                current_block: DataBlock { entries: Vec::new() },
                index: IndexBlock { entries: Vec::new() },
                filter_capacity,
            }
        }

        fn add(&mut self, key: Vec<u8>, value: DataBlockValue) {
            self.current_block.entries.push((key, value));
            if self.current_block.entries.len() * 16 > BLOCK_SIZE_TARGET {
                self.finish_block();
            }
        }

        fn finish_block(&mut self) {
            if self.current_block.entries.is_empty() {
                return;
            }
            let block = std::mem::replace(&mut self.current_block, DataBlock { entries: Vec::new() });
            if let Some((first_key, _)) = block.entries.first() {
                self.index.entries.push((first_key.clone(), BlockHandle { offset: 0, size: 0 }));
            }
            self.data_blocks.push(block);
        }

        fn finish(mut self) -> anyhow::Result<Vec<u8>> {
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

            let mut filter = BloomFilterImpl::new(self.filter_capacity, 0.01);
            for (key, _) in self.data_blocks.iter().flat_map(|block| &block.entries) {
                filter.insert(mvcc_user_key(key));
            }
            let bloom_filter = BloomFilter {
                data: filter.as_bytes().to_vec(),
                num_hashes: filter.num_hashes(),
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

    fn add_entry(builder: &mut SSTableBuilder, key: Vec<u8>, value: DataBlockValue) {
        match value {
            DataBlockValue::Pointer(vp) => builder.add(key, vp),
            DataBlockValue::Inline { data, expire_at } => builder.add_inline(key, data, expire_at),
        }
    }

    /// `count` sorted entries stamped 1 to 9: vLog pointers, tombstones and
    /// inline values of odd lengths, some with an expiry.
    fn mixed_entries(count: usize) -> Vec<(Vec<u8>, DataBlockValue)> {
        (0..count)
            .map(|i| {
                let key = encode(format!("key-{i:05}").as_bytes(), 1 + (i as u64 * 7) % 9);
                let value = match i % 4 {
                    0 => DataBlockValue::Pointer(ValuePointer {
                        file_id: 2, value_offset: i as u64 * 100, value_len: 90, expire_at: 0,
                    }),
                    1 => DataBlockValue::Pointer(ValuePointer {
                        file_id: 0, value_offset: TOMBSTONE_OFFSET, value_len: 0, expire_at: 0,
                    }),
                    2 => DataBlockValue::Inline { data: vec![b'v'; i % 13], expire_at: i as u64 },
                    _ => DataBlockValue::Inline { data: "clé".into(), expire_at: 0 },
                };
                (key, value)
            })
            .collect()
    }

    // Every byte as the in-memory builder wrote it with the same filter
    // capacity (the key count, as a flush sizes it, or more), whether the
    // full blocks are taken as they fill or all at the end; a block is handed
    // over as soon as it is full.
    #[test]
    fn test_streaming_builder_writes_the_bytes_of_the_in_memory_builder() -> anyhow::Result<()> {
        let fixture = |n| -> Vec<(Vec<u8>, DataBlockValue)> {
            match n {
                0 => Vec::new(),
                1 => mixed_entries(1),
                2 => mixed_entries(3 * ENTRIES_PER_BLOCK + 17),
                _ => [b"a".as_slice(), b"bb", b"ccc"]
                    .into_iter()
                    .map(|key| (key.to_vec(), DataBlockValue::Inline { data: b"v".to_vec(), expire_at: 0 }))
                    .collect(),
            }
        };

        for n in 0..4 {
            let count = fixture(n).len();
            for capacity in [count, 2 * count + 100] {
                let mut in_memory = InMemoryBuilder::new(capacity);
                for (key, value) in fixture(n) {
                    in_memory.add(key, value);
                }
                let expected = in_memory.finish()?;

                let mut whole = SSTableBuilder::new(capacity);
                for (key, value) in fixture(n) {
                    add_entry(&mut whole, key, value);
                }
                assert_eq!(whole.finish()?, expected, "{count} entries at once, capacity {capacity}");

                let mut streaming = SSTableBuilder::new(capacity);
                let mut streamed = Vec::new();
                let mut handed_over = Vec::new();
                for (added, (key, value)) in (1..).zip(fixture(n)) {
                    add_entry(&mut streaming, key, value);
                    let encoded = streaming.take_encoded()?;
                    if !encoded.is_empty() {
                        handed_over.push(added);
                    }
                    streamed.extend(encoded);
                }
                let (tail, summary) = streaming.finish_with_summary()?;
                streamed.extend(tail);
                assert_eq!(streamed, expected, "{count} entries streamed, capacity {capacity}");
                let full_blocks: Vec<usize> = (1..=count / ENTRIES_PER_BLOCK).map(|b| b * ENTRIES_PER_BLOCK).collect();
                assert_eq!(handed_over, full_blocks);
                assert_eq!(summary.file_size, expected.len() as u64);
                assert_eq!(summary.total_keys, count);
            }
        }
        Ok(())
    }

    // The summary carries the key range and newest stamp of the entries.
    #[test]
    fn test_builder_summary_describes_the_entries() -> anyhow::Result<()> {
        let count = 2 * ENTRIES_PER_BLOCK + 5;
        let mut builder = SSTableBuilder::new(count);
        for (key, value) in mixed_entries(count) {
            add_entry(&mut builder, key, value);
        }
        let (_, summary) = builder.finish_with_summary()?;
        assert_eq!(summary.smallest_key, encode(b"key-00000", 1));
        assert_eq!(summary.largest_key, mixed_entries(count).pop().unwrap().0);
        assert_eq!(summary.max_timestamp, 9);

        let (_, empty) = SSTableBuilder::new(0).finish_with_summary()?;
        assert_eq!((empty.smallest_key, empty.largest_key, empty.max_timestamp, empty.total_keys), (vec![], vec![], 0, 0));
        Ok(())
    }

    // Release build, warm cache, mean over 10 000 reads of keys spread over
    // the older table (`cargo test --release -- --ignored --nocapture
    // point_read_through_a_newer_table`). Measured on WSL2: 230 µs through
    // the newer table (one table: 3.6 µs) with a filter sized for 10 000
    // keys and a fallback that read to the table's end; 4.6 µs (one table:
    // 4.4 µs) with the filter sized by key count and the bounded fallback.
    #[test]
    #[ignore]
    fn test_point_read_through_a_newer_table_timing() -> anyhow::Result<()> {
        let mut older = spaced_table(0, 2, 100_000, 10)?;
        older.set_file_id(1);
        let mut newer = spaced_table(1, 2, 100_000, 20)?;
        newer.set_file_id(2);
        let cache = StripedBlockCache::new(256 * 1024 * 1024, 0.1, 100);
        let keys: Vec<Vec<u8>> = (0..1000).map(|i| encode(&spaced_key(i * 200), 30)).collect();

        let two_tables = |key: &[u8]| -> anyhow::Result<()> {
            assert!(newer.get_with_cache_and_ts(key, &cache)?.is_none());
            assert!(older.get_with_cache_and_ts(key, &cache)?.is_some());
            Ok(())
        };
        let one_table = |key: &[u8]| -> anyhow::Result<()> {
            assert!(older.get_with_cache_and_ts(key, &cache)?.is_some());
            Ok(())
        };
        for key in &keys {
            two_tables(key)?;
        }
        let mean = |read: &dyn Fn(&[u8]) -> anyhow::Result<()>| -> anyhow::Result<std::time::Duration> {
            let start = std::time::Instant::now();
            for _ in 0..10 {
                for key in &keys {
                    read(key)?;
                }
            }
            Ok(start.elapsed() / 10_000)
        };
        println!("two tables: {:?}, one table: {:?}", mean(&two_tables)?, mean(&one_table)?);
        Ok(())
    }
}
