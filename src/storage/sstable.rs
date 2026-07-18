use crate::engines::lsm::block_cache::{BlockCache, BlockCacheKey, CachedBlock};
use crate::storage::format::{
    ArchivedDataBlockValue, BlockHandle, BloomFilter, CachedValue, DataBlock, DataBlockValue,
    IndexBlock, NULL_OFFSET, SSTableFooter, TOMBSTONE_OFFSET, ValuePointer,
};
use crate::storage::bloom::BloomFilter as BloomFilterImpl;
use rkyv::ser::{serializers::AllocSerializer, Serializer};
use rkyv::util::AlignedVec;
use rkyv::{check_archived_root, Archived};
use anyhow::{Result, bail};

const BLOCK_SIZE_TARGET: usize = 4096; // 4KB target for data blocks

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
            let mut serializer = AllocSerializer::<0>::default();
            serializer.serialize_value(data_block)?;
            let block_bytes = serializer.into_serializer().into_inner();

            let block_offset = buf.len() as u64;
            let block_len = block_bytes.len() as u64;
            self.index.entries[i].1.offset = block_offset;
            self.index.entries[i].1.size = block_len;

            buf.extend_from_slice(&block_bytes);
            pad_to_align8(&mut buf);
        }

        let mut serializer = AllocSerializer::<0>::default();
        serializer.serialize_value(&self.index)?;
        let index_bytes = serializer.into_serializer().into_inner();
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
        let mut serializer = AllocSerializer::<0>::default();
        serializer.serialize_value(&bloom_filter)?;
        let bloom_bytes = serializer.into_serializer().into_inner();
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
        let mut serializer = AllocSerializer::<0>::default();
        serializer.serialize_value(&footer)?;
        let footer_bytes = serializer.into_serializer().into_inner();
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
    /// immutable and only unlinked after the LevelManager drops them.
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
        let footer = check_archived_root::<SSTableFooter>(footer_slice)
            .map_err(|e| anyhow::anyhow!("Footer validation failed: {}", e))?;

        let footer: &'static Archived<SSTableFooter> = unsafe {
            std::mem::transmute(footer)
        };

        let index_offset = u64::from(footer.index_handle.offset) as usize;
        let index_size = u64::from(footer.index_handle.size) as usize;

        if index_offset + index_size > bytes.len() {
            bail!("Invalid index block offset/size");
        }

        let index_slice = &bytes[index_offset..index_offset + index_size];
        let index = check_archived_root::<IndexBlock>(index_slice)
            .map_err(|e| anyhow::anyhow!("Index validation failed: {}", e))?;

        let index: &'static Archived<IndexBlock> = unsafe {
            std::mem::transmute(index)
        };

        let bloom_offset = u64::from(footer.bloom_filter_handle.offset) as usize;
        let bloom_size = u64::from(footer.bloom_filter_handle.size) as usize;

        if bloom_offset + bloom_size > bytes.len() {
            bail!("Invalid bloom filter offset/size");
        }

        let bloom_slice = &bytes[bloom_offset..bloom_offset + bloom_size];
        let bloom_archived = check_archived_root::<BloomFilter>(bloom_slice)
            .map_err(|e| anyhow::anyhow!("Bloom filter validation failed: {}", e))?;

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
        })
    }

    /// Sets the file ID used as part of the block cache key.
    pub fn set_file_id(&mut self, file_id: u64) {
        self.file_id = file_id;
    }

    /// Point lookup that checks and populates the block cache.
    ///
    /// Semantics are identical to [`get`] but every data block read is
    /// first looked up in `cache`; on a miss the raw block bytes are stored
    /// in the cache for future reads.
    pub fn get_with_cache(
        &self,
        key: &[u8],
        cache: &mut BlockCache,
    ) -> Result<Option<CachedValue>> {
        let bloom_key = mvcc_user_key(key);
        if !self.bloom_filter.contains(bloom_key) {
            return Ok(None);
        }

        // ── 1. Exact-match path ───────────────────────────────────────────────
        let block_idx = self.find_block(key)?;
        if let Some(idx) = block_idx {
            let (_, block_handle) = &self.index.entries[idx];
            let block_offset = u64::from(block_handle.offset);
            let cache_key = BlockCacheKey { file_id: self.file_id, block_offset };

            let raw = self.get_or_cache_block(block_handle, &cache_key, cache)?;
            let data_block = check_archived_root::<DataBlock>(raw.as_bytes())
                .map_err(|e| anyhow::anyhow!("DataBlock validation failed: {}", e))?;

            for entry in data_block.entries.iter() {
                if entry.0.as_slice() == key {
                    return Ok(Some(cached_value_from_archived(&raw, &entry.1)));
                }
            }
        }

        // ── 2. MVCC fallback ──────────────────────────────────────────────────
        if key.len() >= 8 {
            return self.get_mvcc_prefix_cached(key, cache);
        }

        Ok(None)
    }

    /// MVCC prefix scan with block cache integration.
    fn get_mvcc_prefix_cached(
        &self,
        key: &[u8],
        cache: &mut BlockCache,
    ) -> Result<Option<CachedValue>> {
        let search_user_key = mvcc_user_key(key);
        let search_inv_ts = mvcc_inv_ts(key);

        let start_idx = self.find_block_by_user_key(search_user_key)?.map_or(0, |i| i.saturating_sub(1));

        for bi in start_idx..self.index.entries.len() {
            let (_, block_handle) = &self.index.entries[bi];
            let block_offset = u64::from(block_handle.offset);
            let cache_key = BlockCacheKey { file_id: self.file_id, block_offset };

            let raw = self.get_or_cache_block(block_handle, &cache_key, cache)?;
            let data_block = check_archived_root::<DataBlock>(raw.as_bytes())
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
                    return Ok(Some(cached_value_from_archived(&raw, &entry.1)));
                }
            }

            // User key seen in this block but no visible version yet —
            // might continue into the next block.
        }

        Ok(None)
    }

    /// Returns the raw bytes of a data block, using the cache when available.
    ///
    /// On a cache miss the bytes are extracted from the in-memory `AlignedVec`
    /// and inserted into the cache before being returned.
    fn get_or_cache_block(
        &self,
        handle: &Archived<BlockHandle>,
        cache_key: &BlockCacheKey,
        cache: &mut BlockCache,
    ) -> Result<CachedBlock> {
        if let Some(cached) = cache.get(cache_key) {
            return Ok(cached);
        }

        let offset = u64::from(handle.offset) as usize;
        let size = u64::from(handle.size) as usize;

        if offset + size > self.data.len() {
            bail!("Invalid data block offset/size");
        }

        let block = match &self.data {
            // Zero-copy: the cache entry references the shared mapping.
            SSTableData::Mapped(mmap) => CachedBlock::Mapped {
                mmap: std::sync::Arc::clone(mmap),
                offset,
                len: size,
            },
            SSTableData::Owned(_) => {
                let mut aligned = AlignedVec::with_capacity(size);
                aligned.extend_from_slice(&self.data.as_slice()[offset..offset + size]);
                CachedBlock::Owned(std::sync::Arc::new(aligned))
            }
        };
        debug_assert_eq!(
            block.as_bytes().as_ptr() as usize % 8,
            0,
            "data block must be 8-byte aligned for rkyv"
        );
        cache.insert(*cache_key, block.clone());
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
            let (_, block_handle) = &self.index.entries[idx];
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
            let (_, block_handle) = &self.index.entries[bi];
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
            let (block_first_key, _) = &self.index.entries[mid];

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
            let (bfk, _) = &self.index.entries[mid];
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
        let offset = u64::from(handle.offset) as usize;
        let size = u64::from(handle.size) as usize;

        if offset + size > self.data.len() {
            bail!("Invalid data block offset/size");
        }

        let block_slice = &self.data.as_slice()[offset..offset + size];
        check_archived_root::<DataBlock>(block_slice)
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
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.iter().filter_map(move |entry| {
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
            let live = match &dbv {
                DataBlockValue::Pointer(vp) => {
                    !(vp.file_id == 0 && vp.value_offset == TOMBSTONE_OFFSET)
                        && !(vp.expire_at != 0 && vp.expire_at <= now)
                }
                DataBlockValue::Inline { expire_at, .. } => {
                    !(*expire_at != 0 && *expire_at <= now)
                }
            };
            Some(Ok((user_key.to_vec(), live)))
        })
    }

    /// Returns an iterator over all entries in the SSTable.
    pub fn iter(&self) -> SSTableIterator<'_> {
        SSTableIterator {
            reader: self,
            block_idx: 0,
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

/// Iterator over all entries in an SSTable.
pub struct SSTableIterator<'a> {
    reader: &'a SSTableReader,
    block_idx: usize,
    entry_idx: usize,
    current_block: Option<&'a Archived<DataBlock>>,
}

impl<'a> Iterator for SSTableIterator<'a> {
    type Item = Result<(&'a [u8], DataBlockValue)>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.current_block.is_none() {
                if self.block_idx >= self.reader.index.entries.len() {
                    return None;
                }

                let (_, handle) = &self.reader.index.entries[self.block_idx];
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
    use crate::storage::format::ArchivedDataBlockValue;
    use rkyv::{check_archived_root, Archived};

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
        let mut cache = BlockCache::new(1024 * 1024, 0.1, 100);

        match reader.get_with_cache(b"inline-key", &mut cache)? {
            Some(CachedValue::Cached { ref block, offset, len, expire_at }) => {
                assert_eq!(expire_at, 99);
                assert_eq!(len, b"hello-inline".len());
                assert_eq!(&block.as_bytes()[offset..offset + len], b"hello-inline");
            }
            other => panic!("expected Cached, got {other:?}"),
        }

        match reader.get_with_cache(b"pointer-key", &mut cache)? {
            Some(CachedValue::VLogPointer { file_id, value_offset, value_len, expire_at }) => {
                assert_eq!((file_id, value_offset, value_len, expire_at), (3, 1234, 56, 7));
            }
            other => panic!("expected VLogPointer, got {other:?}"),
        }

        match reader.get_with_cache(b"tombstone-key", &mut cache)? {
            Some(CachedValue::Tombstone) => {}
            other => panic!("expected Tombstone, got {other:?}"),
        }

        // kv/018: the NULL sentinel is distinct from the tombstone sentinel.
        match reader.get_with_cache(b"null-key", &mut cache)? {
            Some(CachedValue::Null) => {}
            other => panic!("expected Null, got {other:?}"),
        }

        assert!(reader.get_with_cache(b"missing-key", &mut cache)?.is_none());
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
        let mut cache = BlockCache::new(1024 * 1024, 0.1, 100);
        match reader.get_with_cache(b"mkey", &mut cache)? {
            Some(CachedValue::Cached { ref block, offset, len, .. }) => {
                assert!(matches!(block, CachedBlock::Mapped { .. }), "block must be mmap-backed");
                assert_eq!(&block.as_bytes()[offset..offset + len], b"mval");
            }
            other => panic!("expected mmap-backed Cached, got {other:?}"),
        }
        match reader.get_with_cache(b"pkey", &mut cache)? {
            Some(CachedValue::VLogPointer { file_id: 2, .. }) => {}
            other => panic!("expected VLogPointer, got {other:?}"),
        }
        // The uncached path reads from the mapping as well.
        assert!(reader.get(b"mkey")?.is_some());
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

        let footer = check_archived_root::<SSTableFooter>(footer_slice)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        assert_eq!(u64::from(footer.checksum), 0);

        let index_handle = &footer.index_handle;
        let index_offset = u64::from(index_handle.offset) as usize;
        let index_size = u64::from(index_handle.size) as usize;
        let index_slice = &buf[index_offset..index_offset + index_size];
        let index_block = check_archived_root::<IndexBlock>(index_slice)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;

        assert!(!index_block.entries.is_empty());

        let (first_key, first_block_handle) = &index_block.entries[0];
        assert_eq!(first_key.as_slice(), b"key1");

        let data_offset = u64::from(first_block_handle.offset) as usize;
        let data_size = u64::from(first_block_handle.size) as usize;
        let data_slice = &buf[data_offset..data_offset + data_size];
        let data_block = check_archived_root::<DataBlock>(data_slice)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;

        let (key, dbv) = &data_block.entries[0];
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
}
