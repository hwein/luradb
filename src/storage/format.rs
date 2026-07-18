use memmap2::Mmap;
use rkyv::AlignedVec;
use rkyv_derive::{Archive, Deserialize, Serialize};
use std::sync::Arc;

#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[archive(check_bytes)]
#[archive_attr(repr(C))] // Force C layout on Archived type
#[repr(C)]
pub struct ValuePointer {
    pub file_id: u32,
    pub value_offset: u64,
    pub value_len: u32,
    /// Unix timestamp (seconds) after which this entry expires. 0 = no expiry.
    pub expire_at: u64,
}

#[derive(Archive, Deserialize, Serialize, Debug, PartialEq, Copy, Clone)]
#[archive(check_bytes)]
#[archive_attr(repr(C))] // Force C layout on Archived type
#[repr(C)]
pub struct BlockHandle {
    pub offset: u64,
    pub size: u64,
}

#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[archive(check_bytes)]
#[archive_attr(repr(C))] // Force C layout on Archived type
#[repr(C)]
pub struct SSTableFooter {
    pub index_handle: BlockHandle,
    pub bloom_filter_handle: BlockHandle,
    pub checksum: u64,
}

#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[archive(check_bytes)]
#[archive_attr(repr(C))] // Force C layout on Archived type
#[repr(C)]
pub struct IndexBlock {
    pub entries: Vec<(Vec<u8>, BlockHandle)>, // (key, block_handle)
}

/// Value stored in a DataBlock entry: either a VLog pointer (large values)
/// or inline bytes (small values below the vLog threshold).
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[archive(check_bytes)]
pub enum DataBlockValue {
    Pointer(ValuePointer),
    Inline { data: Vec<u8>, expire_at: u64 },
}

#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[archive(check_bytes)]
pub struct DataBlock {
    pub entries: Vec<(Vec<u8>, DataBlockValue)>, // (key, value)
}

#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[archive(check_bytes)]
#[archive_attr(repr(C))] // Force C layout on Archived type
#[repr(C)]
pub struct BloomFilter {
    /// Bit array for the bloom filter
    pub data: Vec<u8>,

    /// Number of hash functions used
    pub num_hashes: u32,
}

/// A cached data block (spec perf/003): either a zero-copy view into a
/// memory-mapped SSTable or owned aligned bytes (non-mmap fallback).
/// Cloning is cheap — an `Arc` clone plus offsets, never a data copy.
#[derive(Debug, Clone)]
pub enum CachedBlock {
    Mapped {
        mmap: Arc<Mmap>,
        offset: usize,
        len: usize,
    },
    Owned(Arc<AlignedVec>),
}

impl CachedBlock {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            CachedBlock::Mapped { mmap, offset, len } => &mmap[*offset..*offset + *len],
            CachedBlock::Owned(bytes) => bytes.as_slice(),
        }
    }

    /// Cache weight in bytes.
    pub fn len(&self) -> usize {
        match self {
            CachedBlock::Mapped { len, .. } => *len,
            CachedBlock::Owned(bytes) => bytes.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Result of a point lookup (spec perf/002): either a zero-copy reference
/// into a cached block or an owned value. `Send + Sync`, no lifetimes —
/// the backing `Arc` keeps the block alive as long as the value exists.
#[derive(Debug, Clone)]
pub enum CachedValue {
    /// Zero-copy: bytes live inside a cached block; `offset`/`len` address
    /// the value relative to the block's bytes.
    Cached {
        block: CachedBlock,
        offset: usize,
        len: usize,
        expire_at: u64,
    },
    /// Value must be fetched from the value log (no VLog read at this layer).
    VLogPointer {
        file_id: u32,
        value_offset: u64,
        value_len: u32,
        expire_at: u64,
    },
    /// Owned bytes (MemTable hits — already in RAM, not rkyv-formatted).
    Owned { data: Vec<u8>, expire_at: u64 },
    /// The key was deleted.
    Tombstone,
}

impl CachedValue {
    /// Bytes of the value: zero-copy slice for `Cached`, reference for
    /// `Owned`; `None` for `VLogPointer` (caller reads the VLog) and
    /// `Tombstone`.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            CachedValue::Cached { block, offset, len, .. } => {
                Some(&block.as_bytes()[*offset..*offset + *len])
            }
            CachedValue::Owned { data, .. } => Some(data),
            CachedValue::VLogPointer { .. } | CachedValue::Tombstone => None,
        }
    }

    /// Expiry timestamp (0 = no expiry).
    pub fn expire_at(&self) -> u64 {
        match self {
            CachedValue::Cached { expire_at, .. }
            | CachedValue::VLogPointer { expire_at, .. }
            | CachedValue::Owned { expire_at, .. } => *expire_at,
            CachedValue::Tombstone => 0,
        }
    }

    /// Materializes the value as owned bytes — the single copy at the end of
    /// the lookup path. Panics for `VLogPointer`/`Tombstone` (callers must
    /// resolve those first).
    pub fn to_owned_bytes(&self) -> Vec<u8> {
        self.as_bytes()
            .expect("to_owned_bytes on VLogPointer/Tombstone — resolve first")
            .to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cached(bytes: &[u8], offset: usize, len: usize) -> CachedValue {
        let mut block = AlignedVec::with_capacity(bytes.len());
        block.extend_from_slice(bytes);
        CachedValue::Cached {
            block: CachedBlock::Owned(Arc::new(block)),
            offset,
            len,
            expire_at: 7,
        }
    }

    // 1./2. Cached: as_bytes slices the block, to_owned_bytes copies it.
    #[test]
    fn test_cached_value_slice_and_materialize() {
        let cv = cached(b"xxhelloyy", 2, 5);
        assert_eq!(cv.as_bytes(), Some(&b"hello"[..]));
        assert_eq!(cv.to_owned_bytes(), b"hello".to_vec());
        assert_eq!(cv.expire_at(), 7);
    }

    // 3./4. VLogPointer and Tombstone expose no bytes.
    #[test]
    fn test_pointer_and_tombstone_have_no_bytes() {
        let vp = CachedValue::VLogPointer {
            file_id: 1,
            value_offset: 42,
            value_len: 8,
            expire_at: 0,
        };
        assert_eq!(vp.as_bytes(), None);
        assert_eq!(CachedValue::Tombstone.as_bytes(), None);
        assert_eq!(CachedValue::Tombstone.expire_at(), 0);
    }

    // 5. Mmap-backed CachedBlock slices the mapped file (spec perf/003).
    #[test]
    fn test_cached_block_mapped_and_owned() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("block.bin");
        std::fs::write(&path, b"0123456789").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let mmap = Arc::new(unsafe { memmap2::MmapOptions::new().map(&file).unwrap() });

        let mapped = CachedBlock::Mapped { mmap, offset: 2, len: 5 };
        assert_eq!(mapped.as_bytes(), b"23456");
        assert_eq!(mapped.len(), 5);

        let mut aligned = AlignedVec::new();
        aligned.extend_from_slice(b"owned");
        let owned = CachedBlock::Owned(Arc::new(aligned));
        assert_eq!(owned.as_bytes(), b"owned");

        let cv = CachedValue::Cached { block: mapped, offset: 1, len: 3, expire_at: 0 };
        assert_eq!(cv.as_bytes(), Some(&b"345"[..]));
        assert_eq!(cv.to_owned_bytes(), b"345".to_vec());
    }
}
