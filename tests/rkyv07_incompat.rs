//! On-disk/wire format break rkyv 0.7 → 0.8 (spec general-010 §5).
//!
//! The fixtures under `tests/fixtures/rkyv07/` were serialized with rkyv 0.7
//! and are frozen. They pin down empirically which of our archived types
//! actually changed layout: structures built from `Vec` and fixed-size integers
//! are unchanged, while the enum-bearing data block is rejected by validation
//! and an inline `String` decodes to a different value. Fixtures are copied into
//! an `AlignedVec` first, so a rejection is a real format mismatch and never a
//! mere alignment artifact.

use luradb::ipc::ShmCommand;
use luradb::storage::format::{BloomFilter, DataBlock, IndexBlock, SSTableFooter};
use rkyv::rancor;
use rkyv::util::AlignedVec;
use rkyv::Archived;

fn load(name: &str) -> AlignedVec {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rkyv07")
        .join(name);
    let raw = std::fs::read(path).expect("rkyv 0.7 fixture present");
    let mut aligned: AlignedVec = AlignedVec::with_capacity(raw.len());
    aligned.extend_from_slice(&raw);
    aligned
}

/// The data block is the one SSTable structure that breaks: `DataBlockValue` is
/// an enum and 0.8 places its payload differently, so validation rejects the
/// block instead of misreading it. Every read path validates a data block, so
/// reads from a ≤ v0.1.1 store fail with a clean error and never yield data.
#[test]
fn rkyv07_data_block_fails_validation() {
    let bytes = load("data_block.bin");
    let err = rkyv::access::<Archived<DataBlock>, rancor::Error>(bytes.as_slice())
        .err()
        .expect("0.7 data block must not validate under 0.8");
    assert!(err.to_string().contains("subtree pointer"), "unexpected error: {err}");
}

/// Footer, index and bloom block are built from fixed-size integers and plain
/// `Vec`s; their layout is unchanged, so they still parse — with their original
/// values, no misread offsets or lengths. None of them can flag a 0.7 store:
/// opening one succeeds and only the first data-block read fails.
#[test]
fn rkyv07_footer_index_and_bloom_parse_unchanged() {
    let bytes = load("sstable_footer.bin");
    let footer = rkyv::access::<Archived<SSTableFooter>, rancor::Error>(bytes.as_slice())
        .expect("0.7 footer layout is unchanged");
    assert_eq!(u64::from(footer.index_handle.offset), 4096);
    assert_eq!(u64::from(footer.index_handle.size), 256);
    assert_eq!(u64::from(footer.bloom_filter_handle.offset), 4352);
    assert_eq!(u64::from(footer.bloom_filter_handle.size), 128);
    assert_eq!(u64::from(footer.checksum), 0);

    let bytes = load("index_block.bin");
    let index = rkyv::access::<Archived<IndexBlock>, rancor::Error>(bytes.as_slice())
        .expect("0.7 index block layout is unchanged");
    assert_eq!(index.entries.len(), 2);
    assert_eq!(index.entries[0].0.as_slice(), b"fixture-key-1");
    assert_eq!(u64::from(index.entries[0].1.offset), 0);
    assert_eq!(u64::from(index.entries[0].1.size), 152);
    assert_eq!(index.entries[1].0.as_slice(), b"fixture-key-9");
    assert_eq!(u64::from(index.entries[1].1.offset), 152);
    assert_eq!(u64::from(index.entries[1].1.size), 96);

    let bytes = load("bloom_filter.bin");
    let bloom = rkyv::access::<Archived<BloomFilter>, rancor::Error>(bytes.as_slice())
        .expect("0.7 bloom filter layout is unchanged");
    assert_eq!(bloom.data.as_slice(), [0xa5u8; 32]);
    assert_eq!(u32::from(bloom.num_hashes), 7);
}

/// A 0.7 command passes 0.8 validation but does **not** decode back to the
/// original value: the inline-`String` representation changed, so the domain
/// gains the byte that used to hold its length. Decoding stays memory-safe and
/// panic-free, but 0.7 payloads are not wire-compatible. SHM segments are
/// volatile (rebuilt on restart), so only stale in-flight bytes are affected.
#[test]
fn rkyv07_shm_command_decodes_to_a_different_value() {
    let bytes = load("shm_command.bin");
    let original = ShmCommand::Put {
        request_id: 42,
        domain: "fixture".to_string(),
        key: b"fixture-key".to_vec(),
        value: b"fixture-value".to_vec(),
        ttl_secs: 60,
    };
    match ShmCommand::decode(bytes.as_slice()) {
        Ok(decoded) => {
            assert_ne!(decoded, original, "0.7 payload must not be wire-compatible");
            match decoded {
                ShmCommand::Put { domain, .. } => {
                    assert_eq!(domain, "fixture\u{7}", "inline string picks up the length byte")
                }
                other => panic!("expected Put, got {other:?}"),
            }
        }
        Err(_) => {} // A future 0.8.x tightening the check is equally acceptable.
    }
}
