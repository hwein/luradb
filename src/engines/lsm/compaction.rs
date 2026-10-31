//! Compaction logic for the LSM-Tree.
//!
//! Implements **Leveled Compaction** with correct MVCC tombstone GC.
//!
//! # Tombstone safety rule
//! A tombstone at timestamp T may only be dropped when `T < low_watermark`,
//! where `low_watermark` is the oldest active snapshot timestamp from the
//! `SnapshotRegistry`, and the job is bottommost: no level below its target
//! level holds SSTables. The first guarantees that no live reader can still
//! observe the pre-deletion state of the key, the second that no older
//! version below the job resurfaces.
//!
//! # Version safety rule
//! Older versions may only be dropped behind a version at `T <= low_watermark`:
//! that one is visible to the oldest active snapshot and therefore shadows
//! everything older for every registered reader. Versions above the watermark
//! may still be the newest visible version of a pinned snapshot — e.g. a
//! running backup export, which would otherwise silently
//! miss the key. A TTL-expired version is dropped only as the oldest one kept
//! and only by a bottommost job; otherwise it stays until the TTL sweeper
//! replaces it with a tombstone.
//!
//! # Multi-level cascade
//! - **L0**: triggers when file count reaches `l0_compaction_threshold`.
//! - **L1**: triggers when total size exceeds `l1_max_size`.
//! - **L2+**: triggers when total size exceeds `l1_max_size * level_size_ratio^(n-1)`.

use crate::engines::lsm::key::{InternalKey, Timestamp};
use crate::storage::file_manager::SSTableFileWriter;
use crate::storage::sstable::{SSTableBuilder, SSTableIterator, SSTableReader, SSTableSummary};
use crate::storage::format::{is_expired, DataBlockValue, ValuePointer, TOMBSTONE_OFFSET};
use crate::storage::manifest::{Manifest, SSTableMetadata};
use anyhow::Result;
use std::collections::BinaryHeap;
use std::sync::Arc;

/// Configuration for the leveled compaction strategy.
#[derive(Debug, Clone)]
pub struct CompactionConfig {
    /// Number of L0 SSTables that triggers an L0 → L1 compaction.
    pub l0_compaction_threshold: usize,

    /// Maximum total byte size of L1 before triggering L1 → L2 compaction.
    pub l1_max_size: u64,

    /// Size multiplier between consecutive levels (e.g. 10 means L2 = 10× L1).
    pub level_size_ratio: u64,

    /// Maximum byte size of a single output SSTable produced by compaction.
    ///
    /// When the compacted result exceeds this limit it is split into multiple files.
    pub max_sstable_size: usize,

    /// MVCC low watermark: the oldest active snapshot timestamp.
    ///
    /// Tombstones with `timestamp < low_watermark` are safe to garbage-collect
    /// in a bottommost job. `None` means no active snapshots — tombstones must
    /// be retained.
    pub low_watermark: Option<Timestamp>,

    /// Whether no level below the job's target level holds SSTables. Only
    /// then may tombstones and expired values be dropped: otherwise an older
    /// version of the key down there would resurface.
    pub bottommost: bool,
}

impl Default for CompactionConfig {
    fn default() -> Self {
        Self {
            l0_compaction_threshold: 4,
            l1_max_size: 100 * 1024 * 1024, // 100 MB
            level_size_ratio: 10,
            max_sstable_size: 64 * 1024 * 1024, // 64 MB
            low_watermark: None,
            bottommost: true,
        }
    }
}

/// A single compaction job that merges two adjacent levels.
///
/// `source_sstables` (e.g. L0) are merged with the overlapping `target_sstables`
/// (e.g. L1), producing a new sorted run destined for the target level.
pub struct CompactionJob {
    source_sstables: Vec<Arc<SSTableReader>>,
    target_sstables: Vec<Arc<SSTableReader>>,
    config: CompactionConfig,
}

impl CompactionJob {
    /// Creates a new compaction job.
    pub fn new(
        source_sstables: Vec<Arc<SSTableReader>>,
        target_sstables: Vec<Arc<SSTableReader>>,
        config: CompactionConfig,
    ) -> Self {
        Self { source_sstables, target_sstables, config }
    }

    /// Starts the compaction; [`CompactionRun::next_sstable`] writes its
    /// output files one at a time.
    ///
    /// Tables enter the merge newest first, in the read path's order: the
    /// sources reversed, then the targets, which sit one level below and are
    /// older than every source. Of identical internal keys (a stamp tie) only
    /// the newest source's entry is kept, the one reads see.
    pub fn compact(&self) -> Result<CompactionRun<'_>> {
        let tables = self.source_sstables.iter().rev().chain(&self.target_sstables);
        Ok(CompactionRun {
            job: self,
            merge: Merge::new(tables.map(|table| table.iter()).collect())?,
            group: GroupFilter::default(),
            next_entry: None,
            filter_capacity_left: self.input_filter_capacity(),
            data_bytes_left: self.input_data_bytes(),
            #[cfg(test)]
            peak_held_entries: 0,
        })
    }

    /// Bounds the keys the job writes: every one of them is a key of an input,
    /// and an input holds no more than its filter or its blocks take.
    fn input_filter_capacity(&self) -> usize {
        self.inputs().map(|table| table.bloom_capacity().min(table.key_count_bound())).sum()
    }

    fn input_data_bytes(&self) -> u64 {
        self.inputs().map(|table| table.data_bytes()).sum()
    }

    fn inputs(&self) -> impl Iterator<Item = &Arc<SSTableReader>> {
        self.source_sstables.iter().chain(&self.target_sstables)
    }

    /// Filters the merged entry stream (newest version first per key) one
    /// entry at a time; `group` holds the state of the current user key.
    ///
    /// Per user-key group:
    /// 1. **Version deduplication**: keep versions down to and including the
    ///    first one that shadows all older ones (see
    ///    [`Self::shadows_older_versions`]); drop the rest.
    /// 2. **Tombstone GC**: drop when `timestamp < low_watermark` (safe for all
    ///    active snapshots) and the job is bottommost; otherwise retain.
    /// 3. **TTL**: expired values are dropped only by a bottommost job and only
    ///    while no older version of the key survives them.
    fn filter_entry(
        &self,
        group: &mut GroupFilter,
        encoded_key: Vec<u8>,
        dbv: DataBlockValue,
    ) -> Option<(Vec<u8>, DataBlockValue)> {
        let user_key = InternalKey::extract_user_key(&encoded_key)?;
        let timestamp = InternalKey::extract_timestamp(&encoded_key)?;

        if group.user_key.as_deref() != Some(user_key) {
            group.user_key = Some(user_key.to_vec());
            group.done = false;
        }

        if group.done {
            return None;
        }

        let oldest_kept = self.shadows_older_versions(timestamp);
        group.done = oldest_kept;
        self.retain_version(encoded_key, dbv, timestamp, oldest_kept)
    }

    /// Whether a version at `timestamp` hides every older version of its key
    /// from every registered reader: it is visible to the oldest active
    /// snapshot, and no snapshot is older than that. Versions above the
    /// watermark can still be the newest visible version of a pinned snapshot.
    /// Without active snapshots this holds for the newest version, which is
    /// the first one tested — the group then ends there, as before.
    fn shadows_older_versions(&self, timestamp: Timestamp) -> bool {
        self.config
            .low_watermark
            .map(|lw| timestamp.as_u64() <= lw.as_u64())
            .unwrap_or(true)
    }

    /// Keep-or-drop decision for one retained version: tombstones survive
    /// unless below the low watermark, live values unless TTL-expired, and
    /// neither is dropped unless the job is bottommost.
    /// `oldest_kept` is false while older versions of the key still follow.
    fn retain_version(
        &self,
        encoded_key: Vec<u8>,
        dbv: DataBlockValue,
        timestamp: Timestamp,
        oldest_kept: bool,
    ) -> Option<(Vec<u8>, DataBlockValue)> {
        // Tombstones are only represented as Pointer entries with the sentinel
        // values. Inline entries are never tombstones. The NULL sentinel
        // (NULL_OFFSET) is data: it falls through to the live path
        // below — overwrites older versions, is never GC'd, has no TTL.
        let is_tombstone = matches!(
            &dbv,
            DataBlockValue::Pointer(vp) if vp.file_id == 0 && vp.value_offset == TOMBSTONE_OFFSET
        );

        if is_tombstone {
            // `timestamp < low_watermark` implies `oldest_kept`, so dropping
            // the tombstone cannot expose an older version kept above;
            // `bottommost` rules out one below the target level.
            let safe_to_drop = self.config.bottommost
                && self
                    .config
                    .low_watermark
                    .map(|lw| timestamp.as_u64() < lw.as_u64())
                    .unwrap_or(false);

            return if safe_to_drop { None } else { Some((encoded_key, dbv)) };
        }

        // Drop TTL-expired live entries — but only the oldest kept one of a
        // bottommost job: removing a version that shadows another, in the job
        // or below its target level, would resurrect that one.
        let expire_at = match &dbv {
            DataBlockValue::Pointer(vp) => vp.expire_at,
            DataBlockValue::Inline { expire_at, .. } => *expire_at,
        };
        if self.config.bottommost && oldest_kept && expire_at != 0 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if is_expired(expire_at, now) {
                return None;
            }
        }

        // Live, non-expired value: keep it.
        Some((encoded_key, dbv))
    }
}

/// A running compaction: merges and filters its inputs as a stream and holds
/// one data block, the index and the Bloom filter of the file it writes.
pub struct CompactionRun<'a> {
    job: &'a CompactionJob,
    merge: Merge<'a>,
    group: GroupFilter,
    /// The entry that opens the next file, read ahead by `has_next` or while
    /// closing the last file.
    next_entry: Option<(Vec<u8>, DataBlockValue)>,
    /// The inputs' filter capacity less the keys of the files written so far.
    filter_capacity_left: usize,
    /// The inputs' data bytes less those of the files written so far.
    data_bytes_left: u64,
    #[cfg(test)]
    peak_held_entries: usize,
}

impl CompactionRun<'_> {
    /// Whether an entry is left for another output file.
    pub fn has_next(&mut self) -> Result<bool> {
        if self.next_entry.is_none() {
            self.next_entry = self.next_filtered()?;
        }
        Ok(self.next_entry.is_some())
    }

    /// Writes the next output SSTable through `writer`, each data block as
    /// soon as it is full; `None` once the inputs are exhausted.
    ///
    /// A file is only cut behind the last version of a user key: the read path
    /// treats the tables of a level as key-disjoint and would otherwise pick an
    /// older version from a sibling file.
    pub async fn next_sstable(&mut self, writer: &mut SSTableFileWriter) -> Result<Option<SSTableSummary>> {
        let mut builder = SSTableBuilder::new(output_filter_capacity(
            self.filter_capacity_left,
            self.data_bytes_left,
            self.job.config.max_sstable_size,
        ));
        let mut current_size: usize = 0;
        let mut last_user_key: Vec<u8> = Vec::new();

        while let Some((key, dbv)) = self.next_filtered()? {
            #[cfg(test)]
            {
                let held = builder.held_entries() + 1 + self.merge.heads.len();
                self.peak_held_entries = self.peak_held_entries.max(held);
            }

            let user_key = InternalKey::extract_user_key(&key).unwrap_or_default();
            let full = current_size > 0 && current_size >= self.job.config.max_sstable_size;
            if full && user_key != last_user_key {
                self.next_entry = Some((key, dbv));
                break;
            }
            last_user_key.clear();
            last_user_key.extend_from_slice(user_key);

            current_size += key.len() + match &dbv {
                DataBlockValue::Pointer(_) => std::mem::size_of::<ValuePointer>(),
                DataBlockValue::Inline { data, .. } => data.len() + 8,
            };
            match dbv {
                DataBlockValue::Pointer(vp) => builder.add(key, vp),
                DataBlockValue::Inline { data, expire_at } => builder.add_inline(key, data, expire_at),
            }
            let encoded = builder.take_encoded()?;
            if !encoded.is_empty() {
                writer.write(&encoded).await?;
            }
        }

        if current_size == 0 {
            return Ok(None);
        }
        let (tail, summary) = builder.finish_with_summary()?;
        self.filter_capacity_left = self.filter_capacity_left.saturating_sub(summary.total_keys);
        self.data_bytes_left = self.data_bytes_left.saturating_sub(summary.data_bytes);
        writer.write(&tail).await?;
        Ok(Some(summary))
    }

    fn next_filtered(&mut self) -> Result<Option<(Vec<u8>, DataBlockValue)>> {
        if let Some(entry) = self.next_entry.take() {
            return Ok(Some(entry));
        }
        while let Some((key, dbv)) = self.merge.next()? {
            if let Some(kept) = self.job.filter_entry(&mut self.group, key, dbv) {
                return Ok(Some(kept));
            }
        }
        Ok(None)
    }

    /// Most entries the run held at once: those of the file it was building,
    /// the one in hand and the waiting heads of its inputs.
    #[cfg(test)]
    pub(crate) fn peak_held_entries(&self) -> usize {
        self.peak_held_entries
    }
}

/// Spare factor on a file's estimated share of the keys: the file size counts
/// raw key and value bytes, the data bytes their encoding, up to about three
/// times as many for small inline values.
const ESTIMATE_MARGIN: u128 = 3;

/// Filter capacity of the next output file: its share of `keys_left` by the
/// file size against the inputs' `data_bytes_left`, with margin. An
/// underestimate only raises the file's false positive rate.
fn output_filter_capacity(keys_left: usize, data_bytes_left: u64, max_sstable_size: usize) -> usize {
    let estimate = if max_sstable_size == 0 {
        // Every user key gets its own file.
        1
    } else if data_bytes_left == 0 {
        // The outputs' blocks took more bytes than the inputs' did.
        keys_left
    } else {
        let share = (keys_left as u128 * max_sstable_size as u128).div_ceil(u128::from(data_bytes_left));
        usize::try_from(share.saturating_mul(ESTIMATE_MARGIN)).unwrap_or(usize::MAX)
    };
    keys_left.min(estimate).max(1)
}

/// State of the user-key group the filter is in.
#[derive(Default)]
struct GroupFilter {
    user_key: Option<Vec<u8>>,
    done: bool,
}

/// The first unread entry of one input table.
struct Head {
    key: Vec<u8>,
    table: usize,
    value: DataBlockValue,
}

/// Reversed for the max-heap: the smallest internal key comes first, and of
/// identical keys the one of the table that entered the merge first.
impl Ord for Head {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (&other.key, other.table).cmp(&(&self.key, self.table))
    }
}

impl PartialOrd for Head {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Head {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl Eq for Head {}

/// k-way merge of the input tables in internal key order; of identical
/// internal keys only the first is yielded.
struct Merge<'a> {
    tables: Vec<SSTableIterator<'a>>,
    heads: BinaryHeap<Head>,
    /// Table whose head was yielded last; it is read on only at the next
    /// call, so no more than one entry per table waits at any time.
    yielded: Option<usize>,
    last_key: Option<Vec<u8>>,
}

impl<'a> Merge<'a> {
    fn new(tables: Vec<SSTableIterator<'a>>) -> Result<Self> {
        let mut merge = Self { tables, heads: BinaryHeap::new(), yielded: None, last_key: None };
        for table in 0..merge.tables.len() {
            merge.read_head(table)?;
        }
        Ok(merge)
    }

    fn read_head(&mut self, table: usize) -> Result<()> {
        if let Some(entry) = self.tables[table].next() {
            let (key, value) = entry?;
            self.heads.push(Head { key: key.to_vec(), table, value });
        }
        Ok(())
    }

    fn next(&mut self) -> Result<Option<(Vec<u8>, DataBlockValue)>> {
        loop {
            if let Some(table) = self.yielded.take() {
                self.read_head(table)?;
            }
            let Some(head) = self.heads.pop() else {
                return Ok(None);
            };
            self.yielded = Some(head.table);
            if self.last_key.as_ref() == Some(&head.key) {
                continue;
            }
            self.last_key = Some(head.key.clone());
            return Ok(Some((head.key, head.value)));
        }
    }
}

/// Maximum allowed total byte size for `level`. Returns `None` for L0 (file-count driven).
pub fn level_max_size(level: usize, config: &CompactionConfig) -> Option<u64> {
    match level {
        0 => None,
        1 => Some(config.l1_max_size),
        n => {
            let ratio = config.level_size_ratio.saturating_pow((n - 1) as u32);
            Some(config.l1_max_size.saturating_mul(ratio))
        }
    }
}

/// Returns `true` if `level` needs compaction.
pub fn should_compact_for_level(
    level: usize,
    manifest: &Manifest,
    config: &CompactionConfig,
) -> bool {
    match level {
        0 => manifest.get_level(0).len() >= config.l0_compaction_threshold,
        n => level_max_size(n, config)
            .map(|max| manifest.get_level(n).iter().map(|m| m.file_size).sum::<u64>() >= max)
            .unwrap_or(false),
    }
}

/// Returns `true` if *any* level requires compaction.
pub fn should_compact(manifest: &Manifest, config: &CompactionConfig) -> bool {
    (0..manifest.levels.len()).any(|lvl| should_compact_for_level(lvl, manifest, config))
}

/// Returns the lowest level that currently needs compaction, or `None`.
pub fn select_level_to_compact(manifest: &Manifest, config: &CompactionConfig) -> Option<usize> {
    (0..manifest.levels.len()).find(|&lvl| should_compact_for_level(lvl, manifest, config))
}

/// File ids deleted by a compaction that merges `src_metas` into `tgt_metas`
/// -- used by the caller to deregister them from the `IoEngine`.
/// Compaction always replaces both inputs wholesale, so this is simply their union.
pub fn deleted_file_ids(src_metas: &[SSTableMetadata], tgt_metas: &[SSTableMetadata]) -> Vec<u64> {
    src_metas.iter().chain(tgt_metas.iter()).map(|m| m.file_id).collect()
}

/// Selects SSTables to compact from L0 into L1 (convenience wrapper).
pub fn select_sstables_for_compaction(
    manifest: &Manifest,
) -> (Vec<SSTableMetadata>, Vec<SSTableMetadata>) {
    select_sstables_for_level_compaction(0, manifest)
}

/// Selects SSTables to compact from `source_level` into `source_level + 1`.
///
/// - **L0**: all tables (they may overlap each other).
/// - **Ln (n > 0)**: the single largest table to bound write amplification.
///
/// Returns `(source_tables, overlapping_target_tables)`.
pub fn select_sstables_for_level_compaction(
    source_level: usize,
    manifest: &Manifest,
) -> (Vec<SSTableMetadata>, Vec<SSTableMetadata>) {
    let source_tables = manifest.get_level(source_level).to_vec();
    if source_tables.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let selected: Vec<SSTableMetadata> = if source_level == 0 {
        source_tables
    } else {
        vec![source_tables.into_iter().max_by_key(|m| m.file_size).unwrap()]
    };

    // Bounds in internal key order, the one the tables are sorted in; their
    // user keys span the source.
    let mut min_key = selected[0].smallest_key.clone();
    let mut max_key = selected[0].largest_key.clone();
    for meta in &selected[1..] {
        if meta.smallest_key < min_key { min_key = meta.smallest_key.clone(); }
        if meta.largest_key > max_key { max_key = meta.largest_key.clone(); }
    }

    let target_tables = manifest.find_overlapping_sstables(
        source_level + 1,
        InternalKey::extract_user_key(&min_key).unwrap_or_default(),
        InternalKey::extract_user_key(&max_key).unwrap_or_default(),
    );

    (selected, target_tables)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::core::engine_runtime::block_on;
    use crate::engines::lsm::engine::LsmStorageEngine;
    use crate::storage::file_manager::FileManager;
    use crate::storage::test_fault;

    impl CompactionJob {
        /// The filter over a whole entry list, newest version first per key.
        fn filter_entries(
            &self,
            entries: Vec<(Vec<u8>, DataBlockValue)>,
        ) -> Result<Vec<(Vec<u8>, DataBlockValue)>> {
            let mut group = GroupFilter::default();
            Ok(entries
                .into_iter()
                .filter_map(|(key, dbv)| self.filter_entry(&mut group, key, dbv))
                .collect())
        }
    }

    fn make_vp(offset: u64) -> DataBlockValue {
        DataBlockValue::Pointer(ValuePointer {
            file_id: 1,
            value_offset: offset,
            value_len: 10,
            expire_at: 0,
        })
    }

    fn tombstone_vp() -> DataBlockValue {
        DataBlockValue::Pointer(ValuePointer {
            file_id: 0,
            value_offset: u64::MAX,
            value_len: 0,
            expire_at: 0,
        })
    }

    fn null_vp() -> DataBlockValue {
        DataBlockValue::Pointer(ValuePointer {
            file_id: 0,
            value_offset: crate::storage::format::NULL_OFFSET,
            value_len: 0,
            expire_at: 0,
        })
    }

    fn encode(user_key: &[u8], ts: u64) -> Vec<u8> {
        InternalKey::new(user_key.to_vec(), Timestamp::new(ts)).encode()
    }

    #[test]
    fn test_keeps_newest_live_version_only() -> Result<()> {
        let entries = vec![
            (encode(b"key1", 300), make_vp(1000)),
            (encode(b"key1", 200), make_vp(2000)),
            (encode(b"key1", 100), make_vp(3000)),
        ];
        let job = CompactionJob::new(vec![], vec![], CompactionConfig::default());
        let out = job.filter_entries(entries)?;
        assert_eq!(out.len(), 1);
        match &out[0].1 {
            DataBlockValue::Pointer(vp) => assert_eq!(vp.value_offset, 1000),
            _ => panic!("Expected Pointer variant"),
        }
        Ok(())
    }

    // While an export snapshot is pinned, the version it can still
    // read must survive — keeping only the newest one loses the key silently.
    #[test]
    fn test_keeps_version_visible_at_low_watermark() -> Result<()> {
        let cfg = CompactionConfig { low_watermark: Some(Timestamp::new(100)), ..Default::default() };
        let entries = vec![
            (encode(b"key1", 150), make_vp(1000)),
            (encode(b"key1", 50), make_vp(2000)),
        ];
        let job = CompactionJob::new(vec![], vec![], cfg);
        let out = job.filter_entries(entries)?;
        assert_eq!(out.len(), 2, "the version visible at the watermark must survive");
        assert_eq!(InternalKey::extract_timestamp(&out[1].0), Some(Timestamp::new(50)));
        Ok(())
    }

    #[test]
    fn test_drops_versions_older_than_the_visible_one() -> Result<()> {
        let cfg = CompactionConfig { low_watermark: Some(Timestamp::new(100)), ..Default::default() };
        let entries = vec![
            (encode(b"key1", 150), make_vp(1000)),
            (encode(b"key1", 100), make_vp(2000)), // visible at the watermark
            (encode(b"key1", 90), make_vp(3000)),
            (encode(b"key1", 10), make_vp(4000)),
        ];
        let job = CompactionJob::new(vec![], vec![], cfg);
        let out = job.filter_entries(entries)?;
        assert_eq!(out.len(), 2, "no reader can reach anything below ts=100");
        assert_eq!(InternalKey::extract_timestamp(&out[1].0), Some(Timestamp::new(100)));
        Ok(())
    }

    // Without an active snapshot the rule degenerates to keep-newest-only.
    #[test]
    fn test_without_low_watermark_only_newest_survives() -> Result<()> {
        let entries = vec![
            (encode(b"key1", 150), make_vp(1000)),
            (encode(b"key1", 100), make_vp(2000)),
            (encode(b"key1", 50), make_vp(3000)),
        ];
        let job = CompactionJob::new(vec![], vec![], CompactionConfig::default());
        let out = job.filter_entries(entries)?;
        assert_eq!(out.len(), 1);
        assert_eq!(InternalKey::extract_timestamp(&out[0].0), Some(Timestamp::new(150)));
        Ok(())
    }

    // A tombstone above the watermark does not end the group: a snapshot at the
    // watermark still reads the live version behind it.
    #[test]
    fn test_tombstone_above_watermark_keeps_older_visible_version() -> Result<()> {
        let cfg = CompactionConfig { low_watermark: Some(Timestamp::new(100)), ..Default::default() };
        let entries = vec![
            (encode(b"key1", 200), tombstone_vp()),
            (encode(b"key1", 60), make_vp(500)),
            (encode(b"key1", 20), make_vp(600)),
        ];
        let job = CompactionJob::new(vec![], vec![], cfg);
        let out = job.filter_entries(entries)?;
        assert_eq!(out.len(), 2, "tombstone plus the version visible at the watermark");
        assert_eq!(InternalKey::extract_timestamp(&out[1].0), Some(Timestamp::new(60)));
        Ok(())
    }

    // An expired version that shadows a kept older one must stay, otherwise
    // that older value resurfaces for readers above it.
    #[test]
    fn test_expired_version_kept_while_it_shadows_an_older_one() -> Result<()> {
        let cfg = CompactionConfig { low_watermark: Some(Timestamp::new(100)), ..Default::default() };
        let expired = DataBlockValue::Pointer(ValuePointer {
            file_id: 1, value_offset: 100, value_len: 10, expire_at: unix_now() - 100,
        });
        let entries = vec![
            (encode(b"key1", 150), expired),
            (encode(b"key1", 50), make_vp(2000)),
        ];
        let job = CompactionJob::new(vec![], vec![], cfg);
        let out = job.filter_entries(entries)?;
        assert_eq!(out.len(), 2, "expired version must not expose the older one");
        Ok(())
    }

    #[test]
    fn test_tombstone_kept_without_low_watermark() -> Result<()> {
        let entries = vec![(encode(b"key1", 100), tombstone_vp())];
        let job = CompactionJob::new(vec![], vec![], CompactionConfig::default());
        let out = job.filter_entries(entries)?;
        assert_eq!(out.len(), 1);
        Ok(())
    }

    #[test]
    fn test_tombstone_dropped_below_low_watermark() -> Result<()> {
        let cfg = CompactionConfig { low_watermark: Some(Timestamp::new(200)), ..Default::default() };
        let entries = vec![(encode(b"key1", 100), tombstone_vp())];
        let job = CompactionJob::new(vec![], vec![], cfg);
        let out = job.filter_entries(entries)?;
        assert!(out.is_empty(), "tombstone below low watermark must be dropped");
        Ok(())
    }

    #[test]
    fn test_tombstone_kept_above_low_watermark() -> Result<()> {
        let cfg = CompactionConfig { low_watermark: Some(Timestamp::new(50)), ..Default::default() };
        let entries = vec![(encode(b"key1", 100), tombstone_vp())];
        let job = CompactionJob::new(vec![], vec![], cfg);
        let out = job.filter_entries(entries)?;
        assert_eq!(out.len(), 1, "tombstone above low watermark must be retained");
        Ok(())
    }

    #[test]
    fn test_tombstone_suppresses_older_live_version() -> Result<()> {
        let entries = vec![
            (encode(b"key1", 200), tombstone_vp()),
            (encode(b"key1", 100), make_vp(500)),
        ];
        let job = CompactionJob::new(vec![], vec![], CompactionConfig::default());
        let out = job.filter_entries(entries)?;
        assert_eq!(out.len(), 1);
        match &out[0].1 {
            DataBlockValue::Pointer(vp) => assert_eq!(vp.value_offset, u64::MAX),
            _ => panic!("Expected tombstone Pointer variant"),
        }
        Ok(())
    }

    // A NULL record is data — it suppresses older live versions and
    // is never dropped, even below the tombstone-GC low watermark.
    #[test]
    fn test_null_record_survives_compaction_and_suppresses_older() -> Result<()> {
        // Everything below 500 is GC-eligible.
        let cfg = CompactionConfig { low_watermark: Some(Timestamp::new(500)), ..Default::default() };
        let entries = vec![
            (encode(b"key1", 200), null_vp()),
            (encode(b"key1", 100), make_vp(500)),
        ];
        let job = CompactionJob::new(vec![], vec![], cfg);
        let out = job.filter_entries(entries)?;
        assert_eq!(out.len(), 1, "NULL must survive; older live version suppressed");
        match &out[0].1 {
            DataBlockValue::Pointer(vp) => {
                assert_eq!(vp.value_offset, crate::storage::format::NULL_OFFSET)
            }
            _ => panic!("Expected NULL Pointer variant"),
        }
        Ok(())
    }

    // Above a non-empty deeper level, the tombstone below the
    // watermark stays to shadow the older versions down there; the older
    // ones in the job still go.
    #[test]
    fn test_tombstone_below_low_watermark_kept_when_not_bottommost() -> Result<()> {
        let cfg = CompactionConfig {
            low_watermark: Some(Timestamp::new(200)),
            bottommost: false,
            ..Default::default()
        };
        let entries = vec![
            (encode(b"key1", 100), tombstone_vp()),
            (encode(b"key1", 50), make_vp(500)),
        ];
        let job = CompactionJob::new(vec![], vec![], cfg);
        let out = job.filter_entries(entries)?;
        assert_eq!(out.len(), 1, "only the tombstone survives");
        assert_eq!(InternalKey::extract_timestamp(&out[0].0), Some(Timestamp::new(100)));
        Ok(())
    }

    // Likewise an expired newest version, which the TTL sweeper later
    // turns into a tombstone.
    #[test]
    fn test_expired_value_kept_when_not_bottommost() -> Result<()> {
        let cfg = CompactionConfig { bottommost: false, ..Default::default() };
        let expired = DataBlockValue::Pointer(ValuePointer {
            file_id: 1, value_offset: 100, value_len: 10, expire_at: 1,
        });
        let entries = vec![
            (encode(b"key1", 100), expired),
            (encode(b"key1", 50), make_vp(500)),
        ];
        let job = CompactionJob::new(vec![], vec![], cfg);
        let out = job.filter_entries(entries)?;
        assert_eq!(out.len(), 1, "only the expired version survives");
        assert_eq!(InternalKey::extract_timestamp(&out[0].0), Some(Timestamp::new(100)));
        Ok(())
    }

    #[test]
    fn test_should_compact_l0_threshold() {
        let mut manifest = Manifest::new();
        let config = CompactionConfig::default();
        assert!(!should_compact(&manifest, &config));
        for i in 0..4u64 {
            manifest.add_sstable(SSTableMetadata {
                file_id: i, level: 0,
                smallest_key: vec![0], largest_key: vec![255], file_size: 1024,
                max_timestamp: 0,
            });
        }
        assert!(should_compact(&manifest, &config));
    }

    #[test]
    fn test_should_compact_l1_size() {
        let mut manifest = Manifest::new();
        let config = CompactionConfig::default();
        manifest.add_sstable(SSTableMetadata {
            file_id: 1, level: 1,
            smallest_key: vec![0], largest_key: vec![255],
            file_size: 101 * 1024 * 1024, // > 100 MB
            max_timestamp: 0,
        });
        assert!(should_compact(&manifest, &config));
        assert_eq!(select_level_to_compact(&manifest, &config), Some(1));
    }

    #[test]
    fn test_level_max_size() {
        let config = CompactionConfig::default(); // ratio = 10
        assert!(level_max_size(0, &config).is_none());
        assert_eq!(level_max_size(1, &config), Some(100 * 1024 * 1024));
        assert_eq!(level_max_size(2, &config), Some(1_000 * 1024 * 1024));
    }

    #[test]
    fn test_deleted_file_ids_unions_source_and_target() {
        let src = vec![SSTableMetadata {
            file_id: 1, level: 0,
            smallest_key: vec![0], largest_key: vec![255], file_size: 1024,
            max_timestamp: 0,
        }];
        let tgt = vec![SSTableMetadata {
            file_id: 10, level: 1,
            smallest_key: vec![0], largest_key: vec![255], file_size: 2048,
            max_timestamp: 0,
        }];
        let mut ids = deleted_file_ids(&src, &tgt);
        ids.sort_unstable();
        assert_eq!(ids, vec![1, 10]);
    }

    #[test]
    fn test_select_sstables_for_compaction() {
        let mut manifest = Manifest::new();
        manifest.add_sstable(SSTableMetadata {
            file_id: 1, level: 0,
            smallest_key: encode(b"a", 20), largest_key: encode(b"d", 20), file_size: 1024,
            max_timestamp: 0,
        });
        manifest.add_sstable(SSTableMetadata {
            file_id: 2, level: 0,
            smallest_key: encode(b"e", 20), largest_key: encode(b"h", 20), file_size: 1024,
            max_timestamp: 0,
        });
        manifest.add_sstable(SSTableMetadata {
            file_id: 10, level: 1,
            smallest_key: encode(b"c", 10), largest_key: encode(b"f", 10), file_size: 2048,
            max_timestamp: 0,
        });
        manifest.add_sstable(SSTableMetadata {
            file_id: 11, level: 1,
            smallest_key: encode(b"i", 10), largest_key: encode(b"z", 10), file_size: 2048,
            max_timestamp: 0,
        });
        let (src, tgt) = select_sstables_for_compaction(&manifest);
        assert_eq!(src.len(), 2);
        assert_eq!(tgt.len(), 1);
        assert_eq!(tgt[0].file_id, 10);
    }

    /// Target file ids an L0 compaction of `l0` into `l1` picks; each table
    /// is given as its (smallest, largest) internal key.
    fn targets_selected(l0: &[(Vec<u8>, Vec<u8>)], l1: &[(Vec<u8>, Vec<u8>)]) -> Vec<u64> {
        let mut manifest = Manifest::new();
        let tables = l0.iter().map(|t| (0, t)).chain(l1.iter().map(|t| (1, t)));
        for (file_id, (level, (smallest, largest))) in tables.enumerate() {
            manifest.add_sstable(SSTableMetadata {
                file_id: file_id as u64, level,
                smallest_key: smallest.clone(), largest_key: largest.clone(), file_size: 1024,
                max_timestamp: 0,
            });
        }
        let (_, tgt) = select_sstables_for_compaction(&manifest);
        tgt.iter().map(|m| m.file_id).collect()
    }

    // An older version of the source's largest user key sorts behind
    // the source's largest internal key, yet its table must join the job.
    #[test]
    fn test_select_includes_target_starting_with_older_version_of_largest_key() {
        let l0 = [(encode(b"a", 20), encode(b"k", 20))];
        let l1 = [(encode(b"k", 10), encode(b"z", 10))];
        assert_eq!(targets_selected(&l0, &l1), vec![1]);
    }

    // Stamped, `user:1` sorts after its extensions such as `user:15`;
    // comparing bare user keys would miss this target table ...
    #[test]
    fn test_select_includes_target_spanning_a_key_and_its_extensions() {
        let l0 = [(encode(b"user:15", 20), encode(b"user:15", 20))];
        let l1 = [(encode(b"user:10", 10), encode(b"user:1", 10))];
        assert_eq!(targets_selected(&l0, &l1), vec![1]);
    }

    // ... and would take `user:15` instead of `user:1` as the source's largest
    // user key.
    #[test]
    fn test_select_bounds_the_source_in_internal_key_order() {
        let l0 = [
            (encode(b"user:1", 20), encode(b"user:1", 20)),
            (encode(b"user:15", 20), encode(b"user:15", 20)),
        ];
        let l1 = [(encode(b"user:1", 10), encode(b"user:1", 10))];
        assert_eq!(targets_selected(&l0, &l1), vec![2]);
    }

    fn unix_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn test_filter_drops_expired_ttl_keeps_unexpired() -> Result<()> {
        let now = unix_now();
        let expired = DataBlockValue::Pointer(ValuePointer {
            file_id: 1, value_offset: 100, value_len: 10, expire_at: now - 100,
        });
        let unexpired = DataBlockValue::Pointer(ValuePointer {
            file_id: 1, value_offset: 200, value_len: 10, expire_at: now + 3600,
        });
        let entries = vec![
            (encode(b"key1", 100), expired),
            (encode(b"key2", 100), unexpired),
        ];
        let job = CompactionJob::new(vec![], vec![], CompactionConfig::default());
        let out = job.filter_entries(entries)?;
        assert_eq!(out.len(), 1, "expired entry must be dropped");
        assert_eq!(InternalKey::extract_user_key(&out[0].0), Some(b"key2".as_slice()));
        Ok(())
    }

    #[test]
    fn test_filter_keeps_inline_and_drops_expired_inline() -> Result<()> {
        let now = unix_now();
        let entries = vec![
            (encode(b"key1", 100), DataBlockValue::Inline { data: b"v1".to_vec(), expire_at: 0 }),
            (encode(b"key2", 100), DataBlockValue::Inline { data: b"v2".to_vec(), expire_at: now - 100 }),
        ];
        let job = CompactionJob::new(vec![], vec![], CompactionConfig::default());
        let out = job.filter_entries(entries)?;
        assert_eq!(out.len(), 1, "expired inline entry must be dropped");
        match &out[0].1 {
            DataBlockValue::Inline { data, .. } => assert_eq!(data, b"v1"),
            _ => panic!("Expected Inline variant"),
        }
        Ok(())
    }

    fn inline(data: &[u8]) -> DataBlockValue {
        DataBlockValue::Inline { data: data.to_vec(), expire_at: 0 }
    }

    /// An in-memory SSTable of `entries`, given in any order.
    fn table(mut entries: Vec<(Vec<u8>, DataBlockValue)>) -> Arc<SSTableReader> {
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let mut builder = SSTableBuilder::new(entries.len());
        for (key, value) in entries {
            match value {
                DataBlockValue::Pointer(vp) => builder.add(key, vp),
                DataBlockValue::Inline { data, expire_at } => builder.add_inline(key, data, expire_at),
            }
        }
        Arc::new(SSTableReader::open(builder.finish().unwrap()).unwrap())
    }

    /// Writes the next output file of `run` into `files`; returns the file
    /// as read back and the summary of its writing.
    async fn write_next(run: &mut CompactionRun<'_>, files: &FileManager) -> Result<Option<(Vec<u8>, SSTableSummary)>> {
        if !run.has_next()? {
            return Ok(None);
        }
        let file_id = files.allocate_file_id();
        let mut writer = files.begin_sstable(file_id).await?;
        let summary = run.next_sstable(&mut writer).await?.expect("has_next promised an entry");
        writer.finish().await?;
        Ok(Some((std::fs::read(files.file_path(file_id))?, summary)))
    }

    /// Every output file of `job` as written to disk, with its summary.
    fn written(job: &CompactionJob) -> Result<Vec<(Vec<u8>, SSTableSummary)>> {
        block_on(async {
            let dir = tempfile::TempDir::new()?;
            let files = FileManager::new(dir.path()).await?;
            let mut run = job.compact()?;
            let mut written = Vec::new();
            while let Some(file) = write_next(&mut run, &files).await? {
                written.push(file);
            }
            Ok(written)
        })
    }

    /// Every output file of `job` as written to disk.
    fn outputs(job: &CompactionJob) -> Result<Vec<Vec<u8>>> {
        Ok(written(job)?.into_iter().map(|(file, _)| file).collect())
    }

    /// The entries of `files` in order, each as user key, stamp and value.
    fn contents(files: &[Vec<u8>]) -> Result<Vec<(Vec<u8>, u64, DataBlockValue)>> {
        let mut entries = Vec::new();
        for file in files {
            let reader = SSTableReader::open(file.clone())?;
            for entry in reader.iter() {
                let (key, value) = entry?;
                let user_key = InternalKey::extract_user_key(key).unwrap().to_vec();
                let timestamp = InternalKey::extract_timestamp(key).unwrap().as_u64();
                entries.push((user_key, timestamp, value));
            }
        }
        Ok(entries)
    }

    /// The compaction as it ran before it streamed: every entry in memory,
    /// sorted, deduplicated, filtered and cut into files. The streaming
    /// merge must produce the same bytes.
    pub(crate) fn compact_in_memory(job: &CompactionJob) -> Result<Vec<Vec<u8>>> {
        let mut all_entries: Vec<(Vec<u8>, DataBlockValue)> = Vec::new();
        for sstable in job.source_sstables.iter().rev().chain(&job.target_sstables) {
            for entry in sstable.iter() {
                let (key, dbv) = entry?;
                all_entries.push((key.to_vec(), dbv));
            }
        }
        all_entries.sort_by(|a, b| a.0.cmp(&b.0));
        all_entries.dedup_by(|later, first| later.0 == first.0);

        let mut filtered = Vec::new();
        let mut last_user_key: Option<Vec<u8>> = None;
        let mut group_done = false;
        for (encoded_key, dbv) in all_entries {
            let Some(user_key) = InternalKey::extract_user_key(&encoded_key) else {
                continue;
            };
            let Some(timestamp) = InternalKey::extract_timestamp(&encoded_key) else {
                continue;
            };
            if last_user_key.as_deref() != Some(user_key) {
                last_user_key = Some(user_key.to_vec());
                group_done = false;
            }
            if group_done {
                continue;
            }
            let oldest_kept = job.shadows_older_versions(timestamp);
            if let Some(kept) = job.retain_version(encoded_key, dbv, timestamp, oldest_kept) {
                filtered.push(kept);
            }
            group_done = oldest_kept;
        }

        let max_size = job.config.max_sstable_size;
        let mut sstables = Vec::new();
        let mut capacity_left = job.input_filter_capacity();
        let mut data_bytes_left = job.input_data_bytes();
        let mut builder = SSTableBuilder::new(output_filter_capacity(capacity_left, data_bytes_left, max_size));
        let mut current_size: usize = 0;
        let mut entries = filtered.into_iter().peekable();
        while let Some((key, dbv)) = entries.next() {
            let entry_size = match &dbv {
                DataBlockValue::Pointer(_) => std::mem::size_of::<ValuePointer>(),
                DataBlockValue::Inline { data, .. } => data.len() + 8,
            };
            current_size += key.len() + entry_size;
            let group_ends = entries.peek().is_none_or(|(next_key, _)| {
                InternalKey::extract_user_key(next_key) != InternalKey::extract_user_key(&key)
            });
            match dbv {
                DataBlockValue::Pointer(vp) => builder.add(key, vp),
                DataBlockValue::Inline { data, expire_at } => builder.add_inline(key, data, expire_at),
            }
            if group_ends && current_size >= max_size {
                let (file, summary) = builder.finish_with_summary()?;
                sstables.push(file);
                capacity_left = capacity_left.saturating_sub(summary.total_keys);
                data_bytes_left = data_bytes_left.saturating_sub(summary.data_bytes);
                builder = SSTableBuilder::new(output_filter_capacity(capacity_left, data_bytes_left, max_size));
                current_size = 0;
            }
        }
        if current_size > 0 {
            sstables.push(builder.finish()?);
        }
        Ok(sstables)
    }

    // Stamp ties across overlapping tables go to the newest source, the
    // targets come last; every other entry keeps internal key order.
    #[test]
    fn test_merge_orders_overlapping_tables_and_breaks_ties_by_newest_table() -> Result<()> {
        let oldest = table(vec![
            (encode(b"a", 10), inline(b"a-oldest")),
            (encode(b"b", 20), inline(b"b-oldest")),
            (encode(b"c", 5), inline(b"c-oldest")),
        ]);
        let middle = table(vec![
            (encode(b"a", 10), inline(b"a-middle")),
            (encode(b"b", 25), inline(b"b-middle")),
            (encode(b"d", 7), inline(b"d-middle")),
        ]);
        let newest = table(vec![
            (encode(b"a", 10), inline(b"a-newest")),
            (encode(b"b", 20), inline(b"b-newest")),
            (encode(b"c", 5), tombstone_vp()),
        ]);
        let target = table(vec![
            (encode(b"b", 20), inline(b"b-target")),
            (encode(b"e", 1), inline(b"e-target")),
        ]);
        // Every version lies above the watermark and survives, so the
        // output shows the whole merge.
        let cfg = CompactionConfig {
            low_watermark: Some(Timestamp::new(0)),
            max_sstable_size: 40,
            ..Default::default()
        };
        let job = CompactionJob::new(vec![oldest, middle, newest], vec![target], cfg);

        let files = outputs(&job)?;
        assert_eq!(
            contents(&files)?,
            vec![
                (b"a".to_vec(), 10, inline(b"a-newest")),
                (b"b".to_vec(), 25, inline(b"b-middle")),
                (b"b".to_vec(), 20, inline(b"b-newest")),
                (b"c".to_vec(), 5, tombstone_vp()),
                (b"d".to_vec(), 7, inline(b"d-middle")),
                (b"e".to_vec(), 1, inline(b"e-target")),
            ]
        );
        assert_eq!(files.len(), 3, "files end behind b and c");
        assert_eq!(files, compact_in_memory(&job)?);
        Ok(())
    }

    // The filter keeps its state per user key across tables and file ends:
    // version cut-off at the watermark, tombstone and TTL GC only bottommost.
    #[test]
    fn test_filter_on_the_merged_stream_matches_the_rules() -> Result<()> {
        let expired = || DataBlockValue::Inline { data: b"gone".to_vec(), expire_at: 1 };
        let live_until = unix_now() + 3600;
        let tables = || {
            let older = table(vec![
                (encode(b"k1", 150), inline(b"v150")),
                (encode(b"k1", 90), inline(b"v90")),
                (encode(b"k2", 80), tombstone_vp()),
                (encode(b"k3", 60), inline(b"v60")),
            ]);
            let newer = table(vec![
                (encode(b"k1", 50), inline(b"v50")),
                (encode(b"k2", 40), inline(b"v40")),
                (encode(b"k3", 120), tombstone_vp()),
            ]);
            let target = table(vec![
                (encode(b"k4", 70), expired()),
                (encode(b"k5", 70), DataBlockValue::Inline { data: b"v70".to_vec(), expire_at: live_until }),
            ]);
            (vec![older, newer], vec![target])
        };
        let config = |bottommost| CompactionConfig {
            low_watermark: Some(Timestamp::new(100)),
            bottommost,
            max_sstable_size: 30,
            ..Default::default()
        };

        let (sources, targets) = tables();
        let job = CompactionJob::new(sources, targets, config(true));
        let files = outputs(&job)?;
        assert_eq!(
            contents(&files)?,
            vec![
                (b"k1".to_vec(), 150, inline(b"v150")),
                (b"k1".to_vec(), 90, inline(b"v90")),
                (b"k3".to_vec(), 120, tombstone_vp()),
                (b"k3".to_vec(), 60, inline(b"v60")),
                (b"k5".to_vec(), 70, DataBlockValue::Inline { data: b"v70".to_vec(), expire_at: live_until }),
            ]
        );
        assert!(files.len() > 1);
        assert_eq!(files, compact_in_memory(&job)?);

        let (sources, targets) = tables();
        let job = CompactionJob::new(sources, targets, config(false));
        let files = outputs(&job)?;
        let kept: Vec<(Vec<u8>, u64)> = contents(&files)?.into_iter().map(|(key, ts, _)| (key, ts)).collect();
        assert_eq!(
            kept,
            vec![
                (b"k1".to_vec(), 150),
                (b"k1".to_vec(), 90),
                (b"k2".to_vec(), 80),
                (b"k3".to_vec(), 120),
                (b"k3".to_vec(), 60),
                (b"k4".to_vec(), 70),
                (b"k5".to_vec(), 70),
            ],
            "not bottommost: the tombstone and the expired value stay"
        );
        assert_eq!(files, compact_in_memory(&job)?);
        Ok(())
    }

    /// `tables` overlapping tables that share the keys `0..keys` round-robin,
    /// each key with a small inline value.
    fn interleaved_tables(tables: usize, keys: usize) -> Vec<Arc<SSTableReader>> {
        (0..tables)
            .map(|t| {
                table(
                    (t..keys)
                        .step_by(tables)
                        .map(|i| (encode(format!("key-{i:04}").as_bytes(), 10), inline(b"val!")))
                        .collect(),
                )
            })
            .collect()
    }

    fn blocks_read(tables: &[Arc<SSTableReader>]) -> usize {
        tables.iter().map(|t| t.blocks_read.load(std::sync::atomic::Ordering::Relaxed)).sum()
    }

    // 1200 entries of 28 bytes over three tables of two blocks each; files
    // are cut at 480 entries.
    fn file_by_file_job() -> (CompactionJob, Vec<Arc<SSTableReader>>) {
        let tables = interleaved_tables(3, 1200);
        let max_sstable_size = 1200 * 28 * 2 / 5;
        let config = CompactionConfig { max_sstable_size, ..Default::default() };
        (CompactionJob::new(tables.clone(), vec![], config), tables)
    }

    // Of a single output file, the first data block goes to the file writer
    // before the last input block is read: a write fault ends the run with
    // input blocks unread.
    #[test]
    fn test_first_data_block_is_written_before_the_last_input_block_is_read() -> Result<()> {
        let tables = interleaved_tables(3, 1200);
        let config = CompactionConfig { max_sstable_size: usize::MAX, ..Default::default() };
        let job = CompactionJob::new(tables.clone(), vec![], config);
        block_on(async {
            let dir = tempfile::TempDir::new()?;
            let files = FileManager::new(dir.path()).await?;
            let mut run = job.compact()?;
            assert!(run.has_next()?);
            let file_id = files.allocate_file_id();
            let mut writer = files.begin_sstable(file_id).await?;

            let temp_path = dir.path().join(format!("sstable_{file_id:06}.sst.tmp"));
            test_fault::fail_writes_of(&temp_path);
            let written = run.next_sstable(&mut writer).await;
            test_fault::allow_writes_of(&temp_path);
            writer.abort().await;

            assert!(written.is_err(), "the first block reaches the writer");
            let read = blocks_read(&tables);
            assert!(read < 6, "{read} of 6 input blocks read");
            Ok(())
        })
    }

    // Inputs of 2.5 times the file size give three files of up to 480
    // entries; the run holds no more than a data block of 257 entries, the
    // entry in hand and one per input.
    #[test]
    fn test_run_holds_one_data_block_and_the_input_heads() -> Result<()> {
        let (job, tables) = file_by_file_job();
        let (files, peak) = block_on(async {
            let dir = tempfile::TempDir::new()?;
            let file_manager = FileManager::new(dir.path()).await?;
            let mut run = job.compact()?;
            let mut files = Vec::new();
            while let Some((file, _)) = write_next(&mut run, &file_manager).await? {
                files.push(file);
            }
            anyhow::Ok((files, run.peak_held_entries()))
        })?;

        let largest_file = files.iter().map(|file| SSTableReader::open(file.clone()).unwrap().iter().count()).max();
        assert_eq!((files.len(), largest_file), (3, Some(480)));
        assert_eq!(blocks_read(&tables), 6, "two blocks per table");
        assert!(peak <= 257 + 1 + tables.len(), "held {peak} entries at once");
        assert_eq!(files, compact_in_memory(&job)?);
        Ok(())
    }

    // Each file's filter is sized for its share of the 3 × 400 keys left,
    // taken from the data bytes left with a margin of three: 594, 594, then
    // the 240 keys left. Together they stay below twice the input keys, each
    // covers the keys of its file, and every key passes its file's filter.
    #[test]
    fn test_each_file_filter_is_sized_for_its_share_of_the_keys_left() -> Result<()> {
        let (job, _) = file_by_file_job();
        let mut capacities = Vec::new();
        for (file, summary) in written(&job)? {
            let reader = SSTableReader::open(file)?;
            assert!(reader.bloom_capacity() >= summary.total_keys, "{} keys", summary.total_keys);
            for entry in reader.iter() {
                let (key, _) = entry?;
                assert!(reader.get(key)?.is_some(), "{key:?} must pass the filter of its file");
            }
            capacities.push(reader.bloom_capacity());
        }
        assert!(capacities.iter().sum::<usize>() <= 2 * 1200);
        assert_eq!(capacities, vec![594, 594, 240]);
        Ok(())
    }

    /// The filter capacity of each output file of `job`.
    fn output_capacities(job: &CompactionJob) -> Result<Vec<usize>> {
        let mut capacities = Vec::new();
        for file in outputs(job)? {
            let reader = SSTableReader::open(file)?;
            for entry in reader.iter() {
                let (key, _) = entry?;
                assert!(reader.get(key)?.is_some(), "{key:?} must pass the filter of its file");
            }
            capacities.push(reader.bloom_capacity());
        }
        Ok(capacities)
    }

    // The special cases of the estimate: no data bytes left give every key
    // left, a size limit of 0 gives one, an empty budget still gives one, an
    // unlimited size gives the keys left, and the worked example gives 594.
    #[test]
    fn test_output_filter_capacity_special_cases() {
        assert_eq!(output_filter_capacity(1200, 0, 13_440), 1200);
        assert_eq!(output_filter_capacity(0, 0, 13_440), 1);
        assert_eq!(output_filter_capacity(1200, 81_672, 0), 1);
        assert_eq!(output_filter_capacity(1200, 81_672, usize::MAX), 1200);
        assert_eq!(output_filter_capacity(1200, 81_672, 13_440), 594);
    }

    // Without a size limit the one file gets every input key; with a limit
    // of 0 each key gets its own file and a filter for one key.
    #[test]
    fn test_filter_of_unlimited_and_zero_file_sizes() -> Result<()> {
        let unlimited = CompactionConfig { max_sstable_size: usize::MAX, ..Default::default() };
        let job = CompactionJob::new(interleaved_tables(3, 1200), vec![], unlimited);
        assert_eq!(output_capacities(&job)?, vec![1200]);

        let zero = CompactionConfig { max_sstable_size: 0, ..Default::default() };
        let job = CompactionJob::new(interleaved_tables(3, 30), vec![], zero);
        assert_eq!(output_capacities(&job)?, vec![1; 30]);
        Ok(())
    }

    // One file per key: each output block costs more bytes than its entry
    // took in the two input blocks, so the data bytes left run out before
    // the keys do. From then on each file gets the filter for all keys left.
    #[test]
    fn test_filter_takes_the_keys_left_once_the_data_bytes_run_out() -> Result<()> {
        let input = table((0..300).map(|i| (encode(format!("k{i:03}").as_bytes(), 1), inline(b"v"))).collect());
        assert_eq!(input.key_count_bound(), 2 * 257);
        let config = CompactionConfig { max_sstable_size: 1, ..Default::default() };
        let capacities = output_capacities(&CompactionJob::new(vec![input], vec![], config))?;
        assert_eq!(capacities.len(), 300);
        assert_eq!(capacities[0], 3, "a share of one key, times three");
        let rest = capacities.iter().rev().zip(1..).take_while(|(capacity, left)| **capacity == *left).count();
        assert!(rest > 1, "capacities {capacities:?}");
        Ok(())
    }

    /// A table of the keys `key-0000..key-0999` written at `ts`, its filter
    /// sized for `filter_capacity` keys.
    fn thousand_keys(ts: u64, filter_capacity: usize) -> Arc<SSTableReader> {
        let mut builder = SSTableBuilder::new(filter_capacity);
        for i in 0..1000 {
            builder.add_inline(encode(format!("key-{i:04}").as_bytes(), ts), b"val!".to_vec(), 0);
        }
        Arc::new(SSTableReader::open(builder.finish().unwrap()).unwrap())
    }

    /// The single output file of compacting `sources` into `targets`.
    fn compact_into_one(sources: Vec<Arc<SSTableReader>>, targets: Vec<Arc<SSTableReader>>) -> Result<Arc<SSTableReader>> {
        let config = CompactionConfig {
            low_watermark: Some(Timestamp::new(u64::MAX)),
            max_sstable_size: usize::MAX,
            ..Default::default()
        };
        let mut files = outputs(&CompactionJob::new(sources, targets, config))?;
        assert_eq!(files.len(), 1);
        Ok(Arc::new(SSTableReader::open(files.remove(0))?))
    }

    // Overwriting the same 1000 keys round after round keeps the filter of
    // the compacted file at their count plus at most one block of slack.
    #[test]
    fn test_filter_does_not_grow_over_repeated_compactions() -> Result<()> {
        let mut output = compact_into_one(vec![thousand_keys(1, 1000)], vec![])?;
        let mut capacities = vec![output.bloom_capacity()];
        for round in 2..=20 {
            let bound = 1000 + output.key_count_bound();
            output = compact_into_one(vec![thousand_keys(round, 1000)], vec![output])?;
            assert!(output.bloom_capacity() <= bound, "round {round}: {} > {bound}", output.bloom_capacity());
            capacities.push(output.bloom_capacity());
        }
        assert_eq!(capacities[19], capacities[2], "capacities {capacities:?}");
        Ok(())
    }

    // An input whose filter was sized for 50 000 keys but holds 1000 counts
    // with its four blocks of up to 257 entries.
    #[test]
    fn test_oversized_input_filter_shrinks_to_its_blocks() -> Result<()> {
        let output = compact_into_one(vec![thousand_keys(2, 1000)], vec![thousand_keys(1, 50_000)])?;
        assert_eq!(output.bloom_capacity(), 1028 + 1000);
        Ok(())
    }

    // Each file's summary is what reading the file back finds, over stamp
    // ties and files of several blocks.
    #[test]
    fn test_summary_of_each_file_matches_the_file() -> Result<()> {
        let mut rng = Lcg(54);
        let sources: Vec<_> = (0..4).map(|_| random_table(&mut rng, 400)).collect();
        let targets: Vec<_> = (0..2).map(|_| random_table(&mut rng, 600)).collect();

        for max_sstable_size in [20_000, usize::MAX] {
            let config = CompactionConfig { low_watermark: Some(Timestamp::new(0)), max_sstable_size, ..Default::default() };
            let written = written(&CompactionJob::new(sources.clone(), targets.clone(), config))?;
            assert!(written.iter().any(|(_, summary)| summary.total_keys > 257), "a file of several blocks");
            for (file, summary) in written {
                let reader = SSTableReader::open(file.clone())?;
                assert_eq!(summary.file_size, file.len() as u64);
                assert_eq!(summary.total_keys, reader.iter().count());
                assert_eq!(
                    LsmStorageEngine::sstable_key_range(&reader)?,
                    (summary.smallest_key, summary.largest_key, summary.max_timestamp)
                );
            }
        }
        Ok(())
    }

    /// Deterministic pseudo-random numbers below `bound`.
    struct Lcg(u64);

    impl Lcg {
        fn below(&mut self, bound: u64) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) % bound
        }
    }

    /// A table of random versions of `key-000..key-079` with stamps up to
    /// 40, so tables share keys and identical internal keys; values are
    /// inline, vLog pointers, tombstones, NULLs and expired or live TTLs.
    fn random_table(rng: &mut Lcg, entries: usize) -> Arc<SSTableReader> {
        let mut versions = std::collections::BTreeMap::new();
        for _ in 0..entries {
            let key = encode(format!("key-{:03}", rng.below(80)).as_bytes(), 1 + rng.below(40));
            let value = match rng.below(6) {
                0 => make_vp(rng.below(1 << 20)),
                1 => tombstone_vp(),
                2 => null_vp(),
                3 => DataBlockValue::Inline { data: vec![b'e'; 5], expire_at: 1 },
                4 => DataBlockValue::Inline { data: vec![b't'; 5], expire_at: unix_now() + 3600 },
                _ => DataBlockValue::Inline { data: vec![b'v'; rng.below(40) as usize], expire_at: 0 },
            };
            versions.insert(key, value);
        }
        table(versions.into_iter().collect())
    }

    // The streaming run writes the same bytes as the in-memory compaction
    // for every watermark, depth and file size.
    #[test]
    fn test_streaming_output_is_byte_identical_to_the_in_memory_compaction() -> Result<()> {
        let mut rng = Lcg(53);
        let sources: Vec<_> = (0..4).map(|_| random_table(&mut rng, 120)).collect();
        let targets: Vec<_> = (0..2).map(|_| random_table(&mut rng, 200)).collect();

        let mut split = false;
        for low_watermark in [None, Some(Timestamp::new(0)), Some(Timestamp::new(20))] {
            for bottommost in [true, false] {
                for max_sstable_size in [0, 1, 600, usize::MAX] {
                    let config = CompactionConfig { low_watermark, bottommost, max_sstable_size, ..Default::default() };
                    let job = CompactionJob::new(sources.clone(), targets.clone(), config);
                    let files = outputs(&job)?;
                    split |= files.len() > 2;
                    assert_eq!(
                        files,
                        compact_in_memory(&job)?,
                        "watermark {low_watermark:?}, bottommost {bottommost}, file size {max_sstable_size}"
                    );
                }
            }
        }
        assert!(split, "some runs must cut several files");
        Ok(())
    }
}
