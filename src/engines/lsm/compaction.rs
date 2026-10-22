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
use crate::storage::sstable::{SSTableBuilder, SSTableReader};
use crate::storage::format::{is_expired, DataBlockValue, ValuePointer, TOMBSTONE_OFFSET};
use crate::storage::manifest::{Manifest, SSTableMetadata};
use anyhow::Result;
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

    /// Runs the compaction job and returns the raw bytes of the new SSTables.
    ///
    /// Tables enter the merge newest first, in the read path's order: the
    /// sources reversed, then the targets, which sit one level below and are
    /// older than every source. Of identical internal keys (a stamp tie) only
    /// the newest source's entry is kept, the one reads see.
    pub fn compact(&self) -> Result<Vec<Vec<u8>>> {
        let mut all_entries: Vec<(Vec<u8>, DataBlockValue)> = Vec::new();

        for sstable in self.source_sstables.iter().rev().chain(&self.target_sstables) {
            for entry in sstable.iter() {
                let (key, dbv) = entry?;
                all_entries.push((key.to_vec(), dbv));
            }
        }

        // Sort by InternalKey encoding: same user key → newest version first;
        // stable, so identical keys keep the table order above.
        all_entries.sort_by(|a, b| a.0.cmp(&b.0));
        all_entries.dedup_by(|later, first| later.0 == first.0);

        let filtered = self.filter_entries(all_entries)?;
        self.build_sstables(filtered)
    }

    /// Filters the merged, sorted entry stream (newest version first per key).
    ///
    /// Per user-key group:
    /// 1. **Version deduplication**: keep versions down to and including the
    ///    first one that shadows all older ones (see
    ///    [`Self::shadows_older_versions`]); drop the rest.
    /// 2. **Tombstone GC**: drop when `timestamp < low_watermark` (safe for all
    ///    active snapshots) and the job is bottommost; otherwise retain.
    /// 3. **TTL**: expired values are dropped only by a bottommost job and only
    ///    while no older version of the key survives them.
    fn filter_entries(
        &self,
        entries: Vec<(Vec<u8>, DataBlockValue)>,
    ) -> Result<Vec<(Vec<u8>, DataBlockValue)>> {
        let mut result = Vec::new();
        let mut last_user_key: Option<Vec<u8>> = None;
        let mut group_done = false;

        for (encoded_key, dbv) in entries {
            let Some(user_key) = InternalKey::extract_user_key(&encoded_key) else {
                continue;
            };
            let Some(timestamp) = InternalKey::extract_timestamp(&encoded_key) else {
                continue;
            };

            let new_key = last_user_key.as_deref() != Some(user_key);
            if new_key {
                last_user_key = Some(user_key.to_vec());
                group_done = false;
            }

            if group_done {
                continue;
            }

            let oldest_kept = self.shadows_older_versions(timestamp);
            if let Some(kept) = self.retain_version(encoded_key, dbv, timestamp, oldest_kept) {
                result.push(kept);
            }
            group_done = oldest_kept;
        }

        Ok(result)
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

    /// Serialises filtered entries into one or more SSTable byte buffers.
    ///
    /// A file is only cut behind the last version of a user key: the read path
    /// treats the tables of a level as key-disjoint and would otherwise pick an
    /// older version from a sibling file.
    fn build_sstables(&self, entries: Vec<(Vec<u8>, DataBlockValue)>) -> Result<Vec<Vec<u8>>> {
        let max_sstable_size = self.config.max_sstable_size;

        let mut sstables: Vec<Vec<u8>> = Vec::new();
        let mut builder = SSTableBuilder::new();
        let mut current_size: usize = 0;

        let mut entries = entries.into_iter().peekable();
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
                DataBlockValue::Inline { data, expire_at } => {
                    builder.add_inline(key, data, expire_at)
                }
            }

            if group_ends && current_size >= max_sstable_size {
                sstables.push(builder.finish()?);
                builder = SSTableBuilder::new();
                current_size = 0;
            }
        }

        if current_size > 0 {
            sstables.push(builder.finish()?);
        }

        Ok(sstables)
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
mod tests {
    use super::*;

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
}
