//! Compaction logic for the LSM-Tree.
//!
//! Implements **Leveled Compaction** with correct MVCC tombstone GC.
//!
//! # Tombstone safety rule
//! A tombstone at timestamp T may only be dropped when `T < low_watermark`,
//! where `low_watermark` is the oldest active snapshot timestamp from the
//! `SnapshotRegistry`. This guarantees that no live reader can still observe
//! the pre-deletion state of the key.
//!
//! # Version safety rule
//! Older versions may only be dropped behind a version at `T <= low_watermark`:
//! that one is visible to the oldest active snapshot and therefore shadows
//! everything older for every registered reader. Versions above the watermark
//! may still be the newest visible version of a pinned snapshot — e.g. a
//! running backup export (spec general/006), which would otherwise silently
//! miss the key.
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

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

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
    /// Tombstones with `timestamp < low_watermark` are safe to garbage-collect.
    /// `None` means no active snapshots — tombstones must be retained.
    pub low_watermark: Option<Timestamp>,
}

impl Default for CompactionConfig {
    fn default() -> Self {
        Self {
            l0_compaction_threshold: 4,
            l1_max_size: 100 * 1024 * 1024, // 100 MB
            level_size_ratio: 10,
            max_sstable_size: 64 * 1024 * 1024, // 64 MB
            low_watermark: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Compaction Job
// ---------------------------------------------------------------------------

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
    pub fn compact(&self) -> Result<Vec<Vec<u8>>> {
        let mut all_entries: Vec<(Vec<u8>, DataBlockValue)> = Vec::new();

        for sstable in &self.source_sstables {
            for entry in sstable.iter() {
                let (key, dbv) = entry?;
                all_entries.push((key.to_vec(), dbv));
            }
        }
        for sstable in &self.target_sstables {
            for entry in sstable.iter() {
                let (key, dbv) = entry?;
                all_entries.push((key.to_vec(), dbv));
            }
        }

        // Sort by InternalKey encoding: same user key → newest version first.
        all_entries.sort_by(|a, b| a.0.cmp(&b.0));

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
    ///    active snapshots); otherwise retain.
    /// 3. **TTL**: expired values are dropped only while no older version of
    ///    the key survives them.
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
    /// unless below the low watermark, live values unless TTL-expired.
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
        // (NULL_OFFSET, kv/018) is data: it falls through to the live path
        // below — overwrites older versions, is never GC'd, has no TTL.
        let is_tombstone = matches!(
            &dbv,
            DataBlockValue::Pointer(vp) if vp.file_id == 0 && vp.value_offset == TOMBSTONE_OFFSET
        );

        if is_tombstone {
            // `timestamp < low_watermark` implies `oldest_kept`, so dropping
            // the tombstone cannot expose an older version kept above.
            let safe_to_drop = self
                .config
                .low_watermark
                .map(|lw| timestamp.as_u64() < lw.as_u64())
                .unwrap_or(false);

            return if safe_to_drop { None } else { Some((encoded_key, dbv)) };
        }

        // Drop TTL-expired live entries — but only the oldest kept one:
        // removing a version that shadows another would resurrect that one.
        let expire_at = match &dbv {
            DataBlockValue::Pointer(vp) => vp.expire_at,
            DataBlockValue::Inline { expire_at, .. } => *expire_at,
        };
        if oldest_kept && expire_at != 0 {
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

// ---------------------------------------------------------------------------
// Trigger helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// IoEngine deregistration (spec perf/004)
// ---------------------------------------------------------------------------

/// File ids deleted by a compaction that merges `src_metas` into `tgt_metas`
/// -- used by the caller to deregister them from the `IoEngine` (perf/004).
/// Compaction always replaces both inputs wholesale, so this is simply their union.
pub fn deleted_file_ids(src_metas: &[SSTableMetadata], tgt_metas: &[SSTableMetadata]) -> Vec<u64> {
    src_metas.iter().chain(tgt_metas.iter()).map(|m| m.file_id).collect()
}

// ---------------------------------------------------------------------------
// SSTable selection
// ---------------------------------------------------------------------------

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

    let mut min_key = selected[0].smallest_key.clone();
    let mut max_key = selected[0].largest_key.clone();
    for meta in &selected[1..] {
        if meta.smallest_key < min_key { min_key = meta.smallest_key.clone(); }
        if meta.largest_key > max_key { max_key = meta.largest_key.clone(); }
    }

    let target_tables =
        manifest.find_overlapping_sstables(source_level + 1, &min_key, &max_key);

    (selected, target_tables)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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

    // general/006: while an export snapshot is pinned, the version it can still
    // read must survive — keeping only the newest one loses the key silently.
    #[test]
    fn test_keeps_version_visible_at_low_watermark() -> Result<()> {
        let mut cfg = CompactionConfig::default();
        cfg.low_watermark = Some(Timestamp::new(100));
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
        let mut cfg = CompactionConfig::default();
        cfg.low_watermark = Some(Timestamp::new(100));
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
        let mut cfg = CompactionConfig::default();
        cfg.low_watermark = Some(Timestamp::new(100));
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
        let mut cfg = CompactionConfig::default();
        cfg.low_watermark = Some(Timestamp::new(100));
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
        let mut cfg = CompactionConfig::default();
        cfg.low_watermark = Some(Timestamp::new(200));
        let entries = vec![(encode(b"key1", 100), tombstone_vp())];
        let job = CompactionJob::new(vec![], vec![], cfg);
        let out = job.filter_entries(entries)?;
        assert!(out.is_empty(), "tombstone below low watermark must be dropped");
        Ok(())
    }

    #[test]
    fn test_tombstone_kept_above_low_watermark() -> Result<()> {
        let mut cfg = CompactionConfig::default();
        cfg.low_watermark = Some(Timestamp::new(50));
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

    // kv/018: a NULL record is data — it suppresses older live versions and
    // is never dropped, even below the tombstone-GC low watermark.
    #[test]
    fn test_null_record_survives_compaction_and_suppresses_older() -> Result<()> {
        let mut cfg = CompactionConfig::default();
        cfg.low_watermark = Some(Timestamp::new(500)); // everything below 500 GC-eligible
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

    #[test]
    fn test_should_compact_l0_threshold() {
        let mut manifest = Manifest::new();
        let config = CompactionConfig::default();
        assert!(!should_compact(&manifest, &config));
        for i in 0..4u64 {
            manifest.add_sstable(SSTableMetadata {
                file_id: i, level: 0,
                smallest_key: vec![0], largest_key: vec![255], file_size: 1024,
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
        }];
        let tgt = vec![SSTableMetadata {
            file_id: 10, level: 1,
            smallest_key: vec![0], largest_key: vec![255], file_size: 2048,
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
            smallest_key: b"a".to_vec(), largest_key: b"d".to_vec(), file_size: 1024,
        });
        manifest.add_sstable(SSTableMetadata {
            file_id: 2, level: 0,
            smallest_key: b"e".to_vec(), largest_key: b"h".to_vec(), file_size: 1024,
        });
        manifest.add_sstable(SSTableMetadata {
            file_id: 10, level: 1,
            smallest_key: b"c".to_vec(), largest_key: b"f".to_vec(), file_size: 2048,
        });
        manifest.add_sstable(SSTableMetadata {
            file_id: 11, level: 1,
            smallest_key: b"i".to_vec(), largest_key: b"z".to_vec(), file_size: 2048,
        });
        let (src, tgt) = select_sstables_for_compaction(&manifest);
        assert_eq!(src.len(), 2);
        assert_eq!(tgt.len(), 1);
        assert_eq!(tgt[0].file_id, 10);
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
