//! Superversion of an LSM instance (spec kv/031 A1): every source a read
//! needs — MemTables, SSTable levels, vLog generations — as one immutable
//! value. A reader clones the current `Arc` and works on it alone; every
//! change installs a complete successor in one swap.

use crate::engines::lsm::memtable::MemTable;
use crate::storage::sstable::SSTableReader;
use crate::storage::vlog::VLog;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// One consistent state of an engine's read sources.
#[derive(Clone)]
pub(crate) struct Version {
    /// Active MemTable, the target of every write.
    pub(crate) memtable: Arc<MemTable>,
    /// Frozen MemTables waiting for their flush, oldest first.
    pub(crate) immutables: Vec<Arc<MemTable>>,
    /// MemTables claimed by a flush in flight, oldest first — the handover
    /// slot between `immutables` and L0 (spec general/028), older than every
    /// entry of `immutables`.
    pub(crate) flushing: Vec<Arc<MemTable>>,
    /// SSTables per level: L0 in flush order (newest last, key ranges may
    /// overlap), L1 and below key-disjoint within a level.
    pub(crate) levels: Vec<Vec<Arc<SSTableReader>>>,
    /// Every vLog generation a pointer in this version's sources can name.
    pub(crate) vlog: Arc<HashMap<u32, Arc<VLog>>>,
    /// The generation new values are appended to.
    pub(crate) active_vlog: Arc<VLog>,
}

impl Version {
    /// Empty sources over a single vLog generation, which is the active one.
    pub(crate) fn new(active_vlog: Arc<VLog>) -> Self {
        let mut vlog = HashMap::new();
        vlog.insert(active_vlog.id(), Arc::clone(&active_vlog));
        Self {
            memtable: Arc::new(MemTable::new()),
            immutables: Vec::new(),
            flushing: Vec::new(),
            levels: Vec::new(),
            vlog: Arc::new(vlog),
            active_vlog,
        }
    }

    /// MemTables newest-first: active, immutables newest-to-oldest, then the
    /// flushes in flight newest-to-oldest.
    pub(crate) fn memtables_newest_first(&self) -> impl Iterator<Item = &Arc<MemTable>> + '_ {
        std::iter::once(&self.memtable)
            .chain(self.immutables.iter().rev())
            .chain(self.flushing.iter().rev())
    }

    /// SSTables newest-first: L0 newest-to-oldest, then L1..Ln (key-disjoint,
    /// order irrelevant).
    pub(crate) fn sstables_newest_first(&self) -> impl Iterator<Item = &Arc<SSTableReader>> + '_ {
        self.levels
            .first()
            .into_iter()
            .flat_map(|l0| l0.iter().rev())
            .chain(self.levels.iter().skip(1).flatten())
    }

    /// SSTables of `level`, empty for a level that does not exist.
    pub(crate) fn level(&self, level: usize) -> &[Arc<SSTableReader>] {
        self.levels.get(level).map(Vec::as_slice).unwrap_or(&[])
    }

    /// The active MemTable joins the immutables (unless it is empty) and a
    /// fresh one takes its place.
    pub(crate) fn rotated(&self) -> Self {
        let mut next = self.clone();
        if !self.memtable.is_empty() {
            next.immutables.push(Arc::clone(&self.memtable));
        }
        next.memtable = Arc::new(MemTable::new());
        next
    }

    /// Makes `vlog` the append target together with a fresh MemTable: every
    /// pointer into `vlog` then lands in a MemTable that only versions knowing
    /// `vlog` hold, never in one an older version holds as active.
    pub(crate) fn with_active_vlog(&self, vlog: Arc<VLog>) -> Self {
        let mut next = self.rotated();
        Arc::make_mut(&mut next.vlog).insert(vlog.id(), Arc::clone(&vlog));
        next.active_vlog = vlog;
        next
    }

    /// Each update replaces its whole level; levels in between that do not
    /// exist yet are created empty.
    pub(crate) fn with_levels(&self, updates: Vec<(usize, Vec<Arc<SSTableReader>>)>) -> Self {
        let mut next = self.clone();
        for (level, sstables) in updates {
            while next.levels.len() <= level {
                next.levels.push(Vec::new());
            }
            next.levels[level] = sstables;
        }
        next
    }

    /// SSTables of this version whose file `next` no longer holds.
    pub(crate) fn sstables_dropped_by(&self, next: &Version) -> Vec<Arc<SSTableReader>> {
        let kept: HashSet<u64> = next.levels.iter().flatten().map(|t| t.file_id).collect();
        self.levels.iter().flatten().filter(|t| !kept.contains(&t.file_id)).cloned().collect()
    }

    /// Generation ids, ascending.
    pub(crate) fn vlog_ids(&self) -> Vec<u32> {
        let mut ids: Vec<u32> = self.vlog.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// Summed size of all generations.
    pub(crate) fn vlog_size(&self) -> u64 {
        self.vlog.values().map(|v| v.size()).sum()
    }
}

/// Holder of the current [`Version`].
pub(crate) struct VersionCell {
    current: RwLock<Arc<Version>>,
}

impl VersionCell {
    pub(crate) fn new(version: Version) -> Self {
        Self { current: RwLock::new(Arc::new(version)) }
    }

    /// The current version; the read guard lives only for the `Arc` clone.
    pub(crate) fn get(&self) -> Arc<Version> {
        Arc::clone(&self.current.read())
    }

    /// Builds the successor from the current version and swaps it in, both
    /// under the write guard: installs never interleave, and no reader sees
    /// one half done. Readers wait while `f` runs, so it does no I/O.
    pub(crate) fn install(&self, f: impl FnOnce(&Version) -> Version) {
        let mut current = self.current.write();
        let next = Arc::new(f(&current));
        let previous = std::mem::replace(&mut *current, next);
        drop(current);
        // The last holder of a retired source may unmap or close it here,
        // outside the guard.
        drop(previous);
    }
}
