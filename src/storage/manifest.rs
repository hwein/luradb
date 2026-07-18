//! Manifest file for LSM-Tree metadata.
//!
//! The manifest tracks which SSTables exist at which levels,
//! enabling recovery after crashes.

use serde::{Serialize, Deserialize};
use std::path::{Path, PathBuf};
use anyhow::{Result, Context};
use tokio::fs::{File, OpenOptions, rename};
use tokio::io::{AsyncWriteExt, AsyncReadExt};

/// Metadata for a single SSTable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SSTableMetadata {
    /// File ID of the SSTable
    pub file_id: u64,

    /// Level where this SSTable resides (0 = L0, 1 = L1, etc.)
    pub level: usize,

    /// Smallest key in this SSTable (for range queries)
    pub smallest_key: Vec<u8>,

    /// Largest key in this SSTable (for range queries)
    pub largest_key: Vec<u8>,

    /// Total size of the SSTable in bytes
    pub file_size: u64,
}

/// The manifest contains all metadata about SSTables in the system.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Manifest {
    /// All SSTables organized by level
    /// levels[0] = L0, levels[1] = L1, etc.
    pub levels: Vec<Vec<SSTableMetadata>>,

    /// Sequence number for manifest versions
    pub version: u64,
}

impl Manifest {
    /// Creates a new empty manifest.
    pub fn new() -> Self {
        Self {
            levels: Vec::new(),
            version: 0,
        }
    }

    /// Adds an SSTable to the manifest.
    pub fn add_sstable(&mut self, metadata: SSTableMetadata) {
        let level = metadata.level;

        // Ensure levels vector is large enough
        while self.levels.len() <= level {
            self.levels.push(Vec::new());
        }

        self.levels[level].push(metadata);
        self.version += 1;
    }

    /// Removes an SSTable from the manifest.
    pub fn remove_sstable(&mut self, level: usize, file_id: u64) -> Option<SSTableMetadata> {
        if level < self.levels.len() {
            if let Some(pos) = self.levels[level].iter().position(|meta| meta.file_id == file_id) {
                self.version += 1;
                return Some(self.levels[level].remove(pos));
            }
        }
        None
    }

    /// Returns all SSTables at a given level.
    pub fn get_level(&self, level: usize) -> &[SSTableMetadata] {
        if level < self.levels.len() {
            &self.levels[level]
        } else {
            &[]
        }
    }

    /// Returns the total number of SSTables across all levels.
    pub fn total_sstables(&self) -> usize {
        self.levels.iter().map(|level| level.len()).sum()
    }

    /// Finds SSTables that overlap with a given key range.
    ///
    /// This is useful for compaction to find SSTables that need to be merged.
    pub fn find_overlapping_sstables(
        &self,
        level: usize,
        start_key: &[u8],
        end_key: &[u8],
    ) -> Vec<SSTableMetadata> {
        if level >= self.levels.len() {
            return Vec::new();
        }

        self.levels[level]
            .iter()
            .filter(|meta| {
                // Check if ranges overlap
                !(meta.largest_key.as_slice() < start_key || meta.smallest_key.as_slice() > end_key)
            })
            .cloned()
            .collect()
    }
}

/// Manages reading and writing the manifest to disk.
pub struct ManifestManager {
    /// Path to the manifest file
    manifest_path: PathBuf,
}

impl ManifestManager {
    /// Creates a new manifest manager.
    pub fn new(base_dir: impl AsRef<Path>) -> Self {
        let manifest_path = base_dir.as_ref().join("MANIFEST");
        Self { manifest_path }
    }

    /// Loads the manifest from disk.
    ///
    /// Returns a new empty manifest if the file doesn't exist.
    pub async fn load(&self) -> Result<Manifest> {
        if !self.manifest_path.exists() {
            return Ok(Manifest::new());
        }

        let mut file = File::open(&self.manifest_path)
            .await
            .context("Failed to open manifest file")?;

        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .await
            .context("Failed to read manifest")?;

        let manifest: Manifest = serde_json::from_slice(&data)
            .context("Failed to deserialize manifest")?;

        Ok(manifest)
    }

    /// Saves the manifest to disk atomically.
    pub async fn save(&self, manifest: &Manifest) -> Result<()> {
        let temp_path = self.manifest_path.with_extension("tmp");

        // Serialize to JSON
        let data = serde_json::to_vec_pretty(manifest)
            .context("Failed to serialize manifest")?;

        // Write to temporary file
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_path)
            .await
            .context("Failed to create temporary manifest")?;

        file.write_all(&data).await.context("Failed to write manifest")?;
        file.sync_all().await.context("Failed to sync manifest")?;

        // Atomic rename
        rename(&temp_path, &self.manifest_path)
            .await
            .context("Failed to rename manifest")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_manifest_basic() {
        let mut manifest = Manifest::new();

        let meta = SSTableMetadata {
            file_id: 1,
            level: 0,
            smallest_key: b"a".to_vec(),
            largest_key: b"z".to_vec(),
            file_size: 1024,
        };

        manifest.add_sstable(meta.clone());

        assert_eq!(manifest.total_sstables(), 1);
        assert_eq!(manifest.get_level(0).len(), 1);
        assert_eq!(manifest.get_level(0)[0], meta);
    }

    #[test]
    fn test_manifest_remove() {
        let mut manifest = Manifest::new();

        manifest.add_sstable(SSTableMetadata {
            file_id: 1,
            level: 0,
            smallest_key: b"a".to_vec(),
            largest_key: b"z".to_vec(),
            file_size: 1024,
        });

        manifest.add_sstable(SSTableMetadata {
            file_id: 2,
            level: 0,
            smallest_key: b"b".to_vec(),
            largest_key: b"y".to_vec(),
            file_size: 2048,
        });

        assert_eq!(manifest.total_sstables(), 2);

        let removed = manifest.remove_sstable(0, 1);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().file_id, 1);

        assert_eq!(manifest.total_sstables(), 1);
    }

    #[test]
    fn test_manifest_find_overlapping() {
        let mut manifest = Manifest::new();

        // Add SSTables with different key ranges
        manifest.add_sstable(SSTableMetadata {
            file_id: 1,
            level: 1,
            smallest_key: b"a".to_vec(),
            largest_key: b"d".to_vec(),
            file_size: 1024,
        });

        manifest.add_sstable(SSTableMetadata {
            file_id: 2,
            level: 1,
            smallest_key: b"e".to_vec(),
            largest_key: b"h".to_vec(),
            file_size: 1024,
        });

        manifest.add_sstable(SSTableMetadata {
            file_id: 3,
            level: 1,
            smallest_key: b"i".to_vec(),
            largest_key: b"z".to_vec(),
            file_size: 1024,
        });

        // Find overlapping with range [c, f]
        let overlapping = manifest.find_overlapping_sstables(1, b"c", b"f");
        assert_eq!(overlapping.len(), 2); // Should find file 1 and 2

        assert!(overlapping.iter().any(|m| m.file_id == 1));
        assert!(overlapping.iter().any(|m| m.file_id == 2));
    }

    #[tokio::test]
    async fn test_manifest_manager() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let manager = ManifestManager::new(temp_dir.path());

        // Create and save manifest
        let mut manifest = Manifest::new();
        manifest.add_sstable(SSTableMetadata {
            file_id: 42,
            level: 1,
            smallest_key: b"key1".to_vec(),
            largest_key: b"key999".to_vec(),
            file_size: 4096,
        });

        manager.save(&manifest).await?;

        // Load it back
        let loaded = manager.load().await?;

        assert_eq!(loaded.total_sstables(), 1);
        assert_eq!(loaded.get_level(1)[0].file_id, 42);

        Ok(())
    }
}
