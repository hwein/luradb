//! File management for SSTables on disk.
//!
//! This module handles file I/O for SSTables, including file ID generation,
//! atomic writes, and crash-safe operations.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use anyhow::{Result, Context};
use tokio::fs::{File, OpenOptions, rename};
use tokio::io::{AsyncWriteExt, AsyncReadExt};

/// Manages SSTable files on disk.
///
/// This manager ensures crash-safe writes using atomic rename operations
/// and maintains sequential file IDs.
pub struct FileManager {
    /// Base directory for SSTable files
    base_dir: PathBuf,

    /// Next file ID to be assigned
    next_file_id: AtomicU64,
}

/// Parses an SSTable file name `sstable_NNNNNN.sst` into its numeric ID.
fn parse_sstable_id(file_name: &str) -> Option<u64> {
    file_name.strip_prefix("sstable_")?.strip_suffix(".sst")?.parse().ok()
}

impl FileManager {
    /// Creates a new file manager.
    ///
    /// # Arguments
    /// * `base_dir` - Directory where SSTable files will be stored
    pub async fn new(base_dir: impl AsRef<Path>) -> Result<Self> {
        let base_dir = base_dir.as_ref().to_path_buf();

        // Create directory if it doesn't exist
        tokio::fs::create_dir_all(&base_dir).await?;

        // Find the highest existing file ID
        let next_file_id = Self::scan_existing_files(&base_dir).await?;

        Ok(Self {
            base_dir,
            next_file_id: AtomicU64::new(next_file_id),
        })
    }

    /// Scans existing files to determine the next file ID.
    ///
    /// Returns 0 when the directory is empty (no existing SSTables), or
    /// `max_existing_id + 1` otherwise.  Using `0` as the base avoids an
    /// off-by-one that would otherwise skip file ID 0 on a fresh database.
    async fn scan_existing_files(dir: &Path) -> Result<u64> {
        let mut max_id: Option<u64> = None;

        let mut entries = tokio::fs::read_dir(dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            if let Some(id) = entry.file_name().to_str().and_then(parse_sstable_id) {
                max_id = Some(max_id.map_or(id, |m| m.max(id)));
            }
        }

        Ok(max_id.map_or(0, |id| id + 1))
    }

    /// Allocates a new file ID.
    pub fn allocate_file_id(&self) -> u64 {
        self.next_file_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Returns the path for a given file ID.
    pub fn file_path(&self, file_id: u64) -> PathBuf {
        self.base_dir.join(format!("sstable_{:06}.sst", file_id))
    }

    /// Returns the temporary path for a file being written.
    fn temp_path(&self, file_id: u64) -> PathBuf {
        self.base_dir.join(format!("sstable_{:06}.sst.tmp", file_id))
    }

    /// Writes an SSTable to disk atomically.
    ///
    /// This uses a temporary file and atomic rename to ensure crash safety.
    ///
    /// # Arguments
    /// * `file_id` - The file ID for this SSTable
    /// * `data` - The SSTable data to write
    ///
    /// # Returns
    /// The path where the file was written
    pub async fn write_sstable(&self, file_id: u64, data: &[u8]) -> Result<PathBuf> {
        let temp_path = self.temp_path(file_id);
        let final_path = self.file_path(file_id);

        // Write to temporary file
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_path)
            .await
            .context("Failed to create temporary file")?;

        file.write_all(data).await.context("Failed to write data")?;
        file.sync_all().await.context("Failed to sync data")?;

        // Atomic rename to final location
        rename(&temp_path, &final_path)
            .await
            .context("Failed to rename file")?;

        Ok(final_path)
    }

    /// Reads an SSTable from disk.
    ///
    /// # Arguments
    /// * `file_id` - The file ID to read
    ///
    /// # Returns
    /// The SSTable data as a byte vector
    pub async fn read_sstable(&self, file_id: u64) -> Result<Vec<u8>> {
        let path = self.file_path(file_id);

        let mut file = File::open(&path)
            .await
            .context(format!("Failed to open SSTable file: {:?}", path))?;

        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .await
            .context("Failed to read SSTable data")?;

        Ok(data)
    }

    /// Deletes an SSTable file.
    ///
    /// Used during compaction when SSTables are merged.
    pub async fn delete_sstable(&self, file_id: u64) -> Result<()> {
        let path = self.file_path(file_id);

        tokio::fs::remove_file(&path)
            .await
            .context(format!("Failed to delete SSTable: {:?}", path))?;

        Ok(())
    }

    /// Returns the list of all SSTable file IDs in the directory.
    pub async fn list_sstables(&self) -> Result<Vec<u64>> {
        let mut file_ids = Vec::new();

        let mut entries = tokio::fs::read_dir(&self.base_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            if let Some(id) = entry.file_name().to_str().and_then(parse_sstable_id) {
                file_ids.push(id);
            }
        }

        file_ids.sort_unstable();
        Ok(file_ids)
    }

    /// Returns the base directory.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_parse_sstable_id() {
        assert_eq!(parse_sstable_id("sstable_000042.sst"), Some(42));
        assert_eq!(parse_sstable_id("sstable_000000.sst"), Some(0));
        assert_eq!(parse_sstable_id("sstable_000042.sst.tmp"), None);
        assert_eq!(parse_sstable_id("report.txt"), None);
        assert_eq!(parse_sstable_id("sstable_abc.sst"), None);
        assert_eq!(parse_sstable_id("sstable_.sst"), None);
    }

    #[tokio::test]
    async fn test_file_manager_basic() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let manager = FileManager::new(temp_dir.path()).await?;

        // Allocate file ID
        let file_id = manager.allocate_file_id();
        assert_eq!(file_id, 0);

        // Write SSTable
        let data = b"test sstable data";
        let path = manager.write_sstable(file_id, data).await?;

        assert!(path.exists());

        // Read back
        let read_data = manager.read_sstable(file_id).await?;
        assert_eq!(read_data, data);

        Ok(())
    }

    #[tokio::test]
    async fn test_file_manager_multiple_files() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let manager = FileManager::new(temp_dir.path()).await?;

        // Write multiple files
        for i in 0..5 {
            let file_id = manager.allocate_file_id();
            let data = format!("data{}", i);
            manager.write_sstable(file_id, data.as_bytes()).await?;
        }

        // List files
        let file_ids = manager.list_sstables().await?;
        assert_eq!(file_ids, vec![0, 1, 2, 3, 4]);

        Ok(())
    }

    #[tokio::test]
    async fn test_file_manager_recovery() -> Result<()> {
        let temp_dir = TempDir::new()?;

        // Create files with first manager
        {
            let manager = FileManager::new(temp_dir.path()).await?;
            for _i in 0..3 {
                let file_id = manager.allocate_file_id();
                manager.write_sstable(file_id, b"data").await?;
            }
        }

        // Create new manager - should recover file IDs
        let manager = FileManager::new(temp_dir.path()).await?;
        let next_id = manager.allocate_file_id();
        assert_eq!(next_id, 3); // Should continue from highest existing ID

        Ok(())
    }

    #[tokio::test]
    async fn test_file_manager_delete() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let manager = FileManager::new(temp_dir.path()).await?;

        let file_id = manager.allocate_file_id();
        manager.write_sstable(file_id, b"data").await?;

        // Delete file
        manager.delete_sstable(file_id).await?;

        // File should not exist
        assert!(!manager.file_path(file_id).exists());

        Ok(())
    }
}
