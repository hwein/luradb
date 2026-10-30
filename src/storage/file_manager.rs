//! File management for SSTables on disk.
//!
//! This module handles file I/O for SSTables, including file ID generation,
//! atomic writes, and crash-safe operations.

use crate::core::engine_runtime::spawn_io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use anyhow::{Result, Context};
use compio::fs::OpenOptions;
use compio::io::AsyncWriteAtExt;

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
        let dir = base_dir.clone();
        spawn_io(async move { compio::fs::create_dir_all(dir).await }).await?;

        // Find the highest existing file ID
        let next_file_id = Self::scan_existing_files(&base_dir)?;

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
    fn scan_existing_files(dir: &Path) -> Result<u64> {
        let mut max_id: Option<u64> = None;

        for entry in std::fs::read_dir(dir)? {
            if let Some(id) = entry?.file_name().to_str().and_then(parse_sstable_id) {
                max_id = Some(max_id.map_or(id, |m| m.max(id)));
            }
        }

        Ok(max_id.map_or(0, |id| id + 1))
    }

    /// Allocates a new file ID.
    pub fn allocate_file_id(&self) -> u64 {
        self.next_file_id.fetch_add(1, Ordering::SeqCst)
    }

    /// The directory of the SSTable files.
    pub fn dir(&self) -> &Path {
        &self.base_dir
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
    /// The written bytes, handed back so a caller can keep using them
    pub async fn write_sstable(&self, file_id: u64, data: Vec<u8>) -> Result<Vec<u8>> {
        let temp_path = self.temp_path(file_id);
        let final_path = self.file_path(file_id);

        // One I/O task from the temporary file to the rename: it runs to its
        // end even if the caller is dropped.
        spawn_io(async move {
            #[cfg(test)]
            crate::storage::test_fault::check(&temp_path).context("Failed to create temporary file")?;
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temp_path)
                .await
                .context("Failed to create temporary file")?;

            let compio::BufResult(written, data) = file.write_all_at(data, 0).await;
            written.context("Failed to write data")?;
            file.sync_all().await.context("Failed to sync data")?;

            // Atomic rename to final location
            compio::fs::rename(&temp_path, &final_path)
                .await
                .context("Failed to rename file")?;

            Ok(data)
        })
        .await
    }

    /// Creates the temporary file of SSTable `file_id` for a writer that
    /// renames it into place once finished.
    pub async fn begin_sstable(&self, file_id: u64) -> Result<SSTableFileWriter> {
        let temp_path = self.temp_path(file_id);
        let path = temp_path.clone();
        spawn_io(async move {
            #[cfg(test)]
            crate::storage::test_fault::check(&path)?;
            OpenOptions::new().write(true).create(true).truncate(true).open(&path).await.map(drop)
        })
        .await
        .context("Failed to create temporary file")?;
        Ok(SSTableFileWriter {
            temp_path,
            final_path: self.file_path(file_id),
            offset: 0,
            buffer: Vec::with_capacity(WRITE_BUFFER_SIZE),
        })
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
        let context = format!("Failed to read SSTable file: {:?}", path);
        let data = spawn_io(async move { compio::fs::read(path).await }).await.context(context)?;
        Ok(data)
    }

    /// Deletes an SSTable file.
    ///
    /// Used during compaction when SSTables are merged.
    pub async fn delete_sstable(&self, file_id: u64) -> Result<()> {
        let path = self.file_path(file_id);
        let context = format!("Failed to delete SSTable: {:?}", path);
        #[cfg(test)]
        let deleted = path.clone();
        spawn_io(async move { compio::fs::remove_file(path).await }).await.context(context)?;
        #[cfg(test)]
        crate::storage::test_trace::record(&deleted, "delete");

        Ok(())
    }

    /// Returns the list of all SSTable file IDs in the directory.
    pub async fn list_sstables(&self) -> Result<Vec<u64>> {
        let mut file_ids = Vec::new();

        for entry in std::fs::read_dir(&self.base_dir)? {
            if let Some(id) = entry?.file_name().to_str().and_then(parse_sstable_id) {
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

/// Bytes an [`SSTableFileWriter`] collects before it writes them.
const WRITE_BUFFER_SIZE: usize = 1 << 20;

/// Writes an SSTable piece by piece into its temporary file. Holds no open
/// file between writes: compio's files are not `Send`, so each write opens
/// it in its own I/O task.
pub struct SSTableFileWriter {
    temp_path: PathBuf,
    final_path: PathBuf,
    /// File offset of the first byte in `buffer`.
    offset: u64,
    buffer: Vec<u8>,
}

impl SSTableFileWriter {
    /// Appends `bytes` to the file.
    pub async fn write(&mut self, bytes: &[u8]) -> Result<()> {
        #[cfg(test)]
        crate::storage::test_fault::check(&self.temp_path).context("Failed to write data")?;
        if self.buffer.len() + bytes.len() > WRITE_BUFFER_SIZE {
            self.write_buffer().await?;
        }
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }

    async fn write_buffer(&mut self) -> Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let path = self.temp_path.clone();
        let offset = self.offset;
        let buffer = std::mem::take(&mut self.buffer);
        let mut buffer = spawn_io(async move {
            let mut file = OpenOptions::new().write(true).open(&path).await?;
            let compio::BufResult(written, buffer) = file.write_all_at(buffer, offset).await;
            written.map(|()| buffer)
        })
        .await
        .context("Failed to write data")?;
        self.offset += buffer.len() as u64;
        buffer.clear();
        self.buffer = buffer;
        Ok(())
    }

    /// Writes what is left, syncs the file and renames it into place; on an
    /// error the temporary file is deleted.
    pub async fn finish(mut self) -> Result<()> {
        let finished = self.sync_and_rename().await;
        if finished.is_err() {
            self.abort().await;
        }
        finished
    }

    async fn sync_and_rename(&mut self) -> Result<()> {
        self.write_buffer().await?;
        let temp_path = self.temp_path.clone();
        let final_path = self.final_path.clone();
        spawn_io(async move {
            let file = OpenOptions::new().write(true).open(&temp_path).await.context("Failed to sync data")?;
            #[cfg(test)]
            crate::storage::test_fault::check_sync(&temp_path).context("Failed to sync data")?;
            file.sync_all().await.context("Failed to sync data")?;
            #[cfg(test)]
            crate::storage::test_fault::check(&final_path).context("Failed to rename file")?;
            compio::fs::rename(&temp_path, &final_path).await.context("Failed to rename file")
        })
        .await
    }

    /// Deletes the temporary file.
    pub async fn abort(self) {
        let path = self.temp_path.clone();
        if let Err(e) = spawn_io(async move { compio::fs::remove_file(path).await }).await {
            tracing::warn!("cannot delete {}: {e}", self.temp_path.display());
        }
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

    #[test]
    fn test_file_manager_basic() -> Result<()> {
        crate::core::engine_runtime::block_on(async {
            let temp_dir = TempDir::new()?;
            let manager = FileManager::new(temp_dir.path()).await?;

            // Allocate file ID
            let file_id = manager.allocate_file_id();
            assert_eq!(file_id, 0);

            // Write SSTable
            let data = b"test sstable data";
            let written = manager.write_sstable(file_id, data.to_vec()).await?;

            assert_eq!(written, data);
            assert!(manager.file_path(file_id).exists());

            // Read back
            let read_data = manager.read_sstable(file_id).await?;
            assert_eq!(read_data, data);

            Ok(())
        })
    }

    #[test]
    fn test_file_manager_multiple_files() -> Result<()> {
        crate::core::engine_runtime::block_on(async {
            let temp_dir = TempDir::new()?;
            let manager = FileManager::new(temp_dir.path()).await?;

            // Write multiple files
            for i in 0..5 {
                let file_id = manager.allocate_file_id();
                let data = format!("data{}", i);
                manager.write_sstable(file_id, data.into_bytes()).await?;
            }

            // List files
            let file_ids = manager.list_sstables().await?;
            assert_eq!(file_ids, vec![0, 1, 2, 3, 4]);

            Ok(())
        })
    }

    #[test]
    fn test_file_manager_recovery() -> Result<()> {
        crate::core::engine_runtime::block_on(async {
            let temp_dir = TempDir::new()?;

            // Create files with first manager
            {
                let manager = FileManager::new(temp_dir.path()).await?;
                for _i in 0..3 {
                    let file_id = manager.allocate_file_id();
                    manager.write_sstable(file_id, b"data".to_vec()).await?;
                }
            }

            // Create new manager - should recover file IDs
            let manager = FileManager::new(temp_dir.path()).await?;
            let next_id = manager.allocate_file_id();
            assert_eq!(next_id, 3); // Should continue from highest existing ID

            Ok(())
        })
    }

    /// The names of the files in `dir`, sorted.
    fn files_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    // Pieces smaller and larger than the write buffer land in order in one
    // file under its final name.
    #[test]
    fn test_sstable_writer_writes_the_pieces_in_order() -> Result<()> {
        crate::core::engine_runtime::block_on(async {
            let temp_dir = TempDir::new()?;
            let manager = FileManager::new(temp_dir.path()).await?;
            let file_id = manager.allocate_file_id();

            let mut writer = manager.begin_sstable(file_id).await?;
            let mut expected = Vec::new();
            for i in 0..600usize {
                let len = if i == 300 { WRITE_BUFFER_SIZE * 3 / 2 } else { 4096 + i % 13 };
                let piece = vec![(i % 251) as u8; len];
                writer.write(&piece).await?;
                expected.extend_from_slice(&piece);
            }
            writer.finish().await?;

            assert!(expected.len() > 3 * WRITE_BUFFER_SIZE);
            assert_eq!(std::fs::read(manager.file_path(file_id))?, expected);
            assert_eq!(files_in(temp_dir.path()), [format!("sstable_{file_id:06}.sst")]);
            Ok(())
        })
    }

    // A temporary file that cannot be created or written: nothing stays once
    // the writer is aborted.
    #[test]
    fn test_sstable_writer_failing_to_write_leaves_no_file() -> Result<()> {
        use crate::storage::test_fault;
        crate::core::engine_runtime::block_on(async {
            let temp_dir = TempDir::new()?;
            let manager = FileManager::new(temp_dir.path()).await?;

            let file_id = manager.allocate_file_id();
            let uncreatable = manager.temp_path(file_id);
            test_fault::fail_writes_of(&uncreatable);
            let begun = manager.begin_sstable(file_id).await;
            test_fault::allow_writes_of(&uncreatable);
            assert!(begun.is_err());

            let file_id = manager.allocate_file_id();
            let mut writer = manager.begin_sstable(file_id).await?;
            writer.write(b"first block").await?;
            test_fault::fail_writes_of(&manager.temp_path(file_id));
            let written = writer.write(b"second block").await;
            test_fault::allow_writes_of(&manager.temp_path(file_id));
            assert!(written.is_err());
            writer.abort().await;

            assert!(files_in(temp_dir.path()).is_empty());
            Ok(())
        })
    }

    // A failed sync or rename ends the finish without a file left.
    #[test]
    fn test_sstable_writer_failing_to_finish_leaves_no_file() -> Result<()> {
        use crate::storage::test_fault;
        crate::core::engine_runtime::block_on(async {
            let temp_dir = TempDir::new()?;
            let manager = FileManager::new(temp_dir.path()).await?;

            let unsyncable = manager.allocate_file_id();
            let mut writer = manager.begin_sstable(unsyncable).await?;
            writer.write(b"block").await?;
            test_fault::fail_syncs_of(&manager.temp_path(unsyncable));
            let synced = writer.finish().await;
            test_fault::allow_syncs_of(&manager.temp_path(unsyncable));
            assert!(synced.is_err());

            let unrenamable = manager.allocate_file_id();
            let mut writer = manager.begin_sstable(unrenamable).await?;
            writer.write(b"block").await?;
            test_fault::fail_writes_of(&manager.file_path(unrenamable));
            let renamed = writer.finish().await;
            test_fault::allow_writes_of(&manager.file_path(unrenamable));
            assert!(renamed.is_err());

            assert!(files_in(temp_dir.path()).is_empty());
            Ok(())
        })
    }

    #[test]
    fn test_file_manager_delete() -> Result<()> {
        crate::core::engine_runtime::block_on(async {
            let temp_dir = TempDir::new()?;
            let manager = FileManager::new(temp_dir.path()).await?;

            let file_id = manager.allocate_file_id();
            manager.write_sstable(file_id, b"data".to_vec()).await?;

            // Delete file
            manager.delete_sstable(file_id).await?;

            // File should not exist
            assert!(!manager.file_path(file_id).exists());

            Ok(())
        })
    }
}
