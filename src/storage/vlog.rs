//! `vlog` module
//!
//! The Value Log (vLog) is an append-only file that stores large values
//! separately from the LSM-Tree index (WiscKey optimisation).
//!
//! Values below the inline threshold live directly in the MemTable;
//! everything larger is written here and referenced via a `ValuePointer`.

use crate::core::storage_thread::StorageHandle;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

#[derive(Error, Debug)]
pub enum VLogError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Partial write: expected {expected} bytes, wrote {wrote}")]
    PartialWrite { expected: usize, wrote: usize },
}

/// `Local` owns the file (default). `Remote` forwards append/read to the perf/005
/// storage thread, which owns the file; `offset` then tracks the size as a
/// high-water mark for reporting only.
enum VLogMode {
    Local(tokio::sync::Mutex<File>),
    Remote(StorageHandle),
}

/// Append-only Value Log.
pub struct VLog {
    inner: VLogMode,
    /// Monotonically increasing write cursor (byte offset of the next append).
    offset: AtomicU64,
    /// Filesystem path of the backing file (needed by the Janitor for GC).
    path: PathBuf,
}

impl VLog {
    /// Opens or creates the vLog at `path` (tokio::fs path — unchanged when the
    /// storage thread is disabled).
    ///
    /// If the file already exists the cursor is positioned at the end so
    /// subsequent appends do not overwrite existing data.
    pub async fn new(path: impl AsRef<Path>) -> Result<Self, VLogError> {
        let path = path.as_ref().to_path_buf();
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .read(true)
            .open(&path)
            .await?;

        let initial_size = file.metadata().await?.len();
        file.seek(std::io::SeekFrom::Start(initial_size)).await?;

        Ok(Self {
            inner: VLogMode::Local(tokio::sync::Mutex::new(file)),
            offset: AtomicU64::new(initial_size),
            path,
        })
    }

    /// Routes all vLog I/O through the perf/005 storage thread, which owns the
    /// file. The size counter is seeded from the file's current length.
    pub fn with_storage_handle(path: impl AsRef<Path>, handle: StorageHandle) -> Self {
        let path = path.as_ref().to_path_buf();
        let initial_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        Self {
            inner: VLogMode::Remote(handle),
            offset: AtomicU64::new(initial_size),
            path,
        }
    }

    /// Appends `value` to the log and returns its start offset.
    ///
    /// The returned offset together with `value.len()` form a `ValuePointer`
    /// that the SSTable stores to identify this value later.
    pub async fn append(&self, value: &[u8]) -> Result<u64, VLogError> {
        if value.is_empty() {
            return Ok(self.offset.load(Ordering::SeqCst));
        }

        match &self.inner {
            VLogMode::Local(file) => {
                let mut file = file.lock().await;
                let offset = self.offset.fetch_add(value.len() as u64, Ordering::SeqCst);
                file.seek(std::io::SeekFrom::Start(offset)).await?;
                file.write_all(value).await?;
                Ok(offset)
            }
            VLogMode::Remote(handle) => {
                let (offset, len) = handle.vlog_append(value.to_vec()).await.map_err(vlog_remote_err)?;
                self.offset.fetch_max(offset + len as u64, Ordering::SeqCst);
                Ok(offset)
            }
        }
    }

    /// Returns the current size of the vLog in bytes.
    pub fn size_bytes(&self) -> u64 {
        self.offset.load(Ordering::Relaxed)
    }

    /// Reads `len` bytes starting at `offset`.
    pub async fn read(&self, offset: u64, len: usize) -> Result<Vec<u8>, VLogError> {
        match &self.inner {
            VLogMode::Local(file) => {
                let mut file = file.lock().await;
                file.seek(std::io::SeekFrom::Start(offset)).await?;
                let mut buf = vec![0u8; len];
                file.read_exact(&mut buf).await?;
                Ok(buf)
            }
            VLogMode::Remote(handle) => handle.vlog_read(offset, len).await.map_err(vlog_remote_err),
        }
    }

    /// Returns the current logical size of the vLog in bytes.
    ///
    /// This equals the total number of payload bytes that have been appended,
    /// which the Janitor uses to estimate the dead-byte ratio.
    pub fn size(&self) -> u64 {
        self.offset.load(Ordering::Relaxed)
    }

    /// Returns the filesystem path of this vLog file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Maps a storage-thread `anyhow` error back into the vLog's error type.
fn vlog_remote_err(e: anyhow::Error) -> VLogError {
    VLogError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
}
