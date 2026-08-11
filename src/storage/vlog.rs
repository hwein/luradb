//! `vlog` module
//!
//! The Value Log (vLog) is an append-only file that stores large values
//! separately from the LSM-Tree index (WiscKey optimisation).
//!
//! Values below the inline threshold live directly in the MemTable;
//! everything larger is written here and referenced via a `ValuePointer`.
//!
//! The log is split into *generations* (spec kv/017): exactly one generation is
//! active and takes appends, older ones are sealed and read-only until the
//! Janitor has copied their live values forward. A pointer therefore carries
//! the generation id (`file_id`) it was written to, and reads resolve it
//! through the [`VLogRegistry`].

use crate::core::storage_thread::StorageHandle;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

#[derive(Error, Debug)]
pub enum VLogError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Partial write: expected {expected} bytes, wrote {wrote}")]
    PartialWrite { expected: usize, wrote: usize },
    /// The Janitor sealed this generation; the writer retries against the
    /// generation that is active now.
    #[error("Value log generation {id} is sealed")]
    Sealed { id: u32 },
    #[error("Unknown value log generation {id}")]
    UnknownGeneration { id: u32 },
}

/// `Local` owns the file (default). `Remote` forwards append/read to the perf/005
/// storage thread, which owns the file; `offset` then tracks the size as a
/// high-water mark for reporting only.
enum VLogMode {
    Local(tokio::sync::Mutex<File>),
    Remote(StorageHandle),
}

/// Append-only Value Log — one generation.
pub struct VLog {
    inner: VLogMode,
    /// Generation id, stamped into every `ValuePointer` written here.
    id: u32,
    /// Sealed generations reject appends but stay readable.
    sealed: AtomicBool,
    /// Monotonically increasing write cursor (byte offset of the next append).
    offset: AtomicU64,
    /// Filesystem path of the backing file (needed by the Janitor for GC).
    path: PathBuf,
}

impl VLog {
    /// Opens or creates the canonical vLog, which is always generation 1.
    pub async fn new(path: impl AsRef<Path>) -> Result<Self, VLogError> {
        Self::open(path, 1).await
    }

    /// Opens or creates the generation `id` vLog at `path` (tokio::fs path —
    /// unchanged when the storage thread is disabled).
    ///
    /// If the file already exists the cursor is positioned at the end so
    /// subsequent appends do not overwrite existing data.
    pub async fn open(path: impl AsRef<Path>, id: u32) -> Result<Self, VLogError> {
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
            id,
            sealed: AtomicBool::new(false),
            offset: AtomicU64::new(initial_size),
            path,
        })
    }

    /// Routes all vLog I/O through the perf/005 storage thread, which owns the
    /// file. The size counter is seeded from the file's current length.
    pub fn with_storage_handle(path: impl AsRef<Path>, handle: StorageHandle, id: u32) -> Self {
        let path = path.as_ref().to_path_buf();
        let initial_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        Self {
            inner: VLogMode::Remote(handle),
            id,
            sealed: AtomicBool::new(false),
            offset: AtomicU64::new(initial_size),
            path,
        }
    }

    /// Generation id of this log.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Seals this generation: further appends fail with [`VLogError::Sealed`],
    /// reads keep working.
    pub fn seal(&self) {
        self.sealed.store(true, Ordering::SeqCst);
    }

    pub fn is_sealed(&self) -> bool {
        self.sealed.load(Ordering::SeqCst)
    }

    /// Appends `value` to the log and returns its start offset.
    ///
    /// The returned offset together with `value.len()` and [`Self::id`] form a
    /// `ValuePointer` that the SSTable stores to identify this value later.
    pub async fn append(&self, value: &[u8]) -> Result<u64, VLogError> {
        if self.is_sealed() {
            return Err(VLogError::Sealed { id: self.id });
        }
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
                let (offset, len) =
                    handle.vlog_append(value.to_vec(), self.id).await.map_err(vlog_remote_err)?;
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
            VLogMode::Remote(handle) => {
                handle.vlog_read(offset, len, self.id).await.map_err(vlog_remote_err)
            }
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

/// Path of generation `id`: generation 1 is the canonical `base` path itself
/// (so pre-generation stores open unchanged), later ones are `<base>.<id>`.
pub fn generation_path(base: &Path, id: u32) -> PathBuf {
    if id <= 1 {
        return base.to_path_buf();
    }
    let mut name = base.as_os_str().to_os_string();
    name.push(format!(".{id}"));
    PathBuf::from(name)
}

/// Ids of all generation files present next to `base`, ascending. Generation 1
/// is always included — [`VLog::new`] creates the canonical file if missing.
pub async fn discover_generations(base: &Path) -> Result<Vec<u32>, VLogError> {
    let mut ids = vec![1u32];
    let dir = match base.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let prefix = match base.file_name().and_then(|n| n.to_str()) {
        Some(name) => format!("{name}."),
        None => return Ok(ids),
    };
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(e) => e,
        Err(_) => return Ok(ids), // no directory yet → only generation 1
    };
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        let Some(suffix) = name.to_str().and_then(|n| n.strip_prefix(&prefix)) else {
            continue;
        };
        if let Ok(id) = suffix.parse::<u32>() {
            if id >= 2 {
                ids.push(id);
            }
        }
    }
    ids.sort_unstable();
    Ok(ids)
}

/// All live vLog generations by id, plus the active one that takes appends.
///
/// The active reference stays the fast write path; readers resolve a pointer's
/// `file_id` through [`Self::read`] so values in sealed generations remain
/// reachable until the Janitor has copied them forward.
pub struct VLogRegistry {
    active: RwLock<Arc<VLog>>,
    generations: RwLock<HashMap<u32, Arc<VLog>>>,
}

impl VLogRegistry {
    /// Registry holding a single generation, which is also the active one.
    pub fn new(active: Arc<VLog>) -> Self {
        let mut generations = HashMap::new();
        generations.insert(active.id(), Arc::clone(&active));
        Self {
            active: RwLock::new(active),
            generations: RwLock::new(generations),
        }
    }

    /// The generation new values are appended to.
    pub fn active(&self) -> Arc<VLog> {
        self.active.read().clone()
    }

    /// Registers `vlog` and makes it the target of all subsequent appends.
    pub fn set_active(&self, vlog: Arc<VLog>) {
        self.generations.write().insert(vlog.id(), Arc::clone(&vlog));
        *self.active.write() = vlog;
    }

    /// Registers a non-active (readable) generation.
    pub fn register(&self, vlog: Arc<VLog>) {
        self.generations.write().insert(vlog.id(), vlog);
    }

    pub fn get(&self, id: u32) -> Option<Arc<VLog>> {
        self.generations.read().get(&id).cloned()
    }

    /// Drops a generation from the registry; readers holding an `Arc` finish
    /// against their open file descriptor.
    pub fn remove(&self, id: u32) -> Option<Arc<VLog>> {
        self.generations.write().remove(&id)
    }

    /// Registered generation ids, ascending.
    pub fn ids(&self) -> Vec<u32> {
        let mut ids: Vec<u32> = self.generations.read().keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// Summed size of all live generations.
    pub fn total_size(&self) -> u64 {
        self.generations.read().values().map(|v| v.size()).sum()
    }

    /// Resolves a pointer against its generation. An unknown `file_id` is a
    /// clean error, never a read against the wrong file.
    pub async fn read(&self, file_id: u32, offset: u64, len: usize) -> Result<Vec<u8>, VLogError> {
        let vlog = self
            .get(file_id)
            .ok_or(VLogError::UnknownGeneration { id: file_id })?;
        vlog.read(offset, len).await
    }
}

/// Maps a storage-thread `anyhow` error back into the vLog's error type.
fn vlog_remote_err(e: anyhow::Error) -> VLogError {
    VLogError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Spec kv/017 test 2: a sealed generation rejects appends but stays readable.
    #[tokio::test]
    async fn test_sealed_vlog_rejects_append_but_reads() {
        let dir = tempfile::TempDir::new().unwrap();
        let vlog = VLog::open(dir.path().join("vlog"), 1).await.unwrap();
        let offset = vlog.append(b"payload").await.unwrap();

        vlog.seal();
        assert!(vlog.is_sealed());
        match vlog.append(b"more").await {
            Err(VLogError::Sealed { id: 1 }) => {}
            other => panic!("expected Sealed, got {other:?}"),
        }
        assert_eq!(vlog.read(offset, 7).await.unwrap(), b"payload");
        assert_eq!(vlog.size(), 7, "the rejected append must not move the cursor");
    }

    // Generation 1 keeps the canonical path so pre-generation stores open
    // unchanged; later generations get the `.<id>` suffix.
    #[tokio::test]
    async fn test_generation_paths_and_discovery() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path().join("luradb.vlog");
        assert_eq!(generation_path(&base, 1), base);
        assert_eq!(generation_path(&base, 3), dir.path().join("luradb.vlog.3"));

        // Only the canonical file → generation 1 alone.
        VLog::new(&base).await.unwrap();
        assert_eq!(discover_generations(&base).await.unwrap(), vec![1]);

        VLog::open(generation_path(&base, 2), 2).await.unwrap();
        // Neither an unrelated file nor a non-numeric suffix is a generation.
        VLog::new(dir.path().join("other.vlog")).await.unwrap();
        VLog::new(dir.path().join("luradb.vlog.tmp")).await.unwrap();
        assert_eq!(discover_generations(&base).await.unwrap(), vec![1, 2]);
    }

    // Registry resolution: known ids read from their own file, unknown ids are
    // a clean error instead of a read against the wrong generation.
    #[tokio::test]
    async fn test_registry_resolves_generations() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path().join("vlog");
        let gen1 = Arc::new(VLog::new(&base).await.unwrap());
        let off1 = gen1.append(b"one").await.unwrap();
        let registry = VLogRegistry::new(gen1);

        let gen2 = Arc::new(VLog::open(generation_path(&base, 2), 2).await.unwrap());
        let off2 = gen2.append(b"two").await.unwrap();
        registry.set_active(Arc::clone(&gen2));

        assert_eq!(registry.active().id(), 2);
        assert_eq!(registry.ids(), vec![1, 2]);
        assert_eq!(registry.read(1, off1, 3).await.unwrap(), b"one");
        assert_eq!(registry.read(2, off2, 3).await.unwrap(), b"two");
        assert_eq!(registry.total_size(), 6);
        assert!(matches!(
            registry.read(7, 0, 1).await,
            Err(VLogError::UnknownGeneration { id: 7 })
        ));

        registry.remove(1);
        assert_eq!(registry.ids(), vec![2]);
    }
}
