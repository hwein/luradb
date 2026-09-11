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
//! through the generation map of the reader's own engine version.

use crate::core::storage_thread::StorageHandle;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

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

/// How appends reach the file. `Local` owns a write handle (default).
/// `Remote` forwards appends to the perf/005 storage thread, which owns the
/// file; `offset` then tracks the size as a high-water mark for reporting only.
enum VLogMode {
    Local(tokio::sync::Mutex<File>),
    Remote(StorageHandle),
}

/// Append-only Value Log — one generation.
pub struct VLog {
    inner: VLogMode,
    /// Read-only descriptor for positional reads in both modes: no cursor, no
    /// lock, any thread at once (spec kv/031 A5).
    reader: std::fs::File,
    /// Generation id, stamped into every `ValuePointer` written here.
    id: u32,
    /// Sealed generations reject appends but stay readable.
    sealed: AtomicBool,
    /// Monotonically increasing write cursor (byte offset of the next append).
    offset: AtomicU64,
    /// Filesystem path of the backing file (needed by the Janitor for GC).
    path: PathBuf,
    /// Test-only count of reads handed to the blocking pool.
    #[cfg(test)]
    offloaded: AtomicU64,
}

/// Cold reads on the blocking pool at a time, process-wide: enough to keep a
/// fast SSD's queue full, far below the pool's 512 threads that WAL commits
/// and file writes need as well.
const COLD_READ_LIMIT: usize = 64;

static COLD_READS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(COLD_READ_LIMIT);

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
        let reader = File::open(&path).await?.into_std().await;

        Ok(Self {
            inner: VLogMode::Local(tokio::sync::Mutex::new(file)),
            reader,
            id,
            sealed: AtomicBool::new(false),
            offset: AtomicU64::new(initial_size),
            path,
            #[cfg(test)]
            offloaded: AtomicU64::new(0),
        })
    }

    /// Routes appends through the perf/005 storage thread, which owns the file
    /// and has already created it. The size counter is seeded from the file's
    /// current length.
    pub fn with_storage_handle(path: impl AsRef<Path>, handle: StorageHandle, id: u32) -> Result<Self, VLogError> {
        let path = path.as_ref().to_path_buf();
        let initial_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            inner: VLogMode::Remote(handle),
            reader: std::fs::File::open(&path)?,
            id,
            sealed: AtomicBool::new(false),
            offset: AtomicU64::new(initial_size),
            path,
            #[cfg(test)]
            offloaded: AtomicU64::new(0),
        })
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
                // tokio completes the write in the background; the bytes must
                // be in the file before the pointer is handed out, since
                // reads go through `reader`, not this handle.
                file.flush().await?;
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

    /// Reads `len` bytes starting at `offset`, positionally on this
    /// generation's own descriptor — in both modes, never through the
    /// storage thread (spec kv/031 A5). Blocks the calling thread until the
    /// bytes are there; see [`Self::read_async`].
    pub fn read(&self, offset: u64, len: usize) -> Result<Vec<u8>, VLogError> {
        let mut buf = vec![0u8; len];
        self.reader.read_exact_at(&mut buf, offset)?;
        Ok(buf)
    }

    /// Reads like [`Self::read`], but never waits for the disk on the calling
    /// thread: what the page cache holds is read in place, the rest on the
    /// blocking pool, by at most [`COLD_READ_LIMIT`] reads at a time.
    pub async fn read_async(self: &Arc<Self>, offset: u64, len: usize) -> Result<Vec<u8>, VLogError> {
        let mut buf = vec![0u8; len];
        let cached = self.read_cached(&mut buf, offset);
        if cached == len {
            return Ok(buf);
        }
        // Waits here, not in the pool: a read dropped meanwhile takes no thread.
        let permit = COLD_READS.acquire().await.map_err(|e| VLogError::Io(std::io::Error::other(e)))?;
        #[cfg(test)]
        self.offloaded.fetch_add(1, Ordering::Relaxed);
        let vlog = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            vlog.reader.read_exact_at(&mut buf[cached..], offset + cached as u64)?;
            Ok(buf)
        })
        .await
        .map_err(|e| VLogError::Io(std::io::Error::other(e)))?
    }

    /// Fills `buf` from `offset` as far as the page cache holds it, without
    /// blocking (`RWF_NOWAIT`); the bytes read, 0 on any error.
    fn read_cached(&self, buf: &mut [u8], offset: u64) -> usize {
        let iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
        // SAFETY: `iov` describes `buf`, which outlives the call.
        let read = unsafe {
            libc::preadv2(self.reader.as_raw_fd(), &iov, 1, offset as libc::off_t, libc::RWF_NOWAIT)
        };
        usize::try_from(read).unwrap_or(0)
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

/// Maps a storage-thread `anyhow` error back into the vLog's error type.
fn vlog_remote_err(e: anyhow::Error) -> VLogError {
    VLogError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

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
        assert_eq!(vlog.read(offset, 7).unwrap(), b"payload");
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

    // Spec kv/031 test 7: reads are positional on the generation's own
    // descriptor -- two threads read one generation at once, each gets
    // exactly its bytes, and neither moves the append cursor.
    #[tokio::test]
    async fn test_two_threads_read_one_generation_at_once() {
        let dir = tempfile::TempDir::new().unwrap();
        let vlog = Arc::new(VLog::new(dir.path().join("vlog")).await.unwrap());
        let mut entries = Vec::new();
        for i in 0..64u8 {
            let value = vec![i; 100 + i as usize];
            entries.push((vlog.append(&value).await.unwrap(), value));
        }
        let entries = Arc::new(entries);
        let size = vlog.size();

        let readers: Vec<_> = (0..2)
            .map(|t| {
                let vlog = Arc::clone(&vlog);
                let entries = Arc::clone(&entries);
                std::thread::spawn(move || {
                    for round in 0..200 {
                        let (offset, value) = &entries[(round * 7 + t * 13) % entries.len()];
                        assert_eq!(&vlog.read(*offset, value.len()).unwrap(), value);
                    }
                })
            })
            .collect();
        for reader in readers {
            reader.join().unwrap();
        }

        assert_eq!(vlog.size(), size);
        assert_eq!(vlog.append(b"next").await.unwrap(), size, "appends continue at the cursor");
    }

    // `read_async` takes what the page cache holds in place and reads the
    // rest off the calling thread, from where the cached part ends: all,
    // part or none of the value cached, exactly the appended bytes, and a
    // read past the end is an error, never a short value.
    #[tokio::test]
    async fn test_read_async_returns_the_bytes_cached_or_not() {
        let dir = tempfile::TempDir::new().unwrap();
        let vlog = Arc::new(VLog::new(dir.path().join("vlog")).await.unwrap());
        let value: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
        let offset = vlog.append(&value).await.unwrap();
        assert_eq!(vlog.read_async(offset, value.len()).await.unwrap(), value);
        assert!(vlog.read_async(vlog.size(), 1).await.is_err());

        let file = std::fs::File::open(vlog.path()).unwrap();
        file.sync_all().unwrap();
        let advise = |advice| {
            assert_eq!(unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, advice) }, 0);
        };
        // Drops the file's clean pages, after a blocking read that waits out
        // any readahead still in flight (pages under I/O would stay). The
        // whole file: a large folio reaching below a range start stays too.
        let drop_pages = || {
            assert_eq!(vlog.read(offset, value.len()).unwrap(), value);
            advise(libc::POSIX_FADV_DONTNEED);
        };
        // Caches the first half alone: `file` reads without readahead.
        advise(libc::POSIX_FADV_RANDOM);
        let half = value.len() / 2;
        let cache_first_half = || {
            let mut first = vec![0u8; half];
            file.read_exact_at(&mut first, offset).unwrap();
        };
        let mut buf = vec![0u8; value.len()];

        drop_pages();
        let cached = vlog.read_cached(&mut buf, offset);
        if cached == value.len() {
            return; // the filesystem keeps its pages regardless of the advice
        }
        assert_eq!(cached, 0, "nothing is cached");
        drop_pages();
        assert_eq!(vlog.read_async(offset, value.len()).await.unwrap(), value);

        drop_pages();
        cache_first_half();
        let cached = vlog.read_cached(&mut buf, offset);
        assert!(0 < cached && cached < value.len(), "only the first half is cached, read {cached}");
        drop_pages();
        cache_first_half();
        assert_eq!(vlog.read_async(offset, value.len()).await.unwrap(), value);
    }

    // Past the end nothing is cached, so the read needs the blocking pool.
    // With every permit taken it waits for one without a thread, and a read
    // dropped while it waits never takes one.
    #[tokio::test]
    async fn test_a_cold_read_waits_for_a_permit_before_it_takes_a_thread() {
        use futures::FutureExt;
        let dir = tempfile::TempDir::new().unwrap();
        let vlog = Arc::new(VLog::new(dir.path().join("vlog")).await.unwrap());
        vlog.append(b"payload").await.unwrap();

        let all = COLD_READS.acquire_many(COLD_READ_LIMIT as u32).await.unwrap();
        assert!(vlog.read_async(vlog.size(), 1).now_or_never().is_none(), "the read waits for a permit");
        assert_eq!(vlog.offloaded.load(Ordering::Relaxed), 0, "a read dropped while it waits takes no thread");

        drop(all);
        assert!(vlog.read_async(vlog.size(), 1).await.is_err());
        assert_eq!(vlog.offloaded.load(Ordering::Relaxed), 1);
    }
}
