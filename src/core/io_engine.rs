//! Registered-buffer I/O via tokio-uring 0.5's `FixedBufPool` (spec perf/004).
//!
//! `IoEngine` allocates and registers a pool of fixed (kernel-pinned) buffers
//! and tracks open file handles by logical id (SSTables use their file id, the
//! WAL and VLog the reserved high ids below). All methods must run inside a
//! `tokio-uring` runtime.
//!
//! Scaffolding only: nothing here is on the hot path yet. The WAL/VLog/SSTable
//! I/O paths are unchanged; spec 005 wires `IoEngine` into a dedicated storage
//! thread that actually uses `read_fixed`/`write_fixed`.

use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::path::Path;
use tokio_uring::buf::fixed::{FixedBuf, FixedBufPool};
use tokio_uring::buf::{BoundedBuf, Slice};
use tokio_uring::fs::{File, OpenOptions};

/// SSTable ids are allocated upwards from 0 (`FileManager`), so the WAL and
/// VLog get reserved ids at the top of the range — one shared namespace,
/// no collisions.
pub const WAL_LOGICAL_ID: u64 = u64::MAX;
pub const VLOG_LOGICAL_ID: u64 = u64::MAX - 1;

/// Maps a logical file id to an open `tokio-uring` file handle.
///
/// No Fixed-File registration yet (that is spec 005's raw `io-uring` work) —
/// these are regular file descriptors opened through `tokio-uring`.
pub struct FileHandleMap {
    handles: HashMap<u64, File>,
}

impl FileHandleMap {
    pub fn new() -> Self {
        Self { handles: HashMap::new() }
    }

    /// Opens `path` read-write (creating it if missing) and tracks the handle
    /// under `logical_id`. Replaces any handle already registered for that id.
    pub async fn register_file(&mut self, logical_id: u64, path: &Path) -> Result<()> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)
            .await
            .with_context(|| format!("failed to open {} for logical id {logical_id}", path.display()))?;
        self.handles.insert(logical_id, file);
        Ok(())
    }

    /// Drops the tracked handle. tokio-uring 0.5 closes the fd synchronously on
    /// drop (a blocking `close(2)`), which briefly stalls other tasks on the
    /// current-thread runtime — relevant once this is used on the hot path.
    /// No-op if the id was not registered.
    pub fn unregister_file(&mut self, logical_id: u64) -> Result<()> {
        self.handles.remove(&logical_id);
        Ok(())
    }

    /// Looks up the handle registered for `logical_id`.
    pub fn get_file(&self, logical_id: u64) -> Option<&File> {
        self.handles.get(&logical_id)
    }
}

impl Default for FileHandleMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Registered-buffer pool plus file-handle bookkeeping for the WAL, VLog, and
/// SSTables. See module docs — not on the hot path in this spec.
pub struct IoEngine {
    buf_pool: FixedBufPool<Vec<u8>>,
    /// Capacity of every slot in `buf_pool`; `FixedBufPool::try_next` is keyed
    /// by requested capacity, so every checkout needs this.
    buffer_size: usize,
    file_handles: FileHandleMap,
}

impl IoEngine {
    /// Allocates `buffer_count` buffers of `buffer_size` bytes each and
    /// registers them with the kernel (`io_uring_register`). Must be called
    /// from within a `tokio-uring` runtime — the underlying
    /// `FixedBufPool::register` panics otherwise.
    ///
    /// Returns `Err` (rather than panicking) when the kernel rejects the
    /// registration itself, e.g. on kernels older than 5.4 without
    /// `IORING_REGISTER_BUFFERS`. Callers should log a warning and continue
    /// without an `IoEngine` in that case.
    pub fn new(buffer_count: usize, buffer_size: usize) -> Result<Self> {
        let bufs = std::iter::repeat_with(move || Vec::with_capacity(buffer_size)).take(buffer_count);
        let buf_pool = FixedBufPool::new(bufs);
        buf_pool
            .register()
            .context("kernel rejected registered-buffer setup (needs Linux 5.4+)")?;
        Ok(Self { buf_pool, buffer_size, file_handles: FileHandleMap::new() })
    }

    /// Opens and tracks the file at `path` under `logical_id` (SSTables:
    /// their file id; WAL/VLog: [`WAL_LOGICAL_ID`]/[`VLOG_LOGICAL_ID`]).
    pub async fn register_file(&mut self, logical_id: u64, path: &Path) -> Result<()> {
        self.file_handles.register_file(logical_id, path).await
    }

    /// Deregisters `logical_id`, e.g. after compaction deletes the SSTable.
    pub fn unregister_file(&mut self, logical_id: u64) -> Result<()> {
        self.file_handles.unregister_file(logical_id)
    }

    /// Looks up the file handle registered for `logical_id`.
    pub fn get_file(&self, logical_id: u64) -> Option<&File> {
        self.file_handles.get_file(logical_id)
    }

    /// Checks out a free registered buffer for the caller to fill (e.g. via
    /// `FixedBuf::put_slice`) before [`Self::write_fixed`]. `None` means the
    /// pool is exhausted — a backpressure signal for the caller.
    pub fn checkout_buffer(&self) -> Option<FixedBuf> {
        self.buf_pool.try_next(self.buffer_size)
    }

    /// Reads up to `len` bytes at `offset` from `logical_id` into a registered
    /// buffer — no kernel-side re-mapping of the memory per call. The returned
    /// view is bounded to the `n` bytes actually read, not the buffer's raw
    /// init_len: a reused pool slot keeps a previous (larger) op's init_len, so
    /// returning the bare `FixedBuf` would expose stale bytes past `n`.
    pub async fn read_fixed(&self, logical_id: u64, offset: u64, len: u32) -> Result<Slice<FixedBuf>> {
        let len = len as usize;
        anyhow::ensure!(
            len <= self.buffer_size,
            "requested read of {len} bytes exceeds the registered buffer size of {}",
            self.buffer_size
        );
        let file = self
            .file_handles
            .get_file(logical_id)
            .ok_or_else(|| anyhow!("File not registered: {logical_id}"))?;
        let buf = self
            .checkout_buffer()
            .ok_or_else(|| anyhow!("Buffer pool exhausted"))?;

        let (result, slice) = file.read_fixed_at(buf.slice(0..len), offset).await;
        let n = result?;
        Ok(slice.slice(0..n))
    }

    /// Writes the buffer's first `len` bytes into `logical_id` at `offset`.
    /// `len` is the caller's intent and is enforced explicitly: a reused pool
    /// slot carries the previous op's (larger) init_len, and `write_fixed_at`
    /// would otherwise persist that many bytes — leaking stale slot data past
    /// the real payload. The buffer returns to the pool once it drops.
    pub async fn write_fixed(&self, logical_id: u64, offset: u64, buf: FixedBuf, len: usize) -> Result<()> {
        anyhow::ensure!(
            len <= buf.bytes_init(),
            "write_fixed: requested {len} bytes but only {} are initialized in the buffer",
            buf.bytes_init()
        );
        let file = self
            .file_handles
            .get_file(logical_id)
            .ok_or_else(|| anyhow!("File not registered: {logical_id}"))?;
        let (result, _buf) = file.write_fixed_at(buf.slice(0..len), offset).await;
        result?;
        Ok(())
    }

    /// fdatasync on `logical_id` for durability.
    pub async fn fsync(&self, logical_id: u64) -> Result<()> {
        let file = self
            .file_handles
            .get_file(logical_id)
            .ok_or_else(|| anyhow!("File not registered: {logical_id}"))?;
        file.sync_data().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Only needed for `FixedBuf::put_slice` in the write-path tests below.
    use tokio_uring::buf::BoundedBufMut;

    fn small_pool(slots: usize, size: usize) -> FixedBufPool<Vec<u8>> {
        FixedBufPool::new(std::iter::repeat_with(move || Vec::with_capacity(size)).take(slots))
    }

    // 1. FixedBufPool -- try_next() gibt Buffer zurueck, Drop gibt ihn zurueck an den Pool.
    #[test]
    fn test_fixed_buf_pool_checkin_on_drop() {
        tokio_uring::start(async {
            let pool = small_pool(1, 64);
            pool.register().unwrap();

            let buf = pool.try_next(64).unwrap();
            assert!(pool.try_next(64).is_none(), "sole slot must be checked out");
            drop(buf);
            assert!(pool.try_next(64).is_some(), "slot must return to the pool on drop");
        });
    }

    // 2. FixedBufPool -- Alle Slots belegt -> try_next() gibt None.
    #[test]
    fn test_fixed_buf_pool_exhausted() {
        tokio_uring::start(async {
            let pool = small_pool(2, 64);
            pool.register().unwrap();

            let _a = pool.try_next(64).unwrap();
            let _b = pool.try_next(64).unwrap();
            assert!(pool.try_next(64).is_none());
        });
    }

    // 3. FileHandleMap -- register_file() + get_file() -> korrekter Handle.
    #[test]
    fn test_file_handle_map_register_and_get() {
        tokio_uring::start(async {
            let dir = tempfile::TempDir::new().unwrap();
            let path = dir.path().join("a.dat");
            let mut map = FileHandleMap::new();
            map.register_file(7, &path).await.unwrap();
            assert!(map.get_file(7).is_some());
            assert!(map.get_file(8).is_none());
        });
    }

    // 4. FileHandleMap -- unregister_file() -> Handle entfernt, get_file() -> None.
    #[test]
    fn test_file_handle_map_unregister() {
        tokio_uring::start(async {
            let dir = tempfile::TempDir::new().unwrap();
            let path = dir.path().join("b.dat");
            let mut map = FileHandleMap::new();
            map.register_file(3, &path).await.unwrap();
            map.unregister_file(3).unwrap();
            assert!(map.get_file(3).is_none());
        });
    }

    // 5. IoEngine::read_fixed() -- Testdaten schreiben, registrieren, per registered buffer lesen.
    #[test]
    fn test_io_engine_read_fixed_reads_correct_data() {
        tokio_uring::start(async {
            let dir = tempfile::TempDir::new().unwrap();
            let path = dir.path().join("read.dat");
            let data = b"hello registered buffers".to_vec();
            std::fs::write(&path, &data).unwrap();

            let mut engine = IoEngine::new(2, 4096).unwrap();
            engine.register_file(0, &path).await.unwrap();

            let buf = engine.read_fixed(0, 0, data.len() as u32).await.unwrap();
            assert_eq!(&buf[..], data.as_slice());
        });
    }

    // 6. IoEngine::write_fixed() -- per registered buffer schreiben, mit Standard-Read pruefen.
    #[test]
    fn test_io_engine_write_fixed_writes_correct_data() {
        tokio_uring::start(async {
            let dir = tempfile::TempDir::new().unwrap();
            let path = dir.path().join("write.dat");

            let mut engine = IoEngine::new(2, 4096).unwrap();
            engine.register_file(0, &path).await.unwrap();

            let payload = b"written via fixed buffer";
            let mut buf = engine.checkout_buffer().unwrap();
            buf.put_slice(payload);
            engine.write_fixed(0, 0, buf, payload.len()).await.unwrap();

            let on_disk = std::fs::read(&path).unwrap();
            assert_eq!(on_disk.as_slice(), payload.as_slice());
        });
    }

    // 7. IoEngine::fsync() -- kein Fehler nach Write + Fsync.
    #[test]
    fn test_io_engine_fsync_after_write() {
        tokio_uring::start(async {
            let dir = tempfile::TempDir::new().unwrap();
            let path = dir.path().join("sync.dat");

            let mut engine = IoEngine::new(2, 4096).unwrap();
            engine.register_file(0, &path).await.unwrap();

            let payload = b"durable";
            let mut buf = engine.checkout_buffer().unwrap();
            buf.put_slice(payload);
            engine.write_fixed(0, 0, buf, payload.len()).await.unwrap();

            engine.fsync(0).await.unwrap();
        });
    }

    // Reading an unregistered logical id must be a clear error, not a panic.
    #[test]
    fn test_io_engine_read_fixed_reports_missing_file() {
        tokio_uring::start(async {
            let engine = IoEngine::new(1, 4096).unwrap();
            // `.err().unwrap()` rather than `.unwrap_err()`: the Ok type
            // `Slice<FixedBuf>` is not `Debug`, which `unwrap_err` would require.
            let err = engine.read_fixed(99, 0, 10).await.err().unwrap();
            assert!(err.to_string().contains("not registered"));
        });
    }

    // Regression (perf/004 finding 1): a pool slot keeps the previous op's
    // init_len across check-in. A large write then a smaller one over the SAME
    // slot must persist only the smaller payload, not the leftover bytes.
    #[test]
    fn test_io_engine_write_fixed_reused_slot_no_stale_leak() {
        tokio_uring::start(async {
            let dir = tempfile::TempDir::new().unwrap();
            let big_path = dir.path().join("big.dat");
            let small_path = dir.path().join("small.dat");

            let mut engine = IoEngine::new(1, 4096).unwrap(); // single slot forces reuse
            engine.register_file(0, &big_path).await.unwrap();
            engine.register_file(1, &small_path).await.unwrap();

            // Large write bumps the sole slot's init_len to 100.
            let mut buf = engine.checkout_buffer().unwrap();
            buf.put_slice(&vec![b'X'; 100]);
            engine.write_fixed(0, 0, buf, 100).await.unwrap();

            // Small write reuses that slot; the file must hold exactly 4 bytes.
            let small = b"tiny";
            let mut buf = engine.checkout_buffer().unwrap();
            buf.put_slice(small);
            engine.write_fixed(1, 0, buf, small.len()).await.unwrap();

            assert_eq!(
                std::fs::read(&small_path).unwrap().as_slice(),
                small.as_slice(),
                "reused slot must not leak the previous write's bytes"
            );
        });
    }

    // Regression (perf/004 finding 1): read must return a view of exactly the
    // n bytes read, even when the reused slot carries a larger init_len.
    #[test]
    fn test_io_engine_read_fixed_reused_slot_exact_len() {
        tokio_uring::start(async {
            let dir = tempfile::TempDir::new().unwrap();
            let big_path = dir.path().join("rbig.dat");
            let small_path = dir.path().join("rsmall.dat");
            std::fs::write(&big_path, vec![b'Y'; 100]).unwrap();
            std::fs::write(&small_path, b"hi").unwrap();

            let mut engine = IoEngine::new(1, 4096).unwrap(); // single slot forces reuse
            engine.register_file(0, &big_path).await.unwrap();
            engine.register_file(1, &small_path).await.unwrap();

            // Large read bumps the sole slot's init_len to 100.
            let big = engine.read_fixed(0, 0, 100).await.unwrap();
            assert_eq!(big.len(), 100);
            drop(big); // return the slot to the pool

            // Small read reuses that slot; the view must expose exactly 2 bytes.
            let small = engine.read_fixed(1, 0, 2).await.unwrap();
            assert_eq!(&small[..], b"hi", "reused slot read must not expose stale bytes");
            assert_eq!(small.len(), 2);
        });
    }
}
