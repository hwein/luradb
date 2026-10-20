//! Registered-buffer I/O on the engine thread's ring (spec perf/004, perf/020).
//!
//! `IoEngine` allocates a pool of fixed (kernel-pinned) buffers, registers it
//! with the ring (`IORING_REGISTER_BUFFERS`) and tracks open file handles by
//! logical id (SSTables use their file id, the WAL and VLog the reserved high
//! ids below). compio has neither buffer registration nor the fixed-buffer
//! ops, so both are built here on its public `OpCode`. All methods must run on
//! the engine runtime ([`crate::core::engine_runtime`]).
//!
//! Scaffolding only: nothing here is on the hot path yet. The WAL/VLog/SSTable
//! I/O paths are unchanged; spec 005 wires `IoEngine` into a dedicated storage
//! thread that actually uses `read_fixed`/`write_fixed`.

use crate::core::engine_runtime;
use anyhow::{anyhow, Context, Result};
use compio::buf::BufResult;
use compio::driver::{OpCode, OpEntry};
use compio::fs::{File, OpenOptions};
use compio::runtime::Runtime;
use std::cell::RefCell;
use std::collections::HashMap;
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;
use std::rc::Rc;

/// Registered-buffer pool of the IoEngine.
pub const REGISTERED_BUFFER_COUNT: usize = 128;
pub const REGISTERED_BUFFER_SIZE: usize = 64 * 1024;

/// SSTable ids are allocated upwards from 0 (`FileManager`), so the WAL and
/// VLog get reserved ids at the top of the range — one shared namespace,
/// no collisions.
pub const WAL_LOGICAL_ID: u64 = u64::MAX;
pub const VLOG_LOGICAL_ID: u64 = u64::MAX - 1;

/// Maps a logical file id to an open file handle.
///
/// No Fixed-File registration yet (that is spec 005's raw `io-uring` work) —
/// these are regular file descriptors.
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
        let owned = path.to_path_buf();
        let file = engine_runtime::spawn_io(async move {
            OpenOptions::new().read(true).write(true).create(true).open(owned).await
        })
        .await
        .with_context(|| format!("failed to open {} for logical id {logical_id}", path.display()))?;
        self.handles.insert(logical_id, file);
        Ok(())
    }

    /// Drops the tracked handle; its descriptor closes once no operation
    /// holds it any more. No-op if the id was not registered.
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
    pool: Rc<FixedPool>,
    file_handles: FileHandleMap,
}

impl IoEngine {
    /// Allocates `buffer_count` buffers of `buffer_size` bytes each and
    /// registers them with the current engine runtime's ring.
    ///
    /// Returns `Err` (rather than panicking) when the kernel rejects the
    /// registration itself. Callers should log a warning and continue
    /// without an `IoEngine` in that case.
    pub fn new(buffer_count: usize, buffer_size: usize) -> Result<Self> {
        anyhow::ensure!(buffer_count <= usize::from(u16::MAX), "at most {} registered buffers", u16::MAX);
        let pool = FixedPool::new(buffer_count, buffer_size);
        let ring = Runtime::with_current(|rt| rt.as_raw_fd());
        register_buffers(ring, &pool).context("kernel rejected registered-buffer setup")?;
        Ok(Self { pool: Rc::new(pool), file_handles: FileHandleMap::new() })
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

    /// Checks out a free, empty registered buffer for the caller to fill (via
    /// [`FixedBuf::put_slice`]) before [`Self::write_fixed`]. `None` means the
    /// pool is exhausted — a backpressure signal for the caller.
    pub fn checkout_buffer(&self) -> Option<FixedBuf> {
        let index = self.pool.free.borrow_mut().pop()?;
        Some(FixedBuf { pool: Rc::clone(&self.pool), index, len: 0 })
    }

    /// Reads up to `len` bytes at `offset` from `logical_id` into a registered
    /// buffer (`IORING_OP_READ_FIXED`). The returned buffer holds exactly the
    /// bytes read.
    pub async fn read_fixed(&self, logical_id: u64, offset: u64, len: u32) -> Result<FixedBuf> {
        anyhow::ensure!(
            len as usize <= self.pool.size,
            "requested read of {len} bytes exceeds the registered buffer size of {}",
            self.pool.size
        );
        let file = self.registered(logical_id)?;
        let buf = self.checkout_buffer().ok_or_else(|| anyhow!("Buffer pool exhausted"))?;
        let op = FixedIo { file, buf, len, offset, write: false };
        let (n, mut op) = engine_runtime::spawn_io(submit(op)).await;
        op.buf.len = n?;
        Ok(op.buf)
    }

    /// Writes the buffer's first `len` bytes into `logical_id` at `offset`
    /// (`IORING_OP_WRITE_FIXED`). The buffer returns to the pool once the
    /// write is done.
    pub async fn write_fixed(&self, logical_id: u64, offset: u64, buf: FixedBuf, len: usize) -> Result<()> {
        anyhow::ensure!(
            len <= buf.bytes_init(),
            "write_fixed: requested {len} bytes but only {} are initialized in the buffer",
            buf.bytes_init()
        );
        let file = self.registered(logical_id)?;
        let op = FixedIo { file, buf, len: len as u32, offset, write: true };
        let (result, _) = engine_runtime::spawn_io(submit(op)).await;
        result?;
        Ok(())
    }

    /// fdatasync on `logical_id` for durability.
    pub async fn fsync(&self, logical_id: u64) -> Result<()> {
        let file = self.registered(logical_id)?;
        engine_runtime::spawn_io(async move { file.sync_data().await }).await?;
        Ok(())
    }

    fn registered(&self, logical_id: u64) -> Result<File> {
        self.get_file(logical_id).cloned().ok_or_else(|| anyhow!("File not registered: {logical_id}"))
    }
}

/// The registered memory: `count` slots of `size` bytes in one allocation,
/// freed only once every [`FixedBuf`] (and so every op using one) is gone.
struct FixedPool {
    memory: *mut u8,
    size: usize,
    count: usize,
    free: RefCell<Vec<u16>>,
}

impl FixedPool {
    fn new(count: usize, size: usize) -> Self {
        let memory = Box::into_raw(vec![0u8; count * size].into_boxed_slice()).cast::<u8>();
        Self { memory, size, count, free: RefCell::new((0..count as u16).rev().collect()) }
    }

    fn slot(&self, index: u16) -> *mut u8 {
        // SAFETY: `index < count`, so the slot lies inside the allocation.
        unsafe { self.memory.add(usize::from(index) * self.size) }
    }
}

impl Drop for FixedPool {
    fn drop(&mut self) {
        // SAFETY: `memory` came from `Box::into_raw` of exactly this length.
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(self.memory, self.count * self.size)) });
    }
}

/// One registered buffer, checked out of the pool until dropped. Derefs to
/// its filled bytes.
pub struct FixedBuf {
    pool: Rc<FixedPool>,
    index: u16,
    len: usize,
}

impl FixedBuf {
    /// Appends `data` behind the filled bytes; panics past the buffer size.
    pub fn put_slice(&mut self, data: &[u8]) {
        assert!(self.len + data.len() <= self.pool.size, "put_slice past the registered buffer size");
        // SAFETY: the range lies inside this buffer's slot, which only this
        // `FixedBuf` writes while it is checked out.
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), self.pool.slot(self.index).add(self.len), data.len()) };
        self.len += data.len();
    }

    /// Number of filled bytes.
    pub fn bytes_init(&self) -> usize {
        self.len
    }
}

impl std::ops::Deref for FixedBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        // SAFETY: the first `len` bytes of the slot are filled.
        unsafe { std::slice::from_raw_parts(self.pool.slot(self.index), self.len) }
    }
}

impl Drop for FixedBuf {
    fn drop(&mut self) {
        self.pool.free.borrow_mut().push(self.index);
    }
}

/// `IORING_OP_READ_FIXED` / `WRITE_FIXED` of `len` bytes at `offset`. The op
/// owns the buffer and the file until its completion; compio keeps an op
/// whose future was dropped until then.
struct FixedIo {
    file: File,
    buf: FixedBuf,
    len: u32,
    offset: u64,
    write: bool,
}

// SAFETY: the op's buffer is registered memory that outlives the op (see
// `FixedBuf`), and `len` never exceeds the buffer size.
unsafe impl OpCode for FixedIo {
    type Control = ();

    fn create_entry(&mut self, _: &mut Self::Control) -> OpEntry {
        use io_uring_compio::{opcode, types::Fd};
        let fd = Fd(self.file.as_raw_fd());
        let ptr = self.buf.pool.slot(self.buf.index);
        let entry = if self.write {
            opcode::WriteFixed::new(fd, ptr, self.len, self.buf.index).offset(self.offset).build()
        } else {
            opcode::ReadFixed::new(fd, ptr, self.len, self.buf.index).offset(self.offset).build()
        };
        entry.into()
    }
}

async fn submit(op: FixedIo) -> (std::io::Result<usize>, FixedIo) {
    let BufResult(result, op) = compio::runtime::submit(op).await;
    (result, op)
}

/// Registers the pool's memory as fixed buffers on the ring behind
/// `ring_fd`; must run on the ring's thread (`SINGLE_ISSUER`).
fn register_buffers(ring_fd: RawFd, pool: &FixedPool) -> std::io::Result<()> {
    const IORING_REGISTER_BUFFERS: libc::c_long = 0;
    let iovecs: Vec<libc::iovec> = (0..pool.count as u16)
        .map(|index| libc::iovec { iov_base: pool.slot(index).cast(), iov_len: pool.size })
        .collect();
    // SAFETY: `iovecs` describes the pool's live memory; the kernel copies the array.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_io_uring_register,
            libc::c_long::from(ring_fd),
            IORING_REGISTER_BUFFERS,
            iovecs.as_ptr(),
            iovecs.len() as libc::c_long,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::engine_runtime::block_on;

    // 1. Pool -- checkout returns a buffer, Drop returns it to the pool.
    #[test]
    fn test_fixed_buf_pool_checkin_on_drop() {
        block_on(async {
            let engine = IoEngine::new(1, 64).unwrap();

            let buf = engine.checkout_buffer().unwrap();
            assert!(engine.checkout_buffer().is_none(), "sole slot must be checked out");
            drop(buf);
            assert!(engine.checkout_buffer().is_some(), "slot must return to the pool on drop");
        });
    }

    // 2. Pool -- all slots occupied -> checkout returns None.
    #[test]
    fn test_fixed_buf_pool_exhausted() {
        block_on(async {
            let engine = IoEngine::new(2, 64).unwrap();

            let _a = engine.checkout_buffer().unwrap();
            let _b = engine.checkout_buffer().unwrap();
            assert!(engine.checkout_buffer().is_none());
        });
    }

    // 3. FileHandleMap -- register_file() + get_file() -> correct handle.
    #[test]
    fn test_file_handle_map_register_and_get() {
        block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let path = dir.path().join("a.dat");
            let mut map = FileHandleMap::new();
            map.register_file(7, &path).await.unwrap();
            assert!(map.get_file(7).is_some());
            assert!(map.get_file(8).is_none());
        });
    }

    // 4. FileHandleMap -- unregister_file() -> handle removed, get_file() -> None.
    #[test]
    fn test_file_handle_map_unregister() {
        block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let path = dir.path().join("b.dat");
            let mut map = FileHandleMap::new();
            map.register_file(3, &path).await.unwrap();
            map.unregister_file(3).unwrap();
            assert!(map.get_file(3).is_none());
        });
    }

    // 5. IoEngine::read_fixed() -- write test data, register, read via registered buffer.
    #[test]
    fn test_io_engine_read_fixed_reads_correct_data() {
        block_on(async {
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

    // 6. IoEngine::write_fixed() -- write via registered buffer, verify with a standard read.
    #[test]
    fn test_io_engine_write_fixed_writes_correct_data() {
        block_on(async {
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

    // 7. IoEngine::fsync() -- no error after write + fsync.
    #[test]
    fn test_io_engine_fsync_after_write() {
        block_on(async {
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
        block_on(async {
            let engine = IoEngine::new(1, 4096).unwrap();
            // `.err().unwrap()` rather than `.unwrap_err()`: the Ok type
            // `FixedBuf` is not `Debug`, which `unwrap_err` would require.
            let err = engine.read_fixed(99, 0, 10).await.err().unwrap();
            assert!(err.to_string().contains("not registered"));
        });
    }

    // Regression (perf/004 finding 1): a large write then a smaller one over
    // the SAME slot must persist only the smaller payload, not the leftover
    // bytes.
    #[test]
    fn test_io_engine_write_fixed_reused_slot_no_stale_leak() {
        block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let big_path = dir.path().join("big.dat");
            let small_path = dir.path().join("small.dat");

            let mut engine = IoEngine::new(1, 4096).unwrap(); // single slot forces reuse
            engine.register_file(0, &big_path).await.unwrap();
            engine.register_file(1, &small_path).await.unwrap();

            let mut buf = engine.checkout_buffer().unwrap();
            buf.put_slice(&[b'X'; 100]);
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

    // Regression (perf/004 finding 1): read must return exactly the n bytes
    // read, even from a reused slot that held a larger read before.
    #[test]
    fn test_io_engine_read_fixed_reused_slot_exact_len() {
        block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let big_path = dir.path().join("rbig.dat");
            let small_path = dir.path().join("rsmall.dat");
            std::fs::write(&big_path, vec![b'Y'; 100]).unwrap();
            std::fs::write(&small_path, b"hi").unwrap();

            let mut engine = IoEngine::new(1, 4096).unwrap(); // single slot forces reuse
            engine.register_file(0, &big_path).await.unwrap();
            engine.register_file(1, &small_path).await.unwrap();

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
