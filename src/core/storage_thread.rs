//! Dedicated OS-thread storage I/O via a raw io_uring ring in SQPOLL mode (spec perf/005).
//!
//! Two separate "ring worlds" exist when the IoEngine is enabled: spec 004's
//! [`crate::core::io_engine::IoEngine`] (tokio-uring `FixedBufPool`, `!Send`,
//! on the main tokio-uring runtime) and this module's raw [`io_uring::IoUring`]
//! (SQPOLL, owned exclusively by one `std::thread`). They cannot share buffers
//! or file handles, so the SQPOLL ring is built and driven entirely here — the
//! spec's "SQPOLL activation in io_engine.rs" lives here instead, because
//! `FixedBufPool` exposes no SQPOLL path.
//!
//! tokio tasks talk to the thread over a bounded `tokio::sync::mpsc` channel
//! (async backpressure) and await the result over a tokio `oneshot`.

use anyhow::{anyhow, Context, Result};
use tokio::sync::mpsc::{self, Receiver, Sender};
use io_uring::{opcode, squeue, types, IoUring};
use std::fs::{File, OpenOptions};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use tokio::sync::oneshot;

/// Runtime parameters for [`StorageThread::new`].
#[derive(Debug, Clone, Copy)]
pub struct StorageThreadConfig {
    pub sqpoll_enabled: bool,
    pub sqpoll_idle_ms: u32,
    pub ring_depth: u32,
    pub channel_capacity: usize,
    /// CPU core to pin the thread to; `-1` disables pinning.
    pub cpu: i32,
}

/// An I/O request from a tokio task to the storage thread.
pub enum IoRequest {
    /// Append bytes to the WAL and fdatasync before responding with the offset.
    WalAppend { data: Vec<u8>, response: oneshot::Sender<Result<u64>> },
    /// Reset the WAL to length 0.
    WalTruncate { response: oneshot::Sender<Result<()>> },
    /// Append bytes to the VLog; responds with `(offset, len)`.
    VlogAppend { data: Vec<u8>, response: oneshot::Sender<Result<(u64, usize)>> },
    /// Read `len` bytes at `offset` from the VLog.
    VlogRead { offset: u64, len: usize, response: oneshot::Sender<Result<Vec<u8>>> },
    /// Write a complete SSTable to `path` (temp file + fsync + atomic rename).
    /// Returns `data` back so a non-mmap flush can build the reader without a copy.
    SstableWrite { path: PathBuf, data: Vec<u8>, response: oneshot::Sender<Result<Vec<u8>>> },
    /// Reopen the VLog on the canonical `path` after GC: close the old fd,
    /// reset the offset to the file length, refresh the fixed-file slot.
    VlogReopen { path: PathBuf, response: oneshot::Sender<Result<()>> },
    /// Drain pending requests, then stop the thread.
    Shutdown,
}

/// Async, clonable interface to the storage thread.
#[derive(Clone)]
pub struct StorageHandle {
    request_tx: Sender<IoRequest>,
}

impl StorageHandle {
    pub async fn wal_append(&self, data: Vec<u8>) -> Result<u64> {
        let (tx, rx) = oneshot::channel();
        self.request_tx
            .send(IoRequest::WalAppend { data, response: tx })
            .await
            .map_err(|_| anyhow!("storage thread shut down"))?;
        rx.await.map_err(|_| anyhow!("storage thread dropped response"))?
    }

    pub async fn wal_truncate(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.request_tx
            .send(IoRequest::WalTruncate { response: tx })
            .await
            .map_err(|_| anyhow!("storage thread shut down"))?;
        rx.await.map_err(|_| anyhow!("storage thread dropped response"))?
    }

    pub async fn vlog_append(&self, data: Vec<u8>) -> Result<(u64, usize)> {
        let (tx, rx) = oneshot::channel();
        self.request_tx
            .send(IoRequest::VlogAppend { data, response: tx })
            .await
            .map_err(|_| anyhow!("storage thread shut down"))?;
        rx.await.map_err(|_| anyhow!("storage thread dropped response"))?
    }

    pub async fn vlog_read(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let (tx, rx) = oneshot::channel();
        self.request_tx
            .send(IoRequest::VlogRead { offset, len, response: tx })
            .await
            .map_err(|_| anyhow!("storage thread shut down"))?;
        rx.await.map_err(|_| anyhow!("storage thread dropped response"))?
    }

    pub async fn sstable_write(&self, path: PathBuf, data: Vec<u8>) -> Result<Vec<u8>> {
        let (tx, rx) = oneshot::channel();
        self.request_tx
            .send(IoRequest::SstableWrite { path, data, response: tx })
            .await
            .map_err(|_| anyhow!("storage thread shut down"))?;
        rx.await.map_err(|_| anyhow!("storage thread dropped response"))?
    }

    pub async fn vlog_reopen(&self, path: PathBuf) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.request_tx
            .send(IoRequest::VlogReopen { path, response: tx })
            .await
            .map_err(|_| anyhow!("storage thread shut down"))?;
        rx.await.map_err(|_| anyhow!("storage thread dropped response"))?
    }
}

/// Owns the storage OS thread and its lifecycle.
pub struct StorageThread {
    join_handle: Option<JoinHandle<()>>,
    request_tx: Sender<IoRequest>,
    shutdown: Arc<AtomicBool>,
}

impl StorageThread {
    /// Spawns the storage thread, which builds its own SQPOLL ring and opens the
    /// WAL and VLog. Blocks until the thread reports readiness (or an init error).
    pub fn new(
        config: StorageThreadConfig,
        wal_path: PathBuf,
        vlog_path: PathBuf,
    ) -> Result<(Self, StorageHandle)> {
        // `.max(1)`: tokio's bounded channel panics on capacity 0; a misconfig
        // must not crash startup.
        let (request_tx, request_rx) = mpsc::channel(config.channel_capacity.max(1));
        let shutdown = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<bool>>();
        let thread_shutdown = Arc::clone(&shutdown);

        let join_handle = std::thread::Builder::new()
            .name("luradb-storage".into())
            .spawn(move || {
                storage_thread_main(config, wal_path, vlog_path, request_rx, thread_shutdown, ready_tx);
            })
            .context("failed to spawn storage thread")?;

        match ready_rx.recv() {
            Ok(Ok(sqpoll_active)) => {
                tracing::info!(
                    "Storage thread ready (SQPOLL {}).",
                    if sqpoll_active { "active" } else { "disabled" }
                );
                let handle = StorageHandle { request_tx: request_tx.clone() };
                Ok((Self { join_handle: Some(join_handle), request_tx, shutdown }, handle))
            }
            Ok(Err(e)) => {
                let _ = join_handle.join();
                Err(e)
            }
            Err(_) => {
                let _ = join_handle.join();
                Err(anyhow!("storage thread exited during initialization"))
            }
        }
    }

    /// Signals shutdown, lets the thread drain pending requests, then joins.
    pub fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Non-blocking: `shutdown` may run on the tokio runtime thread. If the
        // channel is full the wake is redundant — the flag above stops the loop
        // after its current batch, then the queue is drained.
        let _ = self.request_tx.try_send(IoRequest::Shutdown);
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for StorageThread {
    fn drop(&mut self) {
        if self.join_handle.is_some() {
            self.shutdown();
        }
    }
}

// ── Thread internals ────────────────────────────────────────────────────────

struct StorageState {
    ring: IoUring,
    wal: File,
    wal_offset: u64,
    vlog: File,
    vlog_offset: u64,
    /// WAL and VLog are registered as fixed files (slots 0 and 1); `false` after
    /// a failed `register_files` — ops then fall back to raw fds.
    fixed_files: bool,
}

impl StorageState {
    fn wal_file(&self) -> RingFile {
        if self.fixed_files { RingFile::Fixed(WAL_SLOT) } else { RingFile::Raw(self.wal.as_raw_fd()) }
    }
    fn vlog_file(&self) -> RingFile {
        if self.fixed_files { RingFile::Fixed(VLOG_SLOT) } else { RingFile::Raw(self.vlog.as_raw_fd()) }
    }
}

/// Fixed-file slot indices for the two long-lived files.
const WAL_SLOT: u32 = 0;
const VLOG_SLOT: u32 = 1;

/// Target file for a ring op: a registered fixed-file slot, or a raw fd.
#[derive(Clone, Copy)]
enum RingFile {
    Fixed(u32),
    Raw(RawFd),
}

fn storage_thread_main(
    config: StorageThreadConfig,
    wal_path: PathBuf,
    vlog_path: PathBuf,
    mut request_rx: Receiver<IoRequest>,
    shutdown: Arc<AtomicBool>,
    ready_tx: std::sync::mpsc::Sender<Result<bool>>,
) {
    if config.cpu >= 0 {
        if let Err(e) = pin_to_cpu(config.cpu) {
            tracing::warn!("Storage thread CPU pinning to core {} failed: {e}", config.cpu);
        }
    }

    let init = (|| -> Result<(StorageState, bool)> {
        let (ring, sqpoll_active) =
            build_ring(config.sqpoll_enabled, config.sqpoll_idle_ms, config.ring_depth)?;
        let wal = open_rw(&wal_path)?;
        let vlog = open_rw(&vlog_path)?;
        let wal_offset = wal.metadata()?.len();
        let vlog_offset = vlog.metadata()?.len();
        // Register WAL/VLog once as fixed files so the kernel skips fd lookup per
        // op; on failure fall back to raw fds.
        let fixed_files = match ring.submitter().register_files(&[wal.as_raw_fd(), vlog.as_raw_fd()]) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!("io_uring register_files failed: {e}; using raw fds");
                false
            }
        };
        Ok((StorageState { ring, wal, wal_offset, vlog, vlog_offset, fixed_files }, sqpoll_active))
    })();

    let mut state = match init {
        Ok((state, sqpoll_active)) => {
            let _ = ready_tx.send(Ok(sqpoll_active));
            state
        }
        Err(e) => {
            let _ = ready_tx.send(Err(e));
            return;
        }
    };

    event_loop(&mut state, &mut request_rx, &shutdown);
}

fn event_loop(state: &mut StorageState, rx: &mut Receiver<IoRequest>, shutdown: &AtomicBool) {
    loop {
        // Thread is a plain `std::thread`, not a tokio context — `blocking_recv`
        // parks it until a request arrives (or all senders drop).
        let first = match rx.blocking_recv() {
            Some(req) => req,
            None => return, // all senders dropped
        };
        // Coalesce everything currently queued into one batch (group commit).
        let mut batch = vec![first];
        while let Ok(req) = rx.try_recv() {
            batch.push(req);
        }
        let stop = process_batch(state, batch);
        if stop || shutdown.load(Ordering::SeqCst) {
            drain_remaining(state, rx);
            return;
        }
    }
}

/// Drains whatever is still queued (best-effort) so no pending request is lost.
fn drain_remaining(state: &mut StorageState, rx: &mut Receiver<IoRequest>) {
    let mut batch = Vec::new();
    while let Ok(req) = rx.try_recv() {
        batch.push(req);
    }
    if !batch.is_empty() {
        process_batch(state, batch);
    }
}

/// Processes a batch in order, coalescing consecutive WAL appends into a single
/// write + one fdatasync (group commit). Returns `true` if a `Shutdown` was seen.
fn process_batch(state: &mut StorageState, batch: Vec<IoRequest>) -> bool {
    let mut stop = false;
    let mut iter = batch.into_iter().peekable();
    while let Some(req) = iter.next() {
        match req {
            IoRequest::Shutdown => stop = true,
            IoRequest::WalAppend { data, response } => {
                let mut group = vec![(data, response)];
                while matches!(iter.peek(), Some(IoRequest::WalAppend { .. })) {
                    if let Some(IoRequest::WalAppend { data, response }) = iter.next() {
                        group.push((data, response));
                    }
                }
                do_wal_group(state, group);
            }
            IoRequest::WalTruncate { response } => {
                let _ = response.send(do_wal_truncate(state));
            }
            IoRequest::VlogAppend { data, response } => {
                let _ = response.send(do_vlog_append(state, &data));
            }
            IoRequest::VlogRead { offset, len, response } => {
                let _ = response.send(do_vlog_read(state, offset, len));
            }
            IoRequest::SstableWrite { path, data, response } => {
                let result = do_sstable_write(state, &path, &data).map(|()| data);
                let _ = response.send(result);
            }
            IoRequest::VlogReopen { path, response } => {
                let _ = response.send(do_vlog_reopen(state, &path));
            }
        }
    }
    stop
}

type WalGroup = Vec<(Vec<u8>, oneshot::Sender<Result<u64>>)>;

/// One combined write for the whole group, one fdatasync, then per-item offsets.
/// Mirrors the group-commit durability of the tokio::fs WAL committer.
fn do_wal_group(state: &mut StorageState, group: WalGroup) {
    let start = state.wal_offset;
    let mut combined = Vec::new();
    let mut offsets = Vec::with_capacity(group.len());
    for (data, _) in &group {
        offsets.push(state.wal_offset);
        state.wal_offset += data.len() as u64;
        combined.extend_from_slice(data);
    }

    let wal = state.wal_file();
    let result: Result<()> = (|| {
        if !combined.is_empty() {
            ring_write_all(&mut state.ring, wal, start, &combined)?;
            ring_fsync(&mut state.ring, wal, true)?;
        }
        Ok(())
    })();

    match result {
        Ok(()) => {
            for ((_, response), offset) in group.into_iter().zip(offsets) {
                let _ = response.send(Ok(offset));
            }
        }
        Err(e) => {
            state.wal_offset = start; // rollback: nothing was durably written
            let msg = e.to_string();
            for (_, response) in group {
                let _ = response.send(Err(anyhow!("WAL append failed: {msg}")));
            }
        }
    }
}

fn do_wal_truncate(state: &mut StorageState) -> Result<()> {
    state.wal.set_len(0)?;
    state.wal_offset = 0;
    state.wal.sync_all()?;
    Ok(())
}

fn do_vlog_append(state: &mut StorageState, data: &[u8]) -> Result<(u64, usize)> {
    if data.is_empty() {
        return Ok((state.vlog_offset, 0));
    }
    let offset = state.vlog_offset;
    let vlog = state.vlog_file();
    ring_write_all(&mut state.ring, vlog, offset, data)?;
    state.vlog_offset += data.len() as u64;
    Ok((offset, data.len()))
}

fn do_vlog_read(state: &mut StorageState, offset: u64, len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let vlog = state.vlog_file();
    ring_read_exact(&mut state.ring, vlog, offset, &mut buf)?;
    Ok(buf)
}

/// Reopens the VLog on `path` after GC: swaps in the new fd (refreshing fixed
/// slot 1 when registered) and resets the write cursor to the file length.
fn do_vlog_reopen(state: &mut StorageState, path: &Path) -> Result<()> {
    let new = open_rw(path)?;
    let new_offset = new.metadata()?.len();
    if state.fixed_files {
        state
            .ring
            .submitter()
            .register_files_update(VLOG_SLOT, &[new.as_raw_fd()])
            .context("register_files_update VLog slot")?;
    }
    state.vlog = new; // drops the old fd (frees the stale GC'd inode)
    state.vlog_offset = new_offset;
    Ok(())
}

/// Crash-safe SSTable install: write to `<path>.tmp`, full fsync, atomic rename.
/// On any failure the temp file is removed so repeated errors don't accumulate
/// `.tmp` leftovers.
fn do_sstable_write(state: &mut StorageState, path: &Path, data: &[u8]) -> Result<()> {
    let tmp = sstable_tmp_path(path);
    let result = install_sstable(state, &tmp, path, data);
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

fn install_sstable(state: &mut StorageState, tmp: &Path, path: &Path, data: &[u8]) -> Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(tmp)
        .with_context(|| format!("open temp sstable {}", tmp.display()))?;
    // One-shot temp file: raw fd, not worth a fixed-file slot registration.
    let file_ref = RingFile::Raw(file.as_raw_fd());
    ring_write_all(&mut state.ring, file_ref, 0, data)?;
    ring_fsync(&mut state.ring, file_ref, false)?;
    drop(file);
    std::fs::rename(tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

fn sstable_tmp_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

// ── Raw io_uring helpers (single op, submit_and_wait) ────────────────────────

/// Builds the SQPOLL ring; on `EPERM` (missing `CAP_SYS_NICE`) or when disabled,
/// falls back to the standard ring. Returns `(ring, sqpoll_active)`.
fn build_ring(sqpoll_enabled: bool, idle_ms: u32, depth: u32) -> Result<(IoUring, bool)> {
    if sqpoll_enabled {
        let mut builder = IoUring::builder();
        builder.setup_sqpoll(idle_ms);
        match builder.build(depth) {
            Ok(ring) => return Ok((ring, true)),
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => {
                tracing::warn!("SQPOLL requires CAP_SYS_NICE, falling back to standard mode");
            }
            Err(e) => return Err(anyhow::Error::from(e).context("io_uring SQPOLL setup")),
        }
    }
    let ring = IoUring::new(depth).context("io_uring standard setup")?;
    Ok((ring, false))
}

/// Submits one SQE and reaps its single completion; returns the raw CQE result.
///
/// Once `sq.sync()` publishes the SQE, the kernel (in SQPOLL mode, its poll
/// thread) may run the op at any time, so we MUST reap the completion before
/// returning: the caller frees the referenced buffer on return, and an in-flight
/// op would then read or write freed heap. `submit_and_wait` does not retry
/// `EINTR` itself (io-uring 0.6) and can return without reaping when a signal
/// arrives (e.g. at shutdown), so we re-enter until the completion is queued.
/// Any other error leaves a possibly-in-flight op we can neither reap nor cancel;
/// returning would free a live buffer, so we abort instead (safety over uptime).
fn ring_op(ring: &mut IoUring, entry: squeue::Entry) -> std::io::Result<i32> {
    {
        let mut sq = ring.submission();
        // Safe: the caller keeps the referenced buffer alive, and the loop below
        // guarantees we reap (or abort) before returning — never freeing it while
        // a submitted op can still touch it.
        unsafe {
            sq.push(&entry).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::Other, "io_uring submission queue full")
            })?;
        }
        sq.sync();
    }
    loop {
        match ring.submit_and_wait(1) {
            Ok(_) => break,
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
            Err(e) => {
                eprintln!(
                    "luradb storage ring: unrecoverable submit_and_wait error, \
                     aborting to avoid a use-after-free on an in-flight op: {e}"
                );
                std::process::abort();
            }
        }
    }
    let mut cq = ring.completion();
    let result = cq.next().expect("a completion is ready after submit_and_wait(1)").result();
    cq.sync();
    Ok(result)
}

/// Builds a Write SQE for either a fixed-file slot or a raw fd.
fn write_entry(file: RingFile, ptr: *const u8, len: u32, offset: u64) -> squeue::Entry {
    match file {
        RingFile::Fixed(i) => opcode::Write::new(types::Fixed(i), ptr, len).offset(offset).build(),
        RingFile::Raw(fd) => opcode::Write::new(types::Fd(fd), ptr, len).offset(offset).build(),
    }
}

/// Builds a Read SQE for either a fixed-file slot or a raw fd.
fn read_entry(file: RingFile, ptr: *mut u8, len: u32, offset: u64) -> squeue::Entry {
    match file {
        RingFile::Fixed(i) => opcode::Read::new(types::Fixed(i), ptr, len).offset(offset).build(),
        RingFile::Raw(fd) => opcode::Read::new(types::Fd(fd), ptr, len).offset(offset).build(),
    }
}

/// Builds an Fsync SQE for either a fixed-file slot or a raw fd.
fn fsync_entry(file: RingFile, datasync: bool) -> squeue::Entry {
    let flags = if datasync { types::FsyncFlags::DATASYNC } else { types::FsyncFlags::empty() };
    match file {
        RingFile::Fixed(i) => opcode::Fsync::new(types::Fixed(i)).flags(flags).build(),
        RingFile::Raw(fd) => opcode::Fsync::new(types::Fd(fd)).flags(flags).build(),
    }
}

fn ring_write_all(ring: &mut IoUring, file: RingFile, mut offset: u64, data: &[u8]) -> std::io::Result<()> {
    let mut pos = 0usize;
    while pos < data.len() {
        let chunk = &data[pos..];
        let entry = write_entry(file, chunk.as_ptr(), chunk.len() as u32, offset);
        let res = ring_op(ring, entry)?;
        if res < 0 {
            return Err(std::io::Error::from_raw_os_error(-res));
        }
        if res == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "io_uring write returned 0"));
        }
        pos += res as usize;
        offset += res as u64;
    }
    Ok(())
}

fn ring_read_exact(ring: &mut IoUring, file: RingFile, mut offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
    let mut pos = 0usize;
    while pos < buf.len() {
        let dst = &mut buf[pos..];
        let entry = read_entry(file, dst.as_mut_ptr(), dst.len() as u32, offset);
        let res = ring_op(ring, entry)?;
        if res < 0 {
            return Err(std::io::Error::from_raw_os_error(-res));
        }
        if res == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "io_uring read hit EOF"));
        }
        pos += res as usize;
        offset += res as u64;
    }
    Ok(())
}

/// `datasync = true` -> fdatasync, else a full fsync.
fn ring_fsync(ring: &mut IoUring, file: RingFile, datasync: bool) -> std::io::Result<()> {
    let res = ring_op(ring, fsync_entry(file, datasync))?;
    if res < 0 {
        return Err(std::io::Error::from_raw_os_error(-res));
    }
    Ok(())
}

fn open_rw(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))
}

fn pin_to_cpu(cpu: i32) -> Result<()> {
    // `CPU_SET` indexes a fixed-size bitmap; an out-of-range core panics on the
    // bounds check. Reject it here so a misconfig yields a clear error instead
    // (the caller logs a warning and continues without pinning).
    if cpu >= libc::CPU_SETSIZE {
        return Err(anyhow!(
            "CPU core {cpu} exceeds CPU_SETSIZE ({})",
            libc::CPU_SETSIZE
        ));
    }
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu as usize, &mut set);
        let rc = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
        if rc != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::wal::WriteAheadLog;
    use crate::engines::lsm::engine::{LsmEngineOptions, LsmStorageEngine};
    use crate::engines::StorageEngine;
    use crate::storage::file_manager::FileManager;
    use crate::storage::manifest::ManifestManager;
    use crate::storage::vlog::VLog;

    fn cfg(sqpoll: bool, capacity: usize) -> StorageThreadConfig {
        StorageThreadConfig {
            sqpoll_enabled: sqpoll,
            sqpoll_idle_ms: 500,
            ring_depth: 64,
            channel_capacity: capacity,
            cpu: -1,
        }
    }

    fn spawn(dir: &Path, sqpoll: bool, capacity: usize) -> (StorageThread, StorageHandle) {
        StorageThread::new(cfg(sqpoll, capacity), dir.join("wal"), dir.join("vlog")).unwrap()
    }

    // 1. StorageThread startet und stoppt sauber.
    #[test]
    fn test_storage_thread_starts_and_stops() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut st, handle) = spawn(dir.path(), false, 64);
        drop(handle);
        st.shutdown();
    }

    // 2. wal_append -- Daten geschrieben, Offset korrekt.
    #[tokio::test]
    async fn test_wal_append_offsets_and_bytes() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut st, handle) = spawn(dir.path(), false, 64);
        let o1 = handle.wal_append(b"hello".to_vec()).await.unwrap();
        let o2 = handle.wal_append(b"world!".to_vec()).await.unwrap();
        assert_eq!(o1, 0);
        assert_eq!(o2, 5);
        st.shutdown();
        assert_eq!(std::fs::read(dir.path().join("wal")).unwrap(), b"helloworld!");
    }

    // 3. vlog_read -- Daten korrekt gelesen.
    #[tokio::test]
    async fn test_vlog_append_then_read() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut st, handle) = spawn(dir.path(), false, 64);
        let (off, len) = handle.vlog_append(b"payload-XYZ".to_vec()).await.unwrap();
        assert_eq!((off, len), (0, 11));
        let got = handle.vlog_read(off, len).await.unwrap();
        assert_eq!(got, b"payload-XYZ");
        st.shutdown();
    }

    // 4. Batching: 100 gleichzeitige wal_append-Requests korrekt verarbeitet.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_batching_100_concurrent_wal_appends() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut st, handle) = spawn(dir.path(), false, 1024);
        let mut tasks = Vec::new();
        for _ in 0..100u32 {
            let h = handle.clone();
            tasks.push(tokio::spawn(async move { h.wal_append(vec![b'x'; 10]).await.unwrap() }));
        }
        let mut offsets = Vec::new();
        for t in tasks {
            offsets.push(t.await.unwrap());
        }
        offsets.sort_unstable();
        assert_eq!(offsets.len(), 100);
        for (i, off) in offsets.iter().enumerate() {
            assert_eq!(*off, (i as u64) * 10);
        }
        st.shutdown();
        assert_eq!(std::fs::read(dir.path().join("wal")).unwrap().len(), 1000);
    }

    // 5. Backpressure: bounded channel voll -> try_send meldet Full.
    #[test]
    fn test_channel_backpressure_is_bounded() {
        let (tx, _rx) = mpsc::channel::<u32>(2);
        assert!(tx.try_send(1).is_ok());
        assert!(tx.try_send(2).is_ok());
        assert!(matches!(tx.try_send(3), Err(mpsc::error::TrySendError::Full(3))));
    }

    // 6. SQPOLL-Fallback: Standard-Modus liefert einen funktionierenden Ring,
    //    SQPOLL-Anforderung fällt bei Bedarf sauber zurück (kein Fehler).
    #[test]
    fn test_build_ring_fallback_and_sqpoll() {
        let (_ring, sqpoll) = build_ring(false, 500, 64).unwrap();
        assert!(!sqpoll, "sqpoll_enabled=false must yield standard mode");
        // Requesting SQPOLL either succeeds or transparently falls back — never errors.
        let (_ring2, _sqpoll2) = build_ring(true, 500, 64).unwrap();
    }

    // 6b. End-to-end im echten SQPOLL-Modus (WSL2-Kernel unterstützt es).
    #[tokio::test]
    async fn test_wal_append_sqpoll_mode() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut st, handle) = spawn(dir.path(), true, 64);
        handle.wal_append(b"sqpoll".to_vec()).await.unwrap();
        st.shutdown();
        assert_eq!(std::fs::read(dir.path().join("wal")).unwrap(), b"sqpoll");
    }

    // 7. Shutdown: alle ausstehenden Requests werden vor Thread-Exit abgeschlossen.
    #[tokio::test]
    async fn test_shutdown_drains_pending_requests() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut st, handle) = spawn(dir.path(), false, 1024);
        // Enqueue directly (same module) without awaiting, so all requests are
        // in-flight when shutdown is issued.
        let mut receivers = Vec::new();
        for _ in 0..50 {
            let (tx, rx) = oneshot::channel();
            handle
                .request_tx
                .try_send(IoRequest::WalAppend { data: vec![b'a'; 10], response: tx })
                .unwrap();
            receivers.push(rx);
        }
        drop(handle);
        st.shutdown();
        for (i, rx) in receivers.into_iter().enumerate() {
            let offset = rx.await.unwrap().unwrap();
            assert_eq!(offset, (i as u64) * 10);
        }
        assert_eq!(std::fs::read(dir.path().join("wal")).unwrap().len(), 500);
    }

    // WAL truncate resets the write cursor to 0.
    #[tokio::test]
    async fn test_wal_truncate_resets_offset() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut st, handle) = spawn(dir.path(), false, 64);
        handle.wal_append(b"abcde".to_vec()).await.unwrap();
        handle.wal_truncate().await.unwrap();
        let off = handle.wal_append(b"XY".to_vec()).await.unwrap();
        assert_eq!(off, 0);
        st.shutdown();
        assert_eq!(std::fs::read(dir.path().join("wal")).unwrap(), b"XY");
    }

    // SstableWrite installs the file atomically and cleans up the temp file.
    #[tokio::test]
    async fn test_sstable_write_installs_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut st, handle) = spawn(dir.path(), false, 64);
        let path = dir.path().join("sstable_000.sst");
        handle.sstable_write(path.clone(), b"SSTABLE-DATA".to_vec()).await.unwrap();
        st.shutdown();
        assert_eq!(std::fs::read(&path).unwrap(), b"SSTABLE-DATA");
        assert!(!sstable_tmp_path(&path).exists());
    }

    // Finding 4: a failed install removes the temp file (no `.tmp` accumulation).
    #[tokio::test]
    async fn test_sstable_write_removes_tmp_on_error() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut st, handle) = spawn(dir.path(), false, 64);
        // Destination is an existing directory: temp write + fsync succeed, but
        // the atomic rename fails, so the temp file must be cleaned up.
        let path = dir.path().join("dest");
        std::fs::create_dir(&path).unwrap();
        let res = handle.sstable_write(path.clone(), b"DATA".to_vec()).await;
        assert!(res.is_err());
        assert!(!sstable_tmp_path(&path).exists(), "temp file must be removed on error");
        st.shutdown();
    }

    // Finding 3: an out-of-range CPU core is rejected with an error, not a panic.
    #[test]
    fn test_pin_to_cpu_rejects_out_of_range() {
        assert!(pin_to_cpu(libc::CPU_SETSIZE).is_err());
        assert!(pin_to_cpu(libc::CPU_SETSIZE + 1000).is_err());
    }

    // Finding 1: registered (fixed) files — WAL slot 0 / VLog slot 1 round-trip.
    #[test]
    fn test_fixed_files_write_read_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let wal = open_rw(&dir.path().join("wal")).unwrap();
        let vlog = open_rw(&dir.path().join("vlog")).unwrap();
        let (mut ring, _) = build_ring(false, 500, 64).unwrap();
        ring.submitter()
            .register_files(&[wal.as_raw_fd(), vlog.as_raw_fd()])
            .unwrap();

        ring_write_all(&mut ring, RingFile::Fixed(VLOG_SLOT), 0, b"fixed-vlog").unwrap();
        let mut buf = vec![0u8; 10];
        ring_read_exact(&mut ring, RingFile::Fixed(VLOG_SLOT), 0, &mut buf).unwrap();
        assert_eq!(&buf, b"fixed-vlog");

        ring_write_all(&mut ring, RingFile::Fixed(WAL_SLOT), 0, b"fixed-wal").unwrap();
        ring_fsync(&mut ring, RingFile::Fixed(WAL_SLOT), true).unwrap();

        assert_eq!(std::fs::read(dir.path().join("wal")).unwrap(), b"fixed-wal");
        assert_eq!(std::fs::read(dir.path().join("vlog")).unwrap(), b"fixed-vlog");
    }

    // Finding 3 (thread level): VlogReopen swaps the file and resets the offset.
    #[tokio::test]
    async fn test_vlog_reopen_switches_file_and_offset() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut st, handle) = spawn(dir.path(), false, 64);
        handle.vlog_append(b"old-data".to_vec()).await.unwrap();

        let new_path = dir.path().join("vlog_gc");
        std::fs::write(&new_path, b"NEW").unwrap();
        handle.vlog_reopen(new_path.clone()).await.unwrap();

        // Offset now tracks the new file: the append lands after its 3 bytes.
        let (off, len) = handle.vlog_append(b"XY".to_vec()).await.unwrap();
        assert_eq!((off, len), (3, 2));
        assert_eq!(handle.vlog_read(0, 5).await.unwrap(), b"NEWXY");
        st.shutdown();
    }

    // 8. Integration: LsmStorageEngine mit StorageHandle -> Write + Read E2E.
    #[tokio::test]
    async fn test_lsm_engine_with_storage_handle_end_to_end() {
        let dir = tempfile::TempDir::new().unwrap();
        let wal_path = dir.path().join("wal");
        let vlog_path = dir.path().join("vlog");
        let (mut st, handle) = spawn(dir.path(), false, 1024);

        let wal = Arc::new(WriteAheadLog::with_storage_handle(handle.clone()));
        let vlog = Arc::new(VLog::with_storage_handle(&vlog_path, handle.clone()));
        let file_manager = Arc::new(FileManager::new(dir.path()).await.unwrap());
        let manifest_manager = Arc::new(ManifestManager::new(dir.path()));
        let engine = LsmStorageEngine::new(
            wal,
            wal_path,
            vlog,
            vlog_path,
            file_manager,
            manifest_manager,
            LsmEngineOptions::default(),
        )
        .await
        .unwrap();

        // Small value: WAL append routes through the storage thread.
        engine.put(b"k", b"v").await.unwrap();
        assert_eq!(engine.get(b"k").await.unwrap(), Some(b"v".to_vec()));

        // Large value: VLog append + read route through the storage thread.
        let big = vec![b'z'; 4096];
        engine.put(b"big", &big).await.unwrap();
        assert_eq!(engine.get(b"big").await.unwrap(), Some(big));

        st.shutdown();
    }

    // 9. io_engine disabled -> Local (tokio::fs) WAL/VLog path, keine Regression.
    #[tokio::test]
    async fn test_lsm_engine_local_path_no_regression() {
        let dir = tempfile::TempDir::new().unwrap();
        let wal_path = dir.path().join("wal");
        let vlog_path = dir.path().join("vlog");
        let wal = Arc::new(WriteAheadLog::new(&wal_path).await.unwrap());
        let vlog = Arc::new(VLog::new(&vlog_path).await.unwrap());
        let file_manager = Arc::new(FileManager::new(dir.path()).await.unwrap());
        let manifest_manager = Arc::new(ManifestManager::new(dir.path()));
        let engine = LsmStorageEngine::new(
            wal,
            wal_path,
            vlog,
            vlog_path,
            file_manager,
            manifest_manager,
            LsmEngineOptions::default(),
        )
        .await
        .unwrap();
        engine.put(b"k", b"v").await.unwrap();
        assert_eq!(engine.get(b"k").await.unwrap(), Some(b"v".to_vec()));
        let big = vec![b'z'; 4096];
        engine.put(b"big", &big).await.unwrap();
        assert_eq!(engine.get(b"big").await.unwrap(), Some(big));
    }
}
