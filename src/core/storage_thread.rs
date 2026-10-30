//! The storage hub: a dedicated OS thread that writes the write-ahead log of
//! every engine (key-value, JSON, relational, system) through a raw io_uring
//! ring in SQPOLL mode, one group commit across all of them.
//!
//! Two separate "ring worlds" exist when the IoEngine is enabled:
//! [`crate::core::io_engine::IoEngine`] (registered buffers, `!Send`, on the
//! engine thread's ring) and this module's raw [`io_uring::IoUring`]
//! (SQPOLL, owned exclusively by one `std::thread`). They cannot share buffers
//! or file handles, so the SQPOLL ring is built and driven entirely here,
//! because the engine thread's ring runs without SQPOLL.
//!
//! Engine tasks talk to the thread over a bounded `tokio::sync::mpsc` channel
//! (async backpressure) and await the result over a tokio `oneshot`.

use crate::core::wal::{
    log_location, segment_path, segments_in, wal_header, MIGRATING_SUFFIX, WAL_HEADER_LEN, WAL_MAGIC,
};
#[cfg(test)]
use crate::storage::test_trace;
use crate::storage::write_failures::{IoFailures, WriteFailures};
use anyhow::{anyhow, Context, Result};
use tokio::sync::mpsc::{self, Receiver, Sender};
use io_uring::{opcode, squeue, types, IoUring};
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Instant;
use tokio::sync::oneshot;

/// SQPOLL ring; falls back to the standard ring on EPERM (missing CAP_SYS_NICE).
pub const SQPOLL_ENABLED: bool = true;
pub const SQPOLL_IDLE_MS: u32 = 2000;
pub const RING_DEPTH: u32 = 256;
/// No CPU pinning.
pub const STORAGE_THREAD_CPU: i32 = -1;
/// The longest the hub waits on the ring before it looks at the channel
/// again, so a write for a free file never waits for another file's fdatasync.
/// Of 20, 50 and 100 µs, 50 helped three writing engines most and kept a
/// single writer as fast as before.
const REAP_WAIT: types::Timespec = types::Timespec::new().nsec(50_000);
/// A segment that reaches this size takes no further write: the next one
/// goes to the next segment. A batch larger than it gets a segment alone.
pub const WAL_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;

/// Runtime parameters for [`StorageThread::new`].
#[derive(Debug, Clone)]
pub struct StorageThreadConfig {
    pub sqpoll_enabled: bool,
    pub sqpoll_idle_ms: u32,
    pub ring_depth: u32,
    pub channel_capacity: usize,
    /// CPU core to pin the thread to; `-1` disables pinning.
    pub cpu: i32,
    /// [`WAL_SEGMENT_BYTES`] outside tests.
    pub segment_bytes: u64,
    /// Where the logs' failed writes are reported; handed on to the
    /// engines writing through the hub.
    pub io: IoFailures,
}

/// The engine a write-ahead log belongs to; the hub keeps one log directory per engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalTarget {
    Kv,
    Json,
    Rel,
    Sys,
}

/// An I/O request from an engine task to the storage thread.
pub enum IoRequest {
    /// Frame `data` with the next LSN of `engine`'s WAL, append it and
    /// fdatasync before responding with its offset and LSN.
    WalAppend { engine: WalTarget, data: Vec<u8>, response: oneshot::Sender<Result<(u64, u64)>> },
    /// Cut the segment `engine`'s WAL appends to back to its header; its
    /// LSNs go on where they were.
    WalTruncate { engine: WalTarget, response: oneshot::Sender<Result<()>> },
    /// Give the next append to `engine`'s WAL an LSN after `lsn`; never moves
    /// the counter back.
    SetLsnStart { engine: WalTarget, lsn: u64, response: oneshot::Sender<Result<()>> },
    /// Respond with the LSN of the last record durable in `engine`'s WAL.
    WalHeadLsn { engine: WalTarget, response: oneshot::Sender<Result<u64>> },
    /// Respond with where `engine`'s WAL ends after every append queued
    /// before this request.
    WalMark { engine: WalTarget, response: oneshot::Sender<Result<WalMark>> },
    /// Respond with the segments of `engine`'s WAL after every append queued
    /// before this request.
    WalSegments { engine: WalTarget, response: oneshot::Sender<Result<WalSegments>> },
    /// Go on in the next segment of `engine`'s WAL unless the current one
    /// holds no record; refused while its end is unsafe.
    WalRotate { engine: WalTarget, response: oneshot::Sender<Result<()>> },
    /// Forget the segments of `engine`'s WAL before `segment`, which must
    /// not lie after the one appended to; no descriptor of the hub points to
    /// them then, and the caller removes their files.
    WalDropBefore { engine: WalTarget, segment: u64, response: oneshot::Sender<Result<()>> },
    /// Drain pending requests, then stop the thread.
    Shutdown,
}

/// Where a WAL ends: the cursor in the segment appended to and the LSN of
/// its last record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalMark {
    pub offset: u64,
    pub lsn: u64,
}

/// One segment of a WAL as the hub keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentInfo {
    pub segment: u64,
    pub bytes: u64,
    /// The LSN of its last record; the start LSN of the next segment for an
    /// older one, so for one without records too.
    pub last_lsn: u64,
}

/// The segments of a WAL, oldest first, the one appended to last.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalSegments {
    /// The log's directory with every symlink resolved.
    pub dir: PathBuf,
    /// The size at which a segment takes no further write.
    pub segment_bytes: u64,
    pub segments: Vec<SegmentInfo>,
    /// When the segment appended to was opened.
    pub active_since: Instant,
}

impl WalSegments {
    /// The segment appended to.
    pub fn active(&self) -> &SegmentInfo {
        self.segments.last().expect("a WAL has a segment it appends to")
    }

    /// The segments before it.
    pub fn closed(&self) -> &[SegmentInfo] {
        &self.segments[..self.segments.len() - 1]
    }

    pub fn total_bytes(&self) -> u64 {
        self.segments.iter().map(|segment| segment.bytes).sum()
    }
}

/// Async, clonable interface to the storage thread.
#[derive(Clone)]
pub struct StorageHandle {
    request_tx: Sender<IoRequest>,
    io: IoFailures,
}

/// A slot reserved in the request channel for one append to `engine`'s WAL.
pub struct WalPermit<'a> {
    permit: mpsc::Permit<'a, IoRequest>,
    engine: WalTarget,
}

impl WalPermit<'_> {
    /// Queues `data` and waits until it is durable; returns its offset and LSN.
    pub async fn send(self, data: Vec<u8>) -> Result<(u64, u64)> {
        let (response, rx) = oneshot::channel();
        #[cfg(test)]
        let rx = crate::core::write_trace::wal_wait(self.engine, rx);
        self.permit.send(IoRequest::WalAppend { engine: self.engine, data, response });
        rx.await.map_err(|_| anyhow!("storage thread dropped response"))?
    }
}

impl StorageHandle {
    /// Waits for a slot in the request channel for an append to `engine`'s WAL.
    pub async fn reserve_wal(&self, engine: WalTarget) -> Result<WalPermit<'_>> {
        let permit = self.request_tx.reserve().await.map_err(|_| anyhow!("storage thread shut down"))?;
        Ok(WalPermit { permit, engine })
    }

    #[cfg(test)]
    pub async fn wal_append(&self, engine: WalTarget, data: Vec<u8>) -> Result<(u64, u64)> {
        self.reserve_wal(engine).await?.send(data).await
    }

    /// Cuts `engine`'s WAL back to the header of the segment appended to:
    /// the segments before it go first, here and not in the hub, then the
    /// one prepared after it and the log of an earlier version a migration
    /// left beside the directory. A truncate comes only once the SSTables
    /// hold everything the log holds and no append is on its way.
    pub async fn wal_truncate(&self, engine: WalTarget) -> Result<()> {
        let segments = self.wal_segments(engine).await?;
        let active = segments.active().segment;
        self.wal_drop_before(engine, &segments.dir, active).await?;
        self.request(|response| IoRequest::WalTruncate { engine, response }).await?;
        let prepared = segment_path(&segments.dir, active + 1);
        if prepared.try_exists()? {
            std::fs::remove_file(&prepared).with_context(|| format!("removing {}", prepared.display()))?;
            crate::storage::sync_dir(&segments.dir)?;
        }
        let migrated = with_suffix(&segments.dir, MIGRATING_SUFFIX);
        if migrated.try_exists()? {
            std::fs::remove_file(&migrated).with_context(|| format!("removing {}", migrated.display()))?;
            crate::storage::sync_dir(dir_of(&migrated))?;
        }
        Ok(())
    }

    /// The segments of `engine`'s WAL, after every append queued before this
    /// request.
    pub async fn wal_segments(&self, engine: WalTarget) -> Result<WalSegments> {
        self.request(|response| IoRequest::WalSegments { engine, response }).await
    }

    /// Has `engine`'s WAL go on in the next segment, unless the current one
    /// holds no record.
    pub async fn wal_rotate(&self, engine: WalTarget) -> Result<()> {
        self.request(|response| IoRequest::WalRotate { engine, response }).await
    }

    /// Drops the segments of `engine`'s WAL in `dir` before `segment`: the
    /// hub forgets them, then their files go, oldest first, each removal
    /// synced. A file a failed removal leaves goes with the next call.
    pub async fn wal_drop_before(&self, engine: WalTarget, dir: &Path, segment: u64) -> Result<()> {
        self.request(|response| IoRequest::WalDropBefore { engine, segment, response }).await?;
        let dir = dir.to_path_buf();
        tokio::task::spawn_blocking(move || remove_segments_before(&dir, segment))
            .await
            .context("the removal of the segments did not finish")?
    }

    pub async fn set_lsn_start(&self, engine: WalTarget, lsn: u64) -> Result<()> {
        self.request(|response| IoRequest::SetLsnStart { engine, lsn, response }).await
    }

    /// The LSN of the last record durable in `engine`'s WAL, after every
    /// append queued before this request.
    pub async fn wal_head_lsn(&self, engine: WalTarget) -> Result<u64> {
        self.request(|response| IoRequest::WalHeadLsn { engine, response }).await
    }

    /// Where `engine`'s WAL ends, after every append queued before this request.
    pub async fn wal_mark(&self, engine: WalTarget) -> Result<WalMark> {
        self.request(|response| IoRequest::WalMark { engine, response }).await
    }

    /// Where the hub reports failed writes, [`StorageThreadConfig::io`].
    pub fn io_failures(&self) -> &IoFailures {
        &self.io
    }

    async fn request<T>(&self, request: impl FnOnce(oneshot::Sender<Result<T>>) -> IoRequest) -> Result<T> {
        let (tx, rx) = oneshot::channel();
        self.request_tx.send(request(tx)).await.map_err(|_| anyhow!("storage thread shut down"))?;
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
    /// Spawns the storage thread, which builds its own SQPOLL ring and opens
    /// the WAL directory of each engine in `wals`. Blocks until the thread
    /// reports readiness (or an init error).
    pub fn new(config: StorageThreadConfig, wals: Vec<(WalTarget, PathBuf)>) -> Result<(Self, StorageHandle)> {
        // The hub numbers each WAL's appends in the order they leave this
        // channel. A request's place in it is fixed when a permit is filled,
        // not when it is reserved, so a writer draws its stamp in between and
        // the stamps follow the LSNs. A replacement channel must keep that.
        let (request_tx, request_rx) = mpsc::channel(config.channel_capacity);
        let shutdown = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<Ready>>();
        let thread_shutdown = Arc::clone(&shutdown);
        let wal_count = wals.len();
        let io = config.io.clone();

        let join_handle = std::thread::Builder::new()
            .name("luradb-storage".into())
            .spawn(move || {
                storage_thread_main(config, wals, request_rx, thread_shutdown, ready_tx);
            })
            .context("failed to spawn storage thread")?;

        match ready_rx.recv() {
            Ok(Ok(Ready { sqpoll_active })) => {
                tracing::info!(
                    "Storage thread ready (SQPOLL {}, {wal_count} write-ahead logs).",
                    if sqpoll_active { "active" } else { "disabled" }
                );
                let handle = StorageHandle { request_tx: request_tx.clone(), io };
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
        // Non-blocking: `shutdown` may run on the engine thread. If the
        // channel is full the wake is redundant — the flag above stops the loop
        // after its current turn, then the queue is drained.
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

/// What the thread reports once its WALs are open.
struct Ready {
    sqpoll_active: bool,
}

/// One engine's WAL, the segment it appends to and its cursor.
struct WalFile {
    engine: WalTarget,
    /// The segment appends go to.
    file: File,
    /// The log's directory with every symlink resolved; its segments and
    /// their markers lie in it.
    dir: PathBuf,
    /// The number of the segment in `file`; only a rotation raises it.
    segment: u64,
    /// The segments before it, oldest first.
    closed: Vec<SegmentInfo>,
    /// When the segment in `file` was opened.
    opened_at: Instant,
    /// Where a failed cut records `offset` for the next start.
    marker: PathBuf,
    offset: u64,
    /// LSN of the last record written; the next append gets the one after it.
    lsn: u64,
    /// Bytes a failed append left past `offset`, or the unsafe-end marker,
    /// may still be there; the next append cuts first, and the segment
    /// takes the next append before any rotation.
    unsafe_end: bool,
    /// The file or marker whose sync failed, and how: the hub stops the
    /// server as soon as the end of the failed append is safe for the next
    /// start, or once securing it failed for good.
    failed_sync: Option<(PathBuf, String)>,
    /// The appends' writes that failed in a row.
    write_failures: WriteFailures,
    /// The cuts after a failed append whose marker failed as well, in a
    /// row: once they stop the server, it stops without a safe end.
    secure_failures: WriteFailures,
    /// Requests for this file, in channel order, not run yet.
    queued: VecDeque<IoRequest>,
    /// The write on its way to this file; at most one at a time.
    pending: Option<Pending>,
}

/// Totals the thread logs when it stops; appends per fdatasync is the
/// average group-commit size.
#[derive(Debug, Default, PartialEq, Eq)]
struct HubStats {
    appends: u64,
    /// Turns that started at least one append.
    batches: u64,
    fdatasyncs: u64,
    /// Rotations that found no prepared segment and created it.
    created_segments: u64,
}

struct StorageState {
    ring: IoUring,
    /// In the order given to [`StorageThread::new`]; a file's index is its
    /// fixed-file slot.
    wals: Vec<WalFile>,
    segment_bytes: u64,
    /// `false` after a failed `register_files` — ops then fall back to raw fds.
    fixed_files: bool,
    stats: HubStats,
    /// Completions of the chains on the ring not reaped yet.
    unreaped: usize,
    #[cfg(test)]
    faults: Faults,
}

/// Test-only faults, each reported once by the next operation of its kind
/// unless it says otherwise, and the counters the tests read.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct Faults {
    /// The next sync fails after its write has landed.
    pub(crate) sync: bool,
    /// The next write is reported failed with this OS error once its bytes
    /// landed; the cut after it removes them.
    pub(crate) write: Option<i32>,
    /// Until reset, each write of the hub lands at most this many bytes, as
    /// a short write would.
    pub(crate) max_write_len: Option<usize>,
    /// The next cut back to the cursor fails and leaves the file as it is.
    pub(crate) cut: bool,
    /// The next write of the unsafe-end marker fails and writes nothing.
    pub(crate) mark: bool,
    /// The next removal of the unsafe-end marker fails and leaves it.
    pub(crate) unmark: bool,
    /// The next removal of the unsafe-end marker removes it, then fails to
    /// sync its directory.
    pub(crate) unmark_sync: bool,
    /// The directories the removals of the unsafe-end marker have synced, in
    /// order, the injected failure included.
    pub(crate) unmark_syncs: Vec<PathBuf>,
    /// Until reset, the chain of this engine's file stays on its way once
    /// its completions are reaped: its appends wait for their answer.
    pub(crate) held: Option<WalTarget>,
    /// The next update of a fixed-file slot to a new file fails.
    pub(crate) files_update: bool,
    /// The next release of a fixed-file slot fails.
    pub(crate) files_release: bool,
    /// Slots that keep a replaced file open, each logged.
    pub(crate) leaked_slots: u64,
}

#[cfg(test)]
thread_local! {
    /// (fail the next sync, directories synced) of the marker removal running
    /// on this thread, set while its [`DirSyncProbe`] lives.
    static DIR_SYNC_PROBE: std::cell::RefCell<Option<(bool, Vec<PathBuf>)>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
impl Faults {
    /// Lets the directory syncs on this thread see `unmark_sync` and record
    /// into `unmark_syncs` until the returned probe drops.
    pub(crate) fn probe_unmark_syncs(&mut self) -> DirSyncProbe<'_> {
        DIR_SYNC_PROBE.set(Some((std::mem::take(&mut self.unmark_sync), Vec::new())));
        DirSyncProbe(self)
    }
}

#[cfg(test)]
pub(crate) struct DirSyncProbe<'a>(&'a mut Faults);

#[cfg(test)]
impl Drop for DirSyncProbe<'_> {
    fn drop(&mut self) {
        if let Some((fail, synced)) = DIR_SYNC_PROBE.take() {
            self.0.unmark_sync |= fail;
            self.0.unmark_syncs.extend(synced);
        }
    }
}

impl StorageState {
    fn wal_index(&self, engine: WalTarget) -> Result<usize> {
        self.wals
            .iter()
            .position(|wal| wal.engine == engine)
            .ok_or_else(|| anyhow!("the storage thread has no write-ahead log open for the {engine:?} engine"))
    }

    fn ring_file(&self, index: usize) -> RingFile {
        if self.fixed_files { RingFile::Fixed(index as u32) } else { RingFile::Raw(self.wals[index].file.as_raw_fd()) }
    }

    /// Nothing queued and no write on its way.
    fn idle(&self) -> bool {
        self.wals.iter().all(|wal| wal.queued.is_empty() && wal.pending.is_none())
    }

    /// The file's end stays unsafe until the cut and the marker removal both
    /// succeed; a failed cut records the cursor in the marker.
    fn cut_to_cursor(&mut self, index: usize) -> Result<(), CutFailed> {
        self.wals[index].unsafe_end = true;
        if let Err(error) = self.cut_file(index) {
            return Err(match self.mark(index) {
                Ok(()) => {
                    self.wals[index].secure_failures.succeeded();
                    CutFailed { error, secured: true, stops: false }
                }
                Err(marking) => {
                    let wal = &self.wals[index];
                    CutFailed { error, secured: false, stops: wal.secure_failures.stops_for(&wal.marker, &marking) }
                }
            });
        }
        self.wals[index].secure_failures.succeeded();
        if let Err(error) = self.unmark(index) {
            let marker = self.wals[index].marker.clone();
            self.note_sync(index, marker, &error);
            return Err(CutFailed { error, secured: true, stops: false });
        }
        self.wals[index].unsafe_end = false;
        Ok(())
    }

    fn cut_file(&mut self, index: usize) -> std::io::Result<()> {
        #[cfg(test)]
        if std::mem::take(&mut self.faults.cut) {
            return Err(std::io::Error::other("injected cut failure"));
        }
        let wal = &self.wals[index];
        wal.file.set_len(wal.offset)?;
        if let Err(e) = wal.file.sync_all() {
            let segment = segment_path(&wal.dir, wal.segment);
            self.fail_sync(index, segment, &e);
            return Err(e);
        }
        Ok(())
    }

    /// Records the cursor in the marker.
    fn mark(&mut self, index: usize) -> std::io::Result<()> {
        #[cfg(test)]
        if std::mem::take(&mut self.faults.mark) {
            tracing::error!("Writing the unsafe-end marker failed: injected marker failure.");
            return Err(std::io::Error::other("injected marker failure"));
        }
        let (marker, offset) = (self.wals[index].marker.clone(), self.wals[index].offset);
        let marked = mark_unsafe_end(&marker, offset);
        if let Err(e) = &marked {
            self.note_sync(index, marker, e);
        }
        marked
    }

    /// Removes the marker and syncs its directory, the segments' one.
    fn unmark(&mut self, index: usize) -> std::io::Result<()> {
        #[cfg(test)]
        if std::mem::take(&mut self.faults.unmark) {
            return Err(std::io::Error::other("injected marker removal failure"));
        }
        #[cfg(test)]
        let _probe = self.faults.probe_unmark_syncs();
        unmark_unsafe_end(&self.wals[index].marker)
    }

    /// Notes the failed sync of `path`, a file of WAL `index`; the first one
    /// counts.
    fn fail_sync(&mut self, index: usize, path: PathBuf, error: &dyn std::fmt::Display) {
        self.wals[index].failed_sync.get_or_insert_with(|| (path, error.to_string()));
    }

    /// [`Self::fail_sync`] when `error` comes from a sync.
    fn note_sync(&mut self, index: usize, path: PathBuf, error: &std::io::Error) {
        if is_sync_error(error) {
            self.fail_sync(index, path, error);
        }
    }

    /// Stops the server after a cut of WAL `index`, if it must: for a failed
    /// sync once the end of the failed append is safe for the next start,
    /// and without a safe end once securing it failed for good. Returns only
    /// in tests, with the stop's error.
    fn stop_after_cut(&mut self, index: usize, cut: &Result<(), CutFailed>) -> Option<anyhow::Error> {
        let wal = &mut self.wals[index];
        match cut {
            Err(failed) if !failed.secured => {
                if !failed.stops {
                    return None;
                }
                Some(match wal.failed_sync.take() {
                    Some((path, error)) => crate::storage::fatal_sync_error(&path, &error),
                    None => crate::storage::fatal_write_error(&segment_path(&wal.dir, wal.segment), &failed.error),
                })
            }
            _ => {
                let (path, error) = wal.failed_sync.take()?;
                Some(crate::storage::fatal_sync_error(&path, &error))
            }
        }
    }

    /// Puts `file` in place of the file of WAL `index`. A fixed-file slot
    /// that cannot take it is released, and every WAL goes on with raw
    /// descriptors.
    fn swap_file(&mut self, index: usize, file: File) {
        // A slot holds a reference of its own: closing the old descriptor
        // here does not free the old file while its slot still names it.
        self.wals[index].file = file;
        if !self.fixed_files {
            return;
        }
        let (engine, fd) = (self.wals[index].engine, self.wals[index].file.as_raw_fd());
        let failed = match self.update_slot(index, fd) {
            Ok(1) => return,
            Ok(n) => std::io::Error::other(format!("{n} slots updated instead of 1")),
            Err(e) => e,
        };
        tracing::warn!(
            "Updating the fixed-file slot of the {engine:?} write-ahead log failed: {failed}; \
             every write-ahead log uses raw file descriptors from now on."
        );
        if let Err(e) = self.update_slot(index, -1).and_then(|n| match n {
            1 => Ok(()),
            n => Err(std::io::Error::other(format!("{n} slots released instead of 1"))),
        }) {
            tracing::warn!(
                "Releasing the fixed-file slot of the {engine:?} write-ahead log failed as well: {e}; \
                 the replaced file stays on disk until the next start."
            );
            #[cfg(test)]
            {
                self.faults.leaked_slots += 1;
            }
        }
        self.fixed_files = false;
    }

    /// Points fixed-file slot `index` at `fd`, or frees it for `-1`.
    fn update_slot(&mut self, index: usize, fd: RawFd) -> std::io::Result<usize> {
        #[cfg(test)]
        if std::mem::take(if fd < 0 { &mut self.faults.files_release } else { &mut self.faults.files_update }) {
            return Err(std::io::Error::other("injected fixed-file slot failure"));
        }
        self.ring.submitter().register_files_update(index as u32, &[fd])
    }
}

/// Target file for a ring op: a registered fixed-file slot, or a raw fd.
#[derive(Clone, Copy)]
enum RingFile {
    Fixed(u32),
    Raw(RawFd),
}

fn storage_thread_main(
    config: StorageThreadConfig,
    wals: Vec<(WalTarget, PathBuf)>,
    mut request_rx: Receiver<IoRequest>,
    shutdown: Arc<AtomicBool>,
    ready_tx: std::sync::mpsc::Sender<Result<Ready>>,
) {
    if config.cpu >= 0 {
        if let Err(e) = pin_to_cpu(config.cpu) {
            tracing::warn!("Storage thread CPU pinning to core {} failed: {e}", config.cpu);
        }
    }

    let mut state = match open_state(&config, &wals) {
        Ok((state, sqpoll_active)) => {
            let _ = ready_tx.send(Ok(Ready { sqpoll_active }));
            state
        }
        Err(e) => {
            let _ = ready_tx.send(Err(e));
            return;
        }
    };

    event_loop(&mut state, &mut request_rx, &shutdown);
    let HubStats { appends, batches, fdatasyncs, created_segments } = state.stats;
    tracing::info!(
        "Storage thread stopped: {appends} WAL appends in {batches} batches, {fdatasyncs} fdatasyncs, \
         {created_segments} segments created without preparation."
    );
}

/// Builds the ring and opens the WALs; returns the state and whether SQPOLL
/// is active.
fn open_state(config: &StorageThreadConfig, wals: &[(WalTarget, PathBuf)]) -> Result<(StorageState, bool)> {
    // A file's write goes into the submission queue together with its fdatasync.
    if config.ring_depth < 2 {
        return Err(anyhow!("the storage ring needs a depth of at least 2, not {}", config.ring_depth));
    }
    let (ring, sqpoll_active) = build_ring(config.sqpoll_enabled, config.sqpoll_idle_ms, config.ring_depth)?;
    let mut files = Vec::with_capacity(wals.len());
    for (engine, path) in wals {
        move_single_file_aside(path)
            .with_context(|| format!("moving the write-ahead log {} of an earlier version aside", path.display()))?;
        files.push(open_log(*engine, path, &config.io).with_context(|| format!("opening the write-ahead log {}", path.display()))?);
    }
    // Register the WALs once as fixed files so the kernel skips the fd lookup
    // per op; on failure fall back to raw fds.
    let fds: Vec<RawFd> = files.iter().map(|wal| wal.file.as_raw_fd()).collect();
    let fixed_files = match ring.submitter().register_files(&fds) {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!("io_uring register_files failed: {e}; using raw fds");
            false
        }
    };
    let state = StorageState {
        ring,
        wals: files,
        segment_bytes: config.segment_bytes,
        fixed_files,
        stats: HubStats::default(),
        unreaped: 0,
        #[cfg(test)]
        faults: Faults::default(),
    };
    Ok((state, sqpoll_active))
}

/// Gives a log of an earlier version, a single file at `path`, the segment
/// directory of this one: a cut back's leftover goes and its unsafe-end
/// marker is applied as before, the file moves to `<path>.migrating`, where
/// recovery reads it until the next truncate, and a directory with an empty
/// segment 1 takes its place. Found beside a `.migrating` file, a missing
/// directory or segment is created too. With a symlink as the path, all of
/// it happens at its target.
fn move_single_file_aside(path: &Path) -> Result<()> {
    let location = log_location(path)?;
    let migrating = with_suffix(&location, MIGRATING_SUFFIX);
    if std::fs::metadata(&location).is_ok_and(|meta| meta.is_file()) {
        remove_if_there(&with_suffix(&location, ".tmp"))?;
        let file = OpenOptions::new().read(true).write(true).open(&location)?;
        apply_unsafe_end_marker(path, &file)
            .with_context(|| format!("applying the unsafe-end marker {}", unsafe_end_marker(path).display()))?;
        drop(file);
        std::fs::rename(&location, &migrating)?;
        sync_dir(&location)?;
        tracing::info!(
            "Moved the write-ahead log {} of an earlier version to {}; the start replays it from there.",
            location.display(),
            migrating.display()
        );
    }
    if !migrating.try_exists()? {
        return Ok(());
    }
    if create_dir_if_missing(&location)? {
        sync_dir(&location)?;
    }
    if !segment_path(&location, 1).try_exists()? {
        create_segment(&location, 1, 0)?;
    }
    Ok(())
}

/// Creates `dir` unless it exists; whether it did.
fn create_dir_if_missing(dir: &Path) -> std::io::Result<bool> {
    match std::fs::create_dir(dir) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e),
    }
}

/// Creates segment `n` in `dir` with a header that starts after `start_lsn`,
/// synced with its directory entry.
fn create_segment(dir: &Path, n: u64, start_lsn: u64) -> std::io::Result<File> {
    let path = segment_path(dir, n);
    let file = OpenOptions::new().read(true).write(true).create_new(true).open(&path)?;
    file.write_all_at(&wal_header(start_lsn), 0)?;
    file.sync_all()?;
    sync_dir(&path)?;
    Ok(file)
}

/// Opens the log directory at `path`, created if missing: removes the
/// segments a checkpoint left half prepared, drops a last segment without
/// records that follows another, refuses an unsafe-end marker beside any
/// segment but the last, applies the last one's, and opens the last one.
fn open_log(engine: WalTarget, path: &Path, io: &IoFailures) -> Result<WalFile> {
    let location = log_location(path)?;
    if create_dir_if_missing(&location)? {
        sync_dir(&location)?;
    }
    let dir = std::fs::canonicalize(&location)?;
    anyhow::ensure!(dir.is_dir(), "{} is no directory", dir.display());
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?.path();
        if entry.to_str().is_some_and(|name| name.ends_with(".wal.tmp")) {
            std::fs::remove_file(&entry).with_context(|| format!("removing {}", entry.display()))?;
        }
    }
    let mut segments = segments_in(&dir)?;
    if segments.is_empty() {
        create_segment(&dir, 1, 0)?;
        segments = segments_in(&dir)?;
    }
    let (segment, file, start_lsn) = loop {
        let (segment, last) = segments.last().cloned().expect("a segment");
        let behind = segments.len() > 1;
        // An empty last segment behind another one holds nothing; the one
        // before it goes on instead.
        if behind && std::fs::metadata(&last)?.len() <= WAL_HEADER_LEN {
            let marker = unsafe_end_marker(&last);
            anyhow::ensure!(
                !marker.try_exists()?,
                "the unsafe-end marker {} lies beside a segment without records",
                marker.display()
            );
            std::fs::remove_file(&last).with_context(|| format!("removing {}", last.display()))?;
            sync_dir(&last)?;
            segments.pop();
            continue;
        }
        for (_, older) in &segments[..segments.len() - 1] {
            let marker = unsafe_end_marker(older);
            anyhow::ensure!(
                !marker.try_exists()?,
                "the unsafe-end marker {} lies beside a segment that is not the last one",
                marker.display()
            );
        }
        let file = open_rw(&last)?;
        apply_unsafe_end_marker(&last, &file).with_context(|| {
            format!("applying the unsafe-end marker {}", unsafe_end_marker(&last).display())
        })?;
        // Cut back to its header by the marker, it goes as well.
        if behind && file.metadata()?.len() <= WAL_HEADER_LEN {
            continue;
        }
        let start_lsn = ensure_header(&file)
            .with_context(|| format!("writing the header of {}", last.display()))?
            .with_context(|| format!("the segment {} has no header of this version", last.display()))?;
        break (segment, file, start_lsn);
    };
    // An older segment ends where the next one starts.
    let mut closed = Vec::with_capacity(segments.len() - 1);
    let mut next_start = start_lsn;
    for (n, older) in segments[..segments.len() - 1].iter().rev() {
        let bytes = std::fs::metadata(older)?.len();
        closed.push(SegmentInfo { segment: *n, bytes, last_lsn: next_start });
        next_start = start_lsn_of(older)?;
    }
    closed.reverse();
    let offset = file.metadata()?.len();
    let marker = unsafe_end_marker(&segment_path(&dir, segment));
    Ok(WalFile {
        engine,
        file,
        dir,
        segment,
        closed,
        opened_at: Instant::now(),
        marker,
        offset,
        // The recovery sets the counter past the records of the segment.
        lsn: start_lsn,
        unsafe_end: false,
        failed_sync: None,
        write_failures: WriteFailures::new(io),
        secure_failures: WriteFailures::new(io),
        queued: VecDeque::new(),
        pending: None,
    })
}

/// The start LSN in the header of the segment at `path`.
fn start_lsn_of(path: &Path) -> Result<u64> {
    let mut head = [0; WAL_HEADER_LEN as usize];
    File::open(path)?.read_exact_at(&mut head, 0).with_context(|| format!("reading the header of {}", path.display()))?;
    let (magic, start) = head.split_at(WAL_MAGIC.len());
    anyhow::ensure!(magic == WAL_MAGIC, "the segment {} has no header of this version", path.display());
    Ok(u64::from_be_bytes(start.try_into().expect("8 bytes")))
}

/// Removes the segment files in `dir` before `segment`, oldest first, and
/// syncs the directory after each, so no gap opens between segments.
fn remove_segments_before(dir: &Path, segment: u64) -> Result<()> {
    for (n, path) in segments_in(dir)? {
        if n >= segment {
            break;
        }
        #[cfg(test)]
        crate::storage::test_fault::check(&path)?;
        std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
        #[cfg(test)]
        test_trace::record(&path, "unlink");
        crate::storage::sync_dir(dir)?;
    }
    Ok(())
}

/// Prepares segment `segment` of the log directory `dir` for the hub, which
/// then only opens it: the header, whose start LSN the hub writes, goes into
/// `<segment>.wal.tmp`, synced, then under the segment's name unless one is
/// there already, and the directory is synced. Runs outside the hub.
pub(crate) fn prepare_segment(dir: &Path, segment: u64) -> Result<()> {
    let path = segment_path(dir, segment);
    let tmp = with_suffix(&path, ".tmp");
    let file = OpenOptions::new().write(true).create(true).truncate(true).open(&tmp)?;
    file.write_all_at(&wal_header(0), 0)?;
    file.sync_all()?;
    // A link, unlike a rename, never replaces a segment the hub created.
    match std::fs::hard_link(&tmp, &path) {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => return Err(e.into()),
        _ => {}
    }
    std::fs::remove_file(&tmp)?;
    crate::storage::sync_dir(dir)
}

/// Aborts the process when the hub unwinds from a panic with chains on the
/// ring: dropping the state would free buffers the kernel may still use.
struct AbortOnUnwind<'a>(&'a mut StorageState);

impl Drop for AbortOnUnwind<'_> {
    fn drop(&mut self) {
        if must_abort(self.0, std::thread::panicking()) {
            eprintln!("luradb storage hub: panicked with writes on the ring, aborting to avoid a use-after-free");
            std::process::abort();
        }
    }
}

fn must_abort(state: &StorageState, panicking: bool) -> bool {
    panicking && state.unreaped > 0
}

fn event_loop(state: &mut StorageState, rx: &mut Receiver<IoRequest>, shutdown: &AtomicBool) {
    let guard = AbortOnUnwind(state);
    let state = &mut *guard.0;
    let mut stop = false;
    loop {
        // Thread is a plain `std::thread`, not a tokio context — `blocking_recv`
        // parks it until a request arrives (or all senders drop). With a write
        // on its way the hub waits on the ring instead and looks at the
        // channel after each completion, and at least every `REAP_WAIT`.
        if state.idle() {
            match rx.blocking_recv() {
                Some(request) => stop |= accept(state, request),
                None => return, // all senders dropped
            }
        }
        // Everything queued meanwhile joins the next submit (group commit).
        while let Ok(request) = rx.try_recv() {
            stop |= accept(state, request);
        }
        if stop || shutdown.load(Ordering::SeqCst) {
            drain_remaining(state, rx);
            return;
        }
        turn(state);
    }
}

/// Drains whatever is still queued (best-effort) and finishes every write on
/// its way, so no pending request is lost.
fn drain_remaining(state: &mut StorageState, rx: &mut Receiver<IoRequest>) {
    let mut batch = Vec::new();
    while let Ok(req) = rx.try_recv() {
        batch.push(req);
    }
    process_batch(state, batch);
}

/// Takes `batch` in, in channel order, and runs until no chain is on the
/// ring and each file with queued requests waits for its write on its way.
/// Returns `true` if a `Shutdown` was seen.
fn process_batch(state: &mut StorageState, batch: Vec<IoRequest>) -> bool {
    let mut stop = false;
    for request in batch {
        stop |= accept(state, request);
    }
    while turn(state) {}
    stop
}

/// Queues a request behind the earlier ones for its file, or answers it at
/// once if no file is open for its engine. Returns `true` for a `Shutdown`.
fn accept(state: &mut StorageState, request: IoRequest) -> bool {
    let engine = match &request {
        IoRequest::Shutdown => return true,
        IoRequest::WalAppend { engine, .. } => {
            state.stats.appends += 1;
            *engine
        }
        IoRequest::WalTruncate { engine, .. }
        | IoRequest::SetLsnStart { engine, .. }
        | IoRequest::WalHeadLsn { engine, .. }
        | IoRequest::WalMark { engine, .. }
        | IoRequest::WalSegments { engine, .. }
        | IoRequest::WalRotate { engine, .. }
        | IoRequest::WalDropBefore { engine, .. } => *engine,
    };
    match state.wal_index(engine) {
        Ok(index) => state.wals[index].queued.push_back(request),
        Err(e) => refuse(request, e),
    }
    false
}

/// Answers `request` with `e`.
fn refuse(request: IoRequest, e: anyhow::Error) {
    match request {
        IoRequest::WalAppend { response, .. } => {
            let _ = response.send(Err(anyhow!("WAL append failed: {e}")));
        }
        IoRequest::WalTruncate { response, .. }
        | IoRequest::SetLsnStart { response, .. }
        | IoRequest::WalRotate { response, .. }
        | IoRequest::WalDropBefore { response, .. } => {
            let _ = response.send(Err(e));
        }
        IoRequest::WalHeadLsn { response, .. } => {
            let _ = response.send(Err(e));
        }
        IoRequest::WalMark { response, .. } => {
            let _ = response.send(Err(e));
        }
        IoRequest::WalSegments { response, .. } => {
            let _ = response.send(Err(e));
        }
        IoRequest::Shutdown => {}
    }
}

/// One turn of the hub: answers the writes whose chains are reaped, starts
/// what can start and, while chains are on the ring, waits for completions.
/// Returns whether the next turn has work: a chain on the ring, or a queued
/// request of a file without a write on its way (e.g. behind a refused append).
fn turn(state: &mut StorageState) -> bool {
    take_reaped(state);
    start_queued(state);
    push_chains(state);
    if state.unreaped == 0 {
        return state.wals.iter().any(|wal| wal.pending.is_none() && !wal.queued.is_empty());
    }
    reap(state);
    true
}

/// Each file without a write on its way runs its queued requests in channel
/// order: the ones other than appends at once, the appends up to the next
/// such request in one write per file, all files' writes planned together.
fn start_queued(state: &mut StorageState) {
    let mut run = Vec::new();
    for index in 0..state.wals.len() {
        if state.wals[index].pending.is_some() {
            continue;
        }
        let mut appended = false;
        loop {
            match state.wals[index].queued.pop_front() {
                Some(IoRequest::WalAppend { engine, data, response }) => {
                    run.push((engine, data, response));
                    appended = true;
                }
                Some(request) if appended => {
                    state.wals[index].queued.push_front(request);
                    break;
                }
                Some(IoRequest::WalTruncate { engine, response }) => {
                    let _ = response.send(do_wal_truncate(state, engine));
                }
                Some(IoRequest::SetLsnStart { lsn, response, .. }) => {
                    let wal = &mut state.wals[index];
                    wal.lsn = wal.lsn.max(lsn);
                    let _ = response.send(Ok(()));
                }
                Some(IoRequest::WalHeadLsn { response, .. }) => {
                    let _ = response.send(Ok(state.wals[index].lsn));
                }
                Some(IoRequest::WalMark { response, .. }) => {
                    let WalFile { offset, lsn, .. } = state.wals[index];
                    let _ = response.send(Ok(WalMark { offset, lsn }));
                }
                Some(IoRequest::WalSegments { response, .. }) => {
                    let _ = response.send(Ok(segments_of(state, index)));
                }
                Some(IoRequest::WalRotate { response, .. }) => {
                    let wal = &state.wals[index];
                    let rotated = if wal.unsafe_end {
                        Err(anyhow!(
                            "the {:?} write-ahead log keeps its segment until the end of its last failed append is safe",
                            wal.engine
                        ))
                    } else if wal.offset > WAL_HEADER_LEN {
                        rotate(state, index).map_err(Into::into)
                    } else {
                        Ok(())
                    };
                    let _ = response.send(rotated);
                }
                Some(IoRequest::WalDropBefore { segment, response, .. }) => {
                    let wal = &mut state.wals[index];
                    let dropped = if segment > wal.segment {
                        Err(anyhow!(
                            "segment {segment} of the {:?} write-ahead log lies after segment {}, which takes the appends",
                            wal.engine,
                            wal.segment
                        ))
                    } else {
                        wal.closed.retain(|closed| closed.segment >= segment);
                        Ok(())
                    };
                    let _ = response.send(dropped);
                }
                Some(IoRequest::Shutdown) | None => break,
            }
        }
    }
    if !run.is_empty() {
        state.stats.batches += 1;
        start_writes(state, run);
    }
}

/// One combined write of a batch to one WAL file.
#[derive(Debug, PartialEq, Eq)]
struct FileWrite {
    engine: WalTarget,
    /// The records for this file, each framed with its LSN, concatenated in
    /// channel order.
    data: Vec<u8>,
    /// Per record: its position in the batch, its offset within `data` and
    /// its LSN.
    parts: Vec<(usize, u64, u64)>,
}

/// Plans a run of appends: one [`FileWrite`] per engine that has any, in the
/// order the engines first appear. Each engine's records get the LSNs after
/// `last_lsn` of that engine, in channel order.
fn plan_batch<'a>(
    appends: impl IntoIterator<Item = (WalTarget, &'a [u8])>,
    last_lsn: impl Fn(WalTarget) -> u64,
) -> Vec<FileWrite> {
    let mut writes: Vec<FileWrite> = Vec::new();
    for (position, (engine, payload)) in appends.into_iter().enumerate() {
        let index = match writes.iter().position(|write| write.engine == engine) {
            Some(index) => index,
            None => {
                writes.push(FileWrite { engine, data: Vec::new(), parts: Vec::new() });
                writes.len() - 1
            }
        };
        let write = &mut writes[index];
        let lsn = last_lsn(engine) + write.parts.len() as u64 + 1;
        write.parts.push((position, write.data.len() as u64, lsn));
        write.data.extend_from_slice(&lsn.to_be_bytes());
        write.data.extend_from_slice(payload);
    }
    writes
}

type Responder = oneshot::Sender<Result<(u64, u64)>>;
type Append = (WalTarget, Vec<u8>, Responder);

/// Plans a run of appends, one [`FileWrite`] per WAL file, and puts each on
/// its way to its file; a file whose end is not safe for an append answers
/// its requests with the failure at once.
fn start_writes(state: &mut StorageState, run: Vec<Append>) {
    #[cfg(test)]
    let picked = crate::core::write_trace::now();
    let last_lsn = |engine: WalTarget| state.wal_index(engine).map_or(0, |index| state.wals[index].lsn);
    let writes = plan_batch(run.iter().map(|(engine, data, _)| (*engine, data.as_slice())), last_lsn);
    let mut responses: Vec<_> = run.into_iter().map(|(_, _, response)| Some(response)).collect();
    for write in writes {
        let responses = write.parts.iter().map(|part| responses[part.0].take()).collect();
        match ready_to_append(state, write.engine) {
            Ok(index) => {
                let start = state.wals[index].offset;
                state.wals[index].pending = Some(Pending {
                    write,
                    responses,
                    index,
                    start,
                    landed: 0,
                    on_ring: false,
                    wrote: None,
                    synced: None,
                    #[cfg(test)]
                    picked,
                    #[cfg(test)]
                    stamps: Default::default(),
                });
            }
            Err(e) => answer(&write, responses, Err(e)),
        }
    }
}

/// Answers each request of `write` with the offset and the LSN of its
/// record, given the offset the write starts at, or with the failure.
fn answer(write: &FileWrite, responses: Vec<Option<Responder>>, result: Result<u64>) {
    let result = result.map_err(|e| e.to_string());
    for (&(_, offset, lsn), response) in write.parts.iter().zip(responses) {
        let Some(response) = response else { continue };
        let _ = response.send(match &result {
            Ok(start) => Ok((start + offset, lsn)),
            Err(msg) => Err(anyhow!("WAL append failed: {msg}")),
        });
    }
}

/// A write on its way to its file. The hub keeps it, its buffer included,
/// until both completions of its last chain are reaped.
struct Pending {
    write: FileWrite,
    /// Per part of `write`, the request waiting for its answer.
    responses: Vec<Option<Responder>>,
    /// The file's index.
    index: usize,
    /// The file's cursor, where the write starts.
    start: u64,
    /// Bytes of the write that have landed.
    landed: usize,
    /// Its chain is in the submission queue or on the ring.
    on_ring: bool,
    /// The results of the chain's write and fdatasync, once reaped.
    wrote: Option<i32>,
    synced: Option<i32>,
    #[cfg(test)]
    picked: Option<std::time::Instant>,
    #[cfg(test)]
    stamps: crate::core::write_trace::ChainStamps,
}

/// Puts the chain of each write not on the ring yet into the submission
/// queue — a write of the rest of its bytes, linked to an fdatasync of its
/// file — while the completion queue has room for all chains on the ring.
///
/// At most one chain per WAL file is on its way: a file starts its next
/// write only once its last chain is reaped, so it gets its bytes in channel
/// order, the rest of a short write behind the bytes that landed, and a cut
/// after a failure races no write. Other files' chains go in meanwhile.
fn push_chains(state: &mut StorageState) {
    #[cfg(test)]
    let submit = crate::core::write_trace::SubmitStamps::start();
    let room = state.ring.params().sq_entries() as usize;
    for index in 0..state.wals.len() {
        let file = state.ring_file(index);
        let Some(p) = state.wals[index].pending.as_mut().filter(|p| !p.on_ring) else { continue };
        if state.unreaped + 2 > room {
            break;
        }
        let rest = &p.write.data[p.landed..];
        #[cfg(test)]
        let rest = &rest[..rest.len().min(state.faults.max_write_len.unwrap_or(usize::MAX))];
        // An SQE takes a u32 length; the rest of a longer write follows in
        // the file's next chain, as after a short write.
        let len = rest.len().min(u32::MAX as usize) as u32;
        // `user_data` names the file and the step: with one chain per file
        // on the ring, that identifies the chain.
        let write = write_entry(file, rest.as_ptr(), len, p.start + p.landed as u64)
            .flags(squeue::Flags::IO_LINK)
            .user_data(2 * index as u64);
        let sync = fsync_entry(file).user_data(2 * index as u64 + 1);
        // Safe: the buffer stays in `pending` until `reap` has both
        // completions of the chain (or the process aborts).
        if unsafe { state.ring.submission().push_multiple(&[write, sync]) }.is_err() {
            break;
        }
        p.on_ring = true;
        state.unreaped += 2;
        #[cfg(test)]
        {
            p.stamps = submit.chain();
        }
    }
}

/// Submits the chains pushed so far, waits up to [`REAP_WAIT`] for a
/// completion and takes in every completion there is; a completion's
/// `user_data` names its file and step (2 · file + 0 write, 1 fdatasync). The
/// kernel runs a chain's fdatasync only once its write has landed in full and
/// cancels it otherwise.
///
/// Once the SQEs are published, the kernel (in SQPOLL mode, its poll thread)
/// may run them at any time, so a write's buffer lives in its file's
/// `pending` until both completions are reaped. The wait can end without a
/// completion: on the timeout (`ETIME`) or a signal (`EINTR`, not retried by
/// io-uring 0.6); the next turn waits again. Any other error leaves
/// possibly-in-flight ops we can neither reap nor cancel; going on could free
/// a live buffer, so we abort instead (safety over uptime).
fn reap(state: &mut StorageState) {
    let args = types::SubmitArgs::new().timespec(&REAP_WAIT);
    match state.ring.submitter().submit_with_args(1, &args) {
        Ok(_) => {}
        Err(e) if matches!(e.raw_os_error(), Some(libc::EINTR | libc::ETIME)) => {}
        Err(e) => {
            eprintln!(
                "luradb storage ring: unrecoverable submit error, \
                 aborting to avoid a use-after-free on an in-flight op: {e}"
            );
            std::process::abort();
        }
    }
    for entry in state.ring.completion() {
        state.unreaped -= 1;
        let Some(p) = &mut state.wals[entry.user_data() as usize / 2].pending else { continue };
        let synced = entry.user_data() % 2 == 1;
        #[cfg(test)]
        p.stamps.complete(synced);
        if synced {
            p.synced = Some(entry.result());
        } else {
            p.wrote = Some(entry.result());
        }
    }
}

/// Takes in each write whose chain is reaped: answers its requests once the
/// write has its outcome, or leaves the rest of a short write for the next
/// chain.
fn take_reaped(state: &mut StorageState) {
    for index in 0..state.wals.len() {
        #[cfg(test)]
        if state.faults.held == Some(state.wals[index].engine) {
            continue;
        }
        let Some(completed) = state.wals[index].pending.as_ref().and_then(|p| p.wrote.zip(p.synced)) else { continue };
        let Some(mut p) = state.wals[index].pending.take() else { continue };
        match take_chain(state, &mut p, completed) {
            None => {
                (p.on_ring, p.wrote, p.synced) = (false, None, None);
                state.wals[index].pending = Some(p);
            }
            Some(result) => {
                #[cfg(test)]
                if result.is_ok() {
                    crate::core::write_trace::hub_answered(p.picked, p.write.engine, p.write.parts.iter().map(|part| part.2));
                }
                answer(&p.write, p.responses, result);
            }
        }
    }
}

/// The index of `engine`'s file, once its end is safe for an append at the
/// cursor. A segment that reached the segment size is left for the next one
/// first, never with an unsafe end; a failed rotation leaves the appends in
/// the current segment. After a failed sync whose append's end was not safe
/// yet, the cut that makes it safe stops the server, as does the cut whose
/// failure ends the attempts to secure it.
fn ready_to_append(state: &mut StorageState, engine: WalTarget) -> Result<usize> {
    let index = state.wal_index(engine)?;
    if state.wals[index].unsafe_end {
        let cut = state.cut_to_cursor(index);
        if let Err(failed) = &cut {
            log_failed_cut(engine, state.wals[index].offset, &failed.error);
        }
        if let Some(stop) = state.stop_after_cut(index, &cut) {
            return Err(stop);
        }
        cut.map_err(|failed| failed.error)?;
    }
    let offset = state.wals[index].offset;
    if offset >= state.segment_bytes && offset > WAL_HEADER_LEN {
        if let Err(e) = rotate(state, index) {
            tracing::warn!(
                "Moving the {engine:?} write-ahead log to its next segment failed: {e}; it goes on in segment {}.",
                state.wals[index].segment
            );
        }
    }
    Ok(index)
}

/// Goes on in the next segment of WAL `index`: opens the file the checkpoint
/// prepared, or creates it where none is, writes the header that starts
/// after the last LSN, which the first append's fdatasync makes durable, and
/// puts the file in place of the current one. A failure changes nothing.
fn rotate(state: &mut StorageState, index: usize) -> std::io::Result<()> {
    let started = Instant::now();
    let wal = &state.wals[index];
    let (engine, next) = (wal.engine, wal.segment + 1);
    let path = segment_path(&wal.dir, next);
    let file = match open_prepared(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let file = create_segment(&wal.dir, next, wal.lsn)?;
            state.stats.created_segments += 1;
            tracing::warn!(
                "No segment was prepared for the {engine:?} write-ahead log; the storage thread created {} itself.",
                path.display()
            );
            #[cfg(test)]
            test_trace::record(&path, "create");
            file
        }
        opened => opened?,
    };
    file.write_all_at(&wal_header(state.wals[index].lsn), 0)?;
    state.swap_file(index, file);
    let wal = &mut state.wals[index];
    wal.closed.push(SegmentInfo { segment: wal.segment, bytes: wal.offset, last_lsn: wal.lsn });
    (wal.segment, wal.offset, wal.opened_at) = (next, WAL_HEADER_LEN, Instant::now());
    wal.marker = unsafe_end_marker(&path);
    tracing::debug!("Moved the {engine:?} write-ahead log to segment {next} in {:?}.", started.elapsed());
    Ok(())
}

/// The segment a checkpoint prepared at `path`, which holds a header alone.
fn open_prepared(path: &Path) -> std::io::Result<File> {
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    let len = file.metadata()?.len();
    if len != WAL_HEADER_LEN {
        return Err(std::io::Error::other(format!(
            "the prepared segment {} holds {len} bytes instead of a header",
            path.display()
        )));
    }
    Ok(file)
}

/// The segments of WAL `index`, the one appended to last.
fn segments_of(state: &StorageState, index: usize) -> WalSegments {
    let wal = &state.wals[index];
    let active = SegmentInfo { segment: wal.segment, bytes: wal.offset, last_lsn: wal.lsn };
    WalSegments {
        dir: wal.dir.clone(),
        segment_bytes: state.segment_bytes,
        segments: wal.closed.iter().copied().chain([active]).collect(),
        active_since: wal.opened_at,
    }
}

/// Takes in the results of `p`'s chain — of its write and of its fdatasync —
/// and returns the outcome of the write once it has one: the offset it
/// starts at, or the failure, its file cut back to the cursor. `None` leaves
/// a rest to write. A failed fdatasync stops the server once the end of the
/// write is safe for the next start: the file cut back, or the cursor in the
/// marker; until then the next append makes it safe first. A failed write
/// that stops the server ([`WriteFailures::stops_for`]) stops it after the
/// cut, safe or not.
fn take_chain(state: &mut StorageState, p: &mut Pending, (wrote, synced): (i32, i32)) -> Option<Result<u64>> {
    #[cfg(test)]
    let wrote = state.faults.write.take().map_or(wrote, |errno| -errno);
    if wrote > 0 {
        p.landed += wrote as usize;
        // A short write cancels the fdatasync behind it; the rest goes in the
        // file's next chain.
        if p.landed < p.write.data.len() {
            return None;
        }
    }
    let (failure, sync_failed) = match (wrote, synced) {
        (wrote, _) if wrote < 0 => (Some(std::io::Error::from_raw_os_error(-wrote)), false),
        (0, _) => (Some(std::io::Error::new(std::io::ErrorKind::WriteZero, "io_uring write returned 0")), false),
        (_, synced) if synced < 0 => (Some(std::io::Error::from_raw_os_error(-synced)), true),
        #[cfg(test)]
        _ if std::mem::take(&mut state.faults.sync) => (Some(std::io::Error::other("injected fdatasync failure")), true),
        _ => (None, false),
    };
    if let Some(e) = failure {
        let wal = &state.wals[p.index];
        let segment = segment_path(&wal.dir, wal.segment);
        let stops = if sync_failed {
            state.fail_sync(p.index, segment.clone(), &e);
            false
        } else {
            wal.write_failures.stops_for(&segment, &e)
        };
        let cut = state.cut_to_cursor(p.index);
        if let Err(failed) = &cut {
            log_failed_cut(p.write.engine, p.start, &failed.error);
        }
        if stops {
            return Some(Err(crate::storage::fatal_write_error(&segment, &e)));
        }
        if let Some(stop) = state.stop_after_cut(p.index, &cut) {
            return Some(Err(stop));
        }
        return Some(Err(e.into()));
    }
    state.stats.fdatasyncs += 1;
    let wal = &mut state.wals[p.index];
    wal.write_failures.succeeded();
    wal.offset += p.write.data.len() as u64;
    wal.lsn += p.write.parts.len() as u64;
    Some(Ok(p.start))
}

/// A cut back to the cursor that failed.
struct CutFailed {
    error: std::io::Error,
    /// The next start finds the end safe all the same: the file is cut and
    /// only the marker removal failed, or the marker holds the cursor.
    secured: bool,
    /// Unsecured, and the marker's failure stops the server
    /// ([`WriteFailures::stops_for`]).
    stops: bool,
}

/// A failed sync among the errors of the hub's file operations.
#[derive(Debug)]
struct SyncError(std::io::Error);

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for SyncError {}

fn sync_error(e: std::io::Error) -> std::io::Error {
    std::io::Error::new(e.kind(), SyncError(e))
}

fn is_sync_error(e: &std::io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<SyncError>())
}

/// Every failed cut, marker removal included, is logged: the file's end stays
/// unsafe until one succeeds.
fn log_failed_cut(engine: WalTarget, cursor: u64, error: &std::io::Error) {
    tracing::error!(
        "Securing the end of the {engine:?} write-ahead log at {cursor} bytes failed: {error}; \
         the next append retries before it writes."
    );
}

/// Cuts the segment appends go to back to a header that starts after its
/// last LSN. A failed sync stops the server: everything the segment held is
/// in SSTables, and the next start finds either.
fn do_wal_truncate(state: &mut StorageState, engine: WalTarget) -> Result<()> {
    let index = state.wal_index(engine)?;
    let wal = &mut state.wals[index];
    if let Err(e) = wal.file.write_all_at(&wal_header(wal.lsn), 0).and_then(|()| wal.file.set_len(WAL_HEADER_LEN)) {
        let segment = segment_path(&wal.dir, wal.segment);
        if wal.write_failures.stops_for(&segment, &e) {
            return Err(crate::storage::fatal_write_error(&segment, &e));
        }
        return Err(e.into());
    }
    wal.write_failures.succeeded();
    wal.offset = WAL_HEADER_LEN;
    if let Err(e) = wal.file.sync_all() {
        return Err(crate::storage::fatal_sync_error(&segment_path(&wal.dir, wal.segment), &e));
    }
    if let Err(e) = state.unmark(index) {
        state.wals[index].unsafe_end = true;
        log_failed_cut(engine, 0, &e);
        if is_sync_error(&e) {
            return Err(crate::storage::fatal_sync_error(&state.wals[index].marker, &e));
        }
        return Err(e.into());
    }
    state.wals[index].unsafe_end = false;
    Ok(())
}

/// Starts an empty log with the header and completes a torn one; returns
/// the start LSN of the header — `None` for a log of an earlier format,
/// which stays as it is.
pub(crate) fn ensure_header(file: &File) -> std::io::Result<Option<u64>> {
    let len = file.metadata()?.len().min(WAL_HEADER_LEN) as usize;
    let mut head = [0; WAL_HEADER_LEN as usize];
    file.read_exact_at(&mut head[..len], 0)?;
    let (magic, start) = head.split_at(WAL_MAGIC.len());
    if len == head.len() {
        return Ok((magic == WAL_MAGIC).then(|| u64::from_be_bytes(start.try_into().expect("8 bytes"))));
    }
    // A part of the header is a torn one; a header goes only into a file
    // without records, so writing it again loses nothing.
    let magic_len = len.min(WAL_MAGIC.len());
    if magic[..magic_len] != WAL_MAGIC[..magic_len] {
        return Ok(None);
    }
    write_header(file, 0)?;
    file.sync_all()?;
    Ok(Some(0))
}

/// Replaces the content of `file` with a header that starts after
/// `start_lsn`; the caller syncs it.
fn write_header(file: &File, start_lsn: u64) -> std::io::Result<()> {
    file.set_len(0)?;
    file.write_all_at(&wal_header(start_lsn), 0)
}

/// The file beside the segment or log file at `log` that holds the cursor
/// (8 bytes, big-endian) while a failed cut leaves bytes past it; the next
/// start cuts the log back to it before recovery reads the log.
pub(crate) fn unsafe_end_marker(log: &Path) -> PathBuf {
    with_suffix(log, ".unsafe-end")
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Records `cursor` in `marker` unless a marker is there already. A failure
/// is logged and returned, a failed sync as one.
pub(crate) fn mark_unsafe_end(marker: &Path, cursor: u64) -> std::io::Result<()> {
    write_marker(marker, cursor).inspect_err(|e| {
        tracing::error!(
            "Writing the unsafe-end marker {} failed: {e}; a restart before the next \
             successful cut may read the failed append back.",
            marker.display()
        );
    })
}

/// Written beside its final name and renamed into place, so the marker is
/// whole or absent.
fn write_marker(marker: &Path, cursor: u64) -> std::io::Result<()> {
    use std::io::Write;
    if marker.try_exists()? {
        return Ok(());
    }
    let tmp = with_suffix(marker, ".tmp");
    let mut file = File::create(&tmp)?;
    file.write_all(&cursor.to_be_bytes())?;
    file.sync_all().map_err(sync_error)?;
    std::fs::rename(&tmp, marker)?;
    sync_dir(marker).map_err(sync_error)
}

/// Removes `marker` and syncs its directory. A missing marker gets the sync
/// too: a retry after a failed sync finds the marker gone, and only the sync
/// keeps it gone after a power loss. A failed sync is returned as one.
pub(crate) fn unmark_unsafe_end(marker: &Path) -> std::io::Result<()> {
    let failed =
        |step: &str, e: std::io::Error| std::io::Error::new(e.kind(), format!("{step} {}: {e}", marker.display()));
    match std::fs::remove_file(marker) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        removed => removed.map_err(|e| failed("removing", e))?,
    }
    sync_dir(marker).map_err(|e| sync_error(failed("syncing the directory after removing", e)))
}

/// A rename or removal survives a power loss only once its directory is synced.
fn sync_dir(file: &Path) -> std::io::Result<()> {
    let dir = dir_of(file);
    #[cfg(test)]
    {
        let probed = DIR_SYNC_PROBE.with_borrow_mut(|probe| {
            probe.as_mut().map(|(fail, synced)| {
                synced.push(dir.to_path_buf());
                std::mem::take(fail)
            })
        });
        if probed == Some(true) {
            return Err(std::io::Error::other("injected directory sync failure"));
        }
    }
    File::open(dir)?.sync_all()
}

/// The directory that holds `file`.
fn dir_of(file: &Path) -> &Path {
    match file.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    }
}

fn remove_if_there(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        removed => removed,
    }
}

/// Applies the unsafe-end marker a failed cut left beside `log` before the
/// last stop: cuts `file` back to the marker's cursor, then removes the
/// marker, and a temporary marker an interrupted write left. Any failure
/// leaves the log unread.
pub(crate) fn apply_unsafe_end_marker(log: &Path, file: &File) -> Result<()> {
    let marker = unsafe_end_marker(log);
    unmark_unsafe_end(&with_suffix(&marker, ".tmp"))?;
    let bytes = match std::fs::read(&marker) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        read => read?,
    };
    let Ok(cursor) = <[u8; 8]>::try_from(bytes.as_slice()) else {
        return Err(anyhow!("the marker holds {} bytes instead of an 8-byte cursor", bytes.len()));
    };
    let cursor = u64::from_be_bytes(cursor);
    cut_to_marker(log, file, &marker, cursor).with_context(|| format!("cutting the log back to {cursor} bytes"))
}

fn cut_to_marker(log: &Path, file: &File, marker: &Path, cursor: u64) -> std::io::Result<()> {
    let len = file.metadata()?.len();
    // A longer set_len would pad the log with zero bytes.
    if cursor < len {
        file.set_len(cursor)?;
        file.sync_all()?;
        tracing::warn!(
            "Cut the write-ahead log {} from {len} back to {cursor} bytes: the cut after a failed \
             append had failed before the last stop.",
            log.display()
        );
    }
    unmark_unsafe_end(marker)
}

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

/// Builds a Write SQE for either a fixed-file slot or a raw fd.
fn write_entry(file: RingFile, ptr: *const u8, len: u32, offset: u64) -> squeue::Entry {
    match file {
        RingFile::Fixed(i) => opcode::Write::new(types::Fixed(i), ptr, len).offset(offset).build(),
        RingFile::Raw(fd) => opcode::Write::new(types::Fd(fd), ptr, len).offset(offset).build(),
    }
}

/// Builds an fdatasync SQE for either a fixed-file slot or a raw fd.
fn fsync_entry(file: RingFile) -> squeue::Entry {
    let flags = types::FsyncFlags::DATASYNC;
    match file {
        RingFile::Fixed(i) => opcode::Fsync::new(types::Fixed(i)).flags(flags).build(),
        RingFile::Raw(fd) => opcode::Fsync::new(types::Fd(fd)).flags(flags).build(),
    }
}

fn open_rw(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
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

/// Test helper: a running hub over the WALs at the paths it is given, handing out the
/// matching [`WriteAheadLog`](crate::core::wal::WriteAheadLog)s. Dropping it
/// drains and stops the hub.
#[cfg(test)]
pub(crate) struct TestHub {
    thread: StorageThread,
    handle: StorageHandle,
}

#[cfg(test)]
impl TestHub {
    pub(crate) fn start(wals: &[(WalTarget, &Path)]) -> Self {
        Self::with_segment_bytes(wals, WAL_SEGMENT_BYTES)
    }

    /// [`Self::start`] with segments of `segment_bytes`.
    pub(crate) fn with_segment_bytes(wals: &[(WalTarget, &Path)], segment_bytes: u64) -> Self {
        let config = StorageThreadConfig {
            sqpoll_enabled: false,
            sqpoll_idle_ms: SQPOLL_IDLE_MS,
            ring_depth: RING_DEPTH,
            channel_capacity: crate::config::StorageConfig::default().wal_queue_capacity,
            cpu: STORAGE_THREAD_CPU,
            segment_bytes,
            io: IoFailures::default(),
        };
        let wals = wals.iter().map(|(engine, path)| (*engine, path.to_path_buf())).collect();
        let (thread, handle) = StorageThread::new(config, wals).expect("test storage hub");
        Self { thread, handle }
    }

    /// `engine`'s WAL, written through this hub.
    pub(crate) fn wal(&self, engine: WalTarget) -> crate::core::wal::WriteAheadLog {
        crate::core::wal::WriteAheadLog::with_storage_handle(self.handle.clone(), engine)
    }
}

#[cfg(test)]
impl Drop for TestHub {
    fn drop(&mut self) {
        self.thread.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::wal::{self, WalEntry, WriteAheadLog};
    use crate::engines::lsm::engine::{LsmEngineOptions, LsmStorageEngine};
    use crate::engines::StorageEngine;
    use crate::storage::file_manager::FileManager;
    use crate::storage::manifest::ManifestManager;
    use crate::storage::vlog::VLog;

    const ALL_TARGETS: [WalTarget; 4] = [WalTarget::Kv, WalTarget::Json, WalTarget::Rel, WalTarget::Sys];

    fn cfg(sqpoll: bool, capacity: usize) -> StorageThreadConfig {
        StorageThreadConfig {
            sqpoll_enabled: sqpoll,
            sqpoll_idle_ms: 500,
            ring_depth: 64,
            channel_capacity: capacity,
            cpu: -1,
            segment_bytes: WAL_SEGMENT_BYTES,
            io: IoFailures::default(),
        }
    }

    /// A hub with the key-value WAL alone, at `<dir>/wal`.
    fn spawn(dir: &Path, sqpoll: bool, capacity: usize) -> (StorageThread, StorageHandle) {
        StorageThread::new(cfg(sqpoll, capacity), vec![(WalTarget::Kv, dir.join("wal"))]).unwrap()
    }

    /// One WAL directory per target in `dir`, named after the target.
    fn wal_paths(dir: &Path, targets: &[WalTarget]) -> Vec<(WalTarget, PathBuf)> {
        targets.iter().map(|target| (*target, dir.join(format!("{target:?}.wal")))).collect()
    }

    /// The first segment of the log directory `log`.
    fn segment_1(log: &Path) -> PathBuf {
        segment_path(log, 1)
    }

    /// The unsafe-end marker of the first segment of `log`.
    fn marker_of(log: &Path) -> PathBuf {
        unsafe_end_marker(&segment_1(log))
    }

    /// The paths in the log directory `log` whose failed syncs stopped the
    /// server.
    fn stops_in(log: &Path) -> Vec<PathBuf> {
        crate::storage::test_fault::stops_under(&std::fs::canonicalize(log).unwrap())
    }

    /// The file `name` in the log directory `log` as the hub names it,
    /// symlinks resolved.
    fn in_log(log: &Path, name: &str) -> PathBuf {
        std::fs::canonicalize(log).unwrap().join(name)
    }

    /// A log directory `log` whose segment 1 holds `bytes`.
    fn write_segment(log: &Path, bytes: &[u8]) {
        std::fs::create_dir_all(log).unwrap();
        std::fs::write(segment_1(log), bytes).unwrap();
    }

    /// A DELETE record of `key`, the smallest record `wal::recover` reads.
    fn delete_record(timestamp: u64, key: &[u8]) -> Vec<u8> {
        let mut record = vec![2u8];
        record.extend_from_slice(&timestamp.to_be_bytes());
        record.extend_from_slice(&(key.len() as u32).to_be_bytes());
        record.extend_from_slice(key);
        record
    }

    async fn recovered_keys(path: &Path) -> Vec<String> {
        wal::recover_all(path)
            .await
            .unwrap()
            .entries
            .into_iter()
            .map(|(_, entry)| match entry {
                WalEntry::Delete { key, .. } => String::from_utf8(key).unwrap(),
                other => panic!("expected a DELETE record, got {other:?}"),
            })
            .collect()
    }

    /// `records` framed with their LSNs and concatenated.
    fn framed(records: &[(u64, &[u8])]) -> Vec<u8> {
        records.iter().flat_map(|(lsn, payload)| lsn.to_be_bytes().into_iter().chain(payload.iter().copied())).collect()
    }

    // A run of appends for three targets plans one write per target, each
    // with its records in channel order, numbered on from that target's last
    // LSN; a target without appends gets none.
    #[test]
    fn test_plan_batch_writes_each_target_once_in_channel_order() {
        let appends: [(WalTarget, &[u8]); 5] = [
            (WalTarget::Kv, b"k1"),
            (WalTarget::Json, b"j1"),
            (WalTarget::Kv, b"k22"),
            (WalTarget::Sys, b"s1"),
            (WalTarget::Json, b"j2"),
        ];
        let last_lsn = |engine| match engine {
            WalTarget::Json => 7,
            WalTarget::Sys => 41,
            _ => 0,
        };
        assert_eq!(
            plan_batch(appends, last_lsn),
            vec![
                FileWrite {
                    engine: WalTarget::Kv,
                    data: framed(&[(1, b"k1"), (2, b"k22")]),
                    parts: vec![(0, 0, 1), (2, 10, 2)],
                },
                FileWrite {
                    engine: WalTarget::Json,
                    data: framed(&[(8, b"j1"), (9, b"j2")]),
                    parts: vec![(1, 0, 8), (4, 10, 9)],
                },
                FileWrite { engine: WalTarget::Sys, data: framed(&[(42, b"s1")]), parts: vec![(3, 0, 42)] },
            ]
        );
    }

    // 1. StorageThread starts and stops cleanly.
    #[test]
    fn test_storage_thread_starts_and_stops() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut st, handle) = spawn(dir.path(), false, 64);
        drop(handle);
        st.shutdown();
    }

    // 2. wal_append -- a new log starts with the header, each record lands
    // framed with its LSN, offsets correct.
    #[test]
    fn test_wal_append_offsets_and_bytes() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let (mut st, handle) = spawn(dir.path(), false, 64);
            let o1 = handle.wal_append(WalTarget::Kv, b"hello".to_vec()).await.unwrap();
            let o2 = handle.wal_append(WalTarget::Kv, b"world!".to_vec()).await.unwrap();
            assert_eq!(o1, (16, 1));
            assert_eq!(o2, (29, 2));
            st.shutdown();
            let log = [&wal_header(0)[..], &framed(&[(1, b"hello"), (2, b"world!")])].concat();
            assert_eq!(std::fs::read(segment_1(&dir.path().join("wal"))).unwrap(), log);
        })
    }

    // Every engine's appends land in its own file, at offsets that grow per
    // file and with LSNs counted per file; a truncate empties its own file
    // alone, its LSNs go on; `recover` reads each file back on its own. With
    // SQPOLL too: four fixed-file slots on the production ring setup.
    #[test]
    fn test_hub_keeps_one_wal_per_engine() {
        for sqpoll in [false, true] {
            crate::core::engine_runtime::block_on(async {
                let dir = tempfile::TempDir::new().unwrap();
                let wals = wal_paths(dir.path(), &ALL_TARGETS);
                let (mut st, handle) = StorageThread::new(cfg(sqpoll, 64), wals.clone()).unwrap();

                let mut appended = Vec::new();
                for round in 1..=2u64 {
                    for target in ALL_TARGETS {
                        let record = delete_record(round, format!("{target:?}-{round}").as_bytes());
                        appended.push((target, handle.wal_append(target, record).await.unwrap()));
                    }
                }
                // Second offset = header + LSN frame + the first record (13 bytes + the key).
                let expected = [
                    (WalTarget::Kv, (16, 1)), (WalTarget::Json, (16, 1)), (WalTarget::Rel, (16, 1)), (WalTarget::Sys, (16, 1)),
                    (WalTarget::Kv, (41, 2)), (WalTarget::Json, (43, 2)), (WalTarget::Rel, (42, 2)), (WalTarget::Sys, (42, 2)),
                ];
                assert_eq!(appended, expected);

                handle.wal_truncate(WalTarget::Json).await.unwrap();
                assert_eq!(handle.wal_append(WalTarget::Json, delete_record(3, b"Json-3")).await.unwrap(), (16, 3));
                for (target, head) in [(WalTarget::Kv, 2), (WalTarget::Json, 3), (WalTarget::Rel, 2), (WalTarget::Sys, 2)] {
                    assert_eq!(handle.wal_head_lsn(target).await.unwrap(), head);
                }
                st.shutdown();

                let paths: Vec<&Path> = wals.iter().map(|(_, path)| path.as_path()).collect();
                assert_eq!(recovered_keys(paths[0]).await, ["Kv-1", "Kv-2"]);
                assert_eq!(recovered_keys(paths[1]).await, ["Json-3"]);
                assert_eq!(recovered_keys(paths[2]).await, ["Rel-1", "Rel-2"]);
                assert_eq!(recovered_keys(paths[3]).await, ["Sys-1", "Sys-2"]);
                assert_eq!(wal::recover_all(paths[1]).await.unwrap().max_lsn, 3);
            })
        }
    }

    // The hub opens a file for the engines it was given and no other; a
    // request for any other engine fails, and the given ones keep working.
    #[test]
    fn test_requests_for_an_engine_without_a_wal_fail() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let (mut st, handle) = spawn(dir.path(), false, 64);

            let err = handle.wal_append(WalTarget::Json, b"doc".to_vec()).await.unwrap_err();
            assert!(err.to_string().contains("Json"), "{err}");
            let err = handle.wal_truncate(WalTarget::Rel).await.unwrap_err();
            assert!(err.to_string().contains("Rel"), "{err}");
            let err = handle.set_lsn_start(WalTarget::Sys, 3).await.unwrap_err();
            assert!(err.to_string().contains("Sys"), "{err}");
            let err = handle.wal_head_lsn(WalTarget::Json).await.unwrap_err();
            assert!(err.to_string().contains("Json"), "{err}");
            assert_eq!(handle.wal_append(WalTarget::Kv, b"kv".to_vec()).await.unwrap(), (16, 1));

            st.shutdown();
            let files: Vec<_> = std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
            assert_eq!(files, ["wal"]);
        })
    }

    // After `SetLsnStart` with k the next append carries k + 1, and the head
    // follows the appends.
    #[test]
    fn test_set_lsn_start_numbers_the_next_append_after_it() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let (mut st, handle) = spawn(dir.path(), false, 64);
            assert_eq!(handle.wal_head_lsn(WalTarget::Kv).await.unwrap(), 0);

            handle.set_lsn_start(WalTarget::Kv, 41).await.unwrap();
            assert_eq!(handle.wal_head_lsn(WalTarget::Kv).await.unwrap(), 41);
            assert_eq!(handle.wal_append(WalTarget::Kv, delete_record(1, b"first")).await.unwrap(), (16, 42));
            assert_eq!(handle.wal_append(WalTarget::Kv, delete_record(2, b"second")).await.unwrap().1, 43);
            assert_eq!(handle.wal_head_lsn(WalTarget::Kv).await.unwrap(), 43);
            st.shutdown();

            assert_eq!(wal::recover_all(dir.path().join("wal")).await.unwrap().max_lsn, 43);
        })
    }

    // `SetLsnStart` never moves the counter back: an engine that reopens its
    // log on a live hub, the header alone after a clean shutdown, sends 0.
    #[test]
    fn test_set_lsn_start_never_moves_the_counter_back() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let (mut st, handle) = spawn(dir.path(), false, 64);
            for i in 1..=3u64 {
                handle.wal_append(WalTarget::Kv, delete_record(i, b"before")).await.unwrap();
            }
            handle.wal_truncate(WalTarget::Kv).await.unwrap();

            handle.set_lsn_start(WalTarget::Kv, 0).await.unwrap();
            assert_eq!(handle.wal_append(WalTarget::Kv, delete_record(4, b"after")).await.unwrap(), (16, 4));
            assert_eq!(handle.wal_head_lsn(WalTarget::Kv).await.unwrap(), 4);
            st.shutdown();
        })
    }

    // A log of an earlier version, a single file, moves aside to
    // `.migrating` with its bytes, where recovery reads it; a directory with
    // an empty segment 1 takes its place and takes the appends. Of v1, v2 and
    // v3 logs alike.
    #[test]
    fn test_a_single_file_log_moves_aside_for_a_segment_directory() {
        let previous = [&b"LURAWAL\x02"[..], &framed(&[(1, &delete_record(1, b"previous"))])].concat();
        let current = [&wal_header(4)[..], &framed(&[(5, &delete_record(1, b"current"))])].concat();
        for earlier in [delete_record(1, b"earlier"), previous, current] {
            let dir = tempfile::TempDir::new().unwrap();
            let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
            std::fs::write(&wals[0].1, &earlier).unwrap();
            let (mut state, _) = open_state(&cfg(false, 64), &wals).unwrap();

            assert_eq!(std::fs::read(dir.path().join("Kv.wal.migrating")).unwrap(), earlier);
            assert_eq!(names_in(&wals[0].1), ["00000001.wal"]);
            assert_eq!(std::fs::read(segment_1(&wals[0].1)).unwrap(), wal_header(0));
            assert_eq!(append_all(&mut state, WalTarget::Kv, &[b"kept"]), [(WAL_HEADER_LEN, 1)]);
        }
    }

    // A cut back's new file and an unsafe-end marker an earlier version left
    // beside its log are applied as that version did, then the log moves.
    #[test]
    fn test_a_single_file_log_moves_aside_cut_to_its_marker() {
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
        let (tmp, marker) = (dir.path().join("Kv.wal.tmp"), dir.path().join("Kv.wal.unsafe-end"));
        let log = [&wal_header(0)[..], &framed(&[(1, b"kept")])].concat();
        std::fs::write(&wals[0].1, [&log[..], b"unconfirmed"].concat()).unwrap();
        std::fs::write(&tmp, wal_header(0)).unwrap();
        std::fs::write(&marker, (log.len() as u64).to_be_bytes()).unwrap();

        open_state(&cfg(false, 64), &wals).unwrap();
        assert_eq!(std::fs::read(dir.path().join("Kv.wal.migrating")).unwrap(), log);
        assert!(!tmp.exists() && !marker.exists());
        assert_eq!(names_in(dir.path()), ["Kv.wal", "Kv.wal.migrating"]);
    }

    // A start that finds `.migrating` without a directory, or without its
    // segment, as a crash right after the move leaves it, creates them and
    // keeps `.migrating` for recovery; with both there it changes nothing.
    #[test]
    fn test_a_start_after_an_interrupted_move_completes_the_directory() {
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
        let migrating = dir.path().join("Kv.wal.migrating");
        let log = [&wal_header(0)[..], &framed(&[(1, b"kept")])].concat();
        std::fs::write(&migrating, &log).unwrap();
        drop(open_state(&cfg(false, 64), &wals).unwrap());
        assert_eq!(std::fs::read(segment_1(&wals[0].1)).unwrap(), wal_header(0));
        assert_eq!(std::fs::read(&migrating).unwrap(), log);

        std::fs::remove_file(segment_1(&wals[0].1)).unwrap();
        drop(open_state(&cfg(false, 64), &wals).unwrap());
        assert_eq!(names_in(&wals[0].1), ["00000001.wal"]);
        assert_eq!(std::fs::read(&migrating).unwrap(), log);
    }

    // An earlier version, which opens its log as a file, fails on the
    // directory this version leaves at the path.
    #[test]
    fn test_an_earlier_version_cannot_open_the_segment_directory() {
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
        drop(open_state(&cfg(false, 64), &wals).unwrap());
        let err = open_rw(&wals[0].1).unwrap_err();
        let io = err.downcast_ref::<std::io::Error>().expect("an I/O error");
        assert_eq!(io.raw_os_error(), Some(libc::EISDIR), "{err:#}");
    }

    // A request queued behind a refused append still runs when the hub
    // stops: a truncate behind an append whose cut keeps failing is answered.
    #[test]
    fn test_stopping_hub_runs_a_request_behind_a_refused_append() {
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
        let (mut state, _) = state_after_a_failed_cut(&wals);
        state.faults.cut = true;
        let (tx, mut rx) = mpsc::channel(8);

        let (batch, mut refused) = record_appends(WalTarget::Kv, vec![delete_record(2, b"refused")]);
        let (response, mut truncated) = oneshot::channel();
        let rest = [IoRequest::WalTruncate { engine: WalTarget::Kv, response }, IoRequest::Shutdown];
        for request in batch.into_iter().chain(rest) {
            tx.try_send(request).unwrap();
        }
        event_loop(&mut state, &mut rx, &AtomicBool::new(false));

        assert!(refused[0].try_recv().unwrap().is_err());
        truncated.try_recv().unwrap().unwrap();
        assert_eq!(std::fs::read(segment_1(&wals[0].1)).unwrap(), wal_header(1));
    }

    // A crash while the header was written leaves a part of it; the start
    // writes the header again.
    #[test]
    fn test_start_completes_a_torn_header() {
        for torn in [&b"LUR"[..], &wal_header(7)[..11]] {
            let dir = tempfile::TempDir::new().unwrap();
            let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
            write_segment(&wals[0].1, torn);
            let (mut state, _) = open_state(&cfg(false, 64), &wals).unwrap();
            assert_eq!(std::fs::read(segment_1(&wals[0].1)).unwrap(), wal_header(0));
            assert_eq!(state.wals[0].offset, WAL_HEADER_LEN);

            let (batch, mut appended) = record_appends(WalTarget::Kv, vec![delete_record(1, b"first")]);
            process_batch(&mut state, batch);
            assert_eq!(appended[0].try_recv().unwrap().unwrap(), (16, 1));
        }
    }

    // A start on a log that holds only its header numbers the next append
    // after the header's start LSN; a truncate writes the last LSN as the
    // new start.
    #[test]
    fn test_the_lsns_go_on_from_the_start_lsn_of_the_header() {
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
        write_segment(&wals[0].1, &wal_header(50));
        let (mut state, _) = open_state(&cfg(false, 64), &wals).unwrap();
        assert_eq!(append_all(&mut state, WalTarget::Kv, &[b"first"]), [(WAL_HEADER_LEN, 51)]);

        let (response, mut truncated) = oneshot::channel();
        process_batch(&mut state, vec![IoRequest::WalTruncate { engine: WalTarget::Kv, response }]);
        truncated.try_recv().unwrap().unwrap();
        assert_eq!(std::fs::read(segment_1(&wals[0].1)).unwrap(), wal_header(51));
        drop(state);

        let (mut state, _) = open_state(&cfg(false, 64), &wals).unwrap();
        assert_eq!(append_all(&mut state, WalTarget::Kv, &[b"second"]), [(WAL_HEADER_LEN, 52)]);
    }

    // A segment without this version's header stops the start and is named.
    #[test]
    fn test_start_refuses_a_segment_of_an_earlier_format() {
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
        write_segment(&wals[0].1, &[&b"LURAWAL\x02"[..], &framed(&[(1, b"x")])].concat());
        let Err(err) = open_state(&cfg(false, 64), &wals) else { panic!("the start must fail") };
        assert!(format!("{err:#}").contains("00000001.wal has no header of this version"), "{err:#}");
    }

    /// The receivers of append requests, each for the offset and the LSN.
    type Appended = Vec<oneshot::Receiver<Result<(u64, u64)>>>;

    /// One-byte append requests for `targets`, in order, with their receivers.
    fn appends(targets: &[WalTarget]) -> (Vec<IoRequest>, Appended) {
        targets
            .iter()
            .map(|engine| {
                let (response, rx) = oneshot::channel();
                (IoRequest::WalAppend { engine: *engine, data: vec![b'x'], response }, rx)
            })
            .unzip()
    }

    // Group commit across engines: one batch syncs each file it writes to
    // once, however many of its requests go to that file.
    #[test]
    fn test_one_batch_syncs_each_written_file_once() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut state, _) = open_state(&cfg(false, 64), &wal_paths(dir.path(), &ALL_TARGETS)).unwrap();
        use WalTarget::{Json, Kv, Rel};

        let (batch, mut receivers) = appends(&[Kv, Json, Kv, Rel, Json, Kv]);
        process_batch(&mut state, batch);
        assert_eq!(state.stats, HubStats { appends: 6, batches: 1, fdatasyncs: 3, created_segments: 0 });

        let (batch, more) = appends(&[Kv; 20]);
        process_batch(&mut state, batch);
        assert_eq!(state.stats, HubStats { appends: 26, batches: 2, fdatasyncs: 4, created_segments: 0 });

        // Each one-byte payload takes 9 bytes behind the 16-byte header; the
        // LSNs count per file across both batches.
        receivers.extend(more);
        let appended: Vec<(u64, u64)> = receivers.iter_mut().map(|rx| rx.try_recv().unwrap().unwrap()).collect();
        assert_eq!(&appended[..6], [(16, 1), (16, 1), (25, 2), (16, 1), (25, 2), (34, 3)]);
        assert_eq!(appended[6..], (3..23).map(|i| (16 + 9 * i, i + 1)).collect::<Vec<_>>());
    }

    /// Append requests of `records` to `engine`'s WAL, in order, with their receivers.
    fn record_appends(engine: WalTarget, records: Vec<Vec<u8>>) -> (Vec<IoRequest>, Appended) {
        records
            .into_iter()
            .map(|data| {
                let (response, rx) = oneshot::channel();
                (IoRequest::WalAppend { engine, data, response }, rx)
            })
            .unzip()
    }

    // A write that fails on one file cuts that file back to its cursor and
    // fails that file's requests alone, its LSNs unused; the batch's other
    // file commits.
    #[test]
    fn test_failed_write_cuts_its_file_back_to_the_cursor() {
        use std::io::Write;
        use WalTarget::{Json, Kv};
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[Kv, Json]);
        let (mut state, _) = open_state(&cfg(false, 64), &wals).unwrap();
        assert!(state.fixed_files);
        let (batch, _) = appends(&[Kv, Kv, Json]);
        process_batch(&mut state, batch);

        // The bytes a torn write landed before it failed.
        OpenOptions::new().append(true).open(segment_1(&wals[0].1)).unwrap().write_all(b"torn").unwrap();
        // Every further write to the key-value WAL fails: its slot holds /dev/full.
        let dev_full = OpenOptions::new().write(true).open("/dev/full").unwrap();
        state.ring.submitter().register_files_update(0, &[dev_full.as_raw_fd()]).unwrap();

        let (batch, mut receivers) = appends(&[Kv, Json, Kv]);
        process_batch(&mut state, batch);

        assert_eq!(std::fs::metadata(segment_1(&wals[0].1)).unwrap().len(), 34);
        assert_eq!(state.wals[0].offset, 34);
        assert_eq!(state.wals[0].lsn, 2);
        for i in [0, 2] {
            let err = receivers[i].try_recv().unwrap().unwrap_err();
            assert!(err.to_string().starts_with("WAL append failed"), "{err}");
        }
        assert_eq!(receivers[1].try_recv().unwrap().unwrap(), (25, 2));
    }

    /// Two records for each of the four files, file after file, with their receivers.
    fn two_records_per_file() -> (Vec<IoRequest>, Appended) {
        (1..=2u64)
            .flat_map(|round| ALL_TARGETS.map(|target| (target, format!("{target:?}-{round}"), round)))
            .map(|(engine, key, round)| {
                let data = delete_record(round, key.as_bytes());
                let (response, rx) = oneshot::channel();
                (IoRequest::WalAppend { engine, data, response }, rx)
            })
            .unzip()
    }

    // One batch with appends for all four files: each file gets its records
    // at the offsets they would get one file after another and one
    // fdatasync; `recover` reads each file back on its own. With SQPOLL too,
    // and on a ring whose submission queue holds one file's write and
    // fdatasync at a time.
    #[test]
    fn test_one_batch_commits_all_four_files() {
        for (sqpoll, ring_depth) in [(false, 64), (true, 64), (false, 2)] {
            crate::core::engine_runtime::block_on(async {
                let dir = tempfile::TempDir::new().unwrap();
                let wals = wal_paths(dir.path(), &ALL_TARGETS);
                let (mut state, _) = open_state(&StorageThreadConfig { ring_depth, ..cfg(sqpoll, 64) }, &wals).unwrap();

                let (batch, mut receivers) = two_records_per_file();
                process_batch(&mut state, batch);
                assert_eq!(state.stats, HubStats { appends: 8, batches: 1, fdatasyncs: 4, created_segments: 0 });
                let appended: Vec<(u64, u64)> = receivers.iter_mut().map(|rx| rx.try_recv().unwrap().unwrap()).collect();
                // Second offset = header + LSN frame + the first record (13 bytes + the key).
                assert_eq!(appended, [(16, 1), (16, 1), (16, 1), (16, 1), (41, 2), (43, 2), (42, 2), (42, 2)]);

                for (target, path) in &wals {
                    assert_eq!(recovered_keys(path).await, [format!("{target:?}-1"), format!("{target:?}-2")]);
                }
            })
        }
    }

    // Writes that land short go on with the rest of the file's bytes until
    // all have landed; the file is synced once, at the end.
    #[test]
    fn test_short_writes_go_on_with_the_rest_and_sync_once() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
            let (mut state, _) = open_state(&cfg(false, 64), &wals).unwrap();
            state.faults.max_write_len = Some(5);

            let records = vec![delete_record(1, b"first"), delete_record(2, b"second")];
            let (batch, mut appended) = record_appends(WalTarget::Kv, records);
            process_batch(&mut state, batch);
            assert_eq!(state.stats, HubStats { appends: 2, batches: 1, fdatasyncs: 1, created_segments: 0 });
            // The first record takes the LSN frame and 18 bytes.
            assert_eq!(appended[0].try_recv().unwrap().unwrap(), (16, 1));
            assert_eq!(appended[1].try_recv().unwrap().unwrap(), (42, 2));
            assert_eq!(recovered_keys(&wals[0].1).await, ["first", "second"]);
        })
    }

    // While one file's chain is held on its way, an append for another file
    // is written and answered; the held file's append is answered once its
    // chain is taken in. With SQPOLL too.
    #[test]
    fn test_another_file_commits_while_a_chain_is_on_its_way() {
        use WalTarget::{Json, Kv};
        for sqpoll in [false, true] {
            let dir = tempfile::TempDir::new().unwrap();
            let (mut state, _) = open_state(&cfg(sqpoll, 64), &wal_paths(dir.path(), &[Kv, Json])).unwrap();
            state.faults.held = Some(Kv);

            let (batch, mut kv) = appends(&[Kv]);
            process_batch(&mut state, batch);
            let (batch, mut json) = appends(&[Json]);
            process_batch(&mut state, batch);
            assert_eq!(json[0].try_recv().unwrap().unwrap(), (16, 1));
            assert!(kv[0].try_recv().is_err());
            assert_eq!(state.stats, HubStats { appends: 2, batches: 2, fdatasyncs: 1, created_segments: 0 });

            state.faults.held = None;
            process_batch(&mut state, Vec::new());
            assert_eq!(kv[0].try_recv().unwrap().unwrap(), (16, 1));
            assert_eq!(state.stats.fdatasyncs, 2);
        }
    }

    /// A pipe with a full buffer and its size: a write to it waits until the
    /// reader takes bytes.
    fn full_pipe() -> (std::io::PipeReader, std::io::PipeWriter, usize) {
        use std::io::Write;
        let (reader, mut writer) = std::io::pipe().unwrap();
        // SAFETY: F_GETPIPE_SZ reads the size of the pipe behind a valid fd.
        let size = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETPIPE_SZ) };
        let size = usize::try_from(size).unwrap();
        writer.write_all(&vec![0; size]).unwrap();
        (reader, writer, size)
    }

    /// The answer on `rx`; `None` if none comes within ten seconds, so a hub
    /// that never looks fails the test instead of hanging it.
    fn answer_in_time<T>(mut rx: oneshot::Receiver<T>) -> Option<T> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match rx.try_recv() {
                Ok(answer) => return Some(answer),
                Err(oneshot::error::TryRecvError::Empty) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(_) => return None,
            }
        }
    }

    // While one file's chain waits on the ring, the running hub takes in an
    // append for another file and commits it; the waiting chain is answered
    // once its write lands.
    #[test]
    fn test_running_hub_commits_another_file_while_a_chain_waits_on_the_ring() {
        use std::io::Read;
        use WalTarget::{Json, Kv};
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[Kv, Json]);
        let json_path = wals[1].1.clone();
        let (mut reader, writer, filled) = full_pipe();
        let (tx, mut rx) = mpsc::channel(8);
        let hub = std::thread::spawn(move || {
            let (mut state, _) = open_state(&cfg(false, 64), &wals).unwrap();
            assert!(state.fixed_files);
            // The key-value file's slot holds the full pipe: its write waits for the reader.
            state.ring.submitter().register_files_update(0, &[writer.as_raw_fd()]).unwrap();
            event_loop(&mut state, &mut rx, &AtomicBool::new(false));
        });

        let (batch, mut kv) = appends(&[Kv]);
        let (head, head_rx) = oneshot::channel();
        // Answered in the turn that starts the key-value chain, or after it.
        for request in batch.into_iter().chain([IoRequest::WalHeadLsn { engine: Json, response: head }]) {
            tx.try_send(request).unwrap();
        }
        let json_answer = answer_in_time(head_rx).and_then(|_| {
            let (batch, json) = appends(&[Json]);
            batch.into_iter().for_each(|request| tx.try_send(request).unwrap());
            answer_in_time(json.into_iter().next().unwrap())
        });
        let kv_waited = matches!(kv[0].try_recv(), Err(oneshot::error::TryRecvError::Empty));
        // The prefill and the key-value record with its LSN frame.
        reader.read_exact(&mut vec![0; filled + 9]).unwrap();
        let kv_answered = answer_in_time(kv.remove(0)).is_some();
        tx.try_send(IoRequest::Shutdown).unwrap();
        hub.join().unwrap();

        assert_eq!(json_answer.map(|appended| appended.unwrap()), Some((16, 1)));
        assert!(kv_waited);
        assert!(kv_answered);
        assert_eq!(std::fs::read(segment_1(&json_path)).unwrap(), [&wal_header(0)[..], &framed(&[(1, b"x")])].concat());
    }

    // A hub that unwinds from a panic while a chain is on the ring must abort:
    // dropping its state would free a buffer the kernel still writes from.
    // Without a chain on the ring, or without a panic, it need not.
    #[test]
    fn test_unwinding_with_a_chain_on_the_ring_aborts() {
        use std::io::Read;
        let dir = tempfile::TempDir::new().unwrap();
        let (mut state, _) = open_state(&cfg(false, 64), &wal_paths(dir.path(), &[WalTarget::Kv])).unwrap();
        let (mut reader, writer, filled) = full_pipe();
        state.ring.submitter().register_files_update(0, &[writer.as_raw_fd()]).unwrap();
        let (batch, _) = appends(&[WalTarget::Kv]);
        batch.into_iter().for_each(|request| _ = accept(&mut state, request));
        turn(&mut state);

        assert!(must_abort(&state, true));
        assert!(!must_abort(&state, false));
        reader.read_exact(&mut vec![0; filled + 9]).unwrap();
        while turn(&mut state) {}
        assert!(!must_abort(&state, true));
    }

    // A file starts its next write only once its chain on its way is taken
    // in: a second append waits behind the held chain, then goes in a submit
    // of its own.
    #[test]
    fn test_a_file_waits_for_its_chain_on_its_way() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
            let (mut state, _) = open_state(&cfg(false, 64), &wals).unwrap();
            state.faults.held = Some(WalTarget::Kv);

            let (batch, mut first) = record_appends(WalTarget::Kv, vec![delete_record(1, b"first")]);
            process_batch(&mut state, batch);
            let (batch, mut second) = record_appends(WalTarget::Kv, vec![delete_record(2, b"second")]);
            process_batch(&mut state, batch);
            assert!(first[0].try_recv().is_err());
            assert!(second[0].try_recv().is_err());
            // The header and the first record with its LSN frame.
            assert_eq!(std::fs::metadata(segment_1(&wals[0].1)).unwrap().len(), 42);

            state.faults.held = None;
            process_batch(&mut state, Vec::new());
            assert_eq!(first[0].try_recv().unwrap().unwrap(), (16, 1));
            assert_eq!(second[0].try_recv().unwrap().unwrap(), (42, 2));
            assert_eq!(state.stats, HubStats { appends: 2, batches: 2, fdatasyncs: 2, created_segments: 0 });
            assert_eq!(recovered_keys(&wals[0].1).await, ["first", "second"]);
        })
    }

    // A chain that fails while another file's chain is on its way cuts its
    // own file back alone; the other chain commits.
    #[test]
    fn test_a_failed_chain_leaves_a_chain_on_its_way_committed() {
        crate::core::engine_runtime::block_on(async {
            use WalTarget::{Json, Kv};
            let dir = tempfile::TempDir::new().unwrap();
            let wals = wal_paths(dir.path(), &[Kv, Json]);
            let (mut state, _) = open_state(&cfg(false, 64), &wals).unwrap();
            assert!(state.fixed_files);
            state.faults.held = Some(Json);
            let (batch, mut json) = record_appends(Json, vec![delete_record(1, b"json-1")]);
            process_batch(&mut state, batch);

            // Every write to the key-value WAL fails: its slot holds /dev/full.
            let dev_full = OpenOptions::new().write(true).open("/dev/full").unwrap();
            state.ring.submitter().register_files_update(0, &[dev_full.as_raw_fd()]).unwrap();
            let (batch, mut kv) = record_appends(Kv, vec![delete_record(1, b"kv-1")]);
            process_batch(&mut state, batch);
            let err = kv[0].try_recv().unwrap().unwrap_err();
            assert!(err.to_string().starts_with("WAL append failed"), "{err}");
            assert_eq!(std::fs::read(segment_1(&wals[0].1)).unwrap(), wal_header(0));
            assert!(json[0].try_recv().is_err());

            state.faults.held = None;
            process_batch(&mut state, Vec::new());
            assert_eq!(json[0].try_recv().unwrap().unwrap(), (16, 1));
            assert_eq!(recovered_keys(&wals[1].1).await, ["json-1"]);
        })
    }

    // A truncate waits for the chain on its way of its own file alone: it
    // runs beside another file's held chain, and behind its own file's.
    #[test]
    fn test_wal_truncate_waits_for_its_own_file_alone() {
        use WalTarget::{Json, Kv};
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[Kv, Json]);
        let (mut state, _) = open_state(&cfg(false, 64), &wals).unwrap();
        let truncate = |engine| {
            let (response, rx) = oneshot::channel();
            (IoRequest::WalTruncate { engine, response }, rx)
        };

        state.faults.held = Some(Json);
        let (batch, mut json) = appends(&[Json]);
        process_batch(&mut state, batch);
        let (mut batch, mut kv) = appends(&[Kv]);
        let (request, mut truncated) = truncate(Kv);
        batch.push(request);
        process_batch(&mut state, batch);
        assert_eq!(kv[0].try_recv().unwrap().unwrap(), (16, 1));
        truncated.try_recv().unwrap().unwrap();
        assert_eq!(std::fs::read(segment_1(&wals[0].1)).unwrap(), wal_header(1));
        assert!(json[0].try_recv().is_err());

        state.faults.held = Some(Kv);
        let (batch, mut kv) = appends(&[Kv]);
        process_batch(&mut state, batch);
        assert_eq!(json[0].try_recv().unwrap().unwrap(), (16, 1));
        let (request, mut truncated) = truncate(Kv);
        process_batch(&mut state, vec![request]);
        assert!(truncated.try_recv().is_err());
        assert_eq!(std::fs::metadata(segment_1(&wals[0].1)).unwrap().len(), 25);

        state.faults.held = None;
        process_batch(&mut state, Vec::new());
        assert_eq!(kv[0].try_recv().unwrap().unwrap(), (16, 2));
        truncated.try_recv().unwrap().unwrap();
        assert_eq!(std::fs::read(segment_1(&wals[0].1)).unwrap(), wal_header(2));
    }

    // A write that fails on one of four files fails that file's requests
    // alone and leaves the file at its cursor; the batch's other three files
    // commit at their offsets.
    #[test]
    fn test_a_failed_file_leaves_the_other_files_of_its_batch_committed() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let wals = wal_paths(dir.path(), &ALL_TARGETS);
            let (mut state, _) = open_state(&cfg(false, 64), &wals).unwrap();
            assert!(state.fixed_files);
            // Every write to the JSON WAL fails: its slot holds /dev/full.
            let dev_full = OpenOptions::new().write(true).open("/dev/full").unwrap();
            state.ring.submitter().register_files_update(1, &[dev_full.as_raw_fd()]).unwrap();

            let (batch, mut receivers) = two_records_per_file();
            process_batch(&mut state, batch);
            assert_eq!(state.stats.fdatasyncs, 3);
            let mut results = receivers.iter_mut().map(|rx| rx.try_recv().unwrap());
            for expected in [Some((16, 1)), None, Some((16, 1)), Some((16, 1)), Some((41, 2)), None, Some((42, 2)), Some((42, 2))] {
                match (results.next().unwrap(), expected) {
                    (Ok(appended), Some(expected)) => assert_eq!(appended, expected),
                    (Err(err), None) => assert!(err.to_string().starts_with("WAL append failed"), "{err}"),
                    (result, expected) => panic!("expected {expected:?}, got {result:?}"),
                }
            }

            assert_eq!(state.wals[1].offset, WAL_HEADER_LEN);
            assert_eq!(std::fs::read(segment_1(&wals[1].1)).unwrap(), wal_header(0));
            for (target, path) in [&wals[0], &wals[2], &wals[3]] {
                assert_eq!(recovered_keys(path).await, [format!("{target:?}-1"), format!("{target:?}-2")]);
            }
        })
    }

    // A failed fdatasync cuts its run back and stops the server once, naming
    // the segment; nothing stays behind the log's end: after the long run
    // and a shorter one that succeeds, recovery reads the shorter run alone.
    #[test]
    fn test_failed_append_leaves_no_tail_behind_a_shorter_one() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
            let (mut state, _) = open_state(&cfg(false, 64), &wals).unwrap();

            state.faults.sync = true;
            let long = vec![delete_record(1, b"lost-with-a-long-key"), delete_record(1, b"lost-as-well")];
            let (batch, failed) = record_appends(WalTarget::Kv, long);
            process_batch(&mut state, batch);
            for mut rx in failed {
                let err = rx.try_recv().unwrap().unwrap_err();
                assert!(err.to_string().starts_with("WAL append failed: data sync failed on"), "{err}");
            }
            assert_eq!(stops_in(&wals[0].1), [in_log(&wals[0].1, "00000001.wal")]);
            assert_eq!(std::fs::metadata(segment_1(&wals[0].1)).unwrap().len(), WAL_HEADER_LEN, "cut back first");

            let (batch, mut kept) = record_appends(WalTarget::Kv, vec![delete_record(2, b"kept")]);
            process_batch(&mut state, batch);
            assert_eq!(kept[0].try_recv().unwrap().unwrap(), (16, 1));
            assert_eq!(recovered_keys(&wals[0].1).await, ["kept"]);
        })
    }

    // A cut that fails leaves the file's end unsafe: the next append cuts
    // first, fails while it cannot, and writes at the cursor once it can.
    #[test]
    fn test_append_after_a_failed_cut_cuts_first() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
            let path = wals[0].1.as_path();
            let len = || std::fs::metadata(segment_1(path)).unwrap().len();
            let (mut state, start) = state_after_a_failed_cut(&wals);
            let tail = len();

            state.faults.cut = true;
            let (batch, mut refused) = record_appends(WalTarget::Kv, vec![delete_record(3, b"refused")]);
            process_batch(&mut state, batch);
            assert!(refused[0].try_recv().unwrap().is_err());
            assert_eq!(len(), tail);

            let (batch, mut kept) = record_appends(WalTarget::Kv, vec![delete_record(4, b"kept-two")]);
            process_batch(&mut state, batch);
            assert_eq!(kept[0].try_recv().unwrap().unwrap().0, start);
            assert_eq!(recovered_keys(path).await, ["kept-one", "kept-two"]);
        })
    }

    /// A hub over `wals` after an append whose fdatasync and cut failed: the
    /// key-value WAL holds `kept-one`, which ends at the returned cursor, and
    /// a tail past it; the marker holds the cursor, so the failed sync
    /// stopped the server.
    fn state_after_a_failed_cut(wals: &[(WalTarget, PathBuf)]) -> (StorageState, u64) {
        let (mut state, _) = open_state(&cfg(false, 64), wals).unwrap();
        let (batch, _) = record_appends(WalTarget::Kv, vec![delete_record(1, b"kept-one")]);
        process_batch(&mut state, batch);
        let start = state.wals[0].offset;

        state.faults = Faults { sync: true, cut: true, ..Faults::default() };
        let (batch, mut failed) = record_appends(WalTarget::Kv, vec![delete_record(2, b"lost-with-a-long-key")]);
        process_batch(&mut state, batch);
        assert!(failed[0].try_recv().unwrap().is_err());
        assert!(std::fs::metadata(segment_1(&wals[0].1)).unwrap().len() > start);
        assert_eq!(stops_in(&wals[0].1), [in_log(&wals[0].1, "00000001.wal")]);
        (state, start)
    }

    // Test 7: an fdatasync that fails while neither the cut nor the marker
    // succeeds does not stop the server: the end stays unsafe. The next
    // append cuts first and stops then, its own records unwritten; recovery
    // after the crash reads the confirmed records alone.
    #[test]
    fn test_a_failed_fdatasync_stops_once_the_end_is_safe() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
            let log = wals[0].1.as_path();
            let (mut state, _) = open_state(&cfg(false, 64), &wals).unwrap();
            let (batch, _) = record_appends(WalTarget::Kv, vec![delete_record(1, b"kept")]);
            process_batch(&mut state, batch);
            let start = state.wals[0].offset;

            state.faults = Faults { sync: true, cut: true, mark: true, ..Faults::default() };
            let (batch, mut failed) = record_appends(WalTarget::Kv, vec![delete_record(2, b"lost")]);
            process_batch(&mut state, batch);
            assert!(failed[0].try_recv().unwrap().is_err());
            assert!(stops_in(log).is_empty(), "no stop with an unsafe end");
            assert!(state.wals[0].unsafe_end && !marker_of(log).exists());

            let (batch, mut next) = record_appends(WalTarget::Kv, vec![delete_record(3, b"next")]);
            process_batch(&mut state, batch);
            let err = next[0].try_recv().unwrap().unwrap_err();
            assert!(err.to_string().contains("data sync failed on"), "{err}");
            assert_eq!(stops_in(log), [in_log(log, "00000001.wal")]);
            assert_eq!(std::fs::metadata(segment_1(log)).unwrap().len(), start);
            drop(state); // crash
            assert_eq!(recovered_keys(log).await, ["kept"]);
        })
    }

    // Test 2: after a failed fdatasync, the cut and the marker fail three
    // times in a row: the hub stops without a safe end. Recovery after the
    // crash reads every confirmed record; the unconfirmed one may follow,
    // a torn one never.
    #[test]
    fn test_securing_the_end_failing_three_times_stops_without_a_safe_end() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
            let log = wals[0].1.as_path();
            let (mut state, _) = open_state(&cfg(false, 64), &wals).unwrap();
            append_all(&mut state, WalTarget::Kv, &[&delete_record(1, b"kept")]);

            state.faults = Faults { sync: true, cut: true, mark: true, ..Faults::default() };
            let (batch, mut failed) = record_appends(WalTarget::Kv, vec![delete_record(2, b"unconfirmed")]);
            process_batch(&mut state, batch);
            assert!(failed[0].try_recv().unwrap().is_err());
            for attempt in 2..=3 {
                assert!(stops_in(log).is_empty(), "no stop before the third failure");
                (state.faults.cut, state.faults.mark) = (true, true);
                let (batch, mut refused) = record_appends(WalTarget::Kv, vec![delete_record(3, b"refused")]);
                process_batch(&mut state, batch);
                let err = refused[0].try_recv().unwrap().unwrap_err();
                assert_eq!(err.to_string().contains("data sync failed on"), attempt == 3, "{err}");
            }
            assert_eq!(stops_in(log), [in_log(log, "00000001.wal")]);
            drop(state); // crash
            let keys = recovered_keys(log).await;
            assert!(keys == ["kept"] || keys == ["kept", "unconfirmed"], "{keys:?}");
        })
    }

    /// Appends one record with the next write of the hub failing with
    /// `errno`, if any.
    fn append_failing(state: &mut StorageState, errno: Option<i32>) -> Result<(u64, u64)> {
        state.faults.write = errno;
        let (batch, mut appended) = record_appends(WalTarget::Kv, vec![delete_record(1, b"key")]);
        process_batch(state, batch);
        appended[0].try_recv().unwrap()
    }

    // Test 1: a write failing on a read-only file system stops the server at
    // once, naming the segment; nothing of it stays in the log.
    #[test]
    fn test_a_write_failing_on_a_read_only_file_system_stops_at_once() {
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
        let log = wals[0].1.as_path();
        let (mut state, _) = open_state(&cfg(false, 64), &wals).unwrap();

        let err = append_failing(&mut state, Some(libc::EROFS)).unwrap_err();
        assert!(err.to_string().contains("data write failed on"), "{err}");
        assert_eq!(stops_in(log), [in_log(log, "00000001.wal")]);
        assert_eq!(std::fs::metadata(segment_1(log)).unwrap().len(), WAL_HEADER_LEN);
    }

    // Test 1: another I/O error stops at the third failed write in a row, a
    // write that succeeds in between starts the row anew; a full file system
    // never stops.
    #[test]
    fn test_writes_failing_with_an_io_error_stop_at_the_third_in_a_row() {
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
        let log = wals[0].1.as_path();
        let (mut state, _) = open_state(&cfg(false, 64), &wals).unwrap();

        for _ in 0..4 {
            assert!(append_failing(&mut state, Some(libc::ENOSPC)).is_err());
        }
        for errno in [Some(libc::EIO), Some(libc::EIO), None, Some(libc::EIO), Some(libc::EIO)] {
            assert_eq!(append_failing(&mut state, errno).is_ok(), errno.is_none());
        }
        assert!(stops_in(log).is_empty(), "a success starts the row anew");
        let err = append_failing(&mut state, Some(libc::EIO)).unwrap_err();
        assert!(err.to_string().contains("data write failed on"), "{err}");
        assert_eq!(stops_in(log), [in_log(log, "00000001.wal")]);
    }

    // A failed cut leaves the cursor in a marker beside the log; the next
    // start cuts the log back to it before recovery reads the log.
    #[test]
    fn test_start_cuts_the_log_back_to_the_cursor_a_failed_cut_left() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
            let path = wals[0].1.as_path();
            let marker = marker_of(&wals[0].1);
            let (state, start) = state_after_a_failed_cut(&wals);
            assert_eq!(std::fs::read(&marker).unwrap(), start.to_be_bytes());
            drop(state);

            let (mut state, _) = open_state(&cfg(false, 64), &wals).unwrap();
            assert_eq!(std::fs::metadata(segment_1(path)).unwrap().len(), start);
            assert_eq!(state.wals[0].offset, start);
            assert!(!marker.exists());
            assert_eq!(recovered_keys(path).await, ["kept-one"]);
            let (batch, mut kept) = record_appends(WalTarget::Kv, vec![delete_record(3, b"kept-two")]);
            process_batch(&mut state, batch);
            assert_eq!(kept[0].try_recv().unwrap().unwrap().0, start);
        })
    }

    // A cut that fails again leaves the marker as it is: its cursor does not
    // change while the file's end is unsafe.
    #[test]
    fn test_a_repeated_failed_cut_keeps_the_marker() {
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
        let marker = marker_of(&wals[0].1);
        let (mut state, _) = state_after_a_failed_cut(&wals);
        std::fs::write(&marker, 5u64.to_be_bytes()).unwrap();

        state.faults.cut = true;
        let (batch, mut refused) = record_appends(WalTarget::Kv, vec![delete_record(3, b"refused")]);
        process_batch(&mut state, batch);
        assert!(refused[0].try_recv().unwrap().is_err());
        assert_eq!(std::fs::read(&marker).unwrap(), 5u64.to_be_bytes());
    }

    // The cut that succeeds after a failed one removes the marker.
    #[test]
    fn test_a_successful_cut_removes_the_marker() {
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
        let marker = marker_of(&wals[0].1);
        let (mut state, start) = state_after_a_failed_cut(&wals);
        assert!(marker.exists());

        let (batch, mut kept) = record_appends(WalTarget::Kv, vec![delete_record(3, b"kept-two")]);
        process_batch(&mut state, batch);
        assert_eq!(kept[0].try_recv().unwrap().unwrap().0, start);
        assert!(!marker.exists());
    }

    // A truncate after a failed cut empties the log, removes the marker and
    // leaves the log's end safe.
    #[test]
    fn test_wal_truncate_removes_the_marker() {
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
        let marker = marker_of(&wals[0].1);
        let (mut state, _) = state_after_a_failed_cut(&wals);
        assert!(marker.exists());

        let (response, mut truncated) = oneshot::channel();
        process_batch(&mut state, vec![IoRequest::WalTruncate { engine: WalTarget::Kv, response }]);
        truncated.try_recv().unwrap().unwrap();
        assert_eq!(std::fs::metadata(segment_1(&wals[0].1)).unwrap().len(), WAL_HEADER_LEN);
        assert!(!marker.exists());
        assert!(!state.wals[0].unsafe_end);
    }

    // A marker that cannot be removed fails the cut: no append is confirmed
    // while the marker exists, so its cursor never cuts a confirmed append.
    #[test]
    fn test_a_failed_marker_removal_fails_the_cut() {
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
        let marker = marker_of(&wals[0].1);
        let (mut state, start) = state_after_a_failed_cut(&wals);

        state.faults.unmark = true;
        let (batch, mut refused) = record_appends(WalTarget::Kv, vec![delete_record(3, b"refused")]);
        process_batch(&mut state, batch);
        assert!(refused[0].try_recv().unwrap().is_err());
        assert_eq!(std::fs::metadata(segment_1(&wals[0].1)).unwrap().len(), start);
        assert!(marker.exists());

        let (batch, mut kept) = record_appends(WalTarget::Kv, vec![delete_record(4, b"kept-two")]);
        process_batch(&mut state, batch);
        assert_eq!(kept[0].try_recv().unwrap().unwrap().0, start);
        assert!(!marker.exists());
    }

    // A truncate whose marker cannot be removed fails and leaves the log's
    // end unsafe; the next append removes the marker before it writes.
    #[test]
    fn test_a_failed_marker_removal_fails_the_truncate() {
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
        let marker = marker_of(&wals[0].1);
        let (mut state, _) = state_after_a_failed_cut(&wals);

        state.faults.unmark = true;
        let (response, mut truncated) = oneshot::channel();
        process_batch(&mut state, vec![IoRequest::WalTruncate { engine: WalTarget::Kv, response }]);
        assert!(truncated.try_recv().unwrap().is_err());
        assert!(state.wals[0].unsafe_end);
        assert!(marker.exists());

        let (batch, mut kept) = record_appends(WalTarget::Kv, vec![delete_record(3, b"kept-two")]);
        process_batch(&mut state, batch);
        assert_eq!(kept[0].try_recv().unwrap().unwrap(), (16, 2));
        assert!(!marker.exists());
    }

    // A removal whose directory sync fails fails the cut and, the file cut
    // back, stops the server, naming the marker; the retry finds the marker
    // gone and still syncs the directory before it confirms an append.
    #[test]
    fn test_a_failed_directory_sync_after_the_marker_removal_fails_the_cut() {
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
        let marker = marker_of(&wals[0].1);
        let (mut state, start) = state_after_a_failed_cut(&wals);
        assert!(marker.exists());

        state.faults.unmark_sync = true;
        let (batch, mut refused) = record_appends(WalTarget::Kv, vec![delete_record(3, b"refused")]);
        process_batch(&mut state, batch);
        assert!(refused[0].try_recv().unwrap().unwrap_err().to_string().contains("data sync failed on"));
        let segment = in_log(&wals[0].1, "00000001.wal");
        assert_eq!(stops_in(&wals[0].1), [segment.clone(), unsafe_end_marker(&segment)]);
        assert!(!marker.exists());
        assert!(state.wals[0].unsafe_end);

        let syncs = state.faults.unmark_syncs.len();
        let record = delete_record(4, b"kept-two");
        let end = start + 8 + record.len() as u64;
        let (batch, mut kept) = record_appends(WalTarget::Kv, vec![record]);
        process_batch(&mut state, batch);
        assert_eq!(kept[0].try_recv().unwrap().unwrap().0, start);
        assert_eq!(state.faults.unmark_syncs.len(), syncs + 1);
        assert!(!state.wals[0].unsafe_end);
        assert_eq!(std::fs::metadata(segment_1(&wals[0].1)).unwrap().len(), end);
    }

    // A marker that holds no 8-byte cursor stops the start and is named in
    // the error; the log and the marker stay as they are.
    #[test]
    fn test_start_refuses_a_marker_without_a_cursor() {
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
        let marker = marker_of(&wals[0].1);
        write_segment(&wals[0].1, b"log-bytes");
        std::fs::write(&marker, [0, 0, 7]).unwrap();

        let Err(err) = open_state(&cfg(false, 64), &wals) else { panic!("the start must fail") };
        assert!(format!("{err:#}").contains(&marker.display().to_string()), "{err:#}");
        assert_eq!(std::fs::read(segment_1(&wals[0].1)).unwrap(), b"log-bytes");
        assert_eq!(std::fs::read(&marker).unwrap(), [0, 0, 7]);
    }

    // A cursor at or past the log's end leaves the log as it is: cutting to
    // it would pad the log with zero bytes.
    #[test]
    fn test_start_never_lengthens_the_log_to_the_marker_cursor() {
        let records = log_of(&[(1, b"kept")]);
        for (log, cursor) in [(wal_header(0).as_slice(), 21u64), (records.as_slice(), records.len() as u64)] {
            let dir = tempfile::TempDir::new().unwrap();
            let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
            let marker = marker_of(&wals[0].1);
            write_segment(&wals[0].1, log);
            std::fs::write(&marker, cursor.to_be_bytes()).unwrap();

            let (state, _) = open_state(&cfg(false, 64), &wals).unwrap();
            assert_eq!(std::fs::read(segment_1(&wals[0].1)).unwrap(), log);
            assert_eq!(state.wals[0].offset, log.len() as u64);
            assert!(!marker.exists());
        }
    }

    // The temporary marker an interrupted marker write left behind is
    // removed at the start.
    #[test]
    fn test_start_removes_a_temporary_marker() {
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
        write_segment(&wals[0].1, &wal_header(0));
        let tmp = with_suffix(&marker_of(&wals[0].1), ".tmp");
        std::fs::write(&tmp, [0, 0]).unwrap();

        open_state(&cfg(false, 64), &wals).unwrap();
        assert!(!tmp.exists());
    }

    /// A log directory `log` with `segments`, each written as given.
    fn write_segments(log: &Path, segments: &[Vec<u8>]) {
        std::fs::create_dir_all(log).unwrap();
        for (n, bytes) in (1..).zip(segments) {
            std::fs::write(segment_path(log, n), bytes).unwrap();
        }
    }

    // An unsafe-end marker beside a segment other than the last stops the
    // start and is named; one beside the last is applied.
    #[test]
    fn test_start_refuses_a_marker_beside_an_older_segment() {
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
        write_segments(&wals[0].1, &[log_of(&[(1, b"one")]), log_of(&[(2, b"two")])]);
        let older = marker_of(&wals[0].1);
        std::fs::write(&older, 16u64.to_be_bytes()).unwrap();

        let Err(err) = open_state(&cfg(false, 64), &wals) else { panic!("the start must fail") };
        assert!(format!("{err:#}").contains(&older.display().to_string()), "{err:#}");
        std::fs::remove_file(&older).unwrap();
        let last = unsafe_end_marker(&segment_path(&wals[0].1, 2));
        std::fs::write(&last, 16u64.to_be_bytes()).unwrap();

        let (state, _) = open_state(&cfg(false, 64), &wals).unwrap();
        assert!(!last.exists());
        assert_eq!(state.wals[0].segment, 1, "the last one, cut back to its header, goes");
        assert_eq!(names_in(&wals[0].1), ["00000001.wal"]);
    }

    // A crash after a failed cut in segment 1, with segment 2 prepared but
    // never appended to: the start removes segment 2, cuts segment 1 back to
    // the marker's cursor, and the appends go on in segment 1.
    #[test]
    fn test_start_applies_the_marker_before_a_prepared_segment() {
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
        let kept = log_of(&[(1, b"kept")]);
        let tail = &framed(&[(2, b"unconfirmed")])[..5];
        write_segments(&wals[0].1, &[[&kept[..], tail].concat(), wal_header(0).to_vec()]);
        std::fs::write(marker_of(&wals[0].1), (kept.len() as u64).to_be_bytes()).unwrap();

        let (mut state, _) = open_state(&cfg(false, 64), &wals).unwrap();
        assert_eq!(names_in(&wals[0].1), ["00000001.wal"]);
        assert_eq!(std::fs::read(segment_1(&wals[0].1)).unwrap(), kept);
        assert_eq!(append_all(&mut state, WalTarget::Kv, &[b"next"])[0].0, kept.len() as u64);
        assert_eq!(state.wals[0].segment, 1);
        assert_eq!(std::fs::read(segment_1(&wals[0].1)).unwrap(), [&kept[..], &framed(&[(1, b"next")])].concat());
    }

    // Segments a checkpoint left half prepared are removed at the start.
    #[test]
    fn test_start_removes_half_prepared_segments() {
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
        write_segments(&wals[0].1, &[log_of(&[(1, b"one")])]);
        std::fs::write(segment_path(&wals[0].1, 2).with_extension("wal.tmp"), wal_header(0)).unwrap();

        drop(open_state(&cfg(false, 64), &wals).unwrap());
        assert_eq!(names_in(&wals[0].1), ["00000001.wal"]);
    }

    /// Appends `records` to `engine`'s WAL as one batch; each one's offset and LSN.
    fn append_all(state: &mut StorageState, engine: WalTarget, records: &[&[u8]]) -> Vec<(u64, u64)> {
        let (batch, receivers) = record_appends(engine, records.iter().map(|record| record.to_vec()).collect());
        process_batch(state, batch);
        receivers.into_iter().map(|mut rx| rx.try_recv().unwrap().unwrap()).collect()
    }

    fn mark_of(state: &mut StorageState, engine: WalTarget) -> WalMark {
        let (response, mut marked) = oneshot::channel();
        process_batch(state, vec![IoRequest::WalMark { engine, response }]);
        marked.try_recv().unwrap().unwrap()
    }

    /// A log with `records`, each framed with its LSN, behind a header that
    /// starts right before the first of them.
    fn log_of(records: &[(u64, &[u8])]) -> Vec<u8> {
        let start = records.first().map_or(0, |(lsn, _)| lsn - 1);
        [&wal_header(start)[..], &framed(records)].concat()
    }

    /// The names of the files in `dir`, sorted.
    fn names_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> =
            std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        names
    }

    /// A hub over `wals` whose segments take no further write from
    /// `segment_bytes` on.
    fn small_segments(wals: &[(WalTarget, PathBuf)], segment_bytes: u64) -> StorageState {
        open_state(&StorageThreadConfig { segment_bytes, ..cfg(false, 64) }, wals).unwrap().0
    }

    fn segments(state: &mut StorageState, engine: WalTarget) -> WalSegments {
        let (response, mut listed) = oneshot::channel();
        process_batch(state, vec![IoRequest::WalSegments { engine, response }]);
        listed.try_recv().unwrap().unwrap()
    }

    fn rotate_request(state: &mut StorageState, engine: WalTarget) -> Result<()> {
        let (response, mut rotated) = oneshot::channel();
        process_batch(state, vec![IoRequest::WalRotate { engine, response }]);
        rotated.try_recv().unwrap()
    }

    /// Each segment's number, size and last LSN.
    fn listed(segments: &WalSegments) -> Vec<(u64, u64, u64)> {
        segments.segments.iter().map(|s| (s.segment, s.bytes, s.last_lsn)).collect()
    }

    // Records past the segment size go on in segment 2, whose header starts
    // at the last LSN of segment 1; the LSNs run on, the reader hands out
    // every record in order, and the segment list names each one's last LSN.
    #[test]
    fn test_a_full_segment_rotates_to_the_next() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
            let mut state = small_segments(&wals, 64);
            let records: Vec<Vec<u8>> = ["one", "two", "three", "four"].map(|key| delete_record(1, key.as_bytes())).into();
            for record in &records {
                append_all(&mut state, WalTarget::Kv, &[record]);
            }

            // One: 16 + 8 + 16 = 40 bytes; two: 40 + 24 = 64 reaches the size.
            assert_eq!(names_in(&wals[0].1), ["00000001.wal", "00000002.wal"]);
            assert_eq!(std::fs::read(segment_path(&wals[0].1, 2)).unwrap()[..16], wal_header(2));
            assert_eq!(listed(&segments(&mut state, WalTarget::Kv)), [(1, 64, 2), (2, 67, 4)]);
            assert_eq!(mark_of(&mut state, WalTarget::Kv), WalMark { offset: 67, lsn: 4 });
            assert_eq!(recovered_keys(&wals[0].1).await, ["one", "two", "three", "four"]);
            assert_eq!(wal::recover_all(&wals[0].1).await.unwrap().max_lsn, 4);
        })
    }

    // A batch larger than the segment size lands whole, in a segment of its
    // own once the one before is full; the next append starts a new one.
    #[test]
    fn test_a_batch_larger_than_a_segment_gets_one_of_its_own() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
            let mut state = small_segments(&wals, 64);
            let large = delete_record(1, &[b'k'; 200]);
            // 16 + 8 + 40 bytes: the segment is full.
            append_all(&mut state, WalTarget::Kv, &[&delete_record(1, &[b'f'; 27])]);
            assert_eq!(append_all(&mut state, WalTarget::Kv, &[&large]), [(WAL_HEADER_LEN, 2)]);
            append_all(&mut state, WalTarget::Kv, &[&delete_record(1, b"after")]);

            assert_eq!(names_in(&wals[0].1), ["00000001.wal", "00000002.wal", "00000003.wal"]);
            assert_eq!(std::fs::read(segment_path(&wals[0].1, 2)).unwrap(), log_of(&[(2, &large)]));
            assert_eq!(recovered_keys(&wals[0].1).await.len(), 3);
        })
    }

    // A rotation opens the segment the checkpoint prepared: no file created
    // and no directory synced by the hub. Without one — only a half-written
    // `.wal.tmp` there — the hub creates it itself and counts that.
    #[test]
    fn test_a_rotation_opens_the_prepared_segment_or_creates_one() {
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
        let mut state = small_segments(&wals, 32);
        append_all(&mut state, WalTarget::Kv, &[&delete_record(1, b"first-record")]);
        prepare_segment(&state.wals[0].dir, 2).unwrap();

        test_trace::watch(dir.path());
        append_all(&mut state, WalTarget::Kv, &[&delete_record(1, b"second-record")]);
        assert_eq!(state.wals[0].segment, 2);
        assert_eq!(state.stats.created_segments, 0);
        assert_eq!(test_trace::steps(dir.path()), Vec::<String>::new());

        std::fs::write(segment_path(&wals[0].1, 3).with_extension("wal.tmp"), b"LURA").unwrap();
        append_all(&mut state, WalTarget::Kv, &[&delete_record(1, b"third-record")]);
        assert_eq!(state.wals[0].segment, 3);
        assert_eq!(state.stats.created_segments, 1);
        assert_eq!(test_trace::steps(dir.path()), ["create Kv.wal/00000003.wal"]);
        assert_eq!(std::fs::read(segment_path(&wals[0].1, 3)).unwrap()[..16], wal_header(2));
    }

    // After a rotation the appends land in the new segment, through the
    // fixed-file slot and through raw descriptors; a slot that cannot take
    // the new segment is released and every log goes on with raw
    // descriptors, and a release that fails too is logged.
    #[test]
    fn test_appends_after_a_rotation_land_in_the_new_segment() {
        for (fixed_files, update_fails, release_fails) in [(true, false, false), (false, false, false), (true, true, false), (true, true, true)] {
            let dir = tempfile::TempDir::new().unwrap();
            let wals = wal_paths(dir.path(), &[WalTarget::Kv, WalTarget::Json]);
            let mut state = small_segments(&wals, 16);
            assert!(state.fixed_files);
            state.fixed_files = fixed_files;
            (state.faults.files_update, state.faults.files_release) = (update_fails, release_fails);
            append_all(&mut state, WalTarget::Kv, &[b"first"]);

            append_all(&mut state, WalTarget::Kv, &[b"second"]);
            append_all(&mut state, WalTarget::Json, &[b"json"]);
            let case = format!("fixed files {fixed_files}, update fails {update_fails}, release fails {release_fails}");
            assert_eq!(std::fs::read(segment_path(&wals[0].1, 2)).unwrap(), log_of(&[(2, b"second")]), "{case}");
            assert_eq!(std::fs::read(segment_1(&wals[1].1)).unwrap(), log_of(&[(1, b"json")]), "{case}");
            assert_eq!(state.fixed_files, fixed_files && !update_fails, "{case}");
            assert_eq!(state.faults.leaked_slots, u64::from(release_fails), "{case}");
        }
    }

    /// A key-value WAL configured at `<dir>/link/Kv.wal`, a symlink to
    /// `<dir>/real/Kv.wal`; the configured paths and the target's directory.
    fn symlinked_wal(dir: &Path) -> (Vec<(WalTarget, PathBuf)>, PathBuf) {
        let (link, real) = (dir.join("link"), dir.join("real"));
        std::fs::create_dir_all(&link).unwrap();
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(real.join("Kv.wal"), link.join("Kv.wal")).unwrap();
        (vec![(WalTarget::Kv, link.join("Kv.wal"))], std::fs::canonicalize(real).unwrap())
    }

    // A log configured as a symlink stays one: its directory, the segments
    // and their markers lie at the target, also across a rotation.
    #[test]
    fn test_a_symlinked_log_keeps_its_segments_at_the_target() {
        let dir = tempfile::TempDir::new().unwrap();
        let (wals, real) = symlinked_wal(dir.path());
        let mut state = small_segments(&wals, 16);
        append_all(&mut state, WalTarget::Kv, &[b"first"]);
        append_all(&mut state, WalTarget::Kv, &[b"second"]);

        assert!(std::fs::symlink_metadata(&wals[0].1).unwrap().file_type().is_symlink());
        assert_eq!(names_in(&real.join("Kv.wal")), ["00000001.wal", "00000002.wal"]);
        state.faults = Faults { sync: true, cut: true, ..Faults::default() };
        let (batch, _) = record_appends(WalTarget::Kv, vec![b"lost".to_vec()]);
        process_batch(&mut state, batch);
        let names = ["00000001.wal", "00000002.wal", "00000003.wal", "00000003.wal.unsafe-end"];
        assert_eq!(names_in(&real.join("Kv.wal")), names);
        assert_eq!(names_in(&dir.path().join("link")), ["Kv.wal"]);
        let stops = crate::storage::test_fault::stops_under(&real);
        assert_eq!(stops, [real.join("Kv.wal").join("00000003.wal")], "the stop names the target");
    }

    // A segment whose end is unsafe after a failed append is never left: a
    // full one cuts its end back first and rotates after that; a rotation
    // asked for meanwhile is refused, and the next one succeeds.
    #[test]
    fn test_a_segment_with_an_unsafe_end_is_secured_before_it_rotates() {
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
        let (mut state, start) = state_after_a_failed_cut(&wals);
        state.segment_bytes = start;
        assert!(state.wals[0].unsafe_end);

        let err = rotate_request(&mut state, WalTarget::Kv).unwrap_err();
        assert!(err.to_string().contains("is safe"), "{err}");
        assert_eq!(state.wals[0].segment, 1);

        assert_eq!(append_all(&mut state, WalTarget::Kv, &[&delete_record(3, b"kept-two")]), [(WAL_HEADER_LEN, 2)]);
        assert_eq!(std::fs::metadata(segment_1(&wals[0].1)).unwrap().len(), start, "cut back before it was left");
        assert!(!marker_of(&wals[0].1).exists());
        assert_eq!(state.wals[0].segment, 2);

        state.segment_bytes = WAL_SEGMENT_BYTES;
        rotate_request(&mut state, WalTarget::Kv).unwrap();
        assert_eq!(state.wals[0].segment, 3);
        rotate_request(&mut state, WalTarget::Kv).unwrap();
        assert_eq!(state.wals[0].segment, 3, "a segment without records stays");
    }

    // A dropped segment leaves the hub's list, the one appended to never.
    #[test]
    fn test_dropped_segments_leave_the_list() {
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
        let mut state = small_segments(&wals, 16);
        for record in [b"one", b"two", b"six"] {
            append_all(&mut state, WalTarget::Kv, &[record]);
        }
        let drop_before = |state: &mut StorageState, segment| {
            let (response, mut dropped) = oneshot::channel();
            process_batch(state, vec![IoRequest::WalDropBefore { engine: WalTarget::Kv, segment, response }]);
            dropped.try_recv().unwrap()
        };
        assert!(drop_before(&mut state, 4).is_err());
        drop_before(&mut state, 3).unwrap();
        assert_eq!(listed(&segments(&mut state, WalTarget::Kv)), [(3, 27, 3)]);
    }

    // A truncate removes the segments before the one appended to — on the
    // caller's side, each removal synced — and the one prepared after it,
    // and cuts that one back to a header that starts after the last LSN;
    // the log is one segment then.
    #[test]
    fn test_a_truncate_leaves_one_segment_with_its_header() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let log = dir.path().join("wal");
            let config = StorageThreadConfig { segment_bytes: 16, ..cfg(false, 64) };
            let (mut st, handle) = StorageThread::new(config, vec![(WalTarget::Kv, log.clone())]).unwrap();
            for record in [b"one", b"two", b"six"] {
                handle.wal_append(WalTarget::Kv, record.to_vec()).await.unwrap();
            }
            prepare_segment(&log, 4).unwrap();
            test_trace::watch(&log);
            handle.wal_truncate(WalTarget::Kv).await.unwrap();
            st.shutdown();

            assert_eq!(names_in(&log), ["00000003.wal"]);
            assert_eq!(std::fs::read(segment_path(&log, 3)).unwrap(), wal_header(3));
            let steps = ["unlink 00000001.wal", "sync .", "unlink 00000002.wal", "sync .", "sync ."];
            assert_eq!(test_trace::steps(&log), steps);
        })
    }

    // A restart reads the last LSN of each older segment from the header of
    // the one after it and its size from its file; the last one takes the
    // appends.
    #[test]
    fn test_a_restart_lists_the_segments_left() {
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
        let mut state = small_segments(&wals, 16);
        for record in [b"one", b"two", b"six"] {
            append_all(&mut state, WalTarget::Kv, &[record]);
        }
        drop(state);

        let mut state = small_segments(&wals, 16);
        assert_eq!(listed(&segments(&mut state, WalTarget::Kv)), [(1, 27, 1), (2, 27, 2), (3, 27, 2)]);
        assert_eq!(state.wals[0].segment, 3);
    }

    // A ring without room for a write and its fdatasync stops the start.
    #[test]
    fn test_start_refuses_a_ring_without_room_for_a_chain() {
        let dir = tempfile::TempDir::new().unwrap();
        let config = StorageThreadConfig { ring_depth: 1, ..cfg(false, 64) };
        let Err(err) = open_state(&config, &wal_paths(dir.path(), &[WalTarget::Kv])) else { panic!("the start must fail") };
        assert!(err.to_string().contains("depth"), "{err}");
    }

    // 4. Batching: 100 concurrent wal_append requests processed correctly.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[allow(clippy::disallowed_methods, reason = "callers on several threads of a tokio runtime")]
    async fn test_batching_100_concurrent_wal_appends() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut st, handle) = spawn(dir.path(), false, 1024);
        let mut tasks = Vec::new();
        for _ in 0..100u32 {
            let h = handle.clone();
            tasks.push(tokio::spawn(async move { h.wal_append(WalTarget::Kv, vec![b'x'; 10]).await.unwrap() }));
        }
        let mut offsets = Vec::new();
        for t in tasks {
            offsets.push(t.await.unwrap());
        }
        offsets.sort_unstable();
        assert_eq!(offsets.len(), 100);
        for (i, off) in offsets.iter().enumerate() {
            assert_eq!(*off, (WAL_HEADER_LEN + (i as u64) * 18, i as u64 + 1));
        }
        st.shutdown();
        assert_eq!(std::fs::read(segment_1(&dir.path().join("wal"))).unwrap().len() as u64, WAL_HEADER_LEN + 1800);
    }

    // 5. Backpressure: bounded channel full -> try_send reports Full.
    #[test]
    fn test_channel_backpressure_is_bounded() {
        let (tx, _rx) = mpsc::channel::<u32>(2);
        assert!(tx.try_send(1).is_ok());
        assert!(tx.try_send(2).is_ok());
        assert!(matches!(tx.try_send(3), Err(mpsc::error::TrySendError::Full(3))));
    }

    // 6. SQPOLL fallback: standard mode yields a working ring,
    //    SQPOLL request falls back cleanly when needed (no error).
    #[test]
    fn test_build_ring_fallback_and_sqpoll() {
        let (_ring, sqpoll) = build_ring(false, 500, 64).unwrap();
        assert!(!sqpoll, "sqpoll_enabled=false must yield standard mode");
        // Requesting SQPOLL either succeeds or transparently falls back — never errors.
        let (_ring2, _sqpoll2) = build_ring(true, 500, 64).unwrap();
    }

    // 6b. End-to-end in real SQPOLL mode (WSL2 kernel supports it).
    #[test]
    fn test_wal_append_sqpoll_mode() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let (mut st, handle) = spawn(dir.path(), true, 64);
            handle.wal_append(WalTarget::Kv, b"sqpoll".to_vec()).await.unwrap();
            st.shutdown();
            let log = [&wal_header(0)[..], &framed(&[(1, b"sqpoll")])].concat();
            assert_eq!(std::fs::read(segment_1(&dir.path().join("wal"))).unwrap(), log);
        })
    }

    // 7. Shutdown: all pending requests are completed before thread exit.
    #[test]
    fn test_shutdown_drains_pending_requests() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let (mut st, handle) = spawn(dir.path(), false, 1024);
            // Enqueue directly (same module) without awaiting, so all requests are
            // in-flight when shutdown is issued.
            let mut receivers = Vec::new();
            for _ in 0..50 {
                let (tx, rx) = oneshot::channel();
                handle
                    .request_tx
                    .try_send(IoRequest::WalAppend { engine: WalTarget::Kv, data: vec![b'a'; 10], response: tx })
                    .unwrap();
                receivers.push(rx);
            }
            drop(handle);
            st.shutdown();
            for (i, rx) in receivers.into_iter().enumerate() {
                let appended = rx.await.unwrap().unwrap();
                assert_eq!(appended, (WAL_HEADER_LEN + (i as u64) * 18, i as u64 + 1));
            }
            assert_eq!(std::fs::read(segment_1(&dir.path().join("wal"))).unwrap().len() as u64, WAL_HEADER_LEN + 900);
        })
    }

    // WAL truncate resets the write cursor to the end of the header; the LSNs
    // go on.
    #[test]
    fn test_wal_truncate_resets_offset() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let (mut st, handle) = spawn(dir.path(), false, 64);
            handle.wal_append(WalTarget::Kv, b"abcde".to_vec()).await.unwrap();
            handle.wal_truncate(WalTarget::Kv).await.unwrap();
            let appended = handle.wal_append(WalTarget::Kv, b"XY".to_vec()).await.unwrap();
            assert_eq!(appended, (16, 2));
            st.shutdown();
            let log = [&wal_header(1)[..], &framed(&[(2, b"XY")])].concat();
            assert_eq!(std::fs::read(segment_1(&dir.path().join("wal"))).unwrap(), log);
        })
    }

    // Finding 3: an out-of-range CPU core is rejected with an error, not a panic.
    #[test]
    fn test_pin_to_cpu_rejects_out_of_range() {
        assert!(pin_to_cpu(libc::CPU_SETSIZE).is_err());
        assert!(pin_to_cpu(libc::CPU_SETSIZE + 1000).is_err());
    }

    // Registered (fixed) files: each WAL writes and syncs through its own
    // slot, and each write gets its own result.
    #[test]
    fn test_fixed_files_write_through_their_own_slots() {
        use WalTarget::{Json, Kv};
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[Kv, Json]);
        let (mut state, _) = open_state(&cfg(false, 64), &wals).unwrap();
        assert!(state.fixed_files);

        let (mut batch, mut json) = record_appends(Json, vec![b"fixed-json".to_vec()]);
        let (kv_batch, mut kv) = record_appends(Kv, vec![b"fixed-kv".to_vec()]);
        batch.extend(kv_batch);
        process_batch(&mut state, batch);
        assert_eq!(json[0].try_recv().unwrap().unwrap(), (16, 1));
        assert_eq!(kv[0].try_recv().unwrap().unwrap(), (16, 1));

        assert_eq!(std::fs::read(segment_1(&wals[0].1)).unwrap(), [&wal_header(0)[..], &framed(&[(1, b"fixed-kv")])].concat());
        assert_eq!(std::fs::read(segment_1(&wals[1].1)).unwrap(), [&wal_header(0)[..], &framed(&[(1, b"fixed-json")])].concat());
    }

    // Integration: the key-value engine with its WAL on the hub and its
    // vLog local -- small and large values round-trip.
    #[test]
    fn test_lsm_engine_with_storage_handle_end_to_end() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let wal_path = dir.path().join("wal");
            let vlog_path = dir.path().join("vlog");
            let (mut st, handle) = spawn(dir.path(), false, 1024);

            let wal = Arc::new(WriteAheadLog::with_storage_handle(handle.clone(), WalTarget::Kv));
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

            // Small value: inline in the WAL record, which the hub writes.
            engine.put(b"k", b"v").await.unwrap();
            assert_eq!(engine.get(b"k").await.unwrap(), Some(b"v".to_vec()));

            // Large value: the WAL record through the hub, the vLog append local.
            let big = vec![b'z'; 4096];
            engine.put(b"big", &big).await.unwrap();
            assert_eq!(engine.get(b"big").await.unwrap(), Some(big));

            st.shutdown();
        })
    }

    // The test-only local WAL committer: same round trip, no regression.
    #[test]
    fn test_lsm_engine_local_path_no_regression() {
        crate::core::engine_runtime::block_on(async {
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
        })
    }
}
