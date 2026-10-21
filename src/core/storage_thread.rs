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

use crate::core::wal::{WAL_HEADER_LEN, WAL_MAGIC};
use anyhow::{anyhow, Context, Result};
use tokio::sync::mpsc::{self, Receiver, Sender};
use io_uring::{opcode, squeue, types, IoUring};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use tokio::sync::oneshot;

/// SQPOLL ring; falls back to the standard ring on EPERM (missing CAP_SYS_NICE).
pub const SQPOLL_ENABLED: bool = true;
pub const SQPOLL_IDLE_MS: u32 = 2000;
pub const RING_DEPTH: u32 = 256;
/// No CPU pinning.
pub const STORAGE_THREAD_CPU: i32 = -1;

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

/// The engine a write-ahead log belongs to; the hub keeps one file per engine.
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
    /// Cut `engine`'s WAL back to its header; its LSNs go on where they were.
    WalTruncate { engine: WalTarget, response: oneshot::Sender<Result<()>> },
    /// Give the next append to `engine`'s WAL an LSN after `lsn`; never moves
    /// the counter back.
    SetLsnStart { engine: WalTarget, lsn: u64, response: oneshot::Sender<Result<()>> },
    /// Respond with the LSN of the last record durable in `engine`'s WAL.
    WalHeadLsn { engine: WalTarget, response: oneshot::Sender<Result<u64>> },
    /// Drain pending requests, then stop the thread.
    Shutdown,
}

/// Async, clonable interface to the storage thread.
#[derive(Clone)]
pub struct StorageHandle {
    request_tx: Sender<IoRequest>,
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

    pub async fn wal_truncate(&self, engine: WalTarget) -> Result<()> {
        self.request(|response| IoRequest::WalTruncate { engine, response }).await
    }

    pub async fn set_lsn_start(&self, engine: WalTarget, lsn: u64) -> Result<()> {
        self.request(|response| IoRequest::SetLsnStart { engine, lsn, response }).await
    }

    /// The LSN of the last record durable in `engine`'s WAL, after every
    /// append queued before this request.
    pub async fn wal_head_lsn(&self, engine: WalTarget) -> Result<u64> {
        self.request(|response| IoRequest::WalHeadLsn { engine, response }).await
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
    /// one WAL file per engine in `wals`. Blocks until the thread reports
    /// readiness (or an init error).
    pub fn new(config: StorageThreadConfig, wals: Vec<(WalTarget, PathBuf)>) -> Result<(Self, StorageHandle)> {
        // The hub numbers each WAL's appends in the order they leave this
        // channel. A request's place in it is fixed when a permit is filled,
        // not when it is reserved, so a writer draws its stamp in between and
        // the stamps follow the LSNs. A replacement channel must keep that.
        let (request_tx, request_rx) = mpsc::channel(config.channel_capacity);
        let shutdown = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<bool>>();
        let thread_shutdown = Arc::clone(&shutdown);
        let wal_count = wals.len();

        let join_handle = std::thread::Builder::new()
            .name("luradb-storage".into())
            .spawn(move || {
                storage_thread_main(config, wals, request_rx, thread_shutdown, ready_tx);
            })
            .context("failed to spawn storage thread")?;

        match ready_rx.recv() {
            Ok(Ok(sqpoll_active)) => {
                tracing::info!(
                    "Storage thread ready (SQPOLL {}, {wal_count} write-ahead logs).",
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
        // Non-blocking: `shutdown` may run on the engine thread. If the
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

/// One engine's WAL file and its append cursor.
struct WalFile {
    engine: WalTarget,
    file: File,
    /// Where a failed cut records `offset` for the next start.
    marker: PathBuf,
    offset: u64,
    /// LSN of the last record written; the next append gets the one after it.
    lsn: u64,
    /// The file has no header — a log of the earlier format — and takes no
    /// append until a truncate writes one.
    awaits_truncate: bool,
    /// Bytes a failed append left past `offset`, or the unsafe-end marker,
    /// may still be there; the next append cuts first.
    unsafe_end: bool,
}

/// Totals the thread logs when it stops; appends per fdatasync is the
/// average group-commit size.
#[derive(Debug, Default, PartialEq, Eq)]
struct HubStats {
    appends: u64,
    /// Batches with at least one append.
    batches: u64,
    fdatasyncs: u64,
}

struct StorageState {
    ring: IoUring,
    /// In the order given to [`StorageThread::new`]; a file's index is its
    /// fixed-file slot.
    wals: Vec<WalFile>,
    /// `false` after a failed `register_files` — ops then fall back to raw fds.
    fixed_files: bool,
    stats: HubStats,
    #[cfg(test)]
    faults: Faults,
}

/// Test-only faults, each reported once by the next operation of its kind,
/// and the counters the tests read.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct Faults {
    /// The next sync fails after its write has landed.
    pub(crate) sync: bool,
    /// The next cut back to the cursor fails and leaves the file as it is.
    pub(crate) cut: bool,
    /// The next removal of the unsafe-end marker fails and leaves it.
    pub(crate) unmark: bool,
    /// The next removal of the unsafe-end marker removes it, then fails to
    /// sync its directory.
    pub(crate) unmark_sync: bool,
    /// Directory syncs the removals of the unsafe-end marker have attempted,
    /// the injected failure included.
    pub(crate) unmark_syncs: u64,
}

#[cfg(test)]
thread_local! {
    /// (fail the next sync, syncs attempted) of the marker removal running on
    /// this thread, set while its [`DirSyncProbe`] lives.
    static DIR_SYNC_PROBE: std::cell::Cell<Option<(bool, u64)>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
impl Faults {
    /// Lets the directory syncs on this thread see `unmark_sync` and count
    /// into `unmark_syncs` until the returned probe drops.
    pub(crate) fn probe_unmark_syncs(&mut self) -> DirSyncProbe<'_> {
        DIR_SYNC_PROBE.set(Some((std::mem::take(&mut self.unmark_sync), 0)));
        DirSyncProbe(self)
    }
}

#[cfg(test)]
pub(crate) struct DirSyncProbe<'a>(&'a mut Faults);

#[cfg(test)]
impl Drop for DirSyncProbe<'_> {
    fn drop(&mut self) {
        if let Some((fail, syncs)) = DIR_SYNC_PROBE.take() {
            self.0.unmark_sync |= fail;
            self.0.unmark_syncs += syncs;
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

    /// The file's end stays unsafe until the cut and the marker removal both succeed.
    fn cut_to_cursor(&mut self, index: usize) -> std::io::Result<()> {
        self.wals[index].unsafe_end = true;
        if let Err(e) = self.cut_file(index) {
            let wal = &self.wals[index];
            mark_unsafe_end(&wal.marker, wal.offset);
            return Err(e);
        }
        self.unmark(index)?;
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
        wal.file.sync_all()
    }

    fn unmark(&mut self, index: usize) -> std::io::Result<()> {
        #[cfg(test)]
        if std::mem::take(&mut self.faults.unmark) {
            return Err(std::io::Error::other("injected marker removal failure"));
        }
        #[cfg(test)]
        let _probe = self.faults.probe_unmark_syncs();
        unmark_unsafe_end(&self.wals[index].marker)
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
    ready_tx: std::sync::mpsc::Sender<Result<bool>>,
) {
    if config.cpu >= 0 {
        if let Err(e) = pin_to_cpu(config.cpu) {
            tracing::warn!("Storage thread CPU pinning to core {} failed: {e}", config.cpu);
        }
    }

    let mut state = match open_state(&config, &wals) {
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
    let HubStats { appends, batches, fdatasyncs } = state.stats;
    tracing::info!("Storage thread stopped: {appends} WAL appends in {batches} batches, {fdatasyncs} fdatasyncs.");
}

/// Builds the ring and opens the WALs; returns the state and whether SQPOLL
/// is active.
fn open_state(config: &StorageThreadConfig, wals: &[(WalTarget, PathBuf)]) -> Result<(StorageState, bool)> {
    let (ring, sqpoll_active) = build_ring(config.sqpoll_enabled, config.sqpoll_idle_ms, config.ring_depth)?;
    let mut files = Vec::with_capacity(wals.len());
    for (engine, path) in wals {
        let file = open_rw(path)?;
        let marker = unsafe_end_marker(path);
        apply_unsafe_end_marker(path, &file).with_context(|| {
            format!("applying the unsafe-end marker {} to the write-ahead log {}", marker.display(), path.display())
        })?;
        let awaits_truncate = !ensure_header(&file)
            .with_context(|| format!("writing the header of the write-ahead log {}", path.display()))?;
        let offset = file.metadata()?.len();
        files.push(WalFile { engine: *engine, file, marker, offset, lsn: 0, awaits_truncate, unsafe_end: false });
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
        fixed_files,
        stats: HubStats::default(),
        #[cfg(test)]
        faults: Faults::default(),
    };
    Ok((state, sqpoll_active))
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

/// Processes a batch in channel order. Each run of WAL appends is written
/// with one write and one fdatasync per file (group commit across engines);
/// only a truncate or an LSN request ends a run and runs at its place.
/// Returns `true` if a `Shutdown` was seen.
fn process_batch(state: &mut StorageState, batch: Vec<IoRequest>) -> bool {
    let mut stop = false;
    let mut appended = false;
    let mut run = Vec::new();
    for request in batch {
        match request {
            IoRequest::Shutdown => stop = true,
            IoRequest::WalAppend { engine, data, response } => {
                run.push((engine, data, response));
                appended = true;
            }
            IoRequest::WalTruncate { engine, response } => {
                commit_appends(state, std::mem::take(&mut run));
                let _ = response.send(do_wal_truncate(state, engine));
            }
            IoRequest::SetLsnStart { engine, lsn, response } => {
                commit_appends(state, std::mem::take(&mut run));
                let index = state.wal_index(engine);
                if let Ok(index) = &index {
                    let wal = &mut state.wals[*index];
                    wal.lsn = wal.lsn.max(lsn);
                }
                let _ = response.send(index.map(|_| ()));
            }
            IoRequest::WalHeadLsn { engine, response } => {
                commit_appends(state, std::mem::take(&mut run));
                let _ = response.send(state.wal_index(engine).map(|index| state.wals[index].lsn));
            }
        }
    }
    commit_appends(state, run);
    if appended {
        state.stats.batches += 1;
    }
    stop
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

type Append = (WalTarget, Vec<u8>, oneshot::Sender<Result<(u64, u64)>>);

/// Writes a run of appends, one [`FileWrite`] per WAL file, and answers each
/// request with the offset and the LSN of its record.
fn commit_appends(state: &mut StorageState, run: Vec<Append>) {
    state.stats.appends += run.len() as u64;
    let last_lsn = |engine: WalTarget| state.wal_index(engine).map_or(0, |index| state.wals[index].lsn);
    let writes = plan_batch(run.iter().map(|(engine, data, _)| (*engine, data.as_slice())), last_lsn);
    let mut responses: Vec<_> = run.into_iter().map(|(_, _, response)| Some(response)).collect();
    for write in writes {
        let result = write_file(state, &write).map_err(|e| e.to_string());
        for (position, offset, lsn) in write.parts {
            let Some(response) = responses[position].take() else { continue };
            let _ = response.send(match &result {
                Ok(start) => Ok((start + offset, lsn)),
                Err(msg) => Err(anyhow!("WAL append failed: {msg}")),
            });
        }
    }
}

/// Appends `write` at the end of its file and fdatasyncs it; returns the
/// offset it starts at. A failed write or fdatasync cuts the file back to
/// the cursor, which stays where it was, and leaves its LSNs to the next
/// write.
fn write_file(state: &mut StorageState, write: &FileWrite) -> Result<u64> {
    let index = state.wal_index(write.engine)?;
    if state.wals[index].awaits_truncate {
        return Err(appends_refused().into());
    }
    let file = state.ring_file(index);
    let start = state.wals[index].offset;
    if state.wals[index].unsafe_end {
        if let Err(cut) = state.cut_to_cursor(index) {
            log_failed_cut(write.engine, start, &cut);
            return Err(cut.into());
        }
    }
    // At most one write per WAL file in flight: `ring_op` reaps every op
    // before it returns, so the fdatasync and the file's next write are
    // submitted only once this write has completed — each file gets its
    // bytes in channel order, and a cut after a failure races no write.
    if let Err(e) = write_and_sync(state, file, start, &write.data) {
        if let Err(cut) = state.cut_to_cursor(index) {
            log_failed_cut(write.engine, start, &cut);
        }
        return Err(e.into());
    }
    state.stats.fdatasyncs += 1;
    state.wals[index].offset += write.data.len() as u64;
    state.wals[index].lsn += write.parts.len() as u64;
    Ok(start)
}

fn write_and_sync(state: &mut StorageState, file: RingFile, start: u64, data: &[u8]) -> std::io::Result<()> {
    ring_write_all(&mut state.ring, file, start, data)?;
    #[cfg(test)]
    if std::mem::take(&mut state.faults.sync) {
        return Err(std::io::Error::other("injected fdatasync failure"));
    }
    ring_fsync(&mut state.ring, file)
}

/// Every failed cut, marker removal included, is logged: the file's end stays
/// unsafe until one succeeds.
fn log_failed_cut(engine: WalTarget, cursor: u64, error: &std::io::Error) {
    tracing::error!(
        "Securing the end of the {engine:?} write-ahead log at {cursor} bytes failed: {error}; \
         the next append retries before it writes."
    );
}

/// Cuts the log back to its header, or replaces a log of the earlier format
/// with the header alone.
fn do_wal_truncate(state: &mut StorageState, engine: WalTarget) -> Result<()> {
    let index = state.wal_index(engine)?;
    let wal = &mut state.wals[index];
    if wal.awaits_truncate {
        write_header(&wal.file)?;
        wal.awaits_truncate = false;
    } else {
        wal.file.set_len(WAL_HEADER_LEN)?;
    }
    wal.offset = WAL_HEADER_LEN;
    wal.file.sync_all()?;
    if let Err(e) = state.unmark(index) {
        state.wals[index].unsafe_end = true;
        log_failed_cut(engine, 0, &e);
        return Err(e.into());
    }
    state.wals[index].unsafe_end = false;
    Ok(())
}

// ── Log header ──────────────────────────────────────────────────────────────

/// Starts an empty log with the header and completes a torn one; returns
/// whether the log has the header — `false` for a log of the earlier format,
/// which stays as it is.
pub(crate) fn ensure_header(file: &File) -> std::io::Result<bool> {
    let len = file.metadata()?.len().min(WAL_HEADER_LEN) as usize;
    let mut head = [0; WAL_MAGIC.len()];
    file.read_exact_at(&mut head[..len], 0)?;
    if len == WAL_MAGIC.len() {
        return Ok(head == WAL_MAGIC);
    }
    // A part of the header is a torn one; a header goes only into a file
    // without records, so writing it again loses nothing.
    if !WAL_MAGIC.starts_with(&head[..len]) {
        return Ok(false);
    }
    write_header(file)?;
    file.sync_all()?;
    Ok(true)
}

/// Replaces the content of `file` with the header; the caller syncs it.
fn write_header(file: &File) -> std::io::Result<()> {
    file.set_len(0)?;
    file.write_all_at(&WAL_MAGIC, 0)
}

/// Why a log of the earlier format takes no append: records with and without
/// an LSN must never share a file.
pub(crate) fn appends_refused() -> std::io::Error {
    std::io::Error::other(
        "the write-ahead log still has the format of an earlier version; it takes appends once the start has truncated it",
    )
}

// ── Unsafe-end marker ───────────────────────────────────────────────────────

/// The file beside the WAL at `log` that holds the cursor (8 bytes,
/// big-endian) while a failed cut leaves bytes past it; the next start cuts
/// the log back to it before recovery reads the log.
pub(crate) fn unsafe_end_marker(log: &Path) -> PathBuf {
    with_suffix(log, ".unsafe-end")
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Records `cursor` in `marker` unless a marker is there already. A failure
/// is logged; nothing more can be done about it.
pub(crate) fn mark_unsafe_end(marker: &Path, cursor: u64) {
    if let Err(e) = write_marker(marker, cursor) {
        tracing::error!(
            "Writing the unsafe-end marker {} failed: {e}; a restart before the next \
             successful cut may read the failed append back.",
            marker.display()
        );
    }
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
    file.sync_all()?;
    std::fs::rename(&tmp, marker)?;
    sync_dir(marker)
}

/// Removes `marker` and syncs its directory. A missing marker gets the sync
/// too: a retry after a failed sync finds the marker gone, and only the sync
/// keeps it gone after a power loss.
pub(crate) fn unmark_unsafe_end(marker: &Path) -> std::io::Result<()> {
    let failed =
        |step: &str, e: std::io::Error| std::io::Error::new(e.kind(), format!("{step} {}: {e}", marker.display()));
    match std::fs::remove_file(marker) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        removed => removed.map_err(|e| failed("removing", e))?,
    }
    sync_dir(marker).map_err(|e| failed("syncing the directory after removing", e))
}

/// A rename or removal survives a power loss only once its directory is synced.
fn sync_dir(file: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    if let Some((fail, syncs)) = DIR_SYNC_PROBE.get() {
        DIR_SYNC_PROBE.set(Some((false, syncs + 1)));
        if fail {
            return Err(std::io::Error::other("injected directory sync failure"));
        }
    }
    let dir = match file.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    File::open(dir)?.sync_all()
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
                std::io::Error::other("io_uring submission queue full")
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
    // Aborts instead of panicking: this thread wakes engine tasks, and a wake
    // from an unwinding thread aborts the process anyway (compio #1089).
    let Some(entry) = cq.next() else {
        eprintln!("luradb storage ring: no completion after submit_and_wait(1), aborting");
        std::process::abort();
    };
    cq.sync();
    Ok(entry.result())
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

/// fdatasync on `file`; the WAL needs no metadata sync.
fn ring_fsync(ring: &mut IoUring, file: RingFile) -> std::io::Result<()> {
    let res = ring_op(ring, fsync_entry(file))?;
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

/// Test helper: a running hub over the WAL files it is given, handing out the
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
        let config = StorageThreadConfig {
            sqpoll_enabled: false,
            sqpoll_idle_ms: SQPOLL_IDLE_MS,
            ring_depth: RING_DEPTH,
            channel_capacity: crate::config::StorageConfig::default().wal_queue_capacity,
            cpu: STORAGE_THREAD_CPU,
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
        }
    }

    /// A hub with the key-value WAL alone, at `<dir>/wal`.
    fn spawn(dir: &Path, sqpoll: bool, capacity: usize) -> (StorageThread, StorageHandle) {
        StorageThread::new(cfg(sqpoll, capacity), vec![(WalTarget::Kv, dir.join("wal"))]).unwrap()
    }

    /// One WAL file per target in `dir`, named after the target.
    fn wal_paths(dir: &Path, targets: &[WalTarget]) -> Vec<(WalTarget, PathBuf)> {
        targets.iter().map(|target| (*target, dir.join(format!("{target:?}.wal")))).collect()
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
        wal::recover(path)
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
            assert_eq!(o1, (8, 1));
            assert_eq!(o2, (21, 2));
            st.shutdown();
            let log = [&WAL_MAGIC[..], &framed(&[(1, b"hello"), (2, b"world!")])].concat();
            assert_eq!(std::fs::read(dir.path().join("wal")).unwrap(), log);
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
                    (WalTarget::Kv, (8, 1)), (WalTarget::Json, (8, 1)), (WalTarget::Rel, (8, 1)), (WalTarget::Sys, (8, 1)),
                    (WalTarget::Kv, (33, 2)), (WalTarget::Json, (35, 2)), (WalTarget::Rel, (34, 2)), (WalTarget::Sys, (34, 2)),
                ];
                assert_eq!(appended, expected);

                handle.wal_truncate(WalTarget::Json).await.unwrap();
                assert_eq!(handle.wal_append(WalTarget::Json, delete_record(3, b"Json-3")).await.unwrap(), (8, 3));
                for (target, head) in [(WalTarget::Kv, 2), (WalTarget::Json, 3), (WalTarget::Rel, 2), (WalTarget::Sys, 2)] {
                    assert_eq!(handle.wal_head_lsn(target).await.unwrap(), head);
                }
                st.shutdown();

                let paths: Vec<&Path> = wals.iter().map(|(_, path)| path.as_path()).collect();
                assert_eq!(recovered_keys(paths[0]).await, ["Kv-1", "Kv-2"]);
                assert_eq!(recovered_keys(paths[1]).await, ["Json-3"]);
                assert_eq!(recovered_keys(paths[2]).await, ["Rel-1", "Rel-2"]);
                assert_eq!(recovered_keys(paths[3]).await, ["Sys-1", "Sys-2"]);
                assert_eq!(wal::recover(paths[1]).await.unwrap().max_lsn, 3);
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
            assert_eq!(handle.wal_append(WalTarget::Kv, b"kv".to_vec()).await.unwrap(), (8, 1));

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
            assert_eq!(handle.wal_append(WalTarget::Kv, delete_record(1, b"first")).await.unwrap(), (8, 42));
            assert_eq!(handle.wal_append(WalTarget::Kv, delete_record(2, b"second")).await.unwrap().1, 43);
            assert_eq!(handle.wal_head_lsn(WalTarget::Kv).await.unwrap(), 43);
            st.shutdown();

            assert_eq!(wal::recover(dir.path().join("wal")).await.unwrap().max_lsn, 43);
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
            assert_eq!(handle.wal_append(WalTarget::Kv, delete_record(4, b"after")).await.unwrap(), (8, 4));
            assert_eq!(handle.wal_head_lsn(WalTarget::Kv).await.unwrap(), 4);
            st.shutdown();
        })
    }

    // A log of the earlier format stays as it is at the start and refuses
    // appends until a truncate replaces it with the header; no record with an
    // LSN ever lands behind a record without one.
    #[test]
    fn test_a_log_of_the_earlier_format_takes_appends_only_after_a_truncate() {
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
        let earlier = delete_record(1, b"earlier");
        std::fs::write(&wals[0].1, &earlier).unwrap();
        let (mut state, _) = open_state(&cfg(false, 64), &wals).unwrap();

        let (batch, mut refused) = record_appends(WalTarget::Kv, vec![delete_record(2, b"refused")]);
        process_batch(&mut state, batch);
        let err = refused[0].try_recv().unwrap().unwrap_err();
        assert!(err.to_string().contains("earlier version"), "{err}");
        assert_eq!(std::fs::read(&wals[0].1).unwrap(), earlier);

        let (response, mut truncated) = oneshot::channel();
        process_batch(&mut state, vec![IoRequest::WalTruncate { engine: WalTarget::Kv, response }]);
        truncated.try_recv().unwrap().unwrap();
        assert_eq!(std::fs::read(&wals[0].1).unwrap(), WAL_MAGIC);

        let (batch, mut kept) = record_appends(WalTarget::Kv, vec![delete_record(3, b"kept")]);
        process_batch(&mut state, batch);
        assert_eq!(kept[0].try_recv().unwrap().unwrap(), (8, 1));
    }

    // A crash while the header was written leaves a part of it; the start
    // writes the header again.
    #[test]
    fn test_start_completes_a_torn_header() {
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
        std::fs::write(&wals[0].1, b"LUR").unwrap();
        let (mut state, _) = open_state(&cfg(false, 64), &wals).unwrap();
        assert_eq!(std::fs::read(&wals[0].1).unwrap(), WAL_MAGIC);
        assert_eq!(state.wals[0].offset, WAL_HEADER_LEN);

        let (batch, mut appended) = record_appends(WalTarget::Kv, vec![delete_record(1, b"first")]);
        process_batch(&mut state, batch);
        assert_eq!(appended[0].try_recv().unwrap().unwrap(), (8, 1));
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
        assert_eq!(state.stats, HubStats { appends: 6, batches: 1, fdatasyncs: 3 });

        let (batch, more) = appends(&[Kv; 20]);
        process_batch(&mut state, batch);
        assert_eq!(state.stats, HubStats { appends: 26, batches: 2, fdatasyncs: 4 });

        // Each one-byte payload takes 9 bytes behind the 8-byte header; the
        // LSNs count per file across both batches.
        receivers.extend(more);
        let appended: Vec<(u64, u64)> = receivers.iter_mut().map(|rx| rx.try_recv().unwrap().unwrap()).collect();
        assert_eq!(&appended[..6], [(8, 1), (8, 1), (17, 2), (8, 1), (17, 2), (26, 3)]);
        assert_eq!(appended[6..], (3..23).map(|i| (8 + 9 * i, i + 1)).collect::<Vec<_>>());
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
        OpenOptions::new().append(true).open(&wals[0].1).unwrap().write_all(b"torn").unwrap();
        // Every further write to the key-value WAL fails: its slot holds /dev/full.
        let dev_full = OpenOptions::new().write(true).open("/dev/full").unwrap();
        state.ring.submitter().register_files_update(0, &[dev_full.as_raw_fd()]).unwrap();

        let (batch, mut receivers) = appends(&[Kv, Json, Kv]);
        process_batch(&mut state, batch);

        assert_eq!(std::fs::metadata(&wals[0].1).unwrap().len(), 26);
        assert_eq!(state.wals[0].offset, 26);
        assert_eq!(state.wals[0].lsn, 2);
        for i in [0, 2] {
            let err = receivers[i].try_recv().unwrap().unwrap_err();
            assert!(err.to_string().starts_with("WAL append failed"), "{err}");
        }
        assert_eq!(receivers[1].try_recv().unwrap().unwrap(), (17, 2));
    }

    // A failed append leaves nothing behind the log's end: after a long run
    // whose fdatasync fails and a shorter run that succeeds, recovery reads
    // the shorter run alone.
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
                assert!(err.to_string().starts_with("WAL append failed"), "{err}");
            }

            let (batch, mut kept) = record_appends(WalTarget::Kv, vec![delete_record(2, b"kept")]);
            process_batch(&mut state, batch);
            assert_eq!(kept[0].try_recv().unwrap().unwrap(), (8, 1));
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
            let len = || std::fs::metadata(path).unwrap().len();
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

    /// A hub over `wals` after an append whose cut failed: the key-value WAL
    /// holds `kept-one`, which ends at the returned cursor, and a tail past it.
    fn state_after_a_failed_cut(wals: &[(WalTarget, PathBuf)]) -> (StorageState, u64) {
        let (mut state, _) = open_state(&cfg(false, 64), wals).unwrap();
        let (batch, _) = record_appends(WalTarget::Kv, vec![delete_record(1, b"kept-one")]);
        process_batch(&mut state, batch);
        let start = state.wals[0].offset;

        state.faults = Faults { sync: true, cut: true, ..Faults::default() };
        let (batch, mut failed) = record_appends(WalTarget::Kv, vec![delete_record(2, b"lost-with-a-long-key")]);
        process_batch(&mut state, batch);
        assert!(failed[0].try_recv().unwrap().is_err());
        assert!(std::fs::metadata(&wals[0].1).unwrap().len() > start);
        (state, start)
    }

    // A failed cut leaves the cursor in a marker beside the log; the next
    // start cuts the log back to it before recovery reads the log.
    #[test]
    fn test_start_cuts_the_log_back_to_the_cursor_a_failed_cut_left() {
        crate::core::engine_runtime::block_on(async {
            let dir = tempfile::TempDir::new().unwrap();
            let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
            let path = wals[0].1.as_path();
            let marker = dir.path().join("Kv.wal.unsafe-end");
            let (state, start) = state_after_a_failed_cut(&wals);
            assert_eq!(std::fs::read(&marker).unwrap(), start.to_be_bytes());
            drop(state);

            let (mut state, _) = open_state(&cfg(false, 64), &wals).unwrap();
            assert_eq!(std::fs::metadata(path).unwrap().len(), start);
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
        let marker = dir.path().join("Kv.wal.unsafe-end");
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
        let marker = dir.path().join("Kv.wal.unsafe-end");
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
        let marker = dir.path().join("Kv.wal.unsafe-end");
        let (mut state, _) = state_after_a_failed_cut(&wals);
        assert!(marker.exists());

        let (response, mut truncated) = oneshot::channel();
        process_batch(&mut state, vec![IoRequest::WalTruncate { engine: WalTarget::Kv, response }]);
        truncated.try_recv().unwrap().unwrap();
        assert_eq!(std::fs::metadata(&wals[0].1).unwrap().len(), WAL_HEADER_LEN);
        assert!(!marker.exists());
        assert!(!state.wals[0].unsafe_end);
    }

    // A marker that cannot be removed fails the cut: no append is confirmed
    // while the marker exists, so its cursor never cuts a confirmed append.
    #[test]
    fn test_a_failed_marker_removal_fails_the_cut() {
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
        let marker = dir.path().join("Kv.wal.unsafe-end");
        let (mut state, start) = state_after_a_failed_cut(&wals);

        state.faults.unmark = true;
        let (batch, mut refused) = record_appends(WalTarget::Kv, vec![delete_record(3, b"refused")]);
        process_batch(&mut state, batch);
        assert!(refused[0].try_recv().unwrap().is_err());
        assert_eq!(std::fs::metadata(&wals[0].1).unwrap().len(), start);
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
        let marker = dir.path().join("Kv.wal.unsafe-end");
        let (mut state, _) = state_after_a_failed_cut(&wals);

        state.faults.unmark = true;
        let (response, mut truncated) = oneshot::channel();
        process_batch(&mut state, vec![IoRequest::WalTruncate { engine: WalTarget::Kv, response }]);
        assert!(truncated.try_recv().unwrap().is_err());
        assert!(state.wals[0].unsafe_end);
        assert!(marker.exists());

        let (batch, mut kept) = record_appends(WalTarget::Kv, vec![delete_record(3, b"kept-two")]);
        process_batch(&mut state, batch);
        assert_eq!(kept[0].try_recv().unwrap().unwrap(), (8, 2));
        assert!(!marker.exists());
    }

    // A removal whose directory sync fails fails the cut; the retry finds the
    // marker gone and still syncs the directory before it confirms an append.
    #[test]
    fn test_a_failed_directory_sync_after_the_marker_removal_fails_the_cut() {
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
        let marker = dir.path().join("Kv.wal.unsafe-end");
        let (mut state, start) = state_after_a_failed_cut(&wals);
        assert!(marker.exists());

        state.faults.unmark_sync = true;
        let (batch, mut refused) = record_appends(WalTarget::Kv, vec![delete_record(3, b"refused")]);
        process_batch(&mut state, batch);
        assert!(refused[0].try_recv().unwrap().is_err());
        assert!(!marker.exists());
        assert!(state.wals[0].unsafe_end);

        let syncs = state.faults.unmark_syncs;
        let record = delete_record(4, b"kept-two");
        let end = start + 8 + record.len() as u64;
        let (batch, mut kept) = record_appends(WalTarget::Kv, vec![record]);
        process_batch(&mut state, batch);
        assert_eq!(kept[0].try_recv().unwrap().unwrap().0, start);
        assert_eq!(state.faults.unmark_syncs, syncs + 1);
        assert!(!state.wals[0].unsafe_end);
        assert_eq!(std::fs::metadata(&wals[0].1).unwrap().len(), end);
    }

    // A marker that holds no 8-byte cursor stops the start and is named in
    // the error; the log and the marker stay as they are.
    #[test]
    fn test_start_refuses_a_marker_without_a_cursor() {
        let dir = tempfile::TempDir::new().unwrap();
        let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
        let marker = dir.path().join("Kv.wal.unsafe-end");
        std::fs::write(&wals[0].1, b"log-bytes").unwrap();
        std::fs::write(&marker, [0, 0, 7]).unwrap();

        let Err(err) = open_state(&cfg(false, 64), &wals) else { panic!("the start must fail") };
        assert!(err.to_string().contains(&marker.display().to_string()), "{err}");
        assert_eq!(std::fs::read(&wals[0].1).unwrap(), b"log-bytes");
        assert_eq!(std::fs::read(&marker).unwrap(), [0, 0, 7]);
    }

    // A cursor at or past the log's end leaves the log as it is: cutting to
    // it would pad the log with zero bytes.
    #[test]
    fn test_start_never_lengthens_the_log_to_the_marker_cursor() {
        for (log, cursor) in [(WAL_MAGIC.as_slice(), 21u64), (b"log-bytes".as_slice(), 9)] {
            let dir = tempfile::TempDir::new().unwrap();
            let wals = wal_paths(dir.path(), &[WalTarget::Kv]);
            let marker = dir.path().join("Kv.wal.unsafe-end");
            std::fs::write(&wals[0].1, log).unwrap();
            std::fs::write(&marker, cursor.to_be_bytes()).unwrap();

            let (state, _) = open_state(&cfg(false, 64), &wals).unwrap();
            assert_eq!(std::fs::read(&wals[0].1).unwrap(), log);
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
        let tmp = dir.path().join("Kv.wal.unsafe-end.tmp");
        std::fs::write(&tmp, [0, 0]).unwrap();

        open_state(&cfg(false, 64), &wals).unwrap();
        assert!(!tmp.exists());
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
            assert_eq!(*off, (8 + (i as u64) * 18, i as u64 + 1));
        }
        st.shutdown();
        assert_eq!(std::fs::read(dir.path().join("wal")).unwrap().len(), 8 + 1800);
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
            let log = [&WAL_MAGIC[..], &framed(&[(1, b"sqpoll")])].concat();
            assert_eq!(std::fs::read(dir.path().join("wal")).unwrap(), log);
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
                assert_eq!(appended, (8 + (i as u64) * 18, i as u64 + 1));
            }
            assert_eq!(std::fs::read(dir.path().join("wal")).unwrap().len(), 8 + 900);
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
            assert_eq!(appended, (8, 2));
            st.shutdown();
            let log = [&WAL_MAGIC[..], &framed(&[(2, b"XY")])].concat();
            assert_eq!(std::fs::read(dir.path().join("wal")).unwrap(), log);
        })
    }

    // Finding 3: an out-of-range CPU core is rejected with an error, not a panic.
    #[test]
    fn test_pin_to_cpu_rejects_out_of_range() {
        assert!(pin_to_cpu(libc::CPU_SETSIZE).is_err());
        assert!(pin_to_cpu(libc::CPU_SETSIZE + 1000).is_err());
    }

    // Registered (fixed) files: each WAL writes through its own slot.
    #[test]
    fn test_fixed_files_write_through_their_own_slots() {
        let dir = tempfile::TempDir::new().unwrap();
        let kv = open_rw(&dir.path().join("kv.wal")).unwrap();
        let json = open_rw(&dir.path().join("json.wal")).unwrap();
        let (mut ring, _) = build_ring(false, 500, 64).unwrap();
        ring.submitter()
            .register_files(&[kv.as_raw_fd(), json.as_raw_fd()])
            .unwrap();

        ring_write_all(&mut ring, RingFile::Fixed(1), 0, b"fixed-json").unwrap();
        ring_write_all(&mut ring, RingFile::Fixed(0), 0, b"fixed-kv").unwrap();
        ring_fsync(&mut ring, RingFile::Fixed(0)).unwrap();

        assert_eq!(std::fs::read(dir.path().join("kv.wal")).unwrap(), b"fixed-kv");
        assert_eq!(std::fs::read(dir.path().join("json.wal")).unwrap(), b"fixed-json");
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
