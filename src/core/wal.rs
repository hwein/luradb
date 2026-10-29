#[cfg(test)]
use crate::core::storage_thread::{
    appends_refused, apply_unsafe_end_marker, ensure_header, mark_unsafe_end, unmark_unsafe_end, unsafe_end_marker,
    Faults,
};
use crate::core::storage_thread::{StorageHandle, WalMark, WalPermit, WalTarget};
use std::io::SeekFrom;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use thiserror::Error;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, BufReader};
#[cfg(test)]
use tokio::io::AsyncWriteExt;
#[cfg(test)]
use tokio::sync::{mpsc, oneshot};

/// The first bytes of every log this version writes. A log without them has
/// the earlier format, whose first byte is a record type from 1 to 4.
pub const WAL_MAGIC: [u8; 8] = *b"LURAWAL\x02";
pub const WAL_HEADER_LEN: u64 = WAL_MAGIC.len() as u64;

/// Hard ceiling on any single length-prefixed WAL field (a key or a value)
/// read during recovery. Without it, a corrupt tail turns garbage bytes into
/// a u32 length up to 4 GiB and `read_len_prefixed` allocates that much
/// before `read_exact` ever reaches EOF.
///
/// Derived, not guessed, from the largest a legitimate write path can hand
/// to one field: axum's default per-request body cap is 2 MiB (see
/// `api/mod.rs`), the JSON bulk import's explicit override
/// (`json.bulk_body_limit_bytes`) defaults to 64 MiB, and the IPC/SHM
/// command ring (`CLIENT_RING_SIZE`) is 4 MiB -- all well above the
/// engines' 512 KiB default value limit, which every engine (kv/json/rel)
/// checks a value against before it ever reaches the WAL. 64 MiB (the JSON bulk body cap) is the largest of these; 96 MiB
/// gives it headroom no legitimate write can reach.
pub const WAL_MAX_FIELD_LEN: usize = 96 * 1024 * 1024;

/// [`recover`] reads the log through a buffer of this size: its fields are
/// 1 to 8 bytes each, and a read per field made recovery slow.
const RECOVERY_READ_BUFFER: usize = 1024 * 1024;

/// The log as [`recover`] reads it.
type LogReader = BufReader<File>;

#[derive(Error, Debug)]
pub enum WalError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("A partial write to the WAL was detected. Expected to write {expected} bytes, but only wrote {wrote}. The WAL is now in an inconsistent state.")]
    PartialWrite { expected: usize, wrote: usize },
}

/// Represents a single, parsed entry from the Write-Ahead Log.
#[derive(Debug, PartialEq, Eq)]
pub enum WalEntry {
    Set {
        timestamp: u64,
        key: Vec<u8>,
        value: Vec<u8>,
        /// Unix seconds after which this entry expires; 0 means no expiry.
        expire_at: u64,
    },
    Delete {
        timestamp: u64,
        key: Vec<u8>,
        /// An op of a BATCH record (type 3), not a single DELETE record
        /// (type 2): batch ops share one stamp and replay in order.
        in_batch: bool,
    },
    SetNull {
        timestamp: u64,
        key: Vec<u8>,
    },
}

impl WalEntry {
    /// The key the entry writes.
    pub fn key(&self) -> &[u8] {
        match self {
            WalEntry::Set { key, .. } | WalEntry::Delete { key, .. } | WalEntry::SetNull { key, .. } => key,
        }
    }
}

/// What [`recover`] read from a log.
#[derive(Debug, Default)]
pub struct Recovered {
    /// Each entry with the LSN of its record; the ops of a batch share one.
    pub entries: Vec<(u64, WalEntry)>,
    /// The highest LSN in the log, 0 for a log without records.
    pub max_lsn: u64,
}

/// Recovers database state by reading and parsing all entries from the WAL.
///
/// This function is designed to be called once at startup. It reads the entire
/// log from disk and reconstructs the in-memory operations needed to restore
/// the MemTable to its pre-shutdown state.
///
/// A log that starts with [`WAL_MAGIC`] frames every record with its LSN,
/// `[lsn:u64][type:u8]...`; a log of the earlier format has neither, and its
/// records get the LSNs 1 to n in file order.
pub async fn recover(path: impl AsRef<Path>) -> Result<Recovered, WalError> {
    let mut file = match File::open(path.as_ref()).await {
        Ok(f) => BufReader::with_capacity(RECOVERY_READ_BUFFER, f),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Recovered::default()),
        Err(e) => return Err(e.into()),
    };

    let framed = match read_next::<8>(&mut file).await? {
        Some(head) => head == WAL_MAGIC,
        None => return Ok(Recovered::default()),
    };
    if !framed {
        file.seek(SeekFrom::Start(0)).await?;
    }

    let mut recovered = Recovered::default();
    let mut lsn = 0;
    loop {
        // A clean end of the log can only fall before a record.
        let entry_type = if framed {
            let Some(frame) = read_next::<8>(&mut file).await? else { break };
            lsn = u64::from_be_bytes(frame);
            file.read_u8().await?
        } else {
            let Some([entry_type]) = read_next::<1>(&mut file).await? else { break };
            lsn += 1;
            entry_type
        };
        read_record(&mut file, entry_type, lsn, &mut recovered.entries).await?;
        recovered.max_lsn = recovered.max_lsn.max(lsn);
    }

    Ok(recovered)
}

/// The next `N` bytes of the log, `None` at its end; fewer than `N` bytes
/// before the end are a torn record.
async fn read_next<const N: usize>(file: &mut LogReader) -> Result<Option<[u8; N]>, WalError> {
    let mut buf = [0; N];
    let mut filled = 0;
    while filled < N {
        match file.read(&mut buf[filled..]).await? {
            0 if filled == 0 => return Ok(None),
            0 => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into()),
            n => filled += n,
        }
    }
    Ok(Some(buf))
}

/// Reads the rest of one record of `entry_type` and adds its entries with `lsn`.
async fn read_record(
    file: &mut LogReader,
    entry_type: u8,
    lsn: u64,
    entries: &mut Vec<(u64, WalEntry)>,
) -> Result<(), WalError> {
    match entry_type {
        // SET: [ts:u64][key_len:u32][key][value_len:u32][value][expire_at:u64]
        1 => {
            let timestamp = file.read_u64().await?;
            let key = read_len_prefixed(file).await?;
            let value = read_len_prefixed(file).await?;
            let expire_at = file.read_u64().await?;
            entries.push((lsn, WalEntry::Set { timestamp, key, value, expire_at }));
        }
        // DELETE: [ts:u64][key_len:u32][key]
        2 => {
            let timestamp = file.read_u64().await?;
            let key = read_len_prefixed(file).await?;
            entries.push((lsn, WalEntry::Delete { timestamp, key, in_batch: false }));
        }
        // BATCH: [ts:u64][count:u32] then per op [op:u8][key]([value][expire_at]).
        // Parsed all-or-nothing: a torn batch record fails recovery instead of
        // silently applying a prefix of its operations.
        3 => {
            let timestamp = file.read_u64().await?;
            let count = file.read_u32().await?;
            for _ in 0..count {
                let op = file.read_u8().await?;
                let key = read_len_prefixed(file).await?;
                match op {
                    1 => {
                        let value = read_len_prefixed(file).await?;
                        let expire_at = file.read_u64().await?;
                        entries.push((lsn, WalEntry::Set { timestamp, key, value, expire_at }));
                    }
                    2 => entries.push((lsn, WalEntry::Delete { timestamp, key, in_batch: true })),
                    _ => return Err(invalid_entry_error()),
                }
            }
        }
        // SET_NULL: [ts:u64][key_len:u32][key]; type 3 is the batch record above
        4 => {
            let timestamp = file.read_u64().await?;
            let key = read_len_prefixed(file).await?;
            entries.push((lsn, WalEntry::SetNull { timestamp, key }));
        }
        _ => return Err(invalid_entry_error()),
    }
    Ok(())
}

async fn read_len_prefixed(file: &mut LogReader) -> Result<Vec<u8>, WalError> {
    let len = file.read_u32().await? as usize;
    if len > WAL_MAX_FIELD_LEN {
        return Err(field_too_long_error(len));
    }
    let mut buf = vec![0; len];
    file.read_exact(&mut buf).await?;
    Ok(buf)
}

fn invalid_entry_error() -> WalError {
    WalError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "Invalid WAL entry type found during recovery",
    ))
}

fn field_too_long_error(len: usize) -> WalError {
    WalError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("WAL field length {len} exceeds maximum of {WAL_MAX_FIELD_LEN} bytes"),
    ))
}

#[cfg(test)]
enum CommitRequest {
    Append { data: Vec<u8>, responder: AppendResponder },
    Control(Control),
}

/// Requests that end a group: they run after the appends queued before them.
#[cfg(test)]
enum Control {
    Truncate { responder: oneshot::Sender<Result<(), WalError>> },
    SetLsnStart { lsn: u64, responder: oneshot::Sender<()> },
    HeadLsn { responder: oneshot::Sender<u64> },
}

/// A Write-Ahead Log with Group Commit for high-throughput durability.
///
/// `Remote` hands all I/O to the storage hub, which writes and fdatasyncs
/// `engine`'s file on its io_uring ring. `Local` (tests only) runs a tokio::fs
/// committer task with the same semantics: one writer per file, one fsync per
/// group, one LSN source per file. `append`'s empty-input shortcut is
/// identical in both modes.
enum WalMode {
    #[cfg(test)]
    Local(mpsc::Sender<CommitRequest>),
    Remote { handle: StorageHandle, engine: WalTarget },
}

pub struct WriteAheadLog {
    inner: WalMode,
}

/// A slot reserved in the queue to the log; [`Self::send`] fills it.
pub struct Permit<'a>(PermitMode<'a>);

enum PermitMode<'a> {
    #[cfg(test)]
    Local(mpsc::Permit<'a, CommitRequest>),
    Remote(WalPermit<'a>),
}

impl Permit<'_> {
    /// Queues `data` as one record and waits until it is durable; returns the
    /// offset and the LSN of the record. The record's place in the queue, and
    /// so its LSN, is fixed by this call, not by the reservation. `data` is
    /// never empty: the LSN frame alone is no record.
    pub async fn send(self, data: Vec<u8>) -> Result<(u64, u64), WalError> {
        match self.0 {
            #[cfg(test)]
            PermitMode::Local(permit) => {
                let (responder, response) = oneshot::channel();
                permit.send(CommitRequest::Append { data, responder });
                response.await.map_err(|_| broken_pipe_error())?
            }
            PermitMode::Remote(permit) => permit.send(data).await.map_err(wal_remote_err),
        }
    }
}

impl WriteAheadLog {
    /// Tests only: creates a new WAL or opens an existing one at the given
    /// path, written by a local committer task instead of the storage hub.
    #[cfg(test)]
    pub async fn new(path: impl AsRef<Path>) -> Result<Self, WalError> {
        Self::with_capacity(path, crate::config::StorageConfig::default().wal_queue_capacity).await
    }

    /// Tests only: [`Self::new`] with a queue of `capacity` records.
    #[cfg(test)]
    pub async fn with_capacity(path: impl AsRef<Path>, capacity: usize) -> Result<Self, WalError> {
        let wal = LocalWal::open(path.as_ref()).await?;
        let (sender, receiver) = mpsc::channel(capacity);
        compio::runtime::spawn(run_committer(wal, receiver)).detach();

        Ok(Self { inner: WalMode::Local(sender) })
    }

    /// Routes all I/O of `engine`'s WAL through the storage hub. The hub owns
    /// the file; this WAL keeps no file handle of its own.
    pub fn with_storage_handle(handle: StorageHandle, engine: WalTarget) -> Self {
        Self { inner: WalMode::Remote { handle, engine } }
    }

    /// Waits for a slot in the queue to the log. A writer reserves before it
    /// draws the stamp its record carries: the wait for a full queue comes
    /// before the stamp, and [`Permit::send`] places the record right after it.
    pub async fn reserve(&self) -> Result<Permit<'_>, WalError> {
        match &self.inner {
            #[cfg(test)]
            WalMode::Local(sender) => {
                Ok(Permit(PermitMode::Local(sender.reserve().await.map_err(|_| broken_pipe_error())?)))
            }
            WalMode::Remote { handle, engine } => {
                Ok(Permit(PermitMode::Remote(handle.reserve_wal(*engine).await.map_err(wal_remote_err)?)))
            }
        }
    }

    /// Appends a new entry to the WAL and waits for it to be durably flushed.
    ///
    /// Returns the file offset at which this entry was written and its LSN;
    /// an empty entry writes nothing and returns `(0, 0)`.
    /// Concurrent callers are automatically batched into a single fsync.
    pub async fn append(&self, data: &[u8]) -> Result<(u64, u64), WalError> {
        if data.is_empty() {
            return Ok((0, 0));
        }
        self.reserve().await?.send(data.to_vec()).await
    }

    /// Gives the next record an LSN after `lsn`; never moves the counter
    /// back. Recovery sends the log's highest LSN before the first append.
    pub async fn set_lsn_start(&self, lsn: u64) -> Result<(), WalError> {
        match &self.inner {
            #[cfg(test)]
            WalMode::Local(sender) => {
                let (responder, response) = oneshot::channel();
                sender
                    .send(CommitRequest::Control(Control::SetLsnStart { lsn, responder }))
                    .await
                    .map_err(|_| broken_pipe_error())?;
                response.await.map_err(|_| broken_pipe_error())
            }
            WalMode::Remote { handle, engine } => handle.set_lsn_start(*engine, lsn).await.map_err(wal_remote_err),
        }
    }

    /// The LSN of the last record durable in the log, after every append
    /// queued before this call.
    pub async fn head_lsn(&self) -> Result<u64, WalError> {
        match &self.inner {
            #[cfg(test)]
            WalMode::Local(sender) => {
                let (responder, response) = oneshot::channel();
                sender
                    .send(CommitRequest::Control(Control::HeadLsn { responder }))
                    .await
                    .map_err(|_| broken_pipe_error())?;
                response.await.map_err(|_| broken_pipe_error())
            }
            WalMode::Remote { handle, engine } => handle.wal_head_lsn(*engine).await.map_err(wal_remote_err),
        }
    }

    /// Where the log ends, after every append queued before this call.
    pub async fn mark(&self) -> Result<WalMark, WalError> {
        match &self.inner {
            #[cfg(test)]
            WalMode::Local(_) => Err(no_checkpoint_error()),
            WalMode::Remote { handle, engine } => handle.wal_mark(*engine).await.map_err(wal_remote_err),
        }
    }

    /// Drops the records before `mark` from the log; the records after it
    /// stay, and so do the LSNs.
    pub async fn cut_before(&self, mark: &WalMark) -> Result<(), WalError> {
        match &self.inner {
            #[cfg(test)]
            WalMode::Local(_) => Err(no_checkpoint_error()),
            WalMode::Remote { handle, engine } => handle.wal_cut_before(*engine, *mark).await.map_err(wal_remote_err),
        }
    }

    /// Truncates the WAL file back to its header, effectively clearing it.
    /// The LSNs go on where they were.
    ///
    /// This is typically done after the MemTable has been successfully
    /// recovered from the WAL at startup.
    pub async fn truncate(&self) -> Result<(), WalError> {
        match &self.inner {
            #[cfg(test)]
            WalMode::Local(sender) => {
                let (tx, rx) = oneshot::channel();
                sender
                    .send(CommitRequest::Control(Control::Truncate { responder: tx }))
                    .await
                    .map_err(|_| broken_pipe_error())?;
                rx.await.map_err(|_| broken_pipe_error())?
            }
            WalMode::Remote { handle, engine } => handle.wal_truncate(*engine).await.map_err(wal_remote_err),
        }
    }
}

/// Maps a storage-thread `anyhow` error back into the WAL's error type.
fn wal_remote_err(e: anyhow::Error) -> WalError {
    WalError::Io(std::io::Error::other(e.to_string()))
}

#[cfg(test)]
fn no_checkpoint_error() -> WalError {
    WalError::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "the local WAL committer takes no checkpoint",
    ))
}

#[cfg(test)]
fn broken_pipe_error() -> WalError {
    WalError::Io(std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "WAL committer task has stopped",
    ))
}

/// Offset and LSN of an appended record.
#[cfg(test)]
type AppendResponder = oneshot::Sender<Result<(u64, u64), WalError>>;

#[cfg(test)]
struct LocalWal {
    file: File,
    path: PathBuf,
    /// Where a failed cut records `offset` for the next open.
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
    faults: Faults,
}

#[cfg(test)]
impl LocalWal {
    async fn open(path: &Path) -> Result<Self, WalError> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        apply_unsafe_end_marker(path, &file).map_err(|e| std::io::Error::other(format!("{e:#}")))?;
        let awaits_truncate = !ensure_header(&file)?;

        let mut file = File::from_std(file);
        let offset = file.metadata().await?.len();
        file.seek(SeekFrom::Start(offset)).await?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
            marker: unsafe_end_marker(path),
            offset,
            lsn: 0,
            awaits_truncate,
            unsafe_end: false,
            faults: Faults::default(),
        })
    }

    /// A failed write or sync cuts the file back to the cursor, which stays
    /// where it was.
    async fn write_at_cursor(&mut self, data: &[u8]) -> std::io::Result<()> {
        if self.awaits_truncate {
            return Err(appends_refused());
        }
        if self.unsafe_end {
            if let Err(cut) = self.cut_to_cursor().await {
                self.log_failed_cut(&cut);
                return Err(cut);
            }
        }
        let result = async {
            self.file.seek(std::io::SeekFrom::Start(self.offset)).await?;
            self.file.write_all(data).await?;
            self.file.flush().await?;
            if std::mem::take(&mut self.faults.sync) {
                return Err(std::io::Error::other("injected fsync failure"));
            }
            self.file.sync_all().await
        }
        .await;
        if result.is_err() {
            if let Err(cut) = self.cut_to_cursor().await {
                self.log_failed_cut(&cut);
            }
        }
        result
    }

    /// The file's end stays unsafe until the cut and the marker removal both succeed.
    async fn cut_to_cursor(&mut self) -> std::io::Result<()> {
        self.unsafe_end = true;
        if let Err(e) = self.cut_file().await {
            mark_unsafe_end(&self.marker, self.offset);
            return Err(e);
        }
        self.unmark()?;
        self.unsafe_end = false;
        Ok(())
    }

    async fn cut_file(&mut self) -> std::io::Result<()> {
        if std::mem::take(&mut self.faults.cut) {
            return Err(std::io::Error::other("injected cut failure"));
        }
        self.file.set_len(self.offset).await?;
        self.file.sync_all().await
    }

    fn unmark(&mut self) -> std::io::Result<()> {
        if std::mem::take(&mut self.faults.unmark) {
            return Err(std::io::Error::other("injected marker removal failure"));
        }
        let _probe = self.faults.probe_unmark_syncs();
        unmark_unsafe_end(&self.marker)
    }

    /// Every failed cut, marker removal included, is logged: the file's end
    /// stays unsafe until one succeeds.
    fn log_failed_cut(&self, error: &std::io::Error) {
        tracing::error!(
            "Securing the end of the write-ahead log at {} bytes failed: {error}; \
             the next append retries before it writes.",
            self.offset
        );
    }
}

/// Background task: drains the commit queue and batches writes into a single fsync per group.
#[cfg(test)]
async fn run_committer(mut wal: LocalWal, mut rx: mpsc::Receiver<CommitRequest>) {
    loop {
        // Block until at least one request arrives.
        let first = match rx.recv().await {
            Some(r) => r,
            None => return, // All senders dropped — shut down.
        };

        match first {
            CommitRequest::Control(control) => run_control(&mut wal, control).await,
            CommitRequest::Append { data, responder } => {
                commit_append_group(&mut wal, &mut rx, data, responder).await;
            }
        }
    }
}

#[cfg(test)]
async fn run_control(wal: &mut LocalWal, control: Control) {
    match control {
        Control::Truncate { responder } => {
            let _ = responder.send(do_truncate(wal).await);
        }
        Control::SetLsnStart { lsn, responder } => {
            wal.lsn = wal.lsn.max(lsn);
            let _ = responder.send(());
        }
        Control::HeadLsn { responder } => {
            let _ = responder.send(wal.lsn);
        }
    }
}

#[cfg(test)]
async fn commit_append_group(
    wal: &mut LocalWal,
    rx: &mut mpsc::Receiver<CommitRequest>,
    data: Vec<u8>,
    responder: AppendResponder,
) {
    // Collect this append plus all currently pending appends.
    let mut group: Vec<(Vec<u8>, AppendResponder)> = vec![(data, responder)];
    let mut pending_control: Option<Control> = None;

    loop {
        match rx.try_recv() {
            Ok(CommitRequest::Append { data, responder }) => {
                group.push((data, responder));
            }
            Ok(CommitRequest::Control(control)) => {
                // Stop collecting — commit the current group first, then run it.
                pending_control = Some(control);
                break;
            }
            Err(_) => break,
        }
    }

    // Frame each record with its LSN, in queue order, into the single
    // combined write buffer; note each one's offset and LSN.
    let mut combined = Vec::new();
    let mut items = Vec::with_capacity(group.len());
    for (data, _) in &group {
        let lsn = wal.lsn + items.len() as u64 + 1;
        items.push((wal.offset + combined.len() as u64, lsn));
        combined.extend_from_slice(&lsn.to_be_bytes());
        combined.extend_from_slice(data);
    }

    // One write + one fsync for the entire group.
    match wal.write_at_cursor(&combined).await {
        Ok(()) => {
            wal.offset += combined.len() as u64;
            wal.lsn += items.len() as u64;
            for ((_, responder), item) in group.into_iter().zip(items) {
                let _ = responder.send(Ok(item));
            }
        }
        Err(e) => {
            let kind = e.kind();
            let msg = e.to_string();
            for (_, responder) in group {
                let _ = responder.send(Err(WalError::Io(std::io::Error::new(
                    kind,
                    msg.clone(),
                ))));
            }
        }
    }

    if let Some(control) = pending_control {
        run_control(wal, control).await;
    }
}

/// Cuts the log back to its header, or replaces a log of the earlier format
/// with the header alone.
#[cfg(test)]
async fn do_truncate(wal: &mut LocalWal) -> Result<(), WalError> {
    if wal.awaits_truncate {
        wal.file.set_len(0).await?;
        wal.file.seek(SeekFrom::Start(0)).await?;
        wal.file.write_all(&WAL_MAGIC).await?;
        wal.file.flush().await?;
        wal.awaits_truncate = false;
    } else {
        wal.file.set_len(WAL_HEADER_LEN).await?;
    }
    wal.offset = WAL_HEADER_LEN;
    wal.file.sync_all().await?;
    if let Err(e) = wal.unmark() {
        wal.unsafe_end = true;
        wal.log_failed_cut(&e);
        return Err(e.into());
    }
    wal.unsafe_end = false;
    crate::storage::test_trace::record(&wal.path, "truncate");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engines::lsm::hlc::HybridLogicalClock;
    use std::sync::Arc;
    use tempfile::TempDir;

    /// The bytes of a log holding `records`, each framed with its LSN.
    fn log_of(records: &[(u64, &[u8])]) -> Vec<u8> {
        let mut log = WAL_MAGIC.to_vec();
        for (lsn, payload) in records {
            log.extend_from_slice(&lsn.to_be_bytes());
            log.extend_from_slice(payload);
        }
        log
    }

    // N concurrent appends batch into disjoint, monotone offsets and one
    // contiguous file — the local committer's group-commit path. The LSNs
    // follow the offsets.
    #[test]
    fn test_parallel_appends_disjoint_monotone_offsets() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let wal = Arc::new(WriteAheadLog::new(dir.path().join("wal")).await.unwrap());

            let mut tasks = Vec::new();
            for _ in 0..100u32 {
                let w = Arc::clone(&wal);
                tasks.push(compio::runtime::spawn(async move { w.append(&[b'x'; 10]).await.unwrap() }));
            }
            let mut appended = Vec::new();
            for t in tasks {
                appended.push(t.await.unwrap());
            }
            appended.sort_unstable();

            assert_eq!(appended.len(), 100);
            for (i, (offset, lsn)) in appended.iter().enumerate() {
                assert_eq!(*offset, 8 + (i as u64) * 18);
                assert_eq!(*lsn, i as u64 + 1);
            }
            drop(wal);
            assert_eq!(std::fs::read(dir.path().join("wal")).unwrap().len(), 8 + 1800);
        })
    }

    // append → truncate → append: the truncate resets the write cursor to
    // the end of the header; the LSNs go on.
    #[test]
    fn test_append_truncate_append_resets_offset() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let wal = WriteAheadLog::new(dir.path().join("wal")).await.unwrap();

            assert_eq!(wal.append(b"abcde").await.unwrap(), (8, 1));
            assert_eq!(wal.append(b"fgh").await.unwrap(), (21, 2));
            wal.truncate().await.unwrap();
            assert_eq!(wal.append(b"XY").await.unwrap(), (8, 3));

            drop(wal);
            assert_eq!(std::fs::read(dir.path().join("wal")).unwrap(), log_of(&[(3, b"XY".as_slice())]));
        })
    }

    // A Truncate arriving mid-group must land in `pending_control` (the
    // drain loop in commit_append_group), not the top-level Control arm in
    // run_committer — sequential .await calls can never reach that branch.
    //
    // Forced deterministically via tokio::join! (not tokio::spawn): join!
    // polls its arguments left-to-right to each one's first suspend point,
    // every round. On this single-threaded runtime the committer task can't
    // run at all until this task yields, which only happens after BOTH sends
    // already sit in the mpsc queue (Append, then Truncate — in that order).
    // So the committer's first recv() is guaranteed to pop the Append, and
    // commit_append_group's try_recv() drain is guaranteed to then find the
    // Truncate. No sleeps, no thread races, no flake.
    //
    // The returned offset (21, not 8) is the actual proof: it's only possible
    // if the group committed at the pre-truncate offset before truncation
    // reset it, i.e. exactly the "commit group, then truncate" contract.
    #[test]
    fn test_truncate_during_append_group_uses_pending_control() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let wal = WriteAheadLog::new(dir.path().join("wal")).await.unwrap();

            // A record behind the header so the assertion below can distinguish
            // "group committed, then truncated" from "truncated, then committed".
            assert_eq!(wal.append(b"AAAAA").await.unwrap(), (8, 1));

            let (append_result, truncate_result) =
                tokio::join!(wal.append(b"BBB"), wal.truncate());

            assert_eq!(append_result.unwrap(), (21, 2));
            truncate_result.unwrap();
            assert_eq!(std::fs::read(dir.path().join("wal")).unwrap(), WAL_MAGIC);

            // Offset and file state stay consistent after the mid-group truncate.
            assert_eq!(wal.append(b"XY").await.unwrap(), (8, 3));
            drop(wal);
            assert_eq!(std::fs::read(dir.path().join("wal")).unwrap(), log_of(&[(3, b"XY".as_slice())]));
        })
    }

    /// Commits `records` as one group on the local committer, the way
    /// `run_committer` does; returns each append's offset and LSN in order.
    async fn commit_group(wal: &mut LocalWal, records: Vec<Vec<u8>>) -> Vec<Result<(u64, u64), WalError>> {
        let (tx, mut rx) = mpsc::channel(records.len());
        let mut receivers = Vec::new();
        for data in records {
            let (responder, receiver) = oneshot::channel();
            assert!(tx.try_send(CommitRequest::Append { data, responder }).is_ok());
            receivers.push(receiver);
        }
        let Some(CommitRequest::Append { data, responder }) = rx.recv().await else {
            panic!("expected an append");
        };
        commit_append_group(wal, &mut rx, data, responder).await;
        let mut results = Vec::new();
        for receiver in receivers {
            results.push(receiver.await.unwrap());
        }
        results
    }

    fn delete_record(key: &[u8]) -> Vec<u8> {
        raw_delete_record(key.len() as u32, key)
    }

    /// The offset of the first append's record in `results`.
    fn offset(results: &[Result<(u64, u64), WalError>]) -> u64 {
        results[0].as_ref().unwrap().0
    }

    async fn recovered_keys(path: &Path) -> Vec<String> {
        recover(path)
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

    // A failed group cuts the file back to the cursor, keeps the cursor and
    // fails every append of the group; its LSNs go to the next group.
    #[test]
    fn test_failed_group_cuts_the_file_back_to_the_cursor() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("wal");
            let mut wal = LocalWal::open(&path).await.unwrap();
            assert_eq!(commit_group(&mut wal, vec![b"kept".to_vec()]).await[0].as_ref().unwrap(), &(8, 1));

            wal.faults.sync = true;
            let results = commit_group(&mut wal, vec![b"lost-one".to_vec(), b"lost-two".to_vec()]).await;
            assert!(results.iter().all(Result::is_err));
            assert_eq!(wal.offset, 20);
            assert_eq!(std::fs::metadata(&path).unwrap().len(), 20);

            assert_eq!(commit_group(&mut wal, vec![b"next".to_vec()]).await[0].as_ref().unwrap(), &(20, 2));
        })
    }

    // A failed group leaves nothing behind the log's end: after a long group
    // whose fsync fails and a shorter one that succeeds, recovery reads the
    // shorter one alone.
    #[test]
    fn test_failed_group_leaves_no_tail_behind_a_shorter_one() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("wal");
            let mut wal = LocalWal::open(&path).await.unwrap();

            wal.faults.sync = true;
            let long = vec![delete_record(b"lost-with-a-long-key"), delete_record(b"lost-as-well")];
            assert!(commit_group(&mut wal, long).await.iter().all(Result::is_err));

            let kept = commit_group(&mut wal, vec![delete_record(b"kept")]).await;
            assert_eq!(kept[0].as_ref().unwrap(), &(8, 1));
            assert_eq!(recovered_keys(&path).await, ["kept"]);
        })
    }

    // A cut that fails leaves the file's end unsafe: the next group cuts
    // first, fails while it cannot, and writes at the cursor once it can.
    #[test]
    fn test_group_after_a_failed_cut_cuts_first() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("wal");
            let len = || std::fs::metadata(&path).unwrap().len();
            let (mut wal, start) = wal_after_a_failed_cut(&path).await;
            let tail = len();

            wal.faults.cut = true;
            assert!(commit_group(&mut wal, vec![delete_record(b"refused")]).await[0].is_err());
            assert_eq!(len(), tail);

            let kept = commit_group(&mut wal, vec![delete_record(b"kept-two")]).await;
            assert_eq!(offset(&kept), start);
            assert_eq!(recovered_keys(&path).await, ["kept-one", "kept-two"]);
        })
    }

    /// The local committer at `path` after a group whose cut failed: the log
    /// holds `kept-one`, which ends at the returned cursor, and a tail past it.
    async fn wal_after_a_failed_cut(path: &Path) -> (LocalWal, u64) {
        let mut wal = LocalWal::open(path).await.unwrap();
        assert!(commit_group(&mut wal, vec![delete_record(b"kept-one")]).await[0].is_ok());
        let start = wal.offset;

        wal.faults = Faults { sync: true, cut: true, ..Faults::default() };
        assert!(commit_group(&mut wal, vec![delete_record(b"lost-with-a-long-key")]).await[0].is_err());
        assert!(std::fs::metadata(path).unwrap().len() > start);
        (wal, start)
    }

    // A failed cut leaves the cursor in a marker beside the log; the next
    // open cuts the log back to it before recovery reads the log.
    #[test]
    fn test_open_cuts_the_log_back_to_the_cursor_a_failed_cut_left() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("wal");
            let marker = dir.path().join("wal.unsafe-end");
            let (wal, start) = wal_after_a_failed_cut(&path).await;
            assert_eq!(std::fs::read(&marker).unwrap(), start.to_be_bytes());
            drop(wal);

            let mut wal = LocalWal::open(&path).await.unwrap();
            assert_eq!(std::fs::metadata(&path).unwrap().len(), start);
            assert_eq!(wal.offset, start);
            assert!(!marker.exists());
            assert_eq!(recovered_keys(&path).await, ["kept-one"]);
            let kept = commit_group(&mut wal, vec![delete_record(b"kept-two")]).await;
            assert_eq!(offset(&kept), start);
        })
    }

    // A cut that fails again leaves the marker as it is: its cursor does not
    // change while the file's end is unsafe.
    #[test]
    fn test_a_repeated_failed_cut_keeps_the_marker() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("wal");
            let marker = dir.path().join("wal.unsafe-end");
            let (mut wal, _) = wal_after_a_failed_cut(&path).await;
            std::fs::write(&marker, 5u64.to_be_bytes()).unwrap();

            wal.faults.cut = true;
            assert!(commit_group(&mut wal, vec![delete_record(b"refused")]).await[0].is_err());
            assert_eq!(std::fs::read(&marker).unwrap(), 5u64.to_be_bytes());
        })
    }

    // The cut that succeeds after a failed one removes the marker.
    #[test]
    fn test_a_successful_cut_removes_the_marker() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("wal");
            let marker = dir.path().join("wal.unsafe-end");
            let (mut wal, start) = wal_after_a_failed_cut(&path).await;
            assert!(marker.exists());

            let kept = commit_group(&mut wal, vec![delete_record(b"kept-two")]).await;
            assert_eq!(offset(&kept), start);
            assert!(!marker.exists());
        })
    }

    // A truncate after a failed cut empties the log, removes the marker and
    // leaves the log's end safe.
    #[test]
    fn test_truncate_removes_the_marker() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("wal");
            let marker = dir.path().join("wal.unsafe-end");
            let (mut wal, _) = wal_after_a_failed_cut(&path).await;
            assert!(marker.exists());

            do_truncate(&mut wal).await.unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), WAL_MAGIC);
            assert!(!marker.exists());
            assert!(!wal.unsafe_end);
        })
    }

    // A marker that cannot be removed fails the cut: no group is confirmed
    // while the marker exists, so its cursor never cuts a confirmed group.
    #[test]
    fn test_a_failed_marker_removal_fails_the_cut() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("wal");
            let marker = dir.path().join("wal.unsafe-end");
            let (mut wal, start) = wal_after_a_failed_cut(&path).await;

            wal.faults.unmark = true;
            assert!(commit_group(&mut wal, vec![delete_record(b"refused")]).await[0].is_err());
            assert_eq!(std::fs::metadata(&path).unwrap().len(), start);
            assert!(marker.exists());

            let kept = commit_group(&mut wal, vec![delete_record(b"kept-two")]).await;
            assert_eq!(offset(&kept), start);
            assert!(!marker.exists());
        })
    }

    // A truncate whose marker cannot be removed fails and leaves the log's
    // end unsafe; the next group removes the marker before it writes.
    #[test]
    fn test_a_failed_marker_removal_fails_the_truncate() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("wal");
            let marker = dir.path().join("wal.unsafe-end");
            let (mut wal, _) = wal_after_a_failed_cut(&path).await;

            wal.faults.unmark = true;
            assert!(do_truncate(&mut wal).await.is_err());
            assert!(wal.unsafe_end);
            assert!(marker.exists());

            let kept = commit_group(&mut wal, vec![delete_record(b"kept-two")]).await;
            assert_eq!(offset(&kept), WAL_HEADER_LEN);
            assert!(!marker.exists());
        })
    }

    // A removal whose directory sync fails fails the cut; the retry finds the
    // marker gone and still syncs the directory before it confirms a group.
    #[test]
    fn test_a_failed_directory_sync_after_the_marker_removal_fails_the_cut() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("wal");
            let marker = dir.path().join("wal.unsafe-end");
            let (mut wal, start) = wal_after_a_failed_cut(&path).await;
            assert!(marker.exists());

            wal.faults.unmark_sync = true;
            assert!(commit_group(&mut wal, vec![delete_record(b"refused")]).await[0].is_err());
            assert!(!marker.exists());
            assert!(wal.unsafe_end);

            let syncs = wal.faults.unmark_syncs.len();
            let record = delete_record(b"kept-two");
            let end = start + 8 + record.len() as u64;
            let kept = commit_group(&mut wal, vec![record]).await;
            assert_eq!(offset(&kept), start);
            assert_eq!(wal.faults.unmark_syncs.len(), syncs + 1);
            assert!(!wal.unsafe_end);
            assert_eq!(std::fs::metadata(&path).unwrap().len(), end);
        })
    }

    // Builds a raw DELETE record: [type=2][ts:u64][key_len:u32][key]. Used
    // directly (bypassing WriteAheadLog::append) to hand `recover()` a
    // length-prefixed field with a chosen, possibly corrupt, length.
    fn raw_delete_record(key_len_field: u32, key: &[u8]) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.push(2u8);
        raw.extend_from_slice(&1u64.to_be_bytes());
        raw.extend_from_slice(&key_len_field.to_be_bytes());
        raw.extend_from_slice(key);
        raw
    }

    // A length field beyond WAL_MAX_FIELD_LEN must fail recovery immediately
    // -- not attempt an allocation up to 4 GiB. No key bytes follow; the cap
    // check must reject this before read_exact ever runs.
    #[test]
    fn test_recover_rejects_wal_field_length_exceeding_cap() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("wal");
            std::fs::write(&path, raw_delete_record((WAL_MAX_FIELD_LEN + 1) as u32, &[])).unwrap();

            let err = recover(&path).await.unwrap_err();
            assert!(
                err.to_string().contains("exceeds maximum"),
                "expected a field-too-long error, got: {err}"
            );
        })
    }

    // A field of exactly WAL_MAX_FIELD_LEN must still parse -- the cap
    // rejects lengths *above* it, never at it.
    #[test]
    fn test_recover_accepts_wal_field_length_exactly_at_cap() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("wal");
            let key = vec![b'k'; WAL_MAX_FIELD_LEN];
            std::fs::write(&path, raw_delete_record(WAL_MAX_FIELD_LEN as u32, &key)).unwrap();

            let entries = recover(&path).await.unwrap().entries;
            assert_eq!(entries.len(), 1);
            match &entries[0].1 {
                WalEntry::Delete { key: k, .. } => assert_eq!(k.len(), WAL_MAX_FIELD_LEN),
                other => panic!("expected WalEntry::Delete, got {other:?}"),
            }
        })
    }

    /// A log of the earlier format as its writer left it: a SET, a SET with
    /// an expiry, a DELETE, a SET_NULL and a BATCH of a SET and a DELETE.
    const V1_LOG: &[u8] = include_bytes!("../../tests/fixtures/wal/v1.wal");
    /// Where each record of [`V1_LOG`] starts, then its end.
    const V1_RECORD_BOUNDS: [usize; 6] = [0, 33, 65, 83, 101, 148];

    /// The entries of [`V1_LOG`], each with the number of its record as LSN.
    fn v1_log_entries() -> Vec<(u64, WalEntry)> {
        let set = |timestamp, key: &str, value: &str, expire_at| WalEntry::Set {
            timestamp,
            key: key.into(),
            value: value.into(),
            expire_at,
        };
        vec![
            (1, set(0x01a1_5efe_7360_0000, "alpha", "one", 0)),
            (2, set(0x01a1_5efe_7363_0000, "beta", "two", 0x1_26d0_f299)),
            (3, WalEntry::Delete { timestamp: 0x01a1_5efe_7365_0000, key: b"alpha".to_vec(), in_batch: false }),
            (4, WalEntry::SetNull { timestamp: 0x01a1_5efe_7367_0000, key: b"gamma".to_vec() }),
            (5, set(0x01a1_5efe_7369_0000, "clé", "🦀", 0)),
            (5, WalEntry::Delete { timestamp: 0x01a1_5efe_7369_0000, key: b"beta".to_vec(), in_batch: true }),
        ]
    }

    fn write_log(dir: &TempDir, bytes: &[u8]) -> PathBuf {
        let path = dir.path().join("wal");
        std::fs::write(&path, bytes).unwrap();
        path
    }

    // A log of the earlier format reads back unchanged, its records numbered
    // 1 to n.
    #[test]
    fn test_recover_reads_a_log_of_the_earlier_format_with_lsns_one_to_n() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let recovered = recover(write_log(&dir, V1_LOG)).await.unwrap();
            assert_eq!(recovered.entries, v1_log_entries());
            assert_eq!(recovered.max_lsn, 5);
        })
    }

    // The same records appended to a log of this version read back with the
    // LSNs the appends returned; a batch record holds one LSN.
    #[test]
    fn test_recover_reads_lsn_framed_records_back() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("wal");
            let wal = WriteAheadLog::new(&path).await.unwrap();
            for (i, bounds) in V1_RECORD_BOUNDS.windows(2).enumerate() {
                let (_, lsn) = wal.append(&V1_LOG[bounds[0]..bounds[1]]).await.unwrap();
                assert_eq!(lsn, i as u64 + 1);
            }
            drop(wal);

            assert!(std::fs::read(&path).unwrap().starts_with(&WAL_MAGIC));
            let recovered = recover(&path).await.unwrap();
            assert_eq!(recovered.entries, v1_log_entries());
            assert_eq!(recovered.max_lsn, 5);
        })
    }

    // A log whose first byte is a record type, 1 to 4, has the earlier format.
    #[test]
    fn test_recover_reads_a_log_starting_with_a_record_type_as_the_earlier_format() {
        crate::core::engine_runtime::block_on(async {
            let mut types = Vec::new();
            for (i, bounds) in V1_RECORD_BOUNDS.windows(2).enumerate() {
                let dir = TempDir::new().unwrap();
                let record = &V1_LOG[bounds[0]..bounds[1]];
                types.push(record[0]);

                let recovered = recover(write_log(&dir, record)).await.unwrap();
                let expected: Vec<_> =
                    v1_log_entries().into_iter().filter(|(lsn, _)| *lsn == i as u64 + 1).map(|(_, e)| (1, e)).collect();
                assert_eq!(recovered.entries, expected);
                assert_eq!(recovered.max_lsn, 1);
            }
            types.sort_unstable();
            types.dedup();
            assert_eq!(types, [1, 2, 3, 4]);
        })
    }

    // A missing log, an empty one and one with the header alone hold no entries.
    #[test]
    fn test_recover_reads_no_entries_from_an_empty_log() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let missing = recover(dir.path().join("missing")).await.unwrap();
            assert!(missing.entries.is_empty());
            assert_eq!(missing.max_lsn, 0);
            for log in [&[][..], &WAL_MAGIC[..]] {
                let recovered = recover(write_log(&dir, log)).await.unwrap();
                assert!(recovered.entries.is_empty());
                assert_eq!(recovered.max_lsn, 0);
            }
        })
    }

    // A record cut short at the end of the log fails recovery in either
    // format, and so does an LSN frame cut short or without its record.
    #[test]
    fn test_recover_fails_on_a_torn_record() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let framed = log_of(&[(1, &V1_LOG[..33])]);
            let frame_alone = log_of(&[(1, b"".as_slice())]);
            let torn: [&[u8]; 4] = [
                &V1_LOG[..V1_LOG.len() - 1],
                &framed[..framed.len() - 1],
                &frame_alone,
                &frame_alone[..12],
            ];
            for log in torn {
                let err = recover(write_log(&dir, log)).await.unwrap_err();
                assert!(
                    matches!(&err, WalError::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof),
                    "expected a torn record, got: {err}"
                );
            }
        })
    }

    // The local committer takes no checkpoint: a mark and a cut both fail
    // and leave the log as it is.
    #[test]
    fn test_the_local_committer_takes_no_mark_and_no_cut() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("wal");
            let wal = WriteAheadLog::new(&path).await.unwrap();
            wal.append(b"kept").await.unwrap();
            assert!(wal.mark().await.is_err());
            let mark = WalMark { generation: 0, offset: WAL_HEADER_LEN, lsn: 0 };
            assert!(wal.cut_before(&mark).await.is_err());
            assert_eq!(std::fs::read(&path).unwrap(), log_of(&[(1, b"kept")]));
        })
    }

    /// A SET record of `key` and `value` without expiry.
    fn set_record(key: &[u8], value: &[u8]) -> Vec<u8> {
        let mut record = vec![1u8];
        record.extend_from_slice(&7u64.to_be_bytes());
        record.extend_from_slice(&(key.len() as u32).to_be_bytes());
        record.extend_from_slice(key);
        record.extend_from_slice(&(value.len() as u32).to_be_bytes());
        record.extend_from_slice(value);
        record.extend_from_slice(&0u64.to_be_bytes());
        record
    }

    // A record that crosses the edge of the read buffer and a value longer
    // than the buffer read back unchanged.
    #[test]
    fn test_recover_reads_records_across_and_beyond_the_read_buffer() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            // Header, LSN frame and the SET fields around the value take 42 bytes.
            let filler = vec![b'f'; RECOVERY_READ_BUFFER - 42 - 5];
            let large: Vec<u8> = (0..2 * RECOVERY_READ_BUFFER + 3).map(|i| i as u8).collect();
            let records = [set_record(b"a", &filler), set_record(b"across", "clé".as_bytes()), set_record(b"b", &large)];
            let log = log_of(&[(1, &records[0]), (2, &records[1]), (3, &records[2])]);
            assert!(log.len() > 2 * RECOVERY_READ_BUFFER);

            let recovered = recover(write_log(&dir, &log)).await.unwrap();
            let set = |key: &[u8], value: &[u8]| WalEntry::Set { timestamp: 7, key: key.to_vec(), value: value.to_vec(), expire_at: 0 };
            assert_eq!(
                recovered.entries,
                [(1, set(b"a", &filler)), (2, set(b"across", "clé".as_bytes())), (3, set(b"b", &large))]
            );
            assert_eq!(recovered.max_lsn, 3);
        })
    }

    // After `set_lsn_start(k)` the next record carries k + 1.
    #[test]
    fn test_set_lsn_start_numbers_the_next_record_after_it() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("wal");
            let wal = WriteAheadLog::new(&path).await.unwrap();
            wal.set_lsn_start(41).await.unwrap();
            assert_eq!(wal.append(&delete_record(b"first")).await.unwrap(), (8, 42));
            assert_eq!(wal.append(&delete_record(b"second")).await.unwrap().1, 43);
            drop(wal);

            let recovered = recover(&path).await.unwrap();
            assert_eq!(recovered.entries.iter().map(|(lsn, _)| *lsn).collect::<Vec<_>>(), [42, 43]);
            assert_eq!(recovered.max_lsn, 43);
        })
    }

    // `set_lsn_start` never moves the counter back: a log cut back to its
    // header recovers no LSN, and 0 sent after the cut changes nothing.
    #[test]
    fn test_set_lsn_start_never_moves_the_counter_back() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let wal = WriteAheadLog::new(dir.path().join("wal")).await.unwrap();
            for key in [b"a", b"b", b"c"] {
                wal.append(&delete_record(key)).await.unwrap();
            }
            wal.truncate().await.unwrap();

            wal.set_lsn_start(0).await.unwrap();
            assert_eq!(wal.append(&delete_record(b"d")).await.unwrap(), (8, 4));
        })
    }

    /// A DELETE record of `key` dated `timestamp`.
    fn delete_record_at(timestamp: u64, key: &[u8]) -> Vec<u8> {
        let mut record = raw_delete_record(key.len() as u32, key);
        record[1..9].copy_from_slice(&timestamp.to_be_bytes());
        record
    }

    /// One writer's sequence on `wal`: reserve, stamp, send. Returns the
    /// stamp and the LSN.
    async fn reserve_stamp_send(wal: &WriteAheadLog, clock: &HybridLogicalClock, key: &[u8]) -> (u64, u64) {
        let permit = wal.reserve().await.unwrap();
        let stamp = clock.try_now().unwrap().as_u64();
        let (_, lsn) = permit.send(delete_record_at(stamp, key)).await.unwrap();
        (stamp, lsn)
    }

    // A writer that waits for a slot in a full queue draws its stamp after
    // the writer ahead of it has sent: the queue numbers the records in
    // stamp order.
    #[test]
    fn test_a_writer_waiting_for_the_queue_stamps_after_the_one_ahead() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let wal = WriteAheadLog::with_capacity(dir.path().join("wal"), 1).await.unwrap();
            let clock = HybridLogicalClock::new();

            let a = wal.reserve().await.unwrap();
            let mut b = std::pin::pin!(wal.reserve());
            assert!(futures::poll!(b.as_mut()).is_pending(), "the one slot is A's");

            let stamp_a = clock.try_now().unwrap().as_u64();
            let (_, lsn_a) = a.send(delete_record_at(stamp_a, b"a")).await.unwrap();
            let b = b.await.unwrap();
            let stamp_b = clock.try_now().unwrap().as_u64();
            let (_, lsn_b) = b.send(delete_record_at(stamp_b, b"b")).await.unwrap();

            assert_eq!((lsn_a, lsn_b), (1, 2));
            assert!(stamp_b > stamp_a);
        })
    }

    // Three writers reserve in a seeded random order on a queue of one slot;
    // in the log, the LSN order is the stamp order.
    #[test]
    fn test_lsn_order_is_stamp_order_for_any_reservation_order() {
        use rand::{rngs::StdRng, seq::SliceRandom, Rng, SeedableRng};
        crate::core::engine_runtime::block_on(async {
            let mut rng = StdRng::seed_from_u64(0x5eed);
            for round in 0..20 {
                let dir = TempDir::new().unwrap();
                let path = dir.path().join("wal");
                let wal = Arc::new(WriteAheadLog::with_capacity(&path, 1).await.unwrap());
                let clock = Arc::new(HybridLogicalClock::new());
                let mut order = *b"abc";
                order.shuffle(&mut rng);

                let writers: Vec<_> = order
                    .into_iter()
                    .map(|key| {
                        let yields = rng.gen_range(0..3);
                        let (wal, clock) = (Arc::clone(&wal), Arc::clone(&clock));
                        compio::runtime::spawn(async move {
                            for _ in 0..yields {
                                tokio::task::yield_now().await;
                            }
                            reserve_stamp_send(&wal, &clock, &[key]).await
                        })
                    })
                    .collect();
                let mut sent = Vec::new();
                for writer in writers {
                    sent.push(writer.await.unwrap());
                }
                drop(wal);

                let logged: Vec<(u64, u64)> = recover(&path)
                    .await
                    .unwrap()
                    .entries
                    .into_iter()
                    .map(|(lsn, entry)| match entry {
                        WalEntry::Delete { timestamp, .. } => (timestamp, lsn),
                        other => panic!("expected a DELETE record, got {other:?}"),
                    })
                    .collect();
                sent.sort_unstable_by_key(|&(_, lsn)| lsn);
                assert_eq!(logged, sent, "round {round}");
                assert_eq!(logged.iter().map(|&(_, lsn)| lsn).collect::<Vec<_>>(), [1, 2, 3], "round {round}");
                assert!(logged.windows(2).all(|pair| pair[0].0 < pair[1].0), "round {round}: {logged:?}");
            }
        })
    }
}
