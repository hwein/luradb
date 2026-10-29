#[cfg(test)]
use crate::core::storage_thread::{
    apply_unsafe_end_marker, ensure_header, mark_unsafe_end, unmark_unsafe_end, unsafe_end_marker, Faults,
};
use crate::core::storage_thread::{StorageHandle, WalMark, WalPermit, WalSegments, WalTarget};
use std::collections::VecDeque;
use std::ffi::OsStr;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, BufReader};
#[cfg(test)]
use tokio::io::AsyncWriteExt;
#[cfg(test)]
use tokio::sync::{mpsc, oneshot};

/// The first bytes of every log this version writes, followed by the LSN of
/// the last record before the log's first one (`u64`, big-endian): the LSNs
/// go on across restarts. Earlier versions read such a log as one of the
/// first format and refuse it.
pub const WAL_MAGIC: [u8; 8] = *b"LURAWAL\x03";
pub const WAL_HEADER_LEN: u64 = WAL_MAGIC.len() as u64 + 8;
/// The header of the previous format: the magic alone, LSNs from 1 after
/// each clean stop. A log with neither header has the first format, whose
/// first byte is a record type from 1 to 4.
const PREVIOUS_WAL_MAGIC: [u8; 8] = *b"LURAWAL\x02";

/// The header of a log whose first record follows `start_lsn`.
pub fn wal_header(start_lsn: u64) -> [u8; WAL_HEADER_LEN as usize] {
    let mut header = [0; WAL_HEADER_LEN as usize];
    header[..WAL_MAGIC.len()].copy_from_slice(&WAL_MAGIC);
    header[WAL_MAGIC.len()..].copy_from_slice(&start_lsn.to_be_bytes());
    header
}

/// Where the single-file log of an earlier version waits for recovery once
/// its segment directory has taken its place: `<path>.migrating`.
pub const MIGRATING_SUFFIX: &str = ".migrating";

/// Segment `n` of the log directory `dir`.
pub fn segment_path(dir: &Path, n: u64) -> PathBuf {
    dir.join(format!("{n:08}.wal"))
}

/// The number of the segment named `name`: eight digits and `.wal`.
fn segment_number(name: &OsStr) -> Option<u64> {
    let digits = name.to_str()?.strip_suffix(".wal")?;
    if digits.len() != 8 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// The segments of the log directory `dir`, oldest first; a gap in their
/// numbers is an error.
pub(crate) fn segments_in(dir: &Path) -> std::io::Result<Vec<(u64, PathBuf)>> {
    let mut segments = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if let Some(n) = segment_number(&entry.file_name()) {
            segments.push((n, entry.path()));
        }
    }
    segments.sort();
    if let Some(pair) = segments.windows(2).find(|pair| pair[1].0 != pair[0].0 + 1) {
        let missing = segment_path(dir, pair[0].0 + 1);
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("the segment {} of the write-ahead log is missing", missing.display()),
        ));
    }
    Ok(segments)
}

/// `path` with every symlink of its last component followed, also to a
/// target that does not exist: the place of the log's directory.
pub(crate) fn log_location(path: &Path) -> std::io::Result<PathBuf> {
    let mut location = path.to_path_buf();
    // Linux's MAXSYMLINKS.
    for _ in 0..40 {
        match std::fs::read_link(&location) {
            Ok(target) => location = location.parent().unwrap_or(Path::new("")).join(target),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::InvalidInput | std::io::ErrorKind::NotFound) => {
                return Ok(location);
            }
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other(format!("{} has more than 40 symlink hops", path.display())))
}

/// The single-file log of an earlier version beside the log directory at
/// `path`, if a migration left it there.
pub(crate) fn migrating_log(path: &Path) -> std::io::Result<Option<PathBuf>> {
    let mut name = log_location(path)?.into_os_string();
    name.push(MIGRATING_SUFFIX);
    let migrating = PathBuf::from(name);
    Ok(migrating.try_exists()?.then_some(migrating))
}

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

    /// The stamp the entry writes under.
    pub fn timestamp(&self) -> u64 {
        match self {
            WalEntry::Set { timestamp, .. }
            | WalEntry::Delete { timestamp, .. }
            | WalEntry::SetNull { timestamp, .. } => *timestamp,
        }
    }
}

/// A log as [`recover`] reads it, one entry at a time: it holds one record
/// in memory, never the log.
pub struct WalReader {
    /// `None` once the log is read to its end, or for a missing one.
    file: Option<LogReader>,
    /// The records carry an LSN frame; a log of the first format has none.
    framed: bool,
    /// The log has this version's header.
    lsns_continue: bool,
    /// LSN of the record read last.
    lsn: u64,
    max_lsn: u64,
    /// The entries of the record read last not handed out yet.
    record: std::vec::IntoIter<(u64, WalEntry)>,
    /// The segment read now, named in its errors; `None` for a single file.
    segment: Option<PathBuf>,
    /// The segments after it, oldest first.
    rest: VecDeque<PathBuf>,
}

impl WalReader {
    fn empty() -> Self {
        Self {
            file: None,
            framed: false,
            lsns_continue: false,
            lsn: 0,
            max_lsn: 0,
            record: Vec::new().into_iter(),
            segment: None,
            rest: VecDeque::new(),
        }
    }

    /// The next entry with the LSN of its record, `None` at the end of the
    /// log; the ops of a batch share one LSN. After an error the log reads
    /// as ended.
    pub async fn next(&mut self) -> Option<Result<(u64, WalEntry), WalError>> {
        if let Some(entry) = self.record.next() {
            return Some(Ok(entry));
        }
        let next = loop {
            match self.next_record().await {
                Ok(None) if !self.rest.is_empty() => {
                    if let Err(e) = self.open_next_segment().await {
                        break Err(e);
                    }
                }
                next => break next,
            }
        };
        match next {
            Ok(Some(entries)) => {
                self.max_lsn = self.max_lsn.max(self.lsn);
                self.record = entries.into_iter();
                self.record.next().map(Ok)
            }
            Ok(None) => {
                self.file = None;
                None
            }
            Err(e) => {
                self.file = None;
                self.rest.clear();
                Some(Err(self.in_segment(e)))
            }
        }
    }

    /// Opens the next segment; its header must start at the last LSN of the
    /// segment before, or of none for the first.
    async fn open_next_segment(&mut self) -> Result<(), WalError> {
        let Some(path) = self.rest.pop_front() else { return Ok(()) };
        let first = self.segment.is_none();
        self.segment = Some(path.clone());
        let mut file = BufReader::with_capacity(RECOVERY_READ_BUFFER, File::open(&path).await?);
        let start = match read_next::<{ WAL_HEADER_LEN as usize }>(&mut file).await? {
            Some(head) if head[..WAL_MAGIC.len()] == WAL_MAGIC => {
                u64::from_be_bytes(head[WAL_MAGIC.len()..].try_into().expect("8 bytes"))
            }
            _ => return Err(invalid_data("the segment has no header of this version")),
        };
        if first {
            (self.lsns_continue, self.max_lsn) = (true, start);
        } else if start != self.max_lsn {
            return Err(invalid_data(&format!(
                "the segment starts after LSN {start}, but the segment before it ends at LSN {}",
                self.max_lsn
            )));
        }
        (self.file, self.framed) = (Some(file), true);
        Ok(())
    }

    /// `e` with the name of the segment it happened in, of the same kind.
    fn in_segment(&self, e: WalError) -> WalError {
        match (&self.segment, e) {
            (Some(path), WalError::Io(e)) => {
                WalError::Io(std::io::Error::new(e.kind(), format!("{}: {e}", path.display())))
            }
            (_, e) => e,
        }
    }

    /// The entries of the next record, `None` at the end of the log.
    async fn next_record(&mut self) -> Result<Option<Vec<(u64, WalEntry)>>, WalError> {
        let Some(file) = self.file.as_mut() else { return Ok(None) };
        // A clean end of the log can only fall before a record.
        let entry_type = if self.framed {
            let Some(frame) = read_next::<8>(file).await? else { return Ok(None) };
            self.lsn = u64::from_be_bytes(frame);
            file.read_u8().await?
        } else {
            let Some([entry_type]) = read_next::<1>(file).await? else { return Ok(None) };
            self.lsn += 1;
            entry_type
        };
        let mut entries = Vec::new();
        read_record(file, entry_type, self.lsn, &mut entries).await?;
        Ok(Some(entries))
    }

    /// The highest LSN read so far, at least the start LSN of the header;
    /// the log's highest once [`Self::next`] returned `None`.
    pub fn max_lsn(&self) -> u64 {
        self.max_lsn
    }

    /// The log's LSNs go on from those of the logs before it, as this
    /// version writes them. A log of an earlier format numbers its records
    /// from 1 after each clean stop, so they say nothing about what the
    /// SSTables hold.
    pub fn lsns_continue(&self) -> bool {
        self.lsns_continue
    }
}

/// Opens the write-ahead log at `path` for recovery; a missing log reads as
/// an empty one.
///
/// A log that starts with [`WAL_MAGIC`] or the previous format's header
/// frames every record with its LSN, `[lsn:u64][type:u8]...`; a log of the
/// first format has neither, and its records get the LSNs 1 to n in file
/// order.
pub async fn recover(path: impl AsRef<Path>) -> Result<WalReader, WalError> {
    let mut reader = WalReader::empty();
    let mut file = match File::open(path.as_ref()).await {
        Ok(f) => BufReader::with_capacity(RECOVERY_READ_BUFFER, f),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(reader),
        Err(e) => return Err(e.into()),
    };

    reader.framed = match read_next::<8>(&mut file).await? {
        Some(WAL_MAGIC) => {
            // A header cut short before or inside its start LSN came from a
            // crash while it was written, into a file without records.
            let mut start = [0; 8];
            let mut filled = 0;
            while filled < start.len() {
                match file.read(&mut start[filled..]).await? {
                    0 => return Ok(reader),
                    n => filled += n,
                }
            }
            reader.max_lsn = u64::from_be_bytes(start);
            reader.lsns_continue = true;
            true
        }
        Some(head) => head == PREVIOUS_WAL_MAGIC,
        None => return Ok(reader),
    };
    if !reader.framed {
        file.seek(SeekFrom::Start(0)).await?;
    }
    reader.file = Some(file);
    Ok(reader)
}

/// Opens the log directory `dir` for recovery: its segments, oldest first,
/// read as one log. A missing directory reads as an empty log; a torn
/// record, a segment without this version's header or one that does not
/// start where the one before ends fails the read and names the segment.
pub async fn recover_dir(dir: impl AsRef<Path>) -> Result<WalReader, WalError> {
    let mut reader = WalReader::empty();
    reader.rest = match segments_in(dir.as_ref()) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(reader),
        segments => segments?.into_iter().map(|(_, path)| path).collect(),
    };
    if let Err(e) = reader.open_next_segment().await {
        return Err(reader.in_segment(e));
    }
    Ok(reader)
}

/// The logs recovery reads for the log configured at `path`, in order: the
/// single file of an earlier version a migration to segments left beside
/// it, then the segment directory — or the single file a local committer
/// writes there.
pub async fn recover_path(path: &Path) -> Result<Vec<WalReader>, WalError> {
    let mut logs = Vec::with_capacity(2);
    if let Some(migrating) = migrating_log(path)? {
        logs.push(recover(migrating).await?);
    }
    logs.push(if path.is_dir() { recover_dir(path).await? } else { recover(path).await? });
    Ok(logs)
}

/// Every entry of a log and its highest LSN, read in full.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct Recovered {
    pub(crate) entries: Vec<(u64, WalEntry)>,
    pub(crate) max_lsn: u64,
}

/// Tests only: every log [`recover_path`] opens, read to its end.
#[cfg(test)]
pub(crate) async fn recover_all(path: impl AsRef<Path>) -> Result<Recovered, WalError> {
    let (mut entries, mut max_lsn) = (Vec::new(), 0);
    for mut reader in recover_path(path.as_ref()).await? {
        while let Some(entry) = reader.next().await {
            entries.push(entry?);
        }
        max_lsn = max_lsn.max(reader.max_lsn());
    }
    Ok(Recovered { entries, max_lsn })
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

fn invalid_data(message: &str) -> WalError {
    WalError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, message.to_string()))
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

    /// The log's segments, after every append queued before this call.
    pub async fn segments(&self) -> Result<WalSegments, WalError> {
        match &self.inner {
            #[cfg(test)]
            WalMode::Local(_) => Err(no_checkpoint_error()),
            WalMode::Remote { handle, engine } => handle.wal_segments(*engine).await.map_err(wal_remote_err),
        }
    }

    /// Goes on in the next segment, unless the current one holds no record.
    pub async fn rotate(&self) -> Result<(), WalError> {
        match &self.inner {
            #[cfg(test)]
            WalMode::Local(_) => Err(no_checkpoint_error()),
            WalMode::Remote { handle, engine } => handle.wal_rotate(*engine).await.map_err(wal_remote_err),
        }
    }

    /// Drops the segments before `segment` from the log directory `dir`;
    /// the SSTables must hold every record in them.
    pub async fn drop_segments_before(&self, dir: &Path, segment: u64) -> Result<(), WalError> {
        match &self.inner {
            #[cfg(test)]
            WalMode::Local(_) => Err(no_checkpoint_error()),
            WalMode::Remote { handle, engine } => {
                handle.wal_drop_before(*engine, dir, segment).await.map_err(wal_remote_err)
            }
        }
    }

    /// Truncates the WAL back to its header, effectively clearing it: one
    /// segment with the header is left. The LSNs go on where they were.
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

/// Why a log of the earlier format takes no append: records with and without
/// an LSN must never share a file.
#[cfg(test)]
fn appends_refused() -> std::io::Error {
    std::io::Error::other(
        "the write-ahead log still has the format of an earlier version; it takes appends once the start has truncated it",
    )
}

#[cfg(test)]
struct LocalWal {
    file: File,
    path: PathBuf,
    /// Where a failed cut records `offset` for the next open.
    marker: PathBuf,
    offset: u64,
    /// LSN of the last record written; the next append gets the one after it.
    lsn: u64,
    /// The file has the header of an earlier format or none, and takes no
    /// append until a truncate writes this version's.
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
        let start_lsn = ensure_header(&file)?;

        let mut file = File::from_std(file);
        let offset = file.metadata().await?.len();
        file.seek(SeekFrom::Start(offset)).await?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
            marker: unsafe_end_marker(path),
            offset,
            lsn: start_lsn.unwrap_or(0),
            awaits_truncate: start_lsn.is_none(),
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

/// Cuts the log back to a header that starts after the last LSN, or
/// replaces a log of an earlier format with that header alone.
#[cfg(test)]
async fn do_truncate(wal: &mut LocalWal) -> Result<(), WalError> {
    if wal.awaits_truncate {
        wal.file.set_len(0).await?;
    }
    wal.file.seek(SeekFrom::Start(0)).await?;
    wal.file.write_all(&wal_header(wal.lsn)).await?;
    wal.file.flush().await?;
    wal.file.set_len(WAL_HEADER_LEN).await?;
    wal.awaits_truncate = false;
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

    /// The bytes of a log holding `records`, each framed with its LSN, behind
    /// a header that starts right before the first of them.
    fn log_of(records: &[(u64, &[u8])]) -> Vec<u8> {
        let mut log = wal_header(records.first().map_or(0, |(lsn, _)| lsn - 1)).to_vec();
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
                assert_eq!(*offset, WAL_HEADER_LEN + (i as u64) * 18);
                assert_eq!(*lsn, i as u64 + 1);
            }
            drop(wal);
            assert_eq!(std::fs::read(dir.path().join("wal")).unwrap().len() as u64, WAL_HEADER_LEN + 1800);
        })
    }

    // append → truncate → append: the truncate resets the write cursor to
    // the end of the header; the LSNs go on.
    #[test]
    fn test_append_truncate_append_resets_offset() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let wal = WriteAheadLog::new(dir.path().join("wal")).await.unwrap();

            assert_eq!(wal.append(b"abcde").await.unwrap(), (16, 1));
            assert_eq!(wal.append(b"fgh").await.unwrap(), (29, 2));
            wal.truncate().await.unwrap();
            assert_eq!(wal.append(b"XY").await.unwrap(), (16, 3));

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
    // The returned offset (29, not 16) is the actual proof: it's only possible
    // if the group committed at the pre-truncate offset before truncation
    // reset it, i.e. exactly the "commit group, then truncate" contract.
    #[test]
    fn test_truncate_during_append_group_uses_pending_control() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let wal = WriteAheadLog::new(dir.path().join("wal")).await.unwrap();

            // A record behind the header so the assertion below can distinguish
            // "group committed, then truncated" from "truncated, then committed".
            assert_eq!(wal.append(b"AAAAA").await.unwrap(), (16, 1));

            let (append_result, truncate_result) =
                tokio::join!(wal.append(b"BBB"), wal.truncate());

            assert_eq!(append_result.unwrap(), (29, 2));
            truncate_result.unwrap();
            assert_eq!(std::fs::read(dir.path().join("wal")).unwrap(), wal_header(2));

            // Offset and file state stay consistent after the mid-group truncate.
            assert_eq!(wal.append(b"XY").await.unwrap(), (16, 3));
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
        recover_all(path)
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
            assert_eq!(commit_group(&mut wal, vec![b"kept".to_vec()]).await[0].as_ref().unwrap(), &(16, 1));

            wal.faults.sync = true;
            let results = commit_group(&mut wal, vec![b"lost-one".to_vec(), b"lost-two".to_vec()]).await;
            assert!(results.iter().all(Result::is_err));
            assert_eq!(wal.offset, 28);
            assert_eq!(std::fs::metadata(&path).unwrap().len(), 28);

            assert_eq!(commit_group(&mut wal, vec![b"next".to_vec()]).await[0].as_ref().unwrap(), &(28, 2));
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
            assert_eq!(kept[0].as_ref().unwrap(), &(16, 1));
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
            assert_eq!(std::fs::read(&path).unwrap(), wal_header(1));
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
    // directly (bypassing WriteAheadLog::append) to hand `recover_all()` a
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

            let err = recover_all(&path).await.unwrap_err();
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

            let entries = recover_all(&path).await.unwrap().entries;
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
            let recovered = recover_all(write_log(&dir, V1_LOG)).await.unwrap();
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
            let recovered = recover_all(&path).await.unwrap();
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

                let recovered = recover_all(write_log(&dir, record)).await.unwrap();
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

    // A missing log, an empty one, one with a header cut short and one with
    // the header alone hold no entries; the header alone gives its start LSN.
    #[test]
    fn test_recover_reads_no_entries_from_an_empty_log() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let missing = recover_all(dir.path().join("missing")).await.unwrap();
            assert!(missing.entries.is_empty());
            assert_eq!(missing.max_lsn, 0);
            for (log, max_lsn) in [(&[][..], 0), (&WAL_MAGIC[..], 0), (&wal_header(50)[..11], 0), (&wal_header(0)[..], 0), (&wal_header(50)[..], 50)] {
                let recovered = recover_all(write_log(&dir, log)).await.unwrap();
                assert!(recovered.entries.is_empty());
                assert_eq!(recovered.max_lsn, max_lsn);
            }
        })
    }

    // A log that holds records after its start LSN reads them with their
    // LSNs and reports the last; the previous format's header frames records
    // the same way, without a start LSN.
    #[test]
    fn test_recover_reads_the_records_after_the_start_lsn() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let log = log_of(&[(51, &V1_LOG[..33])]);
            assert_eq!(log[..WAL_HEADER_LEN as usize], wal_header(50));
            let recovered = recover_all(write_log(&dir, &log)).await.unwrap();
            assert_eq!(recovered.entries, v1_log_entries().into_iter().take(1).map(|(_, e)| (51, e)).collect::<Vec<_>>());
            assert_eq!(recovered.max_lsn, 51);

            let previous = [&PREVIOUS_WAL_MAGIC[..], &log[WAL_HEADER_LEN as usize..]].concat();
            let recovered = recover_all(write_log(&dir, &previous)).await.unwrap();
            assert_eq!(recovered.entries.len(), 1);
            assert_eq!(recovered.max_lsn, 51);
        })
    }

    // The reader hands out one entry at a time, the ops of a batch with the
    // LSN of their record, and knows the log's highest LSN at its end; only
    // a log of this version's format has LSNs that go on across logs.
    #[test]
    fn test_the_reader_hands_out_one_entry_at_a_time() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let log = log_of(&[(8, &V1_LOG[..33]), (9, &V1_LOG[101..148])]);
            let mut reader = recover(write_log(&dir, &log)).await.unwrap();
            assert!(reader.lsns_continue());
            assert_eq!(reader.max_lsn(), 7, "the start LSN before the first record");
            let mut lsns = Vec::new();
            while let Some(entry) = reader.next().await {
                lsns.push(entry.unwrap().0);
                assert_eq!(reader.max_lsn(), *lsns.last().unwrap());
            }
            assert_eq!(lsns, [8, 9, 9]);
            assert!(reader.next().await.is_none());

            let previous = [&PREVIOUS_WAL_MAGIC[..], &log[WAL_HEADER_LEN as usize..]].concat();
            assert!(!recover(write_log(&dir, &previous)).await.unwrap().lsns_continue());
            assert!(!recover(write_log(&dir, V1_LOG)).await.unwrap().lsns_continue());
        })
    }

    /// How a version before this one reads the start of a log: the previous
    /// format's header, or else a record type of the first format.
    fn read_as_previous_version(log: &[u8]) -> Result<(), WalError> {
        if log.starts_with(&PREVIOUS_WAL_MAGIC) || matches!(log.first(), None | Some(1..=4)) {
            return Ok(());
        }
        Err(invalid_entry_error())
    }

    // A version before this one refuses a log of this one: its first byte is
    // no record type.
    #[test]
    fn test_a_previous_version_refuses_a_log_of_this_version() {
        assert!(read_as_previous_version(&[&PREVIOUS_WAL_MAGIC[..], b"rest"].concat()).is_ok());
        assert!(read_as_previous_version(V1_LOG).is_ok());
        let err = read_as_previous_version(&wal_header(0)).unwrap_err();
        assert!(err.to_string().contains("Invalid WAL entry type"), "{err}");
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
                &frame_alone[..20],
            ];
            for log in torn {
                let err = recover_all(write_log(&dir, log)).await.unwrap_err();
                assert!(
                    matches!(&err, WalError::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof),
                    "expected a torn record, got: {err}"
                );
            }
        })
    }

    // The local committer takes no checkpoint: a mark, the segment list, a
    // rotation and a drop all fail and leave the log as it is.
    #[test]
    fn test_the_local_committer_takes_no_checkpoint() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("wal");
            let wal = WriteAheadLog::new(&path).await.unwrap();
            wal.append(b"kept").await.unwrap();
            assert!(wal.mark().await.is_err());
            assert!(wal.segments().await.is_err());
            assert!(wal.rotate().await.is_err());
            assert!(wal.drop_segments_before(dir.path(), 2).await.is_err());
            assert_eq!(std::fs::read(&path).unwrap(), log_of(&[(1, b"kept")]));
        })
    }

    /// A log directory in `dir` with `segments`, each written as given.
    fn write_segments(dir: &TempDir, segments: &[Vec<u8>]) -> PathBuf {
        let log = dir.path().join("log");
        std::fs::create_dir_all(&log).unwrap();
        for (n, bytes) in (1..).zip(segments) {
            std::fs::write(segment_path(&log, n), bytes).unwrap();
        }
        log
    }

    // The segments of a directory read as one log, in the order of their
    // numbers, not of their names' listing; each starts where the one
    // before ends, an empty one included.
    #[test]
    fn test_recover_dir_reads_the_segments_in_order() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let segments = [
                log_of(&[(1, &delete_record(b"one")), (2, &delete_record(b"two"))]),
                wal_header(2).to_vec(),
                log_of(&[(3, &delete_record(b"three"))]),
            ];
            let log = write_segments(&dir, &segments);
            std::fs::write(log.join("00000003.wal.unsafe-end.tmp"), b"ignored").unwrap();
            let recovered = recover_all(&log).await.unwrap();
            assert_eq!(recovered.entries.iter().map(|(lsn, entry)| (*lsn, entry.key().to_vec())).collect::<Vec<_>>(), [
                (1, b"one".to_vec()),
                (2, b"two".to_vec()),
                (3, b"three".to_vec())
            ]);
            assert_eq!(recovered.max_lsn, 3);
            assert!(recover_dir(&log).await.unwrap().lsns_continue());
            assert!(recover_all(dir.path().join("missing")).await.unwrap().entries.is_empty());
        })
    }

    // A torn record fails the read in any segment, the last one included,
    // and the error names the segment.
    #[test]
    fn test_recover_dir_names_the_segment_of_a_torn_record() {
        crate::core::engine_runtime::block_on(async {
            for torn in [1, 2] {
                let dir = TempDir::new().unwrap();
                let mut segments = vec![log_of(&[(1, &delete_record(b"one"))]), log_of(&[(2, &delete_record(b"two"))])];
                segments[torn - 1].pop();
                let log = write_segments(&dir, &segments);
                let err = recover_all(&log).await.unwrap_err();
                assert!(
                    matches!(&err, WalError::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof),
                    "expected a torn record, got: {err}"
                );
                assert!(err.to_string().contains(&format!("0000000{torn}.wal")), "{err}");
            }
        })
    }

    // A segment that does not start where the one before ends, one without
    // this version's header and a gap in the numbers each fail the read.
    #[test]
    fn test_recover_dir_refuses_a_broken_chain_of_segments() {
        crate::core::engine_runtime::block_on(async {
            let first = log_of(&[(1, &delete_record(b"one"))]);
            let previous = [&PREVIOUS_WAL_MAGIC[..], &first[WAL_HEADER_LEN as usize..]].concat();
            for (second, expected) in [
                (log_of(&[(5, &delete_record(b"far"))]), "00000002.wal: the segment starts after LSN 4"),
                (previous, "00000002.wal: the segment has no header of this version"),
            ] {
                let dir = TempDir::new().unwrap();
                let log = write_segments(&dir, &[first.clone(), second]);
                let err = recover_all(&log).await.unwrap_err();
                assert!(err.to_string().contains(expected), "{err}");
            }
            let dir = TempDir::new().unwrap();
            let log = write_segments(&dir, std::slice::from_ref(&first));
            std::fs::write(segment_path(&log, 3), wal_header(1)).unwrap();
            let err = recover_all(&log).await.unwrap_err();
            assert!(err.to_string().contains("00000002.wal of the write-ahead log is missing"), "{err}");
        })
    }

    // Recovery reads the log of an earlier version a migration left beside
    // the directory first, then the segments.
    #[test]
    fn test_recover_path_reads_the_migrating_log_before_the_segments() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let log = write_segments(&dir, &[log_of(&[(6, &delete_record(b"after"))])]);
            std::fs::write(dir.path().join("log.migrating"), &V1_LOG[..33]).unwrap();
            let logs = recover_path(&log).await.unwrap();
            assert_eq!(logs.iter().map(WalReader::lsns_continue).collect::<Vec<_>>(), [false, true]);
            let recovered = recover_all(&log).await.unwrap();
            assert_eq!(recovered.entries.len(), 2);
            assert_eq!(recovered.entries[1].1.key(), b"after");
            assert_eq!(recovered.max_lsn, 6);
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

            let recovered = recover_all(write_log(&dir, &log)).await.unwrap();
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
            assert_eq!(wal.append(&delete_record(b"first")).await.unwrap(), (16, 42));
            assert_eq!(wal.append(&delete_record(b"second")).await.unwrap().1, 43);
            drop(wal);

            let recovered = recover_all(&path).await.unwrap();
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
            assert_eq!(wal.append(&delete_record(b"d")).await.unwrap(), (16, 4));
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

                let logged: Vec<(u64, u64)> = recover_all(&path)
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
