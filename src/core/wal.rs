#[cfg(test)]
use crate::core::storage_thread::{
    apply_unsafe_end_marker, mark_unsafe_end, unmark_unsafe_end, unsafe_end_marker, Faults,
};
use crate::core::storage_thread::{StorageHandle, WalTarget};
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use thiserror::Error;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
#[cfg(test)]
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
#[cfg(test)]
use tokio::sync::{mpsc, oneshot};

/// Hard ceiling on any single length-prefixed WAL field (a key or a value)
/// read during recovery. Without it, a corrupt tail turns garbage bytes into
/// a u32 length up to 4 GiB and `read_len_prefixed` allocates that much
/// before `read_exact` ever reaches EOF (spec kv/026 Spec-Review F7).
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

#[derive(Error, Debug)]
pub enum WalError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("A partial write to the WAL was detected. Expected to write {expected} bytes, but only wrote {wrote}. The WAL is now in an inconsistent state.")]
    PartialWrite { expected: usize, wrote: usize },
}

/// Represents a single, parsed entry from the Write-Ahead Log.
#[derive(Debug)]
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
        /// (type 2): batch ops share one stamp and replay in order (spec kv/032).
        in_batch: bool,
    },
    SetNull {
        timestamp: u64,
        key: Vec<u8>,
    },
}

/// Recovers database state by reading and parsing all entries from the WAL.
///
/// This function is designed to be called once at startup. It reads the entire
/// log from disk and reconstructs the in-memory operations needed to restore
/// the MemTable to its pre-shutdown state.
pub async fn recover(path: impl AsRef<Path>) -> Result<Vec<WalEntry>, WalError> {
    let mut file = match File::open(path.as_ref()).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };

    let mut entries = Vec::new();
    loop {
        // Attempt to read the entry type byte. A clean EOF here means we're done.
        let entry_type = match file.read_u8().await {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        };

        match entry_type {
            // SET: [ts:u64][key_len:u32][key][value_len:u32][value][expire_at:u64]
            1 => {
                let timestamp = file.read_u64().await?;
                let key = read_len_prefixed(&mut file).await?;
                let value = read_len_prefixed(&mut file).await?;
                let expire_at = file.read_u64().await?;
                entries.push(WalEntry::Set { timestamp, key, value, expire_at });
            }
            // DELETE: [ts:u64][key_len:u32][key]
            2 => {
                let timestamp = file.read_u64().await?;
                let key = read_len_prefixed(&mut file).await?;
                entries.push(WalEntry::Delete { timestamp, key, in_batch: false });
            }
            // BATCH: [ts:u64][count:u32] then per op [op:u8][key]([value][expire_at]).
            // Parsed all-or-nothing: a torn batch record fails recovery instead of
            // silently applying a prefix of its operations.
            3 => {
                let timestamp = file.read_u64().await?;
                let count = file.read_u32().await?;
                for _ in 0..count {
                    let op = file.read_u8().await?;
                    let key = read_len_prefixed(&mut file).await?;
                    match op {
                        1 => {
                            let value = read_len_prefixed(&mut file).await?;
                            let expire_at = file.read_u64().await?;
                            entries.push(WalEntry::Set { timestamp, key, value, expire_at });
                        }
                        2 => entries.push(WalEntry::Delete { timestamp, key, in_batch: true }),
                        _ => return Err(invalid_entry_error()),
                    }
                }
            }
            // SET_NULL: [ts:u64][key_len:u32][key] (kv/018; type 3 is the batch record above)
            4 => {
                let timestamp = file.read_u64().await?;
                let key = read_len_prefixed(&mut file).await?;
                entries.push(WalEntry::SetNull { timestamp, key });
            }
            _ => return Err(invalid_entry_error()),
        }
    }

    Ok(entries)
}

async fn read_len_prefixed(file: &mut File) -> Result<Vec<u8>, WalError> {
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
    Append {
        data: Vec<u8>,
        responder: oneshot::Sender<Result<u64, WalError>>,
    },
    Truncate {
        responder: oneshot::Sender<Result<(), WalError>>,
    },
}

/// A Write-Ahead Log with Group Commit for high-throughput durability.
///
/// `Remote` hands all I/O to the storage hub, which writes and fdatasyncs
/// `engine`'s file on its io_uring ring. `Local` (tests only) runs a tokio::fs
/// committer task with the same semantics: one writer per file, one fsync per
/// group. `append`'s empty-input shortcut is identical in both modes.
enum WalMode {
    #[cfg(test)]
    Local(mpsc::Sender<CommitRequest>),
    Remote { handle: StorageHandle, engine: WalTarget },
}

pub struct WriteAheadLog {
    inner: WalMode,
}

impl WriteAheadLog {
    /// Tests only: creates a new WAL or opens an existing one at the given
    /// path, written by a local committer task instead of the storage hub.
    #[cfg(test)]
    pub async fn new(path: impl AsRef<Path>) -> Result<Self, WalError> {
        let wal = LocalWal::open(path.as_ref()).await?;
        let (sender, receiver) = mpsc::channel(1024);
        compio::runtime::spawn(run_committer(wal, receiver)).detach();

        Ok(Self { inner: WalMode::Local(sender) })
    }

    /// Routes all I/O of `engine`'s WAL through the storage hub. The hub owns
    /// the file; this WAL keeps no file handle of its own.
    pub fn with_storage_handle(handle: StorageHandle, engine: WalTarget) -> Self {
        Self { inner: WalMode::Remote { handle, engine } }
    }

    /// Appends a new entry to the WAL and waits for it to be durably flushed.
    ///
    /// Returns the file offset at which this entry was written.
    /// Concurrent callers are automatically batched into a single fsync.
    pub async fn append(&self, data: &[u8]) -> Result<u64, WalError> {
        if data.is_empty() {
            return Ok(0);
        }

        match &self.inner {
            #[cfg(test)]
            WalMode::Local(sender) => {
                let (tx, rx) = oneshot::channel();
                sender
                    .send(CommitRequest::Append { data: data.to_vec(), responder: tx })
                    .await
                    .map_err(|_| broken_pipe_error())?;
                rx.await.map_err(|_| broken_pipe_error())?
            }
            WalMode::Remote { handle, engine } => {
                handle.wal_append(*engine, data.to_vec()).await.map_err(wal_remote_err)
            }
        }
    }

    /// Truncates the WAL file, effectively clearing it.
    ///
    /// This is typically done after the MemTable has been successfully
    /// recovered from the WAL at startup.
    pub async fn truncate(&self) -> Result<(), WalError> {
        match &self.inner {
            #[cfg(test)]
            WalMode::Local(sender) => {
                let (tx, rx) = oneshot::channel();
                sender
                    .send(CommitRequest::Truncate { responder: tx })
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
fn broken_pipe_error() -> WalError {
    WalError::Io(std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "WAL committer task has stopped",
    ))
}

#[cfg(test)]
type AppendResponder = oneshot::Sender<Result<u64, WalError>>;

#[cfg(test)]
struct LocalWal {
    file: File,
    /// Where a failed cut records `offset` for the next open.
    marker: PathBuf,
    offset: u64,
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

        let mut file = File::from_std(file);
        let offset = file.metadata().await?.len();
        file.seek(std::io::SeekFrom::Start(offset)).await?;
        Ok(Self { file, marker: unsafe_end_marker(path), offset, unsafe_end: false, faults: Faults::default() })
    }

    /// A failed write or sync cuts the file back to the cursor, which stays
    /// where it was.
    async fn write_at_cursor(&mut self, data: &[u8]) -> std::io::Result<()> {
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
            CommitRequest::Truncate { responder } => {
                let _ = responder.send(do_truncate(&mut wal).await);
            }
            CommitRequest::Append { data, responder } => {
                commit_append_group(&mut wal, &mut rx, data, responder).await;
            }
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
    let mut pending_truncate: Option<oneshot::Sender<Result<(), WalError>>> = None;

    loop {
        match rx.try_recv() {
            Ok(CommitRequest::Append { data, responder }) => {
                group.push((data, responder));
            }
            Ok(CommitRequest::Truncate { responder }) => {
                // Stop collecting — commit the current group first, then truncate.
                pending_truncate = Some(responder);
                break;
            }
            Err(_) => break,
        }
    }

    // Compute per-item offsets and build the single combined write buffer.
    let mut combined = Vec::new();
    let mut item_offsets = Vec::with_capacity(group.len());
    for (data, _) in &group {
        item_offsets.push(wal.offset + combined.len() as u64);
        combined.extend_from_slice(data);
    }

    // One write + one fsync for the entire group.
    match wal.write_at_cursor(&combined).await {
        Ok(()) => {
            wal.offset += combined.len() as u64;
            for ((_, responder), item_offset) in group.into_iter().zip(item_offsets) {
                let _ = responder.send(Ok(item_offset));
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

    if let Some(responder) = pending_truncate {
        let _ = responder.send(do_truncate(wal).await);
    }
}

#[cfg(test)]
async fn do_truncate(wal: &mut LocalWal) -> Result<(), WalError> {
    wal.file.set_len(0).await?;
    wal.file.seek(std::io::SeekFrom::Start(0)).await?;
    wal.offset = 0;
    wal.file.sync_all().await?;
    if let Err(e) = wal.unmark() {
        wal.unsafe_end = true;
        wal.log_failed_cut(&e);
        return Err(e.into());
    }
    wal.unsafe_end = false;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tempfile::TempDir;

    // N concurrent appends batch into disjoint, monotone offsets and one
    // contiguous file — the local committer's group-commit path.
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
            let mut offsets = Vec::new();
            for t in tasks {
                offsets.push(t.await.unwrap());
            }
            offsets.sort_unstable();

            assert_eq!(offsets.len(), 100);
            for (i, off) in offsets.iter().enumerate() {
                assert_eq!(*off, (i as u64) * 10);
            }
            drop(wal);
            assert_eq!(std::fs::read(dir.path().join("wal")).unwrap().len(), 1000);
        })
    }

    // append → truncate → append: the truncate resets the write cursor to 0.
    #[test]
    fn test_append_truncate_append_resets_offset() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let wal = WriteAheadLog::new(dir.path().join("wal")).await.unwrap();

            assert_eq!(wal.append(b"abcde").await.unwrap(), 0);
            assert_eq!(wal.append(b"fgh").await.unwrap(), 5);
            wal.truncate().await.unwrap();
            assert_eq!(wal.append(b"XY").await.unwrap(), 0);

            drop(wal);
            assert_eq!(std::fs::read(dir.path().join("wal")).unwrap(), b"XY");
        })
    }

    // A Truncate arriving mid-group must land in `pending_truncate` (the
    // drain loop in commit_append_group), not the top-level Truncate arm in
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
    // The returned offset (5, not 0) is the actual proof: it's only possible
    // if the group committed at the pre-truncate offset before truncation
    // reset it, i.e. exactly the "commit group, then truncate" contract.
    #[test]
    fn test_truncate_during_append_group_uses_pending_truncate() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let wal = WriteAheadLog::new(dir.path().join("wal")).await.unwrap();

            // Nonzero starting offset so the assertion below can distinguish
            // "group committed, then truncated" from "truncated, then committed".
            assert_eq!(wal.append(b"AAAAA").await.unwrap(), 0);

            let (append_result, truncate_result) =
                tokio::join!(wal.append(b"BBB"), wal.truncate());

            assert_eq!(append_result.unwrap(), 5);
            truncate_result.unwrap();
            assert!(std::fs::read(dir.path().join("wal")).unwrap().is_empty());

            // Offset and file state stay consistent after the mid-group truncate.
            assert_eq!(wal.append(b"XY").await.unwrap(), 0);
            drop(wal);
            assert_eq!(std::fs::read(dir.path().join("wal")).unwrap(), b"XY");
        })
    }

    /// Commits `records` as one group on the local committer, the way
    /// `run_committer` does; returns each append's result in order.
    async fn commit_group(wal: &mut LocalWal, records: Vec<Vec<u8>>) -> Vec<Result<u64, WalError>> {
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

    async fn recovered_keys(path: &Path) -> Vec<String> {
        recover(path)
            .await
            .unwrap()
            .into_iter()
            .map(|entry| match entry {
                WalEntry::Delete { key, .. } => String::from_utf8(key).unwrap(),
                other => panic!("expected a DELETE record, got {other:?}"),
            })
            .collect()
    }

    // A failed group cuts the file back to the cursor, keeps the cursor and
    // fails every append of the group.
    #[test]
    fn test_failed_group_cuts_the_file_back_to_the_cursor() {
        crate::core::engine_runtime::block_on(async {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("wal");
            let mut wal = LocalWal::open(&path).await.unwrap();
            assert_eq!(commit_group(&mut wal, vec![b"kept".to_vec()]).await[0].as_ref().unwrap(), &0);

            wal.faults.sync = true;
            let results = commit_group(&mut wal, vec![b"lost-one".to_vec(), b"lost-two".to_vec()]).await;
            assert!(results.iter().all(Result::is_err));
            assert_eq!(wal.offset, 4);
            assert_eq!(std::fs::metadata(&path).unwrap().len(), 4);
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
            assert_eq!(kept[0].as_ref().unwrap(), &0);
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
            assert_eq!(kept[0].as_ref().unwrap(), &start);
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
            assert_eq!(kept[0].as_ref().unwrap(), &start);
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
            assert_eq!(kept[0].as_ref().unwrap(), &start);
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
            assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
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
            assert_eq!(kept[0].as_ref().unwrap(), &start);
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
            assert_eq!(kept[0].as_ref().unwrap(), &0);
            assert!(!marker.exists());
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
    // -- not attempt an allocation up to 4 GiB (spec kv/026 Spec-Review F7,
    // kv/027 §B). No key bytes follow; the cap check must reject this before
    // read_exact ever runs.
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

            let entries = recover(&path).await.unwrap();
            assert_eq!(entries.len(), 1);
            match &entries[0] {
                WalEntry::Delete { key: k, .. } => assert_eq!(k.len(), WAL_MAX_FIELD_LEN),
                other => panic!("expected WalEntry::Delete, got {other:?}"),
            }
        })
    }
}
