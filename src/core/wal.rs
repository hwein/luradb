use crate::core::storage_thread::StorageHandle;
use std::path::Path;
use thiserror::Error;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
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
/// command ring (`shm.command_buffer_size`) defaults to 4 MiB -- all well
/// above `LsmConfig::max_value_size`'s own 512 KiB default, which every
/// engine (kv/json/rel) validates a value against before it ever reaches
/// the WAL. 64 MiB (the JSON bulk body cap) is the largest of these; 96 MiB
/// gives it headroom no legitimate write can reach.
const WAL_MAX_FIELD_LEN: usize = 96 * 1024 * 1024;

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
                entries.push(WalEntry::Delete { timestamp, key });
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
                        2 => entries.push(WalEntry::Delete { timestamp, key }),
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
/// `Local` runs the tokio::fs committer (default). `Remote` forwards all I/O to
/// the perf/005 storage thread, which does the write + fdatasync on its io_uring
/// ring. `append`'s empty-input shortcut is identical in both modes.
enum WalMode {
    Local(mpsc::Sender<CommitRequest>),
    Remote(StorageHandle),
}

pub struct WriteAheadLog {
    inner: WalMode,
}

impl WriteAheadLog {
    /// Creates a new WAL or opens an existing one at the given path (tokio::fs
    /// committer path — unchanged when the storage thread is disabled).
    pub async fn new(path: impl AsRef<Path>) -> Result<Self, WalError> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path.as_ref())
            .await?;

        let initial_size = file.metadata().await?.len();
        file.seek(std::io::SeekFrom::Start(initial_size)).await?;

        let (sender, receiver) = mpsc::channel(1024);
        tokio::spawn(run_committer(file, initial_size, receiver));

        Ok(Self { inner: WalMode::Local(sender) })
    }

    /// Routes all WAL I/O through the perf/005 storage thread. The thread owns
    /// the WAL file; this WAL keeps no file handle of its own.
    pub fn with_storage_handle(handle: StorageHandle) -> Self {
        Self { inner: WalMode::Remote(handle) }
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
            WalMode::Local(sender) => {
                let (tx, rx) = oneshot::channel();
                sender
                    .send(CommitRequest::Append { data: data.to_vec(), responder: tx })
                    .await
                    .map_err(|_| broken_pipe_error())?;
                rx.await.map_err(|_| broken_pipe_error())?
            }
            WalMode::Remote(handle) => handle.wal_append(data.to_vec()).await.map_err(wal_remote_err),
        }
    }

    /// Truncates the WAL file, effectively clearing it.
    ///
    /// This is typically done after the MemTable has been successfully
    /// recovered from the WAL at startup.
    pub async fn truncate(&self) -> Result<(), WalError> {
        match &self.inner {
            WalMode::Local(sender) => {
                let (tx, rx) = oneshot::channel();
                sender
                    .send(CommitRequest::Truncate { responder: tx })
                    .await
                    .map_err(|_| broken_pipe_error())?;
                rx.await.map_err(|_| broken_pipe_error())?
            }
            WalMode::Remote(handle) => handle.wal_truncate().await.map_err(wal_remote_err),
        }
    }
}

/// Maps a storage-thread `anyhow` error back into the WAL's error type.
fn wal_remote_err(e: anyhow::Error) -> WalError {
    WalError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
}

fn broken_pipe_error() -> WalError {
    WalError::Io(std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "WAL committer task has stopped",
    ))
}

type AppendResponder = oneshot::Sender<Result<u64, WalError>>;

/// Background task: drains the commit queue and batches writes into a single fsync per group.
async fn run_committer(
    mut file: File,
    mut offset: u64,
    mut rx: mpsc::Receiver<CommitRequest>,
) {
    loop {
        // Block until at least one request arrives.
        let first = match rx.recv().await {
            Some(r) => r,
            None => return, // All senders dropped — shut down.
        };

        match first {
            CommitRequest::Truncate { responder } => {
                let _ = responder.send(do_truncate(&mut file, &mut offset).await);
            }
            CommitRequest::Append { data, responder } => {
                commit_append_group(&mut file, &mut offset, &mut rx, data, responder).await;
            }
        }
    }
}

async fn commit_append_group(
    file: &mut File,
    offset: &mut u64,
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
    let start_offset = *offset;
    let mut combined = Vec::new();
    let mut item_offsets = Vec::with_capacity(group.len());
    for (data, _) in &group {
        item_offsets.push(*offset);
        *offset += data.len() as u64;
        combined.extend_from_slice(data);
    }

    // One write + one fsync for the entire group.
    let result = async {
        file.seek(std::io::SeekFrom::Start(start_offset)).await?;
        file.write_all(&combined).await?;
        file.flush().await?;
        file.sync_all().await
    }
    .await;

    match result {
        Ok(()) => {
            for ((_, responder), item_offset) in group.into_iter().zip(item_offsets) {
                let _ = responder.send(Ok(item_offset));
            }
        }
        Err(e) => {
            // Roll back offset — data was not durably written.
            *offset = start_offset;
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
        let _ = responder.send(do_truncate(file, offset).await);
    }
}

async fn do_truncate(file: &mut File, offset: &mut u64) -> Result<(), WalError> {
    file.set_len(0).await?;
    file.seek(std::io::SeekFrom::Start(0)).await?;
    *offset = 0;
    file.sync_all().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tempfile::TempDir;

    // N concurrent appends batch into disjoint, monotone offsets and one
    // contiguous file — the local committer's group-commit path.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_parallel_appends_disjoint_monotone_offsets() {
        let dir = TempDir::new().unwrap();
        let wal = Arc::new(WriteAheadLog::new(dir.path().join("wal")).await.unwrap());

        let mut tasks = Vec::new();
        for _ in 0..100u32 {
            let w = Arc::clone(&wal);
            tasks.push(tokio::spawn(async move { w.append(&[b'x'; 10]).await.unwrap() }));
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
    }

    // append → truncate → append: the truncate resets the write cursor to 0.
    #[tokio::test]
    async fn test_append_truncate_append_resets_offset() {
        let dir = TempDir::new().unwrap();
        let wal = WriteAheadLog::new(dir.path().join("wal")).await.unwrap();

        assert_eq!(wal.append(b"abcde").await.unwrap(), 0);
        assert_eq!(wal.append(b"fgh").await.unwrap(), 5);
        wal.truncate().await.unwrap();
        assert_eq!(wal.append(b"XY").await.unwrap(), 0);

        drop(wal);
        assert_eq!(std::fs::read(dir.path().join("wal")).unwrap(), b"XY");
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
    #[tokio::test]
    async fn test_truncate_during_append_group_uses_pending_truncate() {
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
    #[tokio::test]
    async fn test_recover_rejects_wal_field_length_exceeding_cap() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal");
        std::fs::write(&path, raw_delete_record((WAL_MAX_FIELD_LEN + 1) as u32, &[])).unwrap();

        let err = recover(&path).await.unwrap_err();
        assert!(
            err.to_string().contains("exceeds maximum"),
            "expected a field-too-long error, got: {err}"
        );
    }

    // A field of exactly WAL_MAX_FIELD_LEN must still parse -- the cap
    // rejects lengths *above* it, never at it.
    #[tokio::test]
    async fn test_recover_accepts_wal_field_length_exactly_at_cap() {
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
    }
}
