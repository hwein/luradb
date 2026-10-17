//! `disk_manager` module
//!
//! This module is responsible for all direct file I/O operations. It provides
//! an abstraction for reading and writing page-sized chunks of data from the
//! main database file, using the engine thread's io_uring runtime (compio).
//!
//! To bridge the single-threaded nature of that runtime with a multi-threaded
//! application (like an Axum server), this DiskManager uses a channel-based
//! message passing approach. A dedicated background task owns the `File` handle
//! and performs all I/O, while the `DiskManager` struct itself is `Send + Sync`
//! and can be shared across threads.

use crate::core::engine_runtime;
use crate::core::page::{Page, PageId, PAGE_SIZE};
use anyhow::{bail, Result};
use compio::buf::BufResult;
use compio::fs::File;
use compio::io::{AsyncReadAt, AsyncWriteAt};
use std::os::fd::{FromRawFd, IntoRawFd};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{mpsc, oneshot};

// --- I/O Commands ---

/// Represents a command sent to the dedicated I/O task.
enum IoCommand {
    /// A request to read a page from disk.
    Read {
        page_id: PageId,
        responder: oneshot::Sender<Result<Page>>,
    },
    /// A request to write a page to disk.
    Write {
        page_id: PageId,
        page: Page,
        responder: oneshot::Sender<Result<()>>,
    },
}

// --- DiskManager ---

/// Manages reading and writing pages to and from the database file on disk.
/// It sends I/O commands to a dedicated background task.
#[derive(Clone)]
pub struct DiskManager {
    sender: mpsc::Sender<IoCommand>,
    next_page_id: std::sync::Arc<AtomicU64>,
}

impl DiskManager {
    /// Creates a new `DiskManager` and spawns its background I/O task.
    ///
    /// The background task will open the file at `db_path` and listen for
    /// I/O commands.
    pub async fn new(db_path: impl AsRef<Path>) -> Result<Self> {
        let (sender, mut receiver) = mpsc::channel(128);

        // --- File setup ---
        let path = db_path.as_ref().to_path_buf();
        let std_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)?;
        let metadata = std_file.metadata()?;
        let num_pages = metadata.len() / PAGE_SIZE as u64;
        // SAFETY: the descriptor is `std_file`'s, whose ownership moves here.
        let db_file = unsafe { File::from_raw_fd(std_file.into_raw_fd()) };

        // --- Spawn I/O Task --- one command at a time, each as an I/O task
        // that runs to its end.
        compio::runtime::spawn(async move {
            while let Some(command) = receiver.recv().await {
                let db_file = db_file.clone();
                engine_runtime::spawn_io(async move {
                    match command {
                        IoCommand::Read { page_id, responder } => {
                            let _ = responder.send(Self::perform_read(&db_file, page_id).await);
                        }
                        IoCommand::Write { page_id, page, responder } => {
                            let _ = responder.send(Self::perform_write(&db_file, page_id, &page).await);
                        }
                    }
                })
                .await;
            }
        })
        .detach();

        Ok(Self {
            sender,
            next_page_id: std::sync::Arc::new(AtomicU64::new(num_pages)),
        })
    }

    /// Reads the content of a page from the database file.
    pub async fn read_page(&self, page_id: PageId) -> Result<Page> {
        let (responder, receiver) = oneshot::channel();
        let command = IoCommand::Read { page_id, responder };
        
        if self.sender.send(command).await.is_err() {
            bail!("Failed to send read command to I/O task. It may have panicked.");
        }

        receiver.await?
    }

    /// Writes the content of a page to the database file.
    pub async fn write_page(&self, page_id: PageId, page: &Page) -> Result<()> {
        let (responder, receiver) = oneshot::channel();
        let command = IoCommand::Write { page_id, page: *page, responder };

        if self.sender.send(command).await.is_err() {
            bail!("Failed to send write command to I/O task. It may have panicked.");
        }
        
        receiver.await?
    }

    /// Allocates a new page ID.
    pub fn allocate_page(&self) -> PageId {
        let new_page_id = self.next_page_id.fetch_add(1, Ordering::SeqCst);
        PageId(new_page_id)
    }

    // --- Private I/O task functions ---

    async fn perform_read(db_file: &File, page_id: PageId) -> Result<Page> {
        let offset = page_id.0 * PAGE_SIZE as u64;
        let buf = vec![0u8; PAGE_SIZE];

        let BufResult(res, buf) = db_file.read_at(buf, offset).await;
        let bytes_read = res?;

        if bytes_read > 0 && bytes_read < PAGE_SIZE {
            bail!("Partial I/O read: expected {} bytes, got {}", PAGE_SIZE, bytes_read);
        }

        let mut page_data = Page::default();
        page_data.as_mut_bytes().copy_from_slice(&buf);
        Ok(page_data)
    }

    async fn perform_write(db_file: &File, page_id: PageId, page_data: &Page) -> Result<()> {
        let offset = page_id.0 * PAGE_SIZE as u64;
        let data = page_data.as_bytes().to_vec();

        let BufResult(res, _) = (&mut &*db_file).write_at(data, offset).await;
        let bytes_written = res?;

        if bytes_written != PAGE_SIZE {
            bail!("Partial I/O write: expected {} bytes, got {}", PAGE_SIZE, bytes_written);
        }

        db_file.sync_data().await?;
        Ok(())
    }
}