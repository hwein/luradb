//! `kv` module
//!
//! A simple Key-Value storage engine implementation.

use super::StorageEngine;
use crate::core::buffer_pool::BufferPool;
use crate::core::page::{PageId, PAGE_DATA_SIZE};
use crate::core::wal::WriteAheadLog;
use anyhow::{bail, Result};
use std::sync::Arc;

const ROOT_PAGE_ID: PageId = PageId(0);

// --- Constants for the Slotted Page Layout ---
// The header at the start of the page's data section.
const SLOTS_COUNT_HEADER_SIZE: usize = 4; // u32 for number of slots
// Each slot entry at the end of the page.
const SLOT_ENTRY_SIZE: usize = 8; // u32 for offset, u32 for size

/// A simple Key-Value store that uses a single page for storage.
///
/// This implementation uses a "slotted page" layout to store multiple
/// key-value pairs within one page. It's a basic example of how an engine
/// interacts with the Buffer Pool Manager.
pub struct KvStore {
    bpm: BufferPool,
    page_id: PageId,
    wal: Arc<WriteAheadLog>,
}

impl KvStore {
    /// Creates a new `KvStore` or loads an existing one.
    ///
    /// It attempts to fetch the root page (ID 0). If the page doesn't exist
    /// (e.g., new database), it allocates a new page, which will become the
    /// root, and initializes it.
    pub async fn new(bpm: BufferPool, wal: Arc<WriteAheadLog>) -> Result<Self> {
        match bpm.fetch_page(ROOT_PAGE_ID).await {
            Ok(_page_ref) => {
                // Page 0 already exists, just unpin it and we're good to go.
                bpm.unpin_page(ROOT_PAGE_ID, false).await?;
                Ok(Self { bpm, page_id: ROOT_PAGE_ID, wal })
            }
            Err(_) => {
                // Page 0 doesn't exist. Create it.
                // The first page allocated in a new DB will be PageId(0).
                let (page_id, page_ref) = bpm.new_page().await?;
                if page_id != ROOT_PAGE_ID {
                    bail!(
                        "Root page initialization failed. Expected PageId 0, but got {}",
                        page_id
                    );
                }

                // Initialize the new page with 0 slots.
                let mut page_w = page_ref.write().await;
                page_w.data[0..SLOTS_COUNT_HEADER_SIZE].copy_from_slice(&0u32.to_be_bytes());
                
                // Unpin the page, marking it as dirty since we initialized it.
                bpm.unpin_page(page_id, true).await?;

                Ok(Self { bpm, page_id, wal })
            }
        }
    }
}

impl StorageEngine for KvStore {
    fn get(&self, key: &[u8]) -> impl std::future::Future<Output = Result<Option<Vec<u8>>>> + Send {
        async move {
            let page_ref = self.bpm.fetch_page(self.page_id).await?;
            let page_r = page_ref.read().await;

            let num_slots = u32::from_be_bytes(page_r.data[0..4].try_into()?) as usize;
            let mut result = None;

            for i in 0..num_slots {
                let slot_offset = PAGE_DATA_SIZE - (i + 1) * SLOT_ENTRY_SIZE;
                let offset =
                    u32::from_be_bytes(page_r.data[slot_offset..slot_offset + 4].try_into()?)
                        as usize;
                let size =
                    u32::from_be_bytes(page_r.data[slot_offset + 4..slot_offset + 8].try_into()?)
                        as usize;

                // Skip empty slots (e.g., from deletion)
                if size == 0 {
                    continue;
                }

                let kv_pair = &page_r.data[offset..offset + size];
                let key_len = u32::from_be_bytes(kv_pair[0..4].try_into()?) as usize;

                if &kv_pair[4..4 + key_len] == key {
                    let value_len =
                        u32::from_be_bytes(kv_pair[4 + key_len..4 + key_len + 4].try_into()?)
                            as usize;
                    result = Some(kv_pair[4 + key_len + 4..4 + key_len + 4 + value_len].to_vec());
                    break;
                }
            }

            self.bpm.unpin_page(self.page_id, false).await?;
            Ok(result)
        }
    }

    fn set(&self, key: &[u8], value: &[u8]) -> impl std::future::Future<Output = Result<()>> + Send {
        async move {
            // 1. Create Log Entry
            let mut log_entry = Vec::new();
            log_entry.push(1u8); // OpCode for SET
            log_entry.extend_from_slice(&(key.len() as u32).to_be_bytes());
            log_entry.extend_from_slice(key);
            log_entry.extend_from_slice(&(value.len() as u32).to_be_bytes());
            log_entry.extend_from_slice(value);

            // 2. Append to WAL
            self.wal.append(&log_entry).await?;

            let page_ref = self.bpm.fetch_page(self.page_id).await?;
            let mut page_w = page_ref.write().await;

            // This is a very simplified implementation. It does not handle updates
            // or fragmentation. It just appends the new KV pair.
            // A real implementation would be much more complex.

            let num_slots = u32::from_be_bytes(page_w.data[0..4].try_into()?) as usize;

            // Calculate where the new data will start.
            let data_start_offset = if num_slots > 0 {
                // Find the end of the last written KV pair.
                let mut max_offset = SLOTS_COUNT_HEADER_SIZE;
                for i in 0..num_slots {
                    let slot_offset = PAGE_DATA_SIZE - (i + 1) * SLOT_ENTRY_SIZE;
                    let offset =
                        u32::from_be_bytes(page_w.data[slot_offset..slot_offset + 4].try_into()?)
                            as usize;
                    let size = u32::from_be_bytes(
                        page_w.data[slot_offset + 4..slot_offset + 8].try_into()?,
                    ) as usize;
                    if offset + size > max_offset {
                        max_offset = offset + size;
                    }
                }
                max_offset
            } else {
                SLOTS_COUNT_HEADER_SIZE
            };

            let kv_pair_size = 4 + key.len() + 4 + value.len();

            // Check for available space
            let free_space_end = PAGE_DATA_SIZE - (num_slots + 1) * SLOT_ENTRY_SIZE;
            if data_start_offset + kv_pair_size > free_space_end {
                self.bpm.unpin_page(self.page_id, false).await?;
                bail!("Page is full. Cannot insert new key-value pair.");
            }

            // Write the KV pair: [key_len, key, value_len, value]
            let mut buffer = Vec::with_capacity(kv_pair_size);
            buffer.extend_from_slice(&(key.len() as u32).to_be_bytes());
            buffer.extend_from_slice(key);
            buffer.extend_from_slice(&(value.len() as u32).to_be_bytes());
            buffer.extend_from_slice(value);
            page_w.data[data_start_offset..data_start_offset + kv_pair_size]
                .copy_from_slice(&buffer);

            // Add the new slot
            let new_slot_offset = PAGE_DATA_SIZE - (num_slots + 1) * SLOT_ENTRY_SIZE;
            page_w.data[new_slot_offset..new_slot_offset + 4]
                .copy_from_slice(&(data_start_offset as u32).to_be_bytes());
            page_w.data[new_slot_offset + 4..new_slot_offset + 8]
                .copy_from_slice(&(kv_pair_size as u32).to_be_bytes());

            // Update slot count
            page_w.data[0..4].copy_from_slice(&((num_slots + 1) as u32).to_be_bytes());

            // Unpin as dirty
            self.bpm.unpin_page(self.page_id, true).await?;

            Ok(())
        }
    }

    fn delete(&self, key: &[u8]) -> impl std::future::Future<Output = Result<()>> + Send {
        async move {
            // 1. Create Log Entry
            let mut log_entry = Vec::new();
            log_entry.push(2u8); // OpCode for DELETE
            log_entry.extend_from_slice(&(key.len() as u32).to_be_bytes());
            log_entry.extend_from_slice(key);

            // 2. Append to WAL
            self.wal.append(&log_entry).await?;

            let page_ref = self.bpm.fetch_page(self.page_id).await?;
            let mut page_w = page_ref.write().await;

            let num_slots = u32::from_be_bytes(page_w.data[0..4].try_into()?) as usize;
            let mut modified = false;

            for i in 0..num_slots {
                let slot_offset = PAGE_DATA_SIZE - (i + 1) * SLOT_ENTRY_SIZE;
                let offset =
                    u32::from_be_bytes(page_w.data[slot_offset..slot_offset + 4].try_into()?)
                        as usize;
                let size =
                    u32::from_be_bytes(page_w.data[slot_offset + 4..slot_offset + 8].try_into()?)
                        as usize;

                if size == 0 {
                    continue;
                }

                let kv_pair = &page_w.data[offset..offset + size];
                let key_len = u32::from_be_bytes(kv_pair[0..4].try_into()?) as usize;

                if &kv_pair[4..4 + key_len] == key {
                    // Mark slot as empty by setting size to 0.
                    // This leaves garbage but is simple. A real system would need compaction.
                    page_w.data[slot_offset + 4..slot_offset + 8]
                        .copy_from_slice(&0u32.to_be_bytes());
                    modified = true;
                    break;
                }
            }

            self.bpm.unpin_page(self.page_id, modified).await?;

            Ok(())
        }
    }
}
