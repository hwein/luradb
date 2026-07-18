//! `buffer_pool` module
//!
//! The `BufferPoolManager` is responsible for fetching database pages from disk
//! and caching them in memory. It allows multiple threads to safely access and
//! modify pages and handles the eviction of old pages when the buffer pool is full.

use super::disk_manager::DiskManager;
use super::page::{Page, PageId};
use super::replacer::{ClockReplacer, FrameId, Replacer};

use anyhow::{bail, Result};
use dashmap::DashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

/// A reference-counted, thread-safe handle to a page.
/// When a client acquires a `PageRef`, the corresponding frame in the buffer
/// pool is "pinned" and cannot be evicted. The pin is released when the `PageRef`
/// and all of its clones are dropped.
///
/// This implementation is simplified. A real implementation would use a custom
/// Guard that automatically unpins on drop. For now, clients must call
/// `unpin_page` manually.
pub type PageRef = Arc<RwLock<Page>>;

/// Represents a single frame in the buffer pool.
struct Frame {
    /// The actual page data, protected by a `RwLock` for concurrent access.
    page: PageRef,
    /// The number of clients currently using this page. A frame cannot be
    /// evicted if its pin count is greater than zero.
    pin_count: AtomicUsize,
    /// True if the page has been modified since being read from disk.
    is_dirty: AtomicBool,
}

impl Frame {
    fn new() -> Self {
        Self {
            page: Arc::new(RwLock::new(Page::default())),
            pin_count: AtomicUsize::new(0),
            is_dirty: AtomicBool::new(false),
        }
    }
}

/// The `BufferPoolManager` orchestrates the movement of pages between
/// disk and the in-memory buffer pool.
pub struct BufferPoolManager {
    /// The collection of frames that make up the buffer pool.
    frames: Vec<Frame>,
    /// The disk manager to read from and write to the underlying database file.
    disk_manager: DiskManager,
    /// The page replacement algorithm (e.g., Clock-R).
    replacer: Mutex<ClockReplacer>,
    /// A map from `PageId` to the `FrameId` where the page is stored.
    page_table: DashMap<PageId, FrameId>,
    /// A list of frame IDs that are currently unoccupied.
    free_list: Mutex<Vec<FrameId>>,
}

// A convenient alias for the BufferPoolManager wrapped in an Arc.
pub type BufferPool = Arc<BufferPoolManager>;

impl BufferPoolManager {
    /// Creates a new `BufferPoolManager`.
    pub fn new(pool_size: usize, disk_manager: DiskManager) -> Self {
        let mut free_list = Vec::with_capacity(pool_size);
        let mut frames = Vec::with_capacity(pool_size);
        for i in 0..pool_size {
            frames.push(Frame::new());
            free_list.push(i);
        }

        Self {
            frames,
            disk_manager,
            replacer: Mutex::new(ClockReplacer::new(pool_size)),
            page_table: DashMap::new(),
            free_list: Mutex::new(free_list),
        }
    }

    /// Fetches a page from the buffer pool, loading it from disk if necessary.
    pub async fn fetch_page(&self, page_id: PageId) -> Result<PageRef> {
        if let Some(frame_id_ref) = self.page_table.get(&page_id) {
            let frame_id = *frame_id_ref;
            let frame = &self.frames[frame_id];
            frame.pin_count.fetch_add(1, Ordering::SeqCst);
            self.replacer.lock().await.pin(frame_id);
            return Ok(Arc::clone(&frame.page));
        }

        let frame_id = self.find_free_frame().await?
            .ok_or_else(|| anyhow::anyhow!("No free frames available and all pages are pinned."))?;

        if let Some((old_page_id, _)) = self.page_table.remove_by_frame_id(&frame_id) {
            self.flush_page_internal(old_page_id, frame_id).await?;
        }

        let frame = &self.frames[frame_id];
        let new_page_data = self.disk_manager.read_page(page_id).await?;
        
        let mut page_guard = frame.page.write().await;
        page_guard.as_mut_bytes().copy_from_slice(new_page_data.as_bytes());
        
        frame.is_dirty.store(false, Ordering::SeqCst);
        frame.pin_count.store(1, Ordering::SeqCst);
        self.replacer.lock().await.pin(frame_id);
        self.page_table.insert(page_id, frame_id);
        
        Ok(Arc::clone(&frame.page))
    }
    
    /// Unpins a page, making it a candidate for eviction if its pin count becomes zero.
    pub async fn unpin_page(&self, page_id: PageId, is_dirty: bool) -> Result<()> {
        let frame_id = self.page_table.get(&page_id)
            .map(|r| *r)
            .ok_or_else(|| anyhow::anyhow!("Page {} not found in buffer pool", page_id))?;
            
        let frame = &self.frames[frame_id];

        if is_dirty {
            frame.is_dirty.store(true, Ordering::SeqCst);
        }

        if frame.pin_count.fetch_sub(1, Ordering::SeqCst) == 0 {
             bail!("Unpinning a page with a pin count of 0 is not allowed: {}", page_id);
        }

        if frame.pin_count.load(Ordering::SeqCst) == 0 {
            self.replacer.lock().await.unpin(frame_id);
        }

        Ok(())
    }

    /// Creates a new page, allocating it on disk and loading it into the buffer pool.
    pub async fn new_page(&self) -> Result<(PageId, PageRef)> {
        let frame_id = self.find_free_frame().await?
            .ok_or_else(|| anyhow::anyhow!("No free frames available and all pages are pinned."))?;
        
        if let Some((old_page_id, _)) = self.page_table.remove_by_frame_id(&frame_id) {
            self.flush_page_internal(old_page_id, frame_id).await?;
        }
        
        let new_page_id = self.disk_manager.allocate_page();

        let frame = &self.frames[frame_id];
        frame.pin_count.store(1, Ordering::SeqCst);
        frame.is_dirty.store(true, Ordering::SeqCst);
        
        let mut page_guard = frame.page.write().await;
        page_guard.as_mut_bytes().fill(0);
        page_guard.header.page_id = new_page_id; // Set page ID in header

        self.replacer.lock().await.pin(frame_id);
        self.page_table.insert(new_page_id, frame_id);

        Ok((new_page_id, Arc::clone(&frame.page)))
    }

    /// Flushes a specific page to disk if it is dirty.
    pub async fn flush_page(&self, page_id: PageId) -> Result<()> {
        let frame_id = self.page_table.get(&page_id)
            .map(|r| *r)
            .ok_or_else(|| anyhow::anyhow!("Page {} not found in buffer pool", page_id))?;
            
        self.flush_page_internal(page_id, frame_id).await
    }

    /// Flushes all dirty pages in the buffer pool to disk.
    pub async fn flush_all_pages(&self) -> Result<()> {
        // Collect page IDs to avoid holding the iter while awaiting.
        let page_ids: Vec<(PageId, FrameId)> = self.page_table.iter().map(|item| (*item.key(), *item.value())).collect();
        for (page_id, frame_id) in page_ids {
            self.flush_page_internal(page_id, frame_id).await?;
        }
        Ok(())
    }
    
    /// Helper to find a free frame, either from the free list or by evicting one.
    async fn find_free_frame(&self) -> Result<Option<FrameId>> {
        if let Some(frame_id) = self.free_list.lock().await.pop() {
            return Ok(Some(frame_id));
        }
        Ok(self.replacer.lock().await.victim())
    }
    
    /// Internal helper to flush a page given its FrameId.
    async fn flush_page_internal(&self, page_id: PageId, frame_id: FrameId) -> Result<()> {
        let frame = &self.frames[frame_id];
        
        if frame.is_dirty.load(Ordering::SeqCst) {
            let page_copy = {
                let mut page_guard = frame.page.write().await;
                page_guard.header.page_id = page_id;
                page_guard.update_checksum();
                *page_guard
            };

            self.disk_manager.write_page(page_id, &page_copy).await?;
            
            frame.is_dirty.store(false, Ordering::SeqCst);
        }
        Ok(())
    }
}

/// Extension trait to allow removing a value from DashMap and getting the FrameId.
trait RemoveByFrameId<K, V> {
    fn remove_by_frame_id(&self, value_to_find: &V) -> Option<(K, V)>;
}

impl<K, V> RemoveByFrameId<K, V> for DashMap<K, V>
where
    K: Eq + std::hash::Hash + Clone,
    V: Eq + Clone,
{
    fn remove_by_frame_id(&self, value_to_find: &V) -> Option<(K, V)> {
        let key_to_remove = self.iter()
            .find(|entry| entry.value() == value_to_find)
            .map(|entry| entry.key().clone());

        if let Some(key) = key_to_remove {
            self.remove(&key)
        } else {
            None
        }
    }
}

impl Drop for BufferPoolManager {
    fn drop(&mut self) {
        // Note: This runs in a synchronous context. Using block_on is a pragmatic
        // choice here for shutdown logic, but in general, blocking on async code
        // in a sync context can be problematic.
        futures::executor::block_on(async {
            if let Err(e) = self.flush_all_pages().await {
                eprintln!("Failed to flush all pages on shutdown: {}", e);
            }
        });
    }
}
