use luradb::core::storage_thread::{
    StorageHandle, StorageThread, StorageThreadConfig, WalTarget, REQUEST_CHANNEL_CAPACITY, RING_DEPTH,
    SQPOLL_IDLE_MS, STORAGE_THREAD_CPU,
};
use std::path::Path;

/// A storage hub without SQPOLL that writes the key-value WAL at `wal_path`.
pub fn start_kv_hub(wal_path: &Path) -> (StorageThread, StorageHandle) {
    let config = StorageThreadConfig {
        sqpoll_enabled: false,
        sqpoll_idle_ms: SQPOLL_IDLE_MS,
        ring_depth: RING_DEPTH,
        channel_capacity: REQUEST_CHANNEL_CAPACITY,
        cpu: STORAGE_THREAD_CPU,
    };
    StorageThread::new(config, vec![(WalTarget::Kv, wal_path.to_path_buf())]).expect("storage hub")
}
