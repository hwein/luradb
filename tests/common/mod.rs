use luradb::config::StorageConfig;
use luradb::core::storage_thread::{
    StorageHandle, StorageThread, StorageThreadConfig, WalTarget, RING_DEPTH, SQPOLL_IDLE_MS, STORAGE_THREAD_CPU,
};
use std::path::Path;

/// A storage hub without SQPOLL that writes the WAL of each engine at its path.
pub fn start_hub(wals: &[(WalTarget, &Path)]) -> (StorageThread, StorageHandle) {
    let config = StorageThreadConfig {
        sqpoll_enabled: false,
        sqpoll_idle_ms: SQPOLL_IDLE_MS,
        ring_depth: RING_DEPTH,
        channel_capacity: StorageConfig::default().wal_queue_capacity,
        cpu: STORAGE_THREAD_CPU,
    };
    let wals = wals.iter().map(|(target, path)| (*target, path.to_path_buf())).collect();
    StorageThread::new(config, wals).expect("storage hub")
}
