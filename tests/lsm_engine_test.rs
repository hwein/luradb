mod common;

use luradb::core::storage_thread::WalTarget;
use luradb::core::wal::WriteAheadLog;
use luradb::engines::lsm::LsmStorageEngine;
use luradb::engines::lsm::engine::LsmEngineOptions;
use luradb::engines::StorageEngine;
use luradb::storage::file_manager::FileManager;
use luradb::storage::manifest::ManifestManager;
use luradb::storage::vlog::VLog;
use std::sync::Arc;
use tempfile::tempdir;

#[test]
fn test_lsm_engine_writes_and_reads() {
    luradb::core::engine_runtime::block_on(async {
        let dir = tempdir().unwrap();
        let wal_path = dir.path().join("test.wal");
        let vlog_path = dir.path().join("test.vlog");

        let (_hub, handle) = common::start_hub(&[(WalTarget::Kv, &wal_path)]);
        let wal = Arc::new(WriteAheadLog::with_storage_handle(handle, WalTarget::Kv));
        let vlog = Arc::new(VLog::new(&vlog_path).await.unwrap());
        let file_manager = Arc::new(FileManager::new(dir.path()).await.unwrap());
        let manifest_manager = Arc::new(ManifestManager::new(dir.path()));
        let engine = LsmStorageEngine::new(
            wal, wal_path.clone(), vlog, vlog_path, file_manager, manifest_manager,
            LsmEngineOptions::default(),
        )
        .await
        .unwrap();

        // Write 10,000 entries
        for i in 0..10000 {
            let key = format!("key{}", i);
            let value = format!("value{}", i);
            engine.set(key.as_bytes(), value.as_bytes()).await.unwrap();
        }

        // Verify the WAL's first segment holds more than its header
        let wal_metadata = std::fs::metadata(luradb::core::wal::segment_path(&wal_path, 1)).unwrap();
        assert!(wal_metadata.len() > luradb::core::wal::WAL_HEADER_LEN);

        // Read some entries back
        for i in 0..10000 {
            let key = format!("key{}", i);
            let expected_value = format!("value{}", i);
            let value = engine.get(key.as_bytes()).await.unwrap().unwrap();
            assert_eq!(value, expected_value.as_bytes());
        }

        // Test a large value
        let large_value = vec![0u8; 2048];
        engine.set(b"large_key", &large_value).await.unwrap();
        let retrieved_large_value = engine.get(b"large_key").await.unwrap().unwrap();
        assert_eq!(large_value, retrieved_large_value);

        // Test delete
        engine.delete(b"key10").await.unwrap();
        let deleted_value = engine.get(b"key10").await.unwrap();
        assert!(deleted_value.is_none());
    })
}
