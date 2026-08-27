//! `lsm` module
//!
//! Log-Structured Merge-Tree storage engine with MVCC, leveled compaction,
//! and a background Value Log garbage collector (Janitor).

pub mod block_cache;
pub mod key;
pub mod memtable;
pub mod engine;
pub mod reader;
pub mod levels;
pub mod compaction;
pub mod hlc;
pub mod janitor;
pub mod watcher;
pub mod domain;
pub mod rate_limiter;

pub use block_cache::{BlockCache, BlockCacheKey, BlockCacheMetrics};
pub use engine::LsmStorageEngine;
pub use key::{InternalKey, Timestamp};
pub use reader::{GetResult, LsmReader, RegistrySnapshot, Snapshot, SnapshotRegistry, ValueWithMetadata, VersionedEntry};
pub use levels::LevelManager;
pub use compaction::{CompactionConfig, CompactionJob};
pub use janitor::{Janitor, JanitorConfig};
pub use watcher::{OpType, WalEvent};
pub use domain::{Domain, DomainPurger, DomainRegistry, DomainState, DomainStore, KeyMeta};
pub use rate_limiter::{DomainQuota, RateLimiter, TokenBucket};
