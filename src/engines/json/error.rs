//! Error types for the JSON store.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum JsonStoreError {
    #[error("document '{key}' not found in domain '{domain}'")]
    DocumentNotFound { domain: String, key: String },
    #[error("domain '{0}' not found")]
    DomainNotFound(String),
    #[error("domain '{0}' is being deleted")]
    DomainDeleting(String),
    #[error("domain '{0}' already exists")]
    DomainAlreadyExists(String),
    #[error("invalid domain name: {0}")]
    InvalidDomainName(String),
    #[error("index on field '{field}' already exists in domain '{domain}'")]
    IndexAlreadyExists { domain: String, field: String },
    #[error("no index on field '{field}' in domain '{domain}'")]
    IndexNotFound { domain: String, field: String },
    #[error("invalid index field: {0}")]
    InvalidIndexField(String),
    #[error("invalid filter: {0}")]
    InvalidFilter(String),
    #[error("re-index already running for domain '{domain}' (task {task_id})")]
    ReindexInProgress { domain: String, task_id: String },
    /// Both fields carry ETag values (`{generation:x}-{version}`, json/011).
    #[error("version conflict: expected \"{expected}\", actual \"{actual}\"")]
    VersionConflict { expected: String, actual: String },
    #[error("invalid document key: {0}")]
    InvalidKey(String),
    #[error("payload of {size} bytes exceeds maximum of {max} bytes")]
    PayloadTooLarge { size: usize, max: usize },
    #[error("serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("storage error: {0}")]
    StorageError(#[from] anyhow::Error),
}
