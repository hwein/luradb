//! Document model and LSM key mapping for the JSON store.
//!
//! Blob-storage pattern (spec json/002): the whole document is serialized
//! under the composite LSM key `DOC:{domain}:{key}`; the LSM layer treats
//! the payload as opaque bytes.

use super::error::JsonStoreError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(crate) const DOC_PREFIX: &[u8] = b"DOC:";

/// Fixed composite-key overhead of [`doc_key`]: `DOC:` + 16-hex system
/// prefix (json/003) + `:`.
pub(crate) const DOC_KEY_OVERHEAD: usize = DOC_PREFIX.len() + 16 + 1;

/// A JSON document as returned by the engine (transport object).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    pub key: String,
    pub domain: String,
    pub content: Value,
    pub version: u64,
    /// Random incarnation id: fresh on create, stable across updates, so
    /// stale ETags never match a recreated document (OCC/ABA, json/011).
    /// 0 = legacy data written before this field existed.
    #[serde(default)]
    pub generation: u64,
}

/// Persisted payload — key and domain live in the LSM key, not the value.
#[derive(Serialize, Deserialize)]
pub(crate) struct StoredDocument {
    pub version: u64,
    /// See [`Document::generation`]; default keeps legacy payloads readable.
    #[serde(default)]
    pub generation: u64,
    pub content: Value,
}

/// Expected incarnation + version for OCC checks (`If-Match`, json/011).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedVersion {
    pub generation: u64,
    pub version: u64,
}

/// Canonical ETag value (without quotes): `{generation:x}-{version}`.
/// Opaque to clients; unique per document incarnation.
pub fn etag_value(generation: u64, version: u64) -> String {
    format!("{generation:x}-{version}")
}

/// Random incarnation id for newly created documents.
pub(crate) fn new_generation() -> u64 {
    rand::random()
}

/// Builds the composite LSM key `DOC:{system_prefix}:{key}`. The prefix is
/// the domain's colon-free hex prefix, not the user-facing name (json/003).
pub fn doc_key(system_prefix: &[u8], key: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(DOC_PREFIX.len() + system_prefix.len() + 1 + key.len());
    k.extend_from_slice(DOC_PREFIX);
    k.extend_from_slice(system_prefix);
    k.push(b':');
    k.extend_from_slice(key.as_bytes());
    k
}

/// Scan prefix for all documents of a domain: `DOC:{system_prefix}:`.
pub fn doc_scan_prefix(system_prefix: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(DOC_PREFIX.len() + system_prefix.len() + 1);
    k.extend_from_slice(DOC_PREFIX);
    k.extend_from_slice(system_prefix);
    k.push(b':');
    k
}

/// Extracts `(system_prefix, document_key)` from a composite LSM key.
pub fn parse_doc_key(lsm_key: &[u8]) -> Option<(String, String)> {
    let rest = lsm_key.strip_prefix(DOC_PREFIX)?;
    let sep = rest.iter().position(|&b| b == b':')?;
    let prefix = std::str::from_utf8(&rest[..sep]).ok()?;
    let key = std::str::from_utf8(&rest[sep + 1..]).ok()?;
    Some((prefix.to_string(), key.to_string()))
}

/// Colons are forbidden because `:` separates the LSM-key segments.
pub(crate) fn validate_document_key(key: &str, max_len: usize) -> Result<(), JsonStoreError> {
    if key.is_empty() {
        return Err(JsonStoreError::InvalidKey("key must not be empty".to_string()));
    }
    if key.len() > max_len {
        return Err(JsonStoreError::InvalidKey(format!(
            "key length {} exceeds maximum of {} characters",
            key.len(),
            max_len
        )));
    }
    if !key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(JsonStoreError::InvalidKey(format!(
            "key '{}' contains invalid characters (only [a-zA-Z0-9._-] allowed)",
            key
        )));
    }
    Ok(())
}

/// Generates a random UUIDv4 string using the existing `rand` + `hex` crates.
pub(crate) fn generate_uuid_v4() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{}-{}-{}-{}-{}",
        hex::encode(&b[0..4]),
        hex::encode(&b[4..6]),
        hex::encode(&b[6..8]),
        hex::encode(&b[8..10]),
        hex::encode(&b[10..16]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // 1. doc_key/parse_doc_key roundtrip.
    #[test]
    fn test_doc_key_roundtrip() {
        let lsm_key = doc_key(b"00c0ffee00c0ffee", "customer-42");
        assert_eq!(lsm_key, b"DOC:00c0ffee00c0ffee:customer-42".to_vec());
        let parsed = parse_doc_key(&lsm_key);
        assert_eq!(
            parsed,
            Some(("00c0ffee00c0ffee".to_string(), "customer-42".to_string()))
        );
    }

    // 2. parse_doc_key rejects foreign keys.
    #[test]
    fn test_parse_doc_key_rejects_non_doc_keys() {
        assert_eq!(parse_doc_key(b"IDX:shop:x"), None);
        assert_eq!(parse_doc_key(b"DOC:no-separator"), None);
    }

    // 3. Legacy payloads without generation deserialize with generation 0.
    #[test]
    fn test_stored_document_legacy_default_generation() {
        let stored: StoredDocument =
            serde_json::from_str(r#"{"version": 3, "content": {"a": 1}}"#).unwrap();
        assert_eq!(stored.generation, 0);
        assert_eq!(stored.version, 3);
    }

    // 4. ETag value format: hex generation, decimal version.
    #[test]
    fn test_etag_value_format() {
        assert_eq!(etag_value(0x00c0_ffee, 7), "c0ffee-7");
        assert_eq!(etag_value(0, 1), "0-1");
    }
}
