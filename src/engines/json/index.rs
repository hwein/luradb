//! Index definitions and management for the JSON store (spec json/004).
//!
//! An index definition declares *which* field of a domain gets indexed;
//! writing the actual `IDX:` entries happens on the write path (spec 005).

use super::domain::JsonDomainRegistry;
use super::error::JsonStoreError;
use crate::engines::lsm::domain::now_secs;
use crate::engines::lsm::engine::{BatchOp, LsmStorageEngine};
use crate::engines::StorageEngine;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

const SYS_INDEX_PREFIX: &[u8] = b"__sys:index:";
const MAX_FIELD_PATH_LEN: usize = 128;
/// Tombstones per `write_batch` when delete_index purges `IDX:` entries.
const DELETE_INDEX_BATCH: usize = 500;

fn sys_index_key(domain: &str, field: &str) -> Vec<u8> {
    let mut k = SYS_INDEX_PREFIX.to_vec();
    k.extend_from_slice(domain.as_bytes());
    k.push(b':');
    k.extend_from_slice(field.as_bytes());
    k
}

fn validate_field_path(field: &str) -> Result<(), JsonStoreError> {
    if field.is_empty() {
        return Err(JsonStoreError::InvalidIndexField(
            "field must not be empty".to_string(),
        ));
    }
    if field.len() > MAX_FIELD_PATH_LEN {
        return Err(JsonStoreError::InvalidIndexField(format!(
            "field length {} exceeds maximum of {} characters",
            field.len(),
            MAX_FIELD_PATH_LEN
        )));
    }
    if field.starts_with('.') || field.ends_with('.') || field.contains("..") {
        return Err(JsonStoreError::InvalidIndexField(format!(
            "field '{}' has empty path segments",
            field
        )));
    }
    if !field
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(JsonStoreError::InvalidIndexField(format!(
            "field '{}' contains invalid characters (only [a-zA-Z0-9._-] allowed)",
            field
        )));
    }
    Ok(())
}

// ── IndexDefinition ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IndexFieldType {
    String,
    Number,
    Boolean,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexDefinition {
    pub field: String,
    pub field_type: IndexFieldType,
    pub domain: String,
    pub created_at: u64,
}

// ── Field extraction & value encoding ─────────────────────────────────────────

/// Resolves `path` (dot notation) against `doc`. `None` if any segment is
/// missing or an intermediate value is not an object.
pub fn extract_field(doc: &Value, path: &str) -> Option<Value> {
    let mut current = doc;
    for segment in path.split('.') {
        current = current.as_object()?.get(segment)?;
    }
    Some(current.clone())
}

/// Encodes a JSON value into a byte representation whose lexicographic order
/// matches the natural order of the type. Returns `None` for null, arrays,
/// objects, and type mismatches — those produce no index entry.
pub fn encode_index_value(value: &Value, field_type: IndexFieldType) -> Option<Vec<u8>> {
    match (field_type, value) {
        (IndexFieldType::String, Value::String(s)) => Some(s.as_bytes().to_vec()),
        (IndexFieldType::Number, Value::Number(n)) => {
            let f = n.as_f64()?;
            // Canonicalize -0.0 → +0.0: equal values must share one key,
            // queries compare the encodings byte-wise.
            let f = if f == 0.0 { 0.0 } else { f };
            // IEEE-754 total-order trick: flip all bits for negatives, flip
            // only the sign bit for positives — big-endian bytes then sort
            // like the underlying numbers.
            let bits = f.to_bits();
            let sortable = if bits & 0x8000_0000_0000_0000 != 0 {
                !bits
            } else {
                bits ^ 0x8000_0000_0000_0000
            };
            Some(sortable.to_be_bytes().to_vec())
        }
        (IndexFieldType::Boolean, Value::Bool(b)) => Some(vec![u8::from(*b)]),
        _ => None,
    }
}

// ── Index LSM keys (spec json/005) ────────────────────────────────────────────

pub(crate) const IDX_PREFIX: &[u8] = b"IDX:";

/// Scan prefix for ALL index entries of a domain: `IDX:{prefix}:`.
pub fn index_domain_prefix(domain_prefix: &[u8]) -> Vec<u8> {
    let mut k = IDX_PREFIX.to_vec();
    k.extend_from_slice(domain_prefix);
    k.push(b':');
    k
}

/// Scan prefix for all entries of one indexed field: `IDX:{prefix}:{field}:`.
pub fn index_field_prefix(domain_prefix: &[u8], field: &str) -> Vec<u8> {
    let mut k = IDX_PREFIX.to_vec();
    k.extend_from_slice(domain_prefix);
    k.push(b':');
    k.extend_from_slice(field.as_bytes());
    k.push(b':');
    k
}

/// Scan prefix for one exact field value: `IDX:{prefix}:{field}:{value}:`.
pub fn index_scan_prefix(domain_prefix: &[u8], field: &str, encoded_value: &[u8]) -> Vec<u8> {
    let mut k = index_field_prefix(domain_prefix, field);
    k.extend_from_slice(encoded_value);
    k.push(b':');
    k
}

/// Full index entry key: `IDX:{prefix}:{field}:{value}:{document_key}`.
pub fn index_key(
    domain_prefix: &[u8],
    field: &str,
    encoded_value: &[u8],
    document_key: &str,
) -> Vec<u8> {
    let mut k = index_scan_prefix(domain_prefix, field, encoded_value);
    k.extend_from_slice(document_key.as_bytes());
    k
}

/// Splits an index key into `(domain_prefix, field, value_bytes, document_key)`.
///
/// The value may contain `:` bytes (raw number encodings, string values), so
/// the document key is taken from the RIGHT — it is validated colon-free.
pub fn parse_index_key(lsm_key: &[u8]) -> Option<(String, String, Vec<u8>, String)> {
    let rest = lsm_key.strip_prefix(IDX_PREFIX)?;
    let p1 = rest.iter().position(|&b| b == b':')?;
    let domain_prefix = std::str::from_utf8(&rest[..p1]).ok()?;
    let rest = &rest[p1 + 1..];
    let p2 = rest.iter().position(|&b| b == b':')?;
    let field = std::str::from_utf8(&rest[..p2]).ok()?;
    let rest = &rest[p2 + 1..];
    let p3 = rest.iter().rposition(|&b| b == b':')?;
    let value = rest[..p3].to_vec();
    let document_key = std::str::from_utf8(&rest[p3 + 1..]).ok()?;
    Some((
        domain_prefix.to_string(),
        field.to_string(),
        value,
        document_key.to_string(),
    ))
}

// ── IndexRegistry ─────────────────────────────────────────────────────────────

/// Manages index definitions per domain (in-memory cache + LSM persistence).
pub struct IndexRegistry {
    /// Domain name → definitions. Read on every document write (spec 005).
    indexes: RwLock<HashMap<String, Vec<IndexDefinition>>>,
    engine: Arc<LsmStorageEngine>,
    /// Serializes index DDL (create/delete/purge) — check-then-act spans an
    /// await (general/003).
    ddl_lock: Mutex<()>,
}

impl IndexRegistry {
    /// Loads all persisted index definitions into the cache.
    pub async fn recover(engine: Arc<LsmStorageEngine>) -> anyhow::Result<Self> {
        let keys = engine.scan_keys(SYS_INDEX_PREFIX).await?;
        let mut cache: HashMap<String, Vec<IndexDefinition>> = HashMap::new();
        for key in keys {
            if let Some(bytes) = engine.get(&key).await? {
                match serde_json::from_slice::<IndexDefinition>(&bytes) {
                    Ok(def) => cache.entry(def.domain.clone()).or_default().push(def),
                    Err(e) => tracing::warn!(
                        "[IndexRegistry] cannot deserialize index at key {:?}: {e}",
                        key
                    ),
                }
            }
        }
        Ok(Self {
            indexes: RwLock::new(cache),
            engine,
            ddl_lock: Mutex::new(()),
        })
    }

    /// Creates an index definition. The domain state is checked under the DDL
    /// lock so a concurrent delete_domain+purge cannot leave a ghost definition.
    pub async fn create_index(
        &self,
        domains: &JsonDomainRegistry,
        domain: &str,
        field: &str,
        field_type: IndexFieldType,
    ) -> Result<IndexDefinition, JsonStoreError> {
        validate_field_path(field)?;
        let _guard = self.ddl_lock.lock().await;
        domains.require_active(domain)?;
        if self
            .indexes
            .read()
            .get(domain)
            .is_some_and(|defs| defs.iter().any(|d| d.field == field))
        {
            return Err(JsonStoreError::IndexAlreadyExists {
                domain: domain.to_string(),
                field: field.to_string(),
            });
        }
        let def = IndexDefinition {
            field: field.to_string(),
            field_type,
            domain: domain.to_string(),
            created_at: now_secs(),
        };
        let data = serde_json::to_vec(&def)?;
        self.engine.put(&sys_index_key(domain, field), &data).await?;
        self.indexes
            .write()
            .entry(domain.to_string())
            .or_default()
            .push(def.clone());
        Ok(def)
    }

    /// All index definitions of a domain (fast in-memory lookup).
    pub fn get_indexes(&self, domain: &str) -> Vec<IndexDefinition> {
        self.indexes.read().get(domain).cloned().unwrap_or_default()
    }

    /// Removes ALL index definitions of a domain — persistence and cache.
    /// Used by the domain purger (spec json/013).
    pub(crate) async fn purge_domain_definitions(&self, domain: &str) -> Result<(), JsonStoreError> {
        let _guard = self.ddl_lock.lock().await;
        let mut prefix = SYS_INDEX_PREFIX.to_vec();
        prefix.extend_from_slice(domain.as_bytes());
        prefix.push(b':');
        for key in self.engine.scan_keys(&prefix).await? {
            self.engine.delete(&key).await?;
        }
        self.indexes.write().remove(domain);
        Ok(())
    }

    /// Removes an index definition and tombstones all `IDX:` entries of the
    /// field — otherwise a re-created index would serve stale values.
    pub async fn delete_index(
        &self,
        domains: &JsonDomainRegistry,
        domain: &str,
        field: &str,
    ) -> Result<(), JsonStoreError> {
        let _guard = self.ddl_lock.lock().await;
        let dom = domains.require_active(domain)?;
        if !self
            .indexes
            .read()
            .get(domain)
            .is_some_and(|defs| defs.iter().any(|d| d.field == field))
        {
            return Err(JsonStoreError::IndexNotFound {
                domain: domain.to_string(),
                field: field.to_string(),
            });
        }
        // Definition first, so writers stop maintaining the index immediately.
        self.engine.delete(&sys_index_key(domain, field)).await?;
        if let Some(defs) = self.indexes.write().get_mut(domain) {
            defs.retain(|d| d.field != field);
        }
        let entries = self
            .engine
            .scan_keys(&index_field_prefix(&dom.system_prefix, field))
            .await?;
        for chunk in entries.chunks(DELETE_INDEX_BATCH) {
            let ops: Vec<BatchOp> = chunk
                .iter()
                .map(|key| BatchOp::Delete { key: key.clone() })
                .collect();
            self.engine.write_batch(ops).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // 1. extract_field with a top-level field.
    #[test]
    fn test_extract_top_level_field() {
        let doc = json!({"city": "Berlin", "age": 30});
        assert_eq!(extract_field(&doc, "city"), Some(json!("Berlin")));
    }

    // 2. extract_field with dot notation.
    #[test]
    fn test_extract_nested_field() {
        let doc = json!({"address": {"city": "Berlin", "geo": {"lat": 52.5}}});
        assert_eq!(extract_field(&doc, "address.city"), Some(json!("Berlin")));
        assert_eq!(extract_field(&doc, "address.geo.lat"), Some(json!(52.5)));
    }

    // 3. extract_field with missing path or non-object intermediate → None.
    #[test]
    fn test_extract_missing_path() {
        let doc = json!({"a": {"b": 1}, "s": "str"});
        assert_eq!(extract_field(&doc, "a.x"), None);
        assert_eq!(extract_field(&doc, "nope"), None);
        assert_eq!(extract_field(&doc, "s.deeper"), None);
    }

    // 4. Encoding: strings, booleans, numbers; unsupported values → None.
    #[test]
    fn test_encode_index_values() {
        assert_eq!(
            encode_index_value(&json!("abc"), IndexFieldType::String),
            Some(b"abc".to_vec())
        );
        assert_eq!(
            encode_index_value(&json!(false), IndexFieldType::Boolean),
            Some(vec![0x00])
        );
        assert_eq!(
            encode_index_value(&json!(true), IndexFieldType::Boolean),
            Some(vec![0x01])
        );
        assert_eq!(encode_index_value(&json!(null), IndexFieldType::String), None);
        assert_eq!(encode_index_value(&json!([1, 2]), IndexFieldType::Number), None);
        assert_eq!(encode_index_value(&json!({"a": 1}), IndexFieldType::String), None);
        // Type mismatch produces no entry.
        assert_eq!(encode_index_value(&json!("abc"), IndexFieldType::Number), None);
    }

    // 5. Number encoding sorts lexicographically like the numbers themselves.
    #[test]
    fn test_number_encoding_is_sortable() {
        let enc = |v: f64| encode_index_value(&json!(v), IndexFieldType::Number).unwrap();
        assert!(enc(-100.0) < enc(-1.5));
        assert!(enc(-1.5) < enc(0.0));
        assert!(enc(0.0) < enc(1.0));
        assert!(enc(1.0) < enc(1.5));
        assert!(enc(1.5) < enc(2.0));
        assert!(enc(2.0) < enc(1000.0));
    }

    // 5b. -0.0, 0 and 0.0 are numerically equal and must encode identically
    //     (regression: -0.0 got its own key → false query results around 0).
    #[test]
    fn test_negative_zero_encodes_like_zero() {
        let enc = |v: serde_json::Value| encode_index_value(&v, IndexFieldType::Number).unwrap();
        assert_eq!(enc(json!(-0.0)), enc(json!(0.0)));
        assert_eq!(enc(json!(-0.0)), enc(json!(0)));
    }

    // 6. Index key construction and parsing roundtrip, incl. ':' in values.
    #[test]
    fn test_index_key_roundtrip() {
        let key = index_key(b"00c0ffee00c0ffee", "city", b"Ess:en", "doc-1");
        assert_eq!(key, b"IDX:00c0ffee00c0ffee:city:Ess:en:doc-1".to_vec());
        let (prefix, field, value, doc_key) = parse_index_key(&key).unwrap();
        assert_eq!(prefix, "00c0ffee00c0ffee");
        assert_eq!(field, "city");
        assert_eq!(value, b"Ess:en".to_vec());
        assert_eq!(doc_key, "doc-1");
        assert!(parse_index_key(b"DOC:x:y").is_none());
    }

    // 7. Field path validation.
    #[test]
    fn test_validate_field_path() {
        assert!(validate_field_path("city").is_ok());
        assert!(validate_field_path("address.city").is_ok());
        assert!(validate_field_path("user_name-x").is_ok());
        assert!(validate_field_path("").is_err());
        assert!(validate_field_path(".leading").is_err());
        assert!(validate_field_path("trailing.").is_err());
        assert!(validate_field_path("a..b").is_err());
        assert!(validate_field_path("a:b").is_err());
        assert!(validate_field_path("a b").is_err());
        assert!(validate_field_path(&"a".repeat(MAX_FIELD_PATH_LEN)).is_ok());
        assert!(validate_field_path(&"a".repeat(MAX_FIELD_PATH_LEN + 1)).is_err());
    }
}
