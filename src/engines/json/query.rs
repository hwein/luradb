//! Search & query engine for the JSON store (spec json/006).
//!
//! Filters run exclusively over index entries (no full table scans): an
//! `Eq` filter is a prefix scan on `IDX:{prefix}:{field}:{value}:`, range
//! filters scan the field's entries and compare encoded bytes — the sortable
//! encoding from spec 004 makes byte order equal value order.

use super::document::{doc_scan_prefix, parse_doc_key, Document};
use super::domain::JsonDomain;
use super::error::JsonStoreError;
use super::index::{
    self, encode_index_value, index_field_prefix, index_scan_prefix, IndexDefinition,
};
use super::JsonEngine;
use crate::metrics::EngineKind;
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};

pub const DEFAULT_LIMIT: u32 = 50;
pub const MAX_LIMIT: u32 = 1000;

#[derive(Debug, Clone)]
pub enum FilterCondition {
    Eq(Value),
    Gt(Value),
    Gte(Value),
    Lt(Value),
    Lte(Value),
}

#[derive(Debug, Clone)]
pub struct SearchQuery {
    /// Field name → condition; multiple filters are AND-combined.
    pub filters: HashMap<String, FilterCondition>,
    pub limit: u32,
    pub offset: u32,
}

impl Default for SearchQuery {
    fn default() -> Self {
        Self {
            filters: HashMap::new(),
            limit: DEFAULT_LIMIT,
            offset: 0,
        }
    }
}

#[derive(Debug)]
pub struct SearchResult {
    pub documents: Vec<Document>,
    /// Total matches before offset/limit (for pagination).
    pub total: u64,
    pub offset: u32,
    pub limit: u32,
}

// ── Unfiltered listing (spec json/010) ────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ListOptions {
    pub limit: u32,
    pub offset: u32,
    /// `true` returns only keys — no value loads, no deserialization.
    pub keys_only: bool,
}

impl Default for ListOptions {
    fn default() -> Self {
        Self { limit: DEFAULT_LIMIT, offset: 0, keys_only: false }
    }
}

#[derive(Debug)]
pub struct DocumentListResult {
    /// Loaded documents (empty when `keys_only`).
    pub documents: Vec<Document>,
    /// Document keys of the page (always filled).
    pub keys: Vec<String>,
    /// Total documents in the domain.
    pub total: u64,
    pub offset: u32,
    pub limit: u32,
}

impl JsonEngine {
    /// Executes an indexed search. Every filtered field must have an active
    /// index definition — there is no full-table-scan fallback.
    pub async fn search_documents(
        &self,
        domain: &str,
        query: SearchQuery,
    ) -> Result<SearchResult, JsonStoreError> {
        let start = std::time::Instant::now();
        let dom = self.domains.require_active(domain)?;
        if query.filters.is_empty() {
            return Err(JsonStoreError::InvalidFilter(
                "at least one filter is required (unfiltered listing: spec json/010)".to_string(),
            ));
        }
        let limit = query.limit.min(MAX_LIMIT);
        let defs = self.indexes.get_indexes(&dom.name);

        // Intersect per-filter matches; BTreeSet keeps pagination deterministic.
        let mut matched: Option<BTreeSet<String>> = None;
        for (field, condition) in &query.filters {
            let def = defs.iter().find(|d| &d.field == field).ok_or_else(|| {
                JsonStoreError::IndexNotFound {
                    domain: dom.name.clone(),
                    field: field.clone(),
                }
            })?;
            let keys = self.eval_filter(&dom, def, condition).await?;
            matched = Some(match matched {
                None => keys,
                Some(previous) => previous.intersection(&keys).cloned().collect(),
            });
            if matched.as_ref().is_some_and(|m| m.is_empty()) {
                break;
            }
        }
        let matched = matched.unwrap_or_default();
        let total = matched.len() as u64;

        // Only the requested page is actually fetched.
        let mut documents = Vec::new();
        for key in matched.iter().skip(query.offset as usize).take(limit as usize) {
            if let Some(stored) = self.read_stored(&dom, key).await? {
                documents.push(Document {
                    key: key.clone(),
                    domain: dom.name.clone(),
                    content: stored.content,
                    version: stored.version,
                    generation: stored.generation,
                });
            }
        }
        let result = SearchResult {
            documents,
            total,
            offset: query.offset,
            limit,
        };
        self.metrics.record_engine_read(EngineKind::Json, start.elapsed().as_micros() as u64);
        Ok(result)
    }

    /// Lists documents of a domain without filters or index requirements,
    /// in natural LSM key order.
    pub async fn list_documents(
        &self,
        domain: &str,
        options: ListOptions,
    ) -> Result<DocumentListResult, JsonStoreError> {
        let start = std::time::Instant::now();
        let dom = self.domains.require_active(domain)?;
        let limit = options.limit.min(MAX_LIMIT);
        let lsm_keys = self
            .engine
            .scan_keys(&doc_scan_prefix(&dom.system_prefix))
            .await?;
        let all_keys: Vec<String> = lsm_keys
            .iter()
            .filter_map(|k| parse_doc_key(k).map(|(_, doc_key)| doc_key))
            .collect();
        let total = all_keys.len() as u64;
        let keys: Vec<String> = all_keys
            .into_iter()
            .skip(options.offset as usize)
            .take(limit as usize)
            .collect();
        let mut documents = Vec::new();
        if !options.keys_only {
            for key in &keys {
                if let Some(stored) = self.read_stored(&dom, key).await? {
                    documents.push(Document {
                        key: key.clone(),
                        domain: dom.name.clone(),
                        content: stored.content,
                        version: stored.version,
                        generation: stored.generation,
                    });
                }
            }
        }
        let result = DocumentListResult { documents, keys, total, offset: options.offset, limit };
        self.metrics.record_engine_read(EngineKind::Json, start.elapsed().as_micros() as u64);
        Ok(result)
    }

    /// Counts all documents of a domain (key scan only, no value loads).
    pub async fn count_documents(&self, domain: &str) -> Result<u64, JsonStoreError> {
        let start = std::time::Instant::now();
        let dom = self.domains.require_active(domain)?;
        let keys = self
            .engine
            .scan_keys(&doc_scan_prefix(&dom.system_prefix))
            .await?;
        let count = keys.len() as u64;
        self.metrics.record_engine_read(EngineKind::Json, start.elapsed().as_micros() as u64);
        Ok(count)
    }

    /// Evaluates one filter condition to the set of matching document keys.
    async fn eval_filter(
        &self,
        dom: &JsonDomain,
        def: &IndexDefinition,
        condition: &FilterCondition,
    ) -> Result<BTreeSet<String>, JsonStoreError> {
        let encode = |value: &Value| {
            encode_index_value(value, def.field_type).ok_or_else(|| {
                JsonStoreError::InvalidFilter(format!(
                    "filter value for field '{}' does not match index type {:?}",
                    def.field, def.field_type
                ))
            })
        };
        match condition {
            FilterCondition::Eq(value) => {
                let encoded = encode(value)?;
                self.eval_eq(dom, def, &encoded).await
            }
            FilterCondition::Gt(value)
            | FilterCondition::Gte(value)
            | FilterCondition::Lt(value)
            | FilterCondition::Lte(value) => {
                let bound = encode(value)?;
                self.eval_range(dom, def, condition, &bound).await
            }
        }
    }

    async fn eval_eq(
        &self,
        dom: &JsonDomain,
        def: &IndexDefinition,
        encoded: &[u8],
    ) -> Result<BTreeSet<String>, JsonStoreError> {
        let mut matches = BTreeSet::new();
        let prefix = index_scan_prefix(&dom.system_prefix, &def.field, encoded);
        for lsm_key in self.engine.scan_keys(&prefix).await? {
            let Some((_, _, value_bytes, doc_key)) = index::parse_index_key(&lsm_key) else {
                continue;
            };
            // Exact value check: values may themselves contain ':',
            // so a prefix hit is not automatically an exact match.
            if value_bytes == encoded {
                matches.insert(doc_key);
            }
        }
        Ok(matches)
    }

    async fn eval_range(
        &self,
        dom: &JsonDomain,
        def: &IndexDefinition,
        condition: &FilterCondition,
        bound: &[u8],
    ) -> Result<BTreeSet<String>, JsonStoreError> {
        let mut matches = BTreeSet::new();
        let prefix = index_field_prefix(&dom.system_prefix, &def.field);
        for lsm_key in self.engine.scan_keys(&prefix).await? {
            let Some((_, _, value_bytes, doc_key)) = index::parse_index_key(&lsm_key) else {
                continue;
            };
            if range_matches(condition, &value_bytes, bound) {
                matches.insert(doc_key);
            }
        }
        Ok(matches)
    }
}

fn range_matches(condition: &FilterCondition, value: &[u8], bound: &[u8]) -> bool {
    match condition {
        FilterCondition::Gt(_) => value > bound,
        FilterCondition::Gte(_) => value >= bound,
        FilterCondition::Lt(_) => value < bound,
        FilterCondition::Lte(_) => value <= bound,
        FilterCondition::Eq(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::super::JsonEngine;
    use super::*;
    use crate::config::JsonStoreConfig;
    use serde_json::json;
    use std::sync::Arc;

    async fn make_engine() -> (Arc<JsonEngine>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let config = JsonStoreConfig {
            wal_path: dir.path().join("json.wal").to_string_lossy().into_owned(),
            vlog_path: dir.path().join("json.vlog").to_string_lossy().into_owned(),
            sstable_dir: dir.path().join("json_sstables").to_string_lossy().into_owned(),
            ..JsonStoreConfig::default()
        };
        let metrics = crate::metrics::MetricsStore::new(crate::metrics::MetricsConfig::default());
        let engine = JsonEngine::bootstrap(&config, metrics).await.unwrap();
        (engine, dir)
    }

    fn eq_query(pairs: &[(&str, Value)]) -> SearchQuery {
        SearchQuery {
            filters: pairs
                .iter()
                .map(|(f, v)| (f.to_string(), FilterCondition::Eq(v.clone())))
                .collect(),
            ..Default::default()
        }
    }

    // 1. Eq filter finds all matching documents.
    #[tokio::test]
    async fn test_eq_filter_finds_matches() {
        let (json, _dir) = make_engine().await;
        json.create_index("default", "city", super::super::IndexFieldType::String).await.unwrap();
        json.put_document("default", "a", json!({"city": "Essen"})).await.unwrap();
        json.put_document("default", "b", json!({"city": "Berlin"})).await.unwrap();
        json.put_document("default", "c", json!({"city": "Essen"})).await.unwrap();
        let result = json.search_documents("default", eq_query(&[("city", json!("Essen"))])).await.unwrap();
        assert_eq!(result.total, 2);
        let keys: Vec<&str> = result.documents.iter().map(|d| d.key.as_str()).collect();
        assert_eq!(keys, vec!["a", "c"]);
        assert!(result.documents.iter().all(|d| d.content["city"] == json!("Essen")));
    }

    // 2. Eq filter with no matches → empty result.
    #[tokio::test]
    async fn test_eq_filter_no_matches() {
        let (json, _dir) = make_engine().await;
        json.create_index("default", "city", super::super::IndexFieldType::String).await.unwrap();
        json.put_document("default", "a", json!({"city": "Essen"})).await.unwrap();
        let result = json.search_documents("default", eq_query(&[("city", json!("Hamburg"))])).await.unwrap();
        assert_eq!(result.total, 0);
        assert!(result.documents.is_empty());
    }

    // 3. Multiple filters are AND-combined (intersection).
    #[tokio::test]
    async fn test_and_intersection() {
        let (json, _dir) = make_engine().await;
        json.create_index("default", "city", super::super::IndexFieldType::String).await.unwrap();
        json.create_index("default", "role", super::super::IndexFieldType::String).await.unwrap();
        json.put_document("default", "a", json!({"city": "Essen", "role": "admin"})).await.unwrap();
        json.put_document("default", "b", json!({"city": "Essen", "role": "user"})).await.unwrap();
        json.put_document("default", "c", json!({"city": "Berlin", "role": "admin"})).await.unwrap();
        let result = json
            .search_documents("default", eq_query(&[("city", json!("Essen")), ("role", json!("admin"))]))
            .await
            .unwrap();
        assert_eq!(result.total, 1);
        assert_eq!(result.documents[0].key, "a");
    }

    // 4./7. Pagination slices the fetch and reports the full total.
    #[tokio::test]
    async fn test_pagination_with_total() {
        let (json, _dir) = make_engine().await;
        json.create_index("default", "kind", super::super::IndexFieldType::String).await.unwrap();
        for i in 0..10 {
            json.put_document("default", &format!("u{i}"), json!({"kind": "x", "n": i})).await.unwrap();
        }
        let query = SearchQuery {
            filters: HashMap::from([("kind".to_string(), FilterCondition::Eq(json!("x")))]),
            limit: 3,
            offset: 2,
        };
        let result = json.search_documents("default", query).await.unwrap();
        assert_eq!(result.total, 10);
        assert_eq!(result.limit, 3);
        assert_eq!(result.offset, 2);
        let keys: Vec<&str> = result.documents.iter().map(|d| d.key.as_str()).collect();
        assert_eq!(keys, vec!["u2", "u3", "u4"]);
    }

    // 5. Filter on a non-indexed field → IndexNotFound.
    #[tokio::test]
    async fn test_unindexed_field_rejected() {
        let (json, _dir) = make_engine().await;
        json.put_document("default", "a", json!({"city": "Essen"})).await.unwrap();
        let err = json
            .search_documents("default", eq_query(&[("city", json!("Essen"))]))
            .await
            .unwrap_err();
        assert!(matches!(err, JsonStoreError::IndexNotFound { .. }), "got: {err}");
    }

    // 6. Empty domain → empty result, no error.
    #[tokio::test]
    async fn test_empty_domain_empty_result() {
        let (json, _dir) = make_engine().await;
        json.create_domain("empty").await.unwrap();
        json.create_index("empty", "city", super::super::IndexFieldType::String).await.unwrap();
        let result = json.search_documents("empty", eq_query(&[("city", json!("Essen"))])).await.unwrap();
        assert_eq!(result.total, 0);
        assert!(result.documents.is_empty());
    }

    // 8. Filter value not matching the index type → InvalidFilter.
    #[tokio::test]
    async fn test_type_mismatch_rejected() {
        let (json, _dir) = make_engine().await;
        json.create_index("default", "age", super::super::IndexFieldType::Number).await.unwrap();
        let err = json
            .search_documents("default", eq_query(&[("age", json!("not-a-number"))]))
            .await
            .unwrap_err();
        assert!(matches!(err, JsonStoreError::InvalidFilter(_)), "got: {err}");
    }

    // 9. Range filters on a Number index (sortable encoding).
    #[tokio::test]
    async fn test_range_filters() {
        let (json, _dir) = make_engine().await;
        json.create_index("default", "age", super::super::IndexFieldType::Number).await.unwrap();
        for (key, age) in [("a", -5), ("b", 0), ("c", 30), ("d", 42), ("e", 100)] {
            json.put_document("default", key, json!({"age": age})).await.unwrap();
        }
        let gt = SearchQuery {
            filters: HashMap::from([("age".to_string(), FilterCondition::Gt(json!(30)))]),
            ..Default::default()
        };
        let result = json.search_documents("default", gt).await.unwrap();
        let keys: Vec<&str> = result.documents.iter().map(|d| d.key.as_str()).collect();
        assert_eq!(keys, vec!["d", "e"]);

        let lte = SearchQuery {
            filters: HashMap::from([("age".to_string(), FilterCondition::Lte(json!(0)))]),
            ..Default::default()
        };
        let result = json.search_documents("default", lte).await.unwrap();
        let keys: Vec<&str> = result.documents.iter().map(|d| d.key.as_str()).collect();
        assert_eq!(keys, vec!["a", "b"]);
    }

    // 10. Empty filter map → InvalidFilter (unfiltered listing is spec 010).
    #[tokio::test]
    async fn test_empty_filters_rejected() {
        let (json, _dir) = make_engine().await;
        let err = json
            .search_documents("default", SearchQuery::default())
            .await
            .unwrap_err();
        assert!(matches!(err, JsonStoreError::InvalidFilter(_)), "got: {err}");
    }

    // ── Listing & counting (spec json/010) ───────────────────────────────────

    async fn seed(json: &Arc<JsonEngine>, n: usize) {
        for i in 0..n {
            json.put_document("default", &format!("l{i:02}"), json!({"n": i})).await.unwrap();
        }
    }

    // 11. Listing paginates and reports the total.
    #[tokio::test]
    async fn test_list_documents_paginated() {
        let (json, _dir) = make_engine().await;
        seed(&json, 10).await;
        let result = json
            .list_documents("default", ListOptions { limit: 5, ..Default::default() })
            .await
            .unwrap();
        assert_eq!(result.total, 10);
        assert_eq!(result.documents.len(), 5);
        assert_eq!(result.keys.len(), 5);

        let result = json
            .list_documents("default", ListOptions { limit: 5, offset: 8, ..Default::default() })
            .await
            .unwrap();
        assert_eq!(result.total, 10);
        assert_eq!(result.keys, vec!["l08", "l09"]);
        assert_eq!(result.documents.len(), 2);
    }

    // 12. keys_only returns keys without loading documents.
    #[tokio::test]
    async fn test_list_documents_keys_only() {
        let (json, _dir) = make_engine().await;
        seed(&json, 4).await;
        let result = json
            .list_documents("default", ListOptions { keys_only: true, ..Default::default() })
            .await
            .unwrap();
        assert_eq!(result.keys.len(), 4);
        assert!(result.documents.is_empty());
    }

    // 13. count_documents tracks inserts and deletes; empty domain → 0.
    #[tokio::test]
    async fn test_count_documents() {
        let (json, _dir) = make_engine().await;
        json.create_domain("void").await.unwrap();
        assert_eq!(json.count_documents("void").await.unwrap(), 0);
        let empty = json.list_documents("void", ListOptions::default()).await.unwrap();
        assert_eq!(empty.total, 0);
        assert!(empty.keys.is_empty());

        seed(&json, 3).await;
        assert_eq!(json.count_documents("default").await.unwrap(), 3);
        json.delete_document("default", "l01").await.unwrap();
        assert_eq!(json.count_documents("default").await.unwrap(), 2);
    }
}
