//! Bulk operations for the JSON store (spec json/007): NDJSON mass import
//! and streaming export.

use super::document::{
    doc_key, doc_scan_prefix, generate_uuid_v4, new_generation, parse_doc_key,
    validate_document_key, Document, StoredDocument,
};
use super::error::JsonStoreError;
use super::JsonEngine;
use crate::engines::lsm::engine::BatchOp;
use crate::engines::lsm::reader::Snapshot;
use crate::metrics::EngineKind;
use futures::Stream;
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct BulkLoadResult {
    pub imported: u64,
    pub failed: u64,
    /// `(document key or "line N", error message)` per failed document.
    pub errors: Vec<(String, String)>,
}

/// Parses one NDJSON line: extracts `_key` (optional), strips `_version`
/// (assigned by the store, not the import), unwraps `_content` for
/// non-object documents (see [`document_to_ndjson_line`]).
pub(crate) fn parse_ndjson_line(line: &str) -> Result<(Option<String>, Value), String> {
    let value: Value = serde_json::from_str(line).map_err(|e| format!("invalid JSON: {e}"))?;
    let Value::Object(mut map) = value else {
        return Err("line is not a JSON object".to_string());
    };
    let key = match map.remove("_key") {
        Some(Value::String(s)) => Some(s),
        Some(_) => return Err("_key must be a string".to_string()),
        None => None,
    };
    map.remove("_version");
    let content = if map.len() == 1 && map.contains_key("_content") {
        map.remove("_content").unwrap()
    } else {
        Value::Object(map)
    };
    Ok((key, content))
}

/// Merges content with `_key`/`_version` metadata into one JSON object.
/// Non-object content is wrapped under `_content`.
pub fn document_to_value(doc: &Document) -> Value {
    let mut map = match &doc.content {
        Value::Object(m) => m.clone(),
        other => {
            let mut m = Map::new();
            m.insert("_content".to_string(), other.clone());
            m
        }
    };
    map.insert("_key".to_string(), Value::String(doc.key.clone()));
    map.insert("_version".to_string(), Value::from(doc.version));
    Value::Object(map)
}

/// Serializes a document as one NDJSON line with `_key`/`_version` metadata.
pub fn document_to_ndjson_line(doc: &Document) -> String {
    document_to_value(doc).to_string()
}

impl JsonEngine {
    /// Reads, versions and writes one import batch entirely under the write
    /// shards of its own keys, so the read→write cycle cannot race put/delete
    /// (json/011) and no batch lands after the purger finalized the domain
    /// (json/013) — the purger holds every shard.
    async fn load_batch(
        &self,
        domain: &str,
        batch: Vec<(String, Value)>,
        result: &mut BulkLoadResult,
    ) -> Result<(), JsonStoreError> {
        let shards = batch.iter().map(|(key, _)| Self::shard(domain, key)).collect();
        let _guards = self.lock_shards(shards).await;
        let dom = self.domains.require_active(domain)?;
        let mut ops: Vec<BatchOp> = Vec::new();
        for (key, content) in batch {
            let old = self.read_stored(&dom, &key).await?;
            let (generation, version) = match &old {
                Some(o) => (o.generation, o.version + 1),
                None => (new_generation(), 1),
            };
            let stored = StoredDocument { version, generation, content };
            let payload = match serde_json::to_vec(&stored) {
                Ok(p) => p,
                Err(e) => {
                    result.failed += 1;
                    result.errors.push((key, format!("serialization error: {e}")));
                    continue;
                }
            };
            if payload.len() > self.max_value_size {
                result.failed += 1;
                result.errors.push((
                    key,
                    format!(
                        "payload of {} bytes exceeds maximum of {} bytes",
                        payload.len(),
                        self.max_value_size
                    ),
                ));
                continue;
            }
            let new_keys = self.index_entry_keys(&dom, &key, &stored.content);
            let old_keys = old
                .as_ref()
                .map(|o| self.index_entry_keys(&dom, &key, &o.content))
                .unwrap_or_default();
            for stale in old_keys.difference(&new_keys) {
                ops.push(BatchOp::Delete { key: stale.clone() });
            }
            ops.push(BatchOp::Put {
                key: doc_key(&dom.system_prefix, &key),
                value: payload,
            });
            for idx_key in new_keys {
                ops.push(BatchOp::Put { key: idx_key, value: Vec::new() });
            }
            result.imported += 1;
        }
        if !ops.is_empty() {
            self.engine.write_batch(ops).await?;
        }
        Ok(())
    }

    /// Imports documents in atomic batches of `bulk_batch_size`. Per-document
    /// errors are recorded and skipped; engine/storage errors abort the call
    /// (already flushed batches stay imported). The shards are held per batch,
    /// not across the whole import, so single-document writers are not
    /// starved by large imports.
    pub async fn bulk_load(
        &self,
        domain: &str,
        documents: Vec<(Option<String>, Value)>,
    ) -> Result<BulkLoadResult, JsonStoreError> {
        let start = std::time::Instant::now();
        self.domains.require_active(domain)?;
        let mut result = BulkLoadResult::default();

        // Pre-validate keys and split into batches. A repeated key must not
        // share a batch (one timestamp per batch would make the apply order
        // ambiguous) — it starts a new one.
        let mut batches: Vec<Vec<(String, Value)>> = Vec::new();
        let mut batch: Vec<(String, Value)> = Vec::new();
        let mut keys_in_batch: HashSet<String> = HashSet::new();
        for (maybe_key, content) in documents {
            let key = maybe_key.unwrap_or_else(generate_uuid_v4);
            if let Err(e) = validate_document_key(&key, self.max_document_key_length) {
                result.failed += 1;
                result.errors.push((key, e.to_string()));
                continue;
            }
            if keys_in_batch.contains(&key) || batch.len() >= self.bulk_batch_size {
                batches.push(std::mem::take(&mut batch));
                keys_in_batch.clear();
            }
            keys_in_batch.insert(key.clone());
            batch.push((key, content));
        }
        if !batch.is_empty() {
            batches.push(batch);
        }

        for batch in batches {
            self.load_batch(domain, batch, &mut result).await?;
        }
        self.metrics.record_engine_write(EngineKind::Json, start.elapsed().as_micros() as u64);
        Ok(result)
    }

    /// NDJSON convenience wrapper around [`JsonEngine::bulk_load`]. Unparseable
    /// lines are reported as `("line N", message)` and skipped.
    pub async fn bulk_load_ndjson(
        &self,
        domain: &str,
        ndjson: &str,
    ) -> Result<BulkLoadResult, JsonStoreError> {
        let mut parse_errors = Vec::new();
        let mut docs = Vec::new();
        for (i, line) in ndjson.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match parse_ndjson_line(line) {
                Ok(pair) => docs.push(pair),
                Err(msg) => parse_errors.push((format!("line {}", i + 1), msg)),
            }
        }
        let mut result = self.bulk_load(domain, docs).await?;
        result.failed += parse_errors.len() as u64;
        result.errors.extend(parse_errors);
        Ok(result)
    }

    /// Streams all documents of a domain. The key list is scanned upfront
    /// (the LSM has no public streaming scan); document values are fetched
    /// lazily one at a time. Tombstoned/corrupt entries are skipped. The
    /// stream owns an engine Arc, so it can outlive the caller (HTTP body).
    pub async fn bulk_export(
        self: &Arc<Self>,
        domain: &str,
    ) -> Result<impl Stream<Item = Document> + Send + 'static, JsonStoreError> {
        let start = std::time::Instant::now();
        let dom = self.domains.require_active(domain)?;
        let keys = self
            .engine
            .scan_keys(&doc_scan_prefix(&dom.system_prefix))
            .await?;
        self.metrics.record_engine_read(EngineKind::Json, start.elapsed().as_micros() as u64);
        let engine = Arc::clone(self);
        Ok(futures::stream::unfold(
            (engine, keys.into_iter(), dom),
            move |(engine, mut iter, dom)| async move {
                loop {
                    let lsm_key = iter.next()?;
                    let Some((_, document_key)) = parse_doc_key(&lsm_key) else {
                        tracing::warn!("[bulk_export] unparseable doc key {:?}, skipping", lsm_key);
                        continue;
                    };
                    match engine.read_stored(&dom, &document_key).await {
                        Ok(Some(stored)) => {
                            let doc = Document {
                                key: document_key,
                                domain: dom.name.clone(),
                                content: stored.content,
                                version: stored.version,
                                generation: stored.generation,
                            };
                            return Some((doc, (engine, iter, dom)));
                        }
                        Ok(None) => continue,
                        Err(e) => {
                            tracing::warn!(
                                "[bulk_export] skipping corrupt document '{document_key}': {e}"
                            );
                            continue;
                        }
                    }
                }
            },
        ))
    }

    /// Lists all live document keys of a domain visible under `snapshot`
    /// (spec general/006 backup export) — the snapshot-pinned counterpart of
    /// the key-scan step in [`Self::bulk_export`], pairing with
    /// [`JsonEngine::get_document_with_snapshot`] for the per-document read.
    /// Unparseable LSM keys are skipped, like `bulk_export`.
    pub async fn scan_document_keys_with_snapshot(
        &self,
        domain: &str,
        snapshot: &Snapshot,
    ) -> Result<Vec<String>, JsonStoreError> {
        let dom = self.domains.require_active(domain)?;
        let keys = self
            .engine
            .scan_keys_with_snapshot(&doc_scan_prefix(&dom.system_prefix), snapshot)
            .await?;
        Ok(keys
            .into_iter()
            .filter_map(|lsm_key| parse_doc_key(&lsm_key).map(|(_, document_key)| document_key))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{IndexFieldType, JsonEngine};
    use super::*;
    use crate::config::JsonStoreConfig;
    use futures::StreamExt;
    use serde_json::json;
    use std::sync::Arc;

    async fn make_engine_with_batch(batch: usize) -> (Arc<JsonEngine>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let config = JsonStoreConfig {
            wal_path: dir.path().join("json.wal").to_string_lossy().into_owned(),
            vlog_path: dir.path().join("json.vlog").to_string_lossy().into_owned(),
            sstable_dir: dir.path().join("json_sstables").to_string_lossy().into_owned(),
            bulk_batch_size: batch,
            ..JsonStoreConfig::default()
        };
        let metrics = crate::metrics::MetricsStore::new(crate::metrics::MetricsConfig::default());
        let engine = JsonEngine::bootstrap(&config, metrics).await.unwrap();
        (engine, dir)
    }

    // 1. Bulk load across batch boundaries → every doc retrievable.
    #[tokio::test]
    async fn test_bulk_load_basic() {
        let (json, _dir) = make_engine_with_batch(2).await;
        let docs = (0..5)
            .map(|i| (Some(format!("d{i}")), json!({"n": i})))
            .collect();
        let result = json.bulk_load("default", docs).await.unwrap();
        assert_eq!(result.imported, 5);
        assert_eq!(result.failed, 0);
        for i in 0..5 {
            let doc = json.get_document("default", &format!("d{i}")).await.unwrap().unwrap();
            assert_eq!(doc.content, json!({"n": i}));
        }
    }

    // 2. Bulk load maintains index entries.
    #[tokio::test]
    async fn test_bulk_load_with_index() {
        let (json, _dir) = make_engine_with_batch(100).await;
        json.create_index("default", "city", IndexFieldType::String).await.unwrap();
        let docs = vec![
            (Some("a".to_string()), json!({"city": "Essen"})),
            (Some("b".to_string()), json!({"city": "Essen"})),
            (Some("c".to_string()), json!({"city": "Berlin"})),
        ];
        json.bulk_load("default", docs).await.unwrap();
        let query = super::super::SearchQuery {
            filters: std::collections::HashMap::from([(
                "city".to_string(),
                super::super::FilterCondition::Eq(json!("Essen")),
            )]),
            ..Default::default()
        };
        let found = json.search_documents("default", query).await.unwrap();
        assert_eq!(found.total, 2);
    }

    // 3. A bad document is skipped, the rest is imported.
    #[tokio::test]
    async fn test_bulk_load_continues_on_error() {
        let (json, _dir) = make_engine_with_batch(100).await;
        let docs = vec![
            (Some("ok-1".to_string()), json!({"n": 1})),
            (Some("bad:key".to_string()), json!({"n": 2})),
            (Some("ok-2".to_string()), json!({"n": 3})),
        ];
        let result = json.bulk_load("default", docs).await.unwrap();
        assert_eq!(result.imported, 2);
        assert_eq!(result.failed, 1);
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].0, "bad:key");
        assert!(json.get_document("default", "ok-2").await.unwrap().is_some());
    }

    // 4. Existing keys are updated with incremented versions — also when the
    //    same key repeats within one bulk call (forces an early batch flush).
    #[tokio::test]
    async fn test_bulk_load_updates_versions() {
        let (json, _dir) = make_engine_with_batch(100).await;
        json.put_document("default", "k", json!({"v": "pre"})).await.unwrap();
        let docs = vec![
            (Some("k".to_string()), json!({"v": "first"})),
            (Some("k".to_string()), json!({"v": "second"})),
        ];
        let result = json.bulk_load("default", docs).await.unwrap();
        assert_eq!(result.imported, 2);
        let doc = json.get_document("default", "k").await.unwrap().unwrap();
        assert_eq!(doc.version, 3);
        assert_eq!(doc.content, json!({"v": "second"}));
    }

    // 5./6. Export streams all documents; empty domain → empty stream.
    #[tokio::test]
    async fn test_bulk_export() {
        let (json, _dir) = make_engine_with_batch(100).await;
        for i in 0..4 {
            json.put_document("default", &format!("e{i}"), json!({"n": i})).await.unwrap();
        }
        let stream = json.bulk_export("default").await.unwrap();
        let docs: Vec<Document> = stream.collect().await;
        assert_eq!(docs.len(), 4);

        json.create_domain("empty").await.unwrap();
        let stream = json.bulk_export("empty").await.unwrap();
        let docs: Vec<Document> = stream.collect().await;
        assert!(docs.is_empty());
    }

    // ── Snapshot-pinned export (spec general/006 backup export) ─────────────

    // A document created/updated after the snapshot must not appear via the
    // pinned scan/read pair, while the live (unpinned) read sees the update.
    #[tokio::test]
    async fn test_export_with_snapshot_hides_later_writes() {
        let (json, _dir) = make_engine_with_batch(100).await;
        json.put_document("default", "d1", json!({"n": 1})).await.unwrap();
        let snap = json.engine().snapshot();

        json.put_document("default", "d1", json!({"n": 2})).await.unwrap(); // update after snapshot
        json.put_document("default", "d2", json!({"n": 99})).await.unwrap(); // new doc after snapshot

        let keys = json
            .scan_document_keys_with_snapshot("default", snap.snapshot())
            .await
            .unwrap();
        assert_eq!(keys, vec!["d1".to_string()], "d2 was created after the snapshot");

        let doc = json
            .get_document_with_snapshot("default", "d1", snap.snapshot())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(doc.content, json!({"n": 1}), "must see the pre-snapshot version");
        assert_eq!(doc.version, 1);

        let live = json.get_document("default", "d1").await.unwrap().unwrap();
        assert_eq!(live.content, json!({"n": 2}), "live state must show the update");
    }

    // A document deleted after the snapshot must still be readable/listed
    // through the pinned snapshot, even though the live view has moved on.
    #[tokio::test]
    async fn test_export_with_snapshot_sees_doc_deleted_after_snapshot() {
        let (json, _dir) = make_engine_with_batch(100).await;
        json.put_document("default", "gone", json!({"n": 1})).await.unwrap();
        let snap = json.engine().snapshot();
        json.delete_document("default", "gone").await.unwrap();

        let keys = json
            .scan_document_keys_with_snapshot("default", snap.snapshot())
            .await
            .unwrap();
        assert_eq!(keys, vec!["gone".to_string()]);
        let doc = json
            .get_document_with_snapshot("default", "gone", snap.snapshot())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(doc.content, json!({"n": 1}));

        assert!(json.get_document("default", "gone").await.unwrap().is_none(), "live state must show it deleted");
    }

    // 7. NDJSON parsing: _key extraction, missing _key → generated UUID.
    #[tokio::test]
    async fn test_ndjson_parsing_and_generated_keys() {
        let (parsed_key, content) =
            parse_ndjson_line(r#"{"_key": "doc1", "city": "Essen"}"#).unwrap();
        assert_eq!(parsed_key, Some("doc1".to_string()));
        assert_eq!(content, json!({"city": "Essen"}));
        let (no_key, _) = parse_ndjson_line(r#"{"city": "Essen"}"#).unwrap();
        assert_eq!(no_key, None);
        assert!(parse_ndjson_line("not json").is_err());
        assert!(parse_ndjson_line(r#"[1, 2]"#).is_err());

        let (json, _dir) = make_engine_with_batch(100).await;
        json.bulk_load_ndjson("default", "{\"city\": \"Essen\"}\n").await.unwrap();
        let stream = json.bulk_export("default").await.unwrap();
        let docs: Vec<Document> = stream.collect().await;
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].key.len(), 36, "generated key must be a UUID");
    }

    // 8. Roundtrip: NDJSON load → export → identical content.
    #[tokio::test]
    async fn test_ndjson_roundtrip() {
        let (json, _dir) = make_engine_with_batch(100).await;
        let ndjson = concat!(
            "{\"_key\": \"r1\", \"city\": \"Essen\", \"n\": 1}\n",
            "{\"_key\": \"r2\", \"city\": \"Berlin\", \"n\": 2}\n",
        );
        let result = json.bulk_load_ndjson("default", ndjson).await.unwrap();
        assert_eq!(result.imported, 2);
        assert_eq!(result.failed, 0);

        let stream = json.bulk_export("default").await.unwrap();
        let lines: Vec<String> = stream.map(|d| document_to_ndjson_line(&d)).collect().await;
        assert_eq!(lines.len(), 2);
        let reparsed: Vec<(Option<String>, Value)> =
            lines.iter().map(|l| parse_ndjson_line(l).unwrap()).collect();
        assert!(reparsed.contains(&(Some("r1".to_string()), json!({"city": "Essen", "n": 1}))));
        assert!(reparsed.contains(&(Some("r2".to_string()), json!({"city": "Berlin", "n": 2}))));
    }

    // 9. A key within max_document_key_length but too long for the composite
    //    LSM key is skipped (failed+errors), the import continues.
    #[tokio::test]
    async fn test_bulk_load_skips_overlong_key() {
        let (json, _dir) = make_engine_with_batch(100).await;
        let long_key = "k".repeat(250); // 250 + 21 bytes overhead > LSM limit 256
        let docs = vec![
            (Some("ok-1".to_string()), json!({"n": 1})),
            (Some(long_key.clone()), json!({"n": 2})),
            (Some("ok-2".to_string()), json!({"n": 3})),
        ];
        let result = json.bulk_load("default", docs).await.unwrap();
        assert_eq!(result.imported, 2);
        assert_eq!(result.failed, 1);
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].0, long_key);
        assert!(json.get_document("default", "ok-2").await.unwrap().is_some());
    }

    // 10. bulk_load's read→write cycle is serialized against put_document:
    //     regardless of ordering, the version chain has no duplicates and
    //     exactly one index entry (matching the final content) survives.
    #[tokio::test]
    async fn test_bulk_load_serialized_with_put() {
        let (json, _dir) = make_engine_with_batch(100).await;
        json.create_index("default", "city", IndexFieldType::String).await.unwrap();
        json.put_document("default", "k", json!({"city": "Essen"})).await.unwrap();

        let bulk = {
            let json = Arc::clone(&json);
            tokio::spawn(async move {
                json.bulk_load("default", vec![(Some("k".to_string()), json!({"city": "Bochum"}))])
                    .await
            })
        };
        let put = {
            let json = Arc::clone(&json);
            tokio::spawn(
                async move { json.put_document("default", "k", json!({"city": "Berlin"})).await },
            )
        };
        bulk.await.unwrap().unwrap();
        put.await.unwrap().unwrap();

        let doc = json.get_document("default", "k").await.unwrap().unwrap();
        assert_eq!(doc.version, 3, "both writers must see each other's version");
        let city = doc.content["city"].as_str().unwrap();
        let prefix = json.get_domain("default").unwrap().system_prefix;
        let field_prefix = super::super::index::index_field_prefix(&prefix, "city");
        let entries = json.engine().scan_keys(&field_prefix).await.unwrap();
        assert_eq!(
            entries,
            vec![super::super::index::index_key(&prefix, "city", city.as_bytes(), "k")],
            "exactly one index entry, matching the final content"
        );
    }

    // 11. Deadlock probe (spec json/018): two concurrent batches over the same
    //     keys in opposite order finish — the ascending shard acquisition is
    //     the proof object; a naive per-key order would deadlock here.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_bulk_loads_with_opposite_key_order() {
        let (json, _dir) = make_engine_with_batch(100).await;
        let keys: Vec<String> = (0..8).map(|i| format!("k{i}")).collect();
        let forward: Vec<_> = keys.iter().map(|k| (Some(k.clone()), json!({"v": "f"}))).collect();
        let backward: Vec<_> =
            keys.iter().rev().map(|k| (Some(k.clone()), json!({"v": "b"}))).collect();

        let a = tokio::spawn({
            let json = Arc::clone(&json);
            async move { json.bulk_load("default", forward).await }
        });
        let b = tokio::spawn({
            let json = Arc::clone(&json);
            async move { json.bulk_load("default", backward).await }
        });
        let bound = std::time::Duration::from_secs(10);
        tokio::time::timeout(bound, a).await.expect("bulk A deadlocked").unwrap().unwrap();
        tokio::time::timeout(bound, b).await.expect("bulk B deadlocked").unwrap().unwrap();

        for key in &keys {
            let doc = json.get_document("default", key).await.unwrap().unwrap();
            assert_eq!(doc.version, 2, "both imports must see each other's version");
        }
    }

    // ── Spec general/019: per-engine metrics ─────────────────────────────────

    // Test 6: bulk_load with N documents increments json.write_ops by
    // exactly 1, not N, with exactly one latency sample -- proof of the
    // "one call = one op" rule, regardless of how many batches the import
    // splits into internally.
    #[tokio::test]
    async fn test_bulk_load_counts_as_one_write_op() {
        let (json, _dir) = make_engine_with_batch(2).await; // small batch: several internal flushes
        let docs = (0..7)
            .map(|i| (Some(format!("d{i}")), json!({"n": i})))
            .collect();
        let result = json.bulk_load("default", docs).await.unwrap();
        assert_eq!(result.imported, 7);

        // aggregate_engine only sums fully ticked buckets (spec general/019).
        json.metrics.tick_all();
        let m = json.metrics.engine_metrics();
        assert_eq!(
            m[EngineKind::Json as usize].write_ops, 1,
            "one call, one op -- not one per document or batch"
        );
    }
}
