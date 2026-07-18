//! `expand` — link-column resolution for `/sql` and Browse SELECT responses.
//! REFERENCES columns resolve rel-internally via a PK-point lookup in the
//! SELECT's own MVCC snapshot (rel/009); KVREF/JSONREF columns resolve
//! cross-engine via the `CrossEngineResolver` (rel/012 §4) — each a fresh,
//! committed read on the target engine (no shared snapshot across engines).
//! Single-stage only (no recursive/nested expand — non-goal).

use super::catalog::CatalogEntry;
use super::cross_engine::{base64_encode, JsonResolution, KvResolution};
use super::dml::SelectResult;
use super::error::RelStoreError;
use super::join;
use super::keys;
use super::rest_exec::ExpandedBlock;
use super::row::decode_row;
use super::types::{encode_sortable, scalar_to_json, ColumnType};
use super::RelEngine;
use crate::engines::lsm::reader::Snapshot;
use serde_json::{json, Value};

/// How one projected link column resolves (spec §4).
enum ExpandKind {
    /// rel-internal REFERENCES → target table name.
    Reference(String),
    Kv,
    Json,
}

impl RelEngine {
    /// Resolves `expand` against `result` (an already-executed SELECT).
    /// Returns an empty `Vec` when nothing was resolved (wildcard found no
    /// eligible column) — the caller turns that into "no `expanded` key" (§5).
    pub(super) async fn resolve_expand(
        &self,
        domain: &str,
        result: &SelectResult,
        expand: &[String],
    ) -> Result<ExpandedBlock, RelStoreError> {
        let targets = if expand.iter().any(|e| e == "*") {
            wildcard_targets(result)
        } else {
            named_targets(result, expand)?
        };
        if targets.is_empty() {
            return Ok(Vec::new());
        }

        // max_join_depth accounting (rel/009 §5, spec §4): every resolved link
        // column — REFERENCES *and* KVREF/JSONREF — counts like a join stage,
        // column-based (a NULL/masked cell still counts, it just skips its lookup).
        join::check_join_depth(result.joins_used, targets.len(), self.max_join_depth)?;

        let dom = self.domains.require_active(domain)?;
        let prefix = dom.system_prefix.clone();

        let mut expanded: ExpandedBlock = Vec::with_capacity(targets.len());
        for (pos, name, kind) in targets {
            let values = match kind {
                ExpandKind::Reference(target_table) => {
                    // A resolvable REFERENCES column implies exec_select(_joined)
                    // set a snapshot (it always does for a real SELECT).
                    let snap = result
                        .snapshot
                        .clone()
                        .expect("a REFERENCES column implies a SELECT snapshot");
                    self.resolve_one_column(domain, &target_table, &prefix, result, pos, &snap).await?
                }
                ExpandKind::Kv => self.resolve_kv_column(domain, result, pos).await?,
                ExpandKind::Json => self.resolve_json_column(domain, result, pos).await?,
            };
            expanded.push((name, values));
        }
        Ok(expanded)
    }

    /// REFERENCES resolution (rel/009 §5): per row, `v == NULL` or a missing
    /// target row (hanging link, Konzept 3.4) yields `null`; a hit decodes the
    /// target row into a JSON object keyed by the target table's columns.
    async fn resolve_one_column(
        &self,
        domain: &str,
        target_table: &str,
        prefix: &[u8],
        result: &SelectResult,
        pos: usize,
        snap: &Snapshot,
    ) -> Result<Vec<Value>, RelStoreError> {
        let target_schema = match self.catalog.get(&self.domains, domain, target_table) {
            Ok(CatalogEntry::Table(t)) => t,
            _ => return Ok(vec![Value::Null; result.rows.len()]),
        };

        let mut out = Vec::with_capacity(result.rows.len());
        for row in &result.rows {
            let value = match encode_sortable(&row[pos]) {
                None => Value::Null, // NULL/masked link — nothing to resolve
                Some(pk_enc) => {
                    let key = keys::row_key(prefix, target_schema.table_id, &pk_enc);
                    match self.engine.get_with_snapshot(&key, snap).await? {
                        None => Value::Null, // hanging link (Konzept 3.4)
                        Some(bytes) => {
                            let values = decode_row(&bytes, &target_schema);
                            let mut obj = serde_json::Map::with_capacity(target_schema.columns.len());
                            for (c, v) in target_schema.columns.iter().zip(values) {
                                obj.insert(c.name.clone(), scalar_to_json(&v));
                            }
                            Value::Object(obj)
                        }
                    }
                }
            };
            out.push(value);
        }
        Ok(out)
    }

    /// KVREF resolution (spec §4): the link value (post-masking) is looked up
    /// in the same-named KV domain; three "nothing" states stay distinct.
    async fn resolve_kv_column(
        &self,
        domain: &str,
        result: &SelectResult,
        pos: usize,
    ) -> Result<Vec<Value>, RelStoreError> {
        let mut out = Vec::with_capacity(result.rows.len());
        for row in &result.rows {
            let entry = match link_key(&row[pos]) {
                None => Value::Null, // rel-NULL / masked — no lookup
                Some(key) => {
                    self.cross_engine.record_expand_lookup("kv");
                    kv_resolution_json(self.cross_engine.kv_lookup(domain, key).await?)
                }
            };
            out.push(entry);
        }
        Ok(out)
    }

    /// JSONREF resolution (spec §4).
    async fn resolve_json_column(
        &self,
        domain: &str,
        result: &SelectResult,
        pos: usize,
    ) -> Result<Vec<Value>, RelStoreError> {
        let mut out = Vec::with_capacity(result.rows.len());
        for row in &result.rows {
            let entry = match link_key(&row[pos]) {
                None => Value::Null,
                Some(key) => {
                    self.cross_engine.record_expand_lookup("json");
                    json_resolution_json(self.cross_engine.json_lookup(domain, key).await?)
                }
            };
            out.push(entry);
        }
        Ok(out)
    }
}

/// The link key of a materialized cell, or `None` for rel-NULL / a masked cell.
fn link_key(v: &super::types::ScalarValue) -> Option<&str> {
    match v {
        super::types::ScalarValue::Text(s) => Some(s),
        _ => None,
    }
}

/// KVREF → JSON (spec §4): valid UTF-8 → `utf8`, else `base64`; a KV null-value
/// (not producible by today's KV API, §4) → `value:null`; absent/domain-gone →
/// `exists:false`.
fn kv_resolution_json(res: KvResolution) -> Value {
    match res {
        KvResolution::Present(bytes) => match String::from_utf8(bytes) {
            Ok(s) => json!({ "exists": true, "value": s, "encoding": "utf8" }),
            Err(e) => json!({ "exists": true, "value": base64_encode(&e.into_bytes()), "encoding": "base64" }),
        },
        KvResolution::NullValue => json!({ "exists": true, "value": null }),
        KvResolution::Absent | KvResolution::DomainUnavailable => json!({ "exists": false, "value": null }),
    }
}

/// JSONREF → JSON (spec §4): document exists with content, or `exists:false`.
fn json_resolution_json(res: JsonResolution) -> Value {
    match res {
        JsonResolution::Present(doc) => json!({ "exists": true, "document": doc }),
        JsonResolution::Absent | JsonResolution::DomainUnavailable => {
            json!({ "exists": false, "document": null })
        }
    }
}

/// The link kind of one projected column: KVREF/JSONREF by type, else a
/// REFERENCES target if any. `None` = not a link column (not expandable).
fn classify_target(result: &SelectResult, pos: usize) -> Option<ExpandKind> {
    match result.columns[pos].1 {
        ColumnType::KvRef => Some(ExpandKind::Kv),
        ColumnType::JsonRef => Some(ExpandKind::Json),
        _ => result.column_refs.get(pos).and_then(|r| r.clone()).map(ExpandKind::Reference),
    }
}

/// Wildcard mode (spec §4): every projected link column — REFERENCES *and*
/// KVREF/JSONREF (no longer skipped).
fn wildcard_targets(result: &SelectResult) -> Vec<(usize, String, ExpandKind)> {
    result
        .columns
        .iter()
        .enumerate()
        .filter_map(|(i, (name, _))| classify_target(result, i).map(|kind| (i, name.clone(), kind)))
        .collect()
}

/// Named mode (spec §4): every requested name must hit exactly one projected
/// column, which must be a link column (REFERENCES/KVREF/JSONREF). Duplicate
/// names collapse to one resolution (output is keyed by name).
fn named_targets(
    result: &SelectResult,
    expand: &[String],
) -> Result<Vec<(usize, String, ExpandKind)>, RelStoreError> {
    let mut out: Vec<(usize, String, ExpandKind)> = Vec::new();
    for name in expand {
        let mut hits = result.columns.iter().enumerate().filter(|(_, (n, _))| n == name).map(|(i, _)| i);
        let (Some(pos), None) = (hits.next(), hits.next()) else {
            return Err(RelStoreError::InvalidExpand(format!(
                "'{name}' is not a projected column of this SELECT, or is ambiguous \
                 among several projected columns of that name — disambiguate with AS"
            )));
        };
        let Some(kind) = classify_target(result, pos) else {
            return Err(RelStoreError::InvalidExpand(format!(
                "'{name}' is not a REFERENCES/KVREF/JSONREF column"
            )));
        };
        if !out.iter().any(|(p, _, _)| *p == pos) {
            out.push((pos, name.clone(), kind));
        }
    }
    Ok(out)
}
