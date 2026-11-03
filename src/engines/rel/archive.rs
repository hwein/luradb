//! What a backup needs from the relational engine: a domain's catalog, rows
//! and AUTOINCREMENT state read raw as of a snapshot, and the way back in —
//! tables recreated as stored, rows inserted under the engine's own checks.

use super::catalog::{CatalogEntry, IndexInput, TableInput, TableSchema};
use super::cross_engine::LinkAuth;
use super::dml::{coerce_json, InsertChecks, RowPlan};
use super::error::RelStoreError;
use super::keys;
use super::row::{decode_row, decode_value};
use super::types::ScalarValue;
use super::RelEngine;
use crate::core::coop::YieldEvery;
use crate::engines::lsm::engine::BatchOp;
use crate::engines::lsm::reader::Snapshot;
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};

/// Rows staged between two cooperative yields.
const RESTORE_ROW_YIELD_INTERVAL: u32 = 64;

/// The rows of one table as of a snapshot, in key order, read in groups.
pub struct RowScan<'a> {
    rel: &'a RelEngine,
    schema: &'a TableSchema,
    snapshot: &'a Snapshot,
    keys: std::vec::IntoIter<Vec<u8>>,
}

impl RowScan<'_> {
    /// The next up to `n` rows (at least one), each with every column of the
    /// schema in its order; empty at the end.
    pub async fn next_group(&mut self, n: usize) -> Result<Vec<Vec<ScalarValue>>, RelStoreError> {
        let mut rows = Vec::new();
        while rows.len() < n.max(1) {
            let Some(key) = self.keys.next() else { break };
            if let Some(bytes) = self.rel.engine.get_with_snapshot(&key, self.snapshot).await?.into_option() {
                rows.push(decode_row(&bytes, self.schema));
            }
        }
        Ok(rows)
    }
}

impl RelEngine {
    fn system_prefix_of(&self, domain: &str) -> Result<Vec<u8>, RelStoreError> {
        self.domains
            .get_domain_any(domain)
            .map(|d| d.system_prefix)
            .ok_or_else(|| RelStoreError::DomainNotFound(domain.to_string()))
    }

    /// Every table and view of `domain` as stored at `snapshot`.
    pub async fn catalog_at(&self, domain: &str, snapshot: &Snapshot) -> Result<Vec<CatalogEntry>, RelStoreError> {
        let prefix = self.system_prefix_of(domain)?;
        self.catalog.entries_at(&prefix, snapshot).await
    }

    /// The rows of `schema`'s table in `domain` as stored at `snapshot`, link
    /// cells unmasked.
    pub async fn rows_at<'a>(
        &'a self,
        domain: &str,
        schema: &'a TableSchema,
        snapshot: &'a Snapshot,
    ) -> Result<RowScan<'a>, RelStoreError> {
        let prefix = self.system_prefix_of(domain)?;
        let keys = self.engine.scan_keys_with_snapshot(&keys::row_table_prefix(&prefix, schema.table_id), snapshot).await?;
        Ok(RowScan { rel: self, schema, snapshot, keys: keys.into_iter() })
    }

    /// The AUTOINCREMENT high-water mark of table `table_id` at `snapshot`;
    /// 0 when none is stored.
    pub async fn autoincrement_hw_at(&self, domain: &str, table_id: u32, snapshot: &Snapshot) -> Result<u64, RelStoreError> {
        let prefix = self.system_prefix_of(domain)?;
        self.read_seq(&prefix, table_id, snapshot).await
    }

    /// Recreates a table of a backup; see [`super::RelCatalog::restore_table`].
    /// A link column is created even while its target engine is disabled.
    pub(crate) async fn restore_table(
        &self,
        domain: &str,
        input: TableInput,
        indexes: Vec<IndexInput>,
    ) -> Result<TableSchema, RelStoreError> {
        self.catalog.restore_table(&self.domains, domain, input, indexes).await
    }

    /// Inserts rows of a backup into `table`, as one batch: every column is
    /// set as given (a missing one is NULL, no default applies), checked for
    /// NOT NULL, primary key, row size and UNIQUE, but not for its link
    /// targets. Leaves the AUTOINCREMENT high-water mark alone. Returns the
    /// number of rows.
    pub(crate) async fn restore_rows(
        &self,
        domain: &str,
        table: &str,
        rows: Vec<Map<String, Value>>,
    ) -> Result<u64, RelStoreError> {
        let (dom, schema) = self.require_table(domain, table)?;
        let prefix = &dom.system_prefix;
        let mut plans = Vec::with_capacity(rows.len());
        for row in &rows {
            if let Some(unknown) = row.keys().find(|name| !schema.columns.iter().any(|c| &c.name == *name)) {
                return Err(RelStoreError::ColumnNotFound { table: schema.name.clone(), name: unknown.clone() });
            }
            let mut values = HashMap::with_capacity(schema.columns.len());
            for c in &schema.columns {
                let value = match row.get(&c.name) {
                    Some(v) => coerce_json(c.col_type, v, &c.name)?,
                    None => ScalarValue::Null,
                };
                values.insert(c.col_id, value);
            }
            plans.push(RowPlan::new(values));
        }

        let lock = self.table_locks.get(prefix, schema.table_id);
        let _guard = lock.lock().await;
        let snapshot = self.engine.snapshot().await;
        let mut ops: Vec<BatchOp> = Vec::new();
        let mut seen_pk: HashSet<Vec<u8>> = HashSet::new();
        let mut seen_unique: HashSet<(u32, Vec<u8>)> = HashSet::new();
        let mut coop = YieldEvery::new(RESTORE_ROW_YIELD_INTERVAL);
        for plan in &plans {
            coop.tick().await;
            self.stage_insert_row(
                domain,
                &schema,
                prefix,
                plan,
                snapshot.snapshot(),
                &mut seen_pk,
                &mut seen_unique,
                &mut ops,
                LinkAuth::full(),
                InsertChecks::Restore,
            )
            .await?;
        }
        if !ops.is_empty() {
            self.commit_guarded(domain, ops).await?;
        }
        Ok(plans.len() as u64)
    }

    /// Raises the AUTOINCREMENT high-water mark of `table` to `hw`, and at
    /// least to its largest positive primary key, so a later insert never
    /// hands out a key a row already has. Never lowers it.
    pub(crate) async fn raise_autoincrement(&self, domain: &str, table: &str, hw: u64) -> Result<(), RelStoreError> {
        let (dom, schema) = self.require_table(domain, table)?;
        let prefix = &dom.system_prefix;
        let pk = schema.columns.iter().find(|c| c.primary_key).expect("table has a PK");
        let lock = self.table_locks.get(prefix, schema.table_id);
        let _guard = lock.lock().await;
        let snapshot = self.engine.snapshot().await;
        let snap = snapshot.snapshot();

        let current = self.read_seq(prefix, schema.table_id, snap).await?;
        // Integer keys sort by value, so the last row holds the largest one.
        let row_keys = self.engine.scan_keys_with_snapshot(&keys::row_table_prefix(prefix, schema.table_id), snap).await?;
        let largest = match row_keys.last() {
            Some(key) => match self.engine.get_with_snapshot(key, snap).await?.into_option() {
                Some(bytes) => match decode_value(&bytes, pk) {
                    ScalarValue::Integer(v) if v > 0 => v as u64,
                    _ => 0,
                },
                None => 0,
            },
            None => 0,
        };
        let target = current.max(hw).max(largest);
        if target != current {
            let put = BatchOp::Put { key: keys::seq_key(prefix, schema.table_id), value: target.to_be_bytes().to_vec() };
            self.commit_guarded(domain, vec![put]).await?;
        }
        Ok(())
    }
}
