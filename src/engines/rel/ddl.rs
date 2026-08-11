//! DDL executor for table/index statements (spec rel/004 §8).
//!
//! A thin dispatch layer: each `DdlPlan` variant maps to exactly one
//! `RelCatalog` primitive, which is the self-validating, atomic (`ddl_lock`
//! + one `WriteBatch`) source of truth — see rel/003's `create_table` and
//! the primitives this spec adds alongside it (`add_column`, `drop_column`,
//! `rename_column`, `rename_table`, `create_index`, `drop_index`). `DROP
//! TABLE` is the one exception: it reuses the existing generic
//! `RelCatalog::get`/`drop_object` (rel/003) rather than a new primitive,
//! remapping their generic `ObjectNotFound` to the more specific
//! `TableNotFound` and rejecting a same-named view — `DROP TABLE` must not
//! silently delete a view.

use super::binder::DdlPlan;
use super::catalog::{CatalogEntry, IndexMeta, RelCatalog, TableSchema, ViewSchema};
use super::dml::TableLocks;
use super::domain::RelDomainRegistry;
use super::error::RelStoreError;
use super::keys;
use super::row::decode_value;
use super::types::encode_sortable;
use super::view;
use crate::engines::lsm::engine::{BatchOp, LsmStorageEngine};
use crate::metrics::MetricsStore;
use std::collections::HashSet;

/// Outcome of a successfully executed DDL statement.
#[derive(Debug)]
pub enum DdlOutcome {
    TableCreated(TableSchema),
    TableAltered(TableSchema),
    TableDropped { name: String },
    IndexCreated(IndexMeta),
    IndexDropped { name: String },
    ViewCreated(ViewSchema),
    ViewDropped { name: String },
}

/// Executes one bound DDL plan atomically against the catalog.
pub async fn execute(
    catalog: &RelCatalog,
    domains: &RelDomainRegistry,
    metrics: &MetricsStore,
    domain: &str,
    plan: DdlPlan,
) -> Result<DdlOutcome, RelStoreError> {
    match plan {
        DdlPlan::CreateTable(input) => {
            let schema = catalog.create_table(domains, domain, input).await?;
            metrics.record_rel_ddl_op("create_table");
            Ok(DdlOutcome::TableCreated(schema))
        }
        DdlPlan::AddColumn { table, column } => {
            let schema = catalog.add_column(domains, domain, &table, column).await?;
            metrics.record_rel_ddl_op("alter_table");
            Ok(DdlOutcome::TableAltered(schema))
        }
        DdlPlan::DropColumn { table, column } => {
            let object = format!("{table}.{column}");
            let schema = catalog
                .drop_column_checked(domains, domain, &table, &column, |m| {
                    view::check_view_dependents(m, &object, domain)
                })
                .await?;
            metrics.record_rel_ddl_op("alter_table");
            Ok(DdlOutcome::TableAltered(schema))
        }
        DdlPlan::RenameColumn { table, from, to } => {
            let object = format!("{table}.{from}");
            let schema = catalog
                .rename_column_checked(domains, domain, &table, &from, &to, |m| {
                    view::check_view_dependents(m, &object, domain)
                })
                .await?;
            metrics.record_rel_ddl_op("alter_table");
            Ok(DdlOutcome::TableAltered(schema))
        }
        DdlPlan::RenameTable { table, to } => {
            let schema = catalog
                .rename_table_checked(domains, domain, &table, &to, |m| {
                    view::check_view_dependents(m, &table, domain)
                })
                .await?;
            metrics.record_rel_ddl_op("alter_table");
            Ok(DdlOutcome::TableAltered(schema))
        }
        DdlPlan::DropTable { table } => {
            catalog
                .drop_object_checked(domains, domain, &table, |removed, m| match removed {
                    CatalogEntry::Table(_) => view::check_view_dependents(m, &table, domain),
                    // A concurrent re-CREATE turned the name into a view before
                    // the lock: from DROP TABLE's point of view there is no
                    // table by that name — checked atomically here, not before
                    // the lock, so the race cannot drop the wrong object (004).
                    CatalogEntry::View(_) => Err(RelStoreError::TableNotFound {
                        domain: domain.to_string(),
                        name: table.clone(),
                    }),
                })
                .await
                .map_err(object_not_found_as_table)?;
            metrics.record_rel_ddl_op("drop_table");
            Ok(DdlOutcome::TableDropped { name: table })
        }
        // CREATE INDEX runs the backfill-aware path (`execute_create_index`),
        // dispatched directly by `RelEngine::execute` since it needs the LSM
        // engine and the per-table write lock, which this executor lacks.
        DdlPlan::CreateIndex { .. } => {
            unreachable!("CREATE INDEX is dispatched to execute_create_index (spec rel/005 §13)")
        }
        DdlPlan::DropIndex { name } => {
            catalog.drop_index(domains, domain, &name).await?;
            metrics.record_rel_ddl_op("drop_index");
            Ok(DdlOutcome::IndexDropped { name })
        }
    }
}

/// Executes `CREATE [UNIQUE] INDEX` with row backfill (spec rel/005 §13).
///
/// Order is load-bearing: (0) reserve the `index_id` and durably commit the id
/// counter first; (1-3) under the table write lock + a snapshot, scan/decode
/// existing rows, detect UNIQUE duplicates in memory before writing anything,
/// then write the `IDX:` entries in chunk batches; (4) make the `IndexMeta`
/// catalog-visible **last**. A crash between 0 and 4 leaves only a burned id
/// and orphan bytes (purger fodder), never a visible index missing entries.
#[allow(clippy::too_many_arguments)]
pub async fn execute_create_index(
    engine: &LsmStorageEngine,
    catalog: &RelCatalog,
    domains: &RelDomainRegistry,
    metrics: &MetricsStore,
    locks: &TableLocks,
    max_key_length: usize,
    domain: &str,
    table: &str,
    name: &str,
    column: &str,
    unique: bool,
) -> Result<DdlOutcome, RelStoreError> {
    const BACKFILL_CHUNK: usize = 500;

    let (dom, schema, meta) =
        catalog.create_index_reserve(domains, domain, table, name, column, unique).await?;
    let prefix = &dom.system_prefix;
    // Frees the reserved index id if the backfill below aborts (KeyTooLong /
    // UniqueViolation / scan error) so its orphaned IDX bytes get reaped by the
    // rel/013 sweep; the success path disarms it after commit (rel/013 F1).
    let reservation = catalog.index_reservation_guard(prefix, meta.index_id);
    let col = schema
        .columns
        .iter()
        .find(|c| c.name == meta.column)
        .expect("reserve validated the index column exists");
    let pk_col = schema.columns.iter().find(|c| c.primary_key).expect("table has a PK");

    let lock = locks.get(prefix, schema.table_id);
    let _guard = lock.lock().await;
    let snapshot = engine.snapshot();
    let snap = snapshot.snapshot();

    let mut idx_keys: Vec<Vec<u8>> = Vec::new();
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    for rk in engine.scan_keys(&keys::row_table_prefix(prefix, schema.table_id)).await? {
        let Some(bytes) = engine.get_with_snapshot(&rk, snap).await?.into_option() else {
            continue;
        };
        let Some(val_enc) = encode_sortable(&decode_value(&bytes, col)) else {
            continue; // NULL → no index entry
        };
        if unique && !seen.insert(val_enc.clone()) {
            // No IDX entry has been written yet — nothing to roll back.
            return Err(RelStoreError::UniqueViolation { index: meta.name });
        }
        let Some(pk_enc) = encode_sortable(&decode_value(&bytes, pk_col)) else {
            continue;
        };
        let key = keys::index_key(prefix, meta.index_id, &val_enc, &pk_enc);
        if key.len() > max_key_length {
            return Err(RelStoreError::KeyTooLong { len: key.len(), max: max_key_length });
        }
        idx_keys.push(key);
    }

    let total = idx_keys.len() as u64;
    for chunk in idx_keys.chunks(BACKFILL_CHUNK) {
        let ops = chunk
            .iter()
            .map(|k| BatchOp::Put { key: k.clone(), value: Vec::new() })
            .collect();
        engine.write_batch(ops).await?;
    }

    catalog.create_index_commit(domains, domain, table, meta.clone()).await?;
    reservation.disarm(); // committed: the index is live and its reservation freed
    metrics.record_rel_ddl_op("create_index");
    metrics.record_rel_index_backfill_entries(total);
    Ok(DdlOutcome::IndexCreated(meta))
}

/// `DROP TABLE` on a missing name surfaces as `TableNotFound` (rel/003's
/// generic drop reports the neutral `ObjectNotFound`): from `DROP TABLE`'s
/// point of view there is no table by that name. The "it's a view" case is
/// caught atomically inside `drop_object_checked` (see the `DropTable` arm),
/// not by a separate pre-lock probe that a concurrent re-`CREATE` could race.
fn object_not_found_as_table(err: RelStoreError) -> RelStoreError {
    match err {
        RelStoreError::ObjectNotFound { domain, name } => {
            RelStoreError::TableNotFound { domain, name }
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engines::lsm::engine::LsmStorageEngine;
    use crate::engines::rel::catalog::{CatalogLimits, ColumnInput, TableInput};
    use crate::engines::rel::types::ColumnType;
    use crate::metrics::MetricsConfig;
    use crate::storage::file_manager::FileManager;
    use crate::storage::manifest::ManifestManager;
    use crate::core::wal::WriteAheadLog;
    use crate::storage::vlog::VLog;
    use std::sync::Arc;

    async fn make_ctx() -> (
        Arc<RelDomainRegistry>,
        Arc<RelCatalog>,
        Arc<MetricsStore>,
        tempfile::TempDir,
    ) {
        let dir = tempfile::TempDir::new().unwrap();
        let wal = Arc::new(WriteAheadLog::new(&dir.path().join("wal.log")).await.unwrap());
        let vlog = Arc::new(VLog::new(&dir.path().join("vlog.log")).await.unwrap());
        let fm = Arc::new(FileManager::new(dir.path()).await.unwrap());
        let mm = Arc::new(ManifestManager::new(dir.path()));
        let engine = Arc::new(
            LsmStorageEngine::new(
                wal,
                dir.path().join("wal.log"),
                vlog,
                dir.path().join("vlog.log"),
                fm,
                mm,
                crate::engines::lsm::engine::LsmEngineOptions::default(),
            )
            .await
            .unwrap(),
        );
        let domains = Arc::new(RelDomainRegistry::recover(Arc::clone(&engine)).await.unwrap());
        let metrics = MetricsStore::new(MetricsConfig::default());
        let limits = CatalogLimits {
            max_columns: 128,
            max_indexes_per_table: 16,
            max_tables_per_domain: 256,
        };
        let catalog = Arc::new(RelCatalog::recover(Arc::clone(&engine), limits, metrics.clone()).await.unwrap());
        (domains, catalog, metrics, dir)
    }

    // Dispatch smoke test: every DdlPlan variant reaches its catalog primitive.
    #[tokio::test]
    async fn test_dispatch_create_alter_index_drop() {
        let (domains, catalog, metrics, _dir) = make_ctx().await;

        let mut pk = ColumnInput::new("id", ColumnType::Integer);
        pk.primary_key = true;
        let outcome = execute(
            &catalog,
            &domains,
            &metrics,
            "default",
            DdlPlan::CreateTable(TableInput { name: "t".to_string(), columns: vec![pk] }),
        )
        .await
        .unwrap();
        assert!(matches!(outcome, DdlOutcome::TableCreated(_)));

        let outcome = execute(
            &catalog,
            &domains,
            &metrics,
            "default",
            DdlPlan::AddColumn {
                table: "t".to_string(),
                column: ColumnInput::new("age", ColumnType::Integer),
            },
        )
        .await
        .unwrap();
        assert!(matches!(outcome, DdlOutcome::TableAltered(_)));

        // CREATE/DROP INDEX go through RelEngine::execute_create_index (backfill
        // path) and RelEngine::execute; see mod.rs test 18 and dml.rs test 23.

        let outcome = execute(
            &catalog,
            &domains,
            &metrics,
            "default",
            DdlPlan::DropTable { table: "t".to_string() },
        )
        .await
        .unwrap();
        assert!(matches!(outcome, DdlOutcome::TableDropped { .. }));
    }

    // DROP TABLE on a view name (or a missing name) -> TableNotFound, not a
    // silent view delete.
    #[tokio::test]
    async fn test_drop_table_rejects_view_and_missing() {
        let (domains, catalog, metrics, _dir) = make_ctx().await;
        catalog.create_view(&domains, "default", "v", "SELECT 1").await.unwrap();

        let err = execute(
            &catalog,
            &domains,
            &metrics,
            "default",
            DdlPlan::DropTable { table: "v".to_string() },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, RelStoreError::TableNotFound { .. }), "got: {err}");
        // The view must still be there.
        assert!(catalog.get(&domains, "default", "v").is_ok());

        let err = execute(
            &catalog,
            &domains,
            &metrics,
            "default",
            DdlPlan::DropTable { table: "ghost".to_string() },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, RelStoreError::TableNotFound { .. }), "got: {err}");
    }
}
