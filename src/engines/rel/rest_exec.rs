//! REST-edge execution entry point: rate-limits a
//! statement by class *before* any execution I/O, executes it through the
//! shared `execute_checked` core (`mod.rs`), and — for a SELECT with a
//! non-empty `expand` — resolves REFERENCES columns (`expand.rs`) in the
//! same MVCC snapshot the SELECT itself read at.

use super::ast::StatementClass;
use super::cross_engine::LinkAuth;
use super::dml::{DmlResult, SelectResult};
use super::error::RelStoreError;
use super::{ExecOutcome, RelEngine};
use crate::engines::lsm::rate_limiter::RateLimiter;
use std::sync::Arc;

/// One entry per resolved `expand` column: the output name, and one resolved
/// JSON value (an object, or `null`) per SELECT result row, in row order.
/// Built at the engine layer (not `src/api/rel.rs`): the values are already
/// `serde_json::Value` here because resolution needs `scalar_to_json`
/// (`types.rs`) regardless of which layer defines the alias — see that
/// function's doc comment for why it lives engine-side.
pub type ExpandedBlock = Vec<(String, Vec<serde_json::Value>)>;

/// `RelEngine::execute_sql`'s result, tagged by statement class —
/// the REST-facing counterpart of `ExecOutcome`, with `expand` folded in.
#[derive(Debug)]
pub enum SqlOutcome {
    Ddl,
    Dml(DmlResult),
    Select {
        result: SelectResult,
        expanded: Option<ExpandedBlock>,
    },
}

impl RelEngine {
    /// Parse-only classification: lexes/parses `sql`
    /// (the same `max_statement_len` guard as `execute`) and returns its
    /// `StatementClass` without binding or executing it. Unused by
    /// `execute_sql` (which learns the class from its own single
    /// internal parse, via `execute_checked`'s `mid` hook) — provided so
    /// the auth layer can classify-then-authorize *before* calling `execute_sql`,
    /// without changing this method.
    pub fn classify(&self, sql: &str) -> Result<StatementClass, RelStoreError> {
        let tokens = super::lexer::tokenize(sql, self.max_statement_len)?;
        let stmt = super::parser::parse(&tokens)?;
        Ok(stmt.class())
    }

    /// The domain's rate limiter, created from the engine's quota on first use.
    fn limiter_for(&self, domain: &str) -> Arc<RateLimiter> {
        let existing = self.rate_limiters.read().get(domain).cloned();
        existing.unwrap_or_else(|| {
            Arc::clone(
                self.rate_limiters
                    .write()
                    .entry(domain.to_string())
                    .or_insert_with(|| Arc::new(RateLimiter::new(self.domain_quota))),
            )
        })
    }

    /// Charges one op against the domain's rate limiter. `write`: DML/DDL
    /// draw the write bucket, SELECT the read bucket (separate buckets).
    /// `false` ⇒ the caller must not perform any execution I/O.
    pub fn check_domain_budget(&self, domain: &str, write: bool) -> bool {
        let limiter = self.limiter_for(domain);
        if write {
            limiter.check_write()
        } else {
            limiter.check_read()
        }
    }

    /// Test-only counterpart to `check_domain_budget`: drains and locks the
    /// matching bucket (`drain_for_test`) instead of consuming one token, so
    /// the outcome does not depend on refill timing.
    #[cfg(test)]
    pub fn drain_domain_budget_for_test(&self, domain: &str, write: bool) {
        let limiter = self.limiter_for(domain);
        if write {
            limiter.write_bucket.drain_for_test()
        } else {
            limiter.read_bucket.drain_for_test()
        }
    }

    /// The REST-edge entry point: rate-limits by class *before*
    /// any execution I/O, executes the statement once (`execute_checked`,
    /// one parse), and — for a SELECT with a non-empty `expand` — resolves
    /// REFERENCES columns (`expand.rs`) in the same snapshot the SELECT read
    /// at (`SelectResult::snapshot`). Non-empty `expand` on DML/DDL is
    /// rejected. `auth` gates cross-engine link masking/validation for
    /// this call.
    pub async fn execute_sql(
        &self,
        domain: &str,
        sql: &str,
        params: &[serde_json::Value],
        expand: &[String],
        auth: LinkAuth,
    ) -> Result<SqlOutcome, RelStoreError> {
        let domain = domain.to_string();
        // Both checks run inside `mid` — i.e. before `execute_checked` ever
        // binds/dispatches the statement: `expand` on a non-SELECT
        // must reject *before* a DML/DDL statement runs, not after (an
        // INSERT must not silently commit just because the trailing
        // `expand` validation fails) — same reasoning as the rate limit
        // needing to sit before any execution I/O.
        let outcome = self
            .execute_checked(&domain, sql, params, auth, |class| {
                if !expand.is_empty() && class != StatementClass::Read {
                    return Err(RelStoreError::InvalidExpand(
                        "expand is only valid for SELECT".to_string(),
                    ));
                }
                let write = class != StatementClass::Read;
                if self.check_domain_budget(&domain, write) {
                    Ok(())
                } else {
                    self.metrics.record_rate_limit_rejection(&domain);
                    Err(RelStoreError::RateLimited { domain: domain.clone() })
                }
            })
            .await?;

        match outcome {
            ExecOutcome::Ddl(_) => Ok(SqlOutcome::Ddl),
            ExecOutcome::Dml(r) => Ok(SqlOutcome::Dml(r)),
            ExecOutcome::Select(result) => {
                let expanded = if expand.is_empty() {
                    None
                } else {
                    let resolved = self.resolve_expand(&domain, &result, expand).await?;
                    (!resolved.is_empty()).then_some(resolved)
                };
                Ok(SqlOutcome::Select { result, expanded })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RelStoreConfig;
    use crate::metrics::{MetricsConfig, MetricsStore};
    use serde_json::json;

    async fn make_engine() -> (Arc<RelEngine>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let config = RelStoreConfig {
            wal_path: dir.path().join("rel.wal").to_string_lossy().into_owned(),
            vlog_path: dir.path().join("rel.vlog").to_string_lossy().into_owned(),
            sstable_dir: dir.path().join("rel_sstables").to_string_lossy().into_owned(),
            ..RelStoreConfig::default()
        };
        let metrics = MetricsStore::new(MetricsConfig::default());
        let cross_engine = crate::engines::rel::CrossEngineResolver::disabled(Arc::clone(&metrics));
        let engine = RelEngine::bootstrap(&config, metrics, cross_engine).await.unwrap();
        (engine, dir)
    }

    async fn make_parent_child() -> (Arc<RelEngine>, tempfile::TempDir) {
        let (rel, dir) = make_engine().await;
        for sql in [
            "CREATE TABLE parent (id INTEGER PRIMARY KEY, name TEXT)",
            "CREATE TABLE child (id INTEGER PRIMARY KEY, pid INTEGER REFERENCES parent)",
            "INSERT INTO parent VALUES (7, 'p')",
            "INSERT INTO child VALUES (1, 7)",
        ] {
            rel.execute("default", sql, &[]).await.unwrap();
        }
        (rel, dir)
    }

    /// Runs `sql` through `execute_sql` and returns the registry's active count
    /// while the SELECT result is alive, then after it is dropped, plus the
    /// expanded block.
    async fn active_counts(rel: &RelEngine, sql: &str, expand: &[&str]) -> (usize, usize, Option<ExpandedBlock>) {
        let expand: Vec<String> = expand.iter().map(|s| s.to_string()).collect();
        let registry = rel.engine().snapshot_registry();
        assert_eq!(registry.active_count(), 0, "no snapshot registered before the statement");
        match rel.execute_sql("default", sql, &[], &expand, LinkAuth::full()).await.unwrap() {
            SqlOutcome::Select { result, expanded } => {
                let alive = registry.active_count();
                drop(result);
                (alive, registry.active_count(), expanded)
            }
            o => panic!("expected SELECT, got {o:?}"),
        }
    }

    // The guard lives in the result, so the registered stamp covers
    // the expand lookups and everything the caller does with the result.
    #[test]
    fn test_select_expand_keeps_snapshot_registered_until_result_dropped() {
        crate::core::engine_runtime::block_on(async {
            let (rel, _dir) = make_parent_child().await;
            let (alive, after_drop, expanded) = active_counts(&rel, "SELECT * FROM child", &["pid"]).await;
            assert_eq!(alive, 1, "result must hold the registered snapshot");
            assert_eq!(after_drop, 0, "dropping the result deregisters it");
            assert_eq!(expanded.unwrap()[0].1, vec![json!({"id": 7, "name": "p"})]);
        })
    }

    #[test]
    fn test_join_select_expand_keeps_snapshot_registered_until_result_dropped() {
        crate::core::engine_runtime::block_on(async {
            let (rel, _dir) = make_parent_child().await;
            let sql = "SELECT c.id, c.pid FROM child c LEFT JOIN parent p ON c.pid = p.id";
            let (alive, after_drop, expanded) = active_counts(&rel, sql, &["pid"]).await;
            assert_eq!(alive, 1, "result must hold the registered snapshot");
            assert_eq!(after_drop, 0, "dropping the result deregisters it");
            assert_eq!(expanded.unwrap()[0].1, vec![json!({"id": 7, "name": "p"})]);
        })
    }

    #[test]
    fn test_count_star_holds_no_snapshot_after_return() {
        crate::core::engine_runtime::block_on(async {
            let (rel, _dir) = make_parent_child().await;
            for sql in ["SELECT COUNT(*) FROM child", "SELECT COUNT(*) FROM child c LEFT JOIN parent p ON c.pid = p.id"] {
                let (alive, after_drop, _) = active_counts(&rel, sql, &[]).await;
                assert_eq!((alive, after_drop), (0, 0), "{sql}");
            }
        })
    }
}
