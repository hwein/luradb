//! REST-edge execution entry point (spec rel/009 §3/§7/§9): rate-limits a
//! statement by class *before* any execution I/O, executes it through the
//! shared `execute_checked` core (`mod.rs`), and — for a SELECT with a
//! non-empty `expand` — resolves REFERENCES columns (`expand.rs`) in the
//! same MVCC snapshot the SELECT itself read at.

use super::ast::StatementClass;
use super::dml::{DmlResult, SelectResult};
use super::error::RelStoreError;
use super::{ExecOutcome, RelEngine};
use crate::engines::lsm::rate_limiter::{DomainQuota, RateLimiter};
use std::sync::Arc;

/// One entry per resolved `expand` column: the output name, and one resolved
/// JSON value (an object, or `null`) per SELECT result row, in row order
/// (spec §5). Built at the engine layer (not `src/api/rel.rs`, where the
/// spec's own snippet places `ExpandedBlock`): the values are already
/// `serde_json::Value` here because resolution needs `scalar_to_json`
/// (`types.rs`) regardless of which layer defines the alias — see that
/// function's doc comment for why it lives engine-side.
pub type ExpandedBlock = Vec<(String, Vec<serde_json::Value>)>;

/// `RelEngine::execute_sql`'s result, tagged by statement class (spec §3) —
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
    /// Parse-only classification (rel/011 seam, spec §9): lexes/parses `sql`
    /// (the same `max_statement_len` guard as `execute`) and returns its
    /// `StatementClass` without binding or executing it. Unused by this
    /// spec's own `execute_sql` (which learns the class from its own single
    /// internal parse, via `execute_checked`'s `mid` hook) — provided so
    /// rel/011 can classify-then-authorize *before* calling `execute_sql`,
    /// without changing this method.
    pub fn classify(&self, sql: &str) -> Result<StatementClass, RelStoreError> {
        let tokens = super::lexer::tokenize(sql, self.max_statement_len)?;
        let stmt = super::parser::parse(&tokens)?;
        Ok(stmt.class())
    }

    /// Lazily creates a per-domain `RateLimiter` (spec §7, KV `DomainRegistry`
    /// pattern reuse: `DomainQuota::default()`, no per-domain tuning) and
    /// charges one op against it. `write`: DML/DDL draw the write bucket,
    /// SELECT the read bucket (separate buckets, spec §7). `false` ⇒ the
    /// caller must not perform any execution I/O.
    pub fn check_domain_budget(&self, domain: &str, write: bool) -> bool {
        let existing = self.rate_limiters.read().get(domain).cloned();
        let limiter = existing.unwrap_or_else(|| {
            Arc::clone(
                self.rate_limiters
                    .write()
                    .entry(domain.to_string())
                    .or_insert_with(|| Arc::new(RateLimiter::new(DomainQuota::default()))),
            )
        });
        if write {
            limiter.check_write()
        } else {
            limiter.check_read()
        }
    }

    /// Test-only counterpart to `check_domain_budget`: same lazy-registry
    /// lookup, but drains and locks the matching bucket (`drain_for_test`)
    /// instead of consuming one token (flaky-test fix, spec general/008).
    #[cfg(test)]
    pub fn drain_domain_budget_for_test(&self, domain: &str, write: bool) {
        let existing = self.rate_limiters.read().get(domain).cloned();
        let limiter = existing.unwrap_or_else(|| {
            Arc::clone(
                self.rate_limiters
                    .write()
                    .entry(domain.to_string())
                    .or_insert_with(|| Arc::new(RateLimiter::new(DomainQuota::default()))),
            )
        });
        if write {
            limiter.write_bucket.drain_for_test()
        } else {
            limiter.read_bucket.drain_for_test()
        }
    }

    /// The REST-edge entry point (spec §3): rate-limits by class *before*
    /// any execution I/O (§7), executes the statement once (`execute_checked`,
    /// one parse), and — for a SELECT with a non-empty `expand` — resolves
    /// REFERENCES columns (`expand.rs`) in the same snapshot the SELECT read
    /// at (`SelectResult::snapshot`, §5). Non-empty `expand` on DML/DDL is
    /// rejected (§5).
    pub async fn execute_sql(
        &self,
        domain: &str,
        sql: &str,
        params: &[serde_json::Value],
        expand: &[String],
    ) -> Result<SqlOutcome, RelStoreError> {
        let domain = domain.to_string();
        // Both checks run inside `mid` — i.e. before `execute_checked` ever
        // binds/dispatches the statement (§5/§7): `expand` on a non-SELECT
        // must reject *before* a DML/DDL statement runs, not after (an
        // INSERT must not silently commit just because the trailing
        // `expand` validation fails) — same reasoning as the rate limit
        // needing to sit before any execution I/O.
        let outcome = self
            .execute_checked(&domain, sql, params, |class| {
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
