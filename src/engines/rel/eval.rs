//! Three-valued WHERE predicate evaluator (spec rel/005 §6, concept 3.7).
//!
//! `eval` runs a `Pred` (a WHERE expression bound to a table by the deep-binder
//! in `dml.rs`: columns resolved to row positions, literals/params pre-typed
//! against their column) against one decoded row and yields Kleene
//! `Bool3`. WHERE/UPDATE/DELETE keep only `True` rows. The NULL-bind guard
//! (rel/004) already rejected NULL comparison operands, so the evaluator sees
//! `NULL` only as a column value.

use super::ast::CompareOp;
use super::error::RelStoreError;
use super::types::ScalarValue;
use std::cmp::Ordering;

/// Kleene three-valued truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bool3 {
    True,
    False,
    Unknown,
}

/// A comparison operand: a column (index into the decoded row, in
/// `TableSchema.columns` order) or a pre-typed constant.
#[derive(Debug, Clone)]
pub enum PredOperand {
    Column(usize),
    Value(ScalarValue),
}

/// A WHERE predicate bound to one table. `col` fields index the decoded row.
#[derive(Debug, Clone)]
pub enum Pred {
    Compare {
        lhs: PredOperand,
        op: CompareOp,
        rhs: PredOperand,
    },
    In {
        col: usize,
        negated: bool,
        list: Vec<ScalarValue>,
    },
    Like {
        col: usize,
        negated: bool,
        pattern: String,
    },
    IsNull {
        col: usize,
        negated: bool,
    },
    And(Box<Pred>, Box<Pred>),
    Or(Box<Pred>, Box<Pred>),
    Not(Box<Pred>),
}

/// Evaluates `pred` against `row` (values in `TableSchema.columns` order).
///
/// Fallible (rel/017): a pathologically self-similar LIKE pattern aborts
/// `like_match` after its step budget instead of pinning a CPU core; that
/// error propagates through `?` before `maybe_negate` runs, so `NOT LIKE`
/// over budget is the same error, never a silent negation. `And`/`Or` keep
/// evaluating both sides unconditionally (no new short-circuit on the
/// `Bool3` result), so a budget error on either side always propagates.
pub fn eval(pred: &Pred, row: &[ScalarValue]) -> Result<Bool3, RelStoreError> {
    Ok(match pred {
        Pred::Compare { lhs, op, rhs } => {
            let a = resolve(lhs, row);
            let b = resolve(rhs, row);
            if matches!(a, ScalarValue::Null) || matches!(b, ScalarValue::Null) {
                return Ok(Bool3::Unknown);
            }
            apply_op(*op, cmp_scalars(a, b))
        }
        Pred::In { col, negated, list } => {
            let v = &row[*col];
            if matches!(v, ScalarValue::Null) {
                return Ok(Bool3::Unknown);
            }
            let hit = list.iter().any(|e| cmp_scalars(v, e) == Some(Ordering::Equal));
            maybe_negate(from_bool(hit), *negated)
        }
        Pred::Like { col, negated, pattern } => match &row[*col] {
            ScalarValue::Null => Bool3::Unknown,
            ScalarValue::Text(s) => maybe_negate(from_bool(like_match(pattern, s)?), *negated),
            _ => Bool3::Unknown,
        },
        Pred::IsNull { col, negated } => {
            let is_null = matches!(row[*col], ScalarValue::Null);
            from_bool(if *negated { !is_null } else { is_null })
        }
        Pred::And(a, b) => and3(eval(a, row)?, eval(b, row)?),
        Pred::Or(a, b) => or3(eval(a, row)?, eval(b, row)?),
        Pred::Not(a) => not3(eval(a, row)?),
    })
}

fn resolve<'a>(op: &'a PredOperand, row: &'a [ScalarValue]) -> &'a ScalarValue {
    match op {
        PredOperand::Column(i) => &row[*i],
        PredOperand::Value(v) => v,
    }
}

/// Total-ish comparison of two non-NULL scalars; `None` for incomparable pairs
/// (NaN, or type-incompatible — the latter is prevented by binding). Integer
/// widens to Real (the single implicit widening); Timestamp/Text/Boolean only
/// compare among themselves (Integer↔Timestamp share the i64 domain).
///
/// `pub(super)`: reused by the ORDER BY sort comparator (rel/006 `select.rs`)
/// so the widening/ordering rules stay in one place.
pub(super) fn cmp_scalars(a: &ScalarValue, b: &ScalarValue) -> Option<Ordering> {
    use ScalarValue::*;
    match (a, b) {
        (Integer(x), Integer(y))
        | (Timestamp(x), Timestamp(y))
        | (Integer(x), Timestamp(y))
        | (Timestamp(x), Integer(y)) => Some(x.cmp(y)),
        (Real(x), Real(y)) => x.partial_cmp(y),
        (Integer(x), Real(y)) => (*x as f64).partial_cmp(y),
        (Real(x), Integer(y)) => x.partial_cmp(&(*y as f64)),
        (Text(x), Text(y)) => Some(x.cmp(y)),
        (Boolean(x), Boolean(y)) => Some(x.cmp(y)),
        _ => None,
    }
}

fn apply_op(op: CompareOp, ord: Option<Ordering>) -> Bool3 {
    let Some(o) = ord else {
        return Bool3::Unknown;
    };
    from_bool(match op {
        CompareOp::Eq => o == Ordering::Equal,
        CompareOp::NotEq => o != Ordering::Equal,
        CompareOp::Lt => o == Ordering::Less,
        CompareOp::LtEq => o != Ordering::Greater,
        CompareOp::Gt => o == Ordering::Greater,
        CompareOp::GtEq => o != Ordering::Less,
    })
}

/// SQL `LIKE`: `%` = any (incl. empty) run, `_` = exactly one char, fully
/// anchored, no `ESCAPE` (KISS).
///
/// Greedy two-pointer scan backtracking to the last unresolved `%` (rel/015):
/// O(1) extra space instead of the former O(np·nt) DP table. Time stays
/// O(np·nt) in the worst case (one `%` plus a long near-matching literal);
/// measured bound in rel/015's implementation note.
///
/// rel/017: that worst case is bounded by a step budget proportional to the
/// input size (`64·(np+nt) + 4096` — massive headroom over any legitimate
/// pattern, derivation in the spec), counted once per main-loop iteration.
/// Exceeding it aborts loudly (`LikeBudgetExceeded`) rather than silently
/// returning `false`, which would be a silent false negative.
fn like_match(pattern: &str, text: &str) -> Result<bool, RelStoreError> {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (np, nt) = (p.len(), t.len());
    let max_steps = 64 * (np + nt) + 4096;

    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star_pi: Option<usize> = None; // pattern index of the last unresolved '%'
    let mut star_ti = 0usize; // text index right after that '%'s current match
    let mut steps = 0usize;

    while ti < nt {
        steps += 1;
        if steps > max_steps {
            return Err(RelStoreError::LikeBudgetExceeded { steps, max: max_steps });
        }
        // '%' first: a literal '%' in the text must not consume the wildcard.
        if pi < np && p[pi] == '%' {
            star_pi = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if pi < np && (p[pi] == '_' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if let Some(sp) = star_pi {
            star_ti += 1;
            pi = sp + 1;
            ti = star_ti;
        } else {
            return Ok(false);
        }
    }
    while pi < np && p[pi] == '%' {
        pi += 1;
    }
    Ok(pi == np)
}

fn from_bool(b: bool) -> Bool3 {
    if b {
        Bool3::True
    } else {
        Bool3::False
    }
}

fn maybe_negate(b: Bool3, negated: bool) -> Bool3 {
    if negated {
        not3(b)
    } else {
        b
    }
}

fn not3(x: Bool3) -> Bool3 {
    match x {
        Bool3::True => Bool3::False,
        Bool3::False => Bool3::True,
        Bool3::Unknown => Bool3::Unknown,
    }
}

fn and3(x: Bool3, y: Bool3) -> Bool3 {
    match (x, y) {
        (Bool3::False, _) | (_, Bool3::False) => Bool3::False,
        (Bool3::True, Bool3::True) => Bool3::True,
        _ => Bool3::Unknown,
    }
}

fn or3(x: Bool3, y: Bool3) -> Bool3 {
    match (x, y) {
        (Bool3::True, _) | (_, Bool3::True) => Bool3::True,
        (Bool3::False, Bool3::False) => Bool3::False,
        _ => Bool3::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RelStoreConfig;
    use crate::engines::rel::{CrossEngineResolver, LinkAuth, RelEngine, SqlOutcome};
    use crate::metrics::{MetricsConfig, MetricsStore};

    fn col_eq(col: usize, v: ScalarValue) -> Pred {
        Pred::Compare {
            lhs: PredOperand::Column(col),
            op: CompareOp::Eq,
            rhs: PredOperand::Value(v),
        }
    }

    // 18. `col = ?` with a NULL column value → Unknown (row drops from WHERE);
    //     Kleene matrix NOT/AND/OR.
    #[test]
    fn test_three_valued_logic() {
        let row = vec![ScalarValue::Null];
        assert_eq!(eval(&col_eq(0, ScalarValue::Integer(1)), &row).unwrap(), Bool3::Unknown);

        // NOT UNKNOWN = UNKNOWN
        let unknown = col_eq(0, ScalarValue::Integer(1));
        assert_eq!(eval(&Pred::Not(Box::new(unknown.clone())), &row).unwrap(), Bool3::Unknown);

        let t = Pred::IsNull { col: 0, negated: false }; // True (value is NULL)
        assert_eq!(eval(&t, &row).unwrap(), Bool3::True);
        // UNKNOWN AND TRUE = UNKNOWN
        assert_eq!(
            eval(&Pred::And(Box::new(unknown.clone()), Box::new(t.clone())), &row).unwrap(),
            Bool3::Unknown
        );
        // UNKNOWN OR TRUE = TRUE
        assert_eq!(eval(&Pred::Or(Box::new(unknown), Box::new(t)), &row).unwrap(), Bool3::True);
    }

    // 19. IN, LIKE (%/_), IS [NOT] NULL; LIKE on NULL → Unknown.
    #[test]
    fn test_in_like_isnull() {
        let row = vec![ScalarValue::Integer(2), ScalarValue::Text("hello".to_string())];
        let in_pred = Pred::In {
            col: 0,
            negated: false,
            list: vec![ScalarValue::Integer(1), ScalarValue::Integer(2)],
        };
        assert_eq!(eval(&in_pred, &row).unwrap(), Bool3::True);
        let not_in = Pred::In {
            col: 0,
            negated: true,
            list: vec![ScalarValue::Integer(9)],
        };
        assert_eq!(eval(&not_in, &row).unwrap(), Bool3::True);

        let like = |pat: &str| Pred::Like { col: 1, negated: false, pattern: pat.to_string() };
        assert_eq!(eval(&like("h%o"), &row).unwrap(), Bool3::True);
        assert_eq!(eval(&like("h_llo"), &row).unwrap(), Bool3::True);
        assert_eq!(eval(&like("h_lo"), &row).unwrap(), Bool3::False);
        assert_eq!(eval(&like("%"), &row).unwrap(), Bool3::True);

        assert_eq!(eval(&Pred::IsNull { col: 0, negated: false }, &row).unwrap(), Bool3::False);
        assert_eq!(eval(&Pred::IsNull { col: 0, negated: true }, &row).unwrap(), Bool3::True);

        let null_row = vec![ScalarValue::Null, ScalarValue::Null];
        assert_eq!(eval(&like("%"), &null_row).unwrap(), Bool3::Unknown);
    }

    // 20. INTEGER→REAL widening in a comparison: real_col > 3 matches 3.5.
    #[test]
    fn test_integer_real_widening() {
        let row = vec![ScalarValue::Real(3.5)];
        let gt = Pred::Compare {
            lhs: PredOperand::Column(0),
            op: CompareOp::Gt,
            rhs: PredOperand::Value(ScalarValue::Integer(3)),
        };
        assert_eq!(eval(&gt, &row).unwrap(), Bool3::True);
    }

    // like_match semantics beyond test_in_like_isnull above (rel/015): empty
    // pattern/text, bare/doubled '%', leading/middle/trailing '%', '_' at the
    // edge and repeated, '%_' combinations, a wildcard-free pattern, and
    // multi-byte chars (char, not byte, semantics).
    #[test]
    fn test_like_match_semantics() {
        assert!(like_match("", "").unwrap());
        assert!(!like_match("", "x").unwrap());

        assert!(like_match("%", "").unwrap());
        assert!(like_match("%", "anything").unwrap());
        assert!(like_match("%%", "").unwrap());
        assert!(like_match("%%", "anything").unwrap());

        assert!(like_match("%bc", "abc").unwrap()); // leading %
        assert!(!like_match("%bc", "abx").unwrap());
        assert!(like_match("a%c", "abbbc").unwrap()); // middle %
        assert!(!like_match("a%c", "abbbx").unwrap());
        assert!(like_match("ab%", "abcde").unwrap()); // trailing %
        assert!(!like_match("ab%", "xbcde").unwrap());

        assert!(like_match("_", "a").unwrap());
        assert!(!like_match("_", "ab").unwrap());
        assert!(!like_match("_", "").unwrap());
        assert!(like_match("__", "ab").unwrap()); // repeated '_'
        assert!(!like_match("__", "a").unwrap());

        assert!(like_match("%_", "a").unwrap()); // at least one char
        assert!(!like_match("%_", "").unwrap());
        assert!(like_match("_%", "a").unwrap());
        assert!(like_match("a%_", "ab").unwrap());
        assert!(!like_match("a%_", "a").unwrap());

        assert!(like_match("hello", "hello").unwrap()); // no wildcards: exact match
        assert!(!like_match("hello", "hello!").unwrap());
        assert!(!like_match("hello", "hell").unwrap());

        assert!(like_match("%b", "%ab").unwrap()); // literal '%' in text stays matchable by the wildcard
        assert!(like_match("a%b", "a%b").unwrap());
        assert!(like_match("%_", "%").unwrap()); // '_' matches a literal '%'
        assert!(!like_match("%b", "%a").unwrap());

        assert!(like_match("cl%", "clé").unwrap()); // 'é' is one char, not two bytes
        assert!(like_match("cl_", "clé").unwrap());
        assert!(!like_match("cl__", "clé").unwrap());
        assert!(like_match("_", "🎉").unwrap()); // emoji is one char
        assert!(like_match("%🎉%", "party🎉time").unwrap());
        assert!(!like_match("%🎉%", "party time").unwrap());
    }

    // NOT LIKE via eval(): negates True/False; Unknown (NULL column) unchanged.
    #[test]
    fn test_not_like() {
        let row = vec![ScalarValue::Text("hello".to_string())];
        let not_like = |pat: &str| Pred::Like { col: 0, negated: true, pattern: pat.to_string() };
        assert_eq!(eval(&not_like("h%o"), &row).unwrap(), Bool3::False);
        assert_eq!(eval(&not_like("x%"), &row).unwrap(), Bool3::True);

        let null_row = vec![ScalarValue::Null];
        assert_eq!(eval(&not_like("%"), &null_row).unwrap(), Bool3::Unknown);
    }

    // Memory-/runtime proof (rel/015): a ~64Ki-char pattern against a
    // ~64Ki-char text used to allocate an ~4.3 GiB DP table before this fix;
    // the greedy matcher needs O(1) extra space and returns well under a
    // second.
    #[test]
    fn test_like_large_pattern_no_dp_allocation() {
        let text: String = "a".repeat(64 * 1024);
        let pattern = format!("%{text}");
        let start = std::time::Instant::now();
        assert!(like_match(&pattern, &text).unwrap());
        let elapsed = start.elapsed();
        assert!(elapsed < std::time::Duration::from_millis(500), "took {elapsed:?}");
    }

    // rel/017 Budget greift (spec §Tests 2): the rel/015 worst case — one '%'
    // plus a long self-similar literal that never actually matches (the text
    // has no trailing 'b') — aborts with LikeBudgetExceeded. No wall-clock
    // assertion: the step count is capped deterministically (boundary pair
    // below pins the formula), and a timing bound flaked on slower CI
    // hardware. Measured once: ~90 ms debug vs ~9.2 s unbounded (rel/015
    // Umsetzungsnotiz, Prüfpunkt 1).
    #[test]
    fn test_like_budget_exceeded() {
        let pattern = format!("%{}b", "a".repeat(32 * 1024));
        let text = "a".repeat(64 * 1024);
        let err = like_match(&pattern, &text).unwrap_err();
        assert!(matches!(err, RelStoreError::LikeBudgetExceeded { .. }), "{err:?}");
    }

    // rel/017 Budget schont Legitimes (spec §Tests 3): the rel/015
    // measurement case — %-heavy but linear, each '%' only ever backtracks
    // against the next character — stays Ok at the same 64 Ki/64 Ki scale.
    #[test]
    fn test_like_budget_spares_linear_pattern() {
        let pattern = format!("{}b", "%a".repeat(32 * 1024));
        let text = format!("{}b", "a".repeat(64 * 1024));
        let start = std::time::Instant::now();
        let matched = like_match(&pattern, &text).unwrap();
        let elapsed = start.elapsed();
        assert!(matched);
        assert!(elapsed < std::time::Duration::from_millis(500), "took {elapsed:?}");
    }

    // rel/017 NOT LIKE über Budget (spec §Tests 4): the budget error
    // propagates through eval() before maybe_negate — same error, never a
    // silently negated success.
    #[test]
    fn test_not_like_budget_exceeded() {
        let pattern = format!("%{}b", "a".repeat(32 * 1024));
        let row = vec![ScalarValue::Text("a".repeat(64 * 1024))];
        let not_like = Pred::Like { col: 0, negated: true, pattern };
        let err = eval(&not_like, &row).unwrap_err();
        assert!(matches!(err, RelStoreError::LikeBudgetExceeded { .. }), "{err:?}");
    }

    // rel/017 Grenzverhalten (spec §Tests 6): steps == budget still matches;
    // only a strictly greater count aborts. pattern = '%' + 64 'a's (np=65),
    // text = 12351 'a's (nt=12351): like_match's step count for this shape
    // is exactly nt + 1 + 64*(nt-64) = 798720, equal to the budget
    // 64*(np+nt)+4096 = 798720.
    #[test]
    fn test_like_budget_boundary_exact_match_still_ok() {
        let pattern = format!("%{}", "a".repeat(64));
        let text = "a".repeat(12_351);
        assert!(like_match(&pattern, &text).unwrap());
    }

    // Counterpart pinning the boundary empirically: one more text char adds
    // 65 steps but only 64 budget, tipping steps to max+1 — the smallest
    // possible overshoot must already abort. Together with the test above
    // this brackets the budget formula to the exact step.
    #[test]
    fn test_like_budget_boundary_one_step_over_aborts() {
        let pattern = format!("%{}", "a".repeat(64));
        let text = "a".repeat(12_352);
        let err = like_match(&pattern, &text).unwrap_err();
        assert!(matches!(err, RelStoreError::LikeBudgetExceeded { .. }), "{err:?}");
    }

    // End-to-end (rel/015): SELECT ... WHERE txt LIKE '%...' over
    // execute_sql against a table holding a large TEXT row runs through.
    #[tokio::test]
    async fn test_like_end_to_end_large_text() {
        let dir = tempfile::TempDir::new().unwrap();
        let config = RelStoreConfig {
            wal_path: dir.path().join("rel.wal").to_string_lossy().into_owned(),
            vlog_path: dir.path().join("rel.vlog").to_string_lossy().into_owned(),
            sstable_dir: dir.path().join("ss").to_string_lossy().into_owned(),
            ..RelStoreConfig::default()
        };
        let metrics = MetricsStore::new(MetricsConfig::default());
        let cross_engine = CrossEngineResolver::disabled(std::sync::Arc::clone(&metrics));
        let rel = RelEngine::bootstrap(&config, metrics, cross_engine).await.unwrap();

        rel.execute_sql("default", "CREATE TABLE t (id INTEGER PRIMARY KEY, txt TEXT)", &[], &[], LinkAuth::full())
            .await
            .unwrap();
        let big = format!("{}NEEDLE", "a".repeat(60_000));
        rel.execute_sql("default", "INSERT INTO t VALUES (1, ?)", &[serde_json::json!(big)], &[], LinkAuth::full())
            .await
            .unwrap();

        let outcome = rel
            .execute_sql("default", "SELECT id FROM t WHERE txt LIKE '%NEEDLE'", &[], &[], LinkAuth::full())
            .await
            .unwrap();
        match outcome {
            SqlOutcome::Select { result, .. } => {
                assert_eq!(result.rows, vec![vec![ScalarValue::Integer(1)]]);
            }
            o => panic!("expected SELECT, got {o:?}"),
        }
    }
}
