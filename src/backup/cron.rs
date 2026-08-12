//! 5-field cron subset (spec general/006 "Konfigurationsschema"): minute,
//! hour, day-of-month, month, weekday. Supports `*`, single values, lists
//! (`a,b,c`), ranges (`a-b`) and steps (`*/n`, `a-b/n`). No names (`MON`,
//! `JAN`), no special characters (`@daily`, `L`, `#`).
//!
//! Fields are expanded eagerly into sorted value lists at parse time, so
//! `matches` is a pure function over already-split time fields — no
//! wall-clock or date-math access needed here. The unix-seconds → fields
//! conversion is added in a later step.

use anyhow::{ensure, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CronSchedule {
    minute: Vec<u32>,
    hour: Vec<u32>,
    day_of_month: Vec<u32>,
    month: Vec<u32>,
    weekday: Vec<u32>,
    // Whether the raw day-of-month/weekday fields were literally `*` —
    // needed for the OR rule below, independent of what the expanded set covers.
    dom_is_wildcard: bool,
    dow_is_wildcard: bool,
}

impl CronSchedule {
    /// Parses a 5-field cron expression: "minute hour day-of-month month weekday".
    /// Weekday is 0-6 (0 = Sunday).
    pub fn parse(expr: &str) -> Result<Self> {
        let fields: Vec<&str> = expr.split_whitespace().collect();
        ensure!(
            fields.len() == 5,
            "cron expression '{expr}' must have exactly 5 fields (minute hour day-of-month month weekday), got {}",
            fields.len()
        );
        let (minute, _) = parse_field(fields[0], 0, 59, "minute")?;
        let (hour, _) = parse_field(fields[1], 0, 23, "hour")?;
        let (day_of_month, dom_is_wildcard) = parse_field(fields[2], 1, 31, "day-of-month")?;
        let (month, _) = parse_field(fields[3], 1, 12, "month")?;
        let (weekday, dow_is_wildcard) = parse_field(fields[4], 0, 6, "weekday")?;
        Ok(Self {
            minute,
            hour,
            day_of_month,
            month,
            weekday,
            dom_is_wildcard,
            dow_is_wildcard,
        })
    }

    /// Whether this schedule fires at the given UTC time fields. Day-of-month
    /// and weekday combine with OR when both are restricted (classic cron
    /// semantics); if only one of the two is restricted, the other applies alone.
    pub fn matches(&self, minute: u32, hour: u32, day_of_month: u32, month: u32, weekday: u32) -> bool {
        if !self.minute.contains(&minute) || !self.hour.contains(&hour) || !self.month.contains(&month) {
            return false;
        }
        match (self.dom_is_wildcard, self.dow_is_wildcard) {
            (true, true) => true,
            (true, false) => self.weekday.contains(&weekday),
            (false, true) => self.day_of_month.contains(&day_of_month),
            (false, false) => self.day_of_month.contains(&day_of_month) || self.weekday.contains(&weekday),
        }
    }
}

/// Parses one field, returning its expanded, sorted, deduped value set and
/// whether the raw field was exactly `*`.
fn parse_field(field: &str, min: u32, max: u32, name: &str) -> Result<(Vec<u32>, bool)> {
    let is_wildcard = field == "*";
    let mut values = Vec::new();
    for part in field.split(',') {
        ensure!(!part.is_empty(), "cron field '{name}': empty list item in '{field}'");
        values.extend(parse_item(part, min, max, name)?);
    }
    values.sort_unstable();
    values.dedup();
    Ok((values, is_wildcard))
}

/// Parses one comma-separated item: `*`, `*/n`, `a-b/n`, `a-b`, or a plain value.
fn parse_item(part: &str, min: u32, max: u32, name: &str) -> Result<Vec<u32>> {
    if let Some((base, step_str)) = part.split_once('/') {
        let step: u32 = step_str
            .parse()
            .map_err(|_| anyhow::anyhow!("cron field '{name}': invalid step '{step_str}' in '{part}'"))?;
        ensure!(step >= 1, "cron field '{name}': step must be >= 1 in '{part}'");
        let (lo, hi) = if base == "*" {
            (min, max)
        } else {
            parse_range_bounds(base, min, max, name)?
        };
        return Ok((lo..=hi).step_by(step as usize).collect());
    }
    if part == "*" {
        return Ok((min..=max).collect());
    }
    if part.contains('-') {
        let (lo, hi) = parse_range_bounds(part, min, max, name)?;
        return Ok((lo..=hi).collect());
    }
    Ok(vec![parse_bound(part, min, max, name)?])
}

fn parse_range_bounds(part: &str, min: u32, max: u32, name: &str) -> Result<(u32, u32)> {
    let (lo_str, hi_str) = part
        .split_once('-')
        .ok_or_else(|| anyhow::anyhow!("cron field '{name}': expected a range 'a-b' in '{part}'"))?;
    let lo = parse_bound(lo_str, min, max, name)?;
    let hi = parse_bound(hi_str, min, max, name)?;
    ensure!(
        lo <= hi,
        "cron field '{name}': range start {lo} must be <= end {hi} in '{part}'"
    );
    Ok((lo, hi))
}

fn parse_bound(part: &str, min: u32, max: u32, name: &str) -> Result<u32> {
    let v: u32 = part
        .parse()
        .map_err(|_| anyhow::anyhow!("cron field '{name}': invalid value '{part}'"))?;
    ensure!(
        v >= min && v <= max,
        "cron field '{name}': value {v} out of range [{min}, {max}] in '{part}'"
    );
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wildcard_matches_everything() {
        let sched = CronSchedule::parse("* * * * *").unwrap();
        assert!(sched.matches(0, 0, 1, 1, 0));
        assert!(sched.matches(59, 23, 31, 12, 6));
        assert!(sched.matches(30, 12, 15, 6, 3));
    }

    #[test]
    fn test_single_values() {
        let sched = CronSchedule::parse("30 3 1 6 0").unwrap();
        assert!(sched.matches(30, 3, 1, 6, 0));
        assert!(!sched.matches(31, 3, 1, 6, 0));
        assert!(!sched.matches(30, 4, 1, 6, 0));
    }

    #[test]
    fn test_nightly_example_from_spec() {
        // "0 3 * * *" from the spec's [[backup.schedule]] example.
        let sched = CronSchedule::parse("0 3 * * *").unwrap();
        assert!(sched.matches(0, 3, 1, 1, 0));
        assert!(sched.matches(0, 3, 15, 7, 4));
        assert!(!sched.matches(1, 3, 15, 7, 4));
        assert!(!sched.matches(0, 4, 15, 7, 4));
    }

    #[test]
    fn test_list() {
        let sched = CronSchedule::parse("0,15,30,45 * * * *").unwrap();
        for m in [0, 15, 30, 45] {
            assert!(sched.matches(m, 0, 1, 1, 0));
        }
        for m in [1, 14, 16, 44, 59] {
            assert!(!sched.matches(m, 0, 1, 1, 0));
        }
    }

    #[test]
    fn test_range() {
        let sched = CronSchedule::parse("0-10 * * * *").unwrap();
        assert!(sched.matches(0, 0, 1, 1, 0));
        assert!(sched.matches(10, 0, 1, 1, 0));
        assert!(!sched.matches(11, 0, 1, 1, 0));
    }

    #[test]
    fn test_step_over_wildcard() {
        let sched = CronSchedule::parse("*/15 * * * *").unwrap();
        for m in [0, 15, 30, 45] {
            assert!(sched.matches(m, 0, 1, 1, 0));
        }
        for m in [1, 16, 44, 59] {
            assert!(!sched.matches(m, 0, 1, 1, 0));
        }
    }

    #[test]
    fn test_step_over_range() {
        let sched = CronSchedule::parse("0-30/10 * * * *").unwrap();
        for m in [0, 10, 20, 30] {
            assert!(sched.matches(m, 0, 1, 1, 0));
        }
        for m in [5, 31, 40] {
            assert!(!sched.matches(m, 0, 1, 1, 0));
        }
    }

    #[test]
    fn test_list_of_ranges_and_steps_combine() {
        let sched = CronSchedule::parse("0-5,20,40-50/5 * * * *").unwrap();
        for m in [0, 3, 5, 20, 40, 45, 50] {
            assert!(sched.matches(m, 0, 1, 1, 0), "expected {m} to match");
        }
        for m in [6, 19, 21, 41, 49] {
            assert!(!sched.matches(m, 0, 1, 1, 0), "expected {m} to not match");
        }
    }

    #[test]
    fn test_dom_and_dow_both_restricted_are_or_combined() {
        // Day 1 OR Monday(1).
        let sched = CronSchedule::parse("0 0 1 * 1").unwrap();
        assert!(sched.matches(0, 0, 1, 6, 3)); // day 1, any weekday
        assert!(sched.matches(0, 0, 15, 6, 1)); // any day, Monday
        assert!(!sched.matches(0, 0, 2, 6, 2)); // neither day 1 nor Monday
    }

    #[test]
    fn test_dom_wildcard_dow_restricted_applies_alone() {
        let sched = CronSchedule::parse("0 0 * * 1").unwrap();
        assert!(sched.matches(0, 0, 5, 6, 1));
        assert!(!sched.matches(0, 0, 5, 6, 2));
    }

    #[test]
    fn test_dow_wildcard_dom_restricted_applies_alone() {
        let sched = CronSchedule::parse("0 0 15 * *").unwrap();
        assert!(sched.matches(0, 0, 15, 6, 3));
        assert!(!sched.matches(0, 0, 16, 6, 3));
    }

    #[test]
    fn test_reject_wrong_field_count() {
        assert!(CronSchedule::parse("* * * *").is_err());
        assert!(CronSchedule::parse("* * * * * *").is_err());
        assert!(CronSchedule::parse("").is_err());
    }

    #[test]
    fn test_reject_names() {
        assert!(CronSchedule::parse("0 0 * MON *").is_err());
        assert!(CronSchedule::parse("0 0 * JAN *").is_err());
    }

    #[test]
    fn test_reject_special_characters() {
        assert!(CronSchedule::parse("@daily").is_err());
        assert!(CronSchedule::parse("0 0 L * *").is_err());
        assert!(CronSchedule::parse("0 0 * * 1#3").is_err());
    }

    #[test]
    fn test_reject_out_of_range_boundaries() {
        assert!(CronSchedule::parse("60 0 1 1 0").is_err()); // minute 60
        assert!(CronSchedule::parse("0 24 1 1 0").is_err()); // hour 24
        assert!(CronSchedule::parse("0 0 32 1 0").is_err()); // day 32
        assert!(CronSchedule::parse("0 0 0 1 0").is_err()); // day 0
        assert!(CronSchedule::parse("0 0 1 0 0").is_err()); // month 0
        assert!(CronSchedule::parse("0 0 1 13 0").is_err()); // month 13
        assert!(CronSchedule::parse("0 0 1 1 7").is_err()); // weekday 7
    }

    #[test]
    fn test_boundary_values_accepted() {
        let sched = CronSchedule::parse("59 23 31 12 6").unwrap();
        assert!(sched.matches(59, 23, 31, 12, 6));
    }

    #[test]
    fn test_reject_step_zero_does_not_panic() {
        assert!(CronSchedule::parse("*/0 * * * *").is_err());
        assert!(CronSchedule::parse("0-30/0 * * * *").is_err());
    }

    #[test]
    fn test_reject_reversed_range() {
        assert!(CronSchedule::parse("10-5 * * * *").is_err());
    }

    #[test]
    fn test_reject_empty_list_items() {
        assert!(CronSchedule::parse("1,,2 * * * *").is_err());
    }
}
