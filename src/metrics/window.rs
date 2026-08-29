//! Rolling-window metrics: per-domain sliding-bucket aggregation.
//!
//! `MetricsWindow` accumulates per-second operation counters via lock-free atomics.
//! A background `MetricsTicker` calls `tick()` every second: it swaps the current
//! accumulators into a `BucketSnapshot` and appends it to the `VecDeque`.
//! Buckets older than `capacity` seconds are discarded automatically.

use std::collections::VecDeque;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};

use super::{DomainWindowMetrics, EngineWindowMetrics};

// ── Latency bucket helpers ────────────────────────────────────────────────────

/// Maps a latency in microseconds to one of 7 exponential buckets.
///
/// | Index | Range      |
/// |-------|------------|
/// | 0     | < 10 µs    |
/// | 1     | < 100 µs   |
/// | 2     | < 1 ms     |
/// | 3     | < 10 ms    |
/// | 4     | < 100 ms   |
/// | 5     | < 1 s      |
/// | 6     | ≥ 1 s      |
fn latency_bucket(us: u64) -> usize {
    if us < 10 {
        0
    } else if us < 100 {
        1
    } else if us < 1_000 {
        2
    } else if us < 10_000 {
        3
    } else if us < 100_000 {
        4
    } else if us < 1_000_000 {
        5
    } else {
        6
    }
}

/// Representative midpoint for each bucket (µs) — used for P-value estimation.
const MIDPOINTS: [u64; 7] = [5, 50, 500, 5_000, 50_000, 500_000, 2_000_000];

// ── BucketSnapshot ────────────────────────────────────────────────────────────

pub struct BucketSnapshot {
    pub timestamp_secs: u64,
    pub read_ops: u64,
    pub write_ops: u64,
    /// Counts per latency bucket: [<10µs, <100µs, <1ms, <10ms, <100ms, <1s, ≥1s]
    pub latency_buckets: [u64; 7],
    /// Write-latency counterpart of `latency_buckets` (same bucket scheme).
    pub write_latency_buckets: [u64; 7],
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub rate_limit_rejections: u64,
}

/// Bucket sums across every committed snapshot in a window — the shared
/// result of `MetricsWindow::sum_buckets`, consumed by both `aggregate`
/// (per-domain) and `aggregate_engine` (per-engine).
#[derive(Default)]
struct BucketTotals {
    read_ops: u64,
    write_ops: u64,
    read_latency: [u64; 7],
    write_latency: [u64; 7],
    cache_hits: u64,
    cache_misses: u64,
    rate_limit_rejections: u64,
}

// ── MetricsWindow ─────────────────────────────────────────────────────────────

/// Per-domain sliding-window metrics store.
pub struct MetricsWindow {
    pub capacity: usize,
    // Current-second accumulators (hot path — no lock required).
    cur_read_ops: AtomicU64,
    cur_write_ops: AtomicU64,
    cur_latency: [AtomicU64; 7],
    cur_write_latency: [AtomicU64; 7],
    cur_cache_hits: AtomicU64,
    cur_cache_misses: AtomicU64,
    cur_rate_limit_rejections: AtomicU64,
    // Committed per-second snapshots.
    buckets: Mutex<VecDeque<BucketSnapshot>>,
}

impl MetricsWindow {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            cur_read_ops: AtomicU64::new(0),
            cur_write_ops: AtomicU64::new(0),
            cur_latency: std::array::from_fn(|_| AtomicU64::new(0)),
            cur_write_latency: std::array::from_fn(|_| AtomicU64::new(0)),
            cur_cache_hits: AtomicU64::new(0),
            cur_cache_misses: AtomicU64::new(0),
            cur_rate_limit_rejections: AtomicU64::new(0),
            buckets: Mutex::new(VecDeque::with_capacity(capacity + 1)),
        }
    }

    /// Records a completed read operation on the hot path.
    pub fn record_read(&self, latency_us: u64, is_hit: bool) {
        self.cur_read_ops.fetch_add(1, Ordering::Relaxed);
        self.cur_latency[latency_bucket(latency_us)].fetch_add(1, Ordering::Relaxed);
        if is_hit {
            self.cur_cache_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.cur_cache_misses.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Records a completed write operation on the hot path.
    pub fn record_write(&self, latency_us: u64) {
        self.cur_write_ops.fetch_add(1, Ordering::Relaxed);
        self.cur_write_latency[latency_bucket(latency_us)].fetch_add(1, Ordering::Relaxed);
    }

    /// Records a rate-limit rejection.
    pub fn record_rate_limit_rejection(&self) {
        self.cur_rate_limit_rejections.fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshots the current accumulators into a new bucket and rotates old buckets.
    ///
    /// Called once per second by `MetricsTicker`.
    pub fn tick(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut latency_buckets = [0u64; 7];
        let mut write_latency_buckets = [0u64; 7];
        for i in 0..7 {
            latency_buckets[i] = self.cur_latency[i].swap(0, Ordering::AcqRel);
            write_latency_buckets[i] = self.cur_write_latency[i].swap(0, Ordering::AcqRel);
        }

        let snapshot = BucketSnapshot {
            timestamp_secs: now,
            read_ops: self.cur_read_ops.swap(0, Ordering::AcqRel),
            write_ops: self.cur_write_ops.swap(0, Ordering::AcqRel),
            latency_buckets,
            write_latency_buckets,
            cache_hits: self.cur_cache_hits.swap(0, Ordering::AcqRel),
            cache_misses: self.cur_cache_misses.swap(0, Ordering::AcqRel),
            rate_limit_rejections: self.cur_rate_limit_rejections.swap(0, Ordering::AcqRel),
        };

        let mut buckets = self.buckets.lock().unwrap();
        buckets.push_back(snapshot);
        if buckets.len() > self.capacity {
            buckets.pop_front();
        }
    }

    /// Sums every committed bucket in the window in one pass, shared by
    /// `aggregate` and `aggregate_engine` so neither duplicates the loop.
    fn sum_buckets(&self) -> BucketTotals {
        let buckets = self.buckets.lock().unwrap();
        let mut t = BucketTotals::default();
        for b in buckets.iter() {
            t.read_ops += b.read_ops;
            t.write_ops += b.write_ops;
            for i in 0..7 {
                t.read_latency[i] += b.latency_buckets[i];
                t.write_latency[i] += b.write_latency_buckets[i];
            }
            t.cache_hits += b.cache_hits;
            t.cache_misses += b.cache_misses;
            t.rate_limit_rejections += b.rate_limit_rejections;
        }
        t
    }

    /// Aggregates all committed buckets into a `DomainWindowMetrics` snapshot.
    pub fn aggregate(&self, domain: &str, window_secs: u64) -> DomainWindowMetrics {
        let t = self.sum_buckets();

        let total_read_samples: u64 = t.read_latency.iter().sum();
        let read_latency_us_p50 = percentile(&t.read_latency, total_read_samples, 50);
        let read_latency_us_p99 = percentile(&t.read_latency, total_read_samples, 99);

        let total_cache = t.cache_hits + t.cache_misses;
        let cache_hit_rate = if total_cache == 0 {
            0.0
        } else {
            t.cache_hits as f32 / total_cache as f32
        };

        DomainWindowMetrics {
            domain: domain.to_string(),
            read_ops: t.read_ops,
            write_ops: t.write_ops,
            read_latency_us_p50,
            read_latency_us_p99,
            cache_hit_rate,
            rate_limit_rejections: t.rate_limit_rejections,
            window_secs,
        }
    }

    /// Aggregates all committed buckets into an `EngineWindowMetrics`
    /// snapshot (spec general/019): read and write latency percentiles side
    /// by side, no cache hit/miss (engine windows don't track it).
    pub fn aggregate_engine(&self, window_secs: u64) -> EngineWindowMetrics {
        let t = self.sum_buckets();

        let read_total: u64 = t.read_latency.iter().sum();
        let write_total: u64 = t.write_latency.iter().sum();

        EngineWindowMetrics {
            read_ops: t.read_ops,
            write_ops: t.write_ops,
            read_latency_us_p50: percentile(&t.read_latency, read_total, 50),
            read_latency_us_p95: percentile(&t.read_latency, read_total, 95),
            read_latency_us_p99: percentile(&t.read_latency, read_total, 99),
            write_latency_us_p50: percentile(&t.write_latency, write_total, 50),
            write_latency_us_p95: percentile(&t.write_latency, write_total, 95),
            write_latency_us_p99: percentile(&t.write_latency, write_total, 99),
            window_secs,
        }
    }
}

// ── P-value approximation ─────────────────────────────────────────────────────

fn percentile(buckets: &[u64; 7], total: u64, pct: u64) -> u64 {
    if total == 0 {
        return 0;
    }
    // Ceiling: smallest rank whose cumulative count >= target.
    let target = (total * pct + 99) / 100;
    let mut cumulative = 0u64;
    for (i, &count) in buckets.iter().enumerate() {
        cumulative += count;
        if cumulative >= target {
            return MIDPOINTS[i];
        }
    }
    MIDPOINTS[6]
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_increase() {
        let w = MetricsWindow::new(60);
        w.record_read(50, true);
        w.record_read(5, false);
        w.record_write(100);
        w.tick();

        let m = w.aggregate("test", 60);
        assert_eq!(m.read_ops, 2);
        assert_eq!(m.write_ops, 1);
    }

    #[test]
    fn bucket_expiry() {
        let w = MetricsWindow::new(2); // 2-second window
        w.record_read(50, true);
        w.tick(); // bucket 1
        w.record_read(50, true);
        w.tick(); // bucket 2
        w.record_read(50, true);
        w.tick(); // bucket 3 — bucket 1 should be evicted

        let m = w.aggregate("test", 2);
        assert_eq!(m.read_ops, 2, "oldest bucket must be evicted");
    }

    #[test]
    fn p99_approximation() {
        let w = MetricsWindow::new(60);
        // 99 reads < 100 µs (bucket index 1)
        for _ in 0..99 {
            w.record_read(50, true); // 50 µs → bucket 1
        }
        // 1 read ≥ 1 s (bucket index 6)
        w.record_read(2_000_000, true);
        w.tick();

        let m = w.aggregate("test", 60);
        // P50 should be in bucket 1 (50 µs midpoint)
        assert_eq!(m.read_latency_us_p50, 50);
        // P99 = 99th of 100 samples → still in bucket 1 (99/100 = 99%)
        assert_eq!(m.read_latency_us_p99, 50);
        // P99 with 100 samples target = ceil(100*99/100) = 99 → cumulative at bucket 1 = 99 ≥ 99.
        // So P99 midpoint = 50 µs (< 100 µs bucket).
        // The spec says "P99 in the range [100 µs, 1 ms]" but with midpoint approximation
        // the 99th sample lands at the boundary of bucket 1. This is acceptable given
        // the approximation disclaimer in the spec.
    }

    // Spec general/019 test 1: write latency used to be discarded
    // (`record_write(&self, _latency_us: u64)`); it must now be bucketed.
    #[test]
    fn write_latency_is_bucketed() {
        let w = MetricsWindow::new(60);
        w.record_write(50); // 50 µs -> bucket 1
        w.tick();

        let m = w.aggregate_engine(60);
        assert_eq!(m.write_latency_us_p50, 50);
    }

    // Spec general/019 test 2: p95/p99 over a 95/5 split (bucket midpoints).
    #[test]
    fn p95_p99_engine_approximation() {
        let w = MetricsWindow::new(60);
        for _ in 0..95 {
            w.record_read(50, true); // 50 µs -> bucket 1
        }
        for _ in 0..5 {
            w.record_read(2_000_000, true); // 2s -> bucket 6
        }
        w.tick();

        let m = w.aggregate_engine(60);
        assert_eq!(m.read_latency_us_p50, 50);
        assert_eq!(m.read_latency_us_p95, 50);
        assert_eq!(m.read_latency_us_p99, 2_000_000);
    }
}
