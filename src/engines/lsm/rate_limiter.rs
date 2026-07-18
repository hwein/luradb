//! Per-domain token-bucket rate limiter.
//!
//! Each domain gets two `TokenBucket` instances (read IOPS, write IOPS).
//! Tokens are refilled lazily on access — no background thread required.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ── DomainQuota ───────────────────────────────────────────────────────────────

/// Per-domain resource limits (spec §2c).
#[derive(Clone, Copy)]
pub struct DomainQuota {
    /// Max read operations per second.
    pub read_iops: u32,
    /// Max write operations per second.
    pub write_iops: u32,
    /// Max storage bytes (0 = unlimited).
    pub max_storage_bytes: u64,
}

impl Default for DomainQuota {
    fn default() -> Self {
        Self {
            read_iops: 1000,
            write_iops: 500,
            max_storage_bytes: 0,
        }
    }
}

// ── TokenBucket ───────────────────────────────────────────────────────────────

/// Single-rate token bucket with lazy refill.
///
/// Tokens are replenished proportionally to elapsed wall-clock time
/// on the next `try_consume` call — no background task needed.
pub struct TokenBucket {
    /// Available tokens.
    tokens: AtomicU32,
    /// Max tokens (= IOPS limit).
    capacity: u32,
    /// Last refill timestamp in milliseconds since UNIX_EPOCH.
    last_refill: AtomicU64,
}

impl TokenBucket {
    pub fn new(capacity: u32) -> Self {
        Self {
            tokens: AtomicU32::new(capacity),
            capacity,
            last_refill: AtomicU64::new(now_millis()),
        }
    }

    /// Replenishes tokens proportional to elapsed time since the last refill.
    fn refill(&self) {
        let now = now_millis();
        let last = self.last_refill.load(Ordering::Relaxed);
        if now <= last {
            return;
        }
        let elapsed_ms = now - last;
        let to_add = (elapsed_ms * self.capacity as u64) / 1000;
        if to_add == 0 {
            return;
        }
        // CAS ensures only one thread performs the refill for a given interval.
        if self
            .last_refill
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            let old = self.tokens.load(Ordering::Acquire);
            let updated = (old as u64 + to_add).min(self.capacity as u64) as u32;
            self.tokens.store(updated, Ordering::Release);
        }
    }

    /// Tries to consume one token.
    ///
    /// Returns `true` and decrements the counter, or `false` if the bucket
    /// is empty. No I/O is performed.
    pub fn try_consume(&self) -> bool {
        self.refill();
        loop {
            let current = self.tokens.load(Ordering::Acquire);
            if current == 0 {
                return false;
            }
            if self
                .tokens
                .compare_exchange(current, current - 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Drains the bucket and locks out lazy refill (`last_refill` pushed far
    /// into the future) — stays deterministically empty no matter how much
    /// real time passes before the next `try_consume` (flaky-test fix, spec
    /// general/008).
    #[cfg(test)]
    pub fn drain_for_test(&self) {
        // Order matters: lock refill first, then drain — the other way
        // round, a concurrent refill() could sneak in a top-up between the
        // two stores.
        self.last_refill.store(now_millis() + 3_600_000, Ordering::Release);
        self.tokens.store(0, Ordering::Release);
    }
}

// ── RateLimiter ───────────────────────────────────────────────────────────────

/// Holds the read and write token buckets for one domain.
pub struct RateLimiter {
    pub read_bucket: TokenBucket,
    pub write_bucket: TokenBucket,
    pub quota: DomainQuota,
}

impl RateLimiter {
    pub fn new(quota: DomainQuota) -> Self {
        let read = TokenBucket::new(quota.read_iops);
        let write = TokenBucket::new(quota.write_iops);
        Self { read_bucket: read, write_bucket: write, quota }
    }

    /// Consumes one read token. Returns `false` if exhausted (→ 429).
    pub fn check_read(&self) -> bool {
        self.read_bucket.try_consume()
    }

    /// Consumes one write token. Returns `false` if exhausted (→ 429).
    pub fn check_write(&self) -> bool {
        self.write_bucket.try_consume()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Test 1: N+1 requests at capacity N → last rejected.
    #[test]
    fn test_bucket_exhausted_at_capacity() {
        let bucket = TokenBucket::new(3);
        assert!(bucket.try_consume(), "1st");
        assert!(bucket.try_consume(), "2nd");
        assert!(bucket.try_consume(), "3rd");
        assert!(!bucket.try_consume(), "4th request must fail");
    }

    // Test 2: refill after a wait -> requests possible again. The clock is
    // simulated (last_refill set directly) instead of sleeping: under suite
    // load, real wall-clock waits between two statements can easily overshoot
    // or undershoot the intended window and make this flaky either way.
    #[test]
    fn test_bucket_refills_after_wait() {
        let bucket = TokenBucket::new(10);
        bucket.drain_for_test();
        assert!(!bucket.try_consume(), "bucket must be empty");
        // Simulate a 150 ms wait: push last_refill into the past so
        // refill() sees elapsed >= 150 ms -> at least 1 token (10 IOPS).
        bucket.last_refill.store(now_millis() - 150, Ordering::Release);
        assert!(bucket.try_consume(), "must have refilled at least 1 token");
    }
}
