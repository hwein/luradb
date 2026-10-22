//! Hybrid Logical Clock (HLC) implementation.
//!
//! HLC provides causal consistency in distributed systems by combining
//! physical time with logical counters.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A Hybrid Logical Clock timestamp.
///
/// Format: [Physical Time (48 bits)][Logical Counter (16 bits)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct HLCTimestamp {
    /// Combined timestamp (physical + logical)
    value: u64,
}

impl HLCTimestamp {
    /// Creates a new HLC timestamp from raw value.
    pub fn new(value: u64) -> Self {
        Self { value }
    }

    /// Returns the physical time component (milliseconds since epoch).
    pub fn physical(&self) -> u64 {
        self.value >> 16
    }

    /// Returns the logical counter component.
    pub fn logical(&self) -> u16 {
        (self.value & 0xFFFF) as u16
    }

    /// Creates a timestamp from components.
    pub fn from_components(physical: u64, logical: u16) -> Self {
        Self {
            value: (physical << 16) | (logical as u64),
        }
    }

    /// Returns the raw value.
    pub fn as_u64(&self) -> u64 {
        self.value
    }
}

/// Hybrid Logical Clock for distributed timestamp generation.
///
/// The HLC ensures:
/// - Timestamps are monotonically increasing
/// - Causality is preserved across nodes
/// - Physical time bounds logical time
///
/// It never waits: where the logical counter is saturated and the wall clock
/// has not moved past it, a draw returns `None` and the caller yields.
pub struct HybridLogicalClock {
    /// Last issued timestamp
    last_timestamp: AtomicU64,
    /// Wall clock in milliseconds since the UNIX epoch.
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl HybridLogicalClock {
    /// Creates a new HLC on the system clock.
    pub fn new() -> Self {
        Self::with_clock(Self::physical_time)
    }

    /// Creates a new HLC on `clock`, milliseconds since the UNIX epoch.
    pub fn with_clock(clock: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        Self { last_timestamp: AtomicU64::new(0), clock: Box::new(clock) }
    }

    /// Gets the current physical time in milliseconds since UNIX epoch.
    pub(crate) fn physical_time() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time before UNIX epoch")
            .as_millis() as u64
    }

    /// The wall clock this clock reads, in milliseconds since UNIX epoch.
    pub fn wall(&self) -> u64 {
        (self.clock)()
    }

    /// Generates a new timestamp for a local event, or `None` while the
    /// logical counter is saturated and the wall clock has not moved past
    /// the clock.
    pub fn try_now(&self) -> Option<HLCTimestamp> {
        loop {
            let current_physical = self.wall();
            let last = self.last_timestamp.load(Ordering::SeqCst);
            let last_ts = HLCTimestamp::new(last);

            let last_physical = last_ts.physical();
            let last_logical = last_ts.logical();

            let (new_physical, new_logical) = if current_physical > last_physical {
                // Physical time has advanced - reset logical counter
                (current_physical, 0)
            } else {
                // Physical time hasn't advanced - increment logical counter
                if last_logical == u16::MAX {
                    return None;
                }
                (last_physical, last_logical + 1)
            };

            let new_ts = HLCTimestamp::from_components(new_physical, new_logical);

            // Try to update last_timestamp
            if self
                .last_timestamp
                .compare_exchange(last, new_ts.value, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Some(new_ts);
            }
            // If CAS failed, another thread updated it - retry
        }
    }

    /// Updates the clock based on a received timestamp, so the result is
    /// greater than both the local time and the received time; `None` where
    /// the logical counter it would raise is saturated.
    pub fn update(&self, received: HLCTimestamp) -> Option<HLCTimestamp> {
        loop {
            let current_physical = self.wall();
            let last = self.last_timestamp.load(Ordering::SeqCst);
            let last_ts = HLCTimestamp::new(last);

            let received_physical = received.physical();
            let received_logical = received.logical();
            let last_physical = last_ts.physical();
            let last_logical = last_ts.logical();

            let (new_physical, new_logical) = if current_physical > last_physical
                && current_physical > received_physical
            {
                // Physical time has advanced beyond both
                (current_physical, 0)
            } else if last_physical > received_physical {
                // Local time is ahead
                (last_physical, last_logical.checked_add(1)?)
            } else if received_physical > last_physical {
                // Received time is ahead
                (received_physical, received_logical.checked_add(1)?)
            } else {
                // Same physical time - take max logical + 1
                (last_physical, last_logical.max(received_logical).checked_add(1)?)
            };

            let new_ts = HLCTimestamp::from_components(new_physical, new_logical);

            // Try to update
            if self
                .last_timestamp
                .compare_exchange(last, new_ts.value, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Some(new_ts);
            }
        }
    }

    /// Raises the clock to at least `value` (raw HLC encoding); never lowers
    /// it. Used at startup to seed from recovered state.
    pub fn seed(&self, value: u64) {
        self.last_timestamp.fetch_max(value, Ordering::SeqCst);
    }

    /// Returns the current timestamp value without updating.
    pub fn peek(&self) -> HLCTimestamp {
        HLCTimestamp::new(self.last_timestamp.load(Ordering::SeqCst))
    }
}

impl Default for HybridLogicalClock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    /// A clock that reads `now`, and the handle that moves it.
    fn manual_clock(start: u64) -> (HybridLogicalClock, Arc<AtomicU64>) {
        let now = Arc::new(AtomicU64::new(start));
        let read = Arc::clone(&now);
        (HybridLogicalClock::with_clock(move || read.load(Ordering::SeqCst)), now)
    }

    const T: u64 = 1_700_000_000_000;

    #[test]
    fn test_hlc_basic() {
        let (hlc, _now) = manual_clock(T);

        let ts1 = hlc.try_now().unwrap();
        let ts2 = hlc.try_now().unwrap();
        let ts3 = hlc.try_now().unwrap();

        // Timestamps should be monotonically increasing
        assert!(ts2 > ts1);
        assert!(ts3 > ts2);
    }

    #[test]
    fn test_hlc_physical_time_advance() {
        let (hlc, now) = manual_clock(T);

        let ts1 = hlc.try_now().unwrap();
        now.store(T + 1, Ordering::SeqCst);
        let ts2 = hlc.try_now().unwrap();

        assert_eq!(ts2.physical(), T + 1);
        assert_eq!(ts2.logical(), 0);
        assert!(ts2 > ts1);
    }

    #[test]
    fn test_hlc_logical_increment() {
        let (hlc, _now) = manual_clock(T);

        let ts1 = hlc.try_now().unwrap();
        let ts2 = hlc.try_now().unwrap();

        assert_eq!(ts2.physical(), ts1.physical());
        assert_eq!(ts2.logical(), ts1.logical() + 1);
    }

    #[test]
    fn test_hlc_update_with_future_timestamp() {
        let (hlc, _now) = manual_clock(T);

        let local_ts = hlc.try_now().unwrap();

        // Simulate receiving a timestamp from the future
        let future_ts = HLCTimestamp::from_components(local_ts.physical() + 1000, 5);

        let updated_ts = hlc.update(future_ts).unwrap();

        // Updated timestamp should be >= future timestamp
        assert!(updated_ts >= future_ts);
    }

    #[test]
    fn test_hlc_update_with_past_timestamp() {
        let (hlc, now) = manual_clock(T);

        let ts1 = hlc.try_now().unwrap();
        now.store(T + 10, Ordering::SeqCst);
        let ts2 = hlc.try_now().unwrap();

        // Simulate receiving a timestamp from the past
        let updated_ts = hlc.update(ts1).unwrap();

        // Updated timestamp should still be greater than current
        assert!(updated_ts > ts2);
    }

    #[test]
    fn test_hlc_concurrent() {
        let hlc = Arc::new(HybridLogicalClock::new());
        let mut handles = vec![];

        // Spawn multiple threads generating timestamps; 1000 draws cannot
        // saturate the logical counter of one millisecond.
        for _ in 0..10 {
            let hlc_clone = Arc::clone(&hlc);
            let handle = thread::spawn(move || {
                let mut timestamps = vec![];
                for _ in 0..100 {
                    timestamps.push(hlc_clone.try_now().unwrap());
                }
                timestamps
            });
            handles.push(handle);
        }

        // Collect all timestamps
        let mut all_timestamps = vec![];
        for handle in handles {
            all_timestamps.extend(handle.join().unwrap());
        }

        // Check that all timestamps are unique and monotonic per-thread
        all_timestamps.sort();
        for i in 1..all_timestamps.len() {
            assert!(all_timestamps[i] > all_timestamps[i - 1]);
        }
    }

    // A saturated logical counter must not overflow the `+ 1` in either
    // update() branch: the draw fails instead, and succeeds once the wall
    // clock moved past both stamps.
    #[test]
    fn test_hlc_update_survives_logical_overflow() {
        let (hlc, now) = manual_clock(T);

        // Local time ahead of the received one, local logical saturated.
        hlc.seed(HLCTimestamp::from_components(T + 20, u16::MAX).as_u64());
        let before = hlc.peek();
        assert_eq!(hlc.update(HLCTimestamp::from_components(T, 0)), None);
        assert_eq!(hlc.peek(), before, "a failed update issues nothing");
        now.store(T + 21, Ordering::SeqCst);
        let ts1 = hlc.update(HLCTimestamp::from_components(T, 0)).unwrap();
        assert!(ts1 > before);

        // Received time ahead of the local one, received logical saturated.
        let received = HLCTimestamp::from_components(ts1.physical() + 20, u16::MAX);
        assert_eq!(hlc.update(received), None);
        now.store(ts1.physical() + 21, Ordering::SeqCst);
        let ts2 = hlc.update(received).unwrap();
        assert!(ts2 > received);
        assert!(ts2 > ts1);
    }

    // A saturated logical counter ahead of the wall clock: `try_now` returns
    // at once and issues nothing until the wall clock moves past it.
    #[test]
    fn test_try_now_returns_none_on_a_saturated_counter() {
        let (hlc, now) = manual_clock(T);
        hlc.seed(HLCTimestamp::from_components(T, u16::MAX - 1).as_u64());

        let last = HLCTimestamp::from_components(T, u16::MAX);
        assert_eq!(hlc.try_now(), Some(last));
        assert_eq!(hlc.try_now(), None);
        assert_eq!(hlc.peek(), last, "a failed draw issues nothing");

        now.store(T + 1, Ordering::SeqCst);
        assert_eq!(hlc.try_now(), Some(HLCTimestamp::from_components(T + 1, 0)));
    }

    #[test]
    fn test_hlc_seed_never_lowers_the_clock() {
        let (hlc, _now) = manual_clock(T);
        let high = hlc.try_now().unwrap().as_u64() + 1_000_000;

        hlc.seed(high);
        assert_eq!(hlc.peek().as_u64(), high);

        hlc.seed(1);
        assert_eq!(hlc.peek().as_u64(), high);
        assert!(hlc.try_now().unwrap().as_u64() > high);
    }

    #[test]
    fn test_hlc_timestamp_components() {
        let ts = HLCTimestamp::from_components(123456789, 42);

        assert_eq!(ts.physical(), 123456789);
        assert_eq!(ts.logical(), 42);

        // Round-trip test
        let reconstructed = HLCTimestamp::from_components(ts.physical(), ts.logical());
        assert_eq!(reconstructed, ts);
    }
}
