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
pub struct HybridLogicalClock {
    /// Last issued timestamp
    last_timestamp: AtomicU64,
}

impl HybridLogicalClock {
    /// Creates a new HLC.
    pub fn new() -> Self {
        Self {
            last_timestamp: AtomicU64::new(0),
        }
    }

    /// Gets the current physical time in milliseconds since UNIX epoch.
    fn physical_time() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time before UNIX epoch")
            .as_millis() as u64
    }

    /// Generates a new timestamp for a local event.
    ///
    /// This is called when creating a new write operation locally.
    pub fn now(&self) -> HLCTimestamp {
        loop {
            let current_physical = Self::physical_time();
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
                    // Logical counter overflow - wait for physical time to advance
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
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
                return new_ts;
            }
            // If CAS failed, another thread updated it - retry
        }
    }

    /// Updates the clock based on a received timestamp.
    ///
    /// This is called when receiving a message from another node.
    /// It ensures causality by updating the clock to be greater than both
    /// the local time and the received time.
    pub fn update(&self, received: HLCTimestamp) -> HLCTimestamp {
        loop {
            let current_physical = Self::physical_time();
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
                if last_logical == u16::MAX {
                    // Logical counter overflow - wait for physical time to advance
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
                (last_physical, last_logical + 1)
            } else if received_physical > last_physical {
                // Received time is ahead
                if received_logical == u16::MAX {
                    // Logical counter overflow - wait for physical time to advance
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
                (received_physical, received_logical + 1)
            } else {
                // Same physical time - take max logical + 1
                let max_logical = last_logical.max(received_logical);
                if max_logical == u16::MAX {
                    // Wait for physical time to advance
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
                (last_physical, max_logical + 1)
            };

            let new_ts = HLCTimestamp::from_components(new_physical, new_logical);

            // Try to update
            if self
                .last_timestamp
                .compare_exchange(last, new_ts.value, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return new_ts;
            }
        }
    }

    /// Raises the clock to at least `value` (raw HLC encoding); never lowers
    /// it. Used at startup to seed from recovered state (spec kv/026 M3).
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
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_hlc_basic() {
        let hlc = HybridLogicalClock::new();

        let ts1 = hlc.now();
        let ts2 = hlc.now();
        let ts3 = hlc.now();

        // Timestamps should be monotonically increasing
        assert!(ts2 > ts1);
        assert!(ts3 > ts2);
    }

    #[test]
    fn test_hlc_physical_time_advance() {
        let hlc = HybridLogicalClock::new();

        let ts1 = hlc.now();

        // Wait for physical time to advance
        thread::sleep(Duration::from_millis(10));

        let ts2 = hlc.now();

        // Physical component should have advanced
        assert!(ts2.physical() > ts1.physical());
        // Logical component should reset
        assert_eq!(ts2.logical(), 0);
    }

    #[test]
    fn test_hlc_logical_increment() {
        let hlc = HybridLogicalClock::new();

        let ts1 = hlc.now();
        let ts2 = hlc.now();

        // If physical time hasn't advanced, logical should increment
        if ts2.physical() == ts1.physical() {
            assert_eq!(ts2.logical(), ts1.logical() + 1);
        }
    }

    #[test]
    fn test_hlc_update_with_future_timestamp() {
        let hlc = HybridLogicalClock::new();

        let local_ts = hlc.now();

        // Simulate receiving a timestamp from the future
        let future_ts = HLCTimestamp::from_components(local_ts.physical() + 1000, 5);

        let updated_ts = hlc.update(future_ts);

        // Updated timestamp should be >= future timestamp
        assert!(updated_ts >= future_ts);
    }

    #[test]
    fn test_hlc_update_with_past_timestamp() {
        let hlc = HybridLogicalClock::new();

        let ts1 = hlc.now();

        thread::sleep(Duration::from_millis(10));

        let ts2 = hlc.now();

        // Simulate receiving a timestamp from the past
        let past_ts = ts1;

        let updated_ts = hlc.update(past_ts);

        // Updated timestamp should still be greater than current
        assert!(updated_ts > ts2);
    }

    #[test]
    fn test_hlc_concurrent() {
        let hlc = std::sync::Arc::new(HybridLogicalClock::new());
        let mut handles = vec![];

        // Spawn multiple threads generating timestamps
        for _ in 0..10 {
            let hlc_clone = std::sync::Arc::clone(&hlc);
            let handle = thread::spawn(move || {
                let mut timestamps = vec![];
                for _ in 0..100 {
                    timestamps.push(hlc_clone.now());
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

    // Spec kv/026 M3: a saturated logical counter must not overflow the
    // `+ 1` in either update() branch; the result stays monotonic.
    #[test]
    fn test_hlc_update_survives_logical_overflow() {
        let hlc = HybridLogicalClock::new();
        let base = HybridLogicalClock::physical_time();

        // Local time ahead of the received one, local logical saturated.
        hlc.seed(HLCTimestamp::from_components(base + 20, u16::MAX).as_u64());
        let before = hlc.peek();
        let ts1 = hlc.update(HLCTimestamp::from_components(base, 0));
        assert!(ts1.as_u64() > before.as_u64());

        // Received time ahead of the local one, received logical saturated.
        let received = HLCTimestamp::from_components(ts1.physical() + 20, u16::MAX);
        let ts2 = hlc.update(received);
        assert!(ts2.as_u64() > received.as_u64());
        assert!(ts2.as_u64() > ts1.as_u64());
    }

    #[test]
    fn test_hlc_seed_never_lowers_the_clock() {
        let hlc = HybridLogicalClock::new();
        let high = hlc.now().as_u64() + 1_000_000;

        hlc.seed(high);
        assert_eq!(hlc.peek().as_u64(), high);

        hlc.seed(1);
        assert_eq!(hlc.peek().as_u64(), high);
        assert!(hlc.now().as_u64() > high);
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
