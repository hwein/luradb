//! `replacer` module
//!
//! This module contains the logic for page eviction strategies. When the
//! buffer pool is full and a new page needs to be fetched, the replacer
//! decides which existing page to evict.



/// A unique identifier for a frame in the buffer pool.
pub type FrameId = usize;

/// Trait for a page replacement algorithm.
pub trait Replacer {
    /// Finds a victim frame to evict.
    fn victim(&mut self) -> Option<FrameId>;

    /// Pins a frame, indicating it's in use and cannot be evicted.
    fn pin(&mut self, frame_id: FrameId);

    /// Unpins a frame, making it a candidate for eviction.
    fn unpin(&mut self, frame_id: FrameId);

    /// Returns the number of frames currently in the replacer (candidates for eviction).
    fn size(&self) -> usize;
}

/// Implements the Clock-R (Clock with Reference bit) page replacement algorithm.
/// This is a more efficient approximation of the LRU (Least Recently Used) policy.
pub struct ClockReplacer {
    pool_size: usize,
    frames: Vec<ClockFrame>,
    hand: usize,
}

struct ClockFrame {
    is_pinnable: bool,
    ref_bit: bool,
}

impl ClockReplacer {
    pub fn new(pool_size: usize) -> Self {
        Self {
            pool_size,
            frames: (0..pool_size)
                .map(|_| ClockFrame {
                    is_pinnable: false,
                    ref_bit: false,
                })
                .collect(),
            hand: 0,
        }
    }
}

impl Replacer for ClockReplacer {
    fn victim(&mut self) -> Option<FrameId> {
        if self.pool_size == 0 {
            return None;
        }

        let mut rounds = 0;
        loop {
            let frame = &mut self.frames[self.hand];

            if frame.is_pinnable {
                if frame.ref_bit {
                    // Give it a second chance
                    frame.ref_bit = false;
                } else {
                    // Found a victim
                    let victim_id = self.hand;
                    frame.is_pinnable = false;
                    self.hand = (self.hand + 1) % self.pool_size;
                    return Some(victim_id);
                }
            }

            self.hand = (self.hand + 1) % self.pool_size;
            
            // If we have scanned the entire buffer twice and found no victim,
            // it means all frames are pinned.
            if self.hand == 0 {
                rounds += 1;
            }
            if rounds >= 2 {
                return None;
            }
        }
    }

    fn pin(&mut self, frame_id: FrameId) {
        let frame = &mut self.frames[frame_id];
        frame.is_pinnable = false;
        frame.ref_bit = false; // A pinned page is "hot", but not a candidate
    }

    fn unpin(&mut self, frame_id: FrameId) {
        let frame = &mut self.frames[frame_id];
        if !frame.is_pinnable {
            frame.is_pinnable = true;
            frame.ref_bit = true; // Mark as recently used upon unpinning
        }
    }

    fn size(&self) -> usize {
        self.frames.iter().filter(|f| f.is_pinnable).count()
    }
}
