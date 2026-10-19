//! Run queue types: the 256-level priority queue with O(1)
//! highest-priority lookup (bitmap) and the timed sleep queue entry.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

use super::{Priority, Tid};

/// Number of priority levels (0-255)
pub const NUM_PRIORITIES: usize = 256;

/// Priority run queue with O(1) highest-priority lookup
///
/// Uses a bitmap to track which priority levels have runnable tasks,
/// allowing O(1) lookup of the highest priority non-empty queue.
pub struct PriorityRunQueue {
    /// Run queues for each priority level (index = priority)
    /// Box<[T]> slice is used to avoid stack overflow during initialization
    queues: Box<[VecDeque<Tid>]>,
    /// Bitmap tracking non-empty queues (4 x 64 bits = 256 bits)
    /// Bit N is set if priority N has runnable tasks
    bitmap: [u64; 4],
}

impl PriorityRunQueue {
    /// Create a new empty priority run queue
    pub fn new() -> Self {
        // Initialize on heap to avoid stack overflow
        // Create Vec directly and convert to boxed slice
        let mut vec: Vec<VecDeque<Tid>> = Vec::with_capacity(NUM_PRIORITIES);
        for _ in 0..NUM_PRIORITIES {
            vec.push(VecDeque::new());
        }
        Self {
            queues: vec.into_boxed_slice(),
            bitmap: [0; 4],
        }
    }

    /// Make the queue for `priority` hold `n` tasks without growing, so
    /// `enqueue` from an IRQ-context wakeup never allocates (thread
    /// context)
    pub fn reserve(&mut self, priority: Priority, n: usize) {
        let q = &mut self.queues[priority as usize];
        if q.capacity() < n {
            q.reserve(n - q.len());
        }
    }

    /// Add a task to the run queue at the specified priority
    pub fn enqueue(&mut self, tid: Tid, priority: Priority) {
        let prio = priority as usize;
        self.queues[prio].push_back(tid);
        // Set the corresponding bit in the bitmap
        let word = prio / 64;
        let bit = prio % 64;
        self.bitmap[word] |= 1u64 << bit;
    }

    /// Remove and return the highest priority task
    ///
    /// Returns None if no tasks are runnable.
    pub fn dequeue_highest(&mut self) -> Option<Tid> {
        // Find the highest priority with runnable tasks
        // Check from highest word (priorities 192-255) to lowest (0-63)
        for word_idx in (0..4).rev() {
            if self.bitmap[word_idx] != 0 {
                // Find the highest set bit in this word
                let bit = 63 - self.bitmap[word_idx].leading_zeros() as usize;
                let priority = word_idx * 64 + bit;

                // Pop from that queue
                if let Some(tid) = self.queues[priority].pop_front() {
                    // Clear bitmap bit if queue is now empty
                    if self.queues[priority].is_empty() {
                        self.bitmap[word_idx] &= !(1u64 << bit);
                    }
                    return Some(tid);
                }
            }
        }
        None
    }
}

impl Default for PriorityRunQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Entry in the sleep queue
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SleepEntry {
    /// Task ID
    pub tid: Tid,
    /// Timer tick when task should wake
    pub wake_tick: u64,
    /// Priority to use when re-enqueueing (cached to avoid lock in ISR)
    pub priority: Priority,
}
