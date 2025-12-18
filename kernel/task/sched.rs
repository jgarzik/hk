//! Priority-based scheduler implementation
//!
//! Implements a priority scheduler with 256 priority levels and O(1)
//! highest-priority task lookup using a bitmap.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

use super::{Priority, Task, TaskState, Tid};
use crate::arch::{Arch, PageTable};

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

    /// Peek at the highest priority task without removing it
    pub fn peek_highest(&self) -> Option<Tid> {
        for word_idx in (0..4).rev() {
            if self.bitmap[word_idx] != 0 {
                let bit = 63 - self.bitmap[word_idx].leading_zeros() as usize;
                let priority = word_idx * 64 + bit;
                return self.queues[priority].front().copied();
            }
        }
        None
    }

    /// Get the highest priority level that has runnable tasks
    pub fn highest_priority(&self) -> Option<Priority> {
        for word_idx in (0..4).rev() {
            if self.bitmap[word_idx] != 0 {
                let bit = 63 - self.bitmap[word_idx].leading_zeros() as usize;
                return Some((word_idx * 64 + bit) as Priority);
            }
        }
        None
    }

    /// Remove a specific task from its priority queue
    ///
    /// Returns true if the task was found and removed.
    pub fn remove(&mut self, tid: Tid, priority: Priority) -> bool {
        let prio = priority as usize;
        let queue = &mut self.queues[prio];

        // Find and remove the task
        if let Some(pos) = queue.iter().position(|&t| t == tid) {
            queue.remove(pos);
            // Clear bitmap bit if queue is now empty
            if queue.is_empty() {
                let word = prio / 64;
                let bit = prio % 64;
                self.bitmap[word] &= !(1u64 << bit);
            }
            return true;
        }
        false
    }

    /// Check if the run queue is empty
    pub fn is_empty(&self) -> bool {
        self.bitmap.iter().all(|&w| w == 0)
    }

    /// Get the number of runnable tasks
    pub fn len(&self) -> usize {
        self.queues.iter().map(|q| q.len()).sum()
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

impl PartialOrd for SleepEntry {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SleepEntry {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        // Reverse ordering so earlier wakeups come first (min-heap behavior with BinaryHeap)
        other.wake_tick.cmp(&self.wake_tick)
    }
}

/// Priority-based scheduler
pub struct Scheduler<A: Arch, PT: PageTable<VirtAddr = A::VirtAddr, PhysAddr = A::PhysAddr>> {
    /// All tasks by TID
    tasks: Vec<Task<A, PT>>,
    /// Priority run queue for ready tasks
    pub run_queue: PriorityRunQueue,
    /// Currently running task TID
    current: Option<Tid>,
    /// Next TID to assign
    next_tid: Tid,
    /// Next PID to assign
    next_pid: u64,
    /// Sleep queue for tasks waiting on timer
    sleep_queue: Vec<SleepEntry>,
}

impl<A, PT> Scheduler<A, PT>
where
    A: Arch,
    PT: PageTable<VirtAddr = A::VirtAddr, PhysAddr = A::PhysAddr>,
{
    /// Create a new scheduler
    pub fn new() -> Self {
        Self {
            tasks: Vec::new(),
            run_queue: PriorityRunQueue::new(),
            current: None,
            next_tid: 1,
            next_pid: 1,
            sleep_queue: Vec::new(),
        }
    }

    /// Allocate a new TID
    pub fn alloc_tid(&mut self) -> Tid {
        let tid = self.next_tid;
        self.next_tid += 1;
        tid
    }

    /// Allocate a new PID
    pub fn alloc_pid(&mut self) -> u64 {
        let pid = self.next_pid;
        self.next_pid += 1;
        pid
    }

    /// Add a task to the scheduler
    ///
    /// The task is added to the task list and made runnable.
    pub fn add_task(&mut self, task: Task<A, PT>) -> Tid {
        let tid = task.tid;
        let priority = task.priority;
        self.tasks.push(task);
        self.run_queue.enqueue(tid, priority);
        tid
    }

    /// Add a user task to the scheduler (convenience wrapper)
    pub fn add_user_task(&mut self, task: Task<A, PT>) -> Tid {
        self.add_task(task)
    }

    /// Get a reference to a task by TID
    pub fn get_task(&self, tid: Tid) -> Option<&Task<A, PT>> {
        self.tasks.iter().find(|t| t.tid == tid)
    }

    /// Get a mutable reference to a task by TID
    pub fn get_task_mut(&mut self, tid: Tid) -> Option<&mut Task<A, PT>> {
        self.tasks.iter_mut().find(|t| t.tid == tid)
    }

    /// Get the currently running task
    pub fn current(&self) -> Option<Tid> {
        self.current
    }

    /// Get a reference to the current task
    pub fn current_task(&self) -> Option<&Task<A, PT>> {
        self.current.and_then(|tid| self.get_task(tid))
    }

    /// Get a mutable reference to the current task
    pub fn current_task_mut(&mut self) -> Option<&mut Task<A, PT>> {
        if let Some(tid) = self.current {
            self.tasks.iter_mut().find(|t| t.tid == tid)
        } else {
            None
        }
    }

    /// Set the current task
    pub fn set_current(&mut self, tid: Option<Tid>) {
        self.current = tid;
    }

    /// Make a task runnable by adding it to the run queue
    pub fn make_runnable(&mut self, tid: Tid) {
        if let Some(task) = self.get_task_mut(tid) {
            task.state = TaskState::Ready;
            let priority = task.priority;
            self.run_queue.enqueue(tid, priority);
        }
    }

    /// Get the next task to run (does not remove from queue)
    ///
    /// Returns the highest priority runnable task.
    pub fn peek_next(&self) -> Option<&Task<A, PT>> {
        self.run_queue
            .peek_highest()
            .and_then(|tid| self.get_task(tid))
    }

    /// Schedule the next task to run
    ///
    /// Returns the task to switch to, or None if no tasks are runnable.
    /// The current task (if any) is re-added to the run queue.
    pub fn schedule_next(&mut self) -> Option<&Task<A, PT>> {
        // Re-queue the current task if it's still runnable
        if let Some(current_tid) = self.current
            && let Some(task) = self.tasks.iter().find(|t| t.tid == current_tid)
            && task.state == TaskState::Running
        {
            // Mark as ready and re-queue
            let priority = task.priority;
            self.run_queue.enqueue(current_tid, priority);
        }

        // Get the highest priority task
        if let Some(next_tid) = self.run_queue.dequeue_highest() {
            self.current = Some(next_tid);
            if let Some(task) = self.tasks.iter_mut().find(|t| t.tid == next_tid) {
                task.state = TaskState::Running;
            }
            return self.tasks.iter().find(|t| t.tid == next_tid);
        }

        self.current = None;
        None
    }

    /// Check if preemption is needed
    ///
    /// Returns true if there's a higher priority task ready to run
    /// than the current task.
    pub fn needs_preemption(&self) -> bool {
        let current_priority = self
            .current
            .and_then(|tid| self.get_task(tid))
            .map(|t| t.priority)
            .unwrap_or(0);

        if let Some(highest) = self.run_queue.highest_priority() {
            return highest > current_priority;
        }
        false
    }

    /// Put a task to sleep until a specific tick
    pub fn sleep_until(&mut self, tid: Tid, wake_tick: u64) {
        let priority = if let Some(task) = self.get_task_mut(tid) {
            task.state = TaskState::Sleeping;
            let priority = task.priority;
            // Remove from run queue if present
            self.run_queue.remove(tid, priority);
            priority
        } else {
            128 // Default priority if task not found
        };

        // Add to sleep queue (cache priority to avoid lock lookup in ISR)
        self.sleep_queue.push(SleepEntry {
            tid,
            wake_tick,
            priority,
        });
        // Sort by wake time (earliest first)
        self.sleep_queue.sort_by_key(|e| e.wake_tick);
    }

    /// Wake tasks whose sleep time has expired
    ///
    /// Returns the number of tasks woken.
    pub fn wake_expired(&mut self, current_tick: u64) -> usize {
        let mut woken = 0;

        // Find tasks to wake
        while let Some(entry) = self.sleep_queue.first() {
            if entry.wake_tick <= current_tick {
                let tid = entry.tid;
                self.sleep_queue.remove(0);

                // Make the task runnable
                if let Some(task) = self.get_task_mut(tid)
                    && task.state == TaskState::Sleeping
                {
                    task.state = TaskState::Ready;
                    let priority = task.priority;
                    self.run_queue.enqueue(tid, priority);
                    woken += 1;
                }
            } else {
                break;
            }
        }

        woken
    }

    /// Mark current task as exited
    pub fn exit_current(&mut self, status: i32) {
        if let Some(tid) = self.current {
            if let Some(task) = self.tasks.iter_mut().find(|t| t.tid == tid) {
                let priority = task.priority;
                task.state = TaskState::Zombie(status);
                // Remove from run queue (should already be removed since it's running)
                self.run_queue.remove(tid, priority);
            }
            self.current = None;
        }
    }

    /// Exit a specific task
    pub fn exit_task(&mut self, tid: Tid, status: i32) {
        if let Some(task) = self.get_task_mut(tid) {
            let priority = task.priority;
            task.state = TaskState::Zombie(status);
            self.run_queue.remove(tid, priority);
        }
        if self.current == Some(tid) {
            self.current = None;
        }
    }

    /// Yield the current task
    ///
    /// The current task is moved to the back of its priority queue.
    pub fn yield_current(&mut self) {
        if let Some(tid) = self.current {
            if let Some(task) = self.tasks.iter().find(|t| t.tid == tid)
                && task.state == TaskState::Running
            {
                let priority = task.priority;
                self.run_queue.enqueue(tid, priority);
            }
            self.current = None;
        }
    }

    /// Get the number of runnable tasks
    pub fn runnable_count(&self) -> usize {
        self.run_queue.len()
    }

    /// Get the total number of tasks
    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }

    /// Check if the scheduler has any runnable tasks
    pub fn has_runnable(&self) -> bool {
        !self.run_queue.is_empty()
    }
}

impl<A, PT> Default for Scheduler<A, PT>
where
    A: Arch,
    PT: PageTable<VirtAddr = A::VirtAddr, PhysAddr = A::PhysAddr>,
{
    fn default() -> Self {
        Self::new()
    }
}
