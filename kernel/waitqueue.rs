//! Wait queue infrastructure for blocking synchronization
//!
//! Provides a mechanism for tasks to sleep waiting for an event and be woken
//! by another task. This follows Linux's wait queue design:
//!
//! - Tasks calling `wait()` are added to the queue and sleep
//! - Tasks calling `wake_one()` or `wake_all()` wake sleeping tasks
//!
//! ## Usage Example
//!
//! ```ignore
//! static WAITQ: WaitQueue = WaitQueue::new();
//!
//! // Thread A: Wait for event
//! WAITQ.wait();
//!
//! // Thread B: Signal event
//! WAITQ.wake_one();
//! ```
//!
//! ## Lock Ordering
//!
//! WaitQueue uses an internal IrqSpinlock. It should be acquired after any
//! higher-level locks (e.g., page cache lock) but before doing the sleep.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::arch::IrqSpinlock;
use crate::task::{Priority, TaskState, Tid};

/// Wait queue entry flags
pub mod flags {
    /// Entry has been woken
    pub const WQ_FLAG_WOKEN: u32 = 1 << 0;
    /// Exclusive waiter (wake only one)
    pub const WQ_FLAG_EXCLUSIVE: u32 = 1 << 1;
}

/// An entry in the wait queue
#[derive(Debug)]
pub struct WaitQueueEntry {
    /// Task ID of the waiting task
    pub tid: Tid,
    /// Task priority (cached for wake-up re-enqueue)
    pub priority: Priority,
    /// Flags (WQ_FLAG_WOKEN, etc.)
    pub flags: AtomicU32,
}

impl WaitQueueEntry {
    /// Create a new wait queue entry for the current task
    pub fn new(tid: Tid, priority: Priority) -> Self {
        Self {
            tid,
            priority,
            flags: AtomicU32::new(0),
        }
    }

    /// Check if this entry has been woken
    pub fn is_woken(&self) -> bool {
        self.flags.load(Ordering::Acquire) & flags::WQ_FLAG_WOKEN != 0
    }

    /// Mark this entry as woken
    pub fn set_woken(&self) {
        self.flags.fetch_or(flags::WQ_FLAG_WOKEN, Ordering::Release);
    }
}

/// Internal wait queue head (protected by IrqSpinlock)
struct WaitQueueHead {
    /// List of waiting tasks
    waiters: Vec<WaitQueueEntry>,
}

impl WaitQueueHead {
    /// Create an empty wait queue head
    const fn new() -> Self {
        Self {
            waiters: Vec::new(),
        }
    }
}

/// A wait queue for blocking synchronization
///
/// Tasks can wait on this queue and be woken by other tasks.
/// The queue is protected by an IRQ-safe spinlock to allow
/// wake operations from interrupt context.
pub struct WaitQueue {
    /// Protected wait queue head
    head: IrqSpinlock<WaitQueueHead>,
}

// Safety: WaitQueue uses internal synchronization via IrqSpinlock
unsafe impl Send for WaitQueue {}
unsafe impl Sync for WaitQueue {}

impl WaitQueue {
    /// Create a new empty wait queue
    pub const fn new() -> Self {
        Self {
            head: IrqSpinlock::new(WaitQueueHead::new()),
        }
    }

    /// Wait on this queue until woken
    ///
    /// The current task is added to the wait queue and put to sleep.
    /// It will be woken when another task calls `wake_one()` or `wake_all()`.
    ///
    /// # Panics
    ///
    /// Panics if called when scheduling is not enabled or there is no current task.
    pub fn wait(&self) {
        use crate::arch::{ContextOps, PerCpuOps};
        use crate::task::percpu::{SCHEDULING_ENABLED, TASK_TABLE, current_percpu_sched};

        #[cfg(target_arch = "x86_64")]
        type CurrentArch = crate::arch::x86_64::X86_64Arch;
        #[cfg(target_arch = "aarch64")]
        type CurrentArch = crate::arch::aarch64::Aarch64Arch;

        use crate::task::{Cred, CurrentTask};

        if !SCHEDULING_ENABLED.load(Ordering::Acquire) {
            // If scheduling not enabled, busy-wait (should not happen in normal use)
            panic!("WaitQueue::wait() called before scheduling enabled");
        }

        let sched = current_percpu_sched().expect("No scheduler for current CPU");
        if !sched.initialized.load(Ordering::Acquire) {
            panic!("WaitQueue::wait() called before scheduler initialized");
        }

        // Get current TID
        let current_tid: Tid = CurrentArch::current_tid();
        if current_tid == 0 {
            panic!("WaitQueue::wait() called with no current task");
        }

        // Get priority and mark task as waiting (acquire TASK_TABLE first per lock ordering)
        let priority = {
            let mut table = TASK_TABLE.lock();
            if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == current_tid) {
                task.state = TaskState::Sleeping;
                task.priority
            } else {
                128 // Default priority
            }
        };

        // Add ourselves to the wait queue
        {
            let mut head = self.head.lock();
            head.waiters
                .push(WaitQueueEntry::new(current_tid, priority));
        }

        // Now do the context switch to sleep
        // Take the run queue lock
        let mut rq = sched.lock.lock();

        // Verify we're still current
        if rq.current != Some(current_tid) {
            // Race condition - just return
            return;
        }

        // Get next task
        let next_tid = rq
            .queue()
            .dequeue_highest()
            .expect("Idle task should always be runnable");

        if next_tid == current_tid {
            // Shouldn't happen, but handle it
            return;
        }

        // Get next task's info from TASK_TABLE
        let (next_kstack, next_pid, next_ppid, next_pgid, next_sid, next_cr3) = {
            let table = TASK_TABLE.lock();
            table
                .tasks
                .iter()
                .find(|t| t.tid == next_tid)
                .map(|t| {
                    (
                        t.kstack_top,
                        t.pid,
                        t.ppid,
                        t.pgid,
                        t.sid,
                        t.page_table.root_table_phys(),
                    )
                })
                .unwrap_or((0, 0, 0, 0, 0, 0))
        };

        // Get context pointers
        let current_ctx = rq.get_context_mut(current_tid);
        let next_ctx = rq.get_context(next_tid);

        if let (Some(curr), Some(next)) = (current_ctx, next_ctx) {
            // Update current task
            rq.current = Some(next_tid);

            // Update per-CPU state
            CurrentArch::set_current_tid(next_tid);
            CurrentArch::set_current_task(&CurrentTask {
                tid: next_tid,
                pid: next_pid,
                ppid: next_ppid,
                pgid: next_pgid,
                sid: next_sid,
                cred: Cred::ROOT,
            });

            // Context switch
            unsafe {
                CurrentArch::context_switch(curr, next, next_kstack, next_cr3, next_tid);
            }
        }

        // We return here when woken up
    }

    /// Wake one waiter from the queue
    ///
    /// Wakes the first task waiting on this queue and makes it runnable.
    /// Returns true if a task was woken, false if the queue was empty.
    pub fn wake_one(&self) -> bool {
        use crate::task::TaskState;
        use crate::task::percpu::{TASK_TABLE, current_percpu_sched};

        let entry = {
            let mut head = self.head.lock();
            if head.waiters.is_empty() {
                return false;
            }
            // Remove first waiter (FIFO order for fairness)
            head.waiters.remove(0)
        };

        // Mark task as ready in TASK_TABLE
        {
            let mut table = TASK_TABLE.lock();
            if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == entry.tid) {
                task.state = TaskState::Ready;
            }
        }

        // Add to run queue
        if let Some(sched) = current_percpu_sched()
            && sched.initialized.load(Ordering::Acquire)
        {
            let mut rq = sched.lock.lock();
            rq.queue().enqueue(entry.tid, entry.priority);
            rq.nr_running += 1;
        }

        true
    }

    /// Wake all waiters from the queue
    ///
    /// Wakes all tasks waiting on this queue and makes them runnable.
    /// Returns the number of tasks woken.
    pub fn wake_all(&self) -> usize {
        use crate::task::TaskState;
        use crate::task::percpu::{TASK_TABLE, current_percpu_sched};

        let entries: Vec<WaitQueueEntry> = {
            let mut head = self.head.lock();
            core::mem::take(&mut head.waiters)
        };

        if entries.is_empty() {
            return 0;
        }

        let count = entries.len();

        // Mark all tasks as ready
        {
            let mut table = TASK_TABLE.lock();
            for entry in &entries {
                if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == entry.tid) {
                    task.state = TaskState::Ready;
                }
            }
        }

        // Add all to run queue
        if let Some(sched) = current_percpu_sched()
            && sched.initialized.load(Ordering::Acquire)
        {
            let mut rq = sched.lock.lock();
            for entry in entries {
                rq.queue().enqueue(entry.tid, entry.priority);
                rq.nr_running += 1;
            }
        }

        count
    }

    /// Check if the wait queue is empty
    pub fn is_empty(&self) -> bool {
        self.head.lock().waiters.is_empty()
    }

    /// Get the number of waiters
    pub fn len(&self) -> usize {
        self.head.lock().waiters.len()
    }
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Page Wait Table (Linux folio_wait_table pattern)
// ============================================================================

/// Number of buckets in the page wait hash table
const PAGE_WAIT_TABLE_SIZE: usize = 256;

/// Global page wait hash table
///
/// Like Linux's `folio_wait_table`, this provides a fixed number of wait queues
/// for page locking. Pages hash to a bucket to find their wait queue.
/// This is more memory-efficient than per-page wait queues.
static PAGE_WAIT_TABLE: [WaitQueue; PAGE_WAIT_TABLE_SIZE] =
    [const { WaitQueue::new() }; PAGE_WAIT_TABLE_SIZE];

/// Get the wait queue for a page address
///
/// Uses a simple hash of the page address to select a bucket.
pub fn page_wait_queue(page_addr: u64) -> &'static WaitQueue {
    let hash = (page_addr >> 12) as usize; // Shift by page size bits
    let index = hash % PAGE_WAIT_TABLE_SIZE;
    &PAGE_WAIT_TABLE[index]
}

// ============================================================================
// Locking Self-Tests
// ============================================================================

/// Run all locking infrastructure self-tests
///
/// These tests verify that the locking primitives work correctly:
/// - Preemption count tracking across architectures
/// - Wait queue basic operations
/// - Page wait table hash distribution
///
/// Should be called right before jumping to user mode, after all subsystems
/// are initialized.
pub fn run_locking_tests() {
    use crate::printkln;

    printkln!("Running locking infrastructure self-tests...");
    test_preempt_count_tracking();
    test_wait_queue_operations();
    test_page_wait_table_hash();
    printkln!("All locking tests passed!");
}

/// Test that IrqSpinlock correctly tracks preempt_count
fn test_preempt_count_tracking() {
    use crate::printkln;

    #[cfg(target_arch = "aarch64")]
    use crate::arch::aarch64::percpu;
    #[cfg(target_arch = "x86_64")]
    use crate::arch::x86_64::percpu;

    // Get initial preempt_count
    let initial_count = percpu::preempt_count();

    // Test manual preempt_disable/enable
    percpu::preempt_disable();
    let after_disable = percpu::preempt_count();
    assert!(
        after_disable == initial_count + 1,
        "preempt_disable should increment preempt_count"
    );

    percpu::preempt_enable();
    let after_enable = percpu::preempt_count();
    assert!(
        after_enable == initial_count,
        "preempt_enable should restore preempt_count"
    );

    // Test IrqSpinlock preempt tracking
    let test_lock = crate::arch::IrqSpinlock::new(42u32);
    let before_lock = percpu::preempt_count();

    {
        let _guard = test_lock.lock();
        let during_lock = percpu::preempt_count();
        assert!(
            during_lock == before_lock + 1,
            "IrqSpinlock::lock should increment preempt_count"
        );
    }

    let after_drop = percpu::preempt_count();
    assert!(
        after_drop == before_lock,
        "IrqSpinlock guard drop should restore preempt_count"
    );

    printkln!("  preempt_count tracking: OK");
}

/// Test basic WaitQueue operations
fn test_wait_queue_operations() {
    use crate::printkln;

    let wq = WaitQueue::new();

    // Initially empty
    assert!(wq.is_empty(), "New WaitQueue should be empty");
    assert!(wq.is_empty(), "New WaitQueue should have len 0");

    // wake_one on empty queue returns false
    assert!(
        !wq.wake_one(),
        "wake_one on empty queue should return false"
    );

    // wake_all on empty queue returns 0
    assert!(
        wq.wake_all() == 0,
        "wake_all on empty queue should return 0"
    );

    printkln!("  wait queue basic ops: OK");
}

/// Test page wait table hash distribution
fn test_page_wait_table_hash() {
    use crate::printkln;

    // Test that different page addresses hash to different buckets
    let wq1 = page_wait_queue(0x1000); // Page 1
    let wq2 = page_wait_queue(0x2000); // Page 2
    let wq3 = page_wait_queue(0x3000); // Page 3

    // These should be different wait queues (different bucket indices)
    // We test by checking their addresses are different
    let addr1 = wq1 as *const WaitQueue as usize;
    let addr2 = wq2 as *const WaitQueue as usize;
    let addr3 = wq3 as *const WaitQueue as usize;

    // At least 2 of 3 should be different (with good hash)
    let different_count = (if addr1 != addr2 { 1 } else { 0 })
        + (if addr2 != addr3 { 1 } else { 0 })
        + (if addr1 != addr3 { 1 } else { 0 });
    assert!(
        different_count >= 2,
        "Page wait hash should distribute across buckets"
    );

    // Verify the hash function is consistent
    let wq1_again = page_wait_queue(0x1000);
    assert!(
        core::ptr::eq(wq1, wq1_again),
        "Same page address should hash to same bucket"
    );

    printkln!("  page wait table hash: OK");
}
