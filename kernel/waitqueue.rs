//! Wait queue infrastructure for blocking synchronization
//!
//! Linux-style wait queues (include/linux/wait.h, kernel/sched/wait.c):
//!
//! - A sleeper registers on the queue and sets its sleep state *before*
//!   re-checking its condition (`prepare_to_wait`), then calls `schedule()`.
//!   A wakeup that lands between the check and `schedule()` flips the state
//!   back to Running, so `schedule()` returns at once: no lost wakeups.
//! - `wait_event*` wrap the loop; the `_interruptible` variants return
//!   `Err(KernelError::RestartSys)` when a signal is pending (the syscall
//!   exit path turns that into a restart or -EINTR), `_timeout` variants
//!   take scheduler ticks and return the ticks left.
//! - Wakers (`wake_one`/`wake_all`) may run in any context, including IRQ
//!   handlers: the queue lock is an `IrqSpinlock`, the task wakeup only
//!   takes run-queue locks (never TASK_TABLE), and nothing on the wake
//!   path allocates.
//!
//! ## Usage
//!
//! ```ignore
//! static WQ: WaitQueue = WaitQueue::new();
//! // sleeper
//! WQ.wait_event_interruptible(|| data_ready())?;
//! // waker: make the condition true first, then
//! WQ.wake_all();
//! ```
//!
//! ## Lock Ordering
//!
//! The queue's IrqSpinlock is taken before the run-queue lock / remote
//! `wake_list` (wakeups are issued under it, like Linux); nothing else
//! nests inside it. Never call a `wait*` function while holding a
//! spinlock, and never wake while holding this CPU's run-queue lock.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::IrqSpinlock;
use crate::error::KernelError;
use crate::task::Tid;
use crate::task::percpu::{
    MAX_SCHEDULE_TIMEOUT, SleepState, WakeMode, current_cpu, current_tid, schedule,
    schedule_timeout, set_current_state, wake_up_task,
};

/// Source of unique wait entry ids
static NEXT_WAIT_ID: AtomicU64 = AtomicU64::new(1);

/// An entry in the wait queue
#[derive(Debug)]
struct WaitQueueEntry {
    /// Unique id (identifies the registration for removal)
    id: u64,
    /// Waiting task
    tid: Tid,
    /// CPU owning the waiting task
    cpu: u32,
    /// Remove the entry when it is woken (autoremove_wake_function); poll
    /// registrations stay until the poll ends
    autoremove: bool,
}

/// A task's registration on one wait queue (Linux `wait_queue_entry`)
///
/// Create with [`WaitEntry::new`], pass to `prepare_to_wait` in the wait
/// loop and to `finish_wait` when done.
#[derive(Debug, Default)]
pub struct WaitEntry {
    id: u64,
}

impl WaitEntry {
    /// A fresh (unregistered) entry
    pub const fn new() -> Self {
        Self { id: 0 }
    }
}

/// A wait queue for blocking synchronization
///
/// Tasks can wait on this queue and be woken by other tasks or IRQ
/// handlers.
pub struct WaitQueue {
    /// Waiters (FIFO)
    head: IrqSpinlock<Vec<WaitQueueEntry>>,
}

// Safety: WaitQueue uses internal synchronization via IrqSpinlock
unsafe impl Send for WaitQueue {}
unsafe impl Sync for WaitQueue {}

/// True if the current task has a deliverable signal pending
pub fn signal_pending() -> bool {
    crate::signal::has_pending_signals(current_tid())
}

impl WaitQueue {
    /// Create a new empty wait queue
    pub const fn new() -> Self {
        Self {
            head: IrqSpinlock::new(Vec::new()),
        }
    }

    /// Register the current task (if not registered) and set its state
    ///
    /// Linux `prepare_to_wait`: call at the top of every wait-loop
    /// iteration, then re-check the condition, then `schedule()`.
    pub fn prepare_to_wait(&self, entry: &mut WaitEntry, state: SleepState) {
        self.add_entry(entry, true);
        set_current_state(state);
    }

    /// Register the current task without autoremove (poll/select): the
    /// entry stays queued across wakeups until `remove_entry`.
    pub fn add_poll_entry(&self, entry: &mut WaitEntry) {
        self.add_entry(entry, false);
    }

    fn add_entry(&self, entry: &mut WaitEntry, autoremove: bool) {
        let mut head = self.head.lock();
        if entry.id != 0 && head.iter().any(|e| e.id == entry.id) {
            return;
        }
        if entry.id == 0 {
            entry.id = NEXT_WAIT_ID.fetch_add(1, Ordering::Relaxed);
        }
        head.push(WaitQueueEntry {
            id: entry.id,
            tid: current_tid(),
            cpu: current_cpu(),
            autoremove,
        });
    }

    /// Remove a registration (no-op if a wakeup already removed it)
    pub fn remove_entry(&self, entry: &WaitEntry) {
        if entry.id == 0 {
            return;
        }
        let mut head = self.head.lock();
        if let Some(pos) = head.iter().position(|e| e.id == entry.id) {
            head.remove(pos);
        }
    }

    /// End a wait: back to Running and unregister (Linux `finish_wait`)
    pub fn finish_wait(&self, entry: &WaitEntry) {
        set_current_state(SleepState::Running);
        self.remove_entry(entry);
    }

    /// Sleep (uninterruptibly) until `cond()` is true
    pub fn wait_event<F: FnMut() -> bool>(&self, mut cond: F) {
        if cond() {
            return;
        }
        let mut w = WaitEntry::new();
        loop {
            self.prepare_to_wait(&mut w, SleepState::Uninterruptible);
            if cond() {
                break;
            }
            schedule();
        }
        self.finish_wait(&w);
    }

    /// Sleep until `cond()` is true or a signal is pending
    ///
    /// Returns `Err(KernelError::RestartSys)` on a signal.
    pub fn wait_event_interruptible<F: FnMut() -> bool>(&self, cond: F) -> Result<(), KernelError> {
        self.wait_event_interruptible_timeout(cond, MAX_SCHEDULE_TIMEOUT)
            .map(|_| ())
    }

    /// Sleep (uninterruptibly) until `cond()` is true or `timeout` ticks
    /// pass. Returns 0 if the timeout elapsed with `cond()` false, else the
    /// ticks left (at least 1), like Linux `wait_event_timeout`.
    pub fn wait_event_timeout<F: FnMut() -> bool>(&self, cond: F, timeout: u64) -> u64 {
        match self.wait_common(cond, timeout, SleepState::Uninterruptible) {
            Ok(left) => left,
            Err(_) => unreachable!("uninterruptible wait interrupted"),
        }
    }

    /// Sleep until `cond()` is true, a signal is pending, or `timeout`
    /// ticks pass (`MAX_SCHEDULE_TIMEOUT` = forever).
    ///
    /// `Ok(0)`: timed out; `Ok(n >= 1)`: condition true with n ticks left;
    /// `Err(RestartSys)`: signal pending.
    pub fn wait_event_interruptible_timeout<F: FnMut() -> bool>(
        &self,
        cond: F,
        timeout: u64,
    ) -> Result<u64, KernelError> {
        self.wait_common(cond, timeout, SleepState::Interruptible)
    }

    /// Sleep until `cond()` is true, a signal, or the CLOCK_MONOTONIC
    /// `deadline` in ns (`None` = never). `Ok(true)`: condition true;
    /// `Ok(false)`: deadline passed; `Err(RestartSys)`: signal.
    pub fn wait_event_interruptible_deadline<F: FnMut() -> bool>(
        &self,
        mut cond: F,
        deadline: Option<u64>,
    ) -> Result<bool, KernelError> {
        loop {
            let ticks = match deadline {
                None => MAX_SCHEDULE_TIMEOUT,
                Some(d) => {
                    let now = crate::time::monotonic_ns();
                    if now >= d {
                        return Ok(cond());
                    }
                    crate::task::percpu::ns_to_ticks(d - now)
                }
            };
            if self.wait_event_interruptible_timeout(&mut cond, ticks)? != 0 {
                return Ok(true);
            }
            // Tick granularity: re-check the clock before giving up
        }
    }

    fn wait_common<F: FnMut() -> bool>(
        &self,
        mut cond: F,
        timeout: u64,
        state: SleepState,
    ) -> Result<u64, KernelError> {
        if cond() {
            return Ok(timeout.max(1));
        }
        let mut w = WaitEntry::new();
        let mut left = timeout;
        let result = loop {
            self.prepare_to_wait(&mut w, state);
            if cond() {
                break Ok(left.max(1));
            }
            if state == SleepState::Interruptible && signal_pending() {
                break Err(KernelError::RestartSys);
            }
            if left == 0 {
                break Ok(0);
            }
            left = schedule_timeout(left);
            if left == 0 {
                // Timed out: one last look (Linux __wait_event_timeout)
                self.prepare_to_wait(&mut w, state);
                break Ok(if cond() { 1 } else { 0 });
            }
        };
        self.finish_wait(&w);
        result
    }

    /// Wake up to `nr` waiters (`usize::MAX` = all) under the head lock
    /// without allocating (Linux __wake_up_common: try_to_wake_up runs
    /// under wq_head->lock), so IRQ handlers may wake. Order: head ->
    /// run-queue lock / remote `wake_list`.
    fn wake_nr(&self, nr: usize) -> usize {
        let mut head = self.head.lock();
        let mut woken = 0;
        let mut i = 0;
        while i < head.len() && woken < nr {
            let (tid, cpu, auto) = (head[i].tid, head[i].cpu, head[i].autoremove);
            if auto {
                head.remove(i);
            } else {
                i += 1;
            }
            wake_up_task(tid, cpu, WakeMode::Any);
            woken += 1;
        }
        woken
    }

    /// Wake one waiter (FIFO). Returns true if a task was woken.
    pub fn wake_one(&self) -> bool {
        self.wake_nr(1) != 0
    }

    /// Wake all waiters. Returns the number of waiters woken.
    pub fn wake_all(&self) -> usize {
        self.wake_nr(usize::MAX)
    }

    /// Check if the wait queue is empty
    pub fn is_empty(&self) -> bool {
        self.head.lock().is_empty()
    }

    /// Get the number of waiters
    pub fn len(&self) -> usize {
        self.head.lock().len()
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
