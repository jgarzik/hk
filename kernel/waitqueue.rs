//! Wait queue infrastructure for blocking synchronization
//!
//! Linux-style wait queues (include/linux/wait.h, kernel/sched/wait.c):
//!
//! - A sleeper links a [`WaitEntry`] pinned on its stack into the queue
//!   and sets its sleep state *before* re-checking its condition
//!   (`prepare_to_wait`), then calls `schedule()`. A wakeup that lands
//!   between the check and `schedule()` flips the state back to Running,
//!   so `schedule()` returns at once: no lost wakeups.
//! - `wait_event*` wrap the loop; the `_interruptible` variants return
//!   `Err(KernelError::RestartSys)` when a signal is pending (the syscall
//!   exit path turns that into a restart or -EINTR), `_killable` returns
//!   `Err(KernelError::Interrupted)` on SIGKILL only, `_timeout` variants
//!   take scheduler ticks and return the ticks left, `_exclusive` waits
//!   are woken one at a time.
//! - Wakers (`wake_one`/`wake_all`) may run in any context, including IRQ
//!   handlers: the queue lock is an `IrqSpinlock`, the task wakeup only
//!   takes the task's pi_lock and a run-queue lock (never TASKLIST), and
//!   nothing on the wake path allocates. `wake_one` is Linux wake_up:
//!   every non-exclusive waiter and one exclusive waiter.
//! - An entry may carry its own wake function (poll and epoll use one,
//!   Linux pollwake): it runs under the queue lock instead of the
//!   default task wakeup.
//!
//! ## Usage
//!
//! ```ignore
//! static WQ: WaitQueue = WaitQueue::new();
//! // sleeper
//! WQ.wait_event_interruptible(|| data_ready())?;
//! // waker: make the condition true first, then
//! WQ.wake_all();
//! // open-coded
//! let w = core::pin::pin!(WaitEntry::new());
//! loop {
//!     WQ.prepare_to_wait(w.as_ref(), SleepState::Interruptible);
//!     if data_ready() { break; }
//!     schedule();
//! }
//! WQ.finish_wait(w.as_ref());
//! ```
//!
//! ## Lifetime
//!
//! An entry is linked only while pinned; it records the queue it is on,
//! and dropping it unlinks it (under that queue's lock), so no exit path
//! (a signal, an error, a panic unwinding) leaves a stale entry behind.
//! The queue must outlive its entries (they live on a waiter's stack, or
//! in a poll table that holds the file owning the queue). A waker that
//! removes an entry clears its queue pointer last (Release): once a
//! waiter sees it clear (Acquire) the waker no longer touches the entry.
//!
//! ## Lock Ordering
//!
//! The queue's IrqSpinlock is taken before the task's pi_lock and the
//! run-queue lock (wakeups are issued under it, like Linux); nothing
//! else nests inside it, but what an entry's wake function takes (an
//! IrqSpinlock leaf). Never call a `wait*` function while holding a
//! spinlock, and never wake while holding this CPU's run-queue lock.

use core::marker::PhantomPinned;
use core::pin::Pin;
use core::sync::atomic::{AtomicPtr, AtomicU8, Ordering};

use crate::arch::IrqSpinlock;
use crate::error::KernelError;
use crate::hrtimer::HrClock;
use crate::list::{Link, List};
use crate::task::percpu::{
    KernelTask, MAX_SCHEDULE_TIMEOUT, SleepState, WakeMode, current, current_tid, schedule_timeout,
    set_current_state, try_to_wake_up,
};

/// Woken one at a time (Linux WQ_FLAG_EXCLUSIVE): appended, and a
/// `wake_one` stops after waking one
pub const WQ_EXCLUSIVE: u8 = 1;
/// Unlinked by the waker that woke it (Linux autoremove_wake_function)
pub const WQ_AUTOREMOVE: u8 = 2;

/// An entry's wake function (Linux wait_queue_func_t): called under the
/// queue lock with the wake mode and key; true if it woke its waiter
pub type WakeFn = fn(&WaitEntry, WakeMode, usize) -> bool;

/// A task's registration on one wait queue (Linux `wait_queue_entry`)
///
/// Pin it (on the stack: `pin!(WaitEntry::new())`) before linking it.
pub struct WaitEntry {
    link: Link,
    /// The waiting task (the entry is unlinked before it can go away)
    task: *const KernelTask,
    /// WQ_EXCLUSIVE | WQ_AUTOREMOVE
    flags: AtomicU8,
    /// Called by wakers instead of waking `task`
    func: Option<WakeFn>,
    /// The wake function's data
    pub private: usize,
    /// The queue it is on (null: none); written under that queue's lock
    wq: AtomicPtr<WaitQueue>,
    _pin: PhantomPinned,
}

// SAFETY: the links and `task` are only followed under the owning
// queue's lock (see the module docs)
unsafe impl Sync for WaitEntry {}
unsafe impl Send for WaitEntry {}

crate::adapter!(EntryAdapter, WaitEntry, link);

impl WaitEntry {
    /// An entry for the current task (unlinked)
    pub fn new() -> Self {
        Self::with_func(None, 0)
    }

    /// An entry whose wakeups call `func` (with `private` as its data)
    pub fn with_func(func: Option<WakeFn>, private: usize) -> Self {
        Self {
            link: Link::new(),
            task: &*current() as *const KernelTask,
            flags: AtomicU8::new(0),
            func,
            private,
            wq: AtomicPtr::new(core::ptr::null_mut()),
            _pin: PhantomPinned,
        }
    }

    /// The waiting task
    pub fn task(&self) -> &KernelTask {
        // SAFETY: the task outlives its entries (they are unlinked first)
        unsafe { &*self.task }
    }

    /// Linked on a queue (Linux !list_empty_careful)
    pub fn is_queued(&self) -> bool {
        !self.wq.load(Ordering::Acquire).is_null()
    }
}

impl Default for WaitEntry {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for WaitEntry {
    fn drop(&mut self) {
        let wq = self.wq.load(Ordering::Acquire);
        // SAFETY: the queue outlives its entries (module docs)
        if let Some(wq) = unsafe { wq.as_ref() } {
            // SAFETY: pinned until now, and this is its last use
            wq.remove_wait_queue(unsafe { Pin::new_unchecked(&*self) });
        }
    }
}

/// Wake `e`'s task (Linux default_wake_function)
fn default_wake(e: &WaitEntry, mode: WakeMode, _key: usize) -> bool {
    try_to_wake_up(e.task(), mode)
}

/// A wait queue for blocking synchronization
///
/// Tasks can wait on this queue and be woken by other tasks or IRQ
/// handlers.
pub struct WaitQueue {
    /// Waiters: non-exclusive ones first, exclusive ones FIFO
    head: IrqSpinlock<List<EntryAdapter>>,
}

/// True if the current task has a deliverable signal pending
pub fn signal_pending() -> bool {
    crate::signal::has_pending_signals(current_tid())
}

impl WaitQueue {
    /// Create a new empty wait queue
    pub const fn new() -> Self {
        Self {
            head: IrqSpinlock::new(List::new()),
        }
    }

    /// Link `w` unless it is linked (head lock held)
    fn link(&self, list: &mut List<EntryAdapter>, w: Pin<&WaitEntry>, flags: u8) {
        if w.is_queued() {
            return;
        }
        w.flags.store(flags, Ordering::Relaxed);
        let p = &*w as *const WaitEntry;
        // SAFETY: pinned, on no list, unlinked before it goes (Drop)
        unsafe {
            if flags & WQ_EXCLUSIVE != 0 {
                list.push_back(p);
            } else {
                list.push_front(p);
            }
        }
        w.wq.store(self as *const Self as *mut Self, Ordering::Release);
    }

    /// Register `w` (if not registered) and set the current task's state
    ///
    /// Linux `prepare_to_wait`: call at the top of every wait-loop
    /// iteration, then re-check the condition, then `schedule()`.
    pub fn prepare_to_wait(&self, w: Pin<&WaitEntry>, state: SleepState) {
        let mut list = self.head.lock();
        self.link(&mut list, w, WQ_AUTOREMOVE);
        set_current_state(state);
    }

    /// `prepare_to_wait` for an exclusive waiter (Linux
    /// prepare_to_wait_exclusive)
    pub fn prepare_to_wait_exclusive(&self, w: Pin<&WaitEntry>, state: SleepState) {
        let mut list = self.head.lock();
        self.link(&mut list, w, WQ_AUTOREMOVE | WQ_EXCLUSIVE);
        set_current_state(state);
    }

    /// Register `w` until `remove_wait_queue` (Linux add_wait_queue: poll
    /// and epoll; every wakeup calls its function)
    pub fn add_wait_queue(&self, w: Pin<&WaitEntry>) {
        let mut list = self.head.lock();
        self.link(&mut list, w, 0);
    }

    /// Unlink `w` if it is on this queue (Linux remove_wait_queue)
    pub fn remove_wait_queue(&self, w: Pin<&WaitEntry>) {
        let mut list = self.head.lock();
        if core::ptr::eq(w.wq.load(Ordering::Relaxed), self) {
            // SAFETY: on this list (its queue pointer says so)
            unsafe { list.remove(&*w) };
            w.wq.store(core::ptr::null_mut(), Ordering::Release);
        }
    }

    /// End a wait: back to Running and unregister (Linux `finish_wait`)
    pub fn finish_wait(&self, w: Pin<&WaitEntry>) {
        set_current_state(SleepState::Running);
        if w.is_queued() {
            self.remove_wait_queue(w);
        }
    }

    /// Sleep (uninterruptibly) until `cond()` is true
    pub fn wait_event<F: FnMut() -> bool>(&self, cond: F) {
        let r = self.wait_common(
            cond,
            MAX_SCHEDULE_TIMEOUT,
            SleepState::Uninterruptible,
            false,
        );
        debug_assert!(r.is_ok());
    }

    /// `wait_event` as an exclusive waiter: one `wake_one` wakes one
    /// such waiter (a lock or a completion handed to one task)
    pub fn wait_event_exclusive<F: FnMut() -> bool>(&self, cond: F) {
        let r = self.wait_common(
            cond,
            MAX_SCHEDULE_TIMEOUT,
            SleepState::Uninterruptible,
            true,
        );
        debug_assert!(r.is_ok());
    }

    /// Exclusive [`Self::wait_event_interruptible`] (Linux
    /// wait_event_interruptible_exclusive)
    pub fn wait_event_interruptible_exclusive<F: FnMut() -> bool>(
        &self,
        cond: F,
    ) -> Result<(), KernelError> {
        self.wait_common(cond, MAX_SCHEDULE_TIMEOUT, SleepState::Interruptible, true)
            .map(|_| ())
    }

    /// Exclusive [`Self::wait_event_killable`] (Linux
    /// wait_event_killable_exclusive)
    pub fn wait_event_killable_exclusive<F: FnMut() -> bool>(
        &self,
        cond: F,
    ) -> Result<(), KernelError> {
        self.wait_common(cond, MAX_SCHEDULE_TIMEOUT, SleepState::Killable, true)
            .map(|_| ())
    }

    /// Sleep until `cond()` is true or a signal is pending
    ///
    /// Returns `Err(KernelError::RestartSys)` on a signal.
    pub fn wait_event_interruptible<F: FnMut() -> bool>(&self, cond: F) -> Result<(), KernelError> {
        self.wait_event_interruptible_timeout(cond, MAX_SCHEDULE_TIMEOUT)
            .map(|_| ())
    }

    /// Sleep until `cond()` is true or SIGKILL is pending (Linux
    /// wait_event_killable). Returns `Err(KernelError::Interrupted)` on
    /// a fatal signal; other signals do not end the wait.
    pub fn wait_event_killable<F: FnMut() -> bool>(&self, cond: F) -> Result<(), KernelError> {
        self.wait_common(cond, MAX_SCHEDULE_TIMEOUT, SleepState::Killable, false)
            .map(|_| ())
    }

    /// Sleep (uninterruptibly) until `cond()` is true or `timeout` ticks
    /// pass. Returns 0 if the timeout elapsed with `cond()` false, else the
    /// ticks left (at least 1), like Linux `wait_event_timeout`.
    pub fn wait_event_timeout<F: FnMut() -> bool>(&self, cond: F, timeout: u64) -> u64 {
        match self.wait_common(cond, timeout, SleepState::Uninterruptible, false) {
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
        self.wait_common(cond, timeout, SleepState::Interruptible, false)
    }

    /// Sleep (uninterruptibly) until `cond()` is true or `deadline` ns on
    /// `clock` passes (`None` = never). True if `cond()` holds.
    pub fn wait_event_deadline<F: FnMut() -> bool>(
        &self,
        cond: F,
        deadline: Option<u64>,
        clock: HrClock,
    ) -> bool {
        match self.deadline_common(cond, deadline, clock, SleepState::Uninterruptible) {
            Ok(done) => done,
            Err(_) => unreachable!("uninterruptible wait interrupted"),
        }
    }

    /// Sleep until `cond()` is true, a signal, or `deadline` ns on `clock`
    /// (`None` = never). `Ok(true)`: condition true; `Ok(false)`: deadline
    /// passed; `Err(RestartSys)`: signal.
    pub fn wait_event_interruptible_deadline<F: FnMut() -> bool>(
        &self,
        cond: F,
        deadline: Option<u64>,
        clock: HrClock,
    ) -> Result<bool, KernelError> {
        self.deadline_common(cond, deadline, clock, SleepState::Interruptible)
    }

    /// As [`Self::wait_event_interruptible_deadline`], woken only by a
    /// fatal signal (`Err(Interrupted)`)
    pub fn wait_event_killable_deadline<F: FnMut() -> bool>(
        &self,
        cond: F,
        deadline: Option<u64>,
        clock: HrClock,
    ) -> Result<bool, KernelError> {
        self.deadline_common(cond, deadline, clock, SleepState::Killable)
    }

    /// The deadline wait loop (Linux ___wait_event with
    /// schedule_hrtimeout): ns-precise, never early, and an absolute
    /// CLOCK_REALTIME deadline follows clock steps
    fn deadline_common<F: FnMut() -> bool>(
        &self,
        mut cond: F,
        deadline: Option<u64>,
        clock: HrClock,
        state: SleepState,
    ) -> Result<bool, KernelError> {
        crate::sync::might_sleep();
        if cond() {
            return Ok(true);
        }
        let w = core::pin::pin!(WaitEntry::new());
        let result = loop {
            self.prepare_to_wait(w.as_ref(), state);
            if cond() {
                break Ok(true);
            }
            if interrupted(state) {
                break Err(match state {
                    SleepState::Killable => KernelError::Interrupted,
                    _ => KernelError::RestartSys,
                });
            }
            if crate::hrtimer::schedule_hrtimeout(deadline, clock) {
                // Timed out: one last look
                self.prepare_to_wait(w.as_ref(), state);
                break Ok(cond());
            }
        };
        self.finish_wait(w.as_ref());
        result
    }

    /// The wait loop (Linux ___wait_event); the entry is unlinked on
    /// every way out (finish_wait, else its Drop)
    fn wait_common<F: FnMut() -> bool>(
        &self,
        mut cond: F,
        timeout: u64,
        state: SleepState,
        exclusive: bool,
    ) -> Result<u64, KernelError> {
        crate::sync::might_sleep();
        if cond() {
            return Ok(timeout.max(1));
        }
        let w = core::pin::pin!(WaitEntry::new());
        let prepare = |w: Pin<&WaitEntry>| {
            if exclusive {
                self.prepare_to_wait_exclusive(w, state)
            } else {
                self.prepare_to_wait(w, state)
            }
        };
        let mut left = timeout;
        let result = loop {
            prepare(w.as_ref());
            if cond() {
                break Ok(left.max(1));
            }
            if interrupted(state) {
                break Err(match state {
                    SleepState::Killable => KernelError::Interrupted,
                    _ => KernelError::RestartSys,
                });
            }
            if left == 0 {
                break Ok(0);
            }
            left = schedule_timeout(left);
            if left == 0 {
                // Timed out: one last look (Linux __wait_event_timeout)
                prepare(w.as_ref());
                break Ok(if cond() { 1 } else { 0 });
            }
        };
        // A waker that picked this exclusive entry (it is no longer
        // queued) while it gives up (signal, timeout) passes its wakeup
        // on, or the next exclusive waiter would sleep with the
        // condition true (Linux abort_exclusive_wait)
        let gave_up = !matches!(result, Ok(n) if n > 0);
        let picked = !w.is_queued();
        self.finish_wait(w.as_ref());
        if exclusive && gave_up && picked {
            self.wake_one();
        }
        result
    }

    /// Wake waiters (Linux __wake_up_common) under the head lock without
    /// allocating, so IRQ handlers may wake: every non-exclusive entry
    /// and up to `nr_exclusive` exclusive ones whose wake succeeded.
    /// Order: head -> pi_lock -> run-queue lock. Returns the waiters
    /// woken.
    fn wake_common(&self, mode: WakeMode, nr_exclusive: usize, key: usize) -> usize {
        let mut list = self.head.lock();
        let (mut woken, mut excl) = (0, nr_exclusive);
        let mut cur = list.front();
        while let Some(p) = cur {
            // SAFETY: on the list; its next is read before it may go
            cur = unsafe { list.next(p) };
            // SAFETY: linked entries are live (module docs)
            let e = unsafe { &*p };
            let flags = e.flags.load(Ordering::Relaxed);
            if !e.func.unwrap_or(default_wake)(e, mode, key) {
                continue;
            }
            woken += 1;
            if flags & WQ_AUTOREMOVE != 0 {
                // SAFETY: on this list
                unsafe { list.remove(p) };
                // Last touch: the waiter may return once it sees this
                e.wq.store(core::ptr::null_mut(), Ordering::Release);
            }
            if flags & WQ_EXCLUSIVE != 0 {
                excl -= 1;
                if excl == 0 {
                    break;
                }
            }
        }
        woken
    }

    /// Wake every non-exclusive waiter and one exclusive waiter (Linux
    /// wake_up). Returns true if a task was woken.
    pub fn wake_one(&self) -> bool {
        self.wake_common(WakeMode::Any, 1, 0) != 0
    }

    /// Wake all waiters. Returns the number of waiters woken.
    pub fn wake_all(&self) -> usize {
        self.wake_common(WakeMode::Any, usize::MAX, 0)
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

/// A pending signal ends a sleep in `state` (Linux signal_pending_state)
fn interrupted(state: SleepState) -> bool {
    match state {
        SleepState::Interruptible => signal_pending(),
        SleepState::Killable => crate::signal::fatal_signal_pending(),
        _ => false,
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
