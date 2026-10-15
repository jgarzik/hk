//! Workqueue infrastructure for deferred work execution
//!
//! This module provides a workqueue subsystem similar to Linux's workqueue,
//! allowing kernel code to defer work to a worker thread context instead of
//! running in interrupt context.
//!
//! ## Key Types
//!
//! - [`Work`] - A work item with a callback function
//! - [`DelayedWork`] - A work item that executes after a delay
//! - [`Workqueue`] - A queue with worker thread(s) to execute work items
//!
//! ## Usage
//!
//! ```ignore
//! // Create a work item
//! let work = Work::new(|| {
//!     println!("Work executed!");
//! });
//!
//! // Queue for immediate execution
//! SYSTEM_WQ.queue_work(Arc::new(Mutex::new(work)));
//!
//! // Or queue for delayed execution (500 ticks = ~5 seconds)
//! let delayed = DelayedWork::new(|| { ... });
//! SYSTEM_WQ.queue_delayed_work(Arc::new(Mutex::new(delayed)), 500);
//! ```
//!
//! ## Execution and locking
//!
//! Each started workqueue has one worker kernel thread (`kworker/<name>`).
//! The worker moves expired delayed work to the pending queue itself and
//! sleeps on `wait` with a timeout until the earliest delay expires, so
//! nothing runs in IRQ context. `inner` is an `IrqSpinlock` (leaf); the
//! per-item `Mutex` is never held while the work function runs, so work may
//! re-queue itself. `queue_work`/`queue_delayed_work` are process-context
//! only (they take the item's Mutex).

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::sync::spin::Mutex;

use crate::arch::IrqSpinlock;
use crate::task::Tid;
use crate::task::percpu::{SCHEDULING_ENABLED, get_ticks};
use crate::waitqueue::WaitQueue;

// ============================================================================
// Work Flags
// ============================================================================

/// Work item state flags
pub mod work_flags {
    /// Work is pending execution
    pub const WORK_PENDING: u32 = 1 << 0;
    /// Work is currently executing
    pub const WORK_RUNNING: u32 = 1 << 1;
}

// ============================================================================
// Workqueue Flags
// ============================================================================

/// Workqueue flags
pub mod wq_flags {
    /// Queue can be used during memory reclaim (writeback)
    pub const WQ_MEM_RECLAIM: u32 = 1 << 0;
    /// Workers are not bound to specific CPUs
    pub const WQ_UNBOUND: u32 = 1 << 1;
    /// High priority queue
    pub const WQ_HIGHPRI: u32 = 1 << 2;
}

// ============================================================================
// Work
// ============================================================================

/// Work callback function type
///
/// Must be Send + 'static since work may execute on any CPU's worker thread.
pub type WorkFn = Box<dyn FnMut() + Send + 'static>;

/// A work item that can be queued for execution
///
/// Similar to Linux's `work_struct`. Contains a callback function that
/// will be executed by a worker thread.
pub struct Work {
    /// Callback function to execute
    func: Option<WorkFn>,
    /// Atomic state flags (WORK_PENDING, WORK_RUNNING)
    state: AtomicU32,
}

// Safety: Work uses atomic state and boxed callback with Send bound
unsafe impl Send for Work {}
unsafe impl Sync for Work {}

impl Work {
    /// Create a new work item with the given callback
    pub fn new<F: FnMut() + Send + 'static>(func: F) -> Self {
        Self {
            func: Some(Box::new(func)),
            state: AtomicU32::new(0),
        }
    }

    /// Check if work is pending execution
    pub fn is_pending(&self) -> bool {
        self.state.load(Ordering::Acquire) & work_flags::WORK_PENDING != 0
    }

    /// Try to mark as pending (returns true if successful, false if already pending)
    fn try_set_pending(&self) -> bool {
        let prev = self
            .state
            .fetch_or(work_flags::WORK_PENDING, Ordering::AcqRel);
        prev & work_flags::WORK_PENDING == 0
    }

    /// Clear pending flag
    fn clear_pending(&self) {
        self.state
            .fetch_and(!work_flags::WORK_PENDING, Ordering::Release);
    }

    /// Start running: mark RUNNING, clear PENDING (so the function may
    /// re-queue the item) and hand out the callback
    fn begin_run(&mut self) -> Option<WorkFn> {
        self.state
            .fetch_or(work_flags::WORK_RUNNING, Ordering::AcqRel);
        self.clear_pending();
        self.func.take()
    }

    /// Finish a run started with `begin_run`
    fn end_run(&mut self, func: Option<WorkFn>) {
        self.func = func;
        self.state
            .fetch_and(!work_flags::WORK_RUNNING, Ordering::Release);
    }

    /// Run the callback of `work` without holding its lock during the call
    fn run(work: &Mutex<Work>) {
        let mut func = work.lock().begin_run();
        if let Some(f) = func.as_mut() {
            f();
        }
        work.lock().end_run(func);
    }

    /// Run a delayed work item without holding its lock during the call
    fn run_delayed(dw: &Mutex<DelayedWork>) {
        let mut func = dw.lock().work.begin_run();
        if let Some(f) = func.as_mut() {
            f();
        }
        dw.lock().work.end_run(func);
    }
}

// ============================================================================
// DelayedWork
// ============================================================================

/// A work item that executes after a delay
///
/// Similar to Linux's `delayed_work`. Combines a Work with a timer that
/// fires after a specified number of timer ticks.
pub struct DelayedWork {
    /// Underlying work item
    work: Work,
    /// Wake tick (0 = not scheduled, >0 = scheduled for that tick)
    wake_tick: AtomicU64,
}

// Safety: DelayedWork uses atomic wake_tick and inherits Work's safety
unsafe impl Send for DelayedWork {}
unsafe impl Sync for DelayedWork {}

impl DelayedWork {
    /// Create a new delayed work item
    pub fn new<F: FnMut() + Send + 'static>(func: F) -> Self {
        Self {
            work: Work::new(func),
            wake_tick: AtomicU64::new(0),
        }
    }

    /// Check if the timer is armed (scheduled for future execution)
    pub fn is_timer_pending(&self) -> bool {
        self.wake_tick.load(Ordering::Acquire) != 0
    }

    /// Get the scheduled wake tick (0 if not scheduled)
    pub fn get_wake_tick(&self) -> u64 {
        self.wake_tick.load(Ordering::Acquire)
    }

    /// Schedule for execution at the given tick
    ///
    /// Returns the previous wake tick (0 if was not scheduled)
    fn schedule_at(&self, tick: u64) -> u64 {
        self.wake_tick.swap(tick, Ordering::AcqRel)
    }

    /// Cancel the timer
    ///
    /// Returns true if was pending, false if not scheduled
    pub fn cancel_timer(&self) -> bool {
        self.wake_tick.swap(0, Ordering::AcqRel) != 0
    }

    /// Check if the work is pending execution
    pub fn is_pending(&self) -> bool {
        self.work.is_pending()
    }
}

// ============================================================================
// Workqueue
// ============================================================================

/// Inner state protected by IrqSpinlock
struct WorkqueueInner {
    /// Pending immediate work items
    pending: VecDeque<Arc<Mutex<Work>>>,
    /// Pending delayed work items (not sorted - we scan linearly)
    delayed: Vec<Arc<Mutex<DelayedWork>>>,
    /// Worker thread TID (0 = not started)
    worker_tid: Tid,
    /// Flag indicating work is available
    has_work: bool,
}

/// A workqueue for executing deferred work
///
/// Similar to Linux's `workqueue_struct`. Contains queues for pending work
/// and a worker thread that executes items.
pub struct Workqueue {
    /// Name for debugging
    name: &'static str,
    /// Queue flags
    flags: u32,
    /// Protected queue state
    inner: IrqSpinlock<WorkqueueInner>,
    /// Wait queue for worker thread
    wait: WaitQueue,
    /// Bumped whenever delayed work is added or re-timed (worker re-arms)
    delayed_gen: AtomicU64,
    /// Initialization flag
    initialized: AtomicBool,
}

// Safety: Workqueue uses internal synchronization
unsafe impl Send for Workqueue {}
unsafe impl Sync for Workqueue {}

impl Workqueue {
    /// Create a new workqueue
    ///
    /// Note: The workqueue is not active until `init()` is called to start
    /// the worker thread.
    pub const fn new(name: &'static str, flags: u32) -> Self {
        Self {
            name,
            flags,
            inner: IrqSpinlock::new(WorkqueueInner {
                pending: VecDeque::new(),
                delayed: Vec::new(),
                worker_tid: 0,
                has_work: false,
            }),
            wait: WaitQueue::new(),
            delayed_gen: AtomicU64::new(0),
            initialized: AtomicBool::new(false),
        }
    }

    /// Get the workqueue name
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Get the workqueue flags
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// Queue work for immediate execution
    ///
    /// Returns true if the work was queued, false if it was already pending.
    pub fn queue_work(&self, work: Arc<Mutex<Work>>) -> bool {
        // Try to mark as pending
        {
            let guard = work.lock();
            if !guard.try_set_pending() {
                return false; // Already pending
            }
        }

        // Add to pending queue
        {
            let mut inner = self.inner.lock();
            inner.pending.push_back(work);
            inner.has_work = true;
        }

        // Wake worker thread
        self.wait.wake_one();

        true
    }

    /// Queue delayed work for execution after delay_ticks
    ///
    /// Returns true if the work was queued, false if it was already pending.
    pub fn queue_delayed_work(&self, work: Arc<Mutex<DelayedWork>>, delay_ticks: u64) -> bool {
        let current_tick = get_ticks();
        let wake_tick = current_tick.saturating_add(delay_ticks);

        // Try to mark as pending and schedule
        {
            let guard = work.lock();
            if !guard.work.try_set_pending() {
                return false; // Already pending
            }
            guard.schedule_at(wake_tick);
        }

        // Add to delayed queue
        {
            let mut inner = self.inner.lock();
            inner.delayed.push(work);
        }

        // Let the worker re-arm its timeout for the new deadline
        self.delayed_gen.fetch_add(1, Ordering::AcqRel);
        self.wait.wake_one();

        true
    }

    /// Modify a delayed work's delay (reschedule)
    ///
    /// If the work is already pending, cancels the old timer and reschedules.
    /// Returns true if modified, false if work wasn't found.
    pub fn mod_delayed_work(&self, work: &Arc<Mutex<DelayedWork>>, delay_ticks: u64) -> bool {
        let current_tick = get_ticks();
        let wake_tick = current_tick.saturating_add(delay_ticks);

        let modified = {
            let guard = work.lock();
            if guard.is_timer_pending() || guard.is_pending() {
                guard.schedule_at(wake_tick);
                true
            } else {
                false
            }
        };
        if modified {
            self.delayed_gen.fetch_add(1, Ordering::AcqRel);
            self.wait.wake_one();
        }
        modified
    }

    /// Move expired delayed work to the pending queue (worker thread)
    ///
    /// Returns the earliest remaining wake tick, if any.
    fn promote_delayed(&self, current_tick: u64) -> Option<u64> {
        let mut inner = self.inner.lock();
        let mut next: Option<u64> = None;
        let mut i = 0;
        while i < inner.delayed.len() {
            let wake_tick = inner.delayed[i].lock().get_wake_tick();
            if wake_tick == 0 || wake_tick <= current_tick {
                // Expired (or cancelled: run it now, as Linux flush does)
                let dw = inner.delayed.remove(i);
                dw.lock().wake_tick.store(0, Ordering::Release);
                let dw_run = dw.clone();
                let work = Work::new(move || Work::run_delayed(&dw_run));
                // The wrapper is fresh: mark it pending like queue_work
                work.try_set_pending();
                inner.pending.push_back(Arc::new(Mutex::new(work)));
                inner.has_work = true;
            } else {
                next = Some(next.map_or(wake_tick, |n: u64| n.min(wake_tick)));
                i += 1;
            }
        }
        next
    }

    /// Process pending work items (called by worker thread)
    ///
    /// Returns the number of work items processed.
    fn process_pending(&self) -> usize {
        let mut processed = 0;

        loop {
            // Pop one work item
            let work = {
                let mut inner = self.inner.lock();
                inner.pending.pop_front()
            };

            match work {
                Some(w) => {
                    Work::run(&w);
                    processed += 1;
                }
                None => break,
            }
        }

        // Clear has_work flag
        {
            let mut inner = self.inner.lock();
            inner.has_work = !inner.pending.is_empty();
        }

        processed
    }

    /// Check if there is pending work
    pub fn has_pending(&self) -> bool {
        self.inner.lock().has_work
    }

    /// Mark this workqueue as initialized
    fn mark_initialized(&self) {
        self.initialized.store(true, Ordering::Release);
    }

    /// Check if initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
    }
}

// ============================================================================
// Global Workqueues
// ============================================================================

/// System workqueue for general deferred work
pub static SYSTEM_WQ: Workqueue = Workqueue::new("system", 0);

// ============================================================================
// Worker threads
// ============================================================================

impl Workqueue {
    /// Start this workqueue's worker kernel thread
    ///
    /// `cpu`: bind the worker to a CPU, or `None` for any (WQ_UNBOUND-like).
    pub fn start(&'static self, cpu: Option<u32>) -> Result<(), crate::error::KernelError> {
        let k = crate::task::kthread::kthread_run(
            self.name,
            worker_thread_fn,
            self as *const Workqueue as usize,
            cpu,
        )?;
        self.inner.lock().worker_tid = k.tid();
        self.mark_initialized();
        Ok(())
    }
}

/// Worker thread: run pending work, promote expired delayed work, sleep
/// until new work or the next delay expires
fn worker_thread_fn(arg: usize) {
    use crate::task::kthread::kthread_should_stop;
    use crate::task::percpu::MAX_SCHEDULE_TIMEOUT;

    // Safety: `start` takes `&'static self`
    let wq: &'static Workqueue = unsafe { &*(arg as *const Workqueue) };
    loop {
        // Delayed-queue changes after this point re-run the loop
        let seen_gen = wq.delayed_gen.load(Ordering::Acquire);
        let next = wq.promote_delayed(get_ticks());
        wq.process_pending();
        if kthread_should_stop() {
            break;
        }
        let timeout = match next {
            Some(t) => t.saturating_sub(get_ticks()).max(1),
            None => MAX_SCHEDULE_TIMEOUT,
        };
        wq.wait.wait_event_timeout(
            || {
                wq.has_pending()
                    || wq.delayed_gen.load(Ordering::Acquire) != seen_gen
                    || kthread_should_stop()
            },
            timeout,
        );
    }
}

/// Initialize the workqueue subsystem: start the system workqueue's worker
///
/// Call after the schedulers are up (main.rs, before user space).
pub fn init() {
    if !SCHEDULING_ENABLED.load(Ordering::Acquire) {
        panic!("workqueue::init() called before scheduling enabled");
    }
    match SYSTEM_WQ.start(None) {
        Ok(()) => crate::printkln!("Workqueue subsystem initialized"),
        Err(e) => crate::printkln!("workqueue: no system worker: {:?}", e),
    }
}

/// Flush all pending work on a workqueue
///
/// Waits for all currently pending work items to complete (runs them
/// synchronously in the caller if the queue has no worker).
#[allow(dead_code)]
pub fn flush_workqueue(wq: &Workqueue) {
    while wq.has_pending() {
        wq.process_pending();
    }
}
