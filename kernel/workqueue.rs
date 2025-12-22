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

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use spin::Mutex;

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

    /// Execute the work callback
    fn execute(&mut self) {
        self.state
            .fetch_or(work_flags::WORK_RUNNING, Ordering::AcqRel);
        if let Some(ref mut func) = self.func {
            func();
        }
        self.state
            .fetch_and(!work_flags::WORK_RUNNING, Ordering::Release);
        self.clear_pending();
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
    #[allow(dead_code)]
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

        // No need to wake - timer_tick will check and wake when time expires

        true
    }

    /// Modify a delayed work's delay (reschedule)
    ///
    /// If the work is already pending, cancels the old timer and reschedules.
    /// Returns true if modified, false if work wasn't found.
    pub fn mod_delayed_work(&self, work: &Arc<Mutex<DelayedWork>>, delay_ticks: u64) -> bool {
        let current_tick = get_ticks();
        let wake_tick = current_tick.saturating_add(delay_ticks);

        let guard = work.lock();
        if guard.is_timer_pending() || guard.is_pending() {
            guard.schedule_at(wake_tick);
            true
        } else {
            false
        }
    }

    /// Check delayed work and move expired items to pending queue
    ///
    /// Called from timer_tick() in interrupt context.
    /// Uses try_lock to avoid blocking in IRQ.
    pub fn check_delayed_work(&self, current_tick: u64) {
        // Try to acquire lock without blocking (we're in IRQ context)
        let mut inner = match self.inner.try_lock() {
            Some(guard) => guard,
            None => return, // Lock held, skip this tick
        };

        // Find expired delayed work items
        let mut expired_indices: Vec<usize> = Vec::new();
        for (i, dw) in inner.delayed.iter().enumerate() {
            // Try to lock the delayed work item
            let dw_guard: spin::MutexGuard<'_, DelayedWork> = match dw.try_lock() {
                Some(g) => g,
                None => continue, // Skip if locked
            };
            let wake_tick = dw_guard.get_wake_tick();
            if wake_tick > 0 && wake_tick <= current_tick {
                expired_indices.push(i);
            }
        }

        // Move expired items to pending queue (reverse order to preserve indices)
        let mut should_wake = false;
        for i in expired_indices.into_iter().rev() {
            let dw: Arc<Mutex<DelayedWork>> = inner.delayed.remove(i);

            // Clear the timer, keep pending flag set
            {
                let dw_guard: spin::MutexGuard<'_, DelayedWork> = match dw.try_lock() {
                    Some(g) => g,
                    None => continue,
                };
                dw_guard.wake_tick.store(0, Ordering::Release);
            }

            // Create a Work wrapper that executes the delayed work
            let dw_clone = dw.clone();
            let work = Work::new(move || {
                let mut guard = dw_clone.lock();
                guard.work.execute();
            });

            inner.pending.push_back(Arc::new(Mutex::new(work)));
            inner.has_work = true;
            should_wake = true;
        }

        drop(inner);

        // Wake worker thread if we queued work
        if should_wake {
            self.wait.wake_one();
        }
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
                    let mut guard = w.lock();
                    guard.execute();
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

/// List of all workqueues that need timer_tick processing
static WORKQUEUES: IrqSpinlock<Vec<&'static Workqueue>> = IrqSpinlock::new(Vec::new());

/// Register a workqueue for timer_tick processing
#[allow(dead_code)]
fn register_workqueue(wq: &'static Workqueue) {
    let mut wqs = WORKQUEUES.lock();
    wqs.push(wq);
}

// ============================================================================
// Timer Integration
// ============================================================================

/// Timer tick handler - called from timer ISR
///
/// Checks all registered workqueues for expired delayed work and moves
/// them to the pending queue. This runs in interrupt context and uses
/// try_lock to avoid blocking.
pub fn timer_tick() {
    // Only process if scheduling is enabled
    if !SCHEDULING_ENABLED.load(Ordering::Acquire) {
        return;
    }

    let current_tick = get_ticks();

    // Check system workqueue
    SYSTEM_WQ.check_delayed_work(current_tick);

    // Check any other registered workqueues
    if let Some(wqs) = WORKQUEUES.try_lock() {
        for wq in wqs.iter() {
            (*wq).check_delayed_work(current_tick);
        }
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the workqueue subsystem
///
/// This should be called after the scheduler is enabled but before
/// any code needs to queue work. It starts worker threads for the
/// system workqueue.
///
/// # Panics
///
/// Panics if called before scheduling is enabled.
pub fn init() {
    if !SCHEDULING_ENABLED.load(Ordering::Acquire) {
        panic!("workqueue::init() called before scheduling enabled");
    }

    // For now, just mark as initialized
    // Worker thread creation will be added in Phase 2
    SYSTEM_WQ.mark_initialized();

    crate::printkln!("Workqueue subsystem initialized");
}

// ============================================================================
// Worker Thread (Phase 2)
// ============================================================================

/// Worker thread entry point
///
/// This function runs in a kernel thread context and processes work items
/// from the workqueue. It sleeps when no work is pending.
#[allow(dead_code)]
fn worker_thread_fn(wq: &'static Workqueue) -> ! {
    loop {
        // Process all pending work
        wq.process_pending();

        // Wait for more work
        if !wq.has_pending() {
            wq.wait.wait();
        }
    }
}

/// Flush all pending work on a workqueue
///
/// Waits for all currently pending work items to complete.
/// Note: Does not wait for work queued after this call.
#[allow(dead_code)]
pub fn flush_workqueue(wq: &Workqueue) {
    // For now, process synchronously since we don't have worker threads yet
    while wq.has_pending() {
        wq.process_pending();
    }
}
