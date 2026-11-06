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
//! re-queue itself. Queueing, `mod_delayed_work` and
//! `cancel_delayed_work` are process-context only (they take the item's
//! Mutex, under `inner` for delayed work).

extern crate alloc;

use crate::util::kalloc::{arc_nofail, box_nofail};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::sync::spin::Mutex;

use crate::arch::IrqSpinlock;
use crate::sync::waitqueue::WaitQueue;
use crate::task::Tid;
use crate::task::percpu::get_ticks;

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
/// will be executed by a worker thread. Its state is a plain field
/// under the item's own `Mutex`, which every user holds to touch it.
pub struct Work {
    /// Callback function to execute
    func: Option<WorkFn>,
    /// WORK_PENDING, WORK_RUNNING
    state: u32,
}

impl Work {
    /// Create a new work item with the given callback
    pub fn new<F: FnMut() + Send + 'static>(func: F) -> Self {
        Self {
            // Like INIT_WORK, a work item cannot fail to be made: its
            // callers (and DelayedWork's) have no error path
            func: Some(box_nofail(func)),
            state: 0,
        }
    }

    /// Check if work is pending execution
    pub fn is_pending(&self) -> bool {
        self.state & work_flags::WORK_PENDING != 0
    }

    /// Mark pending; false if it already was
    fn try_set_pending(&mut self) -> bool {
        let was = self.is_pending();
        self.state |= work_flags::WORK_PENDING;
        !was
    }

    fn clear_pending(&mut self) {
        self.state &= !work_flags::WORK_PENDING;
    }

    /// Start running: mark RUNNING, clear PENDING (so the function may
    /// re-queue the item) and hand out the callback
    fn begin_run(&mut self) -> Option<WorkFn> {
        self.state |= work_flags::WORK_RUNNING;
        self.clear_pending();
        self.func.take()
    }

    /// Finish a run started with `begin_run`
    fn end_run(&mut self, func: Option<WorkFn>) {
        self.func = func;
        self.state &= !work_flags::WORK_RUNNING;
    }

    /// Run the callback of `work` without holding its lock during the call
    fn run(work: &Mutex<Work>) {
        let mut func = work.lock().begin_run();
        if let Some(f) = func.as_mut() {
            f();
        }
        work.lock().end_run(func);
    }

    /// Run a promoted delayed work item without holding its lock during
    /// the call; nothing if it was re-timed or cancelled after `seq`
    /// was taken (Linux: try_to_grab_pending stole it off the worklist)
    fn run_delayed(dw: &Mutex<DelayedWork>, seq: u64) {
        let mut func = {
            let mut g = dw.lock();
            if g.seq != seq {
                return;
            }
            g.work.begin_run()
        };
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
/// fires after a specified number of timer ticks. Plain fields under the
/// item's `Mutex`; `wake_tick` and the workqueue's delayed list change
/// together (under `Workqueue.inner`, then the item).
pub struct DelayedWork {
    /// Underlying work item
    work: Work,
    /// The tick it is due at while on the delayed list; 0 when not on it
    wake_tick: u64,
    /// Bumped when a promoted copy on the pending list must not run
    /// (re-timed or cancelled before the worker reached it)
    seq: u64,
}

impl DelayedWork {
    /// Create a new delayed work item
    pub fn new<F: FnMut() + Send + 'static>(func: F) -> Self {
        Self {
            work: Work::new(func),
            wake_tick: 0,
            seq: 0,
        }
    }

    /// The timer is armed: on the delayed list (Linux timer_pending)
    pub fn is_timer_pending(&self) -> bool {
        self.wake_tick != 0
    }

    /// Check if the work is pending execution (timed or queued)
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
        if !work.lock().try_set_pending() {
            return false; // Already pending
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

    /// Queue delayed work for execution after `delay_ticks` (Linux
    /// queue_delayed_work): false if it was already pending
    pub fn queue_delayed_work(&self, work: Arc<Mutex<DelayedWork>>, delay_ticks: u64) -> bool {
        let wake_tick = get_ticks().saturating_add(delay_ticks).max(1);
        {
            let mut inner = self.inner.lock();
            let mut g = work.lock();
            if !g.work.try_set_pending() {
                return false;
            }
            g.wake_tick = wake_tick;
            drop(g);
            inner.delayed.push(work);
        }
        self.kick_delayed();
        true
    }

    /// Run delayed work after `delay_ticks` from now, whatever its state
    /// (Linux mod_delayed_work): a timed item is re-timed; one already
    /// moved to the pending list stays there for a zero delay, else is
    /// taken back and timed; an idle one is queued. True if it was
    /// pending.
    pub fn mod_delayed_work(&self, work: &Arc<Mutex<DelayedWork>>, delay_ticks: u64) -> bool {
        let wake_tick = get_ticks().saturating_add(delay_ticks).max(1);
        let was = {
            let mut inner = self.inner.lock();
            let mut g = work.lock();
            let was = g.work.is_pending();
            if was && g.wake_tick == 0 && delay_ticks == 0 {
                // Already on the pending list to run now: leave it
                // there (Linux: a zero delay queues straight to the
                // worklist), so repeated kicks never void a queued run
                return true;
            }
            if g.wake_tick == 0 {
                // Promoted (its copy must not run) or idle: onto the list
                g.seq += 1;
                g.work.try_set_pending();
                inner.delayed.push(work.clone());
            }
            g.wake_tick = wake_tick;
            was
        };
        self.kick_delayed();
        was
    }

    /// Take pending delayed work back without running it (Linux
    /// cancel_delayed_work: a run already under way is not waited for).
    /// True if it was pending.
    pub fn cancel_delayed_work(&self, work: &Arc<Mutex<DelayedWork>>) -> bool {
        let mut inner = self.inner.lock();
        let mut g = work.lock();
        if !g.work.is_pending() {
            return false;
        }
        if g.wake_tick != 0 {
            inner.delayed.retain(|d| !Arc::ptr_eq(d, work));
            g.wake_tick = 0;
        } else {
            g.seq += 1;
        }
        g.work.clear_pending();
        true
    }

    /// Delayed work was added or re-timed: the worker re-arms its sleep
    fn kick_delayed(&self) {
        self.delayed_gen.fetch_add(1, Ordering::AcqRel);
        self.wait.wake_one();
    }

    /// Move expired delayed work to the pending queue (worker thread)
    ///
    /// Returns the earliest remaining wake tick, if any.
    fn promote_delayed(&self, current_tick: u64) -> Option<u64> {
        let mut inner = self.inner.lock();
        let mut next: Option<u64> = None;
        let mut i = 0;
        while i < inner.delayed.len() {
            let mut g = inner.delayed[i].lock();
            let wake_tick = g.wake_tick;
            if wake_tick <= current_tick {
                g.wake_tick = 0;
                let seq = g.seq;
                drop(g);
                let dw = inner.delayed.remove(i);
                let mut work = Work::new(move || Work::run_delayed(&dw, seq));
                // The wrapper is fresh: mark it pending like queue_work
                work.try_set_pending();
                // The worker thread: failure cannot be reported
                inner.pending.push_back(arc_nofail(Mutex::new(work)));
                inner.has_work = true;
            } else {
                drop(g);
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
    pub fn start(&'static self, cpu: Option<u32>) -> Result<(), crate::util::error::KernelError> {
        let k = crate::task::kthread::kthread_run(
            self.name,
            worker_thread_fn,
            core::ptr::from_ref::<Workqueue>(self) as usize,
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
    if !crate::task::percpu::cpu_has_scheduler(crate::cpu::this_id()) {
        panic!("workqueue::init() called before the scheduler runs");
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
pub fn flush_workqueue(wq: &Workqueue) {
    while wq.has_pending() {
        wq.process_pending();
    }
}
