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
//! SYSTEM_WQ.queue_work(Arc::new(IrqSpinlock::new(work)));
//!
//! // Or queue for delayed execution (500 ticks = ~5 seconds)
//! let delayed = DelayedWork::new(|| { ... });
//! SYSTEM_WQ.queue_delayed_work(Arc::new(IrqSpinlock::new(delayed)), 500);
//! ```
//!
//! ## Execution and locking
//!
//! Each started workqueue has one worker kernel thread (`kworker/<name>`).
//! The worker moves expired delayed work to the pending queue itself and
//! sleeps on `wait` with a timeout until the earliest delay expires, so
//! no work function runs in IRQ context. `inner` and every item's lock
//! are `IrqSpinlock`s, and the item lock is never held while the work
//! function runs, so work may re-queue itself.
//!
//! Queueing (`queue_work`, `queue_delayed_work`, `mod_delayed_work`,
//! `cancel_delayed_work`) is allowed in any context, hardirq included
//! (Linux queue_work: pool->lock with interrupts off): the pending and
//! delayed lists are intrusive (Linux work_struct.entry on the pool's
//! worklist, the delayed_work timer), each item linking to the next
//! through its own `next` / `dnext` field, a reference the list owns
//! while it is queued, so queueing never allocates, never drops a last
//! reference and wakes the worker through its wait queue (IRQ-safe).
//! An interrupt handler defers to a thread this way what needs one (a
//! page lock to dirty a pinned page, a file's release: Linux
//! bio_dirty_work, delayed_fput). Linking takes one item's lock at a
//! time under `inner` (order: `inner` -> item); nobody waits for
//! `inner` holding an item's lock.
//!
//! `flush_work` (Linux flush_work) links a barrier item behind the
//! work's last queueing, under that workqueue's `inner` (then the
//! items' locks): right after it while it is pending (marking it
//! WORK_LINKED), first on the workqueue running it while it runs (Linux
//! find_worker_executing_work: the barrier goes first on that worker's
//! scheduled list), and sleeps on the barrier's `Completion` with no
//! lock held. A work item records the workqueue it was last queued on
//! (`Work.wq`, Linux the pwq in work->data) and the one running it
//! (`Work.run_wq`, Linux the executing worker's pool). An item a worker
//! takes off its list while it runs elsewhere is marked to run again
//! there, and the barriers linked behind it move to the front of that
//! workqueue's list (Linux process_one_work's collision:
//! move_linked_works to the colliding worker's scheduled list), so a
//! flush returns only after that run. Moving them takes the other
//! workqueue's `inner` after this one's is released: never two at once.

extern crate alloc;

use crate::sync::completion::Completion;
use crate::util::kalloc::{arc_nofail, box_nofail};
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::sync::IrqSpinlock;
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
    /// Queued again (on any workqueue) while running: the running
    /// worker runs it once more
    pub const WORK_RERUN: u32 = 1 << 2;
    /// A flush barrier is linked right after it on its pending list
    /// (Linux WORK_STRUCT_LINKED): it moves with the item
    pub const WORK_LINKED: u32 = 1 << 3;
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
/// under the item's own `IrqSpinlock`, which every user holds to touch
/// it.
pub struct Work {
    /// Callback function to execute
    func: Option<WorkFn>,
    /// WORK_PENDING, WORK_RUNNING, WORK_RERUN, WORK_LINKED
    state: u32,
    /// The next item on the pending list it is on (Linux entry)
    next: Option<Item>,
    /// The workqueue it was last queued on (Linux the pool_workqueue in
    /// work->data), for `flush_work`
    wq: Option<&'static Workqueue>,
    /// The workqueue running it, while WORK_RUNNING (Linux the pool
    /// find_worker_executing_work searches)
    run_wq: Option<&'static Workqueue>,
}

impl Work {
    /// Create a new work item with the given callback
    pub fn new<F: FnMut() + Send + 'static>(func: F) -> Self {
        Self {
            // Like INIT_WORK, a work item cannot fail to be made: its
            // callers (and DelayedWork's) have no error path
            func: Some(box_nofail(func)),
            state: 0,
            next: None,
            wq: None,
            run_wq: None,
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
    ///
    /// None, with the item marked to run again, if it is running
    /// already: work is non-reentrant across workqueues (Linux
    /// find_worker_executing_work sends it to the worker running it),
    /// and that worker runs it once more
    fn begin_run(&mut self, wq: &'static Workqueue) -> Option<WorkFn> {
        self.clear_pending();
        self.state &= !work_flags::WORK_LINKED;
        if self.is_running() {
            self.state |= work_flags::WORK_RERUN;
            return None;
        }
        self.state |= work_flags::WORK_RUNNING;
        self.run_wq = Some(wq);
        self.func.take()
    }

    fn is_running(&self) -> bool {
        self.state & work_flags::WORK_RUNNING != 0
    }

    /// Take the WORK_LINKED mark
    fn take_linked(&mut self) -> bool {
        let l = self.state & work_flags::WORK_LINKED != 0;
        self.state &= !work_flags::WORK_LINKED;
        l
    }

    /// Finish one run started with `begin_run`: true if it was queued
    /// again meanwhile and must run once more (the callback stays out);
    /// else the callback goes back (never over one already there) and
    /// the item is idle
    fn end_run(&mut self, func: &mut Option<WorkFn>) -> bool {
        if self.state & work_flags::WORK_RERUN != 0 {
            self.state &= !work_flags::WORK_RERUN;
            return true;
        }
        if self.func.is_none() {
            self.func = func.take();
        }
        self.state &= !work_flags::WORK_RUNNING;
        self.run_wq = None;
        false
    }

    /// Run the callback of `work` on `wq` without holding its lock
    /// during the call, again for each queueing during it
    fn run(work: &IrqSpinlock<Work>, wq: &'static Workqueue) {
        let mut func = work.lock().begin_run(wq);
        if func.is_none() {
            return;
        }
        loop {
            if let Some(f) = func.as_mut() {
                f();
            }
            if !work.lock().end_run(&mut func) {
                return;
            }
        }
    }

    /// Run a promoted delayed work item without holding its lock during
    /// the call; nothing if it was re-timed or cancelled after it was
    /// promoted (Linux: try_to_grab_pending stole it off the worklist)
    fn run_delayed(dw: &IrqSpinlock<DelayedWork>, wq: &'static Workqueue) {
        let mut func = {
            let mut g = dw.lock();
            g.on_pending = false;
            if g.seq != g.queued_seq {
                return;
            }
            g.work.begin_run(wq)
        };
        if func.is_none() {
            return;
        }
        loop {
            if let Some(f) = func.as_mut() {
                f();
            }
            if !dw.lock().work.end_run(&mut func) {
                return;
            }
        }
    }
}

// ============================================================================
// DelayedWork
// ============================================================================

/// A work item that executes after a delay
///
/// Similar to Linux's `delayed_work`. Combines a Work with a timer that
/// fires after a specified number of timer ticks. Plain fields under the
/// item's lock; `wake_tick` and the workqueue's delayed list change
/// together (under `Workqueue.inner`, then the item).
pub struct DelayedWork {
    /// Underlying work item
    work: Work,
    /// The tick it is due at while on the delayed list; 0 when not on it
    wake_tick: u64,
    /// Bumped when its entry on the pending list must not run (re-timed
    /// or cancelled before the worker reached it)
    seq: u64,
    /// `seq` when it was last promoted to the pending list
    queued_seq: u64,
    /// On the pending list (through `work.next`)
    on_pending: bool,
    /// The next item on the delayed list it is on
    dnext: Option<Arc<IrqSpinlock<DelayedWork>>>,
}

impl DelayedWork {
    /// Create a new delayed work item
    pub fn new<F: FnMut() + Send + 'static>(func: F) -> Self {
        Self {
            work: Work::new(func),
            wake_tick: 0,
            seq: 0,
            queued_seq: 0,
            on_pending: false,
            dnext: None,
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

/// An item on a pending list
#[derive(Clone)]
enum Item {
    Work(Arc<IrqSpinlock<Work>>),
    /// A promoted delayed item
    Delayed(Arc<IrqSpinlock<DelayedWork>>),
}

impl Item {
    fn set_next(&self, n: Option<Item>) {
        match self {
            Self::Work(w) => w.lock().next = n,
            Self::Delayed(d) => d.lock().work.next = n,
        }
    }

    fn take_next(&self) -> Option<Item> {
        match self {
            Self::Work(w) => w.lock().next.take(),
            Self::Delayed(d) => d.lock().work.next.take(),
        }
    }

    /// The item after this one, left linked
    fn peek_next(&self) -> Option<Item> {
        match self {
            Self::Work(w) => w.lock().next.clone(),
            Self::Delayed(d) => d.lock().work.next.clone(),
        }
    }

    fn is_work(&self, w: &Arc<IrqSpinlock<Work>>) -> bool {
        matches!(self, Self::Work(x) if Arc::ptr_eq(x, w))
    }

    fn run(&self, wq: &'static Workqueue) {
        match self {
            Self::Work(w) => Work::run(w, wq),
            Self::Delayed(d) => Work::run_delayed(d, wq),
        }
    }

    /// Take the WORK_LINKED mark of a work item
    fn take_linked(&self) -> bool {
        match self {
            Self::Work(w) => w.lock().take_linked(),
            Self::Delayed(_) => false,
        }
    }
}

/// The pending list: items linked through their `next` (FIFO)
struct PendList {
    head: Option<Item>,
    tail: Option<Item>,
}

impl PendList {
    const fn new() -> Self {
        Self {
            head: None,
            tail: None,
        }
    }

    /// Append `it` (not on any pending list): no allocation
    fn push(&mut self, it: Item) {
        it.set_next(None);
        match &self.tail {
            Some(t) => t.set_next(Some(it.clone())),
            None => self.head = Some(it.clone()),
        }
        self.tail = Some(it);
    }

    /// Put `it` (not on any pending list) first: it runs next (Linux
    /// insert_wq_barrier on the worker's scheduled list head)
    fn push_front(&mut self, it: Item) {
        it.set_next(self.head.take());
        if self.tail.is_none() {
            self.tail = Some(it.clone());
        }
        self.head = Some(it);
    }

    /// Link `it` right after work `w`; false if `w` is not on the list
    /// (Linux insert_wq_barrier after a pending work's entry)
    fn insert_after(&mut self, w: &Arc<IrqSpinlock<Work>>, it: Item) -> bool {
        let mut cur = self.head.clone();
        while let Some(c) = cur {
            if c.is_work(w) {
                let n = c.take_next();
                if n.is_none() {
                    self.tail = Some(it.clone());
                }
                it.set_next(n);
                c.set_next(Some(it));
                return true;
            }
            cur = c.peek_next();
        }
        false
    }

    /// Put the items of `other` first, in their order (Linux
    /// move_linked_works to a worker's scheduled list)
    fn prepend(&mut self, mut other: PendList) {
        let Some(t) = other.tail.take() else {
            return;
        };
        t.set_next(self.head.take());
        if self.tail.is_none() {
            self.tail = Some(t);
        }
        self.head = other.head.take();
    }

    fn pop(&mut self) -> Option<Item> {
        let h = self.head.take()?;
        self.head = h.take_next();
        if self.head.is_none() {
            self.tail = None;
        }
        Some(h)
    }
}

/// Inner state protected by IrqSpinlock
struct WorkqueueInner {
    /// Pending items, in queueing order
    pending: PendList,
    /// Timed delayed items, linked through `dnext` (unsorted: scanned)
    delayed: Option<Arc<IrqSpinlock<DelayedWork>>>,
    /// Worker thread TID (0 = not started)
    worker_tid: Tid,
    /// Flag indicating work is available
    has_work: bool,
}

impl WorkqueueInner {
    /// Put `d` on the delayed list (not on it): no allocation
    fn delay(&mut self, d: Arc<IrqSpinlock<DelayedWork>>) {
        let next = self.delayed.take();
        d.lock().dnext = next;
        self.delayed = Some(d);
    }

    /// Take the whole delayed list apart, giving `f` each item; those
    /// for which it returns true go back on it
    fn sweep(&mut self, mut f: impl FnMut(&Arc<IrqSpinlock<DelayedWork>>) -> bool) {
        let mut cur = self.delayed.take();
        while let Some(d) = cur {
            cur = d.lock().dnext.take();
            if f(&d) {
                self.delay(d);
            }
        }
    }

    /// Queue the promoted delayed item `d` to run (its entry, if one is
    /// still on the list, now runs with the current `seq`)
    fn promote(&mut self, d: &Arc<IrqSpinlock<DelayedWork>>) {
        let push = {
            let mut g = d.lock();
            g.queued_seq = g.seq;
            !core::mem::replace(&mut g.on_pending, true)
        };
        if push {
            self.pending.push(Item::Delayed(d.clone()));
        }
        self.has_work = true;
    }
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
                pending: PendList::new(),
                delayed: None,
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
    pub fn queue_work(&'static self, work: Arc<IrqSpinlock<Work>>) -> bool {
        // Try to mark as pending
        {
            let mut w = work.lock();
            if !w.try_set_pending() {
                return false; // Already pending
            }
            w.wq = Some(self);
        }

        // Add to pending queue
        {
            let mut inner = self.inner.lock();
            inner.pending.push(Item::Work(work));
            inner.has_work = true;
        }

        // Wake worker thread
        self.wait.wake_one();

        true
    }

    /// Queue delayed work for execution after `delay_ticks` (Linux
    /// queue_delayed_work): false if it was already pending
    pub fn queue_delayed_work(
        &self,
        work: Arc<IrqSpinlock<DelayedWork>>,
        delay_ticks: u64,
    ) -> bool {
        let wake_tick = get_ticks().saturating_add(delay_ticks).max(1);
        {
            let mut inner = self.inner.lock();
            let mut g = work.lock();
            if !g.work.try_set_pending() {
                return false;
            }
            g.wake_tick = wake_tick;
            drop(g);
            inner.delay(work);
        }
        self.kick_delayed();
        true
    }

    /// Run delayed work after `delay_ticks` from now, whatever its state
    /// (Linux mod_delayed_work): a timed item is re-timed; one already
    /// moved to the pending list stays there for a zero delay, else is
    /// taken back and timed; an idle one is queued. True if it was
    /// pending.
    pub fn mod_delayed_work(&self, work: &Arc<IrqSpinlock<DelayedWork>>, delay_ticks: u64) -> bool {
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
            let onto = g.wake_tick == 0;
            if onto {
                // Promoted (its entry must not run) or idle: onto the list
                g.seq += 1;
                g.work.try_set_pending();
            }
            g.wake_tick = wake_tick;
            drop(g);
            if onto {
                inner.delay(work.clone());
            }
            was
        };
        self.kick_delayed();
        was
    }

    /// Take pending delayed work back without running it (Linux
    /// cancel_delayed_work: a run already under way is not waited for).
    /// True if it was pending.
    pub fn cancel_delayed_work(&self, work: &Arc<IrqSpinlock<DelayedWork>>) -> bool {
        let mut inner = self.inner.lock();
        let mut g = work.lock();
        if !g.work.is_pending() {
            return false;
        }
        let timed = g.wake_tick != 0;
        if timed {
            g.wake_tick = 0;
        } else {
            g.seq += 1;
        }
        g.work.clear_pending();
        drop(g);
        if timed {
            inner.sweep(|d| !Arc::ptr_eq(d, work));
        }
        true
    }

    /// Delayed work was added or re-timed: the worker re-arms its sleep
    fn kick_delayed(&self) {
        self.delayed_gen.fetch_add(1, Ordering::AcqRel);
        self.wait.wake_one();
    }

    /// Move expired delayed work to the pending queue (worker thread;
    /// Linux delayed_work_timer_fn queues the item itself)
    ///
    /// Returns the earliest remaining wake tick, if any.
    fn promote_delayed(&self, current_tick: u64) -> Option<u64> {
        let mut inner = self.inner.lock();
        let mut next: Option<u64> = None;
        let mut due = None::<Arc<IrqSpinlock<DelayedWork>>>;
        inner.sweep(|d| {
            let mut g = d.lock();
            if g.wake_tick <= current_tick {
                g.wake_tick = 0;
                // Chained through `dnext`, which the sweep just cleared
                g.dnext = due.take();
                drop(g);
                due = Some(d.clone());
                false
            } else {
                let t = g.wake_tick;
                next = Some(next.map_or(t, |n: u64| n.min(t)));
                true
            }
        });
        while let Some(d) = due {
            due = d.lock().dnext.take();
            inner.promote(&d);
        }
        next
    }

    /// Link `barrier` behind the queueing of `work` on this workqueue
    /// (Linux start_flush_work's insert_wq_barrier): right after it
    /// while it is listed here, first while it is about to run or runs
    /// here. False if it is neither pending here nor running here.
    fn insert_barrier(
        &self,
        work: &Arc<IrqSpinlock<Work>>,
        barrier: &Arc<IrqSpinlock<Work>>,
    ) -> bool {
        let mine = |q: Option<&'static Workqueue>| q.is_some_and(|q| core::ptr::eq(q, self));
        let mut inner = self.inner.lock();
        let (pending, linked) = {
            let w = work.lock();
            if w.is_pending() && mine(w.wq) {
                (true, w.state & work_flags::WORK_LINKED != 0)
            } else if !w.is_pending() && w.is_running() && mine(w.run_wq) {
                (false, false)
            } else {
                return false;
            }
        };
        barrier.lock().try_set_pending();
        let b = Item::Work(barrier.clone());
        if pending && inner.pending.insert_after(work, b.clone()) {
            // Linux insert_wq_barrier: the barrier inherits the link
            if linked {
                barrier.lock().state |= work_flags::WORK_LINKED;
            }
            work.lock().state |= work_flags::WORK_LINKED;
        } else {
            // Running, or pending but not listed: the worker took it and
            // is about to run it, so the barrier goes first
            inner.pending.push_front(b);
        }
        inner.has_work = true;
        true
    }

    /// Take the first item to run, if any. One that runs on another
    /// workqueue (queued here while it ran there) is marked to run
    /// again there, and the barriers linked behind it go first on that
    /// workqueue (Linux process_one_work's collision with
    /// find_worker_executing_work: move_linked_works to that worker's
    /// scheduled list); it is not run here.
    fn take(&'static self) -> Option<Item> {
        loop {
            let (it, to, chain) = {
                let mut inner = self.inner.lock();
                let it = inner.pending.pop();
                if inner.pending.head.is_none() {
                    inner.has_work = false;
                }
                let it = it?;
                let Some(to) = self.collide(&it) else {
                    return Some(it);
                };
                let chain = take_linked(&mut inner, &it);
                (it, to, chain)
            };
            {
                let mut inner = to.inner.lock();
                inner.pending.prepend(chain);
                inner.has_work = true;
            }
            to.wait.wake_one();
            // This list's reference, dropped with no lock held
            drop(it);
        }
    }

    /// Under `inner`: if work item `it` runs on another workqueue, mark
    /// it to run again there and return that workqueue
    fn collide(&'static self, it: &Item) -> Option<&'static Workqueue> {
        let Item::Work(w) = it else {
            return None;
        };
        let mut g = w.lock();
        let to = g
            .run_wq
            .filter(|q| g.is_running() && !core::ptr::eq(*q, self))?;
        g.clear_pending();
        g.state |= work_flags::WORK_RERUN;
        Some(to)
    }

    /// Run the first pending item, if any (a caller without a worker)
    fn process_one(&'static self) -> bool {
        match self.take() {
            Some(it) => {
                it.run(self);
                true
            }
            None => false,
        }
    }

    /// Process pending work items (called by worker thread)
    ///
    /// Returns the number of work items processed.
    fn process_pending(&'static self) -> usize {
        let mut processed = 0;
        while self.process_one() {
            processed += 1;
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
    /// A WQ_HIGHPRI queue's worker runs at nice -20 (Linux the highpri
    /// worker pools)
    pub fn start(&'static self, cpu: Option<u32>) -> Result<(), crate::util::error::KernelError> {
        let prio = if self.flags & wq_flags::WQ_HIGHPRI != 0 {
            crate::task::PRIORITY_NICE_MIN
        } else {
            crate::task::PRIORITY_NORMAL
        };
        let k = crate::task::kthread::kthread_run_prio(
            self.name,
            worker_thread_fn,
            core::ptr::from_ref::<Workqueue>(self) as usize,
            cpu,
            prio,
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

/// Under a workqueue's `inner`: the barriers linked behind `it` (just
/// taken off its list), off the list in their order
fn take_linked(inner: &mut WorkqueueInner, it: &Item) -> PendList {
    let mut chain = PendList::new();
    let mut linked = it.take_linked();
    while linked {
        let Some(b) = inner.pending.pop() else {
            break;
        };
        linked = b.take_linked();
        chain.push(b);
    }
    if inner.pending.head.is_none() {
        inner.has_work = false;
    }
    chain
}

/// Start flushing `work` (Linux start_flush_work): a barrier linked
/// behind its last queueing, or first on the workqueue running it;
/// that workqueue and the barrier's completion, or None if it is idle
fn start_flush(work: &Arc<IrqSpinlock<Work>>) -> Option<(&'static Workqueue, Arc<Completion>)> {
    // Like Linux's on-stack barrier, it cannot fail to be made
    let done = arc_nofail(Completion::new());
    let d = done.clone();
    let barrier = arc_nofail(IrqSpinlock::new(Work::new(move || d.complete_all())));
    loop {
        // Where it is (Linux get_work_pool), checked again under that
        // workqueue's lock: it may have moved meanwhile
        let wq = {
            let w = work.lock();
            if w.is_pending() {
                w.wq
            } else if w.is_running() {
                w.run_wq
            } else {
                None
            }
        }?;
        if wq.insert_barrier(work, &barrier) {
            wq.wait.wake_one();
            return Some((wq, done));
        }
    }
}

/// Wait for the last queueing of `work` to finish running, wherever it
/// runs (Linux flush_work): true if it had to wait, false at once if
/// it was idle. Sleeps; no lock held. Without a worker the caller runs
/// that workqueue's items up to the barrier.
pub fn flush_work(work: &Arc<IrqSpinlock<Work>>) -> bool {
    crate::sync::might_sleep();
    let Some((wq, done)) = start_flush(work) else {
        return false;
    };
    if wq.is_initialized() {
        done.wait();
    } else {
        while !done.is_done() && wq.process_one() {}
    }
    true
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
pub fn flush_workqueue(wq: &'static Workqueue) {
    while wq.has_pending() {
        wq.process_pending();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    use crate::sync::spin::Mutex;

    static LOG: Mutex<Vec<u32>> = Mutex::new(Vec::new());

    fn work(n: u32) -> Arc<IrqSpinlock<Work>> {
        Arc::new(IrqSpinlock::new(Work::new(move || LOG.lock().push(n))))
    }

    fn delayed(n: u32) -> Arc<IrqSpinlock<DelayedWork>> {
        Arc::new(IrqSpinlock::new(DelayedWork::new(move || {
            LOG.lock().push(n)
        })))
    }

    fn take_log() -> Vec<u32> {
        core::mem::take(&mut *LOG.lock())
    }

    /// Queued on another workqueue while it runs: the item is not run
    /// twice at once there (Linux: non-reentrant), the running worker
    /// runs it again, and its callback survives for later runs
    #[test]
    fn queued_elsewhere_while_running() {
        use core::sync::atomic::AtomicU32;
        static RUNS: AtomicU32 = AtomicU32::new(0);
        static OTHER: Workqueue = Workqueue::new("other", 0);
        static ME: spin::Once<Arc<IrqSpinlock<Work>>> = spin::Once::new();
        let w = ME.call_once(|| {
            Arc::new(IrqSpinlock::new(Work::new(|| {
                if RUNS.fetch_add(1, Ordering::Relaxed) == 0 {
                    // Queued again, elsewhere, while running: that
                    // queue's worker finds it running and hands it back
                    // (runs nothing)
                    let me = ME.get().unwrap().clone();
                    assert!(OTHER.queue_work(me));
                    assert_eq!(OTHER.process_pending(), 0);
                    assert!(!OTHER.has_pending());
                }
            })))
        });
        static WQ: Workqueue = Workqueue::new("test2", 0);
        let wq = &WQ;
        assert!(wq.queue_work(w.clone()));
        wq.process_pending();
        assert_eq!(RUNS.load(Ordering::Relaxed), 2);
        // Idle, callback in place: it runs again when queued
        assert!(wq.queue_work(w.clone()));
        wq.process_pending();
        assert_eq!(RUNS.load(Ordering::Relaxed), 3);
    }

    /// flush_work waits for the last queueing to run and no further:
    /// the barrier goes right after the pending item; an idle item or
    /// one queued elsewhere returns at once
    #[test]
    fn flush_work_barrier() {
        use core::sync::atomic::AtomicU32;
        static A: AtomicU32 = AtomicU32::new(0);
        static B: AtomicU32 = AtomicU32::new(0);
        static WQ: Workqueue = Workqueue::new("flush", 0);
        let wq = &WQ;
        let a = Arc::new(IrqSpinlock::new(Work::new(|| {
            A.fetch_add(1, Ordering::Relaxed);
        })));
        let b = Arc::new(IrqSpinlock::new(Work::new(|| {
            B.fetch_add(1, Ordering::Relaxed);
        })));
        assert!(!flush_work(&a));
        assert!(wq.queue_work(a.clone()));
        assert!(wq.queue_work(b.clone()));
        assert!(flush_work(&a));
        assert_eq!(A.load(Ordering::Relaxed), 1);
        assert_eq!(B.load(Ordering::Relaxed), 0);
        assert!(b.lock().is_pending());
        // b was queued here: flushing it runs it
        assert!(flush_work(&b));
        assert_eq!(B.load(Ordering::Relaxed), 1);
        assert!(!wq.has_pending());
        assert!(!flush_work(&a));
        // Last queued on another workqueue: flushed there
        static OTHER: Workqueue = Workqueue::new("flush2", 0);
        assert!(OTHER.queue_work(a.clone()));
        assert!(flush_work(&a));
        assert_eq!(A.load(Ordering::Relaxed), 2);
        assert!(!OTHER.has_pending());
        assert_eq!(Arc::strong_count(&a), 1);
    }

    /// Queued on another workqueue while it runs, then flushed: the
    /// flush returns only after the run the running workqueue makes for
    /// that queueing, whether the barrier was linked behind it before
    /// the other workqueue took it (it moves along, Linux
    /// move_linked_works) or after (it goes on the running one, Linux
    /// find_worker_executing_work)
    #[test]
    fn flush_rerun_elsewhere() {
        use core::sync::atomic::AtomicU32;
        static RUNS: AtomicU32 = AtomicU32::new(0);
        static RUNQ: Workqueue = Workqueue::new("run", 0);
        static OTHER: Workqueue = Workqueue::new("other3", 0);
        static ME: spin::Once<Arc<IrqSpinlock<Work>>> = spin::Once::new();
        static DONE: Mutex<Vec<Arc<Completion>>> = Mutex::new(Vec::new());
        let w = ME.call_once(|| {
            Arc::new(IrqSpinlock::new(Work::new(|| {
                if RUNS.fetch_add(1, Ordering::Relaxed) != 0 {
                    return;
                }
                let me = ME.get().unwrap();
                // Linked behind the queueing on OTHER, which then finds
                // the item running here
                assert!(OTHER.queue_work(me.clone()));
                let (q, linked) = start_flush(me).unwrap();
                assert!(core::ptr::eq(q, &OTHER));
                OTHER.process_pending();
                assert!(!linked.is_done());
                assert!(!OTHER.has_pending());
                // Flushed after: the barrier goes on this workqueue
                let (q, after) = start_flush(me).unwrap();
                assert!(core::ptr::eq(q, &RUNQ));
                OTHER.process_pending();
                assert!(!after.is_done());
                DONE.lock().extend([linked, after]);
            })))
        });
        assert!(RUNQ.queue_work(w.clone()));
        RUNQ.process_one();
        // The run again for OTHER's queueing came first, then both
        // barriers
        assert_eq!(RUNS.load(Ordering::Relaxed), 2);
        let done = core::mem::take(&mut *DONE.lock());
        assert_eq!(done.len(), 2);
        assert!(done.iter().all(|d| !d.is_done()));
        RUNQ.process_pending();
        assert!(done.iter().all(|d| d.is_done()));
        assert!(!flush_work(w));
    }

    /// The intrusive lists in one test (they share LOG): FIFO order, no
    /// double queueing, an item re-queued after its run, and delayed
    /// items promoted, re-timed and cancelled
    #[test]
    fn intrusive_lists() {
        static WQ: Workqueue = Workqueue::new("test", 0);
        let wq = &WQ;
        let (a, b, c) = (work(1), work(2), work(3));
        assert!(wq.queue_work(a.clone()));
        assert!(wq.queue_work(b.clone()));
        assert!(!wq.queue_work(a.clone()));
        assert!(wq.queue_work(c.clone()));
        assert_eq!(wq.process_pending(), 3);
        assert_eq!(take_log(), [1, 2, 3]);
        assert!(!wq.has_pending());
        // Queued again after running; the lists hold no stale links
        assert!(wq.queue_work(b.clone()));
        assert_eq!(wq.process_pending(), 1);
        assert_eq!(take_log(), [2]);
        assert_eq!(Arc::strong_count(&b), 1);

        let now = get_ticks();
        let (d, e, f) = (delayed(10), delayed(11), delayed(12));
        assert!(wq.queue_delayed_work(d.clone(), 5));
        assert!(wq.queue_delayed_work(e.clone(), 50));
        assert!(wq.queue_delayed_work(f.clone(), 5));
        assert!(!wq.queue_delayed_work(d.clone(), 5));
        // f cancelled while timed: off the delayed list
        assert!(wq.cancel_delayed_work(&f));
        assert_eq!(wq.promote_delayed(now + 10), Some(now + 50));
        // d promoted, then cancelled before it ran: its entry is void
        assert!(wq.cancel_delayed_work(&d));
        assert_eq!(wq.process_pending(), 1);
        assert!(take_log().is_empty());
        // e re-timed to now: promoted and run once
        assert!(wq.mod_delayed_work(&e, 0));
        assert_eq!(wq.promote_delayed(now + 10), None);
        wq.process_pending();
        assert_eq!(take_log(), [11]);
        for x in [&d, &e, &f] {
            assert_eq!(Arc::strong_count(x), 1);
        }
    }
}
