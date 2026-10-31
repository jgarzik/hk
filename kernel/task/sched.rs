//! The scheduler's part of a task (Linux sched_entity plus the
//! scheduling fields of task_struct) and the run queue lists built from
//! it, one set per scheduling class (Linux sched_class): stop (the CPU
//! stoppers), rt (SCHED_FIFO/RR: 100 levels with an O(1)
//! highest-priority lookup), fair (SCHED_NORMAL/BATCH/IDLE) and idle
//! (the idle task, never queued). Nothing here allocates, so run queues
//! change in interrupt context.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{
    AtomicBool, AtomicI64, AtomicPtr, AtomicU8, AtomicU32, AtomicU64, Ordering,
};

use super::Priority;
use crate::list::{Adapter, Link, List};

/// Scheduling class, highest first (Linux stop/rt/fair/idle_sched_class)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Class {
    /// The CPU stoppers (`migration/N`)
    Stop = 0,
    /// SCHED_FIFO, SCHED_RR
    Rt = 1,
    /// SCHED_NORMAL, SCHED_BATCH, SCHED_IDLE
    Fair = 2,
    /// The idle task
    Idle = 3,
}

impl Class {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Class::Stop,
            1 => Class::Rt,
            2 => Class::Fair,
            _ => Class::Idle,
        }
    }
}

/// Linux NICE_TO_PRIO(0): static_prio of nice 0
pub const DEFAULT_PRIO: u8 = 120;

/// SCHED_RR's time slice in ticks (Linux RR_TIMESLICE, 100 ms)
pub const RR_TICKS: u32 = 10;

/// The arch's switch frame (callee-saved registers)
pub type TaskContext = <crate::arch::CurrentArch as crate::arch::ContextOps>::TaskContext;

/// Number of priority levels (0-255)
pub const NUM_PRIORITIES: usize = 256;

/// A task's scheduling state (Linux p->__state, p->on_rq, run_list)
///
/// `state` is written by the task itself (set_current_state) and by its
/// wakers (try_to_wake_up, under the task's pi_lock); `on_rq` and `link`
/// change only under the rq lock of the task's CPU. The task is on its
/// run queue (`on_rq`) while it is queued or running; a sleeper leaves
/// it in `schedule()`.
pub struct SchedEntity {
    /// `SleepState` as u8
    state: AtomicU8,
    /// Queued or running on its CPU's run queue
    on_rq: AtomicBool,
    /// It went to sleep counted in its run queue's `nr_uninterruptible`
    /// (Linux p->sched_contributes_to_load), under that rq lock; its
    /// wakeup uncounts it
    pub contrib_load: AtomicBool,
    /// Its CPU runs it or is still switching away from it (Linux
    /// p->on_cpu): set when it is made current, cleared by the task
    /// switched to once the switch is complete (finish_task_switch)
    on_cpu: AtomicBool,
    /// Scheduling class (`Class`)
    class: AtomicU8,
    /// SCHED_* policy (Linux p->policy)
    policy: AtomicU8,
    /// 100 + 20 + nice (Linux p->static_prio)
    static_prio: AtomicU8,
    /// 1..99 for SCHED_FIFO/RR, else 0 (Linux p->rt_priority)
    rt_priority: AtomicU8,
    /// A fork child starts with SCHED_NORMAL and nice >= 0 (Linux
    /// p->sched_reset_on_fork)
    reset_on_fork: AtomicBool,
    /// SCHED_RR: ticks left of its slice (Linux p->rt.time_slice)
    rr_left: AtomicU32,
    /// Fair: virtual runtime, ns (Linux se->vruntime; `fair`)
    pub vruntime: AtomicU64,
    /// Fair: virtual deadline (Linux se->deadline)
    pub deadline: AtomicU64,
    /// Fair: lag saved when it left its run queue (Linux se->vlag)
    pub vlag: AtomicI64,
    /// Fair: when it last started running or was charged (monotonic ns;
    /// 0 while not running)
    pub exec_start: AtomicU64,
    /// Its slice ran out: requeued at the tail, not the head
    requeue_tail: AtomicBool,
    /// Its place in a priority list (under the rq lock)
    pub link: Link,
    /// Saved kernel context while switched out (under the rq lock)
    ctx: UnsafeCell<TaskContext>,
    /// The kernel stack is freed with the task (the boot stack of the
    /// first user task is not)
    owns_stack: AtomicBool,
    /// Next task on a [`WakeQ`](crate::task::percpu::WakeQ); null when
    /// on none (Linux wake_q_node)
    pub wake_q: AtomicPtr<()>,
}

// SAFETY: `ctx` is only touched under the rq lock of the task's CPU
unsafe impl Sync for SchedEntity {}
unsafe impl Send for SchedEntity {}

impl SchedEntity {
    /// A SCHED_NORMAL nice 0 entity in sleep state `state`
    pub const fn new(state: u8) -> Self {
        Self {
            state: AtomicU8::new(state),
            on_rq: AtomicBool::new(false),
            on_cpu: AtomicBool::new(false),
            contrib_load: AtomicBool::new(false),
            class: AtomicU8::new(Class::Fair as u8),
            policy: AtomicU8::new(0),
            static_prio: AtomicU8::new(DEFAULT_PRIO),
            rt_priority: AtomicU8::new(0),
            reset_on_fork: AtomicBool::new(false),
            rr_left: AtomicU32::new(RR_TICKS),
            vruntime: AtomicU64::new(0),
            deadline: AtomicU64::new(0),
            vlag: AtomicI64::new(0),
            exec_start: AtomicU64::new(0),
            requeue_tail: AtomicBool::new(false),
            link: Link::new(),
            // SAFETY: a switch frame is plain integers; zero is valid
            ctx: UnsafeCell::new(unsafe { MaybeUninit::zeroed().assume_init() }),
            owns_stack: AtomicBool::new(true),
            wake_q: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// The sleep state (`SleepState` as u8)
    #[inline]
    pub fn state(&self) -> u8 {
        self.state.load(Ordering::SeqCst)
    }

    /// Set the sleep state; a full barrier orders it before the caller's
    /// condition check (Linux smp_store_mb in set_current_state). The
    /// fence is needed: a SeqCst swap alone (arm64 ldaxr/stlxr) lets a
    /// later relaxed load, such as the TIF_SIGPENDING or flag a waker set
    /// before its try_to_wake_up, be satisfied before the store is
    /// visible, and both sides then miss each other (a lost wakeup)
    #[inline]
    pub fn set_state(&self, s: u8) {
        self.state.store(s, Ordering::SeqCst);
        core::sync::atomic::fence(Ordering::SeqCst);
    }

    #[inline]
    pub fn on_rq(&self) -> bool {
        self.on_rq.load(Ordering::SeqCst)
    }

    /// Under the rq lock
    #[inline]
    pub fn set_on_rq(&self, v: bool) {
        self.on_rq.store(v, Ordering::SeqCst);
    }

    /// Running, or not yet switched away from (Acquire: what the task
    /// did on its CPU is visible once this reads false)
    #[inline]
    pub fn on_cpu(&self) -> bool {
        self.on_cpu.load(Ordering::Acquire)
    }

    /// Under the rq lock of its CPU (Release: see `on_cpu`)
    #[inline]
    pub fn set_on_cpu(&self, v: bool) {
        self.on_cpu.store(v, Ordering::Release);
    }

    pub fn class(&self) -> Class {
        Class::from_u8(self.class.load(Ordering::Relaxed))
    }

    pub fn policy(&self) -> i32 {
        self.policy.load(Ordering::Relaxed) as i32
    }

    pub fn static_prio(&self) -> u8 {
        self.static_prio.load(Ordering::Relaxed)
    }

    /// Linux task_nice
    pub fn nice(&self) -> i32 {
        self.static_prio() as i32 - DEFAULT_PRIO as i32
    }

    pub fn rt_priority(&self) -> u8 {
        self.rt_priority.load(Ordering::Relaxed)
    }

    pub fn reset_on_fork(&self) -> bool {
        self.reset_on_fork.load(Ordering::Relaxed)
    }

    /// Set the scheduling class and parameters (the task's pi_lock and
    /// rq lock held, and off the run queue lists, or not yet started)
    pub fn set_params(&self, class: Class, policy: i32, static_prio: u8, rt_priority: u8) {
        self.class.store(class as u8, Ordering::Relaxed);
        self.policy.store(policy as u8, Ordering::Relaxed);
        self.static_prio.store(static_prio, Ordering::Relaxed);
        self.rt_priority.store(rt_priority, Ordering::Relaxed);
        self.rr_left.store(RR_TICKS, Ordering::Relaxed);
    }

    pub fn set_reset_on_fork(&self, v: bool) {
        self.reset_on_fork.store(v, Ordering::Relaxed);
    }

    /// SCHED_RR tick (its own CPU's tick): true once its slice is used
    /// up, which starts a new one and requeues it at the tail (Linux
    /// task_tick_rt)
    pub fn rr_tick(&self) -> bool {
        if self.rr_left.fetch_sub(1, Ordering::Relaxed) > 1 {
            return false;
        }
        self.rr_left.store(RR_TICKS, Ordering::Relaxed);
        self.requeue_tail.store(true, Ordering::Relaxed);
        true
    }

    /// Whether a preempted task goes to the tail (its slice ran out),
    /// clearing that
    pub fn take_requeue_tail(&self) -> bool {
        self.requeue_tail.swap(false, Ordering::Relaxed)
    }

    /// The switch frame
    ///
    /// # Safety
    /// The rq lock of the task's CPU is held (or the task is not yet
    /// on a run queue), and no other reference to the frame is live.
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn ctx(&self) -> &mut TaskContext {
        // SAFETY: see above
        unsafe { &mut *self.ctx.get() }
    }

    pub fn owns_stack(&self) -> bool {
        self.owns_stack.load(Ordering::Relaxed)
    }

    /// The task runs on a stack it does not own (before it is shared)
    pub fn disown_stack(&self) {
        self.owns_stack.store(false, Ordering::Relaxed);
    }
}

/// The runnable tasks of a CPU but the running one and the idle task,
/// one FIFO list per priority (Linux rt_prio_array). The run queue owns
/// a reference to each of its tasks (from their first wakeup until
/// their final switch away), so the lists hold no counts of their own.
pub struct PrioQueue<A: Adapter> {
    lists: [List<A>; NUM_PRIORITIES],
    /// Bit N set: priority N has tasks
    bitmap: [u64; 4],
}

impl<A: Adapter> PrioQueue<A> {
    pub const fn new() -> Self {
        Self {
            lists: [const { List::new() }; NUM_PRIORITIES],
            bitmap: [0; 4],
        }
    }

    /// Append `item` at priority `prio`
    ///
    /// # Safety
    /// `item` is live, on no priority list, and stays live until
    /// removed.
    pub unsafe fn push(&mut self, item: *const A::Item, prio: Priority) {
        let p = prio as usize;
        // SAFETY: see above
        unsafe { self.lists[p].push_back(item) };
        self.bitmap[p / 64] |= 1u64 << (p % 64);
    }

    /// Put `item` first at priority `prio`
    ///
    /// # Safety
    /// As for `push`.
    pub unsafe fn push_front(&mut self, item: *const A::Item, prio: Priority) {
        let p = prio as usize;
        // SAFETY: see above
        unsafe { self.lists[p].push_front(item) };
        self.bitmap[p / 64] |= 1u64 << (p % 64);
    }

    /// Remove `item`, queued at `prio`
    ///
    /// # Safety
    /// `item` is on the list of `prio`.
    pub unsafe fn remove(&mut self, item: *const A::Item, prio: Priority) {
        let p = prio as usize;
        // SAFETY: see above
        unsafe { self.lists[p].remove(item) };
        if self.lists[p].is_empty() {
            self.bitmap[p / 64] &= !(1u64 << (p % 64));
        }
    }

    /// Remove and return the first task of the highest priority
    pub fn pop(&mut self) -> Option<*const A::Item> {
        for w in (0..4).rev() {
            if self.bitmap[w] == 0 {
                continue;
            }
            let p = w * 64 + 63 - self.bitmap[w].leading_zeros() as usize;
            let item = self.lists[p].pop_front();
            if self.lists[p].is_empty() {
                self.bitmap[w] &= !(1u64 << (p % 64));
            }
            return item;
        }
        None
    }

    pub fn is_empty(&self) -> bool {
        self.bitmap == [0; 4]
    }
}

impl<A: Adapter> Default for PrioQueue<A> {
    fn default() -> Self {
        Self::new()
    }
}

/// A run queue's lists, one set per class (Linux rq->{stop, rt, cfs}):
/// the stoppers, the rt priority levels (by rt_priority, 1..99), and the
/// fair tasks in arrival order
pub struct ClassQueues<A: Adapter> {
    stop: List<A>,
    rt: PrioQueue<A>,
    fair: List<A>,
}

impl<A: Adapter> ClassQueues<A> {
    pub const fn new() -> Self {
        Self {
            stop: List::new(),
            rt: PrioQueue::new(),
            fair: List::new(),
        }
    }

    /// Queue `item` of `class` (rt: at `rt_prio`); at the front of its
    /// list if `head` (a preempted rt task keeps its place)
    ///
    /// # Safety
    /// `item` is live, on no list, and stays live until removed.
    pub unsafe fn push(&mut self, item: *const A::Item, class: Class, rt_prio: u8, head: bool) {
        // SAFETY: see above
        unsafe {
            match class {
                Class::Stop => self.stop.push_back(item),
                Class::Rt if head => self.rt.push_front(item, rt_prio),
                Class::Rt => self.rt.push(item, rt_prio),
                Class::Fair => self.fair.push_back(item),
                Class::Idle => unreachable!("the idle task is never queued"),
            }
        }
    }

    /// Remove `item`, queued as `class` (rt: at `rt_prio`)
    ///
    /// # Safety
    /// `item` is on that list.
    pub unsafe fn remove(&mut self, item: *const A::Item, class: Class, rt_prio: u8) {
        // SAFETY: see above
        unsafe {
            match class {
                Class::Stop => self.stop.remove(item),
                Class::Rt => self.rt.remove(item, rt_prio),
                Class::Fair => self.fair.remove(item),
                Class::Idle => {}
            }
        }
    }

    /// Remove and return the next stop or rt task (Linux pick_next_task
    /// down to the rt class); the fair one is EEVDF's to choose
    pub fn pop_stop_rt(&mut self) -> Option<*const A::Item> {
        self.stop.pop_front().or_else(|| self.rt.pop())
    }

    /// The queued fair tasks
    pub fn fair_iter(&self) -> crate::list::Iter<'_, A> {
        self.fair.iter()
    }

    /// Fair tasks are queued
    pub fn has_fair(&self) -> bool {
        !self.fair.is_empty()
    }

    /// Remove up to `out.len()` queued tasks `f` accepts, rt ones first
    /// (highest priority first: they wait behind a higher one, Linux
    /// pull_rt_task), then fair ones oldest first (Linux load_balance);
    /// the number taken. Stoppers stay.
    pub fn take(
        &mut self,
        out: &mut [*const A::Item],
        mut f: impl FnMut(*const A::Item) -> bool,
    ) -> usize {
        let mut n = 0;
        for p in (0..NUM_PRIORITIES).rev() {
            let mut it = self.rt.lists[p].front();
            while let Some(item) = it {
                if n == out.len() {
                    return n;
                }
                // SAFETY: `item` is on this list
                it = unsafe { self.rt.lists[p].next(item) };
                if f(item) {
                    // SAFETY: as above
                    unsafe { self.rt.remove(item, p as Priority) };
                    out[n] = item;
                    n += 1;
                }
            }
        }
        n + self.take_fair(&mut out[n..], f)
    }

    /// Remove up to `out.len()` fair tasks `f` accepts, oldest first;
    /// the number taken
    fn take_fair(
        &mut self,
        out: &mut [*const A::Item],
        mut f: impl FnMut(*const A::Item) -> bool,
    ) -> usize {
        let mut n = 0;
        let mut it = self.fair.front();
        while let Some(item) = it {
            if n == out.len() {
                break;
            }
            // SAFETY: `item` is on the fair list
            it = unsafe { self.fair.next(item) };
            if f(item) {
                // SAFETY: as above
                unsafe { self.fair.remove(item) };
                out[n] = item;
                n += 1;
            }
        }
        n
    }
}

impl<A: Adapter> Default for ClassQueues<A> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct N {
        v: u32,
        link: Link,
    }
    crate::adapter!(NA, N, link);

    fn n(v: u32) -> N {
        N {
            v,
            link: Link::new(),
        }
    }

    #[test]
    fn highest_first_fifo_within() {
        let (a, b, c, d) = (n(1), n(2), n(3), n(4));
        let mut q: PrioQueue<NA> = PrioQueue::new();
        unsafe {
            q.push(&a, 10);
            q.push(&b, 200);
            q.push(&c, 10);
            q.push(&d, 0);
            q.remove(&c, 10);
        }
        let got: alloc::vec::Vec<u32> =
            core::iter::from_fn(|| q.pop().map(|p| unsafe { (*p).v })).collect();
        assert_eq!(got, [2, 1, 4]);
        assert!(q.is_empty());
    }
}
