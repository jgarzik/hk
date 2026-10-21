//! The scheduler's part of a task (Linux sched_entity plus the
//! run-queue fields of task_struct) and the priority queue built from
//! it: 256 intrusive lists with an O(1) highest-priority lookup
//! (bitmap). Nothing here allocates, so run queues change in interrupt
//! context.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, Ordering};

use super::Priority;
use crate::list::{Adapter, Link, List};

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
    /// Priority (Linux p->prio): written under TASKLIST, read lock-free;
    /// a queued task moves at its next enqueue
    prio: AtomicU8,
    /// Its place in a priority list (under the rq lock)
    pub link: Link,
    /// Saved kernel context while switched out (under the rq lock)
    ctx: UnsafeCell<TaskContext>,
    /// The kernel stack is freed with the task (the boot stack of the
    /// first user task is not)
    owns_stack: AtomicBool,
    /// Next task on a remote wake list (Linux wake_entry)
    pub wake_next: AtomicPtr<()>,
    /// On a remote wake list (one entry per task)
    pub wake_pending: AtomicBool,
    /// Next task on a [`WakeQ`](crate::task::percpu::WakeQ); null when
    /// on none (Linux wake_q_node)
    pub wake_q: AtomicPtr<()>,
}

// SAFETY: `ctx` is only touched under the rq lock of the task's CPU
unsafe impl Sync for SchedEntity {}
unsafe impl Send for SchedEntity {}

impl SchedEntity {
    pub const fn new(prio: Priority, state: u8) -> Self {
        Self {
            state: AtomicU8::new(state),
            on_rq: AtomicBool::new(false),
            prio: AtomicU8::new(prio),
            link: Link::new(),
            // SAFETY: a switch frame is plain integers; zero is valid
            ctx: UnsafeCell::new(unsafe { MaybeUninit::zeroed().assume_init() }),
            owns_stack: AtomicBool::new(true),
            wake_next: AtomicPtr::new(core::ptr::null_mut()),
            wake_pending: AtomicBool::new(false),
            wake_q: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// The sleep state (`SleepState` as u8)
    #[inline]
    pub fn state(&self) -> u8 {
        self.state.load(Ordering::SeqCst)
    }

    /// Set the sleep state; a full barrier orders it before the caller's
    /// condition check (Linux smp_store_mb in set_current_state)
    #[inline]
    pub fn set_state(&self, s: u8) {
        self.state.swap(s, Ordering::SeqCst);
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

    pub fn prio(&self) -> Priority {
        self.prio.load(Ordering::Relaxed)
    }

    pub fn set_prio(&self, p: Priority) {
        self.prio.store(p, Ordering::Relaxed);
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
