//! Per-CPU scheduler with IRQ-safe locking
//!
//! Implements Linux-style per-CPU run queues where each CPU has its own
//! run queue protected by its own lock. This avoids contention on a global
//! lock and allows each CPU to schedule independently.
//!
//! Key invariants:
//! - Each CPU only modifies its own run queue
//! - Run queue lock must be held with IRQs disabled
//! - Context switch happens with the run queue lock held
#![expect(clippy::undocumented_unsafe_blocks)] // TODO(unsafe): SAFETY comments (doc/UNSAFE.md)

use crate::util::kalloc::{arc_nofail, box_nofail, try_arc};
use ::core::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use alloc::sync::Arc;

use crate::arch::ArchPageTable;
use crate::arch::CurrentArch;
use crate::arch::{ContextOps, CpuOps, PerCpuOps};
use crate::printkln;
use crate::sync::IrqSpinlock;
use crate::task::sched::{self, Class, ClassQueues, SeRq};
use crate::task::{Cred, PRIORITY_IDLE, Pid, Priority, Task, TaskKind, TaskState, Tid};
use crate::util::error::{KernelError, KernelResult};

use super::tasklist::{GlobalTaskTable, TASKLIST, TaskRef};
use crate::task::sched::TaskContext;

/// Size of kernel stack per thread (16KB, with a guard gap below it:
/// `mm::vmstack`)
pub const KERNEL_STACK_SIZE: usize = crate::mm::vmstack::THREAD_SIZE;

/// Configuration for creating a user task
///
/// Groups all parameters needed to create a user task, avoiding clippy's
/// too_many_arguments warning while keeping the API clear.
pub struct UserTaskConfig {
    /// Process group ID
    pub pgid: Pid,
    /// Session ID
    pub sid: Pid,
    /// Kernel stack top address
    pub kstack_top: u64,
    /// User stack top address
    pub user_stack_top: u64,
    /// Page table for the process
    pub page_table: ArchPageTable,
}

/// Sleep state of a task (Linux TASK_RUNNING / TASK_INTERRUPTIBLE /
/// TASK_UNINTERRUPTIBLE / TASK_KILLABLE / TASK_DEAD), kept in the task
/// (`Task.se`): set by the task itself before it re-checks its wait
/// condition, set back to Running by its wakers (`try_to_wake_up`)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SleepState {
    /// Runnable or running
    Running = 0,
    /// Sleeping; woken by wakeups and by signals
    Interruptible = 1,
    /// Sleeping; woken only by explicit wakeups / timeouts
    Uninterruptible = 2,
    /// Sleeping; woken by explicit wakeups / timeouts and by SIGKILL
    /// only (Linux TASK_KILLABLE)
    Killable = 3,
    /// Exited; never woken again (Linux TASK_DEAD)
    Dead = 4,
}

/// Which sleepers a wakeup may wake
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WakeMode {
    /// Wait-queue / timer wakeup: wakes any sleeper
    Any,
    /// Signal wakeup: wakes only `SleepState::Interruptible` sleepers
    Interruptible,
    /// Fatal signal (SIGKILL) wakeup: wakes `Interruptible` and
    /// `Killable` sleepers
    Fatal,
}

impl WakeMode {
    /// A sleeper in `state` (`SleepState` as u8) is one this wakeup ends
    /// (Linux ttwu_state_match)
    fn wakes(self, state: u8) -> bool {
        const I: u8 = SleepState::Interruptible as u8;
        const U: u8 = SleepState::Uninterruptible as u8;
        const K: u8 = SleepState::Killable as u8;
        matches!(
            (state, self),
            (I, _) | (U | K, WakeMode::Any) | (K, WakeMode::Fatal)
        )
    }
}

const RUNNING: u8 = SleepState::Running as u8;
const DEAD: u8 = SleepState::Dead as u8;

crate::adapter!(RunAdapter, Task, se.link);

/// Per-CPU run queue (Linux struct rq), under `PerCpuScheduler.lock`
///
/// The run queue owns one reference to each task of its CPU, taken when
/// the task is first made runnable (or created asleep) and handed to
/// `dead` at its final switch (Linux: the task's own usage count,
/// dropped in finish_task_switch for TASK_DEAD); the priority lists
/// and `curr` hold none of their own.
pub struct CpuRunQueue {
    /// Runnable tasks but the running one and the idle task (allocated
    /// with the idle task)
    queue: Option<alloc::boxed::Box<ClassQueues<RunAdapter>>>,
    /// The running task (null until this CPU's first switch)
    curr: *const Task,
    /// This CPU's idle task (Linux rq->idle): runs when nothing is
    /// queued; never queued, never asleep
    idle: *const Task,
    /// The task that exited on this CPU, released once it has switched
    /// away from it (Linux finish_task_switch for TASK_DEAD); one at a
    /// time: the next task takes it before anything else runs
    dead: Option<DeadTask>,
    /// The task this CPU is switching away from (Linux switch_to's
    /// `last`): the task switched to clears its `on_cpu` once off its
    /// stack (`finish_task_switch`). Kept alive by the scheduler's
    /// reference, or by `dead`.
    prev: *const Task,
    /// The CPU this run queue belongs to (Linux rq->cpu)
    cpu: u32,
    /// Fair: a vruntime no fair task here is behind (Linux
    /// cfs_rq->min_vruntime), the average when none is queued
    min_vruntime: u64,
    /// rt time used in this period (Linux rt_rq rt_time)
    rt_bw: crate::task::rt::RtBandwidth,
}

// SAFETY: the task pointers are owned references (see above), used
// under the rq lock
unsafe impl Send for CpuRunQueue {}

/// What an exited task still holds while its CPU runs on its stack and
/// its page tables: freed by the next task (`DeadTask::drop`)
pub struct DeadTask {
    /// Its kernel stack, if it owned one
    stack: Option<crate::mm::vmstack::VmStack>,
    /// mm_count reference on the address space it last ran in (mmdrop)
    mm: Option<alloc::sync::Arc<crate::mm::Mm>>,
    /// The run queue's reference (per-CPU `curr` pointed at it)
    task: Option<TaskRef>,
}

/// Stack an exiting task must have left untouched: room for an
/// interrupt (trap frame with the FP/SIMD registers, handler, tick work)
/// on top of the deepest syscall path
const STACK_MIN_LEFT: usize = 4096;

/// Linux CONFIG_DEBUG_STACK_USAGE check_stack_usage: kernel stacks start
/// zeroed, so the untouched bottom shows how deep the task ever went.
/// An overflow faults in the guard gap below the stack (a "kernel stack
/// overflow" panic); this reports a path that came close. Reported once.
fn check_stack_usage(stack: &crate::mm::vmstack::VmStack, task: Option<&Task>) {
    /// The least left so far (Linux lowest_to_date)
    static LOWEST: AtomicUsize = AtomicUsize::new(usize::MAX);
    let size = crate::mm::vmstack::THREAD_SIZE;
    // SAFETY: the dead task's stack, mapped while `stack` lives and no
    // longer in use
    let words = unsafe { core::slice::from_raw_parts(stack.base() as *const u64, size / 8) };
    let left = words.iter().position(|&w| w != 0).unwrap_or(words.len()) * 8;
    let tid = task.map_or(0, Task::tid);
    // A new lowest is reported with its task (Linux: "%s (%d) used
    // greatest stack depth: %lu bytes left"), racy as Linux's check
    if left < LOWEST.load(Ordering::Relaxed) {
        LOWEST.store(left, Ordering::Relaxed);
        printkln!(
            "stack: tid {} used greatest stack depth: {} bytes left",
            tid,
            left
        );
    }
    if left < STACK_MIN_LEFT {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        if !REPORTED.swap(true, Ordering::Relaxed) {
            printkln!(
                "STACK:FAIL kernel stack nearly overflowed: {} of {} bytes left (need {}) by tid {}",
                left,
                size,
                STACK_MIN_LEFT,
                tid
            );
        }
    }
}

impl Drop for DeadTask {
    fn drop(&mut self) {
        if let Some(stack) = self.stack.take() {
            check_stack_usage(&stack, self.task.as_deref());
        }
        // mmdrop: the last reference frees the top-level table
        drop(self.mm.take());
        drop(self.task.take());
    }
}

impl CpuRunQueue {
    /// An empty run queue (no idle task yet)
    pub const fn uninit() -> Self {
        Self {
            queue: None,
            curr: core::ptr::null(),
            idle: core::ptr::null(),
            dead: None,
            prev: core::ptr::null(),
            cpu: 0,
            min_vruntime: 0,
            rt_bw: crate::task::rt::RtBandwidth::new(),
        }
    }

    fn queue(&mut self) -> &mut ClassQueues<RunAdapter> {
        self.queue.as_mut().expect("run queue not initialized")
    }

    /// `t` belongs to this run queue (Linux task_rq(p) == rq): its
    /// `Task.cpu` names it, so its `se.rq` is ours to touch
    fn owns(&self, t: &Task) -> bool {
        PERCPU_SCHEDS.get(t.cpu()).lock.owns(self)
    }

    /// `t`'s run-queue fields (panics unless `t` belongs here)
    fn ent(&self, t: &Task) -> SeRq {
        assert!(self.owns(t), "sched: task not on this run queue");
        // SAFETY: `self` is the data of `t`'s rq lock (checked), held by
        // the guard it is borrowed from; `Task.cpu` moves only under
        // this lock or while nothing holding an rq lock reaches `t`
        // (LOCKING.md 3.1, rule 1)
        unsafe { t.se.rq.get(self) }
    }

    fn set_ent(&mut self, t: &Task, e: SeRq) {
        assert!(self.owns(t), "sched: task not on this run queue");
        // SAFETY: as in `ent`, borrowed mutably
        unsafe { t.se.rq.set(self, e) };
    }

    /// Change `t`'s run-queue fields with `f`
    fn with_ent<R>(&mut self, t: &Task, f: impl FnOnce(&mut SeRq) -> R) -> R {
        let mut e = self.ent(t);
        let r = f(&mut e);
        self.set_ent(t, e);
        r
    }

    /// Put `p` (runnable, neither running nor queued) on its class's
    /// list (Linux enqueue_task)
    fn enqueue(&mut self, p: &Task) {
        self.enqueue_at(p, false);
    }

    /// `enqueue` at the head of its level (`head`) or the tail
    fn enqueue_at(&mut self, p: &Task, head: bool) {
        // SAFETY: the rq owns a reference to `p`; it is on no list
        unsafe { self.queue().push(p, p.se.class(), p.se.rt_priority(), head) };
    }

    /// Put the task switched away from back: an rt task preempted
    /// before its slice ran out keeps the head of its level (Linux
    /// put_prev_task_rt), anything else goes to the tail
    fn enqueue_prev(&mut self, p: &Task, preempted: bool) {
        let expired = self.take_requeue_tail(p);
        self.enqueue_at(p, preempted && p.se.class() == Class::Rt && !expired);
    }

    /// Whether preempted `p` goes to the tail (its slice ran out),
    /// clearing that
    fn take_requeue_tail(&mut self, p: &Task) -> bool {
        self.with_ent(p, |e| core::mem::take(&mut e.requeue_tail))
    }

    /// Take queued `p` off its list (Linux dequeue_task)
    fn dequeue(&mut self, p: &Task) {
        // SAFETY: queued, so on its class's list of this run queue
        unsafe { self.queue().remove(p, p.se.class(), p.se.rt_priority()) };
    }

    /// Make `p` runnable (Linux ttwu_do_activate): Running, and queued
    /// unless it still is on the run queue (running, or not yet switched
    /// out)
    fn activate(&mut self, p: &Task) {
        p.se.set_state(RUNNING);
        // Under this rq's lock: plain updates (Linux
        // p->sched_contributes_to_load, rq->nr_uninterruptible--); a
        // run queue's count may go negative, the sum is right
        if self.with_ent(p, |e| core::mem::take(&mut e.contrib_load)) {
            crate::sync::Sole::sole_add(&PERCPU_SCHEDS.get(self.cpu).nr_uninterruptible, -1);
        }
        if !p.se.on_rq() {
            self.place_fair(p, false);
            p.se.set_on_rq(true);
            self.add_nr(1);
            self.enqueue(p);
            self.check_preempt(p);
        }
    }

    /// A task made runnable preempts the running one of a lower class,
    /// or of the rt class at a lower rt priority (Linux wakeup_preempt:
    /// a higher class always wins; within rt, the higher priority;
    /// once this CPU's rt runtime is used up, fair wins over rt,
    /// `rt_throttled`); a fair task waits for the tick
    fn check_preempt(&mut self, p: &Task) {
        // SAFETY: the running task, kept alive by this run queue
        let Some(curr) = (unsafe { self.curr.as_ref() }) else {
            return;
        };
        let (pc, cc) = (p.se.class(), curr.se.class());
        // Throttling swaps rt and fair's order
        let throttled = pc.max(cc) == Class::Fair && pc.min(cc) == Class::Rt && self.rt_throttled();
        if self.curr_is_idle()
            || (pc < cc) != throttled
            || (pc == Class::Rt && cc == Class::Rt && p.se.rt_priority() > curr.se.rt_priority())
            || (pc == Class::Fair && cc == Class::Fair && self.fair_wakeup_preempts(p, curr))
        {
            self.resched_curr();
        }
    }

    /// A woken fair task preempts the running fair one if EEVDF would
    /// pick it now (Linux check_preempt_wakeup_fair): never a SCHED_BATCH
    /// or SCHED_IDLE one, always over a SCHED_IDLE one
    fn fair_wakeup_preempts(&mut self, p: &Task, curr: &Task) -> bool {
        use crate::task::{SCHED_BATCH, SCHED_IDLE};
        let (pp, cp) = (p.se.policy(), curr.se.policy());
        if pp == SCHED_BATCH || pp == SCHED_IDLE {
            return false;
        }
        if cp == SCHED_IDLE {
            return true;
        }
        self.update_curr(crate::time::monotonic_ns());
        let ents = self.fair_tasks(true).map(|t| self.fair_ent(t));
        crate::task::fair::pick(ents).is_some_and(|t| core::ptr::eq(t, p))
    }

    /// A task joined (+1) or left (-1) this run queue (Linux
    /// add_nr_running / sub_nr_running)
    fn add_nr(&self, d: i32) {
        // Under this rq's lock, read lock-free elsewhere (Linux
        // rq->nr_running, READ_ONCE): a load and a store
        crate::sync::Sole::sole_add(&PERCPU_SCHEDS.get(self.cpu).nr_running, d as u32);
    }

    /// Make the running task switch at its next scheduling point: flag
    /// it, and interrupt its CPU if that is another one (Linux
    /// resched_curr; the reschedule IPI also ends an idle halt)
    fn resched_curr(&self) {
        // SAFETY: the running task, kept alive by this run queue
        let Some(curr) = (unsafe { self.curr.as_ref() }) else {
            return;
        };
        if curr.has_tif(crate::task::tif::NEED_RESCHED) {
            return;
        }
        curr.set_tif(crate::task::tif::NEED_RESCHED);
        if crate::cpu::try_this_id() != Some(self.cpu) {
            crate::smp::smp_send_reschedule(self.cpu);
        }
    }

    /// The next task to run: a stopper, else the highest rt task
    /// (unless throttled), else EEVDF's fair pick, else an rt task,
    /// else the idle task (Linux pick_next_task)
    fn pick_next(&mut self) -> *const Task {
        let rt = !self.rt_throttled();
        if let Some(t) = self.queue().pop_stop_rt(rt) {
            return t;
        }
        if let Some(t) = self.pick_fair() {
            return t;
        }
        self.queue().pop_stop_rt(true).unwrap_or(self.idle)
    }

    /// EEVDF's pick among the queued fair tasks, taken off their list
    fn pick_fair(&mut self) -> Option<*const Task> {
        let t = crate::task::fair::pick(self.fair_tasks(false).map(|t| self.fair_ent(t)))?;
        // SAFETY: on the fair list (just found there)
        unsafe { self.queue().remove(t, Class::Fair, 0) };
        // SAFETY: as above
        let v = self.ent(unsafe { &*t }).vruntime;
        self.min_vruntime = self.min_vruntime.max(v.min(self.fair_avg(false)));
        Some(t)
    }

    /// This CPU's rt tasks give way to its fair ones: their runtime in
    /// this period is used up and a fair task waits or runs (Linux
    /// rt_rq->rt_throttled; the fair server's rule that throttling
    /// never idles the CPU). The clock is read only once the runtime is
    /// used up.
    fn rt_throttled(&self) -> bool {
        let q = self.queue.as_ref().expect("run queue not initialized");
        self.rt_bw.exceeded()
            && self.rt_bw.exceeded_at(crate::time::monotonic_ns())
            && (q.has_fair() || self.curr_fair().is_some())
    }

    /// Charge the running task for its time since it last was (Linux
    /// curr->sched_class->update_curr): its runtime in every class but
    /// idle (`sched::update_se`), then a fair task's vruntime (true:
    /// its slice ran out) or an rt task's time against this CPU's rt
    /// runtime (update_curr_rt)
    fn update_curr(&mut self, now: u64) -> bool {
        // SAFETY: the running task, kept alive by this run queue
        let Some(curr) = (unsafe { self.curr.as_ref() }) else {
            return false;
        };
        if self.curr_is_idle() {
            return false;
        }
        let mut e = self.ent(curr);
        let delta = sched::update_se(curr, &mut e, now);
        let out = match curr.se.class() {
            Class::Fair if delta != 0 => crate::task::fair::update_curr(&curr.se, &mut e, delta),
            Class::Rt if delta != 0 => {
                self.rt_bw.charge(now, delta);
                false
            }
            _ => false,
        };
        self.set_ent(curr, e);
        out
    }

    /// The tick of a running rt task: charged, true if that used up
    /// its CPU's rt runtime with fair tasks waiting (Linux
    /// sched_rt_runtime_exceeded -> resched_curr)
    fn rt_tick(&mut self, now: u64) -> bool {
        self.update_curr(now);
        self.rt_throttled()
    }

    /// The tick of a running fair task: true if a new period ends a
    /// throttle with rt tasks waiting (Linux do_sched_rt_period_timer)
    fn rt_period_tick(&mut self, now: u64) -> bool {
        self.rt_bw.roll(now) && self.queue().has_rt()
    }

    /// The running task if it is a fair task still on this run queue
    /// and not on its list (Linux cfs_rq->curr)
    fn curr_fair(&self) -> Option<&Task> {
        // SAFETY: the running task, kept alive by this run queue
        unsafe { self.curr.as_ref() }
            .filter(|c| !self.curr_is_idle() && c.se.class() == Class::Fair && c.se.on_rq())
    }

    /// The fair tasks competing here: the queued ones, plus the running
    /// one if `with_curr` and it is one (`curr_fair`)
    fn fair_tasks(&self, with_curr: bool) -> impl Iterator<Item = &Task> + Clone {
        let q = self.queue.as_ref().expect("run queue not initialized");
        let curr = if with_curr { self.curr_fair() } else { None };
        q.fair_iter().chain(curr)
    }

    /// Fair task `t` of this run queue as EEVDF sees it: its address,
    /// weight and run-queue fields
    fn fair_ent(&self, t: &Task) -> (*const Task, u64, SeRq) {
        (
            core::ptr::from_ref(t),
            crate::task::fair::weight(&t.se),
            self.ent(t),
        )
    }

    /// Their weighted average vruntime (`min_vruntime` if none)
    fn fair_avg(&self, with_curr: bool) -> u64 {
        let ents = self.fair_tasks(with_curr).map(|t| {
            let (_, w, e) = self.fair_ent(t);
            (w, e.vruntime)
        });
        crate::task::fair::avg_vruntime(ents).unwrap_or(self.min_vruntime)
    }

    /// Their total weight (Linux cfs_rq->load.weight)
    fn fair_load(&self, with_curr: bool) -> u64 {
        self.fair_tasks(with_curr)
            .map(|t| crate::task::fair::weight(&t.se))
            .sum()
    }

    /// Place fair `p`, joining this run queue, by its lag (Linux
    /// place_entity; `initial`: a new task)
    fn place_fair(&mut self, p: &Task, initial: bool) {
        if p.se.class() == Class::Fair {
            let (avg, load) = (self.fair_avg(true), self.fair_load(true));
            self.with_ent(p, |e| {
                crate::task::fair::place(&p.se, e, avg, load, initial)
            });
        }
    }

    /// Fair `p` (queued here, or running) leaves: keep its lag (Linux
    /// update_entity_lag)
    fn save_lag(&mut self, p: &Task) {
        let avg = self.fair_avg(true);
        self.save_lag_at(p, avg);
    }

    /// `save_lag` against the average `avg`, measured before `p` left
    /// its list
    fn save_lag_at(&mut self, p: &Task, avg: u64) {
        if p.se.class() == Class::Fair {
            self.with_ent(p, |e| crate::task::fair::save_lag(&p.se, e, avg));
        }
    }

    /// The running task is the idle task
    fn curr_is_idle(&self) -> bool {
        core::ptr::eq(self.curr, self.idle)
    }
}

/// Per-CPU scheduler state (lock + run queue)
///
/// Any CPU may take another CPU's rq `lock` (Linux: wakeups lock the
/// target's run queue, `ttwu_queue`); the order between two is lowest
/// CPU first (`double_rq_lock`).
pub struct PerCpuScheduler {
    /// IRQ-safe lock protecting the run queue
    pub lock: IrqSpinlock<CpuRunQueue>,
    /// Whether this CPU's scheduler is initialized
    pub initialized: AtomicBool,
    /// Context switches performed on this CPU (a QSBR RCU would treat a
    /// change as a quiescent state)
    pub nr_switches: AtomicU64,
    /// The address space of the running task (its `Mm` address, 0 for
    /// none), set at each switch: membarrier compares it (Linux reads
    /// rq->curr->mm under RCU); never dereferenced through this
    pub curr_mm: AtomicUsize,
    /// That address space's membarrier registrations, cached at each
    /// switch (Linux rq->membarrier_state)
    pub membarrier_state: AtomicU32,
    /// The running task's `rank`, set at each switch and when it changes
    /// class or priority (Linux cpupri: rt wakeups look for the CPU
    /// running the least important task)
    pub curr_rank: AtomicU32,
    /// This CPU's ticks, for its balancing interval (Linux
    /// rq->next_balance)
    pub ticks: AtomicU64,
    /// Tasks on this run queue, queued or running, the idle task aside
    /// (Linux rq->nr_running): changed under the rq lock, read without
    /// it to place tasks
    pub nr_running: AtomicU32,
    /// Tasks that went to sleep here uninterruptibly (or killably) less
    /// those woken here (Linux rq->nr_uninterruptible: only the sum over
    /// CPUs means anything; one CPU's may be negative)
    pub nr_uninterruptible: AtomicI64,
}

impl PerCpuScheduler {
    /// Create an uninitialized per-CPU scheduler
    pub const fn new() -> Self {
        Self {
            lock: IrqSpinlock::new(CpuRunQueue::uninit()),
            nr_running: AtomicU32::new(0),
            nr_uninterruptible: AtomicI64::new(0),
            initialized: AtomicBool::new(false),
            nr_switches: AtomicU64::new(0),
            curr_mm: AtomicUsize::new(0),
            membarrier_state: AtomicU32::new(0),
            curr_rank: AtomicU32::new(0),
            ticks: AtomicU64::new(0),
        }
    }
}

crate::percpu! {
    /// Global per-CPU scheduler array
    ///
    /// Each CPU accesses its own entry by CPU ID.
    static PERCPU_SCHEDS: PerCpuScheduler = PerCpuScheduler::new();
}

/// The boot CPU has per-CPU data (`init_bsp`); from then on every CPU
/// running kernel code has its own
pub static PERCPU_UP: AtomicBool = AtomicBool::new(false);

/// The current task of a CPU without per-CPU data: early boot (one CPU,
/// no user code yet) is the boot task, root like Linux init_task;
/// after `init_bsp` it is a bug or a corrupted per-CPU pointer, so fail
/// closed instead of guessing credentials
pub fn no_percpu_task() -> usize {
    if PERCPU_UP.load(Ordering::Acquire) {
        panic!("current task: no per-CPU data");
    }
    0
}

/// The boot task (Linux init_task): current on each CPU until it first
/// switches (per-CPU `curr` 0). Root, tid 0, never in TASKLIST.
pub static INIT_TASK: Task = Task::boot(0);

/// The running task (Linux `current`): a `!Send` handle valid while
/// the task runs (the run queue holds its reference)
pub struct Cur {
    task: &'static Task,
    _not_send: core::marker::PhantomData<*const ()>,
}

impl core::ops::Deref for Cur {
    type Target = Task;
    fn deref(&self) -> &Task {
        self.task
    }
}

impl Cur {
    /// Its credentials, copied (Linux current_cred: an override in
    /// force, `task::override_creds`, else its own)
    pub fn cred(&self) -> Cred {
        // SAFETY: the task itself
        unsafe { self.task.subj_cred() }
    }

    /// A reference to its credentials (as `cred`)
    pub fn cred_arc(&self) -> Arc<Cred> {
        // SAFETY: the task itself
        unsafe { self.task.subj_cred_arc() }
    }

    /// Its address space (an mm_count reference)
    pub fn mm(&self) -> Option<Arc<crate::mm::Mm>> {
        // SAFETY: the task itself
        unsafe { self.task.mm() }.as_ref().map(|m| m.arc().clone())
    }

    /// Its address space (a user reference)
    pub fn mm_ref(&self) -> Option<crate::mm::MmRef> {
        // SAFETY: the task itself
        unsafe { self.task.mm() }.clone()
    }

    /// Its descriptor table
    pub fn files(&self) -> Option<Arc<crate::task::fdtable::Files>> {
        // SAFETY: the task itself
        unsafe { self.task.files() }.clone()
    }

    /// Its filesystem context (Linux current->fs)
    pub fn fs(&self) -> Option<Arc<crate::fs::FsStruct>> {
        // SAFETY: the task itself
        unsafe { self.task.fs() }.clone()
    }

    /// Its namespaces (Linux current->nsproxy)
    pub fn nsproxy(&self) -> Option<Arc<crate::ns::NsProxy>> {
        // SAFETY: the task itself
        unsafe { self.task.nsproxy() }.clone()
    }

    /// Its name (Linux current->comm)
    pub fn comm(&self) -> [u8; 16] {
        // SAFETY: the task itself
        unsafe { self.task.comm() }
    }

    /// `t` is the running task (Linux `p == current`)
    pub fn is(&self, t: &Task) -> bool {
        core::ptr::eq(self.task, t)
    }

    /// The task is a kernel thread or the boot task (no user context)
    pub fn is_kthread(&self) -> bool {
        self.task.has_flag(crate::task::pf::KTHREAD)
    }
}

/// The running task of this CPU (Linux `current`)
#[inline]
pub fn current() -> Cur {
    let p = CurrentArch::current_task_ptr() as *const Task;
    let task = if p.is_null() {
        &INIT_TASK
    } else {
        // SAFETY: a nonzero `curr` is the task this CPU switched to,
        // kept alive by its run queue until it has switched away for good
        unsafe { &*p }
    };
    Cur {
        task,
        _not_send: core::marker::PhantomData,
    }
}

/// The user registers of task `t` while it is in the kernel (Linux
/// task_pt_regs): the entry frame at the top of its kernel stack
pub fn task_pt_regs(t: &Task) -> *mut <CurrentArch as crate::arch::Arch>::TrapFrame {
    let size = core::mem::size_of::<<CurrentArch as crate::arch::Arch>::TrapFrame>() as u64;
    (t.kstack_top - size) as *mut _
}

/// The current task's user registers (Linux current_pt_regs); only for a
/// task that entered from user mode (not kernel threads). `'static`: the
/// kernel stack outlives every use by the task itself, and `&UserFrame`
/// is `!Send`, so it never leaves the task.
pub fn current_pt_regs() -> &'static crate::arch::UserFrame {
    // SAFETY: the running task's own frame, on its own kernel stack;
    // only the task and a tracer (while it is stopped) access it
    unsafe { crate::arch::UserFrame::from_ptr(task_pt_regs(&current())) }
}

/// Timer tick counter (global)
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Get the per-CPU scheduler for a given CPU
/// CPU `cpu`'s scheduler, if it exists (membarrier reads its
/// `curr_mm` and `membarrier_state`)
pub fn cpu_sched(cpu: u32) -> Option<&'static PerCpuScheduler> {
    PERCPU_SCHEDS.try_get(cpu)
}

fn get_percpu_sched(cpu_id: u32) -> &'static PerCpuScheduler {
    PERCPU_SCHEDS.get(cpu_id)
}

/// Get the per-CPU scheduler for the current CPU
pub fn current_percpu_sched() -> Option<&'static PerCpuScheduler> {
    crate::cpu::try_this_id().map(|cpu_id| PERCPU_SCHEDS.get(cpu_id))
}

/// Idle task entry function - runs when no other work is available
///
/// This is the lowest priority task (PRIORITY_IDLE = 0) on each CPU.
/// It halts the CPU until an interrupt arrives, then yields immediately
/// to give higher priority tasks a chance to run.
fn idle_task_entry() -> ! {
    // Enable interrupts - they may be disabled from context switch
    // (IrqSpinlock was held during switch but never dropped on our stack)
    CurrentArch::enable_interrupts();

    loop {
        // Yield immediately to give other tasks priority
        yield_now();
        // Idle holds nothing: a quiescent state (Linux rcu_idle_enter's
        // extended one, here reported each pass)
        crate::sync::rcu::idle();
        // Nothing to run here: pull from a busier CPU (Linux
        // sched_balance_newidle); a task pulled flags us to switch
        sched_balance_rq(crate::cpu::this_id());

        // Halt until an interrupt unless a wakeup made a task runnable
        // since the yield (it flags the idle task, interrupts off
        // closes the window; the STI;HLT pattern enables them and halts
        // atomically)
        CurrentArch::disable_interrupts();
        if current().has_tif(crate::task::tif::NEED_RESCHED) {
            CurrentArch::enable_interrupts();
            continue;
        }
        CurrentArch::enable_and_halt();
    }
}

/// Create a kernel task (pid 0, kernel page table) owned by `cpu_id`
///
/// `entry` runs on a fresh kernel stack with the rq lock
/// released (`finish_context_switch`) but interrupts still disabled; it must
/// enable them. A kernel thread is its own process (pid == tid, Linux),
/// created asleep (the creator finishes its setup, then wakes it); an
/// `idle` task is tid 0, outside TASKLIST (Linux swapper/N), and becomes
/// its CPU's idle task. Fails with alloc_pid's error (Linux
/// copy_process's: EAGAIN, ENOMEM), or OutOfMemory for its credentials,
/// stack or task; the caller reports it.
fn create_kernel_task(
    cpu_id: u32,
    name: &str,
    entry: usize,
    priority: Priority,
    idle: bool,
) -> Result<TaskRef, KernelError> {
    let thread_pid = if idle {
        None
    } else {
        Some(crate::task::pid::alloc_pid(&crate::ns::INIT_PID_NS)?)
    };
    // Its numbers go back if creation fails (Linux bad_fork_free_pid)
    let new_pid = thread_pid.as_ref().map(crate::task::pid::NewPid::new);
    let tid = thread_pid.as_ref().map_or(0, |p| Tid::from(p.nr()));
    let pid = tid;

    let cred = try_arc(Cred::root())?;
    let sig = crate::signal::TaskSignalState::new();
    let stack = crate::mm::vmstack::alloc().ok_or(KernelError::OutOfMemory)?;
    let stack_top = stack.top();

    // In no process group or session (never signalled by group); no
    // exit signal, no user-space resources, never traced
    let task_inner = crate::task::TaskInner::new(TaskState::Ready, ArchPageTable::kernel_root());
    // Built in its block; on failure the stack goes with the task's
    // parts
    let task = crate::util::kalloc::try_arc_with(|| {
        Task::new(
            tid,
            crate::task::TaskIds {
                pid,
                seccomp_mode: crate::seccomp::SECCOMP_MODE_DISABLED,
                thread_pid,
            },
            TaskKind::KernelThread,
            stack_top,
            cpu_id,
            &crate::util::cpumask::CpuSet::one(cpu_id),
            cred,
            None,
            crate::task::TaskAlloc::named(name.as_bytes()),
            sig,
            task_inner,
        )
    })?;

    set_kthread_class(&task.se, priority);
    // SAFETY: not on a run queue yet
    unsafe { *task.se.ctx() = TaskContext::new_kernel_thread(entry, stack_top) };
    task.se.stack.set(stack);
    if idle {
        set_idle(cpu_id, &task);
    } else {
        TASKLIST.write().insert(task.clone());
        attach_asleep(&task);
    }
    if let Some(p) = new_pid {
        p.attached();
    }
    Ok(task)
}

/// Make `idle` the idle task of `cpu`, allocating its priority lists
/// (bring-up, before the CPU schedules)
fn set_idle(cpu: u32, idle: &TaskRef) {
    // CPU bring-up: failure cannot be reported
    let q = box_nofail(ClassQueues::new());
    idle.se.set_on_rq(true);
    let mut rq = get_percpu_sched(cpu).lock.lock();
    rq.queue = Some(q);
    rq.cpu = cpu;
    // The run queue's reference, kept for good
    rq.idle = Arc::into_raw(idle.clone());
}

/// Give `p`'s run queue its reference to a task created asleep: it
/// runs once woken (`try_to_wake_up`)
fn attach_asleep(p: &TaskRef) {
    p.se.set_state(SleepState::Uninterruptible as u8);
    let _ = Arc::into_raw(p.clone());
}

/// Start a new task: the scheduler takes its reference and queues it
/// on the CPU `select_task_rq` picks (Linux wake_up_new_task)
pub(super) fn wake_up_new_task(p: &TaskRef) {
    // Its owner fields are its own from here (TaskLock::owner_check)
    p.started.store(true, Ordering::Release);
    let _pi = p.pi_lock.lock();
    set_task_cpu(p, select_task_rq(p, Placement::Fork));
    let mut rq = get_percpu_sched(p.cpu()).lock.lock();
    let _ = Arc::into_raw(p.clone());
    p.se.set_state(RUNNING);
    rq.place_fair(p, true);
    p.se.set_on_rq(true);
    rq.add_nr(1);
    rq.enqueue(p);
    rq.check_preempt(p);
}

/// Create the idle task for a specific CPU and mark its scheduler ready
///
/// The idle task is always runnable at PRIORITY_IDLE (0). The CPU may enter
/// the scheduler only once this is done, so `initialized` is set last.
fn create_idle_task(cpu_id: u32) -> Result<(), KernelError> {
    crate::time::timer::init_cpu(cpu_id);
    create_kernel_task(
        cpu_id,
        "swapper",
        idle_task_entry as *const () as usize,
        PRIORITY_IDLE,
        true,
    )?;
    // Its ticks report quiescent states from here (Linux
    // rcutree_online_cpu), before anything runs on it
    crate::sync::rcu::cpu_online(cpu_id);
    get_percpu_sched(cpu_id)
        .initialized
        .store(true, Ordering::Release);
    sched_cpu_update(cpu_id);
    printkln!("IDLE_TASK_CREATED: cpu={} tid=0", cpu_id);
    Ok(())
}

/// Create a kernel thread on `cpu_id`, asleep (see `task::kthread`; start
/// it with `try_to_wake_up`)
pub fn create_kthread_task(
    cpu_id: u32,
    name: &str,
    entry: usize,
    priority: Priority,
) -> Result<TaskRef, KernelError> {
    if !get_percpu_sched(cpu_id).initialized.load(Ordering::Acquire) {
        return Err(KernelError::InvalidArgument);
    }
    create_kernel_task(cpu_id, name, entry, priority, false)
}

/// Give every online AP a scheduler (idle task); each AP switches into it
/// from its boot idle loop via `try_schedule()`
pub fn init_ap_schedulers() {
    let bsp = crate::cpu::this_id();
    for (cpu, _) in PERCPU_SCHEDS.for_each_possible() {
        if cpu != bsp
            && CurrentArch::cpu_online(cpu)
            && let Err(e) = create_idle_task(cpu)
        {
            printkln!("SCHED: no scheduler for CPU {}: {:?}", cpu, e);
        }
    }
}

/// Whether `cpu` runs a scheduler (can own tasks)
pub fn cpu_has_scheduler(cpu: u32) -> bool {
    PERCPU_SCHEDS
        .try_get(cpu)
        .is_some_and(|s| s.initialized.load(Ordering::Acquire))
}

/// Initialize the global scheduler with idle task for BSP
pub fn init() {
    // Initialize BSP's per-CPU scheduler
    let cpu_id = crate::cpu::this_id();

    printkln!("Per-CPU scheduler initialized for CPU {}", cpu_id);

    // Create idle task for BSP
    match create_idle_task(cpu_id) {
        Ok(_tid) => {}
        Err(e) => panic!("Failed to create BSP idle task: {:?}", e),
    }
}

/// The caller is a task that may sleep: this CPU's scheduler runs and
/// it is neither an idle task nor the boot context before pid 1 exists
/// (both tid 0, which never sleep; Linux: no might_sleep before
/// SYSTEM_SCHEDULING, and idle never sleeps)
pub fn can_sleep() -> bool {
    current_tid() != 0 && this_sched().is_some()
}

/// Create a user task entry for the init process
///
/// Unlike kernel threads, user tasks use syscall/iret for context switching.
/// This function registers the task so the scheduler knows about it.
///
/// The kernel stack must already be allocated by the caller.
///
/// # Arguments
/// * `config` - User task configuration (pgid, sid, priority, stacks, page table)
pub fn create_user_task(config: UserTaskConfig) -> Result<TaskRef, KernelError> {
    let cpu_id = crate::cpu::this_id();
    // init is pid 1 (Linux: the first pid of the root namespace); the
    // caller reports any other error
    let thread_pid =
        crate::task::pid::alloc_pid_nr(&crate::ns::INIT_PID_NS, &[1]).inspect_err(|e| {
            if *e == KernelError::AlreadyExists {
                printkln!("init: pid 1 taken");
            }
        })?;
    let (tid, pid): (Tid, Pid) = (1, 1);
    // The first address space owns the boot-built tables
    let mm = crate::mm::mm_alloc(config.page_table.root_table_phys());

    // Create Task entry
    // The boot group and session, number 0 (Linux init_struct_pid)
    let pgrp = crate::task::pid::find_pgrp(&crate::ns::INIT_PID_NS, config.pgid);
    let session = crate::task::pid::find_pgrp(&crate::ns::INIT_PID_NS, config.sid);
    let task_inner = crate::task::TaskInner {
        user_ns: Some(crate::ns::INIT_USER_NS.clone()),
        exit_signal: crate::signal::ExitSignal::SIGCHLD,
        // Shared resources: set by the caller via init_* functions
        ..crate::task::TaskInner::new(TaskState::Running, config.page_table.root_table_phys())
    };
    // The boot-time init task, built in its block: failure cannot be
    // reported
    let task = crate::util::kalloc::try_arc_with(|| {
        Task::new(
            tid,
            crate::task::TaskIds {
                pid,
                seccomp_mode: crate::seccomp::SECCOMP_MODE_DISABLED,
                thread_pid: Some(thread_pid),
            },
            TaskKind::UserProcess,
            config.kstack_top,
            cpu_id,
            &crate::util::cpumask::CpuSet::all(),
            arc_nofail(Cred::root()),
            Some(mm),
            // comm after the init binary, /bin/init (Linux names init after
            // the file it execs)
            crate::task::TaskAlloc::named(b"init"),
            crate::signal::TaskSignalState::new(),
            task_inner,
        )
    })
    .expect("boot: no memory for the init task");

    // Add to global table, as the root namespace's child reaper
    {
        let mut table = TASKLIST.write();
        table.insert(task.clone());
        crate::task::pidns::attach_init(&mut table, &task);
    }

    // The boot-allocated stack of the first task is not its own (never
    // freed); its switch frame is saved at its first switch out
    task.se.set_state(RUNNING);
    task.se.set_on_rq(true);
    task.se.set_on_cpu(true);
    {
        let sched = get_percpu_sched(cpu_id);
        // SAFETY: the task is not running yet; only its creator sees it
        let mm = unsafe { task.mm() }
            .as_ref()
            .map_or(0, |m| Arc::as_ptr(m.arc()) as usize);
        sched.curr_mm.store(mm, Ordering::SeqCst);
        let mut rq = sched.lock.lock();
        rq.add_nr(1);
        // The boot context becomes this task (Linux: init_task's
        // kernel_init thread execs /sbin/init); the run queue takes
        // its reference
        task.started.store(true, Ordering::Release);
        rq.curr = Arc::into_raw(task.clone());
        CurrentArch::set_current_task_ptr(rq.curr as usize);
    }

    // Initialize filesystem context for the init task
    if let Some(fs) = crate::fs::FsStruct::new_root() {
        crate::fs::init_task_fs(&task, fs);
    }

    // Initialize FD table for the init task
    crate::task::fdtable::init_task_fd(&task, crate::task::fdtable::create_empty_fd_table());

    // Initialize namespace context for the init task
    crate::ns::init_task_ns(&task, crate::ns::INIT_NSPROXY.clone());

    // Initialize signal handlers for the init task
    crate::signal::init_task_signal(
        &task,
        arc_nofail(crate::signal::SigHand::new()),
        [pgrp, session],
    );

    printkln!("USER_TASK_CREATED: pid={} tid={}", pid, tid);
    Ok(task)
}

/// The exiting current task's last switch (Linux do_task_dead): Dead
/// under its pi_lock, off the run queue for good, its stack, `dead_mm`
/// (mmdrop) and the run queue's reference freed by the next task
pub(super) fn do_task_dead(dead_mm: Option<Arc<crate::mm::Mm>>) -> ! {
    // No wakeup touches the task from here on (Linux TASK_DEAD): they
    // see Dead under its pi_lock
    let me = current();
    {
        let _pi = me.pi_lock.lock();
        me.se.set_state(DEAD);
    }

    let sched = current_percpu_sched().expect("No scheduler");
    let mut rq = sched.lock.lock();
    // Its last slice (Linux do_task_dead -> __schedule -> put_prev_task
    // -> update_curr): its runtime, its group's running CPU-timer totals
    // and rt bandwidth
    rq.update_curr(crate::time::monotonic_ns());

    // Off the run queue for good; its stack, mm and the run queue's
    // reference go once this CPU runs something else
    me.se.set_on_rq(false);
    rq.add_nr(-1);
    let stack = me.se.stack.take();
    // SAFETY: the run queue's reference to the running task
    let task = Some(unsafe { Arc::from_raw(rq.curr) });
    rq.dead = Some(DeadTask {
        stack,
        mm: dead_mm,
        task,
    });

    let next = rq.pick_next();
    // The arch thread state while `current` is still the outgoing task
    // (Linux __switch_to: fpsimd_thread_switch)
    // SAFETY: interrupts off (the rq lock), the switch to `next`, a task
    // of this run queue (alive while it holds it, not running), follows
    unsafe { crate::arch::thread_switch(&*next) };
    // SAFETY: a task of this run queue, alive while it holds it
    let (next_kstack, next_mm, (next_tls, next_gs)) = make_current(&mut rq, unsafe { &*next });
    rq.curr = next;
    rq.prev = &raw const *me;
    // Under the rq lock (Linux rq->nr_switches++)
    crate::sync::Sole::sole_add(&sched.nr_switches, 1);

    // The rq lock stays held across the switch, as for any switch: the
    // next task releases it (finish_task_switch), and only then frees our
    // stack (`rq.dead`)
    check_switch_atomic();
    core::mem::forget(rq);

    // Switch to next task - never returns
    unsafe {
        switch_mm(next_mm);
        CurrentArch::context_switch_first((*next).se.ctx(), next_kstack, next_tls, next_gs);
    }
}

/// Make `next` (on this run queue) this CPU's current task: per-CPU
/// `curr` points at it. Returns its kernel stack for user entry (0 for
/// kernel threads, which never return to user mode), its address space
/// (null for none) and its user TLS register and GS base.
///
/// The caller holds the rq lock and `next` is not running, so nothing
/// changes its address space meanwhile (only the task itself does, or
/// its creator before it first runs), and the run queue's reference
/// keeps it alive until it has switched away for good.
fn make_current(rq: &mut CpuRunQueue, t: &Task) -> (u64, *const crate::mm::Mm, (u64, u64)) {
    // Running: its owner fields are its own from now on (owner_check;
    // covers kernel threads and every other way a task first runs)
    if !t.started.load(Ordering::Relaxed) {
        t.started.store(true, Ordering::Release);
    }
    let kstack = if matches!(t.kind, TaskKind::KernelThread) {
        0
    } else {
        t.kstack_top
    };
    // SAFETY: see above
    let mm = unsafe { t.mm() }
        .as_ref()
        .map_or(core::ptr::null(), |m| Arc::as_ptr(m.arc()));
    if let Some(s) = current_percpu_sched() {
        // Full barrier: a membarrier caller that misses this CPU's new
        // address space is ordered before the task's return to user
        // mode (Linux: the barriers around rq->curr's update)
        s.curr_mm.store(mm as usize, Ordering::SeqCst);
        // Then its registrations (Linux membarrier_switch_mm, after
        // rq->curr): a registration either sees this CPU in the mm and
        // updates its cache by IPI, or is seen here
        core::sync::atomic::fence(Ordering::SeqCst);
        // SAFETY: the task's address space, alive while it runs
        let st = unsafe { mm.as_ref() }.map_or(0, |m| m.membarrier_state().load(Ordering::Relaxed));
        s.membarrier_state.store(st, Ordering::Relaxed);
        s.curr_rank.store(rank(t), Ordering::Relaxed);
    }
    CurrentArch::set_current_task_ptr(core::ptr::from_ref::<Task>(t) as usize);
    // Linux prepare_task
    t.se.set_on_cpu(true);
    // Its runtime counts from now (Linux set_next_entity, set_next_task_*)
    let now = crate::time::monotonic_ns();
    rq.with_ent(t, |e| e.exec_start = now);
    let tls = (
        t.tls.load(Ordering::Relaxed),
        t.gsbase.load(Ordering::Relaxed),
    );
    (kstack, mm, tls)
}

/// Load the address space of the task switched to (`make_current`)
///
/// # Safety
/// `mm` is null or an address space kept alive by that task.
unsafe fn switch_mm(mm: *const crate::mm::Mm) {
    // SAFETY: see above
    crate::mm::tlb::switch_mm(unsafe { mm.as_ref() });
}

/// Switch from the current task `prev` to `next` with `rq` held (Linux
/// context_switch)
///
/// The lock stays held across the switch and is released by whichever task
/// runs next (`finish_task_switch`, from here or from
/// `finish_context_switch` for a new task). `prev`'s user registers stay
/// in its pt_regs, on its own kernel stack.
fn context_switch_locked(
    sched: &PerCpuScheduler,
    mut rq: crate::sync::IrqSpinlockGuard<'_, CpuRunQueue>,
    prev: &Task,
    next: *const Task,
) {
    check_switch_atomic();
    crate::sync::rcu::note_context_switch();
    // Save the outgoing task's user TLS register and GS base (user code
    // may have changed them without a syscall, e.g. msr tpidr_el0, mov
    // gs); the arch switch loads `next`'s
    if !prev.has_flag(crate::task::pf::KTHREAD) {
        prev.tls
            .store(crate::arch::read_user_tls(), Ordering::Relaxed);
        prev.gsbase
            .store(crate::arch::read_user_gsbase(), Ordering::Relaxed);
    }
    // SAFETY: a task of this run queue, alive while it holds it
    let n = unsafe { &*next };
    // The outgoing task's runtime up to now if it stays on the run
    // queue (Linux put_prev_entity: `if (prev->on_rq) update_curr`; a
    // sleeper was charged as it left, in deactivate); the incoming one's
    // counts from `make_current` (set_next_entity): its time off the CPU
    // is nobody's
    if prev.se.on_rq() {
        rq.update_curr(crate::time::monotonic_ns());
    }
    // The arch thread state while `current` is still `prev` (Linux
    // __switch_to: fpsimd_thread_switch)
    // SAFETY: interrupts off (the rq lock), the switch to `n` (not
    // running) follows
    unsafe { crate::arch::thread_switch(n) };
    let (next_kstack, next_mm, (next_tls, next_gs)) = make_current(&mut rq, n);
    rq.curr = next;
    rq.prev = prev;
    // Under the rq lock (Linux rq->nr_switches++)
    crate::sync::Sole::sole_add(&sched.nr_switches, 1);

    // SAFETY: both frames are under the rq lock we hold
    unsafe {
        switch_mm(next_mm);
        CurrentArch::context_switch(prev.se.ctx(), n.se.ctx(), next_kstack, next_tls, next_gs);
    }
    // Back on `prev`, holding the rq lock of the CPU it runs on now
    // (taken by the task that switched to it there), which need not be
    // the one `rq` locked
    let this = current_percpu_sched().expect("No scheduler");
    // SAFETY: the switch handed this CPU's rq lock to us
    finish_task_switch(unsafe { rq.rebind(&this.lock) });
}

/// Complete a switch on the task switched to, with this CPU's rq lock
/// (Linux finish_task_switch): the task switched away from is off its
/// stack now, so its `on_cpu` clears; release the lock, then free what
/// a task that exited here left
fn finish_task_switch(mut rq: crate::sync::IrqSpinlockGuard<'_, CpuRunQueue>) {
    // SAFETY: kept alive by the scheduler's reference or by `rq.dead`
    if let Some(prev) = unsafe { rq.prev.as_ref() } {
        prev.se.set_on_cpu(false);
    }
    rq.prev = core::ptr::null();
    let dead = rq.dead.take();
    drop(rq);
    drop(dead);
}

/// Linux schedule_debug ("scheduling while atomic"): a task switches
/// out holding only its rq lock, so the preempt count it leaves behind
/// is exactly that lock's; any other spin lock would stay held (and the
/// count raised) while another task runs. Reported once.
fn check_switch_atomic() {
    let pc = crate::arch::preempt_count();
    if pc != 1 {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        if !REPORTED.swap(true, Ordering::Relaxed) {
            printkln!(
                "SCHED:FAIL scheduling while atomic: preempt count {} (tid {})",
                pc,
                current_tid()
            );
        }
    }
}

/// This CPU's scheduler, if initialized
fn this_sched() -> Option<&'static PerCpuScheduler> {
    current_percpu_sched().filter(|s| s.initialized.load(Ordering::Acquire))
}

/// Set the current task's sleep state (Linux set_current_state)
///
/// Call before re-checking the wait condition (a full barrier orders the
/// two); a wakeup arriving after this point sets it back to Running, so
/// the following `schedule()` returns immediately.
pub fn set_current_state(state: SleepState) {
    current().se.set_state(state as u8);
}

/// Give up the CPU until woken, if the current task's state is not Running
///
/// Linux `schedule()` for a voluntary sleep: callers set their state with
/// [`set_current_state`], re-check their condition, then call this. If a
/// wakeup already arrived (state back to Running) it returns at once.
pub fn schedule() {
    crate::sync::might_sleep();
    let Some(sched) = this_sched() else { return };
    let me = current();
    // Held bios go out before a sleep that may wait for them (Linux
    // sched_submit_work: blk_flush_plug)
    if me.se.state() != RUNNING {
        crate::block::plug::flush_on_sleep();
    }
    // This is the rescheduling a pending NEED_RESCHED asked for
    me.clear_tif(crate::task::tif::NEED_RESCHED);
    let mut rq = sched.lock.lock();
    // A waker takes this rq lock to see us on it (ttwu_runnable): it set
    // Running before we got here, or finds us off it
    if rq.curr.is_null() || rq.curr_is_idle() || me.se.state() == RUNNING {
        return;
    }
    // Leave the run queue (Linux deactivate_task), a fair task keeping
    // its lag; an uninterruptible or killable sleep counts in the load
    // (task_contributes_to_load)
    rq.update_curr(crate::time::monotonic_ns());
    rq.save_lag(&me);
    me.se.set_on_rq(false);
    rq.add_nr(-1);
    // A slice that ran out is not carried past the sleep
    rq.take_requeue_tail(&me);
    let st = me.se.state();
    if st == SleepState::Uninterruptible as u8 || st == SleepState::Killable as u8 {
        rq.with_ent(&me, |e| e.contrib_load = true);
        // Under this rq's lock (Linux rq->nr_uninterruptible++)
        crate::sync::Sole::sole_add(&sched.nr_uninterruptible, 1);
    }
    // The task's own counter (Linux prev->nvcsw++)
    crate::sync::Sole::sole_add(&me.nvcsw, 1);
    let next = rq.pick_next();
    context_switch_locked(sched, rq, &me, next);
}

/// Timeout value meaning "no timeout" for [`schedule_timeout`]
pub const MAX_SCHEDULE_TIMEOUT: u64 = u64::MAX;

/// `schedule()` with a timeout in scheduler ticks (Linux schedule_timeout)
///
/// The caller sets its state first. Returns the ticks left (0 if the
/// timeout expired); whichever of wakeup and timeout comes first ends the
/// sleep and the other is cancelled. The timeout is a HARD timer on
/// this stack (Linux process_timeout), deleted before returning.
pub fn schedule_timeout(timeout: u64) -> u64 {
    if timeout == MAX_SCHEDULE_TIMEOUT {
        schedule();
        return MAX_SCHEDULE_TIMEOUT;
    }
    if this_sched().is_none() {
        return 0;
    }
    let me = current();
    if timeout == 0 {
        me.se.set_state(RUNNING);
        return 0;
    }
    let expire = get_ticks().saturating_add(timeout);
    let t = core::pin::pin!(crate::time::timer::TimerList::new(
        process_timeout,
        crate::time::timer::TIMER_HARD
    ));
    t.set_data(&raw const *me as usize);
    t.as_ref().mod_timer(expire);
    schedule();
    t.del_timer_sync();
    expire.saturating_sub(get_ticks())
}

/// A `schedule_timeout` sleep timed out (tick interrupt): wake its task
fn process_timeout(t: &crate::time::timer::TimerList) {
    // SAFETY: the sleeper, which deletes the timer before it returns
    try_to_wake_up(unsafe { &*(t.data() as *const Task) }, WakeMode::Any);
}

/// Lock the run queue `p` is on (Linux task_rq_lock): the CPU it names
/// once the lock is held
fn task_rq_lock(p: &Task) -> crate::sync::IrqSpinlockGuard<'static, CpuRunQueue> {
    loop {
        let cpu = p.cpu();
        let rq = get_percpu_sched(cpu).lock.lock();
        if p.cpu() == cpu {
            return rq;
        }
    }
}

/// Task `p`'s runtime with the slice it is running now (Linux
/// task_sched_runtime: under its rq lock, the running task is charged
/// up to now first, `update_curr`)
pub fn task_sched_runtime(p: &Task) -> u64 {
    // Not running or not queued: nothing pending (Linux's 64-bit fast
    // path)
    if !p.se.on_cpu() || !p.se.on_rq() {
        return p.se.sum_exec_runtime();
    }
    let mut rq = task_rq_lock(p);
    if core::ptr::eq(rq.curr, p) && p.se.on_rq() && rq.update_curr(crate::time::monotonic_ns()) {
        // Its slice ran out (Linux update_curr -> resched_curr)
        rq.resched_curr();
    }
    p.se.sum_exec_runtime()
}

/// Move `p` to `cpu`'s run queue's ownership (Linux set_task_cpu):
/// under its pi_lock while it is off every run queue (a wakeup, a new
/// task), or under its old rq lock while queued (a migration)
fn set_task_cpu(p: &Task, cpu: u32) {
    p.wake_cpu.store(cpu, Ordering::Relaxed);
    p.cpu.store(cpu, Ordering::Release);
}

/// The class of SCHED_* `policy` (Linux __setscheduler_class)
pub(super) fn policy_class(policy: i32) -> Class {
    if crate::task::is_rt_policy(policy) {
        Class::Rt
    } else {
        Class::Fair
    }
}

/// A kernel thread's class from its creator's priority hint: the idle
/// task, the stoppers (Linux sched_set_stop_task, shown as FIFO 99),
/// SCHED_FIFO 1 for the high ones (`ktimers/N`, as Linux PREEMPT_RT
/// ktimers), SCHED_NORMAL nice -20 for the highpri workqueue workers,
/// the rest SCHED_NORMAL nice 0
fn set_kthread_class(se: &sched::SchedEntity, prio: Priority) {
    use crate::task::{
        PRIORITY_HIGH, PRIORITY_NICE_MIN, PRIORITY_REALTIME, SCHED_FIFO, SCHED_NORMAL,
    };
    let d = sched::DEFAULT_PRIO;
    match prio {
        PRIORITY_IDLE => se.set_params(Class::Idle, SCHED_NORMAL, d, 0),
        PRIORITY_REALTIME => se.set_params(Class::Stop, SCHED_FIFO, d, 99),
        PRIORITY_HIGH => se.set_params(Class::Rt, SCHED_FIFO, d, 1),
        PRIORITY_NICE_MIN => se.set_params(Class::Fair, SCHED_NORMAL, d - 20, 0),
        _ => se.set_params(Class::Fair, SCHED_NORMAL, d, 0),
    }
}

/// Why a CPU is being chosen (Linux WF_TTWU / WF_FORK)
#[derive(Clone, Copy, PartialEq, Eq)]
enum Placement {
    Wake,
    Fork,
}

/// CPUs that run a scheduler and take IPIs (Linux cpu_active_mask):
/// kept as each becomes active and gets its scheduler, read by every
/// wakeup and balancing pass
static SCHED_CPUS: crate::util::cpumask::CpuMask = crate::util::cpumask::CpuMask::new();

fn sched_cpus() -> crate::util::cpumask::CpuSet {
    let s = SCHED_CPUS.snapshot();
    // Pairs with `sched_cpu_update`: a CPU found here has its run queue
    core::sync::atomic::fence(Ordering::Acquire);
    s
}

/// `cpu` became active or got its scheduler: in `sched_cpus` once both
pub fn sched_cpu_update(cpu: u32) {
    if crate::smp::active_cpus().test(cpu) && cpu_has_scheduler(cpu) {
        core::sync::atomic::fence(Ordering::Release);
        SCHED_CPUS.set(cpu);
    }
}

/// Linux p->prio: 99 - rt_priority for an rt task, else static_prio
/// (lower is more important)
fn prio(se: &sched::SchedEntity) -> i32 {
    match se.class() {
        Class::Rt | Class::Stop => 99 - i32::from(se.rt_priority()),
        _ => i32::from(se.static_prio()),
    }
}

/// How important `p` is to keep running, for rt placement (Linux
/// cpupri): idle 0, fair 1, rt 2 + its priority, stop above all
fn rank(p: &Task) -> u32 {
    match p.se.class() {
        Class::Idle => 0,
        Class::Fair => 1,
        Class::Rt => 2 + u32::from(p.se.rt_priority()),
        Class::Stop => 200,
    }
}

/// An rt task's CPU (Linux select_task_rq_rt / find_lowest_rq): its
/// previous one if it would preempt what runs there, else the allowed
/// CPU running the least important task if `p` would preempt that,
/// else its previous one
fn select_task_rq_rt(p: &Task, allowed: &crate::util::cpumask::CpuSet, prev: u32) -> u32 {
    let r = rank(p);
    let at = |c: u32| PERCPU_SCHEDS.get(c).curr_rank.load(Ordering::Relaxed);
    if allowed.test(prev) && at(prev) < r {
        return prev;
    }
    let lowest = allowed.iter().min_by_key(|&c| (at(c), c != prev));
    match lowest {
        Some(c) if at(c) < r => c,
        _ if allowed.test(prev) => prev,
        _ => find_idlest_cpu(allowed, prev),
    }
}

/// CPU `cpu` has nothing to run but its idle task (Linux idle_cpu)
fn idle_cpu(cpu: u32) -> bool {
    PERCPU_SCHEDS.get(cpu).nr_running.load(Ordering::Relaxed) == 0
}

/// The CPU to run `p` on (Linux select_task_rq): one it may run on, as
/// idle as possible. All CPUs form one domain (one LLC), so Linux's
/// domain walk reduces to a scan; a task that may run nowhere active
/// stays where it is.
fn select_task_rq(p: &Task, why: Placement) -> u32 {
    let prev = p.wake_cpu.load(Ordering::Relaxed);
    let allowed = p.cpus_mask.snapshot().and(&sched_cpus());
    if allowed.is_empty() {
        return prev;
    }
    if p.se.class() == Class::Rt && why == Placement::Wake {
        return select_task_rq_rt(p, &allowed, prev);
    }
    match why {
        Placement::Fork => find_idlest_cpu(&allowed, crate::cpu::this_id()),
        Placement::Wake => select_idle_sibling(&allowed, prev),
    }
}

/// The allowed CPU with the fewest tasks, the first found from `from`
/// on (Linux sched_balance_find_dst_cpu, without groups or idle states)
fn find_idlest_cpu(allowed: &crate::util::cpumask::CpuSet, from: u32) -> u32 {
    let n = crate::cpu::nr_cpu_ids();
    let mut best = (u32::MAX, from);
    for i in 0..n {
        let cpu = (from + i) % n;
        if allowed.test(cpu) {
            let nr = PERCPU_SCHEDS.get(cpu).nr_running.load(Ordering::Relaxed);
            if nr < best.0 {
                best = (nr, cpu);
            }
        }
    }
    best.1
}

/// A waking task's CPU (Linux select_idle_sibling, wake_affine left
/// out): its previous one if idle (warm cache), else an idle one, else
/// its previous one, else the least loaded
fn select_idle_sibling(allowed: &crate::util::cpumask::CpuSet, prev: u32) -> u32 {
    if allowed.test(prev) && idle_cpu(prev) {
        return prev;
    }
    let n = crate::cpu::nr_cpu_ids();
    for i in 1..n {
        let cpu = (prev + i) % n;
        if allowed.test(cpu) && idle_cpu(cpu) {
            return cpu;
        }
    }
    if allowed.test(prev) {
        return prev;
    }
    find_idlest_cpu(allowed, prev)
}

/// Wake `p` if it sleeps in a state `mode` ends (Linux try_to_wake_up)
///
/// Any context, including IRQ handlers, but never with an rq lock held.
/// Under `p.pi_lock` (which serializes its wakers):
/// - still on its run queue (it has not switched out, checked under
///   that rq lock): set Running, which its `schedule()` sees (Linux
///   ttwu_runnable);
/// - else wait until its CPU is off its stack (`on_cpu`), choose a CPU
///   (`select_task_rq`) and activate it under that CPU's rq lock (Linux
///   ttwu_queue), interrupting the CPU if it should preempt.
///
/// Returns true if `p` was asleep.
///
/// The sleeper sets its state, then checks its condition; the waker
/// makes the condition true, then reads the state: each side's store
/// comes before its load (full barriers), so one of them sees the
/// other's (no lost wakeup).
pub fn try_to_wake_up(p: &Task, mode: WakeMode) -> bool {
    let _pi = p.pi_lock.lock();
    // Order the caller's condition store before the state load (Linux
    // smp_mb__after_spinlock)
    core::sync::atomic::fence(Ordering::SeqCst);
    if !mode.wakes(p.se.state()) {
        return false;
    }
    if !cpu_has_scheduler(p.cpu()) {
        return false;
    }
    {
        let _rq = task_rq_lock(p);
        if p.se.on_rq() {
            p.se.set_state(RUNNING);
            return true;
        }
    }
    // Its CPU may still be switching away from it (Linux
    // smp_cond_load_acquire(&p->on_cpu, !VAL)): not runnable elsewhere
    // until that is done. The switch runs with interrupts off, so this
    // CPU is never the one being waited for.
    while p.se.on_cpu() {
        core::hint::spin_loop();
    }
    let cpu = select_task_rq(p, Placement::Wake);
    set_task_cpu(p, cpu);
    get_percpu_sched(cpu).lock.lock().activate(p);
    true
}

/// Most tasks one balancing pass moves (Linux sysctl_sched_nr_migrate)
const NR_MIGRATE: usize = 32;

/// Two run queues locked lowest CPU first (Linux double_rq_lock),
/// released in reverse: each guard restores the interrupt state it
/// found, so the second lock's (interrupts off) goes first and the
/// first lock's turns them back on once both are free
struct DoubleRq {
    /// Taken second: fields drop in declaration order
    inner: crate::sync::IrqSpinlockGuard<'static, CpuRunQueue>,
    outer: crate::sync::IrqSpinlockGuard<'static, CpuRunQueue>,
    /// `outer` is `b`'s
    swapped: bool,
}

impl DoubleRq {
    /// The run queues of `a` and `b`, in that order
    fn split(&mut self) -> (&mut CpuRunQueue, &mut CpuRunQueue) {
        if self.swapped {
            (&mut self.inner, &mut self.outer)
        } else {
            (&mut self.outer, &mut self.inner)
        }
    }
}

/// Lock the run queues of CPUs `a` and `b` (different), lowest CPU
/// first (Linux double_rq_lock)
fn double_rq_lock(a: u32, b: u32) -> DoubleRq {
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let outer = get_percpu_sched(lo).lock.lock();
    DoubleRq {
        inner: get_percpu_sched(hi).lock.lock(),
        outer,
        swapped: a > b,
    }
}

/// Runnable tasks on every CPU (Linux nr_running())
pub fn nr_running_all() -> u32 {
    (0..crate::cpu::nr_cpu_ids())
        .filter_map(|c| PERCPU_SCHEDS.try_get(c))
        .map(|s| s.nr_running.load(Ordering::Relaxed))
        .sum()
}

/// Tasks counting in the load: runnable, or asleep uninterruptibly
/// (Linux calc_load_fold_active, summed at once)
pub fn nr_active() -> u64 {
    let unint: i64 = (0..crate::cpu::nr_cpu_ids())
        .filter_map(|c| PERCPU_SCHEDS.try_get(c))
        .map(|s| s.nr_uninterruptible.load(Ordering::Relaxed))
        .sum();
    u64::from(nr_running_all()) + unint.max(0) as u64
}

/// `cpu`'s load for balancing: its task count, one more while an rt or
/// stop task runs there, which keeps the tasks queued behind it from
/// running (Linux lowers such a CPU's capacity, scale_rt_capacity)
fn balance_load(cpu: u32) -> u32 {
    let s = PERCPU_SCHEDS.get(cpu);
    s.nr_running.load(Ordering::Relaxed) + u32::from(s.curr_rank.load(Ordering::Relaxed) > 1)
}

/// Pull queued tasks from the busiest CPU to `this` until the two are
/// within one task of each other (Linux sched_balance_rq: one flat
/// domain, the task count as the load, no cache-hot or active
/// balancing). A task moves only to a CPU its mask allows; the running
/// ones stay. Any context, no rq lock held.
fn sched_balance_rq(this: u32) {
    let cpus = sched_cpus();
    if !cpus.test(this) {
        return;
    }
    let (mut busiest, mut max) = (this, 0);
    for c in cpus.iter() {
        let n = balance_load(c);
        // Something queued to pull (Linux: busiest->nr_running > 1)
        let queued = PERCPU_SCHEDS.get(c).nr_running.load(Ordering::Relaxed) > 1;
        if c != this && queued && n > max {
            (busiest, max) = (c, n);
        }
    }
    if busiest == this || max <= balance_load(this) + 1 {
        return;
    }
    let mut rqs = double_rq_lock(busiest, this);
    let (src, dst) = rqs.split();
    let (sn, dn) = (balance_load(busiest), balance_load(this));
    if sn <= dn + 1 {
        return;
    }
    let mut moved = [core::ptr::null::<Task>(); NR_MIGRATE];
    let want = (((sn - dn) / 2) as usize).clamp(1, NR_MIGRATE);
    // Queued rt tasks, then fair ones: the running one and idle are on
    // no list
    let mut n = 0;
    while n < want {
        // Its lag on the old queue, measured before it leaves (Linux
        // update_entity_lag at dequeue; migrate_task_rq_fair keeps it)
        let avg = src.fair_avg(true);
        let one = src.queue().take(&mut moved[n..n + 1], |t| {
            // SAFETY: on this run queue's list, kept alive by the scheduler
            unsafe { &*t }.cpus_mask.test(this)
        });
        if one == 0 {
            break;
        }
        // SAFETY: as above
        src.save_lag_at(unsafe { &*moved[n] }, avg);
        n += 1;
    }
    for &t in &moved[..n] {
        // SAFETY: as above
        let p = unsafe { &*t };
        src.add_nr(-1);
        set_task_cpu(p, this);
        dst.place_fair(p, false);
        dst.add_nr(1);
        dst.enqueue(p);
        dst.check_preempt(p);
    }
}

/// The tick's balancing (Linux sched_balance_trigger): an idle CPU
/// every tick, a busy one every 8
fn balance_tick(cpu: u32) {
    let interval = if idle_cpu(cpu) { 1 } else { 8 };
    // This CPU's tick count, written only by its tick
    let ticks = &PERCPU_SCHEDS.get(cpu).ticks;
    let t = ticks.load(Ordering::Relaxed);
    ticks.store(t.wrapping_add(1), Ordering::Relaxed);
    if t.is_multiple_of(interval) {
        sched_balance_rq(cpu);
    }
}

/// A task to move and where (`migration_cpu_stop`'s argument)
struct Migration<'a> {
    task: &'a Task,
    dest: u32,
}

/// On the stopper of the task's CPU (Linux migration_cpu_stop): move
/// it to `dest` if it is still on this CPU's run queue. Nothing of this
/// CPU runs meanwhile, so a task on it is queued, not running. One that
/// sleeps (it moved meanwhile, or it is the caller waiting for this)
/// wakes on `dest` if it can (its `wake_cpu`).
fn migration_cpu_stop(m: &Migration<'_>) {
    let p = m.task;
    let _pi = p.pi_lock.lock();
    let Some(sched) = this_sched() else { return };
    let rq = sched.lock.lock();
    if p.cpu() != rq.cpu || !p.cpus_mask.test(m.dest) {
        return;
    }
    if p.se.on_rq() && !core::ptr::eq(rq.curr, m.task) {
        move_queued_task(rq, p, m.dest);
    } else if !p.se.on_rq() {
        p.wake_cpu.store(m.dest, Ordering::Relaxed);
    }
}

/// Move queued `p` from the run queue `rq` (locked, its CPU's) to
/// `dest`'s (Linux move_queued_task), its pi_lock held: off one list,
/// on the other, the two locks one after the other. In between it is on
/// no list while `on_rq`: everything that touches a queued task on its
/// run queue holds its pi_lock or found it on that list.
fn move_queued_task(mut rq: crate::sync::IrqSpinlockGuard<'_, CpuRunQueue>, p: &Task, dest: u32) {
    rq.save_lag(p);
    rq.dequeue(p);
    rq.add_nr(-1);
    set_task_cpu(p, dest);
    drop(rq);
    let mut d = get_percpu_sched(dest).lock.lock();
    d.place_fair(p, false);
    d.add_nr(1);
    d.enqueue(p);
    d.check_preempt(p);
}

/// Restrict `p` to `mask` (Linux __set_cpus_allowed_ptr ->
/// affine_move_task): written under its pi_lock and rq lock; if it runs
/// or is queued on a CPU it may no longer use, that CPU's stopper moves
/// it (the caller sleeps meanwhile, which for a task restricting itself
/// is what lets the stopper find it off the CPU). EINVAL if no active
/// CPU is in `mask`.
pub fn set_cpus_allowed_ptr(p: &Task, mask: &crate::util::cpumask::CpuSet) -> KernelResult<()> {
    let allowed = mask.and(&sched_cpus());
    if mask.and(&crate::smp::active_cpus()).is_empty() {
        return Err(KernelError::InvalidArgument);
    }
    let (cpu, dest) = {
        let _pi = p.pi_lock.lock();
        if !cpu_has_scheduler(p.cpu()) {
            p.cpus_mask.assign(mask);
            return Ok(());
        }
        let _rq = task_rq_lock(p);
        p.cpus_mask.assign(mask);
        let cpu = p.cpu();
        if mask.test(cpu) || !p.se.on_rq() || allowed.is_empty() {
            return Ok(());
        }
        (cpu, find_idlest_cpu(&allowed, cpu))
    };
    let m = Migration { task: p, dest };
    crate::task::stop_machine::stop_one_cpu_ref(cpu, migration_cpu_stop, &m);
    Ok(())
}

/// At exec, move to the least loaded allowed CPU if that is another
/// one (Linux sched_exec: the image is small and the cache cold)
pub fn sched_exec() {
    let me = current();
    let this = crate::cpu::this_id();
    let dest = {
        let _pi = me.pi_lock.lock();
        let allowed = me.cpus_mask.snapshot().and(&sched_cpus());
        if allowed.is_empty() {
            return;
        }
        find_idlest_cpu(&allowed, this)
    };
    if dest == this {
        return;
    }
    let m = Migration { task: &me, dest };
    crate::task::stop_machine::stop_one_cpu_ref(this, migration_cpu_stop, &m);
}

/// Wait until `p`, asleep, is off its CPU (Linux wait_task_inactive):
/// what its switch-out saves (user TLS, GS base, FP state) is complete
/// once its CPU has cleared `on_cpu`, which takes no longer than the
/// rest of a context switch. False if it woke meanwhile.
pub fn wait_task_inactive(p: &Task) -> bool {
    while p.se.on_cpu() {
        if p.se.state() == RUNNING {
            return false;
        }
        core::hint::spin_loop();
    }
    p.se.state() != RUNNING
}

/// Make a task running on another CPU notice new work flags (a signal)
/// soon: a reschedule IPI interrupts it, and its return to user mode
/// runs the work (Linux kick_process). Nothing to do for a task on this
/// CPU (it is the caller, or not running) or not running at all.
pub fn kick_process(t: &Task) {
    let cpu = t.cpu();
    let running = CurrentArch::current_task_ptr_of(cpu) == core::ptr::from_ref::<Task>(t) as usize;
    if running && crate::cpu::try_this_id() != Some(cpu) {
        crate::smp::smp_send_reschedule(cpu);
    }
}

/// Scheduler tick period (each CPU's tick is a HARD hrtimer re-armed
/// every TICK_NS: `hrtimer::tick_fire`)
pub const TICK_MS: u64 = 10;
/// Scheduler tick period in nanoseconds
pub const TICK_NS: u64 = TICK_MS * 1_000_000;

/// Convert milliseconds to ticks, rounding up
pub fn ms_to_ticks(ms: u64) -> u64 {
    ms.div_ceil(TICK_MS)
}

/// Convert nanoseconds to ticks, rounding up
pub fn ns_to_ticks(ns: u64) -> u64 {
    ns.div_ceil(TICK_NS)
}

/// Per-CPU timer tick (IRQ context, every CPU)
///
/// Every CPU's tick hrtimer fires every TICK_MS, so only CPU 0 advances
/// the global tick count (jiffies). All CPUs then run their own timers
/// (HARD callbacks run here, `ktimers/N` is woken for SOFT ones), and
/// the running task's slice (one tick,
/// round robin within a priority) is used up: TIF_NEED_RESCHED, acted
/// on at its next return to user mode (`entry::exit_to_user_mode`;
/// Linux scheduler_tick -> resched_curr).
pub fn scheduler_tick() {
    if crate::cpu::try_this_id() == Some(0) {
        // CPU 0's tick alone writes it (Linux jiffies on the do_timer
        // CPU)
        let t = TICK_COUNT.load(Ordering::Relaxed).wrapping_add(1);
        TICK_COUNT.store(t, Ordering::Relaxed);
        crate::task::loadavg::tick(t);
    }
    crate::time::timer::run_local();
    crate::mm::vmstat::tick();
    crate::time::watchdog::tick();
    crate::kmsg::tick();
    crate::console::tick();
    if let Some(cpu) = crate::cpu::try_this_id() {
        balance_tick(cpu);
    }
    // The running task's slice (Linux task_tick of its class): fair and
    // idle one tick, SCHED_RR its RR_TICKS, SCHED_FIFO and the stoppers
    // none (they run until they block or something higher wakes)
    // rt and fair tasks are charged under the rq lock, rt time against
    // the CPU's rt runtime (`rt_tick`, `rt_period_tick`)
    let me = current();
    let now = crate::time::monotonic_ns();
    // The tick's sample of the task it interrupted, user or system
    // time (Linux update_process_times -> account_process_tick)
    crate::task::cputime::account_process_tick(&me, CurrentArch::irq_from_user());
    let resched = match me.se.class() {
        Class::Stop => false,
        // Under the rq lock (Linux scheduler_tick -> task_tick_rt)
        Class::Rt => this_sched().is_some_and(|s| {
            let mut rq = s.lock.lock();
            let rr = me.se.policy() == crate::task::SCHED_RR && rq.with_ent(&me, SeRq::rr_tick);
            rr | rq.rt_tick(now)
        }),
        // A used-up slice (new deadline) lets EEVDF pick again (Linux
        // task_tick_fair -> update_deadline)
        Class::Fair => this_sched().is_some_and(|s| {
            let mut rq = s.lock.lock();
            rq.update_curr(now) | rq.rt_period_tick(now)
        }),
        Class::Idle => true,
    };
    if resched {
        me.set_tif(crate::task::tif::NEED_RESCHED);
    }
    // Its CPU timers, on the samples and runtime charged above (Linux
    // run_posix_cpu_timers after sched_tick)
    if me.tid() != 0 {
        crate::time::cpu_timer::tick(&me);
    }
}

/// Get current tick count
pub fn get_ticks() -> u64 {
    TICK_COUNT.load(Ordering::Relaxed)
}

/// Sleep until CLOCK_MONOTONIC reaches `deadline_ns` (see [`sleep_until`])
pub fn sleep_until_ns(deadline_ns: u64, interruptible: bool) -> Result<(), u64> {
    sleep_until(
        deadline_ns,
        crate::time::hrtimer::HrClock::Monotonic,
        interruptible,
    )
}

/// Sleep until `clock` reaches `deadline` ns (Linux hrtimer_nanosleep)
///
/// Interruptible sleeps stop early when a signal is pending and return
/// `Err(ns_left)`. ns-precise (an hrtimer), never before the deadline;
/// an absolute CLOCK_REALTIME deadline follows clock steps.
pub fn sleep_until(
    deadline: u64,
    clock: crate::time::hrtimer::HrClock,
    interruptible: bool,
) -> Result<(), u64> {
    let state = if interruptible {
        SleepState::Interruptible
    } else {
        SleepState::Uninterruptible
    };
    loop {
        set_current_state(state);
        let now = clock.now();
        if now >= deadline {
            set_current_state(SleepState::Running);
            return Ok(());
        }
        if interruptible && crate::sync::waitqueue::signal_pending_run_work() {
            set_current_state(SleepState::Running);
            return Err(deadline - now);
        }
        if this_sched().is_none() || current_tid() == 0 {
            set_current_state(SleepState::Running);
            core::hint::spin_loop();
            continue;
        }
        crate::time::hrtimer::schedule_hrtimeout(Some(deadline), clock);
    }
}

/// Sleep the current task (uninterruptibly) for at least `ms` milliseconds
pub fn sleep_current_ms(ms: u64) {
    sleep_current_until(get_ticks().saturating_add(ms_to_ticks(ms)));
}

/// First run of a task (the arch's new-task trampoline): complete the
/// switch to it (Linux schedule_tail -> finish_task_switch). Interrupts
/// stay disabled; the trampoline enables them.
pub fn finish_context_switch() {
    let Some(sched) = current_percpu_sched() else {
        return;
    };
    // SAFETY: the switch handed this CPU's rq lock to the new task
    finish_task_switch(unsafe { sched.lock.assume_held() });
}

/// Write the child TID for CLONE_CHILD_SETTID (from the fork child's
/// first return: clone_child_entry / ret_from_fork)
///
/// This is called in the child's context after its page table is loaded,
/// specifically for fork (non-CLONE_VM) where we couldn't write at clone time.
/// For threads (CLONE_VM), the TID was already written in do_clone().
#[unsafe(no_mangle)]
pub extern "C" fn write_child_tid_if_needed() {
    let me = current();
    if me.tid() == 0 {
        return;
    }
    if let Some(addr) = crate::task::get_set_child_tid(&me) {
        use crate::uaccess::put_user;
        // Its own number, in its namespace (Linux schedule_tail:
        // task_pid_vnr(current))
        let nr = crate::task::pid::vnr(me.tid()) as i32;
        if put_user::<i32>(addr, nr).is_err() {
            printkln!("CLONE: CLONE_CHILD_SETTID write failed in child");
        }
    }
}

/// Put current task to sleep (uninterruptibly) until the specified tick
pub fn sleep_current_until(wake_tick: u64) {
    if this_sched().is_none() || current_tid() == 0 {
        // Early boot / no task: busy-wait with interrupts enabled
        CurrentArch::enable_interrupts();
        while get_ticks() < wake_tick {
            core::hint::spin_loop();
        }
        return;
    }
    loop {
        set_current_state(SleepState::Uninterruptible);
        let now = get_ticks();
        if now >= wake_tick {
            set_current_state(SleepState::Running);
            return;
        }
        schedule_timeout(wake_tick - now);
    }
}

/// Yield the current thread (cooperative scheduling)
///
/// The current thread stays runnable and goes to the back of its priority
/// queue; another runnable thread (if any) gets to run.
pub fn yield_now() {
    yield_cpu(false);
}

/// A scheduling point in a long kernel loop (Linux cond_resched): yield
/// only if this task's slice is used up (TIF_NEED_RESCHED)
pub fn cond_resched() {
    if current().has_tif(crate::task::tif::NEED_RESCHED) {
        yield_cpu(true);
    }
}

/// Give up the CPU on the way back to user mode, the slice used up
/// (TIF_NEED_RESCHED; Linux schedule() in exit_to_user_mode_loop): like
/// `yield_now`, an involuntary switch if another task runs
pub fn preempt_schedule_user() {
    if yield_cpu(true) {
        crate::sync::Sole::sole_add(&current().nivcsw, 1);
    }
}

/// Switch to the next task if there is one, staying runnable: true if
/// another task ran meanwhile. `preempted`: a preemption (NEED_RESCHED),
/// not sched_yield, so an rt task keeps its place (`enqueue_prev`)
fn yield_cpu(preempted: bool) -> bool {
    crate::sync::might_sleep();
    let Some(sched) = this_sched() else {
        return false;
    };
    let me = current();
    me.clear_tif(crate::task::tif::NEED_RESCHED);
    let mut rq = sched.lock.lock();
    if rq.curr.is_null() {
        return false;
    }
    // Back on its class's list, a fair task charged first (and a
    // sched_yield moves its deadline on); the idle task is never queued
    me.se.set_state(RUNNING);
    if !rq.curr_is_idle() {
        rq.update_curr(crate::time::monotonic_ns());
        if me.se.class() == Class::Fair && !preempted {
            rq.with_ent(&me, |e| crate::task::fair::yield_task(&me.se, e));
        }
        rq.enqueue_prev(&me, preempted);
    }
    let next = rq.pick_next();
    if core::ptr::eq(next, &raw const *me) {
        return false;
    }
    context_switch_locked(sched, rq, &me, next);
    true
}

/// Get the current task's process ID
pub fn current_pid() -> Pid {
    current().pid
}

/// The current task's pid namespace (Linux task_active_pid_ns(current)):
/// a creation-time field, read lock-free; it outlives the task's every
/// syscall like `current()` itself
pub fn current_pid_ns() -> &'static crate::ns::PidNamespace {
    current().task.pid_ns()
}

/// Get the current task's thread ID
pub fn current_tid() -> Tid {
    current().tid()
}

/// The current task's parent process as its pid namespace numbers it,
/// 0 for none or one outside it (Linux
/// task_tgid_vnr(rcu_dereference(current->real_parent))): the parent
/// link and the parent's group pid read under RCU, no lock, no
/// reference
pub fn current_ppid_vnr() -> u32 {
    let me = current();
    let g = crate::sync::rcu::read_lock();
    me.task
        .parent(&g)
        .map_or(0, |p| p.tgid_nr_ns(me.task.pid_ns(), &g))
}

/// The current task's process group (root number), 0 for none (Linux
/// pid_nr(task_pgrp(current))), read under RCU
pub fn current_pgid() -> Pid {
    current().task.pgid(&crate::sync::rcu::read_lock())
}

/// The current task's process group as its pid namespace numbers it, 0
/// for none or one outside it (Linux pid_vnr(task_pgrp(current))),
/// read under RCU
pub fn current_pgid_vnr() -> u32 {
    let me = current();
    let g = crate::sync::rcu::read_lock();
    me.task
        .pgrp_rcu(&g)
        .map_or(0, |p| p.nr_ns(me.task.pid_ns()))
}

/// The current task's session (root number), 0 for none (Linux
/// pid_nr(task_session(current))), read under RCU
pub fn current_sid() -> Pid {
    current().task.sid(&crate::sync::rcu::read_lock())
}

/// The current task's session as its pid namespace numbers it, 0 for
/// none or one outside it (Linux pid_vnr(task_session(current))), read
/// under RCU
pub fn current_sid_vnr() -> u32 {
    let me = current();
    let g = crate::sync::rcu::read_lock();
    me.task
        .session_rcu(&g)
        .map_or(0, |p| p.nr_ns(me.task.pid_ns()))
}

/// Increment minor page fault counter for current task
///
/// Called after successfully handling a demand-paging or COW fault
/// (no I/O required - page was already in memory or newly allocated).
pub fn increment_min_flt() {
    // The task's own counter (Linux current->min_flt++)
    crate::sync::Sole::sole_add(&current().min_flt, 1);
}

/// Increment major page fault counter for current task
///
/// Called after successfully handling a swap-in fault
/// (I/O was required - page had to be read from disk).
pub fn increment_maj_flt() {
    crate::sync::Sole::sole_add(&current().maj_flt, 1);
}

/// Get all unique PIDs in the system
///
/// Returns a sorted, deduplicated list of all process IDs.
/// Used by kill(-1, sig) to signal all processes.
pub fn get_all_pids() -> alloc::vec::Vec<Pid> {
    let mut pids = GlobalTaskTable::collect_tasks(|_, t| Some(t.task.pid));
    pids.sort();
    pids.dedup();
    pids
}

/// Get the current task's FsStruct (filesystem context)
///
/// Returns None if there is no current task or no filesystem context.
pub fn current_fs() -> Option<alloc::sync::Arc<crate::fs::FsStruct>> {
    let me = current();
    if me.tid() == 0 {
        return None;
    }
    me.fs().or_else(|| crate::fs::fsstruct::kthread_fs(&me))
}

/// Get the current task's current working directory
///
/// Returns None if there is no current task or no filesystem context.
pub fn current_cwd() -> Option<crate::fs::Path> {
    current_fs().map(|fs| fs.get_pwd())
}

/// The current task's credentials, copied (Linux current_cred; the
/// boot task's are root)
pub fn current_cred() -> crate::task::Cred {
    current().cred()
}

/// Task `t`'s nice value; None once it is reaped
pub fn lookup_task_nice(t: &Task) -> Option<i32> {
    let table = TASKLIST.read();
    table.view(t).map(|t| t.task.se.nice())
}

/// Task `t`'s scheduling policy, with SCHED_RESET_ON_FORK if set; None
/// once it is reaped
pub fn lookup_task_policy(t: &Task) -> Option<i32> {
    let table = TASKLIST.read();
    table.view(t).map(|t| {
        let mut policy = t.task.se.policy();
        if t.task.se.reset_on_fork() {
            policy |= crate::task::SCHED_RESET_ON_FORK;
        }
        policy
    })
}

/// Task `t`'s real-time priority (0 for SCHED_NORMAL); None once it is
/// reaped
pub fn lookup_task_rt_priority(t: &Task) -> Option<i32> {
    let table = TASKLIST.read();
    table.view(t).map(|t| i32::from(t.task.se.rt_priority()))
}

/// Task `t`'s (utime_ns, stime_ns), adjusted (Linux
/// task_cputime_adjusted); (0, 0) once it is reaped
pub fn get_task_times(t: &Task) -> (u64, u64) {
    let table = TASKLIST.read();
    table.view(t).map_or((0, 0), |t| {
        crate::task::cputime::task_cputime_adjusted(t.task)
    })
}

/// Process `pid`'s (utime_ns, stime_ns), adjusted (Linux
/// thread_group_cputime_adjusted)
pub fn get_process_times(pid: Pid) -> (u64, u64) {
    let table = TASKLIST.read();
    crate::task::cputime::thread_group_cputime_adjusted(&table, pid)
}

/// User and system time, ns
pub type Times = (u64, u64);

/// Process `pid`'s user and system time with its reaped children's,
/// TASKLIST held (Linux getrusage(p, RUSAGE_BOTH): a wait's rusage for a
/// stopped, continued or ptrace-stopped child, wait_task_stopped and
/// wait_task_continued)
pub fn rusage_both(table: &GlobalTaskTable, pid: Pid) -> Times {
    let ((u, s), sig) = crate::task::cputime::group_adjusted(table, pid);
    let (cu, cs) = sig.map_or((0, 0), |g| g.child_times());
    (u.saturating_add(cu), s.saturating_add(cs))
}

/// The calling process's children's CPU time (cutime, cstime)
pub fn children_times() -> (u64, u64) {
    let table = TASKLIST.read();
    table
        .view(&current())
        .and_then(|t| t.signal().cloned())
        .map_or((0, 0), |s| s.child_times())
}

/// Task `t`'s CPU affinity mask; None once it is reaped
pub fn lookup_task_cpus_allowed(t: &Task) -> Option<crate::util::cpumask::CpuSet> {
    let table = TASKLIST.read();
    table.view(t).map(|t| t.task.cpus_mask.snapshot())
}

/// ESRCH once task `t` is reaped
fn esrch_if_reaped(t: &Task) -> KernelResult<()> {
    match TASKLIST.read().view(t) {
        Some(_) => Ok(()),
        None => Err(KernelError::NoProcess),
    }
}

/// Set task `t`'s scheduling policy and priority
///
/// This is the core implementation for sched_setscheduler/sched_setparam.
///
/// # Arguments
/// * `task` - Target task
/// * `policy` - New scheduling policy (may include SCHED_RESET_ON_FORK flag)
/// * `rt_priority` - New real-time priority (1-99 for SCHED_FIFO/RR, 0 otherwise)
///
/// # Errors
/// ESRCH: process not found; EINVAL: invalid policy or priority
///
/// # Locking
/// The task's pi_lock and rq lock (`change_class`): a queued task moves
/// to its new class's list at once.
pub fn set_task_scheduler(task: &Task, policy: i32, rt_priority: i32) -> KernelResult<()> {
    use crate::task::{
        MAX_RT_PRIO, MIN_RT_PRIO, SCHED_BATCH, SCHED_FIFO, SCHED_IDLE, SCHED_NORMAL,
        SCHED_RESET_ON_FORK, SCHED_RR, is_rt_policy,
    };

    // Extract SCHED_RESET_ON_FORK flag
    let reset_on_fork = (policy & SCHED_RESET_ON_FORK) != 0;
    let base_policy = policy & !SCHED_RESET_ON_FORK;

    // Validate policy
    if !matches!(
        base_policy,
        SCHED_NORMAL | SCHED_FIFO | SCHED_RR | SCHED_BATCH | SCHED_IDLE
    ) {
        return Err(KernelError::InvalidArgument);
    }

    // Validate rt_priority
    if is_rt_policy(base_policy) {
        if !(MIN_RT_PRIO..=MAX_RT_PRIO).contains(&rt_priority) {
            return Err(KernelError::InvalidArgument);
        }
    } else if rt_priority != 0 {
        return Err(KernelError::InvalidArgument); // non-RT policies must have priority 0
    }

    esrch_if_reaped(task)?;
    // Not the stoppers nor an idle task (Linux: EINVAL for rq->stop)
    if matches!(task.se.class(), Class::Stop | Class::Idle) {
        return Err(KernelError::InvalidArgument);
    }
    // Nothing changes (Linux __sched_setscheduler: same policy and
    // priority only updates reset-on-fork)
    if base_policy == task.se.policy() && rt_priority == i32::from(task.se.rt_priority()) {
        task.se.set_reset_on_fork(reset_on_fork);
        return Ok(());
    }
    let static_prio = task.se.static_prio();
    change_class(task, |se| {
        se.set_params(
            policy_class(base_policy),
            base_policy,
            static_prio,
            rt_priority as u8,
        );
        se.set_reset_on_fork(reset_on_fork);
    });
    Ok(())
}

/// Set task `t`'s CPU affinity mask
///
/// # Arguments
/// * `t` - Target task
/// * `mask` - New CPU affinity mask (bit N = CPU N is allowed)
///
/// # Errors
/// ESRCH: task reaped; EINVAL: empty mask (no CPUs allowed)
///
/// # Locking
/// See [`set_cpus_allowed_ptr`]: a task on a CPU it may no longer use
/// is moved before this returns.
pub fn set_task_cpus_allowed(t: &Task, mask: crate::util::cpumask::CpuSet) -> KernelResult<()> {
    esrch_if_reaped(t)?;
    // Bound kernel threads (Linux sched_setaffinity: EINVAL)
    if t.has_flag(crate::task::pf::NO_SETAFFINITY) {
        return Err(KernelError::InvalidArgument);
    }
    set_cpus_allowed_ptr(t, &mask)
}

/// Get the total number of tasks in the system
///
/// This counts all tasks including zombies, used by sysinfo syscall.
/// Acquires TASKLIST lock briefly.
pub fn task_count() -> usize {
    let table = TASKLIST.read();
    table.len()
}

/// Set task `t`'s nice value (Linux set_user_nice: static_prio,
/// whatever its policy; it counts for the fair class)
///
/// ESRCH once it is reaped
pub fn set_task_nice(t: &Task, nice: i32) -> KernelResult<()> {
    esrch_if_reaped(t)?;
    let static_prio = (i32::from(sched::DEFAULT_PRIO) + nice.clamp(-20, 19)) as u8;
    change_class(t, |se| {
        se.set_params(se.class(), se.policy(), static_prio, se.rt_priority())
    });
    Ok(())
}

/// Change `p`'s scheduling class or parameters with `f` (Linux
/// __sched_setscheduler, set_user_nice: dequeue, change, enqueue under
/// its pi_lock and rq lock): a queued task moves to its new list and
/// may preempt; the running one reschedules, so the next pick sees the
/// change
fn change_class(p: &Task, f: impl FnOnce(&sched::SchedEntity)) {
    let _pi = p.pi_lock.lock();
    if !cpu_has_scheduler(p.cpu()) {
        f(&p.se);
        return;
    }
    let mut rq = task_rq_lock(p);
    let pp = core::ptr::from_ref::<Task>(p);
    let running = core::ptr::eq(rq.curr, pp);
    let queued = p.se.on_rq() && !running && !core::ptr::eq(rq.idle, pp);
    let (old, old_rt, old_prio) = (p.se.class(), p.se.rt_priority(), prio(&p.se));
    f(&p.se);
    let new_prio = prio(&p.se);
    // An rt task whose priority stays keeps its place (sched(7); Linux
    // set_user_nice leaves an rt task's queue position alone)
    if old == Class::Rt && p.se.class() == Class::Rt && old_prio == new_prio {
        return;
    }
    if queued {
        // SAFETY: queued on the list of its old class and priority
        unsafe { rq.queue().remove(p, old, old_rt) };
    }
    // Into the fair class: placed at the average (Linux switched_to_fair)
    if old != Class::Fair && p.se.class() == Class::Fair {
        rq.with_ent(p, |e| e.vlag = 0);
        rq.place_fair(p, false);
    }
    if queued {
        // Lowered: the head of its new level, else the tail (Linux
        // __sched_setscheduler ENQUEUE_HEAD)
        rq.enqueue_at(p, old_prio < new_prio);
        rq.check_preempt(p);
    } else if running {
        // Its CPU's rank follows now: it may run on without a switch
        // (Linux updates cpupri in __sched_setscheduler)
        get_percpu_sched(rq.cpu)
            .curr_rank
            .store(rank(p), Ordering::Relaxed);
        rq.resched_curr();
    }
}

/// Try to schedule a task on the current CPU
///
/// With a current task this is `yield_now()`. Without one (an AP still on
/// its boot stack) it switches into the scheduler for good.
pub fn try_schedule() {
    let Some(sched) = this_sched() else { return };
    if current().tid() != 0 {
        yield_now();
        return;
    }
    let mut rq = sched.lock.lock();
    let next = rq.pick_next();
    // The arch thread state while `current` is still the outgoing task
    // (Linux __switch_to: fpsimd_thread_switch)
    // SAFETY: interrupts off (the rq lock), the switch to `next`, a task
    // of this run queue (alive while it holds it, not running), follows
    unsafe { crate::arch::thread_switch(&*next) };
    // SAFETY: a task of this run queue, alive while it holds it
    let (next_kstack, next_mm, (next_tls, next_gs)) = make_current(&mut rq, unsafe { &*next });
    rq.curr = next;
    // Under the rq lock (Linux rq->nr_switches++)
    crate::sync::Sole::sole_add(&sched.nr_switches, 1);
    // Held across the switch like any other: the task switched to
    // releases it (finish_context_switch or its own guard). Dropping it
    // here left the per-CPU preempt count at -1 after that release.
    core::mem::forget(rq); // context_switch_first never returns
    unsafe {
        switch_mm(next_mm);
        CurrentArch::context_switch_first((*next).se.ctx(), next_kstack, next_tls, next_gs);
    }
}

// =============================================================================
// Personality accessors
// =============================================================================

/// Get the current task's personality value
///
/// Default is 0 (PER_LINUX).
pub fn get_current_personality() -> u32 {
    let table = TASKLIST.read();
    table.view(&current()).map_or(0, |t| t.personality)
}

/// Set the current task's personality value
pub fn set_current_personality(personality: u32) {
    let me = current();
    let mut table = TASKLIST.write();
    if let Some(mut task) = table.view_mut(&me) {
        task.personality = personality;
    }
}
