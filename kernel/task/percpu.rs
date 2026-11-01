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

use ::core::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::arch::{
    ContextOps, CpuOps, FrameAlloc, IrqSpinlock, PerCpuOps, SchedArch, UserModeOps, UserRegs,
};
use crate::cpu::PerCpu;
use crate::printkln;
use crate::sync::spin::RwLock;
use crate::task::sched::{self, Class, ClassQueues};
use crate::task::{Cred, PRIORITY_IDLE, Pid, Priority, Task, TaskKind, TaskState, Tid};

/// Clear the child TID and wake futex waiters
///
/// Called when a task exits if CLONE_CHILD_CLEARTID was set during clone.
/// This:
/// 1. Gets and clears the clear_child_tid address from the Task struct
/// 2. Writes 0 to that address
/// 3. Calls futex_wake on that address to wake pthread_join waiters
fn do_clear_child_tid(tid: Tid) {
    // Get and clear the address from the Task struct directly
    let addr = {
        let mut table = TASKLIST.write();
        if let Some(mut task) = table.get_mut(tid) {
            let addr = task.clear_child_tid;
            task.clear_child_tid = 0;
            if addr != 0 { Some(addr) } else { None }
        } else {
            None
        }
    };

    if let Some(addr) = addr {
        use crate::arch::Uaccess;
        use crate::uaccess::put_user;

        // Write 0 to the address
        if put_user::<Uaccess, i32>(addr, 0).is_ok() {
            // Wake up to 1 waiter on this futex address
            crate::futex::futex_wake(
                addr,
                1,
                crate::futex::futex_op::FUTEX_BITSET_MATCH_ANY,
                true, // private futex
            );
        }
    }
}

/// Signal vfork completion (Linux complete_vfork_done; the child, on
/// exec or exit): wakes the parent sleeping in `do_clone` on the
/// completion on its stack. The pointer is taken once, so the parent's
/// completion is touched at most once and only while it waits.
pub fn signal_vfork_done() {
    let p = current()
        .vfork_done
        .swap(core::ptr::null_mut(), Ordering::AcqRel);
    // SAFETY: set by the vforking parent, which waits (uninterruptibly)
    // until this completes it; `Completion` does not touch itself once
    // the waiter can return
    if let Some(c) = unsafe { p.as_ref() } {
        c.complete();
    }
}

// Architecture-specific type alias
// This allows the scheduler to be generic while still having a concrete type for statics
#[cfg(target_arch = "x86_64")]
type CurrentArch = crate::arch::x86_64::X86_64Arch;
#[cfg(target_arch = "aarch64")]
type CurrentArch = crate::arch::aarch64::Aarch64Arch;

// Re-export the architecture's TaskContext type for convenience
type TaskContext = <CurrentArch as ContextOps>::TaskContext;

/// Size of kernel stack per thread (16KB, with a guard gap below it:
/// `mm::vmstack`)
pub const KERNEL_STACK_SIZE: usize = crate::mm::vmstack::THREAD_SIZE;

// Re-export the architecture's page table type for convenience
type ArchPageTable = <CurrentArch as SchedArch>::SchedPageTable;

/// Configuration for creating a user task
///
/// Groups all parameters needed to create a user task, avoiding clippy's
/// too_many_arguments warning while keeping the API clear.
pub struct UserTaskConfig {
    /// Parent process ID
    pub ppid: Pid,
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

crate::adapter!(RunAdapter, KernelTask, se.link);

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
    curr: *const KernelTask,
    /// This CPU's idle task (Linux rq->idle): runs when nothing is
    /// queued; never queued, never asleep
    idle: *const KernelTask,
    /// The task that exited on this CPU, released once it has switched
    /// away from it (Linux finish_task_switch for TASK_DEAD); one at a
    /// time: the next task takes it before anything else runs
    dead: Option<DeadTask>,
    /// The task this CPU is switching away from (Linux switch_to's
    /// `last`): the task switched to clears its `on_cpu` once off its
    /// stack (`finish_task_switch`). Kept alive by the scheduler's
    /// reference, or by `dead`.
    prev: *const KernelTask,
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
    /// Kernel stack (`mm::vmstack` base) and size; size 0 = not owned
    stack: (u64, usize),
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
fn check_stack_usage(base: u64, size: usize) {
    // SAFETY: the dead task's stack, still owned and no longer in use
    let words = unsafe { core::slice::from_raw_parts(base as *const u64, size / 8) };
    let left = words.iter().position(|&w| w != 0).unwrap_or(words.len()) * 8;
    if left < STACK_MIN_LEFT {
        static REPORTED: AtomicBool = AtomicBool::new(false);
        if !REPORTED.swap(true, Ordering::Relaxed) {
            printkln!(
                "STACK:FAIL kernel stack nearly overflowed: {} of {} bytes left (need {})",
                left,
                size,
                STACK_MIN_LEFT
            );
        }
    }
}

impl Drop for DeadTask {
    fn drop(&mut self) {
        let (base, size) = self.stack;
        if size != 0 {
            check_stack_usage(base, size);
            crate::mm::vmstack::free(base);
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

    /// Put `p` (runnable, neither running nor queued) on its class's
    /// list (Linux enqueue_task)
    fn enqueue(&mut self, p: &KernelTask) {
        self.enqueue_at(p, false);
    }

    /// `enqueue` at the head of its level (`head`) or the tail
    fn enqueue_at(&mut self, p: &KernelTask, head: bool) {
        // SAFETY: the rq owns a reference to `p`; it is on no list
        unsafe { self.queue().push(p, p.se.class(), p.se.rt_priority(), head) };
    }

    /// Put the task switched away from back: an rt task preempted
    /// before its slice ran out keeps the head of its level (Linux
    /// put_prev_task_rt), anything else goes to the tail
    fn enqueue_prev(&mut self, p: &KernelTask, preempted: bool) {
        let expired = p.se.take_requeue_tail();
        self.enqueue_at(p, preempted && p.se.class() == Class::Rt && !expired);
    }

    /// Take queued `p` off its list (Linux dequeue_task)
    fn dequeue(&mut self, p: &KernelTask) {
        // SAFETY: queued, so on its class's list of this run queue
        unsafe { self.queue().remove(p, p.se.class(), p.se.rt_priority()) };
    }

    /// Make `p` runnable (Linux ttwu_do_activate): Running, and queued
    /// unless it still is on the run queue (running, or not yet switched
    /// out)
    fn activate(&mut self, p: &KernelTask) {
        p.se.set_state(RUNNING);
        if p.se.contrib_load.swap(false, Ordering::Relaxed) {
            PERCPU_SCHEDS
                .get(self.cpu)
                .nr_uninterruptible
                .fetch_sub(1, Ordering::Relaxed);
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
    fn check_preempt(&self, p: &KernelTask) {
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
    fn fair_wakeup_preempts(&self, p: &KernelTask, curr: &KernelTask) -> bool {
        use crate::task::{SCHED_BATCH, SCHED_IDLE};
        let (pp, cp) = (p.se.policy(), curr.se.policy());
        if pp == SCHED_BATCH || pp == SCHED_IDLE {
            return false;
        }
        if cp == SCHED_IDLE {
            return true;
        }
        crate::task::fair::update_curr(&curr.se, crate::time::monotonic_ns());
        let q = self.queue.as_ref().expect("run queue not initialized");
        let ents = q
            .fair_iter()
            .map(|t| (t as *const KernelTask, &t.se))
            .chain(self.curr_fair().map(|c| (c as *const KernelTask, &c.se)));
        crate::task::fair::pick(ents).is_some_and(|t| core::ptr::eq(t, p))
    }

    /// A task joined (+1) or left (-1) this run queue (Linux
    /// add_nr_running / sub_nr_running)
    fn add_nr(&self, d: i32) {
        PERCPU_SCHEDS
            .get(self.cpu)
            .nr_running
            .fetch_add(d as u32, Ordering::Relaxed);
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
    fn pick_next(&mut self) -> *const KernelTask {
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
    fn pick_fair(&mut self) -> Option<*const KernelTask> {
        let t = {
            let q = self.queue.as_ref().expect("run queue not initialized");
            crate::task::fair::pick(q.fair_iter().map(|t| (t as *const KernelTask, &t.se)))?
        };
        // SAFETY: on the fair list (just found there)
        unsafe { self.queue().remove(t, Class::Fair, 0) };
        // SAFETY: as above
        let v = unsafe { &*t }.se.vruntime.load(Ordering::Relaxed);
        self.min_vruntime = self.min_vruntime.max(v.min(self.fair_avg(false)));
        Some(t)
    }

    /// This CPU's rt tasks give way to its fair ones: their runtime in
    /// this period is used up and a fair task waits or runs (Linux
    /// rt_rq->rt_throttled; the fair server's rule that throttling
    /// never idles the CPU)
    fn rt_throttled(&self) -> bool {
        let q = self.queue.as_ref().expect("run queue not initialized");
        self.rt_bw.exceeded() && (q.has_fair() || self.curr_fair().is_some())
    }

    /// Charge the running task's CPU time if it is an rt task (Linux
    /// update_curr_rt)
    fn update_curr_rt(&mut self, now: u64) {
        // SAFETY: the running task, kept alive by this run queue
        let Some(curr) = (unsafe { self.curr.as_ref() }) else {
            return;
        };
        if self.curr_is_idle() || curr.se.class() != Class::Rt {
            return;
        }
        let start = curr.se.exec_start.swap(now, Ordering::Relaxed);
        if start != 0 && now > start {
            self.rt_bw.charge(now, now - start);
        }
    }

    /// The tick of a running rt task: charged, true if that used up
    /// its CPU's rt runtime with fair tasks waiting (Linux
    /// sched_rt_runtime_exceeded -> resched_curr)
    fn rt_tick(&mut self, now: u64) -> bool {
        self.update_curr_rt(now);
        self.rt_throttled()
    }

    /// The tick of a running fair task: true if a new period ends a
    /// throttle with rt tasks waiting (Linux do_sched_rt_period_timer)
    fn rt_period_tick(&mut self, now: u64) -> bool {
        self.rt_bw.roll(now) && self.queue().has_rt()
    }

    /// The running task if it is a fair task still on this run queue
    /// and not on its list (Linux cfs_rq->curr)
    fn curr_fair(&self) -> Option<&KernelTask> {
        // SAFETY: the running task, kept alive by this run queue
        unsafe { self.curr.as_ref() }
            .filter(|c| !self.curr_is_idle() && c.se.class() == Class::Fair && c.se.on_rq())
    }

    /// The fair entities competing here: the queued ones, plus the
    /// running one if `with_curr` and it is one (`curr_fair`)
    fn fair_ents(&self, with_curr: bool) -> impl Iterator<Item = &sched::SchedEntity> + Clone {
        let q = self.queue.as_ref().expect("run queue not initialized");
        let curr = if with_curr { self.curr_fair() } else { None };
        q.fair_iter().map(|t| &t.se).chain(curr.map(|c| &c.se))
    }

    /// Their weighted average vruntime (`min_vruntime` if none)
    fn fair_avg(&self, with_curr: bool) -> u64 {
        crate::task::fair::avg_vruntime(self.fair_ents(with_curr)).unwrap_or(self.min_vruntime)
    }

    /// Their total weight (Linux cfs_rq->load.weight)
    fn fair_load(&self, with_curr: bool) -> u64 {
        self.fair_ents(with_curr)
            .map(crate::task::fair::weight)
            .sum()
    }

    /// Place fair `p`, joining this run queue, by its lag (Linux
    /// place_entity; `initial`: a new task)
    fn place_fair(&self, p: &KernelTask, initial: bool) {
        if p.se.class() == Class::Fair {
            crate::task::fair::place(&p.se, self.fair_avg(true), self.fair_load(true), initial);
        }
    }

    /// Fair `p` (queued here, or running) leaves: keep its lag (Linux
    /// update_entity_lag)
    fn save_lag(&self, p: &KernelTask) {
        if p.se.class() == Class::Fair {
            crate::task::fair::save_lag(&p.se, self.fair_avg(true));
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

impl Default for PerCpuScheduler {
    fn default() -> Self {
        Self::new()
    }
}

/// Global per-CPU scheduler array
///
/// Each CPU accesses its own entry by CPU ID.
static PERCPU_SCHEDS: PerCpu<PerCpuScheduler> = crate::percpu![PerCpuScheduler::new()];

/// A task of this kernel's architecture
pub type KernelTask = Task<CurrentArch, ArchPageTable>;

/// A reference to a task (Linux struct task_struct *, pinned by a
/// reference count)
pub type TaskRef = Arc<KernelTask>;

/// Locked fields of a [`KernelTask`]
pub type KernelTaskInner = crate::task::TaskInner<CurrentArch, ArchPageTable>;

/// Every task (Linux tasklist: the list of all tasks, init_task.tasks,
/// plus the pid hash for lookups), under TASKLIST
///
/// fork/exit/reap change it (write lock); lookups and walks read it. A
/// task's locked fields ([`crate::task::TaskInner`]) are reached through
/// the views below, which borrow the locked list: `get`/`iter` read them
/// (shared lock), `get_mut`/`iter_mut` write them (exclusive lock).
pub struct GlobalTaskTable {
    /// Every task in the table, holding a reference each
    tasks: crate::list::ArcList<TasksAdapter>,
}

crate::adapter!(TasksAdapter, KernelTask, tasks_link);
crate::adapter!(pub PgrpLink, KernelTask, pgrp_link);
crate::adapter!(pub SessionLink, KernelTask, session_link);

/// A new reference to a task that lives in an `Arc` (every task but the
/// boot task does: the table and run queues hold `TaskRef`s)
pub fn task_ref(t: &KernelTask) -> TaskRef {
    let p = t as *const KernelTask;
    debug_assert!(!core::ptr::eq(p, &INIT_TASK));
    // SAFETY: `t` is the data of a live `Arc<KernelTask>` (see above)
    unsafe {
        Arc::increment_strong_count(p);
        Arc::from_raw(p)
    }
}

/// A task with its locked fields readable (the table is locked)
#[derive(Clone, Copy)]
pub struct TaskView<'a> {
    pub task: &'a KernelTask,
    inner: &'a KernelTaskInner,
}

impl<'a> TaskView<'a> {
    /// The locked fields, for the whole borrow of the table
    pub fn fields(&self) -> &'a KernelTaskInner {
        self.inner
    }
}

impl core::ops::Deref for TaskView<'_> {
    type Target = KernelTaskInner;
    fn deref(&self) -> &KernelTaskInner {
        self.inner
    }
}

/// A task with its locked fields writable (the table is locked and
/// borrowed mutably)
pub struct TaskViewMut<'a> {
    pub task: &'a KernelTask,
    inner: &'a mut KernelTaskInner,
}

impl core::ops::Deref for TaskViewMut<'_> {
    type Target = KernelTaskInner;
    fn deref(&self) -> &KernelTaskInner {
        self.inner
    }
}

impl core::ops::DerefMut for TaskViewMut<'_> {
    fn deref_mut(&mut self) -> &mut KernelTaskInner {
        self.inner
    }
}

fn view(task: &KernelTask) -> TaskView<'_> {
    // SAFETY: the caller borrows the locked table, so no `&mut` view
    // exists meanwhile
    let inner = unsafe { task.inner().get() };
    let inner = inner.as_ref().expect("task table: boot task");
    TaskView { task, inner }
}

fn view_mut(task: &KernelTask) -> TaskViewMut<'_> {
    // SAFETY: the caller borrows the locked table mutably, and each
    // task's view is handed out once
    let inner = unsafe { task.inner().get_mut() };
    let inner = inner.as_mut().expect("task table: boot task");
    TaskViewMut { task, inner }
}

/// Credentials of a task, read under TASKLIST (the views borrow it)
macro_rules! owner_reads {
    ($t:ident) => {
        impl<'a> $t<'a> {
            /// Its credentials, copied
            pub fn cred(&self) -> Cred {
                // SAFETY: TASKLIST is held (the view borrows it)
                unsafe { self.task.cred() }
            }

            /// A reference to its credentials
            pub fn cred_arc(&self) -> Arc<Cred> {
                // SAFETY: as above
                unsafe { self.task.cred_arc() }
            }
        }
    };
}
owner_reads!(TaskView);
owner_reads!(TaskViewMut);

/// Tracer links of a task, read under TASKLIST (the views borrow it)
macro_rules! tracer_reads {
    ($t:ident) => {
        impl<'a> $t<'a> {
            /// Its tracer, if it is traced and the tracer lives
            pub fn tracer(&self) -> Option<TaskRef> {
                self.ptracer.as_ref().and_then(|w| w.upgrade())
            }

            /// Traced by `t` (pointer identity: never a recycled number)
            pub fn traced_by(&self, t: &KernelTask) -> bool {
                self.ptracer
                    .as_ref()
                    .is_some_and(|w| core::ptr::eq(w.as_ptr(), t))
            }
        }
    };
}
tracer_reads!(TaskView);
tracer_reads!(TaskViewMut);

impl TaskViewMut<'_> {
    /// Install credentials; the old ones go after TASKLIST. Only the
    /// task itself (commit_creds), or its creator before it runs.
    pub fn set_cred(&mut self, c: Arc<Cred>) -> Option<Arc<Cred>> {
        // SAFETY: TASKLIST held mutably; callers are the owner or the
        // creator (see above)
        unsafe { self.task.set_cred(c) }
    }
}

impl GlobalTaskTable {
    const fn new() -> Self {
        Self {
            tasks: crate::list::ArcList::new(),
        }
    }

    /// Task `tid`, found through the pid hash (root namespace)
    fn lookup(&self, tid: Tid) -> Option<&KernelTask> {
        let pid = crate::task::pid::find_pid(&crate::ns::INIT_PID_NS, u32::try_from(tid).ok()?)?;
        let t = pid.task() as *const KernelTask;
        // SAFETY: a nonzero `task` is in this list (set by `insert`,
        // cleared by `remove` under the write lock), which holds a
        // reference; the caller borrows the locked list
        unsafe { t.as_ref() }
    }

    /// Task `tid`
    pub fn get(&self, tid: Tid) -> Option<TaskView<'_>> {
        self.lookup(tid).map(view)
    }

    /// Task `tid`, writable
    pub fn get_mut(&mut self, tid: Tid) -> Option<TaskViewMut<'_>> {
        self.lookup(tid).map(view_mut)
    }

    /// A reference to task `tid`
    pub fn task(&self, tid: Tid) -> Option<TaskRef> {
        self.lookup(tid).map(task_ref)
    }

    /// Every task
    pub fn iter(&self) -> impl Iterator<Item = TaskView<'_>> {
        self.tasks.iter().map(view)
    }

    /// Every task, writable
    pub fn iter_mut(&mut self) -> impl Iterator<Item = TaskViewMut<'_>> {
        self.tasks.iter().map(view_mut)
    }

    /// The first task `f` accepts
    pub fn find(&self, f: impl Fn(&TaskView<'_>) -> bool) -> Option<TaskView<'_>> {
        self.iter().find(|t| f(t))
    }

    /// The first task `f` accepts, writable
    pub fn find_mut(&mut self, f: impl Fn(&TaskViewMut<'_>) -> bool) -> Option<TaskViewMut<'_>> {
        self.iter_mut().find(|t| f(t))
    }

    /// The locked fields of a task in the list, writable
    ///
    /// # Safety
    /// `t` is in this list, and no view of it is live.
    unsafe fn inner_mut_of<'a>(&'a mut self, t: &'a KernelTask) -> &'a mut KernelTaskInner {
        // SAFETY: see above; the list is locked for writing
        unsafe { t.inner().get_mut() }
            .as_mut()
            .expect("task table: boot task")
    }

    /// Put `child` (a group leader in this list) on its real parent's
    /// `children` (Linux list_add_tail(&p->sibling, &parent->children))
    pub fn link_child(&mut self, child: &TaskRef) {
        // SAFETY: in this list; no view is live (we hold &mut self)
        let ci = unsafe { self.inner_mut_of(child) };
        let Some(parent) = ci.real_parent.as_ref().and_then(|w| w.upgrade()) else {
            return;
        };
        if ci.in_children {
            return;
        }
        ci.in_children = true;
        // SAFETY: the parent is alive and in this list (it is unlinked
        // only after its children were reparented)
        let pi = unsafe { self.inner_mut_of(&parent) };
        pi.children.push_back(child.clone());
    }

    /// Take `child` off its real parent's `children`
    fn unlink_child(&mut self, child: &KernelTask) {
        // SAFETY: in this list; no view is live
        let ci = unsafe { self.inner_mut_of(child) };
        if !core::mem::take(&mut ci.in_children) {
            return;
        }
        let Some(parent) = ci.real_parent.as_ref().and_then(|w| w.upgrade()) else {
            return;
        };
        // SAFETY: as in link_child; the child is on its list
        let pi = unsafe { self.inner_mut_of(&parent) };
        drop(unsafe { pi.children.remove(child) });
    }

    /// Move every child of `task` to `reaper` (Linux forget_original_parent
    /// + reparent_leader); true if one was a zombie
    pub fn reparent(&mut self, task: &KernelTask, reaper: &TaskRef) -> bool {
        let mut zombie = false;
        loop {
            // SAFETY: in this list; no view is live
            let Some(child) = (unsafe { self.inner_mut_of(task) }).children.pop_front() else {
                break;
            };
            // SAFETY: as above, a different task
            let ci = unsafe { self.inner_mut_of(&child) };
            ci.in_children = false;
            ci.real_parent = Some(Arc::downgrade(reaper));
            zombie |= matches!(ci.state, TaskState::Zombie(_));
            child.ppid.store(reaper.pid, Ordering::Relaxed);
            self.link_child(&child);
        }
        zombie
    }

    /// Add a task (fork, kernel thread creation); it has a pid. It joins
    /// its group leader's threads (a new process leads its own).
    pub fn insert(&mut self, task: TaskRef) {
        // SAFETY: the list is locked for writing
        if let Some(inner) = unsafe { task.inner().get() }
            && let Some(p) = &inner.thread_pid
        {
            p.set_task(Arc::as_ptr(&task) as *const ());
        }
        self.tasks.push_back(task.clone());
        self.attach_pids(&task);
        let leader = if task.tid() == task.pid {
            Some(task.clone())
        } else {
            self.task(task.pid)
        };
        if let Some(l) = leader {
            // SAFETY: in this list; no view is live
            unsafe { self.inner_mut_of(&l) }.threads.push_back(task);
        }
    }

    /// The threads of process `pid` (its leader's thread group)
    pub fn threads(&self, pid: Pid) -> impl Iterator<Item = TaskView<'_>> {
        self.get(pid)
            .map(|l| l.fields().threads.iter().map(view))
            .into_iter()
            .flatten()
    }

    /// Take `t` off its leader's thread group
    fn unlink_thread(&mut self, t: &KernelTask) {
        let Some(l) = self.task(t.pid) else { return };
        // SAFETY: in this list; no view is live; `t` is in its leader's
        // group (every task in the list is)
        let li = unsafe { self.inner_mut_of(&l) };
        if li.threads.iter().any(|x| core::ptr::eq(x, t)) {
            drop(unsafe { li.threads.remove(t) });
        }
    }

    /// Remove task `tid`; the caller drops it after unlocking (nothing
    /// is released under TASKLIST)
    pub fn remove(&mut self, tid: Tid) -> Option<TaskRef> {
        let t = task_ref(self.lookup(tid)?);
        self.unlink_child(&t);
        self.unlink_thread(&t);
        self.detach_pids(&t);
        // SAFETY: the list is locked for writing, so no view exists
        if let Some(inner) = unsafe { t.inner().get() }
            && let Some(p) = &inner.thread_pid
        {
            p.set_task(core::ptr::null());
        }
        // SAFETY: found through the hash, so on this list
        drop(unsafe { self.tasks.remove(&t) });
        Some(t)
    }

    /// The group leaders in process group `pg` (Linux
    /// do_each_pid_task(pg, PIDTYPE_PGID))
    pub fn pgrp<'a>(
        &'a self,
        pg: &'a crate::task::pid::Pid,
    ) -> impl Iterator<Item = TaskView<'a>> + 'a {
        // SAFETY: TASKLIST is held for 'a (we borrow the table); the
        // list changes only with the table borrowed mutably
        unsafe { pg.pgrp.get() }.iter().map(view)
    }

    /// The threads of every process in group `pg` (Linux
    /// do_each_pid_thread(pg, PIDTYPE_PGID))
    pub fn pgrp_threads<'a>(
        &'a self,
        pg: &'a crate::task::pid::Pid,
    ) -> impl Iterator<Item = TaskView<'a>> + 'a {
        self.pgrp(pg).flat_map(move |l| self.threads(l.task.pid))
    }

    /// A new task joins its creator's process group and session (Linux
    /// copy_process: under the write lock, so the creator's concurrent
    /// setpgid or setsid is not missed); the creator is in this list,
    /// the child not yet
    pub fn inherit_pids(&mut self, child: &KernelTask, parent: &KernelTask) {
        // SAFETY: the parent is in this list, locked for writing; no
        // `&mut` view of it is live
        let Some(pi) = (unsafe { parent.inner().get() }).as_ref() else {
            return;
        };
        let (pg, s) = (pi.pgrp.clone(), pi.session.clone());
        child.pgid.store(parent.pgid(), Ordering::Relaxed);
        child.sid.store(parent.sid(), Ordering::Relaxed);
        // SAFETY: the child is not in the list yet: nothing else reaches
        // its locked fields
        if let Some(ci) = unsafe { child.inner().get_mut() }.as_mut() {
            ci.pgrp = pg;
            ci.session = s;
        }
    }

    /// Put group leader `t` on its process group's and session's lists
    /// (Linux attach_pid PIDTYPE_PGID, PIDTYPE_SID)
    fn attach_pids(&mut self, t: &KernelTask) {
        // SAFETY: in this list; no view is live
        let ti = unsafe { self.inner_mut_of(t) };
        if ti.pids_linked || !ti.leader {
            return;
        }
        let (Some(pg), Some(s)) = (ti.pgrp.as_ref(), ti.session.as_ref()) else {
            return;
        };
        // SAFETY: the table is locked for writing; `t` stays live while
        // in the table and leaves these lists before it (`remove`)
        unsafe {
            pg.pgrp.get_mut().push_back(t);
            s.session.get_mut().push_back(t);
        }
        ti.pids_linked = true;
    }

    /// Take `t` off its process group's and session's lists (Linux
    /// detach_pid)
    fn detach_pids(&mut self, t: &KernelTask) {
        // SAFETY: in this list; no view is live
        let ti = unsafe { self.inner_mut_of(t) };
        if !core::mem::take(&mut ti.pids_linked) {
            return;
        }
        if let (Some(pg), Some(s)) = (ti.pgrp.as_ref(), ti.session.as_ref()) {
            // SAFETY: the table is locked for writing; linked means on
            // both lists
            unsafe {
                pg.pgrp.get_mut().remove(t);
                s.session.get_mut().remove(t);
            }
        }
    }

    /// Move process `pid` (every thread; its leader on the lists) to
    /// group `pg` and, if given, session `s` (Linux change_pid); the
    /// references it held go to `old`, dropped after TASKLIST
    fn change_pids(
        &mut self,
        pid: Pid,
        pg: &Arc<crate::task::pid::Pid>,
        s: Option<&Arc<crate::task::pid::Pid>>,
        old: &mut Vec<Arc<crate::task::pid::Pid>>,
    ) {
        let Some(l) = self.task(pid) else { return };
        self.detach_pids(&l);
        let threads: Vec<TaskRef> = self.threads(pid).map(|t| task_ref(t.task)).collect();
        for t in &threads {
            // SAFETY: in this list; no view is live
            let ti = unsafe { self.inner_mut_of(t) };
            old.extend(ti.pgrp.replace(pg.clone()));
            t.pgid.store(pg.nr() as Pid, Ordering::Relaxed);
            if let Some(s) = s {
                old.extend(ti.session.replace(s.clone()));
                t.sid.store(s.nr() as Pid, Ordering::Relaxed);
            }
        }
        self.attach_pids(&l);
    }

    /// Number of tasks, zombies included
    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }
}

/// Every task (Linux tasklist_lock and the task list): spin RwLock,
/// thread context only (Linux write_lock_irq: hk never takes it in an
/// interrupt handler, so interrupts stay on)
pub static TASKLIST: RwLock<GlobalTaskTable> = RwLock::new(GlobalTaskTable::new());

/// A task's `alloc_lock` held
pub type KernelTaskLock<'a> = crate::task::TaskLock<'a, CurrentArch, ArchPageTable>;

/// A reference to task `tid` (TASKLIST only for the lookup)
pub fn find_task(tid: Tid) -> Option<TaskRef> {
    TASKLIST.read().task(tid)
}

/// Run `f` with task `tid`'s `alloc_lock` held (Linux task_lock(p));
/// TASKLIST is taken only to find it. Whatever `f` takes out of the
/// task is returned, to be dropped after the lock (3.1.1 rule 4).
pub fn with_task_lock<R>(tid: Tid, f: impl FnOnce(&mut KernelTaskLock<'_>) -> R) -> Option<R> {
    let t = find_task(tid)?;
    let r = f(&mut t.task_lock());
    Some(r)
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
pub static INIT_TASK: KernelTask = Task::boot(0);

/// The running task (Linux `current`): a `!Send` handle valid while
/// the task runs (the run queue holds its reference)
pub struct Cur {
    task: &'static KernelTask,
    _not_send: core::marker::PhantomData<*const ()>,
}

impl core::ops::Deref for Cur {
    type Target = KernelTask;
    fn deref(&self) -> &KernelTask {
        self.task
    }
}

impl Cur {
    /// Its credentials, copied (Linux current_cred)
    pub fn cred(&self) -> Cred {
        // SAFETY: the task itself
        unsafe { self.task.cred() }
    }

    /// A reference to its credentials
    pub fn cred_arc(&self) -> Arc<Cred> {
        // SAFETY: the task itself
        unsafe { self.task.cred_arc() }
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

    /// The task is a kernel thread or the boot task (no user context)
    pub fn is_kthread(&self) -> bool {
        self.task.has_flag(crate::task::pf::KTHREAD)
    }
}

/// The running task of this CPU (Linux `current`)
#[inline]
pub fn current() -> Cur {
    let p = CurrentArch::current_task_ptr() as *const KernelTask;
    // SAFETY: a nonzero `curr` is the task this CPU switched to, kept
    // alive by its run queue until it has switched away for good
    let task = if p.is_null() {
        &INIT_TASK
    } else {
        unsafe { &*p }
    };
    Cur {
        task,
        _not_send: core::marker::PhantomData,
    }
}

/// The user registers of task `t` while it is in the kernel (Linux
/// task_pt_regs): the entry frame at the top of its kernel stack
pub fn task_pt_regs(t: &KernelTask) -> *mut <CurrentArch as crate::arch::Arch>::TrapFrame {
    let size = core::mem::size_of::<<CurrentArch as crate::arch::Arch>::TrapFrame>() as u64;
    (t.kstack_top - size) as *mut _
}

/// The current task's user registers (Linux current_pt_regs); only for a
/// task that entered from user mode (not kernel threads)
#[allow(clippy::mut_from_ref)]
pub fn current_pt_regs() -> &'static mut <CurrentArch as crate::arch::Arch>::TrapFrame {
    // SAFETY: the running task's own frame, on its own kernel stack
    unsafe { &mut *task_pt_regs(&current()) }
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
        // Nothing to run here: pull from a busier CPU (Linux
        // sched_balance_newidle); a task pulled flags us to switch
        sched_balance_rq(crate::cpu::this_id());

        // Flush console before halting to ensure all output is sent
        crate::console::console_flush();

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
/// its CPU's idle task.
fn create_kernel_task(
    cpu_id: u32,
    name: &str,
    entry: usize,
    priority: Priority,
    idle: bool,
) -> Result<TaskRef, &'static str> {
    let thread_pid = if idle {
        None
    } else {
        Some(
            crate::task::pid::alloc_pid(&crate::ns::INIT_PID_NS)
                .ok_or("No pid left for kernel thread")?,
        )
    };
    let tid = thread_pid.as_ref().map_or(0, |p| p.nr() as Tid);
    let pid = tid;

    let stack_base = crate::mm::vmstack::alloc().ok_or("Out of memory for kernel thread stack")?;
    let stack_top = stack_base + KERNEL_STACK_SIZE as u64;

    let task_inner = crate::task::TaskInner {
        thread_pid,
        // In no process group or session (never signalled by group)
        pgrp: None,
        session: None,
        pids_linked: false,
        exit_code: 0,
        exit_signal: 0, // Kernel threads don't send exit signals
        pdeath_signal: 0,
        state: TaskState::Ready,
        page_table: ArchPageTable::kernel_identity(),
        // TLS fields (not used for idle task)
        clear_child_tid: 0,
        set_child_tid: 0,
        // Shared resources (kernel threads don't have user-space resources)
        sighand: None,
        signal: None,
        sysvsem: None,
        // Per-task signal state
        robust_list: 0,
        // prctl state
        prctl: crate::task::PrctlState::default(),
        // Process personality (execution domain)
        personality: 0,
        // Seccomp state (kernel threads don't use seccomp)
        seccomp_filter: None,
        // I/O port permissions (x86-64 only, kernel threads don't use I/O ports)
        #[cfg(target_arch = "x86_64")]
        iopl_emul: 0,
        leader: true,
        // Ptrace state (kernel threads are not traced)
        ptrace: 0,
        ptracer: None,
        real_parent: None,
        children: crate::list::ArcList::new(),
        in_children: false,
        threads: crate::list::ArcList::new(),
        ptrace_message: 0,
        ptrace_options: 0,
        ptrace_code: 0,
    };
    let task = Task::new(
        tid,
        crate::task::TaskIds {
            pid,
            ppid: 0,
            pgid: pid,
            sid: pid,
            seccomp_mode: crate::seccomp::SECCOMP_MODE_DISABLED,
        },
        TaskKind::KernelThread,
        stack_top,
        cpu_id,
        &crate::cpumask::CpuSet::one(cpu_id),
        alloc::sync::Arc::new(Cred::ROOT),
        None,
        crate::task::TaskAlloc::named(name.as_bytes()),
        task_inner,
    );

    set_kthread_class(&task.se, priority);
    // SAFETY: not on a run queue yet
    unsafe { *task.se.ctx() = TaskContext::new_kernel_thread(entry, stack_top) };
    let task = Arc::new(task);
    if idle {
        set_idle(cpu_id, &task);
    } else {
        TASKLIST.write().insert(task.clone());
        attach_asleep(&task);
    }
    Ok(task)
}

/// Make `idle` the idle task of `cpu`, allocating its priority lists
/// (bring-up, before the CPU schedules)
fn set_idle(cpu: u32, idle: &TaskRef) {
    let q = alloc::boxed::Box::new(ClassQueues::new());
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
fn wake_up_new_task(p: &TaskRef) {
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
fn create_idle_task(cpu_id: u32) -> Result<(), &'static str> {
    crate::timer::init_cpu(cpu_id);
    create_kernel_task(
        cpu_id,
        "swapper",
        idle_task_entry as *const () as usize,
        PRIORITY_IDLE,
        true,
    )?;
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
) -> Result<TaskRef, &'static str> {
    if !get_percpu_sched(cpu_id).initialized.load(Ordering::Acquire) {
        return Err("CPU has no scheduler");
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
            printkln!("SCHED: no scheduler for CPU {}: {}", cpu, e);
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
        Err(e) => panic!("Failed to create BSP idle task: {}", e),
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
/// * `config` - User task configuration (pid, tid, ppid, pgid, sid, priority, stacks, page table)
pub fn create_user_task(config: UserTaskConfig) -> Result<Tid, &'static str> {
    let cpu_id = crate::cpu::this_id();
    // init is pid 1 (Linux: the first pid of the root namespace)
    let thread_pid = crate::task::pid::alloc_pid_nr(&crate::ns::INIT_PID_NS, Some(1))
        .ok_or("init: pid 1 taken")?;
    let (tid, pid): (Tid, Pid) = (1, 1);
    // The first address space owns the boot-built tables
    let mm = crate::mm::mm_alloc(config.page_table.root_table_phys());

    // Create Task entry
    let task_inner = crate::task::TaskInner {
        thread_pid: Some(thread_pid),
        // The boot group and session, number 0 (Linux init_struct_pid)
        pgrp: crate::task::pid::find_pgrp(config.pgid),
        session: crate::task::pid::find_pgrp(config.sid),
        pids_linked: false,
        exit_code: 0,
        exit_signal: crate::signal::SIGCHLD as i32, // Default: notify parent with SIGCHLD
        pdeath_signal: 0,
        state: TaskState::Running, // Will be running immediately
        page_table: config.page_table,
        // TLS fields (initialized to 0, set by syscalls)
        clear_child_tid: 0,
        set_child_tid: 0,
        // Shared resources (will be initialized by caller via init_* functions)
        sighand: None,
        signal: None,
        sysvsem: None,
        // Per-task signal state
        robust_list: 0,
        prctl: crate::task::PrctlState::default(),
        // Process personality (execution domain)
        personality: 0,
        // Seccomp state (disabled initially)
        seccomp_filter: None,
        // I/O port permissions (x86-64 only, no I/O port access initially)
        #[cfg(target_arch = "x86_64")]
        iopl_emul: 0,
        leader: true,
        // Ptrace state (not traced initially)
        ptrace: 0,
        ptracer: None,
        real_parent: None,
        children: crate::list::ArcList::new(),
        in_children: false,
        threads: crate::list::ArcList::new(),
        ptrace_message: 0,
        ptrace_options: 0,
        ptrace_code: 0,
    };
    let task = Arc::new(Task::new(
        tid,
        crate::task::TaskIds {
            pid,
            ppid: config.ppid,
            pgid: config.pgid,
            sid: config.sid,
            seccomp_mode: crate::seccomp::SECCOMP_MODE_DISABLED,
        },
        TaskKind::UserProcess,
        config.kstack_top,
        cpu_id,
        &crate::cpumask::CpuSet::all(),
        alloc::sync::Arc::new(Cred::ROOT),
        Some(mm),
        // comm after the init binary, /bin/init (Linux names init after
        // the file it execs)
        crate::task::TaskAlloc::named(b"init"),
        task_inner,
    ));

    // Add to global table
    TASKLIST.write().insert(task.clone());

    // The boot-allocated stack of the first task is never freed; its
    // switch frame is saved at its first switch out
    task.se.disown_stack();
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
        rq.curr = Arc::into_raw(task.clone());
        CurrentArch::set_current_task_ptr(rq.curr as usize);
    }

    // Initialize filesystem context for the init task
    if let Some(fs) = crate::fs::FsStruct::new_root() {
        crate::fs::init_task_fs(tid, fs);
    }

    // Initialize FD table for the init task
    crate::task::fdtable::init_task_fd(tid, crate::task::fdtable::create_empty_fd_table());

    // Initialize namespace context for the init task
    crate::ns::init_task_ns(tid, crate::ns::INIT_NSPROXY.clone());

    // Initialize signal handlers for the init task
    crate::signal::init_task_signal(tid, alloc::sync::Arc::new(crate::signal::SigHand::new()));

    printkln!("USER_TASK_CREATED: pid={} tid={}", pid, tid);
    Ok(tid)
}

/// Mark a task as zombie with exit status
pub fn mark_zombie(tid: Tid, status: i32, group_dead: bool) {
    let pid: Option<Pid>;
    {
        let mut table = TASKLIST.write();
        if let Some(mut task) = table.get_mut(tid) {
            task.exit_code = status;
            task.state = TaskState::Zombie(status);
            pid = Some(task.task.pid);
        } else {
            pid = None;
        }
    }

    // Detach from cgroup and decrement task counters
    // This must be done after releasing TASKLIST lock to avoid lock ordering issues
    crate::cgroup::detach_task(tid);

    // The process's pidfds once its last thread is gone (Linux
    // do_notify_pidfd; after TASKLIST)
    if let Some(p) = pid
        && group_dead
    {
        crate::pidfd::notify_process_exit(p, status);
    }
}

/// Reap a zombie child of the given parent
///
/// # Arguments
/// * `parent_pid` - PID of the parent process
/// * `target_pid` - Which child to wait for:
///   - > 0: wait for specific child PID
///   - -1: wait for any child
///   - 0: wait for any child in same process group (not implemented)
///
/// # Returns
/// * Some((child_pid, exit_status)) if a zombie child was found and reaped
/// * None if no zombie child matches
pub fn reap_zombie_child(parent_pid: Pid, target_pid: i64, wflags: i32) -> Option<(Pid, i32)> {
    reap_zombie_child_times(parent_pid, target_pid, wflags).map(|(pid, status, _, _)| (pid, status))
}

/// Whether `child`'s exit_signal makes it eligible under `wflags`
/// (Linux kernel/exit.c eligible_child): __WALL waits for all children;
/// otherwise "clone" children (exit_signal != SIGCHLD) are waited for only
/// with __WCLONE, and normal children only without it.
fn wait_eligible(exit_signal: i32, wflags: i32) -> bool {
    use super::wait_options::{__WALL, __WCLONE};
    if wflags & __WALL != 0 {
        return true;
    }
    let is_clone = exit_signal != crate::signal::SIGCHLD as i32;
    is_clone == (wflags & __WCLONE != 0)
}

/// Like [`reap_zombie_child`], but also returns the reaped child's CPU times
/// as `(pid, exit_status, utime_ns, stime_ns)` (for wait rusage reporting).
pub fn reap_zombie_child_times(
    parent_pid: Pid,
    target_pid: i64,
    wflags: i32,
) -> Option<(Pid, i32, u64, u64)> {
    let mut table = TASKLIST.write();

    // Find a zombie child matching the criteria: a thread-group leader
    // (threads are never waited for) whose other threads are all gone
    // (Linux delay_group_leader)
    let zombie = table.find(|t| {
        // Must be a child of the parent
        if t.task.ppid() != parent_pid || !t.leader {
            return false;
        }

        // Must be a zombie
        if !matches!(t.state, TaskState::Zombie(_)) || group_alive(&table, t) {
            return false;
        }

        if !wait_eligible(t.exit_signal, wflags) {
            return false;
        }

        // Check PID matching
        if target_pid > 0 {
            // Wait for specific PID
            t.task.pid == target_pid as u64
        } else if target_pid == -1 {
            // Wait for any child
            true
        } else {
            // target_pid == 0: wait for same process group (not implemented)
            false
        }
    })?;
    let TaskState::Zombie(status) = zombie.state else {
        return None;
    };
    let (utime, stime) = zombie.task.times();
    let (tid, pid, uid) = (zombie.task.tid(), zombie.task.pid, zombie.cred().uid);
    let report = (pid, group_status(&zombie, status), utime, stime);

    // WNOWAIT (waitid): report the zombie, leave it waitable
    if wflags & super::wait_options::WNOWAIT != 0 {
        return Some(report);
    }

    let task = table.remove(tid);
    // The Task is released after TASKLIST (nothing is released under it)
    drop(table);
    drop(task);
    // Released: drop the RLIMIT_NPROC charge (threads drop it at exit)
    if tid == pid {
        crate::task::nproc_uncharge(uid);
    }
    Some(report)
}

/// A thread of group `tgid` other than `tid` has not exited yet
pub fn group_others(tgid: Pid, tid: Tid) -> bool {
    let table = TASKLIST.read();
    table
        .threads(tgid)
        .any(|u| u.task.tid() != tid && !matches!(u.state, TaskState::Zombie(_)))
}

/// After de_thread: `tid` is the only thread of `tgid` left running and
/// becomes its leader, taking the old leader's place (Linux de_thread:
/// its parent, exit signal and start time); the exited threads are
/// removed from the table and returned, to be released by the caller
/// after TASKLIST
pub fn take_leadership(tgid: Pid, tid: Tid) -> Vec<TaskRef> {
    let mut table = TASKLIST.write();
    let Some(l) = table.find(|t| t.task.pid == tgid && t.leader) else {
        return Vec::new();
    };
    let ltid = l.task.tid();
    if ltid == tid {
        return Vec::new();
    }
    let (ppid, exit_signal, start, uid) = (
        l.task.ppid(),
        l.exit_signal,
        l.task.start_time(),
        l.cred().uid,
    );
    let gone: Vec<Tid> = table
        .threads(tgid)
        .filter(|t| t.task.tid() != tid && matches!(t.state, TaskState::Zombie(_)))
        .map(|t| t.task.tid())
        .collect();
    // The thread group moves to the caller: it is the only live thread
    // (Linux de_thread leaves only the exec'ing thread); the old list's
    // references go after TASKLIST
    let mut old_threads = crate::list::ArcList::new();
    if let Some(l) = table.task(ltid) {
        // SAFETY: in the list; no view is live
        let li = unsafe { table.inner_mut_of(&l) };
        core::mem::swap(&mut li.threads, &mut old_threads);
    }
    let mut dead: Vec<TaskRef> = Vec::new();
    while let Some(t) = old_threads.pop_front() {
        dead.push(t);
    }
    let mut gone: Vec<TaskRef> = gone.into_iter().filter_map(|t| table.remove(t)).collect();
    gone.extend(dead);
    let Some(me) = table.task(tid) else {
        return gone;
    };
    // exchange_tids: the caller takes the leader's tid and pid (Linux
    // de_thread), the old leader (released here) its own
    if let Some(l) = gone.iter().find(|t| t.tid() == ltid) {
        // SAFETY: TASKLIST is held; neither task is in the table now,
        // and the old leader is dead
        let (mi, li) = unsafe { (me.inner().get_mut(), l.inner().get_mut()) };
        if let (Some(mi), Some(li)) = (mi.as_mut(), li.as_mut()) {
            core::mem::swap(&mut mi.thread_pid, &mut li.thread_pid);
            // The pid hash names the caller by its new number
            if let Some(p) = &mi.thread_pid {
                p.set_task(Arc::as_ptr(&me) as *const ());
            }
            if let Some(p) = &li.thread_pid {
                p.set_task(core::ptr::null());
            }
            // Its real parent is the old leader's (threads share it)
            mi.real_parent = li.real_parent.clone();
        }
        l.set_tid(tid);
        // The old leader's RLIMIT_NPROC charge goes with it; the caller
        // keeps its own as the process's
        crate::task::nproc_uncharge(uid);
    }
    me.set_tid(ltid);
    // The new leader takes the old one's place among its parent's
    // children (tracer and parent links are task references: nothing
    // else names the old tid) and leads the group
    table.link_child(&me);
    // SAFETY: in the list; no view is live
    unsafe { table.inner_mut_of(&me) }
        .threads
        .push_back(me.clone());
    let sig = table.get(ltid).and_then(|t| t.signal.clone());
    if let Some(mut m) = table.get_mut(ltid) {
        m.leader = true;
        m.task
            .ppid
            .store(ppid, core::sync::atomic::Ordering::Relaxed);
        m.exit_signal = exit_signal;
        m.task.start_time.store(start, Ordering::Relaxed);
    }
    // ... and its place on the group's and session's lists (Linux
    // de_thread: transfer_pid PIDTYPE_PGID, PIDTYPE_SID)
    table.attach_pids(&me);
    drop(table);
    // The group's timers owned by the caller follow (after TASKLIST:
    // their locks are leaves taken under nothing)
    if let Some(sig) = sig {
        crate::posix_timer::retarget(&sig, tid, ltid);
    }
    gone
}

/// A thread of `t`'s group other than `t` has not exited yet
fn group_alive(table: &GlobalTaskTable, t: &TaskView<'_>) -> bool {
    table
        .threads(t.task.pid)
        .any(|u| u.task.tid() != t.task.tid() && !matches!(u.state, TaskState::Zombie(_)))
}

/// The wait status a zombie leader reports (Linux wait_task_zombie):
/// the group's exit status after a group exit, else its own
fn group_status(t: &KernelTaskInner, own: i32) -> i32 {
    match t.signal.as_ref().map(|s| s.group_exit()) {
        Some(crate::signal::GroupExit::Exit(code)) => code,
        _ => own,
    }
}

/// A ptrace stop of a task traced by the group `tracer_pid`, matching
/// `target_pid` (wait4's pid: > 0 that tid, -1 any, 0 the caller's
/// process group, < -1 that group), not yet reported: its tid and the
/// stop's code. Reported once unless `wnowait` (Linux wait_task_stopped
/// with ptrace: exit_code cleared). Found under the read lock; the write
/// lock only to take the code.
pub fn wait_traced(tracer_pid: Pid, target_pid: i64, wnowait: bool) -> Option<(Tid, u32)> {
    let pgid = current_pgid();
    let found = |t: &TaskView<'_>| {
        matches!(t.state, TaskState::Traced(_))
            && t.ptrace_code != 0
            && tracee_of(t, tracer_pid)
            && wait_match(t, target_pid, pgid)
    };
    let tid = TASKLIST.read().find(found)?.task.tid();
    let mut table = TASKLIST.write();
    // Everything may have changed meanwhile (resumed, reported,
    // detached, the tid reused): the whole check again
    if !table.get(tid).is_some_and(|t| found(&t)) {
        return None;
    }
    let mut t = table.get_mut(tid)?;
    let code = t.ptrace_code;
    if !wnowait {
        t.ptrace_code = 0;
    }
    Some((tid, code))
}

/// `t` is what wait4's `target_pid` names (`pgid`: the caller's group)
fn wait_match(t: &TaskView<'_>, target_pid: i64, pgid: Pid) -> bool {
    match target_pid {
        -1 => true,
        0 => t.task.pgid() == pgid,
        p if p < -1 => t.task.pgid() == p.unsigned_abs(),
        p => t.task.tid() == p as u64,
    }
}

/// `t` is traced by a thread of group `tracer_pid`
fn tracee_of(t: &TaskView<'_>, tracer_pid: Pid) -> bool {
    t.ptrace != 0 && t.tracer().is_some_and(|tr| tr.pid == tracer_pid)
}

/// The group `tracer_pid` traces a task matching `target_pid` (so a
/// wait for it is not ECHILD)
pub fn has_tracees(tracer_pid: Pid, target_pid: i64) -> bool {
    let pgid = current_pgid();
    let table = TASKLIST.read();
    table
        .iter()
        .any(|t| tracee_of(&t, tracer_pid) && wait_match(&t, target_pid, pgid))
}

/// Check if a process has any children matching the criteria
///
/// # Arguments
/// * `parent_pid` - PID of the parent process
/// * `target_pid` - Which children to check for:
///   - > 0: check for specific child PID
///   - -1: check for any child
///   - 0: check for any child in same process group
pub fn has_children(parent_pid: Pid, target_pid: i64, wflags: i32) -> bool {
    let table = TASKLIST.read();

    table.iter().any(|t| {
        // Must be a child of the parent (a thread-group leader)
        if t.task.ppid() != parent_pid || !t.leader {
            return false;
        }

        if !wait_eligible(t.exit_signal, wflags) {
            return false;
        }

        // Check PID matching
        if target_pid > 0 {
            t.task.pid == target_pid as u64
        } else if target_pid == -1 {
            true
        } else {
            // target_pid == 0: same process group
            false
        }
    })
}

/// Clone configuration for do_clone
pub struct CloneConfig {
    /// Clone flags (CLONE_VM, CLONE_THREAD, etc.)
    pub flags: u64,
    /// Child's user stack top (required for CLONE_VM, 0: the parent's)
    pub child_stack: u64,
    /// User address to store parent TID (CLONE_PARENT_SETTID)
    pub parent_tidptr: u64,
    /// User address to store child TID (CLONE_CHILD_SETTID/CLEARTID)
    pub child_tidptr: u64,
    /// TLS pointer for child (CLONE_SETTLS)
    pub tls: u64,
    /// User address to store pidfd (CLONE_PIDFD)
    pub pidfd_ptr: u64,
    /// Exit signal for child (SIGCHLD for fork, 0 for threads)
    pub exit_signal: i32,
    /// Cgroup file descriptor (CLONE_INTO_CGROUP, clone3 only)
    pub cgroup_fd: i32,
}

/// Create a new thread/process via clone()
///
/// # Arguments
/// * `config` - Clone configuration
/// * `frame_alloc` - Frame allocator for kernel stack
///
/// # Returns
/// * Ok(child_tid) on success (returned to parent)
/// * Err(errno) on failure
///
/// The child will return 0 when scheduled.
pub fn do_clone<FA: FrameAlloc<PhysAddr = u64>>(
    config: CloneConfig,
    frame_alloc: &mut FA,
) -> Result<Tid, i32> {
    use crate::arch::Arch;
    use crate::task::clone_flags::*;

    // Validate: CLONE_VM requires child_stack UNLESS CLONE_VFORK is also set
    // (vfork shares parent's stack with the child)
    if config.flags & CLONE_VM != 0 && config.child_stack == 0 && config.flags & CLONE_VFORK == 0 {
        return Err(22); // EINVAL
    }

    // Validate: CLONE_SIGHAND and CLONE_CLEAR_SIGHAND are mutually exclusive
    // (can't share handlers AND reset them at the same time)
    if config.flags & CLONE_SIGHAND != 0 && config.flags & CLONE_CLEAR_SIGHAND != 0 {
        return Err(22); // EINVAL
    }

    // RLIMIT_NPROC: every task, threads included, is charged to its
    // real uid until it is released; over the limit is EAGAIN unless
    // root or CAP_SYS_RESOURCE/CAP_SYS_ADMIN (Linux copy_process). The
    // guard uncharges on every error return.
    let nproc = crate::task::NprocCharge::new(current_cred().uid);
    let parent_nproc_exceeded = {
        let table = TASKLIST.read();
        table
            .get(current_tid())
            .is_some_and(|t| t.task.has_flag(crate::task::pf::NPROC_EXCEEDED))
    };
    if crate::task::nproc_over(nproc.uid, nproc.count) {
        return Err(11); // EAGAIN
    }

    // Check cgroup pids controller limit (if task is in a cgroup with pids.max)
    // This is checked before allocating resources so we fail early if over limit
    let parent_cgroup = {
        let tid = current_tid();
        crate::cgroup::get_task_cgroup(tid)
    };
    if let Some(ref cgroup) = parent_cgroup
        && !crate::cgroup::pids_can_fork(cgroup)
    {
        return Err(11); // EAGAIN - resource temporarily unavailable
    }

    // A TLS base the register cannot take (Linux copy_thread ->
    // set_new_tls -> do_arch_prctl_64)
    if config.flags & CLONE_SETTLS != 0 && !crate::arch::user_tls_ok(config.tls) {
        return Err(1); // EPERM
    }

    // Helper macro to handle early returns with NPROC cleanup
    // If we incremented the process count and then fail, we must decrement it

    // Get current CPU ID
    let cpu_id = crate::cpu::this_id();

    // Get parent task info
    let current_tid = current_tid();
    let (
        parent_pid,
        parent_ppid,
        parent_pgid,
        parent_sid,
        parent_sched,
        parent_cpus_allowed,
        parent_pt_phys,
        parent_cred,
        parent_prctl,
        parent_personality,
        parent_seccomp_mode,
        parent_seccomp_filter,
        parent_ptrace,
        parent_ptracer,
        parent_real_parent,
    ) = {
        let table = TASKLIST.read();
        let parent = table.get(current_tid).ok_or(3)?; // ESRCH - no such process
        (
            parent.task.pid,
            parent.task.ppid(),
            parent.task.pgid(),
            parent.task.sid(),
            (
                parent.task.se.policy(),
                parent.task.se.static_prio(),
                parent.task.se.rt_priority(),
                parent.task.se.reset_on_fork(),
            ),
            parent.task.cpus_mask.snapshot(),
            parent.page_table.root_table_phys(),
            parent.cred_arc(),
            parent.prctl.clone(),
            parent.personality,
            parent.task.seccomp_mode(),
            parent.seccomp_filter.clone(),
            parent.ptrace,
            parent.ptracer.clone(),
            parent.real_parent.clone(),
        )
    };
    // Its own alloc_lock fields (lock-free but the memory policy)
    let me = current();
    let parent_alloc = crate::task::TaskAlloc {
        comm: me.comm(),
        mempolicy: me.task_lock().mempolicy(),
    };
    let parent_pid_ns = me
        .nsproxy()
        .map_or_else(|| crate::ns::INIT_PID_NS.clone(), |n| n.pid_ns.clone());
    let parent_mm = me.mm_ref();

    // Get parent iopl_emul (x86-64 only) - must be done in separate block
    #[cfg(target_arch = "x86_64")]
    let parent_iopl_emul = {
        let table = TASKLIST.read();
        table.get(current_tid).map(|t| t.iopl_emul).unwrap_or(0)
    };

    // Validate CLONE_PARENT: cannot be used by init process (pid 1)
    // Linux checks for SIGNAL_UNKILLABLE flag, but we simplify to pid == 1
    if config.flags & CLONE_PARENT != 0 && parent_pid == 1 {
        return Err(22); // EINVAL
    }

    // The child inherits the policy and priorities; with
    // SCHED_RESET_ON_FORK an rt parent's child is SCHED_NORMAL nice 0,
    // and a negative nice becomes 0 (Linux sched_fork)
    let (mut c_policy, mut c_static, mut c_rt, reset) = parent_sched;
    if reset {
        if crate::task::is_rt_policy(c_policy) {
            (c_policy, c_static, c_rt) = (crate::task::SCHED_NORMAL, sched::DEFAULT_PRIO, 0);
        } else if c_static < sched::DEFAULT_PRIO {
            c_static = sched::DEFAULT_PRIO;
        }
    }

    // The child's pid, numbered in each level of the parent's pid
    // namespace (Linux alloc_pid); a new process's pid is its tid
    // (leader pid == tid), a thread keeps its group's
    let child_thread_pid = crate::task::pid::alloc_pid(&parent_pid_ns).ok_or(11)?; // EAGAIN
    let child_tid = child_thread_pid.nr() as Tid;
    let child_pid = if config.flags & CLONE_THREAD != 0 {
        parent_pid
    } else {
        child_tid
    };

    // The child's address space (Linux copy_mm): shared for CLONE_VM,
    // else a copy (dup_mm). Dropped on any error below.
    let child_mm = match parent_mm {
        None => None,
        Some(pm) if config.flags & CLONE_VM != 0 => Some(pm),
        Some(pm) => {
            let mut pt = ArchPageTable::new_user(frame_alloc).ok_or(12)?; // ENOMEM
            pt.copy_kernel_mappings();
            Some(crate::mm::dup_mm(&pm, pt.root_table_phys())?)
        }
    };
    let child_pt = ArchPageTable::new(child_mm.as_ref().map_or(parent_pt_phys, |m| m.pgd()));

    // The child's kernel stack (zeroed, guard gap below)
    let stack_base = crate::mm::vmstack::alloc().ok_or(12)?; // ENOMEM
    let kstack_top = stack_base + KERNEL_STACK_SIZE as u64;

    // Build child's TrapFrame at the top of the child's kernel stack (its
    // pt_regs), the inherited FP/SIMD state below it if the arch keeps
    // that apart (loaded by clone_child_entry before it returns to user
    // mode)
    let trapframe_size = core::mem::size_of::<<CurrentArch as Arch>::TrapFrame>() as u64;
    let trapframe_ptr = kstack_top - trapframe_size;

    // Every user register of the parent's syscall (Linux copy_thread:
    // *childregs = *current_pt_regs()), returning 0, on its own stack
    // unless it shares the parent's (fork: child_stack 0)
    let mut child_trapframe = current_pt_regs().clone();
    child_trapframe.set_ret(0);
    if config.child_stack != 0 {
        child_trapframe.set_sp(config.child_stack);
    }

    // Copy TrapFrame to child's kernel stack
    unsafe {
        let tf_ptr = trapframe_ptr as *mut <CurrentArch as Arch>::TrapFrame;
        core::ptr::write(tf_ptr, child_trapframe);
    }

    // Create TaskContext pointing to clone_child_entry, its frame below
    // the TrapFrame and the saved FP state
    let frame_top = CurrentArch::clone_child_fpu(trapframe_ptr);
    let context = CurrentArch::new_clone_child_context(frame_top);

    // Determine child's parent PID
    // CLONE_PARENT or CLONE_THREAD: child becomes sibling (same parent as caller)
    // Otherwise: caller becomes the parent
    let child_ppid = if config.flags & (CLONE_PARENT | CLONE_THREAD) != 0 {
        parent_ppid // Child's parent is our parent (grandparent of normal fork)
    } else {
        parent_pid // Normal case: we are the parent
    };

    // Create child task
    let child_task_inner = crate::task::TaskInner {
        thread_pid: Some(child_thread_pid),
        // Set from the creator's under TASKLIST (`inherit_pids`)
        pgrp: None,
        session: None,
        pids_linked: false,
        exit_code: 0,
        exit_signal: config.exit_signal, // From clone3 args (SIGCHLD for fork, 0 for threads)
        pdeath_signal: 0,                // Never inherited, must be set explicitly via prctl
        state: TaskState::Ready,
        page_table: child_pt,
        // TLS fields - will be set based on clone flags below
        clear_child_tid: 0,
        set_child_tid: 0,
        // Shared resources (will be cloned/shared based on clone flags below)
        sighand: None,
        signal: None,
        sysvsem: None,
        // Per-task signal state (always per-task, not shared)
        robust_list: 0,
        // prctl state: the name is inherited (dumpability lives in the
        // mm: shared with CLONE_VM, copied by dup_mm)
        prctl: crate::task::PrctlState {
            no_new_privs: parent_prctl.no_new_privs, // Inherited (irreversible)
            timer_slack_ns: parent_prctl.timer_slack_ns, // Inherited
            keep_caps: false,                        // Reset on fork
            child_subreaper: false,                  // Not inherited
            #[cfg(target_arch = "x86_64")]
            tsc_mode: parent_prctl.tsc_mode, // Inherited
            thp_disable: parent_prctl.thp_disable,   // Inherited
        },
        // Process personality (inherited from parent)
        personality: parent_personality,
        // Seccomp state (inherited from parent)
        // Seccomp filters are reference-counted, so this is cheap
        seccomp_filter: parent_seccomp_filter,
        // I/O port permissions (x86-64 only, inherited from parent)
        #[cfg(target_arch = "x86_64")]
        iopl_emul: parent_iopl_emul,
        // Copied like the rest of task->flags (Linux dup_task_struct)
        leader: config.flags & CLONE_THREAD == 0,
        // Ptrace state: inherited if CLONE_PTRACE is set and parent is traced
        // CLONE_UNTRACED prevents forced inheritance even when tracer requests it
        ptrace: if config.flags & CLONE_UNTRACED != 0 {
            // CLONE_UNTRACED: child is never traced, even if parent is
            0
        } else if config.flags & CLONE_PTRACE != 0 && parent_ptrace != 0 {
            // CLONE_PTRACE: if parent is being traced, child inherits tracing
            // with the same tracer
            parent_ptrace
        } else {
            // Normal case: child is not traced initially
            0
        },
        ptracer: if config.flags & CLONE_UNTRACED != 0 {
            None
        } else if config.flags & CLONE_PTRACE != 0 {
            parent_ptracer
        } else {
            None
        },
        // CLONE_PARENT/CLONE_THREAD: the caller's real parent (Linux
        // copy_process)
        real_parent: if config.flags & (CLONE_PARENT | CLONE_THREAD) != 0 {
            parent_real_parent
        } else {
            Some(Arc::downgrade(&task_ref(&current())))
        },
        children: crate::list::ArcList::new(),
        in_children: false,
        threads: crate::list::ArcList::new(),
        ptrace_message: 0,
        ptrace_options: 0,
        ptrace_code: 0,
    };
    let child_task = Arc::new(Task::new(
        child_tid,
        crate::task::TaskIds {
            pid: child_pid,
            ppid: child_ppid,
            pgid: parent_pgid,
            sid: parent_sid,
            seccomp_mode: parent_seccomp_mode,
        },
        TaskKind::UserProcess,
        kstack_top,
        cpu_id,
        &parent_cpus_allowed,
        crate::task::copy_creds(config.flags, &parent_cred),
        child_mm,
        // The name and memory policy are inherited
        parent_alloc,
        child_task_inner,
    ));
    if parent_nproc_exceeded {
        child_task.set_flag(crate::task::pf::NPROC_EXCEEDED);
    }
    child_task
        .se
        .set_params(policy_class(c_policy), c_policy, c_static, c_rt);
    // SAFETY: not on a run queue yet
    unsafe { *child_task.se.ctx() = context };

    // Add to global task table
    {
        let mut table = TASKLIST.write();
        table.inherit_pids(&child_task, &current());
        table.insert(child_task.clone());
        // A new process joins its real parent's children (Linux: only
        // group leaders are on children lists)
        if config.flags & CLONE_THREAD == 0 {
            table.link_child(&child_task);
        }
    }

    // Handle filesystem context (CLONE_FS)
    // If CLONE_FS is set, child shares parent's FsStruct (cwd changes affect both)
    // Otherwise, child gets an independent copy
    crate::fs::clone_task_fs(current_tid, child_tid, config.flags & CLONE_FS != 0);

    // Handle FD table (CLONE_FILES)
    // If CLONE_FILES is set, child shares parent's FD table
    // Otherwise, child gets an independent deep copy
    crate::task::fdtable::clone_task_fd(current_tid, child_tid, config.flags & CLONE_FILES != 0);

    // Handle namespace context (CLONE_NEW* flags)
    // This must come after filesystem context since mount namespace affects VFS
    crate::ns::copy_namespaces(current_tid, child_tid, config.flags)?;

    // Handle cgroup membership
    // If CLONE_INTO_CGROUP is set, look up cgroup from fd and use that
    // Otherwise, inherit from parent
    if config.flags & CLONE_INTO_CGROUP != 0 && config.cgroup_fd >= 0 {
        // Look up cgroup from file descriptor
        match crate::task::cgroup_from_fd(current_tid, config.cgroup_fd) {
            Some(cgroup) => {
                crate::cgroup::attach_task(child_tid, &cgroup);
            }
            None => {
                // Invalid cgroup fd
                return Err(9); // EBADF
            }
        }
    } else if let Some(ref cgroup) = parent_cgroup {
        // Inherit cgroup membership from parent
        crate::cgroup::attach_task(child_tid, cgroup);
    }

    // Handle signal handlers (CLONE_SIGHAND, CLONE_CLEAR_SIGHAND)
    // If CLONE_SIGHAND is set, child shares parent's signal handler table
    // Otherwise, child gets a deep copy of handlers
    // If CLONE_CLEAR_SIGHAND is set, handlers are reset to default (except SIG_IGN)
    // CLONE_THREAD also implies sharing shared_pending
    crate::signal::clone_task_signal(
        current_tid,
        child_tid,
        config.flags & CLONE_SIGHAND != 0,
        config.flags & CLONE_THREAD != 0,
        config.flags & CLONE_CLEAR_SIGHAND != 0,
    );
    if config.flags & CLONE_THREAD != 0 {
        crate::signal::zap_new_thread(current_tid, child_tid);
    }

    // Handle I/O context (CLONE_IO)
    // If CLONE_IO is set, child shares parent's I/O context (ioprio changes affect both)
    // Otherwise, child gets an independent copy with inherited ioprio value
    // NOTE: Only run when explicitly requested or basic fork
    if config.flags & CLONE_IO != 0 {
        crate::task::clone_task_io(current_tid, child_tid, true);
    }

    // Handle SysV semaphore undo list (CLONE_SYSVSEM)
    // If CLONE_SYSVSEM is set, child shares parent's semaphore undo list
    // Otherwise, child starts with no undo list (allocated on first SEM_UNDO operation)
    if config.flags & CLONE_SYSVSEM != 0 {
        crate::ipc::sem::clone_task_semundo(current_tid, child_tid, true);
    }

    // Handle CLONE_SETTLS: set child's TLS pointer
    // This stores the TLS value so clone_child_entry can load it into the
    // architecture-specific TLS register (FS base on x86_64, TPIDR_EL0 on aarch64)
    // Otherwise the child inherits the parent's TLS register, as every
    // other user register (Linux copy_thread: fsbase / tpidr_el0)
    if config.flags & CLONE_SETTLS != 0 {
        child_task.tls.store(config.tls, Ordering::Relaxed);
    } else {
        child_task
            .tls
            .store(crate::arch::read_user_tls(), Ordering::Relaxed);
    }
    // ... and its user GS base (Linux copy_thread: gsbase)
    child_task
        .gsbase
        .store(crate::arch::read_user_gsbase(), Ordering::Relaxed);

    // Handle CLONE_PARENT_SETTID: write child TID to parent's address space
    if config.flags & CLONE_PARENT_SETTID != 0 && config.parent_tidptr != 0 {
        use crate::arch::Uaccess;
        use crate::uaccess::put_user;
        if put_user::<Uaccess, i32>(config.parent_tidptr, child_tid as i32).is_err() {
            // Continue even if write fails - Linux does the same
            printkln!("CLONE: CLONE_PARENT_SETTID write failed");
        }
    }

    // Handle CLONE_CHILD_SETTID: write child TID to child's address space
    // For threads (CLONE_VM set), parent and child share address space, so we can write now.
    // For fork (CLONE_VM not set), store for clone_child_entry to write in child's context.
    if config.flags & CLONE_CHILD_SETTID != 0 && config.child_tidptr != 0 {
        if config.flags & CLONE_VM != 0 {
            // Shared address space - write directly
            use crate::arch::Uaccess;
            use crate::uaccess::put_user;
            if put_user::<Uaccess, i32>(config.child_tidptr, child_tid as i32).is_err() {
                printkln!("CLONE: CLONE_CHILD_SETTID write failed");
            }
        } else {
            // Separate address space (fork) - store for clone_child_entry to write
            crate::task::set_set_child_tid(child_tid, config.child_tidptr);
        }
    }

    // Handle CLONE_CHILD_CLEARTID: store address to clear and wake on exit
    // This enables pthread_join to work by waking when thread exits
    if config.flags & CLONE_CHILD_CLEARTID != 0 && config.child_tidptr != 0 {
        crate::task::set_clear_child_tid(child_tid, config.child_tidptr);
    }

    // Determine return value before potential blocking
    let return_value = if config.flags & CLONE_THREAD != 0 {
        child_tid
    } else {
        child_pid
    };

    // CLONE_VFORK: the completion must be in place before the child can
    // run (it may exec or exit at once on another CPU; Linux
    // p->vfork_done)
    let vfork = crate::completion::Completion::new();
    if config.flags & CLONE_VFORK != 0 {
        child_task.vfork_done.store(
            &vfork as *const crate::completion::Completion as *mut _,
            Ordering::Release,
        );
    }

    // The child exists now: its charge is released with it; the parent
    // forked within its limit (Linux clears PF_NPROC_EXCEEDED)
    nproc.keep();
    {
        if let Some(t) = TASKLIST.read().get(current_tid) {
            t.task.clear_flag(crate::task::pf::NPROC_EXCEEDED);
        }
    }

    // Only a fully set up child becomes runnable (Linux: wake_up_new_task
    // at the end of kernel_clone); before this it has no mm, files or
    // signal state to run with
    wake_up_new_task(&child_task);

    // CLONE_VFORK: parent sleeps until the child exec()s or _exit()s
    // (Linux wait_for_vfork_done; uninterruptible here, so the
    // completion on this stack outlives the child's use of it)
    if config.flags & CLONE_VFORK != 0 {
        vfork.wait();
    }

    // Handle CLONE_PIDFD: create a pidfd for the child and write it to parent's address space
    if config.flags & CLONE_PIDFD != 0 && config.pidfd_ptr != 0 {
        use crate::arch::Uaccess;
        use crate::uaccess::put_user;

        // Create pidfd for the child
        let pidfd_file = match crate::pidfd::create_pidfd(child_pid, 0) {
            Ok(file) => file,
            Err(_) => {
                // Pidfd creation failed - this is not critical, just don't set it
                // Return success anyway as the child is already created
                return Ok(return_value);
            }
        };

        // Allocate FD in parent's FD table
        let fd_table = match crate::task::fdtable::get_task_fd(current_tid) {
            Some(table) => table,
            None => return Ok(return_value), // No FD table - shouldn't happen
        };

        // Get NOFILE limit
        let nofile = {
            let limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_NOFILE);
            if limit == crate::rlimit::RLIM_INFINITY {
                u64::MAX
            } else {
                limit
            }
        };

        let pidfd_num = {
            let mut table = fd_table.lock();
            // Allocate with O_CLOEXEC by default for pidfds
            match table.alloc_with_flags(pidfd_file, crate::task::FD_CLOEXEC, nofile) {
                Ok(fd) => fd,
                Err(_) => return Ok(return_value), // FD allocation failed
            }
        };

        // Write the pidfd number to parent's address space
        let _ = put_user::<Uaccess, i32>(config.pidfd_ptr, pidfd_num as i32);
    }

    // Return value depends on CLONE_THREAD flag:
    // - CLONE_THREAD: return child TID (thread in same process)
    // - No CLONE_THREAD: return child PID (new process)
    // This matches Linux behavior.
    Ok(return_value)
}

/// Mark the current task exiting (Linux PF_EXITING)
fn set_exiting() {
    current().set_flag(crate::task::pf::EXITING);
}

/// The current task is exiting (Linux current->flags & PF_EXITING)
pub fn current_exiting() -> bool {
    current().has_flag(crate::task::pf::EXITING)
}

/// Hand the current task's children to a new parent before it dies
/// (Linux forget_original_parent): another live thread of its group,
/// else the nearest PR_SET_CHILD_SUBREAPER ancestor, else init
fn forget_original_parent() {
    let me = task_ref(&current());
    let mut table = TASKLIST.write();
    if table.get(me.tid()).is_none_or(|t| t.children.is_empty()) {
        return;
    }
    let live = |t: &TaskView<'_>| {
        !t.task.has_flag(crate::task::pf::EXITING) && !matches!(t.state, TaskState::Zombie(_))
    };
    let mut reaper = table
        .threads(me.pid)
        .find(|t| !core::ptr::eq(t.task, &*me) && live(t))
        .map(|t| task_ref(t.task));
    if reaper.is_none() {
        let mut p = table.get(me.tid()).and_then(|t| t.real_parent.clone());
        while let Some(t) = p.and_then(|w| w.upgrade()) {
            let Some(v) = table.get(t.tid()) else { break };
            if v.prctl.child_subreaper && live(&v) {
                reaper = Some(t.clone());
                break;
            }
            p = v.real_parent.clone();
        }
    }
    let Some(reaper) = reaper.or_else(|| table.task(1)) else {
        return;
    };
    if !Arc::ptr_eq(&reaper, &me) {
        table.reparent(&me, &reaper);
    }
}

/// An exited non-leader thread leaves the task list at once (Linux
/// release_task for an autoreaped thread); its run queue keeps it
/// until it has switched away for good
fn release_thread(tid: Tid) {
    let gone = {
        let mut table = TASKLIST.write();
        match table.get(tid) {
            // A traced thread stays for its tracer's wait
            Some(t) if !t.leader && t.ptrace == 0 => table.remove(tid),
            _ => None,
        }
    };
    drop(gone);
}

/// Exit the current task and switch to another
///
/// This function never returns. The current task is removed from the
/// run queue (but kept in TASKLIST as zombie), and execution switches
/// to the next available task (typically idle if no others).
///
/// With a `status`, the task becomes a zombie carrying it once everything
/// it owned is released (Linux exit_notify after exit_mm/exit_files): a
/// parent's wait never sees it, and never removes it, while it still
/// runs on its resources.
pub fn exit_current(status: Option<i32>) -> ! {
    let tid = current_tid();
    let mut group_dead = true;

    // Release the task's resources first, without the rq lock: these paths
    // take sleeping-context locks and may wake other tasks (futex CLEARTID,
    // robust futexes), which needs this CPU's rq lock.
    if tid != 0 {
        // Linux exit_signals sets PF_EXITING first
        set_exiting();

        // Exactly one thread, the one taking the group's live count to
        // zero, does the group-level exit work (Linux do_exit:
        // group_dead = atomic_dec_and_test(&signal->live))
        group_dead = crate::signal::get_task_signal_struct(tid).is_none_or(|s| s.thread_exiting());

        // Nothing reaps orphans or keeps userspace going without the
        // global init: its death is fatal, and loud (Linux do_exit:
        // is_global_init when group_dead), not a silent idle machine
        if group_dead
            && current_pid() == 1
            && let Some(st) = status
        {
            panic!("Attempted to kill init! exitcode={:#010x}", st);
        }

        // The group's last thread writes the accounting record while the
        // task still has its mm, files and identity (Linux acct_process
        // when group_dead, before exit_mm/exit_files)
        if let Some(st) = status
            && group_dead
        {
            crate::acct::write_acct_record(tid, current_pid(), st);
        }

        // A non-leader thread is released at exit (Linux autoreaps it):
        // its RLIMIT_NPROC charge goes now; a process's when it is reaped
        {
            let table = TASKLIST.read();
            if let Some(task) = table.get(tid)
                && task.task.tid() != task.task.pid
            {
                crate::task::nproc_uncharge(task.cred().uid);
            }
        }

        // Clean up filesystem context for exiting task
        crate::fs::exit_task_fs(tid);

        // Clean up FD table for exiting task
        crate::task::fdtable::exit_task_fd(tid);

        // Clean up SysV semaphore undo list for exiting task
        // This may apply undo operations if this is the last holder
        // MUST be done BEFORE exit_task_ns() since exit_sem needs IPC namespace
        crate::ipc::sem::exit_sem(tid);

        // Clean up I/O context for exiting task
        crate::task::remove_task_io_context(tid);

        // Clean up namespace context for exiting task
        crate::ns::exit_task_ns(tid);

        // Clean up seccomp state for exiting task
        crate::seccomp::exit_seccomp(tid);

        // The group's last thread deletes its timers (Linux exit_itimers
        // when group_dead)
        if group_dead && let Some(sig) = crate::signal::get_task_signal_struct(tid) {
            crate::posix_timer::exit_itimers(&sig);
        }

        // Clean up signal state for exiting task
        crate::signal::exit_task_signal(tid);

        // Clean up robust futex list for exiting task
        // Get pid for futex key creation
        let pid = {
            let table = TASKLIST.read();
            table.get(tid).map(|t| t.task.pid).unwrap_or(0)
        };
        crate::futex::exit_robust_list(tid, pid);

        // Handle CLONE_CHILD_CLEARTID: write 0 and wake futex waiters
        // This must be done before switching away since we need to be in
        // the task's address space to write to user memory
        do_clear_child_tid(tid);

        // Signal vfork completion if parent is waiting
        // This must be done after CLEARTID but before we switch away
        signal_vfork_done();
    }

    // Leave the address space (Linux exit_mm, after mm_release above has
    // used it for the robust list and CLEARTID): the last user tears it
    // down; its top-level table stays loaded here until we switched away
    let dead_mm = if tid != 0 {
        crate::mm::exit_task_mm(tid)
    } else {
        None
    };
    if tid != 0 {
        forget_original_parent();
        crate::task::ptrace::exit_ptrace();
    }
    if let Some(st) = status {
        mark_zombie(tid, st, group_dead);
        release_thread(tid);
    }

    // Let a parent sleeping in wait4/waitid re-check for zombies
    crate::task::proc::CHILD_EXIT_WQ.wake_all();

    // No wakeup touches the task from here on (Linux TASK_DEAD): they
    // see Dead under its pi_lock
    let me = current();
    {
        let _pi = me.pi_lock.lock();
        me.se.set_state(DEAD);
    }

    let sched = current_percpu_sched().expect("No scheduler");
    let mut rq = sched.lock.lock();

    // Off the run queue for good; its stack, mm and the run queue's
    // reference go once this CPU runs something else
    me.se.set_on_rq(false);
    rq.add_nr(-1);
    let stack = if me.se.owns_stack() {
        (me.kstack_top - KERNEL_STACK_SIZE as u64, KERNEL_STACK_SIZE)
    } else {
        (0, 0)
    };
    // SAFETY: the run queue's reference to the running task
    let task = Some(unsafe { Arc::from_raw(rq.curr) });
    rq.dead = Some(DeadTask {
        stack,
        mm: dead_mm,
        task,
    });

    let next = rq.pick_next();
    // SAFETY: a task of this run queue, alive while it holds it
    let (next_kstack, next_mm, (next_tls, next_gs)) = make_current(unsafe { &*next });
    rq.curr = next;
    rq.prev = &*me;
    sched.nr_switches.fetch_add(1, Ordering::Relaxed);

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
fn make_current(t: &KernelTask) -> (u64, *const crate::mm::Mm, (u64, u64)) {
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
    CurrentArch::set_current_task_ptr(t as *const KernelTask as usize);
    // Linux prepare_task
    t.se.set_on_cpu(true);
    // A fair task's runtime counts from now (Linux set_next_entity)
    t.se.exec_start
        .store(crate::time::monotonic_ns(), Ordering::Relaxed);
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
    mut rq: crate::arch::IrqSpinlockGuard<'_, CpuRunQueue>,
    prev: &KernelTask,
    next: *const KernelTask,
) {
    check_switch_atomic();
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
    let (next_kstack, next_mm, (next_tls, next_gs)) = make_current(n);
    rq.curr = next;
    rq.prev = prev;
    sched.nr_switches.fetch_add(1, Ordering::Relaxed);

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
fn finish_task_switch(mut rq: crate::arch::IrqSpinlockGuard<'_, CpuRunQueue>) {
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
    let now = crate::time::monotonic_ns();
    if me.se.class() == Class::Fair {
        crate::task::fair::update_curr(&me.se, now);
        rq.save_lag(&me);
    }
    rq.update_curr_rt(now);
    me.se.set_on_rq(false);
    rq.add_nr(-1);
    // A slice that ran out is not carried past the sleep
    me.se.take_requeue_tail();
    let st = me.se.state();
    if st == SleepState::Uninterruptible as u8 || st == SleepState::Killable as u8 {
        me.se.contrib_load.store(true, Ordering::Relaxed);
        sched.nr_uninterruptible.fetch_add(1, Ordering::Relaxed);
    }
    me.nvcsw.fetch_add(1, Ordering::Relaxed);
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
    let t = core::pin::pin!(crate::timer::TimerList::new(
        process_timeout,
        crate::timer::TIMER_HARD
    ));
    t.set_data(&*me as *const KernelTask as usize);
    t.as_ref().mod_timer(expire);
    schedule();
    t.del_timer_sync();
    expire.saturating_sub(get_ticks())
}

/// A `schedule_timeout` sleep timed out (tick interrupt): wake its task
fn process_timeout(t: &crate::timer::TimerList) {
    // SAFETY: the sleeper, which deletes the timer before it returns
    try_to_wake_up(unsafe { &*(t.data() as *const KernelTask) }, WakeMode::Any);
}

/// Lock the run queue `p` is on (Linux task_rq_lock): the CPU it names
/// once the lock is held
fn task_rq_lock(p: &KernelTask) -> crate::arch::IrqSpinlockGuard<'static, CpuRunQueue> {
    loop {
        let cpu = p.cpu();
        let rq = get_percpu_sched(cpu).lock.lock();
        if p.cpu() == cpu {
            return rq;
        }
    }
}

/// Move `p` to `cpu`'s run queue's ownership (Linux set_task_cpu):
/// under its pi_lock while it is off every run queue (a wakeup, a new
/// task), or under its old rq lock while queued (a migration)
fn set_task_cpu(p: &KernelTask, cpu: u32) {
    p.wake_cpu.store(cpu, Ordering::Relaxed);
    p.cpu.store(cpu, Ordering::Release);
}

/// The class of SCHED_* `policy` (Linux __setscheduler_class)
fn policy_class(policy: i32) -> Class {
    if crate::task::is_rt_policy(policy) {
        Class::Rt
    } else {
        Class::Fair
    }
}

/// A kernel thread's class from its creator's priority hint: the idle
/// task, the stoppers (Linux sched_set_stop_task, shown as FIFO 99),
/// SCHED_FIFO 1 for the high ones (`ktimers/N`, as Linux PREEMPT_RT
/// ktimers), the rest SCHED_NORMAL nice 0
fn set_kthread_class(se: &sched::SchedEntity, prio: Priority) {
    use crate::task::{PRIORITY_HIGH, PRIORITY_REALTIME, SCHED_FIFO, SCHED_NORMAL};
    let d = sched::DEFAULT_PRIO;
    match prio {
        PRIORITY_IDLE => se.set_params(Class::Idle, SCHED_NORMAL, d, 0),
        PRIORITY_REALTIME => se.set_params(Class::Stop, SCHED_FIFO, d, 99),
        PRIORITY_HIGH => se.set_params(Class::Rt, SCHED_FIFO, d, 1),
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
static SCHED_CPUS: crate::cpumask::CpuMask = crate::cpumask::CpuMask::new();

fn sched_cpus() -> crate::cpumask::CpuSet {
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
        Class::Rt | Class::Stop => 99 - se.rt_priority() as i32,
        _ => se.static_prio() as i32,
    }
}

/// How important `p` is to keep running, for rt placement (Linux
/// cpupri): idle 0, fair 1, rt 2 + its priority, stop above all
fn rank(p: &KernelTask) -> u32 {
    match p.se.class() {
        Class::Idle => 0,
        Class::Fair => 1,
        Class::Rt => 2 + p.se.rt_priority() as u32,
        Class::Stop => 200,
    }
}

/// An rt task's CPU (Linux select_task_rq_rt / find_lowest_rq): its
/// previous one if it would preempt what runs there, else the allowed
/// CPU running the least important task if `p` would preempt that,
/// else its previous one
fn select_task_rq_rt(p: &KernelTask, allowed: &crate::cpumask::CpuSet, prev: u32) -> u32 {
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
fn select_task_rq(p: &KernelTask, why: Placement) -> u32 {
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
fn find_idlest_cpu(allowed: &crate::cpumask::CpuSet, from: u32) -> u32 {
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
fn select_idle_sibling(allowed: &crate::cpumask::CpuSet, prev: u32) -> u32 {
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
pub fn try_to_wake_up(p: &KernelTask, mode: WakeMode) -> bool {
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
    inner: crate::arch::IrqSpinlockGuard<'static, CpuRunQueue>,
    outer: crate::arch::IrqSpinlockGuard<'static, CpuRunQueue>,
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
    nr_running_all() as u64 + unint.max(0) as u64
}

/// `cpu`'s load for balancing: its task count, one more while an rt or
/// stop task runs there, which keeps the tasks queued behind it from
/// running (Linux lowers such a CPU's capacity, scale_rt_capacity)
fn balance_load(cpu: u32) -> u32 {
    let s = PERCPU_SCHEDS.get(cpu);
    s.nr_running.load(Ordering::Relaxed) + (s.curr_rank.load(Ordering::Relaxed) > 1) as u32
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
    let mut moved = [core::ptr::null::<KernelTask>(); NR_MIGRATE];
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
        let p = unsafe { &*moved[n] };
        if p.se.class() == Class::Fair {
            crate::task::fair::save_lag(&p.se, avg);
        }
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
    let t = PERCPU_SCHEDS.get(cpu).ticks.fetch_add(1, Ordering::Relaxed);
    if t.is_multiple_of(interval) {
        sched_balance_rq(cpu);
    }
}

/// A task to move and where (`migration_cpu_stop`'s argument)
struct Migration {
    task: *const KernelTask,
    dest: u32,
}

/// On the stopper of the task's CPU (Linux migration_cpu_stop): move
/// it to `dest` if it is still on this CPU's run queue. Nothing of this
/// CPU runs meanwhile, so a task on it is queued, not running. One that
/// sleeps (it moved meanwhile, or it is the caller waiting for this)
/// wakes on `dest` if it can (its `wake_cpu`).
fn migration_cpu_stop(arg: usize) {
    // SAFETY: the caller waits for this call, holding the task
    let m = unsafe { &*(arg as *const Migration) };
    // SAFETY: as above
    let p = unsafe { &*m.task };
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
fn move_queued_task(
    mut rq: crate::arch::IrqSpinlockGuard<'_, CpuRunQueue>,
    p: &KernelTask,
    dest: u32,
) {
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
pub fn set_cpus_allowed_ptr(p: &KernelTask, mask: &crate::cpumask::CpuSet) -> Result<(), i32> {
    let allowed = mask.and(&sched_cpus());
    if mask.and(&crate::smp::active_cpus()).is_empty() {
        return Err(22); // EINVAL
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
    crate::task::stop_machine::stop_one_cpu(
        cpu,
        migration_cpu_stop,
        &m as *const Migration as usize,
    );
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
    let m = Migration { task: &*me, dest };
    crate::task::stop_machine::stop_one_cpu(
        this,
        migration_cpu_stop,
        &m as *const Migration as usize,
    );
}

/// Wait until `p`, asleep, is off its CPU (Linux wait_task_inactive):
/// what its switch-out saves (user TLS, GS base, FP state) is complete
/// once its CPU has cleared `on_cpu`, which takes no longer than the
/// rest of a context switch. False if it woke meanwhile.
pub fn wait_task_inactive(p: &KernelTask) -> bool {
    while p.se.on_cpu() {
        if p.se.state() == RUNNING {
            return false;
        }
        core::hint::spin_loop();
    }
    p.se.state() != RUNNING
}

/// Tasks to wake once the caller's locks are released (Linux
/// wake_q_head): `add` under a lock takes a reference to the task and
/// links it through its `se.wake_q`; `wake_up` (or dropping the queue)
/// wakes them. A task already on some WakeQ is not added again: that
/// queue's wakeup stands for this one (Linux wake_q_add).
pub struct WakeQ {
    first: *mut (),
    last: *const KernelTask,
}

/// `se.wake_q` of the last task on a WakeQ (Linux WAKE_Q_TAIL)
const WAKE_Q_TAIL: *mut () = core::ptr::dangling_mut::<()>();

impl WakeQ {
    pub const fn new() -> Self {
        Self {
            first: WAKE_Q_TAIL,
            last: core::ptr::null(),
        }
    }

    /// Queue `p` for a wakeup (its waiter may return once it sees
    /// itself dequeued: the reference keeps `p` alive)
    pub fn add(&mut self, p: &KernelTask) {
        if p.se
            .wake_q
            .compare_exchange(
                core::ptr::null_mut(),
                WAKE_Q_TAIL,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return;
        }
        let raw = Arc::into_raw(task_ref(p)) as *mut ();
        // SAFETY: `last` is a task this queue holds a reference to
        match unsafe { self.last.as_ref() } {
            Some(l) => l.se.wake_q.store(raw, Ordering::Relaxed),
            None => self.first = raw,
        }
        self.last = raw as *const KernelTask;
    }

    /// Wake every queued task and drop the queue's references (thread
    /// context: the last reference may free the task)
    pub fn wake_up(&mut self) {
        let mut p = core::mem::replace(&mut self.first, WAKE_Q_TAIL);
        self.last = core::ptr::null();
        while p != WAKE_Q_TAIL {
            // SAFETY: added with Arc::into_raw
            let t = unsafe { Arc::from_raw(p as *const KernelTask) };
            p = t.se.wake_q.load(Ordering::Relaxed);
            // Off the queue before the wakeup, so a later waker can
            // queue it again (Linux wake_up_q)
            t.se.wake_q.store(core::ptr::null_mut(), Ordering::Release);
            try_to_wake_up(&t, WakeMode::Any);
        }
    }
}

impl Default for WakeQ {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for WakeQ {
    fn drop(&mut self) {
        self.wake_up();
    }
}

/// Make a task running on another CPU notice new work flags (a signal)
/// soon: a reschedule IPI interrupts it, and its return to user mode
/// runs the work (Linux kick_process). Nothing to do for a task on this
/// CPU (it is the caller, or not running) or not running at all.
pub fn kick_process(t: &KernelTask) {
    let cpu = t.cpu();
    let running = CurrentArch::current_task_ptr_of(cpu) == t as *const KernelTask as usize;
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
        let t = TICK_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
        crate::task::loadavg::tick(t);
    }
    crate::timer::run_local();
    crate::watchdog::tick();
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
    let resched = match me.se.class() {
        Class::Stop => false,
        Class::Rt => {
            let rr = me.se.policy() == crate::task::SCHED_RR && me.se.rr_tick();
            rr | this_sched().is_some_and(|s| s.lock.lock().rt_tick(now))
        }
        // A used-up slice (new deadline) lets EEVDF pick again (Linux
        // task_tick_fair -> update_deadline)
        Class::Fair => this_sched().is_some_and(|s| {
            let mut rq = s.lock.lock();
            crate::task::fair::update_curr(&me.se, now) | rq.rt_period_tick(now)
        }),
        Class::Idle => true,
    };
    if resched {
        me.set_tif(crate::task::tif::NEED_RESCHED);
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
        crate::hrtimer::HrClock::Monotonic,
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
    clock: crate::hrtimer::HrClock,
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
        if interruptible && crate::waitqueue::signal_pending() {
            set_current_state(SleepState::Running);
            return Err(deadline - now);
        }
        if this_sched().is_none() || current_tid() == 0 {
            set_current_state(SleepState::Running);
            core::hint::spin_loop();
            continue;
        }
        crate::hrtimer::schedule_hrtimeout(Some(deadline), clock);
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
    let tid = current_tid();
    if tid == 0 {
        return;
    }
    if let Some(addr) = crate::task::get_set_child_tid(tid) {
        use crate::arch::Uaccess;
        use crate::uaccess::put_user;
        if put_user::<Uaccess, i32>(addr, tid as i32).is_err() {
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
        current().nivcsw.fetch_add(1, Ordering::Relaxed);
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
        let now = crate::time::monotonic_ns();
        rq.update_curr_rt(now);
        if me.se.class() == Class::Fair {
            crate::task::fair::update_curr(&me.se, now);
            if !preempted {
                crate::task::fair::yield_task(&me.se);
            }
        }
        rq.enqueue_prev(&me, preempted);
    }
    let next = rq.pick_next();
    if core::ptr::eq(next, &*me) {
        return false;
    }
    context_switch_locked(sched, rq, &me, next);
    true
}

/// Get the current task's process ID
pub fn current_pid() -> Pid {
    current().pid
}

/// Get the current task's thread ID
pub fn current_tid() -> Tid {
    current().tid()
}

/// Get the current task's parent process ID
pub fn current_ppid() -> Pid {
    current().ppid()
}

/// Get the current task's process group ID
pub fn current_pgid() -> Pid {
    current().pgid()
}

/// Get the current task's session ID
pub fn current_sid() -> Pid {
    current().sid()
}

/// Check if a task exists by TID
pub fn task_exists(tid: Tid) -> bool {
    let table = TASKLIST.read();
    table.iter().any(|t| t.task.tid() == tid)
}

/// Increment minor page fault counter for current task
///
/// Called after successfully handling a demand-paging or COW fault
/// (no I/O required - page was already in memory or newly allocated).
pub fn increment_min_flt() {
    current().min_flt.fetch_add(1, Ordering::Relaxed);
}

/// Increment major page fault counter for current task
///
/// Called after successfully handling a swap-in fault
/// (I/O was required - page had to be read from disk).
pub fn increment_maj_flt() {
    current().maj_flt.fetch_add(1, Ordering::Relaxed);
}

/// Every thread of every process in group `pgid` (its pid links)
pub fn get_tids_by_pgid(pgid: Pid) -> alloc::vec::Vec<Tid> {
    let Some(pg) = crate::task::pid::find_pgrp(pgid) else {
        return alloc::vec::Vec::new();
    };
    let table = TASKLIST.read();
    table.pgrp_threads(&pg).map(|t| t.task.tid()).collect()
}

/// The processes of group `pgid`, by pid (their leaders on its list;
/// Linux do_each_pid_task PIDTYPE_PGID)
pub fn pgrp_pids(pgid: Pid) -> alloc::vec::Vec<Pid> {
    let Some(pg) = crate::task::pid::find_pgrp(pgid) else {
        return alloc::vec::Vec::new();
    };
    let table = TASKLIST.read();
    table.pgrp(&pg).map(|t| t.task.pid).collect()
}

/// Get all unique PIDs in the system
///
/// Returns a sorted, deduplicated list of all process IDs.
/// Used by kill(-1, sig) to signal all processes.
pub fn get_all_pids() -> alloc::vec::Vec<Pid> {
    let table = TASKLIST.read();
    let mut pids: alloc::vec::Vec<Pid> = table.iter().map(|t| t.task.pid).collect();
    pids.sort();
    pids.dedup();
    pids
}

/// Get the current task's FsStruct (filesystem context)
///
/// Returns None if there is no current task or no filesystem context.
pub fn current_fs() -> Option<alloc::sync::Arc<crate::fs::FsStruct>> {
    let tid = current_tid();
    if tid == 0 {
        return None;
    }
    crate::fs::get_task_fs(tid)
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

/// Look up a task's process group ID by PID
///
/// Returns None if the process is not found.
pub fn lookup_task_pgid(pid: Pid) -> Option<Pid> {
    let table = TASKLIST.read();
    table.get(pid).map(|t| t.task.pgid())
}

/// True if some process is in group `pgid`
pub fn pgrp_exists(pgid: Pid) -> bool {
    let Some(pg) = crate::task::pid::find_pgrp(pgid) else {
        return false;
    };
    let table = TASKLIST.read();
    table.pgrp(&pg).next().is_some()
}

/// Look up a task's session ID by PID
///
/// Returns None if the process is not found.
pub fn lookup_task_sid(pid: Pid) -> Option<Pid> {
    let table = TASKLIST.read();
    table.get(pid).map(|t| t.task.sid())
}

/// Look up a task's nice value by PID
///
/// Returns None if the process is not found.
pub fn lookup_task_nice(pid: Pid) -> Option<i32> {
    let table = TASKLIST.read();
    table.get(pid).map(|t| t.task.se.nice())
}

/// Look up a task's scheduling policy by PID
///
/// Returns None if the process is not found.
/// The returned policy includes SCHED_RESET_ON_FORK flag if set.
pub fn lookup_task_policy(pid: Pid) -> Option<i32> {
    let table = TASKLIST.read();
    table.get(pid).map(|t| {
        let mut policy = t.task.se.policy();
        if t.task.se.reset_on_fork() {
            policy |= crate::task::SCHED_RESET_ON_FORK;
        }
        policy
    })
}

/// Look up a task's real-time priority by PID
///
/// Returns None if the process is not found.
/// For SCHED_NORMAL tasks, returns 0.
pub fn lookup_task_rt_priority(pid: Pid) -> Option<i32> {
    let table = TASKLIST.read();
    table.get(pid).map(|t| t.task.se.rt_priority() as i32)
}

/// Get a task's CPU time statistics by TID
///
/// Returns (utime_ns, stime_ns) for the specified task.
/// Returns (0, 0) if the task is not found.
pub fn get_task_times(tid: Tid) -> (u64, u64) {
    let table = TASKLIST.read();
    table.get(tid).map(|t| t.task.times()).unwrap_or((0, 0))
}

/// Get aggregate CPU times for a process (all threads)
///
/// Returns (utime_ns, stime_ns) summed across all threads in the process.
/// Returns (0, 0) if no threads are found.
pub fn get_process_times(pid: Pid) -> (u64, u64) {
    let table = TASKLIST.read();
    let mut utime = 0u64;
    let mut stime = 0u64;
    for task in table.threads(pid) {
        let (u, s) = task.task.times();
        utime = utime.saturating_add(u);
        stime = stime.saturating_add(s);
    }
    (utime, stime)
}

/// Syscall entry: user time ends, system time starts
pub fn account_syscall_enter() {
    account_current(true);
}

/// Syscall return: system time ends, user time starts
pub fn account_syscall_exit() {
    account_current(false);
}

fn account_current(kernel: bool) {
    let me = current();
    if me.tid() != 0 {
        me.account(crate::time::monotonic_ns(), kernel);
    }
}

/// Look up a task's CPU affinity mask by PID
///
/// Returns None if the process is not found.
pub fn lookup_task_cpus_allowed(pid: Pid) -> Option<crate::cpumask::CpuSet> {
    let table = TASKLIST.read();
    table.get(pid).map(|t| t.task.cpus_mask.snapshot())
}

/// Set a task's scheduling policy and priority by PID
///
/// This is the core implementation for sched_setscheduler/sched_setparam.
///
/// # Arguments
/// * `pid` - Target process ID
/// * `policy` - New scheduling policy (may include SCHED_RESET_ON_FORK flag)
/// * `rt_priority` - New real-time priority (1-99 for SCHED_FIFO/RR, 0 otherwise)
///
/// # Returns
/// * Ok(()) on success
/// * Err(errno) on failure:
///   - ESRCH (3): Process not found
///   - EINVAL (22): Invalid policy or priority
///
/// # Locking
/// The task's pi_lock and rq lock (`change_class`): a queued task moves
/// to its new class's list at once.
pub fn set_task_scheduler(pid: Pid, policy: i32, rt_priority: i32) -> Result<(), i32> {
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
        return Err(22); // EINVAL
    }

    // Validate rt_priority
    if is_rt_policy(base_policy) {
        if !(MIN_RT_PRIO..=MAX_RT_PRIO).contains(&rt_priority) {
            return Err(22); // EINVAL
        }
    } else if rt_priority != 0 {
        return Err(22); // EINVAL - non-RT policies must have priority 0
    }

    let task = TASKLIST.read().task(pid).ok_or(3)?; // ESRCH
    // Not the stoppers nor an idle task (Linux: EINVAL for rq->stop)
    if matches!(task.se.class(), Class::Stop | Class::Idle) {
        return Err(22);
    }
    // Nothing changes (Linux __sched_setscheduler: same policy and
    // priority only updates reset-on-fork)
    if base_policy == task.se.policy() && rt_priority == task.se.rt_priority() as i32 {
        task.se.set_reset_on_fork(reset_on_fork);
        return Ok(());
    }
    let static_prio = task.se.static_prio();
    change_class(&task, |se| {
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

/// Set a task's CPU affinity mask by PID
///
/// # Arguments
/// * `pid` - Target process ID
/// * `mask` - New CPU affinity mask (bit N = CPU N is allowed)
///
/// # Returns
/// * Ok(()) on success
/// * Err(errno) on failure:
///   - ESRCH (3): Process not found
///   - EINVAL (22): Empty mask (no CPUs allowed)
///
/// # Locking
/// See [`set_cpus_allowed_ptr`]: a task on a CPU it may no longer use
/// is moved before this returns.
pub fn set_task_cpus_allowed(pid: Pid, mask: crate::cpumask::CpuSet) -> Result<(), i32> {
    let task = TASKLIST.read().task(pid).ok_or(3)?; // ESRCH
    // Bound kernel threads (Linux sched_setaffinity: EINVAL)
    if task.has_flag(crate::task::pf::NO_SETAFFINITY) {
        return Err(22);
    }
    set_cpus_allowed_ptr(&task, &mask)
}

/// Get the total number of tasks in the system
///
/// This counts all tasks including zombies, used by sysinfo syscall.
/// Acquires TASKLIST lock briefly.
pub fn task_count() -> usize {
    let table = TASKLIST.read();
    table.len()
}

/// Set a task's nice value by PID (Linux set_user_nice: static_prio,
/// whatever its policy; it counts for the fair class)
///
/// Error codes:
/// - ESRCH (3): Process not found
pub fn set_task_nice(pid: Pid, nice: i32) -> Result<(), i32> {
    let task = TASKLIST.read().task(pid).ok_or(3)?; // ESRCH
    let static_prio = (sched::DEFAULT_PRIO as i32 + nice.clamp(-20, 19)) as u8;
    change_class(&task, |se| {
        se.set_params(se.class(), se.policy(), static_prio, se.rt_priority())
    });
    Ok(())
}

/// Change `p`'s scheduling class or parameters with `f` (Linux
/// __sched_setscheduler, set_user_nice: dequeue, change, enqueue under
/// its pi_lock and rq lock): a queued task moves to its new list and
/// may preempt; the running one reschedules, so the next pick sees the
/// change
fn change_class(p: &KernelTask, f: impl FnOnce(&sched::SchedEntity)) {
    let _pi = p.pi_lock.lock();
    if !cpu_has_scheduler(p.cpu()) {
        f(&p.se);
        return;
    }
    let mut rq = task_rq_lock(p);
    let pp = p as *const KernelTask;
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
        p.se.vlag.store(0, Ordering::Relaxed);
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

/// Move process `target_pid` (every thread) to group `new_pgid`
///
/// Returns Ok(()) on success, Err(errno) on failure.
/// Error codes:
/// - ESRCH (3): Process not found
/// - EPERM (1): a session leader, another session, or no group
///   `new_pgid` in the caller's session
pub fn set_task_pgid(target_pid: Pid, new_pgid: Pid, caller_sid: Pid) -> Result<(), i32> {
    // Found before TASKLIST (the pid hash's lock is not nested in it)
    let target = crate::task::pid::find_pgrp(new_pgid);
    let mut old = Vec::new();
    let mut table = TASKLIST.write();
    let pg = setpgid_target(&table, target_pid, new_pgid, target.as_ref(), caller_sid)?;
    table.change_pids(target_pid, &pg, None, &mut old);
    drop(table);
    drop(old);
    Ok(())
}

/// The group process `pid` moves to (Linux sys_setpgid's checks): not
/// a session leader, in the caller's session; `pgid` is its own pid (a
/// new group) or a group of that session
fn setpgid_target(
    table: &GlobalTaskTable,
    pid: Pid,
    pgid: Pid,
    target: Option<&Arc<crate::task::pid::Pid>>,
    caller_sid: Pid,
) -> Result<Arc<crate::task::pid::Pid>, i32> {
    let l = table.get(pid).ok_or(3)?; // ESRCH
    let sid = l.task.sid();
    if pid == sid || sid != caller_sid {
        return Err(1); // EPERM
    }
    if pgid == pid {
        return l.thread_pid.clone().ok_or(3);
    }
    let pg = target.ok_or(1)?; // EPERM
    match table.pgrp(pg).next() {
        Some(g) if g.task.sid() == caller_sid => Ok(pg.clone()),
        _ => Err(1), // EPERM: no such group in the caller's session
    }
}

/// Create a new session for the current process
///
/// Returns the new session ID on success, Err(errno) on failure.
/// Error codes:
/// - EPERM (1): a session leader already, or a process group with the
///   caller's pid as id exists
pub fn create_session(caller_pid: Pid) -> Result<Pid, i32> {
    let mut old = Vec::new();
    let mut table = TASKLIST.write();
    let pid = {
        let l = table.get(caller_pid).ok_or(3)?; // ESRCH
        let pid = l.thread_pid.clone().ok_or(3)?;
        // A session leader already, or a process group with the
        // caller's id exists (Linux ksys_setsid)
        if l.task.sid() == caller_pid || table.pgrp(&pid).next().is_some() {
            return Err(1); // EPERM
        }
        pid
    };
    // The whole process: pid becomes sid and pgid
    table.change_pids(caller_pid, &pid, Some(&pid), &mut old);
    drop(table);
    drop(old);
    Ok(caller_pid)
}

/// Implementation of commit_creds - updates both per-CPU cache and TASKLIST
///
/// Like Linux's commit_creds() - atomically updates both storage locations
/// so context switch will restore the correct credentials.
pub fn commit_creds_impl(new: alloc::sync::Arc<Cred>) {
    let me = current();
    if me.tid() == 0 {
        return; // The boot task keeps its static root credentials
    }
    let old = me.cred();

    // Changing euid/egid/fsuid/fsgid makes the task non-dumpable
    // (suid_dumpable, default 0), so a less-privileged identity can't ptrace
    // or core-dump state obtained under the old one (Linux kernel/cred.c
    // commit_creds)
    let ids_changed = old.euid != new.euid
        || old.egid != new.egid
        || old.fsuid != new.fsuid
        || old.fsgid != new.fsgid;

    // Under TASKLIST: other tasks read our credentials under it; the
    // old ones are freed after it (only memory)
    let old = {
        let mut table = TASKLIST.write();
        table.get_mut(me.tid()).and_then(|mut t| {
            // SAFETY: the task itself
            if ids_changed && let Some(mm) = unsafe { me.task.mm() } {
                // On the mm: every thread sharing it (Linux set_dumpable(
                // task->mm))
                mm.set_dumpable(crate::task::dumpable::SUID_DUMP_DISABLE);
            }
            t.set_cred(new)
        })
    };
    drop(old);
}

/// Update current task's UID (all fields: uid, suid, euid, fsuid)
///
/// Called by sys_setuid when privileged (euid==0) changes UID.
/// Sets real, saved, effective, and filesystem UID - permanently drops root.
/// This matches Linux setuid() semantics for privileged callers.
///
/// Uses Linux prepare_creds/commit_creds pattern to ensure credentials
/// are persisted to TASKLIST for context switch.
pub fn set_current_uid_all(uid: crate::task::Uid) {
    let mut new_cred = crate::task::prepare_creds();
    new_cred.uid = uid;
    new_cred.suid = uid;
    new_cred.euid = uid;
    new_cred.fsuid = uid;
    commit_uid_change(new_cred);
}

/// Commit a uid change after the Linux capability fixup
/// (cap_emulate_setxuid)
fn commit_uid_change(mut new_cred: crate::task::Cred) {
    let old = current_cred();
    crate::task::cap_fix_setuid(&old, &mut new_cred, current_keep_caps());
    crate::task::commit_creds(alloc::sync::Arc::new(new_cred));
}

/// PR_SET_KEEPCAPS of the current task
fn current_keep_caps() -> bool {
    let tid = current_tid();
    TASKLIST.read().get(tid).is_some_and(|t| t.prctl.keep_caps)
}

/// Update current task's effective UID only (euid and fsuid)
///
/// Called by sys_setuid for non-root privilege drop.
/// Sets effective and filesystem UID, leaving real UID unchanged.
///
/// Uses Linux prepare_creds/commit_creds pattern to ensure credentials
/// are persisted to TASKLIST for context switch.
pub fn set_current_euid(euid: crate::task::Uid) {
    let mut new_cred = crate::task::prepare_creds();
    new_cred.euid = euid;
    new_cred.fsuid = euid; // fsuid follows euid
    commit_uid_change(new_cred);
}

/// Update current task's GID (all fields: gid, sgid, egid, fsgid)
///
/// Called by sys_setgid when privileged (euid==0) changes GID.
/// Sets real, saved, effective, and filesystem GID.
/// This matches Linux setgid() semantics for privileged callers.
///
/// Uses Linux prepare_creds/commit_creds pattern to ensure credentials
/// are persisted to TASKLIST for context switch.
pub fn set_current_gid_all(gid: crate::task::Gid) {
    let mut new_cred = crate::task::prepare_creds();
    new_cred.gid = gid;
    new_cred.sgid = gid;
    new_cred.egid = gid;
    new_cred.fsgid = gid;
    crate::task::commit_creds(alloc::sync::Arc::new(new_cred));
}

/// Update current task's effective GID only (egid and fsgid)
///
/// Called by sys_setgid for non-root privilege drop.
/// Sets effective and filesystem GID, leaving real GID unchanged.
///
/// Uses Linux prepare_creds/commit_creds pattern to ensure credentials
/// are persisted to TASKLIST for context switch.
pub fn set_current_egid(egid: crate::task::Gid) {
    let mut new_cred = crate::task::prepare_creds();
    new_cred.egid = egid;
    new_cred.fsgid = egid; // fsgid follows egid
    crate::task::commit_creds(alloc::sync::Arc::new(new_cred));
}

/// Get current task's saved UID (suid)
pub fn get_current_suid() -> crate::task::Uid {
    current_cred().suid
}

/// Get current task's saved GID (sgid)
pub fn get_current_sgid() -> crate::task::Gid {
    current_cred().sgid
}

/// Update current task's real, effective, and saved UIDs selectively
///
/// Called by sys_setresuid. Each field is only updated if Some.
/// When euid changes, fsuid follows (Linux semantics).
///
/// Uses Linux prepare_creds/commit_creds pattern to ensure credentials
/// are persisted to TASKLIST for context switch.
pub fn set_current_resuid(
    ruid: Option<crate::task::Uid>,
    euid: Option<crate::task::Uid>,
    suid: Option<crate::task::Uid>,
) {
    let mut new_cred = crate::task::prepare_creds();
    if let Some(uid) = ruid {
        new_cred.uid = uid;
    }
    if let Some(uid) = euid {
        new_cred.euid = uid;
        new_cred.fsuid = uid; // fsuid follows euid
    }
    if let Some(uid) = suid {
        new_cred.suid = uid;
    }
    commit_uid_change(new_cred);
}

/// Update current task's real, effective, and saved GIDs selectively
///
/// Called by sys_setresgid. Each field is only updated if Some.
/// When egid changes, fsgid follows (Linux semantics).
///
/// Uses Linux prepare_creds/commit_creds pattern to ensure credentials
/// are persisted to TASKLIST for context switch.
pub fn set_current_resgid(
    rgid: Option<crate::task::Gid>,
    egid: Option<crate::task::Gid>,
    sgid: Option<crate::task::Gid>,
) {
    let mut new_cred = crate::task::prepare_creds();
    if let Some(gid) = rgid {
        new_cred.gid = gid;
    }
    if let Some(gid) = egid {
        new_cred.egid = gid;
        new_cred.fsgid = gid; // fsgid follows egid
    }
    if let Some(gid) = sgid {
        new_cred.sgid = gid;
    }
    crate::task::commit_creds(alloc::sync::Arc::new(new_cred));
}

/// Get current task's filesystem UID (fsuid)
pub fn get_current_fsuid() -> crate::task::Uid {
    current_cred().fsuid
}

/// Get current task's filesystem GID (fsgid)
pub fn get_current_fsgid() -> crate::task::Gid {
    current_cred().fsgid
}

/// Update current task's real and effective UIDs (setreuid semantics)
///
/// Called by sys_setreuid. Each field is only updated if Some.
/// Also updates suid if new_suid is Some.
/// fsuid always follows euid (set to new euid value).
///
/// Uses Linux prepare_creds/commit_creds pattern to ensure credentials
/// are persisted to TASKLIST for context switch.
pub fn set_current_reuid(
    ruid: Option<crate::task::Uid>,
    euid: Option<crate::task::Uid>,
    new_suid: Option<crate::task::Uid>,
) {
    let mut new_cred = crate::task::prepare_creds();
    if let Some(uid) = ruid {
        new_cred.uid = uid;
    }
    if let Some(uid) = euid {
        new_cred.euid = uid;
        new_cred.fsuid = uid; // fsuid always follows euid
    }
    if let Some(uid) = new_suid {
        new_cred.suid = uid;
    }
    commit_uid_change(new_cred);
}

/// Update current task's real and effective GIDs (setregid semantics)
///
/// Called by sys_setregid. Each field is only updated if Some.
/// Also updates sgid if new_sgid is Some.
/// fsgid always follows egid (set to new egid value).
///
/// Uses Linux prepare_creds/commit_creds pattern to ensure credentials
/// are persisted to TASKLIST for context switch.
pub fn set_current_regid(
    rgid: Option<crate::task::Gid>,
    egid: Option<crate::task::Gid>,
    new_sgid: Option<crate::task::Gid>,
) {
    let mut new_cred = crate::task::prepare_creds();
    if let Some(gid) = rgid {
        new_cred.gid = gid;
    }
    if let Some(gid) = egid {
        new_cred.egid = gid;
        new_cred.fsgid = gid; // fsgid always follows egid
    }
    if let Some(gid) = new_sgid {
        new_cred.sgid = gid;
    }
    crate::task::commit_creds(alloc::sync::Arc::new(new_cred));
}

/// Set current task's filesystem UID directly
///
/// Called by sys_setfsuid. Does NOT auto-update when euid changes elsewhere.
///
/// Uses Linux prepare_creds/commit_creds pattern to ensure credentials
/// are persisted to TASKLIST for context switch.
pub fn set_current_fsuid(fsuid: crate::task::Uid) {
    let mut new_cred = crate::task::prepare_creds();
    new_cred.fsuid = fsuid;
    crate::task::cap_fix_setfsuid(&current_cred(), &mut new_cred);
    crate::task::commit_creds(alloc::sync::Arc::new(new_cred));
}

/// Set current task's filesystem GID directly
///
/// Called by sys_setfsgid. Does NOT auto-update when egid changes elsewhere.
///
/// Uses Linux prepare_creds/commit_creds pattern to ensure credentials
/// are persisted to TASKLIST for context switch.
pub fn set_current_fsgid(fsgid: crate::task::Gid) {
    let mut new_cred = crate::task::prepare_creds();
    new_cred.fsgid = fsgid;
    crate::task::commit_creds(alloc::sync::Arc::new(new_cred));
}

/// Replace current task's address space and jump to new entry point
///
/// This is used by execve to replace the current process image (Linux
/// exec_mmap): the task switches to `mm` first, then drops its user
/// reference on the old address space. That tears it down only if
/// nothing else uses it -- a vfork parent or other CLONE_VM threads keep
/// it alive. The function never returns.
///
/// # Arguments
/// * `mm` - The new address space (its top-level table is loaded)
/// * `entry_point` - The entry point address in the new program
/// * `user_sp` - The initial user stack pointer
pub fn exec_replace_image(
    mm: crate::mm::MmRef,
    entry_point: u64,
    user_sp: u64,
    ident: crate::task::exec::ExecIdentity,
    guard: crate::signal::CredGuard,
) -> ! {
    let tid = current_tid();
    let new = mm.arc().clone();

    // The new mm, name and dumpability together (Linux exec_mmap, then
    // __set_task_comm and set_dumpable), under cred_guard_mutex and
    // exec_update_lock
    let old = guard.exec_update(|| {
        let mut table = TASKLIST.write();
        let task = table.get_mut(tid);
        let mut task = task.expect("exec: current task not in the task table");
        task.page_table = ArchPageTable::new(new.pgd());
        new.set_dumpable(ident.dumpable);
        // The mm and name change as one under task_lock (Linux
        // exec_mmap, __set_task_comm): a reader sees both or neither
        let mut a = task.task.task_lock();
        // SAFETY: the task itself
        unsafe {
            a.set_comm(ident.name);
            a.set_mm(Some(mm))
        }
    });

    // The new image starts with no user GS base (Linux start_thread:
    // load_gs_index(0), gsbase 0)
    current().gsbase.store(0, Ordering::Relaxed);
    crate::arch::write_user_gsbase(0);

    // Leave the old tables before releasing them: their frames may be
    // reused at once by another CPU
    crate::mm::tlb::switch_mm(Some(&new));
    drop(new);
    drop(old);
    drop(guard);

    // Get kernel stack for syscall/interrupt return
    let kstack_top = {
        let table = TASKLIST.read();
        table.get(tid).map(|t| t.task.kstack_top).unwrap_or(0)
    };

    // Jump to user mode at the new entry point
    // This function never returns
    unsafe {
        CurrentArch::jump_to_user(entry_point, user_sp, kstack_top);
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
    // SAFETY: a task of this run queue, alive while it holds it
    let (next_kstack, next_mm, (next_tls, next_gs)) = make_current(unsafe { &*next });
    rq.curr = next;
    sched.nr_switches.fetch_add(1, Ordering::Relaxed);
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
    let tid = current_tid();
    let table = TASKLIST.read();
    table.get(tid).map(|t| t.personality).unwrap_or(0)
}

/// Set the current task's personality value
pub fn set_current_personality(personality: u32) {
    let tid = current_tid();
    let mut table = TASKLIST.write();
    if let Some(mut task) = table.get_mut(tid) {
        task.personality = personality;
    }
}

// =============================================================================
// I/O port permissions (x86-64 only)
// =============================================================================

/// Get the current task's emulated IOPL level (x86-64 only)
///
/// Returns 0-3, where 3 grants full I/O port access.
#[cfg(target_arch = "x86_64")]
pub fn current_iopl_emul() -> u8 {
    let tid = current_tid();
    let table = TASKLIST.read();
    table.get(tid).map(|t| t.iopl_emul).unwrap_or(0)
}

/// Set the current task's emulated IOPL level (x86-64 only)
///
/// Level must be 0-3. Caller is responsible for privilege checks.
#[cfg(target_arch = "x86_64")]
pub fn set_current_iopl_emul(level: u8) {
    let tid = current_tid();
    let mut table = TASKLIST.write();
    if let Some(mut task) = table.get_mut(tid) {
        task.iopl_emul = level;
    }
}
