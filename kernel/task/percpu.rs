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

use ::core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::arch::{ContextOps, CpuOps, FrameAlloc, IrqSpinlock, PerCpuOps, SchedArch, UserModeOps};
use crate::cpu::PerCpu;
use crate::printkln;
use crate::sync::spin::RwLock;
use crate::task::sched::{PriorityRunQueue, SleepEntry};
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
    /// Scheduling priority
    pub priority: Priority,
    /// Kernel stack top address
    pub kstack_top: u64,
    /// User stack top address
    pub user_stack_top: u64,
    /// Page table for the process
    pub page_table: ArchPageTable,
}

/// Sleep state of a task (Linux TASK_RUNNING / TASK_INTERRUPTIBLE /
/// TASK_UNINTERRUPTIBLE / TASK_KILLABLE)
///
/// This is the scheduling source of truth for sleeping, kept in the owning
/// CPU's run queue (IRQ-safe lock) so wakers in IRQ context can use it.
/// `TaskState` in the task table is informational only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SleepState {
    /// Runnable or running
    Running,
    /// Sleeping; woken by wakeups and by signals
    Interruptible,
    /// Sleeping; woken only by explicit wakeups / timeouts
    Uninterruptible,
    /// Sleeping; woken by explicit wakeups / timeouts and by SIGKILL
    /// only (Linux TASK_KILLABLE)
    Killable,
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
    /// One wakeup standing for both `self` and `other`: it wakes every
    /// sleeper either would (Any > Fatal > Interruptible)
    pub fn merge(self, other: WakeMode) -> WakeMode {
        use WakeMode::*;
        match (self, other) {
            (Any, _) | (_, Any) => Any,
            (Fatal, _) | (_, Fatal) => Fatal,
            _ => Interruptible,
        }
    }
}

/// Per-thread kernel context and scheduling state (owned by one CPU's rq)
pub struct KernelThreadContext {
    /// Context for switching (callee-saved registers)
    pub context: TaskContext,
    /// Base address of the kernel stack (`mm::vmstack`)
    pub stack_base: u64,
    /// Its size in bytes, freed when the task is dead; 0 if not owned
    pub stack_size: usize,
    /// Sleep state (see [`SleepState`])
    pub state: SleepState,
    /// True while the task sits in the priority run queue (prevents
    /// double-enqueue; the current task is never queued)
    pub queued: bool,
    /// Priority used when (re-)enqueueing; refreshed on yield
    pub priority: Priority,
    /// The task (the run queue's reference keeps it alive while it can
    /// run, and while per-CPU `curr` points at it)
    pub task: Option<TaskRef>,
}

impl KernelThreadContext {
    fn new(context: TaskContext, stack_base: u64, stack_size: usize, priority: Priority) -> Self {
        Self {
            context,
            stack_base,
            stack_size,
            state: SleepState::Running,
            queued: false,
            priority,
            task: None,
        }
    }
}

/// Spare run-queue slots per priority beyond the CPU's task count
const RQ_SLACK: usize = 16;

/// Per-CPU run queue
///
/// Each CPU has one of these. The run queue is protected by an IRQ-safe
/// spinlock to prevent deadlocks from timer interrupts. Only the owning CPU
/// ever takes this lock (cross-CPU wakeups go through `wake_list`).
pub struct CpuRunQueue {
    /// Priority-based run queue for this CPU (initialized lazily)
    pub queue: Option<PriorityRunQueue>,
    /// Currently running task TID on this CPU (0 = none/idle)
    pub current: Option<Tid>,
    /// Thread contexts for tasks on this CPU
    pub contexts: Vec<(Tid, KernelThreadContext)>,
    /// Number of tasks owned by this CPU (informational)
    pub nr_running: usize,
    /// TID of this CPU's idle task (never migrated, always runnable)
    pub idle_tid: Option<Tid>,
    /// Sleep queue for tasks waiting on timer (sorted by wake_tick)
    pub sleep_queue: Vec<SleepEntry>,
    /// Tasks that exited on this CPU, released once it has switched
    /// away from them (Linux finish_task_switch for TASK_DEAD)
    pub dead: Vec<DeadTask>,
}

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
    }
}

impl CpuRunQueue {
    /// Create an uninitialized run queue
    pub const fn uninit() -> Self {
        Self {
            queue: None,
            current: None,
            contexts: Vec::new(),
            nr_running: 0,
            idle_tid: None,
            sleep_queue: Vec::new(),
            dead: Vec::new(),
        }
    }

    /// Initialize the run queue
    pub fn init(&mut self) {
        if self.queue.is_none() {
            self.queue = Some(PriorityRunQueue::new());
        }
    }

    /// Get the run queue, panics if not initialized
    pub fn queue(&mut self) -> &mut PriorityRunQueue {
        self.queue.as_mut().expect("Run queue not initialized")
    }

    /// Scheduling entry for a task owned by this CPU
    fn entry(&self, tid: Tid) -> Option<&KernelThreadContext> {
        self.contexts
            .iter()
            .find(|(t, _)| *t == tid)
            .map(|(_, c)| c)
    }

    /// Scheduling entry for a task owned by this CPU, writable
    fn entry_mut(&mut self, tid: Tid) -> Option<&mut KernelThreadContext> {
        self.contexts
            .iter_mut()
            .find(|(t, _)| *t == tid)
            .map(|(_, c)| c)
    }

    /// Add a new task (not yet runnable; thread context)
    fn add_task(&mut self, task: &TaskRef, mut ctx: KernelThreadContext) {
        ctx.task = Some(task.clone());
        self.contexts.push((task.tid(), ctx));
        self.nr_running += 1;
        for p in self.priorities() {
            self.reserve_prio(p);
        }
    }

    /// Priorities this CPU's tasks use (few distinct values)
    fn priorities(&self) -> Vec<Priority> {
        let mut v: Vec<Priority> = Vec::new();
        for (_, c) in &self.contexts {
            if !v.contains(&c.priority) {
                v.push(c.priority);
            }
        }
        v
    }

    /// Room for every task of this CPU (plus slack for stale entries of
    /// exited tasks) in the queue of `prio`: IRQ-context wakeups enqueue
    /// without allocating (each task is queued at most once)
    fn reserve_prio(&mut self, prio: Priority) {
        let n = self.contexts.len() + RQ_SLACK;
        self.queue().reserve(prio, n);
    }

    /// Put `tid` on the priority queue unless it is current or already queued
    fn enqueue_task(&mut self, tid: Tid) {
        if self.current == Some(tid) {
            return;
        }
        let prio = match self.entry_mut(tid) {
            Some(e) if !e.queued => {
                e.queued = true;
                e.priority
            }
            _ => return,
        };
        self.queue().enqueue(tid, prio);
    }

    /// Wake `tid` if it sleeps in a state `mode` may wake (try_to_wake_up)
    ///
    /// Returns true if the task was sleeping and is now runnable. Waking a
    /// task that has set its state but not yet called `schedule()` just
    /// flips it back to Running, so its `schedule()` returns immediately.
    fn try_wake(&mut self, tid: Tid, mode: WakeMode) -> bool {
        let wake = match self.entry_mut(tid) {
            Some(e) => match (e.state, mode) {
                (SleepState::Running, _) => false,
                (SleepState::Interruptible, _) => true,
                (SleepState::Uninterruptible | SleepState::Killable, WakeMode::Any) => true,
                (SleepState::Killable, WakeMode::Fatal) => true,
                (SleepState::Uninterruptible, _) | (SleepState::Killable, _) => false,
            },
            None => false,
        };
        if wake {
            if let Some(e) = self.entry_mut(tid) {
                e.state = SleepState::Running;
            }
            self.enqueue_task(tid);
        }
        wake
    }

    /// Dequeue the next task to run (the idle task is always runnable)
    fn dequeue_next(&mut self) -> Tid {
        loop {
            let tid = self
                .queue()
                .dequeue_highest()
                .expect("Idle task should always be runnable");
            if let Some(e) = self.entry_mut(tid) {
                e.queued = false;
                return tid;
            }
            // Stale entry for an exited task: skip it
        }
    }

    /// Get context pointer for a task
    pub fn get_context(&self, tid: Tid) -> Option<*const TaskContext> {
        self.contexts
            .iter()
            .find(|(t, _)| *t == tid)
            .map(|(_, ctx)| &ctx.context as *const TaskContext)
    }

    /// Get mutable context pointer for a task
    pub fn get_context_mut(&mut self, tid: Tid) -> Option<*mut TaskContext> {
        self.contexts
            .iter_mut()
            .find(|(t, _)| *t == tid)
            .map(|(_, ctx)| &mut ctx.context as *mut TaskContext)
    }
}

/// Per-CPU scheduler state (lock + run queue)
///
/// This is accessed via per-CPU data. Each CPU only takes its own `lock`;
/// other CPUs post wakeups to `wake_list`, which the owner drains under its
/// rq lock (Linux ttwu_queue / wake_list pattern).
pub struct PerCpuScheduler {
    /// IRQ-safe lock protecting the run queue (owner CPU only)
    pub lock: IrqSpinlock<CpuRunQueue>,
    /// Remote wakeups for tasks owned by this CPU, at most one entry
    /// per task (`post_wake` merges), with capacity reserved for all of
    /// them when a task is added: posting never allocates (IRQ
    /// context). Leaf lock: nothing is acquired while holding it; nests
    /// inside `lock` when drained.
    wake_list: IrqSpinlock<Vec<(Tid, WakeMode)>>,
    /// Whether this CPU's scheduler is initialized
    pub initialized: AtomicBool,
    /// Context switches performed on this CPU (a QSBR RCU would treat a
    /// change as a quiescent state)
    pub nr_switches: AtomicU64,
}

impl PerCpuScheduler {
    /// Create an uninitialized per-CPU scheduler
    pub const fn new() -> Self {
        Self {
            lock: IrqSpinlock::new(CpuRunQueue::uninit()),
            wake_list: IrqSpinlock::new(Vec::new()),
            initialized: AtomicBool::new(false),
            nr_switches: AtomicU64::new(0),
        }
    }

    /// Apply wakeups posted by other CPUs (caller holds `self.lock`);
    /// the list keeps its capacity
    fn drain_wakes(&self, rq: &mut CpuRunQueue) {
        let mut list = self.wake_list.lock();
        for (tid, mode) in list.drain(..) {
            rq.try_wake(tid, mode);
        }
    }

    /// Post a remote wakeup without allocating: a task already listed
    /// keeps one entry, with the mode that wakes the most sleepers (a
    /// merged SIGKILL must still wake a `Killable` sleeper)
    fn post_wake(&self, tid: Tid, mode: WakeMode) {
        let mut list = self.wake_list.lock();
        if let Some(e) = list.iter_mut().find(|e| e.0 == tid) {
            e.1 = e.1.merge(mode);
            return;
        }
        debug_assert!(list.len() < list.capacity(), "wake_list would allocate");
        list.push((tid, mode));
    }

    /// Room in `wake_list` for each of the CPU's `n` tasks (thread
    /// context, after adding a task)
    fn reserve_wakes(&self, n: usize) {
        let mut list = self.wake_list.lock();
        if list.capacity() < n + RQ_SLACK {
            let extra = n + RQ_SLACK - list.len();
            list.reserve(extra);
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

    /// Its address space, for the whole borrow of the table
    pub fn mm_ref(&self) -> Option<&'a crate::mm::MmRef> {
        // SAFETY: TASKLIST is held for 'a (the view borrows it)
        unsafe { self.task.mm() }.as_ref()
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

/// Owner fields of a task, read under TASKLIST (the views borrow it)
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

            /// Its address space
            pub fn mm(&self) -> Option<&crate::mm::MmRef> {
                // SAFETY: as above
                unsafe { self.task.mm() }.as_ref()
            }

            /// Its descriptor table
            pub fn files(&self) -> Option<&Arc<crate::task::fdtable::Files>> {
                // SAFETY: as above
                unsafe { self.task.files() }.as_ref()
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

    /// Install an address space (rules of `set_cred`)
    pub fn set_mm(&mut self, mm: Option<crate::mm::MmRef>) -> Option<crate::mm::MmRef> {
        // SAFETY: as above
        unsafe { self.task.set_mm(mm) }
    }

    /// Install a descriptor table (rules of `set_cred`)
    pub fn set_files(
        &mut self,
        f: Option<Arc<crate::task::fdtable::Files>>,
    ) -> Option<Arc<crate::task::fdtable::Files>> {
        // SAFETY: as above
        unsafe { self.task.set_files(f) }
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

/// Scheduling enabled flag
pub static SCHEDULING_ENABLED: AtomicBool = AtomicBool::new(false);

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

    /// Its descriptor table
    pub fn files(&self) -> Option<Arc<crate::task::fdtable::Files>> {
        // SAFETY: the task itself
        unsafe { self.task.files() }.clone()
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

/// Timer tick counter (global)
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Get the per-CPU scheduler for a given CPU
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

        // Flush console before halting to ensure all output is sent
        crate::console::console_flush();

        // If we're still running, no other work - halt until interrupt
        // The STI;HLT pattern ensures we wake on the next interrupt atomically
        CurrentArch::enable_and_halt();
    }
}

/// Create a kernel task (pid 0, kernel page table) owned by `cpu_id`
///
/// `entry` runs on a fresh kernel stack with the rq lock
/// released (`finish_context_switch`) but interrupts still disabled; it must
/// enable them. A kernel thread is its own process (pid == tid, Linux);
/// an `idle` task is tid 0, outside TASKLIST (Linux swapper/N).
fn create_kernel_task(
    cpu_id: u32,
    name: &str,
    entry: usize,
    priority: Priority,
    start_asleep: bool,
    idle: bool,
) -> Result<Tid, &'static str> {
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

    let context = TaskContext::new_kernel_thread(entry, stack_top);
    let mut thread_ctx = KernelThreadContext::new(context, stack_base, KERNEL_STACK_SIZE, priority);
    if start_asleep {
        // Not runnable until wake_up_task (lets the creator finish setup)
        thread_ctx.state = SleepState::Uninterruptible;
    }

    let task_inner = crate::task::TaskInner {
        thread_pid,
        exit_code: 0,
        exit_signal: 0, // Kernel threads don't send exit signals
        pdeath_signal: 0,
        state: TaskState::Ready,
        priority,
        policy: if priority == PRIORITY_IDLE {
            crate::task::SCHED_IDLE
        } else {
            crate::task::SCHED_NORMAL
        },
        rt_priority: 0,
        reset_on_fork: false,
        cpus_allowed: crate::cpumask::CpuSet::one(cpu_id),
        page_table: ArchPageTable::kernel_identity(),
        trap_frame: Default::default(),
        // TLS fields (not used for idle task)
        clear_child_tid: 0,
        set_child_tid: 0,
        // Shared resources (kernel threads don't have user-space resources)
        fs: None,
        nsproxy: None,
        sighand: None,
        signal: None,
        io_context: None,
        sysvsem: None,
        // Per-task signal state
        robust_list: 0,
        // prctl state
        prctl: {
            let mut p = crate::task::PrctlState::default();
            let n = name.len().min(15);
            p.name[..n].copy_from_slice(&name.as_bytes()[..n]);
            p
        },
        // Process personality (execution domain)
        personality: 0,
        // NUMA memory policy (kernel threads use default)
        mempolicy: crate::mm::mempolicy::TaskMempolicy::new(),
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
        alloc::sync::Arc::new(Cred::ROOT),
        None,
        task_inner,
    );

    let task = Arc::new(task);
    if !idle {
        TASKLIST.write().insert(task.clone());
    }

    let sched = get_percpu_sched(cpu_id);
    let mut rq = sched.lock.lock();
    rq.init();
    rq.add_task(&task, thread_ctx);
    sched.reserve_wakes(rq.contexts.len());
    if !start_asleep {
        rq.enqueue_task(tid);
    }
    Ok(tid)
}

/// Create the idle task for a specific CPU and mark its scheduler ready
///
/// The idle task is always runnable at PRIORITY_IDLE (0). The CPU may enter
/// the scheduler only once this is done, so `initialized` is set last.
fn create_idle_task(cpu_id: u32) -> Result<Tid, &'static str> {
    let tid = create_kernel_task(
        cpu_id,
        "swapper",
        idle_task_entry as *const () as usize,
        PRIORITY_IDLE,
        false,
        true,
    )?;
    let sched = get_percpu_sched(cpu_id);
    sched.lock.lock().idle_tid = Some(tid);
    sched.initialized.store(true, Ordering::Release);
    printkln!("IDLE_TASK_CREATED: cpu={} tid={}", cpu_id, tid);
    Ok(tid)
}

/// Create a kernel thread on `cpu_id`, asleep (see `task::kthread`; start
/// it with `wake_up_task`)
pub fn create_kthread_task(
    cpu_id: u32,
    name: &str,
    entry: usize,
    priority: Priority,
) -> Result<Tid, &'static str> {
    if !get_percpu_sched(cpu_id).initialized.load(Ordering::Acquire) {
        return Err("CPU has no scheduler");
    }
    create_kernel_task(cpu_id, name, entry, priority, true, false)
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

/// Enable scheduling globally
pub fn enable() {
    SCHEDULING_ENABLED.store(true, Ordering::Release);
    printkln!("Scheduling enabled");
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
        exit_code: 0,
        exit_signal: crate::signal::SIGCHLD as i32, // Default: notify parent with SIGCHLD
        pdeath_signal: 0,
        state: TaskState::Running, // Will be running immediately
        priority: config.priority,
        policy: crate::task::SCHED_NORMAL,
        rt_priority: 0,
        reset_on_fork: false,
        cpus_allowed: crate::cpumask::CpuSet::all(),
        page_table: config.page_table,
        trap_frame: Default::default(),
        // TLS fields (initialized to 0, set by syscalls)
        clear_child_tid: 0,
        set_child_tid: 0,
        // Shared resources (will be initialized by caller via init_* functions)
        fs: None,
        nsproxy: None,
        sighand: None,
        signal: None,
        io_context: None,
        sysvsem: None,
        // Per-task signal state
        robust_list: 0,
        // prctl state; comm after the init binary, /bin/init (Linux
        // names init after the file it execs)
        prctl: crate::task::PrctlState {
            name: *b"init\0\0\0\0\0\0\0\0\0\0\0\0",
            ..crate::task::PrctlState::default()
        },
        // Process personality (execution domain)
        personality: 0,
        // NUMA memory policy (user processes start with default)
        mempolicy: crate::mm::mempolicy::TaskMempolicy::new(),
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
        alloc::sync::Arc::new(Cred::ROOT),
        Some(mm),
        task_inner,
    ));

    // Add to global table
    TASKLIST.write().insert(task.clone());

    // Create a kernel context for this task
    // Initialize with current kernel stack - when the user task makes a syscall,
    // we save its kernel-mode context here for sleeping/yielding
    let context = TaskContext::default();
    // The boot-allocated stack of the first task is never freed
    let thread_ctx = KernelThreadContext::new(
        context,
        config.kstack_top - KERNEL_STACK_SIZE as u64,
        0,
        config.priority,
    );

    // Add to run queue
    let sched = get_percpu_sched(cpu_id);
    {
        let mut rq = sched.lock.lock();
        rq.add_task(&task, thread_ctx);
        sched.reserve_wakes(rq.contexts.len());
        // The boot context becomes this task (Linux: init_task's
        // kernel_init thread execs /sbin/init)
        rq.current = Some(tid);
        CurrentArch::set_current_task_ptr(Arc::as_ptr(&task) as usize);
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
    drop(table);
    // The group's timers owned by the caller follow (after TASKLIST:
    // their locks are leaves taken under nothing)
    if let Some(sig) = sig {
        crate::posix_timer::retarget(&sig, tid, ltid);
    }
    // Its run-queue entry follows (after TASKLIST: rq -> TASKLIST)
    let sched = get_percpu_sched(me.cpu());
    let mut rq = sched.lock.lock();
    if let Some(e) = rq.contexts.iter_mut().find(|(t, _)| *t == tid) {
        e.0 = ltid;
    }
    if rq.current == Some(tid) {
        rq.current = Some(ltid);
    }
    drop(rq);
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
    /// Child's user stack top (required for CLONE_VM, 0 for fork)
    pub child_stack: u64,
    /// Parent's syscall return address (user RIP)
    pub parent_rip: u64,
    /// Parent's RFLAGS
    pub parent_rflags: u64,
    /// Parent's user stack pointer (for fork when child_stack == 0)
    pub parent_rsp: u64,
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
        parent_priority,
        parent_policy,
        parent_rt_priority,
        parent_reset_on_fork,
        parent_cpus_allowed,
        parent_pt_phys,
        parent_cred,
        parent_prctl,
        parent_personality,
        parent_mempolicy,
        parent_seccomp_mode,
        parent_seccomp_filter,
        parent_ptrace,
        parent_ptracer,
        parent_pid_ns,
        parent_real_parent,
    ) = {
        let table = TASKLIST.read();
        let parent = table.get(current_tid).ok_or(3)?; // ESRCH - no such process
        (
            parent.task.pid,
            parent.task.ppid(),
            parent.task.pgid(),
            parent.task.sid(),
            parent.priority,
            parent.policy,
            parent.rt_priority,
            parent.reset_on_fork,
            parent.cpus_allowed,
            parent.page_table.root_table_phys(),
            parent.cred_arc(),
            parent.prctl.clone(),
            parent.personality,
            parent.mempolicy,
            parent.task.seccomp_mode(),
            parent.seccomp_filter.clone(),
            parent.ptrace,
            parent.ptracer.clone(),
            parent
                .nsproxy
                .as_ref()
                .map_or_else(|| crate::ns::INIT_PID_NS.clone(), |n| n.pid_ns.clone()),
            parent.real_parent.clone(),
        )
    };

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

    // Handle SCHED_RESET_ON_FORK: child gets SCHED_NORMAL with nice 0
    let (child_policy, child_rt_priority, child_priority) = if parent_reset_on_fork {
        (crate::task::SCHED_NORMAL, 0, crate::task::PRIORITY_NORMAL)
    } else {
        (parent_policy, parent_rt_priority, parent_priority)
    };

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
    let parent_mm = {
        let table = TASKLIST.read();
        table.get(current_tid).and_then(|t| t.mm().cloned())
    };
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

    // Determine child's user stack pointer
    // For fork (child_stack == 0): inherit parent's stack
    // For clone with explicit stack: use provided stack
    let child_user_rsp = if config.child_stack == 0 {
        config.parent_rsp
    } else {
        config.child_stack
    };

    // Build child's TrapFrame on the child's kernel stack, below the arch's
    // reserve for the inherited FP/SIMD state (filled here, loaded by
    // clone_child_entry before it returns to user mode)
    // This will be restored by clone_child_entry via IRETQ
    let trapframe_size = core::mem::size_of::<<CurrentArch as Arch>::TrapFrame>() as u64;
    let trapframe_ptr = kstack_top - CurrentArch::CLONE_FPU_RESERVE - trapframe_size;
    CurrentArch::clone_child_fpu(kstack_top);

    // Use architecture-specific TrapFrame construction
    let child_trapframe =
        CurrentArch::clone_child_trapframe(config.parent_rip, config.parent_rflags, child_user_rsp);

    // Copy TrapFrame to child's kernel stack
    unsafe {
        let tf_ptr = trapframe_ptr as *mut <CurrentArch as Arch>::TrapFrame;
        core::ptr::write(tf_ptr, child_trapframe);
    }

    // Create TaskContext pointing to clone_child_entry
    // RSP points to the TrapFrame we just placed
    let context = CurrentArch::new_clone_child_context(trapframe_ptr);
    let thread_ctx =
        KernelThreadContext::new(context, stack_base, KERNEL_STACK_SIZE, child_priority);

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
        exit_code: 0,
        exit_signal: config.exit_signal, // From clone3 args (SIGCHLD for fork, 0 for threads)
        pdeath_signal: 0,                // Never inherited, must be set explicitly via prctl
        state: TaskState::Ready,
        priority: child_priority,
        policy: child_policy,
        rt_priority: child_rt_priority,
        reset_on_fork: false, // Never inherited - child must set explicitly
        cpus_allowed: parent_cpus_allowed, // Inherit CPU affinity from parent
        page_table: child_pt,
        trap_frame: Default::default(), // Not used - we have TrapFrame on stack
        // TLS fields - will be set based on clone flags below
        clear_child_tid: 0,
        set_child_tid: 0,
        // Shared resources (will be cloned/shared based on clone flags below)
        fs: None,
        nsproxy: None,
        sighand: None,
        signal: None,
        io_context: None,
        sysvsem: None,
        // Per-task signal state (always per-task, not shared)
        robust_list: 0,
        // prctl state: the name is inherited (dumpability lives in the
        // mm: shared with CLONE_VM, copied by dup_mm)
        prctl: crate::task::PrctlState {
            name: parent_prctl.name,
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
        // NUMA memory policy (inherited from parent)
        mempolicy: parent_mempolicy,
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
        crate::task::copy_creds(config.flags, &parent_cred),
        child_mm,
        child_task_inner,
    ));
    if parent_nproc_exceeded {
        child_task.set_flag(crate::task::pf::NPROC_EXCEEDED);
    }

    // Add to global task table
    {
        let mut table = TASKLIST.write();
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
    let sched = get_percpu_sched(cpu_id);
    {
        let mut rq = sched.lock.lock();
        rq.add_task(&child_task, thread_ctx);
        sched.reserve_wakes(rq.contexts.len());
        rq.enqueue_task(child_tid);
    }

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
    }
    if let Some(st) = status {
        mark_zombie(tid, st, group_dead);
        release_thread(tid);
    }

    // Let a parent sleeping in wait4/waitid re-check for zombies
    crate::task::proc::CHILD_EXIT_WQ.wake_all();

    let sched = current_percpu_sched().expect("No scheduler");
    let mut rq = sched.lock.lock();
    sched.drain_wakes(&mut rq);

    // Remove from the run queue (the Task stays in TASKLIST as a zombie);
    // its stack and mm go once this CPU runs something else
    let mut dead = DeadTask {
        stack: (0, 0),
        mm: dead_mm,
        task: None,
    };
    if let Some(tid) = rq.current.take() {
        if let Some(pos) = rq.contexts.iter().position(|(t, _)| *t == tid) {
            let (_, ctx) = rq.contexts.remove(pos);
            dead.stack = (ctx.stack_base, ctx.stack_size);
            dead.task = ctx.task;
        }
        rq.sleep_queue.retain(|e| e.tid != tid);
        rq.nr_running = rq.nr_running.saturating_sub(1);
    }
    rq.dead.push(dead);

    let next_tid = rq.dequeue_next();
    let (Some(next_ctx), Some((next_kstack, next_mm, next_tls))) =
        (rq.get_context(next_tid), make_current(&rq, next_tid))
    else {
        // No context available, fall back to halt loop
        drop(rq);
        loop {
            CurrentArch::halt();
        }
    };

    rq.current = Some(next_tid);
    sched.nr_switches.fetch_add(1, Ordering::Relaxed);

    // The rq lock stays held across the switch, as for any switch: the
    // next task releases it (its own guard, or finish_context_switch),
    // and only then frees our stack (`rq.dead`)
    check_switch_atomic();
    core::mem::forget(rq);

    // Switch to next task - never returns
    unsafe {
        switch_mm(next_mm);
        CurrentArch::context_switch_first(next_ctx, next_kstack, next_tls);
    }
}

/// Make `next` (on this run queue) this CPU's current task: per-CPU
/// `curr` points at it and /proc sees it running. Returns its kernel
/// stack for user entry (0 for kernel threads, which never return to
/// user mode), its address space (null for none) and its user TLS
/// register.
///
/// The caller holds the rq lock and `next` is not running, so nothing
/// changes its address space meanwhile (only the task itself does, or
/// its creator before it first runs), and the run queue's reference
/// keeps it alive until it has switched away for good.
fn make_current(rq: &CpuRunQueue, next: Tid) -> Option<(u64, *const crate::mm::Mm, u64)> {
    let t = rq.entry(next)?.task.as_ref()?;
    t.sleeping.store(false, Ordering::Relaxed);
    let kstack = if matches!(t.kind, TaskKind::KernelThread) {
        0
    } else {
        t.kstack_top
    };
    // SAFETY: see above
    let mm = unsafe { t.mm() }
        .as_ref()
        .map_or(core::ptr::null(), |m| Arc::as_ptr(m.arc()));
    CurrentArch::set_current_task_ptr(Arc::as_ptr(t) as usize);
    Some((kstack, mm, t.tls.load(Ordering::Relaxed)))
}

/// Load the address space of the task switched to (`make_current`)
///
/// # Safety
/// `mm` is null or an address space kept alive by that task.
unsafe fn switch_mm(mm: *const crate::mm::Mm) {
    // SAFETY: see above
    crate::mm::tlb::switch_mm(unsafe { mm.as_ref() });
}

/// Switch from the current task `cur` to `next` with `rq` held
///
/// The lock stays held across the switch and is released by whichever task
/// runs next (its own guard drop, or `finish_context_switch` for a new
/// task). The per-CPU syscall user-register block belongs to `cur` and is
/// kept on its kernel stack until it runs again.
fn context_switch_locked(
    sched: &PerCpuScheduler,
    mut rq: crate::arch::IrqSpinlockGuard<'_, CpuRunQueue>,
    cur: Tid,
    next: Tid,
) {
    check_switch_atomic();
    let me = current();
    let sleeps = rq
        .entry(cur)
        .is_some_and(|e| e.state != SleepState::Running);
    me.sleeping.store(sleeps, Ordering::Relaxed);
    // Save the outgoing task's user TLS register (user code may have
    // changed it without a syscall, e.g. msr tpidr_el0); the arch switch
    // loads `next`'s
    if !me.is_kthread() {
        me.tls
            .store(crate::arch::read_user_tls(), Ordering::Relaxed);
    }
    if rq.get_context(next).is_none() || rq.get_context(cur).is_none() {
        return;
    }
    let Some((next_kstack, next_mm, next_tls)) = make_current(&rq, next) else {
        return;
    };
    let (Some(curr_ctx), Some(next_ctx)) = (rq.get_context_mut(cur), rq.get_context(next)) else {
        return;
    };
    rq.current = Some(next);
    sched.nr_switches.fetch_add(1, Ordering::Relaxed);

    let saved = CurrentArch::save_syscall_user_state();
    unsafe {
        switch_mm(next_mm);
        CurrentArch::context_switch(curr_ctx, next_ctx, next_kstack, next_tls);
    }
    // Back on `cur` (the rq lock is held again; `rq` releases it)
    CurrentArch::restore_syscall_user_state(&saved);
    let dead = core::mem::take(&mut rq.dead);
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
    if !SCHEDULING_ENABLED.load(Ordering::Acquire) {
        return None;
    }
    current_percpu_sched().filter(|s| s.initialized.load(Ordering::Acquire))
}

/// Set the current task's sleep state (Linux set_current_state)
///
/// Call before re-checking the wait condition; a wakeup arriving after this
/// point makes the following `schedule()` return immediately.
pub fn set_current_state(state: SleepState) {
    let Some(sched) = this_sched() else { return };
    let mut rq = sched.lock.lock();
    if let Some(cur) = rq.current
        && let Some(e) = rq.entry_mut(cur)
    {
        e.state = state;
    }
}

/// Give up the CPU until woken, if the current task's state is not Running
///
/// Linux `schedule()` for a voluntary sleep: callers set their state with
/// [`set_current_state`], re-check their condition, then call this. If a
/// wakeup already arrived (state back to Running) it returns at once.
pub fn schedule() {
    crate::sync::might_sleep();
    let Some(sched) = this_sched() else { return };
    let mut rq = sched.lock.lock();
    sched.drain_wakes(&mut rq);
    let Some(cur) = rq.current else { return };
    match rq.entry_mut(cur) {
        Some(e) if e.state != SleepState::Running => {}
        _ => return,
    }
    let next = rq.dequeue_next();
    if next == cur {
        if let Some(e) = rq.entry_mut(cur) {
            e.state = SleepState::Running;
        }
        return;
    }
    context_switch_locked(sched, rq, cur, next);
}

/// Timeout value meaning "no timeout" for [`schedule_timeout`]
pub const MAX_SCHEDULE_TIMEOUT: u64 = u64::MAX;

/// `schedule()` with a timeout in scheduler ticks (Linux schedule_timeout)
///
/// The caller sets its state first. Returns the ticks left (0 if the
/// timeout expired); whichever of wakeup and timeout comes first ends the
/// sleep and the other is cancelled.
pub fn schedule_timeout(timeout: u64) -> u64 {
    if timeout == MAX_SCHEDULE_TIMEOUT {
        schedule();
        return MAX_SCHEDULE_TIMEOUT;
    }
    let Some(sched) = this_sched() else { return 0 };
    let expire = get_ticks().saturating_add(timeout);
    let cur = {
        let mut rq = sched.lock.lock();
        let Some(cur) = rq.current else { return 0 };
        if timeout == 0 {
            if let Some(e) = rq.entry_mut(cur) {
                e.state = SleepState::Running;
            }
            return 0;
        }
        let pos = rq.sleep_queue.partition_point(|e| e.wake_tick <= expire);
        rq.sleep_queue.insert(
            pos,
            SleepEntry {
                tid: cur,
                wake_tick: expire,
                priority: 0,
            },
        );
        cur
    };
    schedule();
    {
        let mut rq = sched.lock.lock();
        if let Some(pos) = rq
            .sleep_queue
            .iter()
            .position(|e| e.tid == cur && e.wake_tick == expire)
        {
            rq.sleep_queue.remove(pos);
        }
    }
    expire.saturating_sub(get_ticks())
}

/// Wake task `tid` owned by `cpu` (Linux try_to_wake_up)
///
/// Safe from any context, including IRQ handlers, but never while holding
/// this CPU's rq lock. Local wakeups take the own rq lock; remote ones are
/// posted to the owner's wake list and applied at its next scheduling point
/// or tick (no cross-CPU rq locking). Returns true if a local sleeper was
/// woken or a remote wakeup was posted.
pub fn wake_up_task(tid: Tid, cpu: u32, mode: WakeMode) -> bool {
    let Some(target) = PERCPU_SCHEDS.try_get(cpu) else {
        return false;
    };
    if !target.initialized.load(Ordering::Acquire) {
        return false;
    }
    if crate::cpu::try_this_id() == Some(cpu) {
        let mut rq = target.lock.lock();
        rq.try_wake(tid, mode)
    } else {
        target.post_wake(tid, mode);
        // Linux ttwu_queue_wakelist: an idle owner applies it now, not
        // at its next tick
        crate::smp::smp_send_reschedule(cpu);
        true
    }
}

/// Wake task `tid`, looking up its CPU (process context only: takes
/// TASKLIST; the caller must not hold it)
pub fn wake_up_tid(tid: Tid, mode: WakeMode) -> bool {
    let cpu = {
        let table = TASKLIST.read();
        match table.get(tid) {
            Some(t) => t.task.cpu(),
            None => return false,
        }
    };
    wake_up_task(tid, cpu, mode)
}

/// Scheduler tick period (both arches program a 10 ms local timer)
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
/// Every CPU's local timer fires every TICK_MS, so only CPU 0 advances the
/// global tick count (jiffies) and checks software timers; previously each
/// CPU advanced it, making time run ~Ncpu times too fast. All CPUs then do
/// their own scheduler work (remote wakeups, expired sleepers).
pub fn scheduler_tick() {
    crate::sync::lockdep::irq_enter();
    if crate::cpu::try_this_id() == Some(0) {
        TICK_COUNT.fetch_add(1, Ordering::Relaxed);
        // Wake ktimerd if a software timer expired
        crate::timer::check_timers();
    }
    wake_sleepers();
    crate::sync::lockdep::irq_exit();
}

/// Get current tick count
pub fn get_ticks() -> u64 {
    TICK_COUNT.load(Ordering::Relaxed)
}

/// Sleep until CLOCK_MONOTONIC reaches `deadline_ns`
///
/// Interruptible sleeps stop early when a signal is pending and return
/// `Err(ns_left)`. Wakes at tick granularity, never before the deadline.
pub fn sleep_until_ns(deadline_ns: u64, interruptible: bool) -> Result<(), u64> {
    let state = if interruptible {
        SleepState::Interruptible
    } else {
        SleepState::Uninterruptible
    };
    loop {
        set_current_state(state);
        let now = crate::time::monotonic_ns();
        if now >= deadline_ns {
            set_current_state(SleepState::Running);
            return Ok(());
        }
        if interruptible && crate::waitqueue::signal_pending() {
            set_current_state(SleepState::Running);
            return Err(deadline_ns - now);
        }
        if this_sched().is_none() || current_tid() == 0 {
            set_current_state(SleepState::Running);
            core::hint::spin_loop();
            continue;
        }
        schedule_timeout(ns_to_ticks(deadline_ns - now).max(1));
    }
}

/// Sleep the current task (uninterruptibly) for at least `ms` milliseconds
pub fn sleep_current_ms(ms: u64) {
    sleep_current_until(get_ticks().saturating_add(ms_to_ticks(ms)));
}

/// Called after context switch to release the scheduler lock
///
/// When context_switch is called, the IrqSpinlock guard is on the old task's
/// stack. After switching to the new task, we need to release the lock so
/// other code can acquire it.
pub fn finish_context_switch() {
    let sched = match current_percpu_sched() {
        Some(s) => s,
        None => return,
    };

    // Force unlock the scheduler lock - safe because we just switched to this
    // task and the old task won't run until we switch back to it
    unsafe {
        sched.lock.force_unlock();
    }
    // Free what tasks that exited here left (we are off their stacks)
    let dead = core::mem::take(&mut sched.lock.lock().dead);
    drop(dead);
}

/// Get the current task's TLS value
///
/// This is called from clone_child_entry to load the child's TLS register
/// before returning to user mode.
///
/// Returns 0 if no TLS is set for this task.
#[unsafe(no_mangle)]
pub extern "C" fn get_current_task_tls() -> u64 {
    let tid = current_tid();
    if tid == 0 {
        return 0;
    }
    current().tls.load(Ordering::Relaxed)
}

/// Write the child TID for CLONE_CHILD_SETTID (called from clone_child_entry)
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

/// Timer-tick scheduler work for this CPU (IRQ context)
///
/// Applies remote wakeups and wakes tasks whose sleep timeout expired. Only
/// touches this CPU's run queue; never takes TASKLIST.
pub fn wake_sleepers() {
    let current_tick = get_ticks();
    let sched = match current_percpu_sched() {
        Some(s) if s.initialized.load(Ordering::Acquire) => s,
        _ => return,
    };

    let mut rq = sched.lock.lock();
    sched.drain_wakes(&mut rq);
    while let Some(entry) = rq.sleep_queue.first() {
        if entry.wake_tick > current_tick {
            break; // sorted
        }
        let tid = entry.tid;
        rq.sleep_queue.remove(0);
        rq.try_wake(tid, WakeMode::Any);
    }
}

/// Yield the current thread (cooperative scheduling)
///
/// The current thread stays runnable and goes to the back of its priority
/// queue; another runnable thread (if any) gets to run.
pub fn yield_now() {
    crate::sync::might_sleep();
    let Some(sched) = this_sched() else { return };
    let mut rq = sched.lock.lock();
    sched.drain_wakes(&mut rq);
    let Some(cur) = rq.current else { return };

    // Refresh the cached priority (rq -> TASKLIST order); the idle
    // task (tid 0, not in the table) keeps its own
    let priority = TASKLIST.read().get(cur).map(|t| t.priority);
    let (changed, priority) = match rq.entry_mut(cur) {
        Some(e) => {
            let priority = priority.unwrap_or(e.priority);
            e.state = SleepState::Running;
            let changed = e.priority != priority;
            e.priority = priority;
            e.queued = true;
            (changed, priority)
        }
        None => return,
    };
    if changed {
        rq.reserve_prio(priority);
    }
    rq.queue().enqueue(cur, priority);

    let next = rq.dequeue_next();
    if next == cur {
        return;
    }
    context_switch_locked(sched, rq, cur, next);
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

/// Get all TIDs in a process group
pub fn get_tids_by_pgid(pgid: Pid) -> alloc::vec::Vec<Tid> {
    let table = TASKLIST.read();
    table
        .iter()
        .filter(|t| t.task.pgid() == pgid)
        .map(|t| t.task.tid())
        .collect()
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

/// True if some task is in process group `pgid`
pub fn pgrp_exists(pgid: Pid) -> bool {
    TASKLIST.read().iter().any(|t| t.task.pgid() == pgid)
}

/// Look up a task's session ID by PID
///
/// Returns None if the process is not found.
pub fn lookup_task_sid(pid: Pid) -> Option<Pid> {
    let table = TASKLIST.read();
    table.get(pid).map(|t| t.task.sid())
}

/// Look up a task's priority by PID
///
/// Returns None if the process is not found.
pub fn lookup_task_priority(pid: Pid) -> Option<Priority> {
    let table = TASKLIST.read();
    table.get(pid).map(|t| t.priority)
}

/// Look up a task's scheduling policy by PID
///
/// Returns None if the process is not found.
/// The returned policy includes SCHED_RESET_ON_FORK flag if set.
pub fn lookup_task_policy(pid: Pid) -> Option<i32> {
    let table = TASKLIST.read();
    table.get(pid).map(|t| {
        let mut policy = t.policy;
        if t.reset_on_fork {
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
    table.get(pid).map(|t| t.rt_priority)
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
    table.get(pid).map(|t| t.cpus_allowed)
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
/// Acquires TASKLIST lock. Does not re-queue task in run queue (policy
/// change takes effect on next schedule).
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

    let mut table = TASKLIST.write();
    match table.get_mut(pid) {
        Some(mut task) => {
            task.policy = base_policy;
            task.rt_priority = rt_priority;
            task.reset_on_fork = reset_on_fork;

            // Update internal priority based on policy
            // RT tasks get priority in range 200-254 (higher than normal)
            // Normal tasks keep their nice-based priority
            if is_rt_policy(base_policy) {
                // Map rt_priority 1-99 to internal priority 156-254
                // (above PRIORITY_NORMAL=128, below PRIORITY_REALTIME=255)
                task.priority = (155 + rt_priority) as Priority;
            } else if base_policy == SCHED_IDLE {
                task.priority = crate::task::PRIORITY_IDLE;
            }
            // For SCHED_NORMAL/BATCH, keep existing nice-based priority

            Ok(())
        }
        None => Err(3), // ESRCH
    }
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
/// Acquires TASKLIST lock. Migration to new CPU set takes effect on next
/// schedule.
pub fn set_task_cpus_allowed(pid: Pid, mask: crate::cpumask::CpuSet) -> Result<(), i32> {
    // At least one CPU the task can run on (Linux __sched_setaffinity:
    // the mask and cpu_active_mask intersect)
    if mask.and(&crate::smp::active_cpus()).is_empty() {
        return Err(22); // EINVAL
    }

    let mut table = TASKLIST.write();
    match table.get_mut(pid) {
        Some(mut task) => {
            task.cpus_allowed = mask;
            Ok(())
        }
        None => Err(3), // ESRCH
    }
}

/// Get the total number of tasks in the system
///
/// This counts all tasks including zombies, used by sysinfo syscall.
/// Acquires TASKLIST lock briefly.
pub fn task_count() -> usize {
    let table = TASKLIST.read();
    table.len()
}

/// Set a task's priority by PID
///
/// Returns Ok(()) on success, Err(errno) on failure.
/// Error codes:
/// - ESRCH (3): Process not found
pub fn set_task_priority(pid: Pid, priority: Priority) -> Result<(), i32> {
    let mut table = TASKLIST.write();
    match table.get_mut(pid) {
        Some(mut task) => {
            task.priority = priority;
            Ok(())
        }
        None => Err(3), // ESRCH
    }
}

/// Set a task's process group ID
///
/// Returns Ok(()) on success, Err(errno) on failure.
/// Error codes:
/// - ESRCH (3): Process not found
/// - EPERM (1): Cannot change session leader's PGID
/// - EINVAL (22): Target PGID doesn't exist in same session
pub fn set_task_pgid(target_pid: Pid, new_pgid: Pid, caller_sid: Pid) -> Result<(), i32> {
    let mut table = TASKLIST.write();

    let (tid, pid, sid) = match table.get(target_pid) {
        Some(t) => (t.task.tid(), t.task.pid, t.task.sid()),
        None => return Err(3), // ESRCH
    };

    // Cannot change PGID of a session leader (pid == sid), nor move to a
    // different session
    if pid == sid || sid != caller_sid {
        return Err(1); // EPERM
    }

    // A new group (pgid == target_pid), or one that exists in the
    // same session
    if new_pgid != target_pid
        && !table
            .iter()
            .any(|t| t.task.pgid() == new_pgid && t.task.sid() == caller_sid)
    {
        return Err(1); // EPERM - target PGID doesn't exist in same session
    }

    if let Some(t) = table.get_mut(tid) {
        t.task
            .pgid
            .store(new_pgid, core::sync::atomic::Ordering::Relaxed);
    }
    Ok(())
}

/// Create a new session for the current process
///
/// Returns the new session ID on success, Err(errno) on failure.
/// Error codes:
/// - EPERM (1): Process is already a process group leader
pub fn create_session(caller_pid: Pid, caller_pgid: Pid) -> Result<Pid, i32> {
    // Cannot create session if already a process group leader
    if caller_pid == caller_pgid {
        return Err(1); // EPERM
    }

    let mut table = TASKLIST.write();

    // Find the calling process
    let task = match table.get_mut(caller_pid) {
        Some(t) => t,
        None => return Err(3), // ESRCH
    };

    // Create new session: pid becomes sid and pgid
    task.task
        .sid
        .store(caller_pid, core::sync::atomic::Ordering::Relaxed);
    task.task
        .pgid
        .store(caller_pid, core::sync::atomic::Ordering::Relaxed);

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
            if ids_changed && let Some(mm) = t.mm() {
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
        task.prctl.name = ident.name;
        new.set_dumpable(ident.dumpable);
        task.set_mm(Some(mm))
    });

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
    sched.drain_wakes(&mut rq);
    let next = rq.dequeue_next();
    let Some(next_ctx) = rq.get_context(next) else {
        return;
    };
    let Some((next_kstack, next_mm, next_tls)) = make_current(&rq, next) else {
        return;
    };
    rq.current = Some(next);
    sched.nr_switches.fetch_add(1, Ordering::Relaxed);
    // Held across the switch like any other: the task switched to
    // releases it (finish_context_switch or its own guard). Dropping it
    // here left the per-CPU preempt count at -1 after that release.
    core::mem::forget(rq); // context_switch_first never returns
    unsafe {
        switch_mm(next_mm);
        CurrentArch::context_switch_first(next_ctx, next_kstack, next_tls);
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
