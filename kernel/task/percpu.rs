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
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::arch::{ContextOps, CpuOps, FrameAlloc, IrqSpinlock, PerCpuOps, SchedArch, UserModeOps};
use crate::printkln;
use crate::task::sched::{PriorityRunQueue, SleepEntry};
use crate::task::{
    Cred, CurrentTask, PRIORITY_IDLE, Pid, Priority, Task, TaskKind, TaskState, Tid,
};
use spin::Mutex;

/// Vfork completion state
///
/// When CLONE_VFORK is used, the parent must wait until the child calls
/// exec() or _exit(). This table maps child TID -> completion flag.
/// When the child completes, the flag is set to true and the parent wakes.
static VFORK_COMPLETION: Mutex<BTreeMap<Tid, bool>> = Mutex::new(BTreeMap::new());

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
        let mut table = TASK_TABLE.lock();
        if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
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

/// Register a vfork child for completion tracking
///
/// Called from do_clone when CLONE_VFORK is set.
fn register_vfork_child(child_tid: Tid) {
    VFORK_COMPLETION.lock().insert(child_tid, false);
}

/// Wait for vfork child to complete (exec or exit)
///
/// Called by parent after creating vfork child.
/// Uses busy-wait with yield to avoid blocking other tasks.
fn wait_for_vfork(child_tid: Tid) {
    loop {
        {
            let table = VFORK_COMPLETION.lock();
            if let Some(&completed) = table.get(&child_tid) {
                if completed {
                    break;
                }
            } else {
                // Child entry removed (shouldn't happen), stop waiting
                break;
            }
        }

        // Yield to let child run
        yield_now();
    }

    // Clean up the entry
    VFORK_COMPLETION.lock().remove(&child_tid);
}

/// Signal vfork completion (called by child on exec or exit)
///
/// This wakes the parent that was blocked in wait_for_vfork().
pub fn signal_vfork_done(tid: Tid) {
    let mut table = VFORK_COMPLETION.lock();
    if let Some(completed) = table.get_mut(&tid) {
        *completed = true;
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

// Get MAX_CPUS from the architecture
const MAX_CPUS: usize = <CurrentArch as PerCpuOps>::MAX_CPUS;

/// Size of kernel stack per thread (16KB)
pub const KERNEL_STACK_SIZE: usize = 16 * 1024;

// Re-export the architecture's page table type for convenience
type ArchPageTable = <CurrentArch as SchedArch>::SchedPageTable;

/// Configuration for creating a user task
///
/// Groups all parameters needed to create a user task, avoiding clippy's
/// too_many_arguments warning while keeping the API clear.
pub struct UserTaskConfig {
    /// Process ID
    pub pid: Pid,
    /// Thread ID
    pub tid: Tid,
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

/// Page size
const PAGE_SIZE: u64 = 4096;

/// Per-thread kernel context (stored alongside Task)
pub struct KernelThreadContext {
    /// Context for switching (callee-saved registers)
    pub context: TaskContext,
    /// Base address of allocated kernel stack (for freeing)
    #[allow(dead_code)]
    pub stack_base: u64,
}

/// Per-CPU run queue
///
/// Each CPU has one of these. The run queue is protected by an IRQ-safe
/// spinlock to prevent deadlocks from timer interrupts.
pub struct CpuRunQueue {
    /// Priority-based run queue for this CPU (initialized lazily)
    pub queue: Option<PriorityRunQueue>,
    /// Currently running task TID on this CPU (0 = none/idle)
    pub current: Option<Tid>,
    /// Thread contexts for tasks on this CPU
    pub contexts: Vec<(Tid, KernelThreadContext)>,
    /// Number of runnable tasks (including current)
    pub nr_running: usize,
    /// TID of this CPU's idle task (never migrated, always runnable)
    pub idle_tid: Option<Tid>,
    /// Sleep queue for tasks waiting on timer
    pub sleep_queue: Vec<SleepEntry>,
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
/// This is accessed via per-CPU data. Each CPU only takes its own lock.
pub struct PerCpuScheduler {
    /// IRQ-safe lock protecting the run queue
    pub lock: IrqSpinlock<CpuRunQueue>,
    /// Whether this CPU's scheduler is initialized
    pub initialized: AtomicBool,
}

impl PerCpuScheduler {
    /// Create an uninitialized per-CPU scheduler
    pub const fn new() -> Self {
        Self {
            lock: IrqSpinlock::new(CpuRunQueue::uninit()),
            initialized: AtomicBool::new(false),
        }
    }

    /// Initialize this CPU's scheduler (called once per CPU)
    pub fn init(&self) {
        if self.initialized.swap(true, Ordering::SeqCst) {
            return; // Already initialized
        }
        // Initialize the run queue
        let mut guard = self.lock.lock();
        guard.init();
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
static PERCPU_SCHEDS: [PerCpuScheduler; MAX_CPUS] = [const { PerCpuScheduler::new() }; MAX_CPUS];

/// Global task table (for looking up tasks by TID)
///
/// Protected by its own lock, separate from per-CPU run queues.
/// This is only used for fork/exit and task lookup, not hot-path scheduling.
pub struct GlobalTaskTable {
    /// All tasks in the system
    pub tasks: Vec<Task<CurrentArch, ArchPageTable>>,
    next_tid: Tid,
    next_pid: u64,
}

impl GlobalTaskTable {
    const fn new() -> Self {
        Self {
            tasks: Vec::new(),
            next_tid: 1,
            next_pid: 1,
        }
    }
}

/// Global task table containing all tasks in the system
pub static TASK_TABLE: Mutex<GlobalTaskTable> = Mutex::new(GlobalTaskTable::new());

/// Scheduling enabled flag
pub static SCHEDULING_ENABLED: AtomicBool = AtomicBool::new(false);

/// Timer tick counter (global)
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Get the per-CPU scheduler for a given CPU
fn get_percpu_sched(cpu_id: u32) -> &'static PerCpuScheduler {
    &PERCPU_SCHEDS[cpu_id as usize]
}

/// Get the per-CPU scheduler for the current CPU
pub fn current_percpu_sched() -> Option<&'static PerCpuScheduler> {
    CurrentArch::try_current_cpu_id().map(|cpu_id| &PERCPU_SCHEDS[cpu_id as usize])
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

/// Size of idle task stack (8KB - smaller than regular threads)
const IDLE_STACK_SIZE: usize = 8 * 1024;

/// Create the idle task for a specific CPU
///
/// Called once per CPU during scheduler initialization.
/// The idle task is always runnable at PRIORITY_IDLE (0).
fn create_idle_task<FA: FrameAlloc<PhysAddr = u64>>(
    cpu_id: u32,
    frame_alloc: &mut FA,
) -> Result<Tid, &'static str> {
    // Allocate TID from global table, but use pid=0 for kernel idle task
    // This follows Linux convention where pid=0 is the swapper/idle process
    let tid = {
        let mut table = TASK_TABLE.lock();
        let tid = table.next_tid;
        table.next_tid += 1;
        // Don't increment next_pid - idle task uses special pid=0
        tid
    };
    // Idle task gets special pid=0 (kernel swapper/idle convention)
    let pid = 0;

    // Allocate kernel stack for idle task (8KB = 2 pages)
    let stack_pages = IDLE_STACK_SIZE / PAGE_SIZE as usize;
    let mut stack_base: Option<u64> = None;

    for i in 0..stack_pages {
        let frame = frame_alloc
            .alloc_frame()
            .ok_or("Out of memory for idle task stack")?;

        if i == 0 {
            stack_base = Some(frame);
        }

        // Zero the page
        unsafe {
            core::ptr::write_bytes(frame as *mut u8, 0, PAGE_SIZE as usize);
        }
    }

    let stack_base = stack_base.unwrap();
    let stack_top = stack_base + IDLE_STACK_SIZE as u64;

    // Create the task context
    let context = TaskContext::new_kernel_thread(idle_task_entry as *const () as usize, stack_top);
    let thread_ctx = KernelThreadContext {
        context,
        stack_base,
    };

    // Create the task structure
    // Idle task: ppid=0 (no parent), pgid=pid (own group), sid=pid (own session)
    let task = Task {
        magic: crate::task::TASK_MAGIC,
        pid,
        tid,
        tgid: pid, // Thread group leader (tgid == pid)
        ppid: 0,
        pgid: pid,
        sid: pid,
        // Exit handling (kernel threads don't exit normally)
        exit_code: 0,
        exit_signal: 0, // Kernel threads don't send exit signals
        pdeath_signal: 0,
        // Accounting (kernel threads don't track CPU time)
        utime: 0,
        stime: 0,
        start_time: crate::time::monotonic_ns(),
        last_run_ns: crate::time::monotonic_ns(),
        in_kernel: true, // Kernel threads always in kernel mode
        nvcsw: 0,
        nivcsw: 0,
        min_flt: 0,
        maj_flt: 0,
        cred: alloc::sync::Arc::new(Cred::ROOT), // Kernel threads run as root
        kind: TaskKind::KernelThread,
        state: TaskState::Ready,
        priority: PRIORITY_IDLE,
        policy: crate::task::SCHED_IDLE,
        rt_priority: 0,
        reset_on_fork: false,
        cpus_allowed: crate::task::CPU_MASK_ALL,
        page_table: ArchPageTable::kernel_identity(),
        trap_frame: Default::default(),
        kstack_top: stack_top,
        user_stack_top: None,
        cached_pages: Vec::new(),
        // TLS fields (not used for idle task)
        tls_base: 0,
        clear_child_tid: 0,
        set_child_tid: 0,
        // Shared resources (kernel threads don't have user-space resources)
        mm: None,
        files: None,
        fs: None,
        nsproxy: None,
        sighand: None,
        signal: None,
        io_context: None,
        sysvsem: None,
        // Per-task signal state
        signal_state: crate::signal::TaskSignalState::new(),
        tif_sigpending: core::sync::atomic::AtomicBool::new(false),
        robust_list: 0,
        // prctl state
        prctl: crate::task::PrctlState::default(),
        // Process personality (execution domain)
        personality: 0,
        // NUMA memory policy (kernel threads use default)
        mempolicy: crate::mm::mempolicy::TaskMempolicy::new(),
        // Seccomp state (kernel threads don't use seccomp)
        seccomp_mode: crate::seccomp::SECCOMP_MODE_DISABLED,
        seccomp_filter: None,
        // I/O port permissions (x86-64 only, kernel threads don't use I/O ports)
        #[cfg(target_arch = "x86_64")]
        iopl_emul: 0,
        // Ptrace state (kernel threads are not traced)
        ptrace: 0,
        ptracer_tid: None,
        real_parent_tid: 0,
        ptrace_message: 0,
        ptrace_options: 0,
    };

    // Add task to global table
    {
        let mut table = TASK_TABLE.lock();
        table.tasks.push(task);
    }

    // Add to this CPU's run queue
    let sched = get_percpu_sched(cpu_id);
    {
        let mut rq = sched.lock.lock();
        rq.contexts.push((tid, thread_ctx));
        rq.queue().enqueue(tid, PRIORITY_IDLE);
        rq.nr_running += 1;
        rq.idle_tid = Some(tid);
    }

    printkln!("IDLE_TASK_CREATED: cpu={} tid={}", cpu_id, tid);

    Ok(tid)
}

/// Initialize the global scheduler with idle task for BSP
///
/// Must be called with a frame allocator to create the BSP's idle task.
pub fn init<FA: FrameAlloc<PhysAddr = u64>>(frame_alloc: &mut FA) {
    // Initialize BSP's per-CPU scheduler
    let cpu_id = CurrentArch::try_current_cpu_id().unwrap_or(0);

    PERCPU_SCHEDS[cpu_id as usize].init();
    printkln!("Per-CPU scheduler initialized for CPU {}", cpu_id);

    // Create idle task for BSP
    match create_idle_task(cpu_id, frame_alloc) {
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
pub fn create_user_task(config: UserTaskConfig) -> Result<(), &'static str> {
    let cpu_id = CurrentArch::try_current_cpu_id().unwrap_or(0);

    // Create Task entry
    let task = Task {
        magic: crate::task::TASK_MAGIC,
        pid: config.pid,
        tid: config.tid,
        tgid: config.pid, // Thread group leader (tgid == pid)
        ppid: config.ppid,
        pgid: config.pgid,
        sid: config.sid,
        // Exit handling
        exit_code: 0,
        exit_signal: crate::signal::SIGCHLD as i32, // Default: notify parent with SIGCHLD
        pdeath_signal: 0,
        // Accounting
        utime: 0,
        stime: 0,
        start_time: crate::time::monotonic_ns(),
        last_run_ns: crate::time::monotonic_ns(),
        in_kernel: false, // User tasks start in user mode
        nvcsw: 0,
        nivcsw: 0,
        min_flt: 0,
        maj_flt: 0,
        cred: alloc::sync::Arc::new(Cred::ROOT), // Initial user process starts as root
        kind: TaskKind::UserProcess,
        state: TaskState::Running, // Will be running immediately
        priority: config.priority,
        policy: crate::task::SCHED_NORMAL,
        rt_priority: 0,
        reset_on_fork: false,
        cpus_allowed: crate::task::CPU_MASK_ALL,
        page_table: config.page_table,
        trap_frame: Default::default(),
        kstack_top: config.kstack_top,
        user_stack_top: Some(config.user_stack_top),
        cached_pages: Vec::new(),
        // TLS fields (initialized to 0, set by syscalls)
        tls_base: 0,
        clear_child_tid: 0,
        set_child_tid: 0,
        // Shared resources (will be initialized by caller via init_* functions)
        mm: None,
        files: None,
        fs: None,
        nsproxy: None,
        sighand: None,
        signal: None,
        io_context: None,
        sysvsem: None,
        // Per-task signal state
        signal_state: crate::signal::TaskSignalState::new(),
        tif_sigpending: core::sync::atomic::AtomicBool::new(false),
        robust_list: 0,
        // prctl state
        prctl: crate::task::PrctlState::default(),
        // Process personality (execution domain)
        personality: 0,
        // NUMA memory policy (user processes start with default)
        mempolicy: crate::mm::mempolicy::TaskMempolicy::new(),
        // Seccomp state (disabled initially)
        seccomp_mode: crate::seccomp::SECCOMP_MODE_DISABLED,
        seccomp_filter: None,
        // I/O port permissions (x86-64 only, no I/O port access initially)
        #[cfg(target_arch = "x86_64")]
        iopl_emul: 0,
        // Ptrace state (not traced initially)
        ptrace: 0,
        ptracer_tid: None,
        real_parent_tid: config.ppid,
        ptrace_message: 0,
        ptrace_options: 0,
    };

    // Add to global table
    {
        let mut table = TASK_TABLE.lock();
        table.tasks.push(task);
        // Reserve tid+1 for next task
        if table.next_tid <= config.tid {
            table.next_tid = config.tid + 1;
        }
        if table.next_pid <= config.pid {
            table.next_pid = config.pid + 1;
        }
    }

    // Create a kernel context for this task
    // Initialize with current kernel stack - when the user task makes a syscall,
    // we save its kernel-mode context here for sleeping/yielding
    let context = TaskContext::default();
    let thread_ctx = KernelThreadContext {
        context,
        stack_base: config.kstack_top - KERNEL_STACK_SIZE as u64,
    };

    // Add to run queue
    let sched = get_percpu_sched(cpu_id);
    {
        let mut rq = sched.lock.lock();
        rq.contexts.push((config.tid, thread_ctx));
        rq.current = Some(config.tid); // Mark as currently running
        rq.nr_running += 1;
    }

    // Initialize filesystem context for the init task
    if let Some(fs) = crate::fs::FsStruct::new_root() {
        crate::fs::init_task_fs(config.tid, fs);
    }

    // Initialize FD table for the init task
    crate::task::fdtable::init_task_fd(config.tid, crate::task::fdtable::create_empty_fd_table());

    // Initialize namespace context for the init task
    crate::ns::init_task_ns(config.tid, crate::ns::INIT_NSPROXY.clone());

    // Initialize signal handlers for the init task
    crate::signal::init_task_signal(
        config.tid,
        alloc::sync::Arc::new(crate::signal::SigHand::new()),
    );

    // Initialize memory descriptor for the init task
    crate::mm::init_task_mm(config.tid, crate::mm::create_default_mm());

    printkln!("USER_TASK_CREATED: pid={} tid={}", config.pid, config.tid);
    Ok(())
}

/// Mark a task as zombie with exit status
pub fn mark_zombie(tid: Tid, status: i32) {
    let pid: Option<Pid>;
    {
        let mut table = TASK_TABLE.lock();
        if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
            task.exit_code = status;
            task.state = TaskState::Zombie(status);
            // Release cached pages
            task.release_cached_pages();
            pid = Some(task.pid);
        } else {
            pid = None;
        }
    }

    // Detach from cgroup and decrement task counters
    // This must be done after releasing TASK_TABLE lock to avoid lock ordering issues
    crate::cgroup::detach_task(tid);

    // Notify any pidfds watching this process (after releasing TASK_TABLE lock)
    if let Some(p) = pid {
        crate::pidfd::notify_process_exit(p, status);

        // Write accounting record if process accounting is enabled
        crate::acct::write_acct_record(tid, p, status);
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
pub fn reap_zombie_child(parent_pid: Pid, target_pid: i64) -> Option<(Pid, i32)> {
    let mut table = TASK_TABLE.lock();

    // Find a zombie child matching the criteria
    let zombie_idx = table.tasks.iter().position(|t| {
        // Must be a child of the parent
        if t.ppid != parent_pid {
            return false;
        }

        // Must be a zombie
        if !matches!(t.state, TaskState::Zombie(_)) {
            return false;
        }

        // Check PID matching
        if target_pid > 0 {
            // Wait for specific PID
            t.pid == target_pid as u64
        } else if target_pid == -1 {
            // Wait for any child
            true
        } else {
            // target_pid == 0: wait for same process group (not implemented)
            false
        }
    });

    if let Some(idx) = zombie_idx {
        let task = table.tasks.remove(idx);
        if let TaskState::Zombie(status) = task.state {
            return Some((task.pid, status));
        }
    }

    None
}

/// Check if a process has any children matching the criteria
///
/// # Arguments
/// * `parent_pid` - PID of the parent process
/// * `target_pid` - Which children to check for:
///   - > 0: check for specific child PID
///   - -1: check for any child
///   - 0: check for any child in same process group
pub fn has_children(parent_pid: Pid, target_pid: i64) -> bool {
    let table = TASK_TABLE.lock();

    table.tasks.iter().any(|t| {
        // Must be a child of the parent
        if t.ppid != parent_pid {
            return false;
        }

        // Check PID matching
        if target_pid > 0 {
            t.pid == target_pid as u64
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

    // RLIMIT_NPROC enforcement for new processes (not threads)
    // Following Linux pattern: increment first (atomically), then check if over limit
    // This avoids the TOCTOU race where multiple concurrent clones could all pass
    // a check-then-increment pattern before any of them increment.
    let is_new_process = config.flags & CLONE_THREAD == 0;
    let (nproc_uid, nproc_incremented) = if is_new_process {
        let cred = current_cred();
        let new_count = crate::task::increment_user_process_count(cred.uid);

        // Check if over limit (CAP_SYS_RESOURCE bypasses)
        if !crate::task::capable(crate::task::CAP_SYS_RESOURCE) {
            let limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_NPROC);
            if limit != crate::rlimit::RLIM_INFINITY && new_count > limit {
                // Over limit - decrement and return error
                crate::task::decrement_user_process_count(cred.uid);
                return Err(11); // EAGAIN - resource temporarily unavailable
            }
        }
        (cred.uid, true)
    } else {
        (0, false) // Threads don't count toward RLIMIT_NPROC
    };

    // Check cgroup pids controller limit (if task is in a cgroup with pids.max)
    // This is checked before allocating resources so we fail early if over limit
    let parent_cgroup = {
        let tid = current_tid();
        crate::cgroup::TASK_CGROUP.read().get(&tid).cloned()
    };
    if let Some(ref cgroup) = parent_cgroup
        && !crate::cgroup::pids_can_fork(cgroup)
    {
        if nproc_incremented {
            crate::task::decrement_user_process_count(nproc_uid);
        }
        return Err(11); // EAGAIN - resource temporarily unavailable
    }

    // Helper macro to handle early returns with NPROC cleanup
    // If we incremented the process count and then fail, we must decrement it
    macro_rules! try_with_cleanup {
        ($expr:expr) => {
            match $expr {
                Ok(val) => val,
                Err(e) => {
                    if nproc_incremented {
                        crate::task::decrement_user_process_count(nproc_uid);
                    }
                    return Err(e);
                }
            }
        };
    }

    // Get current CPU ID
    let cpu_id = CurrentArch::try_current_cpu_id().unwrap_or(0);

    // Get parent task info
    let current_tid = current_tid();
    let (
        parent_pid,
        parent_tgid,
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
        parent_ptracer_tid,
    ) = {
        let table = TASK_TABLE.lock();
        let parent = try_with_cleanup!(table.tasks.iter().find(|t| t.tid == current_tid).ok_or(3)); // ESRCH - no such process
        (
            parent.pid,
            parent.tgid,
            parent.ppid,
            parent.pgid,
            parent.sid,
            parent.priority,
            parent.policy,
            parent.rt_priority,
            parent.reset_on_fork,
            parent.cpus_allowed,
            parent.page_table.root_table_phys(),
            parent.cred.clone(),
            parent.prctl.clone(),
            parent.personality,
            parent.mempolicy,
            parent.seccomp_mode,
            parent.seccomp_filter.clone(),
            parent.ptrace,
            parent.ptracer_tid,
        )
    };

    // Get parent iopl_emul (x86-64 only) - must be done in separate block
    #[cfg(target_arch = "x86_64")]
    let parent_iopl_emul = {
        let table = TASK_TABLE.lock();
        table
            .tasks
            .iter()
            .find(|t| t.tid == current_tid)
            .map(|t| t.iopl_emul)
            .unwrap_or(0)
    };

    // Validate CLONE_PARENT: cannot be used by init process (pid 1)
    // Linux checks for SIGNAL_UNKILLABLE flag, but we simplify to pid == 1
    if config.flags & CLONE_PARENT != 0 && parent_pid == 1 {
        if nproc_incremented {
            crate::task::decrement_user_process_count(nproc_uid);
        }
        return Err(22); // EINVAL
    }

    // Handle SCHED_RESET_ON_FORK: child gets SCHED_NORMAL with nice 0
    let (child_policy, child_rt_priority, child_priority) = if parent_reset_on_fork {
        (crate::task::SCHED_NORMAL, 0, crate::task::PRIORITY_NORMAL)
    } else {
        (parent_policy, parent_rt_priority, parent_priority)
    };

    // Allocate TID and possibly PID
    let (child_tid, child_pid) = {
        let mut table = TASK_TABLE.lock();
        let tid = table.next_tid;
        table.next_tid += 1;

        // CLONE_THREAD means same process (same PID)
        let pid = if config.flags & CLONE_THREAD != 0 {
            parent_pid
        } else {
            let pid = table.next_pid;
            table.next_pid += 1;
            pid
        };
        (tid, pid)
    };

    // Allocate kernel stack for child (16KB = 4 pages)
    let stack_pages = KERNEL_STACK_SIZE / PAGE_SIZE as usize;
    let mut stack_base: Option<u64> = None;

    for i in 0..stack_pages {
        let frame = try_with_cleanup!(frame_alloc.alloc_frame().ok_or(12)); // ENOMEM

        if i == 0 {
            stack_base = Some(frame);
        }

        // Zero the page
        unsafe {
            core::ptr::write_bytes(frame as *mut u8, 0, PAGE_SIZE as usize);
        }
    }

    let stack_base = stack_base.unwrap();
    let kstack_top = stack_base + KERNEL_STACK_SIZE as u64;

    // Determine page table
    let child_pt = if config.flags & CLONE_VM != 0 {
        // Share address space - just copy the page table reference (threads)
        ArchPageTable::new(parent_pt_phys)
    } else {
        // Fork: duplicate the entire user address space
        let parent_pt = ArchPageTable::new(parent_pt_phys);
        try_with_cleanup!(parent_pt.duplicate_user_space(frame_alloc))
    };

    // Determine child's user stack pointer
    // For fork (child_stack == 0): inherit parent's stack
    // For clone with explicit stack: use provided stack
    let child_user_rsp = if config.child_stack == 0 {
        config.parent_rsp
    } else {
        config.child_stack
    };

    // Build child's TrapFrame on the child's kernel stack
    // This will be restored by clone_child_entry via IRETQ
    let trapframe_size = core::mem::size_of::<<CurrentArch as Arch>::TrapFrame>() as u64;
    let trapframe_ptr = kstack_top - trapframe_size;

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
    let thread_ctx = KernelThreadContext {
        context,
        stack_base,
    };

    // Determine child's parent PID
    // CLONE_PARENT or CLONE_THREAD: child becomes sibling (same parent as caller)
    // Otherwise: caller becomes the parent
    let child_ppid = if config.flags & (CLONE_PARENT | CLONE_THREAD) != 0 {
        parent_ppid // Child's parent is our parent (grandparent of normal fork)
    } else {
        parent_pid // Normal case: we are the parent
    };

    // Create child task
    let child_task = Task {
        magic: crate::task::TASK_MAGIC,
        pid: child_pid,
        tid: child_tid,
        // Thread group ID: same as parent for CLONE_THREAD, else child becomes leader
        tgid: if config.flags & CLONE_THREAD != 0 {
            parent_tgid
        } else {
            child_pid
        },
        ppid: child_ppid,
        pgid: parent_pgid,
        sid: parent_sid,
        // Exit handling
        exit_code: 0,
        exit_signal: config.exit_signal, // From clone3 args (SIGCHLD for fork, 0 for threads)
        pdeath_signal: 0,                // Never inherited, must be set explicitly via prctl
        // Accounting (child starts fresh)
        utime: 0,
        stime: 0,
        start_time: crate::time::monotonic_ns(),
        last_run_ns: crate::time::monotonic_ns(),
        in_kernel: false, // Child starts in user mode
        nvcsw: 0,
        nivcsw: 0,
        min_flt: 0,
        maj_flt: 0,
        cred: crate::task::copy_creds(config.flags, &parent_cred),
        kind: TaskKind::UserProcess,
        state: TaskState::Ready,
        priority: child_priority,
        policy: child_policy,
        rt_priority: child_rt_priority,
        reset_on_fork: false, // Never inherited - child must set explicitly
        cpus_allowed: parent_cpus_allowed, // Inherit CPU affinity from parent
        page_table: child_pt,
        trap_frame: Default::default(), // Not used - we have TrapFrame on stack
        kstack_top,
        user_stack_top: Some(child_user_rsp),
        cached_pages: Vec::new(),
        // TLS fields - will be set based on clone flags below
        tls_base: 0,
        clear_child_tid: 0,
        set_child_tid: 0,
        // Shared resources (will be cloned/shared based on clone flags below)
        mm: None,
        files: None,
        fs: None,
        nsproxy: None,
        sighand: None,
        signal: None,
        io_context: None,
        sysvsem: None,
        // Per-task signal state (always per-task, not shared)
        signal_state: crate::signal::TaskSignalState::new(),
        tif_sigpending: core::sync::atomic::AtomicBool::new(false),
        robust_list: 0,
        // prctl state: inherit no_new_privs from parent, reset others
        prctl: crate::task::PrctlState {
            name: [0u8; 16],                                 // Child gets empty name
            dumpable: crate::task::dumpable::SUID_DUMP_USER, // Reset to default
            no_new_privs: parent_prctl.no_new_privs,         // Inherited (irreversible)
            timer_slack_ns: parent_prctl.timer_slack_ns,     // Inherited
            keep_caps: false,                                // Reset on fork
            child_subreaper: false,                          // Not inherited
        },
        // Process personality (inherited from parent)
        personality: parent_personality,
        // NUMA memory policy (inherited from parent)
        mempolicy: parent_mempolicy,
        // Seccomp state (inherited from parent)
        // Seccomp filters are reference-counted, so this is cheap
        seccomp_mode: parent_seccomp_mode,
        seccomp_filter: parent_seccomp_filter,
        // I/O port permissions (x86-64 only, inherited from parent)
        #[cfg(target_arch = "x86_64")]
        iopl_emul: parent_iopl_emul,
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
        ptracer_tid: if config.flags & CLONE_UNTRACED != 0 {
            None
        } else if config.flags & CLONE_PTRACE != 0 && parent_ptracer_tid.is_some() {
            parent_ptracer_tid
        } else {
            None
        },
        real_parent_tid: child_ppid,
        ptrace_message: 0,
        ptrace_options: 0,
    };

    // Add to global task table
    {
        let mut table = TASK_TABLE.lock();
        table.tasks.push(child_task);
    }

    // Add to run queue
    let sched = get_percpu_sched(cpu_id);
    {
        let mut rq = sched.lock.lock();
        rq.contexts.push((child_tid, thread_ctx));
        rq.queue().enqueue(child_tid, child_priority);
        rq.nr_running += 1;
    }

    // Handle filesystem context (CLONE_FS)
    // If CLONE_FS is set, child shares parent's FsStruct (cwd changes affect both)
    // Otherwise, child gets an independent copy
    crate::fs::clone_task_fs(current_tid, child_tid, config.flags & CLONE_FS != 0);

    // Handle FD table (CLONE_FILES)
    // If CLONE_FILES is set, child shares parent's FD table
    // Otherwise, child gets an independent deep copy
    crate::task::fdtable::clone_task_fd(current_tid, child_tid, config.flags & CLONE_FILES != 0);

    // Handle memory descriptor (CLONE_VM)
    // If CLONE_VM is set, child shares parent's mm (threads)
    // Otherwise, child gets an independent copy of VMAs (fork)
    crate::mm::clone_task_mm(current_tid, child_tid, config.flags & CLONE_VM != 0);

    // Handle namespace context (CLONE_NEW* flags)
    // This must come after filesystem context since mount namespace affects VFS
    try_with_cleanup!(crate::ns::copy_namespaces(
        current_tid,
        child_tid,
        config.flags
    ));

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
                // Invalid cgroup fd - cleanup and return error
                if nproc_incremented {
                    crate::task::decrement_user_process_count(nproc_uid);
                }
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
    if config.flags & CLONE_SETTLS != 0 {
        crate::task::set_task_tls(child_tid, config.tls);
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

    // Handle CLONE_VFORK: parent blocks until child exec()s or _exit()s
    // This must be done after child is fully set up and enqueued
    if config.flags & CLONE_VFORK != 0 {
        register_vfork_child(child_tid);
        // Wait for child to signal completion (via exec or exit)
        wait_for_vfork(child_tid);
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

/// Exit the current task and switch to another
///
/// This function never returns. The current task is removed from the
/// run queue (but kept in TASK_TABLE as zombie), and execution switches
/// to the next available task (typically idle if no others).
pub fn exit_current() -> ! {
    let sched = current_percpu_sched().expect("No scheduler");
    let mut rq = sched.lock.lock();

    let current_tid = rq.current.take();

    // Don't re-enqueue - task is exiting
    // Remove context from list (but Task stays in TASK_TABLE as zombie)
    if let Some(tid) = current_tid {
        rq.contexts.retain(|(t, _)| *t != tid);
        rq.nr_running = rq.nr_running.saturating_sub(1);

        // Decrement user process count for process exits (thread group leader)
        // A process exits when tid == pid (thread group leader)
        {
            let table = TASK_TABLE.lock();
            if let Some(task) = table.tasks.iter().find(|t| t.tid == tid) {
                // Thread group leader: tid == pid
                if task.tid == task.pid {
                    let cred = current_cred();
                    crate::task::decrement_user_process_count(cred.uid);
                }
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

        // Clean up TLS pointer for exiting task
        crate::task::remove_task_tls(tid);

        // Clean up clear_child_tid pointer for exiting task
        crate::task::remove_clear_child_tid(tid);

        // Clean up namespace context for exiting task
        crate::ns::exit_task_ns(tid);

        // Clean up seccomp state for exiting task
        crate::seccomp::exit_seccomp(tid);

        // Clean up signal state for exiting task
        crate::signal::exit_task_signal(tid);

        // Clean up memory descriptor for exiting task
        crate::mm::exit_task_mm(tid);

        // Clean up robust futex list for exiting task
        // Get pid for futex key creation
        let pid = {
            let table = TASK_TABLE.lock();
            table
                .tasks
                .iter()
                .find(|t| t.tid == tid)
                .map(|t| t.pid)
                .unwrap_or(0)
        };
        crate::futex::exit_robust_list(tid, pid);

        // Handle CLONE_CHILD_CLEARTID: write 0 and wake futex waiters
        // This must be done before switching away since we need to be in
        // the task's address space to write to user memory
        do_clear_child_tid(tid);

        // Signal vfork completion if parent is waiting
        // This must be done after CLEARTID but before we switch away
        signal_vfork_done(tid);
    }

    // Get next task (must be idle if nothing else)
    let next_tid = rq
        .queue()
        .dequeue_highest()
        .expect("Idle task should always be runnable");

    // Get next task's kernel stack, pid, ppid, pgid, sid, cred, seccomp_mode from global table
    let (
        next_kstack,
        next_pid,
        next_ppid,
        next_pgid,
        next_sid,
        next_cr3,
        next_cred,
        next_seccomp_mode,
    ) = {
        let table = TASK_TABLE.lock();
        table
            .tasks
            .iter()
            .find(|t| t.tid == next_tid)
            .map(|t| {
                (
                    t.kstack_top,
                    t.pid,
                    t.ppid,
                    t.pgid,
                    t.sid,
                    t.page_table.root_table_phys(),
                    t.cred.clone(),
                    t.seccomp_mode,
                )
            })
            .unwrap_or((0, 0, 0, 0, 0, 0, alloc::sync::Arc::new(Cred::ROOT), 0))
    };

    // Get next task's context
    let next_ctx = match rq.get_context(next_tid) {
        Some(c) => c,
        None => {
            // No context available, fall back to halt loop
            drop(rq);
            loop {
                CurrentArch::halt();
            }
        }
    };

    // Update state
    rq.current = Some(next_tid);

    // Update per-CPU current_tid and current_task
    CurrentArch::set_current_tid(next_tid);
    CurrentArch::set_current_task(&CurrentTask {
        tid: next_tid,
        pid: next_pid,
        ppid: next_ppid,
        pgid: next_pgid,
        sid: next_sid,
        cred: *next_cred,
        seccomp_mode: next_seccomp_mode,
    });

    // Release lock before switch (context_switch_first doesn't return)
    drop(rq);

    // Switch to next task - never returns
    unsafe {
        CurrentArch::context_switch_first(next_ctx, next_kstack, next_cr3, next_tid);
    }
}

/// Called on timer tick
pub fn timer_tick() {
    TICK_COUNT.fetch_add(1, Ordering::Relaxed);
    // Check and fire any expired software timers
    crate::timer::check_timers();
}

/// Get current tick count
pub fn get_ticks() -> u64 {
    TICK_COUNT.load(Ordering::Relaxed)
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
}

/// Get the current task's CR3 (page table root physical address)
///
/// This is called from clone_child_entry to load the child's page table
/// before returning to user mode.
#[unsafe(no_mangle)]
pub extern "C" fn get_current_task_cr3() -> u64 {
    let current_tid = current_tid();
    if current_tid == 0 {
        return 0;
    }

    let table = TASK_TABLE.lock();
    for task in &table.tasks {
        if task.tid == current_tid {
            return task.page_table.root_table_phys();
        }
    }
    0
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
    crate::task::get_task_tls(tid).unwrap_or(0)
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

/// Put current task to sleep until the specified tick
///
/// The current task is removed from the run queue and added to the sleep queue.
/// It will be woken when the specified tick is reached.
///
/// Lock ordering: TASK_TABLE (Mutex) -> IrqSpinlock (per-CPU scheduler)
/// This ensures we never hold IrqSpinlock while acquiring TASK_TABLE,
/// which would risk deadlock if timer ISR also needs TASK_TABLE.
pub fn sleep_current_until(wake_tick: u64) {
    if !SCHEDULING_ENABLED.load(Ordering::Acquire) {
        printkln!("SLEEP: scheduling not enabled, busy-wait");
        // Busy-wait fallback if scheduler not enabled
        while get_ticks() < wake_tick {
            core::hint::spin_loop();
        }
        return;
    }

    let sched = match current_percpu_sched() {
        Some(s) if s.initialized.load(Ordering::Acquire) => s,
        _ => {
            printkln!("SLEEP: no scheduler, busy-wait");
            // Fallback: busy wait
            while get_ticks() < wake_tick {
                core::hint::spin_loop();
            }
            return;
        }
    };

    // Get current TID from per-CPU data (lock-free)
    // CurrentArch::current_tid() returns 0 if per-CPU not initialized
    let current_tid: Tid = CurrentArch::current_tid();

    if current_tid == 0 {
        // No current task, busy-wait with interrupts enabled
        CurrentArch::enable_interrupts();
        while get_ticks() < wake_tick {
            core::hint::spin_loop();
        }
        return;
    }

    // LOCK ORDERING: Acquire TASK_TABLE FIRST (before IrqSpinlock)
    // This prevents deadlock: we get priority and mark sleeping while
    // interrupts are still enabled, then take IrqSpinlock for the context switch.
    let priority = {
        let mut table = TASK_TABLE.lock();
        if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == current_tid) {
            task.state = TaskState::Sleeping;
            task.priority
        } else {
            128 // Default priority if task not found
        }
    };
    // TASK_TABLE lock released here

    // Now take the run queue lock (IRQs disabled automatically)
    let mut rq = sched.lock.lock();

    // Verify this is still the current task on this CPU's run queue
    if rq.current != Some(current_tid) {
        // Race: task changed, just return (lock will be released)
        drop(rq);
        while get_ticks() < wake_tick {
            core::hint::spin_loop();
        }
        return;
    }

    // Add to sleep queue with cached priority (no TASK_TABLE access needed in ISR)
    rq.sleep_queue.push(SleepEntry {
        tid: current_tid,
        wake_tick,
        priority,
    });
    rq.sleep_queue.sort_by_key(|e| e.wake_tick);

    // Get next task - with idle task, this always succeeds
    // Note: we do NOT re-enqueue current task to run queue
    let next_tid = rq
        .queue()
        .dequeue_highest()
        .expect("Idle task should always be runnable");

    if next_tid == current_tid {
        // This shouldn't happen since current is sleeping, but handle it
        // Just busy wait and return
        drop(rq);
        while get_ticks() < wake_tick {
            core::hint::spin_loop();
        }
        return;
    }

    // Get next task's kernel stack, pid, ppid, pgid, sid, cred, seccomp_mode from global table
    let (
        next_kstack,
        next_pid,
        next_ppid,
        next_pgid,
        next_sid,
        next_cr3,
        next_cred,
        next_seccomp_mode,
    ) = {
        let table = TASK_TABLE.lock();
        table
            .tasks
            .iter()
            .find(|t| t.tid == next_tid)
            .map(|t| {
                (
                    t.kstack_top,
                    t.pid,
                    t.ppid,
                    t.pgid,
                    t.sid,
                    t.page_table.root_table_phys(),
                    t.cred.clone(),
                    t.seccomp_mode,
                )
            })
            .unwrap_or((0, 0, 0, 0, 0, 0, alloc::sync::Arc::new(Cred::ROOT), 0))
    };

    // Get context pointers
    let current_ctx = rq.get_context_mut(current_tid);
    let next_ctx = rq.get_context(next_tid);

    if let (Some(curr), Some(next)) = (current_ctx, next_ctx) {
        // Update current task
        rq.current = Some(next_tid);

        // Update per-CPU current_tid and current_task
        CurrentArch::set_current_tid(next_tid);
        CurrentArch::set_current_task(&CurrentTask {
            tid: next_tid,
            pid: next_pid,
            ppid: next_ppid,
            pgid: next_pgid,
            sid: next_sid,
            cred: *next_cred,
            seccomp_mode: next_seccomp_mode,
        });

        // Context switch with lock held!
        // The lock is released by finish_context_switch() in the new task
        // when it starts or resumes.
        unsafe {
            CurrentArch::context_switch(curr, next, next_kstack, next_cr3, next_tid);
        }

        // We return here when woken up
    }

    // Lock is automatically released when guard drops
}

/// Wake tasks whose sleep time has expired (per-CPU only)
///
/// Called from timer interrupt. Each CPU only processes its own sleep queue
/// to maintain per-CPU locality and avoid cross-CPU lock contention.
///
/// IMPORTANT: This function runs in interrupt context and must NOT acquire
/// TASK_TABLE or any non-IRQ-safe lock to avoid deadlock.
pub fn wake_sleepers() {
    let current_tick = get_ticks();

    // Only process the CURRENT CPU's sleep queue (per-CPU locality)
    // This avoids touching other CPUs' locks from interrupt context.
    let sched = match current_percpu_sched() {
        Some(s) if s.initialized.load(Ordering::Acquire) => s,
        _ => return,
    };

    let mut rq = sched.lock.lock();

    // Wake expired sleepers using cached priority (no TASK_TABLE access!)
    while let Some(entry) = rq.sleep_queue.first() {
        if entry.wake_tick <= current_tick {
            let tid = entry.tid;
            let priority = entry.priority; // Use cached priority from SleepEntry
            rq.sleep_queue.remove(0);

            // Re-enqueue to run queue with cached priority
            // Note: Task state update (Sleeping -> Ready) is deferred until
            // the task actually runs, or handled by the scheduler when picking.
            rq.queue().enqueue(tid, priority);
        } else {
            // Sleep queue is sorted, no more expired entries
            break;
        }
    }

    // IrqSpinlock guard drops here, restoring interrupts
}

/// Yield the current thread (cooperative scheduling)
///
/// The current thread gives up its time slice and another runnable
/// thread (if any) gets to run.
pub fn yield_now() {
    if !SCHEDULING_ENABLED.load(Ordering::Acquire) {
        return;
    }

    let sched = match current_percpu_sched() {
        Some(s) if s.initialized.load(Ordering::Acquire) => s,
        _ => return,
    };

    // Take the run queue lock (IRQs disabled automatically)
    let mut rq = sched.lock.lock();

    let current_tid = match rq.current {
        Some(tid) => tid,
        None => return, // No current task
    };

    // Get current task's priority from global table
    let priority = {
        let table = TASK_TABLE.lock();
        table
            .tasks
            .iter()
            .find(|t| t.tid == current_tid)
            .map(|t| t.priority)
            .unwrap_or(128)
    };

    // Re-enqueue current task
    rq.queue().enqueue(current_tid, priority);

    // Get next task - with idle task, this always succeeds
    let next_tid = rq
        .queue()
        .dequeue_highest()
        .expect("Idle task should always be runnable");

    if next_tid == current_tid {
        // Same task, nothing to do
        return;
    }

    // Get next task's kernel stack, pid, ppid, pgid, sid, cred, seccomp_mode from global table
    let (
        next_kstack,
        next_pid,
        next_ppid,
        next_pgid,
        next_sid,
        next_cr3,
        next_cred,
        next_seccomp_mode,
    ) = {
        let table = TASK_TABLE.lock();
        table
            .tasks
            .iter()
            .find(|t| t.tid == next_tid)
            .map(|t| {
                (
                    t.kstack_top,
                    t.pid,
                    t.ppid,
                    t.pgid,
                    t.sid,
                    t.page_table.root_table_phys(),
                    t.cred.clone(),
                    t.seccomp_mode,
                )
            })
            .unwrap_or((0, 0, 0, 0, 0, 0, alloc::sync::Arc::new(Cred::ROOT), 0))
    };

    // Get context pointers
    let current_ctx = rq.get_context_mut(current_tid);
    let next_ctx = rq.get_context(next_tid);

    if let (Some(curr), Some(next)) = (current_ctx, next_ctx) {
        // Update current task
        rq.current = Some(next_tid);

        // Update per-CPU current_tid and current_task
        CurrentArch::set_current_tid(next_tid);
        CurrentArch::set_current_task(&CurrentTask {
            tid: next_tid,
            pid: next_pid,
            ppid: next_ppid,
            pgid: next_pgid,
            sid: next_sid,
            cred: *next_cred,
            seccomp_mode: next_seccomp_mode,
        });

        // Context switch with lock held!
        // The lock is released after we return from context_switch
        // (when another thread switches back to us)
        unsafe {
            CurrentArch::context_switch(curr, next, next_kstack, next_cr3, next_tid);
        }
    }

    // Lock is automatically released when guard drops
}

/// Set the current task context (tid, pid, ppid, pgid, sid, credentials)
///
/// This is called when setting up the initial user process or when
/// context switching to a new task.
pub fn set_current_task(tid: Tid, pid: Pid, ppid: Pid, pgid: Pid, sid: Pid, cred: Cred) {
    CurrentArch::set_current_tid(tid);
    let task_info = CurrentTask::from_parts(tid, pid, ppid, pgid, sid, cred);
    CurrentArch::set_current_task(&task_info);
}

/// Get the current task's process ID
pub fn current_pid() -> Pid {
    CurrentArch::get_current_task().pid
}

/// Get the current task's thread ID
pub fn current_tid() -> Tid {
    CurrentArch::get_current_task().tid
}

/// Get the current task's parent process ID
pub fn current_ppid() -> Pid {
    CurrentArch::get_current_task().ppid
}

/// Get the current task's process group ID
pub fn current_pgid() -> Pid {
    CurrentArch::get_current_task().pgid
}

/// Get the current task's session ID
pub fn current_sid() -> Pid {
    CurrentArch::get_current_task().sid
}

/// Check if a task exists by TID
pub fn task_exists(tid: Tid) -> bool {
    let table = TASK_TABLE.lock();
    table.tasks.iter().any(|t| t.tid == tid)
}

/// Increment minor page fault counter for current task
///
/// Called after successfully handling a demand-paging or COW fault
/// (no I/O required - page was already in memory or newly allocated).
pub fn increment_min_flt() {
    let tid = current_tid();
    let mut table = TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
        task.min_flt = task.min_flt.saturating_add(1);
    }
}

/// Increment major page fault counter for current task
///
/// Called after successfully handling a swap-in fault
/// (I/O was required - page had to be read from disk).
pub fn increment_maj_flt() {
    let tid = current_tid();
    let mut table = TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
        task.maj_flt = task.maj_flt.saturating_add(1);
    }
}

/// Get all TIDs in a process group
pub fn get_tids_by_pgid(pgid: Pid) -> alloc::vec::Vec<Tid> {
    let table = TASK_TABLE.lock();
    table
        .tasks
        .iter()
        .filter(|t| t.pgid == pgid)
        .map(|t| t.tid)
        .collect()
}

/// Get all unique PIDs in the system
///
/// Returns a sorted, deduplicated list of all process IDs.
/// Used by kill(-1, sig) to signal all processes.
pub fn get_all_pids() -> alloc::vec::Vec<Pid> {
    let table = TASK_TABLE.lock();
    let mut pids: alloc::vec::Vec<Pid> = table.tasks.iter().map(|t| t.pid).collect();
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

/// Get current task's credentials
///
/// Returns ROOT credentials if there is no current task.
pub fn current_cred() -> crate::task::Cred {
    CurrentArch::get_current_task().cred
}

/// Look up a task's process group ID by PID
///
/// Returns None if the process is not found.
pub fn lookup_task_pgid(pid: Pid) -> Option<Pid> {
    let table = TASK_TABLE.lock();
    table.tasks.iter().find(|t| t.pid == pid).map(|t| t.pgid)
}

/// Look up a task's session ID by PID
///
/// Returns None if the process is not found.
pub fn lookup_task_sid(pid: Pid) -> Option<Pid> {
    let table = TASK_TABLE.lock();
    table.tasks.iter().find(|t| t.pid == pid).map(|t| t.sid)
}

/// Look up a task's priority by PID
///
/// Returns None if the process is not found.
pub fn lookup_task_priority(pid: Pid) -> Option<Priority> {
    let table = TASK_TABLE.lock();
    table
        .tasks
        .iter()
        .find(|t| t.pid == pid)
        .map(|t| t.priority)
}

/// Look up a task's scheduling policy by PID
///
/// Returns None if the process is not found.
/// The returned policy includes SCHED_RESET_ON_FORK flag if set.
pub fn lookup_task_policy(pid: Pid) -> Option<i32> {
    let table = TASK_TABLE.lock();
    table.tasks.iter().find(|t| t.pid == pid).map(|t| {
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
    let table = TASK_TABLE.lock();
    table
        .tasks
        .iter()
        .find(|t| t.pid == pid)
        .map(|t| t.rt_priority)
}

/// Get a task's CPU time statistics by TID
///
/// Returns (utime_ns, stime_ns) for the specified task.
/// Returns (0, 0) if the task is not found.
pub fn get_task_times(tid: Tid) -> (u64, u64) {
    let table = TASK_TABLE.lock();
    table
        .tasks
        .iter()
        .find(|t| t.tid == tid)
        .map(|t| (t.utime, t.stime))
        .unwrap_or((0, 0))
}

/// Get aggregate CPU times for a process (all threads)
///
/// Returns (utime_ns, stime_ns) summed across all threads in the process.
/// Returns (0, 0) if no threads are found.
pub fn get_process_times(pid: Pid) -> (u64, u64) {
    let table = TASK_TABLE.lock();
    let mut utime = 0u64;
    let mut stime = 0u64;
    for task in table.tasks.iter().filter(|t| t.pid == pid) {
        utime = utime.saturating_add(task.utime);
        stime = stime.saturating_add(task.stime);
    }
    (utime, stime)
}

/// Called when entering kernel mode (syscall entry)
///
/// Accumulates user time and marks task as in kernel mode.
/// Call this at the start of syscall handling.
pub fn account_syscall_enter() {
    let tid = current_tid();
    if tid == 0 {
        return;
    }

    let now = crate::time::monotonic_ns();
    let mut table = TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
        // Accumulate user time (time since last_run_ns while in user mode)
        if !task.in_kernel {
            let delta = now.saturating_sub(task.last_run_ns);
            task.utime = task.utime.saturating_add(delta);
        }
        task.last_run_ns = now;
        task.in_kernel = true;
    }
}

/// Called when exiting kernel mode (syscall return)
///
/// Accumulates system time and marks task as in user mode.
/// Call this just before returning to user space.
pub fn account_syscall_exit() {
    let tid = current_tid();
    if tid == 0 {
        return;
    }

    let now = crate::time::monotonic_ns();
    let mut table = TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
        // Accumulate system time (time since last_run_ns while in kernel mode)
        if task.in_kernel {
            let delta = now.saturating_sub(task.last_run_ns);
            task.stime = task.stime.saturating_add(delta);
        }
        task.last_run_ns = now;
        task.in_kernel = false;
    }
}

/// Called on context switch to accumulate time for outgoing task
///
/// This handles time accounting when switching away from a task.
pub fn account_context_switch(tid: Tid, now: u64) {
    let mut table = TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
        let delta = now.saturating_sub(task.last_run_ns);
        if task.in_kernel {
            task.stime = task.stime.saturating_add(delta);
        } else {
            task.utime = task.utime.saturating_add(delta);
        }
    }
}

/// Called when a task starts running after context switch
///
/// Updates last_run_ns for the incoming task.
pub fn account_task_resume(tid: Tid, now: u64) {
    let mut table = TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
        task.last_run_ns = now;
    }
}

/// Look up a task's CPU affinity mask by PID
///
/// Returns None if the process is not found.
pub fn lookup_task_cpus_allowed(pid: Pid) -> Option<crate::task::CpuMask> {
    let table = TASK_TABLE.lock();
    table
        .tasks
        .iter()
        .find(|t| t.pid == pid)
        .map(|t| t.cpus_allowed)
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
/// Acquires TASK_TABLE lock. Does not re-queue task in run queue (policy
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

    let mut table = TASK_TABLE.lock();
    match table.tasks.iter_mut().find(|t| t.pid == pid) {
        Some(task) => {
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
/// Acquires TASK_TABLE lock. Migration to new CPU set takes effect on next
/// schedule.
pub fn set_task_cpus_allowed(pid: Pid, mask: crate::task::CpuMask) -> Result<(), i32> {
    // Mask must have at least one CPU allowed
    if mask == 0 {
        return Err(22); // EINVAL
    }

    let mut table = TASK_TABLE.lock();
    match table.tasks.iter_mut().find(|t| t.pid == pid) {
        Some(task) => {
            task.cpus_allowed = mask;
            Ok(())
        }
        None => Err(3), // ESRCH
    }
}

/// Get the total number of tasks in the system
///
/// This counts all tasks including zombies, used by sysinfo syscall.
/// Acquires TASK_TABLE lock briefly.
pub fn task_count() -> usize {
    let table = TASK_TABLE.lock();
    table.tasks.len()
}

/// Set a task's priority by PID
///
/// Returns Ok(()) on success, Err(errno) on failure.
/// Error codes:
/// - ESRCH (3): Process not found
pub fn set_task_priority(pid: Pid, priority: Priority) -> Result<(), i32> {
    let mut table = TASK_TABLE.lock();
    match table.tasks.iter_mut().find(|t| t.pid == pid) {
        Some(task) => {
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
    let mut table = TASK_TABLE.lock();

    // Find the target task index
    let task_idx = match table.tasks.iter().position(|t| t.pid == target_pid) {
        Some(idx) => idx,
        None => return Err(3), // ESRCH
    };

    // Check constraints before modifying
    {
        let task = &table.tasks[task_idx];

        // Cannot change PGID of a session leader (pid == sid)
        if task.pid == task.sid {
            return Err(1); // EPERM
        }

        // Cannot move to a different session
        if task.sid != caller_sid {
            return Err(1); // EPERM
        }
    }

    // If creating a new process group (pgid == target_pid), allow it
    if new_pgid == target_pid {
        table.tasks[task_idx].pgid = new_pgid;
        return Ok(());
    }

    // Check if target PGID exists in the same session
    let pgid_exists = table
        .tasks
        .iter()
        .any(|t| t.pgid == new_pgid && t.sid == caller_sid);
    if !pgid_exists {
        return Err(1); // EPERM - target PGID doesn't exist in same session
    }

    table.tasks[task_idx].pgid = new_pgid;
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

    let mut table = TASK_TABLE.lock();

    // Find the calling process
    let task = match table.tasks.iter_mut().find(|t| t.pid == caller_pid) {
        Some(t) => t,
        None => return Err(3), // ESRCH
    };

    // Create new session: pid becomes sid and pgid
    task.sid = caller_pid;
    task.pgid = caller_pid;

    Ok(caller_pid)
}

/// Update current task's pgid and sid in per-CPU data
///
/// Called after setpgid/setsid to update the cached values.
pub fn update_current_pgid_sid(pgid: Pid, sid: Pid) {
    let mut task = CurrentArch::get_current_task();
    task.pgid = pgid;
    task.sid = sid;
    CurrentArch::set_current_task(&task);
}

/// Update the current task's seccomp mode in per-CPU cache
///
/// Called after seccomp mode changes to update the fast-path cache.
/// This allows syscall entry to quickly check if seccomp is enabled
/// without locking TASK_TABLE.
pub fn update_current_seccomp_mode(mode: u8) {
    let mut task = CurrentArch::get_current_task();
    task.seccomp_mode = mode;
    CurrentArch::set_current_task(&task);
}

/// Implementation of commit_creds - updates both per-CPU cache and TASK_TABLE
///
/// Like Linux's commit_creds() - atomically updates both storage locations
/// so context switch will restore the correct credentials.
pub fn commit_creds_impl(new: alloc::sync::Arc<Cred>) {
    let tid = CurrentArch::current_tid();
    if tid == 0 {
        return; // No current task
    }

    // Update per-CPU cache first (so current task sees new creds immediately)
    let mut current = CurrentArch::get_current_task();
    current.cred = *new;
    CurrentArch::set_current_task(&current);

    // Update TASK_TABLE (persistent storage for context switch)
    let mut table = TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
        task.cred = new;
    }
}

/// Update current task's UID (all fields: uid, suid, euid, fsuid)
///
/// Called by sys_setuid when privileged (euid==0) changes UID.
/// Sets real, saved, effective, and filesystem UID - permanently drops root.
/// This matches Linux setuid() semantics for privileged callers.
///
/// Uses Linux prepare_creds/commit_creds pattern to ensure credentials
/// are persisted to TASK_TABLE for context switch.
pub fn set_current_uid_all(uid: crate::task::Uid) {
    let mut new_cred = crate::task::prepare_creds();
    new_cred.uid = uid;
    new_cred.suid = uid;
    new_cred.euid = uid;
    new_cred.fsuid = uid;
    crate::task::commit_creds(alloc::sync::Arc::new(new_cred));
}

/// Update current task's effective UID only (euid and fsuid)
///
/// Called by sys_setuid for non-root privilege drop.
/// Sets effective and filesystem UID, leaving real UID unchanged.
///
/// Uses Linux prepare_creds/commit_creds pattern to ensure credentials
/// are persisted to TASK_TABLE for context switch.
pub fn set_current_euid(euid: crate::task::Uid) {
    let mut new_cred = crate::task::prepare_creds();
    new_cred.euid = euid;
    new_cred.fsuid = euid; // fsuid follows euid
    crate::task::commit_creds(alloc::sync::Arc::new(new_cred));
}

/// Update current task's GID (all fields: gid, sgid, egid, fsgid)
///
/// Called by sys_setgid when privileged (euid==0) changes GID.
/// Sets real, saved, effective, and filesystem GID.
/// This matches Linux setgid() semantics for privileged callers.
///
/// Uses Linux prepare_creds/commit_creds pattern to ensure credentials
/// are persisted to TASK_TABLE for context switch.
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
/// are persisted to TASK_TABLE for context switch.
pub fn set_current_egid(egid: crate::task::Gid) {
    let mut new_cred = crate::task::prepare_creds();
    new_cred.egid = egid;
    new_cred.fsgid = egid; // fsgid follows egid
    crate::task::commit_creds(alloc::sync::Arc::new(new_cred));
}

/// Get current task's saved UID (suid)
pub fn get_current_suid() -> crate::task::Uid {
    CurrentArch::get_current_task().cred.suid
}

/// Get current task's saved GID (sgid)
pub fn get_current_sgid() -> crate::task::Gid {
    CurrentArch::get_current_task().cred.sgid
}

/// Update current task's real, effective, and saved UIDs selectively
///
/// Called by sys_setresuid. Each field is only updated if Some.
/// When euid changes, fsuid follows (Linux semantics).
///
/// Uses Linux prepare_creds/commit_creds pattern to ensure credentials
/// are persisted to TASK_TABLE for context switch.
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
    crate::task::commit_creds(alloc::sync::Arc::new(new_cred));
}

/// Update current task's real, effective, and saved GIDs selectively
///
/// Called by sys_setresgid. Each field is only updated if Some.
/// When egid changes, fsgid follows (Linux semantics).
///
/// Uses Linux prepare_creds/commit_creds pattern to ensure credentials
/// are persisted to TASK_TABLE for context switch.
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
    CurrentArch::get_current_task().cred.fsuid
}

/// Get current task's filesystem GID (fsgid)
pub fn get_current_fsgid() -> crate::task::Gid {
    CurrentArch::get_current_task().cred.fsgid
}

/// Update current task's real and effective UIDs (setreuid semantics)
///
/// Called by sys_setreuid. Each field is only updated if Some.
/// Also updates suid if new_suid is Some.
/// fsuid always follows euid (set to new euid value).
///
/// Uses Linux prepare_creds/commit_creds pattern to ensure credentials
/// are persisted to TASK_TABLE for context switch.
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
    crate::task::commit_creds(alloc::sync::Arc::new(new_cred));
}

/// Update current task's real and effective GIDs (setregid semantics)
///
/// Called by sys_setregid. Each field is only updated if Some.
/// Also updates sgid if new_sgid is Some.
/// fsgid always follows egid (set to new egid value).
///
/// Uses Linux prepare_creds/commit_creds pattern to ensure credentials
/// are persisted to TASK_TABLE for context switch.
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
/// are persisted to TASK_TABLE for context switch.
pub fn set_current_fsuid(fsuid: crate::task::Uid) {
    let mut new_cred = crate::task::prepare_creds();
    new_cred.fsuid = fsuid;
    crate::task::commit_creds(alloc::sync::Arc::new(new_cred));
}

/// Set current task's filesystem GID directly
///
/// Called by sys_setfsgid. Does NOT auto-update when egid changes elsewhere.
///
/// Uses Linux prepare_creds/commit_creds pattern to ensure credentials
/// are persisted to TASK_TABLE for context switch.
pub fn set_current_fsgid(fsgid: crate::task::Gid) {
    let mut new_cred = crate::task::prepare_creds();
    new_cred.fsgid = fsgid;
    crate::task::commit_creds(alloc::sync::Arc::new(new_cred));
}

/// Replace current task's address space and jump to new entry point
///
/// This is used by execve to replace the current process image.
/// The function never returns - it jumps directly to user mode.
///
/// # Arguments
/// * `new_page_table` - The new page table for the process
/// * `entry_point` - The entry point address in the new program
/// * `user_sp` - The initial user stack pointer
pub fn exec_replace_image(new_page_table: ArchPageTable, entry_point: u64, user_sp: u64) -> ! {
    use crate::FRAME_ALLOCATOR;
    use crate::arch::PageTable;

    let tid = current_tid();
    let cr3 = new_page_table.root_table_phys();

    // Update the task's page table in the task table
    // Collect old frames before replacing, then free them
    let old_frames = {
        let mut table = TASK_TABLE.lock();
        if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
            let old_frames = task.page_table.collect_table_frames();
            task.page_table = new_page_table;
            old_frames
        } else {
            alloc::vec::Vec::new()
        }
    };

    // Free old page table frames (outside lock to avoid deadlock)
    for frame in old_frames {
        FRAME_ALLOCATOR.free(frame);
    }

    // Get kernel stack for syscall/interrupt return
    let kstack_top = {
        let table = TASK_TABLE.lock();
        table
            .tasks
            .iter()
            .find(|t| t.tid == tid)
            .map(|t| t.kstack_top)
            .unwrap_or(0)
    };

    // Jump to user mode at the new entry point
    // This function never returns
    unsafe {
        CurrentArch::jump_to_user(entry_point, user_sp, cr3, kstack_top);
    }
}

/// Check if preemption is needed and perform context switch
///
/// Called after returning from timer interrupt.
pub fn maybe_preempt() {
    if !SCHEDULING_ENABLED.load(Ordering::Acquire) {
        return;
    }

    // Get and clear reschedule flag atomically
    let needs_reschedule = CurrentArch::clear_needs_reschedule();

    if !needs_reschedule {
        return;
    }

    // Check interrupt depth
    if CurrentArch::interrupt_depth() > 0 {
        // Still in interrupt, defer by setting the flag again
        CurrentArch::set_needs_reschedule(true);
        return;
    }

    // Try to schedule
    try_schedule();
}

/// Try to schedule a task on the current CPU
pub fn try_schedule() {
    if !SCHEDULING_ENABLED.load(Ordering::Acquire) {
        return;
    }

    let cpu_id = CurrentArch::try_current_cpu_id().unwrap_or(0);

    let sched = get_percpu_sched(cpu_id);
    if !sched.initialized.load(Ordering::Acquire) {
        return;
    }

    // Get current TID from per-CPU data
    let my_current_tid: Tid = CurrentArch::current_tid();

    // Take the run queue lock
    let mut rq = sched.lock.lock();

    if my_current_tid != 0 {
        // We have a current task - yield it and get next
        // Get priority from global table
        let priority = {
            let table = TASK_TABLE.lock();
            table
                .tasks
                .iter()
                .find(|t| t.tid == my_current_tid)
                .map(|t| t.priority)
                .unwrap_or(128)
        };

        // Re-enqueue current
        rq.queue().enqueue(my_current_tid, priority);

        // Get next - with idle task, this always succeeds
        let next_tid = rq
            .queue()
            .dequeue_highest()
            .expect("Idle task should always be runnable");

        if next_tid == my_current_tid {
            return; // Same task
        }

        // Get next task's stack, pid, ppid, pgid, sid, cr3, cred
        let (next_kstack, next_pid, next_ppid, next_pgid, next_sid, next_cr3, next_cred) = {
            let table = TASK_TABLE.lock();
            table
                .tasks
                .iter()
                .find(|t| t.tid == next_tid)
                .map(|t| {
                    (
                        t.kstack_top,
                        t.pid,
                        t.ppid,
                        t.pgid,
                        t.sid,
                        t.page_table.root_table_phys(),
                        t.cred.clone(),
                    )
                })
                .unwrap_or((0, 0, 0, 0, 0, 0, alloc::sync::Arc::new(Cred::ROOT)))
        };

        // Get contexts
        let current_ctx = rq.get_context_mut(my_current_tid);
        let next_ctx = rq.get_context(next_tid);

        if let (Some(curr), Some(next)) = (current_ctx, next_ctx) {
            rq.current = Some(next_tid);

            CurrentArch::set_current_tid(next_tid);
            let task_info = CurrentTask::from_parts(
                next_tid, next_pid, next_ppid, next_pgid, next_sid, *next_cred,
            );
            CurrentArch::set_current_task(&task_info);

            unsafe {
                CurrentArch::context_switch(curr, next, next_kstack, next_cr3, next_tid);
            }
        }
    } else {
        // No current task - get one (with idle task, this always succeeds)
        let next_tid = rq
            .queue()
            .dequeue_highest()
            .expect("Idle task should always be runnable");

        let (next_kstack, next_pid, next_ppid, next_pgid, next_sid, next_cr3, next_cred) = {
            let table = TASK_TABLE.lock();
            table
                .tasks
                .iter()
                .find(|t| t.tid == next_tid)
                .map(|t| {
                    (
                        t.kstack_top,
                        t.pid,
                        t.ppid,
                        t.pgid,
                        t.sid,
                        t.page_table.root_table_phys(),
                        t.cred.clone(),
                    )
                })
                .unwrap_or((0, 0, 0, 0, 0, 0, alloc::sync::Arc::new(Cred::ROOT)))
        };

        let next_ctx = match rq.get_context(next_tid) {
            Some(c) => c,
            None => return,
        };

        rq.current = Some(next_tid);

        CurrentArch::set_current_tid(next_tid);
        let task_info = CurrentTask::from_parts(
            next_tid, next_pid, next_ppid, next_pgid, next_sid, *next_cred,
        );
        CurrentArch::set_current_task(&task_info);

        drop(rq); // Release lock before switch

        unsafe {
            CurrentArch::context_switch_first(next_ctx, next_kstack, next_cr3, next_tid);
        }
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
    let table = TASK_TABLE.lock();
    table
        .tasks
        .iter()
        .find(|t| t.tid == tid)
        .map(|t| t.personality)
        .unwrap_or(0)
}

/// Set the current task's personality value
pub fn set_current_personality(personality: u32) {
    let tid = current_tid();
    let mut table = TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
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
    let table = TASK_TABLE.lock();
    table
        .tasks
        .iter()
        .find(|t| t.tid == tid)
        .map(|t| t.iopl_emul)
        .unwrap_or(0)
}

/// Set the current task's emulated IOPL level (x86-64 only)
///
/// Level must be 0-3. Caller is responsible for privilege checks.
#[cfg(target_arch = "x86_64")]
pub fn set_current_iopl_emul(level: u8) {
    let tid = current_tid();
    let mut table = TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
        task.iopl_emul = level;
    }
}
