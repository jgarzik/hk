//! Task management

pub mod exec;
pub mod fdtable;
pub mod percpu;
pub mod sched;
pub mod syscall;

/// Clone flags for clone() syscall (subset of Linux flags)
///
/// These flags control what resources are shared between parent and child.
pub mod clone_flags {
    /// Share virtual memory (address space) - creates a thread
    pub const CLONE_VM: u64 = 0x00000100;
    /// Share filesystem info (root, cwd, umask)
    pub const CLONE_FS: u64 = 0x00000200;
    /// Share file descriptor table
    pub const CLONE_FILES: u64 = 0x00000400;
    /// Share signal handlers
    pub const CLONE_SIGHAND: u64 = 0x00000800;
    /// Parent blocks until child exec()s or _exit()s (vfork semantics)
    pub const CLONE_VFORK: u64 = 0x00004000;
    /// Share thread group (same PID)
    pub const CLONE_THREAD: u64 = 0x00010000;
    /// Set parent TID at parent_tidptr location
    pub const CLONE_PARENT_SETTID: u64 = 0x00100000;
    /// Set child TID at child_tidptr location (in child's address space)
    pub const CLONE_CHILD_SETTID: u64 = 0x01000000;
    /// Clear child TID at child_tidptr on exit
    pub const CLONE_CHILD_CLEARTID: u64 = 0x00200000;

    // Namespace clone flags (re-exported from ns module for convenience)
    pub use crate::ns::{
        CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUSER,
        CLONE_NEWUTS, CLONE_NS_FLAGS,
    };
}

/// Wait options for waitpid/wait4/waitid
pub mod wait_options {
    /// Return immediately if no child has exited
    pub const WNOHANG: i32 = 1;
    /// Also return if a child has stopped
    pub const WUNTRACED: i32 = 2;
    /// Also return if a stopped child has continued
    pub const WCONTINUED: i32 = 8;

    // waitid-specific options
    /// Wait for children that have terminated
    pub const WEXITED: i32 = 4;
    /// Leave child in waitable state (can be waited for again)
    pub const WNOWAIT: i32 = 0x01000000;

    // idtype_t values for waitid
    /// Wait for any child
    pub const P_ALL: i32 = 0;
    /// Wait for child with specific PID
    pub const P_PID: i32 = 1;
    /// Wait for child in specific process group
    pub const P_PGID: i32 = 2;
}

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::arch::{Arch, PageTable};
use crate::mm::page_cache::CachedPage;

/// Process ID type
pub type Pid = u64;

/// Thread ID type
pub type Tid = u64;

/// User ID type (Linux-compatible)
pub type Uid = u32;

/// Group ID type (Linux-compatible)
pub type Gid = u32;

/// Task credentials (Linux-compatible model)
///
/// Linux has multiple credential sets: real, effective, saved, filesystem.
/// For permission checking, fsuid/fsgid are used. This tracks all eight IDs
/// as Linux does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cred {
    /// Real user ID
    pub uid: Uid,
    /// Real group ID
    pub gid: Gid,
    /// Saved set-user-ID (for setuid binaries and privilege switching)
    pub suid: Uid,
    /// Saved set-group-ID (for setgid binaries and privilege switching)
    pub sgid: Gid,
    /// Effective user ID
    pub euid: Uid,
    /// Effective group ID
    pub egid: Gid,
    /// Filesystem user ID (used for permission checks)
    pub fsuid: Uid,
    /// Filesystem group ID (used for permission checks)
    pub fsgid: Gid,
}

impl Cred {
    /// Root credentials (uid=0, gid=0 for all fields)
    pub const ROOT: Self = Self {
        uid: 0,
        gid: 0,
        suid: 0,
        sgid: 0,
        euid: 0,
        egid: 0,
        fsuid: 0,
        fsgid: 0,
    };

    /// Create credentials for a specific user/group
    ///
    /// Sets all credential fields (uid, suid, euid, fsuid) to the same value.
    /// This is appropriate for new processes. For setuid binaries, suid/sgid
    /// would be set differently during exec.
    pub const fn new(uid: Uid, gid: Gid) -> Self {
        Self {
            uid,
            gid,
            suid: uid,
            sgid: gid,
            euid: uid,
            egid: gid,
            fsuid: uid,
            fsgid: gid,
        }
    }

    /// Check if running as root (fsuid == 0)
    ///
    /// Root bypasses most permission checks.
    pub fn is_root(&self) -> bool {
        self.fsuid == 0
    }
}

impl Default for Cred {
    fn default() -> Self {
        Self::ROOT
    }
}

/// Per-CPU current task state (arch-neutral)
///
/// This struct holds per-task state that needs to be quickly accessible
/// during syscalls and other kernel operations. It is embedded in
/// arch-specific per-CPU structures (e.g., x86_64 PerCpu).
#[derive(Debug, Clone, Copy)]
pub struct CurrentTask {
    /// Thread ID of the currently running task
    pub tid: Tid,
    /// Process ID of the currently running task
    pub pid: Pid,
    /// Parent process ID
    pub ppid: Pid,
    /// Process group ID
    pub pgid: Pid,
    /// Session ID
    pub sid: Pid,
    /// Credentials of the currently running task
    pub cred: Cred,
}

impl CurrentTask {
    /// Create a new CurrentTask with default values (tid=0, pid=0, root credentials)
    pub const fn new() -> Self {
        Self {
            tid: 0,
            pid: 0,
            ppid: 0,
            pgid: 0,
            sid: 0,
            cred: Cred::ROOT,
        }
    }

    /// Update the current task state
    pub fn set(&mut self, tid: Tid, pid: Pid, ppid: Pid, pgid: Pid, sid: Pid, cred: Cred) {
        self.tid = tid;
        self.pid = pid;
        self.ppid = ppid;
        self.pgid = pgid;
        self.sid = sid;
        self.cred = cred;
    }

    /// Create a new CurrentTask from individual parts
    pub const fn from_parts(
        tid: Tid,
        pid: Pid,
        ppid: Pid,
        pgid: Pid,
        sid: Pid,
        cred: Cred,
    ) -> Self {
        Self {
            tid,
            pid,
            ppid,
            pgid,
            sid,
            cred,
        }
    }
}

impl Default for CurrentTask {
    fn default() -> Self {
        Self::new()
    }
}

/// Task priority type (0 = lowest, 255 = highest)
pub type Priority = u8;

/// Idle priority - only runs when nothing else is ready
pub const PRIORITY_IDLE: Priority = 0;
/// Low priority for background tasks
pub const PRIORITY_LOW: Priority = 64;
/// Normal priority for regular tasks
pub const PRIORITY_NORMAL: Priority = 128;
/// High priority for important tasks
pub const PRIORITY_HIGH: Priority = 192;
/// Realtime priority - preempts everything else
pub const PRIORITY_REALTIME: Priority = 255;

/// Priority "which" values for getpriority/setpriority syscalls
pub const PRIO_PROCESS: i32 = 0;
/// Get/set priority for all processes in a process group
pub const PRIO_PGRP: i32 = 1;
/// Get/set priority for all processes owned by a user
pub const PRIO_USER: i32 = 2;

/// Minimum nice value (highest priority)
pub const PRIO_MIN: i32 = -20;
/// Maximum nice value (lowest priority)
pub const PRIO_MAX: i32 = 19;

/// Convert Linux nice value to internal priority
///
/// Nice values range from -20 (highest priority) to 19 (lowest priority).
/// Internal priority ranges from 0 (lowest) to 255 (highest).
///
/// Mapping: nice -20 -> 188, nice 0 -> 128, nice 19 -> 71
pub fn nice_to_priority(nice: i32) -> Priority {
    let clamped = nice.clamp(PRIO_MIN, PRIO_MAX);
    // Map nice -20..19 to priority ~188..71
    (128 - (clamped * 3)) as Priority
}

/// Convert internal priority to Linux nice value
///
/// This is the inverse of nice_to_priority.
pub fn priority_to_nice(priority: Priority) -> i32 {
    ((128i32 - priority as i32) / 3).clamp(PRIO_MIN, PRIO_MAX)
}

// =============================================================================
// Linux scheduling policy constants (from include/uapi/linux/sched.h)
// =============================================================================

/// SCHED_NORMAL: Default CFS (Completely Fair Scheduler) policy
pub const SCHED_NORMAL: i32 = 0;
/// SCHED_FIFO: First-in, first-out real-time policy
pub const SCHED_FIFO: i32 = 1;
/// SCHED_RR: Round-robin real-time policy
pub const SCHED_RR: i32 = 2;
/// SCHED_BATCH: CPU-intensive batch processing
pub const SCHED_BATCH: i32 = 3;
/// SCHED_IDLE: Very low priority background tasks
pub const SCHED_IDLE: i32 = 5;
/// SCHED_DEADLINE: Deadline-based scheduling (not implemented)
pub const SCHED_DEADLINE: i32 = 6;

/// SCHED_RESET_ON_FORK: Reset scheduling policy on fork
/// When set, child processes will not inherit privileged scheduling policies
pub const SCHED_RESET_ON_FORK: i32 = 0x40000000;

/// Minimum real-time priority (for SCHED_FIFO/RR)
pub const MIN_RT_PRIO: i32 = 1;
/// Maximum real-time priority (for SCHED_FIFO/RR)
pub const MAX_RT_PRIO: i32 = 99;

/// sched_param structure for sched_setparam/sched_getparam
/// Matches Linux struct sched_param layout
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SchedParam {
    /// Scheduling priority (1-99 for SCHED_FIFO/RR, 0 for SCHED_NORMAL)
    pub sched_priority: i32,
}

/// Maximum number of CPUs supported
pub const MAX_CPUS: usize = 64;

/// CPU affinity mask type
///
/// A 64-bit mask where bit N indicates CPU N is allowed.
/// For simplicity, we support up to 64 CPUs (matches single u64).
pub type CpuMask = u64;

/// Default CPU affinity mask (all CPUs allowed)
pub const CPU_MASK_ALL: CpuMask = !0u64;

/// Check if a scheduling policy is real-time
pub fn is_rt_policy(policy: i32) -> bool {
    let p = policy & !SCHED_RESET_ON_FORK;
    p == SCHED_FIFO || p == SCHED_RR
}

/// Check if a scheduling policy is valid
pub fn is_valid_policy(policy: i32) -> bool {
    let p = policy & !SCHED_RESET_ON_FORK;
    matches!(
        p,
        SCHED_NORMAL | SCHED_FIFO | SCHED_RR | SCHED_BATCH | SCHED_IDLE
    )
}

/// Round-robin time slice in nanoseconds (default: 100ms like Linux)
pub const RR_TIMESLICE_NS: u64 = 100_000_000;

/// Kind of task
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskKind {
    /// Kernel thread
    KernelThread,
    /// User process
    UserProcess,
}

/// Task state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// Ready to run
    Ready,
    /// Currently running
    Running,
    /// Sleeping/waiting
    Sleeping,
    /// Exited with status
    Zombie(i32),
}

/// File descriptor number type
pub type Fd = i32;

/// Close-on-exec flag for file descriptors
///
/// When set on a file descriptor, the descriptor will be automatically
/// closed when the process calls execve().
pub const FD_CLOEXEC: u32 = 1;

/// File descriptor table for a process
pub struct FdTable<F> {
    /// Mapping from fd number to file object
    files: BTreeMap<Fd, Arc<F>>,
    /// Per-fd flags (FD_CLOEXEC, etc.)
    fd_flags: BTreeMap<Fd, u32>,
    /// Next file descriptor to allocate
    next_fd: Fd,
}

impl<F> FdTable<F> {
    /// Create a new empty file descriptor table
    pub fn new() -> Self {
        Self {
            files: BTreeMap::new(),
            fd_flags: BTreeMap::new(),
            next_fd: 3, // 0, 1, 2 reserved for stdin/stdout/stderr
        }
    }

    /// Create a new empty file descriptor table (const)
    pub const fn new_const() -> Self {
        Self {
            files: BTreeMap::new(),
            fd_flags: BTreeMap::new(),
            next_fd: 3,
        }
    }

    /// Allocate a file descriptor for a file.
    ///
    /// The `nofile` parameter is the RLIMIT_NOFILE limit. If the allocated fd
    /// would be >= nofile, returns Err(EMFILE). Pass `u64::MAX` to disable limit.
    ///
    /// Following Linux pattern: RLIMIT_NOFILE is enforced inside allocation.
    pub fn alloc(&mut self, file: Arc<F>, nofile: u64) -> Result<Fd, i32> {
        let fd = self.next_fd;
        // RLIMIT_NOFILE enforcement
        if (fd as u64) >= nofile {
            return Err(24); // EMFILE - too many open files
        }
        self.files.insert(fd, file);
        self.next_fd += 1;
        Ok(fd)
    }

    /// Allocate a specific file descriptor (for stdin/stdout/stderr).
    ///
    /// This does NOT enforce RLIMIT_NOFILE as it's used for initial fd setup
    /// (stdin=0, stdout=1, stderr=2) where limits don't apply.
    pub fn alloc_at(&mut self, fd: Fd, file: Arc<F>) -> bool {
        if self.files.contains_key(&fd) {
            return false;
        }
        self.files.insert(fd, file);
        true
    }

    /// Get a file by descriptor
    pub fn get(&self, fd: Fd) -> Option<Arc<F>> {
        self.files.get(&fd).cloned()
    }

    /// Close a file descriptor
    pub fn close(&mut self, fd: Fd) -> Option<Arc<F>> {
        self.fd_flags.remove(&fd);
        self.files.remove(&fd)
    }

    /// Check if a file descriptor is valid
    pub fn is_valid(&self, fd: Fd) -> bool {
        self.files.contains_key(&fd)
    }

    /// Get all open file descriptors
    pub fn fds(&self) -> impl Iterator<Item = &Fd> {
        self.files.keys()
    }

    /// Allocate a file descriptor with specific fd flags.
    ///
    /// The `nofile` parameter is the RLIMIT_NOFILE limit. If the allocated fd
    /// would be >= nofile, returns Err(EMFILE). Pass `u64::MAX` to disable limit.
    ///
    /// Following Linux pattern: RLIMIT_NOFILE is enforced inside allocation,
    /// not as a separate pre-check. This avoids TOCTOU races.
    pub fn alloc_with_flags(&mut self, file: Arc<F>, flags: u32, nofile: u64) -> Result<Fd, i32> {
        let fd = self.next_fd;
        // RLIMIT_NOFILE enforcement (Linux: alloc_fd checks fd >= end)
        if (fd as u64) >= nofile {
            return Err(24); // EMFILE - too many open files
        }
        self.files.insert(fd, file);
        if flags != 0 {
            self.fd_flags.insert(fd, flags);
        }
        self.next_fd += 1;
        Ok(fd)
    }

    /// Allocate a specific file descriptor with flags.
    ///
    /// The `nofile` parameter is the RLIMIT_NOFILE limit. If fd >= nofile,
    /// returns Err(EMFILE). Pass `u64::MAX` to disable limit.
    ///
    /// Returns Err(EBADF) if the fd is already in use.
    pub fn alloc_at_with_flags(
        &mut self,
        fd: Fd,
        file: Arc<F>,
        flags: u32,
        nofile: u64,
    ) -> Result<(), i32> {
        // RLIMIT_NOFILE enforcement
        if (fd as u64) >= nofile {
            return Err(24); // EMFILE - too many open files
        }
        if self.files.contains_key(&fd) {
            return Err(9); // EBADF - fd already in use
        }
        self.files.insert(fd, file);
        if flags != 0 {
            self.fd_flags.insert(fd, flags);
        }
        Ok(())
    }

    /// Allocate a file descriptor at or above min_fd (for F_DUPFD).
    ///
    /// Finds the lowest available fd >= min_fd and allocates the file there.
    /// The `nofile` parameter is the RLIMIT_NOFILE limit. If the found fd
    /// would be >= nofile, returns Err(EMFILE).
    ///
    /// Following Linux pattern: RLIMIT_NOFILE is enforced inside allocation.
    pub fn alloc_at_or_above(
        &mut self,
        file: Arc<F>,
        min_fd: Fd,
        flags: u32,
        nofile: u64,
    ) -> Result<Fd, i32> {
        let mut fd = min_fd;
        while self.files.contains_key(&fd) {
            fd += 1;
        }
        // RLIMIT_NOFILE enforcement
        if (fd as u64) >= nofile {
            return Err(24); // EMFILE - too many open files
        }
        self.files.insert(fd, file);
        if flags != 0 {
            self.fd_flags.insert(fd, flags);
        }
        if fd >= self.next_fd {
            self.next_fd = fd + 1;
        }
        Ok(fd)
    }

    /// Get fd flags for a file descriptor
    pub fn get_fd_flags(&self, fd: Fd) -> u32 {
        self.fd_flags.get(&fd).copied().unwrap_or(0)
    }

    /// Set fd flags for a file descriptor
    ///
    /// Returns false if the fd is not valid
    pub fn set_fd_flags(&mut self, fd: Fd, flags: u32) -> bool {
        if !self.files.contains_key(&fd) {
            return false;
        }
        if flags != 0 {
            self.fd_flags.insert(fd, flags);
        } else {
            self.fd_flags.remove(&fd);
        }
        true
    }

    /// Deep clone the FD table (for fork without CLONE_FILES)
    ///
    /// Creates an independent copy of the FD table where each file
    /// descriptor points to the same underlying file (Arc clone),
    /// but the table itself is independent.
    pub fn deep_clone(&self) -> Self {
        Self {
            files: self.files.clone(),
            fd_flags: self.fd_flags.clone(),
            next_fd: self.next_fd,
        }
    }

    /// Get the number of open file descriptors
    pub fn count(&self) -> usize {
        self.files.len()
    }

    /// Get the next fd that would be allocated
    ///
    /// Used for RLIMIT_NOFILE enforcement.
    pub fn next_fd(&self) -> Fd {
        self.next_fd
    }
}

impl<F> Default for FdTable<F> {
    fn default() -> Self {
        Self::new()
    }
}

/// A task (thread or process)
pub struct Task<A: Arch, PT: PageTable<VirtAddr = A::VirtAddr, PhysAddr = A::PhysAddr>> {
    /// Process ID
    pub pid: Pid,
    /// Thread ID
    pub tid: Tid,
    /// Parent process ID (0 for init/orphans)
    pub ppid: Pid,
    /// Process group ID
    pub pgid: Pid,
    /// Session ID
    pub sid: Pid,
    /// Kind of task
    pub kind: TaskKind,
    /// Current state
    pub state: TaskState,
    /// Scheduling priority (higher = more important)
    pub priority: Priority,
    /// Scheduling policy (SCHED_NORMAL, SCHED_FIFO, SCHED_RR, etc.)
    pub policy: i32,
    /// Real-time priority (1-99 for SCHED_FIFO/RR, 0 otherwise)
    pub rt_priority: i32,
    /// Reset scheduling policy on fork (SCHED_RESET_ON_FORK was set)
    pub reset_on_fork: bool,
    /// CPU affinity mask (bit N = CPU N is allowed)
    pub cpus_allowed: CpuMask,
    /// Page table for this task
    pub page_table: PT,
    /// Saved CPU state
    pub trap_frame: A::TrapFrame,
    /// Kernel stack top
    pub kstack_top: A::VirtAddr,
    /// User stack top (if user process)
    pub user_stack_top: Option<A::VirtAddr>,
    /// Cached pages this task is using (for refcount management on exit)
    pub cached_pages: Vec<Arc<CachedPage>>,
}

impl<A: Arch, PT: PageTable<VirtAddr = A::VirtAddr, PhysAddr = A::PhysAddr>> Task<A, PT> {
    /// Release all cached page references held by this task
    ///
    /// Should be called when the task exits to decrement refcounts
    /// on cached pages, making them eligible for eviction.
    pub fn release_cached_pages(&mut self) {
        for page in self.cached_pages.drain(..) {
            page.put();
        }
    }

    /// Add a cached page reference to this task
    pub fn add_cached_page(&mut self, page: Arc<CachedPage>) {
        self.cached_pages.push(page);
    }
}

// =============================================================================
// Linux capability constants (subset)
// =============================================================================

/// CAP_IPC_LOCK - Lock memory (mlock, mlockall, etc.)
pub const CAP_IPC_LOCK: u32 = 14;
/// CAP_SYS_ADMIN - System administration capabilities
pub const CAP_SYS_ADMIN: u32 = 21;
/// CAP_SYS_NICE - Raise process nice value, set real-time priorities
pub const CAP_SYS_NICE: u32 = 23;
/// CAP_SYS_RESOURCE - Override resource limits
pub const CAP_SYS_RESOURCE: u32 = 24;

/// Check if the current task has a specific capability
///
/// Currently simplified: all capabilities are granted when euid == 0 (root).
/// A full capability system would track per-task capability bitmasks.
///
/// # Arguments
/// * `_cap` - The capability constant (CAP_IPC_LOCK, CAP_SYS_RESOURCE, etc.)
///
/// # Returns
/// true if the current task has the capability
#[allow(unused_variables)]
pub fn capable(_cap: u32) -> bool {
    percpu::current_cred().euid == 0
}

// =============================================================================
// Per-UID process counting (for RLIMIT_NPROC)
// =============================================================================

use spin::Mutex;

/// Global table tracking process count per UID
///
/// Used for RLIMIT_NPROC enforcement. Each process (not thread) increments
/// the count for its UID on creation and decrements on exit.
static UID_PROCESS_COUNT: Mutex<BTreeMap<Uid, u64>> = Mutex::new(BTreeMap::new());

/// Increment the process count for a UID
///
/// Called when a new process (not thread) is created successfully.
/// Returns the new count after incrementing.
pub fn increment_user_process_count(uid: Uid) -> u64 {
    let mut counts = UID_PROCESS_COUNT.lock();
    let count = counts.entry(uid).or_insert(0);
    *count += 1;
    *count
}

/// Decrement the process count for a UID
///
/// Called when a process exits. Safe to call even if count is already 0.
pub fn decrement_user_process_count(uid: Uid) {
    let mut counts = UID_PROCESS_COUNT.lock();
    if let Some(count) = counts.get_mut(&uid) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            counts.remove(&uid);
        }
    }
}

/// Get the current process count for a UID
///
/// Used by RLIMIT_NPROC enforcement before creating a new process.
pub fn get_user_process_count(uid: Uid) -> u64 {
    let counts = UID_PROCESS_COUNT.lock();
    counts.get(&uid).copied().unwrap_or(0)
}
