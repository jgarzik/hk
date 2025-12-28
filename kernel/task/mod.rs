//! Task management

pub mod exec;
pub mod fdtable;
pub mod id;
pub mod misc;
pub mod percpu;
pub mod pgrp;
pub mod proc;
pub mod process_vm;
pub mod sched;
pub mod schedsys;
pub mod syscall;

/// Clone flags for clone() syscall (subset of Linux flags)
///
/// These flags control what resources are shared between parent and child.
pub mod clone_flags {
    /// Return a pidfd for the child process
    pub const CLONE_PIDFD: u64 = 0x00001000;
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
    /// Child has same parent as caller (creates sibling, not child)
    pub const CLONE_PARENT: u64 = 0x00008000;
    /// Share thread group (same PID)
    pub const CLONE_THREAD: u64 = 0x00010000;
    /// Share System V semaphore undo list
    pub const CLONE_SYSVSEM: u64 = 0x00040000;
    /// Set thread-local storage pointer for child
    pub const CLONE_SETTLS: u64 = 0x00080000;
    /// Set parent TID at parent_tidptr location
    pub const CLONE_PARENT_SETTID: u64 = 0x00100000;
    /// Set child TID at child_tidptr location (in child's address space)
    pub const CLONE_CHILD_SETTID: u64 = 0x01000000;
    /// Clear child TID at child_tidptr on exit
    pub const CLONE_CHILD_CLEARTID: u64 = 0x00200000;
    /// Share I/O context (ioprio)
    pub const CLONE_IO: u64 = 0x80000000;

    /// Clear signal handlers (reset to SIG_DFL) - Linux 5.5+
    /// Note: SIG_IGN handlers are preserved (intentional Linux behavior)
    pub const CLONE_CLEAR_SIGHAND: u64 = 0x100000000;

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
    /// Wait for child identified by pidfd
    pub const P_PIDFD: i32 = 3;
}

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::AtomicBool;

use crate::arch::{Arch, PageTable};
use crate::fs::{File, FsStruct};
use crate::ipc::sem::SemUndoList;
use crate::mm::MmStruct;
use crate::mm::page_cache::CachedPage;
use crate::ns::NsProxy;
use crate::seccomp::SeccompFilter;
use crate::signal::{SigHand, SignalStruct, TaskSignalState};

use spin::Mutex;

/// Process ID type
pub type Pid = u64;

/// Thread ID type
pub type Tid = u64;

/// User ID type (Linux-compatible)
pub type Uid = u32;

/// Group ID type (Linux-compatible)
pub type Gid = u32;

/// Magic value to detect corrupted/freed Task structs ("TASKMAGI" in ASCII)
pub const TASK_MAGIC: u64 = 0x5441534B_4D414749;

/// Task credentials (Linux-compatible model)
///
/// Linux has multiple credential sets: real, effective, saved, filesystem.
/// For permission checking, fsuid/fsgid are used. This tracks all eight IDs
/// as Linux does, plus the five capability sets.
///
/// Mirrors Linux's `struct cred` from include/linux/cred.h
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

    // Capability sets (mirrors Linux's struct cred)
    /// Capabilities children can inherit
    pub cap_inheritable: KernelCap,
    /// Capabilities we're permitted to use
    pub cap_permitted: KernelCap,
    /// Capabilities we can actually use (checked by capable())
    pub cap_effective: KernelCap,
    /// Capability bounding set (limits caps that can be gained)
    pub cap_bset: KernelCap,
    /// Ambient capability set (automatically inherited by children)
    pub cap_ambient: KernelCap,
}

impl Cred {
    /// Root credentials (uid=0, gid=0, full capabilities)
    pub const ROOT: Self = Self {
        uid: 0,
        gid: 0,
        suid: 0,
        sgid: 0,
        euid: 0,
        egid: 0,
        fsuid: 0,
        fsgid: 0,
        cap_inheritable: CAP_FULL_SET,
        cap_permitted: CAP_FULL_SET,
        cap_effective: CAP_FULL_SET,
        cap_bset: CAP_FULL_SET,
        cap_ambient: CAP_EMPTY_SET, // Ambient starts empty even for root
    };

    /// Create credentials for a specific user/group
    ///
    /// Sets all credential fields (uid, suid, euid, fsuid) to the same value.
    /// For root (uid=0), grants full capabilities.
    /// For non-root, grants empty capabilities.
    pub const fn new(uid: Uid, gid: Gid) -> Self {
        // Root gets full caps, non-root gets empty caps
        let (caps, bset) = if uid == 0 {
            (CAP_FULL_SET, CAP_FULL_SET)
        } else {
            (CAP_EMPTY_SET, CAP_FULL_SET) // Bounding set is full even for non-root
        };

        Self {
            uid,
            gid,
            suid: uid,
            sgid: gid,
            euid: uid,
            egid: gid,
            fsuid: uid,
            fsgid: gid,
            cap_inheritable: CAP_EMPTY_SET,
            cap_permitted: caps,
            cap_effective: caps,
            cap_bset: bset,
            cap_ambient: CAP_EMPTY_SET,
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

// =============================================================================
// Credential APIs (Linux kernel/cred.c pattern)
// =============================================================================

/// Get the current task's credentials from per-CPU cache
///
/// Like Linux's `current_cred()` - fast path for syscalls.
/// Returns a copy since CurrentTask.cred is a Copy type.
pub fn current_cred() -> Cred {
    percpu::current_cred()
}

/// Get the current task's credentials from TASK_TABLE (authoritative source)
///
/// This fetches the Arc<Cred> from the actual Task struct.
/// Used when the per-CPU cache might be stale or for reference counting.
pub fn current_cred_arc() -> Arc<Cred> {
    let tid = percpu::current_tid();
    let table = percpu::TASK_TABLE.lock();
    table
        .tasks
        .iter()
        .find(|t| t.tid == tid)
        .map(|t| t.cred.clone())
        .unwrap_or_else(|| Arc::new(Cred::ROOT))
}

/// Prepare a new credential set by cloning current credentials
///
/// Like Linux's `prepare_creds()` - creates a mutable copy that can be
/// modified before committing. Returns owned Cred (not Arc) for modification.
///
/// Usage pattern (like Linux):
/// ```ignore
/// let mut new_cred = prepare_creds();
/// new_cred.uid = new_uid;
/// new_cred.euid = new_uid;
/// commit_creds(Arc::new(new_cred));
/// ```
pub fn prepare_creds() -> Cred {
    current_cred()
}

/// Commit new credentials to current task
///
/// Like Linux's `commit_creds()` - atomically updates both:
/// 1. Task.cred in TASK_TABLE (persistent storage)
/// 2. CurrentTask.cred in per-CPU cache (fast access)
///
/// The new credentials take effect immediately.
pub fn commit_creds(new: Arc<Cred>) {
    percpu::commit_creds_impl(new);
}

/// Copy credentials for fork/clone
///
/// Like Linux's `copy_creds()` - handles credential inheritance during clone:
/// - CLONE_THREAD: Share credentials (clone Arc reference)
/// - Otherwise (fork): Deep copy credentials (new Arc with copied data)
///
/// This follows Linux's pattern from kernel/cred.c:copy_creds().
pub fn copy_creds(clone_flags: u64, parent_cred: &Arc<Cred>) -> Arc<Cred> {
    use clone_flags::CLONE_THREAD;

    if clone_flags & CLONE_THREAD != 0 {
        // Threads share credentials - just clone the Arc (bump refcount)
        parent_cred.clone()
    } else {
        // Fork: deep copy credentials (child gets independent copy)
        Arc::new(**parent_cred)
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
    /// Seccomp mode (cached for fast syscall-entry check)
    /// 0=DISABLED, 1=STRICT, 2=FILTER
    pub seccomp_mode: u8,
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
            seccomp_mode: 0, // SECCOMP_MODE_DISABLED
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
            seccomp_mode: 0, // SECCOMP_MODE_DISABLED
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

// =============================================================================
// prctl state (PR_SET_NAME, PR_SET_DUMPABLE, etc.)
// =============================================================================

/// prctl operation codes
pub mod prctl_ops {
    /// Set parent death signal
    pub const PR_SET_PDEATHSIG: i32 = 1;
    /// Get parent death signal
    pub const PR_GET_PDEATHSIG: i32 = 2;
    /// Get dumpable flag
    pub const PR_GET_DUMPABLE: i32 = 3;
    /// Set dumpable flag
    pub const PR_SET_DUMPABLE: i32 = 4;
    /// Get keep capabilities flag
    pub const PR_GET_KEEPCAPS: i32 = 7;
    /// Set keep capabilities flag
    pub const PR_SET_KEEPCAPS: i32 = 8;
    /// Set process name (comm)
    pub const PR_SET_NAME: i32 = 15;
    /// Get process name (comm)
    pub const PR_GET_NAME: i32 = 16;
    /// Get seccomp mode
    pub const PR_GET_SECCOMP: i32 = 21;
    /// Set seccomp mode
    pub const PR_SET_SECCOMP: i32 = 22;
    /// Set timer slack value (nanoseconds)
    pub const PR_SET_TIMERSLACK: i32 = 29;
    /// Get timer slack value (nanoseconds)
    pub const PR_GET_TIMERSLACK: i32 = 30;
    /// Get child subreaper flag
    pub const PR_GET_CHILD_SUBREAPER: i32 = 36;
    /// Set child subreaper flag
    pub const PR_SET_CHILD_SUBREAPER: i32 = 37;
    /// Disable privilege escalation via setuid/setgid (irreversible)
    pub const PR_SET_NO_NEW_PRIVS: i32 = 38;
    /// Get no_new_privs flag
    pub const PR_GET_NO_NEW_PRIVS: i32 = 39;
}

/// Dumpable flag values for PR_SET_DUMPABLE
pub mod dumpable {
    /// Not dumpable
    pub const SUID_DUMP_DISABLE: u8 = 0;
    /// Dumpable by user (default)
    pub const SUID_DUMP_USER: u8 = 1;
    /// Dumpable by root only
    pub const SUID_DUMP_ROOT: u8 = 2;
}

/// Per-task prctl state
///
/// Stores settings controlled by the prctl() syscall.
/// These are per-thread (not shared across clone).
#[derive(Clone)]
pub struct PrctlState {
    /// Thread/process name (PR_SET_NAME) - 16 bytes max, null-terminated
    pub name: [u8; 16],
    /// Dumpable flag (PR_SET_DUMPABLE) - controls core dump generation
    pub dumpable: u8,
    /// No-new-privileges flag (PR_SET_NO_NEW_PRIVS) - irreversible once set
    pub no_new_privs: bool,
    /// Timer slack in nanoseconds (PR_SET_TIMERSLACK)
    pub timer_slack_ns: u64,
    /// Keep capabilities across setuid (PR_SET_KEEPCAPS)
    /// When set, capabilities are preserved when changing UIDs
    pub keep_caps: bool,
    /// Child subreaper flag (PR_SET_CHILD_SUBREAPER)
    /// When set, this process becomes the parent of orphaned descendants
    /// instead of init (PID 1)
    pub child_subreaper: bool,
}

impl Default for PrctlState {
    fn default() -> Self {
        Self {
            name: [0u8; 16],
            dumpable: dumpable::SUID_DUMP_USER,
            no_new_privs: false,
            timer_slack_ns: 50_000, // 50 microseconds default
            keep_caps: false,
            child_subreaper: false,
        }
    }
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
    /// Magic number for validation (must be TASK_MAGIC)
    pub magic: u64,
    /// Process ID
    pub pid: Pid,
    /// Thread ID
    pub tid: Tid,
    /// Thread Group ID (equals pid for thread group leader)
    /// For CLONE_THREAD: inherited from parent; otherwise: equals pid
    pub tgid: Pid,
    /// Parent process ID (0 for init/orphans)
    pub ppid: Pid,
    /// Process group ID
    pub pgid: Pid,
    /// Session ID
    pub sid: Pid,

    // =========================================================================
    // Exit handling (like Linux task_struct exit fields)
    // =========================================================================
    /// Exit status code (set when task becomes zombie)
    pub exit_code: i32,
    /// Signal to send to parent on exit (default SIGCHLD, from clone3 exit_signal)
    pub exit_signal: i32,
    /// Signal to send when parent dies (set via prctl PR_SET_PDEATHSIG)
    pub pdeath_signal: i32,

    // =========================================================================
    // Process accounting (like Linux task_struct timing/accounting fields)
    // =========================================================================
    /// User CPU time consumed (nanoseconds)
    pub utime: u64,
    /// System CPU time consumed (nanoseconds)
    pub stime: u64,
    /// Task start time (monotonic clock, nanoseconds since boot)
    pub start_time: u64,
    /// Voluntary context switches (task yielded or slept)
    pub nvcsw: u64,
    /// Involuntary context switches (preempted by scheduler)
    pub nivcsw: u64,
    /// Minor page faults (demand paging, COW - no I/O required)
    pub min_flt: u64,
    /// Major page faults (swap-in required - I/O needed)
    pub maj_flt: u64,

    // =========================================================================
    // Credentials (like Linux task_struct->cred)
    // =========================================================================
    /// Task credentials - reference-counted, immutable after commit
    /// Following Linux pattern: prepare_creds() -> modify -> commit_creds()
    pub cred: Arc<Cred>,

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

    // =========================================================================
    // TLS and thread-exit fields (Linux: embedded in task_struct/thread_struct)
    // =========================================================================
    /// Thread-local storage base address
    /// - x86_64: FS base (set via MSR_FS_BASE or arch_prctl ARCH_SET_FS)
    /// - aarch64: TPIDR_EL0 value
    pub tls_base: u64,

    /// Address to clear and futex-wake on thread exit (set_tid_address syscall)
    /// Used by pthread library for thread cleanup notification.
    pub clear_child_tid: u64,

    /// Address to write child TID on first schedule (CLONE_CHILD_SETTID for fork)
    /// Consumed after first use (one-time operation).
    pub set_child_tid: u64,

    // =========================================================================
    // Shared resources (Arc for clone-sharing, like Linux pointers)
    // =========================================================================
    /// Memory descriptor (shared when CLONE_VM)
    pub mm: Option<Arc<Mutex<MmStruct>>>,

    /// File descriptor table (shared when CLONE_FILES)
    pub files: Option<Arc<Mutex<FdTable<File>>>>,

    /// Filesystem context (shared when CLONE_FS)
    pub fs: Option<Arc<FsStruct>>,

    /// Namespace proxy (shared based on CLONE_NEW* flags)
    pub nsproxy: Option<Arc<NsProxy>>,

    /// Signal handlers (shared when CLONE_SIGHAND)
    pub sighand: Option<Arc<SigHand>>,

    /// Thread-group signal state (shared when CLONE_THREAD)
    pub signal: Option<Arc<SignalStruct>>,

    /// I/O context (shared when CLONE_IO)
    pub io_context: Option<Arc<IoContext>>,

    /// SysV semaphore undo list (shared when CLONE_SYSVSEM)
    pub sysvsem: Option<Arc<SemUndoList>>,

    // =========================================================================
    // Per-task signal state (not shared)
    // =========================================================================
    /// Per-task signal state (blocked signals, pending signals)
    pub signal_state: TaskSignalState,

    /// TIF_SIGPENDING flag (fast check at syscall return)
    pub tif_sigpending: AtomicBool,

    /// Robust futex list head address
    pub robust_list: u64,

    // =========================================================================
    // prctl state (not shared)
    // =========================================================================
    /// Per-task prctl state (name, dumpable, no_new_privs, timer_slack)
    pub prctl: PrctlState,

    // =========================================================================
    // Personality (execution domain)
    // =========================================================================
    /// Process personality (execution domain, affects syscall behavior)
    /// See personality(2). Default is 0 (PER_LINUX).
    pub personality: u32,

    // =========================================================================
    // NUMA memory policy
    // =========================================================================
    /// Per-task NUMA memory policy (set via set_mempolicy)
    /// Inherited by child tasks on fork.
    pub mempolicy: crate::mm::mempolicy::TaskMempolicy,

    // =========================================================================
    // Seccomp state (sandboxing)
    // =========================================================================
    /// Seccomp mode: 0=DISABLED, 1=STRICT, 2=FILTER
    pub seccomp_mode: u8,

    /// Seccomp filter chain (head, reference counted)
    /// Filters are chained: when a new filter is installed, it points to the previous.
    /// On syscall entry, filters are run in order (newest first), and the most
    /// restrictive result wins.
    pub seccomp_filter: Option<Arc<SeccompFilter>>,

    // =========================================================================
    // I/O port permissions (x86-64 only)
    // =========================================================================
    /// Emulated I/O privilege level (x86-64 only)
    /// 0-2 = no direct I/O access, 3 = full I/O port access
    /// This is an emulation of the CPU IOPL mechanism, stored per-task.
    #[cfg(target_arch = "x86_64")]
    pub iopl_emul: u8,
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
// Linux capability system (full implementation)
// =============================================================================

/// Kernel capability set (64-bit bitmask)
///
/// Mirrors Linux's `kernel_cap_t` - a single 64-bit value that can hold
/// all 41 Linux capabilities (CAP_CHOWN=0 through CAP_CHECKPOINT_RESTORE=40).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct KernelCap(pub u64);

// POSIX-draft capabilities (0-7)
/// Override chown restrictions
pub const CAP_CHOWN: u32 = 0;
/// Override DAC access restrictions
pub const CAP_DAC_OVERRIDE: u32 = 1;
/// Override DAC read/search restrictions
pub const CAP_DAC_READ_SEARCH: u32 = 2;
/// Override file ownership checks
pub const CAP_FOWNER: u32 = 3;
/// Override setuid/setgid bits
pub const CAP_FSETID: u32 = 4;
/// Override signal sending restrictions
pub const CAP_KILL: u32 = 5;
/// Allow setgid manipulation
pub const CAP_SETGID: u32 = 6;
/// Allow setuid manipulation
pub const CAP_SETUID: u32 = 7;

// Linux-specific capabilities (8-40)
/// Transfer/remove capabilities
pub const CAP_SETPCAP: u32 = 8;
/// Modify S_IMMUTABLE and S_APPEND attributes
pub const CAP_LINUX_IMMUTABLE: u32 = 9;
/// Bind to ports below 1024
pub const CAP_NET_BIND_SERVICE: u32 = 10;
/// Allow broadcasting/multicasting
pub const CAP_NET_BROADCAST: u32 = 11;
/// Allow network administration
pub const CAP_NET_ADMIN: u32 = 12;
/// Allow raw sockets
pub const CAP_NET_RAW: u32 = 13;
/// Lock memory (mlock, mlockall, etc.)
pub const CAP_IPC_LOCK: u32 = 14;
/// Override IPC ownership checks
pub const CAP_IPC_OWNER: u32 = 15;
/// Insert/remove kernel modules
pub const CAP_SYS_MODULE: u32 = 16;
/// Allow raw I/O access
pub const CAP_SYS_RAWIO: u32 = 17;
/// Use chroot()
pub const CAP_SYS_CHROOT: u32 = 18;
/// Allow ptrace of any process
pub const CAP_SYS_PTRACE: u32 = 19;
/// Configure process accounting
pub const CAP_SYS_PACCT: u32 = 20;
/// System administration capabilities
pub const CAP_SYS_ADMIN: u32 = 21;
/// Use reboot()
pub const CAP_SYS_BOOT: u32 = 22;
/// Raise process nice value, set real-time priorities
pub const CAP_SYS_NICE: u32 = 23;
/// Override resource limits
pub const CAP_SYS_RESOURCE: u32 = 24;
/// Manipulate system clock
pub const CAP_SYS_TIME: u32 = 25;
/// Configure TTY devices
pub const CAP_SYS_TTY_CONFIG: u32 = 26;
/// Privileged mknod operations
pub const CAP_MKNOD: u32 = 27;
/// Take file leases
pub const CAP_LEASE: u32 = 28;
/// Write to audit log
pub const CAP_AUDIT_WRITE: u32 = 29;
/// Configure audit
pub const CAP_AUDIT_CONTROL: u32 = 30;
/// Set file capabilities
pub const CAP_SETFCAP: u32 = 31;
/// Override MAC access
pub const CAP_MAC_OVERRIDE: u32 = 32;
/// Configure MAC
pub const CAP_MAC_ADMIN: u32 = 33;
/// Configure syslog
pub const CAP_SYSLOG: u32 = 34;
/// Trigger wake alarms
pub const CAP_WAKE_ALARM: u32 = 35;
/// Prevent system suspend
pub const CAP_BLOCK_SUSPEND: u32 = 36;
/// Read audit log
pub const CAP_AUDIT_READ: u32 = 37;
/// Performance monitoring
pub const CAP_PERFMON: u32 = 38;
/// BPF operations
pub const CAP_BPF: u32 = 39;
/// Checkpoint/restore operations
pub const CAP_CHECKPOINT_RESTORE: u32 = 40;

/// Last valid capability number
pub const CAP_LAST_CAP: u32 = CAP_CHECKPOINT_RESTORE;

/// Bitmask of all valid capabilities
pub const CAP_VALID_MASK: u64 = (1u64 << (CAP_LAST_CAP + 1)) - 1;

/// Full capability set (all capabilities enabled)
pub const CAP_FULL_SET: KernelCap = KernelCap(CAP_VALID_MASK);

/// Empty capability set (no capabilities enabled)
pub const CAP_EMPTY_SET: KernelCap = KernelCap(0);

impl KernelCap {
    /// Create a new empty capability set
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Create a new full capability set
    pub const fn full() -> Self {
        Self(CAP_VALID_MASK)
    }

    /// Check if a capability is set
    #[inline]
    pub const fn has(&self, cap: u32) -> bool {
        if cap > CAP_LAST_CAP {
            return false;
        }
        (self.0 & (1u64 << cap)) != 0
    }

    /// Raise (enable) a capability
    #[inline]
    pub fn raise(&mut self, cap: u32) {
        if cap <= CAP_LAST_CAP {
            self.0 |= 1u64 << cap;
        }
    }

    /// Drop (disable) a capability
    #[inline]
    pub fn drop(&mut self, cap: u32) {
        if cap <= CAP_LAST_CAP {
            self.0 &= !(1u64 << cap);
        }
    }

    /// Check if this set is a subset of another
    #[inline]
    pub const fn is_subset(&self, superset: &KernelCap) -> bool {
        (self.0 & !superset.0) == 0
    }

    /// Intersect two capability sets
    #[inline]
    pub const fn intersect(&self, other: &KernelCap) -> KernelCap {
        KernelCap(self.0 & other.0)
    }

    /// Union two capability sets
    #[inline]
    pub const fn union(&self, other: &KernelCap) -> KernelCap {
        KernelCap(self.0 | other.0)
    }

    /// Get lower 32 bits (for syscall ABI)
    #[inline]
    pub const fn low(&self) -> u32 {
        self.0 as u32
    }

    /// Get upper 32 bits (for syscall ABI)
    #[inline]
    pub const fn high(&self) -> u32 {
        (self.0 >> 32) as u32
    }

    /// Create from low and high 32-bit values (for syscall ABI)
    #[inline]
    pub const fn from_u32s(low: u32, high: u32) -> Self {
        Self((low as u64) | ((high as u64) << 32))
    }
}

// Linux capability version constants (for syscall ABI)
/// Legacy 32-bit capability version
pub const _LINUX_CAPABILITY_VERSION_1: u32 = 0x19980330;
/// Deprecated 64-bit capability version
pub const _LINUX_CAPABILITY_VERSION_2: u32 = 0x20071026;
/// Current 64-bit capability version
pub const _LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;
/// Number of u32s per capability set in version 3
pub const _LINUX_CAPABILITY_U32S_3: usize = 2;

/// User-space capability header (for syscall ABI)
///
/// Matches Linux's `struct __user_cap_header_struct`
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct CapUserHeader {
    pub version: u32,
    pub pid: i32,
}

/// User-space capability data (for syscall ABI)
///
/// Matches Linux's `struct __user_cap_data_struct`
/// Note: For version 3, userspace provides an array of 2 of these
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct CapUserData {
    pub effective: u32,
    pub permitted: u32,
    pub inheritable: u32,
}

/// Check if a capability number is valid
#[inline]
pub const fn cap_valid(cap: u32) -> bool {
    cap <= CAP_LAST_CAP
}

/// Check if the current task has a specific capability
///
/// Checks the effective capability set of the current task.
/// This is the Linux-compatible capability check function.
///
/// # Arguments
/// * `cap` - The capability constant (CAP_IPC_LOCK, CAP_SYS_RESOURCE, etc.)
///
/// # Returns
/// true if the current task has the capability in its effective set
pub fn capable(cap: u32) -> bool {
    if cap > CAP_LAST_CAP {
        return false;
    }
    percpu::current_cred().cap_effective.has(cap)
}

// =============================================================================
// Per-UID process counting (for RLIMIT_NPROC)
// =============================================================================

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

// =============================================================================
// I/O Priority (ioprio) support for CLONE_IO
// =============================================================================

use core::sync::atomic::{AtomicU16, Ordering};

/// I/O priority type (matches Linux: 3-bit class + 13-bit data)
pub type IoPrio = u16;

/// No I/O priority class (use default)
pub const IOPRIO_CLASS_NONE: u16 = 0;
/// Real-time I/O class (highest priority)
pub const IOPRIO_CLASS_RT: u16 = 1;
/// Best-effort I/O class (default for normal processes)
pub const IOPRIO_CLASS_BE: u16 = 2;
/// Idle I/O class (only when system is otherwise idle)
pub const IOPRIO_CLASS_IDLE: u16 = 3;

/// Number of bits for I/O priority class
pub const IOPRIO_CLASS_SHIFT: u16 = 13;
/// Mask for I/O priority data
pub const IOPRIO_PRIO_MASK: u16 = (1 << IOPRIO_CLASS_SHIFT) - 1;

/// Default I/O priority (best-effort class, level 4)
pub const IOPRIO_DEFAULT: IoPrio = ioprio_prio_value(IOPRIO_CLASS_BE, 4);

/// Extract priority class from ioprio value
#[inline]
pub const fn ioprio_prio_class(ioprio: IoPrio) -> u16 {
    ioprio >> IOPRIO_CLASS_SHIFT
}

/// Extract priority data/level from ioprio value
#[inline]
pub const fn ioprio_prio_data(ioprio: IoPrio) -> u16 {
    ioprio & IOPRIO_PRIO_MASK
}

/// Construct ioprio value from class and data
#[inline]
pub const fn ioprio_prio_value(class: u16, data: u16) -> IoPrio {
    ((class & 0x7) << IOPRIO_CLASS_SHIFT) | (data & IOPRIO_PRIO_MASK)
}

/// Check if an ioprio value is valid
#[inline]
pub fn ioprio_valid(ioprio: IoPrio) -> bool {
    let class = ioprio_prio_class(ioprio);
    class <= IOPRIO_CLASS_IDLE
}

/// I/O context for a task (shareable via CLONE_IO)
///
/// Contains I/O scheduling priority and related state.
/// When CLONE_IO is used, multiple tasks share the same IoContext,
/// so changes to ioprio affect all sharing tasks.
pub struct IoContext {
    /// I/O priority (3-bit class + 13-bit data)
    pub ioprio: AtomicU16,
}

impl IoContext {
    /// Create a new I/O context with default priority
    pub fn new() -> Self {
        Self {
            ioprio: AtomicU16::new(IOPRIO_DEFAULT),
        }
    }

    /// Create a new I/O context with specific priority
    pub fn with_ioprio(ioprio: IoPrio) -> Self {
        Self {
            ioprio: AtomicU16::new(ioprio),
        }
    }

    /// Get current I/O priority
    #[inline]
    pub fn get_ioprio(&self) -> IoPrio {
        self.ioprio.load(Ordering::Relaxed)
    }

    /// Set I/O priority
    #[inline]
    pub fn set_ioprio(&self, ioprio: IoPrio) {
        self.ioprio.store(ioprio, Ordering::Relaxed);
    }
}

impl Default for IoContext {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for IoContext {
    fn clone(&self) -> Self {
        Self {
            ioprio: AtomicU16::new(self.ioprio.load(Ordering::Relaxed)),
        }
    }
}

// =============================================================================
// Task I/O context accessors - uses Task.io_context field via TASK_TABLE
// =============================================================================

/// Get the I/O context for a task
pub fn get_task_io_context(tid: Tid) -> Option<Arc<IoContext>> {
    let table = percpu::TASK_TABLE.lock();
    table
        .tasks
        .iter()
        .find(|t| t.tid == tid)
        .and_then(|t| t.io_context.clone())
}

/// Set the I/O context for a task
pub fn set_task_io_context(tid: Tid, ctx: Arc<IoContext>) {
    let mut table = percpu::TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
        task.io_context = Some(ctx);
    }
}

/// Remove the I/O context for a task (on exit)
pub fn remove_task_io_context(tid: Tid) {
    let mut table = percpu::TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
        task.io_context = None;
    }
}

/// Clone I/O context for a new task
///
/// If `share` is true (CLONE_IO set), child shares parent's Arc<IoContext>.
/// Otherwise, child gets a new IoContext inheriting parent's ioprio value.
pub fn clone_task_io(parent_tid: Tid, child_tid: Tid, share: bool) {
    let parent_ctx = get_task_io_context(parent_tid);

    let child_ctx = if let Some(parent_ctx) = parent_ctx {
        if share {
            // CLONE_IO: share the same context
            parent_ctx
        } else {
            // No CLONE_IO: create new context with inherited ioprio
            Arc::new(IoContext::with_ioprio(parent_ctx.get_ioprio()))
        }
    } else {
        // Parent has no context, create default for child
        Arc::new(IoContext::new())
    };

    set_task_io_context(child_tid, child_ctx);
}

// =============================================================================
// ioprio syscall "which" constants
// =============================================================================

/// ioprio_get/set for a specific process
pub const IOPRIO_WHO_PROCESS: i32 = 1;
/// ioprio_get/set for a process group
pub const IOPRIO_WHO_PGRP: i32 = 2;
/// ioprio_get/set for all processes of a user
pub const IOPRIO_WHO_USER: i32 = 3;

// =============================================================================
// Per-task Thread-Local Storage (TLS) pointer
// =============================================================================
//
// TLS is stored directly in the Task struct (tls_base field), following the
// Linux pattern where it's stored in task_struct->thread.fsbase.
//
// Access pattern (Linux-compatible):
// - TASK_TABLE.lock() for short critical section
// - Direct field access (O(1) once task is found)

/// Get the TLS pointer for a task
pub fn get_task_tls(tid: Tid) -> Option<u64> {
    let table = percpu::TASK_TABLE.lock();
    table
        .tasks
        .iter()
        .find(|t| t.tid == tid)
        .map(|t| t.tls_base)
        .filter(|&v| v != 0)
}

/// Set the TLS pointer for a task
pub fn set_task_tls(tid: Tid, tls: u64) {
    let mut table = percpu::TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
        task.tls_base = tls;
    }
}

/// Remove the TLS pointer for a task (on exit)
pub fn remove_task_tls(tid: Tid) {
    let mut table = percpu::TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
        task.tls_base = 0;
    }
}

// =============================================================================
// Per-task clear_child_tid pointer (for set_tid_address syscall)
// =============================================================================
//
// Stored directly in Task struct (clear_child_tid field), following Linux's
// task_struct->clear_child_tid pattern.

/// Get the clear_child_tid pointer for a task
pub fn get_clear_child_tid(tid: Tid) -> Option<u64> {
    let table = percpu::TASK_TABLE.lock();
    table
        .tasks
        .iter()
        .find(|t| t.tid == tid)
        .map(|t| t.clear_child_tid)
        .filter(|&v| v != 0)
}

/// Set the clear_child_tid pointer for a task
pub fn set_clear_child_tid(tid: Tid, addr: u64) {
    let mut table = percpu::TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
        task.clear_child_tid = addr;
    }
}

/// Remove the clear_child_tid pointer for a task (on exit, after processing)
pub fn remove_clear_child_tid(tid: Tid) {
    let mut table = percpu::TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
        task.clear_child_tid = 0;
    }
}

// =============================================================================
// Per-task set_child_tid pointer (for CLONE_CHILD_SETTID on fork)
// =============================================================================
//
// Stored directly in Task struct (set_child_tid field), following Linux's
// task_struct->set_child_tid pattern.

/// Get and remove the set_child_tid pointer for a task (one-time use)
pub fn get_set_child_tid(tid: Tid) -> Option<u64> {
    let mut table = percpu::TASK_TABLE.lock();
    if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
        let addr = task.set_child_tid;
        if addr != 0 {
            task.set_child_tid = 0; // Consume (one-time use)
            return Some(addr);
        }
    }
    None
}

/// Set the set_child_tid pointer for a task
pub fn set_set_child_tid(tid: Tid, addr: u64) {
    if addr != 0 {
        let mut table = percpu::TASK_TABLE.lock();
        if let Some(task) = table.tasks.iter_mut().find(|t| t.tid == tid) {
            task.set_child_tid = addr;
        }
    }
}
