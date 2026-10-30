//! Task management

pub mod exec;
pub mod fdtable;
pub mod id;
pub mod kthread;
pub mod misc;
pub mod percpu;
pub mod pgrp;
pub mod pid;
pub mod proc;
pub mod process_vm;
pub mod ptrace;
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

    /// Continue tracing child (if parent is being traced)
    pub const CLONE_PTRACE: u64 = 0x00002000;
    /// Prevent forced CLONE_PTRACE by parent's tracer
    pub const CLONE_UNTRACED: u64 = 0x00800000;

    /// Clear signal handlers (reset to SIG_DFL) - Linux 5.5+
    /// Note: SIG_IGN handlers are preserved (intentional Linux behavior)
    pub const CLONE_CLEAR_SIGHAND: u64 = 0x100000000;

    /// Place child in specific cgroup (clone3 only, requires cgroup fd)
    pub const CLONE_INTO_CGROUP: u64 = 0x200000000;

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
    /// Wait only for "clone" children (exit_signal != SIGCHLD)
    pub const __WCLONE: i32 = 0x80000000u32 as i32;
    /// Wait for all children regardless of exit_signal
    pub const __WALL: i32 = 0x40000000;

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
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicU32, AtomicU64};

use crate::arch::{Arch, PageTable};
use crate::fs::FsStruct;
use crate::ipc::sem::SemUndoList;
use crate::ns::NsProxy;
use crate::seccomp::SeccompFilter;
use crate::signal::{SigHand, SignalStruct, TaskSignalState};

use crate::sync::spin::Mutex;

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

    /// No privileges at all (overflow uid/gid 65534, no capabilities,
    /// empty bounding set): what a context without a task gets, so a
    /// missing task never runs privileged
    pub const NOBODY: Self = Self {
        uid: 65534,
        gid: 65534,
        suid: 65534,
        sgid: 65534,
        euid: 65534,
        egid: 65534,
        fsuid: 65534,
        fsgid: 65534,
        cap_inheritable: CAP_EMPTY_SET,
        cap_permitted: CAP_EMPTY_SET,
        cap_effective: CAP_EMPTY_SET,
        cap_bset: CAP_EMPTY_SET,
        cap_ambient: CAP_EMPTY_SET,
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

/// The current task's credentials, copied (Linux current_cred: read
/// lock-free, only the task itself replaces them)
pub fn current_cred() -> Cred {
    percpu::current_cred()
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
/// Like Linux's `commit_creds()`: the task's credential pointer is
/// replaced under TASKLIST (others read it under the lock; the task
/// itself without). The new credentials take effect immediately.
pub fn commit_creds(new: Arc<Cred>) {
    let old = current_cred().uid;
    if old != new.uid {
        flag_nproc_exceeded(new.uid);
    }
    nproc_move(old, new.uid);
    percpu::commit_creds_impl(new);
}

/// execve's RLIMIT_NPROC check (Linux do_execveat_common): EAGAIN if a
/// real-uid change flagged the task and it is still over; else the flag
/// is cleared
pub fn nproc_exec_check() -> Result<(), i32> {
    let tid = percpu::current_tid();
    let uid = current_cred().uid;
    // rlimit() takes TASKLIST: decide before locking it
    let over = nproc_overlimit(nproc_count(uid));
    let table = percpu::TASKLIST.read();
    let Some(t) = table.get(tid) else {
        return Ok(());
    };
    if t.task.has_flag(crate::task::pf::NPROC_EXCEEDED) && over {
        return Err(11); // EAGAIN
    }
    t.task.clear_flag(crate::task::pf::NPROC_EXCEEDED);
    Ok(())
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
    /// Stopped for ptrace (signal number that caused stop)
    Traced(i32),
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
    /// Get TSC (timestamp counter) mode (x86-64 only)
    pub const PR_GET_TSC: i32 = 25;
    /// Set TSC mode (x86-64 only)
    pub const PR_SET_TSC: i32 = 26;
    /// Set timer slack value (nanoseconds)
    pub const PR_SET_TIMERSLACK: i32 = 29;
    /// Get timer slack value (nanoseconds)
    pub const PR_GET_TIMERSLACK: i32 = 30;
    /// Set child subreaper flag
    pub const PR_SET_CHILD_SUBREAPER: i32 = 36;
    /// Get child subreaper flag
    pub const PR_GET_CHILD_SUBREAPER: i32 = 37;
    /// Disable privilege escalation via setuid/setgid (irreversible)
    pub const PR_SET_NO_NEW_PRIVS: i32 = 38;
    /// Get no_new_privs flag
    pub const PR_GET_NO_NEW_PRIVS: i32 = 39;
    /// Disable transparent huge pages for this process
    pub const PR_SET_THP_DISABLE: i32 = 41;
    /// Get THP disable flag
    pub const PR_GET_THP_DISABLE: i32 = 42;

    /// TSC mode: allow RDTSC instruction
    pub const PR_TSC_ENABLE: i32 = 1;
    /// TSC mode: SIGSEGV on RDTSC instruction
    pub const PR_TSC_SIGSEGV: i32 = 2;
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
    /// TSC mode (x86-64 only): PR_TSC_ENABLE or PR_TSC_SIGSEGV
    /// Controls whether RDTSC instruction is allowed
    #[cfg(target_arch = "x86_64")]
    pub tsc_mode: u8,
    /// Transparent Huge Pages disabled for this process
    pub thp_disable: bool,
}

impl Default for PrctlState {
    fn default() -> Self {
        Self {
            no_new_privs: false,
            timer_slack_ns: 50_000, // 50 microseconds default
            keep_caps: false,
            child_subreaper: false,
            #[cfg(target_arch = "x86_64")]
            tsc_mode: prctl_ops::PR_TSC_ENABLE as u8, // RDTSC allowed by default
            thp_disable: false,
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
///
/// Files the table lets go of (close, dup2/dup3 over an open descriptor,
/// an install it refused) are parked in `dead` instead of being dropped
/// under the table lock: releasing a file can sleep (TCP SO_LINGER, a
/// socket's release path), so `fdtable::FilesGuard` drops them after
/// unlocking (Linux file_close_fd_locked under files->file_lock, then
/// filp_close/fput after spin_unlock).
pub struct FdTable<F> {
    /// Mapping from fd number to file object
    files: BTreeMap<Fd, Arc<F>>,
    /// Per-fd flags (FD_CLOEXEC, etc.)
    fd_flags: BTreeMap<Fd, u32>,
    /// Detached files, released once the lock is dropped
    dead: Vec<Arc<F>>,
}

impl<F> FdTable<F> {
    /// Create a new empty file descriptor table
    pub fn new() -> Self {
        Self::new_const()
    }

    /// Create a new empty file descriptor table (const)
    pub const fn new_const() -> Self {
        Self {
            files: BTreeMap::new(),
            fd_flags: BTreeMap::new(),
            dead: Vec::new(),
        }
    }

    /// Park `file` for release after the table lock is dropped
    fn defer(&mut self, file: Arc<F>) {
        self.dead.push(file);
    }

    /// The files detached since the lock was taken (`FilesGuard` drops
    /// them after unlocking)
    pub fn take_dead(&mut self) -> Vec<Arc<F>> {
        core::mem::take(&mut self.dead)
    }

    /// Allocate the lowest free file descriptor for a file (POSIX).
    ///
    /// The `nofile` parameter is the RLIMIT_NOFILE limit. If the allocated fd
    /// would be >= nofile, returns Err(EMFILE). Pass `u64::MAX` to disable limit.
    ///
    /// Following Linux pattern: RLIMIT_NOFILE is enforced inside allocation.
    pub fn alloc(&mut self, file: Arc<F>, nofile: u64) -> Result<Fd, i32> {
        self.alloc_at_or_above(file, 0, 0, nofile)
    }

    /// Allocate a specific file descriptor (for stdin/stdout/stderr).
    ///
    /// This does NOT enforce RLIMIT_NOFILE as it's used for initial fd setup
    /// (stdin=0, stdout=1, stderr=2) where limits don't apply.
    pub fn alloc_at(&mut self, fd: Fd, file: Arc<F>) -> bool {
        if self.files.contains_key(&fd) {
            self.defer(file);
            return false;
        }
        self.files.insert(fd, file);
        true
    }

    /// Get a file by descriptor
    pub fn get(&self, fd: Fd) -> Option<Arc<F>> {
        self.files.get(&fd).cloned()
    }

    /// Close a file descriptor (false: EBADF); the file is released
    /// after the table lock is dropped
    pub fn close(&mut self, fd: Fd) -> bool {
        self.fd_flags.remove(&fd);
        match self.files.remove(&fd) {
            Some(f) => {
                self.defer(f);
                true
            }
            None => false,
        }
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
        self.alloc_at_or_above(file, 0, flags, nofile)
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
            self.defer(file);
            return Err(24); // EMFILE - too many open files
        }
        if self.files.contains_key(&fd) {
            self.defer(file);
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
            self.defer(file);
            return Err(24); // EMFILE - too many open files
        }
        self.files.insert(fd, file);
        if flags != 0 {
            self.fd_flags.insert(fd, flags);
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
            dead: Vec::new(),
        }
    }

    /// Copy for exec (Linux unshare_files + do_close_on_exec): the
    /// descriptors without FD_CLOEXEC, with their flags
    pub fn exec_copy(&self) -> Self {
        let mut t = Self::new();
        for (&fd, file) in &self.files {
            let fl = self.get_fd_flags(fd);
            if fl & FD_CLOEXEC == 0 {
                t.files.insert(fd, file.clone());
                if fl != 0 {
                    t.fd_flags.insert(fd, fl);
                }
            }
        }
        t
    }

    /// Detach the open descriptors in `lo..=hi` (Linux __range_close):
    /// only the open ones are visited, however wide the range
    pub fn close_range(&mut self, lo: Fd, hi: Fd) {
        let mut mid = self.files.split_off(&lo);
        let mut flags = self.fd_flags.split_off(&lo);
        if let Some(next) = hi.checked_add(1) {
            self.files.append(&mut mid.split_off(&next));
            self.fd_flags.append(&mut flags.split_off(&next));
        }
        self.dead.extend(mid.into_values());
    }

    /// Set FD_CLOEXEC on the open descriptors in `lo..=hi` (Linux
    /// __range_cloexec)
    pub fn cloexec_range(&mut self, lo: Fd, hi: Fd) {
        for &fd in self.files.range(lo..=hi).map(|(fd, _)| fd) {
            *self.fd_flags.entry(fd).or_insert(0) |= FD_CLOEXEC;
        }
    }

    /// Get the number of open file descriptors
    pub fn count(&self) -> usize {
        self.files.len()
    }
}

impl<F> Default for FdTable<F> {
    fn default() -> Self {
        Self::new()
    }
}

/// Task flags (Linux PF_*, `Task.flags`): set by the task itself (or
/// its creator before it runs), read lock-free by anyone
pub mod pf {
    /// Exiting (Linux PF_EXITING): what the task still releases (its
    /// files) does not wait on its behalf, e.g. no SO_LINGER wait in
    /// TCP close
    pub const EXITING: u32 = 0x0000_0004;
    /// A real-uid change left the task over RLIMIT_NPROC: its next
    /// execve rechecks (Linux PF_NPROC_EXCEEDED)
    pub const NPROC_EXCEEDED: u32 = 0x0000_1000;
    /// Kernel thread (Linux PF_KTHREAD)
    pub const KTHREAD: u32 = 0x0020_0000;
}

/// Thread flags (Linux TIF_*, `Task.thread_flags`): work to do on the way
/// back to user mode, set by anyone, consumed by the task
pub mod tif {
    /// A signal is deliverable under the blocked mask (Linux
    /// TIF_SIGPENDING)
    pub const SIGPENDING: u32 = 1 << 0;
    /// Give up the CPU on the way back to user mode: the slice is used up
    /// or a reschedule IPI arrived (Linux TIF_NEED_RESCHED)
    pub const NEED_RESCHED: u32 = 1 << 1;
    /// Work queued for the return to user mode (Linux TIF_NOTIFY_RESUME)
    pub const NOTIFY_RESUME: u32 = 1 << 2;
    /// A syscall left a temporary mask in place: `saved_sigmask` goes
    /// back on the way out, or into a handler's frame (Linux
    /// TIF_RESTORE_SIGMASK; set and cleared by the task itself)
    pub const RESTORE_SIGMASK: u32 = 1 << 3;
    /// PTRACE_SYSCALL: stop for the tracer at syscall entry and exit
    /// (Linux SYSCALL_WORK_SYSCALL_TRACE; set and cleared by the tracer
    /// while the task is stopped)
    pub const SYSCALL_TRACE: u32 = 1 << 4;
}

/// A task (thread or process; Linux task_struct), shared as
/// [`TaskRef`]: the task table, run queues and lookups hold references
///
/// Three kinds of fields:
/// - fixed at creation: `tid`, `pid`, `kind`, `kstack_top`;
/// - hot counters and flags: atomics written by the task itself (or
///   its creator before it first runs) or under TASKLIST, and read
///   lock-free by anyone (accounting, `flags`, `thread_flags`, `cpu`,
///   `ppid`/`pgid`/`sid`, `seccomp_mode`);
/// - `cred`: read by the task itself without a lock and by others under
///   TASKLIST, replaced by the task under TASKLIST (commit_creds);
/// - the `alloc_lock` fields (Linux task_lock: `mm`, `files`, `fs`,
///   `nsproxy`, `comm`, `mempolicy`, `io_context`): read by the task
///   itself without a lock (all but `io_context`) and by others under
///   its `alloc_lock` ([`Task::task_lock`]), changed under it by the
///   task (or its creator before it runs; `io_context` by anyone);
/// - everything else ([`TaskInner`]), read and written only under
///   TASKLIST, through the table's views (`GlobalTaskTable::get` etc.).
pub struct Task<A: Arch, PT: PageTable<VirtAddr = A::VirtAddr, PhysAddr = A::PhysAddr>> {
    /// Thread ID: the root number of its `thread_pid`; changes only when
    /// a non-leader execs and takes its leader's (exchange_tids)
    tid: AtomicU64,
    /// Process (thread-group) ID: the leader's tid (Linux tgid)
    pub pid: Pid,
    /// Kind of task
    pub kind: TaskKind,
    /// Kernel stack top
    pub kstack_top: A::VirtAddr,
    /// Task start time (monotonic clock, nanoseconds since boot; a
    /// de_thread successor takes its leader's)
    pub start_time: AtomicU64,

    /// Linux PF_* ([`pf`])
    pub flags: AtomicU32,
    /// Linux TIF_* ([`tif`])
    pub thread_flags: AtomicU32,
    /// CPU whose run queue owns this task (tasks never migrate)
    pub cpu: AtomicU32,
    /// Scheduling state: sleep state, run-queue link, priority, switch
    /// frame (Linux __state, on_rq, sched_entity)
    pub se: sched::SchedEntity,
    /// Serializes the task's wakers (Linux pi_lock): IrqSpinlock, taken
    /// before its CPU's rq lock (`try_to_wake_up`)
    pub pi_lock: crate::arch::IrqSpinlock<()>,

    /// Parent process ID (0 for init/orphans; written under TASKLIST)
    pub ppid: AtomicU64,
    /// Process group ID (written under TASKLIST)
    pub pgid: AtomicU64,
    /// Session ID (written under TASKLIST)
    pub sid: AtomicU64,
    /// User TLS register (x86-64 FS base, arm64 TPIDR_EL0), saved at
    /// switch-out and loaded at switch-in; set by the task itself or its
    /// creator (CLONE_SETTLS)
    pub tls: AtomicU64,
    /// User GS base (x86-64 ARCH_SET_GS, `mov gs`; Linux
    /// thread.gsbase; 0 on arm64), saved at switch-out and loaded at
    /// switch-in like `tls`; inherited by a fork child, 0 after exec
    pub gsbase: AtomicU64,
    /// Seccomp mode (0 = DISABLED, 1 = STRICT, 2 = FILTER), set by the
    /// task itself; read at every syscall entry
    pub seccomp_mode: AtomicU8,

    /// Its signal state (blocked mask, private pending set, altstack;
    /// Linux siglock's per-task part): spin Mutex, thread context only
    /// (no interrupt handler sends signals), under TASKLIST when both
    /// are taken; the shared pending set's lock nests inside
    pub sig: crate::sync::spin::Mutex<TaskSignalState>,
    /// Keyring references (Linux cred->thread_keyring etc.): spin lock,
    /// thread context; the key database is taken under it
    pub keyrings: crate::sync::spin::Mutex<crate::keys::keyring::TaskKeyrings>,
    /// Its cgroup (Linux task->cgroups): spin leaf, thread context
    pub cgroup: crate::sync::spin::Mutex<Option<Arc<crate::cgroup::Cgroup>>>,
    /// Files `defer_fput` still has to drop while an outer frame of this
    /// task drains (Linux task_work fput); only the task itself uses it
    pub fput_defer: crate::sync::spin::Mutex<Option<Vec<Arc<crate::fs::File>>>>,
    /// The vforking parent's completion until this task execs or exits
    /// (Linux vfork_done): set by the parent before the task runs, taken
    /// once by the task
    pub vfork_done: AtomicPtr<crate::completion::Completion>,
    /// Credentials (Linux task->cred): read lock-free by the task, under
    /// TASKLIST by others; replaced only by the task (commit_creds)
    /// under TASKLIST
    cred: TaskCred,
    /// Linux task_lock(p) (p->alloc_lock): guards the cells below. Spin
    /// Mutex, thread context only; order TASKLIST -> pidmap ->
    /// alloc_lock -> `sig`; only memory is freed under it (rule 4: the
    /// old value is taken or replaced under it, dropped after)
    alloc_lock: Mutex<()>,
    /// Address space, one mm_users reference (shared when CLONE_VM)
    mm: OwnCell<Option<crate::mm::MmRef>>,
    /// File descriptor table (shared when CLONE_FILES)
    files: OwnCell<Option<Arc<fdtable::Files>>>,
    /// Filesystem context (shared when CLONE_FS)
    fs: OwnCell<Option<Arc<FsStruct>>>,
    /// Namespace proxy (shared based on CLONE_NEW* flags)
    nsproxy: OwnCell<Option<Arc<NsProxy>>>,
    /// Name (Linux comm: PR_SET_NAME, exec), NUL-terminated
    comm: OwnCell<[u8; 16]>,
    /// NUMA memory policy (set_mempolicy; inherited by fork)
    mempolicy: OwnCell<crate::mm::mempolicy::TaskMempolicy>,
    /// I/O context (shared when CLONE_IO); also set by others
    /// (ioprio_set), so read only under `alloc_lock`
    io_context: OwnCell<Option<Arc<IoContext>>>,

    /// User CPU time consumed (nanoseconds)
    pub utime: AtomicU64,
    /// System CPU time consumed (nanoseconds)
    pub stime: AtomicU64,
    /// When the task last started running or crossed the user/kernel
    /// boundary (for the utime/stime split)
    pub last_run_ns: AtomicU64,
    /// In kernel mode (for the utime/stime split)
    pub in_kernel: AtomicBool,
    /// Voluntary context switches (task yielded or slept)
    pub nvcsw: AtomicU64,
    /// Involuntary context switches (preempted by scheduler)
    pub nivcsw: AtomicU64,
    /// Minor page faults (demand paging, COW - no I/O required)
    pub min_flt: AtomicU64,
    /// Major page faults (swap-in required - I/O needed)
    pub maj_flt: AtomicU64,

    /// Its place in the task list (Linux task->tasks; under TASKLIST)
    pub tasks_link: crate::list::Link,
    /// Its place in its real parent's `children` (Linux sibling; under
    /// TASKLIST)
    pub sibling: crate::list::Link,
    /// Its place in its group leader's `threads` (Linux thread_node;
    /// under TASKLIST)
    pub thread_node: crate::list::Link,
    /// The rest, under TASKLIST (None only for the boot task, which
    /// is never in the table)
    inner: TableCell<Option<TaskInner<A, PT>>>,
}

/// The fields of a [`Task`] read and written under TASKLIST
pub struct TaskInner<A: Arch, PT: PageTable<VirtAddr = A::VirtAddr, PhysAddr = A::PhysAddr>> {
    /// Its process identifier (Linux thread_pid; None for the idle
    /// tasks, tid 0)
    pub thread_pid: Option<Arc<pid::Pid>>,
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
    // Credentials (like Linux task_struct->cred)
    // =========================================================================
    /// Current state
    pub state: TaskState,
    /// Scheduling policy (SCHED_NORMAL, SCHED_FIFO, SCHED_RR, etc.)
    pub policy: i32,
    /// Real-time priority (1-99 for SCHED_FIFO/RR, 0 otherwise)
    pub rt_priority: i32,
    /// Reset scheduling policy on fork (SCHED_RESET_ON_FORK was set)
    pub reset_on_fork: bool,
    /// CPU affinity mask (bit N = CPU N is allowed)
    pub cpus_allowed: crate::cpumask::CpuSet,
    /// Page table for this task
    pub page_table: PT,

    // =========================================================================
    // TLS and thread-exit fields (Linux: embedded in task_struct/thread_struct)
    // =========================================================================
    /// Address to clear and futex-wake on thread exit (set_tid_address syscall)
    /// Used by pthread library for thread cleanup notification.
    pub clear_child_tid: u64,

    /// Address to write child TID on first schedule (CLONE_CHILD_SETTID for fork)
    /// Consumed after first use (one-time operation).
    pub set_child_tid: u64,

    // =========================================================================
    // Shared resources (Arc for clone-sharing, like Linux pointers)
    // =========================================================================
    /// Signal handlers (shared when CLONE_SIGHAND)
    pub sighand: Option<Arc<SigHand>>,

    /// Thread-group signal state (shared when CLONE_THREAD)
    pub signal: Option<Arc<SignalStruct>>,

    /// SysV semaphore undo list (shared when CLONE_SYSVSEM)
    pub sysvsem: Option<Arc<SemUndoList>>,

    // =========================================================================
    // Per-task signal state (not shared)
    // =========================================================================
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
    // Seccomp state (sandboxing)
    // =========================================================================
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

    /// Thread-group leader (Linux thread_group_leader): created without
    /// CLONE_THREAD, or the thread whose exec ended the others
    /// (de_thread). Only leaders are waited for; a leader keeps its
    /// SignalStruct as a zombie, for the group's exit status.
    pub leader: bool,

    // =========================================================================
    // Ptrace state (like Linux task_struct ptrace fields)
    // =========================================================================
    /// Ptrace flags (PT_PTRACED, PT_SEIZED, PT_SYSCALL_TRACE, PT_SINGLESTEP)
    /// 0 = not traced, non-zero = traced with flags
    pub ptrace: u32,

    /// The tracer (Linux task->parent while traced): a task reference,
    /// so a recycled number never names it (under TASKLIST)
    pub ptracer: Option<alloc::sync::Weak<Task<A, PT>>>,

    /// The real parent (Linux real_parent): the task whose `children`
    /// list holds this one; None for init and kernel threads. Weak:
    /// exit reparents children first (under TASKLIST)
    pub real_parent: Option<alloc::sync::Weak<Task<A, PT>>>,

    /// Its children (Linux children; their `sibling` links): the thread
    /// group leaders it created, one strong reference each, until reaped
    /// or reparented (under TASKLIST)
    pub children: crate::list::ArcList<Sibling<A, PT>>,

    /// On its real parent's `children` (a group leader; Linux: only
    /// leaders are)
    pub in_children: bool,

    /// A leader's thread group, itself included (Linux
    /// signal->thread_head; links `thread_node`), one strong reference
    /// each, until a thread leaves the task list (under TASKLIST)
    pub threads: crate::list::ArcList<ThreadNode<A, PT>>,

    /// Message for PTRACE_GETEVENTMSG (child PID, exec old TID, exit code, etc.)
    pub ptrace_message: u64,

    /// Ptrace options (PTRACE_O_TRACESYSGOOD, etc.)
    pub ptrace_options: u32,
    /// A ptrace stop's code (Linux exit_code): the stop's signal until
    /// the tracer's wait reports it (then 0), then the signal the
    /// tracer's resume leaves to deliver (0: none)
    pub ptrace_code: u32,
}

/// Data owned by the TASKLIST lock (Rust-for-Linux LockedBy): only
/// `GlobalTaskTable`'s views reach it, with the table locked
pub struct TableCell<T>(UnsafeCell<T>);

// SAFETY: every access goes through a view of the locked table
unsafe impl<T: Send> Sync for TableCell<T> {}

impl<T> TableCell<T> {
    pub const fn new(v: T) -> Self {
        Self(UnsafeCell::new(v))
    }

    /// # Safety
    /// TASKLIST is held, and no `&mut` to this cell's data exists.
    pub unsafe fn get(&self) -> &T {
        // SAFETY: see above
        unsafe { &*self.0.get() }
    }

    /// # Safety
    /// TASKLIST is held mutably by the caller, and no other reference
    /// to this cell's data exists.
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn get_mut(&self) -> &mut T {
        // SAFETY: see above
        unsafe { &mut *self.0.get() }
    }
}

/// The adapter of `Task.sibling` (children lists)
pub struct Sibling<A, PT>(core::marker::PhantomData<(A, PT)>);

// SAFETY: offset_of! gives `sibling`'s place in the task
unsafe impl<A: Arch, PT: PageTable<VirtAddr = A::VirtAddr, PhysAddr = A::PhysAddr>>
    crate::list::Adapter for Sibling<A, PT>
{
    type Item = Task<A, PT>;
    fn link(t: &Task<A, PT>) -> &crate::list::Link {
        &t.sibling
    }
    unsafe fn item(l: *const crate::list::Link) -> *const Task<A, PT> {
        // SAFETY: `l` is the `sibling` of a live task
        unsafe {
            (l as *const u8).sub(core::mem::offset_of!(Task<A, PT>, sibling)) as *const Task<A, PT>
        }
    }
}

/// The adapter of `Task.thread_node` (thread groups)
pub struct ThreadNode<A, PT>(core::marker::PhantomData<(A, PT)>);

// SAFETY: offset_of! gives `thread_node`'s place in the task
unsafe impl<A: Arch, PT: PageTable<VirtAddr = A::VirtAddr, PhysAddr = A::PhysAddr>>
    crate::list::Adapter for ThreadNode<A, PT>
{
    type Item = Task<A, PT>;
    fn link(t: &Task<A, PT>) -> &crate::list::Link {
        &t.thread_node
    }
    unsafe fn item(l: *const crate::list::Link) -> *const Task<A, PT> {
        // SAFETY: `l` is the `thread_node` of a live task
        unsafe {
            (l as *const u8).sub(core::mem::offset_of!(Task<A, PT>, thread_node))
                as *const Task<A, PT>
        }
    }
}

/// The ids a new task starts with
pub struct TaskIds {
    pub pid: Pid,
    pub ppid: Pid,
    pub pgid: Pid,
    pub sid: Pid,
    pub seccomp_mode: u8,
}

/// An owner field (Linux current->mm, ->files): the owning task reads it
/// without a lock; others read it under the task's `alloc_lock`; it
/// changes only under `alloc_lock`, by the owner or before the task
/// first runs (`io_context`: by anyone, so read under the lock only)
pub struct OwnCell<T>(UnsafeCell<T>);

// SAFETY: see the access rules above (enforced by `Task`'s unsafe API)
unsafe impl<T: Send> Sync for OwnCell<T> {}

impl<T> OwnCell<T> {
    pub const fn new(v: T) -> Self {
        Self(UnsafeCell::new(v))
    }

    /// # Safety
    /// The caller owns the task, or holds its `alloc_lock`.
    unsafe fn get(&self) -> &T {
        // SAFETY: no writer runs meanwhile: writers are the owner (not
        // reading now, or this is it) under `alloc_lock`
        unsafe { &*self.0.get() }
    }

    /// # Safety
    /// The task's `alloc_lock` is held, and the caller owns the task or
    /// it has not run yet; no reference from `get` is live.
    unsafe fn replace(&self, v: T) -> T {
        // SAFETY: see above
        unsafe { core::mem::replace(&mut *self.0.get(), v) }
    }
}

/// The credentials of the boot task (no allocation)
static INIT_CRED: Cred = Cred::ROOT;

/// A task's credentials pointer: an `Arc<Cred>` turned raw, or the boot
/// task's static `INIT_CRED`; the rules of [`OwnCell`] with TASKLIST
/// in place of `alloc_lock`
struct TaskCred(AtomicPtr<Cred>);

impl TaskCred {
    fn new(c: Arc<Cred>) -> Self {
        Self(AtomicPtr::new(Arc::into_raw(c) as *mut Cred))
    }

    const fn boot() -> Self {
        Self(AtomicPtr::new(&INIT_CRED as *const Cred as *mut Cred))
    }

    fn is_static(p: *const Cred) -> bool {
        core::ptr::eq(p, &INIT_CRED)
    }

    /// # Safety
    /// The caller is the task itself, or holds TASKLIST.
    unsafe fn get(&self) -> Cred {
        // SAFETY: the pointer is live (see above)
        unsafe { *self.0.load(Ordering::Acquire) }
    }

    /// # Safety
    /// As [`TaskCred::get`].
    unsafe fn arc(&self) -> Arc<Cred> {
        let p = self.0.load(Ordering::Acquire);
        if Self::is_static(p) {
            return Arc::new(INIT_CRED);
        }
        // SAFETY: `p` came from Arc::into_raw and holds a count
        unsafe {
            Arc::increment_strong_count(p);
            Arc::from_raw(p)
        }
    }

    /// # Safety
    /// TASKLIST is held, and the caller is the task itself or it has
    /// not run yet.
    unsafe fn replace(&self, new: Arc<Cred>) -> Option<Arc<Cred>> {
        let old = self
            .0
            .swap(Arc::into_raw(new) as *mut Cred, Ordering::AcqRel);
        // SAFETY: from Arc::into_raw unless static
        (!Self::is_static(old)).then(|| unsafe { Arc::from_raw(old) })
    }
}

impl Drop for TaskCred {
    fn drop(&mut self) {
        let p = *self.0.get_mut();
        if !Self::is_static(p) {
            // SAFETY: the task's own count
            drop(unsafe { Arc::from_raw(p) });
        }
    }
}

/// The initial `alloc_lock` fields of a new task (the resources are
/// attached after it joins the table, before it first runs)
pub struct TaskAlloc {
    pub comm: [u8; 16],
    pub mempolicy: crate::mm::mempolicy::TaskMempolicy,
}

impl TaskAlloc {
    /// Named `name` (truncated to 15 bytes), default memory policy
    pub fn named(name: &[u8]) -> Self {
        let mut comm = [0u8; 16];
        let n = name.len().min(15);
        comm[..n].copy_from_slice(&name[..n]);
        Self {
            comm,
            mempolicy: crate::mm::mempolicy::TaskMempolicy::new(),
        }
    }
}

/// A task's `alloc_lock` held (Linux task_lock(p)): its `alloc_lock`
/// fields readable, and writable under the owner rule ([`OwnCell`])
pub struct TaskLock<'a, A: Arch, PT: PageTable<VirtAddr = A::VirtAddr, PhysAddr = A::PhysAddr>> {
    task: &'a Task<A, PT>,
    _g: crate::sync::spin::MutexGuard<'a, ()>,
}

impl<A: Arch, PT: PageTable<VirtAddr = A::VirtAddr, PhysAddr = A::PhysAddr>> TaskLock<'_, A, PT> {
    /// Its address space
    pub fn mm(&self) -> Option<&crate::mm::MmRef> {
        // SAFETY: alloc_lock is held (the guard)
        unsafe { self.task.mm.get() }.as_ref()
    }

    /// Its descriptor table
    pub fn files(&self) -> Option<&Arc<fdtable::Files>> {
        // SAFETY: as above
        unsafe { self.task.files.get() }.as_ref()
    }

    /// Its filesystem context
    pub fn fs(&self) -> Option<&Arc<FsStruct>> {
        // SAFETY: as above
        unsafe { self.task.fs.get() }.as_ref()
    }

    /// Its namespaces
    pub fn nsproxy(&self) -> Option<&Arc<NsProxy>> {
        // SAFETY: as above
        unsafe { self.task.nsproxy.get() }.as_ref()
    }

    /// Its name (Linux get_task_comm)
    pub fn comm(&self) -> [u8; 16] {
        // SAFETY: as above
        unsafe { *self.task.comm.get() }
    }

    /// Its memory policy
    pub fn mempolicy(&self) -> crate::mm::mempolicy::TaskMempolicy {
        // SAFETY: as above
        unsafe { *self.task.mempolicy.get() }
    }

    /// Its I/O context
    pub fn io_context(&self) -> Option<&Arc<IoContext>> {
        // SAFETY: as above
        unsafe { self.task.io_context.get() }.as_ref()
    }

    /// Install an I/O context (anyone: ioprio_set), returning the old
    /// one for the caller to drop after unlocking
    pub fn set_io_context(&mut self, c: Option<Arc<IoContext>>) -> Option<Arc<IoContext>> {
        // SAFETY: alloc_lock is held; `io_context` is never read
        // without it
        unsafe { self.task.io_context.replace(c) }
    }

    /// Install an address space, returning the old one
    ///
    /// # Safety
    /// The caller is the task itself, or it has not run yet.
    pub unsafe fn set_mm(&mut self, mm: Option<crate::mm::MmRef>) -> Option<crate::mm::MmRef> {
        // SAFETY: alloc_lock is held, owner rule (see above)
        unsafe { self.task.mm.replace(mm) }
    }

    /// Install a descriptor table, returning the old one
    ///
    /// # Safety
    /// As [`TaskLock::set_mm`].
    pub unsafe fn set_files(
        &mut self,
        f: Option<Arc<fdtable::Files>>,
    ) -> Option<Arc<fdtable::Files>> {
        // SAFETY: as above
        unsafe { self.task.files.replace(f) }
    }

    /// Install a filesystem context, returning the old one
    ///
    /// # Safety
    /// As [`TaskLock::set_mm`].
    pub unsafe fn set_fs(&mut self, fs: Option<Arc<FsStruct>>) -> Option<Arc<FsStruct>> {
        // SAFETY: as above
        unsafe { self.task.fs.replace(fs) }
    }

    /// Install namespaces, returning the old ones
    ///
    /// # Safety
    /// As [`TaskLock::set_mm`].
    pub unsafe fn set_nsproxy(&mut self, ns: Option<Arc<NsProxy>>) -> Option<Arc<NsProxy>> {
        // SAFETY: as above
        unsafe { self.task.nsproxy.replace(ns) }
    }

    /// Rename the task (Linux __set_task_comm)
    ///
    /// # Safety
    /// As [`TaskLock::set_mm`].
    pub unsafe fn set_comm(&mut self, comm: [u8; 16]) {
        // SAFETY: as above
        unsafe { self.task.comm.replace(comm) };
    }
}

impl<A: Arch, PT: PageTable<VirtAddr = A::VirtAddr, PhysAddr = A::PhysAddr>> Task<A, PT> {
    /// A task with its locked fields (not yet in the table)
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tid: Tid,
        ids: TaskIds,
        kind: TaskKind,
        kstack_top: A::VirtAddr,
        cpu: u32,
        cred: Arc<Cred>,
        mm: Option<crate::mm::MmRef>,
        alloc: TaskAlloc,
        inner: TaskInner<A, PT>,
    ) -> Self {
        let now = crate::time::monotonic_ns();
        let flags = match kind {
            TaskKind::KernelThread => pf::KTHREAD,
            TaskKind::UserProcess => 0,
        };
        Self {
            tid: AtomicU64::new(tid),
            pid: ids.pid,
            kind,
            kstack_top,
            start_time: AtomicU64::new(now),
            flags: AtomicU32::new(flags),
            thread_flags: AtomicU32::new(0),
            cpu: AtomicU32::new(cpu),
            se: sched::SchedEntity::new(PRIORITY_NORMAL, 0),
            pi_lock: crate::arch::IrqSpinlock::new(()),
            ppid: AtomicU64::new(ids.ppid),
            pgid: AtomicU64::new(ids.pgid),
            sid: AtomicU64::new(ids.sid),
            tls: AtomicU64::new(0),
            gsbase: AtomicU64::new(0),
            seccomp_mode: AtomicU8::new(ids.seccomp_mode),
            sig: crate::sync::spin::Mutex::new(TaskSignalState::new()),
            keyrings: crate::sync::spin::Mutex::new(crate::keys::keyring::TaskKeyrings::new()),
            cgroup: crate::sync::spin::Mutex::new(None),
            fput_defer: crate::sync::spin::Mutex::new(None),
            vfork_done: AtomicPtr::new(core::ptr::null_mut()),
            cred: TaskCred::new(cred),
            alloc_lock: Mutex::new(()),
            mm: OwnCell::new(mm),
            files: OwnCell::new(None),
            fs: OwnCell::new(None),
            nsproxy: OwnCell::new(None),
            comm: OwnCell::new(alloc.comm),
            mempolicy: OwnCell::new(alloc.mempolicy),
            io_context: OwnCell::new(None),
            utime: AtomicU64::new(0),
            stime: AtomicU64::new(0),
            last_run_ns: AtomicU64::new(now),
            in_kernel: AtomicBool::new(kind == TaskKind::KernelThread),
            nvcsw: AtomicU64::new(0),
            nivcsw: AtomicU64::new(0),
            min_flt: AtomicU64::new(0),
            maj_flt: AtomicU64::new(0),
            tasks_link: crate::list::Link::new(),
            sibling: crate::list::Link::new(),
            thread_node: crate::list::Link::new(),
            inner: TableCell::new(Some(inner)),
        }
    }

    /// The boot task (Linux init_task): current on every CPU until its
    /// first switch, root, never in the task table
    pub const fn boot(kstack_top: A::VirtAddr) -> Self {
        Self {
            tid: AtomicU64::new(0),
            pid: 0,
            kind: TaskKind::KernelThread,
            kstack_top,
            start_time: AtomicU64::new(0),
            flags: AtomicU32::new(pf::KTHREAD),
            thread_flags: AtomicU32::new(0),
            cpu: AtomicU32::new(0),
            se: sched::SchedEntity::new(PRIORITY_NORMAL, 0),
            pi_lock: crate::arch::IrqSpinlock::new(()),
            ppid: AtomicU64::new(0),
            pgid: AtomicU64::new(0),
            sid: AtomicU64::new(0),
            tls: AtomicU64::new(0),
            gsbase: AtomicU64::new(0),
            seccomp_mode: AtomicU8::new(0),
            sig: crate::sync::spin::Mutex::new(TaskSignalState::boot()),
            keyrings: crate::sync::spin::Mutex::new(crate::keys::keyring::TaskKeyrings::new()),
            cgroup: crate::sync::spin::Mutex::new(None),
            fput_defer: crate::sync::spin::Mutex::new(None),
            vfork_done: AtomicPtr::new(core::ptr::null_mut()),
            cred: TaskCred::boot(),
            alloc_lock: Mutex::new(()),
            mm: OwnCell::new(None),
            files: OwnCell::new(None),
            fs: OwnCell::new(None),
            nsproxy: OwnCell::new(None),
            comm: OwnCell::new(*b"swapper\0\0\0\0\0\0\0\0\0"),
            mempolicy: OwnCell::new(crate::mm::mempolicy::TaskMempolicy::new()),
            io_context: OwnCell::new(None),
            utime: AtomicU64::new(0),
            stime: AtomicU64::new(0),
            last_run_ns: AtomicU64::new(0),
            in_kernel: AtomicBool::new(true),
            nvcsw: AtomicU64::new(0),
            nivcsw: AtomicU64::new(0),
            min_flt: AtomicU64::new(0),
            maj_flt: AtomicU64::new(0),
            tasks_link: crate::list::Link::new(),
            sibling: crate::list::Link::new(),
            thread_node: crate::list::Link::new(),
            inner: TableCell::new(None),
        }
    }

    /// Thread ID (Linux task_pid_nr)
    #[inline]
    pub fn tid(&self) -> Tid {
        self.tid.load(Ordering::Relaxed)
    }

    /// Take over thread ID `tid` (exec's exchange_tids, TASKLIST and
    /// the run-queue entry re-keyed by the caller)
    pub fn set_tid(&self, tid: Tid) {
        self.tid.store(tid, Ordering::Relaxed);
    }

    /// The locked fields (see [`TableCell`]); None for the boot task
    pub fn inner(&self) -> &TableCell<Option<TaskInner<A, PT>>> {
        &self.inner
    }

    pub fn ppid(&self) -> Pid {
        self.ppid.load(Ordering::Relaxed)
    }

    pub fn pgid(&self) -> Pid {
        self.pgid.load(Ordering::Relaxed)
    }

    pub fn sid(&self) -> Pid {
        self.sid.load(Ordering::Relaxed)
    }

    /// Seccomp mode (syscall entry)
    pub fn seccomp_mode(&self) -> u8 {
        self.seccomp_mode.load(Ordering::Relaxed)
    }

    /// The task's credentials, copied
    ///
    /// # Safety
    /// The caller is the task itself, or holds TASKLIST.
    pub unsafe fn cred(&self) -> Cred {
        // SAFETY: see above
        unsafe { self.cred.get() }
    }

    /// A reference to the task's credentials
    ///
    /// # Safety
    /// As [`Task::cred`].
    pub unsafe fn cred_arc(&self) -> Arc<Cred> {
        // SAFETY: see above
        unsafe { self.cred.arc() }
    }

    /// Take its `alloc_lock` (Linux task_lock(p))
    pub fn task_lock(&self) -> TaskLock<'_, A, PT> {
        TaskLock {
            task: self,
            _g: self.alloc_lock.lock(),
        }
    }

    /// Install new credentials, returning the old ones (dropped by the
    /// caller after TASKLIST)
    ///
    /// # Safety
    /// The caller holds TASKLIST and is the task itself, or the task
    /// has not run yet.
    pub unsafe fn set_cred(&self, new: Arc<Cred>) -> Option<Arc<Cred>> {
        // SAFETY: see above
        unsafe { self.cred.replace(new) }
    }

    /// The address space, lock-free
    ///
    /// # Safety
    /// The caller is the task itself, or it is not running (the
    /// context switch): only the task itself changes it.
    pub unsafe fn mm(&self) -> &Option<crate::mm::MmRef> {
        // SAFETY: see above
        unsafe { self.mm.get() }
    }

    /// The descriptor table, lock-free
    ///
    /// # Safety
    /// The caller is the task itself.
    pub unsafe fn files(&self) -> &Option<Arc<fdtable::Files>> {
        // SAFETY: see above
        unsafe { self.files.get() }
    }

    /// The filesystem context, lock-free
    ///
    /// # Safety
    /// As [`Task::files`].
    pub unsafe fn fs(&self) -> &Option<Arc<FsStruct>> {
        // SAFETY: see above
        unsafe { self.fs.get() }
    }

    /// The namespaces, lock-free
    ///
    /// # Safety
    /// As [`Task::files`].
    pub unsafe fn nsproxy(&self) -> &Option<Arc<NsProxy>> {
        // SAFETY: see above
        unsafe { self.nsproxy.get() }
    }

    /// The name, lock-free
    ///
    /// # Safety
    /// As [`Task::files`].
    pub unsafe fn comm(&self) -> [u8; 16] {
        // SAFETY: see above
        unsafe { *self.comm.get() }
    }

    /// Linux PF_* test
    pub fn has_flag(&self, f: u32) -> bool {
        self.flags.load(Ordering::Acquire) & f != 0
    }

    pub fn set_flag(&self, f: u32) {
        self.flags.fetch_or(f, Ordering::AcqRel);
    }

    pub fn clear_flag(&self, f: u32) {
        self.flags.fetch_and(!f, Ordering::AcqRel);
    }

    /// The task's CPU (its run queue)
    pub fn cpu(&self) -> u32 {
        self.cpu.load(Ordering::Acquire)
    }

    /// TIF_SIGPENDING (fast check before sleeping and at syscall return)
    pub fn sigpending(&self) -> bool {
        self.thread_flags.load(Ordering::Acquire) & tif::SIGPENDING != 0
    }

    pub fn set_sigpending(&self, on: bool) {
        if on {
            self.set_tif(tif::SIGPENDING);
        } else {
            self.clear_tif(tif::SIGPENDING);
        }
    }

    /// Set Linux TIF_* flags `f` (anyone: the tick, an IPI, a signal)
    pub fn set_tif(&self, f: u32) {
        self.thread_flags.fetch_or(f, Ordering::Release);
    }

    /// Any of TIF_* flags `f` is set
    pub fn has_tif(&self, f: u32) -> bool {
        self.thread_flags.load(Ordering::Acquire) & f != 0
    }

    /// Clear TIF_* flags `f`
    pub fn clear_tif(&self, f: u32) {
        self.thread_flags.fetch_and(!f, Ordering::Release);
    }

    /// Clear TIF_* flags `f`; whether any of them was set
    pub fn test_and_clear_tif(&self, f: u32) -> bool {
        self.thread_flags.fetch_and(!f, Ordering::AcqRel) & f != 0
    }

    /// Charge the time since the last boundary to user or system time
    /// and start a new interval in `kernel` mode (the task itself: the
    /// only writer, so plain loads and stores suffice)
    pub fn account(&self, now: u64, kernel: bool) {
        let delta = now.saturating_sub(self.last_run_ns.load(Ordering::Relaxed));
        let t = if self.in_kernel.load(Ordering::Relaxed) {
            &self.stime
        } else {
            &self.utime
        };
        t.store(
            t.load(Ordering::Relaxed).saturating_add(delta),
            Ordering::Relaxed,
        );
        self.last_run_ns.store(now, Ordering::Relaxed);
        self.in_kernel.store(kernel, Ordering::Relaxed);
    }

    /// Start time (monotonic ns)
    pub fn start_time(&self) -> u64 {
        self.start_time.load(Ordering::Relaxed)
    }

    /// (utime, stime) in nanoseconds
    pub fn times(&self) -> (u64, u64) {
        (
            self.utime.load(Ordering::Relaxed),
            self.stime.load(Ordering::Relaxed),
        )
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
/// Linux cap_emulate_setxuid: leaving uid 0 entirely (real, effective
/// and saved all non-zero) clears permitted and effective capabilities
/// (unless PR_SET_KEEPCAPS) and ambient ones; an effective uid change
/// away from 0 clears effective capabilities, back to 0 restores them
/// from permitted
pub fn cap_fix_setuid(old: &Cred, new: &mut Cred, keep_caps: bool) {
    let had_root = old.uid == 0 || old.euid == 0 || old.suid == 0;
    let has_root = new.uid == 0 || new.euid == 0 || new.suid == 0;
    if had_root && !has_root {
        if !keep_caps {
            new.cap_permitted = CAP_EMPTY_SET;
            new.cap_effective = CAP_EMPTY_SET;
        }
        new.cap_ambient = CAP_EMPTY_SET;
    }
    if old.euid == 0 && new.euid != 0 {
        new.cap_effective = CAP_EMPTY_SET;
    }
    if old.euid != 0 && new.euid == 0 {
        new.cap_effective = new.cap_permitted;
    }
}

/// Capabilities that fsuid 0 historically implied (Linux CAP_FS_SET)
pub const CAP_FS_SET: KernelCap = KernelCap(
    1 << CAP_CHOWN
        | 1 << CAP_MKNOD
        | 1 << CAP_DAC_OVERRIDE
        | 1 << CAP_DAC_READ_SEARCH
        | 1 << CAP_FOWNER
        | 1 << CAP_FSETID
        | 1 << CAP_MAC_OVERRIDE
        | 1 << CAP_LINUX_IMMUTABLE,
);

/// Linux cap_task_fix_setuid(LSM_SETID_FS): leaving fsuid 0 drops the
/// file system capabilities from the effective set, returning to fsuid 0
/// raises them again from the permitted set
pub fn cap_fix_setfsuid(old: &Cred, new: &mut Cred) {
    if old.fsuid == 0 && new.fsuid != 0 {
        new.cap_effective = KernelCap(new.cap_effective.0 & !CAP_FS_SET.0);
    }
    if old.fsuid != 0 && new.fsuid == 0 {
        new.cap_effective = KernelCap(new.cap_effective.0 | (new.cap_permitted.0 & CAP_FS_SET.0));
    }
}

pub fn capable(cap: u32) -> bool {
    if cap > CAP_LAST_CAP {
        return false;
    }
    percpu::current_cred().cap_effective.has(cap)
}

// =============================================================================
// Per-UID process counting (for RLIMIT_NPROC)
// =============================================================================

/// Tasks per real uid for RLIMIT_NPROC (Linux ucounts
/// UCOUNT_RLIMIT_NPROC): every task, threads included, is charged to its
/// real uid from clone until it is released (reaped, or at exit for a
/// non-leader thread); a real-uid change moves the charge
static NPROC: Mutex<BTreeMap<Uid, u64>> = Mutex::new(BTreeMap::new());

/// Charge one task to `uid`; the new count
pub fn nproc_charge(uid: Uid) -> u64 {
    let mut counts = NPROC.lock();
    let count = counts.entry(uid).or_insert(0);
    *count += 1;
    *count
}

/// Release one task's charge to `uid`
pub fn nproc_uncharge(uid: Uid) {
    let mut counts = NPROC.lock();
    if let Some(count) = counts.get_mut(&uid) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            counts.remove(&uid);
        }
    }
}

/// Tasks charged to `uid`
pub fn nproc_count(uid: Uid) -> u64 {
    NPROC.lock().get(&uid).copied().unwrap_or(0)
}

/// `count` tasks exceed the caller's RLIMIT_NPROC (Linux
/// is_rlimit_overlimit)
pub fn nproc_overlimit(count: u64) -> bool {
    let limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_NPROC);
    limit != crate::rlimit::RLIM_INFINITY && count > limit
}

/// clone's check (Linux copy_process): over the limit fails unless the
/// task's user is root or it has CAP_SYS_RESOURCE/CAP_SYS_ADMIN
pub fn nproc_over(uid: Uid, count: u64) -> bool {
    nproc_overlimit(count) && uid != 0 && !capable(CAP_SYS_RESOURCE) && !capable(CAP_SYS_ADMIN)
}

/// A pending RLIMIT_NPROC charge for a task being created: uncharged on
/// drop unless `keep` hands it to the created task
pub struct NprocCharge {
    pub uid: Uid,
    /// Tasks charged to `uid`, this one included
    pub count: u64,
    armed: bool,
}

impl NprocCharge {
    pub fn new(uid: Uid) -> Self {
        Self {
            uid,
            count: nproc_charge(uid),
            armed: true,
        }
    }

    /// The task exists: it now owns the charge
    pub fn keep(mut self) {
        self.armed = false;
    }
}

impl Drop for NprocCharge {
    fn drop(&mut self) {
        if self.armed {
            nproc_uncharge(self.uid);
        }
    }
}

/// The current task's real uid changes from `old` to `new` (Linux
/// commit_creds): move its charge
pub fn nproc_move(old: Uid, new: Uid) {
    if old != new {
        nproc_charge(new);
        nproc_uncharge(old);
    }
}

/// Linux set_user / flag_nproc_exceeded: a task whose real uid becomes
/// `new` is flagged if that user is already over RLIMIT_NPROC (root's
/// user never is); the flag is cleared otherwise
fn flag_nproc_exceeded(new: Uid) {
    let over = new != 0 && nproc_overlimit(nproc_count(new));
    let tid = percpu::current_tid();
    let table = percpu::TASKLIST.read();
    if let Some(t) = table.get(tid) {
        if over {
            t.task.set_flag(crate::task::pf::NPROC_EXCEEDED);
        } else {
            t.task.clear_flag(crate::task::pf::NPROC_EXCEEDED);
        }
    }
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
// Task I/O context accessors - Task.io_context under its alloc_lock
// =============================================================================

/// Get the I/O context for a task
pub fn get_task_io_context(tid: Tid) -> Option<Arc<IoContext>> {
    percpu::with_task_lock(tid, |a| a.io_context().cloned()).flatten()
}

/// Set the I/O context for a task (its old one dropped after the lock)
pub fn set_task_io_context(tid: Tid, ctx: Arc<IoContext>) {
    drop(percpu::with_task_lock(tid, |a| a.set_io_context(Some(ctx))));
}

/// The I/O context of a task, a new one if it has none (Linux
/// set_task_ioprio's alloc_io_context under task_lock); None if there
/// is no such task
pub fn task_io_context(tid: Tid) -> Option<Arc<IoContext>> {
    let new = Arc::new(IoContext::new());
    percpu::with_task_lock(tid, |a| match a.io_context() {
        Some(c) => c.clone(),
        None => {
            a.set_io_context(Some(new.clone()));
            new
        }
    })
}

/// Remove the I/O context for a task (on exit)
pub fn remove_task_io_context(tid: Tid) {
    drop(percpu::with_task_lock(tid, |a| a.set_io_context(None)));
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
// `Task.tls` (Linux thread.fsbase / thread.uw.tp_value): written by the
// task itself (arch_prctl, the switch-out save) or its creator, read at
// switch-in.

/// The TLS pointer of task `tid` (None if unset)
pub fn get_task_tls(tid: Tid) -> Option<u64> {
    let table = percpu::TASKLIST.read();
    table
        .get(tid)
        .map(|t| t.task.tls.load(Ordering::Relaxed))
        .filter(|&v| v != 0)
}

/// Set the TLS pointer of task `tid` (the task itself, or ptrace on a
/// stopped tracee)
pub fn set_task_tls(tid: Tid, tls: u64) {
    if let Some(t) = percpu::TASKLIST.read().get(tid) {
        t.task.tls.store(tls, Ordering::Relaxed);
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
    let table = percpu::TASKLIST.read();
    table
        .get(tid)
        .map(|t| t.clear_child_tid)
        .filter(|&v| v != 0)
}

/// Set the clear_child_tid pointer for a task
pub fn set_clear_child_tid(tid: Tid, addr: u64) {
    let mut table = percpu::TASKLIST.write();
    if let Some(mut task) = table.get_mut(tid) {
        task.clear_child_tid = addr;
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
    let mut table = percpu::TASKLIST.write();
    if let Some(mut task) = table.get_mut(tid) {
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
        let mut table = percpu::TASKLIST.write();
        if let Some(mut task) = table.get_mut(tid) {
            task.set_child_tid = addr;
        }
    }
}

// =============================================================================
// Cgroup file descriptor lookup (for CLONE_INTO_CGROUP)
// =============================================================================

/// Look up a cgroup from a file descriptor.
///
/// The fd must refer to an open directory on cgroupfs.
/// Returns the cgroup Arc if valid, None otherwise.
pub fn cgroup_from_fd(tid: Tid, fd: i32) -> Option<alloc::sync::Arc<crate::cgroup::Cgroup>> {
    use crate::fs::cgroupfs::{CgroupfsInodeData, CgroupfsInodeWrapper};

    // Get the file from fd
    let fd_table = fdtable::get_task_fd(tid)?;
    let file = fd_table.lock().get(fd)?;

    // Get the inode from the file
    let inode = file.get_inode()?;

    // Check if it's a cgroupfs directory inode
    let private = inode.get_private()?;
    let wrapper = private.as_any().downcast_ref::<CgroupfsInodeWrapper>()?;
    let data = wrapper.0.read();

    // Must be a directory (cgroup) not a control file
    if let CgroupfsInodeData::Directory { cgroup } = &*data {
        cgroup.upgrade()
    } else {
        None
    }
}
