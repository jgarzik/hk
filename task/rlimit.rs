//! Resource limits (rlimit) implementation
//!
//! This module implements Linux-compatible resource limits (rlimits).
//!
//! The RLIMIT_* constants are part of the Linux ABI and are exported for use
//! by other kernel modules (e.g., RLIMIT_MEMLOCK enforcement in mm/syscall.rs).
//!
//! Linux stores rlimits in `signal_struct`, which is per-process and shared by
//! all threads in a thread group. We mirror this architecture by storing rlimits
//! in `SignalStruct` (see signal/mod.rs), which is:
//! - Per-process (one per thread group)
//! - Shared via `Arc` when CLONE_THREAD is used
//! - Deep-cloned on fork (without CLONE_THREAD)
//!
//! This matches Linux's semantics exactly:
//! - Threads share rlimits because they share signal_struct
//! - Fork creates independent rlimit copies
//! - prlimit64 can modify another process's rlimits

use crate::signal::get_task_signal_struct;
use crate::task::Tid;
use crate::task::percpu::{current_cred, current_tid};
use crate::uaccess::UserPtr;
use crate::util::error::{KernelError, KernelResult};

// =============================================================================
// Resource Limit Constants (Linux ABI)
// =============================================================================

/// CPU time limit (seconds)
pub const RLIMIT_CPU: u32 = 0;
/// Maximum file size (bytes)
pub const RLIMIT_FSIZE: u32 = 1;
/// Maximum data segment size (bytes)
pub const RLIMIT_DATA: u32 = 2;
/// Maximum stack size (bytes)
pub const RLIMIT_STACK: u32 = 3;
/// Maximum resident set size (bytes, unused on modern Linux)
pub const RLIMIT_RSS: u32 = 5;
/// Maximum number of processes per user
pub const RLIMIT_NPROC: u32 = 6;
/// Maximum number of open files
pub const RLIMIT_NOFILE: u32 = 7;
/// Maximum locked-in-memory address space (bytes)
pub const RLIMIT_MEMLOCK: u32 = 8;
/// Maximum address space size (bytes)
pub const RLIMIT_AS: u32 = 9;
/// Maximum number of pending signals
pub const RLIMIT_SIGPENDING: u32 = 11;
/// Maximum bytes in POSIX message queues
pub const RLIMIT_MSGQUEUE: u32 = 12;
/// Maximum nice priority allowed
pub const RLIMIT_NICE: u32 = 13;
/// Maximum realtime priority allowed
pub const RLIMIT_RTPRIO: u32 = 14;

/// Number of resource limits
pub const RLIM_NLIMITS: usize = 16;

/// Unlimited resource value
pub const RLIM_INFINITY: u64 = !0u64;

// =============================================================================
// RLimit Structure
// =============================================================================

/// Single resource limit (matches Linux struct rlimit64)
///
/// Contains both soft limit (rlim_cur) and hard limit (rlim_max).
/// The soft limit can be freely adjusted by the process up to the hard limit.
/// Only privileged processes (CAP_SYS_RESOURCE) can raise the hard limit.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct RLimit {
    /// Soft limit (current enforced limit)
    pub rlim_cur: u64,
    /// Hard limit (maximum allowed)
    pub rlim_max: u64,
}
crate::pod!(RLimit { rlim_cur, rlim_max });

impl RLimit {
    /// Unlimited resource limit
    pub const INFINITY: Self = Self {
        rlim_cur: RLIM_INFINITY,
        rlim_max: RLIM_INFINITY,
    };

    /// Create a new limit with the same soft and hard values
    pub const fn new(cur: u64, max: u64) -> Self {
        Self {
            rlim_cur: cur,
            rlim_max: max,
        }
    }
}

impl Default for RLimit {
    fn default() -> Self {
        Self::INFINITY
    }
}

// =============================================================================
// Default Limits
// =============================================================================

/// Linux INIT_RLIMITS, before fork_init sizes RLIMIT_NPROC and
/// RLIMIT_SIGPENDING (`init_rlimits`)
fn default_rlimits() -> [RLimit; RLIM_NLIMITS] {
    [
        RLimit::INFINITY,                              // RLIMIT_CPU
        RLimit::INFINITY,                              // RLIMIT_FSIZE
        RLimit::INFINITY,                              // RLIMIT_DATA
        RLimit::new(8 * 1024 * 1024, RLIM_INFINITY),   // RLIMIT_STACK (8MB soft)
        RLimit::new(0, RLIM_INFINITY),                 // RLIMIT_CORE (0 = no core)
        RLimit::INFINITY,                              // RLIMIT_RSS
        RLimit::INFINITY,                              // RLIMIT_NPROC (init_rlimits)
        RLimit::new(1024, 4096),                       // RLIMIT_NOFILE (INR_OPEN_CUR, INR_OPEN_MAX)
        RLimit::new(8 * 1024 * 1024, 8 * 1024 * 1024), // RLIMIT_MEMLOCK (8MB)
        RLimit::INFINITY,                              // RLIMIT_AS
        RLimit::INFINITY,                              // RLIMIT_LOCKS
        RLimit::new(0, 0),                             // RLIMIT_SIGPENDING (init_rlimits)
        RLimit::new(819200, 819200),                   // RLIMIT_MSGQUEUE
        RLimit::new(0, 0),                             // RLIMIT_NICE
        RLimit::new(0, 0),                             // RLIMIT_RTPRIO
        RLimit::INFINITY,                              // RLIMIT_RTTIME
    ]
}

/// Linux set_max_threads (fork_init): as many threads as kernel stacks
/// fit in an eighth of free memory, clamped to [MIN_THREADS,
/// MAX_THREADS (FUTEX_TID_MASK)], computed once, at the global init's
/// signal setup at boot
pub fn max_threads() -> u64 {
    const MIN_THREADS: u64 = 20;
    const MAX_THREADS: u64 = 0x3fff_ffff;
    static N: spin::Once<u64> = spin::Once::new();
    *N.call_once(|| {
        let free = crate::FRAME_ALLOCATOR.stats().free_bytes;
        let stack = crate::mm::vmstack::THREAD_SIZE as u64;
        (free / (stack * 8)).clamp(MIN_THREADS, MAX_THREADS)
    })
}

/// The global init's limits, which every task inherits (Linux
/// INIT_RLIMITS, with RLIMIT_NPROC and RLIMIT_SIGPENDING set to half of
/// max_threads by fork_init)
pub fn init_rlimits() -> [RLimit; RLIM_NLIMITS] {
    let mut r = default_rlimits();
    let half = max_threads() / 2;
    for l in [RLIMIT_NPROC, RLIMIT_SIGPENDING] {
        r[l as usize] = RLimit::new(half, half);
    }
    r
}

// =============================================================================
// Task Accessor Functions
// =============================================================================

/// Get a task's resource limit
///
/// Returns the RLimit for the specified resource, or None if the task
/// or resource doesn't exist.
pub fn get_task_rlimit(tid: Tid, resource: u32) -> Option<RLimit> {
    let signal = get_task_signal_struct(tid)?;
    signal.get_rlimit(resource)
}

/// Set a task's resource limit (`SignalStruct::set_rlimit`: EINVAL,
/// EPERM for an unprivileged raise of the hard limit); the limit it
/// replaced, read in the same hold as the store
pub fn set_task_rlimit(tid: Tid, resource: u32, new: RLimit) -> KernelResult<RLimit> {
    let signal = get_task_signal_struct(tid).ok_or(KernelError::NoProcess)?;
    let old = signal.set_rlimit(resource, new)?;
    // A finite CPU limit is watched from now (Linux update_rlimit_cpu)
    if resource == RLIMIT_CPU {
        let pid = crate::task::percpu::TASKLIST
            .read()
            .get(tid)
            .map(|t| t.task.pid);
        if let Some(pid) = pid {
            crate::time::cpu_timer::rlimit_cpu_changed(&signal, pid);
        }
    }
    Ok(old)
}

/// Convenience function: get soft limit for current task
///
/// Returns RLIM_INFINITY if the task or resource doesn't exist.
pub fn rlimit(resource: u32) -> u64 {
    let tid = current_tid();
    get_task_rlimit(tid, resource)
        .map(|r| r.rlim_cur)
        .unwrap_or(RLIM_INFINITY)
}

// =============================================================================
// Syscall Implementations
// =============================================================================

/// sys_getrlimit - get resource limits
///
/// Syscall number: 97 (x86_64), 163 (aarch64)
///
/// Arguments:
/// - resource: Which resource limit to get (RLIMIT_*)
/// - rlim_ptr: Pointer to user-space rlimit structure to fill
pub fn sys_getrlimit(resource: u32, rlim_ptr: UserPtr<RLimit>) -> KernelResult<()> {
    if resource as usize >= RLIM_NLIMITS {
        return Err(KernelError::InvalidArgument);
    }
    if rlim_ptr.is_null() {
        return Err(KernelError::BadAddress);
    }
    // (None shouldn't happen for the current task)
    let rlim = get_task_rlimit(current_tid(), resource).ok_or(KernelError::NoProcess)?;
    Ok(rlim_ptr.write(&rlim)?)
}

/// sys_setrlimit - set resource limits
///
/// Syscall number: 160 (x86_64), 164 (aarch64)
///
/// Arguments:
/// - resource: Which resource limit to set (RLIMIT_*)
/// - rlim_ptr: Pointer to user-space rlimit structure with new limits
pub fn sys_setrlimit(resource: u32, rlim_ptr: UserPtr<RLimit>) -> KernelResult<()> {
    // Linux sys_setrlimit: copied in first (EFAULT), then do_prlimit
    let new_rlim = rlim_ptr.read()?;
    if resource as usize >= RLIM_NLIMITS {
        return Err(KernelError::InvalidArgument);
    }
    check(resource, &new_rlim)?;
    set_task_rlimit(current_tid(), resource, new_rlim)?;
    Ok(())
}

/// Checks on a new limit before any permission check (Linux
/// do_prlimit): cur above max is EINVAL; a RLIMIT_NOFILE hard limit
/// above fs.nr_open is EPERM, even for CAP_SYS_RESOURCE
fn check(resource: u32, new: &RLimit) -> KernelResult<()> {
    if new.rlim_cur > new.rlim_max {
        return Err(KernelError::InvalidArgument);
    }
    if resource == RLIMIT_NOFILE && new.rlim_max > crate::task::fdbits::nr_open() {
        return Err(KernelError::NotPermitted);
    }
    Ok(())
}

/// sys_prlimit64 - get/set resource limits (can target other processes)
///
/// Syscall number: 302 (x86_64), 261 (aarch64)
///
/// This is the modern, preferred interface for rlimits. It combines
/// getrlimit and setrlimit into one call and can operate on other processes.
///
/// Arguments:
/// - pid: Target process ID (0 = current process)
/// - resource: Which resource limit (RLIMIT_*)
/// - new_rlim_ptr: Pointer to new limits (NULL to only get)
/// - old_rlim_ptr: Pointer to store old limits (NULL to only set)
pub fn sys_prlimit64(
    pid: i32,
    resource: u32,
    new_rlim_ptr: UserPtr<RLimit>,
    old_rlim_ptr: UserPtr<RLimit>,
) -> KernelResult<()> {
    // Linux order: the new limit is copied in (EFAULT), the task found
    // (ESRCH) and the caller's right to it checked (EPERM), then
    // do_prlimit (EINVAL), and the old limit copied out last
    let new = if new_rlim_ptr.is_null() {
        None
    } else {
        Some(new_rlim_ptr.read()?)
    };
    let target_tid = if pid == 0 {
        current_tid()
    } else {
        crate::task::percpu::find_task_by_vpid(pid as u64)
            .map(|t| t.tid())
            .ok_or(KernelError::NoProcess)?
    };
    check_prlimit_permission(target_tid)?;
    if resource as usize >= RLIM_NLIMITS {
        return Err(KernelError::InvalidArgument);
    }
    if let Some(new) = &new {
        check(resource, new)?;
    }
    // The old value is the one replaced (Linux do_prlimit reads it
    // under the same task_lock as the store)
    let old = match new {
        Some(new) => set_task_rlimit(target_tid, resource, new)?,
        None => get_task_rlimit(target_tid, resource).ok_or(KernelError::NoProcess)?,
    };
    if !old_rlim_ptr.is_null() {
        old_rlim_ptr.write(&old)?;
    }
    Ok(())
}

/// Linux check_prlimit_permission: the caller itself, a task whose real,
/// effective and saved ids all equal the caller's real ones, or
/// CAP_SYS_RESOURCE; else EPERM
fn check_prlimit_permission(target: crate::task::Tid) -> KernelResult<()> {
    if target == current_tid() {
        return Ok(());
    }
    let me = current_cred();
    let t = crate::task::percpu::TASKLIST
        .read()
        .get(target)
        .map(|t| t.cred())
        .ok_or(KernelError::NoProcess)?;
    let id_match = [t.uid, t.euid, t.suid].iter().all(|&u| u == me.uid)
        && [t.gid, t.egid, t.sgid].iter().all(|&g| g == me.gid);
    if !id_match && !crate::task::capable(crate::task::CAP_SYS_RESOURCE) {
        return Err(KernelError::NotPermitted);
    }
    Ok(())
}
