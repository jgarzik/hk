//! Resource limits (rlimit) implementation
//!
//! This module implements Linux-compatible resource limits (rlimits).
//!
//! The RLIMIT_* constants are part of the Linux ABI and are exported for use
//! by other kernel modules (e.g., RLIMIT_MEMLOCK enforcement in mm/syscall.rs).
//!
//! Linux stores rlimits in `signal_struct`, which is per-process and shared by
//! all threads in a thread group. We mirror this architecture by storing rlimits
//! in `SignalStruct` (see kernel/signal/mod.rs), which is:
//! - Per-process (one per thread group)
//! - Shared via `Arc` when CLONE_THREAD is used
//! - Deep-cloned on fork (without CLONE_THREAD)
//!
//! This matches Linux's semantics exactly:
//! - Threads share rlimits because they share signal_struct
//! - Fork creates independent rlimit copies
//! - prlimit64 can modify another process's rlimits

#![allow(dead_code)]

use crate::signal::get_task_signal_struct;
use crate::task::percpu::{current_tid, current_cred};
use crate::task::Tid;

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
/// Maximum core file size (bytes)
pub const RLIMIT_CORE: u32 = 4;
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
/// Maximum file locks held
pub const RLIMIT_LOCKS: u32 = 10;
/// Maximum number of pending signals
pub const RLIMIT_SIGPENDING: u32 = 11;
/// Maximum bytes in POSIX message queues
pub const RLIMIT_MSGQUEUE: u32 = 12;
/// Maximum nice priority allowed
pub const RLIMIT_NICE: u32 = 13;
/// Maximum realtime priority allowed
pub const RLIMIT_RTPRIO: u32 = 14;
/// Maximum realtime CPU time (microseconds)
pub const RLIMIT_RTTIME: u32 = 15;

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

/// Create default resource limits (matching Linux defaults)
///
/// These defaults are used when creating a new process.
pub fn default_rlimits() -> [RLimit; RLIM_NLIMITS] {
    [
        RLimit::INFINITY,                                       // RLIMIT_CPU
        RLimit::INFINITY,                                       // RLIMIT_FSIZE
        RLimit::INFINITY,                                       // RLIMIT_DATA
        RLimit::new(8 * 1024 * 1024, RLIM_INFINITY),            // RLIMIT_STACK (8MB soft)
        RLimit::new(0, RLIM_INFINITY),                          // RLIMIT_CORE (0 = no core)
        RLimit::INFINITY,                                       // RLIMIT_RSS
        RLimit::INFINITY,                                       // RLIMIT_NPROC
        RLimit::new(1024, 1024 * 1024),                         // RLIMIT_NOFILE (1024 soft, 1M hard)
        RLimit::new(8 * 1024 * 1024, 8 * 1024 * 1024),          // RLIMIT_MEMLOCK (8MB)
        RLimit::INFINITY,                                       // RLIMIT_AS
        RLimit::INFINITY,                                       // RLIMIT_LOCKS
        RLimit::new(0, 0),                                      // RLIMIT_SIGPENDING
        RLimit::new(819200, 819200),                            // RLIMIT_MSGQUEUE
        RLimit::new(0, 0),                                      // RLIMIT_NICE
        RLimit::new(0, 0),                                      // RLIMIT_RTPRIO
        RLimit::INFINITY,                                       // RLIMIT_RTTIME
    ]
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

/// Set a task's resource limit (with permission checks)
///
/// Validates:
/// - Resource number is valid
/// - rlim_cur <= rlim_max
/// - Only CAP_SYS_RESOURCE (or root) can raise hard limit
///
/// Returns Ok(()) on success, or Err(errno) on failure.
pub fn set_task_rlimit(
    tid: Tid,
    resource: u32,
    new: RLimit,
    has_cap_sys_resource: bool,
) -> Result<(), i32> {
    let signal = get_task_signal_struct(tid).ok_or(-3)?; // ESRCH
    let old = signal.get_rlimit(resource).ok_or(-22)?; // EINVAL
    signal.set_rlimit(resource, new, &old, has_cap_sys_resource)
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

/// Convenience function: get hard limit for current task
///
/// Returns RLIM_INFINITY if the task or resource doesn't exist.
#[allow(dead_code)]
pub fn rlimit_max(resource: u32) -> u64 {
    let tid = current_tid();
    get_task_rlimit(tid, resource)
        .map(|r| r.rlim_max)
        .unwrap_or(RLIM_INFINITY)
}

// =============================================================================
// Syscall Implementations
// =============================================================================

/// Find task TID by process PID
///
/// Searches the task table for a task with the given PID.
fn find_task_by_pid(pid: u64) -> Option<Tid> {
    let table = crate::task::percpu::TASK_TABLE.lock();
    table.tasks.iter().find(|t| t.pid == pid).map(|t| t.tid)
}


/// sys_getrlimit - get resource limits
///
/// Syscall number: 97 (x86_64), 163 (aarch64)
///
/// Arguments:
/// - resource: Which resource limit to get (RLIMIT_*)
/// - rlim_ptr: Pointer to user-space rlimit structure to fill
///
/// Returns: 0 on success, negative errno on error
pub fn sys_getrlimit(resource: u32, rlim_ptr: u64) -> i64 {
    if resource as usize >= RLIM_NLIMITS {
        return -22; // EINVAL
    }

    if rlim_ptr == 0 {
        return -14; // EFAULT
    }

    let tid = current_tid();
    let rlim = match get_task_rlimit(tid, resource) {
        Some(r) => r,
        None => return -3, // ESRCH (shouldn't happen for current task)
    };

    // Copy to user (16 bytes: cur + max)
    unsafe {
        let ptr = rlim_ptr as *mut RLimit;
        core::ptr::write_volatile(ptr, rlim);
    }
    0
}

/// sys_setrlimit - set resource limits
///
/// Syscall number: 160 (x86_64), 164 (aarch64)
///
/// Arguments:
/// - resource: Which resource limit to set (RLIMIT_*)
/// - rlim_ptr: Pointer to user-space rlimit structure with new limits
///
/// Returns: 0 on success, negative errno on error
pub fn sys_setrlimit(resource: u32, rlim_ptr: u64) -> i64 {
    if resource as usize >= RLIM_NLIMITS {
        return -22; // EINVAL
    }

    if rlim_ptr == 0 {
        return -14; // EFAULT
    }

    // Copy from user
    let new_rlim = unsafe {
        let ptr = rlim_ptr as *const RLimit;
        core::ptr::read_volatile(ptr)
    };

    // Validate: cur <= max
    if new_rlim.rlim_cur > new_rlim.rlim_max {
        return -22; // EINVAL
    }

    let tid = current_tid();
    let has_cap = current_cred().euid == 0; // Root has CAP_SYS_RESOURCE

    match set_task_rlimit(tid, resource, new_rlim, has_cap) {
        Ok(()) => 0,
        Err(e) => e as i64,
    }
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
///
/// Returns: 0 on success, negative errno on error
pub fn sys_prlimit64(pid: i32, resource: u32, new_rlim_ptr: u64, old_rlim_ptr: u64) -> i64 {
    if resource as usize >= RLIM_NLIMITS {
        return -22; // EINVAL
    }

    // Determine target task
    let target_tid = if pid == 0 {
        current_tid()
    } else {
        match find_task_by_pid(pid as u64) {
            Some(tid) => tid,
            None => return -3, // ESRCH
        }
    };

    // Get old value if requested
    if old_rlim_ptr != 0 {
        let old = match get_task_rlimit(target_tid, resource) {
            Some(r) => r,
            None => return -3, // ESRCH
        };
        unsafe {
            let ptr = old_rlim_ptr as *mut RLimit;
            core::ptr::write_volatile(ptr, old);
        }
    }

    // Set new value if provided
    if new_rlim_ptr != 0 {
        let new = unsafe {
            let ptr = new_rlim_ptr as *const RLimit;
            core::ptr::read_volatile(ptr)
        };

        if new.rlim_cur > new.rlim_max {
            return -22; // EINVAL
        }

        let has_cap = current_cred().euid == 0;
        if let Err(e) = set_task_rlimit(target_tid, resource, new, has_cap) {
            return e as i64;
        }
    }

    0
}
