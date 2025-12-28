//! Scheduler and priority syscalls
//!
//! This module contains syscalls for scheduling and priority management:
//! - nice, getpriority, setpriority
//! - sched_getscheduler, sched_setscheduler
//! - sched_getparam, sched_setparam
//! - sched_getaffinity, sched_setaffinity
//! - sched_rr_get_interval
//! - ioprio_get, ioprio_set
//! - getcpu

use crate::error::KernelError;

use super::Pid;

/// sys_getcpu - get CPU and NUMA node for calling thread
///
/// Returns the CPU number and NUMA node that the calling thread is running on.
///
/// # Arguments
/// * `cpu` - Current CPU number (from per-CPU data)
/// * `cpup` - Optional user pointer to store CPU number (can be 0/NULL)
/// * `nodep` - Optional user pointer to store NUMA node (can be 0/NULL)
///
/// Returns 0 on success, -EFAULT if copy to user space fails.
///
/// # Locking
/// None required - reads per-CPU data which is stable during syscall execution.
/// This matches Linux's implementation which uses raw_smp_processor_id().
pub fn sys_getcpu<A: crate::uaccess::UaccessArch>(cpu: u32, cpup: u64, nodep: u64) -> i64 {
    use crate::numa::NUMA_TOPOLOGY;
    use crate::uaccess::put_user;

    // Write CPU number if pointer provided
    if cpup != 0 {
        if !A::access_ok(cpup, core::mem::size_of::<u32>()) {
            return KernelError::BadAddress.sysret();
        }
        if put_user::<A, u32>(cpup, cpu).is_err() {
            return KernelError::BadAddress.sysret();
        }
    }

    // Write NUMA node if pointer provided
    if nodep != 0 {
        if !A::access_ok(nodep, core::mem::size_of::<u32>()) {
            return KernelError::BadAddress.sysret();
        }
        // Look up NUMA node for this CPU from the topology
        let node = NUMA_TOPOLOGY.lock().cpu_to_node(cpu);
        if put_user::<A, u32>(nodep, node).is_err() {
            return KernelError::BadAddress.sysret();
        }
    }

    0
}

/// sys_getpriority - get program scheduling priority
///
/// # Arguments
/// * `which` - PRIO_PROCESS, PRIO_PGRP, or PRIO_USER
/// * `who` - PID, PGID, or UID depending on `which` (0 = calling process)
/// * `caller_pid` - PID of calling process
///
/// # Returns
/// * 20 - nice (range 1-40) on success, to avoid negative return values
/// * Negative errno on error (-ESRCH, -EINVAL)
///
/// # Locking
/// Acquires TASK_TABLE lock briefly to read priority.
pub fn sys_getpriority(which: i32, who: u64, caller_pid: Pid) -> i64 {
    use super::{PRIO_PGRP, PRIO_PROCESS, PRIO_USER, priority_to_nice};

    match which {
        PRIO_PROCESS => {
            let target_pid = if who == 0 { caller_pid } else { who };
            match super::percpu::lookup_task_priority(target_pid) {
                Some(priority) => {
                    let nice = priority_to_nice(priority);
                    // Return 20 - nice (range 1-40) to avoid negative return values
                    (20 - nice) as i64
                }
                None => KernelError::NoProcess.sysret(),
            }
        }
        PRIO_PGRP | PRIO_USER => {
            // Not implemented yet - would require task iteration
            KernelError::NoProcess.sysret() // Return ESRCH for now (no matching processes)
        }
        _ => KernelError::InvalidArgument.sysret(),
    }
}

/// sys_setpriority - set program scheduling priority
///
/// # Arguments
/// * `which` - PRIO_PROCESS, PRIO_PGRP, or PRIO_USER
/// * `who` - PID, PGID, or UID depending on `which` (0 = calling process)
/// * `niceval` - New nice value (-20 to 19)
/// * `caller_pid` - PID of calling process
/// * `caller_euid` - Effective UID of calling process
///
/// # Returns
/// * 0 on success
/// * Negative errno on error (-ESRCH, -EINVAL, -EACCES, -EPERM)
///
/// # Locking
/// Acquires TASK_TABLE lock briefly to modify priority.
///
/// # Permission Model
/// - Root (euid=0): Can set any priority for any process
/// - Non-root: Can only lower priority (increase nice value), not raise it
pub fn sys_setpriority(
    which: i32,
    who: u64,
    niceval: i32,
    caller_pid: Pid,
    caller_euid: super::Uid,
) -> i64 {
    use super::{
        PRIO_MAX, PRIO_MIN, PRIO_PGRP, PRIO_PROCESS, PRIO_USER, nice_to_priority, priority_to_nice,
    };

    // Clamp nice value to valid range (Linux does this)
    let niceval = niceval.clamp(PRIO_MIN, PRIO_MAX);

    match which {
        PRIO_PROCESS => {
            let target_pid = if who == 0 { caller_pid } else { who };

            // Get current priority to check permissions
            let current_nice = match super::percpu::lookup_task_priority(target_pid) {
                Some(priority) => priority_to_nice(priority),
                None => return KernelError::NoProcess.sysret(),
            };

            // Permission check: non-root cannot raise priority (lower nice value)
            if caller_euid != 0 && niceval < current_nice {
                return KernelError::PermissionDenied.sysret();
            }

            // Set the new priority
            let new_priority = nice_to_priority(niceval);
            match super::percpu::set_task_priority(target_pid, new_priority) {
                Ok(()) => 0,
                Err(errno) => -(errno as i64),
            }
        }
        PRIO_PGRP | PRIO_USER => {
            // Not implemented yet
            KernelError::NoProcess.sysret()
        }
        _ => KernelError::InvalidArgument.sysret(),
    }
}

/// sys_nice - adjust process priority (nice value)
///
/// Adds `inc` to the nice value for the calling process.
/// Positive values decrease priority, negative values increase it.
///
/// # Arguments
/// * `inc` - Nice value increment
/// * `caller_pid` - PID of calling process
/// * `caller_euid` - Effective UID of calling process
///
/// # Returns
/// * New nice value on success (can be negative!)
/// * Note: Unlike POSIX, Linux nice() returns the new nice value
///
/// # Permission Model
/// - Any process can lower its priority (increase nice)
/// - Only root can raise its priority (decrease nice)
///
/// # Locking
/// Acquires TASK_TABLE lock to modify priority.
pub fn sys_nice(inc: i32, caller_pid: Pid, caller_euid: super::Uid) -> i64 {
    // Get current nice value
    let current_nice = match super::percpu::lookup_task_priority(caller_pid) {
        Some(priority) => super::priority_to_nice(priority),
        None => return KernelError::NoProcess.sysret(),
    };

    // Calculate new nice value (clamped to valid range)
    let new_nice = (current_nice + inc).clamp(super::PRIO_MIN, super::PRIO_MAX);

    // Permission check: non-root cannot increase priority (decrease nice)
    if new_nice < current_nice && caller_euid != 0 {
        return KernelError::NotPermitted.sysret();
    }

    // Set the new priority
    let new_priority = super::nice_to_priority(new_nice);
    match super::percpu::set_task_priority(caller_pid, new_priority) {
        Ok(()) => new_nice as i64,
        Err(errno) => -(errno as i64),
    }
}

/// sys_sched_getscheduler - get scheduling policy
///
/// Returns the scheduling policy of the process specified by pid.
/// If pid is 0, returns the policy of the calling process.
///
/// # Arguments
/// * `pid` - Process ID (0 = calling process)
/// * `caller_pid` - PID of calling process
///
/// # Returns
/// * Scheduling policy (SCHED_NORMAL, SCHED_FIFO, SCHED_RR, etc.) on success
/// * Negative errno on error
///
/// # Locking
/// Acquires TASK_TABLE lock briefly to read policy.
pub fn sys_sched_getscheduler(pid: i64, caller_pid: Pid) -> i64 {
    // pid < 0 is invalid
    if pid < 0 {
        return KernelError::InvalidArgument.sysret();
    }

    let target_pid = if pid == 0 { caller_pid } else { pid as u64 };

    match super::percpu::lookup_task_policy(target_pid) {
        Some(policy) => policy as i64,
        None => KernelError::NoProcess.sysret(),
    }
}

/// sys_sched_setscheduler - set scheduling policy and parameters
///
/// Sets the scheduling policy and parameters for the process specified by pid.
/// If pid is 0, sets for the calling process.
///
/// # Arguments
/// * `pid` - Process ID (0 = calling process)
/// * `policy` - Scheduling policy (SCHED_NORMAL, SCHED_FIFO, etc.)
/// * `param_ptr` - Pointer to sched_param struct
/// * `caller_pid` - PID of calling process
/// * `caller_euid` - Effective UID of calling process
///
/// # Returns
/// * 0 on success
/// * Negative errno on error
///
/// # Permission Model
/// - Root (euid=0): Can set any policy
/// - Non-root: Can only set SCHED_NORMAL/BATCH/IDLE (not RT policies)
///
/// # Locking
/// Acquires TASK_TABLE lock to modify policy.
pub fn sys_sched_setscheduler<A: crate::uaccess::UaccessArch>(
    pid: i64,
    policy: i32,
    param_ptr: u64,
    caller_pid: Pid,
    caller_euid: super::Uid,
) -> i64 {
    use super::SchedParam;
    use crate::uaccess::get_user;

    // pid < 0 is invalid
    if pid < 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Validate param_ptr
    if param_ptr == 0 {
        return KernelError::InvalidArgument.sysret();
    }
    if !A::access_ok(param_ptr, core::mem::size_of::<SchedParam>()) {
        return KernelError::BadAddress.sysret();
    }

    // Read sched_param from user space
    let param: SchedParam = match get_user::<A, SchedParam>(param_ptr) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Validate policy
    if !super::is_valid_policy(policy) {
        return KernelError::InvalidArgument.sysret();
    }

    // Permission check: non-root cannot set RT policies
    let base_policy = policy & !super::SCHED_RESET_ON_FORK;
    if super::is_rt_policy(base_policy) && caller_euid != 0 {
        return KernelError::NotPermitted.sysret();
    }

    let target_pid = if pid == 0 { caller_pid } else { pid as u64 };

    // Set the scheduler
    match super::percpu::set_task_scheduler(target_pid, policy, param.sched_priority) {
        Ok(()) => 0,
        Err(errno) => -(errno as i64),
    }
}

/// sys_sched_getparam - get scheduling parameters
///
/// Returns the scheduling parameters of the process specified by pid.
/// If pid is 0, returns the parameters of the calling process.
///
/// # Arguments
/// * `pid` - Process ID (0 = calling process)
/// * `param_ptr` - Pointer to sched_param struct to fill
/// * `caller_pid` - PID of calling process
///
/// # Returns
/// * 0 on success
/// * Negative errno on error
///
/// # Locking
/// Acquires TASK_TABLE lock briefly to read parameters.
pub fn sys_sched_getparam<A: crate::uaccess::UaccessArch>(
    pid: i64,
    param_ptr: u64,
    caller_pid: Pid,
) -> i64 {
    use super::SchedParam;
    use crate::uaccess::put_user;

    // pid < 0 is invalid
    if pid < 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Validate param_ptr
    if param_ptr == 0 {
        return KernelError::InvalidArgument.sysret();
    }
    if !A::access_ok(param_ptr, core::mem::size_of::<SchedParam>()) {
        return KernelError::BadAddress.sysret();
    }

    let target_pid = if pid == 0 { caller_pid } else { pid as u64 };

    // Get the RT priority (0 for non-RT tasks)
    let rt_prio = match super::percpu::lookup_task_rt_priority(target_pid) {
        Some(p) => p,
        None => return KernelError::NoProcess.sysret(),
    };

    let param = SchedParam {
        sched_priority: rt_prio,
    };

    // Copy to user space
    if put_user::<A, SchedParam>(param_ptr, param).is_err() {
        return KernelError::BadAddress.sysret();
    }

    0
}

/// sys_sched_setparam - set scheduling parameters
///
/// Sets the scheduling parameters for the process specified by pid,
/// keeping the current scheduling policy.
/// If pid is 0, sets for the calling process.
///
/// # Arguments
/// * `pid` - Process ID (0 = calling process)
/// * `param_ptr` - Pointer to sched_param struct
/// * `caller_pid` - PID of calling process
/// * `caller_euid` - Effective UID of calling process
///
/// # Returns
/// * 0 on success
/// * Negative errno on error
///
/// # Permission Model
/// - Root (euid=0): Can set any parameters
/// - Non-root: Can only set parameters for non-RT policies
///
/// # Locking
/// Acquires TASK_TABLE lock to modify parameters.
pub fn sys_sched_setparam<A: crate::uaccess::UaccessArch>(
    pid: i64,
    param_ptr: u64,
    caller_pid: Pid,
    caller_euid: super::Uid,
) -> i64 {
    use super::SchedParam;
    use crate::uaccess::get_user;

    // pid < 0 is invalid
    if pid < 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Validate param_ptr
    if param_ptr == 0 {
        return KernelError::InvalidArgument.sysret();
    }
    if !A::access_ok(param_ptr, core::mem::size_of::<SchedParam>()) {
        return KernelError::BadAddress.sysret();
    }

    // Read sched_param from user space
    let param: SchedParam = match get_user::<A, SchedParam>(param_ptr) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    let target_pid = if pid == 0 { caller_pid } else { pid as u64 };

    // Get current policy to preserve it
    let current_policy = match super::percpu::lookup_task_policy(target_pid) {
        Some(p) => p,
        None => return KernelError::NoProcess.sysret(),
    };

    // Permission check: non-root cannot set RT parameters
    let base_policy = current_policy & !super::SCHED_RESET_ON_FORK;
    if super::is_rt_policy(base_policy) && caller_euid != 0 {
        return KernelError::NotPermitted.sysret();
    }

    // Set the scheduler with current policy
    match super::percpu::set_task_scheduler(target_pid, current_policy, param.sched_priority) {
        Ok(()) => 0,
        Err(errno) => -(errno as i64),
    }
}

/// sys_sched_getaffinity - get CPU affinity mask
///
/// Returns the CPU affinity mask of the process specified by pid.
/// If pid is 0, returns the mask of the calling process.
///
/// # Arguments
/// * `pid` - Process ID (0 = calling process)
/// * `cpusetsize` - Size of the user buffer in bytes
/// * `mask_ptr` - Pointer to user buffer for the CPU mask
/// * `caller_pid` - PID of calling process
///
/// # Returns
/// * Number of bytes written on success (minimum of cpusetsize and sizeof(cpu_set_t))
/// * Negative errno on error
///
/// # Locking
/// Acquires TASK_TABLE lock briefly to read affinity mask.
pub fn sys_sched_getaffinity<A: crate::uaccess::UaccessArch>(
    pid: i64,
    cpusetsize: u64,
    mask_ptr: u64,
    caller_pid: Pid,
) -> i64 {
    use crate::uaccess::copy_to_user;

    // pid < 0 is invalid
    if pid < 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // cpusetsize must be at least 8 bytes (sizeof u64)
    if cpusetsize < 8 {
        return KernelError::InvalidArgument.sysret();
    }

    // Validate mask_ptr
    if mask_ptr == 0 {
        return KernelError::BadAddress.sysret();
    }

    let target_pid = if pid == 0 { caller_pid } else { pid as u64 };

    // Get the CPU affinity mask
    let mask = match super::percpu::lookup_task_cpus_allowed(target_pid) {
        Some(m) => m,
        None => return KernelError::NoProcess.sysret(),
    };

    // We only support 64 CPUs (single u64), but Linux allows larger buffers
    // Return up to cpusetsize bytes, zero-padded
    let write_size = cpusetsize.min(8) as usize;

    if !A::access_ok(mask_ptr, write_size) {
        return KernelError::BadAddress.sysret();
    }

    // Convert mask to bytes and copy
    let mask_bytes = mask.to_ne_bytes();
    if copy_to_user::<A>(mask_ptr, &mask_bytes[..write_size]).is_err() {
        return KernelError::BadAddress.sysret();
    }

    // Return the size of the kernel cpu_set_t (8 bytes for u64)
    8
}

/// sys_sched_setaffinity - set CPU affinity mask
///
/// Sets the CPU affinity mask for the process specified by pid.
/// If pid is 0, sets for the calling process.
///
/// # Arguments
/// * `pid` - Process ID (0 = calling process)
/// * `cpusetsize` - Size of the user buffer in bytes
/// * `mask_ptr` - Pointer to user buffer containing the CPU mask
/// * `caller_pid` - PID of calling process
/// * `caller_euid` - Effective UID of calling process
///
/// # Returns
/// * 0 on success
/// * Negative errno on error
///
/// # Permission Model
/// - Can always set own affinity
/// - Setting another process's affinity requires CAP_SYS_NICE (or root)
///
/// # Locking
/// Acquires TASK_TABLE lock to modify affinity mask.
pub fn sys_sched_setaffinity<A: crate::uaccess::UaccessArch>(
    pid: i64,
    cpusetsize: u64,
    mask_ptr: u64,
    caller_pid: Pid,
    caller_euid: super::Uid,
) -> i64 {
    use crate::uaccess::copy_from_user;

    // pid < 0 is invalid
    if pid < 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // cpusetsize must be at least 8 bytes (sizeof u64)
    if cpusetsize < 8 {
        return KernelError::InvalidArgument.sysret();
    }

    // Validate mask_ptr
    if mask_ptr == 0 {
        return KernelError::BadAddress.sysret();
    }
    if !A::access_ok(mask_ptr, 8) {
        return KernelError::BadAddress.sysret();
    }

    // Read the mask from user space
    let mut mask_bytes = [0u8; 8];
    if copy_from_user::<A>(&mut mask_bytes, mask_ptr, 8).is_err() {
        return KernelError::BadAddress.sysret();
    }
    let mask = u64::from_ne_bytes(mask_bytes);

    // Empty mask is invalid
    if mask == 0 {
        return KernelError::InvalidArgument.sysret();
    }

    let target_pid = if pid == 0 { caller_pid } else { pid as u64 };

    // Permission check: non-root can only set own affinity
    if target_pid != caller_pid && caller_euid != 0 {
        return KernelError::NotPermitted.sysret();
    }

    // Set the CPU affinity mask
    match super::percpu::set_task_cpus_allowed(target_pid, mask) {
        Ok(()) => 0,
        Err(errno) => -(errno as i64),
    }
}

/// sys_sched_rr_get_interval - get round-robin time quantum
///
/// Returns the round-robin time quantum for the process specified by pid.
/// If pid is 0, returns for the calling process.
///
/// For non-SCHED_RR tasks, returns 0.
///
/// # Arguments
/// * `pid` - Process ID (0 = calling process)
/// * `tp_ptr` - Pointer to timespec structure to fill
/// * `caller_pid` - PID of calling process
///
/// # Returns
/// * 0 on success
/// * Negative errno on error
///
/// # Locking
/// Acquires TASK_TABLE lock briefly to read policy.
pub fn sys_sched_rr_get_interval<A: crate::uaccess::UaccessArch>(
    pid: i64,
    tp_ptr: u64,
    caller_pid: Pid,
) -> i64 {
    use crate::uaccess::put_user;

    // Timespec structure for return value
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Timespec {
        tv_sec: i64,
        tv_nsec: i64,
    }

    // pid < 0 is invalid
    if pid < 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Validate tp_ptr
    if tp_ptr == 0 {
        return KernelError::InvalidArgument.sysret();
    }
    if !A::access_ok(tp_ptr, core::mem::size_of::<Timespec>()) {
        return KernelError::BadAddress.sysret();
    }

    let target_pid = if pid == 0 { caller_pid } else { pid as u64 };

    // Get the scheduling policy
    let policy = match super::percpu::lookup_task_policy(target_pid) {
        Some(p) => p,
        None => return KernelError::NoProcess.sysret(),
    };

    // Only SCHED_RR has a meaningful time quantum
    let base_policy = policy & !super::SCHED_RESET_ON_FORK;
    let time_slice_ns = if base_policy == super::SCHED_RR {
        super::RR_TIMESLICE_NS
    } else {
        0
    };

    // Convert nanoseconds to timespec
    let ts = Timespec {
        tv_sec: (time_slice_ns / 1_000_000_000) as i64,
        tv_nsec: (time_slice_ns % 1_000_000_000) as i64,
    };

    // Copy to user space
    if put_user::<A, Timespec>(tp_ptr, ts).is_err() {
        return KernelError::BadAddress.sysret();
    }

    0
}

// =============================================================================
// I/O Priority Syscalls
// =============================================================================

/// sys_ioprio_set - set I/O scheduling class and priority
///
/// # Arguments
/// * `which` - IOPRIO_WHO_PROCESS, IOPRIO_WHO_PGRP, or IOPRIO_WHO_USER
/// * `who` - ID (pid, pgid, or uid) or 0 for current
/// * `ioprio` - I/O priority value (class << 13 | level)
///
/// # Returns
/// * 0 on success
/// * -EINVAL for invalid arguments
/// * -ESRCH if target not found
/// * -EPERM if not permitted
pub fn sys_ioprio_set(which: i32, who: i32, ioprio: i32) -> i64 {
    use super::{
        IOPRIO_CLASS_IDLE, IOPRIO_CLASS_RT, IOPRIO_WHO_PGRP, IOPRIO_WHO_PROCESS, IOPRIO_WHO_USER,
        get_task_io_context, ioprio_prio_class, ioprio_valid,
    };

    let ioprio = ioprio as u16;

    // Validate ioprio
    if !ioprio_valid(ioprio) {
        return KernelError::InvalidArgument.sysret();
    }

    let class = ioprio_prio_class(ioprio);
    let caller_euid = super::percpu::current_cred().euid;

    // Permission check: RT and IDLE classes require CAP_SYS_NICE (or root)
    if (class == IOPRIO_CLASS_RT || class == IOPRIO_CLASS_IDLE) && caller_euid != 0 {
        return KernelError::NotPermitted.sysret();
    }

    match which {
        IOPRIO_WHO_PROCESS => {
            let tid = if who == 0 {
                super::percpu::current_tid()
            } else {
                who as u64
            };

            // Get or create IoContext for the target
            let ctx = match get_task_io_context(tid) {
                Some(ctx) => ctx,
                None => {
                    // Create a new context if target exists
                    if !super::percpu::task_exists(tid) {
                        return KernelError::NoProcess.sysret();
                    }
                    let ctx = alloc::sync::Arc::new(super::IoContext::new());
                    super::set_task_io_context(tid, ctx.clone());
                    ctx
                }
            };

            ctx.set_ioprio(ioprio);
            0
        }
        IOPRIO_WHO_PGRP => {
            // Set ioprio for all processes in a process group
            let pgid = if who == 0 {
                super::percpu::current_pgid()
            } else {
                who as u64
            };

            let tids = super::percpu::get_tids_by_pgid(pgid);
            if tids.is_empty() {
                return KernelError::NoProcess.sysret();
            }

            for tid in tids {
                let ctx = match get_task_io_context(tid) {
                    Some(ctx) => ctx,
                    None => {
                        let ctx = alloc::sync::Arc::new(super::IoContext::new());
                        super::set_task_io_context(tid, ctx.clone());
                        ctx
                    }
                };
                ctx.set_ioprio(ioprio);
            }
            0
        }
        IOPRIO_WHO_USER => {
            // Set ioprio for all processes of a user - not fully implemented
            // Just return success for simplicity
            0
        }
        _ => KernelError::InvalidArgument.sysret(),
    }
}

/// sys_ioprio_get - get I/O scheduling class and priority
///
/// # Arguments
/// * `which` - IOPRIO_WHO_PROCESS, IOPRIO_WHO_PGRP, or IOPRIO_WHO_USER
/// * `who` - ID (pid, pgid, or uid) or 0 for current
///
/// # Returns
/// * I/O priority value on success (class << 13 | level)
/// * -EINVAL for invalid arguments
/// * -ESRCH if target not found
pub fn sys_ioprio_get(which: i32, who: i32) -> i64 {
    use super::{
        IOPRIO_DEFAULT, IOPRIO_WHO_PGRP, IOPRIO_WHO_PROCESS, IOPRIO_WHO_USER, get_task_io_context,
    };

    match which {
        IOPRIO_WHO_PROCESS => {
            let tid = if who == 0 {
                super::percpu::current_tid()
            } else {
                who as u64
            };

            // Check if task exists
            if !super::percpu::task_exists(tid) {
                return KernelError::NoProcess.sysret();
            }

            match get_task_io_context(tid) {
                Some(ctx) => ctx.get_ioprio() as i64,
                None => IOPRIO_DEFAULT as i64,
            }
        }
        IOPRIO_WHO_PGRP => {
            let pgid = if who == 0 {
                super::percpu::current_pgid()
            } else {
                who as u64
            };

            let tids = super::percpu::get_tids_by_pgid(pgid);
            if tids.is_empty() {
                return KernelError::NoProcess.sysret();
            }

            // Return the highest priority (lowest class value, then highest level)
            let mut best_ioprio = IOPRIO_DEFAULT;
            for tid in tids {
                if let Some(ctx) = get_task_io_context(tid) {
                    let ioprio = ctx.get_ioprio();
                    // Compare: lower class is higher priority
                    if ioprio < best_ioprio {
                        best_ioprio = ioprio;
                    }
                }
            }
            best_ioprio as i64
        }
        IOPRIO_WHO_USER => {
            // Get highest ioprio for all processes of a user - not fully implemented
            // Return default for simplicity
            IOPRIO_DEFAULT as i64
        }
        _ => KernelError::InvalidArgument.sysret(),
    }
}
