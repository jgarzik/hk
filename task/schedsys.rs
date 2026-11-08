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

use super::percpu::current_tid;
use crate::util::error::KernelError;

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
    use crate::mm::numa::NUMA_TOPOLOGY;
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
///
/// # Returns
/// * 20 - nice (range 1-40) on success, to avoid negative return values
/// * Negative errno on error (-ESRCH, -EINVAL)
///
/// # Locking
/// Acquires TASKLIST lock briefly to read priority.
pub fn sys_getpriority(which: i32, who: i32) -> i64 {
    use super::{PRIO_PGRP, PRIO_PROCESS, PRIO_USER};

    // `who` is an int (id_t of a pid or pgid): a negative one names none
    if which != PRIO_USER && who < 0 {
        return KernelError::NoProcess.sysret();
    }
    let who = u64::from(who as u32);
    match which {
        PRIO_PROCESS => {
            // 0 is the calling thread (Linux: current)
            let Some(target_pid) = super::pid::from_vnr_or(who, current_tid()) else {
                return KernelError::NoProcess.sysret();
            };
            match super::percpu::lookup_task_nice(target_pid) {
                // 20 - nice (range 1-40) to avoid negative return values
                Some(nice) => i64::from(20 - nice),
                None => KernelError::NoProcess.sysret(),
            }
        }
        PRIO_PGRP => {
            // The highest priority of any thread in the group (Linux:
            // the largest 20 - nice)
            let Some(pgid) = super::pid::from_vnr_or(who, super::percpu::current_pgid()) else {
                return KernelError::NoProcess.sysret();
            };
            super::percpu::get_tids_by_pgid(pgid)
                .into_iter()
                .filter_map(super::percpu::lookup_task_nice)
                .map(|n| i64::from(20 - n))
                .max()
                .unwrap_or(KernelError::NoProcess.sysret())
        }
        PRIO_USER => tids_of_user(who)
            .into_iter()
            .filter_map(super::percpu::lookup_task_nice)
            .map(|n| i64::from(20 - n))
            .max()
            .unwrap_or(KernelError::NoProcess.sysret()),
        _ => KernelError::InvalidArgument.sysret(),
    }
}

/// The threads whose real uid is `who` (0: the caller's), for PRIO_USER
/// (Linux for_each_process_thread with uid_eq(task_uid(p), uid))
fn tids_of_user(who: u64) -> alloc::vec::Vec<Pid> {
    let uid = if who == 0 {
        super::percpu::current_cred().uid
    } else {
        who as super::Uid
    };
    super::percpu::TASKLIST
        .read()
        .iter()
        .filter(|t| !t.task.has_flag(super::pf::KTHREAD) && t.cred().uid == uid)
        .map(|t| t.task.tid())
        .collect()
}

/// Set task `tid`'s nice value (Linux set_one_prio): EPERM unless the
/// caller's euid is its uid or euid or the caller has CAP_SYS_NICE;
/// EACCES for a lower nice beyond RLIMIT_NICE without CAP_SYS_NICE.
/// `error` is the result so far: a success turns ESRCH into 0.
fn set_one_prio(tid: Pid, niceval: i32, caller_euid: super::Uid, error: i64) -> i64 {
    use super::{CAP_SYS_NICE, capable};
    let Some(cur_nice) = super::percpu::lookup_task_nice(tid) else {
        return error;
    };
    let target = super::percpu::TASKLIST.read().get(tid).map(|t| t.cred());
    let Some(c) = target else {
        return error;
    };
    if c.uid != caller_euid && c.euid != caller_euid && !capable(CAP_SYS_NICE) {
        return KernelError::NotPermitted.sysret();
    }
    // Linux can_nice: 20 - nice within the target's RLIMIT_NICE
    let rlim = crate::task::rlimit::get_task_rlimit(tid, crate::task::rlimit::RLIMIT_NICE)
        .map_or(crate::task::rlimit::RLIM_INFINITY, |r| r.rlim_cur);
    let lower = niceval < cur_nice;
    if lower && (20 - niceval) as u64 > rlim && !capable(CAP_SYS_NICE) {
        return KernelError::PermissionDenied.sysret();
    }
    match super::percpu::set_task_nice(tid, niceval) {
        Ok(()) if error == KernelError::NoProcess.sysret() => 0,
        Ok(()) => error,
        Err(errno) => -i64::from(errno),
    }
}

/// sys_setpriority - set program scheduling priority
///
/// # Arguments
/// * `which` - PRIO_PROCESS, PRIO_PGRP, or PRIO_USER
/// * `who` - PID, PGID, or UID depending on `which` (0 = calling process)
/// * `niceval` - New nice value (-20 to 19)
///
/// # Returns
/// * 0 on success
/// * Negative errno on error (-ESRCH, -EINVAL, -EACCES, -EPERM)
///
/// # Locking
/// Acquires TASKLIST lock briefly to modify priority.
///
/// # Permission Model
/// - Root (euid=0): Can set any priority for any process
/// - Non-root: Can only lower priority (increase nice value), not raise it
pub fn sys_setpriority(which: i32, who: i32, niceval: i32) -> i64 {
    use super::{PRIO_MAX, PRIO_MIN, PRIO_PGRP, PRIO_PROCESS, PRIO_USER};

    // Clamp nice value to valid range (Linux does this)
    let niceval = niceval.clamp(PRIO_MIN, PRIO_MAX);
    if which != PRIO_USER && who < 0 {
        return KernelError::NoProcess.sysret();
    }
    let who = u64::from(who as u32);
    let caller_euid = super::percpu::current_cred().euid;

    match which {
        PRIO_PROCESS => {
            let Some(target_pid) = super::pid::from_vnr_or(who, current_tid()) else {
                return KernelError::NoProcess.sysret();
            };
            set_one_prio(
                target_pid,
                niceval,
                caller_euid,
                KernelError::NoProcess.sysret(),
            )
        }
        PRIO_PGRP => {
            // Every thread of the group (Linux set_one_prio each): the
            // first success clears ESRCH, an error stays
            let Some(pgid) = super::pid::from_vnr_or(who, super::percpu::current_pgid()) else {
                return KernelError::NoProcess.sysret();
            };
            let mut ret = KernelError::NoProcess.sysret();
            for tid in super::percpu::get_tids_by_pgid(pgid) {
                ret = set_one_prio(tid, niceval, caller_euid, ret);
            }
            ret
        }
        PRIO_USER => {
            let mut ret = KernelError::NoProcess.sysret();
            for tid in tids_of_user(who) {
                ret = set_one_prio(tid, niceval, caller_euid, ret);
            }
            ret
        }
        _ => KernelError::InvalidArgument.sysret(),
    }
}

/// sys_sched_getscheduler - get scheduling policy
///
/// Returns the scheduling policy of the process specified by pid.
/// If pid is 0, returns the policy of the calling process.
///
/// # Arguments
/// * `pid` - Process ID (0 = calling process)
///
/// # Returns
/// * Scheduling policy (SCHED_NORMAL, SCHED_FIFO, SCHED_RR, etc.) on success
/// * Negative errno on error
///
/// # Locking
/// Acquires TASKLIST lock briefly to read policy.
pub fn sys_sched_getscheduler(pid: i64) -> i64 {
    // pid < 0 is invalid
    if pid < 0 {
        return KernelError::InvalidArgument.sysret();
    }

    let Some(target_pid) = super::pid::from_vnr_or(pid as u64, current_tid()) else {
        return KernelError::NoProcess.sysret();
    };

    match super::percpu::lookup_task_policy(target_pid) {
        Some(policy) => i64::from(policy),
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
///
/// # Returns
/// * 0 on success
/// * Negative errno on error
///
/// # Permission Model
/// - Root (euid=0): Can set any policy
/// - Without CAP_SYS_NICE: see `check_setscheduler`
///
/// # Locking
/// Acquires TASKLIST lock to modify policy.
pub fn sys_sched_setscheduler<A: crate::uaccess::UaccessArch>(
    pid: i64,
    policy: i32,
    param_ptr: u64,
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

    let Some(target_pid) = super::pid::from_vnr_or(pid as u64, current_tid()) else {
        return KernelError::NoProcess.sysret();
    };
    let euid = super::percpu::current_cred().euid;
    if let Err(e) = check_setscheduler(target_pid, policy, param.sched_priority, euid) {
        return e.sysret();
    }

    // Set the scheduler
    match super::percpu::set_task_scheduler(target_pid, policy, param.sched_priority) {
        Ok(()) => 0,
        Err(errno) => -i64::from(errno),
    }
}

/// May the caller give task `tid` `policy` at rt priority `prio` (Linux
/// user_check_sched_setscheduler): with CAP_SYS_NICE anything; else
/// only its own tasks (check_same_owner: its euid is their uid or euid),
/// an rt policy within RLIMIT_RTPRIO (none to switch to one, and no
/// raise past it), leaving SCHED_IDLE only as far as RLIMIT_NICE allows
/// its nice, and never clearing its SCHED_RESET_ON_FORK (`policy` may
/// carry the flag)
fn check_setscheduler(
    tid: Pid,
    policy: i32,
    prio: i32,
    euid: super::Uid,
) -> Result<(), KernelError> {
    use super::{CAP_SYS_NICE, SCHED_IDLE, SCHED_RESET_ON_FORK, capable, is_rt_policy};
    if capable(CAP_SYS_NICE) {
        return Ok(());
    }
    let reset = policy & SCHED_RESET_ON_FORK != 0;
    let policy = policy & !SCHED_RESET_ON_FORK;
    // One snapshot of the task (Linux reads p's fields under its locks)
    let snap = super::percpu::TASKLIST.read().get(tid).map(|t| {
        let se = &t.task.se;
        (
            t.cred(),
            se.policy(),
            se.reset_on_fork(),
            i32::from(se.rt_priority()),
            se.nice(),
        )
    });
    let Some((c, cur, cur_reset, cur_prio, nice)) = snap else {
        return Err(KernelError::NoProcess);
    };
    if c.uid != euid && c.euid != euid {
        return Err(KernelError::NotPermitted);
    }
    if cur_reset && !reset {
        return Err(KernelError::NotPermitted);
    }
    let limit = |r| {
        crate::task::rlimit::get_task_rlimit(tid, r)
            .map_or(0, |l: crate::task::rlimit::RLimit| l.rlim_cur)
    };
    if is_rt_policy(policy) {
        let rtprio = limit(crate::task::rlimit::RLIMIT_RTPRIO);
        if policy != cur && rtprio == 0 {
            return Err(KernelError::NotPermitted);
        }
        if prio > cur_prio && prio as u64 > rtprio {
            return Err(KernelError::NotPermitted);
        }
    }
    if cur == SCHED_IDLE
        && policy != SCHED_IDLE
        && (20 - nice) as u64 > limit(crate::task::rlimit::RLIMIT_NICE)
    {
        return Err(KernelError::NotPermitted);
    }
    Ok(())
}

/// sys_sched_getparam - get scheduling parameters
///
/// Returns the scheduling parameters of the process specified by pid.
/// If pid is 0, returns the parameters of the calling process.
///
/// # Arguments
/// * `pid` - Process ID (0 = calling process)
/// * `param_ptr` - Pointer to sched_param struct to fill
///
/// # Returns
/// * 0 on success
/// * Negative errno on error
///
/// # Locking
/// Acquires TASKLIST lock briefly to read parameters.
pub fn sys_sched_getparam<A: crate::uaccess::UaccessArch>(pid: i64, param_ptr: u64) -> i64 {
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

    let Some(target_pid) = super::pid::from_vnr_or(pid as u64, current_tid()) else {
        return KernelError::NoProcess.sysret();
    };

    // Get the RT priority (0 for non-RT tasks)
    let Some(rt_prio) = super::percpu::lookup_task_rt_priority(target_pid) else {
        return KernelError::NoProcess.sysret();
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
///
/// # Returns
/// * 0 on success
/// * Negative errno on error
///
/// # Permission Model
/// - Root (euid=0): Can set any parameters
/// - Without CAP_SYS_NICE: see `check_setscheduler`
///
/// # Locking
/// Acquires TASKLIST lock to modify parameters.
pub fn sys_sched_setparam<A: crate::uaccess::UaccessArch>(pid: i64, param_ptr: u64) -> i64 {
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

    let Some(target_pid) = super::pid::from_vnr_or(pid as u64, current_tid()) else {
        return KernelError::NoProcess.sysret();
    };

    // Get current policy to preserve it
    let Some(current_policy) = super::percpu::lookup_task_policy(target_pid) else {
        return KernelError::NoProcess.sysret();
    };

    if let Err(e) = check_setscheduler(
        target_pid,
        current_policy,
        param.sched_priority,
        super::percpu::current_cred().euid,
    ) {
        return e.sysret();
    }

    // Set the scheduler with current policy
    match super::percpu::set_task_scheduler(target_pid, current_policy, param.sched_priority) {
        Ok(()) => 0,
        Err(errno) => -i64::from(errno),
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
///
/// # Returns
/// * Number of bytes written on success (minimum of cpusetsize and sizeof(cpu_set_t))
/// * Negative errno on error
///
/// # Locking
/// Acquires TASKLIST lock briefly to read affinity mask.
pub fn sys_sched_getaffinity<A: crate::uaccess::UaccessArch>(
    pid: i64,
    cpusetsize: u64,
    mask_ptr: u64,
) -> i64 {
    use crate::uaccess::copy_to_user;

    // pid < 0 is invalid
    if pid < 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Room for nr_cpu_ids bits, in whole longs (Linux)
    if cpusetsize.saturating_mul(8) < u64::from(crate::cpu::nr_cpu_ids())
        || !cpusetsize.is_multiple_of(8)
    {
        return KernelError::InvalidArgument.sysret();
    }

    let Some(target_pid) = super::pid::from_vnr_or(pid as u64, current_tid()) else {
        return KernelError::NoProcess.sysret();
    };

    // The allowed CPUs that are up (Linux: & cpu_active_mask)
    let mask = match super::percpu::lookup_task_cpus_allowed(target_pid) {
        Some(m) => m.and(&crate::smp::active_cpus()),
        None => return KernelError::NoProcess.sysret(),
    };

    // min(len, cpumask_size()) bytes
    let len = (cpusetsize as usize).min(cpumask_size());
    let mut bytes = alloc::vec::Vec::with_capacity(len);
    for w in mask.words() {
        bytes.extend_from_slice(&w.to_ne_bytes());
    }
    if copy_to_user::<A>(mask_ptr, &bytes[..len]).is_err() {
        return KernelError::BadAddress.sysret();
    }
    len as i64
}

/// Bytes of a kernel cpumask: nr_cpu_ids bits in whole longs (Linux
/// cpumask_size)
fn cpumask_size() -> usize {
    (crate::cpu::nr_cpu_ids() as usize).div_ceil(64) * 8
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
/// Acquires TASKLIST lock to modify affinity mask.
pub fn sys_sched_setaffinity<A: crate::uaccess::UaccessArch>(
    pid: i64,
    cpusetsize: u64,
    mask_ptr: u64,
) -> i64 {
    use crate::uaccess::copy_from_user;

    // pid < 0 is invalid
    if pid < 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Up to cpumask_size() bytes; a shorter mask is zero-extended
    // (Linux get_user_cpu_mask)
    let len = (cpusetsize as usize).min(cpumask_size());
    let mut bytes = alloc::vec![0u8; cpumask_size()];
    if copy_from_user::<A>(&mut bytes[..len], mask_ptr, len).is_err() {
        return KernelError::BadAddress.sysret();
    }
    let words: alloc::vec::Vec<u64> = bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|c| u64::from_ne_bytes(*c))
        .collect();
    let mask = crate::util::cpumask::CpuSet::from_words(&words);

    let Some(target_pid) = super::pid::from_vnr_or(pid as u64, current_tid()) else {
        return KernelError::NoProcess.sysret();
    };

    // Linux sched_setaffinity: the caller's own tasks (check_same_owner:
    // its euid is their uid or euid) or CAP_SYS_NICE
    let euid = super::percpu::current_cred().euid;
    let owner = super::percpu::TASKLIST
        .read()
        .get(target_pid)
        .map(|t| t.cred())
        .map(|c| c.uid == euid || c.euid == euid);
    match owner {
        None => return KernelError::NoProcess.sysret(),
        Some(false) if !super::capable(super::CAP_SYS_NICE) => {
            return KernelError::NotPermitted.sysret();
        }
        _ => {}
    }

    // Set the CPU affinity mask
    match super::percpu::set_task_cpus_allowed(target_pid, mask) {
        Ok(()) => 0,
        Err(errno) => -i64::from(errno),
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
///
/// # Returns
/// * 0 on success
/// * Negative errno on error
///
/// # Locking
/// Acquires TASKLIST lock briefly to read policy.
pub fn sys_sched_rr_get_interval<A: crate::uaccess::UaccessArch>(pid: i64, tp_ptr: u64) -> i64 {
    use crate::uaccess::put_user;

    // Timespec structure for return value
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Timespec {
        tv_sec: i64,
        tv_nsec: i64,
    }
    crate::pod!(Timespec { tv_sec, tv_nsec });

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

    let Some(target_pid) = super::pid::from_vnr_or(pid as u64, current_tid()) else {
        return KernelError::NoProcess.sysret();
    };

    // Get the scheduling policy
    let Some(policy) = super::percpu::lookup_task_policy(target_pid) else {
        return KernelError::NoProcess.sysret();
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
        IOPRIO_CLASS_RT, IOPRIO_WHO_PGRP, IOPRIO_WHO_PROCESS, IOPRIO_WHO_USER, ioprio_prio_class,
        ioprio_valid,
    };

    let ioprio = ioprio as u16;

    // Validate ioprio
    if !ioprio_valid(ioprio) {
        return KernelError::InvalidArgument.sysret();
    }

    let class = ioprio_prio_class(ioprio);

    // Linux ioprio_check_cap: the RT class needs CAP_SYS_NICE or
    // CAP_SYS_ADMIN; IDLE and BE anyone
    if class == IOPRIO_CLASS_RT
        && !super::capable(super::CAP_SYS_NICE)
        && !super::capable(super::CAP_SYS_ADMIN)
    {
        return KernelError::NotPermitted.sysret();
    }

    match which {
        IOPRIO_WHO_PROCESS => {
            let Some(tid) = super::pid::from_vnr_or(who as u64, current_tid()) else {
                return KernelError::NoProcess.sysret();
            };

            if !super::percpu::task_exists(tid) {
                return KernelError::NoProcess.sysret();
            }
            if !ioprio_owner_ok(tid) {
                return KernelError::NotPermitted.sysret();
            }
            // Get or create IoContext for the target
            let ctx = match super::task_io_context(tid) {
                Ok(Some(c)) => c,
                Ok(None) => return KernelError::NoProcess.sysret(),
                Err(e) => return e.sysret(),
            };

            ctx.set_ioprio(ioprio);
            0
        }
        IOPRIO_WHO_PGRP => {
            // Set ioprio for all processes in a process group
            let Some(pgid) = super::pid::from_vnr_or(who as u64, super::percpu::current_pgid())
            else {
                return KernelError::NoProcess.sysret();
            };

            let tids = super::percpu::get_tids_by_pgid(pgid);
            if tids.is_empty() {
                return KernelError::NoProcess.sysret();
            }

            for tid in tids {
                if !ioprio_owner_ok(tid) {
                    return KernelError::NotPermitted.sysret();
                }
                match super::task_io_context(tid) {
                    Ok(Some(ctx)) => ctx.set_ioprio(ioprio),
                    Ok(None) => {}
                    Err(e) => return e.sysret(),
                }
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

/// May the caller change task `tid`'s I/O priority (Linux
/// set_task_ioprio): its uid is the caller's euid or uid, or the caller
/// has CAP_SYS_NICE
fn ioprio_owner_ok(tid: Pid) -> bool {
    let me = super::percpu::current_cred();
    let ok = super::percpu::TASKLIST
        .read()
        .get(tid)
        .is_some_and(|t| t.cred().uid == me.euid || t.cred().uid == me.uid);
    ok || super::capable(super::CAP_SYS_NICE)
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
            let Some(tid) = super::pid::from_vnr_or(who as u64, current_tid()) else {
                return KernelError::NoProcess.sysret();
            };

            // Check if task exists
            if !super::percpu::task_exists(tid) {
                return KernelError::NoProcess.sysret();
            }

            match get_task_io_context(tid) {
                Some(ctx) => i64::from(ctx.get_ioprio()),
                None => i64::from(IOPRIO_DEFAULT),
            }
        }
        IOPRIO_WHO_PGRP => {
            let Some(pgid) = super::pid::from_vnr_or(who as u64, super::percpu::current_pgid())
            else {
                return KernelError::NoProcess.sysret();
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
            i64::from(best_ioprio)
        }
        IOPRIO_WHO_USER => {
            // Get highest ioprio for all processes of a user - not fully implemented
            // Return default for simplicity
            i64::from(IOPRIO_DEFAULT)
        }
        _ => KernelError::InvalidArgument.sysret(),
    }
}
