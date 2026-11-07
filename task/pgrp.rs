//! Process group and session syscalls
//!
//! This module contains syscalls for process groups and sessions:
//! - getpgid, setpgid (process group ID)
//! - getsid, setsid (session ID)

use crate::util::error::KernelError;

use super::Pid;

/// sys_getpgid - get process group ID
///
/// Returns the process group ID of the process specified by pid.
/// If pid is 0, returns the PGID of the calling process.
///
/// # Arguments
/// * `pid` - Process ID to query (0 = calling process)
/// * `caller_pid` - PID of calling process
/// * `caller_pgid` - PGID of calling process
pub fn sys_getpgid(pid: i32, caller_pid: Pid, caller_pgid: Pid) -> i64 {
    if pid < 0 {
        return KernelError::NoProcess.sysret();
    }
    // The caller's number (Linux find_task_by_vpid)
    let Some(pid) = super::pid::from_vnr_or(pid as Pid, caller_pid) else {
        return KernelError::NoProcess.sysret();
    };
    if pid == caller_pid {
        caller_pgid as i64
    } else {
        match super::percpu::lookup_task_pgid(pid) {
            Some(pgid) => pgid as i64,
            None => KernelError::NoProcess.sysret(),
        }
    }
}

/// sys_getsid - get session ID
///
/// Returns the session ID of the process specified by pid.
/// If pid is 0, returns the SID of the calling process.
///
/// Note: Linux does NOT return EPERM for cross-session queries.
///
/// # Arguments
/// * `pid` - Process ID to query (0 = calling process)
/// * `caller_pid` - PID of calling process
/// * `caller_sid` - SID of calling process
pub fn sys_getsid(pid: i32, caller_pid: Pid, caller_sid: Pid) -> i64 {
    if pid < 0 {
        return KernelError::NoProcess.sysret();
    }
    let Some(pid) = super::pid::from_vnr_or(pid as Pid, caller_pid) else {
        return KernelError::NoProcess.sysret();
    };
    if pid == caller_pid {
        caller_sid as i64
    } else {
        match super::percpu::lookup_task_sid(pid) {
            Some(sid) => sid as i64,
            None => KernelError::NoProcess.sysret(),
        }
    }
}

/// sys_setpgid - set process group ID
///
/// Sets the process group ID of the process specified by pid to pgid.
/// If pid is 0, the calling process's PID is used.
/// If pgid is 0, the PID is used as the new PGID (creating a new process group).
///
/// # Restrictions
/// - Only the caller's own process or a child of it (same session, not
///   yet exec'd: EPERM, EACCES; anything else ESRCH)
/// - Cannot change PGID of session leader
/// - Target PGID must exist in same session, or pgid==pid (new group)
///
/// # Arguments
/// * `pid` - Process to modify (0 = calling process)
/// * `pgid` - New process group ID (0 = use pid)
/// * `caller_pid` - PID of calling process
/// * `caller_pgid` - Current PGID of calling process
/// * `caller_sid` - SID of calling process
pub fn sys_setpgid(
    pid: i32,
    pgid: i32,
    caller_pid: Pid,
    _caller_pgid: Pid,
    caller_sid: Pid,
) -> i64 {
    // Linux: a negative pgid is EINVAL, a negative pid names no task
    if pgid < 0 {
        return KernelError::InvalidArgument.sysret();
    }
    if pid < 0 {
        return KernelError::NoProcess.sysret();
    }
    // The caller's numbers (Linux find_task_by_vpid, find_vpid): a
    // process it does not see is ESRCH, a group EPERM (none of its
    // session)
    let Some(target_pid) = super::pid::from_vnr_or(pid as Pid, caller_pid) else {
        return KernelError::NoProcess.sysret();
    };
    let new_pgid = if pgid == 0 || pgid == pid {
        target_pid
    } else {
        match super::pid::from_vnr(pgid as Pid) {
            Some(g) => g,
            None => return KernelError::NotPermitted.sysret(),
        }
    };

    match super::percpu::set_task_pgid(caller_pid, target_pid, new_pgid, caller_sid) {
        Ok(()) => 0,
        Err(errno) => -i64::from(errno),
    }
}

/// sys_setsid - create session and set process group ID
///
/// Creates a new session if the calling process is not a process group leader.
/// Upon return, the calling process will be:
/// - The session leader of the new session
/// - The process group leader of a new process group
/// - Have no controlling terminal
///
/// # Returns
/// - Session ID (== PID) on success
/// - -EPERM if a session leader, or a process group with its id exists
pub fn sys_setsid(caller_pid: Pid) -> i64 {
    match super::percpu::create_session(caller_pid) {
        Ok(new_sid) => new_sid as i64,
        Err(errno) => -i64::from(errno),
    }
}
