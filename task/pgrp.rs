//! Process group and session syscalls
//!
//! This module contains syscalls for process groups and sessions:
//! - getpgid, setpgid (process group ID)
//! - getsid, setsid (session ID)

use crate::util::error::{KernelError, KernelResult};

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
pub fn sys_getpgid(pid: i32, caller_pid: Pid, caller_pgid: Pid) -> KernelResult<i64> {
    if pid < 0 {
        return Err(KernelError::NoProcess);
    }
    // The caller's number (Linux find_task_by_vpid)
    let pid = super::pid::from_vnr_or(pid as Pid, caller_pid).ok_or(KernelError::NoProcess)?;
    // Reported in the caller's namespace, 0 for a group outside it
    // (Linux pid_vnr(task_pgrp(p)))
    if pid == caller_pid {
        return Ok(i64::from(super::pid::vnr(caller_pgid)));
    }
    let pgid = super::percpu::lookup_task_pgid(pid).ok_or(KernelError::NoProcess)?;
    Ok(i64::from(pgid))
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
pub fn sys_getsid(pid: i32, caller_pid: Pid, caller_sid: Pid) -> KernelResult<i64> {
    if pid < 0 {
        return Err(KernelError::NoProcess);
    }
    let pid = super::pid::from_vnr_or(pid as Pid, caller_pid).ok_or(KernelError::NoProcess)?;
    if pid == caller_pid {
        return Ok(i64::from(super::pid::vnr(caller_sid)));
    }
    let sid = super::percpu::lookup_task_sid(pid).ok_or(KernelError::NoProcess)?;
    Ok(i64::from(sid))
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
) -> KernelResult<()> {
    // Linux: a negative pgid is EINVAL, a negative pid names no task
    if pgid < 0 {
        return Err(KernelError::InvalidArgument);
    }
    if pid < 0 {
        return Err(KernelError::NoProcess);
    }
    // The caller's numbers (Linux find_task_by_vpid, find_vpid): a
    // process it does not see is ESRCH, a group EPERM (none of its
    // session)
    let target_pid =
        super::pid::from_vnr_or(pid as Pid, caller_pid).ok_or(KernelError::NoProcess)?;
    let new_pgid = if pgid == 0 || pgid == pid {
        target_pid
    } else {
        super::pid::from_vnr(pgid as Pid).ok_or(KernelError::NotPermitted)?
    };
    super::percpu::set_task_pgid(caller_pid, target_pid, new_pgid, caller_sid)
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
pub fn sys_setsid(caller_pid: Pid) -> KernelResult<i64> {
    let new_sid = super::percpu::create_session(caller_pid)?;
    Ok(i64::from(super::pid::vnr(new_sid)))
}
