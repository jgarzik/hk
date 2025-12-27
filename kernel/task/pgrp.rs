//! Process group and session syscalls
//!
//! This module contains syscalls for process groups and sessions:
//! - getpgid, setpgid (process group ID)
//! - getsid, setsid (session ID)

use crate::error::KernelError;

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
pub fn sys_getpgid(pid: Pid, caller_pid: Pid, caller_pgid: Pid) -> i64 {
    if pid == 0 || pid == caller_pid {
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
pub fn sys_getsid(pid: Pid, caller_pid: Pid, caller_sid: Pid) -> i64 {
    if pid == 0 || pid == caller_pid {
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
/// - Can only set PGID of self or child (we only support self for now)
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
    pid: Pid,
    pgid: Pid,
    caller_pid: Pid,
    _caller_pgid: Pid,
    caller_sid: Pid,
) -> i64 {
    // Normalize pid and pgid
    let target_pid = if pid == 0 { caller_pid } else { pid };
    let new_pgid = if pgid == 0 { target_pid } else { pgid };

    // Validate pgid (cannot be negative in Linux, we use u64 so this is fine)
    if new_pgid == 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // For now, we only support setting own PGID (no child process support yet)
    if target_pid != caller_pid {
        // TODO: When we have fork(), allow setting child's PGID
        return KernelError::NoProcess.sysret();
    }

    // Call the scheduler function to update the task
    match super::percpu::set_task_pgid(target_pid, new_pgid, caller_sid) {
        Ok(()) => {
            // Update per-CPU cached value if we changed our own PGID
            if target_pid == caller_pid {
                super::percpu::update_current_pgid_sid(new_pgid, caller_sid);
            }
            0
        }
        Err(errno) => -(errno as i64),
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
/// - -EPERM if already a process group leader
pub fn sys_setsid(caller_pid: Pid, caller_pgid: Pid) -> i64 {
    match super::percpu::create_session(caller_pid, caller_pgid) {
        Ok(new_sid) => {
            // Update per-CPU cached values (pgid = sid = pid for new session leader)
            super::percpu::update_current_pgid_sid(new_sid, new_sid);
            new_sid as i64
        }
        Err(errno) => -(errno as i64),
    }
}
