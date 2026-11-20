//! Process groups and sessions (Linux kernel/sys.c): the syscalls,
//! the setpgid/setsid moves under TASKLIST, and group lookups. Syscalls:
//! - getpgid, setpgid (process group ID)
//! - getsid, setsid (session ID)

use crate::util::error::{KernelError, KernelResult};

use super::Pid;
use super::tasklist::{GlobalTaskTable, TASKLIST, TaskRef, task_ref, vpid_task};
use alloc::sync::Arc;

/// sys_getpgid - get process group ID
///
/// Returns the process group ID of the process specified by pid.
/// If pid is 0, returns the PGID of the calling process.
///
/// # Arguments
/// * `pid` - Process ID to query (0 = calling process)
pub fn sys_getpgid(pid: i32) -> KernelResult<i64> {
    if pid < 0 {
        return Err(KernelError::NoProcess);
    }
    // Its own: read under RCU, no lock (Linux task_pgrp(current))
    if pid == 0 {
        return Ok(i64::from(super::percpu::current_pgid_vnr()));
    }
    // The caller's number (Linux find_task_by_vpid, under RCU);
    // reported in the caller's namespace, 0 for a group outside it
    // (Linux pid_vnr(task_pgrp(p)))
    let pgid = vpid_pgrp_vnr(pid as u64, false).ok_or(KernelError::NoProcess)?;
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
pub fn sys_getsid(pid: i32) -> KernelResult<i64> {
    if pid < 0 {
        return Err(KernelError::NoProcess);
    }
    // Its own: read under RCU, no lock (Linux task_session(current))
    if pid == 0 {
        return Ok(i64::from(super::percpu::current_sid_vnr()));
    }
    let sid = vpid_pgrp_vnr(pid as u64, true).ok_or(KernelError::NoProcess)?;
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
pub fn sys_setpgid(pid: i32, pgid: i32, caller_pid: Pid) -> KernelResult<()> {
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
    set_task_pgid(caller_pid, target_pid, new_pgid)
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
    let new_sid = create_session(caller_pid)?;
    Ok(i64::from(super::pid::vnr(new_sid)))
}

/// Every thread of every process in group `pgid` (its pid links)
pub fn pgrp_tasks(pgid: Pid) -> alloc::vec::Vec<TaskRef> {
    let Some(pg) = crate::task::pid::find_pgrp(&crate::ns::INIT_PID_NS, pgid) else {
        return alloc::vec::Vec::new();
    };
    GlobalTaskTable::collect_pgrp_threads(&pg, |_, t| Some(task_ref(t.task)))
}

/// Is group `pg` orphaned: no member has a parent in another group of
/// its session (Linux will_become_orphaned_pgrp(pg, NULL); members that
/// exited and children of the global init do not count)
pub fn pgrp_orphaned(pg: &crate::task::pid::Pid) -> bool {
    let table = TASKLIST.read();
    let same = |a: Option<&crate::task::pid::Pid>, b: &crate::task::pid::Pid| {
        a.is_some_and(|a| core::ptr::eq(a, b))
    };
    !table.pgrp(pg).any(|m| {
        if matches!(m.state, crate::task::TaskState::Zombie(_)) {
            return false;
        }
        let Some(parent) = m.real_parent() else {
            return false;
        };
        if parent.pid == 1 {
            return false;
        }
        let Some(p) = table.view(parent) else {
            return false;
        };
        let Some(ms) = m.session() else {
            return false;
        };
        !same(p.pgrp(), pg) && same(p.session(), ms)
    })
}

/// The group (`session`: the session) of the task the caller numbers
/// `nr`, as the caller numbers it, 0 if outside its namespace (Linux
/// getpgid, getsid with a pid: under rcu_read_lock, find_task_by_vpid,
/// pid_vnr(task_pgrp(p)) / task_session); no TASKLIST. None (ESRCH)
/// if no task has that number or its group is gone (a released
/// leader); a kernel thread is in none, 0 (Linux init_struct_pid).
pub fn vpid_pgrp_vnr(nr: u64, session: bool) -> Option<u32> {
    let g = crate::sync::rcu::read_lock();
    let t = vpid_task(nr, &g)?;
    let p = if session { &t.session } else { &t.pgrp };
    match p.read(&g) {
        Some(p) => Some(p.nr_ns(crate::task::pid::current_pid_ns())),
        None if t.has_flag(crate::task::pf::KTHREAD) => Some(0),
        None => None,
    }
}

/// True if some process is in group `pgid`
pub fn pgrp_exists(pgid: Pid) -> bool {
    let Some(pg) = crate::task::pid::find_pgrp(&crate::ns::INIT_PID_NS, pgid) else {
        return false;
    };
    let table = TASKLIST.read();
    table.pgrp(&pg).next().is_some()
}

/// Move process `target_pid` (every thread) to group `new_pgid`
///
/// Returns Ok(()) on success, Err(errno) on failure.
/// Error codes:
/// - ESRCH (3): Process not found
/// - EPERM (1): a session leader, another session, or no group
///   `new_pgid` in the caller's session
pub fn set_task_pgid(caller_pid: Pid, target_pid: Pid, new_pgid: Pid) -> KernelResult<()> {
    // Found before TASKLIST (the pid hash's lock is not nested in it)
    let target = crate::task::pid::find_pgrp(&crate::ns::INIT_PID_NS, new_pgid);
    let mut table = TASKLIST.write();
    // The caller's session, in the write section that changes the
    // group (Linux sys_setpgid: task_session(group_leader))
    let caller_sid = table.get(caller_pid).map_or(0, |l| l.sid());
    setpgid_who(&table, caller_pid, target_pid, caller_sid)?;
    let pg = setpgid_target(&table, target_pid, new_pgid, target.as_ref(), caller_sid)?;
    let old = table.change_pids(target_pid, &pg, None);
    drop(table);
    drop(old);
    Ok(())
}

/// Process `pid` is the caller's own (`caller_pid`, its group leader)
/// or a child of the caller's process in its session that has not
/// exec'd (Linux sys_setpgid: ESRCH, EPERM, EACCES)
fn setpgid_who(
    table: &GlobalTaskTable,
    caller_pid: Pid,
    pid: Pid,
    caller_sid: Pid,
) -> KernelResult<()> {
    if pid == caller_pid {
        return Ok(());
    }
    let p = table.get(pid).ok_or(KernelError::NoProcess)?;
    let child = p
        .real_parent()
        .is_some_and(|parent| parent.pid == caller_pid);
    if !child {
        return Err(KernelError::NoProcess);
    }
    if p.sid() != caller_sid {
        return Err(KernelError::NotPermitted);
    }
    if !p.task.has_flag(crate::task::pf::FORKNOEXEC) {
        return Err(KernelError::PermissionDenied);
    }
    Ok(())
}

/// The group process `pid` moves to (Linux sys_setpgid's checks): not
/// a session leader, in the caller's session; `pgid` is its own pid (a
/// new group) or a group of that session
fn setpgid_target(
    table: &GlobalTaskTable,
    pid: Pid,
    pgid: Pid,
    target: Option<&Arc<crate::task::pid::Pid>>,
    caller_sid: Pid,
) -> KernelResult<Arc<crate::task::pid::Pid>> {
    let l = table.get(pid).ok_or(KernelError::NoProcess)?;
    let sid = l.sid();
    if pid == sid || sid != caller_sid {
        return Err(KernelError::NotPermitted);
    }
    if pgid == pid {
        return l.thread_pid().ok_or(KernelError::NoProcess);
    }
    let pg = target.ok_or(KernelError::NotPermitted)?;
    match table.pgrp(pg).next() {
        Some(g) if g.sid() == caller_sid => Ok(pg.clone()),
        _ => Err(KernelError::NotPermitted), // no such group in the caller's session
    }
}

/// Create a new session for the current process
///
/// Returns the new session ID; EPERM if a session leader already, or a process group with the
///   caller's pid as id exists
pub fn create_session(caller_pid: Pid) -> KernelResult<Pid> {
    let mut table = TASKLIST.write();
    let pid = {
        let l = table.get(caller_pid).ok_or(KernelError::NoProcess)?;
        let pid = l.thread_pid().ok_or(KernelError::NoProcess)?;
        // A session leader already, or a process group with the
        // caller's id exists (Linux ksys_setsid)
        if l.sid() == caller_pid || table.pgrp(&pid).next().is_some() {
            return Err(KernelError::NotPermitted);
        }
        pid
    };
    // The whole process: pid becomes sid and pgid, with no controlling
    // tty (Linux ksys_setsid: proc_clear_tty)
    let old = table.change_pids(caller_pid, &pid, Some(&pid));
    if let Some(sig) = table.get(caller_pid).and_then(|l| l.signal().cloned()) {
        crate::tty::jobctrl::proc_clear_tty(&sig);
    }
    drop(table);
    drop(old);
    Ok(caller_pid)
}
