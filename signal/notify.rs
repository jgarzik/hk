//! Telling a parent or tracer about a child (Linux do_notify_parent,
//! do_notify_parent_cldstop in kernel/signal.c)

use super::{SIGCHLD, SendInfo, SigFields, SigHandler, SigInfo, sa_flags};
use crate::task::Tid;
use crate::task::percpu::{TASKLIST, TaskRef};

/// SIGCHLD info for child `tid` with `code` (CLD_*) and `status`: its
/// pid, real uid and CPU time in clock ticks (Linux
/// do_notify_parent_cldstop's fields). None once it is gone.
fn chld_info(tid: Tid, code: i32, status: i32) -> Option<SigInfo> {
    let (uid, (utime, stime)) = {
        let table = TASKLIST.read();
        let t = table.get(tid)?;
        (
            t.cred_arc().uid,
            t.task.cputime(crate::time::monotonic_ns()),
        )
    };
    let fields = SigFields::Chld {
        pid: tid as i32,
        uid,
        status,
        utime: crate::time::ns_to_clock_t(utime) as i64,
        stime: crate::time::ns_to_clock_t(stime) as i64,
    };
    Some(SigInfo::new(SIGCHLD, code, fields))
}

/// The traced task `tid` stopped with `code` (its exit_code): SIGCHLD
/// with CLD_TRAPPED to its `tracer`'s process, unless the tracer
/// ignores SIGCHLD or set SA_NOCLDSTOP (Linux do_notify_parent_cldstop,
/// for_ptracer)
pub fn notify_tracer_trapped(tid: Tid, tracer: &TaskRef, code: u32) {
    let quiet = super::get_task_sighand(tracer.tid())
        .and_then(|h| h.get_action(SIGCHLD))
        .is_some_and(|a| a.handler == SigHandler::Ignore || a.flags & sa_flags::SA_NOCLDSTOP != 0);
    if quiet {
        return;
    }
    let status = (code & 0x7f) as i32;
    if let Some(info) = chld_info(tid, super::si_code::CLD_TRAPPED, status) {
        super::kill_proc_info(tracer.pid, SIGCHLD, SendInfo::Info(info));
    }
}

/// si_code and si_status of wait status `status` (Linux
/// do_notify_parent: exit_code & 0x80 dumped, & 0x7f killed, else the
/// exit code)
fn chld_code(status: i32) -> (i32, i32) {
    use super::si_code::{CLD_DUMPED, CLD_EXITED, CLD_KILLED};
    if status & 0x80 != 0 {
        (CLD_DUMPED, status & 0x7f)
    } else if status & 0x7f != 0 {
        (CLD_KILLED, status & 0x7f)
    } else {
        (CLD_EXITED, (status >> 8) & 0xff)
    }
}

/// Zombie `tid` tells whoever waits for it that it is gone (Linux
/// do_notify_parent): its tracer, or for a leader whose group is gone
/// its parent, gets its exit signal (SIGCHLD to a tracer that is not
/// the parent) with CLD_EXITED/KILLED/DUMPED, its pid, uid, status and
/// the group's CPU times. True if it is to be released now (autoreap):
/// an untraced child whose parent ignores SIGCHLD (no signal then) or
/// set SA_NOCLDWAIT.
pub fn do_notify_parent(tid: Tid) -> bool {
    let Some((parent, mut sig, traced, info)) = notice(tid) else {
        return false;
    };
    let action = super::get_task_sighand(parent.tid()).and_then(|h| h.get_action(SIGCHLD));
    let mut autoreap = false;
    if !traced && sig == SIGCHLD {
        let ign = action
            .as_ref()
            .is_some_and(|a| a.handler == SigHandler::Ignore);
        let nocldwait = action
            .as_ref()
            .is_some_and(|a| a.flags & sa_flags::SA_NOCLDWAIT != 0);
        if ign || nocldwait {
            autoreap = true;
            if ign {
                sig = 0;
            }
        }
    }
    if sig != 0 {
        let mut info = info;
        info.signo = sig as i32;
        super::kill_proc_info(parent.pid, sig, SendInfo::Info(info));
    }
    autoreap
}

/// What [`do_notify_parent`] sends, read under TASKLIST: the task told,
/// the signal, traced, the info
fn notice(tid: Tid) -> Option<(TaskRef, u32, bool, SigInfo)> {
    let table = TASKLIST.read();
    let t = table.get(tid)?;
    let crate::task::TaskState::Zombie(own) = t.state else {
        return None;
    };
    let real = t.real_parent.as_ref().and_then(|w| w.upgrade());
    let tracer = t.tracer();
    let traced = tracer.is_some();
    let parent = tracer.clone().or(real.clone())?;
    // A tracer that is not the parent, or a thread: SIGCHLD
    let reparented = traced
        && !real
            .as_ref()
            .is_some_and(|r| alloc::sync::Arc::ptr_eq(r, &parent));
    let sig = if t.leader && !reparented {
        t.exit_signal as u32
    } else {
        SIGCHLD
    };
    if sig > 64 {
        return None;
    }
    let status = match t.signal.as_ref().map(|s| s.group_exit()) {
        Some(super::GroupExit::Exit(code)) => code,
        _ => own,
    };
    let (utime, stime) = if t.leader {
        crate::task::percpu::group_times(&table, t.task.pid)
    } else {
        t.task.cputime(crate::time::monotonic_ns())
    };
    let (code, st) = chld_code(status);
    let fields = SigFields::Chld {
        pid: tid as i32,
        uid: t.cred_arc().uid,
        status: st,
        utime: crate::time::ns_to_clock_t(utime) as i64,
        stime: crate::time::ns_to_clock_t(stime) as i64,
    };
    Some((parent, sig, traced, SigInfo::new(SIGCHLD, code, fields)))
}
