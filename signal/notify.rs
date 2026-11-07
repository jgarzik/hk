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
