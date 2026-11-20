//! Telling a parent or tracer about a child (Linux do_notify_parent,
//! do_notify_parent_cldstop in kernel/signal.c)

use super::{SIGCHLD, SendInfo, SigFields, SigHandler, SigInfo, Signal, sa_flags};
use crate::task::tasklist::{GlobalTaskTable, TaskRef};
use crate::task::{Task, Tid};

/// SIGCHLD info for child `t` with `code` (CLD_*) and `status`: its
/// pid, real uid and CPU time in clock ticks (Linux
/// do_notify_parent_cldstop's fields), read under TASKLIST. None once
/// it is gone.
fn chld_info(
    table: &GlobalTaskTable,
    t: &Task,
    code: i32,
    status: i32,
    ns: &crate::ns::PidNamespace,
) -> Option<SigInfo> {
    let v = table.view(t)?;
    let uid = v.cred_arc().uid;
    // Raw samples (Linux task_cputime)
    let c = crate::task::cputime::task_cputime(v.task);
    let (utime, stime) = (c.utime, c.stime);
    let fields = SigFields::Chld {
        pid: crate::task::pid::nr_ns(t.tid(), ns) as i32,
        uid,
        status,
        utime: crate::time::ns_to_clock_t(utime) as i64,
        stime: crate::time::ns_to_clock_t(stime) as i64,
    };
    Some(SigInfo::new(SIGCHLD, code, fields))
}

/// A stop, continue or ptrace trap of `t` told to its tracer
/// (`for_ptracer`: `t` itself, CLD_TRAPPED with its stop's code, or a
/// group stop's code) or to its group leader's real parent (the
/// leader, with the group's stop signal or SIGCONT) (Linux
/// do_notify_parent_cldstop): SIGCHLD with its pid, uid and CPU time,
/// unless the receiver ignores SIGCHLD or set SA_NOCLDSTOP; a wait for
/// it is woken either way. Under TASKLIST's read lock held by the
/// caller, the whole send done there.
pub fn notify_parent_cldstop(
    table: &GlobalTaskTable,
    t: &Task,
    for_ptracer: bool,
    why: super::stop::Why,
) {
    use super::stop::Why;
    let Some(v) = table.view(t) else {
        return;
    };
    let (tsk, parent) = if for_ptracer {
        (
            crate::task::tasklist::task_ref(t),
            v.tracer().map(crate::task::tasklist::task_ref),
        )
    } else {
        let Some(l) = table.get(t.pid) else {
            return;
        };
        (
            crate::task::tasklist::task_ref(l.task),
            l.real_parent().map(crate::task::tasklist::task_ref),
        )
    };
    let Some(parent) = parent else {
        return;
    };
    let status = match why {
        Why::Continued => super::SIGCONT.nr() as i32,
        Why::Stopped => {
            let code = tsk
                .cpu_group()
                .zip(super::lock_sighand_in(&tsk, table))
                .map_or(0, |(s, g)| super::stop::stop_code(&g, s));
            (code & 0x7f) as i32
        }
        Why::Trapped => super::lock_sighand_in(&tsk, table)
            .map_or(0, |g| (super::sig_of(&tsk, &g).ptrace_code & 0x7f) as i32),
    };
    let quiet = table
        .view(&parent)
        .and_then(|v| v.sighand().map(|h| h.get_action(SIGCHLD)))
        .is_some_and(|a| a.handler == SigHandler::Ignore || a.flags & sa_flags::SA_NOCLDSTOP != 0);
    // As the receiver's namespace numbers it (Linux task_pid_nr_ns(tsk,
    // task_active_pid_ns(parent)))
    let info = chld_info(table, &tsk, why.code(), status, parent.pid_ns());
    if !quiet && let Some(info) = info {
        // To the parent thread, for its group (Linux
        // __group_send_sig_info(SIGCHLD, .., parent): send_signal_locked
        // PIDTYPE_TGID); SIGCHLD flushes nothing
        let mut gone = super::SigPending::new();
        let info = SendInfo::Info(info);
        let _ = super::send_task_in(
            &parent,
            SIGCHLD,
            info,
            super::PidType::Tgid,
            false,
            &mut gone,
        );
    }
    // Linux __wake_up_parent
    crate::task::proc::CHILD_EXIT_WQ.wake_all();
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

/// Who is told of zombie `z`: its tracer, else its real parent (`to`,
/// that thread, for its process: Linux __group_send_sig_info to
/// tsk->parent); the signal (its exit signal, or SIGCHLD to a
/// tracer that is not the parent, to a thread, or to an image that did
/// not ask for it; None: none) and whether it is released at once
/// (autoreap)
struct Rcv {
    /// Kept so its last reference, if this is it, goes after TASKLIST
    to: TaskRef,
    sig: Option<Signal>,
    autoreap: bool,
}

/// A zombie whose notice is sent, by the rule its signal follows
/// (Linux: the signal do_notify_parent's caller passes)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Zombie {
    /// The exiting task itself (Linux exit_notify): its exit signal if
    /// it is a leader with no other thread left (thread_group_empty)
    /// and, if traced, its tracer is in its real parent's process
    /// (!ptrace_reparented); else SIGCHLD
    Exiting(Tid),
    /// A zombie leader whose group just emptied, or moved to a new
    /// parent (Linux release_task, reparent_leader): its exit signal
    Leader(Tid),
    /// A traced zombie leader whose tracer is done with it (reaped it,
    /// or exited), told to its real parent as if never traced (Linux
    /// wait_task_zombie EXIT_TRACE, __ptrace_detach): its exit signal
    Detached(Tid),
}

impl Zombie {
    /// Its tid
    pub fn tid(self) -> Tid {
        match self {
            Self::Exiting(t) | Self::Leader(t) | Self::Detached(t) => t,
        }
    }
}

/// [`Rcv`] of `z`, read under TASKLIST
fn receiver(table: &GlobalTaskTable, z: Zombie) -> Option<Rcv> {
    let tid = z.tid();
    let t = table.get(tid)?;
    let real = t.real_parent().map(crate::task::tasklist::task_ref);
    let tracer = match z {
        Zombie::Detached(_) => None,
        _ => t.tracer().map(crate::task::tasklist::task_ref),
    };
    let traced = tracer.is_some();
    let parent = tracer.or(real.clone())?;
    let own = match z {
        Zombie::Exiting(_) => {
            // Linux ptrace_reparented: the tracer is not a thread of
            // the real parent's process
            let reparented = traced && real.as_ref().is_none_or(|r| r.pid != parent.pid);
            t.leader()
                && !reparented
                && !crate::task::exit::group_pending(table, t.task.pid, &[tid])
        }
        Zombie::Leader(_) | Zombie::Detached(_) => true,
    };
    let mut sig = if own {
        t.exit_signal().signal()
    } else {
        Some(SIGCHLD)
    };
    // A custom exit signal only to the image that asked for it (Linux:
    // parent_exec_id != parent->self_exec_id makes it SIGCHLD)
    if sig != Some(SIGCHLD) && t.parent_exec_id() != crate::task::self_exec_id(&parent) {
        sig = Some(SIGCHLD);
    }
    let (sig, autoreap) = if traced {
        (sig, false)
    } else {
        disposition(table, &parent, sig)
    };
    Some(Rcv {
        to: parent,
        sig,
        autoreap,
    })
}

/// What untraced child notice `sig` to the parent thread `to` does, by
/// its process's SIGCHLD action (Linux do_notify_parent: psig =
/// tsk->parent->sighand, the handlers its threads share): the signal
/// sent (None: none) and autoreap. A parent that ignores SIGCHLD or set SA_NOCLDWAIT does not
/// wait for the child; one that ignores it gets no signal.
fn disposition(table: &GlobalTaskTable, to: &Task, sig: Option<Signal>) -> (Option<Signal>, bool) {
    if sig != Some(SIGCHLD) {
        return (sig, false);
    }
    let action = table
        .view(to)
        .and_then(|v| v.sighand().map(|h| h.get_action(SIGCHLD)));
    match action {
        Some(a) if a.handler == SigHandler::Ignore => (None, true),
        Some(a) if a.flags & sa_flags::SA_NOCLDWAIT != 0 => (sig, true),
        _ => (sig, false),
    }
}

/// The process of task `t` reaps its children itself: it ignores
/// SIGCHLD or set SA_NOCLDWAIT (Linux ignoring_children(t->sighand), by
/// its SIGCHLD action as [`disposition`] reads it)
pub fn ignoring_children(table: &GlobalTaskTable, t: &Task) -> bool {
    disposition(table, t, Some(SIGCHLD)).1
}

/// What [`notify`] did: the parent is to release the zombie now
/// (`autoreap`); what the send read is freed by [`Told::finish`]
#[must_use]
#[derive(Default)]
pub struct Told {
    pub autoreap: bool,
    rcv: Option<Rcv>,
    gone: super::SigPending,
}

impl Told {
    /// Free what the send left (TASKLIST not held)
    pub fn finish(self) {
        drop(self.rcv);
        drop(self.gone);
    }
}

/// Zombie `z` tells whoever waits for it that it is gone (Linux
/// do_notify_parent): its tracer, or for a leader whose group is gone
/// its parent, gets the signal [`Zombie`]'s rule gives it with
/// CLD_EXITED/KILLED/DUMPED, its pid, uid, status and
/// the group's CPU times. Autoreap: an untraced child whose parent
/// ignores SIGCHLD (no signal then) or set SA_NOCLDWAIT.
///
/// Under TASKLIST's write lock, in the section that made it reportable
/// (Linux exit_notify, release_task, reparent_leader call
/// do_notify_parent under tasklist_lock), the whole send done there,
/// its queue entry GFP_ATOMIC, its wakeup and any group kill (Linux
/// __group_send_sig_info, complete_signal): no wait reaps it before its
/// signal is pending, and a parent its signal wakes finds it.
pub fn notify(table: &GlobalTaskTable, z: Zombie) -> Told {
    let tid = z.tid();
    // A stop-signal exit signal's flushed entries, freed after TASKLIST
    let mut gone = super::SigPending::new();
    // Its pidfd pollers first (Linux do_notify_parent: do_notify_pidfd)
    crate::task::exit::notify_pidfd(table, tid);
    let Some(r) = receiver(table, z) else {
        return Told {
            gone,
            ..Told::default()
        };
    };
    let (sig, autoreap) = (r.sig, r.autoreap);
    if let (Some(sig), Some(info)) = (sig, chld_notice(table, tid, r.to.pid_ns())) {
        // Its pid as the receiver numbers it, never hidden (Linux
        // do_notify_parent: __send_signal_locked, not send_signal_locked:
        // the last thread's release sends its leader's notice with its
        // own pid already detached)
        let info = SendInfo::Notice(info.with_sig(sig));
        let _ = super::send_task_in(&r.to, sig, info, super::PidType::Tgid, false, &mut gone);
    }
    Told {
        autoreap,
        gone,
        rcv: Some(r),
    }
}

/// Zombie `tid`'s notice info, read under TASKLIST: its pid (as the
/// receiver's namespace `ns` numbers it: Linux do_notify_parent), uid, wait
/// status, and its CPU times with its group's exited threads
fn chld_notice(table: &GlobalTaskTable, tid: Tid, ns: &crate::ns::PidNamespace) -> Option<SigInfo> {
    let t = table.get(tid)?;
    let crate::task::TaskState::Zombie(own) = t.state() else {
        return None;
    };
    let status = match t.task.cpu_group().map(|s| s.group_exit()) {
        Some(super::GroupExit::Exit(code)) => code,
        _ => own,
    };
    // Its raw samples and its group's exited threads' (Linux
    // do_notify_parent: task_cputime + signal->utime/stime)
    let mut c = crate::task::cputime::task_cputime(t.task);
    if let Some(s) = t.task.cpu_group() {
        c = c + s.dead_times();
    }
    let (utime, stime) = (c.utime, c.stime);
    let (code, st) = chld_code(status);
    let fields = SigFields::Chld {
        pid: crate::task::pid::nr_ns(tid, ns) as i32,
        uid: t.cred_arc().uid,
        status: st,
        utime: crate::time::ns_to_clock_t(utime) as i64,
        stime: crate::time::ns_to_clock_t(stime) as i64,
    };
    Some(SigInfo::new(SIGCHLD, code, fields))
}
