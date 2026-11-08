//! Telling a parent or tracer about a child (Linux do_notify_parent,
//! do_notify_parent_cldstop in kernel/signal.c)

use super::{SIGCHLD, SendInfo, SigFields, SigHandler, SigInfo, SigQueue, Signal, sa_flags};
use crate::task::percpu::{GlobalTaskTable, TASKLIST, TaskRef};
use crate::task::{Task, Tid};
use alloc::boxed::Box;

/// SIGCHLD info for child `t` with `code` (CLD_*) and `status`: its
/// pid, real uid and CPU time in clock ticks (Linux
/// do_notify_parent_cldstop's fields). None once it is gone.
fn chld_info(t: &Task, code: i32, status: i32, ns: &crate::ns::PidNamespace) -> Option<SigInfo> {
    let (uid, (utime, stime)) = {
        let table = TASKLIST.read();
        let v = table.view(t)?;
        (
            v.cred_arc().uid,
            v.task.cputime(crate::time::monotonic_ns()),
        )
    };
    let fields = SigFields::Chld {
        pid: crate::task::pid::nr_ns(t.tid(), ns) as i32,
        uid,
        status,
        utime: crate::time::ns_to_clock_t(utime) as i64,
        stime: crate::time::ns_to_clock_t(stime) as i64,
    };
    Some(SigInfo::new(SIGCHLD, code, fields))
}

/// The traced task `t` stopped with `code` (its exit_code): SIGCHLD
/// with CLD_TRAPPED to its `tracer`'s process, unless the tracer
/// ignores SIGCHLD or set SA_NOCLDSTOP (Linux do_notify_parent_cldstop,
/// for_ptracer)
pub fn notify_tracer_trapped(t: &Task, tracer: &Task, code: u32) {
    let quiet = super::get_task_sighand(tracer)
        .map(|h| h.get_action(SIGCHLD))
        .is_some_and(|a| a.handler == SigHandler::Ignore || a.flags & sa_flags::SA_NOCLDSTOP != 0);
    if quiet {
        return;
    }
    let status = (code & 0x7f) as i32;
    // The tracee as its tracer's namespace numbers it (Linux
    // do_notify_parent_cldstop: task_pid_nr_ns(tsk, ns of parent))
    let ns = tracer.pid_ns();
    if let Some(info) = chld_info(t, super::si_code::CLD_TRAPPED, status, ns) {
        let _ = super::group_send_sig_info(tracer, SIGCHLD, SendInfo::Info(info));
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

/// Who is told of zombie `z`: its tracer, else its real parent
/// (`_parent`), through `to`, the thread of that process a group signal
/// is checked against; the signal (its exit signal, or SIGCHLD to a
/// tracer that is not the parent, to a thread, or to an image that did
/// not ask for it; None: none) and whether it is released at once
/// (autoreap)
struct Rcv {
    /// Kept only so its last reference, if this is it, goes after
    /// TASKLIST
    _parent: TaskRef,
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
    let real = t.real_parent();
    let tracer = match z {
        Zombie::Detached(_) => None,
        _ => t.tracer(),
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
                && !crate::task::percpu::group_pending(table, t.task.pid, &[tid])
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
    let to = super::group_task(table, table.get(parent.pid))?;
    let (sig, autoreap) = if traced {
        (sig, false)
    } else {
        disposition(table, &to, sig)
    };
    Some(Rcv {
        _parent: parent,
        to,
        sig,
        autoreap,
    })
}

/// What untraced child notice `sig` to the process `to` is a thread of
/// does, by that process's SIGCHLD action (Linux do_notify_parent:
/// psig, the handlers its threads share; not a thread's own, which an
/// exited one no longer has): the signal sent (None: none) and
/// autoreap. A parent that ignores SIGCHLD or set SA_NOCLDWAIT does not
/// wait for the child; one that ignores it gets no signal.
fn disposition(
    table: &GlobalTaskTable,
    to: &TaskRef,
    sig: Option<Signal>,
) -> (Option<Signal>, bool) {
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

/// The process `pid` reaps its children itself: it ignores SIGCHLD or
/// set SA_NOCLDWAIT (Linux ignoring_children, by its SIGCHLD action as
/// [`disposition`] reads it)
pub fn ignoring_children(table: &GlobalTaskTable, pid: crate::task::Pid) -> bool {
    super::group_task(table, table.get(pid))
        .is_some_and(|to| disposition(table, &to, Some(SIGCHLD)).1)
}

/// The entry a zombie's notice is queued with, made before TASKLIST is
/// taken (nothing allocates under it) and charged to the user it would
/// go to then, none if no signal would be sent; under the lock,
/// [`Entry::fits`] tells whether that is still so, else the caller
/// drops the lock and makes another
#[derive(Default)]
pub struct Entry {
    /// The receiver's real uid and the signal it was made for
    key: Option<(crate::task::Uid, Signal)>,
    q: Option<Box<SigQueue>>,
}

impl Entry {
    /// For zombie (or soon zombie) `z`'s notice
    pub fn child(z: Zombie) -> Self {
        let table = TASKLIST.read();
        let r = receiver(&table, z);
        let pre = r
            .as_ref()
            .and_then(|r| Some((super::target_in(&table, &r.to)?, r.sig?)));
        drop(table);
        drop(r);
        Self::make(pre)
    }

    /// For SIGCHLD to `parent`'s process (an untraced zombie reparented
    /// to it)
    pub fn parent(parent: &TaskRef) -> Self {
        let table = TASKLIST.read();
        let to = adopter(&table, parent);
        let pre = to
            .as_ref()
            .and_then(|to| Some((super::target_in(&table, to)?, SIGCHLD)));
        drop(table);
        drop(to);
        Self::make(pre)
    }

    /// An entry for `pre`'s receiver and signal (TASKLIST not held); its
    /// info is filled in when it is queued
    fn make(pre: Option<(super::Target, Signal)>) -> Self {
        let Some((tg, sig)) = pre else {
            return Self::default();
        };
        let fields = SigFields::Chld {
            pid: 0,
            uid: 0,
            status: 0,
            utime: 0,
            stime: 0,
        };
        let info = SendInfo::Info(SigInfo::new(sig, super::si_code::CLD_EXITED, fields));
        let q = SigQueue::alloc(
            sig,
            // An Info: no namespace to number in (filled when queued)
            info.resolve(sig, &crate::ns::INIT_PID_NS),
            tg.uid,
            tg.limit,
            info.override_rlimit(sig),
        );
        Self {
            key: Some((tg.uid, sig)),
            q,
        }
    }

    /// Under TASKLIST: zombie `z`'s notice would go where this entry
    /// was made for (or needs none)
    pub fn fits(&self, table: &GlobalTaskTable, z: Zombie) -> bool {
        match receiver(table, z) {
            Some(Rcv {
                to, sig: Some(sig), ..
            }) => self.matches(table, &to, sig),
            _ => true,
        }
    }

    /// Under TASKLIST: SIGCHLD to `parent`'s process would go where this
    /// entry was made for (or needs none)
    pub fn fits_parent(&self, table: &GlobalTaskTable, parent: &TaskRef) -> bool {
        adopter(table, parent).is_none_or(|to| self.matches(table, &to, SIGCHLD))
    }

    /// Made for `to`'s user and `sig`, or `to` takes no signal
    fn matches(&self, table: &GlobalTaskTable, to: &TaskRef, sig: Signal) -> bool {
        super::target_in(table, to).is_none_or(|tg| self.key == Some((tg.uid, sig)))
    }
}

/// The thread of `parent`'s process an untraced zombie reparented to it
/// signals, if the signal is sent (SIGCHLD, as [`disposition`] decides)
fn adopter(table: &GlobalTaskTable, parent: &TaskRef) -> Option<TaskRef> {
    super::group_task(table, table.get(parent.pid))
        .filter(|to| disposition(table, to, Some(SIGCHLD)).0.is_some())
}

/// What [`notify`] did: the parent is to release the zombie now
/// (`autoreap`); the signal's wakeups and the entry it left wait for
/// TASKLIST to be dropped ([`Told::finish`])
#[must_use]
#[derive(Default)]
pub struct Told {
    pub autoreap: bool,
    posted: Option<super::Posted>,
    rcv: Option<Rcv>,
    entry: Entry,
}

impl Told {
    /// Wake whoever takes the signal and free what the send left
    /// (TASKLIST not held)
    pub fn finish(self) {
        if let Some(p) = self.posted {
            p.finish();
        }
        drop(self.rcv);
        drop(self.entry);
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
/// do_notify_parent under tasklist_lock), with `entry` checked by
/// [`Entry::fits`] in that section: no wait reaps it before its signal
/// is pending, and a parent its signal wakes finds it.
pub fn notify(table: &GlobalTaskTable, z: Zombie, mut entry: Entry) -> Told {
    let tid = z.tid();
    // Its pidfd pollers first (Linux do_notify_parent: do_notify_pidfd)
    crate::task::percpu::notify_pidfd(table, tid);
    let Some(r) = receiver(table, z) else {
        return Told {
            entry,
            ..Told::default()
        };
    };
    let (sig, autoreap) = (r.sig, r.autoreap);
    let posted = match (sig, chld_notice(table, tid, r.to.pid_ns())) {
        (Some(sig), Some(info)) => {
            let info = SendInfo::Info(info.with_sig(sig));
            super::send_held(table, &r.to, sig, info, super::PidType::Tgid, &mut entry.q)
        }
        _ => None,
    };
    Told {
        autoreap,
        posted,
        rcv: Some(r),
        entry,
    }
}

/// Zombie `tid`'s notice info, read under TASKLIST: its pid (as the
/// receiver's namespace `ns` numbers it: Linux do_notify_parent), uid, wait
/// status, and its CPU times (a leader's: its group's)
fn chld_notice(table: &GlobalTaskTable, tid: Tid, ns: &crate::ns::PidNamespace) -> Option<SigInfo> {
    let t = table.get(tid)?;
    let crate::task::TaskState::Zombie(own) = t.state() else {
        return None;
    };
    let status = match t.signal().map(|s| s.group_exit()) {
        Some(super::GroupExit::Exit(code)) => code,
        _ => own,
    };
    let (utime, stime) = if t.leader() {
        crate::task::percpu::group_times(table, t.task.pid)
    } else {
        t.task.cputime(crate::time::monotonic_ns())
    };
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
