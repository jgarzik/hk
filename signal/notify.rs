//! Telling a parent or tracer about a child (Linux do_notify_parent,
//! do_notify_parent_cldstop in kernel/signal.c)

use super::{SIGCHLD, SendInfo, SigFields, SigHandler, SigInfo, SigQueue, sa_flags};
use crate::task::Tid;
use crate::task::percpu::{GlobalTaskTable, TASKLIST, TaskRef};
use alloc::boxed::Box;
use alloc::sync::Arc;

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

/// Who is told of zombie `tid`: its tracer, else its real parent
/// (`parent`), through `to`, the thread of that process a group signal
/// is checked against; the signal (its exit signal, or SIGCHLD to a
/// tracer that is not the parent, to a thread, or to an image that did
/// not ask for it) and whether it is traced
struct Rcv {
    parent: TaskRef,
    to: TaskRef,
    sig: u32,
    traced: bool,
}

/// [`Rcv`] of `tid`, read under TASKLIST
fn receiver(table: &GlobalTaskTable, tid: Tid) -> Option<Rcv> {
    let t = table.get(tid)?;
    let real = t.real_parent.as_ref().and_then(|w| w.upgrade());
    let tracer = t.tracer();
    let traced = tracer.is_some();
    let parent = tracer.or(real.clone())?;
    // A tracer that is not the parent, or a thread: SIGCHLD
    let reparented = traced && !real.as_ref().is_some_and(|r| Arc::ptr_eq(r, &parent));
    let mut sig = if t.leader && !reparented {
        t.exit_signal as u32
    } else {
        SIGCHLD
    };
    // A custom exit signal only to the image that asked for it (Linux:
    // parent_exec_id != parent->self_exec_id makes it SIGCHLD)
    if sig != SIGCHLD && t.parent_exec_id != crate::task::self_exec_id(parent.pid) {
        sig = SIGCHLD;
    }
    if sig > 64 {
        return None;
    }
    let to = super::group_task(table, table.get(parent.pid))?;
    Some(Rcv {
        parent,
        to,
        sig,
        traced,
    })
}

/// The entry a zombie's notice is queued with, made before TASKLIST is
/// taken (nothing allocates under it) and charged to the user it would
/// go to then; under the lock, [`Entry::fits`] tells whether that is
/// still so, else the caller drops the lock and makes another
#[derive(Default)]
pub struct Entry {
    /// The receiver's real uid and the signal it was made for
    key: Option<(crate::task::Uid, u32)>,
    q: Option<Box<SigQueue>>,
}

impl Entry {
    /// For zombie (or soon zombie) `tid`'s notice
    pub fn child(tid: Tid) -> Self {
        let table = TASKLIST.read();
        let pre =
            receiver(&table, tid).and_then(|r| Some((super::target_in(&table, &r.to)?, r.sig)));
        drop(table);
        Self::make(pre)
    }

    /// For SIGCHLD to `parent`'s process (a zombie reparented to it)
    pub fn parent(parent: &TaskRef) -> Self {
        let table = TASKLIST.read();
        let pre = super::group_task(&table, table.get(parent.pid))
            .and_then(|to| Some((super::target_in(&table, &to)?, SIGCHLD)));
        drop(table);
        Self::make(pre)
    }

    /// An entry for `pre`'s receiver and signal (TASKLIST not held); its
    /// info is filled in when it is queued
    fn make(pre: Option<(super::Target, u32)>) -> Self {
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
            info.resolve(sig),
            tg.uid,
            tg.limit,
            info.override_rlimit(sig),
        );
        Self {
            key: Some((tg.uid, sig)),
            q,
        }
    }

    /// Under TASKLIST: zombie `tid`'s notice would go where this entry
    /// was made for (or needs none)
    pub fn fits(&self, table: &GlobalTaskTable, tid: Tid) -> bool {
        let Some(r) = receiver(table, tid) else {
            return true;
        };
        self.matches(table, &r.to, r.sig)
    }

    /// Under TASKLIST: SIGCHLD to `parent`'s process would go where this
    /// entry was made for (or needs none)
    pub fn fits_parent(&self, table: &GlobalTaskTable, parent: &TaskRef) -> bool {
        let Some(to) = super::group_task(table, table.get(parent.pid)) else {
            return true;
        };
        self.matches(table, &to, SIGCHLD)
    }

    /// Made for `to`'s user and `sig`, or `to` takes no signal
    fn matches(&self, table: &GlobalTaskTable, to: &TaskRef, sig: u32) -> bool {
        super::target_in(table, to).is_none_or(|tg| self.key == Some((tg.uid, sig)))
    }
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

/// Zombie `tid` tells whoever waits for it that it is gone (Linux
/// do_notify_parent): its tracer, or for a leader whose group is gone
/// its parent, gets its exit signal (SIGCHLD to a tracer that is not
/// the parent) with CLD_EXITED/KILLED/DUMPED, its pid, uid, status and
/// the group's CPU times. Autoreap: an untraced child whose parent
/// ignores SIGCHLD (no signal then) or set SA_NOCLDWAIT.
///
/// Under TASKLIST's write lock, in the section that made it reportable
/// (Linux exit_notify, release_task, reparent_leader call
/// do_notify_parent under tasklist_lock), with `entry` checked by
/// [`Entry::fits`] in that section: no wait reaps it before its signal
/// is pending, and a parent its signal wakes finds it.
pub fn notify(table: &GlobalTaskTable, tid: Tid, mut entry: Entry) -> Told {
    let Some(r) = receiver(table, tid) else {
        return Told {
            entry,
            ..Told::default()
        };
    };
    let action = table
        .get(r.parent.tid())
        .and_then(|p| p.sighand.as_ref().and_then(|h| h.get_action(SIGCHLD)));
    let mut sig = r.sig;
    let mut autoreap = false;
    if !r.traced && sig == SIGCHLD {
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
    let posted = match chld_notice(table, tid) {
        Some(mut info) if sig != 0 => {
            info.signo = sig as i32;
            super::send_held(table, &r.to, sig, info, &mut entry.q)
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

/// Zombie `tid`'s notice info, read under TASKLIST: its pid, uid, wait
/// status, and its CPU times (a leader's: its group's)
fn chld_notice(table: &GlobalTaskTable, tid: Tid) -> Option<SigInfo> {
    let t = table.get(tid)?;
    let crate::task::TaskState::Zombie(own) = t.state else {
        return None;
    };
    let status = match t.signal.as_ref().map(|s| s.group_exit()) {
        Some(super::GroupExit::Exit(code)) => code,
        _ => own,
    };
    let (utime, stime) = if t.leader {
        crate::task::percpu::group_times(table, t.task.pid)
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
    Some(SigInfo::new(SIGCHLD, code, fields))
}
