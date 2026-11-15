//! Controlling terminals (Linux drivers/tty/tty_jobctrl.c)
//!
//! A session has at most one controlling tty and a tty at most one
//! session: `Tty.ctrl.session`. A process's controlling tty is its own
//! (Linux `signal->tty`: `SignalStruct.ctty`): set for a session leader
//! when it acquires one, inherited at fork, cleared by setsid, by
//! TIOCNOTTY, by a hangup and for the whole session when the session
//! loses the tty. The tty holds its session and foreground group as pid
//! references (Linux get_pid), so neither can come to name another one.
//! A session leader whose tty was hung up keeps its foreground group
//! (Linux signal->tty_old_pgrp), signalled when the leader exits.
//!
//! Locking (Linux tty_lock → tasklist_lock → siglock → ctrl.lock):
//! `CTTY_LOCK` serializes giving and taking controlling ttys, so a
//! session never gets two; process groups and sessions are walked
//! under TASKLIST (read); `SignalStruct.ctty` and `Tty.ctrl` are leaves
//! inside both, never nested. Signals go out with none held; pid
//! references are dropped after the locks.

use alloc::sync::Arc;

use super::Tty;
use crate::fs::File;
use crate::fs::flags::{O_ACCMODE, O_WRONLY};
use crate::signal::{SIGCONT, SIGHUP, SignalStruct, kill_pgrp_pid};
use crate::sync::spin::Mutex;
use crate::task::percpu::{GlobalTaskTable, TASKLIST, current_pid, current_sid};
use crate::task::pid::Pid;
use crate::util::error::KernelError;

/// Serializes controlling-tty changes
static CTTY_LOCK: Mutex<()> = Mutex::new(());

/// A process's controlling tty (Linux signal->tty) and the foreground
/// group of one it lost to a hangup while leading its session (Linux
/// signal->tty_old_pgrp); `SignalStruct.ctty`, a spin leaf
pub struct Ctty {
    tty: Option<&'static Tty>,
    old_pgrp: Option<Arc<Pid>>,
}

impl Ctty {
    pub const fn new() -> Self {
        Self {
            tty: None,
            old_pgrp: None,
        }
    }

    /// The controlling tty
    pub fn tty(&self) -> Option<&'static Tty> {
        self.tty
    }

    /// A forked process inherits its parent's controlling tty `tty`,
    /// not the old group (Linux copy_process; tty_old_pgrp starts NULL)
    pub fn inherit(&mut self, tty: Option<&'static Tty>) {
        self.tty = tty;
    }
}

/// The caller's process group and session (Linux task_pgrp,
/// task_session); None for a kernel thread
fn pids(table: &GlobalTaskTable) -> Option<(Arc<Pid>, Arc<Pid>)> {
    let me = crate::task::percpu::current();
    let t = table.view(&me)?;
    Some((t.pgrp().cloned()?, t.session().cloned()?))
}

/// The caller's session
fn session() -> Option<Arc<Pid>> {
    pids(&TASKLIST.read()).map(|(_, s)| s)
}

/// The caller leads its session (Linux signal->leader)
fn is_leader() -> bool {
    let sid = current_sid();
    sid != 0 && sid == current_pid()
}

/// Is `s` the session of `tty`?
fn owns(tty: &Tty, s: &Pid) -> bool {
    tty.ctrl
        .lock()
        .session
        .as_deref()
        .is_some_and(|t| core::ptr::eq(t, s))
}

/// The caller's controlling tty (Linux get_current_tty)
pub fn current_tty() -> Option<&'static Tty> {
    crate::signal::with_current_signal(|s| s.ctty.lock().tty).flatten()
}

/// Is `tty` the caller's controlling tty (Linux current->signal->tty
/// == tty)?
fn is_current(tty: &Tty) -> bool {
    current_tty().is_some_and(|t| core::ptr::eq(t, tty))
}

/// Take a process's controlling tty away (Linux proc_clear_tty)
pub fn proc_clear_tty(s: &SignalStruct) {
    s.ctty.lock().tty = None;
}

/// Make `tty` the caller's controlling tty, with the caller's session
/// and group on it (Linux __proc_set_tty); CTTY_LOCK held
fn proc_set_tty(tty: &'static Tty) {
    let table = TASKLIST.read();
    let Some((pg, s)) = pids(&table) else {
        return;
    };
    let old_ctrl = {
        let mut c = tty.ctrl.lock();
        (c.session.replace(s), c.pgrp.replace(pg))
    };
    let old_pgrp = crate::signal::current_signal().and_then(|sig| {
        let mut c = sig.ctty.lock();
        c.tty = Some(tty);
        c.old_pgrp.take()
    });
    drop(table);
    drop((old_ctrl, old_pgrp));
}

/// No member of session `s` has a controlling tty any more (Linux
/// session_clear_tty: proc_clear_tty of each)
fn session_clear(s: &Pid) {
    let table = TASKLIST.read();
    for t in table.session(s) {
        if let Some(sig) = t.signal() {
            proc_clear_tty(sig);
        }
    }
}

/// A tty opened without O_NOCTTY becomes the controlling tty of a
/// session leader that has none, if no session has it and the open can
/// read it (Linux tty_open_proc_set_tty). /dev/tty and /dev/console
/// never get here (Linux noctty for them)
pub fn open_set_tty(tty: &'static Tty, file: &File) {
    if !is_leader() || file.get_flags() & O_ACCMODE == O_WRONLY {
        return;
    }
    let _g = CTTY_LOCK.lock();
    if current_tty().is_none() && tty.ctrl.lock().session.is_none() {
        proc_set_tty(tty);
    }
}

/// TIOCSCTTY (Linux tiocsctty): `steal` (arg 1) takes it from another
/// session, with CAP_SYS_ADMIN, whose members then have none
pub fn tiocsctty(tty: &'static Tty, file: &File, steal: bool) -> Result<(), KernelError> {
    use crate::task::{CAP_SYS_ADMIN, capable};
    let _g = CTTY_LOCK.lock();
    if is_leader() && session().is_some_and(|s| owns(tty, &s)) {
        return Ok(());
    }
    if !is_leader() || current_tty().is_some() {
        return Err(KernelError::NotPermitted);
    }
    let held = tty.ctrl.lock().session.clone();
    if let Some(s) = held {
        if !(steal && capable(CAP_SYS_ADMIN)) {
            return Err(KernelError::NotPermitted);
        }
        session_clear(&s);
    }
    if file.get_flags() & O_ACCMODE == O_WRONLY && !capable(CAP_SYS_ADMIN) {
        return Err(KernelError::NotPermitted);
    }
    proc_set_tty(tty);
    Ok(())
}

/// TIOCNOTTY (Linux no_tty): only for the caller's controlling tty; a
/// session leader gives it up for the whole session, any other process
/// for itself
pub fn tiocnotty(tty: &Tty) -> Result<(), KernelError> {
    if !is_current(tty) {
        return Err(KernelError::NotTty);
    }
    disassociate_ctty(false);
    if let Some(sig) = crate::signal::current_signal() {
        proc_clear_tty(&sig);
    }
    Ok(())
}

/// A hangup takes the tty's session and foreground group (Linux
/// __tty_hangup under ctrl.lock); the window size stays
pub(super) fn hangup_take(tty: &Tty) -> (Option<Arc<Pid>>, Option<Arc<Pid>>) {
    let _g = CTTY_LOCK.lock();
    let mut c = tty.ctrl.lock();
    (c.session.take(), c.pgrp.take())
}

/// A hung up tty leaves its session (Linux tty_signal_session_leader):
/// each member whose controlling tty it was has none; the session
/// leader gets SIGHUP and SIGCONT and keeps the foreground group as its
/// old one; with `exit_session` (the leader is exiting) the foreground
/// group gets SIGHUP too, if the leader is still there
pub(super) fn signal_session_leader(
    tty: &Tty,
    session: Option<Arc<Pid>>,
    pgrp: Option<Arc<Pid>>,
    exit_session: bool,
) {
    use crate::signal::{SendInfo, kill_pid_info};
    let Some(s) = session else {
        return;
    };
    // The leader's old group, dropped once no lock is held (one
    // session leader: nothing to collect)
    let mut gone = None;
    let leader = {
        let table = TASKLIST.read();
        let mut leader = false;
        for t in table.session(&s) {
            let Some(sig) = t.signal() else {
                continue;
            };
            let mut c = sig.ctty.lock();
            if c.tty.is_some_and(|ct| core::ptr::eq(ct, tty)) {
                c.tty = None;
            }
            let leads = t.leader() && t.thread_pid().is_some_and(|p| Arc::ptr_eq(p, &s));
            if leads {
                leader = true;
                if let Some(pg) = &pgrp {
                    gone = c.old_pgrp.replace(pg.clone());
                }
            }
        }
        leader
    };
    drop(gone);
    if !leader {
        return;
    }
    let _ = kill_pid_info(&s, SIGHUP, SendInfo::Kernel, |_, _| Ok(()));
    let _ = kill_pid_info(&s, SIGCONT, SendInfo::Kernel, |_, _| Ok(()));
    if exit_session && let Some(pg) = pgrp {
        kill_pgrp_pid(&pg, SIGHUP);
    }
}

/// A session leader gives up its controlling tty (Linux
/// disassociate_ctty). At exit (`on_exit`) the tty is hung up (Linux
/// tty_vhangup_session), or with none the group of one a hangup took
/// gets SIGHUP and SIGCONT; by TIOCNOTTY the foreground group gets
/// SIGHUP and SIGCONT. Then the tty has no session and no member of the
/// session a controlling tty. No-op for others
pub fn disassociate_ctty(on_exit: bool) {
    if !is_leader() {
        return;
    }
    let me = crate::signal::current_signal();
    match current_tty() {
        Some(tty) if on_exit => tty.hangup(true),
        Some(tty) => {
            if let Some(pg) = tty.pgrp() {
                kill_pgrp_pid(&pg, SIGHUP);
                kill_pgrp_pid(&pg, SIGCONT);
            }
        }
        None if on_exit => {
            let old = me.as_ref().and_then(|s| s.ctty.lock().old_pgrp.take());
            if let Some(pg) = old {
                kill_pgrp_pid(&pg, SIGHUP);
                kill_pgrp_pid(&pg, SIGCONT);
            }
            return;
        }
        None => {}
    }
    let old_ctrl = {
        let _g = CTTY_LOCK.lock();
        current_tty().map(|tty| {
            let mut c = tty.ctrl.lock();
            (c.session.take(), c.pgrp.take())
        })
    };
    drop(old_ctrl);
    let old = me.as_ref().and_then(|s| s.ctty.lock().old_pgrp.take());
    drop(old);
    if let Some(s) = session() {
        session_clear(&s);
    }
}

/// The tty's last close (Linux tty_release's session_clear_tty, then
/// the tty_struct freed): no member of its session has it, no session
/// has it and no group is in the foreground; the window size starts
/// afresh
pub fn session_clear_tty(tty: &Tty) {
    let (s, pg) = {
        let _g = CTTY_LOCK.lock();
        let s = tty.ctrl.lock().session.clone();
        if let Some(s) = &s {
            session_clear(s);
        }
        let mut c = tty.ctrl.lock();
        let old = core::mem::replace(&mut *c, super::TtyCtrl::new());
        (old.session, old.pgrp)
    };
    drop((s, pg));
}

/// A background process changing its controlling tty `tty` (`sig`
/// SIGTTOU) or reading it (SIGTTIN) (Linux __tty_check_change): its
/// group gets `sig` and the call restarts once it is handled (or the
/// group, by default, is stopped and continued); ignored or blocked, a
/// change goes ahead and a read is EIO; an orphaned group gets EIO
pub fn check_change(tty: &Tty, sig: crate::signal::Signal) -> Result<(), KernelError> {
    use crate::signal::{Disposition, SIGTTIN, disposition};
    if !is_current(tty) {
        return Ok(());
    }
    let Some((pg, _)) = pids(&TASKLIST.read()) else {
        return Ok(());
    };
    let fg = tty.ctrl.lock().pgrp.clone();
    match fg {
        Some(fg) if !Arc::ptr_eq(&fg, &pg) => {}
        _ => return Ok(()),
    }
    let d = disposition(sig);
    if d == Disposition::Ignored {
        return if sig == SIGTTIN {
            Err(KernelError::Io)
        } else {
            Ok(())
        };
    }
    if crate::task::percpu::pgrp_orphaned(&pg) {
        return Err(KernelError::Io);
    }
    kill_pgrp_pid(&pg, sig);
    Err(KernelError::RestartSys)
}

/// TIOCGPGRP (Linux tiocgpgrp): the foreground group of the caller's
/// controlling tty, 0 if none
pub fn tiocgpgrp(tty: &Tty) -> Result<u32, KernelError> {
    if !is_current(tty) {
        return Err(KernelError::NotTty);
    }
    // In the caller's namespace (Linux tiocgpgrp: pid_vnr)
    Ok(tty.ctrl.lock().pgrp.as_ref().map_or(0, |p| p.vnr()))
}

/// TIOCSPGRP (Linux tiocspgrp): a group of the caller's session becomes
/// the foreground group of its controlling tty. The group is checked
/// and stored under TASKLIST, so it cannot change in between
pub fn tiocspgrp(tty: &Tty, pgrp: i32) -> Result<(), KernelError> {
    match check_change(tty, crate::signal::SIGTTOU) {
        Err(KernelError::Io) => return Err(KernelError::NotTty),
        r => r?,
    }
    let nr = u64::try_from(pgrp).map_err(|_| KernelError::InvalidArgument)?;
    // A group id names a live pid (Linux find_vpid); 0 never does
    let pg = match nr {
        0 => None,
        n => crate::task::pid::find_pgrp(crate::task::pid::current_pid_ns(), n),
    };
    if !is_current(tty) {
        return Err(KernelError::NotTty);
    }
    let table = TASKLIST.read();
    let (_, s) = pids(&table).ok_or(KernelError::NotTty)?;
    let mut c = tty.ctrl.lock();
    if !c
        .session
        .as_deref()
        .is_some_and(|t| core::ptr::eq(t, &raw const *s))
    {
        return Err(KernelError::NotTty);
    }
    let pg = pg.ok_or(KernelError::NoProcess)?;
    // Its session, from any member (Linux session_of_pgrp)
    let in_session = table
        .pgrp(&pg)
        .next()
        .and_then(|m| m.session().cloned())
        .is_some_and(|ms| Arc::ptr_eq(&ms, &s));
    if !in_session {
        return Err(KernelError::NotPermitted);
    }
    c.pgrp = Some(pg);
    Ok(())
}

/// TIOCGSID (Linux tiocgsid): the session of the caller's controlling
/// tty
pub fn tiocgsid(tty: &Tty) -> Result<u32, KernelError> {
    if !is_current(tty) {
        return Err(KernelError::NotTty);
    }
    tty.ctrl
        .lock()
        .session
        .as_ref()
        .map(|s| s.vnr())
        .ok_or(KernelError::NotTty)
}
