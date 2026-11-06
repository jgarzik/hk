//! Controlling terminals (Linux drivers/tty/tty_jobctrl.c)
//!
//! A session has at most one controlling tty and a tty at most one
//! session: `Tty.ctrl.session`. A process's controlling tty is the tty
//! of its session (Linux `signal->tty`, which every member of the
//! session shares). Unlike Linux, a non-leader cannot drop it alone
//! (TIOCNOTTY by a non-leader changes nothing). The tty holds its
//! session and foreground group as pid references (Linux get_pid), so
//! neither can come to name another one.
//!
//! Locking (Linux tty_lock → tasklist_lock → ctrl.lock): `CTTY_LOCK`
//! serializes giving and taking controlling ttys, so a session never
//! gets two; process groups are looked at under TASKLIST (read), and
//! `Tty.ctrl` nests inside both. Signals go out with none held.

use alloc::sync::Arc;

use super::Tty;
use crate::fs::File;
use crate::fs::flags::{O_ACCMODE, O_WRONLY};
use crate::signal::{SIGCONT, SIGHUP, kill_pgrp_pid};
use crate::sync::spin::Mutex;
use crate::task::percpu::{GlobalTaskTable, TASKLIST, current_pid, current_sid, current_tid};
use crate::task::pid::Pid;
use crate::util::error::KernelError;

/// Serializes controlling-tty changes
static CTTY_LOCK: Mutex<()> = Mutex::new(());

/// The caller's process group and session (Linux task_pgrp,
/// task_session); None for a kernel thread
fn pids(table: &GlobalTaskTable) -> Option<(Arc<Pid>, Arc<Pid>)> {
    let t = table.get(current_tid())?;
    Some((t.pgrp.clone()?, t.session.clone()?))
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

/// The controlling tty of session `s`
fn session_tty(s: &Pid) -> Option<&'static Tty> {
    super::all().iter().copied().find(|t| owns(t, s))
}

/// The caller's controlling tty (Linux get_current_tty)
pub fn current_tty() -> Option<&'static Tty> {
    session_tty(&*session()?)
}

/// Is `tty` the caller's controlling tty?
fn is_current(tty: &Tty) -> bool {
    session().is_some_and(|s| owns(tty, &s))
}

/// Make `tty` the controlling tty of the caller's session, with the
/// caller's group in the foreground (Linux __proc_set_tty); CTTY_LOCK
/// held
fn set_tty(tty: &Tty) {
    let table = TASKLIST.read();
    if let Some((pg, s)) = pids(&table) {
        let mut c = tty.ctrl.lock();
        c.session = Some(s);
        c.pgrp = Some(pg);
    }
}

/// A tty opened without O_NOCTTY becomes the controlling tty of a
/// session leader that has none, if no session has it and the open can
/// read it (Linux tty_open_proc_set_tty). /dev/tty and /dev/console
/// never get here (Linux noctty for them)
pub fn open_set_tty(tty: &Tty, file: &File) {
    if !is_leader() || file.get_flags() & O_ACCMODE == O_WRONLY {
        return;
    }
    let _g = CTTY_LOCK.lock();
    if current_tty().is_none() && tty.ctrl.lock().session.is_none() {
        set_tty(tty);
    }
}

/// TIOCSCTTY (Linux tiocsctty): `steal` (arg 1) takes it from another
/// session, with CAP_SYS_ADMIN
pub fn tiocsctty(tty: &Tty, file: &File, steal: bool) -> Result<(), KernelError> {
    use crate::task::{CAP_SYS_ADMIN, capable};
    let _g = CTTY_LOCK.lock();
    if is_leader() && is_current(tty) {
        return Ok(());
    }
    if !is_leader() || current_tty().is_some() {
        return Err(KernelError::NotPermitted);
    }
    if tty.ctrl.lock().session.is_some() && !(steal && capable(CAP_SYS_ADMIN)) {
        return Err(KernelError::NotPermitted);
    }
    if file.get_flags() & O_ACCMODE == O_WRONLY && !capable(CAP_SYS_ADMIN) {
        return Err(KernelError::NotPermitted);
    }
    set_tty(tty);
    Ok(())
}

/// TIOCNOTTY (Linux no_tty): only for the caller's controlling tty; a
/// session leader gives it up for the whole session
pub fn tiocnotty(tty: &Tty) -> Result<(), KernelError> {
    if !is_current(tty) {
        return Err(KernelError::NotTty);
    }
    disassociate_ctty();
    Ok(())
}

/// A session leader gives up its controlling tty, by TIOCNOTTY or at
/// exit (Linux disassociate_ctty): its foreground group gets SIGHUP and
/// SIGCONT, and the session has no tty any more. No-op for others. At
/// exit Linux hangs the tty up instead (tty_vhangup_session); hk has no
/// hangup.
pub fn disassociate_ctty() {
    if !is_leader() {
        return;
    }
    let pgrp = {
        let _g = CTTY_LOCK.lock();
        let Some(tty) = current_tty() else {
            return;
        };
        let mut c = tty.ctrl.lock();
        c.session = None;
        c.pgrp.take()
    };
    if let Some(pg) = pgrp {
        kill_pgrp_pid(&pg, SIGHUP);
        kill_pgrp_pid(&pg, SIGCONT);
    }
}

/// A background process of the session changing `tty` (`sig` SIGTTOU)
/// or reading it (SIGTTIN) (Linux __tty_check_change): its group gets
/// `sig` and the call restarts once it is handled; ignored or blocked,
/// a change goes ahead and a read is EIO; an orphaned group gets EIO.
/// hk has no group stop, so where Linux would stop the group (SIG_DFL)
/// the signal is sent and the call fails with EIO instead of
/// restarting forever
pub fn check_change(tty: &Tty, sig: u32) -> Result<(), KernelError> {
    use crate::signal::{Disposition, SIGTTIN, disposition};
    let Some((pg, s)) = pids(&TASKLIST.read()) else {
        return Ok(());
    };
    let fg = {
        let c = tty.ctrl.lock();
        if !c
            .session
            .as_deref()
            .is_some_and(|t| core::ptr::eq(t, &raw const *s))
        {
            return Ok(());
        }
        c.pgrp.clone()
    };
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
    match d {
        Disposition::Caught => Err(KernelError::RestartSys),
        _ => Err(KernelError::Io),
    }
}

/// TIOCGPGRP (Linux tiocgpgrp): the foreground group of the caller's
/// controlling tty, 0 if none
pub fn tiocgpgrp(tty: &Tty) -> Result<u32, KernelError> {
    if !is_current(tty) {
        return Err(KernelError::NotTty);
    }
    Ok(tty.ctrl.lock().pgrp.as_ref().map_or(0, |p| p.nr()))
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
        n => crate::task::pid::find_pgrp(n),
    };
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
        .and_then(|m| m.session.clone())
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
        .map(|s| s.nr())
        .ok_or(KernelError::NotTty)
}
