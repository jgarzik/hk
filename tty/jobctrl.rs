//! Controlling terminals (Linux drivers/tty/tty_jobctrl.c)
//!
//! A session has at most one controlling tty and a tty at most one
//! session: `Tty.ctrl.session`. A process's controlling tty is the tty
//! of its session (Linux `signal->tty`, which every member of the
//! session shares). Unlike Linux, a non-leader cannot drop it alone
//! (TIOCNOTTY by a non-leader changes nothing).
//!
//! Locking: `CTTY_LOCK` serializes giving and taking controlling ttys
//! (Linux tty_lock + siglock in __proc_set_tty / session_clear_tty), so
//! a session never gets two; `Tty.ctrl` nests inside it. Signals go out
//! with neither held.

use super::Tty;
use crate::fs::File;
use crate::fs::flags::{O_ACCMODE, O_WRONLY};
use crate::signal::{SIGCONT, SIGHUP, send_signal_to_pgrp};
use crate::sync::spin::Mutex;
use crate::task::Pid;
use crate::task::percpu::{current_pgid, current_pid, current_sid};
use crate::util::error::KernelError;

/// Serializes controlling-tty changes
static CTTY_LOCK: Mutex<()> = Mutex::new(());

/// The caller leads its session (Linux signal->leader)
fn is_leader() -> bool {
    let sid = current_sid();
    sid != 0 && sid == current_pid()
}

/// The controlling tty of session `sid`
fn session_tty(sid: Pid) -> Option<&'static Tty> {
    if sid == 0 {
        return None;
    }
    super::all()
        .iter()
        .copied()
        .find(|t| t.session() == Some(sid))
}

/// The caller's controlling tty (Linux get_current_tty)
pub fn current_tty() -> Option<&'static Tty> {
    session_tty(current_sid())
}

/// Is `tty` the caller's controlling tty?
fn is_current(tty: &Tty) -> bool {
    current_tty().is_some_and(|t| core::ptr::eq(t, tty))
}

/// Make `tty` the controlling tty of the caller's session, with the
/// caller's group in the foreground (Linux __proc_set_tty); CTTY_LOCK
/// held
fn set_tty(tty: &Tty) {
    let mut c = tty.ctrl.lock();
    c.session = Some(current_sid());
    c.pgrp = Some(current_pgid());
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
    if current_tty().is_none() && tty.session().is_none() {
        set_tty(tty);
    }
}

/// TIOCSCTTY (Linux tiocsctty): `steal` (arg 1) takes it from another
/// session, with CAP_SYS_ADMIN
pub fn tiocsctty(tty: &Tty, file: &File, steal: bool) -> Result<(), KernelError> {
    use crate::task::{CAP_SYS_ADMIN, capable};
    let _g = CTTY_LOCK.lock();
    let sid = current_sid();
    if is_leader() && tty.session() == Some(sid) {
        return Ok(());
    }
    if !is_leader() || current_tty().is_some() {
        return Err(KernelError::NotPermitted);
    }
    if tty.session().is_some() && !(steal && capable(CAP_SYS_ADMIN)) {
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
        send_signal_to_pgrp(pg, SIGHUP);
        send_signal_to_pgrp(pg, SIGCONT);
    }
}

/// TIOCGPGRP (Linux tiocgpgrp): the foreground group of the caller's
/// controlling tty, 0 if none
pub fn tiocgpgrp(tty: &Tty) -> Result<Pid, KernelError> {
    if !is_current(tty) {
        return Err(KernelError::NotTty);
    }
    Ok(tty.pgrp().unwrap_or(0))
}

/// TIOCSPGRP (Linux tiocspgrp): a group of the caller's session becomes
/// the foreground group of its controlling tty
pub fn tiocspgrp(tty: &Tty, pgrp: i32) -> Result<(), KernelError> {
    let pgrp = Pid::try_from(pgrp).map_err(|_| KernelError::InvalidArgument)?;
    let sid = current_sid();
    if !is_current(tty) {
        return Err(KernelError::NotTty);
    }
    // The group's session, from any of its processes
    let members = crate::task::percpu::pgrp_pids(pgrp);
    let Some(&p) = members.first() else {
        return Err(KernelError::NoProcess);
    };
    if crate::task::percpu::lookup_task_sid(p) != Some(sid) {
        return Err(KernelError::NotPermitted);
    }
    let mut c = tty.ctrl.lock();
    if c.session != Some(sid) {
        return Err(KernelError::NotTty);
    }
    c.pgrp = Some(pgrp);
    Ok(())
}

/// TIOCGSID (Linux tiocgsid): the session of the caller's controlling
/// tty
pub fn tiocgsid(tty: &Tty) -> Result<Pid, KernelError> {
    if !is_current(tty) {
        return Err(KernelError::NotTty);
    }
    tty.session().ok_or(KernelError::NotTty)
}
