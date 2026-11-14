//! Signal-driven I/O (Linux fs/fcntl.c: struct fown_struct, f_setown,
//! F_SETOWN_EX, F_SETSIG, fasync_helper, kill_fasync, send_sigio)
//!
//! A file's SIGIO owner ([`FOwner`], Linux file->f_owner) is allocated on
//! first use (F_SETOWN, F_SETOWN_EX, F_SETSIG or the file's first fasync
//! entry, Linux file_f_owner_allocate) and lives as long as the file.
//! An object that raises SIGIO keeps a [`FasyncList`] (Linux
//! fasync_struct list); its `FileOps::fasync` puts the file on it with
//! [`fasync_helper`], which keeps O_ASYNC equal to "on a list". An entry
//! names the file's owner (a reference to the `FOwner`, not to the file)
//! and the descriptor it was armed through: the file's last close takes
//! it off every list (`File`'s drop calls `->fasync(-1, off)`, Linux
//! __fput), and an entry left behind could only signal a stale owner.
//!
//! ## Locking
//!
//! `FasyncList.list` is a sleeping `sync::Mutex` (Linux: fasync_lock for
//! changes, RCU for kill_fasync): [`kill_fasync`] sends its signals under
//! it, so it runs in thread context with no spin lock held, the rule for
//! every signal sender (doc/LOCKING.md 3.7). Under it: `File.f_lock` (the
//! helper sets O_ASYNC with the list change, Linux f_lock), `FOwner.st`
//! (spin leaf: a snapshot is taken and the lock dropped before sending),
//! then the signal locks (TASKLIST read, Task.sig, shared_pending).

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::fs::File;
use crate::io::poll::{
    POLLERR, POLLHUP, POLLIN, POLLMSG, POLLOUT, POLLPRI, POLLRDBAND, POLLRDNORM, POLLWRBAND,
    POLLWRNORM,
};
use crate::mm::page_alloc::Gfp;
use crate::signal::siginfo::{SigFields, SigInfo, si_code};
use crate::signal::{
    SIGIO, SIGURG, SendInfo, Signal, group_task, send_group_signal, send_sig_info, valid_signal,
};
use crate::sync::IrqRwLock;
use crate::sync::rcu::RcuHead;
use crate::sync::spin::Mutex;
use crate::task::Uid;
use crate::task::percpu::{GlobalTaskTable, TASKLIST, TaskRef, TaskView};
use crate::task::pid::Pid;
use crate::uaccess::{get_user, put_user};
use crate::util::error::KernelError;
use crate::util::kalloc::try_arc;
use crate::util::kalloc::with_gfp;
use crate::util::list::Link;
use crate::util::rculist::RcuList;

/// SIGPOLL si_codes, the `band` of [`kill_fasync`] (asm-generic
/// siginfo.h)
pub const POLL_IN: i32 = 1;
pub const POLL_OUT: i32 = 2;
pub const POLL_MSG: i32 = 3;
pub const POLL_ERR: i32 = 4;
pub const POLL_PRI: i32 = 5;
pub const POLL_HUP: i32 = 6;

/// F_SETOWN_EX owner types
const F_OWNER_TID: i32 = 0;
const F_OWNER_PID: i32 = 1;
const F_OWNER_PGRP: i32 = 2;

/// What an owner pid names (Linux enum pid_type: PIDTYPE_PID, _TGID,
/// _PGID)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PidType {
    /// One thread (F_OWNER_TID; the type of an owner never set)
    #[default]
    Tid,
    /// A process (F_SETOWN > 0, F_OWNER_PID)
    Tgid,
    /// A process group (F_SETOWN < 0, F_OWNER_PGRP)
    Pgrp,
}

/// The owner's state (Linux fown_struct's fields)
#[derive(Clone, Default)]
struct Owner {
    /// Who is signalled; the reference keeps the number from being
    /// reused
    pid: Option<Arc<Pid>>,
    kind: PidType,
    /// The setter's real and effective uid (sigio_perm)
    uid: Uid,
    euid: Uid,
    /// F_SETSIG: None (0) = SIGIO without info
    signum: Option<Signal>,
}

/// A file's SIGIO owner (Linux struct fown_struct)
#[derive(Default)]
pub struct FOwner {
    /// Linux fown->lock: an IRQ-safe rwlock, its read side held across a
    /// send (the owner's pid borrowed, no reference taken)
    st: IrqRwLock<Owner>,
}

impl FOwner {
    /// A copy of the state, the lock released
    fn get(&self) -> Owner {
        self.st.read().clone()
    }

    /// Linux __f_setown: `pid` of `kind` with the caller's uids, unless
    /// an owner is set and not `force`; the old pid goes after unlocking
    fn set(&self, pid: Option<Arc<Pid>>, kind: PidType, force: bool) {
        let cred = crate::task::current_cred();
        let mut st = self.st.write();
        if !force && st.pid.is_some() {
            drop(st);
            return;
        }
        if pid.is_some() {
            st.uid = cred.uid;
            st.euid = cred.euid;
        }
        st.kind = kind;
        let old = core::mem::replace(&mut st.pid, pid);
        drop(st);
        drop(old);
    }
}

impl File {
    /// The SIGIO owner, if one was ever allocated
    pub fn f_owner(&self) -> Option<&Arc<FOwner>> {
        self.f_owner.get()
    }

    /// The SIGIO owner, allocated on first use (Linux
    /// file_f_owner_allocate)
    fn f_owner_alloc(&self) -> Result<&Arc<FOwner>, KernelError> {
        self.f_owner.try_call_once(|| try_arc(FOwner::default()))
    }
}

/// The `Pid` the caller numbers `nr` while a task uses it as its pid
/// or process group (Linux find_vpid with pid_task / the group's list
/// checked, as f_setown's callers do)
fn find_owner(nr: u32) -> Option<Arc<Pid>> {
    let pid = crate::task::pid::find_vpid(nr)?;
    let used = {
        let table = TASKLIST.read();
        table.pid_tid(&pid).is_some() || table.pgrp(&pid).next().is_some()
    };
    used.then_some(pid)
}

/// `who` > 0 a process, < 0 a process group, 0 none (Linux f_setown):
/// ESRCH if none exists, EINVAL for INT_MIN; `force` = false keeps an
/// owner already set (__f_setown)
pub fn f_setown(file: &File, who: i32, force: bool) -> Result<(), KernelError> {
    if who == i32::MIN {
        return Err(KernelError::InvalidArgument);
    }
    let kind = if who < 0 {
        PidType::Pgrp
    } else {
        PidType::Tgid
    };
    let own = file.f_owner_alloc()?;
    let pid = match who.unsigned_abs() {
        0 => None,
        nr => Some(find_owner(nr).ok_or(KernelError::NoProcess)?),
    };
    own.set(pid, kind, force);
    Ok(())
}

/// Linux __f_setown with a struct pid (a tty's process group, the
/// caller's own pid); `force` false keeps an owner already set
pub fn f_setown_pid(
    file: &File,
    pid: Arc<Pid>,
    kind: PidType,
    force: bool,
) -> Result<(), KernelError> {
    file.f_owner_alloc()?.set(Some(pid), kind, force);
    Ok(())
}

/// The owner's number in the caller's namespace while it names a task
/// of its type (Linux pid_task(pid, type), pid_vnr), 0 otherwise
fn owner_nr(o: &Owner) -> i32 {
    let Some(pid) = &o.pid else {
        return 0;
    };
    let table = TASKLIST.read();
    let live = match o.kind {
        PidType::Tid => table.pid_tid(pid).is_some(),
        PidType::Tgid => table
            .pid_tid(pid)
            .and_then(|t| table.get(t))
            .is_some_and(|t| t.task.tid() == t.task.pid),
        PidType::Pgrp => table.pgrp(pid).next().is_some(),
    };
    if live { pid.vnr() as i32 } else { 0 }
}

/// F_GETOWN (Linux f_getown): a process group is negative
pub fn f_getown(file: &File) -> i32 {
    let Some(o) = file.f_owner().map(|own| own.get()) else {
        return 0;
    };
    let nr = owner_nr(&o);
    if o.kind == PidType::Pgrp { -nr } else { nr }
}

/// struct f_owner_ex
#[repr(C)]
#[derive(Clone, Copy)]
struct FOwnerEx {
    kind: i32,
    pid: i32,
}
crate::pod!(FOwnerEx { kind, pid });

/// F_SETOWN_EX (Linux f_setown_ex): EINVAL for an unknown type, ESRCH
/// for a pid no task uses; pid 0 clears
pub fn f_setown_ex(file: &File, arg: u64) -> Result<(), KernelError> {
    let ex: FOwnerEx = get_user(arg).map_err(|_| KernelError::BadAddress)?;
    let kind = match ex.kind {
        F_OWNER_TID => PidType::Tid,
        F_OWNER_PID => PidType::Tgid,
        F_OWNER_PGRP => PidType::Pgrp,
        _ => return Err(KernelError::InvalidArgument),
    };
    let own = file.f_owner_alloc()?;
    let pid = match ex.pid {
        0 => None,
        nr => Some(
            u32::try_from(nr)
                .ok()
                .and_then(find_owner)
                .ok_or(KernelError::NoProcess)?,
        ),
    };
    own.set(pid, kind, true);
    Ok(())
}

/// F_GETOWN_EX (Linux f_getown_ex): an owner never set is a thread, 0
pub fn f_getown_ex(file: &File, arg: u64) -> Result<(), KernelError> {
    let o = file.f_owner().map(|own| own.get()).unwrap_or_default();
    let ex = FOwnerEx {
        kind: match o.kind {
            PidType::Tid => F_OWNER_TID,
            PidType::Tgid => F_OWNER_PID,
            PidType::Pgrp => F_OWNER_PGRP,
        },
        pid: owner_nr(&o),
    };
    put_user(arg, ex).map_err(|_| KernelError::BadAddress)
}

/// F_SETSIG (Linux f_owner_sig): EINVAL past the last signal
pub fn f_setsig(file: &File, sig: u64) -> Result<(), KernelError> {
    // An int (Linux argi) widened to valid_signal's unsigned long, so
    // a negative one is out of range
    let sig = valid_signal(sig as i32 as u64).ok_or(KernelError::InvalidArgument)?;
    file.f_owner_alloc()?.st.write().signum = sig;
    Ok(())
}

/// F_GETSIG: 0 when never set
pub fn f_getsig(file: &File) -> u32 {
    let sig = file.f_owner().and_then(|own| own.st.read().signum);
    sig.map_or(0, Signal::nr)
}

// =============================================================================
// fasync lists
// =============================================================================

/// What an armed entry signals: the file's owner and the descriptor it
/// was armed through (si_fd); None once the entry is taken off (Linux
/// fa_file = NULL), which a walker that still sees it skips
type FaTarget = Option<(Arc<FOwner>, i32)>;

/// One armed file (Linux fasync_struct), on its object's RCU list and
/// freed a grace period after leaving it
pub struct Fasync {
    /// Linux fa_lock: IRQ-safe rwlock, read by a walker around its
    /// send, written by fasync_helper (a new fd, the entry taken off)
    fa: IrqRwLock<FaTarget>,
    link: Link,
    rcu: RcuHead,
}

crate::adapter!(pub FaList, Fasync, link);
crate::rcu_head!(Fasync, rcu);

impl Fasync {
    /// It signals `owner` (by identity)
    fn is(&self, owner: &Arc<FOwner>) -> bool {
        self.fa
            .read()
            .as_ref()
            .is_some_and(|(o, _)| Arc::ptr_eq(o, owner))
    }
}

/// Serializes changes to every fasync list (Linux fasync_lock): a
/// find-then-insert or remove is one step. Spin, thread context; under
/// `File.f_lock`, above each entry's `fa`
static FASYNC_LOCK: Mutex<()> = Mutex::new(());

/// The files to signal when an object becomes ready (Linux struct
/// fasync_struct *, e.g. pipe->fasync_readers): read under RCU
/// ([`kill_fasync`], any context but hardirq, spin locks held or not),
/// changed under `FASYNC_LOCK` ([`fasync_helper`])
pub struct FasyncList {
    list: RcuList<FaList>,
    /// `list` is not empty: written under `FASYNC_LOCK`, read lock-free
    /// so a wakeup with nobody armed (nearly all) costs one load (Linux
    /// kill_fasync's unlocked `*fp` test); a racing add may be missed,
    /// as in Linux
    armed: AtomicBool,
}

impl FasyncList {
    pub const fn new() -> Self {
        Self {
            list: RcuList::new(),
            armed: AtomicBool::new(false),
        }
    }

    /// Some file is on the list (Linux sock_flag(SOCK_FASYNC) for a
    /// socket's)
    pub fn armed(&self) -> bool {
        self.armed.load(Ordering::Acquire)
    }
}

/// Put `file` on `list` (`on`; an entry already there takes the new
/// `fd`) or take it off (Linux fasync_helper); O_ASYNC follows. True if
/// an entry was added or removed.
pub fn fasync_helper(
    list: &FasyncList,
    file: &File,
    fd: i32,
    on: bool,
) -> Result<bool, KernelError> {
    if !on {
        return Ok(fasync_remove(list, file));
    }
    let owner = file.f_owner_alloc()?.clone();
    // Made before the locks (Linux fasync_alloc)
    let new = try_arc(Fasync {
        fa: IrqRwLock::new(Some((owner.clone(), fd))),
        link: Link::new(),
        rcu: RcuHead::new(),
    })?;
    // Linux fasync_insert_entry: f_lock, then fasync_lock
    let mut fl = file.f_lock();
    let _l = FASYNC_LOCK.lock();
    let g = crate::sync::rcu::read_lock();
    if let Some(e) = list.list.iter(&g).find(|e| e.is(&owner)) {
        if let Some((_, f)) = e.fa.write().as_mut() {
            *f = fd;
        }
        return Ok(false);
    }
    drop(g);
    list.list.push_back(new);
    list.armed.store(true, Ordering::Release);
    *fl |= crate::fs::file::flags::O_ASYNC;
    Ok(true)
}

/// Linux fasync_remove_entry: the entry's target cleared under its
/// `fa` (a walker still seeing it sends nothing), the entry unlinked and
/// freed a grace period later
fn fasync_remove(list: &FasyncList, file: &File) -> bool {
    let Some(owner) = file.f_owner().cloned() else {
        return false;
    };
    let gone = {
        let mut fl = file.f_lock();
        let _l = FASYNC_LOCK.lock();
        let Some(e) = list.list.remove_first(|e| e.is(&owner)) else {
            return false;
        };
        let target = e.item().fa.write().take();
        list.armed.store(!list.list.is_empty(), Ordering::Release);
        *fl &= !crate::fs::file::flags::O_ASYNC;
        (e, target)
    };
    // The owner reference and the entry go after the locks
    let (e, target) = gone;
    drop(target);
    e.defer();
    true
}

/// Signal every file on `list` that the object is ready for `band` (a
/// POLL_* code; Linux kill_fasync, kill_fasync_rcu). `sig` SIGURG
/// reaches only owners that chose a signal (SIGURG has its own path).
/// Any context but hardirq, spin locks held or not: the list is walked
/// under RCU, each entry's `fa` and its owner's `st` read-held around
/// its send, which allocates GFP_ATOMIC (Linux send_sigio).
pub fn kill_fasync(list: &FasyncList, sig: Signal, band: i32) {
    if !list.armed() {
        return;
    }
    let g = crate::sync::rcu::read_lock();
    with_gfp(Gfp::ATOMIC, || {
        for e in list.list.iter(&g) {
            let fa = e.fa.read();
            let Some((owner, fd)) = fa.as_ref() else {
                continue;
            };
            let o = owner.st.read();
            if !(sig == SIGURG && o.signum.is_none()) {
                send_sigio(&o, *fd, band);
            }
        }
    });
}

// =============================================================================
// send_sigio
// =============================================================================

/// si_band per POLL_* code (Linux band_table; POLL and EPOLL bits are
/// the same values on x86-64 and arm64, so no mangle_poll)
fn band(reason: i32) -> i64 {
    let b = match reason {
        POLL_IN => POLLIN | POLLRDNORM,
        POLL_OUT => POLLOUT | POLLWRNORM | POLLWRBAND,
        POLL_MSG => POLLIN | POLLRDNORM | POLLMSG,
        POLL_ERR => POLLERR,
        POLL_PRI => POLLPRI | POLLRDBAND,
        POLL_HUP => POLLHUP | POLLERR,
        _ => return !0,
    };
    i64::from(b)
}

/// The owner's setter may signal task `t` (Linux sigio_perm: setter
/// root, or its uid or euid is the target's uid or saved uid)
fn sigio_perm(o: &Owner, t: &TaskView<'_>) -> bool {
    let cred = t.cred();
    o.euid == 0
        || o.euid == cred.suid
        || o.euid == cred.uid
        || o.uid == cred.suid
        || o.uid == cred.uid
}

/// What a SIGIO to task `t` reaches, if the setter may signal it: the
/// thread itself for a thread owner, else its process (Linux
/// send_sigio_to_task's do_send_sig_info to the task, by reference)
fn sigio_target(table: &GlobalTaskTable, o: &Owner, t: &TaskView<'_>) -> Option<TaskRef> {
    if !sigio_perm(o, t) {
        return None;
    }
    match o.kind {
        PidType::Tid => Some(crate::task::percpu::task_ref(t.task)),
        _ => group_task(table, Some(*t)),
    }
}

/// Linux send_sigio_to_task: the chosen signal with its POLL info, or
/// plain SIGIO (SI_KERNEL) when none was chosen or it could not be
/// queued; thread-directed for a thread owner, else to its process
fn sigio_to_task(o: &Owner, t: &TaskRef, fd: i32, reason: i32) {
    let send = |sig, info| match o.kind {
        PidType::Tid => send_sig_info(t, sig, info),
        _ => send_group_signal(t, sig, info),
    };
    if let Some(sig) = o.signum {
        // A signal with its own positive codes gets SI_SIGIO, not the
        // ambiguous POLL_* (SIGPOLL itself keeps it)
        let code = if sig != SIGIO && crate::signal::siginfo::specific_codes(sig) {
            si_code::SI_SIGIO
        } else {
            reason
        };
        let fields = SigFields::Poll {
            band: band(reason),
            fd,
        };
        if send(sig, SendInfo::Info(SigInfo::new(sig, code, fields))).is_ok() {
            return;
        }
    }
    let _ = send(SIGIO, SendInfo::Kernel);
}

/// Linux send_sigio: to the owner's thread or process, or once to each
/// process of its group, each found through the owner's struct pid
/// (never by a number its process may have freed for reuse)
fn send_sigio(o: &Owner, fd: i32, reason: i32) {
    let Some(pid) = &o.pid else {
        return;
    };
    match o.kind {
        PidType::Tid | PidType::Tgid => {
            let t = {
                let table = TASKLIST.read();
                let v = table.pid_tid(pid).and_then(|tid| table.get(tid));
                v.and_then(|v| sigio_target(&table, o, &v))
            };
            if let Some(t) = t {
                sigio_to_task(o, &t, fd, reason);
            }
        }
        PidType::Pgrp => {
            // GFP_ATOMIC: no memory, no signal (Linux walks the group
            // under tasklist_lock instead)
            let targets =
                GlobalTaskTable::try_collect_pgrp(pid, |table, t| sigio_target(table, o, t))
                    .unwrap_or_default();
            for t in &targets {
                sigio_to_task(o, t, fd, reason);
            }
        }
    }
}
