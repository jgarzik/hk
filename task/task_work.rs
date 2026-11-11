//! Callbacks a task runs in its own context (Linux kernel/task_work.c)
//!
//! `task_work_add` queues a [`CallbackHead`] on a task from any
//! context, hardirq included (an IrqSpinlock and an intrusive list that
//! never allocates), and flags the task by `notify` (Linux enum
//! task_work_notify_mode):
//! - [`Twa::Resume`]: TIF_NOTIFY_RESUME, no wakeup; the work runs on the
//!   task's next return to user mode (`entry::exit_to_user_mode`, Linux
//!   resume_user_mode_work). A file's deferred release (`fs::file`).
//! - [`Twa::Signal`]: TIF_NOTIFY_SIGNAL and a wakeup from an
//!   interruptible sleep (Linux TWA_SIGNAL_NO_IPI): `signal_pending` is
//!   true while it is set, so the sleep ends and its syscall restarts
//!   after the work ran (`signal::do_signal`, Linux get_signal's
//!   task_work_run). io_uring's completions and worker starts.
//!
//! Code that waits for the work itself runs it (`task_work_run`). At
//! exit the list is closed (`exit_task_work`): later adds fail and the
//! caller falls back (a file goes to the delayed list).
//!
//! A head is embedded in its owner (Linux struct callback_head) with
//! the function that runs it; the queuer hands the list a reference to
//! the owner, which that function takes back. [`WorkHead`] is the
//! shared-ownership form: an `Arc`'d head naming its work weakly, so a
//! queued head never keeps its owner alive.
//!
//! Locking: `TaskWorks.q` is an IrqSpinlock leaf (the wakeup comes after
//! it is released); callbacks run with nothing held.

use alloc::sync::{Arc, Weak};

use crate::sync::IrqSpinlock;
use crate::task::percpu::{WakeMode, current, try_to_wake_up};
use crate::task::{Task, tif};
use crate::util::error::KernelError;
use crate::util::list::{Link, List};

/// A queueable callback (Linux struct callback_head)
pub struct CallbackHead {
    link: Link,
    /// Runs the work and takes back the reference its queuer handed the
    /// list (Linux callback_head.func)
    func: unsafe fn(*const CallbackHead),
}

crate::adapter!(pub CbAdapter, CallbackHead, link);

impl CallbackHead {
    /// A head that runs `func` (Linux init_task_work)
    pub const fn new(func: unsafe fn(*const CallbackHead)) -> Self {
        Self {
            link: Link::new(),
            func,
        }
    }

    /// Run the head's function
    ///
    /// # Safety
    /// `cb` came off a list it was queued on, and the reference its
    /// queuer handed over is not used again.
    pub unsafe fn run(cb: *const CallbackHead) {
        // SAFETY: live until its function takes the reference back
        let func = unsafe { (*cb).func };
        // SAFETY: the caller's contract is the function's
        unsafe { func(cb) }
    }
}

/// How a task is told of queued work (Linux enum task_work_notify_mode)
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Twa {
    /// On the return to user mode (TWA_RESUME)
    Resume,
    /// As a signal would, ending an interruptible sleep
    /// (TWA_SIGNAL_NO_IPI, with the wakeup)
    Signal,
}

/// A task's queued callbacks (Linux task->task_works)
pub struct TaskWorks {
    q: IrqSpinlock<Queue>,
}

struct Queue {
    list: List<CbAdapter>,
    /// Closed at exit (Linux &work_exited)
    exited: bool,
}

impl TaskWorks {
    pub const fn new() -> Self {
        Self {
            q: IrqSpinlock::new(Queue {
                list: List::new(),
                exited: false,
            }),
        }
    }
}

/// Queue `cb` on `task` and tell it by `notify` (Linux task_work_add);
/// ESRCH once the task has exited, with `cb` not queued. Any context.
///
/// # Safety
/// `cb` is on no task's list, and stays live until its function ran:
/// on success the caller hands that function the reference keeping it.
pub unsafe fn task_work_add(
    task: &Task,
    cb: *const CallbackHead,
    notify: Twa,
) -> Result<(), KernelError> {
    // SAFETY: the caller's contract
    unsafe { add(task, cb, notify, false) }.map(drop)
}

/// As `task_work_add`; with `once`, a head already on the list stays
/// where it is: Ok(false), no reference handed over
///
/// # Safety
/// `cb` stays live until its function ran; without `once` it is on no
/// task's list, with it on no list but `task`'s.
unsafe fn add(
    task: &Task,
    cb: *const CallbackHead,
    notify: Twa,
    once: bool,
) -> Result<bool, KernelError> {
    {
        let mut q = task.task_works.q.lock();
        if q.exited {
            return Err(KernelError::NoProcess);
        }
        // SAFETY: live (the caller); its link is only ever on this
        // task's list, read and changed under its lock
        if once && unsafe { (*cb).link.is_linked() } {
            return Ok(false);
        }
        // SAFETY: live and unlinked, linked under its lock
        unsafe { q.list.push_back(cb) };
    }
    match notify {
        Twa::Resume => task.set_tif(tif::NOTIFY_RESUME),
        Twa::Signal => {
            task.set_tif(tif::NOTIFY_SIGNAL);
            try_to_wake_up(task, WakeMode::Interruptible);
        }
    }
    Ok(true)
}

/// Run the current task's queued callbacks, those they queue included
/// (Linux task_work_run; TIF_NOTIFY_SIGNAL is cleared here, as Linux's
/// callers do first)
pub fn task_work_run() {
    let me = current();
    me.clear_tif(tif::NOTIFY_SIGNAL);
    loop {
        let cb = me.task_works.q.lock().list.pop_front();
        let Some(cb) = cb else { break };
        // SAFETY: just taken off the list; its queuer's reference is the
        // function's
        unsafe { CallbackHead::run(cb) };
    }
}

/// Close the current task's list and run what is on it (Linux
/// exit_task_work)
pub fn exit_task_work() {
    task_work_run();
    current().task_works.q.lock().exited = true;
    task_work_run();
}

/// Work run in a task's context through a [`WorkHead`]
pub trait TaskWork: Send + Sync {
    fn run(&self);
}

/// A shared callback head (`Arc`'d by its owner) naming its work weakly
pub struct WorkHead {
    cb: CallbackHead,
    /// Set once by its owner (`set_work`); a head without one runs
    /// nothing
    work: spin::Once<Weak<dyn TaskWork>>,
}

impl WorkHead {
    pub const fn new() -> Self {
        Self {
            cb: CallbackHead::new(Self::func),
            work: spin::Once::new(),
        }
    }

    /// Name the work the head runs (once; its owner, weakly)
    pub fn set_work(&self, work: Weak<dyn TaskWork>) {
        self.work.call_once(|| work);
    }

    /// Queue the head on `task` (once: a head already queued stays where
    /// it is) and kick it as a signal would (`Twa::Signal`); ESRCH once
    /// the task has exited. Any context.
    pub fn queue(self: &Arc<Self>, task: &Task) -> Result<(), KernelError> {
        let p = Arc::into_raw(self.clone());
        // SAFETY: `p` is live; its owner queues it on `task` only, so it
        // is on no other list; a queued head keeps the reference until
        // `func`
        let r = unsafe { add(task, &raw const (*p).cb, Twa::Signal, true) };
        if !matches!(r, Ok(true)) {
            // SAFETY: not queued by this call: the reference is still ours
            drop(unsafe { Arc::from_raw(p) });
        }
        r.map(drop)
    }

    /// Run the named work and drop the list's reference
    ///
    /// # Safety
    /// `cb` is the head of a `WorkHead` queued by `queue`.
    unsafe fn func(cb: *const CallbackHead) {
        let off = core::mem::offset_of!(WorkHead, cb);
        // SAFETY: `cb` is inside a WorkHead whose reference `queue`
        // handed the list (Arc::into_raw)
        let h = unsafe { Arc::from_raw(cb.cast::<u8>().sub(off).cast::<WorkHead>()) };
        if let Some(w) = h.work.get().and_then(Weak::upgrade) {
            w.run();
        }
    }
}
