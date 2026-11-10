//! Callbacks a task runs in its own context (Linux kernel/task_work.c)
//!
//! `task_work_add` queues a [`CallbackHead`] on a task from any
//! context, hardirq included (an IrqSpinlock and a list that never
//! allocates), sets TIF_NOTIFY_SIGNAL and wakes the task from an
//! interruptible sleep (Linux TWA_SIGNAL_NO_IPI): `signal_pending` is
//! true while it is set, so an interruptible sleep ends and its syscall
//! restarts after the work ran, on the way back to user mode
//! (`entry::exit_to_user_mode`, Linux get_signal's task_work_run). Code
//! that waits for the work itself runs it (`task_work_run`). At exit
//! the list is closed (`exit_task_work`): later adds fail.
//!
//! A callback head is allocated once by its owner and names the work
//! weakly, so a queued head never keeps its owner alive.
//!
//! Locking: `TaskWorks.q` is an IrqSpinlock leaf (the wakeup comes after
//! it is released); callbacks run with nothing held.

use alloc::sync::{Arc, Weak};

use crate::sync::IrqSpinlock;
use crate::task::percpu::{WakeMode, current, try_to_wake_up};
use crate::task::{Task, tif};
use crate::util::error::KernelError;
use crate::util::list::{ArcList, Link};

/// Work run in a task's context
pub trait TaskWork: Send + Sync {
    fn run(&self);
}

/// A queueable callback (Linux struct callback_head)
pub struct CallbackHead {
    link: Link,
    /// Set once by its owner (`set_work`); a head without one runs
    /// nothing
    work: spin::Once<Weak<dyn TaskWork>>,
}

crate::adapter!(CbAdapter, CallbackHead, link);

impl CallbackHead {
    pub const fn new() -> Self {
        Self {
            link: Link::new(),
            work: spin::Once::new(),
        }
    }

    /// Name the work the head runs (once; its owner, weakly)
    pub fn set_work(&self, work: Weak<dyn TaskWork>) {
        self.work.call_once(|| work);
    }
}

/// A task's queued callbacks (Linux task->task_works)
pub struct TaskWorks {
    q: IrqSpinlock<Queue>,
}

struct Queue {
    list: ArcList<CbAdapter>,
    /// Closed at exit (Linux &work_exited)
    exited: bool,
}

impl TaskWorks {
    pub const fn new() -> Self {
        Self {
            q: IrqSpinlock::new(Queue {
                list: ArcList::new(),
                exited: false,
            }),
        }
    }
}

/// Queue `cb` on `task` (once: a head already queued stays where it is)
/// and kick it (Linux task_work_add with TWA_SIGNAL_NO_IPI); ESRCH once
/// the task has exited. Any context.
pub fn task_work_add(task: &Task, cb: &Arc<CallbackHead>) -> Result<(), KernelError> {
    {
        let mut q = task.task_works.q.lock();
        if q.exited {
            return Err(KernelError::NoProcess);
        }
        // Only ever on this task's list: read under its lock
        if !cb.link.is_linked() {
            q.list.push_back(cb.clone());
        }
    }
    task.set_tif(tif::NOTIFY_SIGNAL);
    try_to_wake_up(task, WakeMode::Interruptible);
    Ok(())
}

/// Run the current task's queued callbacks (Linux task_work_run)
pub fn task_work_run() {
    let me = current();
    me.clear_tif(tif::NOTIFY_SIGNAL);
    loop {
        let cb = me.task_works.q.lock().list.pop_front();
        let Some(cb) = cb else { break };
        if let Some(w) = cb.work.get().and_then(Weak::upgrade) {
            w.run();
        }
    }
}

/// Close the current task's list and run what is on it (Linux
/// exit_task_work)
pub fn exit_task_work() {
    task_work_run();
    current().task_works.q.lock().exited = true;
    task_work_run();
}
