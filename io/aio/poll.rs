//! IOCB_CMD_POLL (Linux fs/aio.c aio_poll, aio_poll_wake,
//! aio_poll_complete_work, aio_poll_cancel)
//!
//! The request polls its file once with a table that puts one entry of
//! its own on the file's wait queue (a second queue is EINVAL, as Linux
//! "multiple wait queues per file are not supported"). Ready at once: it
//! completes within io_submit. Otherwise it waits, cancellable: a
//! wakeup whose events it waits for (or any unkeyed wakeup) queues its
//! work item, which polls again in thread context and, ready or
//! cancelled, takes the entry off the queue and completes with the
//! ready events (0 when cancelled). A wakeup while the work is queued
//! makes it run once more (Linux work_need_resched).
//!
//! Locks: the request's `reg` (sleeping: held by the submission across
//! the file's poll, which may sleep, so the work waits for it) -> the
//! context's `active` list -> the entry's wait queue head -> the
//! request's `st` (IrqSpinlock leaf) -> the workqueue's locks (a wakeup
//! queues the work under the queue head, as Linux's schedule_work from
//! aio_poll_wake). The request keeps a reference to itself while it
//! waits (its completion's reference), so the work and a cancel always
//! find it.

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::pin::Pin;

use super::kiocb::{Base, Kiocb, Op};
use crate::io::poll::{POLLERR, POLLHUP, PollTable};
use crate::sync::IrqSpinlock;
use crate::sync::Mutex;
use crate::sync::waitqueue::{WaitEntry, WaitQueue};
use crate::task::percpu::WakeMode;
use crate::task::workqueue::{SYSTEM_WQ, Work};
use crate::util::error::{KernelError, KernelResult};
use crate::util::kalloc::{arc_nofail, try_box};

/// The entry a poll request put on its file's wait queue, and the
/// owners that queue lives in (Linux aio_poll_table)
pub struct AioRegs {
    /// The queue and the entry on it
    reg: Option<(*const WaitQueue, Pin<Box<WaitEntry>>)>,
    /// What the queue lives in, besides the file (a signalfd's SigHand)
    owners: Vec<Arc<dyn core::any::Any + Send + Sync>>,
    /// The request the entry wakes (its address)
    me: usize,
    /// A second queue, or no memory for the entry
    error: Option<KernelError>,
}

// SAFETY: the queue pointer is followed only while the request holds
// the queue's file or owner (`owners`), under `PollIocb.reg`
unsafe impl Send for AioRegs {}

impl AioRegs {
    fn new(me: usize) -> Self {
        Self {
            reg: None,
            owners: Vec::new(),
            me,
            error: None,
        }
    }

    /// Put the request's entry on `wq` (Linux aio_poll_queue_proc); a
    /// second queue is EINVAL
    pub(crate) fn add(&mut self, wq: &WaitQueue) {
        if self.reg.is_some() {
            self.error = Some(KernelError::InvalidArgument);
            return;
        }
        let Ok(e) = try_box(WaitEntry::with_func(Some(aio_poll_wake), self.me)) else {
            self.error = Some(KernelError::OutOfMemory);
            return;
        };
        let e = Box::into_pin(e);
        wq.add_wait_queue(e.as_ref());
        self.reg = Some((core::ptr::from_ref(wq), e));
    }

    /// Keep `owner` alive while registered
    pub(crate) fn hold(&mut self, owner: Arc<dyn core::any::Any + Send + Sync>) {
        if self.owners.try_reserve(1).is_ok() {
            self.owners.push(owner);
        } else {
            self.error = Some(KernelError::OutOfMemory);
        }
    }

    /// Take the entry off its queue, if it is on one
    fn remove(&mut self) {
        if let Some((wq, e)) = self.reg.take() {
            // SAFETY: the queue lives in the request's file or in
            // `owners`, both held (type invariant of the Send impl)
            unsafe { (*wq).remove_wait_queue(e.as_ref()) };
        }
    }
}

/// The work's state (Linux poll_iocb's flags, under the queue lock)
#[derive(Default)]
struct PollSt {
    /// The work is queued or running (Linux work_scheduled)
    scheduled: bool,
    /// A wakeup came while it was (Linux work_need_resched)
    resched: bool,
    /// io_cancel or the context's end (Linux cancelled)
    cancelled: bool,
}

/// A poll request's part (Linux struct poll_iocb)
pub struct PollIocb {
    /// The events waited for, POLLERR and POLLHUP included
    events: u32,
    reg: Mutex<AioRegs>,
    st: IrqSpinlock<PollSt>,
    /// The request while it waits (its completion's reference)
    me: crate::sync::spin::Mutex<Option<Arc<Kiocb>>>,
    work: Arc<IrqSpinlock<Work>>,
}

impl PollIocb {
    fn new(events: u32, me: &Weak<Kiocb>) -> Self {
        let w = me.clone();
        Self {
            events,
            reg: Mutex::new(AioRegs::new(Weak::as_ptr(me) as usize)),
            st: IrqSpinlock::new(PollSt::default()),
            me: crate::sync::spin::Mutex::new(None),
            work: arc_nofail(IrqSpinlock::new(Work::new(move || {
                if let Some(k) = w.upgrade() {
                    complete_work(&k);
                }
            }))),
        }
    }

    /// Queue the work, or have it run once more (any context)
    fn schedule(&self) {
        {
            let mut st = self.st.lock();
            if st.scheduled {
                st.resched = true;
                return;
            }
            st.scheduled = true;
        }
        SYSTEM_WQ.queue_work(self.work.clone());
    }

    /// Cancel the waiting request `k` (Linux aio_poll_cancel; it is off
    /// the cancellable list)
    pub fn cancel(&self, _k: &Arc<Kiocb>) {
        self.st.lock().cancelled = true;
        self.schedule();
    }
}

fn poll_of(k: &Kiocb) -> &PollIocb {
    match k.op() {
        Op::Poll(p) => p,
        _ => unreachable!("poll work of a request that is not a poll"),
    }
}

/// A wakeup on the polled file's queue (Linux aio_poll_wake), under the
/// queue's lock, possibly in an interrupt handler
fn aio_poll_wake(e: &WaitEntry, _mode: WakeMode, key: usize) -> bool {
    // SAFETY: `private` is the request whose `reg` holds this entry; the
    // entry leaves the queue before the request completes, and the
    // request keeps itself alive until then (`PollIocb.me`)
    let k = unsafe { &*(e.private as *const Kiocb) };
    let Op::Poll(p) = k.op() else {
        return false;
    };
    // Keyed wakeups: only the events it waits for (Linux key_to_poll)
    let mask = key as u32;
    if mask != 0 && mask & p.events == 0 {
        return false;
    }
    p.schedule();
    true
}

/// The poll work (Linux aio_poll_complete_work): poll again; not ready
/// and not cancelled, wait on (or run once more after a wakeup that
/// came meanwhile); else off the queue and the cancellable list, and
/// complete with the ready events
fn complete_work(k: &Arc<Kiocb>) {
    let p = poll_of(k);
    let cancelled = p.st.lock().cancelled;
    let mask = if cancelled {
        0
    } else {
        u32::from(k.file().poll(None)) & p.events
    };
    let ctx = k.ctx().clone();
    {
        // Sleeps while its submission still registers
        let mut reg = p.reg.lock();
        let mut active = ctx.active_lock();
        // Off its queue already (io_submit stole the entry, ready, just
        // after a wakeup queued this): whoever takes `me` first
        // completes it, with its own mask
        if mask == 0 && reg.reg.is_some() {
            let mut st = p.st.lock();
            if !st.cancelled {
                if st.resched {
                    st.resched = false;
                    drop(st);
                    drop(active);
                    SYSTEM_WQ.queue_work(p.work.clone());
                } else {
                    st.scheduled = false;
                }
                return;
            }
        }
        reg.remove();
        if k.on_active() {
            // SAFETY: linked through `active` only on its context's list
            drop(unsafe { active.remove(k) });
        }
    }
    finish(p, mask);
}

/// Complete the poll with `mask`, unless that was done (the work and a
/// ready submission both try when a wakeup came between them): the one
/// that takes `me` sets the result and gives up the reference
fn finish(p: &PollIocb, mask: u32) {
    let me = p.me.lock().take();
    if let Some(me) = me {
        me.set_res_raw(i64::from(mask));
        me.put_thread();
    }
}

/// IOCB_CMD_POLL of `b` for the events `buf` names (Linux aio_poll):
/// Ok when it completed or waits; an error fails the io_submit
pub fn aio_poll(b: Base, buf: u64, offset: i64, nbytes: u64, rw_flags: i32) -> KernelResult<()> {
    // Unknown events past the 16 bits, and fields poll has no use for
    if u64::from(buf as u16) != buf || offset != 0 || nbytes != 0 || rw_flags != 0 {
        return Err(KernelError::InvalidArgument);
    }
    // demangle_poll is the identity on x86-64 and arm64
    let events = u32::from(buf as u16 | POLLERR | POLLHUP);
    let k = Kiocb::new_with(b, |me| Op::Poll(PollIocb::new(events, me)))?;
    let p = poll_of(&k);
    *p.me.lock() = Some(k.clone());
    // Held across the poll (which may sleep) and the decision below: the
    // work, should a wakeup queue it meanwhile, waits for both
    let mut regs = p.reg.lock();
    let mut pt = PollTable::for_aio(&mut regs);
    pt.key = events;
    let mask = u32::from(k.file().poll(Some(&mut pt))) & events;
    let (queued, error) = (regs.reg.is_some(), regs.error);
    // Linux: EINVAL for a file that registers on no queue and is not
    // ready ("same as no support for IOCB_CMD_POLL")
    let mut err = if queued {
        error
    } else {
        Some(KernelError::InvalidArgument)
    };
    let mut mask = mask;
    let ctx = k.ctx().clone();
    {
        let mut active = ctx.active_lock();
        let mut cancel = false;
        if queued && p.st.lock().scheduled {
            // A wakeup already queued the work: it completes the request
            // (Linux: a failed registration then cancels it)
            cancel = err.is_some();
            err = None;
            mask = 0;
        }
        if mask != 0 || err.is_some() {
            // Ready now, or failed: steal the entry back, done here
            regs.remove();
        } else if cancel {
            // The queued work completes it, cancelled
            p.st.lock().cancelled = true;
        } else if queued {
            // Waiting, its work maybe already queued by a wakeup that
            // found nothing yet: cancellable until it completes (Linux
            // aio_poll: list_add_tail onto active_reqs). The context's
            // end cancels the list only once this io_submit's use of
            // it is gone, so it finds the request there.
            active.push_back(k.clone());
        }
    }
    drop(regs);
    if mask != 0 {
        err = None;
        finish(p, mask);
    }
    if let Some(e) = err {
        // Not issued: no event (Linux iocb_destroy)
        drop(p.me.lock().take());
        k.abandon();
        return Err(e);
    }
    k.put_thread();
    Ok(())
}
