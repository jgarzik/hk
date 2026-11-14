//! One AIO request (Linux fs/aio.c struct aio_kiocb)
//!
//! A request holds two references (Linux ki_refcnt = 2): the
//! submitter's, given up when io_submit is done with it, and its
//! completion's, given up when the operation ends (a bio's end_io,
//! possibly in hardirq; the fsync or poll work item; at once for one
//! that completed within io_submit). Each is an `Arc` that its `put`
//! consumes, and the two counts decide the request's life as Linux's
//! one does: an earlier put leaves its `Arc` to the last one, which
//! posts the event (`Kioctx::complete`, Linux aio_complete) and
//! releases the request (Linux iocb_destroy) holding both. No other
//! holder of an `Arc` drops it outside thread context, so the request
//! (its pins, dirtied as they are unpinned under page locks; its file;
//! its eventfd) is released in thread context: by a last put there,
//! else through the context's `reap` list (Linux bio_dirty_work and
//! delayed_fput doing the thread work of an interrupt-time end).

use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicI64, AtomicU32, Ordering};

use super::abi::IoEvent;
use super::ctx::Kioctx;
use super::poll::PollIocb;
use crate::block::dio::AsyncIo;
use crate::fs::FileRef;
use crate::io::eventfd::Eventfd;
use crate::mm::gup::{PageSeg, PinnedPages};
use crate::util::error::KernelError;
use crate::util::kalloc::try_arc_cyclic;
use crate::util::list::Link;

/// What the request does
pub enum Op {
    /// A read or write: the pinned memory of an asynchronous direct I/O
    Rw(Option<PinnedPages>),
    /// IOCB_CMD_FSYNC / FDSYNC, run by a work item
    Fsync,
    /// IOCB_CMD_POLL
    Poll(PollIocb),
}

/// What a request is made with (Linux __io_submit_one's setup)
pub struct Base {
    pub ctx: Arc<Kioctx>,
    pub file: FileRef,
    pub eventfd: Option<Arc<Eventfd>>,
    /// The iocb's aio_data
    pub data: u64,
    /// The iocb's user address
    pub obj: u64,
}

/// An AIO request
pub struct Kiocb {
    /// On its context's `reap` list
    reap: Link,
    /// On its context's `active` (cancellable) list
    active: Link,
    /// Dropped before `file`: a poll's wait entry is on the file's queue
    op: Op,
    file: FileRef,
    eventfd: Option<Arc<Eventfd>>,
    data: u64,
    obj: u64,
    /// The event's result (Linux ki_res.res)
    res: AtomicI64,
    /// The submitter's and the completion's (Linux ki_refcnt)
    refs: AtomicU32,
    /// Its context, the request counted alive on it until everything
    /// above is released (last: fields drop in order)
    ctx: Live,
}

/// A request's count on its context (Linux percpu_ref_get(&ctx->reqs)
/// in aio_get_req, put in iocb_destroy after the file)
struct Live(Arc<Kioctx>);

impl Drop for Live {
    fn drop(&mut self) {
        self.0.req_put();
    }
}

crate::adapter!(pub ReapAdapter, Kiocb, reap);
crate::adapter!(pub ActiveAdapter, Kiocb, active);

impl Kiocb {
    /// A request of `b` doing `op`, alive on its context (which gave it
    /// an event slot); ENOMEM
    pub fn new(b: Base, op: Op) -> Result<Arc<Self>, KernelError> {
        Self::new_with(b, |_| op)
    }

    /// As `new`, its operation made knowing where it will live
    pub fn new_with(b: Base, op: impl FnOnce(&Weak<Self>) -> Op) -> Result<Arc<Self>, KernelError> {
        let ctx = b.ctx.clone();
        let k = try_arc_cyclic(|me| Self {
            reap: Link::new(),
            active: Link::new(),
            op: op(me),
            file: b.file,
            eventfd: b.eventfd,
            data: b.data,
            obj: b.obj,
            res: AtomicI64::new(0),
            refs: AtomicU32::new(2),
            ctx: Live(b.ctx),
        })?;
        ctx.req_get();
        Ok(k)
    }

    /// Release it unissued, with no event (Linux iocb_destroy after an
    /// error from __io_submit_one)
    pub fn abandon(self: Arc<Self>) {
        self.refs.store(0, Ordering::Relaxed);
    }

    pub fn ctx(&self) -> &Arc<Kioctx> {
        &self.ctx.0
    }

    pub fn file(&self) -> &FileRef {
        &self.file
    }

    pub fn op(&self) -> &Op {
        &self.op
    }

    /// The user iocb it came from
    pub fn obj(&self) -> u64 {
        self.obj
    }

    /// On the cancellable list
    pub fn on_active(&self) -> bool {
        self.active.is_linked()
    }

    /// Record the result: bytes, or an error (a restart code is EINTR:
    /// Linux aio_rw_done, no restart of one of many requests)
    pub fn set_res(&self, r: Result<usize, KernelError>) {
        let v = match r {
            Ok(n) => i64::try_from(n).unwrap_or(i64::MAX),
            Err(
                KernelError::RestartSys | KernelError::RestartNoIntr | KernelError::RestartNoHand,
            ) => KernelError::Interrupted.to_errno_neg().into(),
            Err(e) => e.to_errno_neg().into(),
        };
        self.res.store(v, Ordering::Relaxed);
    }

    /// Record a raw result (a poll mask)
    pub fn set_res_raw(&self, v: i64) {
        self.res.store(v, Ordering::Relaxed);
    }

    fn event(&self) -> IoEvent {
        IoEvent {
            data: self.data,
            obj: self.obj,
            res: self.res.load(Ordering::Relaxed),
            res2: 0,
        }
    }

    /// Give up one of its two references (Linux iocb_put), `self`
    /// being its `Arc`: the last posts the event and returns the
    /// request, holding both references' counts, for the caller to
    /// release; an earlier one gives its count over to the last and
    /// touches the request no more, as it may be gone at once
    fn put(self: Arc<Self>) -> Option<Arc<Self>> {
        if self.refs.fetch_sub(1, Ordering::AcqRel) != 1 {
            // Released by the last put, with its own
            core::mem::forget(self);
            return None;
        }
        // SAFETY: the other reference's put forgot its `Arc` (above),
        // leaving its count to this one, which this `Arc` outlives
        unsafe { Arc::decrement_strong_count(Arc::as_ptr(&self)) };
        self.ctx().complete(self.event(), self.eventfd.as_deref());
        Some(self)
    }

    /// `put` in thread context: the request, if released, goes here
    pub fn put_thread(self: Arc<Self>) {
        drop(self.put());
    }

    /// `put` in any context, hardirq included: the request, if
    /// released, goes to its context's reap list for release in thread
    /// context (an earlier put leaves nothing behind to release)
    pub fn put_any(self: Arc<Self>) {
        if let Some(k) = self.put() {
            let ctx = k.ctx().clone();
            ctx.defer(k);
        }
    }

    /// Cancel it (Linux ki_cancel, from io_cancel or the context's end;
    /// it is off the cancellable list): only a poll has a cancel
    pub fn cancel(self: Arc<Self>) {
        if let Op::Poll(p) = &self.op {
            p.cancel(&self);
        }
    }

    /// Complete it within io_submit (the completion's reference, thread
    /// context) with `r`
    pub fn done(self: &Arc<Self>, r: Result<usize, KernelError>) {
        self.set_res(r);
        self.clone().put_thread();
    }
}

// SAFETY: the pieces are the request's own pins (`Op::Rw`), unchanged
// while it lives; `complete` stores an atomic, writes the ring and
// wakes under IrqSpinlocks (`Kioctx::complete`), and either queues the
// request for release in thread context or gives its `Arc` over to the
// submitter's put (`put_any`): nothing it does sleeps or allocates
unsafe impl AsyncIo for Kiocb {
    fn segs(&self) -> &[PageSeg] {
        match &self.op {
            Op::Rw(Some(p)) => p.segs(),
            _ => &[],
        }
    }

    /// The direct I/O ended (Linux aio_complete_rw), any context
    fn complete(self: Arc<Self>, res: Result<usize, KernelError>) {
        self.set_res(res);
        self.put_any();
    }
}
