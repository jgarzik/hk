//! A task's io_uring context (Linux io_uring/tctx.c, tw.c)
//!
//! Asynchronous requests end in any context (a bio's end_io in hardirq):
//! `Tctx::push` puts the request on its submitter's list (an
//! IrqSpinlock over an intrusive list: no allocation) and queues the
//! context's callback on the task (`task_work`, Linux
//! io_req_normal_work_add -> task_work_add). The task then finishes its
//! requests in its own context (`run`, Linux tctx_task_work): posts their
//! CQEs and releases their pinned pages, dirtying page-cache pages under
//! their page locks, which an interrupt handler could not.
//!
//! Exit and exec wait until the task has no request in flight (Linux
//! io_uring_files_cancel / io_uring_task_cancel), finishing them as they
//! end, so a request always finds its task.

use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicU32, Ordering};

use super::IoRing;
use super::rw::{Req, ReqAdapter};
use crate::sync::IrqSpinlock;
use crate::sync::waitqueue::WaitQueue;
use crate::task::percpu::current;
use crate::task::task_work::{CallbackHead, TaskWork, task_work_add, task_work_run};
use crate::util::error::KernelResult;
use crate::util::kalloc::try_arc;
use crate::util::kmem::KVec;
use crate::util::list::ArcList;

/// One task's io_uring state (Linux struct io_uring_task)
pub struct Tctx {
    /// Ended requests to finish in the task's context (Linux task_list)
    reqs: IrqSpinlock<ArcList<ReqAdapter>>,
    /// Queued on the task while `reqs` holds requests
    cb: Arc<CallbackHead>,
    /// Requests of the task in flight (Linux tctx->inflight)
    inflight: AtomicU32,
    /// Woken when `inflight` drops to zero
    idle: WaitQueue,
    /// IOPOLL rings it issued polled requests on: nothing but polling
    /// ends those, so `cancel` polls them (Linux io_uring_cancel_generic
    /// -> io_iopoll_try_reap_events)
    polled: crate::sync::spin::Mutex<KVec<Weak<IoRing>>>,
}

impl TaskWork for Tctx {
    /// Finish the ended requests (Linux tctx_task_work)
    fn run(&self) {
        loop {
            let req = self.reqs.lock().pop_front();
            let Some(req) = req else { break };
            req.finish();
        }
    }
}

impl Tctx {
    fn new() -> KernelResult<Arc<Self>> {
        let cb = try_arc(CallbackHead::new())?;
        let t = try_arc(Self {
            reqs: IrqSpinlock::new(ArcList::new()),
            cb: cb.clone(),
            inflight: AtomicU32::new(0),
            idle: WaitQueue::new(),
            polled: crate::sync::spin::Mutex::new(KVec::new()),
        })?;
        // Named weakly: a queued callback never keeps the context alive
        let weak: Weak<dyn TaskWork> = Arc::downgrade(&t) as Weak<Self>;
        cb.set_work(weak);
        Ok(t)
    }
}

/// The current task's context, made on first use; ENOMEM
pub fn tctx() -> KernelResult<Arc<Tctx>> {
    current().io_uring.try_call_once(Tctx::new).map(Arc::clone)
}

impl Tctx {
    /// A request of the task is in flight
    pub fn get(&self) {
        self.inflight.fetch_add(1, Ordering::Relaxed);
    }

    /// One in flight is done (dropped); the last wakes `idle`
    pub fn put(&self) {
        if self.inflight.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.idle.wake_all();
        }
    }

    /// `req` ended: finish it in its submitter's context (any context).
    /// The callback is queued while `req`, which holds the task, is
    /// still ours: no reference to the task is dropped here (that could
    /// free it in an interrupt handler). Lock order: `reqs` ->
    /// `TaskWorks.q` and the wakeup.
    pub fn push(&self, req: Arc<Req>) {
        let mut l = self.reqs.lock();
        // A task that has exited finishes its requests itself first
        // (`cancel`): nothing is lost if this fails
        if l.is_empty() {
            let _ = task_work_add(req.task(), &self.cb);
        }
        l.push_back(req);
    }

    /// Note that the task issued polled requests on `r`
    pub fn note_polled(&self, r: &Arc<IoRing>) -> KernelResult<()> {
        let mut l = self.polled.lock();
        if !l.iter().any(|w| core::ptr::eq(w.as_ptr(), Arc::as_ptr(r))) {
            l.try_push(Arc::downgrade(r))?;
        }
        Ok(())
    }

    /// Poll the IOPOLL rings the task issued on, once
    fn poll_rings(&self) {
        let rings: KVec<Arc<IoRing>> = {
            let l = self.polled.lock();
            let mut v = KVec::new();
            for r in l.iter().filter_map(Weak::upgrade) {
                // Room is not reserved: a ring left out is polled next time
                let _ = v.try_push(r);
            }
            v
        };
        for r in rings.iter() {
            r.poll_once();
        }
    }

    /// Finish requests until none of the task's is in flight, polling
    /// its IOPOLL rings meanwhile
    fn cancel(&self) {
        loop {
            task_work_run();
            self.poll_rings();
            self.run();
            if self.inflight.load(Ordering::Acquire) == 0 {
                break;
            }
            // Woken at zero; a tick bounds the wait for ended requests,
            // which kick the task's callback, not this queue
            self.idle.wait_event_timeout(
                || self.inflight.load(Ordering::Acquire) == 0 || !self.reqs.lock().is_empty(),
                1,
            );
        }
    }
}

/// Wait out the current task's requests in flight (Linux
/// io_uring_files_cancel at exit, io_uring_task_cancel at exec)
pub fn task_cancel() {
    if let Some(t) = current().io_uring.get() {
        t.cancel();
    }
}
