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
use super::iowq::IoWq;
use super::rw::{Req, ReqAdapter};
use crate::sync::IrqSpinlock;
use crate::sync::waitqueue::WaitQueue;
use crate::task::percpu::current;
use crate::task::task_work::{CallbackHead, TaskWork, task_work_add, task_work_run};
use crate::util::error::{KernelError, KernelResult};
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
    /// Its io-wq, made by its first request that needs one and gone at
    /// exit or exec (Linux tctx->io_wq, tctx->in_cancel)
    io_wq: WqSlot<IoWq>,
}

/// A task's io-wq and whether a cancel began (Linux tctx->io_wq,
/// tctx->in_cancel). A cancel keeps the io-wq in place, refusing work
/// (ECANCELED), until it is done; then it goes, and none is made again
/// after exit (Linux io_queue_iowq: no io_wq, -ECANCELED); after exec
/// the task may make a new one (Linux frees the tctx).
struct WqSlot<T> {
    s: crate::sync::spin::Mutex<SlotState<T>>,
}

struct SlotState<T> {
    wq: Option<Arc<T>>,
    in_cancel: bool,
}

impl<T> WqSlot<T> {
    const fn new() -> Self {
        Self {
            s: crate::sync::spin::Mutex::new(SlotState {
                wq: None,
                in_cancel: false,
            }),
        }
    }

    /// The io-wq, made by `make` (unlocked: it allocates) if there is
    /// none; ECANCELED during or after a cancel without one
    fn get_or_make(&self, make: impl FnOnce() -> KernelResult<Arc<T>>) -> KernelResult<Arc<T>> {
        if let Some(wq) = self.get_live()? {
            return Ok(wq);
        }
        let new = make()?;
        let mut s = self.s.lock();
        if let Some(wq) = s.wq.as_ref() {
            return Ok(wq.clone());
        }
        if s.in_cancel {
            return Err(KernelError::Canceled);
        }
        s.wq = Some(new.clone());
        Ok(new)
    }

    /// The io-wq if there is one; ECANCELED if none may be made
    fn get_live(&self) -> KernelResult<Option<Arc<T>>> {
        let s = self.s.lock();
        match s.wq.as_ref() {
            Some(wq) => Ok(Some(wq.clone())),
            None if s.in_cancel => Err(KernelError::Canceled),
            None => Ok(None),
        }
    }

    fn get(&self) -> Option<Arc<T>> {
        self.s.lock().wq.clone()
    }

    /// A cancel begins (Linux io_uring_cancel_generic: in_cancel): the
    /// io-wq to cancel, which stays in place
    fn cancel_start(&self) -> Option<Arc<T>> {
        let mut s = self.s.lock();
        s.in_cancel = true;
        s.wq.clone()
    }

    /// The cancel is done (Linux io_uring_clean_tctx): the io-wq goes,
    /// returned to drop unlocked; at exec (`exec`) a new one may be made
    fn cancel_end(&self, exec: bool) -> Option<Arc<T>> {
        let mut s = self.s.lock();
        if exec {
            s.in_cancel = false;
        }
        s.wq.take()
    }
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
            io_wq: WqSlot::new(),
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

    /// Its io-wq (made by the owner: the first caller is its
    /// submission, as after an exec); ECANCELED once the task's cancel
    /// began without one
    pub fn io_wq(&self) -> KernelResult<Arc<IoWq>> {
        self.io_wq.get_or_make(IoWq::new)
    }

    /// Its io-wq if it has one (from a context other than the owner's,
    /// which cannot make one)
    pub fn io_wq_get(&self) -> Option<Arc<IoWq>> {
        self.io_wq.get()
    }

    /// Note that the task issued polled requests on `r`
    pub fn note_polled(&self, r: &Arc<IoRing>) -> KernelResult<()> {
        note_live(&mut self.polled.lock(), r)
    }

    /// Poll the IOPOLL rings the task issued on, once; rings gone are
    /// dropped from the list
    fn poll_rings(&self) {
        let rings: KVec<Arc<IoRing>> = {
            let mut l = self.polled.lock();
            prune(&mut l);
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
    /// its IOPOLL rings meanwhile (`exec`: the task goes on)
    fn cancel(&self, exec: bool) {
        // Its workers first: queued work ends, running work is
        // interrupted, and they are gone. The io-wq stays, refusing
        // work: a request queued meanwhile (a reissue as it ends) ends
        // ECANCELED, and no new io-wq starts workers that outlive this
        if let Some(wq) = self.io_wq.cancel_start() {
            wq.cancel();
        }
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
        drop(self.io_wq.cancel_end(exec));
    }
}

/// Wait out the current task's requests in flight (Linux
/// io_uring_files_cancel at exit, io_uring_task_cancel at exec:
/// `exec`)
pub fn task_cancel(exec: bool) {
    if let Some(t) = current().io_uring.get() {
        t.cancel(exec);
    }
}

/// Drop the entries of rings that are gone
fn prune<T>(l: &mut KVec<Weak<T>>) {
    let mut i = 0;
    while i < l.len() {
        if l[i].strong_count() == 0 {
            l.remove(i);
        } else {
            i += 1;
        }
    }
}

/// Add `r` to `l` once, the dead entries pruned first: the list holds
/// live rings only, plus none dead (Linux io_uring_add_tctx_node, with
/// the node removed when the ring goes)
fn note_live<T>(l: &mut KVec<Weak<T>>, r: &Arc<T>) -> KernelResult<()> {
    prune(l);
    if !l.iter().any(|w| core::ptr::eq(w.as_ptr(), Arc::as_ptr(r))) {
        l.try_push(Arc::downgrade(r))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polled_list_stays_bounded() {
        let mut l: KVec<Weak<u32>> = KVec::new();
        let keep = Arc::new(0u32);
        for i in 0..1000 {
            let r = Arc::new(i);
            note_live(&mut l, &r).unwrap();
            note_live(&mut l, &keep).unwrap();
            assert!(l.len() <= 2, "list grew to {}", l.len());
        }
        drop(keep);
        prune(&mut l);
        assert!(l.is_empty());
    }

    /// A request queued while (or after) the task cancels gets the
    /// cancelled io-wq or ECANCELED, never a new one; exec allows one
    #[test]
    fn no_new_io_wq_in_cancel() {
        let slot: WqSlot<u32> = WqSlot::new();
        let first = slot.get_or_make(|| Ok(Arc::new(1))).unwrap();
        let wq = slot.cancel_start().unwrap();
        assert!(Arc::ptr_eq(&wq, &first));
        let again = slot
            .get_or_make(|| panic!("new io-wq during cancel"))
            .unwrap();
        assert!(Arc::ptr_eq(&again, &first));
        assert!(slot.cancel_end(false).is_some());
        let after = slot.get_or_make(|| panic!("new io-wq after exit"));
        assert_eq!(after.err(), Some(KernelError::Canceled));
        // No io-wq when the cancel began: none is made during it either
        let s2: WqSlot<u32> = WqSlot::new();
        assert!(s2.cancel_start().is_none());
        let r = s2.get_or_make(|| panic!("new io-wq during cancel"));
        assert_eq!(r.err(), Some(KernelError::Canceled));
        assert!(s2.cancel_end(true).is_none());
        assert_eq!(*s2.get_or_make(|| Ok(Arc::new(2))).unwrap(), 2);
    }
}
