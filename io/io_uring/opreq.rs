//! Requests run to their end by io-wq workers (Linux io_kiocb on io-wq:
//! io_wq_submit_work issuing without IO_URING_F_NONBLOCK)
//!
//! An `OpReq` is an SQE copied at submission (IORING_FEAT_SUBMIT_STABLE)
//! with what the submitter resolved: its file (a registered one
//! included), a read or write's iovecs or registered buffer. A worker
//! runs it blocking and posts its CQE; a link chain runs its members in
//! order, a failed one cancelling the rest unless hard-linked (Linux
//! io_req_find_next / io_fail_links). In flight from its queueing to its
//! drop, on its ring and its task (an IOSQE_IO_DRAIN waits for those).

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::IoRing;
use super::abi::*;
use super::rsrc::RegBuf;
use super::tctx::Tctx;
use crate::fs::file::{File, RwFlags};
use crate::fs::iov::IoVec;
use crate::task::percpu::current;
use crate::task::{Cred, override_creds};
use crate::util::error::{KernelError, KernelResult};
use crate::util::kmem::KVec;

/// What an `OpReq` does
pub enum Body {
    /// An operation through its syscall (`ops::run_blocking`)
    Op,
    /// A read or write of `file`: user iovecs, or `len` bytes at `addr`
    /// of a registered buffer
    Rw {
        file: Arc<File>,
        write: bool,
        flags: RwFlags,
        mem: RwMem,
    },
    /// It failed before it could run (a chain member): its result
    Failed(KernelError),
}

/// A punted read or write's memory
pub enum RwMem {
    User(Vec<IoVec>),
    Fixed(Arc<RegBuf>),
}

/// A request for a worker
pub struct OpReq {
    ring: Arc<IoRing>,
    tctx: Arc<Tctx>,
    pub sqe: IoUringSqe,
    body: Body,
    /// The submitter's credentials at submission, which the worker runs
    /// it with (Linux io_prep_async_work: req->creds, REQ_F_CREDS)
    creds: Arc<Cred>,
    /// Counted in flight (`count`), given back at the drop
    counted: bool,
}

impl OpReq {
    /// A request for `sqe` doing `body`, not yet in flight; made by the
    /// submitter, whose credentials it keeps
    pub fn new(ring: &Arc<IoRing>, tctx: &Arc<Tctx>, sqe: IoUringSqe, body: Body) -> Self {
        Self {
            ring: ring.clone(),
            tctx: tctx.clone(),
            sqe,
            body,
            creds: current().cred_arc(),
            counted: false,
        }
    }

    /// In flight from now on (queued)
    pub fn count(&mut self) {
        if !self.counted {
            self.counted = true;
            self.ring.inflight_get();
            self.tctx.get();
        }
    }

    /// The task context it counts on
    pub fn tctx(&self) -> &Arc<Tctx> {
        &self.tctx
    }

    /// It may block for good (a pipe, a socket): an unbounded worker
    /// (Linux io_wq_acct: unbound_nonreg_file)
    pub fn unbound(&self) -> bool {
        match &self.body {
            Body::Rw { file, .. } => !super::rw::bounded_file(file),
            Body::Op => super::ops::unbound(self.sqe.opcode),
            Body::Failed(_) => false,
        }
    }

    /// Run it, blocking, with the submitter's credentials (Linux
    /// io_issue_sqe: override_creds(req->creds)): its result, a restart
    /// code as EINTR (Linux io_fixup_restart_res: submitted SQEs cannot
    /// be restarted)
    fn exec(&self) -> KernelResult<i32> {
        let _creds = override_creds(self.creds.clone());
        let r = match &self.body {
            Body::Op => super::ops::run_blocking(&self.sqe),
            Body::Rw {
                file,
                write,
                flags,
                mem,
            } => super::rw::run_blocking(file, &self.sqe, *write, *flags, mem),
            Body::Failed(e) => Err(*e),
        };
        r.map_err(|e| match e {
            KernelError::RestartSys | KernelError::RestartNoIntr | KernelError::RestartNoHand => {
                KernelError::Interrupted
            }
            e => e,
        })
    }

    /// Post its CQE for `res` (unless IOSQE_CQE_SKIP_SUCCESS and a
    /// success); the drop that follows ends it
    fn post(&self, res: KernelResult<i32>) -> i32 {
        let v = res.unwrap_or_else(KernelError::to_errno_neg);
        if v < 0 || self.sqe.flags & IOSQE_CQE_SKIP_SUCCESS == 0 {
            self.ring.post_cqe(self.sqe.user_data, v, 0);
        }
        v
    }

    /// Run it to its end and post its CQE
    pub fn run(self) {
        let r = self.exec();
        self.post(r);
    }

    /// End it unrun (ECANCELED)
    pub fn cancel(self) {
        self.post(Err(KernelError::Canceled));
    }
}

impl Drop for OpReq {
    fn drop(&mut self) {
        if self.counted {
            self.tctx.put();
            self.ring.inflight_put();
        }
    }
}

impl OpReq {
    /// Run it as a chain member, posting its CQE: whether it broke the
    /// chain (Linux req_set_fail: an error, or a read or write short of
    /// its length, unless it is hard-linked)
    pub fn run_linked(self) -> bool {
        let hard = self.sqe.flags & IOSQE_IO_HARDLINK != 0;
        let want = self.want();
        let r = self.exec();
        let v = self.post(r);
        !hard && (v < 0 || want.is_some_and(|w| (v as usize) < w))
    }

    /// The bytes a read or write asks for
    fn want(&self) -> Option<usize> {
        match &self.body {
            Body::Rw {
                mem: RwMem::User(v),
                ..
            } => Some(crate::fs::io::seg_len(v)),
            Body::Rw { .. } => Some(self.sqe.len as usize),
            _ => None,
        }
    }
}

/// Run a link chain to its end: members in order, a failure cancelling
/// the rest (ECANCELED) unless the failed member was hard-linked (Linux
/// IOSQE_IO_LINK / IOSQE_IO_HARDLINK)
pub fn run_chain(c: KVec<OpReq>) {
    let mut failed = false;
    for o in c.into_vec() {
        if failed {
            o.cancel();
        } else {
            failed = o.run_linked();
        }
    }
}
