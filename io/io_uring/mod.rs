//! io_uring (Linux io_uring/io_uring.c, register.c, memmap.c)
//!
//! io_uring_setup makes the rings (`rings::Rings`): the SQ and CQ ring
//! region and the SQE array, mapped by user space at IORING_OFF_SQ_RING
//! (or CQ_RING: one region, IORING_FEAT_SINGLE_MMAP) and IORING_OFF_SQES.
//! io_uring_enter consumes the SQEs user space published (each copied
//! once), runs them, and posts one CQE each (unless
//! IOSQE_CQE_SKIP_SUCCESS); a full CQ keeps CQEs on an overflow list
//! (IORING_FEAT_NODROP, IORING_SQ_CQ_OVERFLOW), moved to the CQ by a
//! later io_uring_enter with IORING_ENTER_GETEVENTS once there is room.
//!
//! ## Locking (doc/LOCKING.md 3.11)
//!
//! - `IoRing.submit` (Linux uring_lock; sleeping Mutex): the kernel's SQ
//!   head, the registered files and the pending list; held across a
//!   whole submission (the operations run under it, so they may sleep)
//!   and across registration. Above `Files` (registering reads the fd
//!   table) and above `IoRing.cq`.
//! - `IoRing.cq` (Linux completion_lock; spin Mutex, thread context): the
//!   kernel's CQ tail and the overflow list; a leaf, but for the
//!   overflow list's growth, GFP_NOWAIT named (Linux
//!   io_cqe_overflow_locked). Wakeups come after it is released.

pub mod abi;
mod iowq;
mod opreq;
mod ops;
mod rings;
mod rsrc;
mod rw;
mod tctx;
mod wait;

pub use tctx::{Tctx, task_cancel};

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use abi::*;
use rings::Rings;
use rw::Kind;

use crate::fs::FileRef;
use crate::fs::KernelError;
use crate::fs::file::{File, FileOps, flags};
use crate::io::pipe::FD_CLOEXEC;
use crate::io::poll::{POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM, PollTable};
use crate::mm::page_alloc::Gfp;
use crate::sync::Mutex;
use crate::sync::waitqueue::WaitQueue;
use crate::task::percpu::current;
use crate::uaccess::{UserPtr, copy_from_user, copy_val_from_user};
use crate::util::error::KernelResult;
use crate::util::kalloc::try_arc;
use crate::util::kmem::{KDeque, KVec};

/// Valid SQE flags (Linux SQE_VALID_FLAGS)
const SQE_VALID_FLAGS: u8 = IOSQE_FIXED_FILE
    | IOSQE_IO_DRAIN
    | IOSQE_IO_LINK
    | IOSQE_IO_HARDLINK
    | IOSQE_ASYNC
    | IOSQE_BUFFER_SELECT
    | IOSQE_CQE_SKIP_SUCCESS;

/// Opcodes past Linux's last fail the SQE before it is queued (Linux
/// io_init_req: opcode >= IORING_OP_LAST)
const IORING_OP_LAST: u8 = 64;

/// What io_uring_setup reports (Linux IORING_FEAT_FLAGS, as far as hk
/// has them)
const FEATURES: u32 = IORING_FEAT_SINGLE_MMAP
    | IORING_FEAT_NODROP
    | IORING_FEAT_SUBMIT_STABLE
    | IORING_FEAT_RW_CUR_POS
    | IORING_FEAT_CUR_PERSONALITY
    | IORING_FEAT_EXT_ARG
    | IORING_FEAT_CQE_SKIP;

/// Setup flags hk implements
const SETUP_FLAGS: u32 = IORING_SETUP_CQSIZE | IORING_SETUP_CLAMP | IORING_SETUP_IOPOLL;

/// io_uring_enter flags hk accepts; SQ_WAKEUP and SQ_WAIT do nothing on
/// a ring without SQPOLL (Linux)
const ENTER_FLAGS: u32 =
    IORING_ENTER_GETEVENTS | IORING_ENTER_SQ_WAKEUP | IORING_ENTER_SQ_WAIT | IORING_ENTER_EXT_ARG;

/// The submission side, under `IoRing.submit` (Linux uring_lock)
pub struct Submit {
    /// SQ entries consumed (Linux cached_sq_head)
    sq_head: u32,
    /// Registered files
    files: Option<Vec<Option<FileRef>>>,
    /// Registered buffers (Linux buf_table)
    bufs: Option<Vec<Option<Arc<rsrc::RegBuf>>>>,
    /// user_data of poll and timeout requests noted but never completed;
    /// at most `cq_entries` (`note_pending`)
    pending: KVec<u64>,
}

/// The completion side, under `IoRing.cq` (Linux completion_lock)
struct Cq {
    /// CQEs posted (Linux cached_cq_tail)
    tail: u32,
    /// CQEs waiting for room (Linux cq_overflow_list)
    overflow: KDeque<IoUringCqe>,
}

/// One io_uring (Linux io_ring_ctx)
pub struct IoRing {
    rings: Rings,
    /// IORING_SETUP_IOPOLL: O_DIRECT only, completions polled for
    iopoll: bool,
    /// Files with polled requests issued (Linux iopoll_list, by file):
    /// polled by GETEVENTS (`iopoll_check`); emptied once nothing is in
    /// flight
    poll_files: crate::sync::Mutex<KVec<FileRef>>,
    /// The user its locked memory is charged to (Linux ctx->user: none
    /// with CAP_IPC_LOCK), and its rings' pages charged
    acct: Option<crate::task::Uid>,
    ring_pages: u64,
    submit: Mutex<Submit>,
    cq: crate::sync::spin::Mutex<Cq>,
    /// `cq.overflow` holds CQEs (Linux IO_CHECK_CQ_OVERFLOW_BIT): set and
    /// cleared under `cq`, read lock-free by poll and GETEVENTS to skip
    /// the lock when nothing waits
    overflowed: AtomicBool,
    /// A CQE was lost since GETEVENTS last said so (Linux
    /// IO_CHECK_CQ_DROPPED_BIT): set under `cq`, cleared by the wait
    /// that returns EBADR
    dropped: AtomicBool,
    /// Pollers of the ring fd (Linux poll_wq)
    wq: WaitQueue,
    /// GETEVENTS waiters (Linux cq_wait), woken by every CQE posted
    cq_wait: WaitQueue,
    /// Asynchronous requests in flight (Linux ctx->refs as a count)
    inflight: AtomicU32,
    /// Woken when `inflight` drops to zero
    idle: WaitQueue,
    /// Requests held back by a drain (Linux defer_list), in order
    defer: crate::sync::spin::Mutex<KDeque<Deferred>>,
}

/// The SQEs' link state across one submission: a chain's members are
/// gathered, then run in order (Linux IOSQE_IO_LINK; a failed member
/// cancels the rest unless it is hard-linked)
#[derive(Default)]
struct Link {
    /// Inside a chain
    on: bool,
    /// Its members so far
    sqes: KVec<IoUringSqe>,
}

/// A request a drain held back (Linux io_defer_entry)
struct Deferred {
    op: opreq::OpReq,
    /// It is itself an IOSQE_IO_DRAIN request: it runs alone, after
    /// everything before it, and before everything after it
    drain: bool,
}

impl Submit {
    /// Registered buffer `i` (EFAULT for none: Linux io_import_reg_buf)
    pub fn fixed_buf(&self, i: u16) -> KernelResult<&Arc<rsrc::RegBuf>> {
        self.bufs
            .as_ref()
            .and_then(|t| t.get(usize::from(i)))
            .and_then(Option::as_ref)
            .ok_or(KernelError::BadAddress)
    }

    /// Note a request that stays pending: at most `max` (the CQ size: the
    /// CQEs they could ever post), EAGAIN past it (Linux: a request that
    /// cannot be allocated)
    pub fn note_pending(&mut self, user_data: u64, max: u32) -> KernelResult<()> {
        if self.pending.len() >= max as usize {
            return Err(KernelError::WouldBlock);
        }
        self.pending.try_push(user_data)
    }
}

impl IoRing {
    fn new(sq: u32, cq: u32, flags: u32) -> KernelResult<Arc<Self>> {
        let rings = Rings::new(sq, cq)?;
        let acct = rsrc::acct_user();
        let ring_pages = rings.pages();
        rsrc::account(acct, ring_pages)?;
        try_arc(Self {
            rings,
            iopoll: flags & IORING_SETUP_IOPOLL != 0,
            poll_files: crate::sync::Mutex::new(KVec::new()),
            acct,
            ring_pages,
            submit: Mutex::new(Submit {
                sq_head: 0,
                files: None,
                bufs: None,
                pending: KVec::new(),
            }),
            cq: crate::sync::spin::Mutex::new(Cq {
                tail: 0,
                overflow: KDeque::new(),
            }),
            overflowed: AtomicBool::new(false),
            dropped: AtomicBool::new(false),
            wq: WaitQueue::new(),
            cq_wait: WaitQueue::new(),
            inflight: AtomicU32::new(0),
            idle: WaitQueue::new(),
            defer: crate::sync::spin::Mutex::new(KDeque::new()),
        })
        // A failed allocation drops the ring it was given, whose Drop
        // gives the charge back: nothing to undo here
    }

    /// Consume up to `nr` published SQEs and run them (Linux
    /// io_submit_sqes): the number consumed. An SQ array slot naming no
    /// SQE is dropped (sq_dropped) and ends the batch; so does an SQE
    /// that fails before it runs, counted.
    fn submit(self: &Arc<Self>, nr: u32) -> u32 {
        let mut s = self.submit.lock();
        let ready = self.rings.sq_tail().wrapping_sub(s.sq_head);
        let n = nr.min(ready.min(self.rings.sq_entries()));
        let mut link = Link::default();
        let mut done = 0;
        for _ in 0..n {
            let slot = s.sq_head;
            s.sq_head = slot.wrapping_add(1);
            let i = self.rings.sq_index(slot);
            if i >= self.rings.sq_entries() {
                self.rings.inc_dropped();
                break;
            }
            let sqe = self.rings.sqe(i);
            done += 1;
            if !self.submit_sqe(&mut s, &sqe, &mut link) {
                break;
            }
        }
        // The SQEs are copied: their slots are user space's again
        self.rings.set_sq_head(s.sq_head);
        done
    }

    /// Run one SQE and post its CQE (when it ends, for one queued): false
    /// if it failed before running (Linux io_init_req), which ends the
    /// batch. A chain's members are gathered and run together (`chain`);
    /// a drain, and what follows it while one is held back, waits on the
    /// defer list for the requests before it (Linux io_drain_req).
    fn submit_sqe(self: &Arc<Self>, s: &mut Submit, sqe: &IoUringSqe, link: &mut Link) -> bool {
        let linked = sqe.flags & (IOSQE_IO_LINK | IOSQE_IO_HARDLINK) != 0;
        if let Err(e) = init_check(sqe, self.iopoll) {
            self.post_cqe(sqe.user_data, e.to_errno_neg(), 0);
            // The chain it ended is cancelled with it
            for m in core::mem::take(link).sqes.iter() {
                self.post_cqe(m.user_data, KernelError::Canceled.to_errno_neg(), 0);
            }
            return false;
        }
        if link.on || linked {
            if let Err(e) = link.sqes.try_push(*sqe) {
                self.post_cqe(sqe.user_data, e.to_errno_neg(), 0);
            }
            link.on = linked;
            if !linked {
                let sqes = core::mem::take(&mut link.sqes);
                self.chain(s, sqes);
            }
            return true;
        }
        let drain = sqe.flags & IOSQE_IO_DRAIN != 0;
        if (drain || !self.defer.lock().is_empty()) && self.defer_sqe(s, sqe, drain) {
            return true;
        }
        if let Some(res) = self.issue(s, sqe) {
            let res = res.unwrap_or_else(KernelError::to_errno_neg);
            if sqe.flags & IOSQE_CQE_SKIP_SUCCESS == 0 || res < 0 {
                self.post_cqe(sqe.user_data, res, 0);
            }
        }
        true
    }

    /// Run the operation of `sqe`: its result, None if queued
    fn issue(self: &Arc<Self>, s: &mut Submit, sqe: &IoUringSqe) -> Option<KernelResult<i32>> {
        match sqe.opcode {
            IORING_OP_READ => return rw::rw(self, s, sqe, false, Kind::Buf),
            IORING_OP_WRITE => return rw::rw(self, s, sqe, true, Kind::Buf),
            IORING_OP_READV => return rw::rw(self, s, sqe, false, Kind::Vec),
            IORING_OP_WRITEV => return rw::rw(self, s, sqe, true, Kind::Vec),
            IORING_OP_READ_FIXED => return rw::rw(self, s, sqe, false, Kind::Fixed),
            IORING_OP_WRITE_FIXED => return rw::rw(self, s, sqe, true, Kind::Fixed),
            // Valid only inside a chain
            IORING_OP_LINK_TIMEOUT => return Some(Err(KernelError::InvalidArgument)),
            _ => {}
        }
        let force = sqe.flags & IOSQE_ASYNC != 0;
        match ops::how(sqe.opcode) {
            ops::How::Inline => {
                Some(ops::issue(self, s, sqe).unwrap_or(Err(KernelError::InvalidArgument)))
            }
            ops::How::TryNoWait if !force => match ops::try_nowait(sqe) {
                Err(KernelError::WouldBlock) => rw::punt(self, sqe, opreq::Body::Op),
                r => Some(r),
            },
            ops::How::TryNoWait | ops::How::Punt => rw::punt(self, sqe, opreq::Body::Op),
        }
    }

    /// A worker's request for `sqe`, not yet in flight: what it needs of
    /// the submission resolved now (a read or write's file, iovecs or
    /// registered buffer; Linux io_prep_rw), a failure kept as its result
    fn prep(self: &Arc<Self>, s: &Submit, sqe: &IoUringSqe) -> KernelResult<opreq::OpReq> {
        let t = tctx::tctx()?;
        let rw = match sqe.opcode {
            IORING_OP_READ | IORING_OP_READV | IORING_OP_READ_FIXED => Some(false),
            IORING_OP_WRITE | IORING_OP_WRITEV | IORING_OP_WRITE_FIXED => Some(true),
            _ => None,
        };
        let body = match rw {
            Some(write) => rw::prep_body(self, s, sqe, write).unwrap_or_else(opreq::Body::Failed),
            None => opreq::Body::Op,
        };
        Ok(opreq::OpReq::new(self, &t, *sqe, body))
    }

    /// Run a link chain (Linux IOSQE_IO_LINK): its members in order, in a
    /// worker; with an operation that needs the submission state (the
    /// poll/timeout bookkeeping) it runs here instead
    fn chain(self: &Arc<Self>, s: &mut Submit, sqes: KVec<IoUringSqe>) {
        if sqes.iter().any(|q| needs_submit(q.opcode)) {
            return self.chain_inline(s, &sqes);
        }
        let mut c = match KVec::try_with_capacity(sqes.len()) {
            Ok(c) => c,
            Err(e) => return self.fail_all(&sqes, e),
        };
        let mut unbound = false;
        for q in sqes.iter() {
            match self.prep(s, q) {
                Ok(mut o) => {
                    unbound |= o.unbound();
                    o.count();
                    // Room was reserved
                    let _ = c.try_push(o);
                }
                Err(e) => return self.fail_all(&sqes, e),
            }
        }
        let wq = tctx::tctx().and_then(|t| t.io_wq());
        match wq.and_then(|wq| iowq::Work::new(iowq::WorkKind::Chain(c)).map(|w| (wq, w))) {
            Ok((wq, w)) => wq.queue(w, unbound),
            Err(e) => self.fail_all(&sqes, e),
        }
    }

    /// A chain run in io_uring_enter, its members to their ends in order
    fn chain_inline(self: &Arc<Self>, s: &mut Submit, sqes: &[IoUringSqe]) {
        let mut failed = false;
        for q in sqes {
            let res = if failed {
                Err(KernelError::Canceled)
            } else if q.opcode == IORING_OP_LINK_TIMEOUT {
                // It arms nothing (BUGS "io_uring gaps")
                Ok(0)
            } else if ops::how(q.opcode) == ops::How::Inline {
                ops::issue(self, s, q).unwrap_or(Err(KernelError::InvalidArgument))
            } else {
                // Anything else to its end, here (a read or write: a short
                // one breaks the chain)
                match self.prep(s, q) {
                    Ok(o) => {
                        failed = o.run_linked();
                        continue;
                    }
                    Err(e) => Err(e),
                }
            };
            let res = res.unwrap_or_else(KernelError::to_errno_neg);
            if res < 0 && q.flags & IOSQE_IO_HARDLINK == 0 {
                failed = true;
            }
            if q.flags & IOSQE_CQE_SKIP_SUCCESS == 0 || res < 0 {
                self.post_cqe(q.user_data, res, 0);
            }
        }
    }

    /// Fail every SQE of `sqes` with `e`
    fn fail_all(&self, sqes: &[IoUringSqe], e: KernelError) {
        for q in sqes {
            self.post_cqe(q.user_data, e.to_errno_neg(), 0);
        }
    }

    /// Hold `sqe` back on the defer list (Linux io_drain_req): false if
    /// it may run now (nothing in flight or held back)
    fn defer_sqe(self: &Arc<Self>, s: &Submit, sqe: &IoUringSqe, drain: bool) -> bool {
        {
            let d = self.defer.lock();
            if d.is_empty() && self.inflight.load(Ordering::Acquire) == 0 {
                return false;
            }
        }
        let o = match self.prep(s, sqe) {
            Ok(o) => o,
            Err(e) => {
                self.post_cqe(sqe.user_data, e.to_errno_neg(), 0);
                return true;
            }
        };
        // Made in the owner now: the flush may come from anywhere
        if let Err(e) = o.tctx().io_wq() {
            self.post_cqe(sqe.user_data, e.to_errno_neg(), 0);
            return true;
        }
        let pushed = self.defer.lock().try_push_back(Deferred { op: o, drain });
        if let Err(e) = pushed {
            self.post_cqe(sqe.user_data, e.to_errno_neg(), 0);
            return true;
        }
        // Its predecessors may have ended meanwhile
        self.flush_defer();
        true
    }

    /// With nothing in flight, queue what the defer list holds up to the
    /// next drain: a drain alone, else every request before the next one
    /// (Linux io_queue_deferred)
    fn flush_defer(&self) {
        let first = {
            let mut d = self.defer.lock();
            if self.inflight.load(Ordering::Acquire) != 0 {
                return;
            }
            match d.pop_front() {
                Some(f) => f,
                None => return,
            }
        };
        let drain = first.drain;
        self.queue_deferred(first.op);
        if drain {
            return;
        }
        // In flight now: the rest before the next drain go too
        loop {
            let next = {
                let mut d = self.defer.lock();
                if d.front().is_none_or(|f| f.drain) {
                    return;
                }
                d.pop_front()
            };
            if let Some(n) = next {
                self.queue_deferred(n.op);
            }
        }
    }

    /// Queue a held-back request on its submitter's io-wq
    fn queue_deferred(&self, mut o: opreq::OpReq) {
        let unbound = o.unbound();
        o.count();
        let Some(wq) = o.tctx().io_wq_get() else {
            return o.cancel();
        };
        // A failed box drops the request: its CQE is lost (no memory)
        if let Ok(w) = iowq::Work::new(iowq::WorkKind::Op(o)) {
            wq.queue(w, unbound);
        }
    }

    /// One more asynchronous request in flight
    fn inflight_get(&self) {
        self.inflight.fetch_add(1, Ordering::Relaxed);
    }

    /// One fewer; the last lets the held-back requests go
    fn inflight_put(&self) {
        if self.inflight.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.idle.wake_all();
            self.flush_defer();
        }
    }

    /// The SQE's file: a registered one with IOSQE_FIXED_FILE, else its
    /// fd's; EBADF
    fn sqe_file(&self, s: &Submit, sqe: &IoUringSqe) -> KernelResult<FileRef> {
        if sqe.flags & IOSQE_FIXED_FILE != 0 {
            let fixed = s.files.as_ref().and_then(|f| f.get(sqe.fd as u32 as usize));
            return fixed.cloned().flatten().ok_or(KernelError::BadFd);
        }
        crate::fs::io::fget(sqe.fd).map_err(|_| KernelError::BadFd)
    }

    /// Post a CQE (Linux io_post_aux_cqe / io_req_complete_post): into
    /// the CQ if it has room and nothing overflowed before, else onto the
    /// overflow list; if even that cannot grow, it is lost and counted
    /// (cq_overflow)
    pub fn post_cqe(&self, user_data: u64, res: i32, flags: u32) {
        let cqe = IoUringCqe {
            user_data,
            res,
            flags,
        };
        {
            let mut cq = self.cq.lock();
            if cq.overflow.is_empty() && self.cq_room(cq.tail) {
                self.rings.write_cqe(cq.tail, cqe);
                cq.tail = cq.tail.wrapping_add(1);
                self.rings.set_cq_tail(cq.tail);
            } else {
                self.overflow(&mut cq, cqe);
            }
        }
        self.cq_wake();
    }

    /// Wake GETEVENTS waiters and pollers (Linux io_cqring_wake)
    fn cq_wake(&self) {
        self.cq_wait.wake_all();
        self.wq.wake_poll(u32::from(POLLIN | POLLRDNORM));
    }

    /// The CQ has room past `tail`
    fn cq_room(&self, tail: u32) -> bool {
        tail.wrapping_sub(self.rings.cq_head()) < self.rings.cq_entries()
    }

    /// Keep `cqe` until there is room (Linux io_cqe_overflow_locked,
    /// GFP_NOWAIT under the completion lock):
    /// at most as many as the CQ holds (Linux charges each to the memory
    /// cgroup; hk has none, so the list is bounded instead), and one that
    /// does not fit is lost: counted in cq_overflow, and the next
    /// GETEVENTS wait says EBADR (Linux IO_CHECK_CQ_DROPPED_BIT)
    fn overflow(&self, cq: &mut Cq, cqe: IoUringCqe) {
        if cq.overflow.len() >= self.rings.cq_entries() as usize
            || cq.overflow.try_push_back_gfp(cqe, Gfp::NOWAIT).is_err()
        {
            self.rings.inc_cq_overflow();
            self.dropped.store(true, Ordering::Release);
            return;
        }
        if cq.overflow.len() == 1 {
            self.overflowed.store(true, Ordering::Release);
            self.rings.sq_flags(IORING_SQ_CQ_OVERFLOW, true);
        }
    }

    /// Move overflowed CQEs into the CQ while it has room (Linux
    /// __io_cqring_overflow_flush)
    fn flush_overflow(&self) {
        if !self.overflowed.load(Ordering::Acquire) {
            return;
        }
        let mut cq = self.cq.lock();
        let start = cq.tail;
        while let Some(&cqe) = cq.overflow.front() {
            if !self.cq_room(cq.tail) {
                break;
            }
            self.rings.write_cqe(cq.tail, cqe);
            cq.tail = cq.tail.wrapping_add(1);
            cq.overflow.pop_front();
        }
        if cq.tail != start {
            self.rings.set_cq_tail(cq.tail);
        }
        if cq.overflow.is_empty() {
            self.overflowed.store(false, Ordering::Release);
            self.rings.sq_flags(IORING_SQ_CQ_OVERFLOW, false);
        }
    }

    /// CQEs user space has not consumed, or overflowed ones wait
    fn cq_ready(&self) -> bool {
        self.rings.cq_tail() != self.rings.cq_head() || self.overflowed.load(Ordering::Acquire)
    }

    /// Register files for fixed file access (Linux
    /// io_sqe_files_register): EBUSY if some are
    fn register_files(&self, fds: &[i32]) -> KernelResult<()> {
        // Reserved before any lock: no allocation under the fd table's
        let mut files = KVec::try_with_capacity(fds.len())?;
        let fd_table = current().files().ok_or(KernelError::BadFd)?;
        let mut s = self.submit.lock();
        if s.files.is_some() {
            return Err(KernelError::Busy);
        }
        {
            let t = fd_table.lock();
            for &fd in fds {
                let slot = if fd == -1 {
                    None
                } else {
                    Some(reg_file(t.get(fd))?)
                };
                // Capacity is reserved; this cannot fail
                let _ = files.try_push(slot);
            }
        }
        s.files = Some(files.into_vec());
        Ok(())
    }

    /// Register `nr` buffers from the iovec array at `arg` (Linux
    /// io_sqe_buffers_register): EINVAL for none or too many, EBUSY if
    /// some are; each pinned and charged (`rsrc`)
    fn register_buffers(&self, arg: u64, nr: u32) -> KernelResult<()> {
        let n = nr as usize;
        if n == 0 || n > rsrc::IORING_MAX_REG_BUFFERS {
            return Err(KernelError::InvalidArgument);
        }
        let mut iovs = crate::util::kmem::try_vec(n, crate::fs::iov::IoVec::default())?;
        copy_from_user(crate::util::pod::slice_bytes_mut(&mut iovs), arg, n * 16)?;
        let mut s = self.submit.lock();
        if s.bufs.is_some() {
            return Err(KernelError::Busy);
        }
        s.bufs = Some(rsrc::register(&iovs, self.acct)?);
        Ok(())
    }

    /// Drop the registered buffers (ENXIO if none, Linux
    /// io_sqe_buffers_unregister); unpinned after the lock, or when the
    /// last request using one ends
    fn unregister_buffers(&self) -> KernelResult<()> {
        let old = self.submit.lock().bufs.take();
        old.map(drop).ok_or(KernelError::NoDeviceOrAddress)
    }

    /// Drop the registered files (ENXIO if none, Linux
    /// io_sqe_files_unregister); released after the lock
    fn unregister_files(&self) -> KernelResult<()> {
        let old = self.submit.lock().files.take();
        old.map(drop).ok_or(KernelError::NoDeviceOrAddress)
    }

    /// Replace registered files from `offset` on (-1 empties a slot,
    /// IORING_REGISTER_FILES_SKIP leaves it): the number done up to the
    /// first bad fd, whose slot is left empty, its error if that is the
    /// first (Linux __io_sqe_files_update)
    fn update_files(&self, offset: u32, fds: &[i32]) -> KernelResult<usize> {
        /// Leave the slot as it is (Linux IORING_REGISTER_FILES_SKIP)
        const SKIP: i32 = -2;
        // The replaced files are released after both locks
        let mut old = KVec::try_with_capacity(fds.len())?;
        let fd_table = current().files().ok_or(KernelError::BadFd)?;
        let mut s = self.submit.lock();
        let reg = s.files.as_mut().ok_or(KernelError::NoDeviceOrAddress)?;
        let offset = offset as usize;
        if offset.checked_add(fds.len()).is_none_or(|e| e > reg.len()) {
            return Err(KernelError::InvalidArgument);
        }
        let t = fd_table.lock();
        let (mut done, mut err) = (0, None);
        for (i, &fd) in fds.iter().enumerate() {
            if fd == SKIP {
                done += 1;
                continue;
            }
            // The slot is emptied first, so a bad fd leaves it empty
            // (Linux: io_reset_rsrc_node before the fget)
            // Capacity is reserved; this cannot fail
            let _ = old.try_push(reg[offset + i].take());
            if fd != -1 {
                match reg_file(t.get(fd)) {
                    Ok(f) => reg[offset + i] = Some(f),
                    Err(e) => {
                        err = Some(e);
                        break;
                    }
                }
            }
            done += 1;
        }
        drop(t);
        drop(s);
        drop(old);
        // The count done, or the error if none was (Linux
        // __io_sqe_files_update: done ? done : err)
        match err {
            Some(e) if done == 0 => Err(e),
            _ => Ok(done),
        }
    }

    /// Entries in the CQ
    fn cq_entries(&self) -> u32 {
        self.rings.cq_entries()
    }

    /// The SQ head user space sees (the kernel's last published one)
    fn sq_head(&self) -> u32 {
        self.rings.sq_head()
    }
}

/// The poll/timeout bookkeeping, which needs the submission state
fn needs_submit(op: u8) -> bool {
    matches!(
        op,
        IORING_OP_POLL_ADD
            | IORING_OP_POLL_REMOVE
            | IORING_OP_TIMEOUT
            | IORING_OP_TIMEOUT_REMOVE
            | IORING_OP_ASYNC_CANCEL
    )
}

/// The checks an SQE fails before it is queued (Linux io_init_req):
/// an opcode past the last, unknown SQE flags, a personality (none can
/// be registered), and on an IOPOLL ring an operation that cannot be
/// polled (Linux !def->iopoll)
fn init_check(sqe: &IoUringSqe, iopoll: bool) -> KernelResult<()> {
    if sqe.opcode >= IORING_OP_LAST || sqe.flags & !SQE_VALID_FLAGS != 0 || sqe.personality != 0 {
        return Err(KernelError::InvalidArgument);
    }
    let pollable = matches!(
        sqe.opcode,
        IORING_OP_NOP
            | IORING_OP_READV
            | IORING_OP_WRITEV
            | IORING_OP_READ_FIXED
            | IORING_OP_WRITE_FIXED
            | IORING_OP_READ
            | IORING_OP_WRITE
    );
    if iopoll && !pollable {
        return Err(KernelError::InvalidArgument);
    }
    Ok(())
}

impl Drop for IoRing {
    fn drop(&mut self) {
        rsrc::unaccount(self.acct, self.ring_pages);
    }
}

// ============================================================================
// The io_uring file
// ============================================================================

/// File operations of an io_uring fd (Linux io_uring_fops)
pub struct IoUringFileOps;

static IO_URING_FOPS: IoUringFileOps = IoUringFileOps;

impl FileOps for IoUringFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    /// Readable with CQEs to reap (or overflowed ones), writable while
    /// the SQ has room (Linux io_uring_poll)
    fn poll(&self, file: &File, pt: Option<&mut PollTable<'_>>) -> u16 {
        let Some(r) = file.private_ref::<IoRing>() else {
            return crate::io::poll::POLLERR;
        };
        if let Some(pt) = pt {
            pt.poll_wait(&r.wq);
        }
        let mut mask = 0;
        if r.rings.sq_tail().wrapping_sub(r.sq_head()) != r.rings.sq_entries() {
            mask |= POLLOUT | POLLWRNORM;
        }
        if r.cq_ready() {
            mask |= POLLIN | POLLRDNORM;
        }
        mask
    }

    /// The rings map, shared or private (Linux io_uring_mmap)
    fn mmap(&self, _file: &File, _shared: bool) -> Result<(), KernelError> {
        Ok(())
    }

    /// At IORING_OFF_SQ_RING, CQ_RING or SQES only (Linux
    /// io_uring_validate_mmap_request)
    fn mmap_offset(&self, file: &File, off: u64) -> Result<(), KernelError> {
        let r = file.private_ref::<IoRing>().ok_or(KernelError::BadFd)?;
        r.rings
            .region(off & IORING_OFF_MMAP_MASK)
            .map(|_| ())
            .ok_or(KernelError::InvalidArgument)
    }

    fn maps_driver_pages(&self, _file: &File) -> bool {
        true
    }

    /// Page `idx` of the region the mapping's offset selects, whatever
    /// the offset's low bits (Linux io_region_mmap: vm_insert_pages from
    /// the region's first page); none past the region
    // SAFETY: the region's frames hold only the rings and SQEs shared
    // with user space, and each one handed out carries a reference that
    // keeps it allocated (`SharedRegion::map_page`)
    unsafe fn map_page(&self, file: &File, off: u64, idx: u64) -> Option<Result<u64, KernelError>> {
        let r = file.private_ref::<IoRing>()?;
        let region = r.rings.region(off & IORING_OFF_MMAP_MASK)?;
        region.map_page(idx).map(Ok)
    }
}

/// The io_uring behind `file`
pub fn get_io_uring(file: &File) -> Option<Arc<IoRing>> {
    file.private_arc::<IoRing>()
}

/// Copy an `int fds[n]` array from user space (EMFILE over
/// IORING_MAX_FIXED_FILES, as Linux io_sqe_files_register)
fn read_user_fds(arg: u64, n: usize) -> Result<Vec<i32>, KernelError> {
    /// Most registered files (Linux IORING_MAX_FIXED_FILES)
    const IORING_MAX_FIXED_FILES: usize = 1 << 15;
    if n > IORING_MAX_FIXED_FILES {
        return Err(KernelError::ProcessFileLimit);
    }
    let mut fds = crate::util::kmem::try_vec(n, 0i32)?;
    copy_from_user(crate::util::pod::slice_bytes_mut(&mut fds), arg, n * 4)?;
    Ok(fds)
}

/// A file to register: none, a path-only one or an io_uring is EBADF
/// (Linux io_sqe_files_register: fget, io_is_uring_fops; a ring in a
/// ring's table would keep both alive forever)
fn reg_file(f: Option<FileRef>) -> KernelResult<FileRef> {
    f.filter(|f| !f.is_path() && !is_uring(f))
        .ok_or(KernelError::BadFd)
}

/// `f` is an io_uring (Linux io_is_uring_fops)
pub fn is_uring(f: &File) -> bool {
    f.f_op.as_any().is::<IoUringFileOps>()
}

// ============================================================================
// Syscalls
// ============================================================================

/// The SQ and CQ sizes for `entries` and `p` (Linux io_uring_fill_params):
/// powers of two, the CQ twice the SQ unless IORING_SETUP_CQSIZE; past
/// the limits EINVAL, or the limit with IORING_SETUP_CLAMP
fn ring_sizes(entries: u32, p: &IoUringParams) -> KernelResult<(u32, u32)> {
    let clamp = p.flags & IORING_SETUP_CLAMP != 0;
    let fit = |n: u32, max: u32| match n {
        0 => Err(KernelError::InvalidArgument),
        n if n > max && !clamp => Err(KernelError::InvalidArgument),
        n => Ok(n.min(max).next_power_of_two()),
    };
    let sq = fit(entries, IORING_MAX_ENTRIES)?;
    if p.flags & IORING_SETUP_CQSIZE == 0 {
        return Ok((sq, 2 * sq));
    }
    let cq = fit(p.cq_entries, IORING_MAX_CQ_ENTRIES)?;
    if cq < sq {
        return Err(KernelError::InvalidArgument);
    }
    Ok((sq, cq))
}

/// io_uring_setup(entries, params): a new io_uring's fd, its sizes,
/// features and ring offsets written to `params` (Linux io_uring_setup)
pub fn sys_io_uring_setup(entries: u32, params_ptr: UserPtr<IoUringParams>) -> KernelResult<i32> {
    let mut p = params_ptr.read()?;
    if p.resv.iter().any(|&r| r != 0) || p.flags & !SETUP_FLAGS != 0 {
        return Err(KernelError::InvalidArgument);
    }
    let (sq, cq) = ring_sizes(entries, &p)?;
    let ring = IoRing::new(sq, cq, p.flags)?;
    p.sq_entries = sq;
    p.cq_entries = cq;
    p.features = FEATURES;
    (p.sq_off, p.cq_off) = ring.rings.offsets();
    params_ptr.write(&p)?;
    let file = crate::fs::anon_inodes::anon_inode_getfile(
        "[io_uring]",
        &IO_URING_FOPS,
        ring,
        flags::O_RDWR,
    )?;
    crate::fs::io::fd_install(file, FD_CLOEXEC)
}

/// io_uring_enter(fd, to_submit, min_complete, flags, argp, argsz):
/// consume up to `to_submit` SQEs, the number consumed (Linux
/// io_uring_enter); with IORING_ENTER_GETEVENTS, after a full
/// submission, wait for `min_complete` CQEs (`wait`), whose error is
/// returned if nothing was submitted
pub fn sys_io_uring_enter(
    fd: u32,
    to_submit: u32,
    min_complete: u32,
    flags: u32,
    argp: u64,
    argsz: usize,
) -> KernelResult<u32> {
    if flags & !ENTER_FLAGS != 0 {
        return Err(KernelError::InvalidArgument);
    }
    let ring = ring_of(fd)?;
    let mut ret = 0;
    if to_submit > 0 {
        ret = ring.submit(to_submit);
        if ret != to_submit {
            return Ok(ret);
        }
    }
    if flags & IORING_ENTER_GETEVENTS != 0 {
        let r = wait::get_ext_arg(flags, argp, argsz).and_then(|ext| {
            if ring.iopoll {
                ring.iopoll_check(min_complete)
            } else {
                ring.cq_wait(min_complete, &ext)
            }
        });
        if ret == 0 {
            // Told once: the drop is reported (Linux clears
            // IO_CHECK_CQ_DROPPED_BIT on returning EBADR)
            if r == Err(KernelError::BadRequest) {
                ring.dropped.store(false, Ordering::Release);
            }
            r?;
        }
    }
    Ok(ret)
}

/// The io_uring open at `fd`: EBADF for no file, EOPNOTSUPP for another
/// kind (Linux io_uring_ctx_get_file)
fn ring_of(fd: u32) -> KernelResult<Arc<IoRing>> {
    let file = crate::fs::io::fget(fd as i32)?;
    get_io_uring(&file).ok_or(KernelError::OperationNotSupported)
}

/// struct io_uring_files_update
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FilesUpdate {
    offset: u32,
    resv: u32,
    fds: u64,
}
crate::pod!(FilesUpdate { offset, resv, fds });

/// io_uring_register(fd, opcode, arg, nr_args) (Linux
/// __io_uring_register): 0, or the number updated for
/// IORING_REGISTER_FILES_UPDATE
pub fn sys_io_uring_register(fd: u32, opcode: u32, arg: u64, nr_args: u32) -> KernelResult<usize> {
    let ring = ring_of(fd)?;
    match opcode {
        IORING_REGISTER_FILES => {
            if nr_args == 0 {
                return Err(KernelError::InvalidArgument);
            }
            let fds = read_user_fds(arg, nr_args as usize)?;
            ring.register_files(&fds).map(|()| 0)
        }
        IORING_UNREGISTER_FILES if arg == 0 && nr_args == 0 => ring.unregister_files().map(|()| 0),
        IORING_UNREGISTER_FILES => Err(KernelError::InvalidArgument),
        IORING_REGISTER_BUFFERS => ring.register_buffers(arg, nr_args).map(|()| 0),
        IORING_UNREGISTER_BUFFERS if arg == 0 && nr_args == 0 => {
            ring.unregister_buffers().map(|()| 0)
        }
        IORING_UNREGISTER_BUFFERS => Err(KernelError::InvalidArgument),
        // Not implemented yet
        IORING_REGISTER_EVENTFD | IORING_UNREGISTER_EVENTFD => {
            Err(KernelError::OperationNotSupported)
        }
        IORING_REGISTER_FILES_UPDATE => {
            if nr_args == 0 {
                return Err(KernelError::InvalidArgument);
            }
            let up: FilesUpdate = copy_val_from_user(arg)?;
            if up.resv != 0 {
                return Err(KernelError::InvalidArgument);
            }
            let fds = read_user_fds(up.fds, nr_args as usize)?;
            ring.update_files(up.offset, &fds)
        }
        _ => Err(KernelError::InvalidArgument),
    }
}
