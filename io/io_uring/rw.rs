//! IORING_OP_READ, WRITE, READV and WRITEV (Linux io_uring/rw.c)
//!
//! O_DIRECT I/O on a file that can start it without waiting (a block
//! device: `FileOps::can_async_dio`) runs asynchronously: the memory is
//! pinned in the submitter (Linux io_import_iovec + the bio's pin), the
//! request issued with IOCB_NOWAIT (Linux io_read/io_write in the
//! submitter, IO_URING_F_NONBLOCK); if that would wait (EAGAIN) it is
//! issued again, blocking, by an io-wq worker (Linux -EAGAIN ->
//! io_queue_iowq), unless the SQE asked RWF_NOWAIT. The bios' end
//! completes the request (`AsyncIo::complete`, Linux io_complete_rw),
//! which is finished in the submitter's context (`Tctx`). Everything
//! else, and requests in a link chain or behind a drain, runs inline
//! through the read/write core.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use super::abi::{IOSQE_ASYNC, IOSQE_CQE_SKIP_SUCCESS, IoUringSqe};
use super::ops::cqe_count;
use super::rsrc::RegBuf;
use super::tctx::{Tctx, tctx};
use super::{IoRing, Submit};
use crate::block::dio::AsyncIo;
use crate::fs::file::{File, RwFlags};
use crate::fs::iov::IoVec;
use crate::fs::iov_iter::{IovDest, IovSource};
use crate::mm::gup::{PageSeg, PinnedPages};
use crate::task::percpu::TaskRef;
use crate::task::percpu::current;
use crate::uaccess::UserPtr;
use crate::util::error::{KernelError, KernelResult};
use crate::util::kalloc::try_arc;
use crate::util::list::Link;
use crate::util::smallvec::SmallVec;

/// The SQE's file, opened for reading (`write` false) or writing, like
/// read(2)/write(2) (EBADF)
fn rw_file(r: &IoRing, s: &Submit, sqe: &IoUringSqe, write: bool) -> KernelResult<Arc<File>> {
    let file = r.sqe_file(s, sqe)?;
    let ok = if write {
        file.is_writable()
    } else {
        file.is_readable()
    };
    if !ok {
        return Err(KernelError::BadFd);
    }
    Ok(file)
}

/// The SQE's RWF_* flags (rw_flags): unknown ones are EOPNOTSUPP (Linux
/// kiocb_set_rw_flags)
fn rw_flags(sqe: &IoUringSqe) -> KernelResult<RwFlags> {
    crate::fs::iov::rwf_check(sqe.op_flags as i32)
}

/// How a read or write names its memory
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `len` bytes at `addr` (READ, WRITE)
    Buf,
    /// `len` iovecs at `addr` (READV, WRITEV)
    Vec,
    /// `len` bytes at `addr` of registered buffer `buf_index`
    /// (READ_FIXED, WRITE_FIXED)
    Fixed,
}

/// The user memory of a READ/WRITE or _FIXED (`len` bytes at `addr`) or
/// a READV/WRITEV (`len` iovecs at `addr`, checked and cut like readv's:
/// Linux io_import_iovec -> __import_iovec)
fn import(sqe: &IoUringSqe, kind: Kind) -> KernelResult<alloc::vec::Vec<IoVec>> {
    if kind == Kind::Vec {
        let n = i32::try_from(sqe.len).map_err(|_| KernelError::InvalidArgument)?;
        return crate::fs::iov::import_iovec(UserPtr::new(sqe.addr), n);
    }
    let seg = crate::fs::io::import_ubuf(UserPtr::new(sqe.addr), u64::from(sqe.len))?;
    crate::util::kmem::try_to_vec(&seg)
}

/// IORING_OP_READ/WRITE, READV/WRITEV and READ_FIXED/WRITE_FIXED: the
/// result, or None when queued (its CQE comes when it ends). `inline`:
/// run it through the blocking core (a chain or drain member; a fixed
/// buffer then goes by its user addresses: BUGS)
pub fn rw(
    r: &Arc<IoRing>,
    s: &Submit,
    sqe: &IoUringSqe,
    write: bool,
    kind: Kind,
    inline: bool,
) -> Option<KernelResult<i32>> {
    let prep = rw_file(r, s, sqe, write).and_then(|f| {
        let flags = rw_flags(sqe)?;
        let fixed = match kind {
            Kind::Fixed => {
                let b = s.fixed_buf(sqe.buf_index)?;
                Some((b.clone(), b.slice(sqe.addr, sqe.len as usize)?))
            }
            _ => None,
        };
        Ok((f, flags, import(sqe, kind)?, fixed))
    });
    let (file, mut flags, segs, fixed) = match prep {
        Ok(p) => p,
        Err(e) => return Some(Err(e)),
    };
    // IOPOLL: O_DIRECT only, polled (Linux io_rw_init_file: IOCB_HIPRI,
    // EOPNOTSUPP without IOCB_DIRECT or ->iopoll)
    if r.iopoll {
        if !async_ok(&file) {
            return Some(Err(KernelError::OperationNotSupported));
        }
        flags |= RwFlags::HIPRI;
    } else if flags.contains(RwFlags::HIPRI) {
        // Polled I/O only on an IOPOLL ring (Linux io_rw_init_file:
        // IOCB_HIPRI without IORING_SETUP_IOPOLL is EINVAL)
        return Some(Err(KernelError::InvalidArgument));
    }
    let len = crate::fs::io::seg_len(&segs);
    if inline || len == 0 || !async_ok(&file) {
        return Some(rw_one(&file, &segs, (sqe.off, sqe.op_flags), write, flags));
    }
    let mem = match fixed {
        Some((b, f)) => Ok(Mem::Fixed { _held: b, segs: f }),
        None => pin(&segs, write).map(Mem::Pinned),
    };
    match mem {
        Ok(mem) => rw_async(r, file, mem, sqe, write, flags),
        Err(e) => Some(Err(e)),
    }
}

/// The memory of an asynchronous request: pinned for it, or pieces of
/// a registered buffer, held (its pages stay pinned if it is
/// unregistered meanwhile)
enum Mem {
    Pinned(PinnedPages),
    /// The buffer is held only to keep its pages pinned
    Fixed {
        _held: Arc<RegBuf>,
        segs: SmallVec<PageSeg, 4>,
    },
}

/// The I/O flags of a request: the file's (O_DIRECT, O_DSYNC, __O_SYNC,
/// O_APPEND) and the SQE's RWF_* ones (Linux io_rw_init_file: ki_flags =
/// iocb_flags(file), then kiocb_set_rw_flags)
fn kiocb_flags(file: RwFlags, rwf: RwFlags) -> RwFlags {
    file | rwf
}

/// The file takes asynchronous I/O for this request: O_DIRECT on a file
/// that starts it without waiting
fn async_ok(file: &File) -> bool {
    file.iocb_flags().contains(RwFlags::DIRECT) && file.f_op.can_async_dio(file)
}

/// Read or write `segs` at `offset`, or at the file position for -1
/// (Linux io_kiocb_update_pos), through the read/write core; `rwf` the
/// SQE's RWF_* flags (`flags` their I/O flags)
fn rw_one(
    file: &File,
    segs: &[IoVec],
    (offset, rwf): (u64, u32),
    write: bool,
    flags: RwFlags,
) -> KernelResult<i32> {
    let at = (offset != u64::MAX).then_some(offset);
    // Any other negative offset is EINVAL (Linux rw_verify_area)
    if at.is_some_and(|o| o > i64::MAX as u64) {
        return Err(KernelError::InvalidArgument);
    }
    let _pos = at.is_none().then(|| file.pos_lock());
    crate::fs::io::verify_area(file, at, crate::fs::io::seg_len(segs))?;
    let r = if write {
        let append = crate::fs::iov::rwf_append(rwf as i32);
        crate::fs::io::file_writev(file, segs, at, flags, append)
    } else {
        crate::fs::io::file_readv(file, segs, at, flags)
    };
    r.map(cqe_count)
}

/// Pin the pages of `segs` for a read from the file (written, dirtied
/// when unpinned) or a write to it (Linux iov_iter_extract_pages): short
/// at the first page that cannot be pinned, its error if none could
fn pin(segs: &[IoVec], write: bool) -> KernelResult<PinnedPages> {
    let max = crate::fs::syscall::MAX_RW_COUNT;
    if write {
        let mut it = IovSource::user(segs, max);
        let n = it.npages(usize::MAX);
        it.get_pages(n, 0, 0)
    } else {
        let mut it = IovDest::user(segs, max);
        let n = it.npages(usize::MAX);
        let mut pp = it.get_pages(n, 0, 0)?;
        pp.set_dirty();
        Ok(pp)
    }
}

/// Start the request asynchronously (Linux io_read / io_write issued
/// nonblocking): None when queued; the result when it ended at once
fn rw_async(
    r: &Arc<IoRing>,
    file: Arc<File>,
    mem: Mem,
    sqe: &IoUringSqe,
    write: bool,
    flags: RwFlags,
) -> Option<KernelResult<i32>> {
    if r.iopoll
        && let Err(e) = r.poll_add(&file)
    {
        return Some(Err(e));
    }
    let flags = kiocb_flags(file.iocb_flags(), flags);
    let req = match Req::new(r, file, mem, sqe, write, flags) {
        Ok(req) => req,
        Err(e) => return Some(Err(e)),
    };
    if r.iopoll
        && let Err(e) = req.tctx.note_polled(r)
    {
        return Some(Err(e));
    }
    if sqe.flags & IOSQE_ASYNC != 0 {
        super::iowq::queue(req);
        return None;
    }
    match req.issue(true) {
        Ok(None) => None,
        Ok(Some(n)) => {
            // Done inline: the file position moves (Linux kiocb_done:
            // REQ_F_CUR_POS, only for an inline completion)
            if req.cur_pos {
                req.file.set_pos(req.pos + n as u64);
            }
            Some(Ok(cqe_count(n)))
        }
        // A file without nonblocking issue says EOPNOTSUPP: blocking from
        // a worker then (Linux io_file_supports_nowait; __io_read retries
        // EOPNOTSUPP of an IOCB_NOWAIT issue from io-wq)
        Err(KernelError::WouldBlock | KernelError::OperationNotSupported) if !req.rwf_nowait => {
            super::iowq::queue(req);
            None
        }
        Err(e) => Some(Err(e)),
    }
}

/// An asynchronous read or write (Linux io_kiocb with its io_rw kiocb)
pub struct Req {
    /// On its submitter's ended list or a worker pool's queue
    link: Link,
    ring: Arc<IoRing>,
    tctx: Arc<Tctx>,
    /// The submitter: finishes the request in its context
    task: TaskRef,
    user_data: u64,
    skip_success: bool,
    file: Arc<File>,
    pos: u64,
    /// The offset was -1: the file position (Linux REQ_F_CUR_POS)
    cur_pos: bool,
    write: bool,
    /// The file's and the SQE's I/O flags, IOCB_NOWAIT not included
    flags: RwFlags,
    /// The SQE asked RWF_NOWAIT: EAGAIN is its result
    rwf_nowait: bool,
    mem: Mem,
    /// The CQE result, set when it ends
    res: AtomicI32,
    /// The current issue is the nonblocking one
    nowait_issue: AtomicBool,
    /// It ended with EAGAIN from the nonblocking issue: issue it again
    /// from a worker (Linux REQ_F_REISSUE)
    reissue: AtomicBool,
}

crate::adapter!(pub ReqAdapter, Req, link);

impl Req {
    /// A request for `mem` at the SQE's offset, counted in flight on its
    /// ring and task
    fn new(
        r: &Arc<IoRing>,
        file: Arc<File>,
        mem: Mem,
        sqe: &IoUringSqe,
        write: bool,
        flags: RwFlags,
    ) -> KernelResult<Arc<Self>> {
        let (pos, cur_pos) = match sqe.off {
            u64::MAX => (file.get_pos(), true),
            o if o > i64::MAX as u64 => return Err(KernelError::InvalidArgument),
            o => (o, false),
        };
        let len = match &mem {
            Mem::Pinned(p) => p.len(),
            Mem::Fixed { segs: f, .. } => f.iter().map(|s| s.len as usize).sum(),
        };
        crate::fs::io::verify_area(&file, Some(pos), len)?;
        let tctx = tctx()?;
        let req = try_arc(Self {
            link: Link::new(),
            ring: r.clone(),
            tctx: tctx.clone(),
            task: crate::task::percpu::task_ref(&current()),
            user_data: sqe.user_data,
            skip_success: sqe.flags & IOSQE_CQE_SKIP_SUCCESS != 0,
            file: file.clone(),
            pos,
            cur_pos,
            write,
            rwf_nowait: flags.nowait(),
            flags,
            mem,
            res: AtomicI32::new(0),
            nowait_issue: AtomicBool::new(false),
            reissue: AtomicBool::new(false),
        })?;
        r.inflight_get();
        tctx.get();
        Ok(req)
    }

    /// Its submitter
    pub fn task(&self) -> &crate::task::Task {
        &self.task
    }

    /// Issue it, nonblocking (`nowait`: IOCB_NOWAIT) or blocking
    fn issue(self: &Arc<Self>, nowait: bool) -> KernelResult<Option<usize>> {
        self.nowait_issue.store(nowait, Ordering::Relaxed);
        let mut flags = self.flags;
        flags.set(RwFlags::NOWAIT, nowait || self.rwf_nowait);
        // Polled only where GETEVENTS polls: an IOPOLL ring
        flags.set(RwFlags::HIPRI, self.ring.iopoll);
        let io: Arc<dyn AsyncIo> = self.clone();
        self.file
            .f_op
            .dio_submit(&self.file, io, self.pos, self.write, flags)
    }

    /// Issue it blocking (an io-wq worker; Linux io_wq_submit_work): its
    /// end comes through `complete` either way
    pub fn issue_blocking(self: Arc<Self>) {
        match self.issue(false) {
            Ok(None) => {}
            Ok(Some(n)) => self.complete(Ok(n)),
            Err(e) => self.complete(Err(e)),
        }
    }

    /// Finish it in the submitter's context (Linux io_req_rw_complete ->
    /// io_req_task_complete): again from a worker if its nonblocking
    /// issue would have waited, else post its CQE; the pins go with the
    /// last reference
    pub fn finish(self: Arc<Self>) {
        if self.reissue.swap(false, Ordering::Relaxed) {
            super::iowq::queue(self);
            return;
        }
        let res = self.res.load(Ordering::Relaxed);
        if res < 0 || !self.skip_success {
            self.ring.post_cqe(self.user_data, res, 0);
        }
    }
}

// SAFETY: the pieces are the request's own pins or a registered
// buffer's pages, which it holds (`Mem`), unchanged while it lives;
// `complete` only stores atomics and pushes the request onto its task's
// list (an IrqSpinlock, no allocation), dropping no task reference
unsafe impl AsyncIo for Req {
    fn segs(&self) -> &[PageSeg] {
        match &self.mem {
            Mem::Pinned(p) => p.segs(),
            Mem::Fixed { segs: f, .. } => f,
        }
    }

    /// The I/O ended (Linux io_complete_rw), in any context: EAGAIN of the
    /// nonblocking issue means issue it again (Linux
    /// io_rw_should_reissue); either way it is finished in the
    /// submitter's context
    fn complete(self: Arc<Self>, res: Result<usize, KernelError>) {
        let again = res == Err(KernelError::WouldBlock)
            && self.nowait_issue.load(Ordering::Relaxed)
            && !self.rwf_nowait;
        if again {
            self.reissue.store(true, Ordering::Relaxed);
        } else {
            let v = res.map_or_else(KernelError::to_errno_neg, cqe_count);
            self.res.store(v, Ordering::Relaxed);
        }
        // Dropping this reference is harmless in any context: a context
        // freed here holds nothing but memory
        let tctx = self.tctx.clone();
        tctx.push(self);
    }
}

impl Drop for Req {
    /// No longer in flight: its pages are unpinned with it, in thread
    /// context (the ended list and the workers drop requests only in the
    /// submitter or a worker)
    fn drop(&mut self) {
        self.tctx.put();
        self.ring.inflight_put();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_dsync_reaches_the_request() {
        let f = kiocb_flags(RwFlags::DIRECT | RwFlags::DSYNC, RwFlags::empty());
        assert!(f.contains(RwFlags::DSYNC) && f.contains(RwFlags::DIRECT));
        let f = kiocb_flags(RwFlags::DIRECT | RwFlags::SYNC, RwFlags::NOWAIT);
        assert!(f.contains(RwFlags::SYNC) && f.contains(RwFlags::NOWAIT));
    }
}
