//! IOCB_CMD_PREAD/PWRITE/PREADV/PWRITEV and FSYNC/FDSYNC (Linux fs/aio.c
//! aio_read, aio_write, aio_prep_rw, aio_fsync)
//!
//! What can fail before the file's read or write is called fails the
//! io_submit (no event): the RWF_* flags, the priority, the file's mode,
//! the memory's import, the position. From then on every result is the
//! request's event: an O_DIRECT I/O on a file that starts it without
//! waiting (`FileOps::can_async_dio`: block devices, vfat) gets its
//! memory pinned and its event from the bios' end, any other read or
//! write runs to its end within io_submit (Linux: ->read_iter returns
//! rather than -EIOCBQUEUED), its event posted before io_submit
//! returns. FSYNC and FDSYNC run in a system workqueue worker with the
//! submitter's credentials (Linux aio_fsync: INIT_WORK + schedule_work).

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::abi::Iocb;
use super::kiocb::{Base, Kiocb, Op};
use crate::fs::file::{File, RwFlags};
use crate::fs::iov::IoVec;
use crate::fs::iov_iter::{IovDest, IovSource};
use crate::mm::gup::PinnedPages;
use crate::task::workqueue::{SYSTEM_WQ, Work};
use crate::uaccess::UserPtr;
use crate::util::error::{KernelError, KernelResult};
use crate::util::kalloc::try_arc;

/// The request's I/O flags: the file's (O_DIRECT, O_DSYNC, O_APPEND,
/// ...) and the iocb's RWF_* ones, which are checked (EOPNOTSUPP for
/// unknown ones), RWF_APPEND / RWF_NOAPPEND over O_APPEND; polled I/O
/// is dropped, as nothing polls for it (Linux aio_prep_rw)
fn prep_flags(file: &File, iocb: &Iocb) -> KernelResult<RwFlags> {
    if iocb.aio_flags & super::abi::IOCB_FLAG_IOPRIO != 0 {
        crate::task::ioprio_check_cap(iocb.aio_reqprio as u16)?;
    }
    let rwf = crate::fs::iov::rwf_check(iocb.aio_rw_flags)?;
    let flags = crate::fs::iov::rwf_set_append(file.iocb_flags() | rwf, iocb.aio_rw_flags);
    Ok(flags - RwFlags::HIPRI)
}

/// The iocb's memory: `aio_nbytes` bytes at `aio_buf`, or that many
/// iovecs there (Linux aio_setup_rw: import_ubuf / __import_iovec)
fn import(iocb: &Iocb, vectored: bool) -> KernelResult<Vec<IoVec>> {
    if vectored {
        let n = i32::try_from(iocb.aio_nbytes).map_err(|_| KernelError::InvalidArgument)?;
        return crate::fs::iov::import_iovec(UserPtr::new(iocb.aio_buf), n);
    }
    let seg = crate::fs::io::import_ubuf(UserPtr::new(iocb.aio_buf), iocb.aio_nbytes)?;
    crate::util::kmem::try_to_vec(&seg)
}

/// A file with a position (regular, block and character devices):
/// I/O at the iocb's offset; a stream (pipe, socket, eventfd) has none
/// and ignores it (Linux: ->read_iter of a stream never looks at
/// ki_pos)
fn positioned(file: &File) -> bool {
    file.get_inode().is_some_and(|i| {
        let m = i.mode();
        m.is_file() || m.is_blkdev() || m.is_chrdev()
    })
}

/// IOCB_CMD_PREAD(V) (`write` false) or PWRITE(V) of `b`
pub fn aio_rw(b: Base, iocb: &Iocb, write: bool, vectored: bool) -> KernelResult<()> {
    let flags = prep_flags(&b.file, iocb)?;
    let ok = if write {
        b.file.is_writable()
    } else {
        b.file.is_readable()
    };
    if !ok {
        return Err(KernelError::BadFd);
    }
    let segs = import(iocb, vectored)?;
    let len = crate::fs::io::seg_len(&segs);
    // Linux rw_verify_area: a negative position is EINVAL
    let pos = u64::try_from(iocb.aio_offset).map_err(|_| KernelError::InvalidArgument)?;
    crate::fs::io::verify_area(&b.file, Some(pos), len)?;
    let direct = flags.contains(RwFlags::DIRECT) && b.file.f_op.can_async_dio(&b.file);
    if direct && len > 0 {
        return start_async(b, &segs, pos, write, flags);
    }
    let append = Some(flags.contains(RwFlags::APPEND));
    let k = Kiocb::new(b, Op::Rw(None))?;
    let at = positioned(k.file()).then_some(pos);
    let r = if write {
        crate::fs::io::file_writev(k.file(), &segs, at, flags, append)
    } else {
        crate::fs::io::file_readv(k.file(), &segs, at, flags)
    };
    k.done(r);
    k.put_thread();
    Ok(())
}

/// Pin `segs` for a read from the file (written, dirtied when unpinned)
/// or a write to it: short at the first page that cannot be pinned, its
/// error if none could be
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

/// Start an O_DIRECT read or write of `segs` at `pos` (Linux
/// __blkdev_direct_IO_async / do_blockdev_direct_IO for an async
/// kiocb): its event comes when the bios end, or now if it ended at
/// once or failed
fn start_async(b: Base, segs: &[IoVec], pos: u64, write: bool, flags: RwFlags) -> KernelResult<()> {
    let pins = pin(segs, write);
    let (pins, early) = match pins {
        Ok(p) => (Some(p), None),
        Err(e) => (None, Some(e)),
    };
    let k = Kiocb::new(b, Op::Rw(pins))?;
    if let Some(e) = early {
        k.done(Err(e));
        k.put_thread();
        return Ok(());
    }
    let io: Arc<dyn crate::block::dio::AsyncIo> = k.clone();
    match k.file().f_op.dio_submit(k.file(), io, pos, write, flags) {
        Ok(None) => {}
        Ok(Some(n)) => k.done(Ok(n)),
        Err(e) => k.done(Err(e)),
    }
    k.put_thread();
    Ok(())
}

/// IOCB_CMD_FSYNC (`datasync` false) or FDSYNC of `b` (Linux aio_fsync):
/// no buffer, offset, length or flags (EINVAL); run by a worker with the
/// submitter's credentials
pub fn aio_fsync(b: Base, iocb: &Iocb, datasync: bool) -> KernelResult<()> {
    if iocb.aio_buf != 0 || iocb.aio_offset != 0 || iocb.aio_nbytes != 0 || iocb.aio_rw_flags != 0 {
        return Err(KernelError::InvalidArgument);
    }
    let creds = crate::task::percpu::current().cred_arc();
    let k = Kiocb::new(b, Op::Fsync)?;
    let mut job = Some((k.clone(), creds));
    let work = try_arc(crate::sync::IrqSpinlock::new(Work::new(move || {
        if let Some((k, creds)) = job.take() {
            let r = {
                let _c = crate::task::override_creds(creds);
                crate::fs::sync::vfs_fsync(k.file(), datasync)
            };
            k.done(r.map(|()| 0));
        }
    })));
    match work {
        Ok(w) => {
            SYSTEM_WQ.queue_work(w);
        }
        Err(e) => {
            // The work holds a reference: gone with it
            k.abandon();
            return Err(e);
        }
    }
    k.put_thread();
    Ok(())
}
