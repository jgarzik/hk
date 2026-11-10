//! IORING_OP_READ, WRITE, READV and WRITEV (Linux io_uring/rw.c)

use alloc::sync::Arc;

use super::abi::IoUringSqe;
use super::ops::cqe_count;
use super::{IoRing, Submit};
use crate::fs::file::{File, RwFlags};
use crate::fs::iov::IoVec;
use crate::uaccess::UserPtr;
use crate::util::error::{KernelError, KernelResult};

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

/// IORING_OP_READ / WRITE: `len` bytes at `addr`
pub fn rw(r: &IoRing, s: &Submit, sqe: &IoUringSqe, write: bool) -> KernelResult<i32> {
    let file = rw_file(r, s, sqe, write)?;
    let flags = rw_flags(sqe)?;
    let seg = crate::fs::io::import_ubuf(UserPtr::new(sqe.addr), u64::from(sqe.len))?;
    rw_one(&file, &seg, (sqe.off, sqe.op_flags), write, flags)
}

/// IORING_OP_READV / WRITEV: the `len` iovecs at `addr`, checked and
/// cut like readv's (Linux io_import_iovec -> __import_iovec)
pub fn rwv(r: &IoRing, s: &Submit, sqe: &IoUringSqe, write: bool) -> KernelResult<i32> {
    let file = rw_file(r, s, sqe, write)?;
    let flags = rw_flags(sqe)?;
    let n = i32::try_from(sqe.len).map_err(|_| KernelError::InvalidArgument)?;
    let v: alloc::vec::Vec<IoVec> = crate::fs::iov::import_iovec(UserPtr::new(sqe.addr), n)?;
    rw_one(&file, &v, (sqe.off, sqe.op_flags), write, flags)
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
