//! Registered buffers and locked-memory accounting (Linux
//! io_uring/rsrc.c io_sqe_buffers_register, io_import_reg_buf,
//! __io_account_mem)
//!
//! IORING_REGISTER_BUFFERS pins each iovec's pages once (Linux FOLL_PIN
//! | FOLL_LONGTERM), so READ_FIXED and WRITE_FIXED name a range of them
//! (`buf_index`, `addr`, `len`) and the I/O uses those pages with no
//! pinning of its own. A ring made without CAP_IPC_LOCK charges its
//! rings and its buffers' pages to its user's locked memory, against
//! RLIMIT_MEMLOCK (ENOMEM past it), until they are released.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fs::iov::IoVec;
use crate::fs::iov_iter::IovDest;
use crate::mm::gup::{PinnedPages, PinnedSlice};
use crate::task::{Ucount, UcountsRef};
use crate::util::error::{KernelError, KernelResult};

/// Most registered buffers (Linux IORING_MAX_REG_BUFFERS)
pub const IORING_MAX_REG_BUFFERS: usize = 1 << 14;
/// Largest registered buffer (Linux SZ_1G)
const MAX_BUF: u64 = 1 << 30;
const PAGE: u64 = 4096;

/// The user a ring charges its locked memory to, a counted reference:
/// none with CAP_IPC_LOCK (Linux ctx->user = get_uid(current_user()),
/// set unless ns_capable(CAP_IPC_LOCK))
pub fn acct_user() -> Option<UcountsRef> {
    (!crate::task::capable(crate::task::CAP_IPC_LOCK))
        .then(|| crate::task::percpu::current_cred().ucounts)
}

/// Charge `pages` to `user` (Linux __io_account_mem): ENOMEM past its
/// RLIMIT_MEMLOCK
pub fn account(user: Option<&UcountsRef>, pages: u64) -> KernelResult<()> {
    let Some(u) = user else { return Ok(()) };
    let lim = crate::task::rlimit::rlimit(crate::task::rlimit::RLIMIT_MEMLOCK) / PAGE;
    if u.inc_max(Ucount::LockedVm, pages, lim) {
        Ok(())
    } else {
        Err(KernelError::OutOfMemory)
    }
}

/// Give back what `account` charged (Linux __io_unaccount_mem)
pub fn unaccount(user: Option<&UcountsRef>, pages: u64) {
    if let Some(u) = user {
        u.dec(Ucount::LockedVm, pages);
    }
}

/// One registered buffer (Linux struct io_mapped_ubuf): its user range
/// and pinned pages, charged while it lives
pub struct RegBuf {
    ubuf: u64,
    len: u64,
    pins: PinnedPages,
    user: Option<UcountsRef>,
}

impl Drop for RegBuf {
    fn drop(&mut self) {
        unaccount(self.user.as_ref(), self.pins.nr_pages() as u64);
    }
}

impl RegBuf {
    /// Pin and charge the buffer `iov` (Linux io_sqe_buffer_register):
    /// none for an empty one (a sparse slot); EFAULT for a null base
    /// with a length, a length past 1 GiB or memory that cannot all be
    /// pinned, EOVERFLOW for a range that wraps
    fn new(iov: &IoVec, user: Option<&UcountsRef>) -> KernelResult<Option<Arc<Self>>> {
        let (base, len) = (iov.iov_base, iov.iov_len);
        if base == 0 {
            return if len == 0 {
                Ok(None)
            } else {
                Err(KernelError::BadAddress)
            };
        }
        if len == 0 || len > MAX_BUF {
            return Err(KernelError::BadAddress);
        }
        base.checked_add(len).ok_or(KernelError::Overflow)?;
        let segs = [IoVec {
            iov_base: base,
            iov_len: len,
        }];
        // Pinned writable, as Linux (FOLL_WRITE): reads land in it
        let mut it = IovDest::user(&segs, usize::MAX);
        let n = it.npages(usize::MAX);
        let pins = it.get_pages(n, 0, 0).map_err(|_| KernelError::BadAddress)?;
        if pins.len() as u64 != len {
            return Err(KernelError::BadAddress);
        }
        account(user, pins.nr_pages() as u64)?;
        let user = user.cloned();
        crate::util::kalloc::try_arc(Self {
            ubuf: base,
            len,
            pins,
            user,
        })
        .map(Some)
        // A failed allocation drops the buffer it was given, whose Drop
        // gives the charge back: nothing to undo here
    }

    /// The pieces of the `len` bytes at user address `addr` (Linux
    /// io_import_reg_buf): EFAULT outside the buffer
    pub fn slice(&self, addr: u64, len: usize) -> KernelResult<PinnedSlice<'_>> {
        let end = addr
            .checked_add(len as u64)
            .ok_or(KernelError::BadAddress)?;
        if addr < self.ubuf || end > self.ubuf + self.len {
            return Err(KernelError::BadAddress);
        }
        self.pins.slice((addr - self.ubuf) as usize, len)
    }
}

/// Pin and charge the `iovs` as a table (Linux io_sqe_buffers_register)
pub fn register(
    iovs: &[IoVec],
    user: Option<&UcountsRef>,
) -> KernelResult<Vec<Option<Arc<RegBuf>>>> {
    let mut t = crate::util::kmem::KVec::try_with_capacity(iovs.len())?;
    for iov in iovs {
        // Capacity is reserved; this cannot fail
        let _ = t.try_push(RegBuf::new(iov, user)?);
    }
    Ok(t.into_vec())
}
