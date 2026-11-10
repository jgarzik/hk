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
use crate::mm::gup::{PageSeg, PinnedPages};
use crate::task::Uid;
use crate::util::error::{KernelError, KernelResult};
use crate::util::smallvec::SmallVec;

/// Most registered buffers (Linux IORING_MAX_REG_BUFFERS)
pub const IORING_MAX_REG_BUFFERS: usize = 1 << 14;
/// Largest registered buffer (Linux SZ_1G)
const MAX_BUF: u64 = 1 << 30;
const PAGE: u64 = 4096;

/// The user a ring charges its locked memory to: none with
/// CAP_IPC_LOCK (Linux ctx->user, set unless ns_capable(CAP_IPC_LOCK))
pub fn acct_user() -> Option<Uid> {
    (!crate::task::capable(crate::task::CAP_IPC_LOCK))
        .then(|| crate::task::percpu::current_cred().uid)
}

/// Charge `pages` to `user` (Linux __io_account_mem): ENOMEM past its
/// RLIMIT_MEMLOCK
pub fn account(user: Option<Uid>, pages: u64) -> KernelResult<()> {
    let Some(uid) = user else { return Ok(()) };
    let lim = crate::task::rlimit::rlimit(crate::task::rlimit::RLIMIT_MEMLOCK) / PAGE;
    if crate::task::locked_vm_charge(uid, pages, lim) {
        Ok(())
    } else {
        Err(KernelError::OutOfMemory)
    }
}

/// Give back what `account` charged (Linux __io_unaccount_mem)
pub fn unaccount(user: Option<Uid>, pages: u64) {
    if let Some(uid) = user {
        crate::task::locked_vm_uncharge(uid, pages);
    }
}

/// One registered buffer (Linux struct io_mapped_ubuf): its user range
/// and pinned pages, charged while it lives
pub struct RegBuf {
    ubuf: u64,
    len: u64,
    pins: PinnedPages,
    user: Option<Uid>,
}

impl Drop for RegBuf {
    fn drop(&mut self) {
        unaccount(self.user, self.pins.nr_pages() as u64);
    }
}

impl RegBuf {
    /// Pin and charge the buffer `iov` (Linux io_sqe_buffer_register):
    /// none for an empty one (a sparse slot); EFAULT for a null base
    /// with a length, a length past 1 GiB or memory that cannot all be
    /// pinned, EOVERFLOW for a range that wraps
    fn new(iov: &IoVec, user: Option<Uid>) -> KernelResult<Option<Arc<Self>>> {
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
    pub fn slice(&self, addr: u64, len: usize) -> KernelResult<SmallVec<PageSeg, 4>> {
        let end = addr
            .checked_add(len as u64)
            .ok_or(KernelError::BadAddress)?;
        if addr < self.ubuf || end > self.ubuf + self.len {
            return Err(KernelError::BadAddress);
        }
        let segs = self.pins.segs();
        // Every piece but the first starts a page: index straight in
        let abs = u64::from(segs[0].off) + (addr - self.ubuf);
        let (mut i, mut at) = ((abs / PAGE) as usize, (abs % PAGE) as u32);
        if i == 0 {
            at -= segs[0].off;
        }
        let mut out = SmallVec::try_with_capacity((len as u64).div_ceil(PAGE) as usize + 1)?;
        let mut left = len;
        while left > 0 {
            let s = segs[i];
            let n = ((s.len - at) as usize).min(left);
            out.push(PageSeg {
                phys: s.phys,
                off: s.off + at,
                // Within a page: lossless
                len: n as u32,
            });
            left -= n;
            i += 1;
            at = 0;
        }
        Ok(out)
    }
}

/// Pin and charge the `iovs` as a table (Linux io_sqe_buffers_register)
pub fn register(iovs: &[IoVec], user: Option<Uid>) -> KernelResult<Vec<Option<Arc<RegBuf>>>> {
    let mut t = crate::util::kmem::KVec::try_with_capacity(iovs.len())?;
    for iov in iovs {
        // Capacity is reserved; this cannot fail
        let _ = t.try_push(RegBuf::new(iov, user)?);
    }
    Ok(t.into_vec())
}
