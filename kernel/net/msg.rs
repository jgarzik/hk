//! User I/O vectors of socket calls (Linux lib/iov_iter.c import_iovec /
//! import_ubuf as used by net/socket.c)
//!
//! An `Iov` is validated once when imported: at most `UIO_MAXIOV`
//! segments (EINVAL), every segment inside user space (EFAULT), and the
//! total clamped to `MAX_RW_COUNT` like Linux, so no length arithmetic
//! on it can overflow. Data is then copied with uaccess only.

use alloc::vec::Vec;

use crate::arch::Uaccess;
use crate::error::KernelError;
use crate::uaccess::{UaccessArch, copy_from_user, copy_to_user, get_user};

/// Most segments in one iovec array (Linux UIO_MAXIOV)
pub const UIO_MAXIOV: usize = 1024;
/// Largest single transfer (Linux MAX_RW_COUNT = INT_MAX & PAGE_MASK)
pub const MAX_RW_COUNT: usize = 0x7fff_f000;

/// One user segment
#[derive(Clone, Copy, Debug, Default)]
pub struct IoVec {
    pub base: u64,
    pub len: usize,
}

/// A validated user I/O vector
#[derive(Clone, Debug, Default)]
pub struct Iov {
    segs: Vec<IoVec>,
    /// Sum of the (clamped) segment lengths, <= MAX_RW_COUNT
    pub total: usize,
}

impl Iov {
    /// One buffer (send/recv; Linux import_ubuf clamps before access_ok)
    pub fn single(base: u64, len: u64) -> Result<Self, KernelError> {
        let mut v = Self::default();
        v.push(base, len.min(MAX_RW_COUNT as u64))?;
        Ok(v)
    }

    /// The iovec of a user msghdr (Linux __copy_msghdr: EMSGSIZE above
    /// UIO_MAXIOV segments)
    pub fn from_msg(ptr: u64, n: usize) -> Result<Self, KernelError> {
        if n > UIO_MAXIOV {
            return Err(KernelError::MessageTooLong);
        }
        Self::import(ptr, n)
    }

    /// A user `struct iovec[n]` at `ptr` (readv-style: EINVAL above
    /// UIO_MAXIOV)
    pub fn import(ptr: u64, n: usize) -> Result<Self, KernelError> {
        if n > UIO_MAXIOV {
            return Err(KernelError::InvalidArgument);
        }
        let mut v = Self {
            segs: Vec::with_capacity(n),
            total: 0,
        };
        for i in 0..n as u64 {
            let at = ptr.checked_add(i * 16).ok_or(KernelError::BadAddress)?;
            let base = get_user::<Uaccess, u64>(at).map_err(|_| KernelError::BadAddress)?;
            let at8 = at.checked_add(8).ok_or(KernelError::BadAddress)?;
            let len = get_user::<Uaccess, u64>(at8).map_err(|_| KernelError::BadAddress)?;
            v.push(base, len)?;
        }
        Ok(v)
    }

    fn push(&mut self, base: u64, len: u64) -> Result<(), KernelError> {
        if len > isize::MAX as u64 || !Uaccess::access_ok(base, len as usize) {
            return Err(KernelError::BadAddress);
        }
        let len = (len as usize).min(MAX_RW_COUNT - self.total);
        self.total += len;
        self.segs.push(IoVec { base, len });
        Ok(())
    }

    /// Copy in the first `min(total, max)` bytes
    pub fn gather(&self, max: usize) -> Result<Vec<u8>, KernelError> {
        let want = self.total.min(max);
        let mut out = alloc::vec![0u8; want];
        let mut off = 0;
        for s in &self.segs {
            if off == want {
                break;
            }
            let n = s.len.min(want - off);
            if n > 0 {
                copy_from_user::<Uaccess>(&mut out[off..off + n], s.base, n)
                    .map_err(|_| KernelError::BadAddress)?;
            }
            off += n;
        }
        Ok(out)
    }

    /// Copy `data` out starting `skip` bytes into the vector; returns the
    /// bytes copied (stops at the end of the vector)
    pub fn scatter(&self, mut skip: usize, data: &[u8]) -> Result<usize, KernelError> {
        let mut done = 0;
        for s in &self.segs {
            if done == data.len() {
                break;
            }
            if skip >= s.len {
                skip -= s.len;
                continue;
            }
            let n = (s.len - skip).min(data.len() - done);
            copy_to_user::<Uaccess>(s.base + skip as u64, &data[done..done + n])
                .map_err(|_| KernelError::BadAddress)?;
            skip = 0;
            done += n;
        }
        Ok(done)
    }
}
