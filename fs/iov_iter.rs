//! I/O iterators (Linux struct iov_iter; Rust-for-Linux IovIterDest /
//! IovIterSource): where a read puts its data and where a write takes
//! it from, user segments or a kernel buffer, so a filesystem copies
//! straight between its pages and the caller's memory (no bounce
//! buffer) and in-kernel readers (exec, splice) use the same path.
//!
//! Both move forward (a write source can step back over what a failed
//! page took, Linux iov_iter_revert). A user copy may fault and sleep:
//! never copy under a spin lock (`might_fault` reports it). A write
//! source copies with page faults disabled and faults pages in between
//! tries (`copy_from_user_atomic`), so it may be used under i_rwsem.
//! Under a page lock a fault-in may need that very page's lock: fault
//! the source in first (`fault_in`), then copy with `copy_from_nofault`
//! (Linux generic_perform_write).

use crate::uaccess::{
    copy_from_user_atomic_some, copy_from_user_some, copy_to_user_some, fault_in_readable,
    pagefault_disable, pagefault_enable,
};
use crate::util::error::KernelError;

use super::iov::IoVec;

/// Position in a list of user segments
struct Segs<'a> {
    segs: &'a [IoVec],
    i: usize,
    off: usize,
    left: usize,
}

impl<'a> Segs<'a> {
    fn new(segs: &'a [IoVec], max: usize) -> Self {
        let total = segs
            .iter()
            .map(|s| s.iov_len as usize)
            .fold(0usize, usize::saturating_add);
        Self {
            segs,
            i: 0,
            off: 0,
            left: total.min(max),
        }
    }

    /// Visit up to `len` bytes as (user address, length, offset into the
    /// caller's buffer) runs; `f` returns the bytes it moved (a short
    /// count ends the walk). Returns the bytes moved.
    fn step(&mut self, len: usize, f: &mut dyn FnMut(u64, usize, usize) -> usize) -> usize {
        let mut done = 0;
        let len = len.min(self.left);
        while done < len {
            let Some(s) = self.segs.get(self.i) else {
                break;
            };
            let n = (s.iov_len as usize - self.off).min(len - done);
            let moved = if n > 0 {
                f(s.iov_base + self.off as u64, n, done)
            } else {
                0
            };
            self.off += moved;
            done += moved;
            self.left -= moved;
            if moved < n {
                break;
            }
            if self.off == s.iov_len as usize {
                self.i += 1;
                self.off = 0;
            }
        }
        done
    }

    /// Fault in the next `len` bytes for reading; the bytes that could
    /// not be (0: all)
    fn fault_in(&self, len: usize) -> usize {
        let mut want = len.min(self.left);
        let (mut i, mut off) = (self.i, self.off);
        while want > 0 {
            let Some(s) = self.segs.get(i) else {
                break;
            };
            let n = (s.iov_len as usize - off).min(want);
            let left = fault_in_readable(s.iov_base + off as u64, n);
            if left > 0 {
                return want - n + left;
            }
            want -= n;
            i += 1;
            off = 0;
        }
        want
    }

    /// Step back over the last `n` bytes moved
    fn revert(&mut self, mut n: usize) {
        self.left += n;
        while n > 0 {
            if self.off == 0 {
                self.i -= 1;
                self.off = self.segs[self.i].iov_len as usize;
                continue;
            }
            let k = self.off.min(n);
            self.off -= k;
            n -= k;
        }
    }
}

enum Dest<'a> {
    User(Segs<'a>),
    Kernel(&'a mut [u8]),
}

/// Where a read puts its data (Linux ITER_DEST)
pub struct IovDest<'a>(Dest<'a>);

impl<'a> IovDest<'a> {
    /// User segments, at most `max` bytes in all
    pub fn user(segs: &'a [IoVec], max: usize) -> Self {
        Self(Dest::User(Segs::new(segs, max)))
    }

    /// A kernel buffer
    pub fn kernel(buf: &'a mut [u8]) -> Self {
        Self(Dest::Kernel(buf))
    }

    /// Room left
    pub fn len(&self) -> usize {
        match &self.0 {
            Dest::User(s) => s.left,
            Dest::Kernel(b) => b.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Take at most `n` more bytes (a read limit: the end of a device)
    pub fn truncate(&mut self, n: usize) {
        match &mut self.0 {
            Dest::User(s) => s.left = s.left.min(n),
            Dest::Kernel(b) => {
                let k = n.min(b.len());
                *b = &mut core::mem::take(b)[..k];
            }
        }
    }

    /// Copy as much of `data` as fits (Linux copy_to_iter); the bytes
    /// copied, EFAULT if a fault stopped it before the first byte
    pub fn copy_to(&mut self, data: &[u8]) -> Result<usize, KernelError> {
        let n = match &mut self.0 {
            Dest::User(s) => s.step(data.len(), &mut |a, n, at| {
                copy_to_user_some(a, &data[at..at + n])
            }),
            Dest::Kernel(b) => {
                let n = data.len().min(b.len());
                let (head, tail) = core::mem::take(b).split_at_mut(n);
                head.copy_from_slice(&data[..n]);
                *b = tail;
                n
            }
        };
        if n == 0 && !data.is_empty() && !self.is_empty() {
            return Err(KernelError::BadAddress);
        }
        Ok(n)
    }

    /// Copy all of `data`, EFAULT if it does not fit or a fault cuts it
    /// short (a record that must arrive whole: an event, a counter)
    pub fn copy_to_full(&mut self, data: &[u8]) -> Result<(), KernelError> {
        match self.copy_to(data)? {
            n if n == data.len() => Ok(()),
            _ => Err(KernelError::BadAddress),
        }
    }

    /// `n` zero bytes (a hole): as many as fit; EFAULT only if a fault
    /// stopped it before the first byte
    pub fn zero(&mut self, n: usize) -> Result<usize, KernelError> {
        // One user copy per page (Linux iov_iter_zero uses clear_user)
        static Z: [u8; 4096] = [0; 4096];
        let mut done = 0;
        while done < n {
            let k = (n - done).min(Z.len());
            let c = match self.copy_to(&Z[..k]) {
                Ok(c) => c,
                Err(e) if done == 0 => return Err(e),
                Err(_) => break,
            };
            done += c;
            if c < k {
                break;
            }
        }
        Ok(done)
    }
}

enum Source<'a> {
    User(Segs<'a>),
    /// The buffer and the bytes taken from it
    Kernel(&'a [u8], usize),
}

/// Where a write takes its data from (Linux ITER_SOURCE)
pub struct IovSource<'a>(Source<'a>);

impl<'a> IovSource<'a> {
    /// User segments, at most `max` bytes in all
    pub fn user(segs: &'a [IoVec], max: usize) -> Self {
        Self(Source::User(Segs::new(segs, max)))
    }

    /// A kernel buffer
    pub fn kernel(buf: &'a [u8]) -> Self {
        Self(Source::Kernel(buf, 0))
    }

    /// Bytes left
    pub fn len(&self) -> usize {
        match &self.0 {
            Source::User(s) => s.left,
            Source::Kernel(b, at) => b.len() - at,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Take at most `n` more bytes (a write limit: RLIMIT_FSIZE,
    /// s_maxbytes)
    pub fn truncate(&mut self, n: usize) {
        match &mut self.0 {
            Source::User(s) => s.left = s.left.min(n),
            Source::Kernel(b, at) => *b = &b[..at.saturating_add(n).min(b.len())],
        }
    }

    /// Fault in the next `n` bytes (Linux fault_in_iov_iter_readable);
    /// the bytes that could not be (0: all)
    pub fn fault_in(&self, n: usize) -> usize {
        match &self.0 {
            Source::User(s) => s.fault_in(n),
            Source::Kernel(..) => 0,
        }
    }

    /// Step back over the last `n` bytes copied (Linux iov_iter_revert)
    pub fn revert(&mut self, n: usize) {
        match &mut self.0 {
            Source::User(s) => s.revert(n),
            Source::Kernel(_, at) => *at -= n,
        }
    }

    /// Fill as much of `buf` as there is data for with page faults
    /// disabled and nothing faulted in (Linux
    /// copy_folio_from_iter_atomic): for a copy under a page lock, after
    /// `fault_in`. The bytes copied, maybe short or none.
    pub fn copy_from_nofault(&mut self, buf: &mut [u8]) -> usize {
        match &mut self.0 {
            Source::User(s) => s.step(buf.len(), &mut |a, n, at| {
                pagefault_disable();
                let c = copy_from_user_some(&mut buf[at..at + n], a);
                pagefault_enable();
                c
            }),
            Source::Kernel(..) => self.copy_from(buf).unwrap_or(0),
        }
    }

    /// Fill as much of `buf` as there is data for (Linux
    /// copy_from_iter); the bytes copied, EFAULT if a fault stopped it
    /// before the first byte
    pub fn copy_from(&mut self, buf: &mut [u8]) -> Result<usize, KernelError> {
        let want = buf.len();
        let n = match &mut self.0 {
            Source::User(s) => s.step(want, &mut |a, n, at| {
                copy_from_user_atomic_some(&mut buf[at..at + n], a)
            }),
            Source::Kernel(b, at) => {
                let n = want.min(b.len() - *at);
                buf[..n].copy_from_slice(&b[*at..*at + n]);
                *at += n;
                n
            }
        };
        if n == 0 && want != 0 && !self.is_empty() {
            return Err(KernelError::BadAddress);
        }
        Ok(n)
    }

    /// Fill all of `buf`, EFAULT if there is less data or a fault cuts
    /// it short (Linux copy_from_iter_full)
    pub fn copy_from_full(&mut self, buf: &mut [u8]) -> Result<(), KernelError> {
        match self.copy_from(buf)? {
            n if n == buf.len() => Ok(()),
            _ => Err(KernelError::BadAddress),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_dest_and_source() {
        let mut out = [0u8; 5];
        let mut d = IovDest::kernel(&mut out);
        assert_eq!(d.copy_to(b"abc").unwrap(), 3);
        assert_eq!(d.copy_to(b"defg").unwrap(), 2);
        assert!(d.is_empty());
        assert_eq!(&out, b"abcde");
        let mut s = IovSource::kernel(b"hello");
        s.truncate(4);
        let mut b = [0u8; 8];
        assert_eq!(s.copy_from(&mut b).unwrap(), 4);
        assert_eq!(&b[..4], b"hell");
        assert!(s.is_empty());
        s.revert(2);
        assert_eq!(s.copy_from_nofault(&mut b), 2);
        assert_eq!(&b[..2], b"ll");
    }

    #[test]
    fn user_revert() {
        let segs = [
            IoVec {
                iov_base: 0x1000,
                iov_len: 3,
            },
            IoVec {
                iov_base: 0x2000,
                iov_len: 0,
            },
            IoVec {
                iov_base: 0x3000,
                iov_len: 5,
            },
        ];
        let mut s = Segs::new(&segs, usize::MAX);
        assert_eq!(s.step(6, &mut |_, n, _| n), 6);
        assert_eq!((s.i, s.off, s.left), (2, 3, 2));
        s.revert(4);
        assert_eq!((s.i, s.off, s.left), (0, 2, 6));
        let mut runs = alloc::vec::Vec::new();
        s.step(8, &mut |a, n, _| {
            runs.push((a, n));
            n
        });
        assert_eq!(runs, [(0x1002, 1), (0x3000, 5)]);
    }

    #[test]
    fn truncated_dest() {
        let mut out = [0u8; 8];
        let mut d = IovDest::kernel(&mut out);
        d.truncate(3);
        assert_eq!(d.copy_to(b"abcdef").unwrap(), 3);
        assert!(d.is_empty());
    }

    #[test]
    fn zero_fills() {
        let mut out = [1u8; 300];
        let mut d = IovDest::kernel(&mut out);
        assert_eq!(d.zero(400).unwrap(), 300);
        assert!(out.iter().all(|&b| b == 0));
    }
}
