//! I/O iterators (Linux struct iov_iter; Rust-for-Linux IovIterDest /
//! IovIterSource): where a read puts its data and where a write takes
//! it from, user segments or a kernel buffer, so a filesystem copies
//! straight between its pages and the caller's memory (no bounce
//! buffer) and in-kernel readers (exec, splice) use the same path.
//!
//! Both move forward only. A user copy may fault and sleep: never copy
//! under a spin lock (`might_fault` reports it). A write source copies
//! with page faults disabled and faults pages in between tries
//! (`copy_from_user_atomic`, Linux generic_perform_write), so it may be
//! used under i_rwsem or a page lock.

use crate::arch::Uaccess;
use crate::uaccess::{copy_from_user_atomic, copy_to_user};
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

    /// Copy as much of `data` as fits (Linux copy_to_iter); the bytes
    /// copied, EFAULT if a fault stopped it before the first byte
    pub fn copy_to(&mut self, data: &[u8]) -> Result<usize, KernelError> {
        let n = match &mut self.0 {
            Dest::User(s) => s.step(data.len(), &mut |a, n, at| match copy_to_user::<Uaccess>(
                a,
                &data[at..at + n],
            ) {
                Ok(_) => n,
                Err(_) => 0,
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

    /// `n` zero bytes (a hole): as many as fit
    pub fn zero(&mut self, n: usize) -> Result<usize, KernelError> {
        const Z: [u8; 256] = [0; 256];
        let mut done = 0;
        while done < n {
            let k = (n - done).min(Z.len());
            let c = self.copy_to(&Z[..k])?;
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
    Kernel(&'a [u8]),
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
        Self(Source::Kernel(buf))
    }

    /// Bytes left
    pub fn len(&self) -> usize {
        match &self.0 {
            Source::User(s) => s.left,
            Source::Kernel(b) => b.len(),
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
            Source::Kernel(b) => *b = &b[..n.min(b.len())],
        }
    }

    /// Fill as much of `buf` as there is data for (Linux
    /// copy_from_iter); the bytes copied, EFAULT if a fault stopped it
    /// before the first byte
    pub fn copy_from(&mut self, buf: &mut [u8]) -> Result<usize, KernelError> {
        let want = buf.len();
        let n = match &mut self.0 {
            Source::User(s) => s.step(
                want,
                &mut |a, n, at| match copy_from_user_atomic::<Uaccess>(&mut buf[at..at + n], a, n) {
                    Ok(_) => n,
                    Err(_) => 0,
                },
            ),
            Source::Kernel(b) => {
                let n = want.min(b.len());
                buf[..n].copy_from_slice(&b[..n]);
                *b = &b[n..];
                n
            }
        };
        if n == 0 && want != 0 && !self.is_empty() {
            return Err(KernelError::BadAddress);
        }
        Ok(n)
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
    }

    #[test]
    fn zero_fills() {
        let mut out = [1u8; 300];
        let mut d = IovDest::kernel(&mut out);
        assert_eq!(d.zero(400).unwrap(), 300);
        assert!(out.iter().all(|&b| b == 0));
    }
}
