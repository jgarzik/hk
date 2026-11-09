//! I/O iterators (Linux struct iov_iter; Rust-for-Linux IovIterDest /
//! IovIterSource): where a read puts its data and where a write takes
//! it from, user segments, a kernel buffer or pinned pages (ITER_BVEC),
//! so a filesystem copies straight between its pages and the caller's
//! memory (no bounce buffer) and in-kernel readers (exec, splice) use
//! the same path. Direct I/O pins the pages of user segments
//! (`extract_pages`, `mm::gup`).
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
use crate::mm::gup::{PinnedPages, pin_user_segs};

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

/// Position in pinned pages (Linux ITER_BVEC)
struct Pages<'a> {
    pp: &'a PinnedPages,
    i: usize,
    at: usize,
    left: usize,
}

impl<'a> Pages<'a> {
    fn new(pp: &'a PinnedPages) -> Self {
        Self {
            pp,
            i: 0,
            at: 0,
            left: pp.len(),
        }
    }

    /// Visit up to `len` bytes segment by segment, as `step` on user
    /// segments; `f` gets (segment, offset in it, length, offset into the
    /// caller's buffer)
    fn step(
        &mut self,
        len: usize,
        f: &mut dyn FnMut(usize, usize, usize, usize) -> usize,
    ) -> usize {
        let mut done = 0;
        let len = len.min(self.left);
        while done < len {
            let Some(s) = self.pp.segs().get(self.i) else {
                break;
            };
            let n = (s.len as usize - self.at).min(len - done);
            let moved = f(self.i, self.at, n, done);
            self.at += moved;
            done += moved;
            self.left -= moved;
            if moved < n {
                break;
            }
            if self.at == s.len as usize {
                self.i += 1;
                self.at = 0;
            }
        }
        done
    }

    /// Step back over the last `n` bytes moved
    fn revert(&mut self, mut n: usize) {
        self.left += n;
        while n > 0 {
            if self.at == 0 {
                self.i -= 1;
                self.at = self.pp.segs()[self.i].len as usize;
                continue;
            }
            let k = self.at.min(n);
            self.at -= k;
            n -= k;
        }
    }
}

enum Dest<'a> {
    User(Segs<'a>),
    Kernel(&'a mut [u8]),
    Pages(Pages<'a>),
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

    /// Pinned pages, the I/O a device would do into them (Linux
    /// ITER_BVEC)
    pub fn pinned(pp: &'a PinnedPages) -> Self {
        Self(Dest::Pages(Pages::new(pp)))
    }

    /// Room left
    pub fn len(&self) -> usize {
        match &self.0 {
            Dest::User(s) => s.left,
            Dest::Kernel(b) => b.len(),
            Dest::Pages(p) => p.left,
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
            Dest::Pages(p) => p.left = p.left.min(n),
        }
    }

    /// Pin the user pages of the next bytes, at most `max` pages, to be
    /// written (a read from a device: Linux iov_iter_extract_pages with
    /// FOLL_WRITE), and step over them: short at the first page that
    /// cannot be pinned, that page's error if it is the first.
    /// EOPNOTSUPP for kernel memory, which is not pinned.
    pub fn extract_pages(&mut self, max: usize) -> Result<PinnedPages, KernelError> {
        match &mut self.0 {
            Dest::User(s) => pin_user_segs(&mut |f| s.step(usize::MAX, f), true, max),
            _ => Err(KernelError::OperationNotSupported),
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
            Dest::Pages(p) => {
                let pp = p.pp;
                p.step(data.len(), &mut |i, at, n, from| {
                    pp.write(i, at, &data[from..from + n])
                })
            }
        };
        if n == 0 && !data.is_empty() && !self.is_empty() {
            return Err(KernelError::BadAddress);
        }
        Ok(n)
    }

    /// Copy `n` bytes at `off` of the page frame `phys` (a page-cache
    /// page) as `copy_to` would; pinned pages get a raw move, as the
    /// frame may be one of them (a buffer mapping the very file range
    /// read)
    ///
    /// # Safety
    /// `phys` is a RAM frame the caller keeps referenced, [off, off + n)
    /// lies in it, and the caller holds no reference to its bytes.
    pub unsafe fn copy_from_page(
        &mut self,
        phys: u64,
        off: usize,
        n: usize,
    ) -> Result<usize, KernelError> {
        if let Dest::Pages(p) = &mut self.0 {
            let pp = p.pp;
            let src = phys + off as u64;
            // SAFETY: the caller's contract, per piece of the frame
            let c = p.step(n, &mut |i, at, k, from| unsafe {
                pp.copy_from_frame(i, at, src + from as u64, k)
            });
            return Ok(c);
        }
        // SAFETY: the caller's contract; read only, as the frame's
        // other readers
        let bytes: &[u8] = unsafe { crate::mm::page::frame_bytes(phys) };
        self.copy_to(&bytes[off..off + n])
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
    Pages(Pages<'a>),
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

    /// Pinned pages, the I/O a device would do from them (Linux
    /// ITER_BVEC)
    pub fn pinned(pp: &'a PinnedPages) -> Self {
        Self(Source::Pages(Pages::new(pp)))
    }

    /// Bytes left
    pub fn len(&self) -> usize {
        match &self.0 {
            Source::User(s) => s.left,
            Source::Kernel(b, at) => b.len() - at,
            Source::Pages(p) => p.left,
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
            Source::Pages(p) => p.left = p.left.min(n),
        }
    }

    /// Pin the user pages of the next bytes, at most `max` pages, to be
    /// read (a write to a device: Linux iov_iter_extract_pages), and step
    /// over them: short at the first page that cannot be pinned, that
    /// page's error if it is the first. EOPNOTSUPP for kernel memory,
    /// which is not pinned.
    pub fn extract_pages(&mut self, max: usize) -> Result<PinnedPages, KernelError> {
        match &mut self.0 {
            Source::User(s) => pin_user_segs(&mut |f| s.step(usize::MAX, f), false, max),
            _ => Err(KernelError::OperationNotSupported),
        }
    }

    /// Fault in the next `n` bytes (Linux fault_in_iov_iter_readable);
    /// the bytes that could not be (0: all)
    pub fn fault_in(&self, n: usize) -> usize {
        match &self.0 {
            Source::User(s) => s.fault_in(n),
            Source::Kernel(..) | Source::Pages(_) => 0,
        }
    }

    /// Step back over the last `n` bytes copied (Linux iov_iter_revert)
    pub fn revert(&mut self, n: usize) {
        match &mut self.0 {
            Source::User(s) => s.revert(n),
            Source::Kernel(_, at) => *at -= n,
            Source::Pages(p) => p.revert(n),
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
            Source::Kernel(..) | Source::Pages(_) => self.copy_from(buf).unwrap_or(0),
        }
    }

    /// Fill `n` bytes at `off` of the locked page frame `phys` (a
    /// page-cache page) as `copy_from_nofault` would; pinned pages give
    /// a raw move, as the frame may be one of them (a buffer mapping the
    /// very file range written)
    ///
    /// # Safety
    /// `phys` is a RAM frame the caller keeps referenced and may write
    /// (its page lock), [off, off + n) lies in it, and the caller holds
    /// no reference to its bytes.
    pub unsafe fn copy_to_page_nofault(&mut self, phys: u64, off: usize, n: usize) -> usize {
        if let Source::Pages(p) = &mut self.0 {
            let pp = p.pp;
            let dst = phys + off as u64;
            // SAFETY: the caller's contract, per piece of the frame
            return p.step(n, &mut |i, at, k, to| unsafe {
                pp.copy_to_frame(i, at, dst + to as u64, k)
            });
        }
        // SAFETY: the caller's contract
        let bytes = unsafe { crate::mm::page::frame_bytes(phys) };
        self.copy_from_nofault(&mut bytes[off..off + n])
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
            Source::Pages(p) => {
                let pp = p.pp;
                p.step(want, &mut |i, at, n, to| {
                    pp.read(i, at, &mut buf[to..to + n])
                })
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
