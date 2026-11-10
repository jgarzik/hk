//! I/O iterators (Linux struct iov_iter; Rust-for-Linux IovIterDest /
//! IovIterSource): where a read puts its data and where a write takes
//! it from, user segments or a kernel buffer, so a filesystem copies straight between its pages and the caller's
//! memory (no bounce buffer) and in-kernel readers (exec, splice) use
//! the same path. Direct I/O pins the pages of user segments
//! (`get_pages`, `mm::gup`).
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
use crate::mm::gup::{PageSeg, PinnedPages, PinnedSlice, pin_user};
use crate::util::seg::step_back;

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

    /// The current segment from the position: its address and the bytes
    /// left in it, whatever the total left (Linux iter_iov_addr,
    /// iter_iov_len); None at the end
    fn cur(&self) -> Option<(u64, usize)> {
        if self.left == 0 {
            return None;
        }
        let s = self.segs.get(self.i)?;
        Some((s.iov_base + self.off as u64, s.iov_len as usize - self.off))
    }

    /// Step over `n` bytes of the current segment, and past it and the
    /// empty ones after it if that ends it (Linux iov_iter_iovec_advance)
    fn advance(&mut self, n: usize) {
        self.off += n;
        self.left -= n;
        if self
            .segs
            .get(self.i)
            .is_some_and(|s| self.off == s.iov_len as usize)
        {
            self.off = 0;
            self.i += 1;
            while self.segs.get(self.i).is_some_and(|s| s.iov_len == 0) {
                self.i += 1;
            }
        }
    }

    /// Pages the bytes left span, at most `max` (Linux iov_iter_npages)
    fn npages(&self, max: usize) -> usize {
        const P: u64 = crate::mm::PAGE_SIZE;
        let (mut i, mut off, mut left, mut n) = (self.i, self.off, self.left, 0usize);
        while left > 0 && n < max {
            let Some(s) = self.segs.get(i) else {
                break;
            };
            let len = (s.iov_len as usize - off).min(left);
            if len > 0 {
                let a = s.iov_base + off as u64;
                n = n.saturating_add(((a % P + len as u64).div_ceil(P)) as usize);
            }
            left -= len;
            i += 1;
            off = 0;
        }
        n.min(max)
    }

    /// Pin the next bytes, at most `max` pages, for `write` (Linux
    /// bio_iov_iter_get_pages over an ITER_IOVEC): segment by segment,
    /// each one's address and remaining length first checked against
    /// `mem_mask` (EINVAL, the pins taken released); short at the first
    /// page that cannot be pinned, that page's error if none was. The
    /// bytes are then cut to a multiple of `len_mask` + 1, the iterator
    /// stepping back over the rest (EFAULT if none are left).
    fn get_pages(
        &mut self,
        write: bool,
        max: usize,
        mem_mask: usize,
        len_mask: usize,
    ) -> Result<PinnedPages, KernelError> {
        let mut pp = PinnedPages::new(max)?;
        while pp.nr_pages() < max {
            let Some((addr, len)) = self.cur() else {
                break;
            };
            if !mem_aligned(addr, len, mem_mask) {
                return Err(KernelError::InvalidArgument);
            }
            let want = len.min(self.left);
            if want == 0 {
                self.i += 1;
                self.off = 0;
                continue;
            }
            match pin_user(&mut pp, addr, want, write, max) {
                Ok(n) => {
                    self.advance(n);
                    if n < want {
                        break;
                    }
                }
                Err(e) if pp.is_empty() => return Err(e),
                Err(_) => break,
            }
        }
        let excess = pp.len() & len_mask;
        pp.trim(excess);
        self.revert(excess);
        if pp.is_empty() {
            return Err(KernelError::BadAddress);
        }
        Ok(pp)
    }

    /// The bits of the bytes left's addresses and lengths, ORed (Linux
    /// iov_iter_alignment_iovec): segment by segment, the last cut to
    /// what is left, empty ones skipped
    fn alignment(&self) -> u64 {
        let (mut res, mut size, mut skip) = (0u64, self.left, self.off);
        for s in self.segs.get(self.i..).unwrap_or(&[]) {
            if size == 0 {
                break;
            }
            let len = (s.iov_len as usize).saturating_sub(skip);
            if len > 0 {
                let len = len.min(size);
                res |= (s.iov_base + skip as u64) | len as u64;
                size -= len;
            }
            skip = 0;
        }
        res
    }

    /// Step back over the last `n` bytes moved
    fn revert(&mut self, n: usize) {
        self.left += n;
        let segs = self.segs;
        step_back(|k| segs[k].iov_len as usize, &mut self.i, &mut self.off, n);
    }
}

/// DMA memory `len` bytes at `addr` meets the device's alignment mask
/// (Linux iov_iter_extract_bvecs: `(start | len) & mem_align_mask`)
pub fn mem_aligned(addr: u64, len: usize, mask: usize) -> bool {
    (addr | len as u64) & mask as u64 == 0
}

/// Position in pinned page pieces (Linux ITER_BVEC): piece `i`, byte
/// `at` of it, `left` bytes to go
struct Pieces<'a> {
    segs: &'a [PageSeg],
    i: usize,
    at: usize,
    left: usize,
}

impl<'a> Pieces<'a> {
    fn new(segs: &'a [PageSeg]) -> Self {
        Self {
            segs,
            i: 0,
            at: 0,
            left: segs.iter().map(|s| s.len as usize).sum(),
        }
    }

    /// Up to `len` bytes, a piece at a time: `f(phys, off, n, done)`
    /// copies `n` bytes at `off` of frame `phys`; the bytes stepped over
    fn step(&mut self, len: usize, f: &mut dyn FnMut(u64, usize, usize, usize)) -> usize {
        let mut done = 0;
        while done < len && self.left > 0 {
            let s = self.segs[self.i];
            let n = (s.len as usize - self.at).min(len - done);
            f(s.phys, s.off as usize + self.at, n, done);
            done += n;
            self.left -= n;
            self.at += n;
            if self.at == s.len as usize {
                self.i += 1;
                self.at = 0;
            }
        }
        done
    }

    /// The bytes left's page offsets and lengths ORed (Linux
    /// iov_iter_alignment_bvec)
    fn alignment(&self) -> u64 {
        let (mut res, mut size, mut skip) = (0u64, self.left, self.at);
        for s in &self.segs[self.i..] {
            if size == 0 {
                break;
            }
            let len = (s.len as usize - skip).min(size);
            res |= (s.off as usize + skip) as u64 | len as u64;
            size -= len;
            skip = 0;
        }
        res
    }

    /// Step back over `n` bytes
    fn revert(&mut self, n: usize) {
        step_back(|k| self.segs[k].len as usize, &mut self.i, &mut self.at, n);
        self.left += n;
    }

    /// Pin the next pieces again (a direct I/O), at most `max` pages,
    /// as `Segs::get_pages`: memory aligned to `mem_mask`, the total
    /// cut to a multiple of `len_mask` + 1
    fn get_pages(
        &mut self,
        max: usize,
        mem_mask: usize,
        len_mask: usize,
    ) -> Result<PinnedPages, KernelError> {
        // The rest of the current piece first, then whole ones
        let mut rest: crate::util::smallvec::SmallVec<PageSeg, 4> =
            crate::util::smallvec::SmallVec::try_with_capacity(max.min(self.segs.len() - self.i))?;
        let mut k = self.i;
        let mut left = self.left;
        let mut at = self.at;
        while left > 0 && rest.len() < max {
            let s = self.segs[k];
            let n = (s.len as usize - at).min(left);
            rest.push(PageSeg {
                phys: s.phys,
                // Within a page: lossless
                off: s.off + at as u32,
                len: n as u32,
            });
            left -= n;
            k += 1;
            at = 0;
        }
        let pp = crate::mm::gup::repin(&rest, max, mem_mask, len_mask)?;
        let n = pp.len();
        self.step(n, &mut |_, _, _, _| {});
        Ok(pp)
    }
}

enum Dest<'a> {
    User(Segs<'a>),
    Kernel(&'a mut [u8]),
    /// Pinned pages (a registered buffer: Linux ITER_BVEC)
    Pages(Pieces<'a>),
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

    /// Pinned pages, pinned as long as the borrow (Linux ITER_BVEC)
    pub fn pinned(p: &'a PinnedSlice<'_>) -> Self {
        Self(Dest::Pages(Pieces::new(p.segs())))
    }

    /// The memory of an asynchronous direct I/O, pinned while it lives
    /// (`AsyncIo`'s contract), so as long as the borrow
    pub fn async_io(io: &'a dyn crate::block::dio::AsyncIo) -> Self {
        Self(Dest::Pages(Pieces::new(io.segs())))
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

    /// User memory (Linux user_backed_iter)
    pub fn user_backed(&self) -> bool {
        matches!(self.0, Dest::User(_))
    }

    /// Memory `get_pages` can pin for direct I/O: user memory, or pages
    /// pinned already (Linux: ITER_UBUF/IOVEC and ITER_BVEC)
    pub fn pinnable(&self) -> bool {
        matches!(self.0, Dest::User(_) | Dest::Pages(_))
    }

    /// Pages the room left spans, at most `max` (Linux iov_iter_npages);
    /// 0 for memory that is not pinned
    pub fn npages(&self, max: usize) -> usize {
        match &self.0 {
            Dest::User(s) => s.npages(max),
            Dest::Pages(p) => (p.segs.len() - p.i).min(max),
            Dest::Kernel(_) => 0,
        }
    }

    /// The room left's addresses and lengths ORed, to test their
    /// alignment (Linux iov_iter_alignment)
    pub fn alignment(&self) -> u64 {
        match &self.0 {
            Dest::User(s) => s.alignment(),
            Dest::Pages(p) => p.alignment(),
            Dest::Kernel([]) => 0,
            Dest::Kernel(b) => b.as_ptr() as u64 | b.len() as u64,
        }
    }

    /// Pin the user pages of the next bytes to be written (a read from a
    /// device; Linux bio_iov_iter_get_pages, FOLL_WRITE): see
    /// `Segs::get_pages`. EOPNOTSUPP for memory that is not pinned.
    pub fn get_pages(
        &mut self,
        max: usize,
        mem_mask: usize,
        len_mask: usize,
    ) -> Result<PinnedPages, KernelError> {
        match &mut self.0 {
            Dest::User(s) => s.get_pages(true, max, mem_mask, len_mask),
            Dest::Pages(p) => p.get_pages(max, mem_mask, len_mask),
            Dest::Kernel(_) => Err(KernelError::OperationNotSupported),
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
            Dest::Pages(p) => p.step(data.len(), &mut |phys, off, n, at| {
                // SAFETY: a piece of pinned frames (`pinned`'s borrow),
                // within its page
                unsafe { crate::mm::page::copy_to_frame_racy(phys, off, &data[at..at + n]) }
            }),
        };
        if n == 0 && !data.is_empty() && !self.is_empty() {
            return Err(KernelError::BadAddress);
        }
        Ok(n)
    }

    /// Copy `n` bytes at `off` of the page frame `phys` (a page-cache
    /// page) as `copy_to` would
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
    /// Pinned pages (a registered buffer: Linux ITER_BVEC)
    Pages(Pieces<'a>),
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

    /// Pinned pages, pinned as long as the borrow (Linux ITER_BVEC)
    pub fn pinned(p: &'a PinnedSlice<'_>) -> Self {
        Self(Source::Pages(Pieces::new(p.segs())))
    }

    /// The memory of an asynchronous direct I/O, pinned while it lives
    /// (`AsyncIo`'s contract), so as long as the borrow
    pub fn async_io(io: &'a dyn crate::block::dio::AsyncIo) -> Self {
        Self(Source::Pages(Pieces::new(io.segs())))
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

    /// User memory (Linux user_backed_iter)
    pub fn user_backed(&self) -> bool {
        matches!(self.0, Source::User(_))
    }

    /// Memory `get_pages` can pin for direct I/O: user memory, or pages
    /// pinned already (Linux: ITER_UBUF/IOVEC and ITER_BVEC)
    pub fn pinnable(&self) -> bool {
        matches!(self.0, Source::User(_) | Source::Pages(_))
    }

    /// Pages the bytes left span, at most `max` (Linux iov_iter_npages);
    /// 0 for memory that is not pinned
    pub fn npages(&self, max: usize) -> usize {
        match &self.0 {
            Source::User(s) => s.npages(max),
            Source::Pages(p) => (p.segs.len() - p.i).min(max),
            Source::Kernel(..) => 0,
        }
    }

    /// The bytes left's addresses and lengths ORed, to test their
    /// alignment (Linux iov_iter_alignment)
    pub fn alignment(&self) -> u64 {
        match &self.0 {
            Source::User(s) => s.alignment(),
            Source::Pages(p) => p.alignment(),
            Source::Kernel(b, at) if *at == b.len() => 0,
            Source::Kernel(b, at) => (b.as_ptr() as u64 + *at as u64) | (b.len() - at) as u64,
        }
    }

    /// Pin the user pages of the next bytes to be read (a write to a
    /// device; Linux bio_iov_iter_get_pages): see `Segs::get_pages`.
    /// EOPNOTSUPP for memory that is not pinned.
    pub fn get_pages(
        &mut self,
        max: usize,
        mem_mask: usize,
        len_mask: usize,
    ) -> Result<PinnedPages, KernelError> {
        match &mut self.0 {
            Source::User(s) => s.get_pages(false, max, mem_mask, len_mask),
            Source::Pages(p) => p.get_pages(max, mem_mask, len_mask),
            Source::Kernel(..) => Err(KernelError::OperationNotSupported),
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
    /// page-cache page) as `copy_from_nofault` would
    ///
    /// # Safety
    /// `phys` is a RAM frame the caller keeps referenced and may write
    /// (its page lock), [off, off + n) lies in it, and the caller holds
    /// no reference to its bytes.
    pub unsafe fn copy_to_page_nofault(&mut self, phys: u64, off: usize, n: usize) -> usize {
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
            Source::Pages(p) => p.step(want, &mut |phys, off, n, at| {
                // SAFETY: a piece of pinned frames (`pinned`'s borrow),
                // within its page
                unsafe { crate::mm::page::copy_from_frame_racy(&mut buf[at..at + n], phys, off) }
            }),
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
    fn alignment_of_segments() {
        let seg = |b, l| IoVec {
            iov_base: b,
            iov_len: l,
        };
        // An empty segment's odd address does not count
        let segs = [seg(0x1000, 0x200), seg(0x2001, 0), seg(0x3000, 0x400)];
        let s = Segs::new(&segs, usize::MAX);
        assert_eq!(s.alignment() & 0x1ff, 0);
        // The last segment counts only as far as the bytes left
        let s = Segs::new(&segs, 0x300);
        assert_eq!(s.alignment() & 0x1ff, 0x100);
        // From the position: a consumed prefix's address is gone
        let segs = [seg(0x1001, 0x201), seg(0x4000, 0x200)];
        let mut s = Segs::new(&segs, usize::MAX);
        assert_ne!(s.alignment() & 0x1ff, 0);
        s.step(0x201, &mut |_, n, _| n);
        assert_eq!(s.alignment() & 0x1ff, 0);
    }

    #[test]
    fn advance_skips_empty() {
        let seg = |b, l| IoVec {
            iov_base: b,
            iov_len: l,
        };
        let segs = [
            seg(0x1000, 3),
            seg(0x2001, 0),
            seg(0x3001, 0),
            seg(0x4000, 5),
        ];
        let mut s = Segs::new(&segs, usize::MAX);
        s.advance(3);
        assert_eq!((s.i, s.off, s.left), (3, 0, 5));
        assert_eq!(s.cur(), Some((0x4000, 5)));
        s.revert(3);
        assert_eq!((s.i, s.off, s.left), (0, 0, 8));
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
