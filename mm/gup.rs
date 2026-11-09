//! Pinning user pages for DMA (Linux mm/gup.c: pin_user_pages,
//! FOLL_PIN, unpin_user_pages_dirty_lock; lib/iov_iter.c
//! iov_iter_extract_pages)
//!
//! A pin is [`GUP_PIN_COUNTING_BIAS`] references on the 4KB page (Linux's
//! scheme for small folios): a page with that many is "maybe pinned"
//! ([`maybe_dma_pinned`]), and the paths that would let a DMA land in
//! the wrong page check it. A 2MB mapping is split before a page in it is
//! pinned (hk's split gives every 4KB page its own count), so every pin
//! is on a 4KB page. Pins are taken under the entry's PTE lock, so fork
//! (`memory::copy_pte`) and reclaim (`rmap::try_to_unmap`), which change
//! entries under it too, see a pin or the entry as it was before:
//!
//! - fork gives the child its own copy of a pinned page of a private
//!   mapping that the parent owns alone (Linux page_needs_cow_for_dma);
//!   the parent keeps the page and its writable entry;
//! - reclaim leaves a maybe-pinned page mapped and resident;
//! - a page pinned in a private mapping is marked anon-exclusive
//!   (`page::PG_ANON_EXCL`), so a write fault or mprotect reuses it in
//!   place whatever its count (Linux PageAnonExclusive): the process keeps
//!   seeing the page the device reads or writes.
//!
//! munmap and exit drop the entries' references only: a pinned page
//! stays allocated until its last unpin.

use alloc::sync::Arc;

use super::fault::{Access, handle_mm_fault, unshare_for_write};
use super::pgtable::PgTables;
use super::{Mm, MmStruct, PAGE_SIZE, PROT_READ, PROT_WRITE, Vma};
use crate::FRAME_ALLOCATOR;
use crate::arch::paging;
use crate::fs::Inode;
use crate::util::error::KernelError;
use crate::util::kmem::KVec;

/// References one pin takes (Linux GUP_PIN_COUNTING_BIAS)
pub const GUP_PIN_COUNTING_BIAS: u32 = 1024;

/// The page at `phys` may be pinned for DMA (Linux
/// folio_maybe_dma_pinned): it holds at least one pin's references; a
/// page with that many ordinary ones is a false positive
pub fn maybe_dma_pinned(phys: u64) -> bool {
    FRAME_ALLOCATOR.refcount(phys & !(PAGE_SIZE - 1)) >= GUP_PIN_COUNTING_BIAS
}

/// Drop one pin of the page at `phys` (Linux unpin_user_page); the last
/// reference frees it. Atomics and the page allocator only: any context.
fn unpin_page(phys: u64) {
    FRAME_ALLOCATOR.put_refs(phys, GUP_PIN_COUNTING_BIAS);
}

/// `len` bytes at `off` in the page at `phys` (Linux bio_vec)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageSeg {
    pub phys: u64,
    pub off: u32,
    pub len: u32,
}

/// User memory pinned for DMA (Linux FOLL_PIN pages with their offsets
/// and lengths, as iov_iter_extract_pages gives them): unpinned when
/// dropped, and first marked dirty if `set_dirty` was called (Linux
/// unpin_user_pages_dirty_lock). Dropped in thread context; a completion
/// in an interrupt handler hands it to a thread (Linux bio_dirty_work):
/// dirtying a page-cache page takes its page lock.
#[must_use]
pub struct PinnedPages {
    segs: KVec<PageSeg>,
    /// Per segment, the inode whose page cache its page belongs to (a
    /// shared file mapping written through): a write dirties it there
    owners: KVec<Option<Arc<Inode>>>,
    dirty: bool,
}

impl PinnedPages {
    /// Room for `max` pages
    fn new(max: usize) -> Result<Self, KernelError> {
        Ok(Self {
            segs: KVec::try_with_capacity(max)?,
            owners: KVec::try_with_capacity(max)?,
            dirty: false,
        })
    }

    /// The pinned pieces, in order
    pub fn segs(&self) -> &[PageSeg] {
        &self.segs
    }

    /// Bytes pinned
    pub fn len(&self) -> usize {
        self.segs.iter().map(|s| s.len as usize).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.segs.is_empty()
    }

    /// The pages were written (a read from the device): dirty them when
    /// unpinned
    pub fn set_dirty(&mut self) {
        self.dirty = true;
    }

    /// Segment `i` from byte `at` on, at most `want` bytes: the direct
    /// map address and the length (0 past the segment)
    fn span(&self, i: usize, at: usize, want: usize) -> (*mut u8, usize) {
        let Some(s) = self.segs.get(i) else {
            return (core::ptr::null_mut(), 0);
        };
        let n = want.min((s.len as usize).saturating_sub(at));
        let va =
            crate::arch::phys_to_virt(s.phys + u64::from(s.off) + at.min(s.len as usize) as u64);
        (va, n)
    }

    /// Copy `data` into segment `i` from byte `at` of it (the kernel
    /// writing what a device would); the bytes copied. `data` may be the
    /// very bytes of the pinned page (a page-cache page the buffer maps):
    /// then they already hold it; a slice overlapping them otherwise is
    /// refused (0), as writing under it would break its borrow (page
    /// copies between frames go through `copy_from_frame`).
    pub fn write(&self, i: usize, at: usize, data: &[u8]) -> usize {
        let (dst, n) = self.span(i, at, data.len());
        match overlap(dst, data.as_ptr(), n) {
            Overlap::Same => n,
            Overlap::Partial => 0,
            // SAFETY: the page is pinned while `self` lives and the n
            // bytes at `dst` lie in it (`span`); `data` is other memory.
            // A raw copy creates no reference to memory the process may
            // access meanwhile (as a device's DMA).
            Overlap::None => unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr(), dst, n);
                n
            },
        }
    }

    /// Copy from segment `i`, byte `at` on, into `buf`; the bytes copied
    /// (as `write`, the other way)
    pub fn read(&self, i: usize, at: usize, buf: &mut [u8]) -> usize {
        let (src, n) = self.span(i, at, buf.len());
        match overlap(src, buf.as_ptr(), n) {
            Overlap::Same => n,
            Overlap::Partial => 0,
            // SAFETY: as `write`: the n bytes at `src` lie in the pinned
            // page, `buf` is other memory
            Overlap::None => unsafe {
                core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), n);
                n
            },
        }
    }

    /// Copy `n` bytes of the frame memory at physical `src` into segment
    /// `i` from byte `at` of it (as `write`); the bytes copied. The two
    /// may be the same page, overlapping (a buffer mapping the very file
    /// range a read fills): a raw move, no reference to either.
    ///
    /// # Safety
    /// [src, src + n) lies in a RAM frame the caller keeps referenced, and
    /// the caller holds no reference to its bytes during the call.
    pub unsafe fn copy_from_frame(&self, i: usize, at: usize, src: u64, n: usize) -> usize {
        let (dst, n) = self.span(i, at, n);
        // SAFETY: both ranges are frames kept alive (the pin, the
        // caller's reference) and borrowed by no reference; `copy`
        // allows them to overlap
        unsafe { core::ptr::copy(crate::arch::phys_to_virt(src), dst, n) };
        n
    }

    /// Copy segment `i`, byte `at` on, into `n` bytes of the frame memory
    /// at physical `dst` (`copy_from_frame` the other way)
    ///
    /// # Safety
    /// As [`PinnedPages::copy_from_frame`], for `dst`.
    pub unsafe fn copy_to_frame(&self, i: usize, at: usize, dst: u64, n: usize) -> usize {
        let (src, n) = self.span(i, at, n);
        // SAFETY: as `copy_from_frame`
        unsafe { core::ptr::copy(src, crate::arch::phys_to_virt(dst), n) };
        n
    }

    /// Mark the page at `phys` dirty: anonymous memory by its flag, a
    /// page-cache page in its `owner`'s mapping under the page lock
    /// (Linux folio_mark_dirty)
    fn dirty_page(phys: u64, owner: Option<&Arc<Inode>>) {
        match owner {
            Some(inode) => {
                super::page::lock_page(phys);
                super::filemap::dirty_page(&inode.i_data, phys);
                super::page::unlock_page(phys);
                crate::fs::fs_writeback::mark_inode_dirty(inode);
            }
            None => {
                if let Some(pg) = super::page::phys_to_page(phys) {
                    pg.set_flag(super::page::PG_DIRTY);
                }
            }
        }
    }
}

impl Drop for PinnedPages {
    fn drop(&mut self) {
        for (s, owner) in self.segs.iter().zip(self.owners.iter()) {
            if self.dirty {
                Self::dirty_page(s.phys, owner.as_ref());
            }
            unpin_page(s.phys);
        }
    }
}

/// How a slice lies against `n` bytes of a pinned page at `page`
enum Overlap {
    /// Elsewhere
    None,
    /// Exactly those bytes
    Same,
    /// Some of them
    Partial,
}

fn overlap(page: *const u8, other: *const u8, n: usize) -> Overlap {
    let (a, b) = (page.addr(), other.addr());
    if n == 0 || a.saturating_add(n) <= b || b.saturating_add(n) <= a {
        Overlap::None
    } else if a == b {
        Overlap::Same
    } else {
        Overlap::Partial
    }
}

/// The VMA of `addr` if pages of it may be pinned (Linux
/// check_vma_flags): a write needs a writable mapping, a read a readable
/// one; EFAULT otherwise
fn pin_vma(map: &MmStruct, addr: u64, write: bool) -> Result<&Vma, KernelError> {
    if addr >= super::TASK_SIZE {
        return Err(KernelError::BadAddress);
    }
    let vma = map.find_vma(addr).ok_or(KernelError::BadAddress)?;
    let need = if write { PROT_WRITE } else { PROT_READ };
    if vma.prot & need == 0 {
        return Err(KernelError::BadAddress);
    }
    Ok(vma)
}

/// What pinning one page found
enum Follow {
    /// Pinned: its frame
    Pinned(u64),
    /// No usable entry: fault the page in for this access, then retry
    Fault(Access),
    /// A private anonymous page still shared copy-on-write, pinned for
    /// reading: give the mapping its own first (Linux gup_must_unshare)
    Unshare,
}

/// Pin the page `addr` of `vma` maps, under its PTE lock (Linux
/// follow_page_pte with FOLL_PIN): a missing page or, for a write, a
/// read-only one (copy-on-write, a private page-cache page) is faulted
/// in first; a 2MB page is split. A frame outside the allocator (MMIO)
/// is EFAULT, and a count that would overflow ENOMEM.
fn follow_pin(
    mm: &Mm,
    t: PgTables<'_>,
    vma: &Vma,
    addr: u64,
    write: bool,
) -> Result<Follow, KernelError> {
    let access = if write { Access::Write } else { Access::Read };
    // A racing fault may have split (or zapped) it first
    if let Some(pmd) = t.pmd(addr).filter(|p| p.huge())
        && super::huge_page::split_huge_pmd(mm, pmd).is_none()
        && t.pmd(addr).is_some_and(|p| p.huge())
    {
        return Err(KernelError::OutOfMemory);
    }
    let Some(ptep) = t.pte(addr) else {
        return Ok(Follow::Fault(access));
    };
    let l = ptep.lock();
    let pte = l.get(addr);
    if !paging::pte_present(pte) || paging::pte_protnone(pte) {
        return Ok(Follow::Fault(access));
    }
    let writable = paging::pte_write(pte);
    if write && !writable {
        return Ok(Follow::Fault(access));
    }
    let phys = paging::pte_addr(pte);
    let pg = super::page::phys_to_page(phys)
        .filter(|_| super::remote::ordinary(phys))
        .ok_or(KernelError::BadAddress)?;
    let private = !vma.is_shared();
    // A private page-cache page pinned for reading stays shared with the
    // cache (Linux: only anonymous pages must be exclusive)
    if private && !writable && pg.is_anon() && !pg.anon_exclusive() {
        return Ok(Follow::Unshare);
    }
    if !FRAME_ALLOCATOR.get_refs(phys, GUP_PIN_COUNTING_BIAS) {
        return Err(KernelError::OutOfMemory);
    }
    // A private entry is writable only if the mapping owns its page alone
    if private && writable {
        pg.set_anon_exclusive();
    }
    Ok(Follow::Pinned(phys))
}

/// Fault page `addr` of `mm` in (the mmap_lock not held); EINTR on a
/// fatal signal, ENOMEM out of memory, else EFAULT
fn fault_in(mm: &Mm, addr: u64, access: Access) -> Result<(), KernelError> {
    use super::fault::VmFault;
    if crate::signal::fatal_signal_pending() {
        return Err(KernelError::Interrupted);
    }
    handle_mm_fault(mm, addr, access).map_err(|e| match e {
        VmFault::Oom => KernelError::OutOfMemory,
        _ => KernelError::BadAddress,
    })
}

/// The inode whose page cache a pinned page written through a shared
/// file mapping belongs to
fn cache_owner(vma: &Vma, write: bool) -> Option<Arc<Inode>> {
    if !write || !vma.is_shared() {
        return None;
    }
    let inode = vma.file.as_ref()?.mapping_inode()?;
    inode.i_op.maps_cache().then_some(inode)
}

/// What a run of pins under one mmap_lock hold ended with
enum Step {
    /// Done, or stopped (with the error if nothing was pinned)
    Done(Result<usize, KernelError>),
    /// The page at this address needs a fault for this access
    Fault(u64, Access),
}

/// The bytes done, or `e` if none were
fn partial(done: usize, e: KernelError) -> Result<usize, KernelError> {
    if done > 0 { Ok(done) } else { Err(e) }
}

/// Pin the pages of the `len` bytes at `addr` of `mm` from byte `done`
/// on, at most `max` pages in `out`, under one hold of its mmap_lock
/// (`map`), the VMA kept while the pages are in it (Linux
/// __get_user_pages); stops at a page that must be faulted in
fn pin_locked(
    out: &mut PinnedPages,
    mm: &Mm,
    map: &MmStruct,
    (addr, len, mut done): (u64, usize, usize),
    write: bool,
    max: usize,
) -> Step {
    let t = PgTables::new(mm, map);
    let mut vma: Option<&Vma> = None;
    while done < len && out.segs.len() < max {
        let Some(a) = addr.checked_add(done as u64) else {
            return Step::Done(partial(done, KernelError::BadAddress));
        };
        let page = a & !(PAGE_SIZE - 1);
        let v = match vma.filter(|v| v.contains(page)) {
            Some(v) => v,
            None => match pin_vma(map, page, write) {
                Ok(v) => *vma.insert(v),
                Err(e) => return Step::Done(partial(done, e)),
            },
        };
        let phys = match follow_pin(mm, t, v, page, write) {
            Ok(Follow::Pinned(phys)) => phys,
            Ok(Follow::Fault(acc)) => return Step::Fault(page, acc),
            Ok(Follow::Unshare) => {
                let r =
                    unshare_for_write(mm, t, page, v.anon_vma.clone(), v.index_of(page), v.prot);
                if r.is_err() {
                    return Step::Done(partial(done, KernelError::OutOfMemory));
                }
                continue;
            }
            Err(e) => return Step::Done(partial(done, e)),
        };
        let off = (a & (PAGE_SIZE - 1)) as usize;
        let n = (len - done).min(PAGE_SIZE as usize - off);
        let seg = PageSeg {
            phys,
            // Within a page: lossless
            off: off as u32,
            len: n as u32,
        };
        // Room was reserved for `max` pages in both
        if out.segs.try_push(seg).is_err() || out.owners.try_push(cache_owner(v, write)).is_err() {
            if out.segs.len() > out.owners.len() {
                out.segs.pop();
            }
            unpin_page(phys);
            break;
        }
        done += n;
    }
    Step::Done(Ok(done))
}

/// Pin the pages of `mm`'s `len` bytes at `addr`, at most `max` pages,
/// into `out` (Linux pin_user_pages_fast, FOLL_PIN, with FOLL_WRITE for
/// `write`): the bytes pinned, short at the first page that cannot be
/// pinned; that page's error if none was. The mmap_lock is held for
/// reading across the run and dropped only to fault a page in.
fn pin_user_range(
    out: &mut PinnedPages,
    mm: &Mm,
    addr: u64,
    len: usize,
    write: bool,
    max: usize,
) -> Result<usize, KernelError> {
    let mut done = 0;
    loop {
        let step = pin_locked(out, mm, &mm.mmap_read(), (addr, len, done), write, max);
        let (page, acc) = match step {
            Step::Done(r) => return r,
            Step::Fault(page, acc) => (page, acc),
        };
        done = (page.max(addr) - addr) as usize;
        if let Err(e) = fault_in(mm, page, acc) {
            return partial(done, e);
        }
    }
}

/// A visitor of user runs: called with (address, length, offset into
/// the caller's buffer), returns the bytes it took (`iov_iter::Segs`)
pub type RunFn<'a> = dyn FnMut(u64, usize, usize) -> usize + 'a;

/// Pin the user pages of up to `max` pages' worth of `segs` (user
/// address, length) runs, in order, for `write` (Linux
/// iov_iter_extract_pages over an ITER_IOVEC): the pinned pages and the
/// bytes they cover, short at the first page that cannot be pinned;
/// that page's error if it is the first
pub fn pin_user_segs(
    segs: &mut dyn FnMut(&mut RunFn<'_>) -> usize,
    write: bool,
    max: usize,
) -> Result<PinnedPages, KernelError> {
    let mm = crate::task::percpu::current()
        .mm()
        .ok_or(KernelError::BadAddress)?;
    let mut out = PinnedPages::new(max)?;
    let mut err = None;
    segs(&mut |addr, len, _| {
        if err.is_some() || out.segs.len() >= max {
            return 0;
        }
        match pin_user_range(&mut out, &mm, addr, len, write, max) {
            Ok(n) => n,
            Err(e) => {
                err = Some(e);
                0
            }
        }
    });
    match err {
        Some(e) if out.is_empty() => Err(e),
        _ => Ok(out),
    }
}
