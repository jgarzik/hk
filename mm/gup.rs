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
use crate::util::seg::trim_tail;
use crate::util::smallvec::SmallVec;

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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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
    segs: SmallVec<PageSeg, INLINE_PAGES>,
    /// Per segment, the inode whose page cache its page belongs to (a
    /// shared file mapping written through): a write dirties it there
    owners: SmallVec<Option<Arc<Inode>>, INLINE_PAGES>,
    dirty: bool,
}

/// Pages kept without a heap allocation (Linux DIO_INLINE_BIO_VECS)
const INLINE_PAGES: usize = 4;

impl PinnedPages {
    /// Room for `max` pages: no allocation up to `INLINE_PAGES`
    pub fn new(max: usize) -> Result<Self, KernelError> {
        Ok(Self {
            segs: SmallVec::try_with_capacity(max)?,
            owners: SmallVec::try_with_capacity(max)?,
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

    /// Pages pinned (one per piece)
    pub fn nr_pages(&self) -> usize {
        self.segs.len()
    }

    /// Give back the last `n` bytes, unpinning the pages left with none
    /// (Linux bio_iov_iter_align_down)
    pub fn trim(&mut self, n: usize) {
        let owners = &mut self.owners;
        trim_tail(
            &mut self.segs,
            n,
            |s| s.len as usize,
            // Less than a page: lossless
            |s, l| s.len = l as u32,
            |s| {
                owners.pop();
                unpin_page(s.phys);
            },
        );
    }

    /// The pages were written (a read from the device): dirty them when
    /// unpinned
    pub fn set_dirty(&mut self) {
        self.dirty = true;
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

/// Part of a `PinnedPages`, the `len` bytes from byte `off` of its
/// pieces (a registered buffer's range: Linux io_import_reg_buf's bvec):
/// pinned as long as the borrow
pub struct PinnedSlice<'a> {
    segs: SmallVec<PageSeg, INLINE_PAGES>,
    _pins: core::marker::PhantomData<&'a PinnedPages>,
}

impl PinnedSlice<'_> {
    /// Its pieces
    pub fn segs(&self) -> &[PageSeg] {
        &self.segs
    }

    /// The pieces, owned: the caller keeps the `PinnedPages` alive as
    /// long as it uses them (an asynchronous I/O holding its buffer)
    pub fn into_segs(self) -> SmallVec<PageSeg, INLINE_PAGES> {
        self.segs
    }
}

impl PinnedPages {
    /// The pieces of bytes [off, off + len) of what is pinned (EFAULT
    /// past the end). Every piece but the first starts a page, so the
    /// first one is found by index.
    pub fn slice(&self, off: usize, len: usize) -> Result<PinnedSlice<'_>, KernelError> {
        const P: usize = PAGE_SIZE as usize;
        if off.checked_add(len).is_none_or(|e| e > self.len()) {
            return Err(KernelError::BadAddress);
        }
        let mut out = SmallVec::try_with_capacity(len.div_ceil(P) + 1)?;
        if len == 0 {
            return Ok(PinnedSlice {
                segs: out,
                _pins: core::marker::PhantomData,
            });
        }
        let first = self.segs[0].off as usize;
        let abs = first + off;
        let (mut i, mut at) = (abs / P, abs % P);
        if i == 0 {
            at -= first;
        }
        let mut left = len;
        while left > 0 {
            let s = self.segs[i];
            let n = (s.len as usize - at).min(left);
            out.push(PageSeg {
                phys: s.phys,
                // Within a page: lossless
                off: s.off + at as u32,
                len: n as u32,
            });
            left -= n;
            i += 1;
            at = 0;
        }
        Ok(PinnedSlice {
            segs: out,
            _pins: core::marker::PhantomData,
        })
    }
}

/// Pin again `segs`, at most `max` pages, pages already pinned (a
/// registered buffer's) for one direct I/O that may outlive the first
/// pin (Linux: a bvec's pages, referenced by the bio): each piece's
/// memory aligned to `mem_mask` (EINVAL), the total cut to a multiple
/// of `len_mask` + 1; the pins and the bytes they cover
pub fn repin(
    segs: &[PageSeg],
    max: usize,
    mem_mask: usize,
    len_mask: usize,
) -> Result<PinnedPages, KernelError> {
    let n = segs.len().min(max);
    let mut out = PinnedPages::new(n)?;
    for s in &segs[..n] {
        if (s.off as usize | s.len as usize) & mem_mask != 0 {
            return Err(KernelError::InvalidArgument);
        }
        if !FRAME_ALLOCATOR.get_refs(s.phys, GUP_PIN_COUNTING_BIAS) {
            return Err(KernelError::OutOfMemory);
        }
        // Room was reserved for `n` pages in both: no allocation
        out.segs.push(*s);
        out.owners.push(None);
    }
    let excess = out.len() & len_mask;
    out.trim(excess);
    if out.is_empty() {
        return Err(KernelError::InvalidArgument);
    }
    Ok(out)
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
        // Room was reserved for `max` pages in both: no allocation
        out.segs.push(seg);
        out.owners.push(cache_owner(v, write));
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

/// Pin the current task's pages of the `len` bytes at `addr`, at most
/// `max` pages in all in `out`, for `write` (Linux pin_user_pages_fast,
/// FOLL_PIN, with FOLL_WRITE for a read from a device): the bytes
/// pinned, short at the first page that cannot be pinned; that page's
/// error if none was
pub fn pin_user(
    out: &mut PinnedPages,
    addr: u64,
    len: usize,
    write: bool,
    max: usize,
) -> Result<usize, KernelError> {
    let mm = crate::task::percpu::current()
        .mm()
        .ok_or(KernelError::BadAddress)?;
    pin_user_range(out, &mm, addr, len, write, max)
}
