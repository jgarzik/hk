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
    /// Page-cache pages of shared file mappings, by index in `segs`,
    /// with their mapping's inode: a write into them dirties them there
    cache: KVec<(usize, Arc<Inode>)>,
    dirty: bool,
}

impl PinnedPages {
    /// Room for `max` pages
    fn new(max: usize) -> Result<Self, KernelError> {
        Ok(Self {
            segs: KVec::try_with_capacity(max)?,
            cache: KVec::new(),
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

    /// Copy `data` into segment `i` from byte `at` of it (the kernel
    /// writing what a device would); the bytes copied
    pub fn write(&self, i: usize, at: usize, data: &[u8]) -> usize {
        let Some(s) = self.segs.get(i) else {
            return 0;
        };
        let n = data.len().min((s.len as usize).saturating_sub(at));
        let dst = crate::arch::phys_to_virt(s.phys + u64::from(s.off) + at as u64);
        // SAFETY: the page is pinned while `self` lives and [off + at,
        // off + at + n) lies in it; a raw copy creates no reference to
        // memory the process may access meanwhile (as a device's DMA)
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), dst, n) };
        n
    }

    /// Copy from segment `i`, byte `at` on, into `buf`; the bytes copied
    pub fn read(&self, i: usize, at: usize, buf: &mut [u8]) -> usize {
        let Some(s) = self.segs.get(i) else {
            return 0;
        };
        let n = buf.len().min((s.len as usize).saturating_sub(at));
        let src = crate::arch::phys_to_virt(s.phys + u64::from(s.off) + at as u64);
        // SAFETY: as `write`, the other way
        unsafe { core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), n) };
        n
    }

    /// Mark segment `i`'s page dirty: anonymous memory by its flag, a
    /// page-cache page in its mapping under the page lock (Linux
    /// folio_mark_dirty)
    fn dirty_seg(&self, i: usize, phys: u64) {
        match self.cache.iter().find(|(k, _)| *k == i) {
            Some((_, inode)) => {
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
        for (i, s) in self.segs.iter().enumerate() {
            if self.dirty {
                self.dirty_seg(i, s.phys);
            }
            unpin_page(s.phys);
        }
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

/// Pin the page `addr` of the current address space, to be written
/// (`write`: a read from a device, Linux FOLL_WRITE) or read; its frame.
/// Takes and drops the mmap_lock (for reading) itself.
fn pin_one(mm: &Mm, addr: u64, write: bool) -> Result<(u64, Option<Arc<Inode>>), KernelError> {
    loop {
        let r = {
            let map = mm.mmap_read();
            let vma = pin_vma(&map, addr, write)?;
            let t = PgTables::new(mm, &map);
            match follow_pin(mm, t, vma, addr, write)? {
                Follow::Pinned(phys) => return Ok((phys, cache_owner(vma, write))),
                Follow::Unshare => {
                    unshare_for_write(
                        mm,
                        t,
                        addr,
                        vma.anon_vma.clone(),
                        vma.index_of(addr),
                        vma.prot,
                    )
                    .map_err(|_| KernelError::OutOfMemory)?;
                    None
                }
                Follow::Fault(a) => Some(a),
            }
        };
        if let Some(a) = r {
            fault_in(mm, addr, a)?;
        }
    }
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

/// Pin the pages of the current task's `len` bytes at `addr`, at most
/// `max` pages, into `out` (Linux pin_user_pages_fast, FOLL_PIN, with
/// FOLL_WRITE for `write`): the bytes pinned, short at the first page
/// that cannot be pinned; that page's error if none was
fn pin_user_range(
    out: &mut PinnedPages,
    addr: u64,
    len: usize,
    write: bool,
    max: usize,
) -> Result<usize, KernelError> {
    let mm = crate::task::percpu::current()
        .mm()
        .ok_or(KernelError::BadAddress)?;
    let mut done = 0usize;
    while done < len && out.segs.len() < max {
        let a = addr
            .checked_add(done as u64)
            .ok_or(KernelError::BadAddress)?;
        let off = (a & (PAGE_SIZE - 1)) as usize;
        let n = (len - done).min(PAGE_SIZE as usize - off);
        let (phys, owner) = match pin_one(&mm, a & !(PAGE_SIZE - 1), write) {
            Ok(p) => p,
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        };
        let seg = PageSeg {
            phys,
            // Within a page: lossless
            off: off as u32,
            len: n as u32,
        };
        // Room was reserved for `max` pages
        if out.segs.try_push(seg).is_err() {
            unpin_page(phys);
            break;
        }
        if let Some(i) = owner
            && out.cache.try_push((out.segs.len() - 1, i)).is_err()
        {
            // Without its owner the page could not be dirtied: give it back
            out.segs.pop();
            unpin_page(phys);
            break;
        }
        done += n;
    }
    Ok(done)
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
    let mut out = PinnedPages::new(max)?;
    let mut err = None;
    segs(&mut |addr, len, _| {
        if err.is_some() || out.segs.len() >= max {
            return 0;
        }
        match pin_user_range(&mut out, addr, len, write, max) {
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
