//! madvise (Linux mm/madvise.c)
//!
//! The advice is checked, then applied VMA by VMA over the part of each
//! that lies in the range (madvise_walk_vmas): advice that changes VMA
//! flags splits a VMA at the range edges; advice that drops pages zaps
//! only memory that is mapped. The first VMA that refuses the advice
//! stops the walk with its error (the VMAs before it keep the advice); a
//! range with unmapped holes is ENOMEM once the rest has been advised.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::shmem::Shmem;
use super::{
    MADV_COLD, MADV_DODUMP, MADV_DOFORK, MADV_DONTDUMP, MADV_DONTFORK, MADV_DONTNEED, MADV_FREE,
    MADV_HUGEPAGE, MADV_KEEPONFORK, MADV_NOHUGEPAGE, MADV_NORMAL, MADV_PAGEOUT, MADV_RANDOM,
    MADV_REMOVE, MADV_SEQUENTIAL, MADV_WILLNEED, MADV_WIPEONFORK, Mm, MmStruct, PAGE_SIZE,
    VM_DONTCOPY, VM_DONTDUMP, VM_HUGEPAGE, VM_NOHUGEPAGE, VM_RAND_READ, VM_SEQ_READ, VM_WIPEONFORK,
    Vma, get_task_mm,
};
use crate::error::KernelError;
use crate::sync::{RwSemReadGuard, RwSemWriteGuard};
use crate::task::percpu::current_tid;

/// A hole to punch in a shared object once the mm lock is dropped
/// (MADV_REMOVE): the object and its page range [from, to)
type Punch = (Arc<Shmem>, u64, u64);

/// madvise(2): give advice about [start, start + len) (Linux do_madvise)
pub fn sys_madvise(start: u64, len: u64, advice: i32) -> i64 {
    if !valid(advice) {
        return KernelError::InvalidArgument.sysret();
    }
    let end = match check_range(start, len) {
        Ok(Some(end)) => end,
        Ok(None) => return 0,
        Err(e) => return e.sysret(),
    };
    let Some(mm) = get_task_mm(current_tid()) else {
        return KernelError::OutOfMemory.sysret();
    };
    let mut punch = Vec::new();
    let map = if needs_write(advice) {
        mm.mmap_write_killable().map(Map::W)
    } else {
        mm.mmap_read_killable().map(Map::R)
    };
    let mut map = match map {
        Ok(m) => m,
        Err(e) => return e.sysret(),
    };
    let r = walk(&mut map, &mm, start, end, advice, &mut punch);
    #[cfg(feature = "mmcheck")]
    super::check::verify(map.get(), mm.pgd(), "madvise");
    drop(map);
    // MADV_REMOVE frees the shared object's pages after the zap, also
    // for the VMAs done before an error (Linux punches VMA by VMA)
    for (sh, from, to) in punch {
        sh.punch(from, to);
    }
    match r {
        Ok(()) => 0,
        Err(e) => e.sysret(),
    }
}

/// The mmap_lock as madvise holds it
enum Map<'a> {
    R(RwSemReadGuard<'a, MmStruct>),
    W(RwSemWriteGuard<'a, MmStruct>),
}

impl Map<'_> {
    fn get(&self) -> &MmStruct {
        match self {
            Map::R(m) => m,
            Map::W(m) => m,
        }
    }
}

/// Advice that changes VMAs needs the mmap_lock for writing; advice that
/// only zaps or hints reads it (Linux madvise_need_mmap_write): zaps
/// change entries under the page-table locks, faults may run alongside
fn needs_write(advice: i32) -> bool {
    !matches!(
        advice,
        MADV_WILLNEED | MADV_DONTNEED | MADV_FREE | MADV_REMOVE | MADV_COLD | MADV_PAGEOUT
    )
}

/// Advice values Linux accepts (madvise_behavior_valid), less those hk
/// does not implement
fn valid(advice: i32) -> bool {
    matches!(
        advice,
        MADV_NORMAL
            | MADV_RANDOM
            | MADV_SEQUENTIAL
            | MADV_WILLNEED
            | MADV_DONTNEED
            | MADV_FREE
            | MADV_REMOVE
            | MADV_DONTFORK
            | MADV_DOFORK
            | MADV_HUGEPAGE
            | MADV_NOHUGEPAGE
            | MADV_DONTDUMP
            | MADV_DODUMP
            | MADV_WIPEONFORK
            | MADV_KEEPONFORK
            | MADV_COLD
            | MADV_PAGEOUT
    )
}

/// The end of the range (Linux check_input_range): EINVAL for an
/// unaligned start or a length that wraps when rounded up to pages;
/// None for an empty range
fn check_range(start: u64, len: u64) -> Result<Option<u64>, KernelError> {
    if start & (PAGE_SIZE - 1) != 0 {
        return Err(KernelError::InvalidArgument);
    }
    let len_pages = len.wrapping_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    if len != 0 && len_pages == 0 {
        return Err(KernelError::InvalidArgument);
    }
    let end = start
        .checked_add(len_pages)
        .ok_or(KernelError::InvalidArgument)?;
    Ok((len != 0).then_some(end))
}

/// Apply `advice` to each VMA part in [start, end), mm lock held (Linux
/// madvise_walk_vmas). The walk goes by address, as a VMA may be split
/// or merged under it.
fn walk(
    map: &mut Map,
    owner: &Mm,
    start: u64,
    end: u64,
    advice: i32,
    punch: &mut Vec<Punch>,
) -> Result<(), KernelError> {
    let mut addr = start;
    let mut unmapped = false;
    loop {
        let mm = map.get();
        let (vs, ve) = match mm.next_vma(addr).and_then(|i| mm.get_vma(i)) {
            Some(v) => (v.start, v.end),
            None => return Err(KernelError::OutOfMemory),
        };
        if addr < vs {
            unmapped = true;
            addr = vs;
            if addr >= end {
                break;
            }
        }
        let e = ve.min(end);
        vma_advise(map, owner, addr, e, advice, punch)?;
        if e >= end {
            break;
        }
        addr = e;
    }
    if unmapped {
        Err(KernelError::OutOfMemory)
    } else {
        Ok(())
    }
}

/// Apply `advice` to [start, end), inside one VMA (Linux
/// madvise_vma_behavior)
fn vma_advise(
    map: &mut Map,
    owner: &Mm,
    start: u64,
    end: u64,
    advice: i32,
    punch: &mut Vec<Punch>,
) -> Result<(), KernelError> {
    let mm = map.get();
    let idx = mm.find_vma_index(start).ok_or(KernelError::OutOfMemory)?;
    let vma = mm.get_vma(idx).ok_or(KernelError::OutOfMemory)?;
    match advice {
        MADV_WILLNEED => Ok(()),
        MADV_COLD | MADV_PAGEOUT => {
            lru_ok(vma)?;
            cold_or_pageout(vma, owner, start, end, advice == MADV_PAGEOUT);
            Ok(())
        }
        MADV_DONTNEED | MADV_FREE => dontneed(vma, owner, start, end, advice),
        MADV_REMOVE => remove(vma, owner, start, end, punch),
        _ => {
            let flags = new_flags(vma, advice)?;
            match map {
                Map::W(mm) => update_flags(mm, idx, start, end, flags),
                Map::R(_) => unreachable!("VMA change under a read hold"),
            }
        }
    }
}

/// Private anonymous memory: no file, shared object or SysV segment
/// behind it (Linux vma_is_anonymous)
fn is_anon(vma: &Vma) -> bool {
    vma.file.is_none() && vma.shmem.is_none() && vma.shm.is_none()
}

/// MADV_COLD / MADV_PAGEOUT: refused on locked memory (Linux
/// can_madv_lru_vma)
fn lru_ok(vma: &Vma) -> Result<(), KernelError> {
    if vma.is_locked() {
        return Err(KernelError::InvalidArgument);
    }
    Ok(())
}

/// MADV_COLD (deactivate) or MADV_PAGEOUT (reclaim) the anonymous pages
/// of [start, end) that this mapping alone maps (Linux
/// madvise_cold_or_pageout_pte_range), mm lock held for reading: 2MB
/// pages are split first, the pages taken off the LRU under each
/// table's PTE lock, then reclaimed with no spinlock held (the swap
/// writes sleep). Without swap, PAGEOUT leaves anonymous memory alone.
fn cold_or_pageout(vma: &Vma, owner: &Mm, start: u64, end: u64, pageout: bool) {
    use super::huge_page::{HUGE_PAGE_SIZE, split_huge_pmd};
    use crate::arch::paging;
    if vma.anon_vma.is_none() || (pageout && super::swap::swap_totals().0 == 0) {
        return;
    }
    super::lru::lru_add_drain_all();
    let pgd = owner.pgd();
    let mut pages = Vec::new();
    let mut addr = start;
    while addr < end {
        let next = ((addr | (HUGE_PAGE_SIZE - 1)) + 1).min(end);
        let Some(pmd) = paging::pmd_ptr(pgd, addr) else {
            addr = ((addr | ((1 << 30) - 1)) + 1).min(end);
            continue;
        };
        // SAFETY: a live 2MB-level entry of the locked mm
        let pmdval = unsafe { core::ptr::read_volatile(pmd) };
        if paging::pmd_huge(pmdval) {
            let _ = split_huge_pmd(owner, addr);
        }
        if let Some(p) = paging::pte_ptr(pgd, addr) {
            let _l = super::ptl::pte_lock(p);
            for a in (addr..next).step_by(PAGE_SIZE as usize) {
                let Some(phys) = own_page(pgd, a) else {
                    continue;
                };
                if !pageout {
                    super::lru::deactivate(phys);
                } else if super::lru::isolate(phys) {
                    pages.push(phys);
                }
            }
        }
        addr = next;
    }
    if !pages.is_empty() {
        super::vmscan::reclaim_pages(pages);
    }
}

/// The anonymous page mapped at `addr`, if no other PTE maps it (Linux
/// skips shared folios: folio_maybe_mapped_shared), PTE lock held
fn own_page(pgd: u64, addr: u64) -> Option<u64> {
    use crate::arch::paging;
    let p = paging::pte_ptr(pgd, addr)?;
    // SAFETY: a live entry under its PTE lock
    let pte = unsafe { core::ptr::read_volatile(p) };
    if !paging::pte_present(pte) {
        return None;
    }
    let phys = paging::pte_addr(pte);
    super::page::phys_to_page(phys)
        .filter(|pg| pg.is_anon() && pg.mapcount() == 1)
        .map(|_| phys)
}

/// MADV_DONTNEED / MADV_FREE (Linux madvise_dontneed_free): not on
/// locked memory, MADV_FREE only on private anonymous memory. MADV_FREE
/// frees at once, like DONTNEED (the pages are not kept for reuse).
fn dontneed(vma: &Vma, owner: &Mm, start: u64, end: u64, advice: i32) -> Result<(), KernelError> {
    if vma.is_locked() || (advice == MADV_FREE && !is_anon(vma)) {
        return Err(KernelError::InvalidArgument);
    }
    // Under the mm lock held for reading: a racing fault may map a page
    // again (the page-table locks order it before or after the zap)
    super::memory::zap_range(&mut super::gather::Gather::new(owner), start, end);
    Ok(())
}

/// MADV_REMOVE (Linux madvise_remove): only memory with a backing object
/// that may be written through the mapping (EINVAL for locked or private
/// anonymous memory; EACCES for a private file mapping, a shared one of
/// a file not open for writing, or a SHM_RDONLY attachment; EOPNOTSUPP
/// for a file, as for a Linux filesystem without hole punching, like
/// ramfs). The range is zapped and its hole recorded in `punch`.
fn remove(
    vma: &Vma,
    owner: &Mm,
    start: u64,
    end: u64,
    punch: &mut Vec<Punch>,
) -> Result<(), KernelError> {
    if vma.is_locked() || (vma.file.is_none() && vma.shmem.is_none()) {
        return Err(KernelError::InvalidArgument);
    }
    let maywrite = vma.is_shared()
        && vma.file.as_ref().is_none_or(|f| f.is_writable())
        && !vma.shm.as_ref().is_some_and(|a| a.rdonly());
    if !maywrite {
        return Err(KernelError::PermissionDenied);
    }
    if vma.file.is_some() {
        return Err(KernelError::OperationNotSupported);
    }
    super::memory::zap_range(&mut super::gather::Gather::new(owner), start, end);
    if let Some(sh) = &vma.shmem {
        let first = vma.offset + start - vma.start;
        let last = vma.offset + end - vma.start;
        punch.push((sh.clone(), first / PAGE_SIZE, last / PAGE_SIZE));
    }
    Ok(())
}

/// The VMA flags `advice` asks for (Linux madvise_vma_behavior)
fn new_flags(vma: &Vma, advice: i32) -> Result<u32, KernelError> {
    let f = vma.flags;
    Ok(match advice {
        MADV_NORMAL => f & !(VM_RAND_READ | VM_SEQ_READ),
        MADV_RANDOM => (f & !VM_SEQ_READ) | VM_RAND_READ,
        MADV_SEQUENTIAL => (f & !VM_RAND_READ) | VM_SEQ_READ,
        MADV_DONTFORK => f | VM_DONTCOPY,
        MADV_DOFORK => f & !VM_DONTCOPY,
        MADV_DONTDUMP => f | VM_DONTDUMP,
        MADV_DODUMP => f & !VM_DONTDUMP,
        MADV_HUGEPAGE => (f & !VM_NOHUGEPAGE) | VM_HUGEPAGE,
        MADV_NOHUGEPAGE => (f & !VM_HUGEPAGE) | VM_NOHUGEPAGE,
        // Only private anonymous memory can be wiped on fork
        MADV_WIPEONFORK if vma.file.is_some() || vma.is_shared() => {
            return Err(KernelError::InvalidArgument);
        }
        MADV_WIPEONFORK => f | VM_WIPEONFORK,
        MADV_KEEPONFORK => f & !VM_WIPEONFORK,
        _ => f,
    })
}

/// Give [start, end) of the VMA at `idx` the flags `flags` (Linux
/// madvise_update_vma): nothing to do if they are its own, else it is
/// split at the range edges and the part merged with its neighbours
fn update_flags(
    mm: &mut MmStruct,
    idx: usize,
    start: u64,
    end: u64,
    flags: u32,
) -> Result<(), KernelError> {
    if mm.get_vma(idx).is_some_and(|v| v.flags == flags) {
        return Ok(());
    }
    mm.split_at(start);
    mm.split_at(end);
    let idx = mm.find_vma_exact(start).ok_or(KernelError::WouldBlock)?;
    mm.set_flags(idx, flags);
    mm.merge_adjacent(idx);
    Ok(())
}
