//! User page faults (Linux mm/memory.c handle_mm_fault)
//!
//! The arch trap handlers decode a fault (address, access, user or
//! kernel mode) and call [`handle_mm_fault`]; its error says what the
//! access earns (Linux VM_FAULT_SIGSEGV / VM_FAULT_SIGBUS /
//! VM_FAULT_OOM). Page tables are reached through the fault's mmap_lock
//! guard (`pgtable::PgTables`), entries built by the `arch::paging` PTE
//! helpers (`mk_pte`, `pte_mkwrite`, ...).
//!
//! The fault holds the mmap_lock for reading from the VMA lookup to the
//! PTE update, I/O included (doc/LOCKING.md, Address Spaces): a PTE is
//! installed under its table's PTE lock with a compare and swap against
//! the value the fault saw, so a racing fault on the same page wins once
//! and the loser drops its page (Linux pte_same under the page table
//! lock).

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use super::anon_vma::AnonVma;
use super::huge_page::{HUGE_PAGE_SIZE, split_huge_pmd};
use super::pgtable::{PgTables, Pte, PteTable};
use super::tlb::flush_tlb_page;
use super::{Mm, MmStruct, PAGE_SIZE, PROT_EXEC, PROT_READ, PROT_WRITE, SwapEntry};
use crate::FRAME_ALLOCATOR;
use crate::arch::{PageFlags, paging, phys_to_virt};
use crate::fs::File;
use crate::mm::page_alloc::Gfp;
use crate::task::percpu::{increment_maj_flt, increment_min_flt};

/// The access that faulted
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Access {
    Read,
    Write,
    Exec,
}

/// Why a fault was not resolved
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VmFault {
    /// No mapping, or the mapping forbids the access (SIGSEGV)
    Segv,
    /// The mapping has no page there (SIGBUS)
    Bus,
    /// No memory for the page or a page table
    Oom,
    /// Changed under the fault: return and let the access retry (never
    /// returned by `handle_mm_fault`)
    Retry,
}

/// What a fault needs of its VMA, copied out under the mm lock
#[derive(Default)]
struct Area {
    start: u64,
    end: u64,
    prot: u32,
    shared: bool,
    anon: bool,
    thp: bool,
    offset: u64,
    /// Anonymous page index of `start` (Linux vm_pgoff)
    pgoff: u64,
    file: Option<Arc<File>>,
    anon_vma: Option<Arc<AnonVma>>,
}

impl Area {
    /// Linear page index of `addr` (Linux linear_page_index)
    fn index(&self, addr: u64) -> u64 {
        self.pgoff + (addr - self.start) / PAGE_SIZE
    }

    /// Byte offset of the page at `addr` in the mapped object
    fn pgoff(&self, addr: u64) -> u64 {
        self.offset + (addr & !(PAGE_SIZE - 1)) - self.start
    }

    /// Private anonymous: its pages go on the rmap and LRU
    fn anon_private(&self) -> bool {
        self.anon && !self.shared
    }
}

/// The VMA allows `access` (Linux access_error / vma_is_accessible)
fn access_ok(prot: u32, access: Access) -> bool {
    match access {
        Access::Read => prot & (PROT_READ | PROT_WRITE | PROT_EXEC) != 0,
        Access::Write => prot & PROT_WRITE != 0,
        Access::Exec => prot & PROT_EXEC != 0,
    }
}

/// Find the VMA of `addr` and check the access; `Retry` if a stack
/// must first grow down to it (needs the mmap_lock for writing)
fn find_area(map: &MmStruct, addr: u64, access: Access) -> Result<Area, VmFault> {
    let Some(idx) = map.find_vma_index(addr) else {
        map.find_expandable_vma(addr).ok_or(VmFault::Segv)?;
        return Err(VmFault::Retry);
    };
    let vma = map.get_vma(idx).ok_or(VmFault::Segv)?;
    if !access_ok(vma.prot, access) {
        return Err(VmFault::Segv);
    }
    Ok(area_of(vma))
}

/// What a fault needs of `vma`
fn area_of(vma: &super::Vma) -> Area {
    Area {
        start: vma.start,
        end: vma.end,
        prot: vma.prot,
        shared: vma.is_shared(),
        anon: vma.is_anonymous(),
        thp: vma.is_thp_eligible(),
        offset: vma.offset,
        pgoff: vma.pgoff,
        file: vma.file.clone(),
        anon_vma: vma.anon_vma.clone(),
    }
}

/// A frame for user data: below the low watermark it reclaims (swaps
/// pages out) where the caller may sleep, else none (the kernel's
/// allocations may go on to min; see `page_alloc::alloc_mark`)
pub(crate) fn alloc_user() -> Option<u64> {
    FRAME_ALLOCATOR.alloc_gfp(Gfp::HIGHUSER_MOVABLE)
}

/// Replace the present entry `old` for `addr` in the locked table `t`
/// by `new`, which maps another page (Linux ptep_clear_flush +
/// set_pte_at): the entry is cleared and its TLB entry flushed before
/// `new` is written, so no CPU caches both translations at once (arm64
/// break-before-make). False if the entry no longer holds `old`.
fn replace_pte(mm: &Mm, t: &PteTable<'_>, addr: u64, old: u64, new: u64) -> bool {
    if !t.set(addr, old, 0) {
        return false;
    }
    flush_tlb_page(mm, addr);
    t.store(addr, new);
    true
}

/// A new anonymous page at `addr` joins the rmap and LRU
fn add_anon(phys: u64, area: &Area, addr: u64) {
    if let Some(av) = &area.anon_vma {
        super::rmap::page_add_anon_rmap(phys, av, area.index(addr));
    }
    super::lru::lru_add(phys);
}

/// Resolve a fault at `addr` of the address space `mm` (the current
/// task's, or one it is pinned to).
///
/// The mmap_lock is held for reading from the VMA lookup through the
/// PTE update, reads of a file page or swap slot included, so a fault
/// cannot race fork's copy, munmap or mprotect of the range (Linux:
/// mmap_lock for read + the page table lock).
pub fn handle_mm_fault(mm: &Mm, addr: u64, access: Access) -> Result<(), VmFault> {
    match fault(mm, addr, access) {
        Err(VmFault::Retry) => Ok(()),
        r => r,
    }
}

/// Grow the stack VMA below `addr` down to it (Linux expand_stack),
/// with the mmap_lock held for writing
fn grow_stack(mm: &Mm, addr: u64) -> Result<(), VmFault> {
    let mut map = mm.mmap_write();
    if map.find_vma_index(addr).is_some() {
        return Ok(()); // grown meanwhile
    }
    let i = map.find_expandable_vma(addr).ok_or(VmFault::Segv)?;
    map.expand_downwards(i, addr).map_err(|_| VmFault::Segv)
}

/// The fault's VMA, the mmap_lock held for reading (Linux
/// lock_mm_and_find_vma: a stack to grow takes it for writing first)
fn lock_area(mm: &Mm, addr: u64, access: Access) -> Result<(MmRead<'_>, Area), VmFault> {
    loop {
        let map = mm.mmap_read();
        match find_area(&map, addr, access) {
            Ok(area) => return Ok((map, area)),
            Err(VmFault::Retry) => {
                drop(map);
                grow_stack(mm, addr)?;
            }
            Err(e) => return Err(e),
        }
    }
}

type MmRead<'a> = crate::sync::RwSemReadGuard<'a, MmStruct>;

fn fault(mm: &Mm, addr: u64, access: Access) -> Result<(), VmFault> {
    let (map, area) = lock_area(mm, addr, access)?;
    let t = PgTables::new(mm, &map);
    if let Some(r) = huge_fault(mm, t, addr, &area, access) {
        return r;
    }
    let ptep = leaf(mm, t, addr)?;
    let pte = ptep.get();
    if paging::pte_protnone(pte) {
        // Only mprotect makes protnone entries, with the VMA (which
        // allows this access): restore it, read-only, and retry (a
        // write then goes through do_wp_page; write implies read)
        let prot = (area.prot & !PROT_WRITE) | PROT_READ;
        let l = ptep.lock();
        if l.set(addr, pte, paging::pte_modify(pte, prot)) {
            flush_tlb_page(mm, addr);
        }
        drop(l);
        return Ok(());
    }
    if paging::pte_present(pte) {
        if access == Access::Write && !paging::pte_write(pte) {
            return do_wp_page(mm, ptep, pte, addr, &area);
        }
        if access == Access::Exec && !paging::pte_exec(pte) {
            return Err(VmFault::Segv);
        }
        // Spurious: another CPU resolved it, or a stale TLB entry
        flush_tlb_page(mm, addr);
        return Ok(());
    }
    // A swap slot, a file page or a new page: the reads may sleep, with
    // the mm lock held for reading (Linux holds it across the I/O; the
    // VMA cannot change meanwhile)
    if SwapEntry::is_swap_pte(pte) {
        return do_swap_page(mm, ptep, pte, addr, &area, access);
    }
    let (page, locked, wp) = fault_page(addr, &area, access)?;
    let r = do_fault(mm, ptep, pte, page, addr, &area, wp);
    if locked {
        // Mapped under the page lock (Linux finish_fault): see
        // filemap::fault
        super::page::unlock_page(page);
    }
    drop(map);
    r
}

/// The leaf entry for `addr`, allocating missing tables; out of memory,
/// pages are reclaimed and the allocation tried again while that frees
/// some, a bounded number of times
fn leaf<'a>(mm: &Mm, t: PgTables<'a>, addr: u64) -> Result<Pte<'a>, VmFault> {
    for _ in 0..16 {
        if let Some(p) = t.pte_alloc(mm, addr) {
            return Ok(p);
        }
        // A huge page mapped there: the access is retried
        if still_huge(t, addr) {
            return Err(VmFault::Retry);
        }
        if super::vmscan::try_to_free_pages(super::vmscan::SWAP_CLUSTER_MAX) == 0 {
            return Err(VmFault::Oom);
        }
    }
    Err(VmFault::Oom)
}

/// A fault in a 2MB region: None to continue at the 4KB level
fn huge_fault(
    mm: &Mm,
    t: PgTables<'_>,
    addr: u64,
    area: &Area,
    access: Access,
) -> Option<Result<(), VmFault>> {
    let pmdp = t.pmd(addr)?;
    let pmd = pmdp.get();
    if paging::pmd_huge(pmd) {
        if access == Access::Write && !paging::pte_write(pmd) {
            // Write-protected huge page: split, then fault on the 4KB
            // page; a racing fault may have split (or unmapped) it first
            if split_huge_pmd(mm, pmdp).is_none() && still_huge(t, addr) {
                return Some(Err(VmFault::Oom));
            }
            return None;
        }
        if access == Access::Exec && !paging::pte_exec(pmd) {
            return Some(Err(VmFault::Segv));
        }
        flush_tlb_page(mm, addr);
        return Some(Ok(()));
    }
    if pmd == 0 && area.thp {
        return do_huge_anon(mm, t, addr, area).then_some(Ok(()));
    }
    None
}

/// A 2MB page still maps `addr`
fn still_huge(t: PgTables<'_>, addr: u64) -> bool {
    t.pmd(addr).is_some_and(|p| p.huge())
}

/// Map a zeroed 2MB page for a THP-eligible area if it covers the whole
/// aligned 2MB around `addr` (Linux do_huge_pmd_anonymous_page); false
/// to fall back to a 4KB page
fn do_huge_anon(mm: &Mm, t: PgTables<'_>, addr: u64, area: &Area) -> bool {
    let base = addr & !(HUGE_PAGE_SIZE - 1);
    if base < area.start || base + HUGE_PAGE_SIZE > area.end {
        return false;
    }
    let Some(frame) = FRAME_ALLOCATOR.alloc_huge() else {
        return false;
    };
    // The table its split will need, kept with it (Linux
    // pte_alloc_one + pgtable_trans_huge_deposit)
    let Some(pt) = FRAME_ALLOCATOR.alloc() else {
        FRAME_ALLOCATOR.free_huge(frame);
        return false;
    };
    // SAFETY: a fresh 2MB frame, reached through the direct map
    unsafe { core::ptr::write_bytes(phys_to_virt(frame), 0, HUGE_PAGE_SIZE as usize) };
    if area.prot & PROT_EXEC != 0 {
        super::mprotect::sync_huge(frame);
    }
    let mut flags = PageFlags::READ | PageFlags::USER;
    if area.prot & PROT_WRITE != 0 {
        flags |= PageFlags::WRITE;
    }
    if area.prot & PROT_EXEC != 0 {
        flags |= PageFlags::EXECUTE;
    }
    // The upper tables first, outside the page_table_lock (Linux
    // __handle_mm_fault's pmd_alloc); fails if a racing fault installed
    // a table or a page first
    let pmd = t.pmd_alloc(mm, base);
    let l = super::ptl::pt_lock(mm);
    let entry = crate::arch::paging::mk_pmd(frame, flags);
    let Some(pmd) = pmd.filter(|p| p.set_huge(&l, entry)) else {
        FRAME_ALLOCATOR.free_huge(frame);
        FRAME_ALLOCATOR.free(pt);
        return false;
    };
    super::huge_page::deposit(&pmd, &l, pt);
    add_anon(frame, area, base);
    increment_min_flt();
    true
}

/// The page to map at `addr` of a VMA with no page there yet, with a
/// reference for the new PTE: the page cache's for a file that maps its
/// cache (tmpfs files of shared anonymous memory and SysV shm included,
/// Linux shmem_fault), else a new page, zeroed for anonymous memory or
/// holding a private copy of the file data (Linux do_anonymous_page,
/// do_read_fault)
/// Also whether the page comes locked (a page-cache page: unlocked
/// once mapped) and whether it must be mapped read-only (a private
/// mapping's page-cache page: a write copies it, Linux do_read_fault).
fn fault_page(addr: u64, area: &Area, access: Access) -> Result<(u64, bool, bool), VmFault> {
    let exec = area.prot & PROT_EXEC != 0;
    if let (false, Some(f)) = (area.anon, &area.file)
        && let Some(r) = file_page(f, area.pgoff(addr), area, access)
    {
        return r;
    }
    let frame = alloc_user().ok_or(VmFault::Oom)?;
    // SAFETY: a fresh frame, ours alone
    let buf = unsafe { super::page::frame_bytes(frame) };
    buf.fill(0);
    let file = matches!((area.anon, &area.file), (false, Some(_)));
    if let (false, Some(f)) = (area.anon, &area.file) {
        // A short read (EOF, error) leaves the rest zero
        let _ = f.pread(buf, area.pgoff(addr));
    }
    // Executable, even zeroed: the frame's old code may still sit in
    // the instruction caches (Linux __sync_icache_dcache)
    if file || exec {
        paging::sync_page(frame, exec);
    }
    Ok((frame, false, false))
}

/// The page-cache page at byte offset `off` of `file`, for a mapping
/// of a filesystem that maps its cache (Linux filemap_fault): SIGBUS
/// past the end of the file. None: the fault copies the data. A shared
/// mapping maps the page itself, locked, with a reference for the PTE;
/// a writable one dirties it (Linux do_shared_fault). A private one
/// maps it read-only on a read (do_read_fault: the cache page is shared
/// until written) and a copy on a write (do_cow_fault).
fn file_page(
    file: &File,
    off: u64,
    area: &Area,
    access: Access,
) -> Option<Result<(u64, bool, bool), VmFault>> {
    let inode = file.mapping_inode()?;
    if !inode.i_op.maps_cache() {
        return None;
    }
    let exec = area.prot & PROT_EXEC != 0;
    let page = match super::filemap::fault(&inode, off / PAGE_SIZE) {
        Ok(p) => p,
        Err(e) => return Some(Err(e)),
    };
    paging::sync_page(page, exec);
    if area.shared && area.prot & PROT_WRITE != 0 && inode.i_swapfile.load(Ordering::Acquire) {
        // An active swap file is written only by swap: a write through
        // a mapping made before swapon is SIGBUS (Linux
        // do_page_mkwrite), a read maps the page read-only
        if access == Access::Write {
            super::page::unlock_page(page);
            super::filemap::put_page(page);
            return Some(Err(VmFault::Bus));
        }
        return Some(Ok((page, true, true)));
    }
    if area.shared {
        if area.prot & PROT_WRITE != 0 {
            super::filemap::dirty_page(&inode.i_data, page);
            crate::fs::fs_writeback::mark_inode_dirty(&inode);
        }
        return Some(Ok((page, true, false)));
    }
    if access != Access::Write {
        return Some(Ok((page, true, true)));
    }
    let copy = alloc_user();
    if let Some(new) = copy {
        // The cache page is locked and referenced, the new one ours
        // SAFETY: the new frame is ours; the cache page is locked
        unsafe { super::page::copy_page(new, page) };
        paging::sync_page(new, exec);
    }
    super::page::unlock_page(page);
    super::filemap::put_page(page);
    Some(copy.map(|n| (n, false, false)).ok_or(VmFault::Oom))
}

/// Map `page` (with its reference for the PTE) at `addr`, where the
/// entry held `old` (none); read-only with `wp` (a private mapping's
/// page-cache page: the first write copies it)
fn do_fault(
    mm: &Mm,
    ptep: Pte<'_>,
    old: u64,
    page: u64,
    addr: u64,
    area: &Area,
    wp: bool,
) -> Result<(), VmFault> {
    let prot = if wp {
        area.prot & !PROT_WRITE
    } else {
        area.prot
    };
    // Held across the rmap add and the flush (Linux do_anonymous_page
    // / finish_fault under the PTL): a reverse-map walk never sees the
    // entry without its page's rmap
    let l = ptep.lock();
    if !l.set(addr, old, paging::mk_pte(page, prot)) {
        drop(l);
        // A racing fault mapped the page first
        super::memory::put_page(page);
        return Ok(());
    }
    if area.anon_private() {
        add_anon(page, area, addr);
    }
    // A private mapping's own page: fresh, not the page cache's
    if !area.shared && !wp {
        set_exclusive(page);
    }
    flush_tlb_page(mm, addr);
    drop(l);
    increment_min_flt();
    Ok(())
}

/// The private mapping that just mapped `phys` owns it alone (Linux
/// RMAP_EXCLUSIVE)
fn set_exclusive(phys: u64) {
    if let Some(pg) = super::page::phys_to_page(phys) {
        pg.set_anon_exclusive();
    }
}

/// `phys` is a private mapping's own page, writable in place (Linux
/// PageAnonExclusive; `Page::reusable`)
fn is_exclusive(phys: u64) -> bool {
    super::page::phys_to_page(phys).is_some_and(|pg| pg.reusable())
}

/// Map the page of the swap PTE `pte` at `ptep` (Linux do_swap_page),
/// mm lock held for reading: the swap-cache page, or one read from the
/// slot into the cache (may sleep). The PTE takes the slot's place: a
/// write fault on a page no one else needs keeps it writable and drops
/// it from the swap cache (the slot is freed); otherwise it is mapped
/// read-only and copy-on-write, still in the cache (a clean copy of the
/// slot), and a later write fault decides.
fn do_swap_page(
    mm: &Mm,
    ptep: Pte<'_>,
    pte: u64,
    addr: u64,
    area: &Area,
    access: Access,
) -> Result<(), VmFault> {
    let e = SwapEntry::from_pte(pte);
    let page = match super::swap_state::read_swap_page(e) {
        Err(VmFault::Retry) => return Ok(()),
        r => r?,
    };
    paging::sync_page(page, area.prot & PROT_EXEC != 0);
    let r = map_swap_page(mm, ptep, pte, page, addr, area, access);
    super::page::unlock_page(page);
    r
}

/// The locked swap-cache page `page`, with a reference that becomes the
/// PTE's, replaces the swap PTE `pte` if the entry still holds it
fn map_swap_page(
    mm: &Mm,
    ptep: Pte<'_>,
    pte: u64,
    page: u64,
    addr: u64,
    area: &Area,
    access: Access,
) -> Result<(), VmFault> {
    let t = ptep.lock();
    if t.get(addr) != pte {
        FRAME_ALLOCATOR.decref(page);
        return Ok(());
    }
    super::swap::swap_free(SwapEntry::from_pte(pte));
    // The cache lets the page go on a write, or when swap runs short
    // (Linux should_try_to_free_swap: vm_swap_full), if no other swap
    // PTE needs the slot; exclusive: then no reference but ours
    let write = access == Access::Write;
    let freed = (write || super::swap::swap_full()) && super::swap_state::try_free_swap(page);
    let exclusive = write && freed && FRAME_ALLOCATOR.refcount(page) == 1;
    // A PROT_NONE VMA (swapoff's unuse_pte skips the access check) gets
    // a protnone entry from mk_pte, not a readable one
    let mut entry = paging::mk_pte(page, area.prot);
    if !exclusive && !area.shared {
        entry = paging::pte_mkcow(entry);
    }
    let ok = t.set(addr, pte, entry);
    debug_assert!(ok, "swap PTE changed under its PTE lock");
    if exclusive {
        set_exclusive(page);
    }
    if let Some(av) = &area.anon_vma {
        super::rmap::page_add_anon_rmap(page, av, area.index(addr));
    }
    flush_tlb_page(mm, addr);
    increment_maj_flt();
    Ok(())
}

/// swapoff: fault in the swap PTE at `addr` of `vma` (Linux
/// unuse_pte), mm lock held for reading (`t` borrows it)
pub fn unuse_pte(mm: &Mm, t: PgTables<'_>, vma: &super::Vma, addr: u64) -> Result<(), VmFault> {
    let area = area_of(vma);
    let Some(ptep) = t.pte(addr) else {
        return Ok(());
    };
    let pte = ptep.get();
    if !SwapEntry::is_swap_pte(pte) {
        return Ok(());
    }
    do_swap_page(mm, ptep, pte, addr, &area, Access::Read)
}

/// A write to a present read-only page of a writable VMA (Linux
/// do_wp_page): a shared mapping, or a private page no one else maps,
/// is made writable in place; a private page still shared (fork's
/// copy-on-write) is copied first
fn do_wp_page(mm: &Mm, ptep: Pte<'_>, pte: u64, addr: u64, area: &Area) -> Result<(), VmFault> {
    // A shared file page written back (write-protected by mkclean) is
    // dirty again once writable (Linux wp_page_shared ->
    // fault_dirty_shared_page)
    // Under the page lock, like Linux wp_page_shared: writeback holds it
    // across mkclean and clearing the dirty bit, so it never sees the
    // PTE writable but the page still clean (a later write would be
    // lost). The PTE's page is referenced first (it may be unmapped
    // meanwhile; wp_locked rechecks the entry).
    if area.shared
        && let Some(inode) = area.file.as_ref().and_then(|f| f.mapping_inode())
        && inode.i_op.maps_cache()
    {
        // An active swap file is written only by swap (Linux
        // do_page_mkwrite: SIGBUS), also after a read mapped it
        if inode.i_swapfile.load(Ordering::Acquire) {
            return Err(VmFault::Bus);
        }
        let phys = paging::pte_addr(pte);
        if !FRAME_ALLOCATOR.incref(phys) {
            return Ok(());
        }
        super::page::lock_page(phys);
        let r = wp_locked(mm, ptep, pte, addr, area, &mut None);
        super::filemap::dirty_page(&inode.i_data, phys);
        super::page::unlock_page(phys);
        FRAME_ALLOCATOR.decref(phys);
        crate::fs::fs_writeback::mark_inode_dirty(&inode);
        super::writeback::balance_dirty_pages(&inode);
        return r;
    }
    let mut spare = None;
    loop {
        match wp_locked(mm, ptep, pte, addr, area, &mut spare) {
            // Out of memory under the PTE lock: reclaim without it
            // (Linux wp_page_copy allocates before taking it)
            Err(VmFault::Retry) => spare = Some(alloc_user().ok_or(VmFault::Oom)?),
            r => {
                if let Some(p) = spare {
                    FRAME_ALLOCATOR.free(p);
                }
                return r;
            }
        }
    }
}

/// `do_wp_page` under the PTE lock; the copy's page comes from `spare`
/// if there is one, else `Retry` asks for one when none is free at once
fn wp_locked(
    mm: &Mm,
    ptep: Pte<'_>,
    pte: u64,
    addr: u64,
    area: &Area,
    spare: &mut Option<u64>,
) -> Result<(), VmFault> {
    let t = ptep.lock();
    if t.get(addr) != pte {
        return Ok(()); // changed meanwhile: the access is retried
    }
    // This mapping's own page, writable only if the mapping is (a
    // forced remote write into a read-only one: Linux maybe_mkwrite)
    let own = |e: u64| {
        if area.prot & PROT_WRITE != 0 {
            paging::pte_mkwrite(e)
        } else {
            paging::pte_wrprotect(paging::pte_mkwrite(e))
        }
    };
    let old = paging::pte_addr(pte);
    if !area.shared && FRAME_ALLOCATOR.refcount(old) > 1 {
        reuse_swap_page(old);
    }
    // The mapping's own page, pinned or not, is reused in place (Linux
    // wp_can_reuse_anon_folio, PageAnonExclusive)
    let excl = !area.shared && is_exclusive(old);
    if area.shared || excl || FRAME_ALLOCATOR.refcount(old) <= 1 {
        if t.set(addr, pte, own(pte)) {
            if !area.shared {
                set_exclusive(old);
            }
            flush_tlb_page(mm, addr);
            increment_min_flt();
        }
        return Ok(());
    }
    let new = spare.take().or_else(alloc_user).ok_or(VmFault::Retry)?;
    // `old` stays mapped (and referenced) until the PTE is switched
    // SAFETY: the new frame is ours; `old` stays mapped and referenced
    unsafe { super::page::copy_page(new, old) };
    paging::sync_page(new, paging::pte_exec(pte));
    let entry = own((pte & !paging::PTE_ADDR_MASK) | new);
    if !replace_pte(mm, &t, addr, pte, entry) {
        FRAME_ALLOCATOR.free(new);
        return Ok(());
    }
    if area.anon_private() {
        add_anon(new, area, addr);
    }
    if !area.shared {
        set_exclusive(new);
    }
    super::memory::put_page(old);
    increment_min_flt();
    Ok(())
}

/// A write fault on a swap-cache page: drop it from the cache if no
/// swap PTE needs its slot (Linux wp_can_reuse_anon_folio), so the
/// page may be reused in place. PTE lock held: trylock only.
fn reuse_swap_page(phys: u64) {
    let cached = super::page::phys_to_page(phys).is_some_and(|p| p.is_swapcache());
    if cached && super::page::trylock_page(phys) {
        super::swap_state::try_free_swap(phys);
        super::page::unlock_page(phys);
    }
}

/// A user-mode fault found no memory (Linux pagefault_out_of_memory).
/// hk has no OOM killer to choose a victim: the faulting process is the
/// one killed, as the OOM killer would kill it (SIGKILL to every
/// thread, logged like oom_kill_process), so the fault is never retried
/// in a loop and the kernel keeps its reserve. Interrupts enabled.
pub fn pagefault_out_of_memory() -> ! {
    use crate::signal::SIGKILL;

    let me = crate::task::percpu::current();
    let (pid, name) = (me.pid, me.comm());
    let len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    let exe = crate::task::percpu::current()
        .mm()
        .and_then(|mm| mm.mmap_read().exe())
        .map(|p| p.dentry.name());
    let comm: &[u8] = match &name[..len] {
        n if !n.is_empty() => n,
        _ => exe.as_deref().unwrap_or(b"?"),
    };
    let comm = crate::fs::name::Escaped(comm);
    crate::printkln!("Out of memory: Killed process {} ({})", pid, comm);
    crate::signal::do_group_exit(i32::from(SIGKILL))
}

/// Before a write into another process's private page by the kernel
/// (ptrace POKEDATA, process_vm_writev; Linux FOLL_WRITE): give it its
/// own copy if it is still shared copy-on-write, so the write cannot
/// reach the process it is shared with. The caller checked that the
/// VMA is private (writable, or the write is forced: ptrace), and holds
/// the target's mm lock (`t` borrows it); the copy gets the VMA's
/// `prot` and joins its rmap (`anon_vma`) like a write fault's copy.
pub fn unshare_for_write(
    mm: &Mm,
    t: PgTables<'_>,
    addr: u64,
    anon_vma: Option<Arc<AnonVma>>,
    index: u64,
    prot: u32,
) -> Result<(), VmFault> {
    // Never a kernel-half address (shared kernel tables)
    if addr >= super::TASK_SIZE {
        return Err(VmFault::Segv);
    }
    let Some(ptep) = t.pte(addr) else {
        return Ok(()); // not mapped, or a 2MB page (never shared)
    };
    let pte = ptep.get();
    // A PROT_NONE entry keeps its frame: a forced write copies it too
    // (Linux FOLL_FORCE follows protnone), and the copy stays PROT_NONE
    let mapped = paging::pte_present(pte) || paging::pte_protnone(pte);
    if !mapped || paging::pte_write(pte) {
        return Ok(());
    }
    let page = addr & !(PAGE_SIZE - 1);
    // The copy keeps the mapping's protection: a forced write into a
    // read-only mapping leaves it read-only to the task (Linux
    // maybe_mkwrite: writable only with VM_WRITE)
    let area = Area {
        start: page,
        end: page + PAGE_SIZE,
        prot,
        anon: anon_vma.is_some(),
        pgoff: index,
        anon_vma,
        ..Default::default()
    };
    do_wp_page(mm, ptep, pte, addr, &area)
}
