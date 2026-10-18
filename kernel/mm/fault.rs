//! User page faults (Linux mm/memory.c handle_mm_fault)
//!
//! The arch trap handlers decode a fault (address, access, user or
//! kernel mode) and call [`handle_mm_fault`]; its error says what the
//! access earns (Linux VM_FAULT_SIGSEGV / VM_FAULT_SIGBUS /
//! VM_FAULT_OOM). Page tables are read and changed through the
//! `arch::paging` PTE helpers (`pte_alloc`, `mk_pte`, `pte_mkwrite`, ...).
//!
//! The fault holds the mmap_lock for reading from the VMA lookup to the
//! PTE update, I/O included (doc/LOCKING.md, Address Spaces): a PTE is
//! installed under its table's PTE lock with a compare and swap against
//! the value the fault saw, so a racing fault on the same page wins once
//! and the loser drops its page (Linux pte_same under the page table
//! lock).

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use super::anon_vma::AnonVma;
use super::huge_page::{HUGE_PAGE_SIZE, split_huge_pmd};
use super::ptl::pte_lock;
use super::shmem::Shmem;
use super::tlb::flush_tlb_page;
use super::{Mm, MmStruct, PAGE_SIZE, PROT_EXEC, PROT_READ, PROT_WRITE, SwapEntry};
use crate::FRAME_ALLOCATOR;
use crate::arch::{CurrentArch, PageFlags, SchedArch, paging, phys_to_virt};
use crate::fs::File;
use crate::mm::page_alloc::Gfp;
use crate::task::percpu::{increment_maj_flt, increment_min_flt};

type ArchPageTable = <CurrentArch as SchedArch>::SchedPageTable;

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
    shmem: Option<Arc<Shmem>>,
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
        shmem: vma.shmem.clone(),
    }
}

/// A frame for user data: none once free memory is down to the low
/// watermark (the kernel's allocations may go on to min; see
/// `page_alloc::alloc_mark`)
pub(crate) fn alloc_user() -> Option<u64> {
    FRAME_ALLOCATOR.alloc_gfp(Gfp::HIGHUSER_MOVABLE)
}

/// Install `new` in the leaf entry at `ptep` if it still holds `old`
fn set_pte(ptep: *mut u64, old: u64, new: u64) -> bool {
    // SAFETY: `ptep` points into a live page table of the faulting mm
    let pte = unsafe { AtomicU64::from_ptr(ptep) };
    pte.compare_exchange(old, new, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

/// Replace the present entry `old` at `ptep` by `new`, which maps
/// another page (Linux ptep_clear_flush + set_pte_at): the entry is
/// cleared and its TLB entry flushed before `new` is written, so no CPU
/// caches both translations at once (arm64 break-before-make). False
/// if the entry no longer holds `old`.
fn replace_pte(mm: &Mm, ptep: *mut u64, old: u64, new: u64, addr: u64) -> bool {
    if !set_pte(ptep, old, 0) {
        return false;
    }
    flush_tlb_page(mm, addr);
    // SAFETY: as in `set_pte`
    unsafe { AtomicU64::from_ptr(ptep) }.store(new, Ordering::Release);
    true
}

/// Read the entry at `ptep`
fn get_pte(ptep: *mut u64) -> u64 {
    // SAFETY: as in `set_pte`
    unsafe { AtomicU64::from_ptr(ptep) }.load(Ordering::Acquire)
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
    if let Some(r) = huge_fault(mm, addr, &area, access) {
        return r;
    }
    let ptep = leaf(mm, addr)?;
    let pte = get_pte(ptep);
    if paging::pte_protnone(pte) {
        // Only mprotect makes protnone entries, with the VMA (which
        // allows this access): restore it, read-only, and retry (a
        // write then goes through do_wp_page; write implies read)
        let prot = (area.prot & !PROT_WRITE) | PROT_READ;
        let _l = pte_lock(ptep);
        if set_pte(ptep, pte, paging::pte_modify(pte, prot)) {
            flush_tlb_page(mm, addr);
        }
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
    let page = fault_page(addr, &area)?;
    let r = do_fault(mm, ptep, pte, page, addr, &area);
    drop(map);
    r
}

/// The leaf entry for `addr`, allocating missing tables
fn leaf(mm: &Mm, addr: u64) -> Result<*mut u64, VmFault> {
    super::ptl::pte_alloc(mm, addr).ok_or_else(|| {
        // A huge page mapped there: the access is retried
        match paging::pmd_ptr(mm.pgd(), addr).map(get_pte) {
            Some(pmd) if paging::pmd_huge(pmd) => VmFault::Retry,
            _ => VmFault::Oom,
        }
    })
}

/// A fault in a 2MB region: None to continue at the 4KB level
fn huge_fault(mm: &Mm, addr: u64, area: &Area, access: Access) -> Option<Result<(), VmFault>> {
    let pmd = get_pte(paging::pmd_ptr(mm.pgd(), addr)?);
    if paging::pmd_huge(pmd) {
        if access == Access::Write && !paging::pte_write(pmd) {
            // Write-protected huge page: split, then fault on the 4KB
            // page; a racing fault may have split (or unmapped) it first
            if split_huge_pmd(mm, addr).is_none() && still_huge(mm, addr) {
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
        return do_huge_anon(mm, addr, area).then_some(Ok(()));
    }
    None
}

/// A 2MB page still maps `addr`
fn still_huge(mm: &Mm, addr: u64) -> bool {
    paging::pmd_ptr(mm.pgd(), addr).is_some_and(|p| paging::pmd_huge(get_pte(p)))
}

/// Map a zeroed 2MB page for a THP-eligible area if it covers the whole
/// aligned 2MB around `addr` (Linux do_huge_pmd_anonymous_page); false
/// to fall back to a 4KB page
fn do_huge_anon(mm: &Mm, addr: u64, area: &Area) -> bool {
    let base = addr & !(HUGE_PAGE_SIZE - 1);
    if base < area.start || base + HUGE_PAGE_SIZE > area.end {
        return false;
    }
    let Some(frame) = FRAME_ALLOCATOR.alloc_huge() else {
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
    // Fails if a racing fault installed a table or a page first
    let _l = super::ptl::pt_lock(mm);
    if ArchPageTable::map_huge_page(mm.pgd(), base, frame, flags, &mut &FRAME_ALLOCATOR).is_err() {
        FRAME_ALLOCATOR.free_huge(frame);
        return false;
    }
    add_anon(frame, area, base);
    increment_min_flt();
    true
}

/// The page to map at `addr` of a VMA with no page there yet, with a
/// reference for the new PTE: the shared object's page for shared
/// anonymous memory (Linux shmem_fault), else a new page, zeroed for
/// anonymous memory or holding a private copy of the file data (Linux
/// do_anonymous_page, do_read_fault)
fn fault_page(addr: u64, area: &Area) -> Result<u64, VmFault> {
    let exec = area.prot & PROT_EXEC != 0;
    if let Some(sh) = &area.shmem {
        return sh
            .get_page(area.pgoff(addr) / PAGE_SIZE)
            .inspect(|&f| paging::sync_page(f, exec));
    }
    if let (true, false, Some(f)) = (area.shared, area.anon, &area.file)
        && let Some(r) = file_page(f, area.pgoff(addr), area.prot & PROT_EXEC != 0)
    {
        return r;
    }
    let frame = alloc_user().ok_or(VmFault::Oom)?;
    // SAFETY: a fresh frame, reached through the direct map
    let buf = unsafe { core::slice::from_raw_parts_mut(phys_to_virt(frame), PAGE_SIZE as usize) };
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
    Ok(frame)
}

/// The page-cache page at byte offset `off` of `file`, for a shared
/// mapping of a filesystem that maps its cache (Linux filemap_fault):
/// SIGBUS past the end of the file. None: the fault copies the data.
fn file_page(file: &File, off: u64, exec: bool) -> Option<Result<u64, VmFault>> {
    use crate::error::KernelError;

    let inode = file.get_inode()?;
    if !inode.i_op.maps_cache() {
        return None;
    }
    if off >= inode.get_size().div_ceil(PAGE_SIZE) * PAGE_SIZE {
        return Some(Err(VmFault::Bus));
    }
    Some(
        inode
            .i_op
            .map_page(&inode, off / PAGE_SIZE)
            .inspect(|&f| paging::sync_page(f, exec))
            .map_err(|e| match e {
                KernelError::OutOfMemory | KernelError::NoSpace => VmFault::Oom,
                _ => VmFault::Bus,
            }),
    )
}

/// Map `page` (with its reference for the PTE) at `addr`, where the
/// entry held `old` (none)
fn do_fault(
    mm: &Mm,
    ptep: *mut u64,
    old: u64,
    page: u64,
    addr: u64,
    area: &Area,
) -> Result<(), VmFault> {
    let _l = pte_lock(ptep);
    if !set_pte(ptep, old, paging::mk_pte(page, area.prot)) {
        // A racing fault mapped the page first
        super::memory::put_page(page);
        return Ok(());
    }
    if area.anon_private() {
        add_anon(page, area, addr);
    }
    flush_tlb_page(mm, addr);
    increment_min_flt();
    Ok(())
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
    ptep: *mut u64,
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
    ptep: *mut u64,
    pte: u64,
    page: u64,
    addr: u64,
    area: &Area,
    access: Access,
) -> Result<(), VmFault> {
    let _l = pte_lock(ptep);
    if get_pte(ptep) != pte {
        FRAME_ALLOCATOR.decref(page);
        return Ok(());
    }
    super::swap::swap_free(SwapEntry::from_pte(pte));
    // Exclusive: no other swap PTE, and no reference but ours once the
    // cache lets go (Linux do_swap_page exclusive + folio_free_swap)
    let exclusive = access == Access::Write
        && super::swap_state::try_free_swap(page)
        && FRAME_ALLOCATOR.refcount(page) == 1;
    let mut entry = paging::mk_pte(page, area.prot);
    if !exclusive && !area.shared {
        entry = paging::pte_mkcow(entry);
    }
    let ok = set_pte(ptep, pte, entry);
    debug_assert!(ok, "swap PTE changed under its PTE lock");
    if let Some(av) = &area.anon_vma {
        super::rmap::page_add_anon_rmap(page, av, area.index(addr));
    }
    flush_tlb_page(mm, addr);
    increment_maj_flt();
    Ok(())
}

/// swapoff: fault in the swap PTE at `addr` of `vma` (Linux
/// unuse_pte), mm lock held for reading
pub fn unuse_pte(mm: &Mm, vma: &super::Vma, addr: u64) -> Result<(), VmFault> {
    let area = area_of(vma);
    let Some(ptep) = paging::pte_ptr(mm.pgd(), addr) else {
        return Ok(());
    };
    let pte = get_pte(ptep);
    if !SwapEntry::is_swap_pte(pte) {
        return Ok(());
    }
    do_swap_page(mm, ptep, pte, addr, &area, Access::Read)
}

/// A write to a present read-only page of a writable VMA (Linux
/// do_wp_page): a shared mapping, or a private page no one else maps,
/// is made writable in place; a private page still shared (fork's
/// copy-on-write) is copied first
fn do_wp_page(mm: &Mm, ptep: *mut u64, pte: u64, addr: u64, area: &Area) -> Result<(), VmFault> {
    let _l = pte_lock(ptep);
    if get_pte(ptep) != pte {
        return Ok(()); // changed meanwhile: the access is retried
    }
    let old = paging::pte_addr(pte);
    if !area.shared && FRAME_ALLOCATOR.refcount(old) > 1 {
        reuse_swap_page(old);
    }
    if area.shared || FRAME_ALLOCATOR.refcount(old) <= 1 {
        if set_pte(ptep, pte, paging::pte_mkwrite(pte)) {
            flush_tlb_page(mm, addr);
            increment_min_flt();
        }
        return Ok(());
    }
    let new = alloc_user().ok_or(VmFault::Oom)?;
    // SAFETY: both frames are reached through the direct map; `old`
    // stays mapped (and referenced) until the PTE is switched
    unsafe {
        core::ptr::copy_nonoverlapping(phys_to_virt(old), phys_to_virt(new), PAGE_SIZE as usize)
    };
    paging::sync_page(new, paging::pte_exec(pte));
    let entry = paging::pte_mkwrite((pte & !paging::PTE_ADDR_MASK) | new);
    if !replace_pte(mm, ptep, pte, entry, addr) {
        FRAME_ALLOCATOR.free(new);
        return Ok(());
    }
    if area.anon_private() {
        add_anon(new, area, addr);
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
    use crate::task::percpu::{TASK_TABLE, current_tid};

    let tid = current_tid();
    let (pid, name) = {
        let table = TASK_TABLE.lock();
        let me = table.tasks.iter().find(|t| t.tid == tid);
        let pid = me.map_or(0, |t| t.pid);
        let name = me.map_or([0; 16], |t| t.prctl.name);
        (pid, name)
    };
    let len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    let exe = super::get_task_mm(tid).and_then(|mm| mm.mmap_read().exe());
    let comm = match core::str::from_utf8(&name[..len]) {
        Ok(n) if !n.is_empty() => n,
        _ => exe
            .as_deref()
            .and_then(|p| p.rsplit('/').next())
            .unwrap_or("?"),
    };
    crate::printkln!("Out of memory: Killed process {} ({})", pid, comm);
    crate::signal::do_group_exit(SIGKILL as i32)
}

/// Before a write into another process's private page by the kernel
/// (ptrace POKEDATA, process_vm_writev; Linux FOLL_WRITE): give it its
/// own copy if it is still shared copy-on-write, so the write cannot
/// reach the process it is shared with. The caller checked that the
/// VMA is writable and private, and holds the target's mm lock; the new
/// page joins the VMA's rmap (`anon_vma`) like a write fault's copy.
pub fn unshare_for_write(
    mm: &Mm,
    addr: u64,
    anon_vma: Option<Arc<AnonVma>>,
    index: u64,
) -> Result<(), VmFault> {
    // Never a kernel-half address (shared kernel tables)
    if addr >= super::TASK_SIZE {
        return Err(VmFault::Segv);
    }
    let Some(ptep) = paging::pte_ptr(mm.pgd(), addr) else {
        return Ok(()); // not mapped, or a 2MB page (never shared)
    };
    let pte = get_pte(ptep);
    if !paging::pte_present(pte) || paging::pte_protnone(pte) || paging::pte_write(pte) {
        return Ok(());
    }
    let page = addr & !(PAGE_SIZE - 1);
    let area = Area {
        start: page,
        end: page + PAGE_SIZE,
        prot: PROT_READ | PROT_WRITE,
        shared: false,
        anon: anon_vma.is_some(),
        thp: false,
        offset: 0,
        pgoff: index,
        file: None,
        anon_vma,
        shmem: None,
    };
    do_wp_page(mm, ptep, pte, addr, &area)
}
