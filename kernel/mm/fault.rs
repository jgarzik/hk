//! User page faults (Linux mm/memory.c handle_mm_fault)
//!
//! The arch trap handlers decode a fault (address, access, user or
//! kernel mode) and call [`handle_mm_fault`]; its error says what the
//! access earns (Linux VM_FAULT_SIGSEGV / VM_FAULT_SIGBUS /
//! VM_FAULT_OOM). Page tables are read and changed through the
//! `arch::paging` PTE helpers (`pte_alloc`, `mk_pte`, `pte_mkwrite`, ...).
//!
//! The VMA is looked up under the mm lock, which is dropped before
//! pages are allocated or read (doc/LOCKING.md, Address Spaces): a PTE
//! is installed with a compare and swap against the value the fault
//! saw, so a racing fault on the same page wins once and the loser
//! drops its page (Linux pte_same under the page table lock).

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use super::anon_vma::AnonVma;
use super::huge_page::HUGE_PAGE_SIZE;
use super::{Mm, PAGE_SIZE, PROT_EXEC, PROT_READ, PROT_WRITE, SwapEntry};
use crate::FRAME_ALLOCATOR;
use crate::arch::{CurrentArch, PageFlags, SchedArch, paging, phys_to_virt};
use crate::fs::File;
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
    file: Option<Arc<File>>,
    anon_vma: Option<Arc<AnonVma>>,
}

impl Area {
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

/// Find the VMA of `addr` (growing a stack down to it, Linux
/// expand_stack) and check the access
fn find_area(mm: &Mm, addr: u64, access: Access) -> Result<Area, VmFault> {
    let mut map = mm.lock();
    let idx = match map.find_vma_index(addr) {
        Some(i) => i,
        None => {
            let i = map.find_expandable_vma(addr).ok_or(VmFault::Segv)?;
            map.expand_downwards(i, addr).map_err(|_| VmFault::Segv)?;
            i
        }
    };
    let vma = map.get_vma(idx).ok_or(VmFault::Segv)?;
    if !access_ok(vma.prot, access) {
        return Err(VmFault::Segv);
    }
    Ok(Area {
        start: vma.start,
        end: vma.end,
        prot: vma.prot,
        shared: vma.is_shared(),
        anon: vma.is_anonymous(),
        thp: vma.is_thp_eligible(),
        offset: vma.offset,
        file: vma.file.clone(),
        anon_vma: vma.anon_vma.clone(),
    })
}

/// A frame for user data, unless free memory is down to the reserve
/// kept for the kernel (Linux: user allocations stop at the min
/// watermark; page tables, stacks and DMA buffers may still dip below)
fn alloc_user() -> Option<u64> {
    if FRAME_ALLOCATOR.below_reserve() {
        return None;
    }
    FRAME_ALLOCATOR.alloc()
}

/// Install `new` in the leaf entry at `ptep` if it still holds `old`
fn set_pte(ptep: *mut u64, old: u64, new: u64) -> bool {
    // SAFETY: `ptep` points into a live page table of the faulting mm
    let pte = unsafe { AtomicU64::from_ptr(ptep) };
    pte.compare_exchange(old, new, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

/// Read the entry at `ptep`
fn get_pte(ptep: *mut u64) -> u64 {
    // SAFETY: as in `set_pte`
    unsafe { AtomicU64::from_ptr(ptep) }.load(Ordering::Acquire)
}

/// A new anonymous page at `addr` joins the rmap and LRU
fn add_anon(phys: u64, area: &Area, addr: u64) {
    if let Some(av) = &area.anon_vma {
        super::rmap::page_add_anon_rmap(phys, av, addr & !(PAGE_SIZE - 1));
    }
    super::lru::lru_add_new(phys);
}

/// Resolve a fault at `addr` of the address space `mm` (the current
/// task's, or one it is pinned to)
pub fn handle_mm_fault(mm: &Mm, addr: u64, access: Access) -> Result<(), VmFault> {
    let area = find_area(mm, addr, access)?;
    let pgd = mm.pgd();
    if let Some(r) = huge_fault(pgd, addr, &area, access) {
        return r;
    }
    let Some(ptep) = paging::pte_alloc(pgd, addr) else {
        // A huge page mapped meanwhile: the access is retried
        return match paging::pmd_ptr(pgd, addr).map(get_pte) {
            Some(pmd) if paging::pmd_huge(pmd) => Ok(()),
            _ => Err(VmFault::Oom),
        };
    };
    let pte = get_pte(ptep);
    if !paging::pte_present(pte) {
        if SwapEntry::is_swap_pte(pte) {
            return do_swap_page(ptep, pte, addr, &area);
        }
        return do_fault(ptep, pte, addr, &area);
    }
    if access == Access::Write && !paging::pte_write(pte) {
        return do_wp_page(ptep, pte, addr, &area);
    }
    if access == Access::Exec && !paging::pte_exec(pte) {
        return Err(VmFault::Segv);
    }
    // Spurious: another CPU resolved it, or a stale TLB entry
    paging::flush_tlb(addr);
    Ok(())
}

/// A fault in a 2MB region: None to continue at the 4KB level
fn huge_fault(pgd: u64, addr: u64, area: &Area, access: Access) -> Option<Result<(), VmFault>> {
    let pmd = get_pte(paging::pmd_ptr(pgd, addr)?);
    if paging::pmd_huge(pmd) {
        if access == Access::Write && !paging::pte_write(pmd) {
            // Write-protected huge page: split, then fault on the 4KB page
            let base = addr & !(HUGE_PAGE_SIZE - 1);
            let fa = &mut &FRAME_ALLOCATOR;
            if ArchPageTable::split_huge_page(pgd, base, fa).is_err() {
                return Some(Err(VmFault::Oom));
            }
            return None;
        }
        if access == Access::Exec && !paging::pte_exec(pmd) {
            return Some(Err(VmFault::Segv));
        }
        paging::flush_tlb(addr);
        return Some(Ok(()));
    }
    if pmd == 0 && area.thp {
        return do_huge_anon(pgd, addr, area).then_some(Ok(()));
    }
    None
}

/// Map a zeroed 2MB page for a THP-eligible area if it covers the whole
/// aligned 2MB around `addr` (Linux do_huge_pmd_anonymous_page); false
/// to fall back to a 4KB page
fn do_huge_anon(pgd: u64, addr: u64, area: &Area) -> bool {
    let base = addr & !(HUGE_PAGE_SIZE - 1);
    if base < area.start || base + HUGE_PAGE_SIZE > area.end || FRAME_ALLOCATOR.below_reserve() {
        return false;
    }
    let Some(frame) = FRAME_ALLOCATOR.alloc_huge() else {
        return false;
    };
    // SAFETY: a fresh 2MB frame, reached through the direct map
    unsafe { core::ptr::write_bytes(phys_to_virt(frame), 0, HUGE_PAGE_SIZE as usize) };
    let mut flags = PageFlags::READ | PageFlags::USER;
    if area.prot & PROT_WRITE != 0 {
        flags |= PageFlags::WRITE;
    }
    if area.prot & PROT_EXEC != 0 {
        flags |= PageFlags::EXECUTE;
    }
    // Fails if a racing fault installed a table or a page first
    if ArchPageTable::map_huge_page(pgd, base, frame, flags, &mut &FRAME_ALLOCATOR).is_err() {
        FRAME_ALLOCATOR.free_huge(frame);
        return false;
    }
    add_anon(frame, area, base);
    increment_min_flt();
    true
}

/// The page to map at `addr` of a VMA with no page there yet, with a
/// reference for the new PTE: zeroed for anonymous memory, a private
/// copy of the file data otherwise (Linux do_anonymous_page,
/// do_read_fault)
fn fault_page(addr: u64, area: &Area) -> Result<u64, VmFault> {
    let frame = alloc_user().ok_or(VmFault::Oom)?;
    // SAFETY: a fresh frame, reached through the direct map
    let buf = unsafe { core::slice::from_raw_parts_mut(phys_to_virt(frame), PAGE_SIZE as usize) };
    buf.fill(0);
    if let (false, Some(f)) = (area.anon, &area.file) {
        // A short read (EOF, error) leaves the rest zero
        let _ = f.pread(buf, area.pgoff(addr));
        paging::sync_page(frame, area.prot & PROT_EXEC != 0);
    }
    Ok(frame)
}

/// Map the first page at `addr` (the entry holds `old`: none)
fn do_fault(ptep: *mut u64, old: u64, addr: u64, area: &Area) -> Result<(), VmFault> {
    let page = fault_page(addr, area)?;
    if !set_pte(ptep, old, paging::mk_pte(page, area.prot)) {
        // A racing fault mapped the page first
        super::memory::put_page(page);
        return Ok(());
    }
    if area.anon_private() {
        add_anon(page, area, addr);
    }
    paging::flush_tlb(addr);
    increment_min_flt();
    Ok(())
}

/// Read a swapped-out page back in (Linux do_swap_page)
fn do_swap_page(ptep: *mut u64, pte: u64, addr: u64, area: &Area) -> Result<(), VmFault> {
    let entry = SwapEntry::from_pte(pte);
    if let Some(cached) = super::swap_cache_lookup(entry) {
        // The PTE takes its own reference on the swap-cache page
        FRAME_ALLOCATOR.incref(cached.frame);
        if !set_pte(ptep, pte, paging::mk_pte(cached.frame, area.prot)) {
            FRAME_ALLOCATOR.decref(cached.frame);
            return Ok(());
        }
        paging::flush_tlb(addr);
        increment_maj_flt();
        return Ok(());
    }
    let frame = alloc_user().ok_or(VmFault::Oom)?;
    if super::swap_read_page(entry, frame).is_err() {
        FRAME_ALLOCATOR.free(frame);
        return Err(VmFault::Bus);
    }
    paging::sync_page(frame, area.prot & PROT_EXEC != 0);
    if !set_pte(ptep, pte, paging::mk_pte(frame, area.prot)) {
        FRAME_ALLOCATOR.free(frame);
        return Ok(());
    }
    paging::flush_tlb(addr);
    super::free_swap_entry(entry);
    if area.anon_private() {
        add_anon(frame, area, addr);
    }
    increment_maj_flt();
    Ok(())
}

/// A write to a present read-only page of a writable VMA (Linux
/// do_wp_page): a shared mapping, or a private page no one else maps,
/// is made writable in place; a private page still shared (fork's
/// copy-on-write) is copied first
fn do_wp_page(ptep: *mut u64, pte: u64, addr: u64, area: &Area) -> Result<(), VmFault> {
    let old = paging::pte_addr(pte);
    if area.shared || FRAME_ALLOCATOR.refcount(old) <= 1 {
        if set_pte(ptep, pte, paging::pte_mkwrite(pte)) {
            paging::flush_tlb(addr);
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
    if !set_pte(ptep, pte, entry) {
        FRAME_ALLOCATOR.free(new);
        return Ok(());
    }
    paging::flush_tlb(addr);
    if area.anon_private() {
        add_anon(new, area, addr);
    }
    super::rmap::page_remove_rmap(old);
    FRAME_ALLOCATOR.decref(old);
    increment_min_flt();
    Ok(())
}

/// A user-mode fault found no memory (Linux pagefault_out_of_memory).
/// hk has no OOM killer to choose a victim: the faulting process is the
/// one killed, as the OOM killer would kill it (SIGKILL to every
/// thread, logged like oom_kill_process), so the fault is never retried
/// in a loop and the kernel keeps its reserve. Interrupts enabled.
pub fn pagefault_out_of_memory() -> ! {
    use crate::signal::{SIGKILL, send_signal};
    use crate::task::percpu::{TASK_TABLE, current_tid};

    let tid = current_tid();
    let (pid, name, threads) = {
        let table = TASK_TABLE.lock();
        let me = table.tasks.iter().find(|t| t.tid == tid);
        let pid = me.map_or(0, |t| t.pid);
        let name = me.map_or([0; 16], |t| t.prctl.name);
        let threads: alloc::vec::Vec<_> = table
            .tasks
            .iter()
            .filter(|t| t.pid == pid && t.tid != tid)
            .map(|t| t.tid)
            .collect();
        (pid, name, threads)
    };
    let len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    let exe = super::get_task_mm(tid).and_then(|mm| mm.lock().exe());
    let comm = match core::str::from_utf8(&name[..len]) {
        Ok(n) if !n.is_empty() => n,
        _ => exe
            .as_deref()
            .and_then(|p| p.rsplit('/').next())
            .unwrap_or("?"),
    };
    crate::printkln!("Out of memory: Killed process {} ({})", pid, comm);
    for t in threads {
        send_signal(t, SIGKILL);
    }
    crate::task::proc::do_exit(SIGKILL as i32)
}
