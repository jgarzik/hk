//! Remote process memory access (Linux access_remote_vm,
//! get_user_pages_remote)
//!
//! For process_vm_readv/writev (no force) and ptrace / /proc (force,
//! Linux FOLL_FORCE). Each page is reached under the target's mmap_lock
//! (read), taken here per page; a page not present is faulted in with
//! the lock released, then retried, until a fatal signal (EINTR). As
//! Linux check_vma_flags: without force a non-readable or non-writable
//! mapping is EFAULT; with force a read reaches any mapping and a write
//! only a private (copy-on-write) one, whose page is then copied and
//! stays read-only to the target if its mapping is.

use core::sync::atomic::Ordering;

use crate::arch::paging;
use crate::mm::ptl::{pt_lock, pte_lock};
use crate::mm::vma::{PROT_READ, PROT_WRITE};
use crate::mm::{Mm, MmStruct, Vma};
use crate::util::error::KernelError;

#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::paging::{X86_64PageTable, phys_to_virt};

#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::paging::{Aarch64PageTable, phys_to_virt};

/// Page size constant
const PAGE_SIZE: u64 = 4096;

/// Translate virtual address to physical using another process's page table
#[cfg(target_arch = "x86_64")]
fn translate_with_root(page_table_root: u64, va: u64) -> Option<u64> {
    X86_64PageTable::translate_with_root(page_table_root, va)
}

#[cfg(target_arch = "aarch64")]
fn translate_with_root(page_table_root: u64, va: u64) -> Option<u64> {
    Aarch64PageTable::translate_with_root(page_table_root, va)
}

/// The VMA of `addr` in the target, if it may be accessed (Linux
/// check_vma_flags): a user address with a VMA; without `force` the VMA
/// must allow the access; a forced write needs a private mapping
fn remote_vma(mm: &MmStruct, addr: u64, write: bool, force: bool) -> Result<&Vma, KernelError> {
    if addr >= crate::mm::TASK_SIZE {
        return Err(KernelError::BadAddress);
    }
    let vma = mm.find_vma(addr).ok_or(KernelError::BadAddress)?;
    let ok = if write {
        vma.prot & PROT_WRITE != 0 || (force && !vma.is_shared())
    } else {
        vma.prot & PROT_READ != 0 || force
    };
    if ok {
        Ok(vma)
    } else {
        Err(KernelError::BadAddress)
    }
}

/// Fault page `addr` of `target` in, the mmap_lock not held (it takes
/// it); EFAULT if it cannot be, EINTR on a fatal signal
fn fault_in(target: &Mm, addr: u64, write: bool) -> Result<(), KernelError> {
    use crate::mm::fault::{Access, handle_mm_fault};
    if crate::signal::fatal_signal_pending() {
        return Err(KernelError::Interrupted);
    }
    let access = if write { Access::Write } else { Access::Read };
    handle_mm_fault(target, addr, access).map_err(|_| KernelError::BadAddress)
}

/// `phys` is in a frame of the allocator (a 4KB page, or a 2MB page by
/// its head), not MMIO or other memory outside it
fn ordinary(phys: u64) -> bool {
    let fa = &crate::FRAME_ALLOCATOR;
    fa.refcount(phys & !(PAGE_SIZE - 1)) > 0 || fa.refcount_huge(phys & !((2 << 20) - 1)) > 0
}

/// Bytes from `addr` to the end of its page, at most `n`
fn page_chunk(addr: u64, n: usize) -> usize {
    n.min((PAGE_SIZE - (addr & (PAGE_SIZE - 1))) as usize)
}

/// What a remote access returns after `done` bytes when page `e` fails:
/// the short count, or the error if nothing was done
fn short(done: usize, e: KernelError) -> Result<usize, KernelError> {
    if done > 0 { Ok(done) } else { Err(e) }
}

/// Read `buf.len()` bytes at `remote_addr` of `target` (Linux
/// access_remote_vm, FOLL_FORCE with `force`): the bytes read, short at
/// the first page that cannot be, else its error
pub fn access_remote_vm_read(
    target: &Mm,
    remote_addr: u64,
    buf: &mut [u8],
    force: bool,
) -> Result<usize, KernelError> {
    if remote_addr.checked_add(buf.len() as u64).is_none() {
        return Err(KernelError::BadAddress);
    }
    let mut done = 0usize;
    while done < buf.len() {
        let addr = remote_addr + done as u64;
        let chunk = page_chunk(addr, buf.len() - done);
        let n = {
            let map = target.mmap_read();
            if let Err(e) = remote_vma(&map, addr, false, force) {
                return short(done, e);
            }
            read_pages(target, addr, &mut buf[done..done + chunk])?
        };
        if n == 0 {
            // Not present: fault it in and retry
            if let Err(e) = fault_in(target, addr, false) {
                return short(done, e);
            }
            continue;
        }
        done += n;
    }
    Ok(done)
}

/// Write `buf` at `remote_addr` of `target` (Linux access_remote_vm with
/// FOLL_WRITE, FOLL_FORCE with `force`), into ordinary frames only
/// (never MMIO: Linux refuses VM_IO/VM_PFNMAP)
pub fn access_remote_vm_write(
    target: &Mm,
    remote_addr: u64,
    buf: &[u8],
    force: bool,
) -> Result<usize, KernelError> {
    if remote_addr.checked_add(buf.len() as u64).is_none() {
        return Err(KernelError::BadAddress);
    }
    let mut done = 0usize;
    while done < buf.len() {
        let addr = remote_addr + done as u64;
        let chunk = page_chunk(addr, buf.len() - done);
        let (r, writable) = {
            let map = target.mmap_read();
            let vma = match remote_vma(&map, addr, true, force) {
                Ok(v) => v,
                Err(e) => return short(done, e),
            };
            let r = write_page(target, vma, addr, &buf[done..done + chunk]);
            (r, vma.prot & PROT_WRITE != 0)
        };
        match r {
            Ok(Wrote::Done(n)) => done += n,
            // Not present: a read fault brings in the page a forced
            // write then copies
            Ok(Wrote::Absent) => {
                if let Err(e) = fault_in(target, addr, writable) {
                    return short(done, e);
                }
            }
            // A racing fault left a shared page: copy again
            Ok(Wrote::Shared) => {
                if crate::signal::fatal_signal_pending() {
                    return short(done, KernelError::Interrupted);
                }
            }
            Err(e) => return short(done, e),
        }
    }
    Ok(done)
}

/// Run `f` on the physical address `addr` maps to in `mm` (None if
/// unmapped), with the page-table lock of its entry held, so a racing
/// zap (MADV_DONTNEED) or copy-on-write break cannot free the frame
/// while `f` copies through it
fn with_frame<R>(mm: &Mm, addr: u64, f: impl FnOnce(u64) -> R) -> Option<R> {
    let pgd = mm.pgd();
    loop {
        if let Some(p) = paging::pte_ptr(pgd, addr) {
            let _l = pte_lock(p);
            return translate_with_root(pgd, addr).map(f);
        }
        // No 4KB table: a 2MB page or nothing, both stable under the
        // page_table_lock unless a split installed a table meanwhile
        let _l = pt_lock(mm);
        if paging::pte_ptr(pgd, addr).is_none() {
            return translate_with_root(pgd, addr).map(f);
        }
    }
}

/// Copy the start of page `addr` into `buf` (within one page); the
/// bytes read, 0 if not mapped
fn read_pages(mm: &Mm, addr: u64, buf: &mut [u8]) -> Result<usize, KernelError> {
    let n = buf.len();
    Ok(with_frame(mm, addr, |phys| {
        // SAFETY: a mapped frame, kept by the held page-table lock
        unsafe { core::ptr::copy_nonoverlapping(phys_to_virt(phys), buf.as_mut_ptr(), n) };
        n
    })
    .unwrap_or(0))
}

/// What one page write did
enum Wrote {
    /// Bytes written
    Done(usize),
    /// No page mapped there: fault it in
    Absent,
    /// The private page is not yet this mapping's own: copy again
    Shared,
}

/// Write `buf` to page `addr` (within one page) of `vma` in `mm`. A
/// private page still shared copy-on-write gets its own copy first
/// (read-only if the mapping is), and the write happens only if, under
/// the PTE lock that keeps the frame, the entry still maps a page this
/// mapping alone owns (Linux can_follow_write_pte, after CVE-2016-5195):
/// a racing MADV_DONTNEED or fault may have put another page there,
/// which is never written through. A frame outside the allocator
/// (MMIO) is EFAULT.
fn write_page(mm: &Mm, vma: &Vma, addr: u64, buf: &[u8]) -> Result<Wrote, KernelError> {
    if !vma.is_shared() {
        crate::mm::fault::unshare_for_write(
            mm,
            addr,
            vma.anon_vma.clone(),
            vma.index_of(addr),
            vma.prot,
        )
        .map_err(|_| KernelError::OutOfMemory)?;
    }
    write_frame(mm, addr, buf, !vma.is_shared())
}

/// A private 4KB entry `pte` maps a page this mapping alone owns:
/// writable, or neither copy-on-write nor referenced elsewhere
fn exclusive(pte: u64) -> bool {
    paging::pte_present(pte)
        && !paging::pte_protnone(pte)
        && (paging::pte_write(pte)
            || (!paging::pte_cow(pte)
                && crate::FRAME_ALLOCATOR.refcount(paging::pte_addr(pte)) == 1))
}

/// Copy `buf` to page `addr` under the entry's page-table lock; with
/// `private`, only if the 4KB entry is `exclusive` (a 2MB page is never
/// shared)
fn write_frame(mm: &Mm, addr: u64, buf: &[u8], private: bool) -> Result<Wrote, KernelError> {
    let pgd = mm.pgd();
    if private && let Some(p) = paging::pte_ptr(pgd, addr) {
        let _l = pte_lock(p);
        // SAFETY: `p` points into a live table; its lock is held
        let pte = unsafe { core::sync::atomic::AtomicU64::from_ptr(p) }.load(Ordering::Acquire);
        if !paging::pte_present(pte) {
            return Ok(Wrote::Absent);
        }
        if !exclusive(pte) {
            return Ok(Wrote::Shared);
        }
        return match translate_with_root(pgd, addr) {
            Some(phys) => copy_to_frame(phys, buf),
            None => Ok(Wrote::Absent),
        };
    }
    with_frame(mm, addr, |phys| copy_to_frame(phys, buf)).unwrap_or(Ok(Wrote::Absent))
}

/// Copy `buf` into the frame at `phys`: an ordinary frame only (Linux
/// refuses VM_IO/VM_PFNMAP: EFAULT)
fn copy_to_frame(phys: u64, buf: &[u8]) -> Result<Wrote, KernelError> {
    if !ordinary(phys) {
        return Err(KernelError::BadAddress);
    }
    let n = buf.len();
    // SAFETY: a mapped frame, kept by the held page-table lock
    unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), phys_to_virt(phys), n) };
    // It may be code (ptrace POKETEXT; Linux flush_ptrace_access)
    crate::arch::paging::sync_icache(phys, n);
    Ok(Wrote::Done(n))
}
