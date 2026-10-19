//! Remote process memory access
//!
//! Provides infrastructure for accessing another process's virtual memory,
//! used by process_vm_readv/process_vm_writev syscalls.

use core::sync::atomic::Ordering;

use crate::arch::paging;
use crate::error::KernelError;
use crate::mm::ptl::{pt_lock, pte_lock};
use crate::mm::vma::{PROT_READ, PROT_WRITE};
use crate::mm::{Mm, MmStruct, Vma};

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

/// The VMA of `addr` in the target, which must allow `prot` (Linux
/// access_remote_vm / get_user_pages_remote): a user address with a
/// VMA, else EFAULT; no read or write permission: EPERM
fn remote_vma(mm: &MmStruct, addr: u64, prot: u32) -> Result<&Vma, KernelError> {
    if addr >= crate::mm::TASK_SIZE {
        return Err(KernelError::BadAddress);
    }
    let vma = mm.find_vma(addr).ok_or(KernelError::BadAddress)?;
    if vma.prot & prot == 0 {
        return Err(KernelError::NotPermitted);
    }
    Ok(vma)
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

/// Read from a remote process's memory into a kernel buffer, page by
/// page, each in a readable VMA of the user half
///
/// # Arguments
/// * `target` - The target process's address space
/// * `mm` - Its VMAs (`target`'s mmap_lock held, for reading is enough)
/// * `remote_addr` - Virtual address in the target's address space
/// * `buf` - Kernel buffer to read into
///
/// # Returns
/// Number of bytes read, or error
pub fn access_remote_vm_read(
    target: &Mm,
    mm: &MmStruct,
    remote_addr: u64,
    buf: &mut [u8],
) -> Result<usize, KernelError> {
    if remote_addr.checked_add(buf.len() as u64).is_none() {
        return Err(KernelError::BadAddress);
    }
    let mut done = 0usize;
    while done < buf.len() {
        let addr = remote_addr + done as u64;
        if let Err(e) = remote_vma(mm, addr, PROT_READ) {
            return short(done, e);
        }
        let chunk = page_chunk(addr, buf.len() - done);
        let n = read_pages(target, addr, &mut buf[done..done + chunk])?;
        if n == 0 {
            // Not faulted in
            return short(done, KernelError::BadAddress);
        }
        done += n;
    }
    Ok(done)
}

/// Write from a kernel buffer to a remote process's memory, page by
/// page, each in a writable VMA of the user half and backed by an
/// ordinary frame (never MMIO: Linux refuses VM_IO/VM_PFNMAP)
///
/// # Arguments
/// * `target` - The target process's address space
/// * `mm` - Its VMAs (`target`'s mmap_lock held, for reading is enough)
/// * `remote_addr` - Virtual address in the target's address space
/// * `buf` - Kernel buffer to write from
///
/// # Returns
/// Number of bytes written, or error
pub fn access_remote_vm_write(
    target: &Mm,
    mm: &MmStruct,
    remote_addr: u64,
    buf: &[u8],
) -> Result<usize, KernelError> {
    if remote_addr.checked_add(buf.len() as u64).is_none() {
        return Err(KernelError::BadAddress);
    }
    let mut done = 0usize;
    while done < buf.len() {
        let addr = remote_addr + done as u64;
        let vma = match remote_vma(mm, addr, PROT_WRITE) {
            Ok(v) => v,
            Err(e) => return short(done, e),
        };
        let chunk = page_chunk(addr, buf.len() - done);
        let n = match write_page(target, vma, addr, &buf[done..done + chunk]) {
            Ok(0) => return short(done, KernelError::BadAddress),
            Ok(n) => n,
            Err(e) => return short(done, e),
        };
        done += n;
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

/// Tries at a private page before giving up (each lost to a racing
/// zap or fault that left a page the write may not reach)
const COW_TRIES: u32 = 16;

/// Write `buf` to page `addr` (within one page) of `vma` in `mm`; the
/// bytes written, 0 if no ordinary frame maps it. A private page still
/// shared copy-on-write gets its own copy first, and the write happens
/// only if, under the PTE lock that keeps the frame, the entry still
/// maps a page this mapping alone owns (Linux can_follow_write_pte,
/// after CVE-2016-5195): a racing MADV_DONTNEED or fault may have put
/// another page there, which is never written through; the copy is
/// then broken again.
fn write_page(mm: &Mm, vma: &Vma, addr: u64, buf: &[u8]) -> Result<usize, KernelError> {
    if vma.is_shared() {
        return Ok(write_frame(mm, addr, buf, false).unwrap_or(0));
    }
    for _ in 0..COW_TRIES {
        crate::mm::fault::unshare_for_write(mm, addr, vma.anon_vma.clone(), vma.index_of(addr))
            .map_err(|_| KernelError::OutOfMemory)?;
        match write_frame(mm, addr, buf, true) {
            Some(n) => return Ok(n),
            None if paging::pte_ptr(mm.pgd(), addr).is_none_or(|p| !present(p)) => return Ok(0),
            None => {}
        }
    }
    Err(KernelError::BadAddress)
}

/// The entry at `p` maps a page
fn present(p: *mut u64) -> bool {
    // SAFETY: `p` points into a live table of the locked mm
    paging::pte_present(
        unsafe { core::sync::atomic::AtomicU64::from_ptr(p) }.load(Ordering::Acquire),
    )
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

/// Copy `buf` to page `addr` if an ordinary frame maps it, under the
/// entry's page-table lock; with `private`, only if the 4KB entry is
/// `exclusive` (a 2MB page is never shared). Some(bytes written, 0 if
/// unmapped or not ordinary); None if a private entry is not exclusive.
fn write_frame(mm: &Mm, addr: u64, buf: &[u8], private: bool) -> Option<usize> {
    let pgd = mm.pgd();
    if private && let Some(p) = paging::pte_ptr(pgd, addr) {
        let _l = pte_lock(p);
        // SAFETY: `p` points into a live table; its lock is held
        let pte = unsafe { core::sync::atomic::AtomicU64::from_ptr(p) }.load(Ordering::Acquire);
        if !paging::pte_present(pte) {
            return Some(0);
        }
        if !exclusive(pte) {
            return None;
        }
        return Some(translate_with_root(pgd, addr).map_or(0, |phys| copy_to_frame(phys, buf)));
    }
    Some(with_frame(mm, addr, |phys| copy_to_frame(phys, buf)).unwrap_or(0))
}

/// Copy `buf` into the frame at `phys` (an ordinary frame only)
fn copy_to_frame(phys: u64, buf: &[u8]) -> usize {
    if !ordinary(phys) {
        return 0;
    }
    let n = buf.len();
    // SAFETY: a mapped frame, kept by the held page-table lock
    unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), phys_to_virt(phys), n) };
    // It may be code (ptrace POKETEXT; Linux flush_ptrace_access)
    crate::arch::paging::sync_icache(phys, n);
    n
}
