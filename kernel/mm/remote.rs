//! Remote process memory access
//!
//! Provides infrastructure for accessing another process's virtual memory,
//! used by process_vm_readv/process_vm_writev syscalls.

use crate::error::KernelError;
use crate::mm::vma::{PROT_READ, PROT_WRITE};
use crate::mm::{MmStruct, Vma};

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
/// * `mm` - The target process's memory descriptor (locked)
/// * `page_table_root` - Physical address of the target's page table root
/// * `remote_addr` - Virtual address in the target's address space
/// * `buf` - Kernel buffer to read into
///
/// # Returns
/// Number of bytes read, or error
pub fn access_remote_vm_read(
    mm: &MmStruct,
    page_table_root: u64,
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
        let n = read_pages(page_table_root, addr, &mut buf[done..done + chunk])?;
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
/// * `mm` - Its VMAs (`target` locked)
/// * `remote_addr` - Virtual address in the target's address space
/// * `buf` - Kernel buffer to write from
///
/// # Returns
/// Number of bytes written, or error
pub fn access_remote_vm_write(
    target: &crate::mm::Mm,
    mm: &MmStruct,
    remote_addr: u64,
    buf: &[u8],
) -> Result<usize, KernelError> {
    let page_table_root = target.pgd();
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
        // A private page still shared copy-on-write (fork) gets its own
        // copy first: the write must not reach the other process
        if !vma.is_shared()
            && crate::mm::fault::unshare_for_write(target, addr, vma.anon_vma.clone()).is_err()
        {
            return short(done, KernelError::OutOfMemory);
        }
        if !translate_with_root(page_table_root, addr).is_some_and(ordinary) {
            return short(done, KernelError::BadAddress);
        }
        let chunk = page_chunk(addr, buf.len() - done);
        let n = write_pages(page_table_root, addr, &buf[done..done + chunk])?;
        if n == 0 {
            return short(done, KernelError::BadAddress);
        }
        done += n;
    }
    Ok(done)
}

/// Read from pages using page table translation
fn read_pages(page_table_root: u64, start_addr: u64, buf: &mut [u8]) -> Result<usize, KernelError> {
    let mut total = 0usize;
    let mut addr = start_addr;
    let mut remaining = buf.len();

    while remaining > 0 {
        // Translate virtual to physical
        let phys = match translate_with_root(page_table_root, addr) {
            Some(p) => p,
            None => return Ok(total), // Page not mapped
        };

        // Calculate bytes to read from this page
        let page_offset = (addr & (PAGE_SIZE - 1)) as usize;
        let page_remaining = (PAGE_SIZE as usize) - page_offset;
        let to_copy = remaining.min(page_remaining);

        // Copy from physical memory
        unsafe {
            let src = phys_to_virt(phys);
            core::ptr::copy_nonoverlapping(src, buf[total..].as_mut_ptr(), to_copy);
        }

        total += to_copy;
        addr += to_copy as u64;
        remaining -= to_copy;
    }

    Ok(total)
}

/// Write to pages using page table translation
fn write_pages(page_table_root: u64, start_addr: u64, buf: &[u8]) -> Result<usize, KernelError> {
    let mut total = 0usize;
    let mut addr = start_addr;
    let mut remaining = buf.len();

    while remaining > 0 {
        // Translate virtual to physical
        let phys = match translate_with_root(page_table_root, addr) {
            Some(p) => p,
            None => return Ok(total), // Page not mapped
        };

        // Calculate bytes to write to this page
        let page_offset = (addr & (PAGE_SIZE - 1)) as usize;
        let page_remaining = (PAGE_SIZE as usize) - page_offset;
        let to_copy = remaining.min(page_remaining);

        // Copy to physical memory
        unsafe {
            let dst = phys_to_virt(phys);
            core::ptr::copy_nonoverlapping(buf[total..].as_ptr(), dst, to_copy);
        }
        // It may be code (ptrace POKETEXT; Linux flush_ptrace_access)
        crate::arch::paging::sync_icache(phys, to_copy);

        total += to_copy;
        addr += to_copy as u64;
        remaining -= to_copy;
    }

    Ok(total)
}
