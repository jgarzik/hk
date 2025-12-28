//! Remote process memory access
//!
//! Provides infrastructure for accessing another process's virtual memory,
//! used by process_vm_readv/process_vm_writev syscalls.

use crate::error::KernelError;
use crate::mm::MmStruct;
use crate::mm::vma::{PROT_READ, PROT_WRITE};

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

/// Read from a remote process's memory into a kernel buffer
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
    if buf.is_empty() {
        return Ok(0);
    }

    let mut total_read = 0usize;
    let mut current_addr = remote_addr;
    let mut remaining = buf.len();

    while remaining > 0 {
        // Check VMA if present (for permission checking)
        // Note: Some mappings (like initial stack) may not have VMAs,
        // so we only check permissions if a VMA exists
        if let Some(vma) = mm.find_vma(current_addr)
            && vma.prot & PROT_READ == 0
        {
            if total_read > 0 {
                return Ok(total_read);
            }
            return Err(KernelError::NotPermitted);
        }

        // Read page by page using page table translation
        let bytes_read = read_pages(page_table_root, current_addr, &mut buf[total_read..])?;

        if bytes_read == 0 {
            // Page not mapped - stop
            if total_read > 0 {
                return Ok(total_read);
            }
            return Err(KernelError::BadAddress);
        }

        total_read += bytes_read;
        current_addr += bytes_read as u64;
        remaining -= bytes_read;
    }

    Ok(total_read)
}

/// Write from a kernel buffer to a remote process's memory
///
/// # Arguments
/// * `mm` - The target process's memory descriptor (locked)
/// * `page_table_root` - Physical address of the target's page table root
/// * `remote_addr` - Virtual address in the target's address space
/// * `buf` - Kernel buffer to write from
///
/// # Returns
/// Number of bytes written, or error
pub fn access_remote_vm_write(
    mm: &MmStruct,
    page_table_root: u64,
    remote_addr: u64,
    buf: &[u8],
) -> Result<usize, KernelError> {
    if buf.is_empty() {
        return Ok(0);
    }

    let mut total_written = 0usize;
    let mut current_addr = remote_addr;
    let mut remaining = buf.len();

    while remaining > 0 {
        // Check VMA if present (for permission checking)
        // Note: Some mappings (like initial stack) may not have VMAs,
        // so we only check permissions if a VMA exists
        if let Some(vma) = mm.find_vma(current_addr)
            && vma.prot & PROT_WRITE == 0
        {
            if total_written > 0 {
                return Ok(total_written);
            }
            return Err(KernelError::NotPermitted);
        }

        // Write page by page using page table translation
        let bytes_written = write_pages(page_table_root, current_addr, &buf[total_written..])?;

        if bytes_written == 0 {
            if total_written > 0 {
                return Ok(total_written);
            }
            return Err(KernelError::BadAddress);
        }

        total_written += bytes_written;
        current_addr += bytes_written as u64;
        remaining -= bytes_written;
    }

    Ok(total_written)
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

        total += to_copy;
        addr += to_copy as u64;
        remaining -= to_copy;
    }

    Ok(total)
}
