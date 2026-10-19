//! User memory access primitives
//!
//! This module provides safe primitives for copying data between kernel and user space.
//! These functions ensure proper validation of user pointers before access, preventing
//! the kernel from accidentally accessing invalid or kernel memory when handling
//! user-provided pointers.
//!
//! # Security Model
//!
//! In Linux and similar kernels, user pointers must NEVER be dereferenced directly.
//! The `copy_to_user` and `copy_from_user` functions:
//! 1. Validate the user address range is within user space bounds
//! 2. Check the pointer doesn't overflow
//! 3. On x86_64, use SMAP/SMEP protection (if available) via stac/clac instructions
//!
//! # Error Handling
//!
//! Functions return the number of bytes that could NOT be copied (0 = success),
//! following the Linux kernel convention. This allows partial copies to be detected.

extern crate alloc;

use core::sync::atomic::{AtomicU32, Ordering};

use crate::cpu::PerCpu;

/// Per-CPU page-fault-disable depth (Linux pagefault_disable)
static PF_DISABLE: PerCpu<AtomicU32> = crate::percpu![AtomicU32::new(0)];

/// Linux pagefault_disable: until `pagefault_enable`, a user access that
/// faults is not resolved (no sleeping fault-in) but fails at once
/// (EFAULT through the copy's fixup). For user reads under a spinlock
/// (futex values); the caller stays on this CPU (it holds a spinlock).
pub fn pagefault_disable() {
    PF_DISABLE.this().fetch_add(1, Ordering::Relaxed);
}

pub fn pagefault_enable() {
    PF_DISABLE.this().fetch_sub(1, Ordering::Relaxed);
}

/// Faults on user addresses must not be resolved here
pub fn pagefault_disabled() -> bool {
    PF_DISABLE.this().load(Ordering::Relaxed) != 0
}

/// Linux might_fault: a user access may sleep resolving a fault, unless
/// faults are disabled
#[track_caller]
#[inline]
fn might_fault() {
    if !pagefault_disabled() {
        crate::sync::might_sleep();
    }
}

/// Error type for user memory access failures
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UaccessError {
    /// Address is not in valid user space range
    BadAddress,
    /// Address range overflows
    Overflow,
    /// Page fault during access (would block or fail)
    Fault,
}

/// Result type for user access operations
pub type UaccessResult<T> = Result<T, UaccessError>;

/// Trait for architecture-specific user memory access
///
/// Architectures implement this trait to provide:
/// - User address space bounds checking (`access_ok`)
/// - SMAP/SMEP or equivalent protection toggling
pub trait UaccessArch {
    /// End of user space (exclusive; Linux TASK_SIZE_MAX)
    const TASK_SIZE: u64;

    /// Check if a user address range is valid
    ///
    /// True if the whole range [addr, addr+size) lies below TASK_SIZE
    /// (Linux `access_ok`: no lower bound; a pointer into an unmapped
    /// low page faults and the copy returns EFAULT).
    fn access_ok(addr: u64, size: usize) -> bool {
        addr.checked_add(size as u64)
            .is_some_and(|end| end <= Self::TASK_SIZE)
    }

    /// Enable user memory access (for SMAP-enabled CPUs)
    ///
    /// On x86_64 with SMAP, this executes `stac` to set the AC flag.
    /// Called before accessing user memory.
    ///
    /// # Safety
    /// Must be paired with `user_access_end()`. Failing to call `user_access_end()`
    /// leaves the CPU in a state where user memory access is allowed, which
    /// defeats SMAP protection.
    unsafe fn user_access_begin();

    /// Copy `len` bytes where `src` and/or `dst` is a user address.
    ///
    /// Faults on not-yet-populated user pages are resolved by the page-fault
    /// handler; an unresolvable fault is caught via the arch exception fixup.
    /// Returns the number of bytes NOT copied (0 = success).
    ///
    /// # Safety
    /// The kernel side must be valid for `len` bytes; must be called between
    /// `user_access_begin()`/`user_access_end()`.
    unsafe fn copy_user_raw(dst: *mut u8, src: *const u8, len: usize) -> usize;

    /// Disable user memory access (for SMAP-enabled CPUs)
    ///
    /// On x86_64 with SMAP, this executes `clac` to clear the AC flag.
    /// Called after accessing user memory.
    ///
    /// # Safety
    /// Must be paired with a prior `user_access_begin()` call.
    unsafe fn user_access_end();
}

/// Copy data from kernel space to user space
///
/// # Arguments
/// * `to` - User space destination address
/// * `from` - Kernel space source slice
///
/// # Returns
/// * `Ok(0)` on success (all bytes copied)
/// * `Err(UaccessError::BadAddress)` if user address is invalid
/// * `Err(UaccessError::Overflow)` if address range overflows
///
/// # Safety
/// The kernel source slice must be valid. The user destination is validated
/// by this function.
///
/// # Example
/// ```ignore
/// let data = [1u8, 2, 3, 4];
/// if copy_to_user::<X86_64Uaccess>(user_ptr, &data).is_ok() {
///     // Success
/// }
/// ```
#[track_caller]
pub fn copy_to_user<A: UaccessArch>(to: u64, from: &[u8]) -> UaccessResult<usize> {
    might_fault();
    let len = from.len();

    // Validate user address
    if !A::access_ok(to, len) {
        return Err(UaccessError::BadAddress);
    }

    // Perform the copy with SMAP protection disabled
    let left = unsafe {
        A::user_access_begin();
        let left = A::copy_user_raw(to as *mut u8, from.as_ptr(), len);
        A::user_access_end();
        left
    };

    if left != 0 {
        return Err(UaccessError::Fault);
    }
    Ok(0)
}

/// Copy data from user space to kernel space
///
/// # Arguments
/// * `to` - Kernel space destination slice (must have sufficient capacity)
/// * `from` - User space source address
/// * `len` - Number of bytes to copy
///
/// # Returns
/// * `Ok(0)` on success (all bytes copied)
/// * `Err(UaccessError::BadAddress)` if user address is invalid
/// * `Err(UaccessError::Overflow)` if address range overflows
///
/// # Safety
/// The kernel destination slice must be valid and have capacity >= len.
/// The user source is validated by this function.
#[track_caller]
pub fn copy_from_user<A: UaccessArch>(
    to: &mut [u8],
    from: u64,
    len: usize,
) -> UaccessResult<usize> {
    might_fault();
    // Validate user address
    if !A::access_ok(from, len) {
        return Err(UaccessError::BadAddress);
    }

    // Check destination has enough space
    if to.len() < len {
        return Err(UaccessError::Overflow);
    }

    // Perform the copy with SMAP protection disabled
    let left = unsafe {
        A::user_access_begin();
        let left = A::copy_user_raw(to.as_mut_ptr(), from as *const u8, len);
        A::user_access_end();
        left
    };

    if left != 0 {
        return Err(UaccessError::Fault);
    }
    Ok(0)
}

/// Linux fault_in_readable: fault in every page of [addr, addr + len)
/// for reading (one byte read per page, faults resolved as usual).
/// Returns the bytes from the first page that could not be faulted in
/// to the end (0: all present). Call with no spinlock and no mmap_lock
/// held; i_rwsem may be held (i_rwsem -> mmap_lock).
pub fn fault_in_readable<A: UaccessArch>(addr: u64, len: usize) -> usize {
    let end = addr.saturating_add(len as u64);
    let mut a = addr;
    while a < end {
        if get_user::<A, u8>(a).is_err() {
            return (end - a) as usize;
        }
        a = (a & !0xfff) + 0x1000;
    }
    0
}

/// Linux fault_in_safe_writeable: fault in every page of [addr, addr +
/// len) for writing through the fault path (no write to user memory:
/// copy-on-write broken, missing pages mapped). Returns the bytes not
/// faulted in, as `fault_in_readable`; same locking rules.
pub fn fault_in_writeable<A: UaccessArch>(addr: u64, len: usize) -> usize {
    use crate::mm::fault::{Access, handle_mm_fault};
    let end = addr.saturating_add(len as u64);
    if !A::access_ok(addr, len) {
        return len;
    }
    let mm = crate::mm::get_task_mm(crate::task::percpu::current_tid());
    let mut a = addr;
    while a < end {
        let page = a & !0xfff;
        if mm
            .as_ref()
            .is_none_or(|m| handle_mm_fault(m, page, Access::Write).is_err())
        {
            return (end - a) as usize;
        }
        a = page + 0x1000;
    }
    0
}

/// `copy_from_user` for a copy made under a lock that a fault must not
/// nest under (Linux generic_perform_write: i_rwsem, later the page
/// lock): the copy runs with page faults disabled; a missing page is
/// faulted in (`fault_in_readable`) and the copy retried, EFAULT if it
/// cannot be
#[track_caller]
pub fn copy_from_user_atomic<A: UaccessArch>(
    to: &mut [u8],
    from: u64,
    len: usize,
) -> UaccessResult<usize> {
    loop {
        pagefault_disable();
        let r = copy_from_user::<A>(to, from, len);
        pagefault_enable();
        match r {
            Err(UaccessError::Fault) if fault_in_readable::<A>(from, len) == 0 => continue,
            r => return r,
        }
    }
}

/// Write a single value to user space
///
/// This is equivalent to Linux's `put_user()` macro.
///
/// # Arguments
/// * `to` - User space destination address
/// * `value` - Value to write
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(UaccessError::BadAddress)` if user address is invalid
#[track_caller]
pub fn put_user<A: UaccessArch, T: Copy>(to: u64, value: T) -> UaccessResult<()> {
    might_fault();
    let size = ::core::mem::size_of::<T>();

    // Validate user address
    if !A::access_ok(to, size) {
        return Err(UaccessError::BadAddress);
    }

    // Check alignment
    if !to.is_multiple_of(::core::mem::align_of::<T>() as u64) {
        return Err(UaccessError::BadAddress);
    }

    // Perform the write with SMAP protection disabled
    let left = unsafe {
        A::user_access_begin();
        let left = A::copy_user_raw(to as *mut u8, &value as *const T as *const u8, size);
        A::user_access_end();
        left
    };

    if left != 0 {
        return Err(UaccessError::Fault);
    }
    Ok(())
}

/// Read a single value from user space
///
/// This is equivalent to Linux's `get_user()` macro.
///
/// # Arguments
/// * `from` - User space source address
///
/// # Returns
/// * `Ok(value)` on success
/// * `Err(UaccessError::BadAddress)` if user address is invalid
#[track_caller]
pub fn get_user<A: UaccessArch, T: Copy + Default>(from: u64) -> UaccessResult<T> {
    might_fault();
    let size = ::core::mem::size_of::<T>();

    // Validate user address
    if !A::access_ok(from, size) {
        return Err(UaccessError::BadAddress);
    }

    // Check alignment
    if !from.is_multiple_of(::core::mem::align_of::<T>() as u64) {
        return Err(UaccessError::BadAddress);
    }

    // Perform the read with SMAP protection disabled
    let mut value = T::default();
    let left = unsafe {
        A::user_access_begin();
        let left = A::copy_user_raw(&mut value as *mut T as *mut u8, from as *const u8, size);
        A::user_access_end();
        left
    };

    if left != 0 {
        return Err(UaccessError::Fault);
    }
    Ok(value)
}

/// Copy a plain-data value from user space (no alignment requirement,
/// unlike [`get_user`]); for user structs such as `struct timespec[2]`.
///
/// `T` must be valid for any bit pattern (repr(C) integer fields).
pub fn copy_val_from_user<A: UaccessArch, T: Copy + Default>(from: u64) -> UaccessResult<T> {
    let mut value = T::default();
    let size = ::core::mem::size_of::<T>();
    // SAFETY: the byte view covers exactly `value`; T is plain data.
    let bytes = unsafe { ::core::slice::from_raw_parts_mut(&mut value as *mut T as *mut u8, size) };
    copy_from_user::<A>(bytes, from, size)?;
    Ok(value)
}

/// Copy a plain-data value to user space (no alignment requirement, unlike
/// [`put_user`]). `T` must have no implicit padding (it would leak kernel
/// stack bytes).
pub fn copy_val_to_user<A: UaccessArch, T: Copy>(to: u64, value: &T) -> UaccessResult<()> {
    let size = ::core::mem::size_of::<T>();
    // SAFETY: the byte view covers exactly `*value`.
    let bytes = unsafe { ::core::slice::from_raw_parts(value as *const T as *const u8, size) };
    copy_to_user::<A>(to, bytes)?;
    Ok(())
}

/// Read a null-terminated string from user space
///
/// Reads up to `max_len` bytes from user space, stopping at the first null byte.
///
/// # Arguments
/// * `from` - User space source address
/// * `max_len` - Maximum number of bytes to read (including null terminator)
///
/// # Returns
/// * `Ok(String)` containing the string (without null terminator) on success
/// * `Err(UaccessError::BadAddress)` if user address is invalid
/// * `Err(UaccessError::Overflow)` if string exceeds max_len
#[track_caller]
pub fn strncpy_from_user<A: UaccessArch>(
    from: u64,
    max_len: usize,
) -> UaccessResult<alloc::string::String> {
    might_fault();
    use alloc::string::String;

    // Validate initial address (we'll check byte by byte)
    if !A::access_ok(from, 1) {
        return Err(UaccessError::BadAddress);
    }

    let mut result = String::new();
    let mut ptr = from;

    unsafe {
        A::user_access_begin();

        for _ in 0..max_len {
            // Check each byte is in valid user space
            if !A::access_ok(ptr, 1) {
                A::user_access_end();
                return Err(UaccessError::BadAddress);
            }

            let mut byte = 0u8;
            if A::copy_user_raw(&mut byte, ptr as *const u8, 1) != 0 {
                A::user_access_end();
                return Err(UaccessError::Fault);
            }
            if byte == 0 {
                break;
            }
            result.push(byte as char);
            ptr += 1;
        }

        A::user_access_end();
    }

    // If we hit max_len without finding null, it's an overflow
    if result.len() == max_len {
        return Err(UaccessError::Overflow);
    }

    Ok(result)
}

/// Copy a NUL-terminated byte string from user space (Linux
/// `strndup_user` without the UTF-8 assumption of [`strncpy_from_user`]).
///
/// Copies in chunks that never cross a page boundary, so a string that
/// ends just before an unmapped page is read without faulting.
///
/// # Returns
/// * `Ok(bytes)` without the terminator
/// * `Err(BadAddress)` / `Err(Fault)` for an invalid or unmapped address
/// * `Err(Overflow)` if no NUL is found within `max_len` bytes
pub fn strndup_user_bytes<A: UaccessArch>(
    from: u64,
    max_len: usize,
) -> UaccessResult<alloc::vec::Vec<u8>> {
    const PAGE: u64 = 4096;
    let mut out = alloc::vec::Vec::new();
    let mut ptr = from;
    let mut chunk = [0u8; 256];
    while out.len() < max_len {
        let to_page_end = (PAGE - (ptr % PAGE)) as usize;
        let n = chunk.len().min(to_page_end).min(max_len - out.len());
        copy_from_user::<A>(&mut chunk[..n], ptr, n)?;
        if let Some(z) = chunk[..n].iter().position(|&b| b == 0) {
            out.extend_from_slice(&chunk[..z]);
            return Ok(out);
        }
        out.extend_from_slice(&chunk[..n]);
        ptr = ptr.checked_add(n as u64).ok_or(UaccessError::Overflow)?;
    }
    Err(UaccessError::Overflow)
}
