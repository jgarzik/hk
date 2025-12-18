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
    /// Start of valid user address space
    const USER_START: u64;
    /// End of valid user address space (exclusive)
    const USER_END: u64;

    /// Check if a user address range is valid for access
    ///
    /// Returns true if the entire range [addr, addr+size) is within user space.
    /// This is equivalent to Linux's `access_ok()` macro.
    fn access_ok(addr: u64, size: usize) -> bool {
        // Check for overflow
        let end = match addr.checked_add(size as u64) {
            Some(e) => e,
            None => return false,
        };

        // Check bounds
        addr >= Self::USER_START && end <= Self::USER_END
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
pub fn copy_to_user<A: UaccessArch>(to: u64, from: &[u8]) -> UaccessResult<usize> {
    let len = from.len();

    // Validate user address
    if !A::access_ok(to, len) {
        return Err(UaccessError::BadAddress);
    }

    // Perform the copy with SMAP protection disabled
    unsafe {
        A::user_access_begin();
        ::core::ptr::copy_nonoverlapping(from.as_ptr(), to as *mut u8, len);
        A::user_access_end();
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
pub fn copy_from_user<A: UaccessArch>(
    to: &mut [u8],
    from: u64,
    len: usize,
) -> UaccessResult<usize> {
    // Validate user address
    if !A::access_ok(from, len) {
        return Err(UaccessError::BadAddress);
    }

    // Check destination has enough space
    if to.len() < len {
        return Err(UaccessError::Overflow);
    }

    // Perform the copy with SMAP protection disabled
    unsafe {
        A::user_access_begin();
        ::core::ptr::copy_nonoverlapping(from as *const u8, to.as_mut_ptr(), len);
        A::user_access_end();
    }

    Ok(0)
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
pub fn put_user<A: UaccessArch, T: Copy>(to: u64, value: T) -> UaccessResult<()> {
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
    unsafe {
        A::user_access_begin();
        ::core::ptr::write(to as *mut T, value);
        A::user_access_end();
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
pub fn get_user<A: UaccessArch, T: Copy + Default>(from: u64) -> UaccessResult<T> {
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
    let value = unsafe {
        A::user_access_begin();
        let v = ::core::ptr::read(from as *const T);
        A::user_access_end();
        v
    };

    Ok(value)
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
pub fn strncpy_from_user<A: UaccessArch>(
    from: u64,
    max_len: usize,
) -> UaccessResult<alloc::string::String> {
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

            let byte = ::core::ptr::read(ptr as *const u8);
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
