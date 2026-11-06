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
#![expect(clippy::undocumented_unsafe_blocks)] // TODO(unsafe): SAFETY comments (doc/UNSAFE.md)

extern crate alloc;

use core::mem::MaybeUninit;
use core::sync::atomic::Ordering;

use crate::util::pod::{FromBytes, IntoBytes};

/// Linux pagefault_disable: until `pagefault_enable`, a user access that
/// faults is not resolved (no sleeping fault-in) but fails at once
/// (EFAULT through the copy's fixup). For user reads under a spinlock
/// (futex values). The depth is the current task's (Linux
/// p->pagefault_disabled), so it follows the task to whatever CPU it
/// runs on.
pub fn pagefault_disable() {
    crate::task::percpu::current()
        .pagefault_disabled
        .fetch_add(1, Ordering::Relaxed);
}

pub fn pagefault_enable() {
    crate::task::percpu::current()
        .pagefault_disabled
        .fetch_sub(1, Ordering::Relaxed);
}

/// Faults on user addresses must not be resolved here
pub fn pagefault_disabled() -> bool {
    crate::task::percpu::current()
        .pagefault_disabled
        .load(Ordering::Relaxed)
        != 0
}

/// Linux might_fault: a user access may sleep resolving a fault, unless
/// faults are disabled
#[track_caller]
#[inline]
fn might_fault() {
    // Host tests have no current task
    if !cfg!(test) && !pagefault_disabled() {
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
    /// A string that must be text is not valid UTF-8
    /// ([`strncpy_from_user_str`])
    Encoding,
    /// No NUL within the string's maximum length
    TooLong,
    /// An exclusive store kept failing ([`cmpxchg_user_u32`] on LL/SC
    /// machines; Linux -EAGAIN): retry
    Again,
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

    /// Atomically store `new` in the user word at `uaddr` if it holds
    /// `old` (Linux futex_atomic_cmpxchg_inatomic). 0 with the value
    /// found in `*cur` (`old` when `new` was stored); -EFAULT on a fault
    /// the page-fault handler cannot resolve (caught via the arch
    /// exception fixup); -EAGAIN when an exclusive store kept failing
    /// (LL/SC), `*cur` untouched then.
    ///
    /// # Safety
    /// `uaddr` passed `access_ok` for 4 bytes and is 4-byte aligned;
    /// `cur` is valid for a write; must be called between
    /// `user_access_begin()`/`user_access_end()`.
    unsafe fn cmpxchg_user_raw(uaddr: *mut u32, old: u32, new: u32, cur: *mut u32) -> i32;

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
/// This is equivalent to Linux's `put_user()` macro: any alignment, as
/// on x86-64 and arm64.
///
/// # Arguments
/// * `to` - User space destination address
/// * `value` - Value to write
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(UaccessError::BadAddress)` if user address is invalid
#[track_caller]
pub fn put_user<A: UaccessArch, T: IntoBytes>(to: u64, value: T) -> UaccessResult<()> {
    might_fault();
    let size = ::core::mem::size_of::<T>();

    // Validate user address
    if !A::access_ok(to, size) {
        return Err(UaccessError::BadAddress);
    }

    // Perform the write with SMAP protection disabled
    let src = value.as_bytes();
    // SAFETY: `to` passed access_ok for `size` bytes (a fault is caught
    // and counted); `src` is the value's `size` initialized bytes
    let left = unsafe {
        A::user_access_begin();
        let left = A::copy_user_raw(to as *mut u8, src.as_ptr(), size);
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
/// This is equivalent to Linux's `get_user()` macro: any alignment, as
/// on x86-64 and arm64.
///
/// # Arguments
/// * `from` - User space source address
///
/// # Returns
/// * `Ok(value)` on success
/// * `Err(UaccessError::BadAddress)` if user address is invalid
#[track_caller]
pub fn get_user<A: UaccessArch, T: FromBytes>(from: u64) -> UaccessResult<T> {
    might_fault();
    let size = ::core::mem::size_of::<T>();

    // Validate user address
    if !A::access_ok(from, size) {
        return Err(UaccessError::BadAddress);
    }

    // Perform the read with SMAP protection disabled
    let mut value = MaybeUninit::<T>::zeroed();
    // SAFETY: `from` passed access_ok for `size` bytes (a fault is caught
    // and counted); the destination is `value`'s `size` bytes
    let left = unsafe {
        A::user_access_begin();
        let left = A::copy_user_raw(value.as_mut_ptr().cast::<u8>(), from as *const u8, size);
        A::user_access_end();
        left
    };

    if left != 0 {
        return Err(UaccessError::Fault);
    }
    // SAFETY: every byte is set (zeroed, then copied over), and any bit
    // pattern is a valid T (FromBytes)
    Ok(unsafe { value.assume_init() })
}

/// Compare and exchange a u32 in user space (Linux
/// futex_atomic_cmpxchg_inatomic, its faults resolved unless page faults
/// are disabled): the value found, `old` when `new` was stored.
/// BadAddress outside user space or not 4-byte aligned; Fault for an
/// unresolvable fault; Again when an exclusive store kept failing
#[track_caller]
pub fn cmpxchg_user_u32<A: UaccessArch>(uaddr: u64, old: u32, new: u32) -> UaccessResult<u32> {
    might_fault();
    if !A::access_ok(uaddr, 4) || !uaddr.is_multiple_of(4) {
        return Err(UaccessError::BadAddress);
    }
    let mut cur = 0u32;
    // SAFETY: `uaddr` passed access_ok for 4 bytes and is aligned (a
    // fault is caught by the fixup); `cur` is a local; begin/end paired
    let r = unsafe {
        A::user_access_begin();
        let r = A::cmpxchg_user_raw(uaddr as *mut u32, old, new, &raw mut cur);
        A::user_access_end();
        r
    };
    match r {
        0 => Ok(cur),
        -11 => Err(UaccessError::Again),
        _ => Err(UaccessError::Fault),
    }
}

/// Copy a plain-data value from user space; for user structs such as
/// `struct timespec[2]`
pub fn copy_val_from_user<A: UaccessArch, T: FromBytes>(from: u64) -> UaccessResult<T> {
    let mut value = MaybeUninit::<T>::zeroed();
    let size = ::core::mem::size_of::<T>();
    // SAFETY: `value`'s own bytes, all initialized (zeroed)
    let bytes = unsafe { ::core::slice::from_raw_parts_mut(value.as_mut_ptr().cast::<u8>(), size) };
    copy_from_user::<A>(bytes, from, size)?;
    // SAFETY: any bit pattern is a valid T (FromBytes)
    Ok(unsafe { value.assume_init() })
}

/// Copy a plain-data value to user space; `T` has no padding, which
/// would leak kernel stack bytes
pub fn copy_val_to_user<A: UaccessArch, T: IntoBytes>(to: u64, value: &T) -> UaccessResult<()> {
    copy_to_user::<A>(to, value.as_bytes())?;
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
/// * `Ok(bytes)` without the terminator
/// * `Err(UaccessError::BadAddress)` if user address is invalid
/// * `Err(UaccessError::TooLong)` if no NUL is found within `max_len` bytes
#[track_caller]
pub fn strncpy_from_user<A: UaccessArch>(
    from: u64,
    max_len: usize,
) -> UaccessResult<alloc::vec::Vec<u8>> {
    might_fault();
    // Names are bytes (Linux getname): any but NUL
    strndup_user_bytes::<A>(from, max_len)
}

/// As [`strncpy_from_user`], for strings that are text by definition (key
/// types, xattr names, filesystem type names): not valid UTF-8 is
/// `UaccessError::Encoding`
#[track_caller]
pub fn strncpy_from_user_str<A: UaccessArch>(
    from: u64,
    max_len: usize,
) -> UaccessResult<alloc::string::String> {
    let bytes = strncpy_from_user::<A>(from, max_len)?;
    alloc::string::String::from_utf8(bytes).map_err(|_| UaccessError::Encoding)
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
/// * `Err(TooLong)` if no NUL is found within `max_len` bytes
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
    Err(UaccessError::TooLong)
}

impl From<UaccessError> for crate::util::error::KernelError {
    /// The errno a syscall returns for a failed user access: EFAULT for
    /// a bad or unmapped address, EAGAIN for a contended exclusive
    /// store, EINVAL for text that is not UTF-8, ENAMETOOLONG for a
    /// string without a NUL in its limit (callers with another limit
    /// errno map `TooLong` themselves)
    fn from(e: UaccessError) -> Self {
        use crate::util::error::KernelError as E;
        match e {
            UaccessError::BadAddress | UaccessError::Overflow | UaccessError::Fault => {
                E::BadAddress
            }
            UaccessError::Again => E::WouldBlock,
            UaccessError::Encoding => E::InvalidArgument,
            UaccessError::TooLong => E::NameTooLong,
        }
    }
}

/// A user-space address of a `T` (Linux `T __user *`): never
/// dereferenced, only copied through with the uaccess functions, so a
/// user address cannot be mistaken for a kernel one
#[repr(transparent)]
pub struct UserPtr<T> {
    addr: u64,
    _t: core::marker::PhantomData<fn() -> T>,
}

impl<T> Clone for UserPtr<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for UserPtr<T> {}

impl<T> core::fmt::Debug for UserPtr<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "UserPtr({:#x})", self.addr)
    }
}

impl<T> UserPtr<T> {
    /// The user address `addr` (a syscall argument)
    pub const fn new(addr: u64) -> Self {
        Self {
            addr,
            _t: core::marker::PhantomData,
        }
    }

    pub const fn addr(self) -> u64 {
        self.addr
    }

    pub const fn is_null(self) -> bool {
        self.addr == 0
    }

    /// The `n`th `T` after this one; None on overflow
    pub fn offset(self, n: usize) -> Option<Self> {
        let off = n.checked_mul(core::mem::size_of::<T>())?;
        Some(Self::new(self.addr.checked_add(off as u64)?))
    }

    /// The same address as a `U`
    pub const fn cast<U>(self) -> UserPtr<U> {
        UserPtr::new(self.addr)
    }
}

impl<T: FromBytes> UserPtr<T> {
    /// The `T` at this address, read once
    #[track_caller]
    pub fn read(self) -> UaccessResult<T> {
        get_user::<crate::arch::Uaccess, T>(self.addr)
    }
}

impl<T: IntoBytes> UserPtr<T> {
    /// Store `v` at this address
    #[track_caller]
    pub fn write(self, v: &T) -> UaccessResult<()> {
        copy_to_user::<crate::arch::Uaccess>(self.addr, v.as_bytes()).map(|_| ())
    }
}

/// A user buffer of `len` bytes at `addr` (Rust-for-Linux `UserSlice`):
/// read it through one [`UserSliceReader`] or write it through one
/// [`UserSliceWriter`], each moving forward only, so no byte is fetched
/// twice (no double fetch to race against)
pub struct UserSlice {
    addr: u64,
    len: usize,
}

impl UserSlice {
    pub const fn new(addr: u64, len: usize) -> Self {
        Self { addr, len }
    }

    /// Read the buffer front to back
    pub fn reader(self) -> UserSliceReader {
        UserSliceReader::<crate::arch::Uaccess>::new(self.addr, self.len)
    }

    /// Write the buffer front to back
    pub fn writer(self) -> UserSliceWriter {
        UserSliceWriter::<crate::arch::Uaccess>::new(self.addr, self.len)
    }
}

/// The reading half of a [`UserSlice`]
pub struct UserSliceReader<A: UaccessArch = crate::arch::Uaccess> {
    addr: u64,
    len: usize,
    _a: core::marker::PhantomData<A>,
}

impl<A: UaccessArch> UserSliceReader<A> {
    pub const fn new(addr: u64, len: usize) -> Self {
        Self {
            addr,
            len,
            _a: core::marker::PhantomData,
        }
    }

    /// Bytes not read yet
    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Fill `out` from the buffer and move past it; Overflow if fewer
    /// bytes are left (nothing consumed then)
    #[track_caller]
    pub fn read_slice(&mut self, out: &mut [u8]) -> UaccessResult<()> {
        if out.len() > self.len {
            return Err(UaccessError::Overflow);
        }
        copy_from_user::<A>(out, self.addr, out.len())?;
        self.skip(out.len())
    }

    /// The next `T` in the buffer
    #[track_caller]
    pub fn read<T: FromBytes>(&mut self) -> UaccessResult<T> {
        let mut v = T::zeroed();
        // SAFETY: `v`'s own bytes; any bytes written leave a valid T
        // (FromBytes), and `v` is initialized (zeroed)
        let b = unsafe {
            core::slice::from_raw_parts_mut(
                core::ptr::from_mut(&mut v).cast::<u8>(),
                core::mem::size_of::<T>(),
            )
        };
        self.read_slice(b)?;
        Ok(v)
    }

    /// Move past `n` bytes unread
    pub fn skip(&mut self, n: usize) -> UaccessResult<()> {
        if n > self.len {
            return Err(UaccessError::Overflow);
        }
        self.addr = self
            .addr
            .checked_add(n as u64)
            .ok_or(UaccessError::Overflow)?;
        self.len -= n;
        Ok(())
    }
}

/// The writing half of a [`UserSlice`]
pub struct UserSliceWriter<A: UaccessArch = crate::arch::Uaccess> {
    addr: u64,
    len: usize,
    _a: core::marker::PhantomData<A>,
}

impl<A: UaccessArch> UserSliceWriter<A> {
    pub const fn new(addr: u64, len: usize) -> Self {
        Self {
            addr,
            len,
            _a: core::marker::PhantomData,
        }
    }

    /// Room left
    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Append `data`; Overflow if it does not fit (nothing written then)
    #[track_caller]
    pub fn write_slice(&mut self, data: &[u8]) -> UaccessResult<()> {
        if data.len() > self.len {
            return Err(UaccessError::Overflow);
        }
        copy_to_user::<A>(self.addr, data)?;
        self.addr += data.len() as u64;
        self.len -= data.len();
        Ok(())
    }

    /// Append `v`'s bytes (no padding: `IntoBytes`)
    #[track_caller]
    pub fn write<T: IntoBytes>(&mut self, v: &T) -> UaccessResult<()> {
        self.write_slice(v.as_bytes())
    }
}

/// Linux copy_struct_from_user: a size-versioned struct (clone_args,
/// open_how, sched_attr) of `usize` bytes at `src` into `dst`. A shorter
/// user struct leaves `dst`'s tail zero (older ABI); a longer one must
/// be zero past `dst`'s size (newer ABI fields this kernel does not
/// know), else `E2BIG` (`Err(None)`). A failed access is `Err(Some(e))`.
pub fn copy_struct_from_user<A: UaccessArch, T: FromBytes + IntoBytes>(
    src: u64,
    usize: usize,
) -> Result<T, Option<UaccessError>> {
    let ksize = core::mem::size_of::<T>();
    let mut r = UserSliceReader::<A>::new(src, usize);
    let mut v = T::zeroed();
    // SAFETY: `v`'s own initialized bytes; any bytes leave a valid T
    let b =
        unsafe { core::slice::from_raw_parts_mut(core::ptr::from_mut(&mut v).cast::<u8>(), ksize) };
    let n = ksize.min(usize);
    r.read_slice(&mut b[..n]).map_err(Some)?;
    // The rest of a longer user struct must be zero (Linux
    // check_zeroed_user)
    let mut chunk = [0u8; 64];
    while !r.is_empty() {
        let n = r.len().min(chunk.len());
        r.read_slice(&mut chunk[..n]).map_err(Some)?;
        if chunk[..n].iter().any(|&b| b != 0) {
            return Err(None);
        }
    }
    Ok(v)
}

/// A uaccess "architecture" over the host's own memory, for host unit
/// tests of code that copies from and to user space: user addresses are
/// host pointers
#[cfg(test)]
pub struct HostUaccess;

#[cfg(test)]
impl UaccessArch for HostUaccess {
    const TASK_SIZE: u64 = u64::MAX;

    unsafe fn user_access_begin() {}

    unsafe fn copy_user_raw(dst: *mut u8, src: *const u8, len: usize) -> usize {
        // SAFETY: test "user" addresses are live host buffers
        unsafe { core::ptr::copy(src, dst, len) };
        0
    }

    unsafe fn cmpxchg_user_raw(uaddr: *mut u32, old: u32, new: u32, cur: *mut u32) -> i32 {
        // SAFETY: as above; aligned (the caller checked)
        let a = unsafe { core::sync::atomic::AtomicU32::from_ptr(uaddr) };
        let v = match a.compare_exchange(old, new, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(v) | Err(v) => v,
        };
        // SAFETY: `cur` is valid for a write (the caller)
        unsafe { cur.write(v) };
        0
    }

    unsafe fn user_access_end() {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ua<T>(p: &T) -> u64 {
        core::ptr::from_ref(p).addr() as u64
    }

    #[test]
    fn reader_moves_forward_once() {
        let buf: [u32; 3] = [1, 2, 3];
        let mut r = UserSliceReader::<HostUaccess>::new(ua(&buf), 12);
        assert_eq!(r.read::<u32>(), Ok(1));
        assert_eq!(r.read::<u64>(), Ok(2 | (3 << 32)));
        assert!(r.is_empty());
        assert_eq!(r.read::<u8>(), Err(UaccessError::Overflow));
    }

    #[test]
    fn writer_bounds() {
        let mut buf = [0u8; 6];
        let mut w = UserSliceWriter::<HostUaccess>::new(buf.as_mut_ptr().addr() as u64, 6);
        w.write(&0x0403_0201u32).unwrap();
        assert_eq!(w.write(&0u32), Err(UaccessError::Overflow));
        w.write_slice(&[5, 6]).unwrap();
        assert_eq!(buf, [1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn struct_versions() {
        // Shorter user struct: the tail stays zero
        let short: [u32; 1] = [7];
        let v = copy_struct_from_user::<HostUaccess, [u32; 2]>(ua(&short), 4);
        assert_eq!(v, Ok([7, 0]));
        // Longer with a zero tail: accepted
        let long: [u32; 3] = [7, 8, 0];
        let v = copy_struct_from_user::<HostUaccess, [u32; 2]>(ua(&long), 12);
        assert_eq!(v, Ok([7, 8]));
        // Longer with a nonzero tail: E2BIG
        let long: [u32; 3] = [7, 8, 9];
        let v = copy_struct_from_user::<HostUaccess, [u32; 2]>(ua(&long), 12);
        assert_eq!(v, Err(None));
    }

    #[test]
    fn strings_and_cmpxchg() {
        let s = *b"hello\0world";
        assert_eq!(
            strndup_user_bytes::<HostUaccess>(ua(&s), 64).unwrap(),
            b"hello"
        );
        assert_eq!(
            strndup_user_bytes::<HostUaccess>(ua(&s), 3),
            Err(UaccessError::TooLong)
        );
        let mut w = 5u32;
        let wa = core::ptr::from_mut(&mut w).addr() as u64;
        assert_eq!(cmpxchg_user_u32::<HostUaccess>(wa, 5, 9), Ok(5));
        assert_eq!(cmpxchg_user_u32::<HostUaccess>(wa, 5, 1), Ok(9));
    }
}
