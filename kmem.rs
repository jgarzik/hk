//! Fallible allocation for sizes the user controls
//!
//! The global allocator cannot fail gracefully (an allocation it cannot
//! meet panics), so a buffer sized by a syscall argument goes through
//! [`try_vec`]: ENOMEM instead, as Linux's kvmalloc callers return. The
//! heap has no vmalloc, so nothing above [`MAX_KMALLOC`] is tried.

use alloc::vec::Vec;

use crate::error::KernelError;

/// Largest heap allocation (MAX_ORDER pages: no vmalloc)
pub const MAX_KMALLOC: usize = 4 << 20;

/// `n` copies of `v`, or ENOMEM if that is over [`MAX_KMALLOC`] or the
/// heap cannot provide it
pub fn try_vec<T: Clone>(n: usize, v: T) -> Result<Vec<T>, KernelError> {
    let bytes = n
        .checked_mul(core::mem::size_of::<T>())
        .ok_or(KernelError::OutOfMemory)?;
    if bytes > MAX_KMALLOC {
        return Err(KernelError::OutOfMemory);
    }
    let mut x = Vec::new();
    x.try_reserve_exact(n)
        .map_err(|_| KernelError::OutOfMemory)?;
    x.resize(n, v);
    Ok(x)
}
