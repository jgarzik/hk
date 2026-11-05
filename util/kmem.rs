//! Fallible allocation for sizes the user, the network or a disk control
//!
//! The global allocator cannot fail gracefully (an allocation it cannot
//! meet panics). A buffer whose size comes from outside the kernel must
//! therefore grow through a fallible path that returns
//! [`KernelError::OutOfMemory`] (ENOMEM), as Linux's kvmalloc callers
//! do. The heap serves large blocks from `mm::vmalloc` (kvmalloc), up
//! to [`MAX_KMALLOC`], Linux kvmalloc's INT_MAX.
//!
//! - [`try_vec`] allocates a filled buffer of a known size.
//! - [`KVec`] and [`KDeque`] wrap the standard containers with growth
//!   that is always fallible: there is no infallible `push`/`extend`/
//!   `with_capacity` on them, so code holding one cannot panic the
//!   kernel by growing it from an untrusted length.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::util::error::KernelError;

/// Largest heap allocation (Linux kvmalloc refuses more than INT_MAX).
/// Host tests use a small cap so its limits can be reached.
#[cfg(not(test))]
pub const MAX_KMALLOC: usize = i32::MAX as usize;
#[cfg(test)]
pub const MAX_KMALLOC: usize = 4 << 20;

/// ENOMEM unless `count` items of `T` fit under [`MAX_KMALLOC`]
fn fits<T>(count: usize) -> Result<usize, KernelError> {
    let bytes = count
        .checked_mul(core::mem::size_of::<T>())
        .ok_or(KernelError::OutOfMemory)?;
    if bytes > MAX_KMALLOC {
        return Err(KernelError::OutOfMemory);
    }
    Ok(bytes)
}

/// `n` copies of `v`, or ENOMEM if that is over [`MAX_KMALLOC`] or the
/// heap cannot provide it
pub fn try_vec<T: Clone>(n: usize, v: T) -> Result<Vec<T>, KernelError> {
    fits::<T>(n)?;
    let mut x = Vec::new();
    x.try_reserve_exact(n)
        .map_err(|_| KernelError::OutOfMemory)?;
    x.resize(n, v);
    Ok(x)
}

/// A `Vec` whose every growth is fallible (ENOMEM, capped at
/// [`MAX_KMALLOC`]): hand an untrusted length to one of these and the
/// worst case is an error, not a kernel panic.
#[derive(Debug, Default)]
pub struct KVec<T>(Vec<T>);

impl<T> KVec<T> {
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Reserve `n` up front (one allocation)
    pub fn try_with_capacity(n: usize) -> Result<Self, KernelError> {
        let mut v = Self::new();
        v.try_reserve(n)?;
        Ok(v)
    }

    /// Room for `n` more items, total under [`MAX_KMALLOC`]. Reserves
    /// exactly, so the allocation never exceeds the cap `fits` enforced
    /// (amortized `try_reserve` can round up to roughly twice it); build
    /// a buffer incrementally with `try_with_capacity` first, not a loop
    /// of `try_push`.
    pub fn try_reserve(&mut self, n: usize) -> Result<(), KernelError> {
        fits::<T>(self.0.len().saturating_add(n))?;
        self.0
            .try_reserve_exact(n)
            .map_err(|_| KernelError::OutOfMemory)
    }

    pub fn try_push(&mut self, v: T) -> Result<(), KernelError> {
        if self.0.len() == self.0.capacity() {
            let max = MAX_KMALLOC / core::mem::size_of::<T>().max(1);
            let target = grow(self.0.len(), max);
            self.try_reserve(target.saturating_sub(self.0.len()))?;
        }
        self.0.push(v);
        Ok(())
    }

    pub fn into_vec(self) -> Vec<T> {
        self.0
    }

    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }

    pub fn pop(&mut self) -> Option<T> {
        self.0.pop()
    }

    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.0.iter()
    }
}

impl<T: Clone> KVec<T> {
    /// `n` copies of `v`
    pub fn try_filled(n: usize, v: T) -> Result<Self, KernelError> {
        Ok(Self(try_vec(n, v)?))
    }

    /// Grow or shrink to `n`, filling with `v`
    pub fn try_resize(&mut self, n: usize, v: T) -> Result<(), KernelError> {
        if n > self.0.len() {
            self.try_reserve(n - self.0.len())?;
        }
        self.0.resize(n, v);
        Ok(())
    }
}

impl<T: Copy> KVec<T> {
    pub fn try_extend_from_slice(&mut self, s: &[T]) -> Result<(), KernelError> {
        self.try_reserve(s.len())?;
        self.0.extend_from_slice(s);
        Ok(())
    }
}

impl<T> core::ops::Deref for KVec<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.0
    }
}

impl<T> core::ops::DerefMut for KVec<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.0
    }
}

impl<'a, T> IntoIterator for &'a KVec<T> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// The capacity after `len` (full): doubled, at least 4, at most `max`
/// items (`len < max`, so it always grows)
fn grow(len: usize, max: usize) -> usize {
    len.saturating_mul(2).max(4).min(max)
}

/// A `VecDeque` whose every growth is fallible (ENOMEM, capped at
/// [`MAX_KMALLOC`]): used for queues fed by untrusted input, e.g. a
/// stream of data chunks.
#[derive(Debug, Default)]
pub struct KDeque<T>(VecDeque<T>);

impl<T> KDeque<T> {
    pub const fn new() -> Self {
        Self(VecDeque::new())
    }

    /// Append `v`. Growth doubles, but reserves exactly and never past
    /// [`MAX_KMALLOC`] (amortized `try_reserve` may round up beyond the
    /// cap and fail while `len + 1` still fits)
    pub fn try_push_back(&mut self, v: T) -> Result<(), KernelError> {
        let len = self.0.len();
        fits::<T>(len.saturating_add(1))?;
        if len == self.0.capacity() {
            let max = MAX_KMALLOC / core::mem::size_of::<T>().max(1);
            self.0
                .try_reserve_exact(grow(len, max) - len)
                .map_err(|_| KernelError::OutOfMemory)?;
        }
        self.0.push_back(v);
        Ok(())
    }

    pub fn pop_front(&mut self) -> Option<T> {
        self.0.pop_front()
    }

    pub fn front(&self) -> Option<&T> {
        self.0.front()
    }

    pub fn front_mut(&mut self) -> Option<&mut T> {
        self.0.front_mut()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }

    pub fn iter(&self) -> alloc::collections::vec_deque::Iter<'_, T> {
        self.0.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_vec_caps_at_max() {
        assert!(try_vec::<u8>(MAX_KMALLOC + 1, 0).is_err());
        assert!(try_vec::<u8>(16, 7).unwrap().iter().all(|&b| b == 7));
        // count * size_of overflow is caught, not wrapped
        assert!(try_vec::<u64>(usize::MAX, 0).is_err());
    }

    #[test]
    fn kvec_growth_is_bounded() {
        let mut v: KVec<u8> = KVec::new();
        v.try_extend_from_slice(&[1, 2, 3]).unwrap();
        v.try_push(4).unwrap();
        assert_eq!(v.as_slice(), &[1, 2, 3, 4]);
        // one item past a full buffer fails rather than panicking
        let mut big: KVec<u8> = KVec::new();
        big.try_resize(MAX_KMALLOC, 0).unwrap();
        assert!(big.try_push(0).is_err());
    }

    #[test]
    fn growth_never_passes_max() {
        assert_eq!(grow(0, 1), 1);
        assert_eq!(grow(1, 2), 2);
        assert_eq!(grow(0, 100), 4);
        assert_eq!(grow(64, 104), 104);
        assert_eq!(grow(8, 100), 16);
    }

    #[test]
    fn kdeque_fills_to_the_cap() {
        // 104 items of 40000 bytes fit; doubling from 64 would not
        let mut q: KDeque<[u8; 40000]> = KDeque::new();
        let max = MAX_KMALLOC / 40000;
        for _ in 0..max {
            q.try_push_back([0; 40000]).unwrap();
            assert!(q.0.capacity() * 40000 <= MAX_KMALLOC);
        }
        assert_eq!(q.try_push_back([0; 40000]), Err(KernelError::OutOfMemory));
    }

    #[test]
    fn kdeque_push_pop() {
        let mut q: KDeque<u32> = KDeque::new();
        q.try_push_back(10).unwrap();
        q.try_push_back(20).unwrap();
        assert_eq!(q.len(), 2);
        assert_eq!(q.pop_front(), Some(10));
        assert_eq!(q.front(), Some(&20));
    }
}
