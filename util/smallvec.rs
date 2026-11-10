//! A vector whose first `N` elements live inline: no heap allocation
//! while it stays that small, one when it grows past (Linux's inline
//! bio_vecs: BIO_INLINE_VECS, DIO_INLINE_BIO_VECS). For per-I/O arrays
//! that are usually tiny and bounded by the kernel: bio segments, the
//! pages of a direct I/O.

use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};

use crate::util::error::KernelError;

/// Up to `N` elements inline, then on the heap
pub struct SmallVec<T, const N: usize>(Repr<T, N>);

enum Repr<T, const N: usize> {
    /// The elements and how many of them are in use
    Inline([T; N], usize),
    Heap(Vec<T>),
}

impl<T: Default, const N: usize> SmallVec<T, N> {
    /// Empty, inline
    pub fn new() -> Self {
        Self(Repr::Inline(core::array::from_fn(|_| T::default()), 0))
    }

    /// Room for `n` elements: inline up to `N`, else one heap
    /// allocation (ENOMEM)
    pub fn try_with_capacity(n: usize) -> Result<Self, KernelError> {
        if n <= N {
            return Ok(Self::new());
        }
        let mut v = Vec::new();
        v.try_reserve_exact(n)
            .map_err(|_| KernelError::OutOfMemory)?;
        Ok(Self(Repr::Heap(v)))
    }

    /// Append `v`; past the room it grows (for counts the kernel bounds)
    pub fn push(&mut self, v: T) {
        match &mut self.0 {
            Repr::Inline(a, len) if *len < N => {
                a[*len] = v;
                *len += 1;
            }
            Repr::Inline(a, len) => {
                let mut h = Vec::with_capacity(2 * N.max(1));
                h.extend(a[..*len].iter_mut().map(core::mem::take));
                h.push(v);
                self.0 = Repr::Heap(h);
            }
            Repr::Heap(h) => h.push(v),
        }
    }

    /// Remove and return the last element
    pub fn pop(&mut self) -> Option<T> {
        match &mut self.0 {
            Repr::Inline(_, 0) => None,
            Repr::Inline(a, len) => {
                *len -= 1;
                Some(core::mem::take(&mut a[*len]))
            }
            Repr::Heap(h) => h.pop(),
        }
    }

    /// Drop every element (the room stays)
    pub fn clear(&mut self) {
        while self.pop().is_some() {}
    }
}

impl<T: Default, const N: usize> Default for SmallVec<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Deref for SmallVec<T, N> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        match &self.0 {
            Repr::Inline(a, len) => &a[..*len],
            Repr::Heap(h) => h,
        }
    }
}

impl<T, const N: usize> DerefMut for SmallVec<T, N> {
    fn deref_mut(&mut self) -> &mut [T] {
        match &mut self.0 {
            Repr::Inline(a, len) => &mut a[..*len],
            Repr::Heap(h) => h,
        }
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a SmallVec<T, N> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_then_heap() {
        let mut v: SmallVec<u32, 2> = SmallVec::new();
        assert!(v.is_empty());
        v.push(1);
        v.push(2);
        assert!(matches!(v.0, Repr::Inline(_, 2)));
        v.push(3);
        assert!(matches!(v.0, Repr::Heap(_)));
        assert_eq!(&v[..], [1, 2, 3]);
        assert_eq!(v.pop(), Some(3));
        v[0] = 9;
        assert_eq!(v.iter().copied().collect::<Vec<_>>(), [9, 2]);
        v.clear();
        assert!(v.is_empty() && v.pop().is_none());
    }

    #[test]
    fn capacity() {
        let v: SmallVec<u8, 4> = SmallVec::try_with_capacity(4).unwrap();
        assert!(matches!(v.0, Repr::Inline(_, 0)));
        let mut v: SmallVec<u8, 4> = SmallVec::try_with_capacity(5).unwrap();
        assert!(matches!(&v.0, Repr::Heap(h) if h.capacity() >= 5));
        for i in 0..5 {
            v.push(i);
        }
        assert_eq!(v.len(), 5);
        assert_eq!(v.pop(), Some(4));
    }

    #[test]
    fn drops_owned() {
        use alloc::sync::Arc;
        let a = Arc::new(());
        let mut v: SmallVec<Option<Arc<()>>, 1> = SmallVec::new();
        v.push(Some(a.clone()));
        v.push(Some(a.clone()));
        assert_eq!(Arc::strong_count(&a), 3);
        drop(v.pop());
        assert_eq!(Arc::strong_count(&a), 2);
        drop(v);
        assert_eq!(Arc::strong_count(&a), 1);
    }
}
