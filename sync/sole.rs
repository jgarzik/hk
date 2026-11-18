//! Atomics with one writer (LOCKING.md §5.4 rule 10)
//!
//! A word only one task or one CPU writes, which others may read, needs
//! no read-modify-write: Linux updates such state with a plain `++`,
//! `|=` or WRITE_ONCE (`current->nvcsw++`, `current->flags |= PF_*`,
//! `rq->nr_switches++` under the rq lock). [`Sole`] is that: a load
//! then a store, atomic only so other contexts may read the word.
//! [`SoleCell`] is a field kept that way: a `Copy` value its writer
//! stores where it changes (Linux WRITE_ONCE) and anyone loads with no
//! lock (Linux READ_ONCE).

use core::fmt;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering};

/// Updates of an atomic only the caller writes: no lock prefix, no
/// exclusive pair
pub trait Sole {
    type V;
    /// Add `v` (wrapping)
    fn sole_add(&self, v: Self::V);
    /// Set the bits of `v`; the store is `ord` (Release to publish)
    fn sole_or(&self, v: Self::V, ord: Ordering);
    /// Clear the bits of `v`; the store is `ord`
    fn sole_clear(&self, v: Self::V, ord: Ordering);
}

macro_rules! sole {
    ($t:ty, $v:ty) => {
        impl Sole for $t {
            type V = $v;

            #[inline]
            fn sole_add(&self, v: $v) {
                self.store(
                    self.load(Ordering::Relaxed).wrapping_add(v),
                    Ordering::Relaxed,
                );
            }

            #[inline]
            fn sole_or(&self, v: $v, ord: Ordering) {
                self.store(self.load(Ordering::Relaxed) | v, ord);
            }

            #[inline]
            fn sole_clear(&self, v: $v, ord: Ordering) {
                self.store(self.load(Ordering::Relaxed) & !v, ord);
            }
        }
    };
}

sole!(AtomicU32, u32);
sole!(AtomicU64, u64);
sole!(AtomicUsize, usize);
sole!(AtomicI64, i64);

/// A value packed into one word, so a lockless reader sees it whole
pub trait Word: Copy {
    fn pack(self) -> u64;
    fn unpack(w: u64) -> Self;
}

impl Word for u64 {
    #[inline]
    fn pack(self) -> u64 {
        self
    }

    #[inline]
    fn unpack(w: u64) -> Self {
        w
    }
}

impl Word for u32 {
    #[inline]
    fn pack(self) -> u64 {
        u64::from(self)
    }

    #[inline]
    fn unpack(w: u64) -> Self {
        w as u32
    }
}

impl Word for bool {
    #[inline]
    fn pack(self) -> u64 {
        u64::from(self)
    }

    #[inline]
    fn unpack(w: u64) -> Self {
        w != 0
    }
}

/// `None` is `u64::MAX`, which a value never is
impl Word for Option<u64> {
    #[inline]
    fn pack(self) -> u64 {
        self.unwrap_or(u64::MAX)
    }

    #[inline]
    fn unpack(w: u64) -> Self {
        (w != u64::MAX).then_some(w)
    }
}

/// A field one context at a time writes and any reads with no lock
/// (Linux WRITE_ONCE / READ_ONCE of a plain field): `set` stores and
/// `get` loads, both Relaxed, never a read-modify-write (rule 10). A
/// reader sees each field whole, not a consistent set of fields.
pub struct SoleCell<T: Word> {
    w: AtomicU64,
    _t: PhantomData<T>,
}

impl<T: Word> SoleCell<T> {
    pub fn new(v: T) -> Self {
        Self {
            w: AtomicU64::new(v.pack()),
            _t: PhantomData,
        }
    }

    /// Linux READ_ONCE
    #[inline]
    pub fn get(&self) -> T {
        T::unpack(self.w.load(Ordering::Relaxed))
    }

    /// Linux WRITE_ONCE, by the field's one writer
    #[inline]
    pub fn set(&self, v: T) {
        self.w.store(v.pack(), Ordering::Relaxed);
    }
}

impl<T: Word + Default> Default for SoleCell<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: Word + fmt::Debug> fmt::Debug for SoleCell<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cell_round_trip() {
        let c = SoleCell::<Option<u64>>::default();
        assert_eq!(c.get(), None);
        c.set(Some(0));
        assert_eq!(c.get(), Some(0));
        let b = SoleCell::new(true);
        assert!(b.get());
        let n = SoleCell::new(u32::MAX);
        assert_eq!(n.get(), u32::MAX);
    }
}
