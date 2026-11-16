//! Atomics with one writer (LOCKING.md §5.4 rule 10)
//!
//! A word only one task or one CPU writes, which others may read, needs
//! no read-modify-write: Linux updates such state with a plain `++`,
//! `|=` or WRITE_ONCE (`current->nvcsw++`, `current->flags |= PF_*`,
//! `rq->nr_switches++` under the rq lock). [`Sole`] is that: a load
//! then a store, atomic only so other contexts may read the word.

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

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
