//! Small-id allocator (Linux lib/idr.c ida): the lowest free id
//!
//! A bitmap. Freeing only clears a bit, so an id may be freed in any
//! context (a disk index goes when its last reference drops), as Linux
//! ida_free; allocating grows the bitmap outside the lock.
//!
//! ## Locking
//!
//! One `IrqSpinlock` per allocator, leaf; nothing allocates or frees
//! memory under it.

use alloc::vec::Vec;

use crate::arch::IrqSpinlock;

/// An id allocator (Linux struct ida)
pub struct Ida(IrqSpinlock<Vec<u64>>);

impl Ida {
    pub const fn new() -> Self {
        Self(IrqSpinlock::new(Vec::new()))
    }

    /// The lowest free id (Linux ida_alloc); thread context
    pub fn alloc(&self) -> u32 {
        loop {
            let mut w = self.0.lock();
            if let Some((i, word)) = w.iter_mut().enumerate().find(|(_, x)| **x != !0) {
                let b = (!*word).trailing_zeros();
                *word |= 1 << b;
                return i as u32 * 64 + b;
            }
            let n = w.len();
            drop(w);
            // Full: a bigger bitmap, allocated with the lock dropped
            let mut bigger = Vec::with_capacity(n + 1);
            let mut w = self.0.lock();
            if w.len() == n {
                bigger.extend_from_slice(&w);
                bigger.push(0);
                core::mem::swap(&mut *w, &mut bigger);
            }
            drop(w);
            drop(bigger);
        }
    }

    /// Give `id` back (Linux ida_free); any context
    pub fn free(&self, id: u32) {
        let mut w = self.0.lock();
        if let Some(word) = w.get_mut((id / 64) as usize) {
            *word &= !(1 << (id % 64));
        }
    }
}

impl Default for Ida {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowest_free() {
        let ida = Ida::new();
        assert_eq!((ida.alloc(), ida.alloc(), ida.alloc()), (0, 1, 2));
        ida.free(1);
        ida.free(0);
        assert_eq!(ida.alloc(), 0);
        assert_eq!(ida.alloc(), 1);
        assert_eq!(ida.alloc(), 3);
        for _ in 4..200 {
            ida.alloc();
        }
        ida.free(130);
        assert_eq!(ida.alloc(), 130);
        assert_eq!(ida.alloc(), 200);
    }
}
