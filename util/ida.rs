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

use crate::sync::IrqSpinlock;

/// An id allocator (Linux struct ida)
pub struct Ida(IrqSpinlock<Vec<u64>>);

impl Ida {
    pub const fn new() -> Self {
        Self(IrqSpinlock::new(Vec::new()))
    }

    /// The lowest free id (Linux ida_alloc); thread context
    pub fn alloc(&self) -> u32 {
        // A device index: boot and probe time, a handful of ids
        self.try_alloc().expect("ida: out of memory")
    }

    /// [`alloc`](Self::alloc), or ENOMEM if the bitmap cannot grow
    pub fn try_alloc(&self) -> Result<u32, crate::util::error::KernelError> {
        self.try_alloc_min(0)
    }

    /// The lowest free id from `min` (Linux ida_alloc_min); thread
    /// context, panicking where the bitmap cannot grow
    pub fn alloc_min(&self, min: u32) -> u32 {
        self.try_alloc_min(min).expect("ida: out of memory")
    }

    /// [`alloc_min`](Self::alloc_min), or ENOMEM if the bitmap cannot
    /// grow
    pub fn try_alloc_min(&self, min: u32) -> Result<u32, crate::util::error::KernelError> {
        loop {
            let mut w = self.0.lock();
            for (i, word) in w.iter_mut().enumerate() {
                let base = i as u32 * 64;
                // The bits below `min` count as taken
                let below = match min.saturating_sub(base) {
                    0 => 0,
                    k if k >= 64 => !0,
                    k => (1u64 << k) - 1,
                };
                let free = !(*word | below);
                if free != 0 {
                    let b = free.trailing_zeros();
                    *word |= 1 << b;
                    return Ok(base + b);
                }
            }
            let n = w.len();
            drop(w);
            // Full: a bigger bitmap, allocated with the lock dropped
            let mut bigger = Vec::new();
            bigger
                .try_reserve_exact(n + 1)
                .map_err(|_| crate::util::error::KernelError::OutOfMemory)?;
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

    /// Ids from a minimum, as Linux mnt_group_ida's ida_alloc_min(1)
    #[test]
    fn alloc_min() {
        let ida = Ida::new();
        assert_eq!(ida.alloc_min(1), 1);
        assert_eq!(ida.alloc_min(1), 2);
        assert_eq!(ida.alloc_min(70), 70);
        ida.free(1);
        assert_eq!(ida.alloc_min(1), 1);
        assert_eq!(ida.alloc(), 0);
        assert_eq!(ida.alloc_min(64), 64);
    }
}
