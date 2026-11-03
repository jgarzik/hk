//! Small-id allocator (Linux lib/idr.c ida): the lowest free id
//!
//! ## Locking
//!
//! One spin `Mutex` per allocator, thread context only, leaf: nothing
//! is taken under it (the free set's node allocation runs under it, as
//! for `MNT_IDS`).

use alloc::collections::BTreeSet;

use crate::sync::spin::Mutex;

struct Ids {
    /// Ids below this were handed out at some point
    next: u32,
    /// Ids below `next` given back
    free: BTreeSet<u32>,
}

/// An id allocator (Linux struct ida)
pub struct Ida(Mutex<Ids>);

impl Ida {
    pub const fn new() -> Self {
        Self(Mutex::new(Ids {
            next: 0,
            free: BTreeSet::new(),
        }))
    }

    /// The lowest free id (Linux ida_alloc)
    pub fn alloc(&self) -> u32 {
        let mut ids = self.0.lock();
        if let Some(id) = ids.free.pop_first() {
            return id;
        }
        ids.next += 1;
        ids.next - 1
    }

    /// Give `id` back (Linux ida_free)
    pub fn free(&self, id: u32) {
        let mut ids = self.0.lock();
        if id < ids.next {
            ids.free.insert(id);
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
    }
}
