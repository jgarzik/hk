//! Hash buckets with the lock in the head (Linux include/linux/list_bl.h)
//!
//! A [`BlHead`] is one word: the first entry's [`Link`], with bit 0 as
//! a spinning bit lock (Linux hlist_bl_lock / bit_spin_lock), so a
//! table of them costs a pointer per bucket. Entries are linked through
//! an [`Adapter`]'s link and the bucket owns a counted reference to
//! each (a [`RefPtr`], an `Arc` by default: `into_raw` on insert, back
//! on removal): an entry lives at
//! least as long as it is hashed, and every operation is safe. A link's
//! `prev` is null for the first entry (Linux's pprev points into the
//! head). Removal walks the chain to check the entry is there (chains
//! are short: tables are sized to memory).
//!
//! The lock counts as a spin lock for the preempt count and lockdep
//! (one class for every bucket: two are never held at once). Entries
//! are added at the head and published with a Release store, the shape
//! an RCU walk needs (hlist_bl_add_head_rcu); today every walk holds
//! the lock.

use alloc::sync::Arc;
use core::marker::PhantomData;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, Ordering};

use super::list::{Adapter, Link, RefPtr};
use crate::sync::spin::{RawClass, raw_enter, raw_leave};

/// The lock bit in a head (Linux LIST_BL_LOCKMASK)
const LOCK: usize = 1;

/// Every bucket's lockdep class
static CLASS: RawClass = RawClass::new();

/// A bucket (Linux struct hlist_bl_head)
///
/// # Invariants
/// Apart from `LOCK`, `first` is the first entry's link (or null); from
/// it `next` runs through the links of live items, each inserted with
/// `P::into_raw` (the bucket holds that reference) and on no other
/// list through this link, each one's `prev` the link before it (null
/// for the first). The chain changes only under `LOCK`.
pub struct BlHead<A: Adapter, P: RefPtr<Target = A::Item> = Arc<<A as Adapter>::Item>> {
    first: AtomicPtr<Link>,
    /// It drops `P`s wherever it goes: Send/Sync as P's
    _owns: PhantomData<(fn() -> A, P)>,
}

// SAFETY: the chain is only touched under `LOCK` (type invariant) and
// the bucket hands out `P` clones: Send/Sync as `P`
unsafe impl<A: Adapter, P: RefPtr<Target = A::Item> + Send + Sync> Send for BlHead<A, P> {}
// SAFETY: as above
unsafe impl<A: Adapter, P: RefPtr<Target = A::Item> + Send + Sync> Sync for BlHead<A, P> {}

impl<A: Adapter, P: RefPtr<Target = A::Item>> BlHead<A, P> {
    pub const fn new() -> Self {
        Self {
            first: AtomicPtr::new(null_mut()),
            _owns: PhantomData,
        }
    }

    /// Take the bucket's bit lock (Linux hlist_bl_lock)
    pub fn lock(&self) -> BlGuard<'_, A, P> {
        let id = core::ptr::from_ref(self).addr();
        raw_enter(id, &CLASS);
        while self.first.fetch_or(LOCK, Ordering::Acquire).addr() & LOCK != 0 {
            while self.first.load(Ordering::Relaxed).addr() & LOCK != 0 {
                core::hint::spin_loop();
            }
        }
        BlGuard {
            head: self,
            id,
            _not_send: PhantomData,
        }
    }
}

impl<A: Adapter, P: RefPtr<Target = A::Item>> Default for BlHead<A, P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Adapter, P: RefPtr<Target = A::Item>> Drop for BlHead<A, P> {
    fn drop(&mut self) {
        let mut g = self.lock();
        while let Some(i) = g.find(|_| true) {
            drop(g.del(&i));
        }
    }
}

/// A locked bucket: releases the bit lock when dropped
#[must_use]
pub struct BlGuard<'a, A: Adapter, P: RefPtr<Target = A::Item> = Arc<<A as Adapter>::Item>> {
    head: &'a BlHead<A, P>,
    id: usize,
    /// Holding a lock is CPU state (the preempt count)
    _not_send: PhantomData<*const ()>,
}

impl<A: Adapter, P: RefPtr<Target = A::Item>> BlGuard<'_, A, P> {
    fn first(&self) -> *mut Link {
        self.head
            .first
            .load(Ordering::Relaxed)
            .map_addr(|a| a & !LOCK)
    }

    /// Point the head at `l`, keeping the lock bit; Release, so a
    /// lockless reader would see `l` initialized (rcu_assign_pointer)
    fn set_first(&mut self, l: *mut Link) {
        self.head
            .first
            .store(l.map_addr(|a| a | LOCK), Ordering::Release);
    }

    fn link(item: &A::Item) -> *mut Link {
        core::ptr::from_ref(A::link(item)).cast_mut()
    }

    /// The link after `l` in the chain
    fn next(l: *mut Link) -> *mut Link {
        // SAFETY: `l` is a link of this bucket, whose items are live
        // while hashed (type invariant), and the lock is held
        unsafe { (*l).next() }
    }

    /// `item`'s link if it is in this bucket
    fn find_link(&self, item: &A::Item) -> Option<*mut Link> {
        let want = Self::link(item);
        let mut l = self.first();
        while !l.is_null() {
            if l == want {
                return Some(l);
            }
            l = Self::next(l);
        }
        None
    }

    /// Hash `item` at the head (Linux hlist_bl_add_head_rcu); panics if
    /// its link is on a list
    pub fn add_head(&mut self, item: P) {
        assert!(A::link(&item).claim(), "hlist_bl: item already linked");
        let l = Self::link(&item);
        let f = self.first();
        // SAFETY: `l` was claimed for this insert just now and `f` is
        // this bucket's first link (or null), both live, the lock held
        unsafe {
            (*l).set_prev(null_mut());
            (*l).set_next(f);
            if let Some(f) = f.as_ref() {
                f.set_prev(l);
            }
        }
        // INVARIANT: `l` heads the chain, its item's reference kept by
        // the bucket (`into_raw`)
        let _ = P::into_raw(item);
        self.set_first(l);
    }

    /// Unhash `item` (Linux hlist_bl_del) and hand back the bucket's
    /// reference; None if it is not in this bucket
    pub fn del(&mut self, item: &A::Item) -> Option<P> {
        let l = self.find_link(item)?;
        // SAFETY: `l` and its neighbours are links of this bucket (just
        // found), live, the lock held
        unsafe {
            let (prev, next) = ((*l).prev(), (*l).next());
            match prev.as_ref() {
                Some(p) => p.set_next(next),
                None => self.set_first(next),
            }
            if let Some(n) = next.as_ref() {
                n.set_prev(prev);
            }
            // INVARIANT: off the chain, and no lockless reader stands on
            // it (every walk holds the lock)
            (*l).reset();
        }
        // SAFETY: hashed by `add_head`'s `into_raw`, whose reference the
        // bucket held until now
        Some(unsafe { P::from_raw(core::ptr::from_ref(item)) })
    }

    /// The first entry for which `pred` holds, as a new reference: one
    /// walk of the chain (Linux hlist_bl_for_each_entry)
    pub fn find(&self, pred: impl Fn(&A::Item) -> bool) -> Option<P> {
        let mut l = self.first();
        while !l.is_null() {
            // SAFETY: a link of this bucket, inside a live item (type
            // invariant)
            let p = unsafe { A::item(l) };
            // SAFETY: live while hashed, and the lock is held
            let item = unsafe { &*p };
            if pred(item) {
                // SAFETY: `p` came from `P::into_raw` and the bucket
                // still holds that reference
                return Some(unsafe { P::clone_raw(p) });
            }
            l = Self::next(l);
        }
        None
    }
}

impl<A: Adapter, P: RefPtr<Target = A::Item>> Drop for BlGuard<'_, A, P> {
    #[inline]
    fn drop(&mut self) {
        self.head.first.fetch_and(!LOCK, Ordering::Release);
        raw_leave(self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::kalloc::try_arc;

    struct Item {
        v: u32,
        link: Link,
    }
    crate::adapter!(ItemAdapter, Item, link);

    fn item(v: u32) -> Arc<Item> {
        try_arc(Item {
            v,
            link: Link::new(),
        })
        .unwrap()
    }

    /// Entries come back in reverse order of adding; a deleted one is
    /// gone, its reference handed back; one not there is None
    #[test]
    fn add_find_del() {
        let h = BlHead::<ItemAdapter>::new();
        let (a, b, c) = (item(1), item(2), item(3));
        let mut g = h.lock();
        for i in [&a, &b, &c] {
            g.add_head(i.clone());
        }
        let first = g.find(|_| true).unwrap();
        assert_eq!(first.v, 3);
        assert_eq!(g.find(|i| i.v < 3).unwrap().v, 2);
        assert_eq!(Arc::strong_count(&b), 2);
        assert!(g.del(&b).is_some());
        assert!(g.del(&b).is_none() && !b.link.is_linked());
        assert!(g.find(|i| i.v == 2).is_none());
        assert_eq!(g.find(|i| i.v < 3).unwrap().v, 1);
        drop(g);
        drop(first);
        drop(h);
        assert_eq!(Arc::strong_count(&a), 1);
        assert!(!a.link.is_linked() && !c.link.is_linked());
    }
}
