//! RCU-protected intrusive lists (Linux include/linux/rculist.h)
//!
//! An [`RcuList`] owns a strong reference to each entry, linked through
//! an embedded [`Link`] (`util::list::adapter!`). Readers walk it under
//! an [`RcuReadGuard`] with no lock and no allocation (Linux
//! list_for_each_entry_rcu); writers serialize on the list's own leaf
//! spin lock (`ends`; Linux leaves this to the caller's lock, which
//! the caller still holds for its logic: RTNL, a socket table's lock).
//! An entry removed keeps its `next`, so a reader standing on it walks
//! on (Linux list_del_rcu); the list's reference is handed back as
//! [`RcuUnlinked`], dropped after a grace period, when the link becomes
//! free again.
//!
//! Ordering: an entry is initialized before a Release store publishes
//! it (rcu_assign_pointer); readers load `next` with Acquire
//! (rcu_dereference).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, Ordering::Acquire, Ordering::Relaxed, Ordering::Release};

use crate::sync::rcu::{HasRcuHead, RcuReadGuard, call_rcu};
use crate::sync::spin::Mutex;
use crate::util::list::{Adapter, Link};

/// The writers' end of a list
struct Ends {
    tail: *mut Link,
    len: usize,
}

// SAFETY: the tail is a link of the list, used only under `ends`
unsafe impl Send for Ends {}

/// An RCU list of `Arc<A::Item>` (Linux list_head with the _rcu
/// operations)
///
/// # Invariants
/// From `head` through `next` are the links of `ends.len` live items,
/// each inserted with `Arc::into_raw` (the list's reference), `tail` the
/// last; an item unlinked stays allocated until a grace period after
/// it left (`RcuUnlinked`), and its link is not reused before.
pub struct RcuList<A: Adapter> {
    head: AtomicPtr<Link>,
    ends: Mutex<Ends>,
    _owns: PhantomData<Arc<A::Item>>,
}

// SAFETY: it holds `Arc<Item>`s and hands out `&Item` to any thread
unsafe impl<A: Adapter> Send for RcuList<A> where A::Item: Send + Sync {}
// SAFETY: as above; writers serialize on `ends`, readers only load
unsafe impl<A: Adapter> Sync for RcuList<A> where A::Item: Send + Sync {}

impl<A: Adapter> RcuList<A> {
    #[track_caller]
    pub const fn new() -> Self {
        Self {
            head: AtomicPtr::new(null_mut()),
            ends: Mutex::new(Ends {
                tail: null_mut(),
                len: 0,
            }),
            _owns: PhantomData,
        }
    }

    fn lk(item: &A::Item) -> *mut Link {
        core::ptr::from_ref::<Link>(A::link(item)).cast_mut()
    }

    /// Append `item` (Linux list_add_tail_rcu); panics if its link is
    /// on a list, or still in a grace period after leaving one
    pub fn push_back(&self, item: Arc<A::Item>) {
        let l = Self::lk(&item);
        assert!(A::link(&item).claim(), "RcuList: item already linked");
        let mut e = self.ends.lock();
        // SAFETY: `l` is the claimed link of a live item; the tail is a
        // live link of this list (invariant), changed only under `ends`
        unsafe {
            (*l).set_next(null_mut());
            (*l).set_prev(e.tail);
            // Published after its fields (Release)
            match e.tail.as_ref() {
                Some(t) => t.publish_next(l),
                None => self.head.store(l, Release),
            }
        }
        // INVARIANT: linked after the tail, holding the into_raw reference
        e.tail = l;
        e.len += 1;
        let _ = Arc::into_raw(item);
    }

    /// Unlink the first entry `f` accepts (Linux list_del_rcu): readers
    /// may still see it until a grace period passes, so the list's
    /// reference comes back as [`RcuUnlinked`]
    pub fn remove_first(&self, mut f: impl FnMut(&A::Item) -> bool) -> Option<RcuUnlinked<A>> {
        let mut e = self.ends.lock();
        let mut cur = self.head.load(Relaxed);
        while !cur.is_null() {
            // SAFETY: a link of this list (invariant; `ends` held)
            let item = unsafe { &*A::item(cur) };
            if f(item) {
                // SAFETY: `cur` and its neighbours are links of this list
                unsafe {
                    let next = (*cur).next();
                    let prev = (*cur).prev();
                    match prev.as_ref() {
                        Some(p) => p.publish_next(next),
                        None => self.head.store(next, Release),
                    }
                    match next.as_ref() {
                        Some(n) => n.set_prev(prev),
                        None => e.tail = prev,
                    }
                }
                // INVARIANT: off the list; `next` kept for readers on it
                e.len -= 1;
                // SAFETY: the reference the list took with into_raw
                let arc = unsafe { Arc::from_raw(A::item(cur)) };
                return Some(RcuUnlinked(Some(arc), PhantomData));
            }
            // SAFETY: as above
            cur = unsafe { (*cur).next() };
        }
        None
    }

    /// The entries, front to back, valid while `g` is held (Linux
    /// list_for_each_entry_rcu): an entry added meanwhile may or may not
    /// be seen, one removed may still be
    pub fn iter<'a>(&'a self, _g: &'a RcuReadGuard) -> RcuIter<'a, A> {
        RcuIter {
            cur: self.head.load(Acquire),
            _l: PhantomData,
        }
    }

    /// A reference to the first entry `f` accepts (no allocation)
    pub fn find(&self, mut f: impl FnMut(&A::Item) -> bool) -> Option<Arc<A::Item>> {
        let g = crate::sync::rcu::read_lock();
        let it = self.iter(&g).find(|it| f(it))?;
        // SAFETY: an entry reached under the guard
        Some(unsafe { arc_ref(it) })
    }

    /// References to the entries now (for work that sleeps per entry):
    /// sized, then filled under the guard without allocating; again if
    /// the list grew in between. The kernel bounds the length (no
    /// untrusted growth), so the vector is allocated infallibly.
    pub fn snapshot(&self) -> Vec<Arc<A::Item>> {
        loop {
            let n = self.ends.lock().len;
            let mut v = Vec::with_capacity(n + 1);
            let g = crate::sync::rcu::read_lock();
            for it in self.iter(&g) {
                if v.len() == v.capacity() {
                    break;
                }
                // SAFETY: a live entry (the guard), referenced by the list
                v.push(unsafe { arc_ref(it) });
            }
            if v.len() < v.capacity() {
                return v;
            }
        }
    }

    /// Number of entries
    pub fn count(&self) -> usize {
        self.ends.lock().len
    }

    /// Take the entries off, front to back, with their references: no
    /// reader can stand on them (`&mut`), so no grace period
    pub fn drain(&mut self) -> Drain<'_, A> {
        Drain { list: self }
    }
}

/// The entries of an [`RcuList`] taken off one at a time (`drain`);
/// those not taken stay on it
pub struct Drain<'a, A: Adapter> {
    list: &'a mut RcuList<A>,
}

impl<A: Adapter> Iterator for Drain<'_, A> {
    type Item = Arc<A::Item>;
    fn next(&mut self) -> Option<Arc<A::Item>> {
        let cur = *self.list.head.get_mut();
        if cur.is_null() {
            return None;
        }
        // SAFETY: the first link of the list, borrowed `&mut` (no reader
        // or writer): a live entry holding the list's reference
        unsafe {
            let next = (*cur).next();
            *self.list.head.get_mut() = next;
            let e = self.list.ends.get_mut();
            e.len -= 1;
            match next.as_ref() {
                Some(n) => n.set_prev(null_mut()),
                None => e.tail = null_mut(),
            }
            (*cur).reset();
            Some(Arc::from_raw(A::item(cur)))
        }
    }
}

/// A new reference to an entry of an [`RcuList`]
///
/// # Safety
/// `it` is an entry that is, or was until a grace period not yet over,
/// on an `RcuList`, which holds an `Arc` reference to it.
unsafe fn arc_ref<T>(it: &T) -> Arc<T> {
    let p = core::ptr::from_ref::<T>(it);
    // SAFETY: the list's `into_raw` reference keeps the Arc alive
    unsafe {
        Arc::increment_strong_count(p);
        Arc::from_raw(p)
    }
}

impl<A: Adapter> Drop for RcuList<A> {
    fn drop(&mut self) {
        let mut cur = *self.head.get_mut();
        while !cur.is_null() {
            // SAFETY: no reader borrows the list (`&mut`): its links are
            // live entries holding the list's references
            unsafe {
                let next = (*cur).next();
                (*cur).reset();
                drop(Arc::from_raw(A::item(cur)));
                cur = next;
            }
        }
    }
}

/// Iterator over an [`RcuList`] under a read guard
pub struct RcuIter<'a, A: Adapter> {
    cur: *mut Link,
    _l: PhantomData<(&'a RcuList<A>, &'a RcuReadGuard)>,
}

impl<'a, A: Adapter> Iterator for RcuIter<'a, A> {
    type Item = &'a A::Item;
    fn next(&mut self) -> Option<&'a A::Item> {
        if self.cur.is_null() {
            return None;
        }
        // SAFETY: a link reached from the list under the guard: its item
        // stays allocated until a grace period after it was unlinked
        let item = unsafe { &*A::item(self.cur) };
        // SAFETY: as above (an unlinked link keeps its `next`)
        self.cur = unsafe { (*self.cur).next_rcu() };
        Some(item)
    }
}

/// An entry taken off an [`RcuList`], with the list's reference: on
/// drop, after a grace period, its link is free and the reference goes
/// (Linux list_del_rcu + synchronize_rcu)
#[must_use]
pub struct RcuUnlinked<A: Adapter>(Option<Arc<A::Item>>, PhantomData<A>);

impl<A: Adapter> RcuUnlinked<A> {
    /// The entry
    pub fn item(&self) -> &A::Item {
        self.0.as_deref().expect("RcuUnlinked: taken")
    }
}

impl<A: Adapter> RcuUnlinked<A>
where
    A::Item: HasRcuHead + Send + Sync,
{
    /// Free the link and drop the list's reference after a grace period
    /// without waiting for one (Linux list_del_rcu + kfree_rcu): any
    /// context. The drop runs in `rcuc/N`, preemption off, so the
    /// item's last drop must not sleep (`sync::rcu::kfree_rcu`).
    pub fn defer(mut self) {
        /// After the grace period: the link is free, the reference goes
        ///
        /// # Safety
        /// `p` is the `Arc::into_raw` queued with it, a grace period
        /// after the item left its list.
        unsafe fn release<A: Adapter>(p: *const ()) {
            // SAFETY: `Arc::into_raw` of `defer`, taken back once
            let a = unsafe { Arc::from_raw(p.cast::<A::Item>()) };
            // SAFETY: no reader stands on the link any more (the grace
            // period) and no list has it
            unsafe { (*RcuList::<A>::lk(&a)).reset() };
            drop(a);
        }
        let Some(a) = self.0.take() else { return };
        let h = core::ptr::from_ref(a.rcu_head());
        let p = Arc::into_raw(a).cast::<()>();
        // SAFETY: the head is a field of the item (HasRcuHead), kept by
        // the reference `p` until `release` drops it; the item is Send
        // + Sync
        unsafe { call_rcu(&*h, release::<A>, p) };
    }
}

impl<A: Adapter> Drop for RcuUnlinked<A> {
    fn drop(&mut self) {
        if let Some(a) = self.0.take() {
            crate::sync::rcu::synchronize();
            // SAFETY: no reader stands on the link any more (the grace
            // period) and no list has it
            unsafe { (*RcuList::<A>::lk(&a)).reset() };
            drop(a);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::rcu::read_lock;
    use crate::util::list::Link;

    struct Item {
        v: u32,
        link: Link,
    }

    crate::adapter!(ItemLink, Item, link);

    fn item(v: u32) -> Arc<Item> {
        crate::util::kalloc::arc_nofail(Item {
            v,
            link: Link::new(),
        })
    }

    fn values(l: &RcuList<ItemLink>) -> Vec<u32> {
        let g = read_lock();
        l.iter(&g).map(|i| i.v).collect()
    }

    #[test]
    fn push_find_snapshot() {
        let l = RcuList::<ItemLink>::new();
        for v in 1..=3 {
            l.push_back(item(v));
        }
        assert_eq!(values(&l), [1, 2, 3]);
        assert_eq!(l.count(), 3);
        assert_eq!(l.find(|i| i.v == 2).map(|i| i.v), Some(2));
        assert!(l.find(|i| i.v == 9).is_none());
        let s = l.snapshot();
        assert_eq!(s.iter().map(|i| i.v).collect::<Vec<_>>(), [1, 2, 3]);
    }

    #[test]
    fn reader_walks_past_removed() {
        let l = RcuList::<ItemLink>::new();
        for v in 1..=4 {
            l.push_back(item(v));
        }
        let g = read_lock();
        let mut it = l.iter(&g);
        assert_eq!(it.next().map(|i| i.v), Some(1));
        assert_eq!(it.next().map(|i| i.v), Some(2));
        // The reader stands on 2; 2 and 3 leave
        let two = l.remove_first(|i| i.v == 2).unwrap();
        let three = l.remove_first(|i| i.v == 3).unwrap();
        assert_eq!(two.item().v, 2);
        // It still walks on, through the removed 3, to 4
        assert_eq!(it.map(|i| i.v).collect::<Vec<_>>(), [3, 4]);
        drop(g);
        assert_eq!(values(&l), [1, 4]);
        drop((two, three));
        // Removing the ends keeps head and tail right
        drop(l.remove_first(|i| i.v == 4));
        l.push_back(item(5));
        drop(l.remove_first(|i| i.v == 1));
        assert_eq!(values(&l), [5]);
    }

    #[test]
    fn link_free_after_grace_period() {
        let l = RcuList::<ItemLink>::new();
        let a = item(7);
        l.push_back(a.clone());
        let gone = l.remove_first(|i| i.v == 7).unwrap();
        // Still linked for readers until the grace period ends
        assert!(a.link.is_linked());
        drop(gone);
        assert!(!a.link.is_linked());
        assert_eq!(Arc::strong_count(&a), 1);
        l.push_back(a.clone());
        assert_eq!(values(&l), [7]);
    }

    #[test]
    #[should_panic(expected = "already linked")]
    fn relink_before_grace_period_panics() {
        let l = RcuList::<ItemLink>::new();
        let a = item(1);
        l.push_back(a.clone());
        let _gone = l.remove_first(|i| i.v == 1);
        l.push_back(a);
    }

    #[test]
    fn drop_releases_entries() {
        let a = item(1);
        let b = item(2);
        {
            let l = RcuList::<ItemLink>::new();
            l.push_back(a.clone());
            l.push_back(b.clone());
            assert_eq!(Arc::strong_count(&a), 2);
        }
        assert_eq!(Arc::strong_count(&a), 1);
        assert_eq!(Arc::strong_count(&b), 1);
        assert!(!a.link.is_linked());
    }
}
