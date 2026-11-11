//! Lists walked while their entries come and go (Linux lib/klist.c)
//!
//! A [`Klist`] owns one `Arc` per entry, linked through a [`KlistNode`]
//! embedded in it: adding or removing allocates nothing. An iterator
//! takes the list's lock only to step, holding a reference to the entry
//! it stands on (the node's count) and an `Arc` to it, so the walker may
//! sleep between entries (a driver probe). A removed entry that an
//! iterator stands on is marked dead and skipped, and unlinked when the
//! last iterator moves off it (Linux klist_del / klist_put).
//!
//! The lock is a spin leaf: nothing allocates or drops an entry under it
//! (an unlinked entry's `Arc` is returned and dropped after the unlock).

use alloc::sync::Arc;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering::Relaxed};

use crate::sync::spin::Mutex;
use crate::util::list::{Adapter, Link, List};

/// The hook an entry embeds (Linux struct klist_node); `link` is what the
/// adapter names (`klist_adapter!`)
pub struct KlistNode {
    pub link: Link,
    /// Iterators standing on it (under the list's lock)
    refs: AtomicU32,
    /// Removed while an iterator stood on it (under the list's lock)
    dead: AtomicBool,
    /// The list it was added to (null: none)
    owner: AtomicPtr<()>,
}

impl KlistNode {
    pub const fn new() -> Self {
        Self {
            link: Link::new(),
            refs: AtomicU32::new(0),
            dead: AtomicBool::new(false),
            owner: AtomicPtr::new(core::ptr::null_mut()),
        }
    }
}

impl Default for KlistNode {
    fn default() -> Self {
        Self::new()
    }
}

/// An [`Adapter`] whose link is a [`KlistNode`]'s, which it also names
///
/// # Safety
/// As `Adapter`, and `knode(item).link` is the link `link(item)` returns.
pub unsafe trait KlistAdapter: Adapter {
    fn knode(item: &Self::Item) -> &KlistNode;
}

/// `klist_adapter!(vis Name, Type, field)`: an adapter for the
/// `KlistNode` at `Type.field`
#[macro_export]
macro_rules! klist_adapter {
    ($vis:vis $name:ident, $t:ty, $field:ident) => {
        $crate::adapter!($vis $name, $t, $field.link);
        // SAFETY: the adapter above names `$field.link`
        unsafe impl $crate::util::klist::KlistAdapter for $name {
            fn knode(item: &$t) -> &$crate::util::klist::KlistNode {
                &item.$field
            }
        }
    };
}

/// A list of `Arc<A::Item>` iterated while entries are added and removed
/// (Linux struct klist)
///
/// # Invariants
/// The links on `list` are of live items, each holding the reference the
/// list took with `Arc::into_raw`, and each with `owner` set to this list.
pub struct Klist<A: KlistAdapter> {
    list: Mutex<List<A>>,
    _owns: PhantomData<Arc<A::Item>>,
}

// SAFETY: it holds `Arc<Item>`s and hands out `Arc<Item>`s to any thread
unsafe impl<A: KlistAdapter> Send for Klist<A> where A::Item: Send + Sync {}
// SAFETY: as above; the list is used only under its lock
unsafe impl<A: KlistAdapter> Sync for Klist<A> where A::Item: Send + Sync {}

impl<A: KlistAdapter> Klist<A> {
    #[track_caller]
    pub const fn new() -> Self {
        Self {
            list: Mutex::new(List::new()),
            _owns: PhantomData,
        }
    }

    fn me(&self) -> *mut () {
        core::ptr::from_ref(self).cast_mut().cast()
    }

    /// Append `item` (Linux klist_add_tail); panics if it is on a list
    pub fn add_tail(&self, item: Arc<A::Item>) {
        let n = A::knode(&item);
        // Checked and reset under the lock (Linux klist_add_tail), where
        // a walker steps and drops its count
        let mut l = self.list.lock();
        assert!(!n.link.is_linked(), "Klist: item already linked");
        n.refs.store(0, Relaxed);
        n.dead.store(false, Relaxed);
        n.owner.store(self.me(), Relaxed);
        // SAFETY: an unlinked live item, kept alive by the reference the
        // list now holds (into_raw)
        unsafe { l.push_back(Arc::into_raw(item)) };
    }

    /// Unlink `item` now if no iterator stands on it, else mark it dead
    /// for the last one to unlink; the list's reference comes back when
    /// unlinked here, to drop after the unlock
    fn put_locked(l: &mut List<A>, item: &A::Item) -> Option<Arc<A::Item>> {
        let n = A::knode(item);
        if n.refs.load(Relaxed) != 0 || !n.dead.load(Relaxed) {
            return None;
        }
        let p = core::ptr::from_ref(item);
        n.owner.store(core::ptr::null_mut(), Relaxed);
        // SAFETY: on this list (owner checked by the caller or set by
        // add_tail for an item an iterator holds); its reference came
        // from into_raw
        unsafe {
            l.remove(p);
            Some(Arc::from_raw(p))
        }
    }

    /// Remove `item` (Linux klist_del): no iterator reaches it again; the
    /// list's reference is dropped when the last one standing on it
    /// moves on. Nothing if it is not on this list.
    pub fn del(&self, item: &A::Item) {
        let gone = {
            let mut l = self.list.lock();
            let n = A::knode(item);
            if n.owner.load(Relaxed) != self.me() || n.dead.load(Relaxed) {
                return;
            }
            n.dead.store(true, Relaxed);
            Self::put_locked(&mut l, item)
        };
        drop(gone);
    }

    /// The entries from the first, each taken under the lock and held
    /// while the walker uses it (Linux klist_iter_init + klist_next)
    pub fn iter(&self) -> KlistIter<'_, A> {
        KlistIter {
            list: self,
            cur: None,
        }
    }

    /// The first live entry `f` accepts, by reference, with no lock held
    /// after
    pub fn find(&self, mut f: impl FnMut(&A::Item) -> bool) -> Option<Arc<A::Item>> {
        let l = self.list.lock();
        let it = l
            .iter()
            .find(|it| !A::knode(it).dead.load(Relaxed) && f(it))?;
        // SAFETY: a live entry of the list, which holds a reference
        Some(unsafe { arc_ref(it) })
    }
}

/// A new reference to an entry the list holds
///
/// # Safety
/// `it` is on a `Klist` (holding its `into_raw` reference) under its lock.
unsafe fn arc_ref<T>(it: &T) -> Arc<T> {
    let p = core::ptr::from_ref(it);
    // SAFETY: the list's reference keeps the Arc alive
    unsafe {
        Arc::increment_strong_count(p);
        Arc::from_raw(p)
    }
}

impl<A: KlistAdapter> Drop for Klist<A> {
    fn drop(&mut self) {
        let l = self.list.get_mut();
        while let Some(p) = l.pop_front() {
            // SAFETY: the list's into_raw reference, now unlinked
            drop(unsafe { Arc::from_raw(p) });
        }
    }
}

/// An iterator over a [`Klist`] (Linux struct klist_iter)
pub struct KlistIter<'a, A: KlistAdapter> {
    list: &'a Klist<A>,
    /// The entry it stands on, counted in its node's `refs`
    cur: Option<Arc<A::Item>>,
}

/// A step's result: the next entry, and a reference to drop
type Step<T> = (Option<Arc<T>>, Option<Arc<T>>);

impl<A: KlistAdapter> KlistIter<'_, A> {
    /// Step off `cur` under the lock: the next live entry, now counted,
    /// and `cur`'s list reference if it was unlinked here
    fn step(&mut self) -> Step<A::Item> {
        let mut l = self.list.list.lock();
        let mut nxt = match &self.cur {
            // SAFETY: `cur` is counted, so still on the list
            Some(c) => unsafe { l.next(Arc::as_ptr(c)) },
            None => l.front(),
        };
        while let Some(p) = nxt
            // SAFETY: every pointer from front/next is a live entry
            && A::knode(unsafe { &*p }).dead.load(Relaxed)
        {
            // SAFETY: an entry of this list
            nxt = unsafe { l.next(p) };
        }
        let next = nxt.map(|p| {
            // SAFETY: a live entry under the lock
            let it = unsafe { &*p };
            A::knode(it).refs.fetch_add(1, Relaxed);
            // SAFETY: as above
            unsafe { arc_ref(it) }
        });
        let gone = self.cur.as_ref().and_then(|c| {
            A::knode(c).refs.fetch_sub(1, Relaxed);
            Klist::put_locked(&mut l, c)
        });
        (next, gone)
    }
}

impl<A: KlistAdapter> Iterator for KlistIter<'_, A> {
    type Item = Arc<A::Item>;

    fn next(&mut self) -> Option<Arc<A::Item>> {
        let (next, gone) = self.step();
        // Both dropped with the lock released
        drop(gone);
        drop(core::mem::replace(&mut self.cur, next.clone()));
        next
    }
}

impl<A: KlistAdapter> Drop for KlistIter<'_, A> {
    /// Linux klist_iter_exit: step off the current entry
    fn drop(&mut self) {
        if let Some(c) = self.cur.take() {
            let gone = {
                let mut l = self.list.list.lock();
                A::knode(&c).refs.fetch_sub(1, Relaxed);
                Klist::put_locked(&mut l, &c)
            };
            drop(gone);
            drop(c);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Item {
        v: u32,
        node: KlistNode,
    }

    crate::klist_adapter!(ItemNode, Item, node);

    fn item(v: u32) -> Arc<Item> {
        crate::util::kalloc::arc_nofail(Item {
            v,
            node: KlistNode::new(),
        })
    }

    #[test]
    fn walk_while_removing() {
        let l = Klist::<ItemNode>::new();
        let items: alloc::vec::Vec<_> = (1..=4).map(item).collect();
        for it in &items {
            l.add_tail(it.clone());
        }
        let mut it = l.iter();
        assert_eq!(it.next().map(|i| i.v), Some(1));
        let two = it.next().unwrap();
        assert_eq!(two.v, 2);
        // The walker stands on 2: removing it and 3 leaves 2 linked
        // (dead) until the walker moves, 3 unlinked at once
        l.del(&items[1]);
        l.del(&items[2]);
        assert!(items[1].node.link.is_linked());
        assert!(!items[2].node.link.is_linked());
        assert_eq!(it.next().map(|i| i.v), Some(4));
        assert!(!items[1].node.link.is_linked());
        assert!(it.next().is_none());
        drop(it);
        drop(two);
        let left: alloc::vec::Vec<u32> = l.iter().map(|i| i.v).collect();
        assert_eq!(left, [1, 4]);
        assert_eq!(Arc::strong_count(&items[1]), 1);
        assert_eq!(l.find(|i| i.v == 4).map(|i| i.v), Some(4));
        assert!(l.find(|i| i.v == 2).is_none());
        // Deleting twice, or from another list, does nothing
        l.del(&items[1]);
        let other = Klist::<ItemNode>::new();
        other.del(&items[0]);
        assert!(items[0].node.link.is_linked());
    }

    #[test]
    fn drop_releases_entries() {
        let a = item(1);
        {
            let l = Klist::<ItemNode>::new();
            l.add_tail(a.clone());
            assert_eq!(Arc::strong_count(&a), 2);
        }
        assert_eq!(Arc::strong_count(&a), 1);
    }
}
