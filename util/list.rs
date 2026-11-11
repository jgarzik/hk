//! Intrusive doubly linked lists (Linux include/linux/list.h)
//!
//! An item embeds a [`Link`]; an [`Adapter`] (made with [`adapter!`])
//! maps between the item and its link field (`offset_of!`). Lists never
//! allocate, so they can be changed under spinlocks and in interrupt
//! context.
//!
//! - [`List`]: raw, for items whose lifetime the owner manages (entries
//!   pinned on a waiter's stack that unlink themselves before they go,
//!   Linux wait_queue_entry).
//! - [`ArcList`]: the list owns one strong reference per entry
//!   (`Arc::into_raw` on insert, back on removal): run queues, children
//!   and thread-group lists.
//! - [`BoxList`]: the list owns each entry as a `Box`: queued signals.
//!
//! A list and the links of its entries are only touched under the lock
//! that owns the list (the caller's: `&mut List` is that proof); the
//! link words are atomics only so items stay `Sync`. An item is on at
//! most one list per link: a link off every list holds [`UNLINKED`] (on
//! a list, the ends hold null), which [`ArcList`] checks on insert.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::marker::PhantomData;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, Ordering::Relaxed};

/// The pointers of a link that is on no list (Linux LIST_POISON):
/// never a link's address (no link is at address 8)
const UNLINKED: *mut Link = core::ptr::dangling_mut();

/// The list hook embedded in an item (Linux struct list_head)
///
/// # Invariants
/// `next` is `UNLINKED` exactly when the link is on no list (`prev`
/// too, once an insert finished); a claimed link (`next` null, by
/// `claim`) belongs to the one insert that claimed it.
pub struct Link {
    next: AtomicPtr<Link>,
    prev: AtomicPtr<Link>,
}

impl Link {
    pub const fn new() -> Self {
        Self {
            next: AtomicPtr::new(UNLINKED),
            prev: AtomicPtr::new(UNLINKED),
        }
    }

    /// On a list (read under the lock of the list it may be on)
    pub fn is_linked(&self) -> bool {
        self.next.load(Relaxed) != UNLINKED
    }

    /// Claim an unlinked link for an insert: false if it is on a list or
    /// being inserted (two lists under different locks cannot both win)
    pub(super) fn claim(&self) -> bool {
        self.next
            .compare_exchange(UNLINKED, null_mut(), Relaxed, Relaxed)
            .is_ok()
    }
}

/// Raw link access for the RCU list (`util::rculist`), whose writers
/// hold its lock and whose readers load `next` with Acquire
impl Link {
    pub(super) fn next(&self) -> *mut Link {
        self.next.load(Relaxed)
    }

    pub(super) fn prev(&self) -> *mut Link {
        self.prev.load(Relaxed)
    }

    /// `next` for a reader under RCU (Linux rcu_dereference)
    pub(super) fn next_rcu(&self) -> *mut Link {
        self.next.load(core::sync::atomic::Ordering::Acquire)
    }

    /// # Safety
    /// The caller holds the lock of the list this link is claimed for or
    /// on, and `n` keeps that list's invariant.
    pub(super) unsafe fn set_next(&self, n: *mut Link) {
        self.next.store(n, Relaxed);
    }

    /// # Safety
    /// As [`Link::set_next`].
    pub(super) unsafe fn set_prev(&self, p: *mut Link) {
        self.prev.store(p, Relaxed);
    }

    /// Point `next` at `n` for readers, after `n` is initialized (Linux
    /// rcu_assign_pointer)
    ///
    /// # Safety
    /// As [`Link::set_next`].
    pub(super) unsafe fn publish_next(&self, n: *mut Link) {
        self.next.store(n, core::sync::atomic::Ordering::Release);
    }

    /// Mark the link free again
    ///
    /// # Safety
    /// No list holds it and no reader stands on it.
    pub(super) unsafe fn reset(&self) {
        self.next.store(UNLINKED, Relaxed);
        self.prev.store(UNLINKED, Relaxed);
    }
}

/// Maps a list's items to their [`Link`] and back
///
/// # Safety
/// `link` and `item` must be inverse: `item(link(x)) == x`.
pub unsafe trait Adapter {
    type Item;
    fn link(item: &Self::Item) -> &Link;
    /// # Safety
    /// `link` is the link of a live `Item`.
    unsafe fn item(link: *const Link) -> *const Self::Item;
}

/// `adapter!(vis Name, Type, field)`: an [`Adapter`] for `Type.field`
/// (a nested `a.b` field too)
#[macro_export]
macro_rules! adapter {
    ($vis:vis $name:ident, $t:ty, $($field:ident).+) => {
        $vis struct $name;
        // SAFETY: offset_of! gives the field's place in the item
        unsafe impl $crate::util::list::Adapter for $name {
            type Item = $t;
            fn link(item: &$t) -> &$crate::util::list::Link {
                &item.$($field).+
            }
            unsafe fn item(link: *const $crate::util::list::Link) -> *const $t {
                // SAFETY: the caller passes a link inside a live item
                unsafe { link.cast::<u8>().sub(core::mem::offset_of!($t, $($field).+)).cast::<$t>() }
            }
        }
    };
}

/// A doubly linked list of items linked through adapter `A` (Linux
/// list_head as a list head). Movable: the ends are pointers, not a
/// sentinel.
///
/// # Invariants
/// `head`..`tail` through `next` (and back through `prev`) are the
/// links of `len` live items, each on no other list through this
/// adapter's link; `head` and `tail` are both null when `len` is 0.
pub struct List<A: Adapter> {
    head: *mut Link,
    tail: *mut Link,
    len: usize,
    _a: PhantomData<A>,
}

// SAFETY: a list is only used under its owner's lock and hands out
// `&Item` (so `Item: Sync`); it owns no items (ArcList adds Arc's bound)
unsafe impl<A: Adapter> Send for List<A> where A::Item: Sync {}
// SAFETY: as above
unsafe impl<A: Adapter> Sync for List<A> where A::Item: Sync {}

impl<A: Adapter> List<A> {
    pub const fn new() -> Self {
        Self {
            head: null_mut(),
            tail: null_mut(),
            len: 0,
            _a: PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn lk(item: *const A::Item) -> *mut Link {
        // SAFETY: callers pass live items
        core::ptr::from_ref::<Link>(A::link(unsafe { &*item })).cast_mut()
    }

    /// Append `item` (Linux list_add_tail)
    ///
    /// # Safety
    /// `item` is live, not on a list through this link, and stays live
    /// until removed.
    pub unsafe fn push_back(&mut self, item: *const A::Item) {
        let l = Self::lk(item);
        // SAFETY: `l` is live (the caller) and the tail is a live link of
        // this list (type invariant)
        unsafe {
            (*l).next.store(null_mut(), Relaxed);
            (*l).prev.store(self.tail, Relaxed);
            match self.tail.as_ref() {
                Some(t) => t.next.store(l, Relaxed),
                None => self.head = l,
            }
        }
        // INVARIANT: `l` is linked after the old tail, and counted
        self.tail = l;
        self.len += 1;
    }

    /// Prepend `item` (Linux list_add)
    ///
    /// # Safety
    /// As [`List::push_back`].
    pub unsafe fn push_front(&mut self, item: *const A::Item) {
        let l = Self::lk(item);
        // SAFETY: as above
        unsafe {
            (*l).prev.store(null_mut(), Relaxed);
            (*l).next.store(self.head, Relaxed);
            match self.head.as_ref() {
                Some(h) => h.prev.store(l, Relaxed),
                None => self.tail = l,
            }
        }
        self.head = l;
        self.len += 1;
    }

    /// Insert `item` after `at` (Linux list_add(item, at))
    ///
    /// # Safety
    /// `at` is on this list; `item` as for [`List::push_back`].
    pub unsafe fn insert_after(&mut self, at: *const A::Item, item: *const A::Item) {
        let (a, l) = (Self::lk(at), Self::lk(item));
        // SAFETY: `a` is on this list, `l` is a free live link
        unsafe {
            let n = (*a).next.load(Relaxed);
            (*l).prev.store(a, Relaxed);
            (*l).next.store(n, Relaxed);
            match n.as_ref() {
                Some(n) => n.prev.store(l, Relaxed),
                None => self.tail = l,
            }
            (*a).next.store(l, Relaxed);
        }
        self.len += 1;
    }

    /// Unlink `item` (Linux list_del)
    ///
    /// # Safety
    /// `item` is on this list.
    pub unsafe fn remove(&mut self, item: *const A::Item) {
        let l = Self::lk(item);
        // SAFETY: `l` and its neighbours are links of this list
        unsafe {
            let next = (*l).next.load(Relaxed);
            let prev = (*l).prev.load(Relaxed);
            match next.as_ref() {
                Some(n) => n.prev.store(prev, Relaxed),
                None => self.tail = prev,
            }
            match prev.as_ref() {
                Some(p) => p.next.store(next, Relaxed),
                None => self.head = next,
            }
            // INVARIANT: on no list again (`claim` is only raced by a
            // buggy caller, which its assert stops)
            (*l).next.store(UNLINKED, Relaxed);
            (*l).prev.store(UNLINKED, Relaxed);
        }
        self.len -= 1;
    }

    /// The first item
    pub fn front(&self) -> Option<*const A::Item> {
        // SAFETY: a non-null head is an entry's link
        (!self.head.is_null()).then(|| unsafe { A::item(self.head) })
    }

    /// The item after `item` (Linux list_next_entry), read before
    /// `item` is removed when walking and unlinking
    ///
    /// # Safety
    /// `item` is on this list.
    pub unsafe fn next(&self, item: *const A::Item) -> Option<*const A::Item> {
        // SAFETY: `item` is a live entry of this list
        let n = unsafe { (*Self::lk(item)).next.load(Relaxed) };
        // SAFETY: a non-null next is an entry's link
        (!n.is_null()).then(|| unsafe { A::item(n) })
    }

    /// Remove and return the last item (Linux list_last_entry +
    /// list_del)
    pub fn pop_back(&mut self) -> Option<*const A::Item> {
        // SAFETY: a non-null tail is an entry's link
        let item = (!self.tail.is_null()).then(|| unsafe { A::item(self.tail) })?;
        // SAFETY: it is on this list
        unsafe { self.remove(item) };
        Some(item)
    }

    /// Remove and return the first item (Linux list_first_entry +
    /// list_del)
    pub fn pop_front(&mut self) -> Option<*const A::Item> {
        let item = self.front()?;
        // SAFETY: it is on this list
        unsafe { self.remove(item) };
        Some(item)
    }

    /// The items, front to back (Linux list_for_each_entry; the list
    /// must not change meanwhile)
    pub fn iter(&self) -> Iter<'_, A> {
        Iter {
            cur: self.head,
            _l: PhantomData,
        }
    }
}

/// Iterator over a [`List`]'s items
pub struct Iter<'a, A: Adapter> {
    cur: *mut Link,
    _l: PhantomData<&'a List<A>>,
}

impl<A: Adapter> Clone for Iter<'_, A> {
    fn clone(&self) -> Self {
        Self {
            cur: self.cur,
            _l: PhantomData,
        }
    }
}

impl<'a, A: Adapter> Iterator for Iter<'a, A> {
    type Item = &'a A::Item;
    fn next(&mut self) -> Option<&'a A::Item> {
        if self.cur.is_null() {
            return None;
        }
        // SAFETY: an entry of the borrowed list, live while it is on it
        let item = unsafe { &*A::item(self.cur) };
        // SAFETY: `cur` is a live link
        self.cur = unsafe { (*self.cur).next.load(Relaxed) };
        Some(item)
    }
}

/// A [`List`] that owns a strong reference to each entry
///
/// # Invariants
/// Every item on `list` was inserted with `Arc::into_raw`: the list
/// holds that reference until the item leaves it through `from_raw`.
pub struct ArcList<A: Adapter> {
    list: List<A>,
    /// It drops `Arc<Item>`s wherever it goes: Send/Sync as Arc's
    _owns: PhantomData<Arc<A::Item>>,
}

impl<A: Adapter> ArcList<A> {
    pub const fn new() -> Self {
        Self {
            list: List::new(),
            _owns: PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Append `item`; panics if it is on a list through this link
    pub fn push_back(&mut self, item: Arc<A::Item>) {
        assert!(A::link(&item).claim(), "ArcList: item already linked");
        // SAFETY: unlinked and claimed for this insert (the CAS), and live
        // while the list owns this reference
        unsafe { self.list.push_back(Arc::into_raw(item)) };
    }

    /// Prepend `item` (as `push_back`)
    pub fn push_front(&mut self, item: Arc<A::Item>) {
        assert!(A::link(&item).claim(), "ArcList: item already linked");
        // SAFETY: as above
        unsafe { self.list.push_front(Arc::into_raw(item)) };
    }

    /// Unlink `item` and hand back the list's reference
    ///
    /// # Safety
    /// `item` is on this list.
    pub unsafe fn remove(&mut self, item: &A::Item) -> Arc<A::Item> {
        let p = core::ptr::from_ref::<A::Item>(item);
        // SAFETY: on this list, which holds the reference from into_raw
        unsafe {
            self.list.remove(p);
            Arc::from_raw(p)
        }
    }

    /// Remove and return the first entry
    pub fn pop_front(&mut self) -> Option<Arc<A::Item>> {
        // SAFETY: entries were inserted with into_raw
        self.list.pop_front().map(|p| unsafe { Arc::from_raw(p) })
    }

    /// Remove and return the last entry
    pub fn pop_back(&mut self) -> Option<Arc<A::Item>> {
        // SAFETY: entries were inserted with into_raw
        self.list.pop_back().map(|p| unsafe { Arc::from_raw(p) })
    }

    /// The first entry
    pub fn front(&self) -> Option<&A::Item> {
        // SAFETY: live while on the list (the list holds a reference)
        self.list.front().map(|p| unsafe { &*p })
    }

    pub fn iter(&self) -> Iter<'_, A> {
        self.list.iter()
    }
}

impl<A: Adapter> Drop for ArcList<A> {
    fn drop(&mut self) {
        while self.pop_front().is_some() {}
    }
}

/// A [`List`] that owns each entry as a `Box` (Linux list_head of
/// kmalloc'd entries: struct sigpending's sigqueues)
///
/// # Invariants
/// Every item on `list` was inserted with `Box::into_raw`: the list owns
/// it until it leaves through `from_raw`.
pub struct BoxList<A: Adapter> {
    list: List<A>,
    /// It drops `Box<Item>`s wherever it goes: Send/Sync as Box's
    _owns: PhantomData<Box<A::Item>>,
}

impl<A: Adapter> BoxList<A> {
    pub const fn new() -> Self {
        Self {
            list: List::new(),
            _owns: PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Append `item` (Linux list_add_tail); panics if it is on a list
    /// through this link
    pub fn push_back(&mut self, item: Box<A::Item>) {
        assert!(A::link(&item).claim(), "BoxList: item already linked");
        // SAFETY: unlinked and claimed for this insert (the CAS), and live
        // while the list owns it
        unsafe { self.list.push_back(Box::into_raw(item)) };
    }

    /// Remove and return the first entry
    pub fn pop_front(&mut self) -> Option<Box<A::Item>> {
        // SAFETY: entries were inserted with into_raw
        self.list
            .pop_front()
            .map(|p| unsafe { Box::from_raw(p.cast_mut()) })
    }

    /// Unlink and return the first entry `f` picks
    pub fn remove_first(&mut self, f: impl Fn(&A::Item) -> bool) -> Option<Box<A::Item>> {
        let p = core::ptr::from_ref(self.list.iter().find(|i| f(i))?);
        // SAFETY: found on this list, which owns it from into_raw
        unsafe {
            self.list.remove(p);
            Some(Box::from_raw(p.cast_mut()))
        }
    }

    /// Unlink every entry `f` picks, in one walk, handing each to `sink`
    /// in list order
    pub fn drain_if(&mut self, f: impl Fn(&A::Item) -> bool, mut sink: impl FnMut(Box<A::Item>)) {
        let mut cur = self.list.front();
        while let Some(p) = cur {
            // SAFETY: `p` is on this list; its successor is read before
            // `p` may leave it
            cur = unsafe { self.list.next(p) };
            // SAFETY: a live entry of this list
            if f(unsafe { &*p }) {
                // SAFETY: on this list, which owns it from into_raw
                unsafe {
                    self.list.remove(p);
                    sink(Box::from_raw(p.cast_mut()));
                }
            }
        }
    }

    pub fn iter(&self) -> Iter<'_, A> {
        self.list.iter()
    }
}

impl<A: Adapter> Default for BoxList<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Adapter> Drop for BoxList<A> {
    fn drop(&mut self) {
        while self.pop_front().is_some() {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    struct Node {
        v: u32,
        link: Link,
    }
    crate::adapter!(NodeA, Node, link);

    fn node(v: u32) -> Arc<Node> {
        Arc::new(Node {
            v,
            link: Link::new(),
        })
    }

    fn vals(l: &ArcList<NodeA>) -> Vec<u32> {
        l.iter().map(|n| n.v).collect()
    }

    struct BNode {
        v: u32,
        link: Link,
        dropped: Option<Arc<core::sync::atomic::AtomicU32>>,
    }
    crate::adapter!(BNodeA, BNode, link);

    impl Drop for BNode {
        fn drop(&mut self) {
            if let Some(d) = &self.dropped {
                d.fetch_add(1, Relaxed);
            }
        }
    }

    fn bnode(v: u32) -> Box<BNode> {
        Box::new(BNode {
            v,
            link: Link::new(),
            dropped: None,
        })
    }

    fn bvals(l: &BoxList<BNodeA>) -> Vec<u32> {
        l.iter().map(|n| n.v).collect()
    }

    #[test]
    fn box_list_remove_first_and_drain() {
        let mut l: BoxList<BNodeA> = BoxList::new();
        for v in 1..=6 {
            l.push_back(bnode(v));
        }
        assert_eq!(l.remove_first(|n| n.v % 2 == 0).map(|n| n.v), Some(2));
        assert!(l.remove_first(|n| n.v == 9).is_none());
        let mut got = Vec::new();
        // Head, middle and tail all leave in one walk
        l.drain_if(|n| n.v != 3, |n| got.push(n.v));
        assert_eq!(got, [1, 4, 5, 6]);
        assert_eq!(bvals(&l), [3]);
        // A removed entry can be queued again
        let n = l.pop_front().unwrap();
        assert!(l.is_empty());
        l.push_back(n);
        l.push_back(bnode(7));
        assert_eq!((bvals(&l), l.len()), (alloc::vec![3, 7], 2));
    }

    #[test]
    fn box_list_drop_frees_entries() {
        let d = Arc::new(core::sync::atomic::AtomicU32::new(0));
        {
            let mut l: BoxList<BNodeA> = BoxList::new();
            for v in 0..3 {
                let mut n = bnode(v);
                n.dropped = Some(d.clone());
                l.push_back(n);
            }
        }
        assert_eq!(d.load(Relaxed), 3);
    }

    #[test]
    fn push_remove_order() {
        let mut l: ArcList<NodeA> = ArcList::new();
        let (a, b, c) = (node(1), node(2), node(3));
        l.push_back(a.clone());
        l.push_back(b.clone());
        l.push_front(c.clone());
        assert_eq!(vals(&l), [3, 1, 2]);
        assert_eq!(Arc::strong_count(&a), 2);
        // Middle, then ends
        let got = unsafe { l.remove(&a) };
        assert!(Arc::ptr_eq(&got, &a));
        drop(got);
        assert_eq!(Arc::strong_count(&a), 1);
        assert_eq!(vals(&l), [3, 2]);
        assert_eq!(l.pop_front().map(|n| n.v), Some(3));
        assert_eq!(l.front().map(|n| n.v), Some(2));
        drop(unsafe { l.remove(&b) });
        assert!(l.is_empty() && l.front().is_none());
        // Reinsert after removal
        l.push_back(a.clone());
        assert_eq!(vals(&l), [1]);
    }

    #[test]
    #[should_panic(expected = "already linked")]
    fn double_insert_panics() {
        let mut l: ArcList<NodeA> = ArcList::new();
        let mut m: ArcList<NodeA> = ArcList::new();
        let a = node(1);
        l.push_back(a.clone());
        m.push_back(a);
    }

    #[test]
    fn drop_releases_entries() {
        let a = node(7);
        {
            let mut l: ArcList<NodeA> = ArcList::new();
            l.push_back(a.clone());
            assert_eq!(Arc::strong_count(&a), 2);
        }
        assert_eq!(Arc::strong_count(&a), 1);
    }

    #[test]
    fn raw_list_stack_items() {
        let x = Node {
            v: 5,
            link: Link::new(),
        };
        let y = Node {
            v: 6,
            link: Link::new(),
        };
        let mut l: List<NodeA> = List::new();
        unsafe {
            l.push_back(&x);
            l.push_back(&y);
        }
        assert_eq!(l.iter().map(|n| n.v).collect::<Vec<_>>(), [5, 6]);
        unsafe { l.remove(&y) };
        assert_eq!(l.len(), 1);
        assert_eq!(l.pop_front().map(|p| unsafe { (*p).v }), Some(5));
        assert!(l.is_empty());
    }

    #[test]
    fn insert_after_middle_and_tail() {
        let n = |v| Node {
            v,
            link: Link::new(),
        };
        let (a, b, c) = (n(1), n(3), n(2));
        let mut l: List<NodeA> = List::new();
        unsafe {
            l.push_back(&a);
            l.insert_after(&a, &b);
            l.insert_after(&a, &c);
        }
        assert_eq!(l.iter().map(|n| n.v).collect::<Vec<_>>(), [1, 2, 3]);
        let d = n(4);
        unsafe { l.insert_after(&b, &d) };
        assert_eq!(l.len(), 4);
        unsafe { l.remove(&d) };
        assert_eq!(l.iter().map(|n| n.v).collect::<Vec<_>>(), [1, 2, 3]);
        // The tail moved back to `b`
        let e = n(5);
        unsafe { l.push_back(&e) };
        assert_eq!(l.iter().map(|n| n.v).collect::<Vec<_>>(), [1, 2, 3, 5]);
        while l.pop_front().is_some() {}
    }
}
