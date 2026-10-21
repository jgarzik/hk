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
//!
//! A list and the links of its entries are only touched under the lock
//! that owns the list (the caller's: `&mut List` is that proof); the
//! link words are atomics only so items stay `Sync`. An item is on at
//! most one list per link.

use alloc::sync::Arc;
use core::marker::PhantomData;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, Ordering::Relaxed};

/// The list hook embedded in an item (Linux struct list_head)
pub struct Link {
    next: AtomicPtr<Link>,
    prev: AtomicPtr<Link>,
}

impl Link {
    pub const fn new() -> Self {
        Self {
            next: AtomicPtr::new(null_mut()),
            prev: AtomicPtr::new(null_mut()),
        }
    }
}

impl Default for Link {
    fn default() -> Self {
        Self::new()
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
        unsafe impl $crate::list::Adapter for $name {
            type Item = $t;
            fn link(item: &$t) -> &$crate::list::Link {
                &item.$($field).+
            }
            unsafe fn item(link: *const $crate::list::Link) -> *const $t {
                // SAFETY: the caller passes a link inside a live item
                unsafe { (link as *const u8).sub(core::mem::offset_of!($t, $($field).+)) as *const $t }
            }
        }
    };
}

/// A doubly linked list of items linked through adapter `A` (Linux
/// list_head as a list head). Movable: the ends are pointers, not a
/// sentinel.
pub struct List<A: Adapter> {
    head: *mut Link,
    tail: *mut Link,
    len: usize,
    _a: PhantomData<A>,
}

// SAFETY: a list is only used under its owner's lock
unsafe impl<A: Adapter> Send for List<A> where A::Item: Sync {}
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
        A::link(unsafe { &*item }) as *const Link as *mut Link
    }

    /// Append `item` (Linux list_add_tail)
    ///
    /// # Safety
    /// `item` is live, not on a list through this link, and stays live
    /// until removed.
    pub unsafe fn push_back(&mut self, item: *const A::Item) {
        let l = Self::lk(item);
        // SAFETY: `l` and the tail are live links of this list
        unsafe {
            (*l).next.store(null_mut(), Relaxed);
            (*l).prev.store(self.tail, Relaxed);
            match self.tail.as_ref() {
                Some(t) => t.next.store(l, Relaxed),
                None => self.head = l,
            }
        }
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
            (*l).next.store(null_mut(), Relaxed);
            (*l).prev.store(null_mut(), Relaxed);
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

impl<A: Adapter> Default for List<A> {
    fn default() -> Self {
        Self::new()
    }
}

/// Iterator over a [`List`]'s items
pub struct Iter<'a, A: Adapter> {
    cur: *mut Link,
    _l: PhantomData<&'a List<A>>,
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
pub struct ArcList<A: Adapter> {
    list: List<A>,
}

impl<A: Adapter> ArcList<A> {
    pub const fn new() -> Self {
        Self { list: List::new() }
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Append `item`, which must not be on a list through this link
    pub fn push_back(&mut self, item: Arc<A::Item>) {
        // SAFETY: the list now owns this reference until removal
        unsafe { self.list.push_back(Arc::into_raw(item)) };
    }

    /// Prepend `item` (as `push_back`)
    pub fn push_front(&mut self, item: Arc<A::Item>) {
        // SAFETY: as above
        unsafe { self.list.push_front(Arc::into_raw(item)) };
    }

    /// Unlink `item` and hand back the list's reference
    ///
    /// # Safety
    /// `item` is on this list.
    pub unsafe fn remove(&mut self, item: &A::Item) -> Arc<A::Item> {
        let p = item as *const A::Item;
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

    /// The first entry
    pub fn front(&self) -> Option<&A::Item> {
        // SAFETY: live while on the list (the list holds a reference)
        self.list.front().map(|p| unsafe { &*p })
    }

    pub fn iter(&self) -> Iter<'_, A> {
        self.list.iter()
    }
}

impl<A: Adapter> Default for ArcList<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Adapter> Drop for ArcList<A> {
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
}
