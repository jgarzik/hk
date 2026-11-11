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
//! - [`PtrList`]: the list owns each entry through an owning pointer
//!   ([`ListPtr`]: `into_raw` on insert, back on removal):
//!   [`ArcList`] one strong reference per entry (run queues, children
//!   and thread-group lists), [`BoxList`] the entry itself (queued
//!   signals, the packet backlog).
//! - [`OwnedList`]: an `ArcList` whose items carry an [`Owner`] mark,
//!   so removing or stepping from any given item is safe in O(1): a
//!   dentry's children.
//! - [`WeakList`]: the list holds a `Weak` per entry, which leaves it in
//!   its own teardown: superblocks, a superblock's mounts and inodes.
//!
//! A list and the links of its entries are only touched under the lock
//! that owns the list (the caller's: `&mut List` is that proof); the
//! link words are atomics only so items stay `Sync`. An item is on at
//! most one list per link: a link off every list holds [`UNLINKED`] (on
//! a list, the ends hold null), which [`PtrList`] checks on insert.

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use core::marker::PhantomData;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering::Relaxed};

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

    /// Move every item of `other` to the end of this list, in order,
    /// leaving `other` empty (Linux list_splice_tail_init)
    pub fn append(&mut self, other: &mut Self) {
        if other.head.is_null() {
            return;
        }
        let first = other.head;
        // SAFETY: `first` and this list's tail are live links of the two
        // lists (type invariant)
        unsafe {
            (*first).prev.store(self.tail, Relaxed);
            match self.tail.as_ref() {
                Some(t) => t.next.store(first, Relaxed),
                None => self.head = first,
            }
        }
        // INVARIANT: `other`'s chain now follows the old tail; `other`
        // is the empty list
        self.tail = other.tail;
        self.len += other.len;
        *other = Self::new();
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

/// An owning pointer a [`PtrList`] can hold as a raw pointer: `Box`
/// (the list owns the entry) or `Arc` (the list owns one reference)
///
/// # Safety
/// `into_raw` hands over ownership as a pointer to the live value
/// `Deref` reached, which stays live and unmoved until `from_raw` takes
/// it back; `from_raw(into_raw(p))` is `p` again.
pub unsafe trait ListPtr: core::ops::Deref<Target: Sized> {
    fn into_raw(this: Self) -> *const Self::Target;
    /// # Safety
    /// `p` came from `into_raw` of this pointer type and is taken back
    /// once.
    unsafe fn from_raw(p: *const Self::Target) -> Self;
}

// SAFETY: Box::into_raw/from_raw; a box's value never moves
unsafe impl<T> ListPtr for Box<T> {
    #[inline]
    fn into_raw(this: Self) -> *const T {
        Box::into_raw(this)
    }
    #[inline]
    unsafe fn from_raw(p: *const T) -> Self {
        // SAFETY: from `into_raw` (the caller), taken back once
        unsafe { Box::from_raw(p.cast_mut()) }
    }
}

// SAFETY: Arc::into_raw/from_raw keep the reference; the value never
// moves
unsafe impl<T> ListPtr for Arc<T> {
    #[inline]
    fn into_raw(this: Self) -> *const T {
        Arc::into_raw(this)
    }
    #[inline]
    unsafe fn from_raw(p: *const T) -> Self {
        // SAFETY: from `into_raw` (the caller), taken back once
        unsafe { Arc::from_raw(p) }
    }
}

/// A [`List`] that owns its entries through `P` (Linux list_head of
/// kmalloc'd or refcounted entries): a [`BoxList`] owns each entry
/// (struct sigpending's sigqueues, the per-CPU packet backlog), an
/// [`ArcList`] one strong reference to each (run queues, children and
/// thread-group lists)
///
/// # Invariants
/// Every item on `list` was inserted with `P::into_raw`: the list owns
/// that pointer until the item leaves it through `from_raw`.
pub struct PtrList<A: Adapter, P: ListPtr<Target = A::Item>> {
    list: List<A>,
    /// It drops `P`s wherever it goes: Send/Sync as P's
    _owns: PhantomData<P>,
}

/// A [`PtrList`] owning each entry as a `Box`
pub type BoxList<A> = PtrList<A, Box<<A as Adapter>::Item>>;
/// A [`PtrList`] owning a strong reference to each entry
pub type ArcList<A> = PtrList<A, Arc<<A as Adapter>::Item>>;

impl<A: Adapter, P: ListPtr<Target = A::Item>> PtrList<A, P> {
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
    pub fn push_back(&mut self, item: P) {
        assert!(A::link(&item).claim(), "list: item already linked");
        // SAFETY: unlinked and claimed for this insert (the CAS), and live
        // while the list owns it
        unsafe { self.list.push_back(P::into_raw(item)) };
    }

    /// Prepend `item` (Linux list_add; as `push_back`)
    pub fn push_front(&mut self, item: P) {
        assert!(A::link(&item).claim(), "list: item already linked");
        // SAFETY: as above
        unsafe { self.list.push_front(P::into_raw(item)) };
    }

    /// Unlink `item` and hand back the list's pointer
    ///
    /// # Safety
    /// `item` is on this list.
    pub unsafe fn remove(&mut self, item: &A::Item) -> P {
        let p = core::ptr::from_ref::<A::Item>(item);
        // SAFETY: on this list, which owns it from into_raw
        unsafe {
            self.list.remove(p);
            P::from_raw(p)
        }
    }

    /// Remove and return the first entry
    pub fn pop_front(&mut self) -> Option<P> {
        // SAFETY: entries were inserted with into_raw
        self.list.pop_front().map(|p| unsafe { P::from_raw(p) })
    }

    /// Remove and return the last entry
    pub fn pop_back(&mut self) -> Option<P> {
        // SAFETY: entries were inserted with into_raw
        self.list.pop_back().map(|p| unsafe { P::from_raw(p) })
    }

    /// The first entry
    pub fn front(&self) -> Option<&A::Item> {
        // SAFETY: live while on the list (the list owns it)
        self.list.front().map(|p| unsafe { &*p })
    }

    pub fn iter(&self) -> Iter<'_, A> {
        self.list.iter()
    }

    /// Unlink and return the first entry `f` picks
    pub fn remove_first(&mut self, f: impl Fn(&A::Item) -> bool) -> Option<P> {
        let p = core::ptr::from_ref(self.list.iter().find(|i| f(i))?);
        // SAFETY: found on this list, which owns it from into_raw
        unsafe {
            self.list.remove(p);
            Some(P::from_raw(p))
        }
    }

    /// Unlink every entry `f` picks, in one walk, handing each to `sink`
    /// in list order (Linux list_for_each_entry_safe + list_del)
    pub fn drain_if(&mut self, mut f: impl FnMut(&A::Item) -> bool, mut sink: impl FnMut(P)) {
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
                    sink(P::from_raw(p));
                }
            }
        }
    }

    /// Move every entry `f` picks to the tail of `to`, in order, with
    /// its pointer (Linux move_expired_inodes' list_move to the
    /// dispatch queue)
    pub fn move_if(&mut self, to: &mut Self, mut f: impl FnMut(&A::Item) -> bool) {
        let mut cur = self.list.front();
        while let Some(p) = cur {
            // SAFETY: `p` is on this list; its successor is read before
            // `p` may leave it
            cur = unsafe { self.list.next(p) };
            // SAFETY: a live entry (the list owns it)
            if f(unsafe { &*p }) {
                // SAFETY: on this list, then on no list; both lists own
                // one into_raw pointer per entry (type invariant), so
                // the pointer moves with it
                unsafe {
                    self.list.remove(p);
                    to.list.push_back(p);
                }
            }
        }
    }
}

impl<A: Adapter, P: ListPtr<Target = A::Item>> Default for PtrList<A, P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Adapter, P: ListPtr<Target = A::Item>> Drop for PtrList<A, P> {
    fn drop(&mut self) {
        while self.pop_front().is_some() {}
    }
}

/// Which [`OwnedList`] an item is on (0: none), kept beside its link
pub struct Owner(AtomicU64);

impl Owner {
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    /// On some list now: a hint read without that list's lock (Linux's
    /// unlocked list_empty() before taking it); exact under it
    pub fn is_set(&self) -> bool {
        self.0.load(Relaxed) != 0
    }
}

impl Default for Owner {
    fn default() -> Self {
        Self::new()
    }
}

/// An [`Adapter`] whose items also carry an [`Owner`] for that link
///
/// # Safety
/// `owner` returns a field of the item used by no other adapter.
pub unsafe trait OwnerAdapter: Adapter {
    fn owner(item: &Self::Item) -> &Owner;
}

/// `owned_adapter!(vis Name, Type, link, owner)`: an [`OwnerAdapter`]
/// for `Type.link`, marked in `Type.owner`
#[macro_export]
macro_rules! owned_adapter {
    ($vis:vis $name:ident, $t:ty, $link:ident, $owner:ident) => {
        $crate::adapter!($vis $name, $t, $link);
        // SAFETY: a field of the item, named for this adapter only
        unsafe impl $crate::util::list::OwnerAdapter for $name {
            fn owner(item: &$t) -> &$crate::util::list::Owner {
                &item.$owner
            }
        }
    };
}

/// Ids of [`OwnedList`]s: each list its own, never reused (64 bits)
static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

/// An [`ArcList`] that knows its items by their [`Owner`] mark, so
/// removing or stepping from a given item is safe and O(1) (Linux
/// hlist_del / the next sibling on a dentry's d_children)
///
/// # Invariants
/// An item's owner mark is `id` exactly while it is on `list`; no
/// other list ever writes `id`.
pub struct OwnedList<A: OwnerAdapter> {
    list: ArcList<A>,
    id: u64,
}

impl<A: OwnerAdapter> OwnedList<A> {
    pub fn new() -> Self {
        Self {
            list: ArcList::new(),
            id: NEXT_OWNER.fetch_add(1, Relaxed),
        }
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    fn mine(&self, item: &A::Item) -> bool {
        A::owner(item).0.load(Relaxed) == self.id
    }

    /// `item` is on this list
    pub fn contains(&self, item: &A::Item) -> bool {
        self.mine(item)
    }

    /// Append `item`; panics if it is on a list through this link
    pub fn push_back(&mut self, item: Arc<A::Item>) {
        let mark = item.clone();
        self.list.push_back(item);
        // INVARIANT: on this list from here (the push claimed its link)
        A::owner(&mark).0.store(self.id, Relaxed);
    }

    /// Take `item` off and hand back the list's reference; None if it
    /// is not on this list
    pub fn remove(&mut self, item: &A::Item) -> Option<Arc<A::Item>> {
        if !self.mine(item) {
            return None;
        }
        // INVARIANT: leaving the list
        A::owner(item).0.store(0, Relaxed);
        // SAFETY: marked with this list's id, so on it (type invariant)
        Some(unsafe { self.list.remove(item) })
    }

    /// A new reference to the first entry
    pub fn front(&self) -> Option<Arc<A::Item>> {
        self.list.list.front().map(|p| {
            // SAFETY: inserted with `into_raw`; the list holds that
            // reference while the entry is on it
            unsafe { Arc::increment_strong_count(p) };
            // SAFETY: the reference just taken
            unsafe { Arc::from_raw(p) }
        })
    }

    /// A new reference to the entry after `item`; None if `item` is the
    /// last or not on this list
    pub fn next(&self, item: &A::Item) -> Option<Arc<A::Item>> {
        if !self.mine(item) {
            return None;
        }
        // SAFETY: marked with this list's id, so on it (type invariant)
        let p = unsafe { self.list.list.next(core::ptr::from_ref(item)) }?;
        // SAFETY: as in `front`
        unsafe { Arc::increment_strong_count(p) };
        // SAFETY: the reference just taken
        Some(unsafe { Arc::from_raw(p) })
    }

    pub fn iter(&self) -> Iter<'_, A> {
        self.list.iter()
    }
}

impl<A: OwnerAdapter> Default for OwnedList<A> {
    fn default() -> Self {
        Self::new()
    }
}

/// A [`List`] that holds a `Weak` reference to each entry: for objects
/// that stay listed for their whole life and leave the list in their
/// teardown (Linux super_blocks and fs_supers, whose entries
/// __put_super and generic_shutdown_super unlink; an sb's s_mounts and
/// s_inodes). A walker under the list's lock may meet an entry whose
/// last strong reference is gone and whose teardown waits for that lock
/// (Linux SB_DYING, I_FREEING): [`WeakEntry::upgrade`] fails for it
/// (refcount_inc_not_zero).
///
/// The item's owner keeps the contract the walkers rely on: every
/// entry leaves the list (`remove`) under its lock as the first step of
/// its `Drop`, before any field is dropped, so a linked entry is never
/// a dropped value. The list's `Weak` keeps the allocation, which is
/// what lets an entry be upgraded from its link.
///
/// # Invariants
/// Every item on `list` was inserted with `Weak::into_raw`: the list
/// holds that weak reference until the item leaves it through
/// `from_raw`.
pub struct WeakList<A: Adapter> {
    list: List<A>,
    /// It drops `Weak<Item>`s wherever it goes: Send/Sync as Weak's
    _owns: PhantomData<Weak<A::Item>>,
}

impl<A: Adapter> WeakList<A> {
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
    pub fn push_back(&mut self, item: &Arc<A::Item>) {
        assert!(A::link(item).claim(), "WeakList: item already linked");
        // SAFETY: unlinked and claimed for this insert (the CAS); the
        // weak reference keeps the allocation, and the owner unlinks it
        // before it is dropped (type contract)
        unsafe { self.list.push_back(Weak::into_raw(Arc::downgrade(item))) };
    }

    /// Prepend `item` (Linux list_add / hlist_add_head)
    pub fn push_front(&mut self, item: &Arc<A::Item>) {
        assert!(A::link(item).claim(), "WeakList: item already linked");
        // SAFETY: as in push_back
        unsafe { self.list.push_front(Weak::into_raw(Arc::downgrade(item))) };
    }

    /// Unlink `item` and hand back the list's weak reference (dropping
    /// it never runs the item's `Drop`)
    ///
    /// # Safety
    /// `item` is on this list.
    pub unsafe fn remove(&mut self, item: &A::Item) -> Weak<A::Item> {
        let p = core::ptr::from_ref::<A::Item>(item);
        // SAFETY: on this list, which holds the weak reference from
        // into_raw
        unsafe {
            self.list.remove(p);
            Weak::from_raw(p)
        }
    }

    /// Remove the first entry, handing back the list's weak reference
    pub fn pop_front(&mut self) -> Option<Weak<A::Item>> {
        // SAFETY: entries were inserted with into_raw
        self.list.pop_front().map(|p| unsafe { Weak::from_raw(p) })
    }

    /// The entries, front to back (the list must not change meanwhile:
    /// its lock is held for the walk)
    pub fn iter(&self) -> WeakIter<'_, A> {
        WeakIter {
            list: self,
            cur: self.list.front(),
        }
    }

    /// The entries after `item`, which the walker holds (an `Arc`), so
    /// it is still listed (Linux list_for_each_entry_continue)
    ///
    /// # Safety
    /// `item` is on this list.
    pub unsafe fn iter_after(&self, item: &A::Item) -> WeakIter<'_, A> {
        WeakIter {
            list: self,
            // SAFETY: on this list (the caller)
            cur: unsafe { self.list.next(item) },
        }
    }
}

impl<A: Adapter> Drop for WeakList<A> {
    fn drop(&mut self) {
        while self.pop_front().is_some() {}
    }
}

/// Iterator over a [`WeakList`]'s entries
pub struct WeakIter<'a, A: Adapter> {
    list: &'a WeakList<A>,
    cur: Option<*const A::Item>,
}

impl<'a, A: Adapter> Iterator for WeakIter<'a, A> {
    type Item = WeakEntry<'a, A>;
    fn next(&mut self) -> Option<WeakEntry<'a, A>> {
        let p = self.cur?;
        // SAFETY: an entry of the borrowed list
        self.cur = unsafe { self.list.list.next(p) };
        Some(WeakEntry { p, _l: PhantomData })
    }
}

/// One entry of a [`WeakList`], under the list's lock
///
/// # Invariants
/// `p` is on the list borrowed for 'a, which holds a weak reference to
/// it from `Weak::into_raw`.
pub struct WeakEntry<'a, A: Adapter> {
    p: *const A::Item,
    _l: PhantomData<&'a WeakList<A>>,
}

impl<'a, A: Adapter> WeakEntry<'a, A> {
    /// The item, possibly in its teardown (its last strong reference
    /// gone, its `Drop` waiting for the list's lock): only what stays
    /// valid until that `Drop` unlinks it may be used (no field has
    /// been dropped yet; Linux reads a dying sb under sb_lock likewise)
    pub fn get(&self) -> &'a A::Item {
        // SAFETY: listed, so not dropped (type contract: an entry leaves
        // the list before any of it is dropped, under the lock the
        // borrowed list stands for)
        unsafe { &*self.p }
    }

    /// The list's weak reference, borrowed
    fn weak(&self) -> core::mem::ManuallyDrop<Weak<A::Item>> {
        // SAFETY: the list holds this weak reference (type invariant);
        // ManuallyDrop leaves it the list's
        core::mem::ManuallyDrop::new(unsafe { Weak::from_raw(self.p) })
    }

    /// A strong reference, unless the item is in its teardown (Linux
    /// refcount_inc_not_zero). It must not be dropped under the list's
    /// lock: the last one's `Drop` takes that lock.
    pub fn upgrade(&self) -> Option<Arc<A::Item>> {
        self.weak().upgrade()
    }

    /// Some strong reference is alive
    pub fn is_live(&self) -> bool {
        self.weak().strong_count() != 0
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

    struct ONode {
        v: u32,
        link: Link,
        owner: Owner,
    }
    crate::owned_adapter!(ONodeA, ONode, link, owner);

    fn onode(v: u32) -> Arc<ONode> {
        Arc::new(ONode {
            v,
            link: Link::new(),
            owner: Owner::new(),
        })
    }

    /// An owned list removes and steps only from its own items
    #[test]
    fn owned_list_knows_its_items() {
        let (mut a, mut b) = (OwnedList::<ONodeA>::new(), OwnedList::<ONodeA>::new());
        let (x, y, z) = (onode(1), onode(2), onode(3));
        a.push_back(x.clone());
        a.push_back(y.clone());
        b.push_back(z.clone());
        assert!(b.remove(&x).is_none() && b.next(&x).is_none());
        assert_eq!(a.next(&x).map(|n| n.v), Some(2));
        assert_eq!(a.front().map(|n| n.v), Some(1));
        assert!(a.remove(&x).is_some() && a.remove(&x).is_none());
        assert_eq!(Arc::strong_count(&x), 1);
        assert!(a.next(&y).is_none() && a.len() == 1);
        b.push_back(x.clone());
        assert_eq!(b.next(&z).map(|n| n.v), Some(1));
        assert!(b.contains(&x) && !a.contains(&x) && a.contains(&y));
        assert!(x.owner.is_set());
        drop(b.remove(&x));
        assert!(!x.owner.is_set());
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
    fn move_if_keeps_order_and_references() {
        let (mut l, mut m): (ArcList<NodeA>, ArcList<NodeA>) = (ArcList::new(), ArcList::new());
        let nodes: Vec<_> = (1..=5).map(node).collect();
        for n in &nodes {
            l.push_back(n.clone());
        }
        m.push_back(node(9));
        l.move_if(&mut m, |n| n.v % 2 == 1);
        assert_eq!(
            (vals(&l), vals(&m)),
            (alloc::vec![2, 4], alloc::vec![9, 1, 3, 5])
        );
        assert!(nodes.iter().all(|n| Arc::strong_count(n) == 2));
        l.move_if(&mut m, |_| true);
        assert!(l.is_empty() && l.front().is_none());
        assert_eq!(vals(&m), [9, 1, 3, 5, 2, 4]);
        // The emptied list takes entries again
        l.push_back(m.pop_back().unwrap());
        assert_eq!(vals(&l), [4]);
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

    struct WNode {
        v: u32,
        link: Link,
        list: *const crate::sync::spin::Mutex<WeakList<WNodeA>>,
    }
    crate::adapter!(WNodeA, WNode, link);
    // SAFETY: the tests use the list pointer only under its lock
    unsafe impl Send for WNode {}
    // SAFETY: as above
    unsafe impl Sync for WNode {}

    impl Drop for WNode {
        /// The owner's side of the contract: unlink first, under the lock
        fn drop(&mut self) {
            // SAFETY: the list outlives its nodes in the test
            let mut l = unsafe { &*self.list }.lock();
            if self.link.is_linked() {
                // SAFETY: linked only on this list
                drop(unsafe { l.remove(self) });
            }
        }
    }

    #[test]
    fn weak_list_entries_leave_in_teardown() {
        let l = crate::sync::spin::Mutex::new(WeakList::<WNodeA>::new());
        let mk = |v| {
            Arc::new(WNode {
                v,
                link: Link::new(),
                list: &raw const l,
            })
        };
        let (a, b, c) = (mk(1), mk(2), mk(3));
        for n in [&a, &b, &c] {
            l.lock().push_back(n);
        }
        // The list holds no strong reference
        assert_eq!((Arc::strong_count(&a), Arc::weak_count(&a)), (1, 1));
        let vals = |l: &WeakList<WNodeA>| l.iter().map(|e| e.get().v).collect::<Vec<_>>();
        assert_eq!(vals(&l.lock()), [1, 2, 3]);
        // A walk continues after an entry it holds
        let after: Vec<u32> = {
            let g = l.lock();
            unsafe { g.iter_after(&a) }
                .filter_map(|e| e.upgrade())
                .map(|n| n.v)
                .collect()
        };
        assert_eq!(after, [2, 3]);
        drop(b);
        assert_eq!(vals(&l.lock()), [1, 3]);
        assert!(l.lock().iter().all(|e| e.is_live()));
        drop(a);
        drop(c);
        assert!(l.lock().is_empty());
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
    fn append_moves_all() {
        let n = |v| Node {
            v,
            link: Link::new(),
        };
        let (a, b, c) = (n(1), n(2), n(3));
        let (mut l, mut m): (List<NodeA>, List<NodeA>) = (List::new(), List::new());
        l.append(&mut m);
        assert!(l.is_empty());
        unsafe {
            m.push_back(&a);
            m.push_back(&b);
        }
        l.append(&mut m);
        assert!(m.is_empty() && m.front().is_none());
        unsafe { m.push_back(&c) };
        l.append(&mut m);
        assert_eq!(l.iter().map(|n| n.v).collect::<Vec<_>>(), [1, 2, 3]);
        assert_eq!(l.len(), 3);
        unsafe { l.remove(&c) };
        assert_eq!(l.pop_front().map(|p| unsafe { (*p).v }), Some(1));
        assert_eq!(l.pop_front().map(|p| unsafe { (*p).v }), Some(2));
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
