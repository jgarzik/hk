//! RCU-protected intrusive lists (Linux include/linux/rculist.h)
//!
//! An [`RcuList`] owns each entry through an owning pointer `P` (a
//! strong `Arc` reference by default, or a `&'static` item that is never
//! freed: Linux's static packet_types), linked through an embedded
//! [`Link`] (`util::list::adapter!`). Readers walk it under an
//! [`RcuReadGuard`] with no lock and no allocation (Linux
//! list_for_each_entry_rcu); writers serialize on the list's own leaf
//! spin lock (`ends`; Linux leaves this to the caller's lock, which
//! the caller still holds for its logic: RTNL, a socket table's lock).
//! Writers insert at the tail, before or after a chosen entry (picked
//! under `ends`, so the position cannot go stale), or put a new entry in
//! an old one's place (Linux list_add_tail_rcu, list_add_rcu at a
//! position, list_replace_rcu). An entry removed keeps its `next`, so a
//! reader standing on it walks on (Linux list_del_rcu); the list's
//! pointer is handed back as [`RcuUnlinked`], dropped after a grace
//! period, when the link becomes free again.
//!
//! [`RcuHList`] is a hash chain (Linux hlist_head with the _rcu
//! operations) without a lock of its own: its writers prove they hold
//! the lock that owns it by borrowing that lock's unique data
//! (`sync::UniqueOwner`), so a table of chains costs one pointer each
//! (Linux's fnhe_lock over every nexthop's exception buckets).
//!
//! Ordering: an entry is initialized before a Release store publishes
//! it (rcu_assign_pointer); readers load `next` with Acquire
//! (rcu_dereference).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, Ordering::Acquire, Ordering::Relaxed, Ordering::Release};

use crate::sync::UniqueOwner;
use crate::sync::rcu::{HasRcuHead, RcuReadGuard, call_rcu};
use crate::sync::spin::Mutex;
use crate::util::list::{Adapter, Link, ListPtr};

/// The writers' end of a list
struct Ends {
    tail: *mut Link,
    len: usize,
}

// SAFETY: the tail is a link of the list, used only under `ends`
unsafe impl Send for Ends {}

/// The link of `item` through adapter `A`
fn lk<A: Adapter>(item: &A::Item) -> *mut Link {
    core::ptr::from_ref::<Link>(A::link(item)).cast_mut()
}

/// An RCU list of entries owned through `P` (Linux list_head with the
/// _rcu operations)
///
/// # Invariants
/// From `head` through `next` are the links of `ends.len` live items,
/// each inserted with `P::into_raw` (the list's pointer), `tail` the
/// last; an item unlinked stays allocated until a grace period after
/// it left (`RcuUnlinked`), and its link is not reused before.
pub struct RcuList<A: Adapter, P: ListPtr<Target = A::Item> = Arc<<A as Adapter>::Item>> {
    head: AtomicPtr<Link>,
    ends: Mutex<Ends>,
    _owns: PhantomData<(P, fn() -> A)>,
}

// SAFETY: it holds `P`s to `Item`s and hands out `&Item` to any thread
unsafe impl<A: Adapter, P: ListPtr<Target = A::Item>> Send for RcuList<A, P> where
    A::Item: Send + Sync
{
}
// SAFETY: as above; writers serialize on `ends`, readers only load
unsafe impl<A: Adapter, P: ListPtr<Target = A::Item>> Sync for RcuList<A, P> where
    A::Item: Send + Sync
{
}

impl<A: Adapter, P: ListPtr<Target = A::Item>> Default for RcuList<A, P> {
    #[track_caller]
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Adapter, P: ListPtr<Target = A::Item>> RcuList<A, P> {
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

    /// Claim `item`'s link for an insert; panics if it is on a list, or
    /// still in a grace period after leaving one
    fn claim(item: &P) -> *mut Link {
        assert!(A::link(item).claim(), "RcuList: item already linked");
        lk::<A>(item)
    }

    /// Link the claimed `l` between `prev` and `next` (null: the head,
    /// the tail) and keep `item`'s pointer
    ///
    /// # Safety
    /// `l` is the claimed link of `item`; `prev` and `next` are adjacent
    /// links of this list (or null at its ends), whose `ends` is held as
    /// `e`.
    unsafe fn link(&self, e: &mut Ends, item: P, l: *mut Link, prev: *mut Link, next: *mut Link) {
        // SAFETY: the caller: `l` is claimed for this insert and its
        // neighbours are links of this list, changed only under `ends`
        unsafe {
            (*l).set_next(next);
            (*l).set_prev(prev);
            // Published after its fields (Release)
            match prev.as_ref() {
                Some(p) => p.publish_next(l),
                None => self.head.store(l, Release),
            }
            match next.as_ref() {
                Some(n) => n.set_prev(l),
                None => e.tail = l,
            }
        }
        // INVARIANT: linked between its neighbours, holding the into_raw
        // pointer
        e.len += 1;
        let _ = P::into_raw(item);
    }

    /// The first link whose item `f` accepts, or null (`ends` held)
    fn find_link(&self, _e: &Ends, mut f: impl FnMut(&A::Item) -> bool) -> *mut Link {
        let mut cur = self.head.load(Relaxed);
        while !cur.is_null() {
            // SAFETY: a link of this list (invariant; `ends` held)
            if f(unsafe { &*A::item(cur) }) {
                break;
            }
            // SAFETY: as above
            cur = unsafe { (*cur).next() };
        }
        cur
    }

    /// Append `item` (Linux list_add_tail_rcu); panics if its link is
    /// on a list, or still in a grace period after leaving one
    pub fn push_back(&self, item: P) {
        let l = Self::claim(&item);
        let mut e = self.ends.lock();
        let tail = e.tail;
        // SAFETY: claimed; the tail is the last link of this list
        unsafe { self.link(&mut e, item, l, tail, null_mut()) };
    }

    /// Insert `item` before the first entry `f` accepts, at the tail if
    /// none does (Linux list_add_tail_rcu(new, &pos->list)). The walk
    /// runs under the writers' lock, so the position cannot go stale;
    /// `f` must not allocate.
    pub fn insert_before(&self, item: P, f: impl FnMut(&A::Item) -> bool) {
        let l = Self::claim(&item);
        let mut e = self.ends.lock();
        let next = self.find_link(&e, f);
        let prev = if next.is_null() {
            e.tail
        } else {
            // SAFETY: a link of this list (`ends` held)
            unsafe { (*next).prev() }
        };
        // SAFETY: claimed; `prev` and `next` are adjacent links of it
        unsafe { self.link(&mut e, item, l, prev, next) };
    }

    /// Insert `item` after the last entry `f` accepts, at the head if
    /// none does (Linux list_add_rcu(new, &pos->list)); `f` runs under
    /// the writers' lock, as in `insert_before`
    pub fn insert_after(&self, item: P, mut f: impl FnMut(&A::Item) -> bool) {
        let l = Self::claim(&item);
        let mut e = self.ends.lock();
        let mut prev = null_mut();
        let mut cur = self.head.load(Relaxed);
        while !cur.is_null() {
            // SAFETY: a link of this list (invariant; `ends` held)
            if f(unsafe { &*A::item(cur) }) {
                prev = cur;
            }
            // SAFETY: as above
            cur = unsafe { (*cur).next() };
        }
        let next = if prev.is_null() {
            self.head.load(Relaxed)
        } else {
            // SAFETY: a link of this list
            unsafe { (*prev).next() }
        };
        // SAFETY: claimed; `prev` and `next` are adjacent links of it
        unsafe { self.link(&mut e, item, l, prev, next) };
    }

    /// Put `new` in the place of the first entry `f` accepts (Linux
    /// list_replace_rcu): readers see the old entry or the new one, and
    /// one standing on the old walks on to its successor. The old comes
    /// back as [`RcuUnlinked`]; `new` comes back if no entry matched.
    pub fn replace(&self, new: P, f: impl FnMut(&A::Item) -> bool) -> Result<RcuUnlinked<A, P>, P> {
        let mut e = self.ends.lock();
        let old = self.find_link(&e, f);
        if old.is_null() {
            return Err(new);
        }
        let l = Self::claim(&new);
        // SAFETY: `old` is a link of this list, its neighbours too
        let (prev, next) = unsafe { ((*old).prev(), (*old).next()) };
        // INVARIANT: `old` leaves as `new` takes its place; it keeps its
        // `next` for readers standing on it
        e.len -= 1;
        // SAFETY: claimed; `prev` and `next` were `old`'s neighbours
        unsafe { self.link(&mut e, new, l, prev, next) };
        // SAFETY: the pointer the list took with into_raw
        let p = unsafe { P::from_raw(A::item(old)) };
        Ok(RcuUnlinked(Some(p), PhantomData))
    }

    /// Unlink the first entry `f` accepts (Linux list_del_rcu): readers
    /// may still see it until a grace period passes, so the list's
    /// pointer comes back as [`RcuUnlinked`]
    pub fn remove_first(&self, f: impl FnMut(&A::Item) -> bool) -> Option<RcuUnlinked<A, P>> {
        let mut e = self.ends.lock();
        let cur = self.find_link(&e, f);
        if cur.is_null() {
            return None;
        }
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
        // SAFETY: the pointer the list took with into_raw
        let p = unsafe { P::from_raw(A::item(cur)) };
        Some(RcuUnlinked(Some(p), PhantomData))
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

    /// Number of entries
    pub fn count(&self) -> usize {
        self.ends.lock().len
    }

    /// No entries (Linux list_empty_rcu)
    pub fn is_empty(&self) -> bool {
        self.head.load(Acquire).is_null()
    }

    /// Take the entries off, front to back, with their pointers: no
    /// reader can stand on them (`&mut`), so no grace period
    pub fn drain(&mut self) -> Drain<'_, A, P> {
        Drain { list: self }
    }
}

impl<A: Adapter> RcuList<A> {
    /// The entries as [`RcuRef`]s, valid while `g` is held
    pub fn iter_ref<'a>(&'a self, g: &'a RcuReadGuard) -> RcuRefIter<'a, A> {
        RcuRefIter(self.iter(g))
    }

    /// A reference to the first entry `f` accepts (no allocation)
    pub fn find(&self, mut f: impl FnMut(&A::Item) -> bool) -> Option<Arc<A::Item>> {
        let g = crate::sync::rcu::read_lock();
        self.iter_ref(&g).find(|it| f(it)).map(RcuRef::get)
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
            for it in self.iter_ref(&g) {
                if v.len() == v.capacity() {
                    break;
                }
                v.push(it.get());
            }
            if v.len() < v.capacity() {
                return v;
            }
        }
    }
}

/// The entries of an [`RcuList`] taken off one at a time (`drain`);
/// those not taken stay on it
pub struct Drain<'a, A: Adapter, P: ListPtr<Target = A::Item>> {
    list: &'a mut RcuList<A, P>,
}

impl<A: Adapter, P: ListPtr<Target = A::Item>> Iterator for Drain<'_, A, P> {
    type Item = P;
    fn next(&mut self) -> Option<P> {
        let cur = *self.list.head.get_mut();
        if cur.is_null() {
            return None;
        }
        // SAFETY: the first link of the list, borrowed `&mut` (no reader
        // or writer): a live entry holding the list's pointer
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
            Some(P::from_raw(A::item(cur)))
        }
    }
}

/// An entry an RCU walk of an `Arc` [`RcuList`] or [`RcuHList`]
/// reached, valid while the walk's guard (or the chain's writers' lock)
/// is held: it derefs to the item, and [`get`](Self::get) takes a
/// reference that outlives the guard (Linux an rcu_dereference'd
/// pointer, then a refcount_inc), allocating nothing
///
/// # Invariants
/// The item holds the list's `Arc::into_raw` reference, or did until
/// a grace period that cannot end during `'a`.
pub struct RcuRef<'a, T>(&'a T);

impl<T> Clone for RcuRef<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for RcuRef<'_, T> {}

impl<T> core::ops::Deref for RcuRef<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.0
    }
}

impl<'a, T> RcuRef<'a, T> {
    /// The item, for the walk's lifetime
    pub fn item(self) -> &'a T {
        self.0
    }

    /// A reference of its own to the item
    pub fn get(self) -> Arc<T> {
        let p = core::ptr::from_ref::<T>(self.0);
        // SAFETY: the list's `Arc::into_raw` reference keeps the
        // allocation alive meanwhile (type invariant)
        unsafe {
            Arc::increment_strong_count(p);
            Arc::from_raw(p)
        }
    }
}

/// An [`RcuIter`] of an `Arc` list handing out [`RcuRef`]s
pub struct RcuRefIter<'a, A: Adapter>(RcuIter<'a, A>);

impl<'a, A: Adapter> Iterator for RcuRefIter<'a, A> {
    type Item = RcuRef<'a, A::Item>;
    fn next(&mut self) -> Option<Self::Item> {
        // INVARIANT: an entry of an `Arc` list reached under its guard
        // (or its writers' lock)
        self.0.next().map(RcuRef)
    }
}

impl<A: Adapter, P: ListPtr<Target = A::Item>> Drop for RcuList<A, P> {
    fn drop(&mut self) {
        self.drain().for_each(drop);
    }
}

/// Iterator over an RCU list or chain under a read guard (or its
/// writers' lock: `RcuHList::iter_locked`)
pub struct RcuIter<'a, A: Adapter> {
    cur: *mut Link,
    _l: PhantomData<&'a A::Item>,
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

/// An entry taken off an [`RcuList`] or [`RcuHList`], with the list's
/// pointer: on drop, after a grace period, its link is free and the
/// pointer goes (Linux list_del_rcu + synchronize_rcu)
#[must_use]
pub struct RcuUnlinked<A: Adapter, P: ListPtr<Target = A::Item> = Arc<<A as Adapter>::Item>>(
    Option<P>,
    PhantomData<A>,
);

impl<A: Adapter, P: ListPtr<Target = A::Item>> RcuUnlinked<A, P> {
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
            unsafe { (*lk::<A>(&a)).reset() };
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

    /// As [`defer`](Self::defer), for one entry taken off two lists
    /// (through its links `A` and `B`), with its one callback head:
    /// both links are free and both references gone after one grace
    /// period (Linux __inet_del_ifa's list and hash unlinks, then one
    /// inet_free_ifa). Panics if they are different entries.
    pub fn defer_with<B: Adapter<Item = A::Item>>(mut self, mut other: RcuUnlinked<B>) {
        /// After the grace period: both links are free, the reference
        /// goes
        ///
        /// # Safety
        /// `p` is the `Arc::into_raw` queued with it, a grace period
        /// after the item left both lists.
        unsafe fn release2<A: Adapter, B: Adapter<Item = A::Item>>(p: *const ()) {
            // SAFETY: `Arc::into_raw` of `defer_with`, taken back once
            let a = unsafe { Arc::from_raw(p.cast::<A::Item>()) };
            // SAFETY: no reader stands on either link any more (the
            // grace period) and no list has them
            unsafe {
                (*lk::<A>(&a)).reset();
                (*lk::<B>(&a)).reset();
            }
            drop(a);
        }
        let (Some(a), Some(b)) = (self.0.take(), other.0.take()) else {
            panic!("RcuUnlinked: taken");
        };
        assert!(Arc::ptr_eq(&a, &b), "RcuUnlinked: two entries");
        // `a`'s reference keeps the item until the callback
        drop(b);
        let h = core::ptr::from_ref(a.rcu_head());
        let p = Arc::into_raw(a).cast::<()>();
        // SAFETY: as in `defer`
        unsafe { call_rcu(&*h, release2::<A, B>, p) };
    }
}

impl<A: Adapter, P: ListPtr<Target = A::Item>> Drop for RcuUnlinked<A, P> {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            crate::sync::rcu::synchronize();
            // SAFETY: no reader stands on the link any more (the grace
            // period) and no list has it
            unsafe { (*lk::<A>(&p)).reset() };
            drop(p);
        }
    }
}

/// Marks a chain as belonging to `O`'s lock, without owning an `O`
type Owned<O> = fn(&O);

/// An RCU hash chain of `Arc` entries (Linux hlist_head with
/// hlist_add_head_rcu / hlist_del_rcu) whose writers hold the lock that
/// owns `O`, passing its one value, borrowed mutably, as proof
///
/// # Invariants
/// From `first` through `next` are the links of live items, each
/// inserted with `Arc::into_raw` (the chain's reference); the first's
/// `prev` is null. Links change only under a mutable borrow of the one
/// `O`.
pub struct RcuHList<A: Adapter, O: UniqueOwner> {
    first: AtomicPtr<Link>,
    _owns: PhantomData<(Arc<A::Item>, Owned<O>)>,
}

// SAFETY: it holds `Arc<Item>`s and hands out `&Item` to any thread
unsafe impl<A: Adapter, O: UniqueOwner> Send for RcuHList<A, O> where A::Item: Send + Sync {}
// SAFETY: as above; writers serialize on `O`'s lock, readers only load
unsafe impl<A: Adapter, O: UniqueOwner> Sync for RcuHList<A, O> where A::Item: Send + Sync {}

impl<A: Adapter, O: UniqueOwner> Default for RcuHList<A, O> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Adapter, O: UniqueOwner> RcuHList<A, O> {
    pub const fn new() -> Self {
        Self {
            first: AtomicPtr::new(null_mut()),
            _owns: PhantomData,
        }
    }

    /// The entries, valid while `g` is held (Linux
    /// hlist_for_each_entry_rcu)
    pub fn iter<'a>(&'a self, _g: &'a RcuReadGuard) -> RcuIter<'a, A> {
        RcuIter {
            cur: self.first.load(Acquire),
            _l: PhantomData,
        }
    }

    /// The entries as [`RcuRef`]s, valid while `g` is held
    pub fn iter_ref<'a>(&'a self, g: &'a RcuReadGuard) -> RcuRefIter<'a, A> {
        RcuRefIter(self.iter(g))
    }

    /// The entries as their writer sees them, its lock held (`_o`):
    /// none can leave meanwhile
    pub fn iter_locked<'a>(&'a self, _o: &'a O) -> RcuRefIter<'a, A> {
        RcuRefIter(RcuIter {
            cur: self.first.load(Relaxed),
            _l: PhantomData,
        })
    }

    /// Add `item` first (Linux hlist_add_head_rcu); panics if its link
    /// is on a list, or still in a grace period after leaving one
    pub fn push_front(&self, item: Arc<A::Item>, _o: &mut O) {
        assert!(A::link(&item).claim(), "RcuHList: item already linked");
        let l = lk::<A>(&item);
        let first = self.first.load(Relaxed);
        // SAFETY: `l` is claimed for this insert; `first` is the first
        // link of the chain, changed only under `O`'s lock (`_o`)
        unsafe {
            (*l).set_next(first);
            (*l).set_prev(null_mut());
            if let Some(f) = first.as_ref() {
                f.set_prev(l);
            }
        }
        // INVARIANT: first, holding the into_raw reference; published
        // after its fields
        self.first.store(l, Release);
        let _ = Arc::into_raw(item);
    }

    /// Unlink the first entry `f` accepts (Linux hlist_del_rcu); its
    /// reference comes back as [`RcuUnlinked`]
    pub fn remove_first(
        &self,
        mut f: impl FnMut(&A::Item) -> bool,
        _o: &mut O,
    ) -> Option<RcuUnlinked<A>> {
        let mut cur = self.first.load(Relaxed);
        while !cur.is_null() {
            // SAFETY: a link of this chain (invariant; `O`'s lock held)
            if f(unsafe { &*A::item(cur) }) {
                break;
            }
            // SAFETY: as above
            cur = unsafe { (*cur).next() };
        }
        if cur.is_null() {
            return None;
        }
        // SAFETY: `cur` and its neighbours are links of this chain
        unsafe {
            let next = (*cur).next();
            let prev = (*cur).prev();
            match prev.as_ref() {
                Some(p) => p.publish_next(next),
                None => self.first.store(next, Release),
            }
            if let Some(n) = next.as_ref() {
                n.set_prev(prev);
            }
        }
        // INVARIANT: off the chain; `next` kept for readers on it
        // SAFETY: the reference the chain took with into_raw
        let arc = unsafe { Arc::from_raw(A::item(cur)) };
        Some(RcuUnlinked(Some(arc), PhantomData))
    }

    /// Move every entry, with its reference, to the head of the chain
    /// `to` picks for it, with no grace period in between (Linux
    /// neigh_hash_grow: hlist_del_rcu, then hlist_add_head_rcu of the
    /// same node into the new table). A reader standing on a moved
    /// entry walks on into its new chain: it may miss entries, but
    /// every link it reaches is live. Panics if `to` picks this chain.
    pub fn move_all<'b>(&self, mut to: impl FnMut(&A::Item) -> &'b Self, _o: &mut O)
    where
        Self: 'b,
    {
        loop {
            let cur = self.first.load(Relaxed);
            if cur.is_null() {
                return;
            }
            // SAFETY: the first link of this chain, live (invariant;
            // `O`'s lock held)
            let item = unsafe { &*A::item(cur) };
            let dst = to(item);
            assert!(!core::ptr::eq(dst, self), "RcuHList: moved to itself");
            // SAFETY: `cur` and its successor are links of this chain;
            // `dst` is another chain under the same lock (`_o`), its
            // first link live. `cur` stays claimed throughout.
            unsafe {
                let next = (*cur).next();
                self.first.store(next, Release);
                if let Some(n) = next.as_ref() {
                    n.set_prev(null_mut());
                }
                let first = dst.first.load(Relaxed);
                // A reader standing on `cur` follows this into `dst`,
                // whose links were published initialized
                (*cur).publish_next(first);
                (*cur).set_prev(null_mut());
                if let Some(f) = first.as_ref() {
                    f.set_prev(cur);
                }
            }
            // INVARIANT: `cur` heads `dst` with the reference this chain
            // held
            dst.first.store(cur, Release);
        }
    }
}

impl<A: Adapter, O: UniqueOwner> Drop for RcuHList<A, O> {
    fn drop(&mut self) {
        let mut cur = *self.first.get_mut();
        while !cur.is_null() {
            // SAFETY: no reader or writer borrows the chain (`&mut`): its
            // links are live entries holding the chain's references
            unsafe {
                let next = (*cur).next();
                (*cur).reset();
                drop(Arc::from_raw(A::item(cur)));
                cur = next;
            }
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

    #[test]
    fn insert_at_positions() {
        let l = RcuList::<ItemLink>::new();
        // Into an empty list: either end
        l.insert_before(item(5), |_| true);
        l.insert_after(item(1), |_| false);
        assert_eq!(values(&l), [1, 5]);
        // Before the first entry above 2; after the last entry below 5
        l.insert_before(item(3), |i| i.v > 2);
        l.insert_after(item(4), |i| i.v < 5);
        assert_eq!(values(&l), [1, 3, 4, 5]);
        // No match: the tail, the head
        l.insert_before(item(9), |i| i.v > 100);
        l.insert_after(item(0), |i| i.v > 100);
        assert_eq!(values(&l), [0, 1, 3, 4, 5, 9]);
        assert_eq!(l.count(), 6);
        // The ends stay right: removing the tail, then appending
        drop(l.remove_first(|i| i.v == 9));
        l.push_back(item(7));
        drop(l.remove_first(|i| i.v == 0));
        l.insert_after(item(8), |i| i.v == 7);
        assert_eq!(values(&l), [1, 3, 4, 5, 7, 8]);
    }

    #[test]
    fn replace_in_place() {
        let l = RcuList::<ItemLink>::new();
        for v in 1..=3 {
            l.push_back(item(v));
        }
        let g = read_lock();
        let mut it = l.iter(&g);
        assert_eq!(it.next().map(|i| i.v), Some(1));
        assert_eq!(it.next().map(|i| i.v), Some(2));
        // The reader stands on 2 as 20 takes its place, and on 3 as 30
        // takes the tail's
        let old = l.replace(item(20), |i| i.v == 2).ok().unwrap();
        let tail = l.replace(item(30), |i| i.v == 3).ok().unwrap();
        assert_eq!(old.item().v, 2);
        assert_eq!(it.map(|i| i.v).collect::<Vec<_>>(), [3]);
        drop(g);
        assert_eq!(values(&l), [1, 20, 30]);
        assert_eq!(l.count(), 3);
        assert!(l.replace(item(4), |i| i.v == 99).is_err());
        drop((old, tail));
        // The tail is the replacement
        l.push_back(item(40));
        assert_eq!(values(&l), [1, 20, 30, 40]);
    }

    #[test]
    fn static_entries() {
        static A: Item = Item {
            v: 1,
            link: Link::new(),
        };
        static B: Item = Item {
            v: 2,
            link: Link::new(),
        };
        let l = RcuList::<ItemLink, &'static Item>::new();
        l.push_back(&B);
        l.insert_before(&A, |i| i.v == 2);
        let g = read_lock();
        assert_eq!(l.iter(&g).map(|i| i.v).collect::<Vec<_>>(), [1, 2]);
        drop(g);
        drop(l.remove_first(|i| i.v == 1));
        assert!(!A.link.is_linked());
        drop(l);
        assert!(!B.link.is_linked());
    }

    struct Owner;
    // SAFETY: each test makes one
    unsafe impl UniqueOwner for Owner {}

    #[test]
    fn hash_chain() {
        let mut o = Owner;
        let h = RcuHList::<ItemLink, Owner>::new();
        let a = item(1);
        h.push_front(a.clone(), &mut o);
        h.push_front(item(2), &mut o);
        h.push_front(item(3), &mut o);
        let g = read_lock();
        assert_eq!(h.iter(&g).map(|i| i.v).collect::<Vec<_>>(), [3, 2, 1]);
        let two = h.iter_ref(&g).find(|i| i.v == 2).unwrap().get();
        drop(g);
        assert_eq!(h.iter_locked(&o).count(), 3);
        // The middle, then the first
        let gone = h.remove_first(|i| i.v == 2, &mut o).unwrap();
        assert_eq!(gone.item().v, 2);
        assert_eq!(Arc::strong_count(&two), 2);
        drop(gone);
        assert_eq!(Arc::strong_count(&two), 1);
        drop(h.remove_first(|i| i.v == 3, &mut o));
        assert!(h.remove_first(|i| i.v == 3, &mut o).is_none());
        assert_eq!(h.iter_locked(&o).map(|i| i.v).collect::<Vec<_>>(), [1]);
        drop(h);
        assert_eq!(Arc::strong_count(&a), 1);
        assert!(!a.link.is_linked());
    }

    /// A rehash moves entries and their references between chains at
    /// once; a reader standing on one walks on into its new chain
    #[test]
    fn hash_chain_move() {
        let mut o = Owner;
        let old = RcuHList::<ItemLink, Owner>::new();
        let new = [RcuHList::new(), RcuHList::new()];
        let a = item(1);
        old.push_front(a.clone(), &mut o);
        for v in 2..=4 {
            old.push_front(item(v), &mut o);
        }
        new[1].push_front(item(9), &mut o);
        let g = read_lock();
        let mut it = old.iter(&g);
        assert_eq!(it.next().map(|i| i.v), Some(4));
        old.move_all(|i| &new[(i.v % 2) as usize], &mut o);
        // The reader had read 4 and stood at 3, which moved to the odd
        // chain: it walks on there
        assert_eq!(it.map(|i| i.v).collect::<Vec<_>>(), [3, 9]);
        drop(g);
        assert_eq!(old.iter_locked(&o).count(), 0);
        fn vals(h: &RcuHList<ItemLink, Owner>, o: &Owner) -> Vec<u32> {
            h.iter_locked(o).map(|i| i.v).collect()
        }
        assert_eq!(vals(&new[0], &o), [2, 4]);
        assert_eq!(vals(&new[1], &o), [1, 3, 9]);
        assert_eq!(Arc::strong_count(&a), 2);
        // The moved links stay usable: removal from the new chain
        drop(new[1].remove_first(|i| i.v == 3, &mut o));
        assert_eq!(vals(&new[1], &o), [1, 9]);
        drop(new);
        assert_eq!(Arc::strong_count(&a), 1);
    }
}
