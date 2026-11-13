//! Hash chains for lockless lookups, ended by a nulls marker (Linux
//! include/linux/list_nulls.h, rculist_nulls.h)
//!
//! A [`NullsHead`] is a bucket whose chain ends not in null but in a
//! "nulls" marker that carries a value, the bucket's (its index: Linux
//! INIT_HLIST_NULLS_HEAD(head, i)). Readers walk a chain under
//! [`rcu::read_lock`](crate::sync::rcu::read_lock) with no lock (Linux
//! hlist_nulls_for_each_entry_rcu); writers take the bucket's own spin
//! lock (Linux inet_ehash_lockp). Entries are linked through an
//! embedded [`NullsLink`] ([`nulls_adapter!`](crate::nulls_adapter)) and
//! the bucket owns a strong reference to each (`Arc::into_raw` on
//! insert, back on removal).
//!
//! An entry taken off keeps its `next`, so a reader standing on it
//! walks on (Linux hlist_nulls_del_init_rcu), and it may be hashed
//! again at once, into the same or another bucket, with no grace period
//! in between: that is what the marker is for. A reader standing on an
//! entry that moved follows it into the other chain and ends at a
//! different nulls value; a lookup that ends at a value other than its
//! bucket's may have skipped entries and starts over ([`find_rcu`],
//! Linux __inet_lookup_established's `get_nulls_value(node) != slot`).
//!
//! The bucket's reference to an entry taken off comes back as
//! [`NullsUnlinked`], dropped no earlier than a grace period later
//! (readers may still stand on the entry): [`NullsUnlinked::defer`]
//! hands it to `rcu::put_rcu`, [`NullsUnlinked::rehash`] gives it to a
//! bucket again. So any entry a reader reaches stays referenced while
//! its guard is held, and [`NullsRef::arc`] takes a reference safely.
//!
//! Ordering: an entry's `next` is written with Release before a Release
//! store publishes it (rcu_assign_pointer); every pointer a reader
//! follows is stored with Release and loaded with Acquire
//! (rcu_dereference).
//!
//! [`find_rcu`]: NullsHead::find_rcu

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, Ordering::Acquire, Ordering::Relaxed, Ordering::Release};

use crate::sync::rcu::{HasRcuPuts, RcuReadGuard, put_rcu, synchronize};
use crate::sync::spin::{Mutex, MutexGuard};
use crate::util::error::KernelError;

/// The marker ending a chain whose value is `v` (Linux
/// INIT_HLIST_NULLS_HEAD: `(v << 1) | 1`): bit 0 set, never a link's
/// address (links are pointer aligned)
const fn nulls(v: usize) -> *mut NullsLink {
    core::ptr::without_provenance_mut((v << 1) | 1)
}

/// `p` ends a chain (Linux is_a_nulls)
fn is_a_nulls(p: *const NullsLink) -> bool {
    p.addr() & 1 != 0
}

/// The value of the marker `p` (Linux get_nulls_value)
fn get_nulls_value(p: *const NullsLink) -> usize {
    p.addr() >> 1
}

/// The `pprev` of a link one insert has claimed, before it is linked
/// (never a pointer's address)
const CLAIMED: *mut AtomicPtr<NullsLink> = core::ptr::dangling_mut();

/// The chain hook embedded in an item (Linux struct hlist_nulls_node)
///
/// # Invariants
/// `pprev` is null while the link is in no chain (Linux
/// hlist_nulls_unhashed), `CLAIMED` while one insert owns it, and
/// otherwise the address of the pointer to it (its bucket's `first` or
/// the previous link's `next`). While hashed, `next` is the following
/// link or the chain's nulls marker; unhashed, it keeps its last value
/// for readers standing on the link.
pub struct NullsLink {
    next: AtomicPtr<NullsLink>,
    pprev: AtomicPtr<AtomicPtr<NullsLink>>,
    /// The `first` of the bucket it is in (null: none), so removal
    /// checks membership with no walk; written under that bucket's lock
    bucket: AtomicPtr<AtomicPtr<NullsLink>>,
}

impl Default for NullsLink {
    fn default() -> Self {
        Self::new()
    }
}

impl NullsLink {
    pub const fn new() -> Self {
        Self {
            next: AtomicPtr::new(nulls(0)),
            pprev: AtomicPtr::new(null_mut()),
            bucket: AtomicPtr::new(null_mut()),
        }
    }

    /// In a chain (Linux !hlist_nulls_unhashed)
    pub fn is_hashed(&self) -> bool {
        !self.pprev.load(Relaxed).is_null()
    }

    /// Claim an unhashed link for an insert: false if it is hashed or
    /// being hashed (two buckets under different locks cannot both win;
    /// Acquire pairs with the Release that unhashed it)
    fn claim(&self) -> bool {
        self.pprev
            .compare_exchange(null_mut(), CLAIMED, Acquire, Relaxed)
            .is_ok()
    }
}

/// Maps a table's items to their [`NullsLink`] and back
///
/// # Safety
/// `link` and `item` must be inverse: `item(link(x)) == x`.
pub unsafe trait NullsAdapter {
    type Item;
    fn link(item: &Self::Item) -> &NullsLink;
    /// # Safety
    /// `link` is the link of a live `Item`.
    unsafe fn item(link: *const NullsLink) -> *const Self::Item;
}

/// `nulls_adapter!(vis Name, Type, field)`: a [`NullsAdapter`] for
/// `Type.field`. Its own trait, not `util::list::Adapter`: a
/// `list::Link` never holds a tagged pointer and marks "unlinked" in
/// `next`, which a nulls link keeps after removal.
#[macro_export]
macro_rules! nulls_adapter {
    ($vis:vis $name:ident, $t:ty, $($field:ident).+) => {
        $vis struct $name;
        // SAFETY: offset_of! gives the field's place in the item
        unsafe impl $crate::util::hlist_nulls::NullsAdapter for $name {
            type Item = $t;
            fn link(item: &$t) -> &$crate::util::hlist_nulls::NullsLink {
                &item.$($field).+
            }
            unsafe fn item(link: *const $crate::util::hlist_nulls::NullsLink) -> *const $t {
                // SAFETY: the caller passes a link inside a live item
                unsafe { link.cast::<u8>().sub(core::mem::offset_of!($t, $($field).+)).cast::<$t>() }
            }
        }
    };
}

/// A bucket (Linux struct hlist_nulls_head, with its inet_ehash_lockp
/// lock beside it)
///
/// # Invariants
/// From `first` through `next` run the links of live items, ending in
/// `nulls(nulls)`; each was hashed with `Arc::into_raw` (the bucket
/// holds that reference) and its `pprev` is the address of the pointer
/// to it. The chain changes only under `lock`. The reference of an
/// entry taken off is dropped no earlier than a grace period after
/// (`NullsUnlinked`), so every link a reader reaches is live while its
/// guard is held.
pub struct NullsHead<A: NullsAdapter> {
    first: AtomicPtr<NullsLink>,
    nulls: usize,
    /// Writers' lock; one lockdep class for every bucket (built here),
    /// and two are never held at once
    lock: Mutex<()>,
    /// It drops `Arc<Item>`s wherever it goes: Send/Sync as Arc's
    _owns: PhantomData<Arc<A::Item>>,
}

impl<A: NullsAdapter> NullsHead<A> {
    /// An empty bucket ending at `nulls` (Linux INIT_HLIST_NULLS_HEAD);
    /// `nulls` < 2^63
    pub const fn new(nulls: usize) -> Self {
        assert!(nulls <= usize::MAX >> 1, "hlist_nulls: value too large");
        Self {
            first: AtomicPtr::new(self::nulls(nulls)),
            nulls,
            lock: Mutex::new(()),
            _owns: PhantomData,
        }
    }

    /// `n` empty buckets, each ending at its index (Linux
    /// inet_ehash_init's loop over INIT_HLIST_NULLS_HEAD(.., i))
    pub fn table(n: usize) -> Result<Box<[Self]>, KernelError> {
        let mut v = Vec::new();
        v.try_reserve_exact(n)
            .map_err(|_| KernelError::OutOfMemory)?;
        v.extend((0..n).map(Self::new));
        Ok(v.into_boxed_slice())
    }

    /// The value this bucket's chain ends at
    pub fn nulls(&self) -> usize {
        self.nulls
    }

    /// Take the bucket's lock (Linux spin_lock(inet_ehash_lockp)):
    /// thread context, never with another bucket's held
    #[track_caller]
    pub fn lock(&self) -> NullsGuard<'_, A> {
        NullsGuard {
            head: self,
            _lock: self.lock.lock(),
        }
    }

    /// The chain, valid while `g` is held (Linux
    /// hlist_nulls_for_each_entry_rcu): an entry added meanwhile may or
    /// may not be seen, one removed may still be, and a walk that
    /// followed a moved entry ends in another chain (`ended_at`)
    pub fn iter_rcu<'a>(&'a self, _g: &'a RcuReadGuard) -> NullsIter<'a, A> {
        NullsIter {
            cur: self.first.load(Acquire),
            end: None,
            _l: PhantomData,
        }
    }

    /// The first entry `pred` accepts, walking again while a walk ends
    /// at another bucket's nulls value (Linux __inet_lookup_established:
    /// `if (get_nulls_value(node) != slot) goto begin`). The bucket's
    /// own value is the expected one, so a lookup cannot be pointed at
    /// a value no walk of this chain ever reaches.
    pub fn find_rcu<'a>(
        &'a self,
        g: &'a RcuReadGuard,
        mut pred: impl FnMut(&A::Item) -> bool,
    ) -> Option<NullsRef<'a, A>> {
        loop {
            let mut it = self.iter_rcu(g);
            if let Some(e) = it.find(|e| pred(e.get())) {
                return Some(e);
            }
            if it.ended_at() == Some(self.nulls) {
                return None;
            }
        }
    }
}

impl<A: NullsAdapter> Drop for NullsHead<A> {
    /// Unhash every entry and drop its reference; with entries, after a
    /// grace period: a reader of another bucket may stand on one (it
    /// followed an entry that moved in or out), so this sleeps, and
    /// panics in atomic context, unless the bucket is empty
    fn drop(&mut self) {
        if is_a_nulls(*self.first.get_mut()) {
            return;
        }
        synchronize();
        let mut cur = core::mem::replace(self.first.get_mut(), nulls(self.nulls));
        while !is_a_nulls(cur) {
            // SAFETY: a link of this bucket, borrowed `&mut` (no writer;
            // the grace period: no reader), its item live and holding
            // the bucket's reference (type invariant)
            unsafe {
                let next = (*cur).next.load(Relaxed);
                (*cur).bucket.store(null_mut(), Relaxed);
                (*cur).pprev.store(null_mut(), Release);
                drop(Arc::from_raw(A::item(cur)));
                cur = next;
            }
        }
    }
}

/// A locked bucket: releases the lock when dropped
#[must_use]
pub struct NullsGuard<'a, A: NullsAdapter> {
    head: &'a NullsHead<A>,
    _lock: MutexGuard<'a, ()>,
}

impl<A: NullsAdapter> NullsGuard<'_, A> {
    fn link(item: &A::Item) -> *mut NullsLink {
        core::ptr::from_ref(A::link(item)).cast_mut()
    }

    /// The link after `l`
    fn next(l: *mut NullsLink) -> *mut NullsLink {
        // SAFETY: `l` is a link of this bucket, live while hashed (type
        // invariant), and the lock is held
        unsafe { (*l).next.load(Relaxed) }
    }

    /// `item`'s link if it is in this bucket, by a walk (a debug check
    /// of `bucket`)
    fn find_link(&self, item: &A::Item) -> Option<*mut NullsLink> {
        let want = Self::link(item);
        let mut l = self.head.first.load(Relaxed);
        while !is_a_nulls(l) {
            if l == want {
                return Some(l);
            }
            l = Self::next(l);
        }
        None
    }

    /// Hash `item` at the head (Linux hlist_nulls_add_head_rcu); panics
    /// if it is hashed. An item taken off may come back at once, here
    /// or in another bucket: a reader standing on it walks on into this
    /// chain and ends at this bucket's nulls value.
    pub fn add_head_rcu(&mut self, item: Arc<A::Item>) {
        let n = A::link(&item);
        assert!(n.claim(), "hlist_nulls: item already hashed");
        let h = &self.head.first;
        let first = h.load(Relaxed);
        // A reader standing on `n` (it was in a chain) sees `first`
        // initialized
        n.next.store(first, Release);
        // INVARIANT: claimed above; it heads the chain once published
        n.pprev.store(core::ptr::from_ref(h).cast_mut(), Relaxed);
        n.bucket.store(core::ptr::from_ref(h).cast_mut(), Relaxed);
        let next = core::ptr::from_ref(&n.next).cast_mut();
        let n = core::ptr::from_ref(n).cast_mut();
        // INVARIANT: the bucket keeps the item's reference
        let _ = Arc::into_raw(item);
        h.store(n, Release);
        if !is_a_nulls(first) {
            // SAFETY: the old first link of this bucket, live, the lock
            // held; `n`'s `next` now points at it
            unsafe { (*first).pprev.store(next, Relaxed) };
        }
    }

    /// Unhash `item` (Linux hlist_nulls_del_init_rcu), keeping its
    /// `next` for readers standing on it, and hand back the bucket's
    /// reference; None if it is not in this bucket. O(1): the link
    /// names its bucket (Linux trusts the caller instead).
    pub fn del_rcu(&mut self, item: &A::Item) -> Option<NullsUnlinked<A>> {
        let l = A::link(item);
        // Set under this bucket's lock when hashed here, cleared under
        // it when unhashed: held now, so it cannot change meanwhile
        if l.bucket.load(Relaxed) != core::ptr::from_ref(&self.head.first).cast_mut() {
            debug_assert!(self.find_link(item).is_none());
            return None;
        }
        debug_assert!(self.find_link(item).is_some());
        let n = Self::link(item);
        // SAFETY: `n` is a link of this bucket (its `bucket` says so) and `pprev`
        // the pointer to it, in this bucket's head or a link of it, all
        // live, the lock held (type invariant)
        unsafe {
            let next = (*n).next.load(Relaxed);
            let pprev = (*n).pprev.load(Relaxed);
            (*pprev).store(next, Release);
            if !is_a_nulls(next) {
                (*next).pprev.store(pprev, Relaxed);
            }
            // INVARIANT: unhashed, `next` kept; Release pairs with the
            // next insert's claim
            (*n).bucket.store(null_mut(), Relaxed);
            (*n).pprev.store(null_mut(), Release);
        }
        // SAFETY: hashed by `add_head_rcu`'s `into_raw`, whose reference
        // the bucket held until now
        let a = unsafe { Arc::from_raw(core::ptr::from_ref(item)) };
        Some(NullsUnlinked(Some(a), PhantomData))
    }

    /// The first entry `pred` accepts, as a new reference: one walk of
    /// the chain, under the lock
    pub fn find(&self, pred: impl Fn(&A::Item) -> bool) -> Option<Arc<A::Item>> {
        let mut l = self.head.first.load(Relaxed);
        while !is_a_nulls(l) {
            // SAFETY: a link of this bucket, inside a live item (type
            // invariant), the lock held
            let item = unsafe { &*A::item(l) };
            if pred(item) {
                // SAFETY: hashed, so the bucket holds a reference
                return Some(unsafe { arc_ref(item) });
            }
            l = Self::next(l);
        }
        None
    }
}

/// A new reference to an entry
///
/// # Safety
/// `it` is in an `Arc` that stays referenced meanwhile: an entry of a
/// [`NullsHead`] reached under its lock, or under a read guard (the
/// bucket's reference outlives the guard: type invariant).
unsafe fn arc_ref<T>(it: &T) -> Arc<T> {
    let p = core::ptr::from_ref::<T>(it);
    // SAFETY: the caller's reference keeps the Arc alive
    unsafe {
        Arc::increment_strong_count(p);
        Arc::from_raw(p)
    }
}

/// An entry reached under a read guard: the item, and a reference to
/// it taken safely ([`NullsRef::arc`])
pub struct NullsRef<'a, A: NullsAdapter> {
    item: &'a A::Item,
    _a: PhantomData<fn() -> A>,
}

impl<A: NullsAdapter> Clone for NullsRef<'_, A> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<A: NullsAdapter> Copy for NullsRef<'_, A> {}

impl<'a, A: NullsAdapter> NullsRef<'a, A> {
    /// The item, for the guard's lifetime
    pub fn get(&self) -> &'a A::Item {
        self.item
    }

    /// A new reference to the item (Linux refcount_inc_not_zero after
    /// the lookup; never zero here: the entry is referenced by a bucket
    /// or by a `NullsUnlinked` until a grace period after the guard)
    pub fn arc(&self) -> Arc<A::Item> {
        // SAFETY: reached from a bucket under the read guard `'a`
        // borrows (NullsHead::iter_rcu): referenced until it ends
        unsafe { arc_ref(self.item) }
    }
}

impl<A: NullsAdapter> core::ops::Deref for NullsRef<'_, A> {
    type Target = A::Item;
    fn deref(&self) -> &A::Item {
        self.item
    }
}

/// A walk of a chain under a read guard ([`NullsHead::iter_rcu`])
pub struct NullsIter<'a, A: NullsAdapter> {
    cur: *mut NullsLink,
    /// The nulls value the walk ended at
    end: Option<usize>,
    _l: PhantomData<(&'a NullsHead<A>, &'a RcuReadGuard)>,
}

impl<A: NullsAdapter> NullsIter<'_, A> {
    /// The nulls value the walk ended at, None before its end: another
    /// bucket's means it followed a moved entry and may have skipped
    /// entries of its own chain (Linux get_nulls_value(node))
    pub fn ended_at(&self) -> Option<usize> {
        self.end
    }
}

impl<'a, A: NullsAdapter> Iterator for NullsIter<'a, A> {
    type Item = NullsRef<'a, A>;
    fn next(&mut self) -> Option<NullsRef<'a, A>> {
        if is_a_nulls(self.cur) {
            self.end = Some(get_nulls_value(self.cur));
            return None;
        }
        // SAFETY: a link reached from a bucket under the guard: its item
        // stays allocated until a grace period after it was unhashed
        // (NullsHead invariant)
        let item = unsafe { &*A::item(self.cur) };
        // SAFETY: as above (an unhashed link keeps its `next`)
        self.cur = unsafe { (*self.cur).next.load(Acquire) };
        Some(NullsRef {
            item,
            _a: PhantomData,
        })
    }
}

/// An entry taken off a bucket, with the bucket's reference, which must
/// outlive every reader that may stand on the entry. Dropped, it waits
/// for a grace period first (Linux synchronize_rcu; it panics in atomic
/// context, where `defer` is the way).
#[must_use]
pub struct NullsUnlinked<A: NullsAdapter>(Option<Arc<A::Item>>, PhantomData<fn() -> A>);

impl<A: NullsAdapter> NullsUnlinked<A> {
    /// The entry
    pub fn item(&self) -> &A::Item {
        self.0.as_deref().expect("NullsUnlinked: taken")
    }

    /// Hash it again at once, in `g`'s bucket (Linux
    /// hlist_nulls_add_head_rcu right after the del): the reference
    /// stays held, so no grace period is needed; panics if the entry
    /// was hashed again meanwhile
    pub fn rehash(mut self, g: &mut NullsGuard<'_, A>) {
        if let Some(a) = self.0.take() {
            g.add_head_rcu(a);
        }
    }
}

impl<A: NullsAdapter> NullsUnlinked<A>
where
    A::Item: HasRcuPuts + Send + Sync,
{
    /// Drop the reference a grace period from now without waiting
    /// (`rcu::put_rcu`): any context. The entry may be hashed again
    /// meanwhile. The drop runs in `rcuc/N`, preemption off, so the
    /// item's last drop must not sleep.
    pub fn defer(mut self) {
        if let Some(a) = self.0.take() {
            put_rcu(a);
        }
    }
}

impl<A: NullsAdapter> Drop for NullsUnlinked<A> {
    fn drop(&mut self) {
        if let Some(a) = self.0.take() {
            synchronize();
            drop(a);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::rcu::{RcuPuts, read_lock};
    use crate::util::kalloc::arc_nofail;

    struct Item {
        v: u32,
        link: NullsLink,
        puts: RcuPuts,
    }
    crate::nulls_adapter!(ItemAdapter, Item, link);
    crate::rcu_puts!(Item, puts);

    type Head = NullsHead<ItemAdapter>;

    fn item(v: u32) -> Arc<Item> {
        arc_nofail(Item {
            v,
            link: NullsLink::new(),
            puts: RcuPuts::new(),
        })
    }

    /// The values of `h`'s chain and the nulls value the walk ended at
    fn walk(h: &Head) -> (Vec<u32>, Option<usize>) {
        let g = read_lock();
        let mut it = h.iter_rcu(&g);
        let v = it.by_ref().map(|i| i.v).collect();
        (v, it.ended_at())
    }

    /// Entries come back newest first; a deleted one is gone with its
    /// reference handed back, one not there is None; each bucket of a
    /// table ends at its index
    #[test]
    fn add_find_del() {
        let t = Head::table(4).unwrap();
        assert_eq!(walk(&t[2]), (Vec::new(), Some(2)));
        let (a, b, c) = (item(1), item(2), item(3));
        let mut g = t[3].lock();
        for i in [&a, &b, &c] {
            g.add_head_rcu(i.clone());
        }
        assert_eq!(g.find(|i| i.v < 3).unwrap().v, 2);
        assert!(t[1].lock().del_rcu(&b).is_none());
        let gone = g.del_rcu(&b).unwrap();
        assert_eq!(gone.item().v, 2);
        assert!(!b.link.is_hashed());
        assert!(g.del_rcu(&b).is_none());
        drop(g);
        drop(gone);
        assert_eq!(Arc::strong_count(&b), 1);
        assert_eq!(walk(&t[3]), (alloc::vec![3, 1], Some(3)));
        let r = read_lock();
        let found = t[3].find_rcu(&r, |i| i.v == 1).unwrap().arc();
        assert!(Arc::ptr_eq(&found, &a));
        assert!(t[3].find_rcu(&r, |i| i.v == 2).is_none());
        drop(r);
        // Deleting the head and tail of a chain keeps it whole
        drop(t[3].lock().del_rcu(&c));
        assert_eq!(walk(&t[3]), (alloc::vec![1], Some(3)));
        drop(t[3].lock().del_rcu(&a));
        assert_eq!(walk(&t[3]), (Vec::new(), Some(3)));
    }

    /// A reader standing on an entry that moves to another bucket walks
    /// on into that chain and ends at its nulls value
    #[test]
    fn reader_follows_moved_entry() {
        let (a, b) = (Head::new(0), Head::new(1));
        let (x, y, z) = (item(1), item(2), item(3));
        a.lock().add_head_rcu(x.clone());
        a.lock().add_head_rcu(y.clone());
        b.lock().add_head_rcu(z.clone());
        let g = read_lock();
        let mut it = a.iter_rcu(&g);
        // Standing on y, whose next (x) is loaded
        assert_eq!(it.next().map(|i| i.v), Some(2));
        // x moves to b at once, no grace period
        let gone = a.lock().del_rcu(&x).unwrap();
        gone.rehash(&mut b.lock());
        assert_eq!(it.by_ref().map(|i| i.v).collect::<Vec<_>>(), [1, 3]);
        assert_eq!(it.ended_at(), Some(1));
        drop(g);
        assert_eq!(walk(&a), (alloc::vec![2], Some(0)));
        assert_eq!(walk(&b), (alloc::vec![1, 3], Some(1)));
    }

    /// A lookup that followed a moved entry out of its chain without a
    /// match starts over; one that matched on the way keeps the match
    #[test]
    fn find_rcu_restarts() {
        let (a, b) = (Head::new(0), Head::new(1));
        let (x, y) = (item(1), item(2));
        a.lock().add_head_rcu(x.clone());
        a.lock().add_head_rcu(y.clone());
        // Visiting y first moves x (y's next) to b, then 1 <-> 0 back
        let mut calls = Vec::new();
        let g = read_lock();
        let found = a.find_rcu(&g, |i| {
            calls.push(i.v);
            if calls.len() == 1 {
                a.lock().del_rcu(&x).unwrap().rehash(&mut b.lock());
            }
            i.v == 9
        });
        assert!(found.is_none());
        // Walk 1: y, x (now in b), end at 1: again. Walk 2: y, end at 0
        assert_eq!(calls, [2, 1, 2]);
        // Moving x back and searching it: found on the first walk,
        // though in another chain by then
        let found = b.find_rcu(&g, |i| {
            if i.v == 1 {
                b.lock().del_rcu(&x).unwrap().rehash(&mut a.lock());
            }
            i.v == 1
        });
        assert!(Arc::ptr_eq(&found.unwrap().arc(), &x));
        drop(g);
        assert_eq!(walk(&a), (alloc::vec![1, 2], Some(0)));
    }

    /// An entry taken off may be hashed again at once; while hashed,
    /// a second add panics
    #[test]
    fn readd_after_del() {
        let a = Head::new(0);
        let x = item(1);
        a.lock().add_head_rcu(x.clone());
        let gone = a.lock().del_rcu(&x).unwrap();
        a.lock().add_head_rcu(x.clone());
        assert_eq!(walk(&a), (alloc::vec![1], Some(0)));
        drop(gone);
        assert_eq!(Arc::strong_count(&x), 2);
    }

    #[test]
    #[should_panic(expected = "already hashed")]
    fn double_add_panics() {
        let (a, b) = (Head::new(0), Head::new(1));
        let x = item(1);
        a.lock().add_head_rcu(x.clone());
        b.lock().add_head_rcu(x);
    }

    /// Dropping buckets releases every reference and unhashes the links
    #[test]
    fn drop_releases_entries() {
        let (x, y) = (item(1), item(2));
        {
            let t = Head::table(2).unwrap();
            t[0].lock().add_head_rcu(x.clone());
            t[0].lock().add_head_rcu(y.clone());
            assert_eq!(Arc::strong_count(&x), 2);
        }
        assert_eq!((Arc::strong_count(&x), Arc::strong_count(&y)), (1, 1));
        assert!(!x.link.is_hashed() && !y.link.is_hashed());
    }

    /// The marker keeps its value and never looks like a link
    #[test]
    fn nulls_marker() {
        let m = nulls(usize::MAX >> 1);
        assert!(is_a_nulls(m) && get_nulls_value(m) == usize::MAX >> 1);
        assert!(!is_a_nulls(core::ptr::from_ref(&NullsLink::new())));
    }
}
