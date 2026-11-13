//! RCU-protected hash chains (Linux include/linux/rculist.h, the
//! hlist_*_rcu half: hlist_add_head_rcu, hlist_del_init_rcu,
//! hlist_for_each_entry_rcu)
//!
//! An [`RcuHList`] is one hash chain: a head pointer to the first
//! [`HNode`], each node with `next` and `pprev` (the address of the
//! pointer that points at it: the head's `first` or the previous node's
//! `next`), so unlinking needs no walk. The chain owns a strong
//! reference to each entry (Linux sk_add_node_rcu's sock_hold).
//! Readers walk it under an [`RcuReadGuard`] with no lock (Acquire loads
//! of `next`, Linux rcu_dereference). A chain has no lock of its own:
//! its writers prove they hold the lock that owns it by borrowing that
//! lock's unique data (`sync::UniqueOwner`), as Linux leaves chain
//! writes to the table's lock (ping_table.lock, tbl->lock,
//! fnhe_lock), so a table of chains costs one pointer each.
//!
//! Removal is Linux hlist_del_init_rcu: the node keeps `next` for a
//! reader standing on it and is free for a new insert at once (`pprev`
//! null), so an entry can leave its chain and join another at once
//! (disconnect, then bind again; a hash table growing). A reader
//! standing on it may then follow it into its new chain: lookups
//! recheck their key on every entry, as Linux's do. Each node records
//! the chain it is on, so a removal proves membership in O(1). The
//! chain's reference comes back as an [`RcuHRef`], released a grace
//! period later (Linux SOCK_RCU_FREE, kfree_rcu: the entry's memory
//! outlives every reader that may stand on it), never at once.
//!
//! # The deferred release contract (doc/UNSAFE.md)
//!
//! An entry's last reference may be the one an [`RcuHRef`] releases in
//! `rcuc/N` with preemption off: the entry's `Drop` (and every drop it
//! causes) must not sleep and allocates only with a GFP named.

use alloc::sync::Arc;
use core::marker::PhantomData;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, Ordering::Acquire, Ordering::Relaxed, Ordering::Release};

use crate::sync::UniqueOwner;
use crate::sync::rcu::{HasRcuPuts, RcuReadGuard, put_rcu};
use crate::util::rculist::RcuRef;

/// A chain link embedded in an entry (Linux struct hlist_node)
///
/// # Invariants
/// `pprev` is null exactly when the node is on no chain (Linux
/// hlist_unhashed); `head` is the `first` of the chain it is on (null:
/// none). Both change only under the lock owning that chain.
pub struct HNode {
    next: AtomicPtr<HNode>,
    pprev: AtomicPtr<AtomicPtr<HNode>>,
    /// The chain it is on, so removal checks membership
    head: AtomicPtr<AtomicPtr<HNode>>,
}

impl HNode {
    pub const fn new() -> Self {
        Self {
            next: AtomicPtr::new(null_mut()),
            pprev: AtomicPtr::new(null_mut()),
            head: AtomicPtr::new(null_mut()),
        }
    }

    /// On a chain now (Linux !hlist_unhashed): a hint unless the
    /// chain's lock is held
    pub fn is_hashed(&self) -> bool {
        !self.pprev.load(Relaxed).is_null()
    }
}

impl Default for HNode {
    fn default() -> Self {
        Self::new()
    }
}

/// Maps a chain's entries to their [`HNode`] and back
///
/// # Safety
/// `node` and `item` must be inverse: `item(node(x)) == x`.
pub unsafe trait HAdapter {
    type Item;
    fn node(item: &Self::Item) -> &HNode;
    /// # Safety
    /// `node` is the node of a live `Item`.
    unsafe fn item(node: *const HNode) -> *const Self::Item;
}

/// `hadapter!(vis Name, Type, field)`: an [`HAdapter`] for `Type.field`
#[macro_export]
macro_rules! hadapter {
    ($vis:vis $name:ident, $t:ty, $field:ident) => {
        $vis struct $name;
        // SAFETY: offset_of! gives the field's place in the item
        unsafe impl $crate::util::rcuhlist::HAdapter for $name {
            type Item = $t;
            fn node(item: &$t) -> &$crate::util::rcuhlist::HNode {
                &item.$field
            }
            unsafe fn item(node: *const $crate::util::rcuhlist::HNode) -> *const $t {
                // SAFETY: the caller passes a node inside a live item
                unsafe { node.cast::<u8>().sub(core::mem::offset_of!($t, $field)).cast::<$t>() }
            }
        }
    };
}

/// Marks a chain as belonging to `O`'s lock, without owning an `O`
type Owned<O> = fn(&O);

/// One RCU hash chain of `Arc<A::Item>` (Linux hlist_head with the _rcu
/// operations) whose writers hold the lock that owns `O`, passing its
/// one value, borrowed mutably, as proof
///
/// # Invariants
/// From `first` through `next` are the nodes of the live items on the
/// chain, each inserted with `Arc::into_raw` (the chain's reference),
/// with `pprev` pointing at the pointer that points at it and `head` at
/// `first`. Nodes change only under a mutable borrow of the one `O`. A
/// node taken off keeps its item allocated until a grace period after
/// that (`RcuHRef`).
pub struct RcuHList<A: HAdapter, O: UniqueOwner> {
    first: AtomicPtr<HNode>,
    _owns: PhantomData<(Arc<A::Item>, Owned<O>)>,
}

// SAFETY: it holds `Arc<Item>`s and hands out `&Item` to any thread
unsafe impl<A: HAdapter, O: UniqueOwner> Send for RcuHList<A, O> where A::Item: Send + Sync {}
// SAFETY: as above; writers serialize on `O`'s lock, readers only load
unsafe impl<A: HAdapter, O: UniqueOwner> Sync for RcuHList<A, O> where A::Item: Send + Sync {}

impl<A: HAdapter, O: UniqueOwner> Default for RcuHList<A, O> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: HAdapter, O: UniqueOwner> RcuHList<A, O> {
    pub const fn new() -> Self {
        Self {
            first: AtomicPtr::new(null_mut()),
            _owns: PhantomData,
        }
    }

    fn first_ptr(&self) -> *mut AtomicPtr<HNode> {
        core::ptr::from_ref(&self.first).cast_mut()
    }

    fn np(item: &A::Item) -> *mut HNode {
        core::ptr::from_ref(A::node(item)).cast_mut()
    }

    /// The entries, first to last, valid while `g` is held (Linux
    /// hlist_for_each_entry_rcu): one added meanwhile may or may not be
    /// seen, one removed may still be, or lead into another chain
    pub fn iter<'a>(&'a self, _g: &'a RcuReadGuard) -> RcuHIter<'a, A> {
        RcuHIter {
            cur: self.first.load(Acquire),
            _l: PhantomData,
        }
    }

    /// The entries as [`RcuRef`]s, valid while `g` is held
    pub fn iter_ref<'a>(&'a self, g: &'a RcuReadGuard) -> RcuHRefIter<'a, A> {
        RcuHRefIter(self.iter(g))
    }

    /// The entries as their writer sees them, its lock held (`_o`):
    /// none can leave meanwhile (Linux sk_for_each under the table
    /// lock)
    pub fn iter_locked<'a>(&'a self, _o: &'a O) -> RcuHRefIter<'a, A> {
        RcuHRefIter(RcuHIter {
            cur: self.first.load(Relaxed),
            _l: PhantomData,
        })
    }

    /// Link `item` first (Linux hlist_add_head_rcu); panics if it is on
    /// a chain
    pub fn add_head(&self, item: Arc<A::Item>, _o: &mut O) {
        let n = A::node(&item);
        assert!(!n.is_hashed(), "RcuHList: item already hashed");
        let first = self.first.load(Relaxed);
        let np = Self::np(&item);
        // A reader standing on `n` (it was on a chain) sees `first`
        // initialized
        n.next.store(first, Release);
        n.pprev.store(self.first_ptr(), Relaxed);
        n.head.store(self.first_ptr(), Relaxed);
        // Published after its fields (rcu_assign_pointer)
        self.first.store(np, Release);
        // SAFETY: `first` is a node of this chain (type invariant), its
        // fields changed only under `O`'s lock (`_o`)
        if let Some(f) = unsafe { first.as_ref() } {
            f.pprev
                .store(core::ptr::from_ref(&n.next).cast_mut(), Relaxed);
        }
        // INVARIANT: linked first, holding the into_raw reference
        let _ = Arc::into_raw(item);
    }

    /// Unlink `item` (Linux hlist_del_init_rcu): its node is free for a
    /// new insert at once and keeps `next` for readers on it; the
    /// chain's reference comes back, to release after a grace period.
    /// None if it is not on this chain.
    #[must_use]
    pub fn del_init(&self, item: &A::Item, _o: &mut O) -> Option<RcuHRef<A>> {
        let n = A::node(item);
        if n.head.load(Relaxed) != self.first_ptr() || !n.is_hashed() {
            return None;
        }
        let next = n.next.load(Relaxed);
        let pprev = n.pprev.load(Relaxed);
        // SAFETY: on this chain (its head says so, under `O`'s lock):
        // `pprev` points at the pointer to it, in `first` or a live
        // node, and `next` is a live node of the chain or null
        unsafe {
            (*pprev).store(next, Release);
            if let Some(nx) = next.as_ref() {
                nx.pprev.store(pprev, Relaxed);
            }
        }
        // INVARIANT: off the chain, `next` kept for readers on it
        n.pprev.store(null_mut(), Relaxed);
        n.head.store(null_mut(), Relaxed);
        // SAFETY: the reference the chain took with into_raw
        let arc = unsafe { Arc::from_raw(core::ptr::from_ref(item)) };
        Some(RcuHRef(Some(arc), PhantomData))
    }

    /// Unlink the first entry `f` accepts (a walk, then
    /// [`del_init`](Self::del_init))
    #[must_use]
    pub fn remove_first(
        &self,
        mut f: impl FnMut(&A::Item) -> bool,
        o: &mut O,
    ) -> Option<RcuHRef<A>> {
        let p = self
            .iter_locked(o)
            .find(|e| f(e))
            .map(|e| core::ptr::from_ref(e.item()))?;
        // SAFETY: an entry of this chain, which holds a reference to it
        // while `O`'s lock is held (no writer can run meanwhile)
        self.del_init(unsafe { &*p }, o)
    }

    /// Move every entry, with its reference, to the head of the chain
    /// `to` picks for it, with no grace period in between (Linux
    /// neigh_hash_grow: hlist_del_rcu, then hlist_add_head_rcu of the
    /// same node into the new table). A reader standing on a moved
    /// entry walks on into its new chain: it may miss entries, but
    /// every node it reaches is live. Panics if `to` picks this chain.
    pub fn move_all<'b>(&self, mut to: impl FnMut(&A::Item) -> &'b Self, o: &mut O)
    where
        Self: 'b,
    {
        loop {
            let cur = self.first.load(Relaxed);
            if cur.is_null() {
                return;
            }
            // SAFETY: the first node of this chain, live (invariant;
            // `O`'s lock held), its reference moved below
            let item = unsafe { &*A::item(cur) };
            let dst = to(item);
            assert!(!core::ptr::eq(dst, self), "RcuHList: moved to itself");
            // The chain's reference moves with the node
            let a = self
                .del_init(item, o)
                .expect("RcuHList: first not on chain");
            dst.add_head(a.into_arc(), o);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.first.load(Relaxed).is_null()
    }
}

impl<A: HAdapter, O: UniqueOwner> Drop for RcuHList<A, O> {
    fn drop(&mut self) {
        let mut cur = *self.first.get_mut();
        // SAFETY: no reader or writer borrows the chain (`&mut`): its
        // nodes are live entries holding the chain's references
        while let Some(n) = unsafe { cur.as_ref() } {
            let next = n.next.load(Relaxed);
            n.pprev.store(null_mut(), Relaxed);
            n.head.store(null_mut(), Relaxed);
            // SAFETY: the chain's into_raw reference, taken back once
            drop(unsafe { Arc::from_raw(A::item(cur)) });
            cur = next;
        }
    }
}

/// Iterator over an [`RcuHList`] under a read guard (or its writers'
/// lock)
pub struct RcuHIter<'a, A: HAdapter> {
    cur: *mut HNode,
    _l: PhantomData<&'a A::Item>,
}

impl<'a, A: HAdapter> Iterator for RcuHIter<'a, A> {
    type Item = &'a A::Item;
    fn next(&mut self) -> Option<&'a A::Item> {
        // SAFETY: a node reached from a chain under the guard: its item
        // stays allocated until a grace period after it left any chain
        let n = unsafe { self.cur.as_ref() }?;
        // SAFETY: as above
        let item = unsafe { &*A::item(self.cur) };
        self.cur = n.next.load(Acquire);
        Some(item)
    }
}

/// An [`RcuHIter`] handing out [`RcuRef`]s
pub struct RcuHRefIter<'a, A: HAdapter>(RcuHIter<'a, A>);

impl<'a, A: HAdapter> Iterator for RcuHRefIter<'a, A> {
    type Item = RcuRef<'a, A::Item>;
    fn next(&mut self) -> Option<Self::Item> {
        // SAFETY: an entry of a chain reached under its guard (or its
        // writers' lock): the chain's `Arc::into_raw` reference, or its
        // deferred one (`RcuHRef`), lasts the walk
        self.0.next().map(|i| unsafe { RcuRef::new(i) })
    }
}

/// A chain's reference to an entry it no longer holds: released after
/// a grace period, as readers may still stand on the entry (Linux
/// SOCK_RCU_FREE). Dropping it waits for the grace period
/// (synchronize_rcu: thread context only); `defer` does not wait.
#[must_use]
pub struct RcuHRef<A: HAdapter>(Option<Arc<A::Item>>, PhantomData<A>);

impl<A: HAdapter> RcuHRef<A> {
    /// The entry
    pub fn item(&self) -> &A::Item {
        self.0.as_deref().expect("RcuHRef: taken")
    }

    /// The reference, for a chain it moves to with no grace period
    /// (readers on it walk on into that chain)
    fn into_arc(mut self) -> Arc<A::Item> {
        self.0.take().expect("RcuHRef: taken")
    }
}

impl<A: HAdapter> RcuHRef<A>
where
    A::Item: HasRcuPuts + Send + Sync,
{
    /// Release the reference after a grace period without waiting
    /// (Linux call_rcu of SOCK_RCU_FREE's __sk_destruct, kfree_rcu):
    /// any context. Its drop runs in `rcuc/N` (the module's contract).
    /// The entry may have left another chain within the same grace
    /// period: `put_rcu` counts both.
    pub fn defer(mut self) {
        if let Some(a) = self.0.take() {
            put_rcu(a);
        }
    }
}

impl<A: HAdapter> Drop for RcuHRef<A> {
    fn drop(&mut self) {
        if let Some(a) = self.0.take() {
            crate::sync::rcu::synchronize();
            drop(a);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::rcu::{RcuPuts, read_lock};
    use alloc::vec::Vec;

    struct Item {
        v: u32,
        node: HNode,
        puts: RcuPuts,
    }

    crate::hadapter!(ItemNode, Item, node);
    crate::rcu_puts!(Item, puts);

    /// The test's lock data
    struct Own;
    // SAFETY: each test makes one, used only by itself
    unsafe impl UniqueOwner for Own {}

    type Chain = RcuHList<ItemNode, Own>;

    fn item(v: u32) -> Arc<Item> {
        crate::util::kalloc::arc_nofail(Item {
            v,
            node: HNode::new(),
            puts: RcuPuts::new(),
        })
    }

    fn values(l: &Chain) -> Vec<u32> {
        let g = read_lock();
        l.iter(&g).map(|i| i.v).collect()
    }

    /// Head insertion order; removal from the front, middle and end
    #[test]
    fn add_head_and_del() {
        let mut o = Own;
        let l = Chain::new();
        let it: Vec<_> = (1..=4).map(item).collect();
        for i in &it {
            l.add_head(i.clone(), &mut o);
        }
        assert_eq!(values(&l), [4, 3, 2, 1]);
        drop(l.del_init(&it[2], &mut o));
        assert_eq!(values(&l), [4, 2, 1]);
        drop(l.del_init(&it[3], &mut o));
        drop(l.del_init(&it[0], &mut o));
        assert_eq!(values(&l), [2]);
        assert!(!it[0].node.is_hashed());
        assert_eq!(Arc::strong_count(&it[0]), 1);
        drop(l.remove_first(|i| i.v == 2, &mut o));
        assert!(l.is_empty());
    }

    /// A node can join another chain at once (hlist_del_init_rcu), and
    /// a removal from a chain it is not on does nothing
    #[test]
    fn readd_and_membership() {
        let mut o = Own;
        let a = Chain::new();
        let b = Chain::new();
        let x = item(7);
        a.add_head(x.clone(), &mut o);
        assert!(b.del_init(&x, &mut o).is_none());
        let gone = a.del_init(&x, &mut o).unwrap();
        b.add_head(x.clone(), &mut o);
        assert_eq!(values(&b), [7]);
        assert!(a.is_empty());
        // Both references held: the chain's and the one leaving
        assert_eq!(Arc::strong_count(&x), 3);
        drop(gone);
        assert_eq!(Arc::strong_count(&x), 2);
        drop(b);
        assert_eq!(Arc::strong_count(&x), 1);
        assert!(!x.node.is_hashed());
    }

    /// A reader on a removed entry walks on; a reference taken under the
    /// guard outlives the chain's
    #[test]
    fn reader_walks_past_removed() {
        let mut o = Own;
        let l = Chain::new();
        let it: Vec<_> = (1..=3).map(item).collect();
        for i in &it {
            l.add_head(i.clone(), &mut o);
        }
        let g = read_lock();
        let mut r = l.iter_ref(&g);
        let held = r.next().unwrap().get();
        let gone = l.del_init(&it[2], &mut o).unwrap();
        let gone2 = l.del_init(&it[1], &mut o).unwrap();
        assert_eq!(r.map(|i| i.v).collect::<Vec<_>>(), [2, 1]);
        drop(g);
        drop((gone, gone2));
        assert_eq!(held.v, 3);
        assert_eq!(values(&l), [1]);
    }

    /// Every entry moves, references and all, to the chain picked
    #[test]
    fn move_all_moves() {
        let mut o = Own;
        let (a, odd, even) = (Chain::new(), Chain::new(), Chain::new());
        let it: Vec<_> = (1..=4).map(item).collect();
        for i in &it {
            a.add_head(i.clone(), &mut o);
        }
        a.move_all(|i| if i.v % 2 == 1 { &odd } else { &even }, &mut o);
        assert!(a.is_empty());
        assert_eq!(values(&odd), [1, 3]);
        assert_eq!(values(&even), [2, 4]);
        assert!(it.iter().all(|i| Arc::strong_count(i) == 2));
        assert!(odd.del_init(&it[1], &mut o).is_none());
    }

    /// A rehash moves entries between chains at once; a reader standing
    /// on one walks on into its new chain
    #[test]
    fn move_all_reader() {
        let mut o = Own;
        let old = Chain::new();
        let new = [Chain::new(), Chain::new()];
        for v in 1..=4 {
            old.add_head(item(v), &mut o);
        }
        new[1].add_head(item(9), &mut o);
        let g = read_lock();
        let mut it = old.iter(&g);
        assert_eq!(it.next().map(|i| i.v), Some(4));
        old.move_all(|i| &new[(i.v % 2) as usize], &mut o);
        // The reader had read 4 and stood at 3, which moved to the odd
        // chain: it walks on there
        assert_eq!(it.map(|i| i.v).collect::<Vec<_>>(), [3, 9]);
        drop(g);
        assert_eq!(values(&new[0]), [2, 4]);
        assert_eq!(values(&new[1]), [1, 3, 9]);
    }

    /// The writer walk sees every entry
    #[test]
    fn writer_walk() {
        let mut o = Own;
        let l = Chain::new();
        for v in 1..=3 {
            l.add_head(item(v), &mut o);
        }
        let seen: Vec<_> = l.iter_locked(&o).map(|i| i.v).collect();
        assert_eq!(seen, [3, 2, 1]);
    }

    #[test]
    #[should_panic(expected = "already hashed")]
    fn double_add_panics() {
        let mut o = Own;
        let l = Chain::new();
        let x = item(1);
        l.add_head(x.clone(), &mut o);
        l.add_head(x, &mut o);
    }
}
