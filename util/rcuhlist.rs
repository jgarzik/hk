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
//! of `next`, Linux rcu_dereference); writers take the chain's own leaf
//! spin lock (`w`; Linux leaves it to the table's lock, which the
//! caller also takes for its own logic, e.g. a port search over many
//! chains).
//!
//! Removal is Linux hlist_del_init_rcu: the node keeps `next` for a
//! reader standing on it and is free for a new insert at once (`pprev`
//! null), so a socket can leave its chain and join another at once
//! (disconnect, then bind again). A reader standing on it may then
//! follow it into its new chain: lookups recheck their key on every
//! entry, as Linux's do. The chain's reference comes back as an
//! [`RcuHRef`], released after a grace period (Linux SOCK_RCU_FREE: the
//! socket's memory outlives every reader that may stand on it), never
//! at once.
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

use crate::sync::rcu::{HasRcuHead, RcuReadGuard};
use crate::sync::spin::Mutex;

/// A chain link embedded in an entry (Linux struct hlist_node)
///
/// # Invariants
/// `pprev` is null exactly when the node is on no chain (Linux
/// hlist_unhashed); `head` is the chain it is on (null: none). Both
/// change only under that chain's `w` lock.
pub struct HNode {
    next: AtomicPtr<HNode>,
    pprev: AtomicPtr<AtomicPtr<HNode>>,
    /// The chain it is on (its `first`), so removal checks membership
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

/// One RCU hash chain of `Arc<A::Item>` (Linux hlist_head with the _rcu
/// operations)
///
/// # Invariants
/// From `first` through `next` are the nodes of the live items on the
/// chain, each inserted with `Arc::into_raw` (the chain's reference),
/// with `pprev` pointing at the pointer that points at it and `head` at
/// `first`. A node taken off keeps its item allocated until a grace
/// period after that (`RcuHRef`).
pub struct RcuHList<A: HAdapter> {
    first: AtomicPtr<HNode>,
    /// Writers (Linux: the table's lock)
    w: Mutex<()>,
    _owns: PhantomData<Arc<A::Item>>,
}

// SAFETY: it holds `Arc<Item>`s and hands out `&Item` to any thread
unsafe impl<A: HAdapter> Send for RcuHList<A> where A::Item: Send + Sync {}
// SAFETY: as above; writers serialize on `w`, readers only load
unsafe impl<A: HAdapter> Sync for RcuHList<A> where A::Item: Send + Sync {}

impl<A: HAdapter> RcuHList<A> {
    #[track_caller]
    pub const fn new() -> Self {
        Self {
            first: AtomicPtr::new(null_mut()),
            w: Mutex::new(()),
            _owns: PhantomData,
        }
    }

    fn first_ptr(&self) -> *mut AtomicPtr<HNode> {
        core::ptr::from_ref(&self.first).cast_mut()
    }

    fn np(item: &A::Item) -> *mut HNode {
        core::ptr::from_ref(A::node(item)).cast_mut()
    }

    /// Link `item` first (Linux hlist_add_head_rcu); panics if it is on
    /// a chain
    pub fn add_head(&self, item: Arc<A::Item>) {
        let n = A::node(&item);
        let _w = self.w.lock();
        assert!(!n.is_hashed(), "RcuHList: item already hashed");
        let first = self.first.load(Relaxed);
        let np = Self::np(&item);
        n.next.store(first, Relaxed);
        n.pprev.store(self.first_ptr(), Relaxed);
        n.head.store(self.first_ptr(), Relaxed);
        // Published after its fields (rcu_assign_pointer)
        self.first.store(np, Release);
        // SAFETY: `first` is a node of this chain (type invariant), its
        // fields changed only under `w`
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
    pub fn del_init(&self, item: &A::Item) -> Option<RcuHRef<A>> {
        let n = A::node(item);
        let _w = self.w.lock();
        if n.head.load(Relaxed) != self.first_ptr() || !n.is_hashed() {
            return None;
        }
        let next = n.next.load(Relaxed);
        let pprev = n.pprev.load(Relaxed);
        // SAFETY: on this chain (its head says so, under `w`): `pprev`
        // points at the pointer to it, in `first` or a live node, and
        // `next` is a live node of the chain or null
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

    /// The entries, first to last, valid while `g` is held (Linux
    /// hlist_for_each_entry_rcu): one added meanwhile may or may not be
    /// seen, one removed may still be, or lead into another chain
    pub fn iter<'a>(&'a self, _g: &'a RcuReadGuard) -> RcuHIter<'a, A> {
        RcuHIter {
            cur: self.first.load(Acquire),
            _l: PhantomData,
        }
    }

    /// The entries, for a writer that holds the table lock all writers
    /// of this chain also take (Linux sk_for_each under the table lock:
    /// a port search); walked under the chain's own lock
    pub fn for_each(&self, mut f: impl FnMut(&A::Item)) {
        let _w = self.w.lock();
        let mut cur = self.first.load(Relaxed);
        // SAFETY: nodes of this chain under `w` (type invariant)
        while let Some(n) = unsafe { cur.as_ref() } {
            // SAFETY: as above: a live item
            f(unsafe { &*A::item(cur) });
            cur = n.next.load(Relaxed);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.first.load(Relaxed).is_null()
    }
}

impl<A: HAdapter> Default for RcuHList<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: HAdapter> Drop for RcuHList<A> {
    fn drop(&mut self) {
        let mut cur = *self.first.get_mut();
        // SAFETY: no reader borrows the chain (`&mut`): its nodes are
        // live entries holding the chain's references
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

/// A reference to an entry reached under the guard (Linux sock_hold
/// on a socket found by an RCU lookup): the chain's reference, or its
/// deferred one, keeps the entry alive while the guard is held
pub fn get<A: HAdapter>(item: &A::Item, _g: &RcuReadGuard) -> Arc<A::Item> {
    let p = core::ptr::from_ref(item);
    // SAFETY: an entry reached from a chain under the guard: the chain
    // holds an Arc reference to it, or holds it for the grace period
    // after it left (RcuHRef), which the guard keeps from ending
    unsafe { Arc::increment_strong_count(p) };
    // SAFETY: the reference just taken
    unsafe { Arc::from_raw(p) }
}

/// Iterator over an [`RcuHList`] under a read guard
pub struct RcuHIter<'a, A: HAdapter> {
    cur: *mut HNode,
    _l: PhantomData<(&'a RcuHList<A>, &'a RcuReadGuard)>,
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
}

impl<A: HAdapter> RcuHRef<A>
where
    A::Item: HasRcuHead + Send + Sync,
{
    /// Release the reference after a grace period without waiting
    /// (Linux call_rcu of SOCK_RCU_FREE's __sk_destruct): its drop runs
    /// in `rcuc/N` (the module's contract). An entry whose head is
    /// still queued for an earlier removal (it left a chain, joined
    /// another and left it within one grace period) waits for this one
    /// instead: thread context only.
    pub fn defer(mut self) {
        let Some(a) = self.0.take() else { return };
        if let Err(a) = crate::sync::rcu::try_kfree_rcu(a) {
            crate::sync::rcu::synchronize();
            drop(a);
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
    use crate::sync::rcu::read_lock;
    use alloc::vec::Vec;

    struct Item {
        v: u32,
        node: HNode,
    }

    crate::hadapter!(ItemNode, Item, node);

    fn item(v: u32) -> Arc<Item> {
        crate::util::kalloc::arc_nofail(Item {
            v,
            node: HNode::new(),
        })
    }

    fn values(l: &RcuHList<ItemNode>) -> Vec<u32> {
        let g = read_lock();
        l.iter(&g).map(|i| i.v).collect()
    }

    /// Head insertion order; removal from the front, middle and end
    #[test]
    fn add_head_and_del() {
        let l = RcuHList::<ItemNode>::new();
        let it: Vec<_> = (1..=4).map(item).collect();
        for i in &it {
            l.add_head(i.clone());
        }
        assert_eq!(values(&l), [4, 3, 2, 1]);
        drop(l.del_init(&it[2]));
        assert_eq!(values(&l), [4, 2, 1]);
        drop(l.del_init(&it[3]));
        drop(l.del_init(&it[0]));
        assert_eq!(values(&l), [2]);
        assert!(!it[0].node.is_hashed());
        assert_eq!(Arc::strong_count(&it[0]), 1);
        drop(l.del_init(&it[1]));
        assert!(l.is_empty());
    }

    /// A node can join another chain at once (hlist_del_init_rcu), and
    /// a removal from a chain it is not on does nothing
    #[test]
    fn readd_and_membership() {
        let a = RcuHList::<ItemNode>::new();
        let b = RcuHList::<ItemNode>::new();
        let x = item(7);
        a.add_head(x.clone());
        assert!(b.del_init(&x).is_none());
        let gone = a.del_init(&x).unwrap();
        b.add_head(x.clone());
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
        let l = RcuHList::<ItemNode>::new();
        let it: Vec<_> = (1..=3).map(item).collect();
        for i in &it {
            l.add_head(i.clone());
        }
        let g = read_lock();
        let mut r = l.iter(&g);
        let three = r.next().unwrap();
        let held = get::<ItemNode>(three, &g);
        let gone = l.del_init(&it[2]).unwrap();
        let gone2 = l.del_init(&it[1]).unwrap();
        assert_eq!(r.map(|i| i.v).collect::<Vec<_>>(), [2, 1]);
        drop(g);
        drop((gone, gone2));
        assert_eq!(held.v, 3);
        assert_eq!(values(&l), [1]);
    }

    /// The writer walk sees every entry
    #[test]
    fn writer_walk() {
        let l = RcuHList::<ItemNode>::new();
        for v in 1..=3 {
            l.add_head(item(v));
        }
        let mut seen = Vec::new();
        l.for_each(|i| seen.push(i.v));
        assert_eq!(seen, [3, 2, 1]);
    }

    #[test]
    #[should_panic(expected = "already hashed")]
    fn double_add_panics() {
        let l = RcuHList::<ItemNode>::new();
        let x = item(1);
        l.add_head(x.clone());
        l.add_head(x);
    }
}
