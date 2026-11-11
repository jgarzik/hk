//! A radix tree of 64-bit entries by index, with marks (Linux
//! lib/xarray.c)
//!
//! Nodes have 64 slots (6 index bits, Linux XA_CHUNK_SHIFT) and the
//! tree is as tall as its largest index needs: an entry at index 0
//! alone is held in the root itself with no node, a tree of indexes
//! below 64 is one node, below 4096 two levels, and so on up to the
//! full 64 bits. Nodes freed as they empty, and the tree shrinks back
//! when only index 0 is left, so a mapping costs about one node per
//! 64 entries (a 552-byte heap object).
//!
//! An entry is any nonzero value (0: empty). Each entry carries three
//! marks (Linux XA_MARK_0..2; the page cache's DIRTY, WRITEBACK and
//! TOWRITE): a node keeps one bitmap per mark over its slots, and a
//! parent's bit says "some entry below has the mark", so a marked
//! search skips unmarked subtrees.
//!
//! Locking: the tree has no lock of its own: its owner keeps it under
//! one (Linux xa_lock), e.g. a mapping's `i_pages`, the swap cache. Nodes come from the closure a store is given: under a
//! spinlock that is a [`Preload`] filled before taking the lock (Linux
//! xas_nomem), so the allocation can sleep and reclaim.

use alloc::alloc::{Layout, alloc_zeroed, dealloc};
use core::ptr::NonNull;

/// Index bits per level
const SHIFT: u32 = 6;

/// Slots a node
const SLOTS: usize = 1 << SHIFT;

/// Marks an entry can carry
pub const MARKS: usize = 3;

/// Page cache marks (Linux PAGECACHE_TAG_*)
pub const MARK_DIRTY: usize = 0;
pub const MARK_WRITEBACK: usize = 1;
pub const MARK_TOWRITE: usize = 2;

/// Most levels a 64-bit index needs
const MAX_LEVELS: usize = 64usize.div_ceil(SHIFT as usize);

/// One node (Linux struct xa_node)
pub struct Node {
    /// Its parent (null: the root node)
    parent: *mut Node,
    /// Its slot in the parent
    offset: u8,
    /// Nonzero slots
    count: u8,
    /// Entries (a leaf node) or child nodes, 0 when empty
    slots: [u64; SLOTS],
    /// Per mark, the slots having it (an entry) or a marked entry below
    marks: [u64; MARKS],
}

/// A new zeroed node from the heap, None when out of memory (no panic:
/// the allocation is fallible, unlike `Box::new`)
pub fn node_alloc() -> Option<NonNull<Node>> {
    #[cfg(test)]
    tests::LIVE.with(|l| l.set(l.get() + 1));
    // SAFETY: Node is not zero-sized; all-zero is a valid empty node
    NonNull::new(unsafe { alloc_zeroed(Layout::new::<Node>()) }.cast::<Node>())
}

fn node_free(n: NonNull<Node>) {
    #[cfg(test)]
    tests::LIVE.with(|l| l.set(l.get() - 1));
    // SAFETY: allocated by `node_alloc` with this layout
    unsafe { dealloc(n.as_ptr().cast::<u8>(), Layout::new::<Node>()) }
}

/// Nodes allocated before taking the tree's lock (Linux xas_nomem /
/// radix_tree_preload); the ones not used are freed on drop
pub struct Preload {
    nodes: [Option<NonNull<Node>>; MAX_LEVELS + 1],
}

impl Preload {
    /// A preload holding enough nodes for any one store; None when out
    /// of memory
    pub fn new() -> Option<Self> {
        let mut p = Self {
            nodes: [None; MAX_LEVELS + 1],
        };
        for n in p.nodes.iter_mut() {
            *n = Some(node_alloc()?);
        }
        Some(p)
    }

    /// The allocator a store takes nodes from
    pub fn take(&mut self) -> Option<NonNull<Node>> {
        self.nodes.iter_mut().find_map(|n| n.take())
    }
}

impl Drop for Preload {
    fn drop(&mut self) {
        for n in self.nodes.iter_mut().filter_map(|n| n.take()) {
            node_free(n);
        }
    }
}

/// Store `val` at `idx` in the tree that `lock` locks, allocating no
/// node under the lock (Linux xa_store's __xas_nomem): the first try
/// uses only the nodes the tree has; when one is missing, the lock is
/// dropped, a preload allocated (may reclaim) and the store retried
/// once. `check` runs under the lock before each try and may refuse.
/// Returns the old entry, or `nomem` when the preload fails or the retry
/// still falls short.
pub fn store_nomem<G, E>(
    mut lock: impl FnMut() -> G,
    idx: u64,
    val: u64,
    mut check: impl FnMut(&XArray) -> Result<(), E>,
    nomem: E,
) -> Result<u64, E>
where
    G: core::ops::DerefMut<Target = XArray>,
    E: Copy,
{
    let mut pre: Option<Preload> = None;
    loop {
        let mut t = lock();
        check(&t)?;
        let stored = match pre.as_mut() {
            Some(p) => t.store(idx, val, &mut || p.take()),
            None => t.store(idx, val, &mut || None),
        };
        if let Some(old) = stored {
            return Ok(old);
        }
        drop(t);
        if pre.is_some() {
            return Err(nomem);
        }
        pre = Some(Preload::new().ok_or(nomem)?);
    }
}

/// A tree of entries by index (Linux struct xarray)
pub struct XArray {
    /// The root: the entry at index 0 when `height` is 0, else the top
    /// node (0: empty)
    head: u64,
    /// Levels of nodes (0: no node)
    height: u8,
    /// Marks of the entry held in `head` (height 0)
    head_marks: u8,
}

/// Node `p`, shared (the `&self` paths)
///
/// # Safety
/// `p` is a live node of a tree the caller borrows for `'a`, and no
/// `&mut` to it exists meanwhile.
unsafe fn node<'a>(p: u64) -> &'a Node {
    // SAFETY: per the caller
    unsafe { &*(p as *const Node) }
}

/// Node `p`, exclusive (the `&mut self` paths)
///
/// # Safety
/// `p` is a live node of a tree the caller borrows `&mut` for `'a`, and
/// no other reference to that node is used meanwhile.
unsafe fn node_mut<'a>(p: u64) -> &'a mut Node {
    // SAFETY: per the caller
    unsafe { &mut *(p as *mut Node) }
}

/// Indexes a tree of `height` levels holds
fn span(height: u8) -> u128 {
    1u128 << (SHIFT * u32::from(height))
}

/// Slot of `idx` in a node at `level` (1: a leaf node)
fn slot_of(idx: u64, level: u8) -> usize {
    ((idx >> (SHIFT * (u32::from(level) - 1))) as usize) & (SLOTS - 1)
}

impl XArray {
    pub const fn new() -> Self {
        Self {
            head: 0,
            height: 0,
            head_marks: 0,
        }
    }

    /// The tree has no entry (and no node)
    pub fn is_empty(&self) -> bool {
        self.head == 0
    }

    /// The leaf node holding `idx` and its slot, if the path exists
    fn leaf(&self, idx: u64) -> Option<(u64, usize)> {
        if self.height == 0 || u128::from(idx) >= span(self.height) {
            return None;
        }
        let mut n = self.head;
        for level in (2..=self.height).rev() {
            // SAFETY: a live node of this tree, borrowed as the method's self
            n = unsafe { node(n) }.slots[slot_of(idx, level)];
            if n == 0 {
                return None;
            }
        }
        Some((n, slot_of(idx, 1)))
    }

    /// The entry at `idx` (0: none; Linux xa_load)
    pub fn load(&self, idx: u64) -> u64 {
        if self.height == 0 {
            return if idx == 0 { self.head } else { 0 };
        }
        // SAFETY: a live node of this tree, borrowed as the method's self
        self.leaf(idx)
            .map_or(0, |(n, s)| unsafe { node(n) }.slots[s])
    }

    /// Grow by one level: the root becomes slot 0 of a new top node
    fn grow(&mut self, top: NonNull<Node>) {
        // SAFETY: a live node of this tree, borrowed as the method's self
        let t = unsafe { node_mut(top.as_ptr() as u64) };
        if self.head != 0 {
            t.slots[0] = self.head;
            t.count = 1;
            if self.height == 0 {
                for m in 0..MARKS {
                    t.marks[m] = u64::from((self.head_marks >> m) & 1);
                }
            } else {
                // SAFETY: a live node of this tree, borrowed as the method's self
                let old = unsafe { node_mut(self.head) };
                old.parent = t;
                old.offset = 0;
                for m in 0..MARKS {
                    t.marks[m] = u64::from(old.marks[m] != 0);
                }
            }
        }
        self.head = top.as_ptr() as u64;
        self.height += 1;
        self.head_marks = 0;
    }

    /// Store `val` (nonzero) at `idx` (Linux xa_store), taking nodes
    /// from `alloc`: the old entry, or None if a node could not be
    /// allocated (nothing changed: nodes made for the store are freed
    /// again). The entry keeps its marks.
    pub fn store(
        &mut self,
        idx: u64,
        val: u64,
        alloc: &mut dyn FnMut() -> Option<NonNull<Node>>,
    ) -> Option<u64> {
        debug_assert_ne!(val, 0);
        if self.height == 0 && idx == 0 {
            return Some(core::mem::replace(&mut self.head, val));
        }
        if self.head == 0 {
            let mut h = 1;
            while u128::from(idx) >= span(h) {
                h += 1;
            }
            self.head = alloc()?.as_ptr() as u64;
            self.height = h;
        }
        while u128::from(idx) >= span(self.height) {
            match alloc() {
                Some(t) => self.grow(t),
                None => {
                    self.shrink();
                    return None;
                }
            }
        }
        let mut n = self.head;
        for level in (2..=self.height).rev() {
            let s = slot_of(idx, level);
            // SAFETY: a live node of this tree, borrowed as the method's self
            if unsafe { node_mut(n) }.slots[s] == 0 {
                let Some(c) = alloc() else {
                    self.prune(n);
                    return None;
                };
                // SAFETY: a live node of this tree, borrowed as the method's self
                let cn = unsafe { node_mut(c.as_ptr() as u64) };
                cn.parent = n as *mut Node;
                cn.offset = s as u8;
                // SAFETY: a live node of this tree, borrowed as the method's self
                unsafe { node_mut(n) }.slots[s] = c.as_ptr() as u64;
                // SAFETY: a live node of this tree, borrowed as the method's self
                unsafe { node_mut(n) }.count += 1;
            }
            // SAFETY: a live node of this tree, borrowed as the method's self
            n = unsafe { node_mut(n) }.slots[s];
        }
        // SAFETY: a live node of this tree, borrowed as the method's self
        let leaf = unsafe { node_mut(n) };
        let s = slot_of(idx, 1);
        let old = core::mem::replace(&mut leaf.slots[s], val);
        if old == 0 {
            leaf.count += 1;
        }
        Some(old)
    }

    /// Free `n` and the ancestors a failed store left empty, then shrink
    fn prune(&mut self, mut n: u64) {
        // SAFETY: a live node of this tree, borrowed as the method's self
        while n != 0 && unsafe { node_mut(n) }.count == 0 {
            // SAFETY: a live node of this tree, borrowed as the method's self
            let cur = unsafe { node_mut(n) };
            let parent = cur.parent as u64;
            if parent == 0 {
                self.head = 0;
                self.height = 0;
            } else {
                // SAFETY: a live node of this tree, borrowed as the method's self
                unsafe { node_mut(parent) }.slots[cur.offset as usize] = 0;
                // SAFETY: a live node of this tree, borrowed as the method's self
                unsafe { node_mut(parent) }.count -= 1;
            }
            // SAFETY: an unlinked, empty node of this tree
            node_free(unsafe { NonNull::new_unchecked(cur) });
            n = parent;
        }
        self.shrink();
    }

    /// Clear `idx` (Linux xa_erase) and its marks, freeing nodes that
    /// empty: the old entry (0: none)
    pub fn erase(&mut self, idx: u64) -> u64 {
        if self.height == 0 {
            if idx != 0 {
                return 0;
            }
            self.head_marks = 0;
            return core::mem::take(&mut self.head);
        }
        let Some((n, s)) = self.leaf(idx) else {
            return 0;
        };
        // SAFETY: a live node of this tree, borrowed as the method's self
        let n = unsafe { node_mut(n) };
        let old = core::mem::take(&mut n.slots[s]);
        if old == 0 {
            return 0;
        }
        for m in 0..MARKS {
            n.marks[m] &= !(1 << s);
        }
        n.count -= 1;
        let mut n: *mut Node = n;
        loop {
            // SAFETY: a live node of this tree, borrowed as the method's self
            let cur = unsafe { node_mut(n as u64) };
            let parent = cur.parent;
            if parent.is_null() {
                break;
            }
            // SAFETY: a live node of this tree, borrowed as the method's self
            let p = unsafe { node_mut(parent as u64) };
            let o = cur.offset as usize;
            if cur.count == 0 {
                p.slots[o] = 0;
                p.count -= 1;
                // SAFETY: an unlinked node of this tree
                node_free(unsafe { NonNull::new_unchecked(n) });
            }
            for m in 0..MARKS {
                // SAFETY: a live node of this tree, borrowed as the method's self
                if p.slots[o] == 0 || unsafe { node_mut(p.slots[o]) }.marks[m] == 0 {
                    p.marks[m] &= !(1 << o);
                }
            }
            n = parent;
        }
        self.shrink();
        old
    }

    /// Drop top nodes that only hold slot 0 (Linux xas_shrink); an
    /// empty tree frees its last node
    fn shrink(&mut self) {
        while self.height > 0 {
            // SAFETY: a live node of this tree, borrowed as the method's self
            let top = unsafe { node_mut(self.head) };
            if top.count == 0 {
                // SAFETY: the tree's own top node
                node_free(unsafe { NonNull::new_unchecked(top) });
                self.head = 0;
                self.height = 0;
                self.head_marks = 0;
                return;
            }
            if top.count != 1 || top.slots[0] == 0 {
                return;
            }
            let child = top.slots[0];
            let marks = top.marks;
            // SAFETY: the tree's own top node, unlinked below
            node_free(unsafe { NonNull::new_unchecked(top) });
            self.head = child;
            self.height -= 1;
            if self.height == 0 {
                self.head_marks = (0..MARKS).fold(0, |a, m| a | (((marks[m] & 1) as u8) << m));
            } else {
                // SAFETY: a live node of this tree, borrowed as the method's self
                unsafe { node_mut(child) }.parent = core::ptr::null_mut();
            }
        }
    }

    /// Set mark `m` on the entry at `idx` (Linux xa_set_mark); no
    /// effect if there is none
    pub fn set_mark(&mut self, idx: u64, m: usize) {
        if self.height == 0 {
            if idx == 0 && self.head != 0 {
                self.head_marks |= 1 << m;
            }
            return;
        }
        let Some((n, s)) = self.leaf(idx) else {
            return;
        };
        // SAFETY: a live node of this tree, borrowed as the method's self
        let mut n = unsafe { node_mut(n) };
        if n.slots[s] == 0 {
            return;
        }
        let mut s = s;
        loop {
            if n.marks[m] & (1 << s) != 0 {
                return;
            }
            n.marks[m] |= 1 << s;
            if n.parent.is_null() {
                return;
            }
            s = n.offset as usize;
            // SAFETY: a live node of this tree, borrowed as the method's self
            n = unsafe { node_mut(n.parent as u64) };
        }
    }

    /// Clear mark `m` of the entry at `idx` (Linux xa_clear_mark)
    pub fn clear_mark(&mut self, idx: u64, m: usize) {
        if self.height == 0 {
            if idx == 0 {
                self.head_marks &= !(1 << m);
            }
            return;
        }
        let Some((n, s)) = self.leaf(idx) else {
            return;
        };
        // SAFETY: a live node of this tree, borrowed as the method's self
        let mut n = unsafe { node_mut(n) };
        let mut s = s;
        loop {
            n.marks[m] &= !(1 << s);
            if n.marks[m] != 0 || n.parent.is_null() {
                return;
            }
            s = n.offset as usize;
            // SAFETY: a live node of this tree, borrowed as the method's self
            n = unsafe { node_mut(n.parent as u64) };
        }
    }

    /// The entry at `idx` has mark `m` (Linux xa_get_mark)
    pub fn get_mark(&self, idx: u64, m: usize) -> bool {
        if self.height == 0 {
            return idx == 0 && self.head != 0 && self.head_marks & (1 << m) != 0;
        }
        self.leaf(idx).is_some_and(|(n, s)| {
            // SAFETY: a live node of this tree, borrowed as the method's self
            let n = unsafe { node(n) };
            n.slots[s] != 0 && n.marks[m] & (1 << s) != 0
        })
    }

    /// Some entry has mark `m` (Linux xa_marked)
    pub fn marked(&self, m: usize) -> bool {
        match self.height {
            0 => self.head != 0 && self.head_marks & (1 << m) != 0,
            // SAFETY: a live node of this tree, borrowed as the method's self
            _ => unsafe { node(self.head) }.marks[m] != 0,
        }
    }

    /// The first entry with index in [from, to], having mark `m` if
    /// given (Linux xa_find / xa_find_marked): (index, entry)
    pub fn find(&self, from: u64, to: u64, m: Option<usize>) -> Option<(u64, u64)> {
        if self.head == 0 || from > to {
            return None;
        }
        if self.height == 0 {
            let ok = m.is_none_or(|m| self.head_marks & (1 << m) != 0);
            return (from == 0 && ok).then_some((0, self.head));
        }
        if u128::from(from) >= span(self.height) {
            return None;
        }
        // SAFETY: a live node of this tree, borrowed as the method's self
        find_in(unsafe { node(self.head) }, self.height, 0, from, to, m)
    }

    /// `f(index, entry)` for each entry with index in [from, to], in
    /// order (Linux xa_for_each_range)
    pub fn for_each(&self, from: u64, to: u64, f: &mut dyn FnMut(u64, u64)) {
        let mut at = from;
        while let Some((i, e)) = self.find(at, to, None) {
            f(i, e);
            match i.checked_add(1) {
                Some(n) => at = n,
                None => return,
            }
        }
    }

    /// Erase every entry with index in [from, to], handing each to `f`
    pub fn erase_range(&mut self, from: u64, to: u64, f: &mut dyn FnMut(u64, u64)) {
        let mut at = from;
        while let Some((i, e)) = self.find(at, to, None) {
            self.erase(i);
            f(i, e);
            match i.checked_add(1) {
                Some(n) => at = n,
                None => return,
            }
        }
    }

    /// Free every node, handing each entry to `f` (Linux xa_destroy)
    pub fn destroy(&mut self, f: &mut dyn FnMut(u64)) {
        let head = core::mem::take(&mut self.head);
        let h = core::mem::take(&mut self.height);
        self.head_marks = 0;
        if head == 0 {
            return;
        }
        if h == 0 {
            f(head);
        } else {
            destroy(head, h, f);
        }
    }
}

impl Drop for XArray {
    fn drop(&mut self) {
        debug_assert!(self.height == 0, "xarray dropped with nodes");
        if self.height != 0 {
            self.destroy(&mut |_| {});
        }
    }
}

/// The first entry in [from, to] below `n` at `level`, whose first
/// index is `base`
fn find_in(
    n: &Node,
    level: u8,
    base: u64,
    from: u64,
    to: u64,
    m: Option<usize>,
) -> Option<(u64, u64)> {
    let shift = SHIFT * (u32::from(level) - 1);
    let first = if from > base {
        ((from - base) >> shift) as usize
    } else {
        0
    };
    for s in first..SLOTS {
        let lo = base + ((s as u64) << shift);
        if lo > to {
            return None;
        }
        let e = n.slots[s];
        if e == 0 || m.is_some_and(|m| n.marks[m] & (1 << s) == 0) {
            continue;
        }
        if level == 1 {
            return Some((lo, e));
        }
        // SAFETY: a live node of this tree, borrowed as the method's self
        if let Some(r) = find_in(unsafe { node(e) }, level - 1, lo, from.max(lo), to, m) {
            return Some(r);
        }
    }
    None
}

/// Free node `n` at `level` and everything below it
fn destroy(n: u64, level: u8, f: &mut dyn FnMut(u64)) {
    // SAFETY: a live node of this tree, borrowed as the method's self
    for &e in unsafe { node_mut(n) }.slots.iter().filter(|&&e| e != 0) {
        if level == 1 {
            f(e);
        } else {
            destroy(e, level - 1, f);
        }
    }
    // SAFETY: a node of the destroyed tree
    node_free(unsafe { NonNull::new_unchecked(n as *mut Node) });
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;

    std::thread_local! {
        /// Nodes allocated and not freed on this thread
        pub static LIVE: core::cell::Cell<isize> = const { core::cell::Cell::new(0) };
    }

    fn live() -> isize {
        LIVE.with(|l| l.get())
    }

    #[test]
    fn matches_a_map_and_frees_every_node() {
        let mut xa = XArray::new();
        let mut model: BTreeMap<u64, (u64, u8)> = BTreeMap::new();
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut rnd = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for step in 0..20000u64 {
            let r = rnd();
            // Clustered indexes plus the occasional huge one
            let idx = match r % 4 {
                0 => r >> 60,
                1 => (r >> 20) % 5000,
                2 => (r >> 8) % (1 << 20),
                _ => r >> (r % 64),
            };
            match (r >> 40) % 6 {
                0 | 1 => {
                    let v = step + 1;
                    let old = xa.store(idx, v, &mut node_alloc).unwrap();
                    let m = model.insert(idx, (v, 0));
                    assert_eq!(old, m.map_or(0, |x| x.0));
                    if let Some((_, marks)) = m {
                        model.get_mut(&idx).unwrap().1 = marks;
                    }
                }
                2 => {
                    assert_eq!(xa.erase(idx), model.remove(&idx).map_or(0, |x| x.0));
                }
                3 => {
                    let mk = (r >> 50) as usize % MARKS;
                    xa.set_mark(idx, mk);
                    if let Some(e) = model.get_mut(&idx) {
                        e.1 |= 1 << mk;
                    }
                }
                4 => {
                    let mk = (r >> 50) as usize % MARKS;
                    xa.clear_mark(idx, mk);
                    if let Some(e) = model.get_mut(&idx) {
                        e.1 &= !(1 << mk);
                    }
                }
                _ => {
                    // A failing store changes nothing
                    let before = live();
                    if xa.store(idx, 1, &mut || None).is_none() {
                        assert_eq!(live(), before);
                        assert_eq!(xa.load(idx), model.get(&idx).map_or(0, |x| x.0));
                    } else {
                        model.entry(idx).or_insert((1, 0)).0 = 1;
                    }
                }
            }
            if step % 500 == 0 {
                let from = rnd();
                for mk in [None, Some(0), Some(1), Some(2)] {
                    let want = model
                        .range(from..)
                        .find(|(_, (_, m))| mk.is_none_or(|k| m & (1 << k) != 0))
                        .map(|(&i, &(v, _))| (i, v));
                    assert_eq!(xa.find(from, u64::MAX, mk), want);
                    let any = model
                        .values()
                        .any(|(_, m)| mk.is_none_or(|k| m & (1 << k) != 0));
                    if let Some(k) = mk {
                        assert_eq!(xa.marked(k), any);
                    }
                }
                for (&i, &(v, m)) in model.iter().take(50) {
                    assert_eq!(xa.load(i), v);
                    for k in 0..MARKS {
                        assert_eq!(xa.get_mark(i, k), m & (1 << k) != 0);
                    }
                }
            }
        }
        let keys: Vec<u64> = model.keys().copied().collect();
        for k in keys {
            xa.erase(k);
        }
        assert!(xa.is_empty());
        assert_eq!(live(), 0);
    }

    #[test]
    fn store_load_erase() {
        let mut xa = XArray::new();
        assert!(xa.is_empty());
        assert_eq!(xa.load(5), 0);
        let idxs = [0, 1, 63, 64, 511, 512, 1 << 20, 1 << 40, u64::MAX];
        for idx in idxs {
            assert_eq!(xa.store(idx, idx | 1 << 63 | 1, &mut node_alloc), Some(0));
        }
        for idx in idxs {
            assert_eq!(xa.load(idx), idx | 1 << 63 | 1);
        }
        assert_eq!(xa.store(1, 99, &mut node_alloc), Some(1 << 63 | 1));
        assert_eq!(xa.load(2), 0);
        assert_eq!(xa.erase(512), 512 | 1 << 63 | 1);
        assert_eq!(xa.erase(512), 0);
        let mut seen = Vec::new();
        xa.destroy(&mut |e| seen.push(e));
        assert_eq!(seen.len(), idxs.len() - 1);
        assert!(xa.is_empty());
    }

    #[test]
    fn lone_index_zero_needs_no_node() {
        let mut xa = XArray::new();
        assert_eq!(xa.store(0, 7, &mut || None), Some(0));
        assert_eq!(xa.load(0), 7);
        xa.set_mark(0, MARK_DIRTY);
        assert!(xa.get_mark(0, MARK_DIRTY));
        // Growing keeps index 0 and its mark
        xa.store(100, 8, &mut node_alloc);
        assert_eq!(xa.load(0), 7);
        assert!(xa.get_mark(0, MARK_DIRTY));
        assert!(!xa.get_mark(100, MARK_DIRTY));
        // Erasing the rest shrinks back to no node
        xa.erase(100);
        assert_eq!(xa.height, 0);
        assert!(xa.get_mark(0, MARK_DIRTY));
        assert_eq!(xa.erase(0), 7);
        assert!(xa.is_empty());
    }

    #[test]
    fn failed_node_allocation_changes_nothing() {
        let mut xa = XArray::new();
        assert_eq!(xa.store(3, 1, &mut || None), None);
        assert!(xa.is_empty());
        xa.store(3, 1, &mut node_alloc);
        assert_eq!(xa.store(1 << 30, 2, &mut || None), None);
        assert_eq!(xa.load(3), 1);
        assert_eq!(xa.height, 1);
        // One node short also changes nothing
        let mut left = 2;
        let mut few = || {
            left -= 1;
            if left > 0 { node_alloc() } else { None }
        };
        assert_eq!(xa.store(1 << 30, 2, &mut few), None);
        assert_eq!(xa.height, 1);
        xa.destroy(&mut |_| {});
    }

    #[test]
    fn marks_propagate_and_find() {
        let mut xa = XArray::new();
        for idx in [10, 600, 1 << 18, 5 << 18] {
            xa.store(idx, idx, &mut node_alloc);
        }
        assert!(!xa.marked(MARK_DIRTY));
        xa.set_mark(600, MARK_DIRTY);
        xa.set_mark(5 << 18, MARK_DIRTY);
        assert!(xa.marked(MARK_DIRTY));
        assert_eq!(xa.find(0, u64::MAX, Some(MARK_DIRTY)), Some((600, 600)));
        assert_eq!(
            xa.find(601, u64::MAX, Some(MARK_DIRTY)),
            Some((5 << 18, 5 << 18))
        );
        assert_eq!(xa.find(601, (5 << 18) - 1, Some(MARK_DIRTY)), None);
        assert_eq!(xa.find(11, u64::MAX, None), Some((600, 600)));
        xa.clear_mark(600, MARK_DIRTY);
        xa.erase(5 << 18);
        assert!(!xa.marked(MARK_DIRTY));
        xa.destroy(&mut |_| {});
    }

    #[test]
    fn for_each_and_erase_range() {
        let mut xa = XArray::new();
        for idx in [10, 600, 1 << 18, 5 << 18] {
            xa.store(idx, idx, &mut node_alloc);
        }
        let mut seen = Vec::new();
        xa.for_each(11, 5 << 18, &mut |i, _| seen.push(i));
        assert_eq!(seen, [600, 1 << 18, 5 << 18]);
        seen.clear();
        xa.erase_range(11, (5 << 18) - 1, &mut |i, _| seen.push(i));
        assert_eq!(seen, [600, 1 << 18]);
        assert_eq!(xa.load(10), 10);
        assert_eq!(xa.load(600), 0);
        xa.erase(10);
        xa.erase(5 << 18);
        assert!(xa.is_empty());
    }

    #[test]
    fn preload_covers_any_store() {
        let mut xa = XArray::new();
        let mut p = Preload::new().unwrap();
        assert_eq!(xa.store(u64::MAX, 1, &mut || p.take()), Some(0));
        drop(p);
        xa.erase(u64::MAX);
        assert!(xa.is_empty());
    }
}
