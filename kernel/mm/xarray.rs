//! A radix tree of 64-bit entries by index (Linux lib/xarray.c, fixed
//! height)
//!
//! Four levels of 512-slot nodes, like a page table: an index has 36
//! bits, 9 per level (more than a mapping or a swap device can hold).
//! Each node is one page frame, given by the caller's allocator (shared
//! memory takes user memory, the swap cache kernel memory), so the tree
//! costs no kernel heap. An entry is any nonzero value (0: empty);
//! nodes stay until the tree is destroyed.
//!
//! The tree has no lock of its own: its owner keeps it under one (Linux
//! xa_lock), e.g. `Shmem.root`, the swap cache's `i_pages`. A store
//! under a spinlock allocates nodes through the closure it is given,
//! which must not sleep (the swap cache hands in nodes allocated before
//! taking its lock, Linux xas_nomem).

/// Index bits per level (512 slots a node)
const BITS: u32 = 9;

/// Levels below the root
const LEVELS: u32 = 4;

/// One past the largest index
pub const MAX_INDEX: u64 = 1 << (BITS * LEVELS);

/// A tree of entries by index (Linux struct xarray)
pub struct XArray {
    /// Root node (a frame; 0 until the first store)
    root: u64,
}

/// The slots of node `node`
#[cfg(not(test))]
fn slots(node: u64) -> *mut u64 {
    crate::arch::phys_to_virt(node) as *mut u64
}

/// Host tests: nodes are host allocations, `node` their address
#[cfg(test)]
fn slots(node: u64) -> *mut u64 {
    node as *mut u64
}

/// Slot `i` (mod 512) of `node`
fn slot(node: u64, i: u64) -> &'static mut u64 {
    // SAFETY: a node frame of a tree, reached through the direct map,
    // used under the tree owner's lock (or by its destroy)
    unsafe { &mut *slots(node).add((i & 511) as usize) }
}

#[cfg(not(test))]
fn free_node(node: u64) {
    crate::FRAME_ALLOCATOR.free(node);
}

#[cfg(test)]
fn free_node(node: u64) {
    // SAFETY: allocated by `tests::node` as a leaked box
    drop(unsafe { alloc::boxed::Box::from_raw(node as *mut [u64; 512]) });
}

/// A zeroed node from `alloc`
fn new_node(alloc: &mut dyn FnMut() -> Option<u64>) -> Option<u64> {
    let n = alloc()?;
    // SAFETY: a fresh node frame
    unsafe { core::ptr::write_bytes(slots(n), 0, 512) };
    Some(n)
}

impl XArray {
    pub const fn new() -> Self {
        Self { root: 0 }
    }

    /// The tree has no entry (and no node)
    pub fn is_empty(&self) -> bool {
        self.root == 0
    }

    /// The leaf slot of `idx`, if its nodes exist
    fn leaf(&self, idx: u64) -> Option<&'static mut u64> {
        if self.root == 0 || idx >= MAX_INDEX {
            return None;
        }
        let mut node = self.root;
        for level in (1..LEVELS).rev() {
            node = *slot(node, idx >> (BITS * level));
            if node == 0 {
                return None;
            }
        }
        Some(slot(node, idx))
    }

    /// The leaf slot of `idx`, creating missing nodes with `alloc`
    fn leaf_alloc(
        &mut self,
        idx: u64,
        alloc: &mut dyn FnMut() -> Option<u64>,
    ) -> Option<&'static mut u64> {
        if idx >= MAX_INDEX {
            return None;
        }
        if self.root == 0 {
            self.root = new_node(alloc)?;
        }
        let mut node = self.root;
        for level in (1..LEVELS).rev() {
            let e = slot(node, idx >> (BITS * level));
            if *e == 0 {
                *e = new_node(alloc)?;
            }
            node = *e;
        }
        Some(slot(node, idx))
    }

    /// The entry at `idx` (0: none; Linux xa_load)
    pub fn load(&self, idx: u64) -> u64 {
        self.leaf(idx).map_or(0, |e| *e)
    }

    /// Store `val` at `idx` (Linux xa_store), creating nodes with
    /// `alloc`: the old entry, or None if a node could not be allocated
    /// (nothing changed) or `idx` is out of range
    pub fn store(
        &mut self,
        idx: u64,
        val: u64,
        alloc: &mut dyn FnMut() -> Option<u64>,
    ) -> Option<u64> {
        let e = self.leaf_alloc(idx, alloc)?;
        Some(core::mem::replace(e, val))
    }

    /// Clear `idx` (Linux xa_erase): the old entry (0: none)
    pub fn erase(&mut self, idx: u64) -> u64 {
        self.leaf(idx).map_or(0, core::mem::take)
    }

    /// `f(index, slot)` for each entry with index in [from, to), in
    /// order; `f` may change or clear the slot. Empty subtrees are
    /// skipped.
    pub fn for_each(&self, from: u64, to: u64, f: &mut dyn FnMut(u64, &mut u64)) {
        if self.root != 0 {
            visit(self.root, LEVELS - 1, 0, from, to.min(MAX_INDEX), f);
        }
    }

    /// Free every node, handing each entry to `f` (Linux xa_destroy)
    pub fn destroy(&mut self, f: &mut dyn FnMut(u64)) {
        let root = core::mem::take(&mut self.root);
        if root != 0 {
            destroy(root, LEVELS - 1, f);
        }
    }
}

impl Default for XArray {
    fn default() -> Self {
        Self::new()
    }
}

/// Visit the entries of `node` at `level` (0: a leaf node) whose
/// indexes fall in [from, to); `base` is the node's first index
fn visit(node: u64, level: u32, base: u64, from: u64, to: u64, f: &mut dyn FnMut(u64, &mut u64)) {
    let span = 1u64 << (BITS * level);
    for i in 0..512u64 {
        let lo = base + i * span;
        if lo >= to || lo + span <= from {
            continue;
        }
        let e = slot(node, i);
        if *e == 0 {
            continue;
        }
        if level == 0 {
            f(lo, e);
        } else {
            visit(*e, level - 1, lo, from, to, f);
        }
    }
}

/// Free `node` at `level` and everything below it
fn destroy(node: u64, level: u32, f: &mut dyn FnMut(u64)) {
    for i in 0..512 {
        let e = *slot(node, i);
        if e == 0 {
            continue;
        }
        if level == 0 {
            f(e);
        } else {
            destroy(e, level - 1, f);
        }
    }
    free_node(node);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node() -> Option<u64> {
        Some(alloc::boxed::Box::into_raw(alloc::boxed::Box::new([0u64; 512])) as u64)
    }

    #[test]
    fn store_load_erase() {
        let mut xa = XArray::new();
        assert!(xa.is_empty());
        assert_eq!(xa.load(5), 0);
        for idx in [0, 1, 511, 512, 1 << 20, MAX_INDEX - 1] {
            assert_eq!(xa.store(idx, idx + 7, &mut node), Some(0));
        }
        assert_eq!(xa.store(1, 99, &mut node), Some(8));
        assert_eq!(xa.load(1), 99);
        assert_eq!(xa.load(MAX_INDEX - 1), MAX_INDEX + 6);
        assert_eq!(xa.load(2), 0);
        assert_eq!(xa.store(MAX_INDEX, 1, &mut node), None);
        assert_eq!(xa.erase(512), 519);
        assert_eq!(xa.erase(512), 0);
        let mut seen = Vec::new();
        xa.destroy(&mut |e| seen.push(e));
        seen.sort();
        assert_eq!(seen, [7, 99, 511 + 7, (1 << 20) + 7, MAX_INDEX + 6]);
        assert!(xa.is_empty());
    }

    #[test]
    fn failed_node_allocation_changes_nothing() {
        let mut xa = XArray::new();
        assert_eq!(xa.store(3, 1, &mut || None), None);
        assert!(xa.is_empty());
        xa.store(3, 1, &mut node);
        // A new subtree needs three nodes: the store fails, 3 stays
        assert_eq!(xa.store(1 << 30, 2, &mut || None), None);
        assert_eq!(xa.load(3), 1);
        xa.destroy(&mut |_| {});
    }

    #[test]
    fn for_each_visits_the_range_in_order() {
        let mut xa = XArray::new();
        for idx in [10, 600, 1 << 18, 5 << 18] {
            xa.store(idx, idx, &mut node);
        }
        let mut seen = Vec::new();
        xa.for_each(11, 5 << 18, &mut |i, e| {
            seen.push(i);
            *e = 0;
        });
        assert_eq!(seen, [600, 1 << 18]);
        assert_eq!(xa.load(600), 0);
        assert_eq!(xa.load(10), 10);
        assert_eq!(xa.load(5 << 18), 5 << 18);
        xa.destroy(&mut |_| {});
    }
}
