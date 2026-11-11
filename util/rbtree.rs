//! Red-black trees (Linux lib/rbtree.c, include/linux/rbtree.h)
//!
//! [`RbTree`] is a sorted map whose nodes the caller allocates before
//! taking the tree's lock ([`RbTreeNodeReservation`], Linux's rb_node
//! embedded in an object allocated beforehand): inserting and removing
//! allocate and free nothing, so a tree can change under a spinlock. A
//! removed node comes back to the caller, to free after the unlock. The
//! API follows Rust-for-Linux's `kernel::rbtree`.
//!
//! The rebalancing core is lib/rbtree.c without the augmented
//! callbacks: [`RbLink`] is struct rb_node, its color in bit 0 of the
//! parent pointer (set and cleared with `map_addr`, so the pointer keeps
//! its provenance).

use alloc::boxed::Box;
use core::cmp::Ordering;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ptr::null_mut;

use crate::util::error::KernelError;
use crate::util::kalloc::{box_nofail, try_box};

const RED: usize = 0;
const BLACK: usize = 1;

/// A node's tree hook (Linux struct rb_node): the parent pointer with
/// the color in bit 0 (a link is pointer-aligned, so that bit is free),
/// and the children
#[repr(C)]
struct RbLink {
    parent_color: *mut RbLink,
    left: *mut RbLink,
    right: *mut RbLink,
}

impl RbLink {
    const fn new() -> Self {
        Self {
            parent_color: null_mut(),
            left: null_mut(),
            right: null_mut(),
        }
    }
}

/// Linux rb_parent
///
/// # Safety
/// `n` is a live link.
unsafe fn rb_parent(n: *mut RbLink) -> *mut RbLink {
    // SAFETY: the caller
    unsafe { (*n).parent_color }.map_addr(|a| a & !BLACK)
}

/// Linux rb_is_black
///
/// # Safety
/// `n` is a live link.
unsafe fn rb_is_black(n: *mut RbLink) -> bool {
    // SAFETY: the caller
    unsafe { (*n).parent_color }.addr() & BLACK == BLACK
}

/// Linux rb_is_red
///
/// # Safety
/// `n` is a live link.
unsafe fn rb_is_red(n: *mut RbLink) -> bool {
    // SAFETY: the caller
    !unsafe { rb_is_black(n) }
}

/// Linux rb_set_parent: `n`'s parent is `p`, its color unchanged
///
/// # Safety
/// `n` is a live link.
unsafe fn rb_set_parent(n: *mut RbLink, p: *mut RbLink) {
    // SAFETY: the caller
    unsafe {
        let color = (*n).parent_color.addr() & BLACK;
        (*n).parent_color = p.map_addr(|a| a | color);
    }
}

/// Linux rb_set_parent_color
///
/// # Safety
/// `n` is a live link.
unsafe fn rb_set_parent_color(n: *mut RbLink, p: *mut RbLink, color: usize) {
    // SAFETY: the caller
    unsafe { (*n).parent_color = p.map_addr(|a| a | color) };
}

/// Linux rb_set_black
///
/// # Safety
/// `n` is a live link.
unsafe fn rb_set_black(n: *mut RbLink) {
    // SAFETY: the caller
    unsafe { (*n).parent_color = (*n).parent_color.map_addr(|a| a | BLACK) };
}

/// Linux rb_link_node: hang `node` from `parent` in the empty slot `link`
///
/// # Safety
/// `node` is a live link on no tree; `link` is the root slot of the tree
/// (with `parent` null) or an empty child slot of `parent`, a live link.
unsafe fn rb_link_node(node: *mut RbLink, parent: *mut RbLink, link: *mut *mut RbLink) {
    // SAFETY: the caller
    unsafe {
        (*node).parent_color = parent;
        (*node).left = null_mut();
        (*node).right = null_mut();
        *link = node;
    }
}

/// The in-order successor of `n` (Linux rb_next)
///
/// # Safety
/// `n` is a link of a valid tree whose links are all live.
unsafe fn rb_next(mut n: *mut RbLink) -> *mut RbLink {
    // SAFETY: the caller: every link reached from `n` is live
    unsafe {
        if !(*n).right.is_null() {
            n = (*n).right;
            while !(*n).left.is_null() {
                n = (*n).left;
            }
            return n;
        }
        let mut parent = rb_parent(n);
        while !parent.is_null() && n == (*parent).right {
            n = parent;
            parent = rb_parent(n);
        }
        parent
    }
}

/// The first link in post-order under `n` (Linux rb_left_deepest_node)
///
/// # Safety
/// As [`rb_next`].
unsafe fn rb_left_deepest(mut n: *mut RbLink) -> *mut RbLink {
    // SAFETY: the caller
    unsafe {
        loop {
            if !(*n).left.is_null() {
                n = (*n).left;
            } else if !(*n).right.is_null() {
                n = (*n).right;
            } else {
                return n;
            }
        }
    }
}

/// The post-order successor of `n` (Linux rb_next_postorder): `n`'s
/// children may be freed already, its parent and the parent's right
/// subtree not
///
/// # Safety
/// `n`, its ancestors and the subtrees right of it are live links of a
/// valid tree.
unsafe fn rb_next_postorder(n: *mut RbLink) -> *mut RbLink {
    // SAFETY: the caller; a freed child of `parent` is only compared
    unsafe {
        let parent = rb_parent(n);
        if !parent.is_null() && n == (*parent).left && !(*parent).right.is_null() {
            rb_left_deepest((*parent).right)
        } else {
            parent
        }
    }
}

/// A tree's root slot (Linux struct rb_root) and the rebalancing core
/// (lib/rbtree.c)
struct Root {
    node: *mut RbLink,
}

impl Root {
    /// Point the slot holding `old` (`parent`'s child, or the root if
    /// `parent` is null) at `new` (Linux __rb_change_child)
    ///
    /// # Safety
    /// `parent` is null or a live link of this tree.
    unsafe fn change_child(&mut self, old: *mut RbLink, new: *mut RbLink, parent: *mut RbLink) {
        if parent.is_null() {
            self.node = new;
            return;
        }
        // SAFETY: the caller
        unsafe {
            if (*parent).left == old {
                (*parent).left = new;
            } else {
                (*parent).right = new;
            }
        }
    }

    /// `new` takes rotated `old`'s place and color; `old` gets `color`
    /// under `new` (Linux __rb_rotate_set_parents)
    ///
    /// # Safety
    /// `old` and `new` are live links of this tree.
    unsafe fn rotate_set_parents(&mut self, old: *mut RbLink, new: *mut RbLink, color: usize) {
        // SAFETY: the caller; `old`'s parent is null or a link of this tree
        unsafe {
            let parent = rb_parent(old);
            (*new).parent_color = (*old).parent_color;
            rb_set_parent_color(old, new, color);
            self.change_child(old, new, parent);
        }
    }

    /// Rebalance after linking red `node` (Linux rb_insert_color,
    /// __rb_insert)
    ///
    /// # Safety
    /// `node` was just linked into this tree by [`rb_link_node`]; every
    /// link of the tree is live.
    unsafe fn insert_color(&mut self, mut node: *mut RbLink) {
        // SAFETY: the caller: every link reached from `node` through
        // parent and child pointers is a live link of this tree
        unsafe {
            let mut parent = rb_parent(node);
            loop {
                // Loop invariant: node is red
                if parent.is_null() {
                    // The root: the first node, or recursed at case 1
                    rb_set_parent_color(node, null_mut(), BLACK);
                    break;
                }
                if rb_is_black(parent) {
                    break;
                }
                let gparent = rb_parent(parent);
                let mut tmp = (*gparent).right;
                if parent != tmp {
                    // parent == gparent->left
                    if !tmp.is_null() && rb_is_red(tmp) {
                        // Case 1: red uncle, color flips; recurse at g
                        rb_set_parent_color(tmp, gparent, BLACK);
                        rb_set_parent_color(parent, gparent, BLACK);
                        node = gparent;
                        parent = rb_parent(node);
                        rb_set_parent_color(node, parent, RED);
                        continue;
                    }
                    tmp = (*parent).right;
                    if node == tmp {
                        // Case 2: black uncle, node a right child: left
                        // rotate at parent, then case 3
                        tmp = (*node).left;
                        (*parent).right = tmp;
                        (*node).left = parent;
                        if !tmp.is_null() {
                            rb_set_parent_color(tmp, parent, BLACK);
                        }
                        rb_set_parent_color(parent, node, RED);
                        parent = node;
                        tmp = (*node).right;
                    }
                    // Case 3: black uncle, node a left child: right
                    // rotate at gparent
                    (*gparent).left = tmp;
                    (*parent).right = gparent;
                    if !tmp.is_null() {
                        rb_set_parent_color(tmp, gparent, BLACK);
                    }
                    self.rotate_set_parents(gparent, parent, RED);
                    break;
                }
                tmp = (*gparent).left;
                if !tmp.is_null() && rb_is_red(tmp) {
                    // Case 1: color flips
                    rb_set_parent_color(tmp, gparent, BLACK);
                    rb_set_parent_color(parent, gparent, BLACK);
                    node = gparent;
                    parent = rb_parent(node);
                    rb_set_parent_color(node, parent, RED);
                    continue;
                }
                tmp = (*parent).left;
                if node == tmp {
                    // Case 2: right rotate at parent
                    tmp = (*node).right;
                    (*parent).left = tmp;
                    (*node).right = parent;
                    if !tmp.is_null() {
                        rb_set_parent_color(tmp, parent, BLACK);
                    }
                    rb_set_parent_color(parent, node, RED);
                    parent = node;
                    tmp = (*node).left;
                }
                // Case 3: left rotate at gparent
                (*gparent).right = tmp;
                (*parent).left = gparent;
                if !tmp.is_null() {
                    rb_set_parent_color(tmp, gparent, BLACK);
                }
                self.rotate_set_parents(gparent, parent, RED);
                break;
            }
        }
    }

    /// Unlink `node` (Linux rb_erase)
    ///
    /// # Safety
    /// `node` is a link of this tree; every link of the tree is live.
    unsafe fn erase(&mut self, node: *mut RbLink) {
        // SAFETY: the caller
        let rebalance = unsafe { self.erase_node(node) };
        if !rebalance.is_null() {
            // SAFETY: a link of this tree, which is valid but for the
            // black height under `rebalance`
            unsafe { self.erase_color(rebalance) };
        }
    }

    /// Unlink `node`; the parent to rebalance from, or null (Linux
    /// __rb_erase_augmented without callbacks)
    ///
    /// # Safety
    /// As [`Root::erase`].
    unsafe fn erase_node(&mut self, node: *mut RbLink) -> *mut RbLink {
        // SAFETY: the caller: every link reached from `node` is a live
        // link of this tree
        unsafe {
            let child = (*node).right;
            let mut tmp = (*node).left;
            if tmp.is_null() {
                // Case 1: at most one child (then red, and node black):
                // colors fixed here, no rebalance
                let pc = (*node).parent_color;
                let parent = pc.map_addr(|a| a & !BLACK);
                self.change_child(node, child, parent);
                if !child.is_null() {
                    (*child).parent_color = pc;
                    return null_mut();
                }
                return if pc.addr() & BLACK == BLACK {
                    parent
                } else {
                    null_mut()
                };
            }
            if child.is_null() {
                // Still case 1, the child on the left
                let pc = (*node).parent_color;
                (*tmp).parent_color = pc;
                self.change_child(node, tmp, pc.map_addr(|a| a & !BLACK));
                return null_mut();
            }
            let mut successor = child;
            let parent;
            let child2;
            tmp = (*child).left;
            if tmp.is_null() {
                // Case 2: the successor is node's right child
                parent = successor;
                child2 = (*successor).right;
            } else {
                // Case 3: the successor is leftmost under node's right
                // child
                let mut p;
                loop {
                    p = successor;
                    successor = tmp;
                    tmp = (*tmp).left;
                    if tmp.is_null() {
                        break;
                    }
                }
                parent = p;
                child2 = (*successor).right;
                (*parent).left = child2;
                (*successor).right = child;
                rb_set_parent(child, successor);
            }
            tmp = (*node).left;
            (*successor).left = tmp;
            rb_set_parent(tmp, successor);
            let pc = (*node).parent_color;
            self.change_child(node, successor, pc.map_addr(|a| a & !BLACK));
            let rebalance = if !child2.is_null() {
                rb_set_parent_color(child2, parent, BLACK);
                null_mut()
            } else if rb_is_black(successor) {
                parent
            } else {
                null_mut()
            };
            (*successor).parent_color = pc;
            rebalance
        }
    }

    /// Restore the black height after an erase left the paths through
    /// `parent`'s (null or black) child one black short (Linux
    /// ____rb_erase_color)
    ///
    /// # Safety
    /// `parent` is a link of this tree; every link of the tree is live.
    unsafe fn erase_color(&mut self, mut parent: *mut RbLink) {
        // SAFETY: the caller: every link reached from `parent` is a live
        // link of this tree; a short path's sibling is never null
        unsafe {
            let mut node: *mut RbLink = null_mut();
            loop {
                // Loop invariants: node is black (or null at first),
                // parent is not null, and the paths through node are one
                // black short
                let mut sibling = (*parent).right;
                if node != sibling {
                    // node == parent->left
                    if rb_is_red(sibling) {
                        // Case 1: left rotate at parent
                        let tmp1 = (*sibling).left;
                        (*parent).right = tmp1;
                        (*sibling).left = parent;
                        rb_set_parent_color(tmp1, parent, BLACK);
                        self.rotate_set_parents(parent, sibling, RED);
                        sibling = tmp1;
                    }
                    let mut tmp1 = (*sibling).right;
                    if tmp1.is_null() || rb_is_black(tmp1) {
                        let tmp2 = (*sibling).left;
                        if tmp2.is_null() || rb_is_black(tmp2) {
                            // Case 2: sibling color flip; recurse at a
                            // black parent
                            rb_set_parent_color(sibling, parent, RED);
                            if rb_is_red(parent) {
                                rb_set_black(parent);
                            } else {
                                node = parent;
                                parent = rb_parent(node);
                                if !parent.is_null() {
                                    continue;
                                }
                            }
                            break;
                        }
                        // Case 3: right rotate at sibling
                        tmp1 = (*tmp2).right;
                        (*sibling).left = tmp1;
                        (*tmp2).right = sibling;
                        (*parent).right = tmp2;
                        if !tmp1.is_null() {
                            rb_set_parent_color(tmp1, sibling, BLACK);
                        }
                        tmp1 = sibling;
                        sibling = tmp2;
                    }
                    // Case 4: left rotate at parent, color flips
                    let tmp2 = (*sibling).left;
                    (*parent).right = tmp2;
                    (*sibling).left = parent;
                    rb_set_parent_color(tmp1, sibling, BLACK);
                    if !tmp2.is_null() {
                        rb_set_parent(tmp2, parent);
                    }
                    self.rotate_set_parents(parent, sibling, BLACK);
                    break;
                }
                sibling = (*parent).left;
                if rb_is_red(sibling) {
                    // Case 1: right rotate at parent
                    let tmp1 = (*sibling).right;
                    (*parent).left = tmp1;
                    (*sibling).right = parent;
                    rb_set_parent_color(tmp1, parent, BLACK);
                    self.rotate_set_parents(parent, sibling, RED);
                    sibling = tmp1;
                }
                let mut tmp1 = (*sibling).left;
                if tmp1.is_null() || rb_is_black(tmp1) {
                    let tmp2 = (*sibling).right;
                    if tmp2.is_null() || rb_is_black(tmp2) {
                        // Case 2: sibling color flip
                        rb_set_parent_color(sibling, parent, RED);
                        if rb_is_red(parent) {
                            rb_set_black(parent);
                        } else {
                            node = parent;
                            parent = rb_parent(node);
                            if !parent.is_null() {
                                continue;
                            }
                        }
                        break;
                    }
                    // Case 3: left rotate at sibling
                    tmp1 = (*tmp2).left;
                    (*sibling).right = tmp1;
                    (*tmp2).left = sibling;
                    (*parent).left = tmp2;
                    if !tmp1.is_null() {
                        rb_set_parent_color(tmp1, sibling, BLACK);
                    }
                    tmp1 = sibling;
                    sibling = tmp2;
                }
                // Case 4: right rotate at parent, color flips
                let tmp2 = (*sibling).right;
                (*parent).left = tmp2;
                (*sibling).right = parent;
                rb_set_parent_color(tmp1, sibling, BLACK);
                if !tmp2.is_null() {
                    rb_set_parent(tmp2, parent);
                }
                self.rotate_set_parents(parent, sibling, BLACK);
                break;
            }
        }
    }

    /// `new` takes `victim`'s place, position and color (Linux
    /// rb_replace_node)
    ///
    /// # Safety
    /// `victim` is a link of this tree, every link of which is live;
    /// `new` is a live link on no tree.
    unsafe fn replace(&mut self, victim: *mut RbLink, new: *mut RbLink) {
        // SAFETY: the caller
        unsafe {
            let parent = rb_parent(victim);
            (*new).parent_color = (*victim).parent_color;
            (*new).left = (*victim).left;
            (*new).right = (*victim).right;
            if !(*victim).left.is_null() {
                rb_set_parent((*victim).left, new);
            }
            if !(*victim).right.is_null() {
                rb_set_parent((*victim).right, new);
            }
            self.change_child(victim, new, parent);
        }
    }
}

/// A tree node: the link first, so a link pointer is its node's
#[repr(C)]
struct Node<K, V> {
    link: RbLink,
    key: K,
    value: V,
}

/// A sorted map of preallocated nodes (Linux struct rb_root; the
/// Rust-for-Linux `RBTree`)
///
/// # Invariants
/// `root.node` is null or the root of a valid red-black tree of `len`
/// links (parent pointers and colors as Linux keeps them). Each link is
/// the `link` field, at offset 0, of a `Node<K, V>` leaked from a `Box`
/// and owned by this tree alone. In order, the keys ascend (if `K`'s
/// `Ord` is consistent; memory safety does not depend on it).
pub struct RbTree<K, V> {
    root: Root,
    len: usize,
    /// It owns and drops `Box<Node<K, V>>`s
    _own: PhantomData<Box<Node<K, V>>>,
}

// SAFETY: the tree owns its nodes and only it reaches them (type
// invariant): Send as the `K`s and `V`s it holds, as a BTreeMap
unsafe impl<K: Send, V: Send> Send for RbTree<K, V> {}
// SAFETY: `&RbTree` hands out only `&K` and `&V`: Sync as a BTreeMap
unsafe impl<K: Sync, V: Sync> Sync for RbTree<K, V> {}

impl<K, V> RbTree<K, V> {
    pub const fn new() -> Self {
        // INVARIANT: the empty tree
        Self {
            root: Root { node: null_mut() },
            len: 0,
            _own: PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The entries in order (Linux rb_first + rb_next)
    pub fn iter(&self) -> Iter<'_, K, V> {
        let mut n = self.root.node;
        // SAFETY: the tree's links are live (type invariant)
        while !n.is_null() && unsafe { !(*n).left.is_null() } {
            // SAFETY: as above
            n = unsafe { (*n).left };
        }
        Iter {
            cur: n,
            _t: PhantomData,
        }
    }

    /// The entry with the greatest key (Linux rb_last)
    pub fn last(&self) -> Option<(&K, &V)> {
        let mut n = self.root.node;
        if n.is_null() {
            return None;
        }
        // SAFETY: the tree's links are live and each heads a node (type
        // invariant), borrowed with the tree
        unsafe {
            while !(*n).right.is_null() {
                n = (*n).right;
            }
            let node = &*n.cast::<Node<K, V>>();
            Some((&node.key, &node.value))
        }
    }
}

impl<K: Ord, V> RbTree<K, V> {
    /// The link of `key`'s node, or null
    fn find(&self, key: &K) -> *mut RbLink {
        let mut n = self.root.node;
        while !n.is_null() {
            // SAFETY: a link of this tree heads a live node (type
            // invariant)
            let node = unsafe { &*n.cast::<Node<K, V>>() };
            n = match key.cmp(&node.key) {
                Ordering::Less => node.link.left,
                Ordering::Greater => node.link.right,
                Ordering::Equal => break,
            };
        }
        n
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        let n = self.find(key);
        // SAFETY: a non-null result heads a live node of this tree (type
        // invariant), borrowed with the tree
        (!n.is_null()).then(|| unsafe { &(*n.cast::<Node<K, V>>()).value })
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let n = self.find(key);
        // SAFETY: as in `get`; the tree, and so the node, is borrowed
        // mutably
        (!n.is_null()).then(|| unsafe { &mut (*n.cast::<Node<K, V>>()).value })
    }

    /// Insert `node`, allocating nothing; the node it replaces (same
    /// key), if any
    pub fn insert(&mut self, node: RbTreeNode<K, V>) -> Option<RbTreeNode<K, V>> {
        let new = Box::into_raw(node.node);
        let link = new.cast::<RbLink>();
        let mut parent = null_mut();
        let mut slot: *mut *mut RbLink = &raw mut self.root.node;
        // SAFETY: `new` is a node of ours, on no tree; `slot` is the root
        // slot or a child slot of a live link of this tree, each heading
        // a live node (type invariant)
        unsafe {
            while !(*slot).is_null() {
                parent = *slot;
                let cur = parent.cast::<Node<K, V>>();
                slot = match (*new).key.cmp(&(*cur).key) {
                    Ordering::Less => &raw mut (*parent).left,
                    Ordering::Greater => &raw mut (*parent).right,
                    Ordering::Equal => {
                        // INVARIANT: `new` takes `cur`'s place, with an
                        // equal key; `cur` leaves the tree to its box
                        self.root.replace(parent, link);
                        return Some(RbTreeNode {
                            node: Box::from_raw(cur),
                        });
                    }
                };
            }
            rb_link_node(link, parent, slot);
            self.root.insert_color(link);
        }
        // INVARIANT: one more link, owned by the tree (from the box)
        self.len += 1;
        None
    }

    /// Unlink `key`'s node and hand it back (to free after the unlock)
    pub fn remove_node(&mut self, key: &K) -> Option<RbTreeNode<K, V>> {
        let n = self.find(key);
        if n.is_null() {
            return None;
        }
        // SAFETY: `n` is a link of this tree (type invariant)
        unsafe { self.root.erase(n) };
        // INVARIANT: `n` is off the tree; its node goes back to a box
        self.len -= 1;
        // SAFETY: `n` heads a node leaked from a `Box` (type invariant),
        // which nothing reaches now that it is off the tree
        let node = unsafe { Box::from_raw(n.cast::<Node<K, V>>()) };
        Some(RbTreeNode { node })
    }

    /// The entries with keys from `key` up, in order (BTreeMap
    /// `range(key..)`; Rust-for-Linux `cursor_lower_bound`)
    pub fn range_from(&self, key: &K) -> Iter<'_, K, V> {
        let (mut n, mut first) = (self.root.node, null_mut());
        while !n.is_null() {
            // SAFETY: a link of this tree heads a live node (type
            // invariant)
            let node = unsafe { &*n.cast::<Node<K, V>>() };
            if *key <= node.key {
                first = n;
                n = node.link.left;
            } else {
                n = node.link.right;
            }
        }
        Iter {
            cur: first,
            _t: PhantomData,
        }
    }
}

impl<K, V> Drop for RbTree<K, V> {
    /// Free every node, each after its children (Linux
    /// rbtree_postorder_for_each_entry_safe)
    fn drop(&mut self) {
        let mut n = self.root.node;
        if !n.is_null() {
            // SAFETY: the tree's links are live (type invariant)
            n = unsafe { rb_left_deepest(n) };
        }
        while !n.is_null() {
            // SAFETY: in post-order, `n`, its ancestors and the subtrees
            // right of it are not freed yet
            let next = unsafe { rb_next_postorder(n) };
            // SAFETY: `n` heads a node leaked from a `Box` (type
            // invariant), and the walk never reads it again
            drop(unsafe { Box::from_raw(n.cast::<Node<K, V>>()) });
            n = next;
        }
    }
}

/// In-order iterator over an [`RbTree`]'s entries
pub struct Iter<'a, K, V> {
    cur: *mut RbLink,
    _t: PhantomData<&'a RbTree<K, V>>,
}

impl<'a, K, V> Iterator for Iter<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        if self.cur.is_null() {
            return None;
        }
        // SAFETY: a link of the borrowed tree heads a live node (its type
        // invariant), which lives while the tree is borrowed
        let node = unsafe { &*self.cur.cast::<Node<K, V>>() };
        // SAFETY: as above: the tree's links are live
        self.cur = unsafe { rb_next(self.cur) };
        Some((&node.key, &node.value))
    }
}

/// Memory for one node, allocated before the tree's lock is taken
/// (Rust-for-Linux `RBTreeNodeReservation`)
pub struct RbTreeNodeReservation<K, V> {
    node: Box<MaybeUninit<Node<K, V>>>,
}

impl<K, V> RbTreeNodeReservation<K, V> {
    /// ENOMEM if it cannot be had
    pub fn new() -> Result<Self, KernelError> {
        Ok(Self {
            node: try_box(MaybeUninit::uninit())?,
        })
    }

    /// Infallible: see `kalloc::box_nofail`
    #[track_caller]
    pub fn new_nofail() -> Self {
        Self {
            node: box_nofail(MaybeUninit::uninit()),
        }
    }

    /// The node for `key` and `value`, allocating nothing
    pub fn into_node(self, key: K, value: V) -> RbTreeNode<K, V> {
        let node = Node {
            link: RbLink::new(),
            key,
            value,
        };
        RbTreeNode {
            node: Box::write(self.node, node),
        }
    }
}

/// A node off any tree, for [`RbTree::insert`] or back from
/// [`RbTree::remove_node`] (Rust-for-Linux `RBTreeNode`)
pub struct RbTreeNode<K, V> {
    node: Box<Node<K, V>>,
}

impl<K, V> RbTreeNode<K, V> {
    /// The key and value, freeing the node (Rust-for-Linux
    /// `to_key_value`)
    pub fn to_key_value(self) -> (K, V) {
        let n = *self.node;
        (n.key, n.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::rc::Rc;
    use alloc::vec::Vec;

    fn node<K, V>(k: K, v: V) -> RbTreeNode<K, V> {
        RbTreeNodeReservation::new().unwrap().into_node(k, v)
    }

    /// xorshift64: deterministic, no crates
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// Check the subtree at `n` (child of `parent`) and append its keys
    /// in order; its black height
    fn check_sub<V>(n: *mut RbLink, parent: *mut RbLink, keys: &mut Vec<u32>) -> usize {
        if n.is_null() {
            return 1;
        }
        // SAFETY: links of a live test tree
        unsafe {
            assert_eq!(rb_parent(n), parent, "parent pointer");
            if rb_is_red(n) {
                for c in [(*n).left, (*n).right] {
                    assert!(c.is_null() || rb_is_black(c), "red-red");
                }
            }
            let lh = check_sub::<V>((*n).left, n, keys);
            keys.push((*n.cast::<Node<u32, V>>()).key);
            let rh = check_sub::<V>((*n).right, n, keys);
            assert_eq!(lh, rh, "black height");
            lh + usize::from(rb_is_black(n))
        }
    }

    /// The red-black invariants; the keys in order
    fn check<V>(t: &RbTree<u32, V>) -> Vec<u32> {
        let root = t.root.node;
        // SAFETY: a link of the live tree
        assert!(root.is_null() || unsafe { rb_is_black(root) }, "red root");
        let mut keys = Vec::new();
        check_sub::<V>(root, null_mut(), &mut keys);
        assert!(keys.windows(2).all(|w| w[0] < w[1]), "unsorted");
        assert_eq!(keys.len(), t.len());
        keys
    }

    #[test]
    fn random_against_btreemap() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let mut t = RbTree::new();
        let mut m = BTreeMap::new();
        for i in 0..40_000u64 {
            let k = rng.below(300) as u32;
            match rng.below(5) {
                0 | 1 => {
                    let old = t.insert(node(k, i));
                    assert_eq!(old.map(|n| n.node.value), m.insert(k, i));
                }
                2 => {
                    let old = t.remove_node(&k).map(|n| n.node.value);
                    assert_eq!(old, m.remove(&k));
                }
                3 => {
                    if let Some(v) = t.get_mut(&k) {
                        *v += 1;
                    }
                    if let Some(v) = m.get_mut(&k) {
                        *v += 1;
                    }
                    assert_eq!(t.get(&k), m.get(&k));
                }
                _ => {
                    let a: Vec<_> = t.range_from(&k).map(|(k, v)| (*k, *v)).collect();
                    let b: Vec<_> = m.range(k..).map(|(k, v)| (*k, *v)).collect();
                    assert_eq!(a, b);
                }
            }
            let keys = check(&t);
            assert!(keys.iter().eq(m.keys()));
        }
    }

    #[test]
    fn ascending_and_descending() {
        let mut t = RbTree::new();
        for k in 0..1000 {
            assert!(t.insert(node(k, ())).is_none());
        }
        for k in (1000..2000).rev() {
            assert!(t.insert(node(k, ())).is_none());
        }
        assert_eq!(check(&t), (0..2000).collect::<Vec<_>>());
        for k in (0..2000).step_by(2) {
            assert!(t.remove_node(&k).is_some());
            check(&t);
        }
        assert!(t.remove_node(&0).is_none());
        assert!(t.iter().map(|(k, _)| *k).eq((1..2000).step_by(2)));
        assert_eq!(t.last().map(|(k, _)| *k), Some(1999));
        assert_eq!(t.range_from(&1999).count(), 1);
        assert_eq!(t.range_from(&2000).count(), 0);
    }

    #[test]
    fn empty_iter_last() {
        let mut t: RbTree<u32, u32> = RbTree::new();
        assert!(t.iter().next().is_none() && t.last().is_none());
        t.insert(node(3, 30));
        assert_eq!(t.last(), Some((&3, &30)));
        assert_eq!(
            t.remove_node(&3).map(RbTreeNode::to_key_value),
            Some((3, 30))
        );
        assert!(t.iter().next().is_none());
    }

    #[test]
    fn replace_returns_old() {
        let mut t = RbTree::new();
        for k in 0..10 {
            assert!(t.insert(node(k, k * 10)).is_none());
        }
        let old = t.insert(node(5, 555)).expect("replaced");
        assert_eq!((old.node.key, old.node.value), (5, 50));
        assert_eq!(t.get(&5), Some(&555));
        assert_eq!(t.len(), 10);
        check(&t);
        // A returned node goes back in
        assert!(t.remove_node(&5).is_some());
        assert!(t.insert(old).is_none());
        assert_eq!(t.get(&5), Some(&50));
        check(&t);
    }

    #[test]
    fn drop_frees_all() {
        let live = Rc::new(());
        let mut rng = Rng(42);
        let mut t = RbTree::new();
        let mut out = Vec::new();
        for _ in 0..5000 {
            let k = rng.below(1000) as u32;
            if rng.below(3) == 0 {
                out.extend(t.remove_node(&k));
            } else {
                out.extend(t.insert(node(k, live.clone())));
            }
        }
        assert!(!t.is_empty());
        assert_eq!(Rc::strong_count(&live), 1 + t.len() + out.len());
        drop(t);
        drop(out);
        assert_eq!(Rc::strong_count(&live), 1);
    }
}
