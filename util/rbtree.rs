//! Red-black trees (Linux lib/rbtree.c, include/linux/rbtree.h)
//!
//! [`RbTree`] is a sorted map whose nodes the caller allocates before
//! taking the tree's lock ([`RbTreeNodeReservation`], Linux's rb_node
//! embedded in an object allocated beforehand): inserting and removing
//! allocate and free nothing, so a tree can change under a spinlock. A
//! removed node comes back to the caller, to free after the unlock. The
//! API follows Rust-for-Linux's `kernel::rbtree`.
//!
//! [`RbRoot`] is the intrusive form, as Linux uses rb_node most: the
//! item embeds an [`RbNode`] (an `skb->rbnode`), an [`RbAdapter`] (made
//! with [`rb_adapter!`]) maps between the two, and the tree owns each
//! item through a [`ListPtr`] (`Box` or `Arc`), like `util::list`'s
//! `PtrList`. The caller orders the items (`insert_by`), so keys may be
//! modular (TCP sequence numbers); a cursor walks the tree and erases or
//! replaces items on the way. Nothing allocates.
//!
//! The rebalancing core is lib/rbtree.c without the augmented
//! callbacks: [`RbLink`] is struct rb_node, its color in bit 0 of the
//! parent pointer (set and cleared with `map_addr`, so the pointer keeps
//! its provenance).

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::cmp::Ordering;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, Ordering::Relaxed};

use crate::mm::page_alloc::Gfp;
use crate::util::error::KernelError;
use crate::util::kalloc::{box_nofail, try_box, try_box_gfp};
use crate::util::list::ListPtr;

const RED: usize = 0;
const BLACK: usize = 1;

/// A node's tree hook (Linux struct rb_node): the parent pointer with
/// the color in bit 0 (a link is pointer-aligned, so that bit is free),
/// and the children
#[repr(C)]
#[derive(Clone, Copy)]
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

/// The in-order predecessor of `n` (Linux rb_prev)
///
/// # Safety
/// As [`rb_next`].
unsafe fn rb_prev(mut n: *mut RbLink) -> *mut RbLink {
    // SAFETY: the caller: every link reached from `n` is live
    unsafe {
        if !(*n).left.is_null() {
            n = (*n).left;
            while !(*n).right.is_null() {
                n = (*n).right;
            }
            return n;
        }
        let mut parent = rb_parent(n);
        while !parent.is_null() && n == (*parent).left {
            n = parent;
            parent = rb_parent(n);
        }
        parent
    }
}

/// The leftmost link under `n`, or null if `n` is null (Linux rb_first)
///
/// # Safety
/// `n` is null or a link of a valid tree whose links are all live.
unsafe fn rb_first(mut n: *mut RbLink) -> *mut RbLink {
    // SAFETY: the caller
    while !n.is_null() && unsafe { !(*n).left.is_null() } {
        // SAFETY: as above
        n = unsafe { (*n).left };
    }
    n
}

/// The rightmost link under `n`, or null if `n` is null (Linux rb_last)
///
/// # Safety
/// As [`rb_first`].
unsafe fn rb_last(mut n: *mut RbLink) -> *mut RbLink {
    // SAFETY: the caller
    while !n.is_null() && unsafe { !(*n).right.is_null() } {
        // SAFETY: as above
        n = unsafe { (*n).right };
    }
    n
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
        Iter {
            // SAFETY: the tree's links are live (type invariant)
            cur: unsafe { rb_first(self.root.node) },
            _t: PhantomData,
        }
    }

    /// The entry with the greatest key (Linux rb_last)
    pub fn last(&self) -> Option<(&K, &V)> {
        // SAFETY: the tree's links are live (type invariant)
        let n = unsafe { rb_last(self.root.node) };
        if n.is_null() {
            return None;
        }
        // SAFETY: a link of this tree heads a live node (type invariant),
        // borrowed with the tree
        let node = unsafe { &*n.cast::<Node<K, V>>() };
        Some((&node.key, &node.value))
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

// SAFETY: it owns its memory alone and holds no initialized link, key
// or value: Send and Sync as a `Box` of the node would be
unsafe impl<K: Send, V: Send> Send for RbTreeNodeReservation<K, V> {}
// SAFETY: as above; `&self` gives nothing out
unsafe impl<K: Sync, V: Sync> Sync for RbTreeNodeReservation<K, V> {}

impl<K, V> RbTreeNodeReservation<K, V> {
    /// ENOMEM if it cannot be had
    pub fn new() -> Result<Self, KernelError> {
        Ok(Self {
            node: try_box(MaybeUninit::uninit())?,
        })
    }

    /// As [`RbTreeNodeReservation::new`], with `gfp` named (Linux
    /// kmalloc(size, GFP_ATOMIC) in atomic context)
    pub fn new_gfp(gfp: Gfp) -> Result<Self, KernelError> {
        Ok(Self {
            node: try_box_gfp(MaybeUninit::uninit(), gfp)?,
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

    /// Drop the key and value and keep the memory for another node
    /// (Rust-for-Linux `into_reservation`)
    pub fn into_reservation(self) -> RbTreeNodeReservation<K, V> {
        let p = Box::into_raw(self.node);
        // SAFETY: `p` is a live, initialized node from the box; its key
        // is dropped once and not read again
        unsafe { core::ptr::drop_in_place(&raw mut (*p).key) };
        // SAFETY: as above, for the value
        unsafe { core::ptr::drop_in_place(&raw mut (*p).value) };
        // SAFETY: the box's allocation, whose contents are now treated
        // as uninitialized (`MaybeUninit<Node>` has `Node`'s layout)
        let node = unsafe { Box::from_raw(p.cast::<MaybeUninit<Node<K, V>>>()) };
        RbTreeNodeReservation { node }
    }
}

/// The tree hook embedded in an item (Linux struct rb_node inside the
/// item, e.g. `skb->rbnode`)
///
/// # Invariants
/// `linked` is true exactly while the node is on an [`RbRoot`] or
/// claimed by an insert into one; `link` is read and written only by
/// that tree, through its owner's `&RbRoot` (reads) or `&mut RbRoot`.
#[repr(C)]
pub struct RbNode {
    /// First, so a link pointer is its node's
    link: UnsafeCell<RbLink>,
    linked: AtomicBool,
}

// SAFETY: `link` is only touched by the one tree the node is on, under
// that tree's borrow (type invariant), and `linked` is atomic: an item
// embedding a node stays Send
unsafe impl Send for RbNode {}
// SAFETY: as above: `&RbNode` alone reads only `linked`
unsafe impl Sync for RbNode {}

impl Default for RbNode {
    fn default() -> Self {
        Self::new()
    }
}

impl RbNode {
    pub const fn new() -> Self {
        // INVARIANT: on no tree
        Self {
            link: UnsafeCell::new(RbLink::new()),
            linked: AtomicBool::new(false),
        }
    }

    /// On a tree (Linux !RB_EMPTY_NODE): exact under the lock of the
    /// tree it may be on, a hint without it
    pub fn is_linked(&self) -> bool {
        self.linked.load(Relaxed)
    }

    /// Claim the node for an insert: false if it is on a tree or being
    /// inserted (two trees under different locks cannot both win).
    /// Acquire pairs with `release`: the last tree's accesses to `link`
    /// happen before the next one's.
    fn claim(&self) -> bool {
        self.linked
            .compare_exchange(false, true, core::sync::atomic::Ordering::Acquire, Relaxed)
            .is_ok()
    }

    /// Mark the node free again (Linux RB_CLEAR_NODE)
    ///
    /// # Safety
    /// No tree holds it, and its last tree touches `link` no more.
    unsafe fn release(&self) {
        self.linked
            .store(false, core::sync::atomic::Ordering::Release);
    }

    /// The link, as the tree core uses it (derived from the whole node,
    /// so it casts back to the node)
    #[inline]
    fn raw(&self) -> *mut RbLink {
        core::ptr::from_ref(self).cast_mut().cast::<RbLink>()
    }
}

/// Maps a tree's items to their [`RbNode`] and back
///
/// # Safety
/// `node` returns the same field of the item on every call, and `item`
/// is its inverse: `item(node(x)) == x`.
pub unsafe trait RbAdapter {
    type Item;
    fn node(item: &Self::Item) -> &RbNode;
    /// # Safety
    /// `node` is the node of a live `Item`.
    unsafe fn item(node: *const RbNode) -> *const Self::Item;
}

/// `rb_adapter!(vis Name, Type, field)`: an [`RbAdapter`] for
/// `Type.field` (a nested `a.b` field too)
#[macro_export]
macro_rules! rb_adapter {
    ($vis:vis $name:ident, $t:ty, $($field:ident).+) => {
        $vis struct $name;
        // SAFETY: offset_of! gives the field's place in the item
        unsafe impl $crate::util::rbtree::RbAdapter for $name {
            type Item = $t;
            fn node(item: &$t) -> &$crate::util::rbtree::RbNode {
                &item.$($field).+
            }
            unsafe fn item(node: *const $crate::util::rbtree::RbNode) -> *const $t {
                // SAFETY: the caller passes a node inside a live item
                unsafe { node.cast::<u8>().sub(core::mem::offset_of!($t, $($field).+)).cast::<$t>() }
            }
        }
    };
}

/// The item whose node's link is `l`
///
/// # Safety
/// `l` is the link of the node of a live `A::Item` (from
/// [`RbNode::raw`]).
unsafe fn rb_item<A: RbAdapter>(l: *mut RbLink) -> *const A::Item {
    // SAFETY: the caller; the link is at offset 0 of its node
    unsafe { A::item(l.cast_const().cast::<RbNode>()) }
}

/// A red-black tree of items linked through their embedded [`RbNode`]
/// (Linux struct rb_root of e.g. sk_buffs, `tp->out_of_order_queue`),
/// owning each through `P` (`Box`: the item; `Arc`: one reference).
/// The caller orders it: [`RbRoot::insert_by`] takes the comparison.
/// Nothing allocates, so it can change under a spinlock.
///
/// # Invariants
/// `root.node` is null or the root of a valid red-black tree of `len`
/// links (as [`RbTree`] keeps them). Each link is the `link` of the
/// claimed [`RbNode`] (`A::node`) of an item inserted with
/// `P::into_raw`, owned by this tree until it leaves through
/// `P::from_raw`.
pub struct RbRoot<A: RbAdapter, P: ListPtr<Target = A::Item>> {
    root: Root,
    len: usize,
    _a: PhantomData<fn() -> A>,
    /// It drops `P`s wherever it goes
    _own: PhantomData<P>,
}

// SAFETY: the tree owns its `P`s and only it reaches their nodes (type
// invariant): Send as the `P`s are
unsafe impl<A: RbAdapter, P: ListPtr<Target = A::Item> + Send> Send for RbRoot<A, P> {}
// SAFETY: `&RbRoot` hands out only `&A::Item`, which `P: Sync` allows
// (`Box<T>`: `T: Sync`; `Arc<T>`: `T: Send + Sync`)
unsafe impl<A: RbAdapter, P: ListPtr<Target = A::Item> + Sync> Sync for RbRoot<A, P> {}

impl<A: RbAdapter, P: ListPtr<Target = A::Item>> Default for RbRoot<A, P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: RbAdapter, P: ListPtr<Target = A::Item>> RbRoot<A, P> {
    pub const fn new() -> Self {
        // INVARIANT: the empty tree
        Self {
            root: Root { node: null_mut() },
            len: 0,
            _a: PhantomData,
            _own: PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The item at `l`, borrowed with the tree; None for null
    ///
    /// # Safety
    /// `l` is null or a link of this tree.
    unsafe fn get(&self, l: *mut RbLink) -> Option<&A::Item> {
        // SAFETY: the caller: a link of this tree heads a live item it
        // owns (type invariant), borrowed with it
        (!l.is_null()).then(|| unsafe { &*rb_item::<A>(l) })
    }

    /// The first item in order (Linux rb_first)
    pub fn first(&self) -> Option<&A::Item> {
        // SAFETY: the tree's links are live (type invariant)
        let l = unsafe { rb_first(self.root.node) };
        // SAFETY: null or a link of this tree
        unsafe { self.get(l) }
    }

    /// The last item in order (Linux rb_last)
    pub fn last(&self) -> Option<&A::Item> {
        // SAFETY: the tree's links are live (type invariant)
        let l = unsafe { rb_last(self.root.node) };
        // SAFETY: null or a link of this tree
        unsafe { self.get(l) }
    }

    /// The items in order (Linux rb_first + rb_next)
    pub fn iter(&self) -> RbIter<'_, A> {
        RbIter {
            // SAFETY: the tree's links are live (type invariant)
            cur: unsafe { rb_first(self.root.node) },
            _t: PhantomData,
        }
    }

    /// The empty slot `new` hangs from, and its parent: left of every
    /// item it is `less` than, else right (after its equals)
    fn slot(
        &mut self,
        new: &A::Item,
        less: impl Fn(&A::Item, &A::Item) -> bool,
    ) -> (*mut RbLink, *mut *mut RbLink) {
        let mut parent = null_mut();
        let mut slot: *mut *mut RbLink = &raw mut self.root.node;
        loop {
            // SAFETY: the root slot or a child slot of a live link of
            // this tree (type invariant)
            let cur = unsafe { *slot };
            if cur.is_null() {
                return (parent, slot);
            }
            parent = cur;
            // SAFETY: a link of this tree
            let item = unsafe { self.get(cur) }.expect("non-null");
            slot = if less(new, item) {
                // SAFETY: `cur` is a live link of this tree
                unsafe { &raw mut (*cur).left }
            } else {
                // SAFETY: as above
                unsafe { &raw mut (*cur).right }
            };
        }
    }

    /// Insert `item` in the order `less` gives (`less(a, b)`: a goes
    /// before b), after any equal ones; allocates nothing (Linux
    /// rb_link_node + rb_insert_color after the caller's walk, e.g.
    /// tcp_data_queue_ofo's `before(seq, TCP_SKB_CB(skb1)->seq)`).
    /// Panics if the item is on a tree.
    pub fn insert_by(&mut self, item: P, less: impl Fn(&A::Item, &A::Item) -> bool) {
        let (parent, slot) = self.slot(&item, less);
        assert!(A::node(&item).claim(), "rbtree: item already linked");
        let p = P::into_raw(item);
        // SAFETY: live while the tree owns it (from into_raw)
        let l = A::node(unsafe { &*p }).raw();
        // SAFETY: `l` is claimed for this insert and on no tree; `slot`
        // is an empty slot of this tree hanging from `parent`, unchanged
        // since the walk
        unsafe { rb_link_node(l, parent, slot) };
        // SAFETY: just linked; every link of the tree is live
        unsafe { self.root.insert_color(l) };
        // INVARIANT: one more link, claimed, owned through into_raw
        self.len += 1;
    }

    /// Unlink `l` and hand back the tree's pointer to its item (Linux
    /// rb_erase)
    ///
    /// # Safety
    /// `l` is a link of this tree.
    unsafe fn unlink(&mut self, l: *mut RbLink) -> P {
        // SAFETY: the caller; the tree's links are live (type invariant)
        unsafe { self.root.erase(l) };
        // INVARIANT: off the tree; its pointer goes back to the caller
        self.len -= 1;
        // SAFETY: the link of a live item's node (type invariant)
        let p = unsafe { rb_item::<A>(l) };
        // SAFETY: no tree holds it, and this one is done with it
        unsafe { A::node(&*p).release() };
        // SAFETY: inserted with into_raw (type invariant), taken back once
        unsafe { P::from_raw(p) }
    }

    /// Remove and return the first item (Linux rb_first + rb_erase, to
    /// drain: skb_rbtree_purge)
    pub fn pop_first(&mut self) -> Option<P> {
        // SAFETY: the tree's links are live (type invariant)
        let l = unsafe { rb_first(self.root.node) };
        // SAFETY: a link of this tree
        (!l.is_null()).then(|| unsafe { self.unlink(l) })
    }

    /// Unlink `item` and hand back the tree's pointer (Linux rb_erase).
    /// Unsafe because a node does not record which tree it is on: an
    /// owner id per item would cost a word and a global counter, for
    /// users that remove through a cursor anyway.
    ///
    /// # Safety
    /// `item` is on this tree.
    pub unsafe fn remove(&mut self, item: &A::Item) -> P {
        let l = A::node(item).raw();
        // SAFETY: the caller: a link of this tree
        unsafe { self.unlink(l) }
    }

    fn cursor(&mut self, cur: *mut RbLink) -> RbCursorMut<'_, A, P> {
        RbCursorMut { tree: self, cur }
    }

    /// A cursor at the first item (the ghost if empty)
    pub fn cursor_front_mut(&mut self) -> RbCursorMut<'_, A, P> {
        // SAFETY: the tree's links are live (type invariant)
        let l = unsafe { rb_first(self.root.node) };
        // INVARIANT: null or a link of this tree
        self.cursor(l)
    }

    /// A cursor at the last item (the ghost if empty)
    pub fn cursor_back_mut(&mut self) -> RbCursorMut<'_, A, P> {
        // SAFETY: the tree's links are live (type invariant)
        let l = unsafe { rb_last(self.root.node) };
        // INVARIANT: null or a link of this tree
        self.cursor(l)
    }

    /// A cursor at the last item for which `at_or_before` holds (the
    /// ghost if none), where `at_or_before` holds for a prefix of the
    /// order: the greatest item at or before a key, as
    /// tcp_data_queue_ofo looks for the skb whose seq is the greatest
    /// not after the new one's (`|s| !after(s.seq, seq)`). O(log n).
    pub fn cursor_floor_mut(
        &mut self,
        at_or_before: impl Fn(&A::Item) -> bool,
    ) -> RbCursorMut<'_, A, P> {
        let (mut n, mut best) = (self.root.node, null_mut());
        while !n.is_null() {
            // SAFETY: a link of this tree
            let item = unsafe { self.get(n) }.expect("non-null");
            let right = at_or_before(item);
            if right {
                best = n;
            }
            // SAFETY: `n` is a live link of this tree
            n = unsafe { if right { (*n).right } else { (*n).left } };
        }
        // INVARIANT: null or a link of this tree
        self.cursor(best)
    }
}

impl<A: RbAdapter, P: ListPtr<Target = A::Item>> Drop for RbRoot<A, P> {
    /// Drop every item's pointer, each after its children (Linux
    /// rbtree_postorder_for_each_entry_safe)
    fn drop(&mut self) {
        let mut n = self.root.node;
        if !n.is_null() {
            // SAFETY: the tree's links are live (type invariant)
            n = unsafe { rb_left_deepest(n) };
        }
        while !n.is_null() {
            // SAFETY: in post-order, `n`, its ancestors and the subtrees
            // right of it are still on the tree; released nodes are
            // never read again
            let next = unsafe { rb_next_postorder(n) };
            // SAFETY: the link of a live item's node (type invariant)
            let p = unsafe { rb_item::<A>(n) };
            // SAFETY: the walk is done with `n`; the tree goes away
            unsafe { A::node(&*p).release() };
            // SAFETY: inserted with into_raw (type invariant), taken back
            // once
            drop(unsafe { P::from_raw(p) });
            n = next;
        }
    }
}

/// In-order iterator over an [`RbRoot`]'s items
pub struct RbIter<'a, A: RbAdapter> {
    cur: *mut RbLink,
    _t: PhantomData<&'a A::Item>,
}

impl<'a, A: RbAdapter> Iterator for RbIter<'a, A> {
    type Item = &'a A::Item;

    fn next(&mut self) -> Option<&'a A::Item> {
        if self.cur.is_null() {
            return None;
        }
        // SAFETY: a link of the borrowed tree heads a live item it owns
        // (its type invariant), live while the tree is borrowed
        let item = unsafe { &*rb_item::<A>(self.cur) };
        // SAFETY: as above: the tree's links are live
        self.cur = unsafe { rb_next(self.cur) };
        Some(item)
    }
}

/// A position in an [`RbRoot`] that can erase or replace the item it is
/// at, Linux style (rb_erase/rb_replace_node while walking with
/// rb_next/rb_prev). Besides the items there is one "ghost" position,
/// past both ends: stepping forward from it goes to the first item,
/// back to the last.
///
/// # Invariants
/// `cur` is null (the ghost) or a link of `tree`.
pub struct RbCursorMut<'a, A: RbAdapter, P: ListPtr<Target = A::Item>> {
    tree: &'a mut RbRoot<A, P>,
    cur: *mut RbLink,
}

impl<A: RbAdapter, P: ListPtr<Target = A::Item>> RbCursorMut<'_, A, P> {
    /// The link after `cur` (the first after the ghost; the ghost after
    /// the last)
    fn next_link(&self) -> *mut RbLink {
        if self.cur.is_null() {
            // SAFETY: the tree's links are live (its type invariant)
            unsafe { rb_first(self.tree.root.node) }
        } else {
            // SAFETY: `cur` is a link of the tree (type invariant)
            unsafe { rb_next(self.cur) }
        }
    }

    /// The link before `cur` (the last before the ghost)
    fn prev_link(&self) -> *mut RbLink {
        if self.cur.is_null() {
            // SAFETY: the tree's links are live (its type invariant)
            unsafe { rb_last(self.tree.root.node) }
        } else {
            // SAFETY: `cur` is a link of the tree (type invariant)
            unsafe { rb_prev(self.cur) }
        }
    }

    /// The item at the cursor; None at the ghost
    pub fn current(&self) -> Option<&A::Item> {
        // SAFETY: null or a link of the tree (type invariant)
        unsafe { self.tree.get(self.cur) }
    }

    /// The item after the cursor (Linux rb_next), without moving
    pub fn peek_next(&self) -> Option<&A::Item> {
        let l = self.next_link();
        // SAFETY: null or a link of the tree
        unsafe { self.tree.get(l) }
    }

    /// The item before the cursor (Linux rb_prev), without moving
    pub fn peek_prev(&self) -> Option<&A::Item> {
        let l = self.prev_link();
        // SAFETY: null or a link of the tree
        unsafe { self.tree.get(l) }
    }

    /// Step to the next item (Linux rb_next)
    pub fn move_next(&mut self) {
        // INVARIANT: null or a link of the tree
        self.cur = self.next_link();
    }

    /// Step to the previous item (Linux rb_prev)
    pub fn move_prev(&mut self) {
        // INVARIANT: null or a link of the tree
        self.cur = self.prev_link();
    }

    /// Unlink the current item and hand back the tree's pointer; the
    /// cursor moves to its successor (Linux rb_next, then rb_erase).
    /// None at the ghost.
    pub fn remove_current(&mut self) -> Option<P> {
        if self.cur.is_null() {
            return None;
        }
        let (l, next) = (self.cur, self.next_link());
        // INVARIANT: the successor stays on the tree
        self.cur = next;
        // SAFETY: a link of the tree (type invariant)
        Some(unsafe { self.tree.unlink(l) })
    }

    /// Put `new` in the current item's place and color, and hand back
    /// the tree's pointer to the old one; the cursor stays at `new`
    /// (Linux rb_replace_node). The caller keeps the order: `new` sorts
    /// where the old item did. Panics at the ghost or if `new` is on a
    /// tree.
    pub fn replace_current(&mut self, new: P) -> P {
        let old = self.cur;
        assert!(!old.is_null(), "rbtree: replace at the ghost");
        assert!(A::node(&new).claim(), "rbtree: item already linked");
        let p = P::into_raw(new);
        // SAFETY: live while the tree owns it (from into_raw)
        let l = A::node(unsafe { &*p }).raw();
        // SAFETY: `old` is a link of the tree (type invariant), `l` a
        // claimed link on no tree
        unsafe { self.tree.root.replace(old, l) };
        // INVARIANT: `l` holds `old`'s place, owned through into_raw
        self.cur = l;
        // SAFETY: `old` is off the tree, its item live (type invariant)
        let q = unsafe { rb_item::<A>(old) };
        // SAFETY: no tree holds it, and this one is done with it
        unsafe { A::node(&*q).release() };
        // SAFETY: inserted with into_raw (type invariant), taken back once
        unsafe { P::from_raw(q) }
    }
}

/// Puts a node's tree state back after its item was lent out mutably,
/// even if the borrower unwinds
struct Relink<A: RbAdapter> {
    item: *const A::Item,
    link: RbLink,
}

impl<A: RbAdapter> Drop for Relink<A> {
    fn drop(&mut self) {
        // SAFETY: an item the tree owns (`with_current_mut`), no longer
        // lent out
        let node = A::node(unsafe { &*self.item });
        // SAFETY: the tree's own link, which only it touches (RbNode
        // type invariant); nothing else reads it now
        unsafe { node.raw().write(self.link) };
        // INVARIANT: still on the tree, as before the loan
        node.linked.store(true, Relaxed);
    }
}

impl<A: RbAdapter> RbCursorMut<'_, A, Box<A::Item>> {
    /// Run `f` on the current item mutably (the tree owns it as a
    /// `Box`, so uniquely); None at the ghost. `f` keeps the item's
    /// place in the order. A bare `&mut` would let the caller overwrite
    /// the item's [`RbNode`] (`*item = other`) and corrupt the tree, so
    /// the item is lent to a closure and its node's tree state put back
    /// afterwards; a node moved out of the item keeps saying it is
    /// linked, so inserting its new owner panics.
    pub fn with_current_mut<R>(&mut self, f: impl FnOnce(&mut A::Item) -> R) -> Option<R> {
        if self.cur.is_null() {
            return None;
        }
        // SAFETY: a link of the tree (type invariant), heading its item
        let item = unsafe { rb_item::<A>(self.cur) }.cast_mut();
        // SAFETY: the tree's live link
        let link = unsafe { self.cur.read() };
        let relink = Relink::<A> { item, link };
        // SAFETY: the tree owns the item as a Box, so nothing else
        // reaches it, and the cursor borrows the tree mutably; the tree
        // reads no link while `f` runs
        let r = f(unsafe { &mut *item });
        drop(relink);
        Some(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::rc::Rc;
    use alloc::sync::Arc;
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
    /// (`key` of each link) in order; its black height
    fn check_sub(
        n: *mut RbLink,
        parent: *mut RbLink,
        keys: &mut Vec<u32>,
        key: &impl Fn(*mut RbLink) -> u32,
    ) -> usize {
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
            let lh = check_sub((*n).left, n, keys, key);
            keys.push(key(n));
            let rh = check_sub((*n).right, n, keys, key);
            assert_eq!(lh, rh, "black height");
            lh + usize::from(rb_is_black(n))
        }
    }

    /// The red-black invariants of the tree at `root`; its keys in order
    fn check_root(root: *mut RbLink, key: impl Fn(*mut RbLink) -> u32) -> Vec<u32> {
        // SAFETY: a link of the live tree
        assert!(root.is_null() || unsafe { rb_is_black(root) }, "red root");
        let mut keys = Vec::new();
        check_sub(root, null_mut(), &mut keys, &key);
        keys
    }

    /// The red-black invariants; the keys in order
    fn check<V>(t: &RbTree<u32, V>) -> Vec<u32> {
        // SAFETY: links of the live tree head its nodes
        let keys = check_root(t.root.node, |n| unsafe { (*n.cast::<Node<u32, V>>()).key });
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
    fn node_back_to_reservation() {
        let live = Rc::new(());
        let mut t = RbTree::new();
        t.insert(node(1, live.clone()));
        let r = t.remove_node(&1).expect("present").into_reservation();
        // The value was dropped; the memory takes another node
        assert_eq!(Rc::strong_count(&live), 1);
        t.insert(r.into_node(2, live.clone()));
        assert_eq!(check(&t), [2]);
        drop(t);
        assert_eq!(Rc::strong_count(&live), 1);
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

    #[test]
    fn reservation_gfp() {
        let mut t = RbTree::new();
        let r = RbTreeNodeReservation::new_gfp(Gfp::ATOMIC).unwrap();
        assert!(t.insert(r.into_node(7u32, 70u32)).is_none());
        assert_eq!(t.get(&7), Some(&70));
    }

    /// An intrusive item: its key, an id telling equal keys apart, and a
    /// reference counting live items
    #[derive(Default)]
    struct It {
        key: u32,
        id: u64,
        node: RbNode,
        live: Rc<()>,
    }

    crate::rb_adapter!(ItA, It, node);

    fn it(key: u32, id: u64, live: &Rc<()>) -> It {
        It {
            key,
            id,
            node: RbNode::new(),
            live: live.clone(),
        }
    }

    fn less(a: &It, b: &It) -> bool {
        a.key < b.key
    }

    fn kid(i: &It) -> (u32, u64) {
        (i.key, i.id)
    }

    /// The red-black invariants and `len`; the (key, id)s in order
    fn check_rb<P: ListPtr<Target = It>>(t: &RbRoot<ItA, P>) -> Vec<(u32, u64)> {
        // SAFETY: links of the live tree head its items
        let keys = check_root(t.root.node, |n| unsafe { (*rb_item::<ItA>(n)).key });
        let v: Vec<_> = t.iter().map(kid).collect();
        assert!(keys.iter().eq(v.iter().map(|x| &x.0)));
        assert!(keys.windows(2).all(|w| w[0] <= w[1]), "unsorted");
        assert_eq!(v.len(), t.len());
        assert_eq!(t.is_empty(), v.is_empty());
        assert_eq!(t.first().map(kid), v.first().copied());
        assert_eq!(t.last().map(kid), v.last().copied());
        v
    }

    /// Where an insert of `k` lands in the reference: after its equals
    fn ref_insert(r: &mut Vec<(u32, u64)>, k: u32, id: u64) {
        let at = r.partition_point(|x| x.0 <= k);
        r.insert(at, (k, id));
    }

    /// One random step at a cursor placed by `cursor_floor_mut`
    fn floor_op<P: ListPtr<Target = It>>(
        t: &mut RbRoot<ItA, P>,
        r: &mut Vec<(u32, u64)>,
        rng: &mut Rng,
        mk: fn(It) -> P,
        live: &Rc<()>,
        id: &mut u64,
    ) {
        let k = rng.below(220) as u32;
        let at = r.partition_point(|x| x.0 <= k).checked_sub(1);
        let mut c = t.cursor_floor_mut(|i| i.key <= k);
        assert_eq!(c.current().map(kid), at.map(|a| r[a]));
        let Some(a) = at else {
            // The ghost: next is the first, prev the last
            assert_eq!(c.peek_next().map(kid), r.first().copied());
            assert_eq!(c.peek_prev().map(kid), r.last().copied());
            assert!(c.remove_current().is_none());
            return;
        };
        match rng.below(4) {
            0 => {
                let old = c.remove_current().expect("at an item");
                assert_eq!(kid(&old), r.remove(a));
                assert!(!old.node.is_linked());
                assert_eq!(c.current().map(kid), r.get(a).copied());
            }
            1 => {
                *id += 1;
                let old = c.replace_current(mk(it(r[a].0, *id, live)));
                assert_eq!(kid(&old), r[a]);
                assert!(!old.node.is_linked());
                r[a].1 = *id;
                assert_eq!(c.current().map(kid), Some(r[a]));
            }
            2 => {
                let prev = a.checked_sub(1).map(|b| r[b]);
                assert_eq!(c.peek_prev().map(kid), prev);
                c.move_prev();
                assert_eq!(c.current().map(kid), prev);
            }
            _ => {
                let next = r.get(a + 1).copied();
                assert_eq!(c.peek_next().map(kid), next);
                c.move_next();
                assert_eq!(c.current().map(kid), next);
            }
        }
    }

    /// Walk the whole tree, removing the items `id % 3 == 0` on the way
    fn walk_remove<P: ListPtr<Target = It>>(t: &mut RbRoot<ItA, P>, r: &mut Vec<(u32, u64)>) {
        let mut c = t.cursor_front_mut();
        while let Some(i) = c.current() {
            if i.id % 3 == 0 {
                c.remove_current();
            } else {
                c.move_next();
            }
        }
        r.retain(|x| x.1 % 3 != 0);
    }

    fn random_rb<P: ListPtr<Target = It>>(mk: fn(It) -> P, seed: u64) {
        let live = Rc::new(());
        let mut rng = Rng(seed);
        let mut t: RbRoot<ItA, P> = RbRoot::new();
        let mut r = Vec::new();
        let mut id = 0;
        for _ in 0..20_000 {
            match rng.below(10) {
                0..=4 => {
                    id += 1;
                    let k = rng.below(200) as u32;
                    t.insert_by(mk(it(k, id, &live)), less);
                    ref_insert(&mut r, k, id);
                }
                5 => {
                    let got = t.pop_first().map(|i| kid(&i));
                    assert_eq!(got, (!r.is_empty()).then(|| r.remove(0)));
                }
                6 if rng.below(50) == 0 => walk_remove(&mut t, &mut r),
                _ => floor_op(&mut t, &mut r, &mut rng, mk, &live, &mut id),
            }
            assert_eq!(check_rb(&t), r);
            assert_eq!(Rc::strong_count(&live), 1 + r.len());
        }
        assert!(!r.is_empty());
        // Back to front
        let mut c = t.cursor_back_mut();
        for x in r.iter().rev() {
            assert_eq!(c.current().map(kid), Some(*x));
            c.move_prev();
        }
        assert!(c.current().is_none());
        drop(t);
        assert_eq!(Rc::strong_count(&live), 1);
    }

    #[test]
    fn intrusive_random_box() {
        random_rb::<Box<It>>(Box::new, 0x2545_f491_4f6c_dd1d);
    }

    #[test]
    fn intrusive_random_arc() {
        random_rb::<Arc<It>>(Arc::new, 0x9e37_79b9_7f4a_7c15);
    }

    #[test]
    fn intrusive_equal_keys_go_right() {
        let live = Rc::new(());
        let mut t: RbRoot<ItA, Box<It>> = RbRoot::new();
        for id in 0..100u64 {
            t.insert_by(Box::new(it((id % 3) as u32, id, &live)), less);
        }
        let v = check_rb(&t);
        for k in 0..3 {
            let ids: Vec<_> = v.iter().filter(|x| x.0 == k).map(|x| x.1).collect();
            assert!(ids.windows(2).all(|w| w[0] < w[1]), "insertion order");
        }
        // Drained in order
        let mut out = Vec::new();
        while let Some(i) = t.pop_first() {
            out.push(kid(&i));
        }
        assert_eq!(out, v);
        assert!(t.is_empty() && t.first().is_none());
        assert!(t.cursor_front_mut().current().is_none());
        assert_eq!(Rc::strong_count(&live), 1);
    }

    #[test]
    fn intrusive_arc_shared() {
        let live = Rc::new(());
        let mut t: RbRoot<ItA, Arc<It>> = RbRoot::new();
        let items: Vec<_> = (0..50u32)
            .map(|k| Arc::new(it(k, k.into(), &live)))
            .collect();
        for i in &items {
            assert!(!i.node.is_linked());
            t.insert_by(i.clone(), less);
            assert!(i.node.is_linked());
        }
        check_rb(&t);
        for i in items.iter().step_by(2) {
            // SAFETY: on this tree
            let p = unsafe { t.remove(i) };
            assert!(Arc::ptr_eq(&p, i) && !i.node.is_linked());
        }
        assert!(check_rb(&t).iter().all(|x| x.0 % 2 == 1));
        drop(t);
        // The tree let go of every node: they go on another tree
        assert!(
            items
                .iter()
                .all(|i| !i.node.is_linked() && Arc::strong_count(i) == 1)
        );
        let mut t2: RbRoot<ItA, Arc<It>> = RbRoot::default();
        for i in &items {
            t2.insert_by(i.clone(), less);
        }
        assert_eq!(check_rb(&t2).len(), 50);
    }

    #[test]
    fn intrusive_with_current_mut() {
        let live = Rc::new(());
        let mut t: RbRoot<ItA, Box<It>> = RbRoot::new();
        for k in 0..20u32 {
            t.insert_by(Box::new(it(k, k.into(), &live)), less);
        }
        let mut c = t.cursor_floor_mut(|i| i.key <= 7);
        let old = c.with_current_mut(|i| core::mem::replace(&mut i.id, 700));
        assert_eq!(old, Some(7));
        // Overwriting the whole item leaves the tree intact
        c.with_current_mut(|i| *i = it(8, 800, &live));
        // A node moved out still claims to be linked
        c.move_next();
        let out = c
            .with_current_mut(|i| core::mem::replace(i, it(8, 888, &live)))
            .expect("at 8");
        assert!(out.node.is_linked() && out.key == 8);
        drop(out);
        let v = check_rb(&t);
        assert_eq!(v[7], (8, 800));
        assert_eq!(v[8], (8, 888));
        let mut c = t.cursor_front_mut();
        c.move_prev();
        assert!(c.with_current_mut(|_| ()).is_none());
        drop(t);
        assert_eq!(Rc::strong_count(&live), 1);
    }

    #[test]
    #[should_panic(expected = "already linked")]
    fn intrusive_double_insert_panics() {
        let live = Rc::new(());
        let mut t: RbRoot<ItA, Arc<It>> = RbRoot::new();
        let i = Arc::new(it(1, 1, &live));
        t.insert_by(i.clone(), less);
        t.insert_by(i, less);
    }

    #[test]
    #[should_panic(expected = "already linked")]
    fn intrusive_replace_linked_panics() {
        let live = Rc::new(());
        let mut t: RbRoot<ItA, Arc<It>> = RbRoot::new();
        let i = Arc::new(it(1, 1, &live));
        t.insert_by(i.clone(), less);
        t.insert_by(Arc::new(it(2, 2, &live)), less);
        t.cursor_back_mut().replace_current(i);
    }
}
