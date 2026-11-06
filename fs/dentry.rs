//! Dentry - directory entry cache
//!
//! A dentry represents a name-to-inode mapping in the directory tree.
//! The dentry cache (dcache) speeds up path lookups by caching these mappings.
//!
//! ## Locking Model
//!
//! Following Linux's `d_lock` pattern, each dentry has a single RwLock (`d_lock`)
//! that protects all mutable state. This simplifies lock ordering and matches
//! the proven Linux design.

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use crate::sync::spin::RwLock;

use super::inode::Inode;
use super::name::FileName;
use super::path_ref::Path;
use super::superblock::SuperBlock;
use crate::util::error::KernelError;
use crate::util::kalloc::try_arc;

/// Dentry flags
#[derive(Debug, Clone, Copy, Default)]
pub struct DentryFlags {
    /// Mounts sitting on this dentry, in every namespace (Linux
    /// DCACHE_MOUNTED, held while a struct mountpoint exists): a hint
    /// for the walk; which mount covers it is the namespace's business
    pub mounted: u32,
    /// Dropped from its parent's children: deleted, or replaced by a
    /// rename (Linux d_unhashed)
    pub unhashed: bool,
}

/// The dcache's tree shape: held for writing by d_move / d_exchange,
/// for reading by whoever walks parents and names and needs one
/// consistent picture (is_subdir, full_path) (Linux rename_lock, a
/// seqlock there). Spinning, never taken in IRQ context; taken before
/// any d_lock.
static RENAME_LOCK: RwLock<()> = RwLock::new(());

/// Dentries alive (/proc/sys/fs/dentry-state nr_dentry)
static NR_DENTRY: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(0);

/// Inner mutable state protected by d_lock
struct DentryInner {
    /// Name in the parent (empty for a root); changed by d_move
    name: FileName,
    /// The inode this dentry points to (None for negative dentry)
    inode: Option<Arc<Inode>>,
    /// Parent dentry (None for a root), pinned by the child (Linux
    /// d_parent holds a reference): a cwd or open directory keeps its
    /// whole chain valid
    parent: Option<Arc<Dentry>>,
    /// Children dentries (for directories)
    children: BTreeMap<FileName, Arc<Dentry>>,
    /// Dentry flags
    flags: DentryFlags,
}

/// A directory entry - maps a name to an inode
///
/// ## Locking
///
/// `d_lock` protects all mutable state, the name and parent included
/// (Linux d_lock); a parent's d_lock is taken before a child's. `sb` is
/// immutable.
pub struct Dentry {
    /// Back pointer to superblock - immutable after creation
    pub sb: Weak<SuperBlock>,

    /// Single lock protecting all mutable state (like Linux d_lock)
    d_lock: RwLock<DentryInner>,
}

impl Dentry {
    fn with(name: FileName, inode: Option<Arc<Inode>>, sb: Weak<SuperBlock>) -> Self {
        NR_DENTRY.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Self {
            sb,
            d_lock: RwLock::new(DentryInner {
                name,
                inode,
                parent: None,
                children: BTreeMap::new(),
                flags: DentryFlags::default(),
            }),
        }
    }

    /// Create root dentry for a filesystem
    pub fn new_root(inode: Arc<Inode>, sb: Weak<SuperBlock>) -> Self {
        Self::with(FileName::default(), Some(inode), sb)
    }

    /// Create an anonymous dentry (for pipes, sockets, etc.)
    ///
    /// Anonymous dentries have no superblock and are not part of any filesystem.
    /// They exist solely to provide a File's required dentry reference.
    pub fn new_anonymous(name: FileName, inode: Option<Arc<Inode>>) -> Self {
        Self::with(name, inode, Weak::new())
    }

    /// The child `name` of `parent` with `inode` (Linux d_alloc +
    /// d_add): the cached one if there is one (a negative one gets
    /// `inode`), so a name never has two dentries
    pub fn alloc(
        parent: &Arc<Dentry>,
        name: &[u8],
        inode: Option<Arc<Inode>>,
    ) -> Result<Arc<Dentry>, KernelError> {
        let mut p = parent.d_lock.write();
        if let Some(c) = p.children.get(name) {
            let mut ci = c.d_lock.write();
            if ci.inode.is_some() {
                drop(ci);
                return Ok(c.clone());
            }
            // A negative one is filled only if no one else holds it
            // (lookups take their reference under the parent's d_lock);
            // a held one is replaced, so a holder never sees an inode
            // it did not look up
            if Arc::strong_count(c) == 1 {
                ci.inode = inode;
                drop(ci);
                return Ok(c.clone());
            }
            ci.flags.unhashed = true;
        }
        let d = try_arc(Self::with(name.into(), inode, parent.sb.clone()))?;
        d.d_lock.write().parent = Some(parent.clone());
        p.children.insert(name.into(), d.clone());
        Ok(d)
    }

    /// Name in the parent (a copy: d_move may change it)
    pub fn name(&self) -> FileName {
        self.d_lock.read().name.clone()
    }

    /// Get the inode this dentry points to
    pub fn get_inode(&self) -> Option<Arc<Inode>> {
        self.d_lock.read().inode.clone()
    }

    /// Set the inode for this dentry
    pub fn set_inode(&self, inode: Arc<Inode>) {
        self.d_lock.write().inode = Some(inode);
    }

    /// The child `name` was unlinked (Linux d_delete): one no one but
    /// the caller (`held` references) holds becomes negative in place,
    /// with what was cached under it dropped; a held one leaves the
    /// tree. Decided under this parent's d_lock, where lookups take
    /// their references.
    pub fn d_delete(&self, name: &[u8], held: usize) {
        let mut p = self.d_lock.write();
        let Some(c) = p.children.get(name) else {
            return;
        };
        if Arc::strong_count(c) <= held + 1 {
            let mut ci = c.d_lock.write();
            ci.inode = None;
            ci.children.clear();
        } else if let Some(c) = p.children.remove(name) {
            c.d_lock.write().flags.unhashed = true;
            drop(p);
            d_drop_tree(&c);
        }
    }

    /// Check if this is a negative (failed lookup) dentry
    pub fn is_negative(&self) -> bool {
        self.d_lock.read().inode.is_none()
    }

    /// Dropped from the tree: deleted or renamed over
    pub fn is_unhashed(&self) -> bool {
        self.d_lock.read().flags.unhashed
    }

    /// Get parent dentry
    pub fn get_parent(&self) -> Option<Arc<Dentry>> {
        self.d_lock.read().parent.clone()
    }

    /// Look up a child dentry by name
    pub fn lookup_child(&self, name: &[u8]) -> Option<Arc<Dentry>> {
        self.d_lock.read().children.get(name).cloned()
    }

    /// Drop the child `name` from the tree (Linux d_delete / d_drop):
    /// later lookups ask the file system; a holder keeps an unhashed
    /// dentry
    pub fn remove_child(&self, name: &[u8]) -> Option<Arc<Dentry>> {
        let c = self.d_lock.write().children.remove(name)?;
        c.d_lock.write().flags.unhashed = true;
        d_drop_tree(&c);
        Some(c)
    }

    /// Some mount, in some namespace, sits on this dentry
    pub fn is_mountpoint(&self) -> bool {
        self.d_lock.read().flags.mounted != 0
    }

    /// Count a mount on (`+1`) or off (`-1`) this dentry
    pub fn note_mounted(&self, delta: i32) {
        let f = &mut self.d_lock.write().flags;
        f.mounted = f.mounted.saturating_add_signed(delta);
    }

    /// Get the superblock this dentry belongs to
    pub fn superblock(&self) -> Option<Arc<SuperBlock>> {
        self.sb.upgrade()
    }

    /// Get number of children
    pub fn num_children(&self) -> usize {
        self.d_lock.read().children.len()
    }
}

/// The name of `p` as seen from `root` (Linux prepend_path): climbs
/// dentry parents and, at a mount's root, to its mountpoint in the
/// parent mount; one consistent picture under RENAME_LOCK. The bool is
/// false when the walk ended without meeting `root` (a path outside
/// the caller's root, or on a detached mount): the name then starts at
/// whatever root it reached.
pub fn d_path(p: &Path, root: &Path) -> (Vec<u8>, bool) {
    let _r = RENAME_LOCK.read();
    let (mut mnt, mut d) = (p.mnt.clone(), p.dentry.clone());
    let mut names = Vec::new();
    let reached = loop {
        if Arc::ptr_eq(&mnt, &root.mnt) && Arc::ptr_eq(&d, &root.dentry) {
            break true;
        }
        if Arc::ptr_eq(&d, &mnt.root) {
            match (mnt.get_parent(), mnt.get_mountpoint()) {
                (Some(m), Some(mp)) => {
                    (mnt, d) = (m, mp);
                    continue;
                }
                _ => break false,
            }
        }
        let Some(parent) = d.get_parent() else {
            break false;
        };
        names.push(d.name());
        d = parent;
    };
    if names.is_empty() {
        return (b"/".to_vec(), reached);
    }
    let mut out = Vec::new();
    for n in names.iter().rev() {
        out.push(b'/');
        out.extend_from_slice(n);
    }
    (out, reached)
}

/// The path of `d` from the root of its filesystem (Linux
/// dentry_path_raw): a mount's root in mountinfo
pub fn dentry_path(d: &Arc<Dentry>) -> Vec<u8> {
    let _r = RENAME_LOCK.read();
    let mut names = Vec::new();
    let mut cur = d.clone();
    while let Some(p) = cur.get_parent() {
        names.push(cur.name());
        cur = p;
    }
    if names.is_empty() {
        return b"/".to_vec();
    }
    let mut out = Vec::new();
    for n in names.iter().rev() {
        out.push(b'/');
        out.extend_from_slice(n);
    }
    out
}

/// A /proc link's name for `p` (Linux d_path): as `d_path` from the
/// reader's root, " (deleted)" appended for a removed file
pub fn d_path_link(p: &Path) -> Vec<u8> {
    let mut out = match super::namei::nd_root() {
        Ok(root) => d_path(p, &root).0,
        Err(_) => Vec::new(),
    };
    if p.dentry.is_unhashed() {
        out.extend_from_slice(b" (deleted)");
    }
    out
}

impl Drop for Dentry {
    fn drop(&mut self) {
        NR_DENTRY.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
    }
}

/// /proc/sys/fs/dentry-state (Linux: nr_dentry, nr_unused, age_limit,
/// want_pages, nr_negative, dummy); hk counts only nr_dentry
pub fn dentry_state() -> Vec<i64> {
    let n = NR_DENTRY.load(core::sync::atomic::Ordering::Relaxed);
    alloc::vec![n, 0, 45, 0, 0, 0]
}

/// Drop `d` from `parent` if it is an unused leaf: in the tree and held
/// by nothing but the tree and the caller, nothing cached below, nothing
/// mounted on it; decided under the parent's d_lock, where lookups take
/// their references (Linux dentry_kill from the LRU)
fn prune_one(parent: &Arc<Dentry>, d: &Arc<Dentry>) -> bool {
    let mut p = parent.d_lock.write();
    let di = d.d_lock.read();
    let unused = Arc::strong_count(d) == 2 && di.children.is_empty() && di.flags.mounted == 0;
    let ours = p.children.get(&di.name).is_some_and(|c| Arc::ptr_eq(c, d));
    if !unused || !ours {
        return false;
    }
    let name = di.name.clone();
    drop(di);
    p.children.remove(&name);
    d.d_lock.write().flags.unhashed = true;
    true
}

/// Everything cached below `d` leaves the tree (Linux
/// shrink_dcache_parent / shrink_dcache_for_umount): a subtree out of
/// the tree is no cache, and its parent<->child references would keep
/// it alive. A dentry still held elsewhere (an open file, a cwd)
/// survives, unhashed, with its parent chain. One leaf at a time, from
/// `d` down, allocating nothing.
pub fn d_drop_tree(d: &Arc<Dentry>) {
    loop {
        let mut cur = d.clone();
        while let Some(c) = first_child(&cur) {
            cur = c;
        }
        if Arc::ptr_eq(&cur, d) {
            return;
        }
        let Some(parent) = cur.get_parent() else {
            return;
        };
        let mut p = parent.d_lock.write();
        let mut ci = cur.d_lock.write();
        let gone = p.children.remove(&ci.name).is_some();
        ci.flags.unhashed = true;
        drop(ci);
        drop(p);
        if !gone {
            return;
        }
    }
}

/// The child after `d` in `parent`, by name
fn next_sibling(parent: &Dentry, d: &Dentry) -> Option<Arc<Dentry>> {
    use core::ops::Bound::{Excluded, Unbounded};
    let p = parent.d_lock.read();
    let di = d.d_lock.read();
    let key: &[u8] = &di.name;
    p.children
        .range::<[u8], _>((Excluded(key), Unbounded))
        .next()
        .map(|(_, c)| c.clone())
}

fn first_child(d: &Dentry) -> Option<Arc<Dentry>> {
    d.d_lock.read().children.values().next().cloned()
}

/// Prune up to `budget` unused leaves of the tree under `root`, post
/// order, so a directory left empty goes too
fn prune_tree(root: &Arc<Dentry>, budget: usize) -> usize {
    let mut freed = 0;
    let mut cur = root.clone();
    loop {
        while let Some(c) = first_child(&cur) {
            cur = c;
        }
        loop {
            if Arc::ptr_eq(&cur, root) || freed >= budget {
                return freed;
            }
            let Some(parent) = cur.get_parent() else {
                return freed;
            };
            let next = next_sibling(&parent, &cur);
            if prune_one(&parent, &cur) {
                freed += 1;
            }
            match next {
                Some(n) => {
                    cur = n;
                    break;
                }
                None => cur = parent,
            }
        }
    }
}

/// The dcache shrinker (Linux prune_dcache_sb over every superblock):
/// up to `budget` unused dentries, negative ones included, leave the
/// tree; what they held (inodes not otherwise cached) goes with them.
/// Allocates nothing. Deviation: no LRU, so not oldest first. The
/// number dropped.
pub fn shrink_dcache(budget: usize) -> usize {
    let mut freed = 0;
    let mut i = 0;
    while let Some(sb) = super::superblock::nth_sb(i) {
        i += 1;
        if let Some(root) = sb.and_then(|sb| sb.get_root()) {
            freed += prune_tree(&root, budget - freed);
        }
        if freed >= budget {
            break;
        }
    }
    freed
}

/// Unhook `d` from its parent's children if it is still there
fn unhook(d: &Arc<Dentry>) -> Option<(Arc<Dentry>, FileName)> {
    let parent = d.get_parent()?;
    let name = d.name();
    let mut p = parent.d_lock.write();
    if p.children.get(&name).is_some_and(|c| Arc::ptr_eq(c, d)) {
        p.children.remove(&name);
    }
    drop(p);
    Some((parent, name))
}

/// Re-hang `d` as `name` under `parent`
fn rehook(d: &Arc<Dentry>, parent: &Arc<Dentry>, name: FileName) {
    let mut di = d.d_lock.write();
    di.name = name.clone();
    di.parent = Some(parent.clone());
    di.flags.unhashed = false;
    drop(di);
    parent.d_lock.write().children.insert(name, d.clone());
}

/// A rename moved `d` to `name` in `parent` (Linux d_move): a dentry
/// cached there (the replaced target) is unhashed; `d` keeps its
/// identity, so whoever holds it (a cwd, an fd, a mountpoint) follows
/// it. Callers hold both parents' i_rwsem.
pub fn d_move(d: &Arc<Dentry>, parent: &Arc<Dentry>, name: &[u8]) {
    let _w = RENAME_LOCK.write();
    unhook(d);
    let t = parent.d_lock.write().children.remove(name);
    if let Some(t) = &t {
        t.d_lock.write().flags.unhashed = true;
    }
    rehook(d, parent, name.into());
    drop(_w);
    if let Some(t) = t {
        d_drop_tree(&t);
    }
}

/// RENAME_EXCHANGE swapped `a` and `b` (Linux d_exchange): each takes
/// the other's name and parent
pub fn d_exchange(a: &Arc<Dentry>, b: &Arc<Dentry>) {
    let _w = RENAME_LOCK.write();
    let (Some((pa, na)), Some((pb, nb))) = (unhook(a), unhook(b)) else {
        return;
    };
    rehook(a, &pb, nb);
    rehook(b, &pa, na);
}

/// Global dentry cache
/// For now, this is simple - dentries are cached implicitly via Arc references.
/// A more sophisticated implementation would use an LRU cache with hash table.
pub struct DentryCache {
    /// Root dentry of the namespace
    root: RwLock<Option<Arc<Dentry>>>,
}

impl DentryCache {
    /// Create a new empty dentry cache
    pub const fn new() -> Self {
        Self {
            root: RwLock::new(None),
        }
    }

    /// Set the root dentry
    pub fn set_root(&self, root: Arc<Dentry>) {
        *self.root.write() = Some(root);
    }

    /// Get the root dentry
    pub fn get_root(&self) -> Option<Arc<Dentry>> {
        self.root.read().clone()
    }
}

impl Default for DentryCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Global dentry cache instance
pub static DCACHE: DentryCache = DentryCache::new();

// ============================================================================
// Rename locking helpers (Linux lock_rename pattern)
// ============================================================================

/// Check if `ancestor` is an ancestor of `child` in the directory tree
///
/// Returns true if:
/// - ancestor and child are the same dentry, OR
/// - ancestor is a parent (or grandparent, etc.) of child
///
/// This is used by lock_rename() to determine lock ordering and by
/// sys_renameat2() to prevent creating directory cycles.
///
/// Following Linux's is_subdir() in fs/dcache.c
pub fn is_subdir(child: &Arc<Dentry>, ancestor: &Arc<Dentry>) -> bool {
    // Same dentry - trivially true
    if Arc::ptr_eq(child, ancestor) {
        return true;
    }

    // Walk up the parent chain from child, one picture of the tree
    let _r = RENAME_LOCK.read();
    let mut current = child.get_parent();
    while let Some(parent) = current {
        if Arc::ptr_eq(&parent, ancestor) {
            return true;
        }
        current = parent.get_parent();
    }

    false
}
