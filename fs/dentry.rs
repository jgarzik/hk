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

/// The dcache's tree shape (Linux rename_lock): held for writing by
/// d_move / d_exchange, which bumps its sequence; for reading by
/// whoever walks parents and names and needs one consistent picture
/// (is_subdir, full_path). A scoped walk (RESOLVE_BENEATH /
/// RESOLVE_IN_ROOT) samples the sequence at its start and gives up
/// (EAGAIN) if a ".." raced a rename. Spinning, never taken in IRQ
/// context; taken before any d_lock.
static RENAME_LOCK: crate::sync::SeqRwLock = crate::sync::SeqRwLock::new();

/// Sample the rename sequence (Linux path_init's r_seq)
pub fn rename_seq_begin() -> u32 {
    RENAME_LOCK.read_begin()
}

/// A rename happened since `start` (Linux read_seqretry on rename_lock)
pub fn rename_seq_retry(start: u32) -> bool {
    RENAME_LOCK.read_retry(start)
}

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

    /// A dentry of `inode` on the pseudo filesystem `sb`, outside any
    /// tree (Linux d_alloc_pseudo): a pipe's, socket's, anonymous
    /// inode's or namespace file's
    pub fn new_pseudo(name: FileName, inode: Arc<Inode>, sb: &Arc<SuperBlock>) -> Self {
        Self::with(name, Some(inode), Arc::downgrade(sb))
    }

    /// The child `name` of `parent` with `inode` (Linux d_alloc +
    /// d_add): the cached one if there is one (a negative one gets
    /// `inode`), so a name never has two dentries
    pub fn alloc(
        parent: &Arc<Dentry>,
        name: &[u8],
        inode: Option<Arc<Inode>>,
    ) -> Result<Arc<Dentry>, KernelError> {
        let d = Self::prealloc(parent, name)?;
        Ok(Self::add(parent, d, inode))
    }

    /// The dentry of an O_TMPFILE file in `parent` (Linux d_tmpfile):
    /// named "#<ino>", never in the tree (unhashed: lookups miss it, its
    /// path reads " (deleted)")
    pub fn tmpfile(parent: &Arc<Dentry>, inode: Arc<Inode>) -> Result<Arc<Dentry>, KernelError> {
        let name = alloc::format!("#{}", inode.ino);
        Self::tmpfile_named(parent, name.as_bytes(), inode)
    }

    /// An unhashed dentry `name` of `inode` under `parent` (`tmpfile`;
    /// Linux d_alloc_pseudo for an internal file such as a memfd)
    pub fn tmpfile_named(
        parent: &Arc<Dentry>,
        name: &[u8],
        inode: Arc<Inode>,
    ) -> Result<Arc<Dentry>, KernelError> {
        let d = try_arc(Self::with(name.into(), Some(inode), parent.sb.clone()))?;
        {
            let mut dl = d.d_lock.write();
            dl.parent = Some(parent.clone());
            dl.flags.unhashed = true;
        }
        Ok(d)
    }

    /// A new child dentry of `parent`, not yet in the tree: the
    /// allocation a create does before the filesystem makes the entry
    /// (Linux d_alloc in lookup_create), so an ENOMEM leaves nothing
    /// half made
    pub fn prealloc(parent: &Arc<Dentry>, name: &[u8]) -> Result<Arc<Dentry>, KernelError> {
        try_arc(Self::with(name.into(), None, parent.sb.clone()))
    }

    /// Put `d` (from `prealloc` on `parent`) in the tree with `inode`
    /// (Linux d_add / d_instantiate): the cached child of that name if
    /// there is one (a negative one gets `inode`), so a name never has
    /// two dentries
    pub fn add(parent: &Arc<Dentry>, d: Arc<Dentry>, inode: Option<Arc<Inode>>) -> Arc<Dentry> {
        let name = d.name();
        let name = name.as_bytes();
        let mut p = parent.d_lock.write();
        if let Some(c) = p.children.get(name) {
            let mut ci = c.d_lock.write();
            if ci.inode.is_some() {
                drop(ci);
                return c.clone();
            }
            // A negative one is filled only if no one else holds it
            // (lookups take their reference under the parent's d_lock);
            // a held one is replaced, so a holder never sees an inode
            // it did not look up
            if Arc::strong_count(c) == 1 {
                ci.inode = inode;
                drop(ci);
                return c.clone();
            }
            ci.flags.unhashed = true;
        }
        {
            let mut dl = d.d_lock.write();
            dl.inode = inode;
            dl.parent = Some(parent.clone());
        }
        p.children.insert(name.into(), d.clone());
        d
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
    /// with what was cached under it dropped, and lets go of its inode
    /// after the locks (dentry_unlink_inode); a held one leaves the
    /// tree, and lets go when its last holder does. Decided under this
    /// parent's d_lock, where lookups take their references.
    pub fn d_delete(&self, name: &[u8], held: usize) {
        let mut p = self.d_lock.write();
        let Some(c) = p.children.get(name) else {
            return;
        };
        if Arc::strong_count(c) <= held + 1 {
            let mut ci = c.d_lock.write();
            let inode = ci.inode.take();
            ci.children.clear();
            drop(ci);
            drop(p);
            if let Some(i) = inode {
                crate::io::inotify::d_iput(&i);
            }
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

/// Longest path name, its NUL included (Linux PATH_MAX)
pub const PATH_MAX: usize = 4096;

/// A path name built backwards from the end of a PATH_MAX buffer
/// allocated up front, so nothing allocates under RENAME_LOCK (Linux
/// struct prepend_buffer over a page); one byte stays for the NUL
struct Prepend {
    buf: Vec<u8>,
    pos: usize,
}

impl Prepend {
    fn new() -> Result<Self, KernelError> {
        Ok(Self {
            buf: crate::util::kmem::try_vec(PATH_MAX, 0u8)?,
            pos: PATH_MAX - 1,
        })
    }

    /// "/name" of `d` in front (ENAMETOOLONG when it does not fit)
    fn name(&mut self, d: &Dentry) -> Result<(), KernelError> {
        let di = d.d_lock.read();
        let n: &[u8] = &di.name;
        let start = self
            .pos
            .checked_sub(n.len() + 1)
            .ok_or(KernelError::NameTooLong)?;
        self.buf[start] = b'/';
        self.buf[start + 1..self.pos].copy_from_slice(n);
        self.pos = start;
        Ok(())
    }

    /// The name ("/" when nothing was prepended)
    fn into_name(mut self) -> Vec<u8> {
        let end = PATH_MAX - 1;
        if self.pos == end {
            self.pos -= 1;
            self.buf[self.pos] = b'/';
        }
        self.buf.copy_within(self.pos..end, 0);
        self.buf.truncate(end - self.pos);
        self.buf
    }
}

/// The name of `p` as seen from `root` (Linux prepend_path): climbs
/// dentry parents and, at a mount's root, to its mountpoint in the
/// parent mount; one consistent picture under RENAME_LOCK. The bool is
/// false when the walk ended without meeting `root` (a path outside
/// the caller's root, or on a detached mount): the name then starts at
/// whatever root it reached. ENAMETOOLONG past PATH_MAX (its NUL
/// included), ENOMEM without a buffer.
pub fn try_d_path(p: &Path, root: &Path) -> Result<(Vec<u8>, bool), KernelError> {
    let mut b = Prepend::new()?;
    let reached = {
        let _r = RENAME_LOCK.read();
        let (mut mnt, mut d) = (p.mnt.clone(), p.dentry.clone());
        loop {
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
            b.name(&d)?;
            d = parent;
        }
    };
    Ok((b.into_name(), reached))
}

/// [`try_d_path`], with an empty name not reaching `root` when it
/// fails (a name too long, no memory)
pub fn d_path(p: &Path, root: &Path) -> (Vec<u8>, bool) {
    try_d_path(p, root).unwrap_or_default()
}

/// The path of `d` from the root of its filesystem (Linux
/// dentry_path_raw): a mount's root in mountinfo; ENAMETOOLONG past
/// PATH_MAX
pub fn dentry_path(d: &Arc<Dentry>) -> Result<Vec<u8>, KernelError> {
    let mut b = Prepend::new()?;
    {
        let _r = RENAME_LOCK.read();
        let mut cur = d.clone();
        while let Some(p) = cur.get_parent() {
            b.name(&cur)?;
            cur = p;
        }
    }
    Ok(b.into_name())
}

/// A /proc link's name for `p` (Linux d_path): as `try_d_path` from the
/// reader's root, " (deleted)" appended for a removed file
pub fn d_path_link(p: &Path) -> Result<Vec<u8>, KernelError> {
    let mut out = match super::namei::nd_root() {
        Ok(root) => try_d_path(p, &root)?.0,
        Err(_) => Vec::new(),
    };
    if p.dentry.is_unhashed() {
        out.extend_from_slice(b" (deleted)");
    }
    Ok(out)
}

impl Drop for Dentry {
    /// The parents this dentry alone held go here in a loop, not by
    /// nested drops: a chain of removed directories pinned only by its
    /// deepest one (an open descriptor) may be as deep as the caller
    /// could make it
    fn drop(&mut self) {
        NR_DENTRY.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
        // Its inode, if the last name of it is gone, takes its watches
        // with it (Linux dentry_unlink_inode at the final dput)
        if let Some(i) = self.d_lock.get_mut().inode.take() {
            crate::io::inotify::d_iput(&i);
        }
        let mut next = self.d_lock.get_mut().parent.take();
        while let Some(p) = next {
            next = Arc::into_inner(p).and_then(|mut d| d.d_lock.get_mut().parent.take());
        }
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
    unhook_from(d, &parent, &name);
    Some((parent, name))
}

/// Take `d` off `parent`'s children, if it is the one cached as `name`
fn unhook_from(d: &Arc<Dentry>, parent: &Dentry, name: &FileName) {
    let mut p = parent.d_lock.write();
    if p.children.get(name).is_some_and(|c| Arc::ptr_eq(c, d)) {
        p.children.remove(name);
    }
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
    let w = RENAME_LOCK.write();
    unhook(d);
    let t = parent.d_lock.write().children.remove(name);
    if let Some(t) = &t {
        t.d_lock.write().flags.unhashed = true;
    }
    rehook(d, parent, name.into());
    drop(w);
    if let Some(t) = t {
        d_drop_tree(&t);
    }
}

/// RENAME_EXCHANGE swapped `a` and `b` (Linux d_exchange): each takes
/// the other's name and parent. Neither may be a root (Linux WARN_ON
/// IS_ROOT); if one is, nothing changes.
pub fn d_exchange(a: &Arc<Dentry>, b: &Arc<Dentry>) {
    let _w = RENAME_LOCK.write();
    let (Some(pa), Some(pb)) = (a.get_parent(), b.get_parent()) else {
        return;
    };
    let (na, nb) = (a.name(), b.name());
    unhook_from(a, &pa, &na);
    unhook_from(b, &pb, &nb);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::inode::{InodeMode, NULL_INODE_OPS, Timespec};

    fn inode() -> Arc<Inode> {
        try_arc(Inode::new(
            1,
            InodeMode::directory(0o755),
            0,
            0,
            0,
            Timespec::from_secs(0),
            Weak::new(),
            &NULL_INODE_OPS,
        ))
        .unwrap()
    }

    /// An exchange with a root changes nothing: the other dentry stays
    /// where it was, cached under its parent
    #[test]
    fn exchange_with_root_is_noop() {
        let r = try_arc(Dentry::new_root(inode(), Weak::new())).unwrap();
        let a = Dentry::alloc(&r, b"a", Some(inode())).unwrap();
        let other = try_arc(Dentry::new_root(inode(), Weak::new())).unwrap();
        d_exchange(&a, &other);
        assert!(r.lookup_child(b"a").is_some_and(|c| Arc::ptr_eq(&c, &a)));
        assert!(a.get_parent().is_some_and(|p| Arc::ptr_eq(&p, &r)));
    }

    /// A real exchange swaps names and parents
    #[test]
    fn exchange_swaps() {
        let r = try_arc(Dentry::new_root(inode(), Weak::new())).unwrap();
        let a = Dentry::alloc(&r, b"a", Some(inode())).unwrap();
        let b = Dentry::alloc(&r, b"b", Some(inode())).unwrap();
        d_exchange(&a, &b);
        assert!(r.lookup_child(b"b").is_some_and(|c| Arc::ptr_eq(&c, &a)));
        assert!(r.lookup_child(b"a").is_some_and(|c| Arc::ptr_eq(&c, &b)));
    }
}
