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
//!
//! The tree is Linux's shape: a parent's children are an intrusive list
//! (Linux d_children / d_sib) under its d_lock, and a child is found by
//! (parent, name) in the global hash table of bit-locked buckets
//! (dentry_hashtable, d_hash). Neither allocates to add or remove a
//! child.

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::mem::ManuallyDrop;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering, Ordering::Relaxed, fence};

use crate::sync::spin::RwLock;
use crate::util::hlist_bl::BlHead;
use crate::util::list::{Link, OwnedList, Owner};

use super::inode::Inode;
use super::mount::{MOUNT_LOCK, Mount, MountRef};
use super::name::DName;
use super::path_ref::Path;
use super::superblock::SuperBlock;
use crate::sync::rcu::RcuHead;
use crate::util::error::KernelError;
use crate::util::list::{ListPtr, RefPtr};

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
/// (is_subdir, d_path, dentry_path: lockless first, under the lock if
/// a rename raced; inside MOUNT_LOCK). A scoped walk (RESOLVE_BENEATH /
/// RESOLVE_IN_ROOT) samples the sequence at its start and gives up
/// (EAGAIN) if a ".." raced a rename. A locking read excludes other
/// readers, as Linux read_seqlock_excl. Spinning, never taken in IRQ
/// context; taken before any d_lock.
static RENAME_LOCK: crate::sync::SeqLock = crate::sync::SeqLock::new(());

/// Sample the rename sequence (Linux path_init's r_seq)
pub fn rename_seq_begin() -> u32 {
    RENAME_LOCK.read_begin()
}

/// A rename happened since `start` (Linux read_seqretry on rename_lock)
pub fn rename_seq_retry(start: u32) -> bool {
    RENAME_LOCK.read_retry(start)
}

crate::owned_adapter!(SibAdapter, Dentry, d_sib, d_sib_owner);
crate::adapter!(HashAdapter, Dentry, d_hash);

/// A parent's children, each entry the list's reference
type Children = OwnedList<SibAdapter, DentryRef>;
/// A hash bucket, each entry the bucket's reference
type Bucket = BlHead<HashAdapter, DentryRef>;

/// The references a dentry in the tree has from it: its parent's
/// children list and its hash bucket
const TREE_REFS: usize = 2;

/// The dentry hash table (Linux dentry_hashtable): a power of two of
/// buckets, sized at boot by `dcache_init`
static DENTRY_HASHTABLE: spin::Once<Box<[Bucket]>> = spin::Once::new();

/// Buckets for `pages` pages of RAM (Linux alloc_large_system_hash
/// with scale 13: one per 8 KiB, rounded up to a power of two)
fn dhash_entries(pages: u64) -> usize {
    usize::try_from(pages >> 1)
        .unwrap_or(usize::MAX)
        .clamp(1 << 10, 1 << 32)
        .next_power_of_two()
}

/// Allocate the hash table (Linux dcache_init, from vfs_caches_init):
/// before any dentry is hashed. Like Linux, no memory for it is fatal.
pub fn dcache_init(pages: u64) {
    DENTRY_HASHTABLE.call_once(|| {
        let n = dhash_entries(pages);
        let mut v = Vec::new();
        v.try_reserve_exact(n)
            .expect("dcache: no memory for the dentry hash table");
        v.extend((0..n).map(|_| BlHead::new()));
        // Host tests have no console
        #[cfg(not(test))]
        crate::printkln!(
            "Dentry cache hash table entries: {} ({} bytes)",
            n,
            n * core::mem::size_of::<Bucket>()
        );
        v.into_boxed_slice()
    });
}

fn table() -> &'static [Bucket] {
    #[cfg(test)]
    dcache_init(0);
    DENTRY_HASHTABLE
        .get()
        .expect("dcache: hash table used before dcache_init")
}

/// The hash key of the child `hash` (a name's, keyed per boot:
/// `name::name_hash`) of `parent`: the name's hash salted with the
/// parent (Linux full_name_hash's salt), so neither a name nor a
/// parent alone picks the bucket
fn d_key(parent: &Dentry, hash: u64) -> u64 {
    let p = core::ptr::from_ref(parent).addr() as u64;
    (hash ^ p.rotate_left(29)).wrapping_mul(0x61c8_8646_80b5_83eb)
}

/// The bucket of `key` (Linux d_hash: its top bits)
fn d_hash(key: u64) -> &'static Bucket {
    let t = table();
    let bits = t.len().trailing_zeros();
    // The top `bits` bits: less than the table's length
    let i = if bits == 0 {
        0
    } else {
        (key >> (64 - bits)) as usize
    };
    &t[i]
}

/// Put `d` (parent `parent`, named `name`) in the tree: on the
/// parent's children (`p`, its d_lock held for writing), then in its
/// bucket (Linux d_add's __d_rehash, d_sib)
fn hash_in(parent: &Dentry, p: &mut DentryInner, d: &DentryRef, name: &DName) {
    let key = d_key(parent, name.hash());
    d.d_hkey.store(key, Relaxed);
    d.d_hparent
        .store(core::ptr::from_ref(parent).addr(), Relaxed);
    p.children.push_back(d.clone());
    d_hash(key).lock().add_head(d.clone());
}

/// Take `d` out of the tree if it is a child of the parent whose
/// d_lock (`p`) is held for writing (Linux __d_drop and the d_sib
/// unlink): the children list's reference, None if it was not there.
/// The caller still holds `d`, so it drops nothing last.
fn hash_out(p: &mut DentryInner, d: &Dentry) -> Option<DentryRef> {
    let c = p.children.remove(d)?;
    let _bucket_ref = d_hash(d.d_hkey.load(Relaxed)).lock().del(d);
    Some(c)
}

/// The child `name` of `parent` (Linux __d_lookup), whose d_lock `_p`
/// is held (lookups take their references under it): one walk of the
/// bucket under its lock, comparing key, parent and name as Linux
/// compares d_name there. A hashed dentry's key and parent change only
/// while it is out of its bucket, and its name only under `d_name`, a
/// leaf taken here inside the bucket lock (written only while the
/// dentry is out of the tree, by d_move). A new reference.
fn d_lookup(parent: &Dentry, _p: &DentryInner, name: &[u8]) -> Option<DentryRef> {
    let key = d_key(parent, super::name::name_hash(name));
    let pa = core::ptr::from_ref(parent).addr();
    d_hash(key).lock().find(|c| {
        c.d_hkey.load(Relaxed) == key
            && c.d_hparent.load(Relaxed) == pa
            && c.d_name.read().as_bytes() == name
    })
}

/// Dentries alive (/proc/sys/fs/dentry-state nr_dentry)
static NR_DENTRY: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(0);

/// Inner mutable state protected by d_lock
struct DentryInner {
    /// The inode this dentry points to (None for negative dentry)
    inode: Option<Arc<Inode>>,
    /// Children in the tree (Linux d_children), each with the list's
    /// reference; each is also in its hash bucket
    children: Children,
    /// Dentry flags
    flags: DentryFlags,
}

/// A directory entry - maps a name to an inode
///
/// ## Locking
///
/// `d_lock` protects all mutable state, the parent included (Linux
/// d_lock); a parent's d_lock is taken before a child's. The name has
/// its own leaf lock, `d_name`, so a bucket walk can compare it (Linux
/// reads d_name there under d_seq): written by d_move with the dentry's
/// d_lock held and the dentry out of the tree. `sb` is immutable. `d_sib`/`d_sib_owner` belong to the parent's children
/// list (its d_lock), `d_hash` to the bucket's bit lock; `d_hkey` and
/// `d_hparent` are written under the parent's d_lock before the dentry
/// goes in its bucket and read under the bucket's lock; they change
/// only while it is out (Linux d_name.hash, d_parent). `d_parent` is
/// written under the dentry's d_lock (and, once it is in the tree,
/// RENAME_LOCK) and read lock-free (Linux READ_ONCE(d_parent)).
///
/// Held through [`DentryRef`] (Linux d_lockref's count); its memory is
/// freed a grace period after the last one goes (Linux dentry_free's
/// call_rcu), so an RCU reader may follow `d_parent` and read `d_name`
/// of a dentry it holds no reference to.
pub struct Dentry {
    /// Back pointer to superblock - immutable after creation
    pub sb: Weak<SuperBlock>,

    /// References ([`DentryRef`], Linux d_lockref.count): the tree's
    /// (its parent's children list and its bucket), children's
    /// `d_parent`, and every holder's; 0 once killed
    d_count: AtomicUsize,
    /// The parent (null for a root), a reference while the dentry
    /// lives (Linux d_parent holds one): a cwd or open directory keeps
    /// its whole chain valid. Left in place when the dentry is killed
    /// (its reference released), for RCU readers standing on it.
    d_parent: AtomicPtr<Dentry>,
    /// The free a grace period after the last reference (Linux
    /// d_u.d_rcu)
    d_rcu: RcuHead,

    /// On the parent's children (Linux d_sib)
    d_sib: Link,
    d_sib_owner: Owner,
    /// In a hash bucket (Linux d_hash)
    d_hash: Link,
    /// The key it was hashed under (`d_key`)
    d_hkey: AtomicU64,
    /// The parent's address when hashed (compared, never followed)
    d_hparent: AtomicUsize,

    /// Name in the parent (empty for a root): a leaf, taken inside
    /// d_lock or a bucket lock
    d_name: RwLock<DName>,

    /// Single lock protecting all mutable state (like Linux d_lock)
    d_lock: RwLock<DentryInner>,
}

impl Dentry {
    fn with(name: DName, inode: Option<Arc<Inode>>, sb: Weak<SuperBlock>) -> Self {
        Self {
            sb,
            d_count: AtomicUsize::new(1),
            d_parent: AtomicPtr::new(core::ptr::null_mut()),
            d_rcu: RcuHead::new(),
            d_sib: Link::new(),
            d_sib_owner: Owner::new(),
            d_hash: Link::new(),
            d_hkey: AtomicU64::new(0),
            d_hparent: AtomicUsize::new(0),
            d_name: RwLock::new(name),
            d_lock: RwLock::new(DentryInner {
                inode,
                children: OwnedList::new(),
                flags: DentryFlags::default(),
            }),
        }
    }

    /// Create root dentry for a filesystem
    pub fn new_root(inode: Arc<Inode>, sb: Weak<SuperBlock>) -> Self {
        Self::with(DName::default(), Some(inode), sb)
    }

    /// Create an anonymous dentry (for pipes, sockets, etc.)
    ///
    /// Anonymous dentries have no superblock and are not part of any filesystem.
    /// They exist solely to provide a File's required dentry reference.
    pub fn new_anonymous(name: &[u8], inode: Option<Arc<Inode>>) -> Result<Self, KernelError> {
        Ok(Self::with(DName::new(name)?, inode, Weak::new()))
    }

    /// A dentry of `inode` on the pseudo filesystem `sb`, outside any
    /// tree (Linux d_alloc_pseudo): a pipe's, socket's, anonymous
    /// inode's or namespace file's
    pub fn new_pseudo(
        name: &[u8],
        inode: Arc<Inode>,
        sb: &Arc<SuperBlock>,
    ) -> Result<Self, KernelError> {
        Ok(Self::with(
            DName::new(name)?,
            Some(inode),
            Arc::downgrade(sb),
        ))
    }

    /// The child `name` of `parent` with `inode` (Linux d_alloc +
    /// d_add): the cached one if there is one (a negative one gets
    /// `inode`), so a name never has two dentries
    pub fn alloc(
        parent: &DentryRef,
        name: &[u8],
        inode: Option<Arc<Inode>>,
    ) -> Result<DentryRef, KernelError> {
        let d = Self::prealloc(parent, name)?;
        Ok(Self::add(parent, d, inode))
    }

    /// The dentry of an O_TMPFILE file in `parent` (Linux d_tmpfile):
    /// named "#<ino>", never in the tree (unhashed: lookups miss it, its
    /// path reads " (deleted)")
    pub fn tmpfile(parent: &DentryRef, inode: Arc<Inode>) -> Result<DentryRef, KernelError> {
        let name = alloc::format!("#{}", inode.ino);
        Self::tmpfile_named(parent, name.as_bytes(), inode)
    }

    /// An unhashed dentry `name` of `inode` under `parent` (`tmpfile`;
    /// Linux d_alloc_pseudo for an internal file such as a memfd)
    pub fn tmpfile_named(
        parent: &DentryRef,
        name: &[u8],
        inode: Arc<Inode>,
    ) -> Result<DentryRef, KernelError> {
        let d = DentryRef::new(Self::with(
            DName::new(name)?,
            Some(inode),
            parent.sb.clone(),
        ))?;
        {
            let mut dl = d.d_lock.write();
            d.set_parent(&dl, parent.clone());
            dl.flags.unhashed = true;
        }
        Ok(d)
    }

    /// A new child dentry of `parent`, not yet in the tree: the
    /// allocation a create or rename does before the filesystem makes
    /// the entry (Linux d_alloc in lookup_create), so an ENOMEM leaves
    /// nothing half made. It holds its parent already (Linux d_alloc's
    /// dget of the parent).
    pub fn prealloc(parent: &DentryRef, name: &[u8]) -> Result<DentryRef, KernelError> {
        let d = DentryRef::new(Self::with(DName::new(name)?, None, parent.sb.clone()))?;
        let dl = d.d_lock.write();
        d.set_parent(&dl, parent.clone());
        drop(dl);
        Ok(d)
    }

    /// Point `d_parent` at `p` under this dentry's d_lock (`_dl`,
    /// written; RENAME_LOCK too once it is in the tree), with Release
    /// for lock-free readers (Linux WRITE_ONCE(d_parent)); the old
    /// parent's reference is released
    fn set_parent(&self, _dl: &DentryInner, p: DentryRef) {
        let old = self
            .d_parent
            .swap(DentryRef::into_raw(p).cast_mut(), Ordering::Release);
        // SAFETY: a non-null `d_parent` of a live dentry is a reference
        // it holds (field invariant), handed back once here
        drop(NonNull::new(old).map(|o| unsafe { DentryRef::from_raw(o.as_ptr()) }));
    }

    /// The parent's address, lock-free (Linux READ_ONCE(d_parent)):
    /// null for a root. Following it needs RENAME_LOCK, or an RCU read
    /// guard and the rename sequence checked after (`parent_rcu`).
    fn parent_ptr(&self) -> *const Dentry {
        self.d_parent.load(Ordering::Acquire)
    }

    /// Put `d` (from `prealloc` on `parent`) in the tree with `inode`
    /// (Linux d_add / d_instantiate): the cached child of that name if
    /// there is one (a negative one gets `inode`), so a name never has
    /// two dentries
    pub fn add(parent: &DentryRef, d: DentryRef, inode: Option<Arc<Inode>>) -> DentryRef {
        let name = d.name();
        let mut p = parent.d_lock.write();
        if let Some(c) = d_lookup(parent, &p, &name) {
            let mut ci = c.d_lock.write();
            if ci.inode.is_some() {
                drop(ci);
                return c;
            }
            // A negative one is filled only if no one else holds it
            // (lookups take their reference under the parent's d_lock);
            // a held one is replaced, so a holder never sees an inode
            // it did not look up
            if DentryRef::count(&c) == TREE_REFS + 1 {
                ci.inode = inode;
                drop(ci);
                return c;
            }
            ci.flags.unhashed = true;
            drop(ci);
            hash_out(&mut p, &c);
        }
        {
            let mut dl = d.d_lock.write();
            dl.inode = inode;
            d.set_parent(&dl, parent.clone());
        }
        hash_in(parent, &mut p, &d, &name);
        d
    }

    /// Name in the parent, a snapshot (Linux take_dentry_name_snapshot:
    /// d_move may change it): a byte copy or a shared reference, never an
    /// allocation
    pub fn name(&self) -> DName {
        self.d_name.read().clone()
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
    /// the caller (`held` references) holds becomes negative in place
    /// and lets go of its inode after the locks (Linux
    /// dentry_unlink_inode: fsnotify_inoderemove and iput after d_lock
    /// and i_lock are dropped); a held one leaves the tree (__d_drop),
    /// and lets go when its last holder does. Decided under this
    /// parent's d_lock, where lookups take their references. A removed
    /// directory has nothing cached below it any more (`delete_entry`,
    /// Linux vfs_rmdir's shrink_dcache_parent).
    pub fn d_delete(&self, name: &[u8], held: usize) {
        let mut p = self.d_lock.write();
        let Some(c) = d_lookup(self, &p, name) else {
            return;
        };
        if DentryRef::count(&c) <= held + TREE_REFS + 1 {
            let inode = c.d_lock.write().inode.take();
            drop(p);
            if let Some(i) = inode {
                crate::io::inotify::d_iput(&i);
            }
        } else {
            c.d_lock.write().flags.unhashed = true;
            let ours = hash_out(&mut p, &c);
            drop(p);
            drop(ours);
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

    /// A reference to the parent (Linux dget_parent): taken under the
    /// d_lock every `d_parent` writer holds
    pub fn get_parent(&self) -> Option<DentryRef> {
        let _dl = self.d_lock.read();
        let p = self.parent_ptr();
        // SAFETY: a non-null `d_parent` is a reference this dentry holds
        // (field invariant), and it cannot change while `_dl` is held
        (!p.is_null()).then(|| unsafe { DentryRef::clone_raw(p) })
    }

    /// The parent, borrowed for an RCU read guard's life with no
    /// reference (Linux READ_ONCE(d_parent) in an RCU walk): the parent
    /// at the time of the read, or for a killed dentry the one it held
    /// until its kill. A walk on it checks RENAME_LOCK's sequence after,
    /// or holds that lock (then it is the parent still).
    fn parent_rcu<'g>(&self, _g: &'g crate::sync::rcu::RcuReadGuard) -> Option<&'g Dentry> {
        let p = self.parent_ptr();
        // SAFETY: `self` is readable under the guard, so it was live when
        // the guard began or reached through links read under it; its
        // `d_parent` then held a reference when the guard began, or was
        // released by a kill after that. Either way the parent's free
        // (`dentry_kill`'s call_rcu) comes after the guard began, and
        // waits for it.
        unsafe { p.as_ref() }
    }

    /// Look up a child dentry by name
    pub fn lookup_child(&self, name: &[u8]) -> Option<DentryRef> {
        let p = self.d_lock.read();
        d_lookup(self, &p, name)
    }

    /// Drop the child `name` from the tree (Linux d_delete / d_drop):
    /// later lookups ask the file system; a holder keeps an unhashed
    /// dentry
    pub fn remove_child(&self, name: &[u8]) -> Option<DentryRef> {
        let mut p = self.d_lock.write();
        let c = d_lookup(self, &p, name)?;
        c.d_lock.write().flags.unhashed = true;
        let ours = hash_out(&mut p, &c);
        drop(p);
        drop(ours);
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

    /// Empty again, for another pass
    fn reset(&mut self) {
        self.pos = PATH_MAX - 1;
    }

    /// "/name" of `d` in front (ENAMETOOLONG when it does not fit)
    fn name(&mut self, d: &Dentry) -> Result<(), KernelError> {
        let dn = d.d_name.read();
        let n: &[u8] = &dn;
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
/// parent mount. Like Linux it walks first with no lock, under an RCU
/// read guard (dentries and mounts are freed a grace period after they
/// go), and trusts the result only if neither MOUNT_LOCK's sequence
/// (the mount tree's links) nor RENAME_LOCK's (the dentry tree's)
/// moved; otherwise it walks again under that lock's locking read
/// (read_seqbegin_or_lock, mount_lock outside rename_lock). It takes no
/// reference, so nothing is dropped inside the walk. The bool is false
/// when the walk ended without meeting `root` (a path outside the
/// caller's root, or on a detached mount): the name then starts at
/// whatever root it reached. ENAMETOOLONG past PATH_MAX (its NUL
/// included), ENOMEM without a buffer.
pub fn try_d_path(p: &Path, root: &Path) -> Result<(Vec<u8>, bool), KernelError> {
    let mut b = Prepend::new()?;
    let g = crate::sync::rcu::read_lock();
    let reached = MOUNT_LOCK.read_or_lock(|_| {
        RENAME_LOCK.read_or_lock(|_| {
            b.reset();
            prepend_path(&mut b, p, root, &g)
        })
    })?;
    drop(g);
    Ok((b.into_name(), reached))
}

/// One pass of [`try_d_path`]'s walk (Linux __prepend_path), on what
/// `g` keeps readable: on a changing tree it may go wrong (a name too
/// long, the wrong root), never unsafe; the caller decides by the
/// sequences
fn prepend_path(
    b: &mut Prepend,
    p: &Path,
    root: &Path,
    g: &crate::sync::rcu::RcuReadGuard,
) -> Result<bool, KernelError> {
    let (mut mnt, mut d): (&Mount, &Dentry) = (&p.mnt, &p.dentry);
    loop {
        if core::ptr::eq(mnt, MountRef::as_ptr(&root.mnt))
            && core::ptr::eq(d, DentryRef::as_ptr(&root.dentry))
        {
            return Ok(true);
        }
        if core::ptr::eq(d, mnt.root_addr()) {
            match mnt.up_rcu(g) {
                Some(up) => {
                    (mnt, d) = up;
                    continue;
                }
                None => return Ok(false),
            }
        }
        let Some(parent) = d.parent_rcu(g) else {
            return Ok(false);
        };
        b.name(d)?;
        d = parent;
    }
}

/// [`try_d_path`], with an empty name not reaching `root` when it
/// fails (a name too long, no memory)
pub fn d_path(p: &Path, root: &Path) -> (Vec<u8>, bool) {
    try_d_path(p, root).unwrap_or_default()
}

/// The path of `d` from the root of its filesystem (Linux
/// dentry_path_raw): a mount's root in mountinfo; lockless first, as
/// [`try_d_path`], again under RENAME_LOCK if a rename raced it;
/// ENAMETOOLONG past PATH_MAX
pub fn dentry_path(d: &DentryRef) -> Result<Vec<u8>, KernelError> {
    let mut b = Prepend::new()?;
    let g = crate::sync::rcu::read_lock();
    RENAME_LOCK.read_or_lock(|_| {
        b.reset();
        let mut cur: &Dentry = d;
        while let Some(p) = cur.parent_rcu(&g) {
            b.name(cur)?;
            cur = p;
        }
        Ok::<(), KernelError>(())
    })?;
    drop(g);
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

/// A counted reference to a dentry (Linux a dget'd `struct dentry *`):
/// a clone takes one (dget), a drop puts it (dput); the last put kills
/// the dentry (Linux __dentry_kill: its inode and parent let go there)
/// and frees its memory after a grace period (dentry_free's call_rcu)
///
/// # Invariants
/// Holds one of its dentry's `d_count` references, which keep it live.
pub struct DentryRef(NonNull<Dentry>);

// SAFETY: a counted reference to a Sync dentry, usable from any thread
unsafe impl Send for DentryRef {}
// SAFETY: as above; `&DentryRef` only reads the dentry
unsafe impl Sync for DentryRef {}

impl DentryRef {
    /// The first reference to a new dentry (Linux d_alloc's count of
    /// one); ENOMEM
    pub fn new(d: Dentry) -> Result<Self, KernelError> {
        let b = crate::util::kalloc::try_box(d)?;
        NR_DENTRY.fetch_add(1, Ordering::Relaxed);
        Ok(Self(NonNull::from(Box::leak(b))))
    }

    /// Both are the same dentry
    pub fn ptr_eq(a: &Self, b: &Self) -> bool {
        a.0 == b.0
    }

    /// The dentry's address (its identity)
    pub fn as_ptr(this: &Self) -> *const Dentry {
        this.0.as_ptr()
    }

    /// Its references (Linux d_count): exact only where no other can be
    /// taken or put meanwhile (under the parent's d_lock, where lookups
    /// take theirs)
    pub fn count(this: &Self) -> usize {
        this.d_count.load(Ordering::Acquire)
    }

    /// A reference to `d`, unless its last one went (Linux
    /// lockref_get_not_dead): for a dentry found with no reference held,
    /// under an RCU read guard that keeps its memory
    pub fn try_get(d: &Dentry) -> Option<Self> {
        let mut n = d.d_count.load(Ordering::Relaxed);
        loop {
            if n == 0 {
                return None;
            }
            match d
                .d_count
                .compare_exchange_weak(n, n + 1, Ordering::Acquire, Ordering::Relaxed)
            {
                Ok(_) => return Some(Self(NonNull::from(d))),
                Err(v) => n = v,
            }
        }
    }
}

impl Clone for DentryRef {
    /// dget: the caller's reference keeps the count above zero
    fn clone(&self) -> Self {
        self.d_count.fetch_add(1, Ordering::Relaxed);
        Self(self.0)
    }
}

impl core::ops::Deref for DentryRef {
    type Target = Dentry;
    fn deref(&self) -> &Dentry {
        // SAFETY: the type invariant keeps the dentry live
        unsafe { self.0.as_ref() }
    }
}

impl Drop for DentryRef {
    /// dput: the last reference kills the dentry; the parents it alone
    /// held go here in a loop, not by nested drops (Linux dput's
    /// parent loop): a chain of removed directories pinned only by its
    /// deepest one (an open descriptor) may be as deep as the caller
    /// could make it
    fn drop(&mut self) {
        let mut d = self.0;
        loop {
            // SAFETY: a reference held (the caller's, or the parent's
            // that the kill below handed over) keeps it live
            let r = unsafe { d.as_ref() };
            if r.d_count.fetch_sub(1, Ordering::Release) != 1 {
                return;
            }
            // Every access through other references before the kill
            fence(Ordering::Acquire);
            // SAFETY: the count reached zero: no reference is left and
            // none can be taken (`try_get` refuses), so this is its one
            // kill
            match unsafe { dentry_kill(d) } {
                Some(p) => d = p,
                None => return,
            }
        }
    }
}

// SAFETY: into_raw leaks the reference, from_raw takes it back; the
// dentry stays live and put while one is held
unsafe impl ListPtr for DentryRef {
    #[inline]
    fn into_raw(this: Self) -> *const Dentry {
        ManuallyDrop::new(this).0.as_ptr()
    }
    #[inline]
    unsafe fn from_raw(p: *const Dentry) -> Self {
        // SAFETY: from `into_raw` (the caller), never null
        Self(unsafe { NonNull::new_unchecked(p.cast_mut()) })
    }
}

// SAFETY: a count increment, then the reference it stands for
unsafe impl RefPtr for DentryRef {
    #[inline]
    unsafe fn clone_raw(p: *const Dentry) -> Self {
        // SAFETY: the caller's reference keeps it live and counted
        unsafe { &*p }.d_count.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the reference just taken, never null
        Self(unsafe { NonNull::new_unchecked(p.cast_mut()) })
    }
}

/// This CPU can queue RCU callbacks (not in host unit tests, nor at
/// the start of boot, when no other CPU runs a reader)
fn have_cpu() -> bool {
    !cfg!(test) && crate::cpu::try_this_id().is_some()
}

/// Kill a dentry whose last reference went (Linux __dentry_kill): its
/// inode, if the last name of it is gone, takes its watches with it
/// (dentry_unlink_inode at the final dput); its memory is freed after
/// a grace period (dentry_free), `d_parent` left for RCU readers on it.
/// The parent's reference it held, handed to the caller to put.
///
/// # Safety
/// `d`'s count reached zero: no reference is left or can be taken, and
/// this runs once for it.
unsafe fn dentry_kill(d: NonNull<Dentry>) -> Option<NonNull<Dentry>> {
    // SAFETY: live until the free queued below runs
    let r = unsafe { d.as_ref() };
    NR_DENTRY.fetch_sub(1, Ordering::Relaxed);
    let inode = r.d_lock.write().inode.take();
    if let Some(i) = inode {
        crate::io::inotify::d_iput(&i);
    }
    // The parent's reference is ours now; the pointer stays
    let parent = NonNull::new(r.parent_ptr().cast_mut());
    let p = d.as_ptr().cast_const().cast::<()>();
    if have_cpu() {
        // SAFETY: `d_rcu` is in the dentry, which nothing frees before
        // `d_free` runs; `d_free` only drops the box it is given, which
        // may happen in any context
        unsafe { crate::sync::rcu::call_rcu(&r.d_rcu, d_free, p) };
    } else {
        // SAFETY: no reader can stand on it (one CPU, no RCU yet)
        unsafe { d_free(p) };
    }
    parent
}

/// Free a killed dentry's memory (Linux __d_free): its name and the
/// box
///
/// # Safety
/// `p` is a killed dentry (`dentry_kill`), freed once, a grace period
/// after its kill (no RCU reader still on it).
unsafe fn d_free(p: *const ()) {
    // SAFETY: the box `DentryRef::new` leaked, taken back once
    drop(unsafe { Box::from_raw(p.cast::<Dentry>().cast_mut()) });
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
fn prune_one(parent: &DentryRef, d: &DentryRef) -> bool {
    let mut p = parent.d_lock.write();
    let di = d.d_lock.read();
    let unused =
        DentryRef::count(d) == TREE_REFS + 1 && di.children.is_empty() && di.flags.mounted == 0;
    drop(di);
    if !unused {
        return false;
    }
    let Some(ours) = hash_out(&mut p, d) else {
        return false;
    };
    d.d_lock.write().flags.unhashed = true;
    drop(p);
    drop(ours);
    true
}

/// Everything cached below `d` leaves the tree (Linux
/// shrink_dcache_parent / shrink_dcache_for_umount): a subtree out of
/// the tree is no cache, and its parent<->child references would keep
/// it alive. A dentry still held elsewhere (an open file, a cwd)
/// survives, unhashed, with its parent chain. One leaf at a time, from
/// `d` down, allocating nothing.
pub fn d_drop_tree(d: &DentryRef) {
    loop {
        let mut cur = d.clone();
        while let Some(c) = first_child(&cur) {
            cur = c;
        }
        if DentryRef::ptr_eq(&cur, d) {
            return;
        }
        let Some(parent) = cur.get_parent() else {
            return;
        };
        let mut p = parent.d_lock.write();
        let mut ci = cur.d_lock.write();
        let ours = hash_out(&mut p, &cur);
        ci.flags.unhashed = true;
        drop(ci);
        drop(p);
        // A leaf another remover took out first (the shrinker, a move)
        // is not ours to drop: look again from the top, so no child is
        // left holding the subtree
        drop(ours);
    }
}

/// The child after `d` in `parent` (none if `d` left it)
fn next_sibling(parent: &Dentry, d: &Dentry) -> Option<DentryRef> {
    parent.d_lock.read().children.next(d)
}

fn first_child(d: &Dentry) -> Option<DentryRef> {
    d.d_lock.read().children.front()
}

/// Prune up to `budget` unused leaves of the tree under `root`, post
/// order, so a directory left empty goes too
fn prune_tree(root: &DentryRef, budget: usize) -> usize {
    let mut freed = 0;
    let mut cur = root.clone();
    loop {
        while let Some(c) = first_child(&cur) {
            cur = c;
        }
        loop {
            if DentryRef::ptr_eq(&cur, root) || freed >= budget {
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
    super::superblock::iterate_supers(|sb| {
        if freed < budget
            && let Some(root) = sb.get_root()
        {
            freed += prune_tree(&root, budget - freed);
        }
    });
    freed
}

/// Take `d` out of the tree under `parent`, if it is there
fn unhook_from(d: &DentryRef, parent: &Dentry) {
    let mut p = parent.d_lock.write();
    let ours = hash_out(&mut p, d);
    drop(p);
    drop(ours);
}

/// Re-hang `d` as `name` under `parent` (the name a snapshot of the
/// target's: Linux copy_name, a copy or a shared reference)
fn rehook(d: &DentryRef, parent: &DentryRef, name: DName) {
    let mut di = d.d_lock.write();
    *d.d_name.write() = name.clone();
    d.set_parent(&di, parent.clone());
    di.flags.unhashed = false;
    drop(di);
    hash_in(parent, &mut parent.d_lock.write(), d, &name);
}

/// A rename moved `d` to where `target` is (Linux d_move): the target
/// (the replaced dentry, or a negative one the rename made up front,
/// so nothing allocates here) leaves the tree, and `d` takes its parent
/// and name; `d` keeps its identity, so whoever holds it (a cwd, an fd,
/// a mountpoint) follows it. Callers hold both parents' i_rwsem.
pub fn d_move(d: &DentryRef, target: &DentryRef) {
    let w = RENAME_LOCK.write();
    let Some(parent) = target.get_parent() else {
        return;
    };
    let name = target.name();
    if let Some(old) = d.get_parent() {
        unhook_from(d, &old);
    }
    unhook_from(target, &parent);
    target.d_lock.write().flags.unhashed = true;
    rehook(d, &parent, name);
    drop(w);
    d_drop_tree(target);
}

/// RENAME_EXCHANGE swapped `a` and `b` (Linux d_exchange): each takes
/// the other's name and parent. Neither may be a root (Linux WARN_ON
/// IS_ROOT); if one is, nothing changes.
pub fn d_exchange(a: &DentryRef, b: &DentryRef) {
    let _w = RENAME_LOCK.write();
    let (Some(pa), Some(pb)) = (a.get_parent(), b.get_parent()) else {
        return;
    };
    let (na, nb) = (a.name(), b.name());
    unhook_from(a, &pa);
    unhook_from(b, &pb);
    rehook(a, &pb, nb);
    rehook(b, &pa, na);
}

/// Global dentry cache
/// For now, this is simple - dentries are cached implicitly via Arc references.
/// A more sophisticated implementation would use an LRU cache with hash table.
pub struct DentryCache {
    /// Root dentry of the namespace
    root: RwLock<Option<DentryRef>>,
}

impl DentryCache {
    /// Create a new empty dentry cache
    pub const fn new() -> Self {
        Self {
            root: RwLock::new(None),
        }
    }

    /// Set the root dentry
    pub fn set_root(&self, root: DentryRef) {
        *self.root.write() = Some(root);
    }

    /// Get the root dentry
    pub fn get_root(&self) -> Option<DentryRef> {
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
pub fn is_subdir(child: &DentryRef, ancestor: &DentryRef) -> bool {
    is_subdir_borrowed(child, ancestor)
}

/// [`is_subdir`] of dentries the caller keeps by other means (a lock
/// that pins the mount tree it borrowed them from)
pub fn is_subdir_borrowed(child: &Dentry, ancestor: &Dentry) -> bool {
    // Same dentry - trivially true
    if core::ptr::eq(child, ancestor) {
        return true;
    }

    // Lockless once, under the lock if a rename raced it (Linux: rcu,
    // read_seqbegin, d_ancestor, read_seqlock_excl on retry)
    let g = crate::sync::rcu::read_lock();
    RENAME_LOCK.read_or_lock(|_| {
        let mut cur: &Dentry = child;
        while let Some(p) = cur.parent_rcu(&g) {
            if core::ptr::eq(p, ancestor) {
                return true;
            }
            cur = p;
        }
        false
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::inode::{InodeMode, NULL_INODE_OPS, Timespec};

    fn inode() -> Arc<Inode> {
        Inode::alloc(Inode::new(
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
        let r = crate::fs::DentryRef::new(Dentry::new_root(inode(), Weak::new())).unwrap();
        let a = Dentry::alloc(&r, b"a", Some(inode())).unwrap();
        let other = crate::fs::DentryRef::new(Dentry::new_root(inode(), Weak::new())).unwrap();
        d_exchange(&a, &other);
        assert!(
            r.lookup_child(b"a")
                .is_some_and(|c| DentryRef::ptr_eq(&c, &a))
        );
        assert!(a.get_parent().is_some_and(|p| DentryRef::ptr_eq(&p, &r)));
    }

    /// rmdir's shape (Linux vfs_rmdir): the cache below goes first, then
    /// d_delete turns an unused dentry negative in place, keeping it
    /// in the tree
    #[test]
    fn rmdir_shrinks_then_deletes() {
        let r = crate::fs::DentryRef::new(Dentry::new_root(inode(), Weak::new())).unwrap();
        let a = Dentry::alloc(&r, b"a", Some(inode())).unwrap();
        let x = Dentry::alloc(&a, b"x", None).unwrap();
        d_drop_tree(&a);
        assert_eq!(a.num_children(), 0);
        assert!(x.is_unhashed());
        drop(x);
        r.d_delete(b"a", 1);
        assert!(a.is_negative() && !a.is_unhashed());
        assert!(
            r.lookup_child(b"a")
                .is_some_and(|c| DentryRef::ptr_eq(&c, &a))
        );
    }

    /// d_delete of a dentry someone else holds unhashes it and keeps
    /// its inode for the holder
    #[test]
    fn delete_held_unhashes() {
        let r = crate::fs::DentryRef::new(Dentry::new_root(inode(), Weak::new())).unwrap();
        let a = Dentry::alloc(&r, b"a", Some(inode())).unwrap();
        let other = a.clone();
        r.d_delete(b"a", 1);
        assert!(other.is_unhashed() && !other.is_negative());
        assert!(r.lookup_child(b"a").is_none());
    }

    /// A move onto a preallocated target takes its parent and name
    /// (a long name shared, Linux copy_name), and the target is dead
    #[test]
    fn move_takes_target_name() {
        let r = crate::fs::DentryRef::new(Dentry::new_root(inode(), Weak::new())).unwrap();
        let a = Dentry::alloc(&r, b"a", Some(inode())).unwrap();
        let d = Dentry::alloc(&r, b"d", Some(inode())).unwrap();
        let long = [b'n'; 60];
        let t = Dentry::prealloc(&d, &long).unwrap();
        d_move(&a, &t);
        assert!(r.lookup_child(b"a").is_none());
        assert!(
            d.lookup_child(&long)
                .is_some_and(|c| DentryRef::ptr_eq(&c, &a))
        );
        assert!(a.get_parent().is_some_and(|p| DentryRef::ptr_eq(&p, &d)));
        assert!(a.name().as_bytes() == long && t.is_unhashed());
    }

    /// A move over a cached dentry unhashes it, keeping its inode for
    /// whoever holds it
    #[test]
    fn move_over_replaces() {
        let r = crate::fs::DentryRef::new(Dentry::new_root(inode(), Weak::new())).unwrap();
        let a = Dentry::alloc(&r, b"a", Some(inode())).unwrap();
        let b = Dentry::alloc(&r, b"b", Some(inode())).unwrap();
        d_move(&a, &b);
        assert!(
            r.lookup_child(b"b")
                .is_some_and(|c| DentryRef::ptr_eq(&c, &a))
        );
        assert!(b.is_unhashed() && !b.is_negative());
        assert_eq!(r.num_children(), 1);
    }

    /// The hash finds a child by parent and name: one name under two
    /// parents is two dentries, and a removed one is gone from both the
    /// bucket and the children list
    #[test]
    fn hash_keys_parent_and_name() {
        let r = crate::fs::DentryRef::new(Dentry::new_root(inode(), Weak::new())).unwrap();
        let a = Dentry::alloc(&r, b"a", Some(inode())).unwrap();
        let b = Dentry::alloc(&r, b"b", Some(inode())).unwrap();
        let long = [b'z'; 50];
        let xa = Dentry::alloc(&a, &long, Some(inode())).unwrap();
        let xb = Dentry::alloc(&b, &long, Some(inode())).unwrap();
        assert!(!DentryRef::ptr_eq(&xa, &xb));
        assert!(
            a.lookup_child(&long)
                .is_some_and(|c| DentryRef::ptr_eq(&c, &xa))
        );
        assert!(
            b.lookup_child(&long)
                .is_some_and(|c| DentryRef::ptr_eq(&c, &xb))
        );
        assert!(Dentry::alloc(&a, &long, None).is_ok_and(|c| DentryRef::ptr_eq(&c, &xa)));
        assert!(a.remove_child(&long).is_some());
        assert!(a.lookup_child(&long).is_none() && a.num_children() == 0);
        assert!(b.lookup_child(&long).is_some() && xa.is_unhashed());
        assert_eq!(DentryRef::count(&xa), 1);
    }

    /// The shrinker drops unused leaves, then the directories they
    /// leave empty, and keeps what someone holds
    #[test]
    fn prune_keeps_held() {
        let r = crate::fs::DentryRef::new(Dentry::new_root(inode(), Weak::new())).unwrap();
        let a = Dentry::alloc(&r, b"a", Some(inode())).unwrap();
        for n in [b"x", b"y"] {
            Dentry::alloc(&a, n, None).unwrap();
        }
        let k = Dentry::alloc(&r, b"k", Some(inode())).unwrap();
        drop(a);
        assert_eq!(prune_tree(&r, 100), 3);
        assert!(r.lookup_child(b"a").is_none());
        assert!(
            r.lookup_child(b"k")
                .is_some_and(|c| DentryRef::ptr_eq(&c, &k))
        );
    }

    /// The last put of a deep chain of parents, each held only by its
    /// child, frees it in a loop (Linux dput's parent loop), not by
    /// nested drops
    #[test]
    fn dput_chain_is_a_loop() {
        let r = DentryRef::new(Dentry::new_root(inode(), Weak::new())).unwrap();
        let mut d = r.clone();
        for _ in 0..100_000 {
            d = Dentry::prealloc(&d, b"x").unwrap();
        }
        assert_eq!(DentryRef::count(&r), 2);
        drop(d);
        assert_eq!(DentryRef::count(&r), 1);
    }

    /// A reference taken from a borrowed dentry is counted like a clone
    #[test]
    fn try_get_counts() {
        let r = DentryRef::new(Dentry::new_root(inode(), Weak::new())).unwrap();
        let g = DentryRef::try_get(&r).unwrap();
        assert!(DentryRef::ptr_eq(&g, &r) && DentryRef::count(&r) == 2);
        drop(g);
        assert_eq!(DentryRef::count(&r), 1);
    }

    /// A real exchange swaps names and parents
    #[test]
    fn exchange_swaps() {
        let r = crate::fs::DentryRef::new(Dentry::new_root(inode(), Weak::new())).unwrap();
        let a = Dentry::alloc(&r, b"a", Some(inode())).unwrap();
        let b = Dentry::alloc(&r, b"b", Some(inode())).unwrap();
        d_exchange(&a, &b);
        assert!(
            r.lookup_child(b"b")
                .is_some_and(|c| DentryRef::ptr_eq(&c, &a))
        );
        assert!(
            r.lookup_child(b"a")
                .is_some_and(|c| DentryRef::ptr_eq(&c, &b))
        );
    }
}
