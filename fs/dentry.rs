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
use core::sync::atomic::{
    AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering, Ordering::Relaxed, fence,
};

use crate::sync::spin::RwLock;
use crate::util::hlist_bl::BlHead;
use crate::util::list::{Link, OwnedList, Owner};

use super::inode::Inode;
use super::mount::{MOUNT_LOCK, Mount, MountRef};
use super::name::{DName, DNameSlot};
use super::path_ref::Path;
use super::superblock::SuperBlock;
use crate::sync::rcu::{RcuHead, RcuReadGuard};
use crate::sync::{SeqCount, SeqCountGuard};
use crate::util::error::KernelError;
use crate::util::list::{ListPtr, RefPtr};

/// `Dentry.d_flags` bit: a mountpoint exists for it (Linux
/// DCACHE_MOUNTED, set and cleared with its struct mountpoint under
/// MOUNT_LOCK): a hint for the walk; which mount covers it is the
/// namespace's business
const DCACHE_MOUNTED: u32 = 1 << 16;
/// Nothing may be mounted on it any more (Linux DCACHE_CANT_MOUNT): its
/// name was removed
const DCACHE_CANT_MOUNT: u32 = 1 << 8;

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
crate::adapter!(pub AliasA, Dentry, d_alias);

/// An inode's dentries (Linux i_dentry), its `i_dentry`'s contents
type Aliases = crate::util::list::List<AliasA>;

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

/// A filesystem's dentry operations (Linux dentry_operations, from
/// its s_d_op): name hashing and comparison for one whose names match
/// more than their bytes (vfat ignores case and trailing dots, so each
/// object has one dentry whatever the spelling it was reached by),
/// revalidation of a cached dentry, and a hook at a dentry's kill
/// (nsfs forgets its stashed dentry). None: Linux's default (its
/// DCACHE_OP_* bit clear).
pub struct DentryOps {
    /// The name's hash (Linux d_hash): names `d_compare` matches hash
    /// alike
    pub d_hash: Option<fn(&[u8]) -> u64>,
    /// The cached name `stored` is `name` (Linux d_compare)
    pub d_compare: Option<CompareFn>,
    /// A cached dentry, positive or negative (`inode` None), is still
    /// good for the walk (Linux d_revalidate): Ok(false) drops it and
    /// the walk looks the name up again. With `rcu` (LOOKUP_RCU) an RCU
    /// walk asks: the dentry and `inode` are borrowed with no
    /// reference and may be torn down already, so only fields with no
    /// drop glue may be read (`IFree`); ECHILD where that is not
    /// enough, and the walk asks again in ref mode.
    pub d_revalidate: Option<RevalidateFn>,
    /// A dentry no one holds any more is killed, not kept cached (Linux
    /// d_delete, asked by retain_dentry at the last dput: ramfs's
    /// always_delete_dentry). Asked only of a negative one: every
    /// filesystem here with one pins its positive dentries
    /// (`SuperOps::d_persistent`, Linux d_make_persistent's reference)
    pub d_delete: Option<fn(&Dentry) -> bool>,
    /// Called as the dentry is killed, before its memory's grace period
    /// starts (Linux d_prune): no reference is left or can be taken
    pub d_prune: Option<fn(&Dentry)>,
}

/// [`DentryOps::d_compare`]: the cached name `stored` is `name`
pub type CompareFn = fn(stored: &[u8], name: &[u8]) -> bool;

/// [`DentryOps::d_revalidate`]: the dentry, its inode as the caller
/// read it (None: negative), LOOKUP_RCU
pub type RevalidateFn = fn(&Dentry, Option<&Inode>, bool) -> Result<bool, KernelError>;

impl DentryOps {
    /// No operation set (Linux's defaults), for `..DentryOps::NONE`
    pub const NONE: Self = Self {
        d_hash: None,
        d_compare: None,
        d_revalidate: None,
        d_delete: None,
        d_prune: None,
    };
}

/// The hash of the child name `name` under `parent` (Linux
/// full_name_hash, or d_hash where the filesystem has one)
fn name_hash_in(parent: &Dentry, name: &[u8]) -> u64 {
    match parent.d_op.and_then(|o| o.d_hash) {
        Some(h) => h(name),
        None => super::name::name_hash(name),
    }
}

/// Put `d` (parent `parent`, named `name`) in the tree: on the
/// parent's children (`p`, its d_lock held for writing), then in its
/// bucket (Linux d_add's __d_rehash, d_sib)
fn hash_in(parent: &Dentry, p: &mut DentryInner, d: &DentryRef, name: &DName) {
    let h = match parent.d_op.and_then(|o| o.d_hash) {
        Some(h) => h(name),
        None => name.hash(),
    };
    let key = d_key(parent, h);
    d.d_hkey.store(key, Relaxed);
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

/// Take `d` out of the tree if it is a child of the parent whose
/// d_lock (`p`) is held for writing, `d`'s own (`_dl`) too (Linux
/// __d_drop): unhashed, and its `d_seq` moved on so an RCU walk that
/// read it repeats (write_seqcount_invalidate). The children list's
/// reference, None (and nothing changed) if it was not there.
fn __d_drop(p: &mut DentryInner, d: &Dentry, _dl: &mut DentryInner) -> Option<DentryRef> {
    let r = hash_out(p, d)?;
    d.d_seq.invalidate();
    Some(r)
}

/// The bucket's test for the child `name` of `parent`: key and parent
/// (atomics, so a dentry being moved reads safely; under the bucket's
/// lock both are those it was hashed with, since a move takes it out
/// first; Linux compares d_parent)
fn d_matcher<'a>(parent: &'a Dentry, name: &'a [u8]) -> (u64, impl Fn(&Dentry) -> bool + 'a) {
    let key = d_key(parent, name_hash_in(parent, name));
    (key, move |c: &Dentry| {
        c.d_hkey.load(Relaxed) == key && core::ptr::eq(c.parent_ptr(), parent)
    })
}

/// `stored` names the child `name` of `parent` (Linux d_same_name)
fn d_same_name(parent: &Dentry, stored: &[u8], name: &[u8]) -> bool {
    match parent.d_op.and_then(|o| o.d_compare) {
        Some(cmp) => cmp(stored, name),
        None => stored == name,
    }
}

/// The child `name` of `parent` (Linux __d_lookup): one walk of the
/// bucket under an RCU read guard with no lock; a candidate (key and
/// parent address match) is checked under its own d_lock (Linux
/// spin_lock(&dentry->d_lock)): still a child of `parent`, in the
/// tree, the name matching (`d_name`, written only while a dentry is
/// out of the tree), and the reference is taken there (Linux
/// d_lockref.count++; `try_get`, which refuses a dying one), so the
/// count checks made under a child's d_lock (`add`, `d_delete`) see
/// every lookup's reference. May miss while a rename moves a dentry
/// the walk stands on: `d_lookup` retries.
fn __d_lookup(parent: &Dentry, name: &[u8]) -> Option<DentryRef> {
    let (key, is) = d_matcher(parent, name);
    let g = crate::sync::rcu::read_lock();
    let mut found = None;
    d_hash(key).find_rcu(&g, |c| {
        if !is(c) {
            return false;
        }
        let _cl = c.d_lock.read();
        if !core::ptr::eq(c.parent_ptr(), parent)
            || c.d_unhashed()
            || !c.d_name.read(&g, |s| d_same_name(parent, s, name))
        {
            return false;
        }
        found = DentryRef::try_get(c);
        found.is_some()
    });
    found
}

/// The child `name` of `parent` for an RCU path walk (Linux
/// __d_lookup_rcu): one walk of the bucket under `g` taking no lock
/// and no reference, storing nothing. Each candidate is read after a
/// raw `d_seq` sample (a writer is not waited out: its odd count fails
/// the caller's check): parent, key, name, then hashed (checked after
/// the compare, as Linux: it may have been unhashed after the sample
/// was read). With the parent's `DentryOps` the name is read whole
/// first (a `d_seq` retry repeats the candidate), then compared (Linux
/// __d_lookup_rcu_op_compare). The `d_seq` value comes back with the
/// hit: the caller confirms anything it read of it with
/// [`Dentry::d_seq_retry`] before using it, and takes a reference with
/// [`DentryRef::try_get`] then checks the seq again (Linux
/// legitimize_path; a reference that then fails is dropped after the
/// guard, as terminate_walk). May miss while a rename moves a dentry
/// the walk stands on: the caller checks RENAME_LOCK's sequence (Linux
/// path walk's r_seq) or falls back to `d_lookup`.
pub fn __d_lookup_rcu<'g>(
    parent: &Dentry,
    name: &[u8],
    g: &'g RcuReadGuard,
) -> Option<(&'g Dentry, u32)> {
    let key = d_key(parent, name_hash_in(parent, name));
    let mut seq = 0;
    let d = d_hash(key).find_rcu(g, |c| match parent.d_op.and_then(|o| o.d_compare) {
        None => {
            let s = c.d_seq.raw_begin();
            if !core::ptr::eq(c.parent_ptr(), parent)
                || c.d_hkey.load(Relaxed) != key
                || !c.d_name.read(g, |n| n == name)
                || c.d_unhashed()
            {
                return false;
            }
            seq = s;
            true
        }
        Some(cmp) => loop {
            let s = c.d_seq.raw_begin();
            if !core::ptr::eq(c.parent_ptr(), parent)
                || c.d_unhashed()
                || c.d_hkey.load(Relaxed) != key
            {
                return false;
            }
            // A consistent name for d_compare: checked against the
            // sample before the compare
            let hit = c
                .d_name
                .read(g, |n| (!c.d_seq.read_retry(s)).then(|| cmp(n, name)));
            match hit {
                Some(h) => {
                    seq = s;
                    return h;
                }
                None => core::hint::spin_loop(),
            }
        },
    })?;
    Some((d, seq))
}

/// The child `name` of `parent` (Linux d_lookup): [`__d_lookup`],
/// repeated while a rename raced a miss (read_seqbegin / read_seqretry
/// on RENAME_LOCK). The caller holds no d_lock: a rename takes them
/// inside RENAME_LOCK. A new reference.
fn d_lookup(parent: &Dentry, name: &[u8]) -> Option<DentryRef> {
    loop {
        let seq = RENAME_LOCK.read_begin();
        if let Some(d) = __d_lookup(parent, name) {
            return Some(d);
        }
        if !RENAME_LOCK.read_retry(seq) {
            return None;
        }
    }
}

/// The child `name` of `parent`, whose d_lock `_p` is held for writing
/// (to add or drop a child): one walk of the bucket under its lock,
/// which every hash writer holds, so it is exact (Linux __d_add and
/// d_alloc_parallel decide under the bucket's hlist_bl_lock). With `_p`
/// held no child of `parent` enters or leaves the tree, and a name
/// changes only out of every bucket (a move holds the bucket's lock to
/// take it out), so the names read are whole. A new reference.
fn d_lookup_locked(parent: &Dentry, _p: &DentryInner, name: &[u8]) -> Option<DentryRef> {
    let (key, is) = d_matcher(parent, name);
    let g = crate::sync::rcu::read_lock();
    d_hash(key)
        .lock()
        .find(|c| is(c) && c.d_name.read(&g, |s| d_same_name(parent, s, name)))
}

crate::percpu! {
    /// Dentries alive (/proc/sys/fs/dentry-state nr_dentry): per CPU,
    /// summed on read (Linux DEFINE_PER_CPU nr_dentry, get_nr_dentry); a
    /// CPU's count goes negative when it frees others' dentries
    static NR_DENTRY: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(0);
}

/// Inner mutable state protected by d_lock
struct DentryInner {
    /// Children in the tree (Linux d_children), each with the list's
    /// reference; each is also in its hash bucket
    children: Children,
}

/// A directory entry - maps a name to an inode
///
/// ## Locking
///
/// `d_lock` serializes every change, the parent included (Linux
/// d_lock); a parent's d_lock is taken before a child's. What an RCU
/// walk reads (`d_inode`, `d_flags`, `d_name`, `d_parent`) are atomics
/// written under it (inside `d_seq` write sections for the inode, the
/// name and a move's parent) and read with no lock (Linux READ_ONCE
/// under d_seq). `sb` is immutable. `d_sib`/`d_sib_owner` belong to
/// the parent's children list (its d_lock), `d_hash` to the bucket's
/// bit lock; `d_hkey` is written under the parent's d_lock before the
/// dentry goes in its bucket and read under the bucket's lock; it
/// changes only while it is out (Linux d_name.hash). `d_parent` is
/// written under the dentry's d_lock (and, once it is in the tree,
/// RENAME_LOCK) and read lock-free (Linux READ_ONCE(d_parent)).
///
/// Held through [`DentryRef`] (Linux d_lockref's count); its memory is
/// freed a grace period after the last one goes (Linux dentry_free's
/// call_rcu), so an RCU reader may follow `d_parent` and read `d_name`
/// of a dentry it holds no reference to.
///
/// # Invariants
/// A dentry a [`DentryRef`] owns is on its inode's `i_dentry` through
/// `d_alias` exactly while `d_inode` is set, from
/// `DentryRef::new` or the `add` that set it until the `d_delete` or
/// `dentry_kill` that takes it; both change together under that
/// inode's `i_dentry` lock and the dentry's d_lock (Linux
/// d_instantiate and dentry_unlink_inode under i_lock and d_lock), so
/// it is unlinked before its memory is freed.
pub struct Dentry {
    /// Back pointer to superblock - immutable after creation
    pub sb: Weak<SuperBlock>,
    /// Its superblock's name operations, for its children (Linux d_op,
    /// from s_d_op at d_alloc): immutable
    d_op: Option<&'static DentryOps>,

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
    /// What an RCU walk reads of it changes inside a write section
    /// under its d_lock held for writing (Linux d_seq): its inode set
    /// or cleared, its parent and name by a move; leaving the tree
    /// moves it on (write_seqcount_invalidate)
    d_seq: SeqCount,
    /// Its inode (Linux d_inode), null for a negative dentry: an
    /// `Arc::into_raw`, the dentry's reference; written under its
    /// d_lock (write) inside a `d_seq` write section with Release, read
    /// with no lock (Acquire): a holder's reference keeps it set, an
    /// RCU reader borrows it (`d_inode_rcu`)
    d_inode: AtomicPtr<Inode>,
    /// `DCACHE_*` bits (Linux d_flags): changed under its d_lock held
    /// for writing (a plain store, Release), read with no lock
    /// (Acquire, Linux READ_ONCE): an RCU walk confirms what it read
    /// by `d_seq`
    d_flags: AtomicU32,

    /// On the parent's children (Linux d_sib)
    d_sib: Link,
    d_sib_owner: Owner,
    /// In a hash bucket (Linux d_hash): hashed exactly while the
    /// dentry is in the tree (`d_unhashed`)
    d_hash: Link,
    /// The key it was hashed under (`d_key`)
    d_hkey: AtomicU64,
    /// On its inode's `i_dentry` (Linux d_u.d_alias)
    d_alias: Link,

    /// Name in the parent (empty for a root; Linux d_name): changed
    /// only by a move, under the d_lock (write) inside a `d_seq` write
    /// section, with the dentry out of every bucket; read with no lock
    /// (`DNameSlot::read`, checked by `d_seq` unless the d_lock or a
    /// bucket lock it is in is held)
    d_name: DNameSlot,

    /// Single lock protecting all mutable state (like Linux d_lock)
    d_lock: RwLock<DentryInner>,
}

impl Drop for Dentry {
    /// A dentry dropped without its kill (one never given to a
    /// `DentryRef`) lets go of its inode; a killed one has none left.
    /// A killed dentry is dropped by `d_free`, a grace period after its
    /// kill, when no RCU reader can borrow it any more.
    fn drop(&mut self) {
        let p = *self.d_inode.get_mut();
        // SAFETY: a non-null `d_inode` is an `Arc::into_raw` the dentry
        // owns; `&mut self`: no reader is left
        drop(NonNull::new(p).map(|p| unsafe { Arc::from_raw(p.as_ptr()) }));
    }
}

impl Dentry {
    fn with(name: DName, inode: Option<Arc<Inode>>, sb: Weak<SuperBlock>) -> Self {
        let d_op = sb.upgrade().and_then(|s| s.d_op());
        Self::with_op(name, inode, sb, d_op)
    }

    /// With `d_op` (its superblock's s_d_op: a child's is its parent's)
    fn with_op(
        name: DName,
        inode: Option<Arc<Inode>>,
        sb: Weak<SuperBlock>,
        d_op: Option<&'static DentryOps>,
    ) -> Self {
        Self {
            d_op,
            sb,
            d_count: AtomicUsize::new(1),
            d_parent: AtomicPtr::new(core::ptr::null_mut()),
            d_rcu: RcuHead::new(),
            d_seq: SeqCount::new(),
            d_inode: AtomicPtr::new(
                inode.map_or(core::ptr::null_mut(), |i| Arc::into_raw(i).cast_mut()),
            ),
            d_flags: AtomicU32::new(0),
            d_sib: Link::new(),
            d_sib_owner: Owner::new(),
            d_hash: Link::new(),
            d_hkey: AtomicU64::new(0),
            d_alias: Link::new(),
            d_name: DNameSlot::new(name),
            d_lock: RwLock::new(DentryInner {
                children: OwnedList::new(),
            }),
        }
    }

    /// Create root dentry for a filesystem
    pub fn new_root(inode: Arc<Inode>, sb: Weak<SuperBlock>) -> Self {
        Self::with(DName::default(), Some(inode), sb)
    }

    /// A root with dentry operations `op` and no superblock, for tests
    #[cfg(test)]
    pub(crate) fn new_root_op(inode: Arc<Inode>, op: &'static DentryOps) -> Self {
        Self::with_op(DName::default(), Some(inode), Weak::new(), Some(op))
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
        let d = DentryRef::new(Self::with_op(
            DName::new(name)?,
            Some(inode),
            parent.sb.clone(),
            parent.d_op,
        ))?;
        let dl = d.d_lock.write();
        d.set_parent(&dl, parent.clone());
        drop(dl);
        Ok(d)
    }

    /// A new child dentry of `parent`, not yet in the tree: the
    /// allocation a create or rename does before the filesystem makes
    /// the entry (Linux d_alloc in lookup_create), so an ENOMEM leaves
    /// nothing half made. It holds its parent already (Linux d_alloc's
    /// dget of the parent).
    pub fn prealloc(parent: &DentryRef, name: &[u8]) -> Result<DentryRef, KernelError> {
        let d = DentryRef::new(Self::with_op(
            DName::new(name)?,
            None,
            parent.sb.clone(),
            parent.d_op,
        ))?;
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
        // The inode's alias lock first (Linux d_add: i_lock, then d_lock)
        let i = inode.clone();
        let mut al = i.as_ref().map(|i| i.i_dentry.lock());
        let mut p = parent.d_lock.write();
        if let Some(c) = d_lookup_locked(parent, &p, &name) {
            let mut ci = c.d_lock.write();
            if !c.is_negative() {
                drop(ci);
                return c;
            }
            // A negative one is filled only if no one else holds it
            // (lookups take their reference under its d_lock, held here);
            // a held one is replaced, so a holder never sees an inode
            // it did not look up
            if DentryRef::count(&c) == TREE_REFS + 1 {
                // Linux __d_instantiate: inside a d_seq write section
                let s = c.seq_write(&mut ci);
                c.set_inode(&mut ci, inode);
                if let Some(al) = &mut al {
                    alias_add(al, &ci, &c);
                }
                drop(s);
                drop(ci);
                return c;
            }
            let old = __d_drop(&mut p, &c, &mut ci);
            drop(ci);
            drop(old);
        }
        // Linux __d_add: the inode set inside a d_seq write section,
        // then hashed, under the dentry's d_lock
        let mut dl = d.d_lock.write();
        debug_assert!(d.is_negative(), "dcache: add of a positive dentry");
        let s = d.seq_write(&mut dl);
        d.set_inode(&mut dl, inode);
        if let Some(al) = &mut al {
            alias_add(al, &dl, &d);
        }
        drop(s);
        d.set_parent(&dl, parent.clone());
        hash_in(parent, &mut p, &d, &name);
        drop(dl);
        d
    }

    /// Name in the parent, a snapshot (Linux take_dentry_name_snapshot:
    /// d_move may change it): a byte copy or a shared reference, never an
    /// allocation
    pub fn name(&self) -> DName {
        let g = crate::sync::rcu::read_lock();
        // Linux take_dentry_name_snapshot: repeated while a move raced
        loop {
            let seq = self.d_seq.read_begin();
            let n = self.d_name.snapshot(&g);
            if !self.d_seq.read_retry(seq) {
                return n;
            }
        }
    }

    /// Name in the parent, a snapshot taken under its d_lock (`_dl`),
    /// which every name writer holds: whole with no `d_seq` check (so
    /// also inside this dentry's own write section)
    fn name_locked(&self, _dl: &DentryInner) -> DName {
        self.d_name.snapshot(&crate::sync::rcu::read_lock())
    }

    /// A reference to its inode (Linux d_inode + ihold): read with no
    /// lock (`d_inode_rcu`), the reference taken unless that inode's
    /// last one went (Linux igrab), which happens only after a writer
    /// took it off this dentry: then it is negative
    pub fn get_inode(&self) -> Option<Arc<Inode>> {
        let g = crate::sync::rcu::read_lock();
        self.d_inode_rcu(&g).and_then(Inode::igrab)
    }

    /// Its inode, borrowed for an RCU read guard with no reference
    /// (Linux READ_ONCE(dentry->d_inode) in an RCU walk), None when
    /// negative: what it was at the read, which a walk confirms with
    /// `d_seq` (the inode changes inside a write section). Only the
    /// inode's fields with no drop glue may be read through it (atomics,
    /// `ino`, `i_op`): it may be torn down already (`inode::IFree`).
    pub fn d_inode_rcu<'g>(&self, _g: &'g RcuReadGuard) -> Option<&'g Inode> {
        let p = self.d_inode.load(Ordering::Acquire);
        // SAFETY: a non-null `d_inode` held a strong reference when it
        // was read, under the guard; a writer clears the pointer before
        // it drops that reference, and an inode's memory is freed a
        // grace period after its teardown (`inode::IFree`, Linux
        // i_callback), which `_g` holds off
        unsafe { p.as_ref() }
    }

    /// Point `d_inode` at `inode` (Linux __d_set_inode_and_type), under
    /// this dentry's d_lock held for writing and a `d_seq` write section;
    /// the pointer owns the reference
    fn set_inode(&self, _dl: &mut DentryInner, inode: Option<Arc<Inode>>) {
        let new = inode.map_or(core::ptr::null_mut(), |i| Arc::into_raw(i).cast_mut());
        let old = self.d_inode.swap(new, Ordering::Release);
        debug_assert!(old.is_null(), "dcache: inode set twice");
    }

    /// Clear `d_inode` (Linux __d_clear_type_and_inode), under this
    /// dentry's d_lock held for writing and a `d_seq` write section: the
    /// reference it held, for the caller to drop after the locks
    fn take_inode(&self, _dl: &mut DentryInner) -> Option<Arc<Inode>> {
        let p = self.d_inode.swap(core::ptr::null_mut(), Ordering::Release);
        // SAFETY: a non-null `d_inode` is an `Arc::into_raw` the dentry
        // owns (`set_inode`, `with`), taken out once by this swap
        NonNull::new(p).map(|p| unsafe { Arc::from_raw(p.as_ptr()) })
    }

    /// The child `name` was unlinked (Linux d_delete): one no one but
    /// the caller (`held` references) holds becomes negative in place
    /// and lets go of its inode after the locks (Linux
    /// dentry_unlink_inode: fsnotify_inoderemove and iput after d_lock
    /// and i_lock are dropped); a held one leaves the tree (__d_drop),
    /// and lets go when its last holder does. Decided under this
    /// parent's d_lock and the child's, where lookups take their references. A removed
    /// directory has nothing cached below it any more (`delete_entry`,
    /// Linux vfs_rmdir's shrink_dcache_parent).
    pub fn d_delete(&self, name: &[u8], held: usize) {
        // The child and its inode first: the inode's alias lock comes
        // before any d_lock (Linux d_delete: i_lock, then d_lock)
        let Some(c) = d_lookup(self, name) else {
            return;
        };
        let Some(inode) = c.get_inode() else {
            return;
        };
        let mut al = inode.i_dentry.lock();
        let mut p = self.d_lock.write();
        // Under the child's d_lock, where lookups take their references
        // (Linux d_delete: d_lockref.count == 1 under dentry->d_lock)
        let mut cl = c.d_lock.write();
        // Still this child of that name with that inode (the caller
        // holds the directory's i_rwsem: no rename or delete raced)
        let same = !c.d_unhashed()
            && core::ptr::eq(c.parent_ptr(), self)
            && c.d_name.read(&crate::sync::rcu::read_lock(), |s| {
                d_same_name(self, s, name)
            })
            && core::ptr::eq(c.d_inode.load(Relaxed), Arc::as_ptr(&inode));
        if !same {
            return;
        }
        if DentryRef::count(&c) <= held + TREE_REFS + 1 {
            // Negative in place: a name made there later may be mounted
            // on again (Linux d_delete clears DCACHE_CANT_MOUNT)
            c.set_flag(&mut cl, DCACHE_CANT_MOUNT, false);
            // Linux dentry_unlink_inode: inside a d_seq write section
            let s = c.seq_write(&mut cl);
            let i = c.take_inode(&mut cl);
            alias_del(&mut al, &cl, &c);
            drop(s);
            drop(cl);
            drop(p);
            drop(al);
            crate::io::inotify::d_iput(&inode);
            drop(i);
        } else {
            let ours = __d_drop(&mut p, &c, &mut cl);
            drop(cl);
            drop(p);
            drop(al);
            drop(ours);
        }
    }

    /// Its filesystem's d_revalidate, else valid (Linux d_revalidate
    /// without DCACHE_OP_REVALIDATE): `inode` is its inode as the
    /// caller read it, None for a negative dentry; `rcu` as
    /// [`DentryOps::d_revalidate`]
    pub fn revalidate(&self, inode: Option<&Inode>, rcu: bool) -> Result<bool, KernelError> {
        match self.d_op.and_then(|o| o.d_revalidate) {
            Some(f) => f(self, inode, rcu),
            None => Ok(true),
        }
    }

    /// Check if this is a negative (failed lookup) dentry
    pub fn is_negative(&self) -> bool {
        self.d_inode.load(Ordering::Acquire).is_null()
    }

    /// Out of the tree (Linux d_unhashed, `!d_hash.pprev`): deleted,
    /// renamed over, not yet added, or never in it (a root, an O_TMPFILE
    /// file's, a pseudo filesystem's). A lockless snapshot: exact under
    /// the dentry's d_lock (every unhash and rehash holds it), else
    /// confirmed by `d_seq`.
    pub fn d_unhashed(&self) -> bool {
        !self.d_hash.is_hashed()
    }

    /// Removed from its directory (Linux d_unlinked: unhashed and not a
    /// root): a path reads " (deleted)", getcwd fails ENOENT
    pub fn d_unlinked(&self) -> bool {
        self.d_unhashed() && !self.parent_ptr().is_null()
    }

    /// A `d_flags` bit, read with no lock (Linux READ_ONCE(d_flags)):
    /// what an RCU walk reads, confirmed by `d_seq`
    fn flag(&self, f: u32) -> bool {
        self.d_flags.load(Ordering::Acquire) & f != 0
    }

    /// Set or clear a `d_flags` bit under this dentry's d_lock held for
    /// writing (`_dl`, the bits' one writer lock: a plain store, as
    /// Linux changes d_flags under d_lock)
    fn set_flag(&self, _dl: &mut DentryInner, f: u32, on: bool) {
        let v = self.d_flags.load(Relaxed);
        let v = if on { v | f } else { v & !f };
        self.d_flags.store(v, Ordering::Release);
    }

    /// Begin reading what an RCU walk reads of it (Linux
    /// read_seqcount_begin(&dentry->d_seq)): waits out a writer
    pub fn d_seq_begin(&self) -> u32 {
        self.d_seq.read_begin()
    }

    /// What was read of it since `seq` may have changed (Linux
    /// read_seqcount_retry(&dentry->d_seq, seq)): an RCU walk repeats or
    /// leaves RCU mode (try_to_unlazy)
    pub fn d_seq_retry(&self, seq: u32) -> bool {
        self.d_seq.read_retry(seq)
    }

    /// Begin a change an RCU walk must notice (Linux
    /// write_seqcount_begin(&dentry->d_seq)), under this dentry's d_lock
    /// held for writing (`_dl`, its writers' lock)
    fn seq_write(&self, _dl: &mut DentryInner) -> SeqCountGuard<'_> {
        self.d_seq.write()
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
    pub(super) fn parent_rcu<'g>(
        &self,
        _g: &'g crate::sync::rcu::RcuReadGuard,
    ) -> Option<&'g Dentry> {
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
        d_lookup(self, name)
    }

    /// Drop the child `name` from the tree (Linux d_delete / d_drop):
    /// later lookups ask the file system; a holder keeps an unhashed
    /// dentry
    pub fn remove_child(&self, name: &[u8]) -> Option<DentryRef> {
        let mut p = self.d_lock.write();
        let c = d_lookup_locked(self, &p, name)?;
        let ours = __d_drop(&mut p, &c, &mut c.d_lock.write());
        drop(p);
        drop(ours);
        d_drop_tree(&c);
        Some(c)
    }

    /// Some mount, in some namespace, sits on this dentry
    pub fn is_mountpoint(&self) -> bool {
        self.flag(DCACHE_MOUNTED)
    }

    /// Mark it a mountpoint or not (Linux d_set_mounted, clearing
    /// DCACHE_MOUNTED); under MOUNT_LOCK, with its mountpoint
    pub fn set_mounted(&self, on: bool) {
        self.set_flag(&mut self.d_lock.write(), DCACHE_MOUNTED, on);
    }

    /// Its name was removed (rmdir, unlink, a rename over it): nothing
    /// may be mounted on it from now on (Linux dont_mount, under d_lock)
    pub fn dont_mount(&self) {
        self.set_flag(&mut self.d_lock.write(), DCACHE_CANT_MOUNT, true);
    }

    /// Nothing may be mounted on it (Linux cant_mount)
    pub fn cant_mount(&self) -> bool {
        self.flag(DCACHE_CANT_MOUNT)
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

/// Link `d`, just made positive (its d_lock `dl`, written, holds the
/// inode `al` belongs to), on that inode's aliases (Linux
/// __d_instantiate's hlist_add_head)
fn alias_add(al: &mut Aliases, _dl: &DentryInner, d: &DentryRef) {
    debug_assert!(!d.is_negative());
    // SAFETY: `d` is owned by a DentryRef (live, its memory freed only
    // after `dentry_kill` unlinks it) and was negative until now, so on
    // no alias list (type invariant); `al` is its inode's, locked
    unsafe { al.push_front(DentryRef::as_ptr(d)) };
}

/// Unlink `d`, whose inode its d_lock `dl` (written) just let go of,
/// from that inode's aliases `al` (Linux dentry_unlink_inode's
/// hlist_del_init)
fn alias_del(al: &mut Aliases, _dl: &DentryInner, d: &Dentry) {
    debug_assert!(d.is_negative());
    // SAFETY: `d` was positive with the inode `al` belongs to, so on
    // that list (type invariant), under its lock
    unsafe { al.remove(d) };
}

/// The first alias of `inode` for which `ok` holds under its d_lock,
/// with a reference (Linux __d_find_any_alias / __d_find_alias): under
/// the inode's alias lock, which keeps every entry's memory (unlinked
/// before it is freed); a dying one is skipped. No reference is
/// dropped under the lock.
fn find_alias(inode: &Inode, ok: impl Fn(&Dentry) -> bool) -> Option<DentryRef> {
    let al = inode.i_dentry.lock();
    al.iter().find_map(|d| {
        let _dl = d.d_lock.read();
        ok(d).then(|| DentryRef::try_get(d)).flatten()
    })
}

/// A reference to a dentry of `inode` (Linux d_find_any_alias)
pub fn d_find_any_alias(inode: &Inode) -> Option<DentryRef> {
    find_alias(inode, |_| true)
}

/// A reference to a hashed dentry of `inode`, or to a directory's one
/// dentry, hashed or not (Linux d_find_alias)
pub fn d_find_alias(inode: &Inode) -> Option<DentryRef> {
    if inode.mode().is_dir() {
        return d_find_any_alias(inode);
    }
    find_alias(inode, |d| !d.d_unhashed())
}

/// The first alias of `inode` for which `f` holds (Linux
/// find_acceptable_alias's walk): each taken under the alias lock and
/// tested with it released, so `f` may take any lock and the
/// references not kept are dropped unlocked; aliases added or removed
/// meanwhile may be missed or seen twice
pub fn d_find_alias_by(inode: &Inode, mut f: impl FnMut(&DentryRef) -> bool) -> Option<DentryRef> {
    for n in 0.. {
        let d = {
            let al = inode.i_dentry.lock();
            DentryRef::try_get(al.iter().nth(n)?)
        };
        if let Some(d) = d.filter(|d| f(d)) {
            return Some(d);
        }
    }
    None
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

    /// "/name" of `d` in front (ENAMETOOLONG when it does not fit):
    /// read with no lock (Linux prepend_name), torn by a rename only in
    /// a pass that RENAME_LOCK's sequence then rejects
    fn name(&mut self, d: &Dentry, g: &RcuReadGuard) -> Result<(), KernelError> {
        d.d_name.read(g, |n| self.prepend(n))
    }

    fn prepend(&mut self, n: &[u8]) -> Result<(), KernelError> {
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
        b.name(d, g)?;
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
            b.name(cur, &g)?;
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
    if p.dentry.d_unlinked() {
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
        NR_DENTRY.this_add(1);
        let r = Self(NonNull::from(Box::leak(b)));
        // A positive one joins its inode's aliases (Linux d_instantiate)
        if let Some(i) = r.get_inode() {
            let mut al = i.i_dentry.lock();
            alias_add(&mut al, &r.d_lock.read(), &r);
        }
        Ok(r)
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

    /// Put a reference that is not the last: one the caller holds
    /// outlives it (a dentry the tree drops under MOUNT_LOCK, Linux
    /// d_drop's, which holds none). A decrement alone, safe under any
    /// spin lock; a put that is the last instead leaks the dentry,
    /// never kills it.
    fn put_held(self) {
        let me = ManuallyDrop::new(self);
        let n = me.d_count.fetch_sub(1, Ordering::Release);
        debug_assert!(n > 1, "dcache: put_held put the last reference");
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
        // Linux dput's retain_dentry: the last holder of a hashed
        // dentry its filesystem keeps no unused copy of takes it out of
        // the tree, so this put kills it
        if Self::count(self) == TREE_REFS + 1 && !self.d_unhashed() && self.unretained() {
            d_delete_unused(self);
        }
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

// SAFETY: a dentry's last put frees its memory by call_rcu
// (`dentry_kill`), or at once only where no other CPU runs a reader
unsafe impl crate::util::hlist_bl::RcuFreePtr for DentryRef {}

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

impl Dentry {
    /// Negative, and its filesystem keeps no unused one (Linux
    /// retain_dentry false: d_op->d_delete)
    fn unretained(&self) -> bool {
        self.is_negative() && self.d_op.and_then(|o| o.d_delete).is_some_and(|f| f(self))
    }
}

/// The caller is the last holder of `d`, hashed, which its filesystem
/// keeps no unused copy of (`Dentry::unretained`): it leaves the tree
/// if it is still unused and negative, decided under its parent's
/// d_lock and its own (`prune_one`, Linux dput -> lock_for_kill ->
/// __dentry_kill), the tree's references put after the locks; the
/// caller's put then kills it. A DentryRef of a hashed dentry is never
/// put under a d_lock.
fn d_delete_unused(d: &DentryRef) {
    if let Some(parent) = d.get_parent() {
        prune_one(&parent, d, true);
    }
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
    NR_DENTRY.this_add(-1);
    if let Some(prune) = r.d_op.and_then(|o| o.d_prune) {
        prune(r);
    }
    // Its inode's alias lock first; nothing else changes the inode of
    // a dentry with no reference left
    if let Some(i) = r.get_inode() {
        let mut al = i.i_dentry.lock();
        let mut dl = r.d_lock.write();
        // Linux dentry_unlink_inode: inside a d_seq write section
        let s = r.seq_write(&mut dl);
        let taken = r.take_inode(&mut dl);
        alias_del(&mut al, &dl, r);
        drop(s);
        drop(dl);
        drop(al);
        drop(taken);
        crate::io::inotify::d_iput(&i);
    }
    // The parent's reference is ours now; the pointer stays
    let parent = NonNull::new(r.parent_ptr().cast_mut());
    let p = d.as_ptr().cast_const().cast::<()>();
    if crate::sync::rcu::can_queue() {
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
    let n: i64 = NR_DENTRY
        .for_each_possible()
        .map(|(_, c)| c.load(core::sync::atomic::Ordering::Relaxed))
        .sum::<i64>()
        .max(0);
    alloc::vec![n, 0, 45, 0, 0, 0]
}

/// Drop `d` from `parent` if it is an unused leaf: in the tree and held
/// by nothing but the tree and the caller, nothing cached below, nothing
/// mounted on it, and negative if its filesystem keeps its positive
/// dentries (`keep`, Linux DCACHE_PERSISTENT); decided under the
/// parent's d_lock, where lookups take their references (Linux
/// dentry_kill from the LRU)
fn prune_one(parent: &DentryRef, d: &DentryRef, keep: bool) -> bool {
    let mut p = parent.d_lock.write();
    let mut di = d.d_lock.write();
    let unused = DentryRef::count(d) == TREE_REFS + 1
        && di.children.is_empty()
        && !d.flag(DCACHE_MOUNTED)
        && !(keep && !d.is_negative());
    if !unused {
        return false;
    }
    let Some(ours) = __d_drop(&mut p, d, &mut di) else {
        return false;
    };
    drop(di);
    drop(p);
    drop(ours);
    true
}

/// Take `d` out of the tree unless it left already (Linux d_drop): the
/// parent's d_lock, then its own, the parent read again if a rename
/// moved it meanwhile. The parent is borrowed under an RCU read guard
/// (Linux lock_parent), and the tree's references go with
/// [`DentryRef::put_held`] (the caller's own outlives them), so no
/// reference is taken or put last: callable under MOUNT_LOCK, as Linux
/// d_drop, which takes and puts none. Whether it was in the tree.
pub fn d_drop(d: &DentryRef) -> bool {
    let g = crate::sync::rcu::read_lock();
    loop {
        let Some(parent) = d.parent_rcu(&g) else {
            return false;
        };
        let mut p = parent.d_lock.write();
        let mut dl = d.d_lock.write();
        // Under both locks a parent `d` still names is the one `d`
        // holds a reference to: live
        if core::ptr::eq(d.parent_ptr(), parent) {
            let ours = __d_drop(&mut p, d, &mut dl);
            return ours.map(DentryRef::put_held).is_some();
        }
    }
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
        let ours = __d_drop(&mut p, &cur, &mut ci);
        drop(ci);
        drop(p);
        // A leaf another remover took out first (the shrinker, a move)
        // is not ours to drop: look again from the top, so no child is
        // left holding the subtree
        drop(ours);
    }
}

/// Take `d` itself out of the tree, unless it left already, then
/// what is mounted on it or below it, then everything cached below it
/// (Linux d_invalidate: a dentry its d_revalidate found stale; that
/// dentry, not whatever holds its name by now; find_submount and
/// detach_mounts for each mountpoint of the subtree). The parent's
/// d_lock, then `d`'s, as for every unhook; a rename between reading
/// the parent and locking it is seen under the locks and the parent
/// read again. The mounts go before the subtree is dropped (Linux
/// shrinks it first, which leaves a mountpoint, held by its
/// mountpoint, in the tree; `d_drop_tree` takes held ones out too).
/// May sleep (NAMESPACE_SEM).
pub fn d_invalidate(d: &DentryRef) {
    loop {
        let Some(parent) = d.get_parent() else {
            return;
        };
        let mut p = parent.d_lock.write();
        let mut dl = d.d_lock.write();
        if !core::ptr::eq(d.parent_ptr(), DentryRef::as_ptr(&parent)) {
            continue;
        }
        let ours = __d_drop(&mut p, d, &mut dl);
        drop(dl);
        drop(p);
        if ours.is_none() {
            return;
        }
        break;
    }
    if d.is_negative() {
        return;
    }
    // A mountpoint held only by covers detaches nothing: stop there
    while let Some(v) = find_submount(d) {
        if !super::mount::detach_mounts(&v) {
            break;
        }
    }
    d_drop_tree(d);
}

/// The first dentry at or below `top` that something is mounted on
/// (Linux d_walk with find_submount), depth first; walked again from
/// `top` if a rename raced the climb back up (Linux d_walk's
/// rename_lock retry), so the walk never leaves the subtree
fn find_submount(top: &DentryRef) -> Option<DentryRef> {
    'again: loop {
        let seq = rename_seq_begin();
        let mut cur = top.clone();
        loop {
            if cur.is_mountpoint() {
                return Some(cur);
            }
            if let Some(c) = first_child(&cur) {
                cur = c;
                continue;
            }
            // The next sibling of `cur` or of an ancestor below `top`
            loop {
                if DentryRef::ptr_eq(&cur, top) {
                    return None;
                }
                let parent = cur.get_parent()?;
                if rename_seq_retry(seq) {
                    continue 'again;
                }
                if let Some(n) = next_sibling(&parent, &cur) {
                    cur = n;
                    break;
                }
                cur = parent;
            }
        }
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
/// order, so a directory left empty goes too; positive ones stay if
/// `keep`
fn prune_tree(root: &DentryRef, budget: usize, keep: bool) -> usize {
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
            if prune_one(&parent, &cur, keep) {
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

/// The dcache shrinker (Linux prune_dcache_sb over every superblock,
/// super_cache_scan: one whose s_umount is busy is skipped): up to
/// `budget` unused dentries, negative ones included, leave the tree;
/// what they held (inodes not otherwise cached) goes with them. The
/// positive dentries of a filesystem whose entries live in the dcache
/// (ramfs, tmpfs: `SuperOps::d_persistent`, Linux d_make_persistent)
/// stay. Allocates nothing. Deviation: no LRU, so not oldest first.
/// The number dropped.
pub fn shrink_dcache(budget: usize) -> usize {
    let mut freed = 0;
    super::superblock::iterate_supers_trylock(|sb| {
        if freed < budget
            && let Some(root) = sb.get_root()
        {
            freed += prune_tree(&root, budget - freed, sb.s_op.d_persistent());
        }
    });
    freed
}

/// `p1` is an ancestor of `p2`: the child of `p1` on the way up from
/// `p2` (`p2` itself if it is a child of `p1`), else None (Linux
/// d_ancestor). Its caller holds RENAME_LOCK for writing, so no parent
/// changes during the walk.
fn d_ancestor<'g>(p1: &Dentry, p2: &'g Dentry, g: &'g RcuReadGuard) -> Option<&'g Dentry> {
    let mut p = p2;
    while let Some(up) = p.parent_rcu(g) {
        if core::ptr::eq(up, p1) {
            return Some(p);
        }
        p = up;
    }
    None
}

/// Move `d` to where `target` is (Linux __d_move), under RENAME_LOCK
/// held for writing (the caller's). The d_locks of both parents, an
/// ancestor first (`d_ancestor`: whoever else takes two of them takes
/// a parent before its child), then of `d`, then of `target`, all held
/// for the switch, inside both dentries' `d_seq` write sections, so an
/// RCU walk that read either one's parent or name repeats: both leave
/// their buckets, `d` takes `target`'s parent and name (and with
/// `exchange` `target` takes `d`'s), and the moved ones are hashed
/// again. Without `exchange` `target` stays out, unhashed. Nothing is
/// allocated: names move by copy or a shared reference (Linux
/// copy_name, swap_names), and no reference dropped under the locks is
/// the last (the caller holds both dentries, and this both parents).
fn __d_move(d: &DentryRef, target: &DentryRef, exchange: bool) {
    if DentryRef::ptr_eq(d, target) {
        return;
    }
    let Some(np) = target.get_parent() else {
        return;
    };
    let op = d.get_parent();
    let ancestor = op.as_ref().map(|o| {
        let g = crate::sync::rcu::read_lock();
        d_ancestor(o, target, &g).is_some()
    });
    // The new parent's guard, and the old one's when it is another
    let (mut npl, mut opl) = match (&op, ancestor) {
        (Some(o), Some(true)) if DentryRef::ptr_eq(o, &np) => (np.d_lock.write(), None),
        (Some(o), Some(true)) => {
            let ol = o.d_lock.write();
            (np.d_lock.write(), Some(ol))
        }
        (Some(o), _) => {
            let nl = np.d_lock.write();
            (nl, Some(o.d_lock.write()))
        }
        (None, _) => (np.d_lock.write(), None),
    };
    let mut dl = d.d_lock.write();
    let mut tl = target.d_lock.write();
    // Both names, whole under the d_locks
    let (dn, tn) = (target.name_locked(&tl), d.name_locked(&dl));
    let sd = d.seq_write(&mut dl);
    let st = target.seq_write(&mut tl);
    // Out of both buckets (Linux ___d_drop of each)
    let d_old = match (&op, &mut opl) {
        (Some(_), Some(ol)) => hash_out(ol, d),
        (Some(_), None) => hash_out(&mut npl, d),
        (None, _) => None,
    };
    let t_old = hash_out(&mut npl, target);
    d.set_parent(&dl, np.clone());
    d.d_name.store(dn.clone());
    if exchange && let Some(o) = &op {
        target.set_parent(&tl, o.clone());
        target.d_name.store(tn.clone());
        let ol = opl.as_mut().unwrap_or(&mut npl);
        hash_in(o, ol, target, &tn);
    }
    hash_in(&np, &mut npl, d, &dn);
    drop((st, sd));
    drop((tl, dl));
    drop((opl, npl));
    drop((d_old, t_old));
}

/// A rename moved `d` to where `target` is (Linux d_move): the target
/// (the replaced dentry, or a negative one the rename made up front,
/// so nothing allocates here) leaves the tree, and `d` takes its parent
/// and name; `d` keeps its identity, so whoever holds it (a cwd, an fd,
/// a mountpoint) follows it. Callers hold both parents' i_rwsem.
pub fn d_move(d: &DentryRef, target: &DentryRef) {
    let w = RENAME_LOCK.write();
    __d_move(d, target, false);
    drop(w);
    d_drop_tree(target);
}

/// RENAME_EXCHANGE swapped `a` and `b` (Linux d_exchange): each takes
/// the other's name and parent. Neither may be a root (Linux WARN_ON
/// IS_ROOT); if one is, nothing changes.
pub fn d_exchange(a: &DentryRef, b: &DentryRef) {
    let _w = RENAME_LOCK.write();
    if a.parent_ptr().is_null() || b.parent_ptr().is_null() {
        return;
    }
    __d_move(a, b, true);
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
        assert!(x.d_unhashed());
        drop(x);
        r.d_delete(b"a", 1);
        assert!(a.is_negative() && !a.d_unhashed());
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
        assert!(other.d_unhashed() && !other.is_negative());
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
        assert!(a.name().as_bytes() == long && t.d_unhashed());
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
        assert!(b.d_unhashed() && !b.is_negative());
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
        assert!(b.lookup_child(&long).is_some() && xa.d_unhashed());
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
        assert_eq!(prune_tree(&r, 100, false), 3);
        assert!(r.lookup_child(b"a").is_none());
        assert!(
            r.lookup_child(b"k")
                .is_some_and(|c| DentryRef::ptr_eq(&c, &k))
        );
    }

    /// On a filesystem that keeps its positive dentries only the
    /// negative ones go
    #[test]
    fn prune_keeps_persistent() {
        let r = crate::fs::DentryRef::new(Dentry::new_root(inode(), Weak::new())).unwrap();
        let a = Dentry::alloc(&r, b"a", Some(inode())).unwrap();
        for n in [b"x", b"y"] {
            Dentry::alloc(&a, n, None).unwrap();
        }
        drop(a);
        assert_eq!(prune_tree(&r, 100, true), 2);
        assert!(r.lookup_child(b"a").is_some_and(|a| a.num_children() == 0));
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

    /// An inode's aliases follow its dentries: a hashed one is found
    /// before one a delete left unhashed for its holder, and a killed
    /// one leaves the list
    #[test]
    fn aliases_follow_dentries() {
        let r = DentryRef::new(Dentry::new_root(inode(), Weak::new())).unwrap();
        let i = Inode::alloc(Inode::new(
            2,
            InodeMode::regular(0o644),
            0,
            0,
            0,
            Timespec::from_secs(0),
            Weak::new(),
            &NULL_INODE_OPS,
        ))
        .unwrap();
        let b = Dentry::alloc(&r, b"b", Some(i.clone())).unwrap();
        let a = Dentry::alloc(&r, b"a", Some(i.clone())).unwrap();
        assert!(d_find_any_alias(&i).is_some_and(|d| DentryRef::ptr_eq(&d, &a)));
        let holder = a.clone();
        r.d_delete(b"a", 1);
        assert!(a.d_unhashed() && !a.is_negative());
        assert!(d_find_alias(&i).is_some_and(|d| DentryRef::ptr_eq(&d, &b)));
        assert!(d_find_alias_by(&i, |d| DentryRef::ptr_eq(d, &a)).is_some());
        drop((a, holder));
        assert_eq!(i.i_dentry.lock().len(), 1);
        r.d_delete(b"b", 1);
        assert!(b.is_negative() && d_find_any_alias(&i).is_none());
    }

    /// Moves between a directory and one below it, both ways (the old
    /// parent an ancestor of the target, then the new parent an
    /// ancestor of the old: Linux __d_move's lock order cases) land the
    /// dentry under its new parent and name, and each move and drop
    /// moves the dentries' d_seq on (an RCU walk would repeat)
    #[test]
    fn move_nested_parents() {
        let r = DentryRef::new(Dentry::new_root(inode(), Weak::new())).unwrap();
        let b = Dentry::alloc(&r, b"b", Some(inode())).unwrap();
        let x = Dentry::alloc(&r, b"x", Some(inode())).unwrap();
        let s0 = x.d_seq.read_begin();
        let t = Dentry::prealloc(&b, b"y").unwrap();
        d_move(&x, &t);
        assert!(x.d_seq.read_retry(s0) && t.d_seq.read_retry(0));
        assert!(
            b.lookup_child(b"y")
                .is_some_and(|c| DentryRef::ptr_eq(&c, &x))
        );
        assert!(r.lookup_child(b"x").is_none());
        let t = Dentry::prealloc(&r, b"z").unwrap();
        d_move(&x, &t);
        assert!(
            r.lookup_child(b"z")
                .is_some_and(|c| DentryRef::ptr_eq(&c, &x))
        );
        assert!(b.lookup_child(b"y").is_none() && b.num_children() == 0);
        assert!(x.get_parent().is_some_and(|p| DentryRef::ptr_eq(&p, &r)));
        let s1 = x.d_seq.read_begin();
        assert!(r.remove_child(b"z").is_some());
        assert!(x.d_seq.read_retry(s1) && x.d_unhashed() && x.d_unlinked());
        // A root is unhashed but not unlinked (Linux d_unlinked)
        assert!(r.d_unhashed() && !r.d_unlinked());
    }

    /// `d_inode_rcu` borrows the dentry's inode with no reference and
    /// `get_inode` takes one from it (Linux igrab); once the dentry is
    /// made negative both see none
    #[test]
    fn d_inode_rcu_and_igrab() {
        let r = DentryRef::new(Dentry::new_root(inode(), Weak::new())).unwrap();
        let i = inode();
        let a = Dentry::alloc(&r, b"a", Some(i.clone())).unwrap();
        let n = Arc::strong_count(&i);
        {
            let g = crate::sync::rcu::read_lock();
            let b = a.d_inode_rcu(&g).unwrap();
            assert!(core::ptr::eq(b, Arc::as_ptr(&i)) && Arc::strong_count(&i) == n);
        }
        let got = a.get_inode().unwrap();
        assert!(Arc::ptr_eq(&got, &i) && Arc::strong_count(&i) == n + 1);
        drop(got);
        let s = a.d_seq.read_begin();
        drop(a);
        r.d_delete(b"a", 0);
        let c = r.lookup_child(b"a").unwrap();
        assert!(c.is_negative() && c.get_inode().is_none() && c.d_seq.read_retry(s));
        assert_eq!(Arc::strong_count(&i), n - 1);
    }

    /// The RCU walk's lookup takes no reference: it finds a child (long
    /// names too) with a `d_seq` value that holds until a move or drop,
    /// misses an unhashed one, and the reference taken after it is
    /// counted (Linux __d_lookup_rcu, legitimize_path)
    #[test]
    fn lookup_rcu_seq() {
        let r = DentryRef::new(Dentry::new_root(inode(), Weak::new())).unwrap();
        let a = Dentry::alloc(&r, b"a", Some(inode())).unwrap();
        let long = [b'l'; 90];
        let l = Dentry::alloc(&r, &long, Some(inode())).unwrap();
        let n = DentryRef::count(&a);
        let g = crate::sync::rcu::read_lock();
        let (c, seq) = __d_lookup_rcu(&r, b"a", &g).unwrap();
        assert!(core::ptr::eq(c, DentryRef::as_ptr(&a)) && !c.d_seq_retry(seq));
        assert!(c.d_inode_rcu(&g).is_some() && DentryRef::count(&a) == n);
        assert!(__d_lookup_rcu(&r, &long, &g).is_some_and(|(c, _)| core::ptr::eq(c, &*l)));
        assert!(__d_lookup_rcu(&r, b"b", &g).is_none());
        let got = DentryRef::try_get(c).filter(|_| !c.d_seq_retry(seq));
        drop(g);
        assert!(got.is_some_and(|d| DentryRef::ptr_eq(&d, &a)));
        let t = Dentry::prealloc(&r, b"b").unwrap();
        d_move(&a, &t);
        assert!(a.d_seq_retry(seq) && a.d_seq_begin() != seq);
        let g = crate::sync::rcu::read_lock();
        assert!(__d_lookup_rcu(&r, b"a", &g).is_none());
        assert!(__d_lookup_rcu(&r, b"b", &g).is_some_and(|(c, _)| core::ptr::eq(c, &*a)));
        drop(g);
        r.remove_child(b"b");
        let g = crate::sync::rcu::read_lock();
        assert!(__d_lookup_rcu(&r, b"b", &g).is_none());
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

    /// A lookup holds no d_lock of the parent (Linux d_lookup): it runs
    /// while the parent's is held for writing, takes its reference
    /// under the child's, and skips an unhashed child
    #[test]
    fn lookup_without_parent_lock() {
        let r = DentryRef::new(Dentry::new_root(inode(), Weak::new())).unwrap();
        let a = Dentry::alloc(&r, b"a", Some(inode())).unwrap();
        let w = r.d_lock.write();
        let found = r.lookup_child(b"a").unwrap();
        assert!(DentryRef::ptr_eq(&found, &a));
        drop(w);
        assert_eq!(DentryRef::count(&a), TREE_REFS + 2);
        let s = a.d_seq.read_begin();
        drop(r.remove_child(b"a"));
        assert!(r.lookup_child(b"a").is_none() && a.d_unhashed() && a.d_seq.read_retry(s));
    }
}
