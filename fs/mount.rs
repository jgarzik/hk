//! Mount - filesystem mount infrastructure
//!
//! Manages the mount tree that connects filesystems into a unified namespace.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use crate::sync::spin::RwLock;
use crate::sync::{LockedByEither, RwSem, RwSemReadGuard, RwSemWriteGuard, SeqLock, UniqueOwner};
use crate::util::list::{Link, OwnedList, Owner};
use ::core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::KernelError;
use super::dentry::Dentry;
use super::inode::FileType;
pub use super::mntput::MountRef;
use super::mntput::{
    __cleanup_mnt, MNT_NS_INTERNAL, MntOwned, MntPcp, alloc_pcp, alloc_pcp_nofail,
};
use super::path_ref::Path;
use super::superblock::{FileSystemType, SuperBlock};
use crate::task::task_work::CallbackHead;
use crate::util::ida::Ida;
use crate::util::kalloc::{arc_nofail, try_arc};
use alloc::boxed::Box;
use core::sync::atomic::AtomicBool;

use crate::block::get_blkdev;

/// Ignore set-user/group-ID bits on exec (Linux MNT_NOSUID)
pub const MNT_NOSUID: u32 = 0x1;
/// No access to device nodes (Linux MNT_NODEV)
pub const MNT_NODEV: u32 = 0x2;
/// No program execution (Linux MNT_NOEXEC)
pub const MNT_NOEXEC: u32 = 0x4;
/// No atime updates (Linux MNT_NOATIME)
pub const MNT_NOATIME: u32 = 0x8;
/// No atime updates on directories (Linux MNT_NODIRATIME)
pub const MNT_NODIRATIME: u32 = 0x10;
/// atime updated only when older than mtime/ctime or a day (Linux
/// MNT_RELATIME, the default)
pub const MNT_RELATIME: u32 = 0x20;
/// The atime flags (Linux MNT_ATIME_MASK)
pub const MNT_ATIME_MASK: u32 = MNT_NOATIME | MNT_NODIRATIME | MNT_RELATIME;
/// This mount is read-only, whatever its superblock (Linux MNT_READONLY)
pub const MNT_READONLY: u32 = 0x40;
/// Symlinks on this mount are not followed (Linux MNT_NOSYMFOLLOW)
pub const MNT_NOSYMFOLLOW: u32 = 0x80;
/// Cannot be bind-mounted (Linux T_UNBINDABLE, in `t_flags`)
pub const T_UNBINDABLE: u32 = 0x1;
/// Cannot be unmounted, moved or pivoted away (Linux MNT_LOCKED: a mount
/// a less privileged namespace copied, which would uncover what is
/// under it; the initial root is protected by having no parent)
pub const MNT_LOCKED: u32 = 0x80_0000;

/// What [`MOUNT_LOCK`] owns: the mount tree's links, with
/// NAMESPACE_SEM ([`NsTree`]); `&MntHash` (a locking read) holds them
/// still
pub struct MntHash(());

// SAFETY: one value, built here for MOUNT_LOCK alone (private field)
// and reachable only through its guards
unsafe impl UniqueOwner for MntHash {}

/// Every write of a mount's `mnt_flags` and every change of the mount
/// tree's links (Linux mount_lock, lock_mount_hash: a seqlock whose
/// sequence lockless readers may check; read_seqlock_excl is
/// `read_excl`); under NAMESPACE_SEM, s_umount and (d_path's locking
/// read) RENAME_LOCK, above nothing but leaves
pub static MOUNT_LOCK: SeqLock<MntHash> = SeqLock::new(MntHash(()));

/// Old mount -> its copy, from [`Mount::clone_tree`]
pub type MountMap = Vec<(MountRef, MountRef)>;

/// What NAMESPACE_SEM owns: the mount tree's links (each mount's
/// `mnt_mounts`), changed with MOUNT_LOCK also held; `&NsTree`
/// (either side held) holds them still
pub struct NsTree(());

// SAFETY: one value, built here for NAMESPACE_SEM alone (private
// field) and reachable only through its guards
unsafe impl UniqueOwner for NsTree {}

/// Mount topology changes: attach, umount, namespace copy, pivot_root;
/// /proc mount lists and is_local_mountpoint read under it (Linux
/// namespace_sem, a sleeping rw_semaphore). Outside it: the
/// mountpoint's i_rwsem; inside it: s_umount, then MOUNT_LOCK and the
/// spinning Mount fields.
static NAMESPACE_SEM: RwSem<NsTree> = RwSem::new(NsTree(()));

/// NAMESPACE_SEM held shared
pub type NsRead = RwSemReadGuard<'static, NsTree>;
/// NAMESPACE_SEM held exclusive
pub type NsWrite = RwSemWriteGuard<'static, NsTree>;

/// Take NAMESPACE_SEM for a topology change (Linux namespace_lock)
pub fn namespace_lock() -> NsWrite {
    NAMESPACE_SEM.write()
}

/// Take NAMESPACE_SEM to read the mount tree (Linux
/// down_read(&namespace_sem))
pub fn namespace_read() -> NsRead {
    NAMESPACE_SEM.read()
}

/// A held lock under which no mount's `mnt_mounts` changes:
/// NAMESPACE_SEM ([`NsTree`], either side) or MOUNT_LOCK ([`MntHash`])
pub trait Stable {
    /// `m`'s submounts
    fn mounts<'a>(&'a self, m: &'a Mount) -> &'a OwnedList<MntChild>;
}

impl Stable for NsTree {
    fn mounts<'a>(&'a self, m: &'a Mount) -> &'a OwnedList<MntChild> {
        m.mnt_mounts.access_a(self)
    }
}

impl Stable for MntHash {
    fn mounts<'a>(&'a self, m: &'a Mount) -> &'a OwnedList<MntChild> {
        m.mnt_mounts.access_b(self)
    }
}

crate::owned_adapter!(pub MntChild, Mount, mnt_child, mnt_child_owner);

/// Mount ids: the lowest free one, from 0 (Linux mnt_id_ida, now an
/// XA_FLAGS_ALLOC xarray: the kernel's tmpfs gets 0, the nullfs root
/// 1); allocated outside every lock, freed in any context (a mount's
/// drop)
static MNT_IDS: Ida = Ida::new();

/// Never-reused mount ids start above this (Linux MNT_UNIQUE_ID_OFFSET,
/// 2^31 since 6.11), clear of the reused 32-bit ones
const MNT_UNIQUE_ID_OFFSET: u64 = 1 << 31;

/// The next never-reused mount id (Linux mnt_id_ctr + 1)
static MNT_ID_UNIQUE: AtomicU64 = AtomicU64::new(MNT_UNIQUE_ID_OFFSET + 1);

/// A mount point in the namespace (Linux struct mount / vfsmount)
///
/// Held through [`MountRef`] (a per-CPU count, Linux mnt_pcp, exact
/// once out of its namespace); the last reference's teardown
/// (`cleanup`) is deferred (`fs::mntput`), so a reference may be dropped
/// under any lock but MOUNT_LOCK. Its users (`users`: open
/// files, a task's root and cwd) make it busy for umount.
pub struct Mount {
    /// The mounted filesystem's superblock (Linux mnt_sb)
    pub sb: MntOwned<Arc<SuperBlock>>,

    /// Root dentry of the mounted filesystem (Linux mnt_root)
    pub root: MntOwned<Arc<Dentry>>,

    /// The dentry where this filesystem is mounted (mount point)
    /// None for the root mount
    pub mountpoint: RwLock<Option<Arc<Dentry>>>,

    /// Parent mount (None for root)
    pub parent: RwLock<Option<Weak<Mount>>>,

    /// Submounts, each holding a reference (Linux mnt_mounts): changed
    /// under NAMESPACE_SEM write and MOUNT_LOCK, read under either
    mnt_mounts: LockedByEither<OwnedList<MntChild>, NsTree, MntHash>,
    /// On the parent's `mnt_mounts` (Linux mnt_child)
    mnt_child: Link,
    mnt_child_owner: Owner,

    /// Per-mount MNT_* flags (Linux mnt_flags): MNT_NOSUID, MNT_NODEV,
    /// MNT_NOEXEC
    mnt_flags: AtomicU32,

    /// Peer group, 0 if not shared (Linux mnt_group_id; fs/pnode.rs)
    pub(super) group: AtomicU32,
    /// Topology flags (Linux mnt_t_flags: T_UNBINDABLE), written only
    /// under NAMESPACE_SEM write, read lock-free
    t_flags: AtomicU32,
    /// Group this mount is a slave of, 0 if none (Linux mnt_master)
    pub(super) master: AtomicU32,
    /// Id of the mount namespace this mount is in, 0 if none (Linux
    /// mnt_ns): written only under NAMESPACE_SEM write (commit_tree,
    /// namespace root and copy, umount), read under NAMESPACE_SEM
    mnt_ns: AtomicU64,

    /// Marked by a first umount2(MNT_EXPIRE) (Linux mnt_expiry_mark)
    expiry: core::sync::atomic::AtomicBool,

    /// Holders of write access through this mount and the WRITE_HOLD bit
    /// (Linux mnt_writers and WRITE_HOLD): see superblock::get_write
    writers: AtomicU64,

    /// Id in /proc/<pid>/mountinfo and statx (Linux mnt_id): reused
    pub mnt_id: u32,
    /// Id never reused (Linux mnt_id_unique, STATX_MNT_ID_UNIQUE)
    pub mnt_id_unique: u64,
    /// What was mounted: the source argument, or the fs type for
    /// mounts made by the kernel (Linux mnt_devname)
    pub devname: super::name::FileName,

    /// Its references' count, per CPU ([`MountRef`], Linux mnt_pcp's
    /// mnt_count)
    pub(super) mnt_pcp: Box<[MntPcp]>,
    /// Its last reference went (Linux MNT_DOOMED): set under MOUNT_LOCK
    /// write by that put
    pub(super) doomed: AtomicBool,

    /// The deferred teardown's head (Linux mnt_rcu as task_work, or
    /// mnt_llist on delayed_mntput_list)
    pub(super) mnt_task_work: CallbackHead,

    /// On its superblock's `s_mounts` (Linux mnt_instance)
    pub(super) mnt_instance: crate::util::list::Link,
}

impl Mount {
    /// A new mount, its first reference, or ENOMEM (Linux alloc_vfsmnt)
    pub fn alloc(
        sb: Arc<SuperBlock>,
        root: Arc<Dentry>,
        flags: u32,
        devname: super::name::FileName,
    ) -> Result<MountRef, KernelError> {
        let pcp = alloc_pcp()?;
        let m = try_arc(Self::init(
            sb,
            root,
            flags,
            devname,
            pcp,
            MNT_IDS.try_alloc()?,
        ))?;
        m.sb.add_mount(&m);
        Ok(MountRef::first(m))
    }

    /// [`Mount::alloc`] for a tree copy, which cannot unwind a partial
    /// copy (its peer groups and attachments) on failure
    fn alloc_nofail(
        sb: Arc<SuperBlock>,
        root: Arc<Dentry>,
        flags: u32,
        devname: super::name::FileName,
    ) -> MountRef {
        let pcp = alloc_pcp_nofail();
        let m = arc_nofail(Self::init(sb, root, flags, devname, pcp, MNT_IDS.alloc()));
        m.sb.add_mount(&m);
        MountRef::first(m)
    }

    /// A mount with id `mnt_id`, which its drop gives back
    fn init(
        sb: Arc<SuperBlock>,
        root: Arc<Dentry>,
        flags: u32,
        devname: super::name::FileName,
        mnt_pcp: Box<[MntPcp]>,
        mnt_id: u32,
    ) -> Self {
        Self {
            sb: MntOwned::new(sb),
            root: MntOwned::new(root),
            mountpoint: RwLock::new(None),
            parent: RwLock::new(None),
            mnt_mounts: LockedByEither::new(OwnedList::new()),
            mnt_child: Link::new(),
            mnt_child_owner: Owner::new(),
            mnt_flags: AtomicU32::new(flags),
            writers: AtomicU64::new(0),
            expiry: core::sync::atomic::AtomicBool::new(false),
            group: AtomicU32::new(0),
            t_flags: AtomicU32::new(0),
            master: AtomicU32::new(0),
            mnt_ns: AtomicU64::new(0),
            mnt_id,
            mnt_id_unique: MNT_ID_UNIQUE.fetch_add(1, Ordering::Relaxed),
            devname,
            mnt_pcp,
            doomed: AtomicBool::new(false),
            mnt_task_work: CallbackHead::new(__cleanup_mnt),
            mnt_instance: crate::util::list::Link::new(),
        }
    }

    /// A copy of `self` for a namespace copy into namespace `ns`: same
    /// filesystem, root, flags and source, new ids, not attached
    fn copy(&self, ns: u64) -> MountRef {
        let c = Self::alloc_nofail(
            self.sb.clone(),
            self.root.clone(),
            self.flags(),
            self.devname.clone(),
        );
        c.inherit_t_flags(self);
        c.set_ns(ns);
        // A namespace copy keeps peerage (Linux copy_mnt_ns: CL_COPY_ALL)
        super::pnode::clone_prop(self, &c);
        c
    }

    /// Id of the mount namespace this mount is in, 0 if none; stable
    /// under NAMESPACE_SEM
    pub(super) fn ns(&self) -> u64 {
        self.mnt_ns.load(Ordering::Relaxed)
    }

    /// A kernel mount, in no namespace of its own (Linux kern_mount's
    /// MNT_NS_INTERNAL): its references take the fast path, and it is
    /// never taken out; set before the mount is shared
    pub(super) fn set_internal(&self) {
        self.mnt_ns.store(MNT_NS_INTERNAL, Ordering::Relaxed);
    }

    /// Put it in namespace `ns` (0: none); under NAMESPACE_SEM write
    fn set_ns(&self, ns: u64) {
        self.mnt_ns.store(ns, Ordering::Relaxed);
    }

    /// MNT_* flags
    pub fn flags(&self) -> u32 {
        self.mnt_flags.load(Ordering::Relaxed)
    }

    /// Replace the MNT_* flags (mount, remount): turning MNT_READONLY on
    /// is EBUSY, nothing changed, while anyone holds write access
    /// through the mount (Linux mnt_make_readonly)
    pub fn set_flags(&self, f: u32) -> Result<(), KernelError> {
        let _ml = MOUNT_LOCK.write();
        // Lock state is not the caller's to set here
        let f = (f & !MNT_LOCKED) | (self.flags() & MNT_LOCKED);
        // Linux mnt_make_readonly: writers held off; read-only only if
        // none holds access, set before the hold is released
        if f & MNT_READONLY != 0 && self.flags() & MNT_READONLY == 0 {
            let free = self.hold_writers();
            if free {
                self.mnt_flags.store(f, Ordering::SeqCst);
            }
            self.unhold_writers();
            return if free { Ok(()) } else { Err(KernelError::Busy) };
        }
        self.mnt_flags.store(f, Ordering::SeqCst);
        Ok(())
    }

    /// Linux mnt_hold_writers, under MOUNT_LOCK
    pub(super) fn hold_writers(&self) -> bool {
        super::superblock::hold_writers(&self.writers)
    }

    /// Linux mnt_unhold_writers, under MOUNT_LOCK
    pub(super) fn unhold_writers(&self) {
        super::superblock::unhold_writers(&self.writers)
    }

    /// Set (`on`) or clear MNT_* bits that need no other checks, under
    /// MOUNT_LOCK as every mnt_flags write
    pub fn mark(&self, bits: u32, on: bool) {
        let _ml = MOUNT_LOCK.write();
        if on {
            self.mnt_flags.fetch_or(bits, Ordering::SeqCst);
        } else {
            self.mnt_flags.fetch_and(!bits, Ordering::SeqCst);
        }
    }

    /// Cannot be bind-mounted (Linux IS_MNT_UNBINDABLE)
    pub fn is_unbindable(&self) -> bool {
        self.t_flags.load(Ordering::Acquire) & T_UNBINDABLE != 0
    }

    /// A new copy of `old` stays unbindable if `old` is (Linux clone_mnt:
    /// `mnt_t_flags = old->mnt_t_flags & T_UNBINDABLE`); not yet visible
    fn inherit_t_flags(&self, old: &Mount) {
        let t = old.t_flags.load(Ordering::Acquire) & T_UNBINDABLE;
        self.t_flags.store(t, Ordering::Release);
    }

    /// Make it (un)bindable; the caller holds NAMESPACE_SEM write (Linux
    /// change_mnt_propagation, EXCL[namespace_sem])
    pub(super) fn set_unbindable(&self, on: bool) {
        if on {
            self.t_flags.fetch_or(T_UNBINDABLE, Ordering::Release);
        } else {
            self.t_flags.fetch_and(!T_UNBINDABLE, Ordering::Release);
        }
    }

    /// This mount or its superblock is read-only (Linux
    /// __mnt_is_readonly)
    pub fn is_readonly(&self) -> bool {
        self.flags() & MNT_READONLY != 0 || self.sb.rdonly()
    }

    /// Release what want_write took
    pub(super) fn put_write(&self) {
        self.writers.fetch_sub(1, Ordering::SeqCst);
    }

    /// A use of the mount ended (Linux mntput): an MNT_EXPIRE mark
    /// goes; read first, so the common case writes nothing
    pub fn clear_expiry(&self) {
        if self.expiry.load(Ordering::Relaxed) {
            self.expiry.store(false, Ordering::Relaxed);
        }
    }

    /// Get the mount point dentry
    pub fn get_mountpoint(&self) -> Option<Arc<Dentry>> {
        self.mountpoint.read().clone()
    }

    /// Set the mount point
    pub fn set_mountpoint(&self, dentry: Arc<Dentry>) {
        note_mp(&dentry, 1);
        *self.mountpoint.write() = Some(dentry);
    }

    /// The parent mount, unless it is gone (Linux mnt_parent: a
    /// lazily unmounted parent's teardown may be queued)
    pub fn get_parent(&self) -> Option<MountRef> {
        // Out of the field lock first: a refused fast path takes
        // MOUNT_LOCK, which nests outside the Mount fields
        let w = self.parent.read().clone()?;
        MountRef::try_get(&w)
    }

    /// The parent mount and the mountpoint in it, borrowed from a
    /// locking read of MOUNT_LOCK (Linux mnt_parent, mnt_mountpoint
    /// under mount_lock): no reference taken. None for a mount on no
    /// parent.
    pub fn up<'a>(&'a self, _ml: &'a MntHash) -> Option<(&'a Mount, &'a Dentry)> {
        let parent = self.parent.read().as_ref().map(Weak::as_ptr)?;
        let mp = self.mountpoint.read().as_ref().map(Arc::as_ptr)?;
        // SAFETY: both links change only under MOUNT_LOCK write
        // (attach_mnt, detach_mnt, a teardown's unhang_children; the
        // last takes the mountpoint after the unlock, but only once the
        // parent link, read first, is gone for good), so they stay
        // while `_ml` is held and `self` lives. The mountpoint is kept by
        // `self.mountpoint`. The parent's memory is kept by a counted
        // reference, or once those are gone by its queued teardown's
        // `Arc`, which cannot finish (nor release its root) before
        // unhanging `self`, under MOUNT_LOCK write.
        Some(unsafe { (&*parent, &*mp) })
    }

    /// Set parent mount
    pub fn set_parent(&self, parent: &MountRef) {
        *self.parent.write() = Some(MountRef::downgrade(parent));
    }

    /// `self`'s submounts, under a lock that holds them still
    pub fn kids<'a>(&'a self, s: &'a impl Stable) -> Kids<'a> {
        let list = s.mounts(self);
        Kids {
            list,
            next: entry(list.front()),
        }
    }

    /// Something is mounted on this mount
    pub fn has_children(&self, s: &impl Stable) -> bool {
        !s.mounts(self).is_empty()
    }

    /// Deep clone a mount tree for a new namespace
    ///
    /// Creates a copy of the entire mount tree rooted at this mount.
    /// Each mount in the new tree references the same superblock/dentry
    /// as the original (the filesystem data is shared), but the mount
    /// structures themselves are independent (Linux copy_mnt_ns'
    /// copy_tree with CL_COPY_ALL).
    ///
    /// This is used by CLONE_NEWNS to give a new mount namespace its
    /// own view of the mount hierarchy.
    pub fn clone_tree(root: &MountRef, ns: u64) -> (MountRef, MountMap) {
        let mut g = namespace_lock();
        let new_root = root.copy(ns);
        let mut map = alloc::vec![(root.clone(), new_root.clone())];
        copy_below(&mut g, root, &new_root, |o| {
            let c = o.copy(ns);
            map.push((o.clone(), c.clone()));
            c
        });
        (new_root, map)
    }
}

/// A mount's submounts in order, each a new reference (Linux
/// list_for_each_entry over mnt_mounts); borrows the lock that holds
/// the list still
pub struct Kids<'a> {
    list: &'a OwnedList<MntChild>,
    next: Option<MountRef>,
}

impl Iterator for Kids<'_> {
    type Item = MountRef;
    fn next(&mut self) -> Option<MountRef> {
        let c = self.next.take()?;
        self.next = entry(self.list.next(&c));
        Some(c)
    }
}

/// A reference to a submount taken from its parent's `mnt_mounts`,
/// whose lock the caller holds: each entry there is counted
/// (`attach_mnt`)
fn entry(c: Option<Arc<Mount>>) -> Option<MountRef> {
    c.as_deref().map(MountRef::entry_ref)
}

/// The mount after `p` in a walk of the tree at `root`, parents first
/// (Linux next_mnt: the first submount, else the next sibling of the
/// nearest mount up to `root` that has one; no stack)
pub fn next_mnt(p: &MountRef, root: &Mount, s: &impl Stable) -> Option<MountRef> {
    if let Some(c) = entry(s.mounts(p).front()) {
        return Some(c);
    }
    let mut p = p.clone();
    while !core::ptr::eq(MountRef::as_ptr(&p), root) {
        let parent = p.get_parent()?;
        if let Some(n) = entry(s.mounts(&parent).next(&p)) {
            return Some(n);
        }
        p = parent;
    }
    None
}

/// `root` and every mount below it, parents first, by [`next_mnt`]
pub fn walk<'a, S: Stable>(root: &'a MountRef, s: &'a S) -> Walk<'a, S> {
    Walk {
        root,
        s,
        next: Some(root.clone()),
    }
}

/// Iterator of [`walk`]
pub struct Walk<'a, S: Stable> {
    root: &'a MountRef,
    s: &'a S,
    next: Option<MountRef>,
}

impl<S: Stable> Iterator for Walk<'_, S> {
    type Item = MountRef;
    fn next(&mut self) -> Option<MountRef> {
        let c = self.next.take()?;
        self.next = next_mnt(&c, self.root, self.s);
        Some(c)
    }
}

/// Copies of the mounts below `src` hung on `top`, a copy of `src`, at
/// the same places and in the same shape (Linux copy_tree's next_mnt
/// walk, its source and copy cursors climbing together); `copy` makes
/// each one. Under NAMESPACE_SEM write.
pub(super) fn copy_below(
    ns: &mut NsTree,
    src: &MountRef,
    top: &MountRef,
    mut copy: impl FnMut(&MountRef) -> MountRef,
) {
    let (mut p, mut q) = (src.clone(), top.clone());
    let mut next = next_mnt(src, src, &*ns);
    while let Some(s) = next {
        // An attached mount has both, set together under MOUNT_LOCK
        let sp = s.get_parent().expect("mount: submount without a parent");
        let mp = s
            .get_mountpoint()
            .expect("mount: submount without a mountpoint");
        while !MountRef::ptr_eq(&p, &sp) {
            let (Some(pp), Some(qp)) = (p.get_parent(), q.get_parent()) else {
                unreachable!("mount: copy cursor climbed past the top");
            };
            (p, q) = (pp, qp);
        }
        let c = copy(&s);
        attach_mnt(ns, c.clone(), &Path::new(q.clone(), mp));
        (p, q) = (s, c);
        next = next_mnt(&p, src, &*ns);
    }
}

/// The kernel threads' nullfs mount (Linux knullfs, an internal mount)
static KNULLFS: spin::Once<MountRef> = spin::Once::new();

/// The initial mount tree (Linux init_mount_tree, 7.0+): a nullfs mount
/// (id 1) is the namespace root and the mutable rootfs, a tmpfs under
/// the type name "rootfs" (id 2), is mounted on it. Root and cwd go to the rootfs, so it can be
/// pivoted away or unmounted like any other mount. Then the private
/// nullfs kernel threads start in (id 3, Linux 7.3 knullfs). Returns
/// the rootfs.
pub fn init_mount_tree() -> Result<MountRef, KernelError> {
    let nullfs = &super::nullfs::NULLFS_TYPE;
    let null = attach(
        (nullfs.mount)(nullfs, b"")?,
        None,
        0,
        false,
        b"nullfs".as_slice().into(),
    )?;
    let rootfs_type = &super::ramfs::tmpfs::ROOTFS_TYPE;
    let sb = (rootfs_type.mount)(rootfs_type, b"")?;
    let on = Path::new(null.clone(), null.root.clone());
    let rootfs = attach(sb, Some(on), 0, false, b"rootfs".as_slice().into())?;
    let ksb = (nullfs.mount)(nullfs, b"")?;
    let root = ksb.get_root().ok_or(KernelError::InvalidArgument)?;
    let k = Mount::alloc(ksb, root, MNT_READONLY, b"nullfs".as_slice().into())?;
    k.set_internal();
    super::fsstruct::kthread_fs_init(k.clone());
    KNULLFS.call_once(|| k);
    Ok(rootfs)
}

/// Mount `sb` on `mountpoint` (None: as the namespace root) with MNT_*
/// flags `mnt_flags` and read-only state `ro`, which are set before the
/// mount becomes visible (Linux do_new_mount: no window with weaker
/// flags). The new mount is a child of the mount the mountpoint is in.
pub fn attach(
    sb: Arc<SuperBlock>,
    mountpoint: Option<Path>,
    mnt_flags: u32,
    ro: bool,
    devname: super::name::FileName,
) -> Result<MountRef, KernelError> {
    let root = sb.get_root().ok_or(KernelError::InvalidArgument)?;
    if ro {
        sb.make_rdonly()?;
    }
    let mount = Mount::alloc(sb, root, mnt_flags, devname)?;
    let mnt_ns = crate::ns::current_mnt_ns();
    if let Some(mp) = mountpoint {
        // Under the mountpoint's i_rwsem (Linux lock_mount), which rmdir
        // and a rename replacing it hold: a directory removed meanwhile
        // is refused, one being removed sees this mount (EBUSY)
        let dir = mp.dentry.get_inode().ok_or(KernelError::NotFound)?;
        let _dir_lock = dir.lock();
        if dir.is_dead() {
            return Err(KernelError::NotFound);
        }
        let mut ns = namespace_lock();
        // Linux do_add_mount
        if !check_mnt(&mp.mnt) {
            return Err(KernelError::InvalidArgument);
        }
        graft(&mut ns, mount.clone(), &mp);
        drop(ns);
        drop(_dir_lock);
    } else {
        let _ns = namespace_lock();
        mount.set_ns(mnt_ns.id);
        mnt_ns.set_root(mount.clone());
    }
    Ok(mount)
}

/// `m` is in the caller's mount namespace (Linux check_mnt); under
/// NAMESPACE_SEM, or an optimistic early check as Linux's
pub fn check_mnt(m: &Mount) -> bool {
    m.ns() == crate::ns::current_mnt_ns().id
}

/// The tree at `m`, just hung on its parent, joins the parent's
/// namespace (Linux commit_tree); under NAMESPACE_SEM write
pub(super) fn commit_tree(ns: &NsTree, m: &MountRef) {
    let id = m.get_parent().map_or(0, |p| p.ns());
    for t in walk(m, ns) {
        t.set_ns(id);
    }
}

/// A new mount of `m`'s filesystem rooted at `root`, with its flags
/// and source (Linux clone_mnt); not attached
pub fn clone_mnt(m: &Mount, root: Arc<Dentry>) -> MountRef {
    let c = Mount::alloc_nofail(
        m.sb.clone(),
        root,
        m.flags() & !MNT_LOCKED,
        m.devname.clone(),
    );
    c.inherit_t_flags(m);
    c
}

/// One mount [`copy_tree`] copies: its source, the entry of the copy
/// it hangs on, and where (the copy's root for the top)
struct CopyEnt {
    src: MountRef,
    parent: usize,
    at: Arc<Dentry>,
}

/// What copy_tree copies of `m` at `root`, parents first: the mounts
/// below `root`; an unbindable submount is left out with whatever is
/// under it, EPERM if it is also locked (it hides what is under it)
fn copy_plan(ns: &NsTree, m: &MountRef, root: &Arc<Dentry>) -> Result<Vec<CopyEnt>, KernelError> {
    let mut plan = alloc::vec![CopyEnt {
        src: m.clone(),
        parent: 0,
        at: root.clone(),
    }];
    let mut i = 0;
    while i < plan.len() {
        let src = plan[i].src.clone();
        for c in src.kids(ns) {
            let Some(mp) = c.get_mountpoint() else {
                continue;
            };
            if i == 0 && !super::is_subdir(&mp, root) {
                continue;
            }
            if c.is_unbindable() {
                if c.flags() & MNT_LOCKED != 0 {
                    return Err(KernelError::NotPermitted);
                }
                continue;
            }
            plan.push(CopyEnt {
                src: c,
                parent: i,
                at: mp,
            });
        }
        i += 1;
    }
    Ok(plan)
}

/// The copies of `plan` (Linux copy_tree): the top loses MNT_LOCKED
/// (clone_mnt), a submount keeps it (it still hides what is under
/// it); under NAMESPACE_SEM write
fn copy_tree(ns: &mut NsTree, plan: &[CopyEnt]) -> MountRef {
    let mut out: Vec<MountRef> = Vec::new();
    for (k, e) in plan.iter().enumerate() {
        let root = if k == 0 { &e.at } else { &e.src.root };
        let n = clone_mnt(&e.src, root.clone());
        super::pnode::clone_prop(&e.src, &n);
        if k > 0 {
            if e.src.flags() & MNT_LOCKED != 0 {
                n.mark(MNT_LOCKED, true);
            }
            attach_mnt(
                ns,
                n.clone(),
                &Path::new(out[e.parent].clone(), e.at.clone()),
            );
        }
        out.push(n);
    }
    out.swap_remove(0)
}

/// A mount under `d` in `m` is locked (Linux has_locked_children): a
/// bind of `d` alone would uncover what it hides
fn has_locked_children(ns: &NsTree, m: &Mount, d: &Arc<Dentry>) -> bool {
    m.kids(ns).any(|c| {
        c.get_mountpoint()
            .is_some_and(|mp| super::is_subdir(&mp, d))
            && c.flags() & MNT_LOCKED != 0
    })
}

/// Bind `old` (with its submounts if `rec`) on `mp` (Linux do_loopback,
/// __do_loopback and graft_tree), in Linux's order: the target must be
/// in the caller's namespace, the source bindable and in it too
/// (EINVAL), a lone bind must not uncover a locked submount (EINVAL),
/// a recursive one not leave out a locked unbindable one (EPERM); a
/// directory goes only on a directory and a file on a file (ENOTDIR)
pub fn do_loopback(old: &Path, mp: &Path, rec: bool) -> Result<(), KernelError> {
    let _l = lock_mountpoint(mp)?;
    let mut ns = namespace_lock();
    if !check_mnt(&mp.mnt) || old.mnt.is_unbindable() || !check_mnt(&old.mnt) {
        return Err(KernelError::InvalidArgument);
    }
    if !rec && has_locked_children(&ns, &old.mnt, &old.dentry) {
        return Err(KernelError::InvalidArgument);
    }
    let plan = if rec {
        copy_plan(&ns, &old.mnt, &old.dentry)?
    } else {
        alloc::vec![CopyEnt {
            src: old.mnt.clone(),
            parent: 0,
            at: old.dentry.clone(),
        }]
    };
    let is_dir = |d: &Dentry| d.get_inode().is_some_and(|i| i.mode().is_dir());
    if is_dir(&mp.dentry) != is_dir(&old.dentry) {
        return Err(KernelError::NotDirectory);
    }
    let t = copy_tree(&mut ns, &plan);
    graft(&mut ns, t, mp);
    Ok(())
}

/// Superblock of a device-backed filesystem (vfat, ...) on the block
/// device at `source` (e.g. "/dev/rd1"); mount it with `attach`
pub fn dev_super(
    fs_type: &'static FileSystemType,
    source: &[u8],
    opts: &[u8],
) -> Result<Arc<SuperBlock>, KernelError> {
    // The filesystem must support device mounting
    let mount_dev_fn = fs_type
        .mount_dev
        .ok_or(KernelError::OperationNotSupported)?;

    // Look up the source device path
    let source_dentry = super::namei::lookup_path(source)?;
    let source_inode = source_dentry.get_inode().ok_or(KernelError::NotFound)?;

    // Verify it's a block device
    if source_inode.mode().file_type() != Some(FileType::BlockDev) {
        return Err(KernelError::NotBlockDevice);
    }

    // Get the BlockDevice from the registry using the inode's rdev
    let bdev = get_blkdev(source_inode.rdev).ok_or(KernelError::NoDevice)?;

    // Opened (under the disk's open_mutex, failing for a removed
    // device) for the superblock's life: a rescan sees it in use
    let h = bdev.open_handle()?;
    let sb = mount_dev_fn(fs_type, bdev, opts)?;
    sb.set_bdev(h);
    Ok(sb)
}

// ============================================================================
// Umount Support
// ============================================================================

/// Umount flags (from Linux)
pub mod umount_flags {
    /// Force unmount even if busy
    pub const MNT_FORCE: i32 = 1;
    /// Lazy unmount - detach now, cleanup later
    pub const MNT_DETACH: i32 = 2;
    /// Unmount only an unused mount marked by an earlier call
    pub const MNT_EXPIRE: i32 = 4;
    /// Don't follow symlinks in path
    pub const UMOUNT_NOFOLLOW: i32 = 8;
}

/// A mount is busy for umount (Linux propagate_mount_busy's
/// do_refcount_check): it has submounts, or more references than the
/// `refs` its caller and the tree hold; under MOUNT_LOCK, a racing fast
/// path makes it approximate, as in Linux
fn is_mount_busy(mount: &MountRef, s: &impl Stable, refs: isize) -> bool {
    mount.has_children(s) || mount.mnt_get_count() > refs
}

/// The references umount's caller and the tree hold on its target
/// (Linux do_umount's propagate_mount_busy(mnt, 2)): the caller's, the
/// parent's (a propagated copy's: `propagate_umount`'s list and the
/// parent's)
const UMOUNT_REFS: isize = 2;

/// Unmount `mount` (Linux can_umount, do_umount): EINVAL for a mount
/// of another namespace, a locked one, or an unattached one (the
/// namespace root); the caller's own root is instead remounted
/// read-only (do_umount_root). MNT_DETACH takes the whole subtree out of
/// the namespace at once, busy or not: open files keep working, the
/// filesystem goes with its last user. Otherwise a mount with
/// submounts or users is EBUSY, MNT_FORCE too. MNT_EXPIRE (not with
/// MNT_FORCE or MNT_DETACH, not the root) only marks an unmarked mount
/// (EAGAIN).
pub fn do_umount(mount: MountRef, flags: i32) -> Result<(), KernelError> {
    use umount_flags::{MNT_DETACH, MNT_EXPIRE, MNT_FORCE};
    // Linux can_umount, optimistic; repeated under NAMESPACE_SEM
    if !check_mnt(&mount) || mount.flags() & MNT_LOCKED != 0 {
        return Err(KernelError::InvalidArgument);
    }
    let detach = flags & MNT_DETACH != 0;
    let is_root = crate::task::percpu::current_fs()
        .is_some_and(|fs| MountRef::ptr_eq(&fs.get_root().mnt, &mount));
    if flags & MNT_EXPIRE != 0 {
        if is_root || flags & (MNT_FORCE | MNT_DETACH) != 0 {
            return Err(KernelError::InvalidArgument);
        }
        // Busy first (Linux: mnt_get_count != 2 under lock_mount_hash),
        // then the mark
        let busy = {
            let _ml = MOUNT_LOCK.read_excl();
            mount.mnt_get_count() != UMOUNT_REFS
        };
        if busy {
            return Err(KernelError::Busy);
        }
        if !mount.expiry.swap(true, Ordering::SeqCst) {
            return Err(KernelError::WouldBlock);
        }
    }
    if is_root && !detach {
        let _s = mount.sb.s_umount.write();
        return mount.sb.make_rdonly();
    }
    if mount.get_mountpoint().is_none() {
        return Err(KernelError::InvalidArgument);
    }
    let mut ns = namespace_lock();
    if !check_mnt(&mount) || mount.flags() & MNT_LOCKED != 0 {
        return Err(KernelError::InvalidArgument);
    }
    // The propagated copies go too (Linux propagate_mount_busy,
    // propagate_umount); a busy one makes it all EBUSY
    let copies = super::pnode::propagate_umount(&ns, &mount);
    let busy = {
        let ml = MOUNT_LOCK.read_excl();
        is_mount_busy(&mount, &*ml, UMOUNT_REFS)
            || copies.iter().any(|c| is_mount_busy(c, &*ml, UMOUNT_REFS))
    };
    if !detach && busy {
        return Err(KernelError::Busy);
    }
    // The tree references taken off, put after a grace period by this
    // task (Linux namespace_unlock: synchronize_rcu, then mntput), so a
    // last one's teardown runs before the syscall returns
    let mut gone: Vec<MountRef> = Vec::new();
    gone.try_reserve(copies.len() + 1)
        .map_err(|_| KernelError::OutOfMemory)?;
    for m in core::iter::once(&mount).chain(copies.iter()) {
        if let Some(t) = detach_mnt(&mut ns, m) {
            gone.push(t);
        }
        // Unmounted mounts leave propagation and the namespace
        // (Linux umount_tree)
        for t in walk(m, &*ns) {
            super::pnode::change_propagation(&t, super::pnode::Prop::Private);
            t.set_ns(0);
        }
    }
    drop(ns);
    crate::sync::rcu::synchronize();
    drop(gone);

    // Write the filesystem back, outside namespace_sem: writeback takes
    // inode locks, which nest outside it (Linux: deactivate_super ->
    // sync_filesystem after namespace_unlock)
    let _ = super::fs_writeback::writeback_sb(&mount.sb);
    Ok(())
}

/// A mount namespace's last reference went (Linux put_mnt_ns): its whole
/// tree is unmounted at once (Linux umount_tree of the root): every
/// mount leaves the namespace and propagation, and loses its parent
/// and mountpoint; after a grace period (Linux namespace_unlock) the
/// tree's references, the root's included, are put by the caller,
/// which may sleep. A mount still used elsewhere (an open file, another
/// task's cwd) lives on, detached.
pub fn put_mnt_ns(root: MountRef) {
    let mut gone = OwnedList::<MntChild>::new();
    {
        let mut ns = namespace_lock();
        for t in walk(&root, &*ns) {
            super::pnode::change_propagation(&t, super::pnode::Prop::Private);
            t.set_ns(0);
        }
        // Every submount off its parent, breadth first, onto `gone`
        // (intrusive: nothing allocated under the locks)
        let mut ml = MOUNT_LOCK.write();
        let mut todo = OwnedList::<MntChild>::new();
        let top = root.mnt_mounts.access_mut(&mut ns, &mut ml);
        while let Some(c) = top.pop_front() {
            todo.push_back(c);
        }
        while let Some(c) = todo.pop_front() {
            *c.parent.write() = None;
            let kids = c.mnt_mounts.access_mut(&mut ns, &mut ml);
            while let Some(k) = kids.pop_front() {
                todo.push_back(k);
            }
            gone.push_back(c);
        }
    }
    crate::sync::rcu::synchronize();
    while let Some(c) = gone.pop_front() {
        // SAFETY: entries of mnt_mounts are references (`attach_mnt`),
        // moved here as they were
        let c = unsafe { MountRef::from_entry(c) };
        // Its parent link is gone: `up` no longer reads this
        if let Some(mp) = c.mountpoint.write().take() {
            note_mp(&mp, -1);
        }
    }
    drop(root);
}

/// Take `m` (and what is mounted below it) off its parent; under
/// NAMESPACE_SEM write
fn detach_mnt(ns: &mut NsTree, m: &MountRef) -> Option<MountRef> {
    let parent = m.get_parent();
    // A tree change under MOUNT_LOCK (Linux umount_tree under
    // lock_mount_hash), for the walks that check its sequence; the
    // mountpoint goes after the unlock, the parent's tree reference to
    // `m` to the caller (a move hangs it elsewhere, an umount releases
    // it)
    let mut ml = MOUNT_LOCK.write();
    let link = parent
        .as_ref()
        .and_then(|p| p.mnt_mounts.access_mut(ns, &mut ml).remove(m))
        // SAFETY: entries of mnt_mounts are references (`attach_mnt`)
        .map(|c| unsafe { MountRef::from_entry(c) });
    *m.parent.write() = None;
    let mp = m.mountpoint.write().take();
    if let Some(mp) = &mp {
        note_mp(mp, -1);
    }
    drop(ml);
    link
}

/// Hang `m` on `mp` (Linux attach_mnt, under lock_mount_hash: here
/// MOUNT_LOCK, for the walks that check its sequence); under
/// NAMESPACE_SEM write
pub(super) fn attach_mnt(ns: &mut NsTree, m: MountRef, mp: &Path) {
    let mut ml = MOUNT_LOCK.write();
    m.set_mountpoint(mp.dentry.clone());
    m.set_parent(&mp.mnt);
    mp.mnt
        .mnt_mounts
        .access_mut(ns, &mut ml)
        .push_back(m.into_entry());
}

/// Hang the tree at `m` on `mp` and, under a shared mount, propagate
/// it (Linux attach_recursive_mnt: the tree is made shared first);
/// under NAMESPACE_SEM write
fn graft(ns: &mut NsTree, t: MountRef, mp: &Path) {
    let m = MountRef::clone(&t);
    let shared = mp.mnt.group.load(Ordering::SeqCst) != 0;
    if shared {
        super::pnode::invent_groups(ns, &m);
    }
    attach_mnt(ns, t, mp);
    commit_tree(ns, &m);
    if shared {
        super::pnode::propagate_mnt(ns, &mp.mnt, &mp.dentry, &m);
    }
}

/// `p` is at or below `root`, across mounts (Linux is_path_reachable,
/// path_is_under)
pub fn is_path_reachable(p: &Path, root: &Path) -> bool {
    let (mut mnt, mut d) = (p.mnt.clone(), p.dentry.clone());
    while !MountRef::ptr_eq(&mnt, &root.mnt) {
        match (mnt.get_parent(), mnt.get_mountpoint()) {
            (Some(m), Some(mp)) => (mnt, d) = (m, mp),
            _ => return false,
        }
    }
    super::is_subdir(&d, &root.dentry)
}

/// The mountpoint's i_rwsem (Linux lock_mount): a directory removed
/// meanwhile is ENOENT
fn lock_mountpoint(mp: &Path) -> Result<super::inode::InodeLockArc, KernelError> {
    let dir = mp.dentry.get_inode().ok_or(KernelError::NotFound)?;
    let lock = dir.lock_arc();
    if dir.is_dead() {
        return Err(KernelError::NotFound);
    }
    Ok(lock)
}

/// MS_MOVE (Linux do_move_mount): `old` must be the root of a mount,
/// a directory goes only on a directory (EINVAL); then, in
/// Linux's order, `old` in the caller's namespace, attached, unlocked,
/// not under a shared mount, and the target in the namespace too
/// (EINVAL), and not into its own subtree (ELOOP)
pub fn do_move(old: &Path, mp: &Path) -> Result<(), KernelError> {
    if !Arc::ptr_eq(&old.dentry, &old.mnt.root) {
        return Err(KernelError::InvalidArgument);
    }
    let is_dir = |d: &Dentry| d.get_inode().is_some_and(|i| i.mode().is_dir());
    if is_dir(&mp.dentry) != is_dir(&old.dentry) {
        return Err(KernelError::InvalidArgument);
    }
    let _l = lock_mountpoint(mp)?;
    let mut ns = namespace_lock();
    let shared = |m: &Mount| m.group.load(Ordering::SeqCst) != 0;
    let parent = old.mnt.get_parent();
    if !check_mnt(&old.mnt)
        || parent.is_none()
        || old.mnt.flags() & MNT_LOCKED != 0
        || parent.is_some_and(|p| shared(&p))
        || !check_mnt(&mp.mnt)
    {
        return Err(KernelError::InvalidArgument);
    }
    // An unbindable tree not under a shared mount
    if shared(&mp.mnt) && walk(&old.mnt, &*ns).any(|m| m.is_unbindable()) {
        return Err(KernelError::InvalidArgument);
    }
    if is_path_reachable(mp, old) {
        return Err(KernelError::TooManySymlinks);
    }
    // It has a parent (checked above): it moves with its tree reference
    let Some(t) = detach_mnt(&mut ns, &old.mnt) else {
        unreachable!("mount: an attached mount off no parent");
    };
    graft(&mut ns, t, mp);
    Ok(())
}

/// pivot_root (Linux 6.8 SYSCALL pivot_root): `new` becomes the root of
/// the caller's namespace view and the old root (the caller's root,
/// which must be a mount root on a parent, like `new`) moves to
/// `put_old`, reachable from `new`. Every task rooted or standing at
/// the old root follows (chroot_fs_refs).
pub fn do_pivot_root(new: &Path, put_old: &Path) -> Result<(), KernelError> {
    let root = crate::task::percpu::current_fs()
        .ok_or(KernelError::InvalidArgument)?
        .get_root();
    let _l = lock_mountpoint(put_old)?;
    let mut ns = namespace_lock();
    // Only a mount in the namespace has a parent NAMESPACE_SEM pins
    // (Linux check_mnt before reading them)
    if !check_mnt(&root.mnt) || !check_mnt(&new.mnt) {
        return Err(KernelError::InvalidArgument);
    }
    // Nothing moves under a shared mount here without propagating
    // (Linux: put_old's mount, new's parent, root's parent not shared)
    let shared = |m: Option<MountRef>| m.is_some_and(|m| m.group.load(Ordering::SeqCst) != 0);
    if shared(Some(put_old.mnt.clone()))
        || shared(new.mnt.get_parent())
        || shared(root.mnt.get_parent())
    {
        return Err(KernelError::InvalidArgument);
    }
    if new.mnt.flags() & MNT_LOCKED != 0 {
        return Err(KernelError::InvalidArgument);
    }
    if new.dentry.is_unhashed() {
        return Err(KernelError::NotFound);
    }
    if MountRef::ptr_eq(&new.mnt, &root.mnt) || MountRef::ptr_eq(&put_old.mnt, &root.mnt) {
        return Err(KernelError::Busy);
    }
    let mounted = |p: &Path| Arc::ptr_eq(&p.dentry, &p.mnt.root) && p.mnt.get_parent().is_some();
    if !mounted(&root) || !mounted(new) {
        return Err(KernelError::InvalidArgument);
    }
    if !is_path_reachable(put_old, new) || !is_path_reachable(new, &root) {
        return Err(KernelError::InvalidArgument);
    }
    let (Some(root_parent), Some(root_mp)) = (root.mnt.get_parent(), root.mnt.get_mountpoint())
    else {
        return Err(KernelError::InvalidArgument);
    };
    // Both are mounted (checked above): each comes off its parent with
    // the tree reference it moves with
    let (Some(tn), Some(tr)) = (
        detach_mnt(&mut ns, &new.mnt),
        detach_mnt(&mut ns, &root.mnt),
    ) else {
        unreachable!("pivot_root: a mounted mount off no parent");
    };
    if root.mnt.flags() & MNT_LOCKED != 0 {
        new.mnt.mark(MNT_LOCKED, true);
        root.mnt.mark(MNT_LOCKED, false);
    }
    attach_mnt(&mut ns, tr, put_old);
    attach_mnt(&mut ns, tn, &Path::new(root_parent, root_mp));
    drop(ns);
    chroot_fs_refs(&root, &Path::new(new.mnt.clone(), new.mnt.root.clone()));
    Ok(())
}

/// Every task whose root or cwd is `old` moves to `new` (Linux
/// chroot_fs_refs)
fn chroot_fs_refs(old: &Path, new: &Path) {
    use crate::task::percpu::{GlobalTaskTable, task_ref};
    // Gathered with no allocation under TASKLIST
    let tasks = GlobalTaskTable::collect_tasks(|_, t| Some(task_ref(t.task)));
    for t in tasks {
        let Some(fs) = super::get_task_fs(&t) else {
            continue;
        };
        if fs.get_root().same(old) {
            fs.set_root(new.clone());
        }
        if fs.get_pwd().same(old) {
            fs.set_pwd(new.clone());
        }
    }
}

/// Count a mount on (`+1`) or off (`-1`) the dentry `mp` and the
/// filesystem it is in
fn note_mp(mp: &Dentry, delta: i32) {
    mp.note_mounted(delta);
    if let Some(sb) = mp.superblock() {
        sb.note_mounted_on(delta);
    }
}

impl Mount {
    /// Tear the mount down (Linux cleanup_mnt, with mntput_no_expire's
    /// release of the submounts still hung on it): off its
    /// superblock's s_mounts, its submounts and mountpoint let go, its
    /// id freed, then its root dentry and superblock released. Sleeps.
    ///
    /// # Safety
    /// Once per mount, with no counted reference left or to come: it is
    /// doomed, or it never had a reference.
    pub(super) unsafe fn cleanup(&self) {
        // Off s_mounts first, so no walk of it borrows the mount after
        // this (the list's contract, `WeakList`)
        let weak = {
            let mut l = self.sb.s_mounts.lock();
            // SAFETY: a linked mnt_instance is on its superblock's list
            self.mnt_instance
                .is_linked()
                .then(|| unsafe { l.remove(self) })
        };
        drop(weak);
        // A tree torn down whole (a namespace's last reference) still
        // has its submounts hung on it: each loses its parent and
        // mountpoint, and the reference this one held
        let (mut kids, in_ns) = self.unhang_children();
        // One that was still in a namespace (Linux never has such: the
        // parent of a doomed mount is in none) had fast puts: wait them
        // out before its reference goes (Linux namespace_unlock)
        if in_ns {
            crate::sync::rcu::synchronize();
        }
        while let Some(c) = kids.pop_front() {
            // SAFETY: entries of mnt_mounts are references
            // (`attach_mnt`), moved here as they were
            let c = unsafe { MountRef::from_entry(c) };
            // Its parent link is gone: `up` no longer reads this
            if let Some(mp) = c.mountpoint.write().take() {
                note_mp(&mp, -1);
            }
        }
        if let Some(mp) = self.mountpoint.write().take() {
            note_mp(&mp, -1);
        }
        MNT_IDS.free(self.mnt_id);
        // SAFETY: the caller's contract: no reference can reach these
        // any more, and this is their one release
        let (root, sb) = unsafe { (self.root.take(), self.sb.take()) };
        drop(root);
        drop(sb);
    }

    /// Unhang every submount (Linux umount_mnt for each) in one
    /// section under NAMESPACE_SEM write and MOUNT_LOCK: each loses its
    /// parent link there, and moves, with the reference it held, to the
    /// list returned (intrusive: nothing allocated), released after the
    /// locks
    fn unhang_children(&self) -> (OwnedList<MntChild>, bool) {
        let mut out = OwnedList::new();
        if !self.has_children(&*MOUNT_LOCK.read_excl()) {
            return (out, false);
        }
        let mut ns = namespace_lock();
        let mut ml = MOUNT_LOCK.write();
        let list = self.mnt_mounts.access_mut(&mut ns, &mut ml);
        let mut in_ns = false;
        while let Some(c) = list.pop_front() {
            debug_assert_eq!(c.ns(), 0, "mount: a doomed mount's submount in a namespace");
            in_ns |= c.ns() != 0;
            c.set_ns(0);
            *c.parent.write() = None;
            out.push_back(c);
        }
        (out, in_ns)
    }
}

impl MountRef {
    /// Write access through this mount (Linux mnt_want_write): EROFS
    /// for a read-only mount or superblock; hold the guard across the
    /// modification
    pub fn want_write(&self) -> Result<super::superblock::WriteAccess, KernelError> {
        super::superblock::get_write(&self.writers, || self.is_readonly())?;
        Ok(super::superblock::WriteAccess::mnt(self.clone()))
    }
}

/// The memory of a mount: torn down already, unless it never had a
/// reference (`Mount::alloc` failed to allocate its `Arc`)
impl Drop for Mount {
    fn drop(&mut self) {
        if !*self.doomed.get_mut() {
            // SAFETY: never referenced (`&mut self`), so this is its one
            // teardown
            unsafe { self.cleanup() };
        }
    }
}

/// Something is mounted on `d` in the caller's mount namespace (Linux
/// is_local_mountpoint, __is_local_mountpoint under namespace_sem
/// read): a walk of the namespace's mounts for one whose mountpoint is
/// the dentry `d`
pub fn is_local_mountpoint(d: &Arc<Dentry>) -> bool {
    // Nothing is mounted on this dentry (or an alias) anywhere: no walk
    if !may_be_mountpoint(d) {
        return false;
    }
    let ns = namespace_read();
    let Some(root) = crate::ns::current_mnt_ns().get_root() else {
        return false;
    };
    walk(&root, &*ns).any(|m| m.get_mountpoint().is_some_and(|mp| same_place(&mp, d)))
}

/// Where a walk lands on `p` (Linux traverse_mounts): the root of the
/// topmost mount stacked on it, else `p` itself
pub fn follow_mount(p: Path) -> Path {
    let mut p = p;
    while may_be_mountpoint(&p.dentry) {
        match lookup_mnt(&p) {
            Some(m) => p = Path::new(m.clone(), m.root.clone()),
            None => break,
        }
    }
    p
}

/// The mount on `p` (Linux lookup_mnt): a child of `p.mnt` whose
/// mountpoint is the place `p.dentry` names, under mount_lock's
/// locking read (Linux walks the mount hash under RCU and the
/// sequence)
fn lookup_mnt(p: &Path) -> Option<MountRef> {
    let ml = MOUNT_LOCK.read_excl();
    // Borrowed while scanning (Linux __lookup_mnt takes no reference):
    // a put under MOUNT_LOCK of a mount out of its namespace would take
    // it again; only the match gets one
    ml.mounts(&p.mnt)
        .iter()
        .find(|c| {
            c.mountpoint
                .read()
                .as_ref()
                .is_some_and(|mp| same_place(mp, &p.dentry))
        })
        .map(MountRef::entry_ref)
}

/// Names on this inode's filesystem are their exact bytes (in-memory
/// ones): otherwise another spelling (vfat: case, trailing dots) is
/// another dentry for the same object
fn exact_names(i: &super::inode::Inode) -> bool {
    i.superblock()
        .is_some_and(|sb| sb.fs_type.fs_flags == super::superblock::fs_flags::FS_IN_MEMORY)
}

/// The mountpoint `mp` and the dentry `d` are one place: the same
/// dentry (renames move dentries), or the same inode where that cannot
/// be another object: a directory (no hard links), or a filesystem
/// without exact names (FAT has no hard links either; Linux gets one
/// dentry there through vfat's d_hash/d_compare)
fn same_place(mp: &Arc<Dentry>, d: &Arc<Dentry>) -> bool {
    if Arc::ptr_eq(mp, d) {
        return true;
    }
    let (Some(a), Some(b)) = (mp.get_inode(), d.get_inode()) else {
        return false;
    };
    a.ino == b.ino && a.sb.ptr_eq(&b.sb) && (a.mode().is_dir() || !exact_names(&b))
}

/// The walk must look for a mount on `d`: it is marked, or (no exact
/// names, something mounted on its filesystem) an alias of it may be
fn may_be_mountpoint(d: &Dentry) -> bool {
    d.is_mountpoint()
        || d.get_inode().is_some_and(|i| {
            !exact_names(&i) && i.sb.upgrade().is_some_and(|sb| sb.has_mounts_on())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An unattached nullfs mount
    fn mnt() -> MountRef {
        let t = &super::super::nullfs::NULLFS_TYPE;
        let sb = (t.mount)(t, b"").unwrap();
        let root = sb.get_root().unwrap();
        Mount::alloc(sb, root, 0, b"t".as_slice().into()).unwrap()
    }

    /// A new mount on `parent`'s root
    fn hang(ns: &mut NsTree, parent: &MountRef) -> MountRef {
        let c = mnt();
        attach_mnt(
            ns,
            c.clone(),
            &Path::new(parent.clone(), parent.root.clone()),
        );
        c
    }

    fn locked(m: &Mount) -> bool {
        m.flags() & MNT_LOCKED != 0
    }

    #[test]
    fn copy_tree_locks_submounts_not_top() {
        let mut ns = namespace_lock();
        let top = mnt();
        top.mark(MNT_LOCKED, true);
        let c = hang(&mut ns, &top);
        c.mark(MNT_LOCKED, true);
        let g = hang(&mut ns, &c);
        let plan = copy_plan(&ns, &top, &top.root).unwrap();
        let t = copy_tree(&mut ns, &plan);
        assert!(!locked(&t));
        let kids: Vec<_> = t.kids(&*ns).collect();
        assert_eq!(kids.len(), 1);
        assert!(locked(&kids[0]));
        let grand: Vec<_> = kids[0].kids(&*ns).collect();
        assert_eq!(grand.len(), 1);
        assert!(!locked(&grand[0]));
        assert_eq!(walk(&t, &*ns).count(), 3);
        drop(g);
    }

    #[test]
    fn copy_plan_locked_unbindable_is_eperm() {
        let mut ns = namespace_lock();
        let top = mnt();
        let c = hang(&mut ns, &top);
        c.set_unbindable(true);
        let plan = copy_plan(&ns, &top, &top.root).unwrap();
        assert_eq!(plan.len(), 1);
        c.mark(MNT_LOCKED, true);
        let r = copy_plan(&ns, &top, &top.root);
        assert!(matches!(r, Err(KernelError::NotPermitted)));
    }

    #[test]
    fn locked_child_blocks_lone_bind() {
        let mut ns = namespace_lock();
        let top = mnt();
        let c = hang(&mut ns, &top);
        assert!(!has_locked_children(&ns, &top, &top.root));
        c.mark(MNT_LOCKED, true);
        assert!(has_locked_children(&ns, &top, &top.root));
    }
}
