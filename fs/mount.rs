//! Mount - filesystem mount infrastructure
//!
//! Manages the mount tree that connects filesystems into a unified namespace.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use crate::sync::LockedBy;
use crate::sync::rcu::{RcuPuts, RcuReadGuard};
use crate::sync::spin::RwLock;
use crate::sync::{LockedByEither, RwSem, RwSemReadGuard, RwSemWriteGuard, SeqLock, UniqueOwner};
use crate::util::list::{BoxList, Link, OwnedList, Owner};
use crate::util::rcuhlist::{HNode, RcuHList};
use ::core::sync::atomic::{AtomicU32, AtomicU64, Ordering, fence};
use alloc::boxed::Box;

use super::KernelError;
use super::dentry::{Dentry, DentryRef};
use super::inode::FileType;
pub use super::mntput::MountRef;
use super::mntput::{__cleanup_mnt, MNT_NS_INTERNAL, MntOwned};
use super::path_ref::Path;
use super::superblock::{FileSystemType, SuperBlock};
use crate::task::task_work::CallbackHead;
use crate::util::ida::Ida;
use crate::util::kalloc::{arc_nofail, try_arc};
use crate::util::percpu_alloc::PcpSlot;
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
/// New write access through the mount waits (Linux MNT_WRITE_HOLD):
/// set only under MOUNT_LOCK while writers are counted, never seen by
/// [`Mount::flags`]
const MNT_WRITE_HOLD: u32 = 0x200;
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
/// `read_excl`); under NAMESPACE_SEM and s_umount, above RENAME_LOCK
/// (d_path, path_is_under) and leaves
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
/// under any lock but MOUNT_LOCK. References beyond its caller's and
/// the tree's make it busy for umount.
pub struct Mount {
    /// The mounted filesystem's superblock (Linux mnt_sb)
    pub sb: MntOwned<Arc<SuperBlock>>,

    /// Root dentry of the mounted filesystem (Linux mnt_root)
    pub root: MntOwned<DentryRef>,

    /// The dentry where this filesystem is mounted (mount point)
    /// None for the root mount
    pub mountpoint: RwLock<Option<DentryRef>>,

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

    /// Holders of write access through this mount, per CPU (Linux
    /// mnt_pcp's mnt_writers): a writer adds to any CPU's part, a
    /// holder sums them with MNT_WRITE_HOLD set (`want_write`,
    /// `hold_writers`)
    mnt_writers: PcpSlot,

    /// Id in /proc/<pid>/mountinfo and statx (Linux mnt_id): reused
    pub mnt_id: u32,
    /// Id never reused (Linux mnt_id_unique, STATX_MNT_ID_UNIQUE)
    pub mnt_id_unique: u64,
    /// What was mounted: the source argument, or the fs type for
    /// mounts made by the kernel (Linux mnt_devname)
    pub devname: super::name::FileName,

    /// Its references' count, per CPU ([`MountRef`], Linux mnt_pcp's
    /// mnt_count)
    pub(super) mnt_pcp: PcpSlot,
    /// Its last reference went (Linux MNT_DOOMED): set under MOUNT_LOCK
    /// write by that put
    pub(super) doomed: AtomicBool,

    /// In the mount hash while attached (Linux mnt_hash), its chain's
    /// reference released a grace period after it leaves (`mnt_puts`)
    mnt_hash: HNode,
    /// The mount hash's deferred releases (`RcuHRef::defer_put`)
    mnt_puts: RcuPuts,

    /// The deferred teardown's head (Linux mnt_rcu as task_work, or
    /// mnt_llist on delayed_mntput_list)
    pub(super) mnt_task_work: CallbackHead,
    /// The free a grace period after the teardown (Linux mnt_rcu)
    mnt_rcu: crate::sync::rcu::RcuHead,

    /// On its superblock's `s_mounts` (Linux mnt_instance)
    pub(super) mnt_instance: crate::util::list::Link,
}

impl Mount {
    /// A new mount, its first reference, or ENOMEM (Linux alloc_vfsmnt)
    pub fn alloc(
        sb: Arc<SuperBlock>,
        root: DentryRef,
        flags: u32,
        devname: super::name::FileName,
    ) -> Result<MountRef, KernelError> {
        let pcp = PcpSlot::new()?;
        let m = try_arc(Self::init(
            sb,
            root,
            flags,
            devname,
            pcp,
            PcpSlot::new()?,
            MNT_IDS.try_alloc()?,
        ))?;
        m.sb.add_mount(&m);
        Ok(MountRef::first(m))
    }

    /// [`Mount::alloc`] for a tree copy, which cannot unwind a partial
    /// copy (its peer groups and attachments) on failure
    fn alloc_nofail(
        sb: Arc<SuperBlock>,
        root: DentryRef,
        flags: u32,
        devname: super::name::FileName,
    ) -> MountRef {
        let pcp = PcpSlot::new_nofail();
        let w = PcpSlot::new_nofail();
        let m = arc_nofail(Self::init(
            sb,
            root,
            flags,
            devname,
            pcp,
            w,
            MNT_IDS.alloc(),
        ));
        m.sb.add_mount(&m);
        MountRef::first(m)
    }

    /// A mount with id `mnt_id`, which its drop gives back
    fn init(
        sb: Arc<SuperBlock>,
        root: DentryRef,
        flags: u32,
        devname: super::name::FileName,
        mnt_pcp: PcpSlot,
        mnt_writers: PcpSlot,
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
            mnt_writers,
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
            mnt_hash: HNode::new(),
            mnt_puts: RcuPuts::new(),
            mnt_task_work: CallbackHead::new(__cleanup_mnt),
            mnt_rcu: crate::sync::rcu::RcuHead::new(),
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

    /// Mounted in some namespace, not a kernel mount (Linux is_mounted:
    /// mnt_ns neither NULL nor MNT_NS_INTERNAL)
    pub fn is_mounted(&self) -> bool {
        let ns = self.ns();
        ns != 0 && ns != MNT_NS_INTERNAL
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

    /// MNT_* flags (MNT_WRITE_HOLD, a MOUNT_LOCK holder's, left out:
    /// Linux clone_mnt and remount clear it from what they copy)
    pub fn flags(&self) -> u32 {
        self.mnt_flags.load(Ordering::Relaxed) & !MNT_WRITE_HOLD
    }

    /// Replace the MNT_* flags (mount, remount): turning MNT_READONLY on
    /// is EBUSY, nothing changed, while anyone holds write access
    /// through the mount (Linux mnt_make_readonly)
    pub fn set_flags(&self, f: u32) -> Result<(), KernelError> {
        let _ml = MOUNT_LOCK.write();
        // Lock state is not the caller's to set here, nor the hold
        let f = (f & !(MNT_LOCKED | MNT_WRITE_HOLD)) | (self.flags() & MNT_LOCKED);
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

    /// Hold new writers off (Linux mnt_hold_writers), under MOUNT_LOCK:
    /// true if none holds write access now. The flag is stored before
    /// the parts are summed (smp_mb), and a writer adds before it looks
    /// at the flag, so a writer the sum misses waits, then sees the
    /// read-only state set before `unhold_writers`.
    pub(super) fn hold_writers(&self) -> bool {
        self.mnt_flags.fetch_or(MNT_WRITE_HOLD, Ordering::SeqCst);
        fence(Ordering::SeqCst);
        self.mnt_writers.sum() <= 0
    }

    /// Let writers in again (Linux mnt_unhold_writers), under
    /// MOUNT_LOCK: after the read-only state they must see (smp_wmb)
    pub(super) fn unhold_writers(&self) {
        fence(Ordering::Release);
        self.mnt_flags.fetch_and(!MNT_WRITE_HOLD, Ordering::Release);
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

    /// Release what want_write took (Linux mnt_put_write_access): from
    /// any CPU's part, the sum adds up
    pub(super) fn put_write(&self) {
        self.mnt_writers.add(-1);
    }

    /// Take write access (Linux mnt_get_write_access): count first,
    /// then (smp_mb) wait out a hold, spinning (a holder holds MOUNT_LOCK
    /// and never waits for writers), then (smp_rmb) EROFS if read-only
    fn get_write(&self) -> Result<(), KernelError> {
        self.mnt_writers.add(1);
        fence(Ordering::SeqCst);
        while self.mnt_flags.load(Ordering::Relaxed) & MNT_WRITE_HOLD != 0 {
            core::hint::spin_loop();
        }
        fence(Ordering::Acquire);
        if self.is_readonly() {
            self.mnt_writers.add(-1);
            return Err(KernelError::ReadOnlyFs);
        }
        Ok(())
    }

    /// A use of the mount ended (Linux mntput): an MNT_EXPIRE mark
    /// goes; read first, so the common case writes nothing
    pub fn clear_expiry(&self) {
        if self.expiry.load(Ordering::Relaxed) {
            self.expiry.store(false, Ordering::Relaxed);
        }
    }

    /// Get the mount point dentry
    pub fn get_mountpoint(&self) -> Option<DentryRef> {
        self.mountpoint.read().clone()
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
        let mp = self.mountpoint.read().as_ref().map(DentryRef::as_ptr)?;
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

    /// The parent mount and the mountpoint in it, borrowed for an RCU
    /// read guard's life with no reference (Linux READ_ONCE of
    /// mnt_parent and mnt_mountpoint in an RCU walk): a walk on them
    /// checks MOUNT_LOCK's sequence after. None for a mount on no
    /// parent.
    pub fn up_rcu<'g>(
        &self,
        _g: &'g crate::sync::rcu::RcuReadGuard,
    ) -> Option<(&'g Mount, &'g Dentry)> {
        let parent = self.parent.read().as_ref().map(Weak::as_ptr)?;
        let mp = self.mountpoint.read().as_ref().map(DentryRef::as_ptr)?;
        // SAFETY: each link was set when read under the guard: the parent
        // then still had `self` hung on it, and is freed only a grace
        // period after its teardown, which unhangs `self` first
        // (`kfree_rcu` in `__cleanup_mnt`); the mountpoint was then a
        // reference `self` held, and a dentry is freed only a grace
        // period after its last one goes. Both frees wait for `_g`.
        Some(unsafe { (&*parent, &*mp) })
    }

    /// The root dentry's address, read even after the teardown released
    /// it (Linux compares mnt_root of a mount an RCU walk reached): for
    /// comparison only
    pub(super) fn root_addr(&self) -> *const Dentry {
        // SAFETY: the cell holds a `DentryRef`'s bits, which `take`
        // leaves in place; only its address is read
        DentryRef::as_ptr(unsafe { &*self.root.stale() })
    }

    /// The parent mount, borrowed from the lock `_s` holds the tree
    /// still with: its link changes only under NAMESPACE_SEM write and
    /// MOUNT_LOCK both, and a parent's teardown unhangs its submounts
    /// under both before it goes
    fn parent_in<'a>(&'a self, _s: &'a impl Stable) -> Option<&'a Mount> {
        let p = self.parent.read().as_ref().map(Weak::as_ptr)?;
        // SAFETY: as above: while `_s` is held the link stays and the
        // parent, which still has `self` hung on it, lives
        Some(unsafe { &*p })
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

/// `f` on `root` and every mount below it, parents first, borrowed
/// from the lock `s` holds the tree still with (Linux umount_tree's
/// next_mnt walk): no reference is taken or put, as a walk must not
/// that clears `mnt_ns` before the grace period
fn for_each_mnt<'a, S: Stable>(root: &'a Mount, s: &'a S, mut f: impl FnMut(&'a Mount)) {
    let mut p = root;
    loop {
        f(p);
        if let Some(c) = s.mounts(p).first() {
            p = c;
            continue;
        }
        // The next sibling of the nearest mount up to `root` that has one
        loop {
            if core::ptr::eq(p, root) {
                return;
            }
            let Some(parent) = p.parent_in(s) else {
                return;
            };
            if let Some(n) = s.mounts(parent).next_ref(p) {
                p = n;
                break;
            }
            p = parent;
        }
    }
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

/// A dentry something is mounted on (Linux struct mountpoint): in
/// `MountTables.mp` while `m_count` attached mounts sit on it, holding
/// the dentry, which is marked mounted (DCACHE_MOUNTED) meanwhile.
/// Changed under MOUNT_LOCK (its locking read or write).
pub struct Mountpoint {
    /// In its hash bucket (Linux m_hash)
    m_hash: Link,
    /// The dentry (Linux m_dentry, a reference)
    m_dentry: DentryRef,
    /// Mounts attached on it (Linux m_count)
    m_count: AtomicU32,
}

crate::adapter!(MpHashA, Mountpoint, m_hash);
crate::hadapter!(MntHashA, Mount, mnt_hash);

/// A mountpoint hash bucket (Linux mountpoint_hashtable's hlist_head)
type MpBucket = LockedBy<BoxList<MpHashA>, MntHash>;
/// A mount hash chain (Linux mount_hashtable's hlist_head), read under
/// RCU
type MBucket = RcuHList<MntHashA, MntHash>;

/// The mount and mountpoint hash tables (Linux mount_hashtable and
/// mountpoint_hashtable), sized at boot by [`mnt_hash_init`]; changed
/// under MOUNT_LOCK
struct MountTables {
    m: Box<[MBucket]>,
    mp: Box<[MpBucket]>,
}

static MOUNT_TABLES: spin::Once<MountTables> = spin::Once::new();

/// Buckets for `pages` pages of RAM (Linux alloc_large_system_hash
/// with scale 19: one per 512 KiB, rounded up to a power of two)
fn mhash_entries(pages: u64) -> usize {
    usize::try_from(pages >> 7)
        .unwrap_or(usize::MAX)
        .clamp(1 << 8, 1 << 20)
        .next_power_of_two()
}

/// Allocate the mount and mountpoint hash tables (Linux mnt_init):
/// before the first mount. Like Linux, no memory for them is fatal.
pub fn mnt_hash_init(pages: u64) {
    MOUNT_TABLES.call_once(|| {
        let n = mhash_entries(pages);
        let mut m = Vec::new();
        let mut mp = Vec::new();
        m.try_reserve_exact(n)
            .and_then(|()| mp.try_reserve_exact(n))
            .expect("mount: no memory for the mount hash tables");
        m.extend((0..n).map(|_| MBucket::new()));
        mp.extend((0..n).map(|_| LockedBy::new(BoxList::new())));
        MountTables {
            m: m.into_boxed_slice(),
            mp: mp.into_boxed_slice(),
        }
    });
}

fn tables() -> &'static MountTables {
    #[cfg(test)]
    mnt_hash_init(0);
    MOUNT_TABLES
        .get()
        .expect("mount: hash tables used before mnt_init")
}

/// An address's hash part (Linux: the pointer over L1_CACHE_BYTES)
fn addr_key<T>(p: *const T) -> usize {
    p.addr() / 64
}

/// The bucket of `n` buckets for `tmp` (Linux: tmp + (tmp >> shift),
/// masked)
fn bucket_of(tmp: usize, n: usize) -> usize {
    tmp.wrapping_add(tmp >> n.trailing_zeros()) & (n - 1)
}

/// The mount hash chain of children of `parent` on `d` (Linux m_hash)
fn m_hash(parent: *const Mount, d: *const Dentry) -> &'static MBucket {
    let t = &tables().m;
    &t[bucket_of(addr_key(parent).wrapping_add(addr_key(d)), t.len())]
}

/// The mountpoint bucket of `d` (Linux mp_hash)
fn mp_hash(d: *const Dentry) -> &'static MpBucket {
    let t = &tables().mp;
    &t[bucket_of(addr_key(d), t.len())]
}

/// The mountpoint of `d`, if one exists (Linux lookup_mountpoint)
fn lookup_mountpoint<'a>(ml: &'a MntHash, d: &Dentry) -> Option<&'a Mountpoint> {
    mp_hash(d)
        .access(ml)
        .iter()
        .find(|mp| core::ptr::eq(DentryRef::as_ptr(&mp.m_dentry), d))
}

/// A new mountpoint for `d`, made before MOUNT_LOCK is taken (Linux
/// get_mountpoint's kmalloc) if none exists yet. Under NAMESPACE_SEM
/// write, so no other one is made meanwhile.
fn prealloc_mountpoint(d: &DentryRef) -> Option<Box<Mountpoint>> {
    if lookup_mountpoint(&MOUNT_LOCK.read_excl(), d).is_some() {
        return None;
    }
    Some(crate::util::kalloc::box_nofail(Mountpoint {
        m_hash: Link::new(),
        m_dentry: d.clone(),
        m_count: AtomicU32::new(0),
    }))
}

/// Count a mount on `d`'s mountpoint, made from `new` if it has none
/// (Linux get_mountpoint, d_set_mounted); under MOUNT_LOCK. What is
/// left of `new` goes after the unlock.
fn get_mountpoint(ml: &mut MntHash, d: &DentryRef, new: &mut Option<Box<Mountpoint>>) {
    if let Some(mp) = lookup_mountpoint(ml, d) {
        mp.m_count.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let mp = new
        .take()
        .expect("mount: a new mountpoint with none made for it");
    mp.m_count.store(1, Ordering::Relaxed);
    d.set_mounted(true);
    mp_hash(DentryRef::as_ptr(d)).access_mut(ml).push_back(mp);
}

/// A mount left `d` (Linux put_mountpoint, maybe_free_mountpoint);
/// under MOUNT_LOCK: the last one takes the mountpoint out and unmarks
/// the dentry, and hands it back to be dropped (its dentry put) after
/// the unlock
fn put_mountpoint(ml: &mut MntHash, d: &Dentry) -> Option<Box<Mountpoint>> {
    let mp = lookup_mountpoint(ml, d)?;
    if mp.m_count.fetch_sub(1, Ordering::Relaxed) != 1 {
        return None;
    }
    d.set_mounted(false);
    mp_hash(d)
        .access_mut(ml)
        .remove_first(|m| core::ptr::eq(DentryRef::as_ptr(&m.m_dentry), d))
}

/// The child of `parent` mounted on `d` (Linux __lookup_mnt): one walk
/// of its hash chain under an RCU read guard, comparing each entry's
/// `parent` and `mountpoint`, which a lockless caller checks with
/// MOUNT_LOCK's sequence after
fn __lookup_mnt<'g>(parent: &Mount, d: &Dentry, g: &'g RcuReadGuard) -> Option<&'g Mount> {
    m_hash(parent, d).iter(g).find(|c| {
        c.parent
            .read()
            .as_ref()
            .is_some_and(|p| core::ptr::eq(p.as_ptr(), parent))
            && c.mountpoint
                .read()
                .as_ref()
                .is_some_and(|mp| core::ptr::eq(DentryRef::as_ptr(mp), d))
    })
}

/// Take `m` out of the mount hash (Linux hlist_del_init_rcu of
/// mnt_hash), before its `parent` or `mountpoint` changes; under
/// MOUNT_LOCK write. The chain's reference goes a grace period later.
fn unhash_mnt(ml: &mut MntHash, m: &Mount) {
    let parent = m.parent.read().as_ref().map(Weak::as_ptr);
    let mp = m.mountpoint.read().as_ref().map(DentryRef::as_ptr);
    if let (Some(p), Some(d)) = (parent, mp)
        && let Some(r) = m_hash(p, d).del_init(m, ml)
    {
        r.defer_put();
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
        // A namespace's root is set once (Linux alloc_mnt_ns' tree root)
        mnt_ns.set_root(mount.clone())?;
        mount.set_ns(mnt_ns.id);
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
pub fn clone_mnt(m: &Mount, root: DentryRef) -> MountRef {
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
    at: DentryRef,
}

/// What copy_tree copies of `m` at `root`, parents first: the mounts
/// below `root`; an unbindable submount is left out with whatever is
/// under it, EPERM if it is also locked (it hides what is under it)
fn copy_plan(ns: &NsTree, m: &MountRef, root: &DentryRef) -> Result<Vec<CopyEnt>, KernelError> {
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
fn has_locked_children(ns: &NsTree, m: &Mount, d: &DentryRef) -> bool {
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
        // Unmounted mounts leave propagation (Linux umount_tree), while
        // still in the namespace: the references taken here go by the
        // fast path
        for t in walk(m, &*ns) {
            super::pnode::change_propagation(&t, super::pnode::Prop::Private);
        }
    }
    // Then the namespace, in a walk that takes no reference: none may be
    // put by the exact path before the grace period
    for m in core::iter::once(&mount).chain(copies.iter()) {
        for_each_mnt(m, &*ns, |t| t.set_ns(0));
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
        // Propagation first, while every mount is in the namespace (the
        // references taken go by the fast path), then the namespace, in
        // a walk that takes none
        for t in walk(&root, &*ns) {
            super::pnode::change_propagation(&t, super::pnode::Prop::Private);
        }
        for_each_mnt(&root, &*ns, |t| t.set_ns(0));
        // Every submount off its parent, breadth first, onto `gone`
        // (intrusive: nothing allocated under the locks)
        let mut ml = MOUNT_LOCK.write();
        let mut todo = OwnedList::<MntChild>::new();
        let top = root.mnt_mounts.access_mut(&mut ns, &mut ml);
        while let Some(c) = top.pop_front() {
            todo.push_back(c);
        }
        while let Some(c) = todo.pop_front() {
            unhash_mnt(&mut ml, &c);
            *c.parent.write() = None;
            let kids = c.mnt_mounts.access_mut(&mut ns, &mut ml);
            while let Some(k) = kids.pop_front() {
                todo.push_back(k);
            }
            gone.push_back(c);
        }
    }
    crate::sync::rcu::synchronize();
    put_unhung(gone);
    drop(root);
}

/// Release submounts unhung onto `l` (their parent links cleared under
/// MOUNT_LOCK write, their namespace left a grace period ago or never
/// held): each one's mountpoint, then the reference its list entry held
/// (Linux umount_mnt's put_mountpoint, then mntput)
fn put_unhung(mut l: OwnedList<MntChild>) {
    while let Some(c) = l.pop_front() {
        // SAFETY: entries of mnt_mounts are references (`attach_mnt`),
        // moved onto `l` as they were
        let c = unsafe { MountRef::from_entry(c) };
        // Its parent link is gone: `up` no longer reads this
        c.put_mountpoint();
    }
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
    unhash_mnt(&mut ml, m);
    let link = parent
        .as_ref()
        .and_then(|p| p.mnt_mounts.access_mut(ns, &mut ml).remove(m))
        // SAFETY: entries of mnt_mounts are references (`attach_mnt`)
        .map(|c| unsafe { MountRef::from_entry(c) });
    *m.parent.write() = None;
    let mp = m.mountpoint.write().take();
    let gone = mp.as_deref().and_then(|d| put_mountpoint(&mut ml, d));
    drop(ml);
    drop(gone);
    drop(mp);
    link
}

/// Hang `m` on `mp` (Linux attach_mnt, under lock_mount_hash: here
/// MOUNT_LOCK, for the walks that check its sequence); under
/// NAMESPACE_SEM write
pub(super) fn attach_mnt(ns: &mut NsTree, m: MountRef, mp: &Path) {
    let mut new = prealloc_mountpoint(&mp.dentry);
    let mut ml = MOUNT_LOCK.write();
    get_mountpoint(&mut ml, &mp.dentry, &mut new);
    *m.mountpoint.write() = Some(mp.dentry.clone());
    m.set_parent(&mp.mnt);
    // Linux make_visible: in the mount hash and on the parent's list
    m_hash(MountRef::as_ptr(&mp.mnt), DentryRef::as_ptr(&mp.dentry))
        .add_head(MountRef::arc_of(&m), &mut ml);
    mp.mnt
        .mnt_mounts
        .access_mut(ns, &mut ml)
        .push_back(m.into_entry());
    drop(ml);
    drop(new);
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

/// Where `m` is mounted, past mounts stacked on their parent's root,
/// as a path holding references (Linux choose_mountpoint): None for a
/// mount on no parent, or when the climb meets `root`. The climb runs
/// under an RCU read guard and MOUNT_LOCK's sequence, and is repeated
/// if a mount change raced it (legitimize_mnt).
pub fn choose_mountpoint(m: &Mount, root: &Path) -> Option<Path> {
    loop {
        let g = crate::sync::rcu::read_lock();
        let seq = MOUNT_LOCK.read_begin();
        let Some((pm, pd)) = choose_mountpoint_rcu(m, root, &g) else {
            if !MOUNT_LOCK.read_retry(seq) {
                return None;
            }
            continue;
        };
        // The mountpoint is held while the child is hung there, which
        // the unmoved sequence vouches for (Linux __legitimize_path)
        let put = match MountRef::legitimize(pm, seq) {
            Ok(mnt) => match DentryRef::try_get(pd) {
                Some(d) => return Some(Path::new(mnt, d)),
                None => Some(mnt),
            },
            Err(put) => put,
        };
        // Puts after the guard (Linux rcu_read_unlock; path_put)
        drop(g);
        drop(put);
    }
}

/// One climb of [`choose_mountpoint`] (Linux choose_mountpoint_rcu)
fn choose_mountpoint_rcu<'g>(
    m: &'g Mount,
    root: &Path,
    g: &'g crate::sync::rcu::RcuReadGuard,
) -> Option<(&'g Mount, &'g Dentry)> {
    let mut m = m;
    while let Some((p, mp)) = m.up_rcu(g) {
        if core::ptr::eq(mp, DentryRef::as_ptr(&root.dentry))
            && core::ptr::eq(p, MountRef::as_ptr(&root.mnt))
        {
            return None;
        }
        if !core::ptr::eq(mp, p.root_addr()) {
            return Some((p, mp));
        }
        m = p;
    }
    None
}

/// `p` is at or below `root`, across mounts (Linux path_is_under:
/// is_path_reachable under mount_lock's locking read, the mounts
/// borrowed from it, then is_subdir, which reads RENAME_LOCK's
/// sequence inside it)
pub fn is_path_reachable(p: &Path, root: &Path) -> bool {
    let ml = MOUNT_LOCK.read_excl();
    let (mut mnt, mut d): (&Mount, &Dentry) = (&p.mnt, &p.dentry);
    while !core::ptr::eq(mnt, MountRef::as_ptr(&root.mnt)) {
        match mnt.up(&ml) {
            Some(up) => (mnt, d) = up,
            None => return false,
        }
    }
    super::dentry::is_subdir_borrowed(d, &root.dentry)
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
    if !DentryRef::ptr_eq(&old.dentry, &old.mnt.root) {
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
    let mounted =
        |p: &Path| DentryRef::ptr_eq(&p.dentry, &p.mnt.root) && p.mnt.get_parent().is_some();
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

impl Mount {
    /// Let go of the mountpoint of a mount already off its parent and
    /// out of the mount hash (Linux umount_mnt's put_mountpoint)
    fn put_mountpoint(&self) {
        let Some(mp) = self.mountpoint.write().take() else {
            return;
        };
        let gone = put_mountpoint(&mut MOUNT_LOCK.read_excl(), &mp);
        drop(gone);
    }

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
        // (Linux mntput_no_expire's stuck children: out of any namespace,
        // as their doomed parent is, so put by the exact path)
        put_unhung(self.unhang_children());
        self.put_mountpoint();
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
    fn unhang_children(&self) -> OwnedList<MntChild> {
        let mut out = OwnedList::new();
        if !self.has_children(&*MOUNT_LOCK.read_excl()) {
            return out;
        }
        let mut ns = namespace_lock();
        let mut ml = MOUNT_LOCK.write();
        while let Some(c) = self.mnt_mounts.access_mut(&mut ns, &mut ml).pop_front() {
            // A doomed mount is in no namespace, nor what hangs on it
            // (umount and put_mnt_ns clear the whole tree)
            debug_assert_eq!(c.ns(), 0, "mount: a doomed mount's submount in a namespace");
            unhash_mnt(&mut ml, &c);
            *c.parent.write() = None;
            out.push_back(c);
        }
        out
    }
}

impl MountRef {
    /// Write access through this mount (Linux mnt_want_write): EROFS
    /// for a read-only mount or superblock; hold the guard across the
    /// modification
    pub fn want_write(&self) -> Result<super::superblock::WriteAccess, KernelError> {
        self.get_write()?;
        Ok(super::superblock::WriteAccess::mnt(self.clone()))
    }
}

crate::rcu_head!(Mount, mnt_rcu);
crate::rcu_puts!(Mount, mnt_puts);

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
pub fn is_local_mountpoint(d: &DentryRef) -> bool {
    // Nothing is mounted on this dentry anywhere: no walk (Linux
    // d_mountpoint)
    if !d.is_mountpoint() {
        return false;
    }
    let ns = namespace_read();
    let Some(root) = crate::ns::current_mnt_ns().get_root() else {
        return false;
    };
    walk(&root, &*ns).any(|m| {
        m.get_mountpoint()
            .is_some_and(|mp| DentryRef::ptr_eq(&mp, d))
    })
}

/// Where a walk lands on `p` (Linux traverse_mounts): the root of the
/// topmost mount stacked on it, else `p` itself
pub fn follow_mount(p: Path) -> Path {
    let mut p = p;
    while p.dentry.is_mountpoint() {
        match lookup_mnt(&p) {
            Some(m) => p = Path::new(m.clone(), m.root.clone()),
            None => break,
        }
    }
    p
}

/// The mount on `p` (Linux lookup_mnt): a child of `p.mnt` on
/// `p.dentry`, found in the mount hash under an RCU read guard with
/// MOUNT_LOCK's sequence sampled, and a reference taken to it
/// (legitimize_mnt); repeated if a mount change raced
fn lookup_mnt(p: &Path) -> Option<MountRef> {
    loop {
        let g = crate::sync::rcu::read_lock();
        let seq = MOUNT_LOCK.read_begin();
        let put = match __lookup_mnt(&p.mnt, &p.dentry, &g) {
            None if !MOUNT_LOCK.read_retry(seq) => return None,
            None => None,
            Some(c) => match MountRef::legitimize(c, seq) {
                Ok(m) => return Some(m),
                Err(put) => put,
            },
        };
        // A put after the guard (Linux legitimize_mnt's mntput)
        drop(g);
        drop(put);
    }
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

    /// The mount hash finds a child by (parent, mountpoint), the latest
    /// stacked one first; the mountpoint stays, the dentry marked,
    /// while any mount sits on it (Linux m_count)
    #[test]
    fn mount_hash_and_mountpoint() {
        let mut ns = namespace_lock();
        let top = mnt();
        let at = Path::new(top.clone(), top.root.clone());
        let a = hang(&mut ns, &top);
        let b = hang(&mut ns, &top);
        assert!(top.root.is_mountpoint());
        let found = lookup_mnt(&at).unwrap();
        assert!(MountRef::ptr_eq(&found, &b));
        drop(found);
        assert!(detach_mnt(&mut ns, &b).is_some());
        assert!(lookup_mnt(&at).is_some_and(|m| MountRef::ptr_eq(&m, &a)));
        assert!(top.root.is_mountpoint());
        assert!(detach_mnt(&mut ns, &a).is_some());
        assert!(lookup_mnt(&at).is_none() && !top.root.is_mountpoint());
    }

    /// A held write access makes a read-only flip EBUSY (Linux
    /// mnt_make_readonly over mnt_get_writers' per-CPU sum); once it
    /// goes the flip succeeds, the hold never shows in the flags, and
    /// new writers get EROFS
    #[test]
    fn writers_block_readonly() {
        let m = mnt();
        let w = m.want_write().unwrap();
        assert!(matches!(m.set_flags(MNT_READONLY), Err(KernelError::Busy)));
        assert_eq!(m.flags() & (MNT_READONLY | MNT_WRITE_HOLD), 0);
        drop(w);
        assert!(m.set_flags(MNT_READONLY).is_ok());
        assert_eq!(m.flags(), MNT_READONLY);
        assert!(matches!(m.want_write(), Err(KernelError::ReadOnlyFs)));
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
