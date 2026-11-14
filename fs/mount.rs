//! Mount - filesystem mount infrastructure
//!
//! Manages the mount tree that connects filesystems into a unified namespace.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use crate::sync::LockedBy;
use crate::sync::rcu::{RcuPuts, RcuReadGuard};
use crate::sync::{LockedByEither, RwSem, RwSemReadGuard, RwSemWriteGuard, SeqLock, UniqueOwner};
use crate::util::list::{BoxList, Link, OwnedList, Owner};
use crate::util::rcuhlist::{HNode, RcuHList};
use ::core::ptr::NonNull;
use ::core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering, fence};
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
/// The flags mount(2) sets (Linux MNT_USER_SETTABLE_MASK): a remount
/// replaces these and keeps the rest
pub const MNT_USER_SETTABLE_MASK: u32 =
    MNT_NOSUID | MNT_NODEV | MNT_NOEXEC | MNT_ATIME_MASK | MNT_READONLY | MNT_NOSYMFOLLOW;
/// New write access through the mount waits (Linux MNT_WRITE_HOLD):
/// set only under MOUNT_LOCK while writers are counted, never seen by
/// [`Mount::flags`]
const MNT_WRITE_HOLD: u32 = 0x200;
/// Cannot be bind-mounted (Linux T_UNBINDABLE, in `t_flags`)
pub const T_UNBINDABLE: u32 = 0x1;
/// A copy for a less privileged user namespace keeps its atime flags
/// (Linux MNT_LOCK_ATIME), and each lock below the flag it names, set
/// then: a remount may not drop it (lock_mnt_tree). Set under
/// MOUNT_LOCK, never cleared, copied by a clone.
pub const MNT_LOCK_ATIME: u32 = 0x4_0000;
/// Keeps MNT_NOEXEC (Linux MNT_LOCK_NOEXEC)
pub const MNT_LOCK_NOEXEC: u32 = 0x8_0000;
/// Keeps MNT_NOSUID (Linux MNT_LOCK_NOSUID)
pub const MNT_LOCK_NOSUID: u32 = 0x10_0000;
/// Keeps MNT_NODEV (Linux MNT_LOCK_NODEV)
pub const MNT_LOCK_NODEV: u32 = 0x20_0000;
/// Keeps MNT_READONLY (Linux MNT_LOCK_READONLY)
pub const MNT_LOCK_READONLY: u32 = 0x40_0000;
/// Cannot be unmounted, moved or pivoted away (Linux MNT_LOCKED: a mount
/// a less privileged namespace copied, which would uncover what is
/// under it; the initial root is protected by having no parent)
pub const MNT_LOCKED: u32 = 0x80_0000;
/// Taken out by a synchronous umount (Linux MNT_SYNC_UMOUNT): a
/// lockless walk that raced it gives back the reference it took
/// (legitimize), so the umount's puts are the last; set under
/// MOUNT_LOCK, never cleared
pub const MNT_SYNC_UMOUNT: u32 = 0x200_0000;
/// Unmounted, or committed to it by an umount under way (Linux
/// MNT_UMOUNT): set under MOUNT_LOCK, never cleared
pub const MNT_UMOUNT: u32 = 0x800_0000;
/// The kernel's state in `mnt_flags`, not copied by a clone (Linux
/// MNT_INTERNAL_FLAGS)
const MNT_INTERNAL_FLAGS: u32 = MNT_SYNC_UMOUNT | MNT_LOCKED | MNT_UMOUNT;

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
/// (either side held) holds them still. Also what an umount leaves
/// for [`namespace_unlock`] (Linux `unmounted`, `ex_mountpoints`,
/// "protected by namespace_sem"): filled under MOUNT_LOCK write,
/// where nothing that may sleep is put or dropped.
pub struct NsTree {
    /// The unmounted mounts, each entry a reference, put a grace
    /// period after the unlock (Linux unmounted); made on first use
    unmounted: Option<UmountList>,
    /// Mountpoints whose last mount left, dropped (their dentries put)
    /// after the unlock (Linux ex_mountpoints)
    ex_mountpoints: BoxList<MpHashA>,
}

// SAFETY: one value, built here for NAMESPACE_SEM alone (private
// fields) and reachable only through its guards
unsafe impl UniqueOwner for NsTree {}

impl NsTree {
    /// Put `m`'s reference a grace period after [`namespace_unlock`]
    /// (Linux hlist_add_head on unmounted)
    fn add_unmounted(&mut self, m: Arc<Mount>) {
        self.unmounted
            .get_or_insert_with(UmountList::new)
            .push_back(m);
    }

    /// A mount left `mp` (Linux maybe_free_mountpoint onto
    /// ex_mountpoints), under MOUNT_LOCK write: a last one's
    /// mountpoint and dentry go in [`namespace_unlock`]
    fn maybe_free_mountpoint(&mut self, ml: &mut MntHash, mp: MpPtr) {
        if let Some(b) = put_mp(ml, mp) {
            self.ex_mountpoints.push_back(b);
        }
    }
}

/// Mount topology changes: attach, umount, namespace copy, pivot_root;
/// /proc mount lists and is_local_mountpoint read under it (Linux
/// namespace_sem, a sleeping rw_semaphore). Outside it: the
/// mountpoint's i_rwsem; inside it: s_umount, then MOUNT_LOCK.
static NAMESPACE_SEM: RwSem<NsTree> = RwSem::new(NsTree {
    unmounted: None,
    ex_mountpoints: BoxList::new(),
});

/// NAMESPACE_SEM held shared
pub type NsRead = RwSemReadGuard<'static, NsTree>;

/// NAMESPACE_SEM held exclusive (Linux namespace_lock): its drop is
/// [`namespace_unlock`]
pub struct NsWrite(core::mem::ManuallyDrop<RwSemWriteGuard<'static, NsTree>>);

impl core::ops::Deref for NsWrite {
    type Target = NsTree;
    fn deref(&self) -> &NsTree {
        &self.0
    }
}

impl core::ops::DerefMut for NsWrite {
    fn deref_mut(&mut self) -> &mut NsTree {
        &mut self.0
    }
}

impl Drop for NsWrite {
    fn drop(&mut self) {
        namespace_unlock(self);
    }
}

/// Take NAMESPACE_SEM for a topology change (Linux namespace_lock)
pub fn namespace_lock() -> NsWrite {
    NsWrite(core::mem::ManuallyDrop::new(NAMESPACE_SEM.write()))
}

/// Release NAMESPACE_SEM (Linux namespace_unlock): what umounts left
/// is taken off first, then the semaphore released; the mountpoints
/// go, then, a grace period later (no fast put that saw a mount in
/// its namespace still runs), the unmounted mounts' references, a
/// last one's teardown queued for this task
fn namespace_unlock(ns: &mut NsWrite) {
    let head = ns.unmounted.take();
    let list = core::mem::take(&mut ns.ex_mountpoints);
    // SAFETY: from NsWrite's drop, once; the guard is not used after
    unsafe { core::mem::ManuallyDrop::drop(&mut ns.0) };
    drop(list);
    let Some(head) = head.filter(|h| !h.is_empty()) else {
        return;
    };
    crate::sync::rcu::synchronize();
    put_umounted(head);
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
crate::owned_adapter!(pub MntListA, Mount, mnt_list, mnt_list_owner);

/// An umount's list of mounts (Linux lists through mnt_list), each
/// entry a reference: under NAMESPACE_SEM write, the unmounted
/// until namespace_unlock puts them
pub type UmountList = OwnedList<MntListA>;

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

    /// Parent mount (Linux mnt_parent): a `Weak`'s raw pointer
    /// (`Weak::into_raw`: no reference to the mount), null for none.
    /// Written under NAMESPACE_SEM write and MOUNT_LOCK write, read
    /// under either, or under RCU with MOUNT_LOCK's sequence checked.
    mnt_parent: AtomicPtr<Mount>,
    /// Where it is mounted (Linux mnt_mountpoint): no reference, the
    /// dentry pinned by its [`Mountpoint`] (m_dentry) while set; null
    /// for none. Set with `mnt_parent`; cleared with it, or (a mount
    /// already unhung) under MOUNT_LOCK alone.
    mnt_mountpoint: AtomicPtr<Dentry>,
    /// Its [`Mountpoint`] (Linux mnt_mp), which counts it: set and
    /// cleared with `mnt_mountpoint`; null for none
    mnt_mp: AtomicPtr<Mountpoint>,
    /// The mount hung on its root (Linux overmount), no reference: set
    /// when one is made visible there, cleared when it leaves; written
    /// under NAMESPACE_SEM write and MOUNT_LOCK write, read under either
    overmount: AtomicPtr<Mount>,

    /// Submounts, each holding a reference (Linux mnt_mounts): changed
    /// under NAMESPACE_SEM write and MOUNT_LOCK, read under either
    mnt_mounts: LockedByEither<OwnedList<MntChild>, NsTree, MntHash>,
    /// On the parent's `mnt_mounts` (Linux mnt_child)
    mnt_child: Link,
    mnt_child_owner: Owner,
    /// On an umount's list (Linux mnt_list: its set, candidates, or the
    /// unmounted), under NAMESPACE_SEM write
    mnt_list: Link,
    mnt_list_owner: Owner,

    /// Per-mount MNT_* flags (Linux mnt_flags): MNT_NOSUID, MNT_NODEV,
    /// MNT_NOEXEC
    mnt_flags: AtomicU32,

    /// Propagation: peer group, peer ring, slaves, master (Linux
    /// mnt_group_id, mnt_share, mnt_slave_list, mnt_slave, mnt_master;
    /// fs/pnode.rs), under NAMESPACE_SEM
    pub(super) prop: LockedBy<super::pnode::PropLinks, NsTree>,
    /// Topology flags (Linux mnt_t_flags: T_UNBINDABLE), written only
    /// under NAMESPACE_SEM write, read lock-free
    t_flags: AtomicU32,
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

    /// The cover it leaves at its parent if both are unmounted at once
    /// and it is locked (Linux mnt_cover, allocated with the mount so
    /// the umount cannot fail): taken once, under MOUNT_LOCK write
    mnt_cover: LockedBy<Option<Arc<MntCover>>, MntHash>,
    /// The covers its unmounted submounts left (Linux mnt_covers): added
    /// under MOUNT_LOCK write, read under RCU by `__lookup_mnt` once this
    /// mount is unmounted, released by its teardown
    mnt_covers: RcuHList<CoverA, MntHash>,

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
        let cover = try_arc(MntCover::new())?;
        let m = try_arc(Self::init(
            sb,
            root,
            flags,
            devname,
            (pcp, PcpSlot::new()?),
            cover,
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
            (pcp, w),
            arc_nofail(MntCover::new()),
            MNT_IDS.alloc(),
        ));
        m.sb.add_mount(&m);
        MountRef::first(m)
    }

    /// A mount with id `mnt_id`, which its drop gives back; `pcp` are
    /// its count's and its writers' parts
    fn init(
        sb: Arc<SuperBlock>,
        root: DentryRef,
        flags: u32,
        devname: super::name::FileName,
        pcp: (PcpSlot, PcpSlot),
        cover: Arc<MntCover>,
        mnt_id: u32,
    ) -> Self {
        let (mnt_pcp, mnt_writers) = pcp;
        Self {
            sb: MntOwned::new(sb),
            root: MntOwned::new(root),
            mnt_parent: AtomicPtr::new(core::ptr::null_mut()),
            mnt_mountpoint: AtomicPtr::new(core::ptr::null_mut()),
            mnt_mp: AtomicPtr::new(core::ptr::null_mut()),
            overmount: AtomicPtr::new(core::ptr::null_mut()),
            mnt_mounts: LockedByEither::new(OwnedList::new()),
            mnt_child: Link::new(),
            mnt_child_owner: Owner::new(),
            mnt_list: Link::new(),
            mnt_list_owner: Owner::new(),
            mnt_flags: AtomicU32::new(flags),
            mnt_writers,
            expiry: core::sync::atomic::AtomicBool::new(false),
            prop: LockedBy::new(super::pnode::PropLinks::new()),
            t_flags: AtomicU32::new(0),
            mnt_ns: AtomicU64::new(0),
            mnt_id,
            mnt_id_unique: MNT_ID_UNIQUE.fetch_add(1, Ordering::Relaxed),
            devname,
            mnt_pcp,
            doomed: AtomicBool::new(false),
            mnt_cover: LockedBy::new(Some(cover)),
            mnt_covers: RcuHList::new(),
            mnt_hash: HNode::new(),
            mnt_puts: RcuPuts::new(),
            mnt_task_work: CallbackHead::new(__cleanup_mnt),
            mnt_rcu: crate::sync::rcu::RcuHead::new(),
            mnt_instance: crate::util::list::Link::new(),
        }
    }

    /// A copy of `self` for a namespace copy into namespace `ns`: same
    /// filesystem, root, flags (not the kernel's: Linux clone_mnt) and
    /// source, new ids, not attached; a peer of `self`, or with CL_SLAVE
    /// in `flag` its slave
    fn copy(&self, g: &mut NsTree, ns: u64, flag: u32) -> MountRef {
        let c = Self::alloc_nofail(
            self.sb.clone(),
            self.root.clone(),
            self.flags() & !MNT_INTERNAL_FLAGS,
            self.devname.clone(),
        );
        c.inherit_t_flags(self);
        c.set_ns(ns);
        super::pnode::clone_links(g, self, &c, flag);
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
        // Only what mount(2) sets changes (Linux set_mount_attributes):
        // the locks and the kernel's state stay, the hold is not seen
        let f = (f & MNT_USER_SETTABLE_MASK) | (self.flags() & !MNT_USER_SETTABLE_MASK);
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

    /// A remount to MNT_* flags `f` keeps every flag a lock holds
    /// (Linux can_change_locked_flags): no lock is ever cleared, so no
    /// lock is needed to read them
    pub fn can_change_locked_flags(&self, f: u32) -> bool {
        let fl = self.flags();
        let keeps = |lock: u32, flag: u32| fl & lock == 0 || f & flag != 0;
        keeps(MNT_LOCK_READONLY, MNT_READONLY)
            && keeps(MNT_LOCK_NODEV, MNT_NODEV)
            && keeps(MNT_LOCK_NOSUID, MNT_NOSUID)
            && keeps(MNT_LOCK_NOEXEC, MNT_NOEXEC)
            && (fl & MNT_LOCK_ATIME == 0 || fl & MNT_ATIME_MASK == f & MNT_ATIME_MASK)
    }

    /// Set (`on`) or clear MNT_* bits that need no other checks, under
    /// MOUNT_LOCK as every mnt_flags write
    pub fn mark(&self, bits: u32, on: bool) {
        self.mark_in(&mut MOUNT_LOCK.write(), bits, on);
    }

    /// [`Mount::mark`] for a holder of MOUNT_LOCK write
    pub(super) fn mark_in(&self, _ml: &mut MntHash, bits: u32, on: bool) {
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

    /// The mountpoint dentry, a new reference, under a lock that holds
    /// the tree's links still (Linux mnt_mountpoint under namespace_sem
    /// or mount_lock)
    pub fn get_mountpoint(&self, _s: &impl Stable) -> Option<DentryRef> {
        let _g = crate::sync::rcu::read_lock();
        let d = self.mnt_mountpoint.load(Ordering::Acquire);
        // SAFETY: a set `mnt_mountpoint` was pinned by its mountpoint
        // when read, and a dentry is freed only a grace period after
        // its last reference goes, which waits for `_g`; `try_get`
        // refuses a dead one
        unsafe { d.as_ref() }.and_then(DentryRef::try_get)
    }

    /// The parent mount, unless it is gone (Linux mnt_parent: a
    /// lazily unmounted parent's teardown may be queued), under a lock
    /// that holds the tree's links still
    pub fn get_parent(&self, s: &impl Stable) -> Option<MountRef> {
        MountRef::try_get_mnt(self.parent_in(s)?)
    }

    /// It hangs on a parent (Linux mnt_has_parent), under a lock that
    /// holds the tree's links still
    pub fn has_parent(&self, _s: &impl Stable) -> bool {
        !self.mnt_parent.load(Ordering::Relaxed).is_null()
    }

    /// Hang it on `parent` at `mp` (Linux mnt_set_mountpoint), under
    /// MOUNT_LOCK write (and NAMESPACE_SEM write): the mountpoint counts
    /// this mount, which names its dentry
    pub(super) fn set_mountpoint(&self, _ml: &mut MntHash, parent: &MountRef, mp: MpPtr) {
        // SAFETY: the caller holds `mp` (a pin or a mount on it), and
        // MOUNT_LOCK, under which alone it is freed
        let m = unsafe { mp.get() };
        m.m_count.fetch_add(1, Ordering::Relaxed);
        let w = Weak::into_raw(MountRef::downgrade(parent)).cast_mut();
        let old = self.mnt_parent.swap(w, Ordering::Release);
        debug_assert!(old.is_null(), "mount: hung twice");
        self.mnt_mp.store(mp.0.as_ptr(), Ordering::Release);
        self.mnt_mountpoint
            .store(DentryRef::as_ptr(&m.m_dentry).cast_mut(), Ordering::Release);
    }

    /// Clear the parent link, and the parent's overmount if it is this
    /// mount (Linux __umount_mnt), under MOUNT_LOCK write (and
    /// NAMESPACE_SEM write); the `Weak` it held is the caller's to drop
    fn take_parent(&self, _ml: &mut MntHash) -> Option<Weak<Mount>> {
        let p = self
            .mnt_parent
            .swap(core::ptr::null_mut(), Ordering::Relaxed);
        // SAFETY: a parent lives while this mount hangs on it (`up`)
        if let Some(parent) = unsafe { p.as_ref() } {
            let me = core::ptr::from_ref(self).cast_mut();
            let _ = parent.overmount.compare_exchange(
                me,
                core::ptr::null_mut(),
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        }
        // SAFETY: a set link came from `Weak::into_raw` (`set_mountpoint`)
        // and is given back once, here
        (!p.is_null()).then(|| unsafe { Weak::from_raw(p) })
    }

    /// Clear the mountpoint links, under MOUNT_LOCK: the mountpoint they
    /// named, which still counts this mount until the caller's
    /// `put_mp`
    fn take_mountpoint(&self, _ml: &MntHash) -> Option<MpPtr> {
        self.mnt_mountpoint
            .store(core::ptr::null_mut(), Ordering::Relaxed);
        let mp = self.mnt_mp.swap(core::ptr::null_mut(), Ordering::Relaxed);
        NonNull::new(mp).map(MpPtr)
    }

    /// Its mountpoint (Linux mnt_mp), under a lock that holds the tree's
    /// links still: None for a mount on no parent. It stays while the
    /// lock is held (the mount counts it, and leaves it only under
    /// MOUNT_LOCK, or once off its parent).
    pub(super) fn mp_in(&self, _s: &impl Stable) -> Option<MpPtr> {
        if self.mnt_parent.load(Ordering::Relaxed).is_null() {
            return None;
        }
        NonNull::new(self.mnt_mp.load(Ordering::Relaxed)).map(MpPtr)
    }

    /// Where it is mounted (Linux mnt_mountpoint), for comparison or a
    /// lookup under a lock that holds the tree's links still: null for
    /// none
    pub(super) fn mountpoint_in(&self, _s: &impl Stable) -> *const Dentry {
        self.mnt_mountpoint.load(Ordering::Relaxed).cast_const()
    }

    /// The mount on its root (Linux overmount), null for none, under a
    /// lock that holds the tree's links still
    pub(super) fn overmount_in(&self, _s: &impl Stable) -> *const Mount {
        self.overmount.load(Ordering::Relaxed).cast_const()
    }

    /// Its submounts, borrowed from the lock that holds them still
    pub(super) fn kids_in<'a>(
        &'a self,
        s: &'a impl Stable,
    ) -> crate::util::list::Iter<'a, MntChild> {
        s.mounts(self).iter()
    }

    /// The parent mount and the mountpoint in it, borrowed from a
    /// locking read of MOUNT_LOCK (Linux mnt_parent, mnt_mountpoint
    /// under mount_lock): no reference taken. None for a mount on no
    /// parent.
    pub fn up<'a>(&'a self, _ml: &'a MntHash) -> Option<(&'a Mount, &'a Dentry)> {
        let parent = self.mnt_parent.load(Ordering::Relaxed).cast_const();
        let mp = self.mnt_mountpoint.load(Ordering::Relaxed).cast_const();
        if parent.is_null() || mp.is_null() {
            return None;
        }
        // SAFETY: both links change only under MOUNT_LOCK (attach_mnt,
        // detach_mnt, a teardown's unhang_children and put_unhung, the
        // last clearing the mountpoint only once the parent link is gone
        // for good), so they stay while `_ml` is held and `self` lives.
        // The mountpoint is pinned by its `Mountpoint` while set. The
        // parent's memory is kept by a counted
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
        let parent = self.mnt_parent.load(Ordering::Acquire).cast_const();
        let mp = self.mnt_mountpoint.load(Ordering::Acquire).cast_const();
        if parent.is_null() || mp.is_null() {
            return None;
        }
        // SAFETY: each link was set when read under the guard: the parent
        // then still had `self` hung on it, and is freed only a grace
        // period after its teardown, which unhangs `self` first
        // (`kfree_rcu` in `__cleanup_mnt`); the mountpoint was then
        // pinned by its `Mountpoint`, and a dentry is freed only a grace
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
    pub(super) fn parent_in<'a>(&'a self, _s: &'a impl Stable) -> Option<&'a Mount> {
        let p = self.mnt_parent.load(Ordering::Relaxed);
        // SAFETY: as above: while `_s` is held the link stays and the
        // parent, which still has `self` hung on it, lives
        unsafe { p.as_ref() }
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
    /// copy_tree with CL_COPY_UNBINDABLE): peers of the originals, or
    /// with `slave` (a copy for another user namespace) their slaves
    /// (CL_SLAVE).
    ///
    /// This is used by CLONE_NEWNS to give a new mount namespace its
    /// own view of the mount hierarchy. A submount's copy keeps
    /// MNT_LOCKED, the root's does not (Linux copy_tree); a copy for
    /// another user namespace is locked whole (lock_mnt_tree).
    pub fn clone_tree(root: &MountRef, ns: u64, slave: bool) -> (MountRef, MountMap) {
        let flag = if slave { super::pnode::CL_SLAVE } else { 0 };
        let mut g = namespace_lock();
        let new_root = root.copy(&mut g, ns, flag);
        let mut map = alloc::vec![(root.clone(), new_root.clone())];
        copy_below(&mut g, root, &new_root, |g, o| {
            let c = o.copy(g, ns, flag);
            if o.flags() & MNT_LOCKED != 0 {
                c.mark(MNT_LOCKED, true);
            }
            map.push((o.clone(), c.clone()));
            c
        });
        if slave {
            lock_mnt_tree(&g, &new_root);
        }
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
        let parent = p.get_parent(s)?;
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
    mut copy: impl FnMut(&mut NsTree, &MountRef) -> MountRef,
) {
    let (mut p, mut q) = (src.clone(), top.clone());
    let mut next = next_mnt(src, src, &*ns);
    while let Some(s) = next {
        // An attached mount has both, set together under MOUNT_LOCK
        let sp = s
            .get_parent(&*ns)
            .expect("mount: submount without a parent");
        let mp = s.mp_in(&*ns).expect("mount: submount without a mountpoint");
        while !MountRef::ptr_eq(&p, &sp) {
            let (Some(pp), Some(qp)) = (p.get_parent(&*ns), q.get_parent(&*ns)) else {
                unreachable!("mount: copy cursor climbed past the top");
            };
            (p, q) = (pp, qp);
        }
        let c = copy(ns, &s);
        attach_mnt(ns, c.clone(), &q, mp);
        (p, q) = (s, c);
        next = next_mnt(&p, src, &*ns);
    }
}

/// What an unmounted locked mount leaves at its unmounted parent
/// instead of staying hung there (Linux struct mnt_cover): a lookup on
/// the parent at the mountpoint finds a stand-in, so what the mount hid
/// stays hidden. The cover counts its mountpoint, which keeps the
/// dentry; the parent's teardown releases both.
pub struct MntCover {
    /// On the parent's `mnt_covers` (Linux node), read under RCU
    node: HNode,
    /// The mountpoint dentry, for comparison only (Linux dentry): set
    /// before the cover is linked, under MOUNT_LOCK write
    dentry: AtomicPtr<Dentry>,
    /// Its mountpoint, counted (Linux mp; m_covers' pin)
    mp: AtomicPtr<Mountpoint>,
    /// The free a grace period after it leaves its list
    rcu: crate::sync::rcu::RcuHead,
}

impl MntCover {
    fn new() -> Self {
        Self {
            node: HNode::new(),
            dentry: AtomicPtr::new(core::ptr::null_mut()),
            mp: AtomicPtr::new(core::ptr::null_mut()),
            rcu: crate::sync::rcu::RcuHead::new(),
        }
    }
}

crate::hadapter!(CoverA, MntCover, node);
crate::rcu_head!(MntCover, rcu);

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

/// A [`Mountpoint`] held by a mount on it or a pin (its `m_count`), so
/// it stays in the hash (Linux struct mountpoint *)
#[derive(Clone, Copy)]
pub(super) struct MpPtr(NonNull<Mountpoint>);

// SAFETY: names a Mountpoint (a dentry reference and a counter, both
// Sync), dereferenced only under MOUNT_LOCK or NAMESPACE_SEM
unsafe impl Send for MpPtr {}
// SAFETY: as above
unsafe impl Sync for MpPtr {}

impl MpPtr {
    /// The mountpoint, borrowed
    ///
    /// # Safety
    /// It is still counted (a mount on it or a pin), and stays so for the
    /// borrow: the caller holds MOUNT_LOCK, or NAMESPACE_SEM while a
    /// mount on it is hung there.
    unsafe fn get<'a>(self) -> &'a Mountpoint {
        // SAFETY: the caller's contract: a counted mountpoint is in the
        // hash, which owns its box, until its count reaches zero under
        // MOUNT_LOCK
        unsafe { self.0.as_ref() }
    }

    /// The dentry, a new reference (Linux dget(mp->m_dentry))
    ///
    /// # Safety
    /// As [`MpPtr::get`].
    pub(super) unsafe fn dentry(self) -> DentryRef {
        // SAFETY: the caller's contract
        unsafe { self.get() }.m_dentry.clone()
    }
}

/// A pin on a mountpoint (Linux pinned_mountpoint): it stays in the hash
/// until [`unpin_mountpoint`], under MOUNT_LOCK
#[must_use]
pub(super) struct MpPin(MpPtr);

impl MpPin {
    pub(super) fn mp(&self) -> MpPtr {
        self.0
    }
}

/// The mountpoint of `d`, if one exists (Linux lookup_mountpoint)
fn lookup_mountpoint(ml: &MntHash, d: &Dentry) -> Option<MpPtr> {
    mp_hash(d)
        .access(ml)
        .iter()
        .find(|mp| core::ptr::eq(DentryRef::as_ptr(&mp.m_dentry), d))
        .map(|mp| MpPtr(NonNull::from(mp)))
}

/// Pin `d`'s mountpoint, made if it has none (Linux get_mountpoint,
/// d_set_mounted): a new one is allocated outside MOUNT_LOCK, and the
/// lookup repeated (one may have come or gone meanwhile); one left over
/// goes after the unlock
pub(super) fn get_mountpoint(d: &DentryRef) -> MpPin {
    let mut new: Option<Box<Mountpoint>> = None;
    loop {
        let pinned = {
            let mut ml = MOUNT_LOCK.read_excl();
            if let Some(mp) = lookup_mountpoint(&ml, d) {
                Some(pin_mp(&mut ml, mp))
            } else if let Some(b) = new.take() {
                b.m_count.store(1, Ordering::Relaxed);
                d.set_mounted(true);
                let mp = MpPtr(NonNull::from(&*b));
                mp_hash(DentryRef::as_ptr(d))
                    .access_mut(&mut ml)
                    .push_back(b);
                Some(MpPin(mp))
            } else {
                None
            }
        };
        if let Some(p) = pinned {
            drop(new);
            return p;
        }
        new = Some(crate::util::kalloc::box_nofail(Mountpoint {
            m_hash: Link::new(),
            m_dentry: d.clone(),
            m_count: AtomicU32::new(0),
        }));
    }
}

/// Pin a mountpoint that is counted already (Linux pinning old_mp for
/// pivot_root); under MOUNT_LOCK
fn pin_mp(_ml: &mut MntHash, mp: MpPtr) -> MpPin {
    // SAFETY: counted (the caller's contract), under MOUNT_LOCK
    unsafe { mp.get() }.m_count.fetch_add(1, Ordering::Relaxed);
    MpPin(mp)
}

/// Let go of a pin (Linux unpin_mountpoint); under MOUNT_LOCK, the
/// mountpoint handed back by a last one is the caller's to drop after
/// the unlock
pub(super) fn unpin_mountpoint(ml: &mut MntHash, p: MpPin) -> Option<Box<Mountpoint>> {
    put_mp(ml, p.0)
}

/// A mount or pin left `mp` (Linux maybe_free_mountpoint); under
/// MOUNT_LOCK: the last one takes the mountpoint out and unmarks the
/// dentry, and hands it back to be dropped (its dentry put) after the
/// unlock
fn put_mp(ml: &mut MntHash, mp: MpPtr) -> Option<Box<Mountpoint>> {
    // SAFETY: counted by what leaves it here, under MOUNT_LOCK
    let m = unsafe { mp.get() };
    if m.m_count.fetch_sub(1, Ordering::Relaxed) != 1 {
        return None;
    }
    m.m_dentry.set_mounted(false);
    mp_hash(DentryRef::as_ptr(&m.m_dentry))
        .access_mut(ml)
        .remove_first(|e| core::ptr::eq(e, mp.0.as_ptr()))
}

/// The child of `parent` mounted on `d` (Linux __lookup_mnt): one walk
/// of its hash chain under an RCU read guard, comparing each entry's
/// `parent` and `mountpoint`, which a lockless caller checks with
/// MOUNT_LOCK's sequence after. An unmounted `parent` with a cover left
/// at `d` gives the stand-in: the kernel's nullfs for a directory, its
/// file for anything else.
pub(super) fn __lookup_mnt<'g>(
    parent: &Mount,
    d: &Dentry,
    g: &'g RcuReadGuard,
) -> Option<&'g Mount> {
    let c = m_hash(parent, d).iter(g).find(|c| {
        core::ptr::eq(c.mnt_parent.load(Ordering::Acquire), parent)
            && core::ptr::eq(c.mnt_mountpoint.load(Ordering::Acquire), d)
    });
    if c.is_some() {
        return c;
    }
    // A stale flag is harmless: a lockless caller rechecks the sequence
    // after a miss
    if parent.mnt_flags.load(Ordering::Relaxed) & MNT_UMOUNT == 0 {
        return None;
    }
    let dp = core::ptr::from_ref(d).cast_mut();
    if !parent
        .mnt_covers
        .iter(g)
        .any(|c| c.dentry.load(Ordering::Acquire) == dp)
    {
        return None;
    }
    let dir = d.get_inode().is_some_and(|i| i.mode().is_dir());
    let stand_in = if dir { &KNULLFS } else { &KNULLFS_FILE };
    stand_in.get().map(|m| &**m)
}

/// Take `m` out of the mount hash (Linux hlist_del_init_rcu of
/// mnt_hash), before its `parent` or `mountpoint` changes; under
/// MOUNT_LOCK write. The chain's reference goes a grace period later.
fn unhash_mnt(ml: &mut MntHash, m: &Mount) {
    let p = m.mnt_parent.load(Ordering::Relaxed).cast_const();
    let d = m.mnt_mountpoint.load(Ordering::Relaxed).cast_const();
    if !p.is_null()
        && !d.is_null()
        && let Some(r) = m_hash(p, d).del_init(m, ml)
    {
        r.defer_put();
    }
}

/// The kernel threads' nullfs mount (Linux knullfs, an internal mount)
static KNULLFS: spin::Once<MountRef> = spin::Once::new();

/// A second mount of knullfs's superblock rooted on its regular file
/// (Linux knullfs_file): a cover's stand-in for a mount on a file
static KNULLFS_FILE: spin::Once<MountRef> = spin::Once::new();

/// The initial mount tree (Linux init_mount_tree, 7.0+): a nullfs mount
/// (id 1) is the namespace root and the mutable rootfs, a tmpfs under
/// the type name "rootfs" (id 2), is mounted on it. Root and cwd go to the rootfs, so it can be
/// pivoted away or unmounted like any other mount. Then the private
/// nullfs kernel threads start in (id 3, Linux 7.3 knullfs), and a
/// mount of it on its regular file (id 4, Linux 7.4 knullfs_file), the
/// stand-ins a cover shows. Returns the rootfs.
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
    let file = super::nullfs::new_file(&ksb)?;
    let k = Mount::alloc(ksb.clone(), root, MNT_READONLY, b"nullfs".as_slice().into())?;
    k.set_internal();
    super::fsstruct::kthread_fs_init(k.clone());
    KNULLFS.call_once(|| k);
    // Linux knullfs_file_mount: writable, so a write to it is dropped
    let f = Mount::alloc(ksb, file, 0, b"nullfs".as_slice().into())?;
    f.set_internal();
    KNULLFS_FILE.call_once(|| f);
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
        let mut l = lock_mount(&mp)?;
        // Linux do_add_mount
        if !check_mnt(&l.at.mnt) {
            return Err(KernelError::InvalidArgument);
        }
        graft(&mut l.ns, mount.clone(), &l.at)?;
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
    let id = m.parent_in(ns).map_or(0, Mount::ns);
    for t in walk(m, ns) {
        t.set_ns(id);
    }
}

/// A new mount of `m`'s filesystem rooted at `root`, with its flags
/// and source, in propagation as `flag` says (Linux clone_mnt); not
/// attached
fn clone_mnt(ns: &mut NsTree, m: &Mount, root: DentryRef, flag: u32) -> MountRef {
    let c = Mount::alloc_nofail(
        m.sb.clone(),
        root,
        m.flags() & !MNT_INTERNAL_FLAGS,
        m.devname.clone(),
    );
    c.inherit_t_flags(m);
    super::pnode::clone_links(ns, m, &c, flag);
    c
}

/// `f` on `root` and every mount below it, parents first, by
/// [`next_mnt`], with the guard free for `f` to change propagation
/// under
pub(super) fn for_each_mut(
    ns: &mut NsTree,
    root: &MountRef,
    mut f: impl FnMut(&mut NsTree, &MountRef),
) {
    let mut t = Some(root.clone());
    while let Some(c) = t {
        f(ns, &c);
        t = next_mnt(&c, root, &*ns);
    }
}

/// One mount [`copy_tree`] copies: its source, the entry of the copy
/// it hangs on, and where (the copy's root for the top)
pub(super) struct CopyEnt {
    src: MountRef,
    parent: usize,
    at: DentryRef,
}

/// What copy_tree copies of `m` at `root`, parents first: the mounts
/// below `root`; an unbindable submount is left out with whatever is
/// under it, EPERM if it is also locked (it hides what is under it)
pub(super) fn copy_plan(
    ns: &NsTree,
    m: &MountRef,
    root: &DentryRef,
) -> Result<Vec<CopyEnt>, KernelError> {
    let mut plan = alloc::vec![CopyEnt {
        src: m.clone(),
        parent: 0,
        at: root.clone(),
    }];
    let mut i = 0;
    while i < plan.len() {
        let src = plan[i].src.clone();
        for c in src.kids(ns) {
            let Some(mp) = c.get_mountpoint(ns) else {
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

/// The copies of `plan` (Linux copy_tree), each in propagation as
/// `flag` says: the top loses MNT_LOCKED (clone_mnt), a submount keeps
/// it (it still hides what is under it); under NAMESPACE_SEM write
pub(super) fn copy_tree(ns: &mut NsTree, plan: &[CopyEnt], flag: u32) -> MountRef {
    let mut out: Vec<MountRef> = Vec::new();
    for (k, e) in plan.iter().enumerate() {
        let root = if k == 0 { &e.at } else { &e.src.root };
        let n = clone_mnt(ns, &e.src, root.clone(), flag);
        if k > 0 {
            if e.src.flags() & MNT_LOCKED != 0 {
                n.mark(MNT_LOCKED, true);
            }
            // On its source's mountpoint (Linux copy_tree's
            // attach_mnt on src_parent->mnt_mp)
            let mp = e
                .src
                .mp_in(&*ns)
                .expect("mount: submount without a mountpoint");
            attach_mnt(ns, n.clone(), &out[e.parent], mp);
        }
        out.push(n);
    }
    out.swap_remove(0)
}

/// The tree at `m` goes to a less privileged user namespace (Linux
/// lock_mnt_tree): each mount's atime flags and each of its read-only,
/// nodev, nosuid and noexec flags are locked on, and every mount below
/// `m` is MNT_LOCKED, so what it hides stays hidden; under
/// NAMESPACE_SEM
fn lock_mnt_tree(ns: &NsTree, m: &Mount) {
    let _ml = MOUNT_LOCK.write();
    for_each_mnt(m, ns, |p| {
        let fl = p.flags();
        let mut add = MNT_LOCK_ATIME;
        for (flag, lock) in [
            (MNT_READONLY, MNT_LOCK_READONLY),
            (MNT_NODEV, MNT_LOCK_NODEV),
            (MNT_NOSUID, MNT_LOCK_NOSUID),
            (MNT_NOEXEC, MNT_LOCK_NOEXEC),
        ] {
            if fl & flag != 0 {
                add |= lock;
            }
        }
        if !core::ptr::eq(p, m) {
            add |= MNT_LOCKED;
        }
        p.mnt_flags.fetch_or(add, Ordering::SeqCst);
    });
}

/// A mount under `d` in `m` is locked (Linux has_locked_children): a
/// bind of `d` alone would uncover what it hides
fn has_locked_children(ns: &NsTree, m: &Mount, d: &DentryRef) -> bool {
    m.kids(ns).any(|c| {
        c.get_mountpoint(ns)
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
    let mut l = lock_mount(mp)?;
    let (ns, mp): (&mut NsTree, _) = (&mut l.ns, &l.at);
    if !check_mnt(&mp.mnt) || old.mnt.is_unbindable() || !check_mnt(&old.mnt) {
        return Err(KernelError::InvalidArgument);
    }
    if !rec && has_locked_children(ns, &old.mnt, &old.dentry) {
        return Err(KernelError::InvalidArgument);
    }
    let plan = if rec {
        copy_plan(ns, &old.mnt, &old.dentry)?
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
    let t = copy_tree(ns, &plan, 0);
    graft(ns, t, mp)
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

/// The references umount's caller and the tree hold on its target
/// (Linux do_umount's propagate_mount_busy(mnt, 2)): the caller's and
/// the parent's (a propagated copy: the parent's alone)
const UMOUNT_REFS: isize = 2;

/// [`umount_tree`]: a synchronous umount (Linux UMOUNT_SYNC)
const UMOUNT_SYNC: u32 = 1;
/// [`umount_tree`]: what propagation takes goes too (Linux
/// UMOUNT_PROPAGATE)
const UMOUNT_PROPAGATE: u32 = 2;

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
    {
        let mut ns = namespace_lock();
        let mut ml = MOUNT_LOCK.write();
        // Linux: repeated now that the locks are held
        if !check_mnt(&mount) || mount.flags() & MNT_LOCKED != 0 || !mount.has_parent(&*ns) {
            return Err(KernelError::InvalidArgument);
        }
        if detach {
            umount_tree(&mut ns, &mut ml, &mount, UMOUNT_PROPAGATE);
        } else {
            if super::pnode::propagate_mount_busy(&ns, &mut ml, &mount, UMOUNT_REFS) {
                return Err(KernelError::Busy);
            }
            umount_tree(&mut ns, &mut ml, &mount, UMOUNT_PROPAGATE | UMOUNT_SYNC);
        }
        // MOUNT_LOCK, then NAMESPACE_SEM (namespace_unlock: the
        // references put a grace period later by this task, so a last
        // one's teardown runs before the syscall returns)
    }

    // Write the filesystem back, outside namespace_sem: writeback takes
    // inode locks, which nest outside it (Linux: deactivate_super ->
    // sync_filesystem after namespace_unlock)
    let _ = super::fs_writeback::writeback_sb(&mount.sb);
    Ok(())
}

/// A mount namespace's last reference went (Linux put_mnt_ns): its whole
/// tree is unmounted at once (Linux umount_tree of the root, no
/// propagation) under NAMESPACE_SEM write and MOUNT_LOCK write; a grace
/// period after the unlock (Linux namespace_unlock) the tree's
/// references are put, then the caller's to the root, which may sleep.
/// A mount still used elsewhere (an open file, another task's cwd)
/// lives on, detached.
pub fn put_mnt_ns(root: MountRef) {
    {
        let mut ns = namespace_lock();
        umount_tree(&mut ns, &mut MOUNT_LOCK.write(), &root, 0);
    }
    drop(root);
}

/// Unmount the tree at `mnt` (Linux umount_tree), under NAMESPACE_SEM
/// write and MOUNT_LOCK write throughout: each of its mounts is marked
/// MNT_UMOUNT and taken off its parent's list, and with
/// UMOUNT_PROPAGATE what propagation takes along joins them; all leave
/// propagation together (bulk_make_private), then each leaves its
/// namespace and comes off its parent and mountpoint. Nothing is put or
/// freed that may sleep: each mount's reference goes on the unmounted
/// list, a last mountpoint on ex_mountpoints, both released by
/// [`namespace_unlock`], the references a grace period later (none may
/// be put by the exact path before).
fn umount_tree(ns: &mut NsTree, ml: &mut MntHash, mnt: &Mount, how: u32) {
    if how & UMOUNT_PROPAGATE != 0 {
        super::pnode::propagate_mount_unlock(ns, ml, mnt);
    }
    // Gather the mounts to umount
    let mut set = UmountList::new();
    for_each_mnt(mnt, &*ns, |p| {
        // A mount is unmounted once
        debug_assert_eq!(p.flags() & MNT_UMOUNT, 0, "mount: unmounted twice");
        p.mnt_flags.fetch_or(MNT_UMOUNT, Ordering::SeqCst);
        set.push_back(MountRef::entry_ref(p).into_entry());
    });
    // Hide them from their parents' lists; the set's references keep
    // them
    for p in set.iter() {
        if let Some(e) = unlist(ns, ml, p) {
            // SAFETY: entries of mnt_mounts are references (`attach_mnt`)
            unsafe { MountRef::from_entry(e) }.put_held();
        }
    }
    // Add propagated mounts to the set
    if how & UMOUNT_PROPAGATE != 0 {
        super::pnode::propagate_umount(ns, ml, &mut set);
    }
    super::pnode::bulk_make_private(ns, &set);
    while let Some(p) = set.pop_front() {
        p.set_ns(0);
        if how & UMOUNT_SYNC != 0 {
            p.mnt_flags.fetch_or(MNT_SYNC_UMOUNT, Ordering::SeqCst);
        }
        if p.has_parent(&*ml) {
            if needs_cover(ml, &p, how) {
                leave_cover(ml, &p);
            }
            umount_mnt(ns, ml, &p);
        }
        ns.add_unmounted(p);
    }
}

/// Take `m` off its parent's list (Linux list_del_init of mnt_child),
/// under both locks: the list's reference, None if it is on none
fn unlist(ns: &mut NsTree, ml: &mut MntHash, m: &Mount) -> Option<Arc<Mount>> {
    let p = m.mnt_parent.load(Ordering::Relaxed).cast_const();
    // SAFETY: a parent lives while `m` hangs on it (`up`)
    let parent = unsafe { p.as_ref() }?;
    parent.mnt_mounts.access_mut(ns, ml).remove(m)
}

/// `m` committed to unmounting (Linux umount_one's MNT_UMOUNT and
/// list_del_init of mnt_child), under NAMESPACE_SEM write and
/// MOUNT_LOCK write; the caller holds a reference past the list's
pub(super) fn hide_mnt(ns: &mut NsTree, ml: &mut MntHash, m: &Mount) {
    m.mnt_flags.fetch_or(MNT_UMOUNT, Ordering::SeqCst);
    if let Some(e) = unlist(ns, ml, m) {
        // SAFETY: entries of mnt_mounts are references (`attach_mnt`)
        unsafe { MountRef::from_entry(e) }.put_held();
    }
}

/// Move `m` onto `to` at `mp` (Linux mnt_change_mountpoint, for
/// propagate_umount's reparent), under NAMESPACE_SEM write and
/// MOUNT_LOCK write: a last old mountpoint goes on ex_mountpoints
pub(super) fn change_mountpoint(
    ns: &mut NsTree,
    ml: &mut MntHash,
    to: &MountRef,
    mp: MpPtr,
    m: &Mount,
) {
    let (w, old) = mnt_change_mountpoint(ns, ml, to, mp, m);
    // The old parent link's `Weak`: at most a free (Linux kfree under
    // mount_lock), never a teardown
    drop(w);
    if let Some(b) = old {
        ns.ex_mountpoints.push_back(b);
    }
}

/// `m` off its parent and mountpoint, out of the mount hash (Linux
/// umount_mnt; already off the parent's list), under NAMESPACE_SEM
/// write and MOUNT_LOCK write: a last mountpoint goes on
/// ex_mountpoints
fn umount_mnt(ns: &mut NsTree, ml: &mut MntHash, m: &Mount) {
    unhash_mnt(ml, m);
    // The parent link's `Weak`: at most a free (Linux kfree under
    // mount_lock), never a teardown
    drop(m.take_parent(ml));
    if let Some(mp) = m.take_mountpoint(ml) {
        ns.maybe_free_mountpoint(ml, mp);
    }
}

/// `m`, unmounted with its parent, must leave the mountpoint covered
/// (Linux needs_cover): not for a synchronous umount (nothing held it),
/// only when the parent goes too and `m` is locked; under MOUNT_LOCK
fn needs_cover(ml: &MntHash, m: &Mount, how: u32) -> bool {
    if how & UMOUNT_SYNC != 0 {
        return false;
    }
    m.parent_in(ml)
        .is_some_and(|p| p.flags() & MNT_UMOUNT != 0 && m.flags() & MNT_LOCKED != 0)
}

/// Leave `m`'s cover at its parent before `m` comes off it (Linux
/// leave_cover): a lookup on the parent at the mountpoint keeps finding
/// a mount instead of what `m` covered; the cover counts the
/// mountpoint, which `m` lets go of next. Under MOUNT_LOCK write.
fn leave_cover(ml: &mut MntHash, m: &Mount) {
    let (Some(cover), Some(mp)) = (m.mnt_cover.access_mut(ml).take(), m.mp_in(&*ml)) else {
        return;
    };
    // SAFETY: `m` still counts it, under MOUNT_LOCK
    unsafe { mp.get() }.m_count.fetch_add(1, Ordering::Relaxed);
    cover.mp.store(mp.0.as_ptr(), Ordering::Relaxed);
    cover
        .dentry
        .store(m.mountpoint_in(&*ml).cast_mut(), Ordering::Release);
    let p = m.mnt_parent.load(Ordering::Relaxed);
    // SAFETY: `m` hangs on it (`mp_in` saw the link), so it lives
    let parent = unsafe { &*p };
    parent.mnt_covers.add_head(cover, ml);
}

/// Put the references on an umount's list (Linux namespace_unlock's
/// mntput of each unmounted mount)
fn put_umounted(mut l: UmountList) {
    while let Some(e) = l.pop_front() {
        // SAFETY: umount list entries are references (`into_entry`)
        drop(unsafe { MountRef::from_entry(e) });
    }
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
    let parent = m.get_parent(&*ns);
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
    let w = m.take_parent(&mut ml);
    // The put hands back a last one to drop after the unlock
    let gone = m.take_mountpoint(&ml).and_then(|mp| put_mp(&mut ml, mp));
    drop(ml);
    drop(gone);
    drop(w);
    link
}

/// Hang `m` on `parent` at `mp`, which the caller holds (Linux
/// attach_mnt, under lock_mount_hash: here MOUNT_LOCK, for the walks
/// that check its sequence); under NAMESPACE_SEM write
pub(super) fn attach_mnt(ns: &mut NsTree, m: MountRef, parent: &MountRef, mp: MpPtr) {
    let mut ml = MOUNT_LOCK.write();
    m.set_mountpoint(&mut ml, parent, mp);
    make_visible(ns, &mut ml, m);
}

/// `m`, just hung on its parent, joins the tree (Linux make_visible):
/// its parent's overmount if it is on the parent's root, in the mount
/// hash, and on the parent's list, with the caller's reference
fn make_visible(ns: &mut NsTree, ml: &mut MntHash, m: MountRef) {
    let p = m.mnt_parent.load(Ordering::Relaxed).cast_const();
    let d = m.mnt_mountpoint.load(Ordering::Relaxed).cast_const();
    // SAFETY: just hung there by the caller under these locks: the
    // parent lives while `m` hangs on it (`up`)
    let parent = unsafe { &*p };
    if core::ptr::eq(d, parent.root_addr()) {
        parent
            .overmount
            .store(MountRef::as_ptr(&m).cast_mut(), Ordering::Relaxed);
    }
    m_hash(p, d).add_head(MountRef::arc_of(&m), ml);
    parent
        .mnt_mounts
        .access_mut(ns, ml)
        .push_back(m.into_entry());
}

/// Move `m` onto `parent` at `mp`, which the caller holds (Linux
/// mnt_change_mountpoint): off its old parent's list and the hash, on
/// the new ones, with the reference the old list held; under
/// NAMESPACE_SEM write and MOUNT_LOCK write. What is left of the old
/// links is the caller's to drop after the unlock.
fn mnt_change_mountpoint(
    ns: &mut NsTree,
    ml: &mut MntHash,
    parent: &MountRef,
    mp: MpPtr,
    m: &Mount,
) -> (Option<Weak<Mount>>, Option<Box<Mountpoint>>) {
    unhash_mnt(ml, m);
    let old = m.mnt_parent.load(Ordering::Relaxed).cast_const();
    // SAFETY: `m` hangs on it (the caller's contract), so it lives
    let old = unsafe { &*old };
    let entry = old
        .mnt_mounts
        .access_mut(ns, ml)
        .remove(m)
        .expect("mount: a mount moved off a parent it is not on");
    // SAFETY: entries of mnt_mounts are references (`attach_mnt`)
    let m = unsafe { MountRef::from_entry(entry) };
    let w = m.take_parent(ml);
    let old_mp = m.take_mountpoint(ml);
    m.set_mountpoint(ml, parent, mp);
    make_visible(ns, ml, m);
    (w, old_mp.and_then(|o| put_mp(ml, o)))
}

/// The topmost mount stacked on `m`'s root (Linux topmost_overmount),
/// borrowed from the lock `_s` holds the tree still with
pub(super) fn topmost_overmount<'a>(m: &'a Mount, _s: &'a impl Stable) -> &'a Mount {
    let mut m = m;
    loop {
        let o = m.overmount.load(Ordering::Relaxed);
        // SAFETY: an overmount hangs on `m`, which keeps it (its list
        // entry) until it leaves under both locks, one of them held
        match unsafe { o.as_ref() } {
            Some(o) => m = o,
            None => return m,
        }
    }
}

/// [`attach_mnt`] at `at`, its mountpoint pinned meanwhile (Linux
/// lock_mount's get_mountpoint around the attach); under NAMESPACE_SEM
/// write
pub(super) fn attach_at(ns: &mut NsTree, m: MountRef, at: &Path) {
    let pin = get_mountpoint(&at.dentry);
    attach_mnt(ns, m, &at.mnt, pin.mp());
    let gone = unpin_mountpoint(&mut MOUNT_LOCK.read_excl(), pin);
    drop(gone);
}

/// Hang the tree at `t` on `at` and, under a shared mount, propagate
/// it (Linux attach_recursive_mnt): the tree gets peer groups, its
/// copies are made and hung on their mountpoints before any of them
/// joins the namespace, so the propagation walk passes them by; then
/// the original and each copy join it in turn. One that lands where a
/// mount already is goes under it: that mount moves onto the root of
/// the topmost mount of the new tree's root (Linux's tucking), taking
/// its lock along. A copy in a namespace of another user namespace is
/// locked (lock_mnt_tree). Under NAMESPACE_SEM write.
fn graft(ns: &mut NsTree, t: MountRef, at: &Path) -> Result<(), KernelError> {
    let source = MountRef::clone(&t);
    // A mountpoint for where a mount tucked under goes (Linux: get
    // before anything is done)
    let top_root = topmost_overmount(&source, &*ns).root.clone();
    let root = get_mountpoint(&top_root);
    let dest = get_mountpoint(&at.dentry);
    let shared = super::pnode::is_shared(ns, &at.mnt);
    let ids = if shared {
        super::pnode::invent_group_ids(ns, &source, true)
    } else {
        Ok(())
    };
    if let Err(e) = ids {
        unpin_both(root, dest);
        return Err(e);
    }
    let copies = if shared {
        super::pnode::propagate_mnt(ns, &at.mnt, dest.mp(), &source)
    } else {
        Vec::new()
    };
    if shared {
        // Linux set_mnt_shared over the source tree
        for t in walk(&source, &*ns) {
            t.set_unbindable(false);
        }
    }
    // The original now in its copies' state: on its mountpoint, not
    // visible (Linux mnt_set_mountpoint)
    source.set_mountpoint(&mut MOUNT_LOCK.write(), &at.mnt, dest.mp());
    // The original first, then the copies newest first (Linux tree_list)
    let dest_ns = at.mnt.ns();
    for child in core::iter::once(t).chain(copies.into_iter().rev()) {
        let is_source = MountRef::ptr_eq(&child, &source);
        commit_one(ns, child, is_source, root.mp(), dest_ns);
    }
    unpin_both(root, dest);
    Ok(())
}

/// Let go of graft's pins, after MOUNT_LOCK what they leave
fn unpin_both(a: MpPin, b: MpPin) {
    let gone = {
        let mut ml = MOUNT_LOCK.read_excl();
        (unpin_mountpoint(&mut ml, a), unpin_mountpoint(&mut ml, b))
    };
    drop(gone);
}

/// One mount of graft's list joins the namespace and the tree (Linux
/// attach_recursive_mnt's loop over tree_list: __lookup_mnt, then
/// commit_tree, then a mount found there tucked over `child`'s topmost
/// overmount at `root_mp`); under NAMESPACE_SEM write
fn commit_one(ns: &mut NsTree, child: MountRef, is_source: bool, root_mp: MpPtr, dest_ns: u64) {
    // Propagated into a namespace of another user namespace (Linux:
    // its parent's mnt_ns->user_ns not the destination's)
    let pns = child.parent_in(&*ns).map_or(0, Mount::ns);
    if pns != dest_ns && !crate::ns::mnt_ns_same_owner(pns, dest_ns) {
        lock_mnt_tree(ns, &child);
    }
    let q = {
        let _ml = MOUNT_LOCK.read_excl();
        let p = child.mnt_parent.load(Ordering::Relaxed).cast_const();
        let d = child.mnt_mountpoint.load(Ordering::Relaxed).cast_const();
        let g = crate::sync::rcu::read_lock();
        // SAFETY: just hung there under NAMESPACE_SEM, which is held: the
        // parent lives while it hangs (`up`), the dentry is pinned by
        // its mountpoint
        let (p, d) = unsafe { (&*p, &*d) };
        // On its parent's list (in the hash only while there)
        __lookup_mnt(p, d, &g).map(MountRef::entry_ref)
    };
    commit_tree(ns, &child);
    let r = MountRef::entry_ref(topmost_overmount(&child, &*ns));
    let c = MountRef::clone(&child);
    let (w, gone) = {
        let mut ml = MOUNT_LOCK.write();
        make_visible(ns, &mut ml, child);
        match &q {
            Some(q) => {
                // A lock on `q` hid what is under it: the new mount takes
                // that job; `q` keeps its own unless the new mount is the
                // caller's (a propagated copy goes with its original)
                if q.flags() & MNT_LOCKED != 0 {
                    c.mnt_flags.fetch_or(MNT_LOCKED, Ordering::SeqCst);
                    if is_source {
                        q.mnt_flags.fetch_and(!MNT_LOCKED, Ordering::SeqCst);
                    }
                }
                mnt_change_mountpoint(ns, &mut ml, &r, root_mp, q)
            }
            None => (None, None),
        }
    };
    drop(gone);
    drop(w);
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

/// What [`lock_mount`] holds: NAMESPACE_SEM write, the mountpoint's
/// i_rwsem, and where to mount (Linux pinned_mountpoint's parent and
/// dentry)
pub(super) struct LockedMp {
    pub(super) ns: NsWrite,
    _dir: super::inode::InodeLockArc,
    pub(super) at: Path,
}

/// Where a mount on `p` goes (Linux where_to_mount): on the root of the
/// topmost mount stacked on `p`, else on `p` itself; under MOUNT_LOCK
fn where_to_mount(p: &Path, ml: &MntHash) -> Path {
    let g = crate::sync::rcu::read_lock();
    match __lookup_mnt(&p.mnt, &p.dentry, &g) {
        Some(m) => {
            let m = topmost_overmount(m, ml);
            // In the hash, so on its parent's list, held still by
            // MOUNT_LOCK
            Path::new(MountRef::entry_ref(m), m.root.clone())
        }
        None => p.clone(),
    }
}

/// Lock the place to mount on `p` (Linux do_lock_mount): the target's
/// i_rwsem, then NAMESPACE_SEM; repeated if what is mounted there
/// changed meanwhile. A directory removed meanwhile, or a path on a
/// mount in no namespace, is ENOENT.
fn lock_mount(p: &Path) -> Result<LockedMp, KernelError> {
    loop {
        let at = where_to_mount(p, &MOUNT_LOCK.read_excl());
        let dir = at.dentry.get_inode().ok_or(KernelError::NotFound)?;
        let lock = dir.lock_arc();
        let ns = namespace_lock();
        let now = where_to_mount(p, &MOUNT_LOCK.read_excl());
        if !now.same(&at) {
            // Something moved: again
            drop(now);
            drop(ns);
            drop(lock);
            continue;
        }
        if dir.is_dead() || !p.mnt.is_mounted() {
            return Err(KernelError::NotFound);
        }
        return Ok(LockedMp { ns, _dir: lock, at });
    }
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
    let mut l = lock_mount(mp)?;
    let (ns, mp): (&mut NsTree, _) = (&mut l.ns, &l.at);
    let shared = |m: &Mount| super::pnode::is_shared(ns, m);
    let parent = old.mnt.get_parent(&*ns);
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
    // Peer groups before anything moves (Linux attach_recursive_mnt's
    // invent_group_ids precedes the detach), so the graft cannot fail
    if super::pnode::is_shared(ns, &mp.mnt) {
        super::pnode::invent_group_ids(ns, &old.mnt, true)?;
    }
    // It has a parent (checked above): it moves with its tree reference
    let Some(t) = detach_mnt(ns, &old.mnt) else {
        unreachable!("mount: an attached mount off no parent");
    };
    graft(ns, t, mp)
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
    let mut l = lock_mount(put_old)?;
    let (ns, put_old): (&mut NsTree, _) = (&mut l.ns, &l.at);
    // Only a mount in the namespace has a parent NAMESPACE_SEM pins
    // (Linux check_mnt before reading them)
    if !check_mnt(&root.mnt) || !check_mnt(&new.mnt) {
        return Err(KernelError::InvalidArgument);
    }
    // Nothing moves under a shared mount here without propagating
    // (Linux: put_old's mount, new's parent, root's parent not shared)
    let shared = |m: Option<MountRef>| m.is_some_and(|m| super::pnode::is_shared(ns, &m));
    if shared(Some(put_old.mnt.clone()))
        || shared(new.mnt.get_parent(&*ns))
        || shared(root.mnt.get_parent(&*ns))
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
    let mounted = |p: &Path| DentryRef::ptr_eq(&p.dentry, &p.mnt.root) && p.mnt.has_parent(&*ns);
    if !mounted(&root) || !mounted(new) {
        return Err(KernelError::InvalidArgument);
    }
    if !is_path_reachable(put_old, new) || !is_path_reachable(new, &root) {
        return Err(KernelError::InvalidArgument);
    }
    let (Some(root_parent), Some(root_mp)) = (root.mnt.get_parent(&*ns), root.mnt.mp_in(&*ns))
    else {
        return Err(KernelError::InvalidArgument);
    };
    // Kept while the old root comes off it (Linux pivot_root's old_mp)
    let root_mp = pin_mp(&mut MOUNT_LOCK.read_excl(), root_mp);
    // Both are mounted (checked above): each comes off its parent with
    // the tree reference it moves with
    let (Some(tn), Some(tr)) = (detach_mnt(ns, &new.mnt), detach_mnt(ns, &root.mnt)) else {
        unreachable!("pivot_root: a mounted mount off no parent");
    };
    if root.mnt.flags() & MNT_LOCKED != 0 {
        new.mnt.mark(MNT_LOCKED, true);
        root.mnt.mark(MNT_LOCKED, false);
    }
    attach_at(ns, tr, put_old);
    attach_mnt(ns, tn, &root_parent, root_mp.mp());
    let gone = unpin_mountpoint(&mut MOUNT_LOCK.read_excl(), root_mp);
    drop(l);
    drop(gone);
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
        let gone = {
            let mut ml = MOUNT_LOCK.read_excl();
            self.take_mountpoint(&ml).and_then(|mp| put_mp(&mut ml, mp))
        };
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
        self.drop_covers();
        super::pnode::teardown_prop(self);
        self.put_mountpoint();
        MNT_IDS.free(self.mnt_id);
        // SAFETY: the caller's contract: no reference can reach these
        // any more, and this is their one release
        let (root, sb) = unsafe { (self.root.take(), self.sb.take()) };
        drop(root);
        drop(sb);
    }

    /// Release the covers its submounts left (Linux mntput_no_expire's
    /// drop_cover): all in one MOUNT_LOCK write section, each off the
    /// list, freed a grace period later, its mountpoint put; a last
    /// mountpoint is dropped after the unlock (Linux shrink_dentry_list)
    fn drop_covers(&self) {
        if self.mnt_covers.is_empty() {
            return;
        }
        let mut list = BoxList::<MpHashA>::new();
        {
            let mut ml = MOUNT_LOCK.write();
            while let Some(c) = self.mnt_covers.remove_first(|_| true, &mut ml) {
                let mp = NonNull::new(c.item().mp.load(Ordering::Relaxed)).map(MpPtr);
                c.defer();
                if let Some(b) = mp.and_then(|mp| put_mp(&mut ml, mp)) {
                    list.push_back(b);
                }
            }
        }
        drop(list);
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
            drop(c.take_parent(&mut ml));
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
        let p = *self.mnt_parent.get_mut();
        if !p.is_null() {
            // SAFETY: from `Weak::into_raw` (`set_mountpoint`), not given
            // back (the link is still set)
            drop(unsafe { Weak::from_raw(p) });
        }
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
        m.get_mountpoint(&*ns)
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

/// An unattached nullfs mount, for unit tests
#[cfg(test)]
pub(super) fn test_mnt() -> MountRef {
    let t = &super::nullfs::NULLFS_TYPE;
    let sb = (t.mount)(t, b"").unwrap();
    let root = sb.get_root().unwrap();
    Mount::alloc(sb, root, 0, b"t".as_slice().into()).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mnt() -> MountRef {
        test_mnt()
    }

    /// A new mount on `parent`'s root
    fn hang(ns: &mut NsTree, parent: &MountRef) -> MountRef {
        let c = mnt();
        attach_at(
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
        let t = copy_tree(&mut ns, &plan, 0);
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
        // Both point at the dentry's one mountpoint (Linux mnt_mp),
        // which counts them
        let (ma, mb) = (a.mp_in(&*ns).unwrap(), b.mp_in(&*ns).unwrap());
        assert_eq!(ma.0, mb.0);
        // SAFETY: counted by `a` and `b`, under NAMESPACE_SEM
        let m = unsafe { ma.get() };
        assert!(DentryRef::ptr_eq(&m.m_dentry, &top.root));
        assert_eq!(m.m_count.load(Ordering::Relaxed), 2);
        let found = lookup_mnt(&at).unwrap();
        assert!(MountRef::ptr_eq(&found, &b));
        drop(found);
        assert!(detach_mnt(&mut ns, &b).is_some());
        assert!(lookup_mnt(&at).is_some_and(|m| MountRef::ptr_eq(&m, &a)));
        assert!(top.root.is_mountpoint());
        // The links name the parent and the dentry its mountpoint pins
        let mp = a.get_mountpoint(&*ns).unwrap();
        assert!(DentryRef::ptr_eq(&mp, &top.root));
        assert!(
            a.get_parent(&*ns)
                .is_some_and(|p| MountRef::ptr_eq(&p, &top))
        );
        drop(mp);
        assert!(detach_mnt(&mut ns, &a).is_some());
        assert!(lookup_mnt(&at).is_none() && !top.root.is_mountpoint());
        assert!(a.get_mountpoint(&*ns).is_none() && !a.has_parent(&*ns));
        assert!(a.mnt_mp.load(Ordering::Relaxed).is_null());
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

    /// umount_tree runs whole in its caller's MOUNT_LOCK write section
    /// (Linux umount_tree under lock_mount_hash), propagation included:
    /// a peer's copy at the same place goes along, a mount over that
    /// copy slides down to its place (reparent), and both unmounted
    /// mounts wait on the unmounted list for namespace_unlock
    #[test]
    fn umount_tree_propagates_under_mount_lock() {
        use super::super::pnode::{
            Prop, change_mnt_propagation, clone_links, invent_group_ids, is_shared,
        };
        let mut ns = namespace_lock();
        let a = mnt();
        let b = Mount::alloc(a.sb.clone(), a.root.clone(), 0, b"b".as_slice().into()).unwrap();
        invent_group_ids(&mut ns, &a, false).unwrap();
        clone_links(&mut ns, &a, &b, 0);
        assert!(is_shared(&ns, &b));
        let c = hang(&mut ns, &a);
        let d = hang(&mut ns, &b);
        let e = hang(&mut ns, &d);
        umount_tree(&mut ns, &mut MOUNT_LOCK.write(), &c, UMOUNT_PROPAGATE);
        for m in [&c, &d] {
            assert_ne!(m.flags() & MNT_UMOUNT, 0);
            assert!(!m.has_parent(&*ns));
        }
        assert_eq!(e.flags() & MNT_UMOUNT, 0);
        assert!(e.get_parent(&*ns).is_some_and(|p| MountRef::ptr_eq(&p, &b)));
        assert!(DentryRef::ptr_eq(&e.get_mountpoint(&*ns).unwrap(), &a.root));
        assert_eq!(ns.unmounted.as_ref().map_or(0, |l| l.len()), 2);
        drop(ns);
        let mut ns = namespace_lock();
        assert!(ns.unmounted.as_ref().is_none_or(|l| l.is_empty()));
        assert!(detach_mnt(&mut ns, &e).is_some());
        change_mnt_propagation(&mut ns, &a, Prop::Private);
        change_mnt_propagation(&mut ns, &b, Prop::Private);
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
