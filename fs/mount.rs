//! Mount - filesystem mount infrastructure
//!
//! Manages the mount tree that connects filesystems into a unified namespace.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use crate::sync::spin::RwLock;
use ::core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::KernelError;
use super::dentry::Dentry;
use super::inode::FileType;
use super::path_ref::Path;
use super::superblock::{FileSystemType, SuperBlock};

use crate::block::get_blkdev;

/// Ignore set-user/group-ID bits on exec (Linux MNT_NOSUID)
pub const MNT_NOSUID: u32 = 0x1;
/// No access to device nodes (Linux MNT_NODEV)
pub const MNT_NODEV: u32 = 0x2;
/// No program execution (Linux MNT_NOEXEC)
pub const MNT_NOEXEC: u32 = 0x4;
/// This mount is read-only, whatever its superblock (Linux MNT_READONLY)
pub const MNT_READONLY: u32 = 0x40;
/// Cannot be bind-mounted (Linux MNT_UNBINDABLE)
pub const MNT_UNBINDABLE: u32 = 0x2000;
/// Cannot be unmounted, moved or pivoted away (Linux MNT_LOCKED: a mount
/// a less privileged namespace copied, which would uncover what is
/// under it; the initial root is protected by having no parent)
pub const MNT_LOCKED: u32 = 0x80_0000;

/// Old mount -> its copy, from [`Mount::clone_tree`]
pub type MountMap = Vec<(Arc<Mount>, Arc<Mount>)>;

/// Mount topology changes: attach, umount, namespace copy, pivot_root;
/// /proc mount lists read under it (Linux namespace_sem, a sleeping
/// rw_semaphore). Outside it: the mountpoint's i_rwsem; inside it:
/// s_umount, then the spinning Mount fields.
pub static NAMESPACE_SEM: crate::sync::RwSem<()> = crate::sync::RwSem::new(());

/// Mount ids (Linux mnt_id_ida): the lowest free one, from 1
struct MntIds {
    next: u32,
    free: alloc::collections::BTreeSet<u32>,
}

static MNT_IDS: crate::sync::spin::Mutex<MntIds> = crate::sync::spin::Mutex::new(MntIds {
    next: 0,
    free: alloc::collections::BTreeSet::new(),
});

/// Never-reused mount ids start above this (Linux MNT_UNIQUE_ID_OFFSET,
/// 2^31 since 6.11), clear of the reused 32-bit ones
const MNT_UNIQUE_ID_OFFSET: u64 = 1 << 31;

/// The next never-reused mount id (Linux mnt_id_ctr + 1)
static MNT_ID_UNIQUE: AtomicU64 = AtomicU64::new(MNT_UNIQUE_ID_OFFSET + 1);

fn mnt_alloc_id() -> u32 {
    let mut ids = MNT_IDS.lock();
    if let Some(id) = ids.free.pop_first() {
        return id;
    }
    ids.next += 1;
    ids.next
}

fn mnt_free_id(id: u32) {
    MNT_IDS.lock().free.insert(id);
}

/// A mount point in the namespace
///
/// This struct mirrors Linux's `struct vfsmount`. The reference count
/// (`mnt_count`) tracks users of this mount - each open file that references
/// this mount holds a reference via `mntget()`.
pub struct Mount {
    /// The mounted filesystem's superblock
    pub sb: Arc<SuperBlock>,

    /// Root dentry of the mounted filesystem
    pub root: Arc<Dentry>,

    /// The dentry where this filesystem is mounted (mount point)
    /// None for the root mount
    pub mountpoint: RwLock<Option<Arc<Dentry>>>,

    /// Parent mount (None for root)
    pub parent: RwLock<Option<Weak<Mount>>>,

    /// Child mounts (filesystems mounted under this one)
    pub children: RwLock<Vec<Arc<Mount>>>,

    /// Per-mount MNT_* flags (Linux mnt_flags): MNT_NOSUID, MNT_NODEV,
    /// MNT_NOEXEC
    mnt_flags: AtomicU32,

    /// Peer group, 0 if not shared (Linux mnt_group_id; fs/pnode.rs)
    pub(super) group: AtomicU32,
    /// Group this mount is a slave of, 0 if none (Linux mnt_master)
    pub(super) master: AtomicU32,

    /// Marked by a first umount2(MNT_EXPIRE) (Linux mnt_expiry_mark)
    expiry: core::sync::atomic::AtomicBool,

    /// Holders of write access through this mount (Linux mnt_writers):
    /// against making it read-only, the protocol of SuperBlock::s_writers
    writers: AtomicU64,

    /// Id in /proc/<pid>/mountinfo and statx (Linux mnt_id): reused
    pub mnt_id: u32,
    /// Id never reused (Linux mnt_id_unique, STATX_MNT_ID_UNIQUE)
    pub mnt_id_unique: u64,
    /// What was mounted: the source argument, or the fs type for
    /// mounts made by the kernel (Linux mnt_devname)
    pub devname: super::name::FileName,

    /// Reference count for this mount (like Linux mnt_count)
    ///
    /// Tracks active users of this mount. Each open file holds a reference
    /// via mntget(). Incremented by mntget(), decremented by mntput().
    /// The mount cannot be unmounted while mnt_count > 0 (unless MNT_FORCE/MNT_DETACH).
    mnt_count: AtomicU64,
}

impl Mount {
    /// Create a new mount
    pub fn new(
        sb: Arc<SuperBlock>,
        root: Arc<Dentry>,
        flags: u32,
        devname: super::name::FileName,
    ) -> Arc<Self> {
        Arc::new(Self {
            sb,
            root,
            mountpoint: RwLock::new(None),
            parent: RwLock::new(None),
            children: RwLock::new(Vec::new()),
            mnt_flags: AtomicU32::new(flags),
            writers: AtomicU64::new(0),
            expiry: core::sync::atomic::AtomicBool::new(false),
            group: AtomicU32::new(0),
            master: AtomicU32::new(0),
            mnt_id: mnt_alloc_id(),
            mnt_id_unique: MNT_ID_UNIQUE.fetch_add(1, Ordering::Relaxed),
            devname,
            mnt_count: AtomicU64::new(0),
        })
    }

    /// A copy of `self` for a namespace copy: same filesystem, root,
    /// flags and source, new ids, not attached
    fn copy(&self) -> Arc<Self> {
        let c = Self::new(
            self.sb.clone(),
            self.root.clone(),
            self.flags(),
            self.devname.clone(),
        );
        // A namespace copy keeps peerage (Linux copy_mnt_ns: CL_COPY_ALL)
        super::pnode::clone_prop(self, &c);
        c
    }

    /// MNT_* flags
    pub fn flags(&self) -> u32 {
        self.mnt_flags.load(Ordering::Relaxed)
    }

    /// Replace the MNT_* flags (mount, remount): turning MNT_READONLY on
    /// is EBUSY, nothing changed, while anyone holds write access
    /// through the mount (Linux mnt_make_readonly)
    pub fn set_flags(&self, f: u32) -> Result<(), KernelError> {
        // Propagation and lock state are not the caller's to set here
        const KEEP: u32 = MNT_UNBINDABLE | MNT_LOCKED;
        let f = (f & !KEEP) | (self.flags() & KEEP);
        let old = self.mnt_flags.fetch_or(f & MNT_READONLY, Ordering::SeqCst);
        if f & MNT_READONLY != 0
            && old & MNT_READONLY == 0
            && self.writers.load(Ordering::SeqCst) != 0
        {
            self.mnt_flags.fetch_and(!MNT_READONLY, Ordering::SeqCst);
            return Err(KernelError::Busy);
        }
        self.mnt_flags.store(f, Ordering::SeqCst);
        Ok(())
    }

    /// Set (`on`) or clear MNT_* bits that need no other checks
    pub fn mark(&self, bits: u32, on: bool) {
        if on {
            self.mnt_flags.fetch_or(bits, Ordering::SeqCst);
        } else {
            self.mnt_flags.fetch_and(!bits, Ordering::SeqCst);
        }
    }

    /// This mount or its superblock is read-only (Linux
    /// __mnt_is_readonly)
    pub fn is_readonly(&self) -> bool {
        self.flags() & MNT_READONLY != 0 || self.sb.rdonly()
    }

    /// Write access through this mount (Linux mnt_want_write): EROFS
    /// for a read-only mount or superblock; hold the guard across the
    /// modification
    pub fn want_write(self: &Arc<Self>) -> Result<super::superblock::WriteAccess, KernelError> {
        self.writers.fetch_add(1, Ordering::SeqCst);
        if self.flags() & MNT_READONLY != 0 {
            self.put_write();
            return Err(KernelError::ReadOnlyFs);
        }
        match self.sb.want_write() {
            Ok(w) => Ok(w.with_mnt(self.clone())),
            Err(e) => {
                self.put_write();
                Err(e)
            }
        }
    }

    /// Release what want_write took
    pub(super) fn put_write(&self) {
        self.writers.fetch_sub(1, Ordering::SeqCst);
    }

    /// Increment mount reference count (like Linux mntget)
    ///
    /// Called when a file is opened on this filesystem.
    /// The caller should hold an Arc<Mount> reference and call this
    /// to indicate active use of the mount.
    pub fn mntget(&self) {
        self.mnt_count.fetch_add(1, Ordering::Relaxed);
        // Use clears an MNT_EXPIRE mark (Linux mntput)
        self.expiry.store(false, Ordering::Relaxed);
    }

    /// Decrement mount reference count (like Linux mntput)
    ///
    /// Called when a file is closed.
    pub fn mntput(&self) {
        self.mnt_count.fetch_sub(1, Ordering::Relaxed);
    }

    /// Get current mount reference count (like Linux mnt_get_count)
    ///
    /// Returns the number of active users of this mount.
    pub fn mnt_get_count(&self) -> u64 {
        self.mnt_count.load(Ordering::Relaxed)
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

    /// Get parent mount
    pub fn get_parent(&self) -> Option<Arc<Mount>> {
        self.parent
            .read()
            .as_ref()
            .and_then(|w: &Weak<Mount>| w.upgrade())
    }

    /// Set parent mount
    pub fn set_parent(&self, parent: &Arc<Mount>) {
        *self.parent.write() = Some(Arc::downgrade(parent));
    }

    /// Add a child mount
    pub fn add_child(&self, child: Arc<Mount>) {
        self.children.write().push(child);
    }

    /// Remove a child mount from this mount's children list
    pub fn remove_child(&self, child: &Arc<Mount>) -> bool {
        let mut children = self.children.write();
        if let Some(pos) = children.iter().position(|c| Arc::ptr_eq(c, child)) {
            children.remove(pos);
            true
        } else {
            false
        }
    }

    /// Check if this mount has any child mounts
    pub fn has_children(&self) -> bool {
        !self.children.read().is_empty()
    }

    /// Deep clone a mount tree for a new namespace
    ///
    /// Creates a copy of the entire mount tree rooted at this mount.
    /// Each mount in the new tree references the same superblock/dentry
    /// as the original (the filesystem data is shared), but the mount
    /// structures themselves are independent.
    ///
    /// This is used by CLONE_NEWNS to give a new mount namespace its
    /// own view of the mount hierarchy.
    pub fn clone_tree(root: &Arc<Mount>) -> Result<(Arc<Mount>, MountMap), i32> {
        let _ns = NAMESPACE_SEM.write();
        let new_root = root.copy();

        // Recursively clone children
        let mut map = alloc::vec![(root.clone(), new_root.clone())];
        for child in root.children.read().iter() {
            Self::clone_subtree(&new_root, child, &mut map)?;
        }

        Ok((new_root, map))
    }

    /// Clone a subtree and attach it to a parent
    fn clone_subtree(
        new_parent: &Arc<Mount>,
        old_mount: &Arc<Mount>,
        map: &mut MountMap,
    ) -> Result<(), i32> {
        let new_mount = old_mount.copy();
        if let Some(mp) = old_mount.get_mountpoint() {
            new_mount.set_mountpoint(mp);
        }
        new_mount.set_parent(new_parent);

        // Add to parent's children
        new_parent.children.write().push(new_mount.clone());
        map.push((old_mount.clone(), new_mount.clone()));

        // Recursively clone this mount's children
        for child in old_mount.children.read().iter() {
            Self::clone_subtree(&new_mount, child, map)?;
        }

        Ok(())
    }
}

/// The initial mount tree (Linux init_mount_tree, 7.0+): a nullfs mount
/// (id 1) is the namespace root and the mutable rootfs, a ramfs under
/// the type name "rootfs" (id 2), is mounted on it. Root and cwd go to the rootfs, so it can be
/// pivoted away or unmounted like any other mount. Then the private
/// nullfs kernel threads start in (id 3, Linux 7.3 knullfs). Returns
/// the rootfs.
pub fn init_mount_tree() -> Result<Arc<Mount>, KernelError> {
    let nullfs = &super::nullfs::NULLFS_TYPE;
    let null = attach(
        (nullfs.mount)(nullfs, b"")?,
        None,
        0,
        false,
        b"nullfs".as_slice().into(),
    )?;
    let rootfs_type = &super::ramfs::ROOTFS_TYPE;
    let sb = (rootfs_type.mount)(rootfs_type, b"")?;
    let on = Path::new(null.clone(), null.root.clone());
    let rootfs = attach(sb, Some(on), 0, false, b"rootfs".as_slice().into())?;
    let ksb = (nullfs.mount)(nullfs, b"")?;
    let root = ksb.get_root().ok_or(KernelError::InvalidArgument)?;
    super::fsstruct::kthread_fs_init(Mount::new(
        ksb,
        root,
        MNT_READONLY,
        b"nullfs".as_slice().into(),
    ));
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
) -> Result<Arc<Mount>, KernelError> {
    let root = sb.get_root().ok_or(KernelError::InvalidArgument)?;
    if ro {
        sb.make_rdonly()?;
    }
    let mount = Mount::new(sb, root, mnt_flags, devname);
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
        let _ns = NAMESPACE_SEM.write();
        graft(&mount, &mp);
        drop(_dir_lock);
    } else {
        mnt_ns.set_root(mount.clone());
    }
    Ok(mount)
}

/// A new mount of `m`'s filesystem rooted at `root`, with its flags
/// and source (Linux clone_mnt); not attached
pub fn clone_mnt(m: &Mount, root: Arc<Dentry>) -> Arc<Mount> {
    Mount::new(
        m.sb.clone(),
        root,
        m.flags() & !(MNT_UNBINDABLE | MNT_LOCKED),
        m.devname.clone(),
    )
}

/// `m` at `root` with the mounts below `root` in it (Linux copy_tree):
/// an unbindable submount is left out with whatever is under it
pub fn copy_tree(m: &Arc<Mount>, root: &Arc<Dentry>) -> Arc<Mount> {
    let top = clone_mnt(m, root.clone());
    super::pnode::clone_prop(m, &top);
    let mut todo = alloc::vec![(m.clone(), top.clone())];
    while let Some((src, dst)) = todo.pop() {
        let children: Vec<Arc<Mount>> = src.children.read().clone();
        for c in children {
            let Some(mp) = c.get_mountpoint() else {
                continue;
            };
            let below = !Arc::ptr_eq(&src, m) || super::is_subdir(&mp, root);
            if !below || c.flags() & MNT_UNBINDABLE != 0 {
                continue;
            }
            let n = clone_mnt(&c, c.root.clone());
            super::pnode::clone_prop(&c, &n);
            attach_mnt(&n, &Path::new(dst.clone(), mp));
            todo.push((c, n));
        }
    }
    top
}

/// Bind `old` (with its submounts if `rec`) on `mp` (Linux do_loopback
/// and graft_tree): an unbindable source is EINVAL; a directory goes
/// only on a directory and a file on a file (ENOTDIR)
pub fn do_loopback(old: &Path, mp: &Path, rec: bool) -> Result<(), KernelError> {
    if old.mnt.flags() & MNT_UNBINDABLE != 0 {
        return Err(KernelError::InvalidArgument);
    }
    let is_dir = |d: &Dentry| d.get_inode().is_some_and(|i| i.mode().is_dir());
    if is_dir(&mp.dentry) != is_dir(&old.dentry) {
        return Err(KernelError::NotDirectory);
    }
    let dir = mp.dentry.get_inode().ok_or(KernelError::NotFound)?;
    let _dir_lock = dir.lock();
    if dir.is_dead() {
        return Err(KernelError::NotFound);
    }
    let _ns = NAMESPACE_SEM.write();
    let m = if rec {
        copy_tree(&old.mnt, &old.dentry)
    } else {
        let m = clone_mnt(&old.mnt, old.dentry.clone());
        super::pnode::clone_prop(&old.mnt, &m);
        m
    };
    graft(&m, mp);
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
    super::fs_writeback::register_sb(&sb);
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

/// Check if a mount is busy (has open files or child mounts)
///
/// This mirrors Linux's may_umount() / vfs_is_busy() logic:
/// - Check for child mounts
/// - Check mnt_count for active file references
fn is_mount_busy(mount: &Arc<Mount>) -> bool {
    // Check for child mounts - can't unmount if there are filesystems mounted under us
    if mount.has_children() {
        return true;
    }

    // Check for open files on this mount
    // Each open File holds a reference via mntget()
    if mount.mnt_get_count() > 0 {
        return true;
    }

    false
}

/// Unmount `mount` (Linux do_umount): EINVAL for an unattached mount
/// (the namespace root); the caller's own root is instead remounted
/// read-only (do_umount_root). MNT_DETACH takes the whole subtree out of
/// the namespace at once, busy or not: open files keep working, the
/// filesystem goes with its last user. Otherwise a mount with
/// submounts or users is EBUSY, MNT_FORCE too. MNT_EXPIRE (not with
/// MNT_FORCE or MNT_DETACH, not the root) only marks an unmarked mount
/// (EAGAIN).
pub fn do_umount(mount: Arc<Mount>, flags: i32) -> Result<(), KernelError> {
    use umount_flags::{MNT_DETACH, MNT_EXPIRE, MNT_FORCE};
    // Linux can_umount
    if mount.flags() & MNT_LOCKED != 0 {
        return Err(KernelError::InvalidArgument);
    }
    let detach = flags & MNT_DETACH != 0;
    let is_root =
        crate::task::percpu::current_fs().is_some_and(|fs| Arc::ptr_eq(&fs.get_root().mnt, &mount));
    if flags & MNT_EXPIRE != 0 {
        if is_root || flags & (MNT_FORCE | MNT_DETACH) != 0 {
            return Err(KernelError::InvalidArgument);
        }
        // Busy first (Linux: mnt_get_count != 2), then the mark
        if is_mount_busy(&mount) {
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
    let ns = NAMESPACE_SEM.write();
    // The propagated copies go too (Linux propagate_mount_busy,
    // propagate_umount); a busy one makes it all EBUSY
    let copies = super::pnode::propagate_umount(&mount);
    if !detach && (is_mount_busy(&mount) || copies.iter().any(|c| c.mnt_get_count() > 0)) {
        return Err(KernelError::Busy);
    }
    for m in core::iter::once(&mount).chain(copies.iter()) {
        detach_mnt(m);
        // Unmounted mounts leave propagation (Linux umount_tree)
        for t in super::pnode::subtree(m) {
            super::pnode::change_propagation(&t, super::pnode::Prop::Private);
        }
    }
    drop(ns);

    // Write the filesystem back, outside namespace_sem: writeback takes
    // inode locks, which nest outside it (Linux: deactivate_super ->
    // sync_filesystem after namespace_unlock)
    let _ = super::fs_writeback::writeback_sb(&mount.sb);
    Ok(())
}

/// Take `m` (and what is mounted below it) off its parent; under
/// NAMESPACE_SEM
fn detach_mnt(m: &Arc<Mount>) {
    if let Some(parent) = m.get_parent() {
        parent.remove_child(m);
    }
    *m.parent.write() = None;
    if let Some(mp) = m.mountpoint.write().take() {
        note_mp(&mp, -1);
    }
}

/// Hang `m` on `mp` (Linux attach_mnt); under NAMESPACE_SEM
pub(super) fn attach_mnt(m: &Arc<Mount>, mp: &Path) {
    m.set_mountpoint(mp.dentry.clone());
    m.set_parent(&mp.mnt);
    mp.mnt.add_child(m.clone());
}

/// Hang the tree at `m` on `mp` and, under a shared mount, propagate
/// it (Linux attach_recursive_mnt: the tree is made shared first);
/// under NAMESPACE_SEM
fn graft(m: &Arc<Mount>, mp: &Path) {
    let shared = mp.mnt.group.load(Ordering::SeqCst) != 0;
    if shared {
        super::pnode::invent_groups(m);
    }
    attach_mnt(m, mp);
    if shared {
        super::pnode::propagate_mnt(&mp.mnt, &mp.dentry, m);
    }
}

/// `p` is at or below `root`, across mounts (Linux is_path_reachable)
fn is_path_reachable(p: &Path, root: &Path) -> bool {
    let (mut mnt, mut d) = (p.mnt.clone(), p.dentry.clone());
    while !Arc::ptr_eq(&mnt, &root.mnt) {
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

/// MS_MOVE (Linux do_move_mount): `old` must be the root of an attached
/// mount (EINVAL), a directory goes only on a directory (ENOTDIR), and
/// not into its own subtree (ELOOP)
pub fn do_move(old: &Path, mp: &Path) -> Result<(), KernelError> {
    if !Arc::ptr_eq(&old.dentry, &old.mnt.root)
        || old.mnt.get_parent().is_none()
        || old.mnt.flags() & MNT_LOCKED != 0
    {
        return Err(KernelError::InvalidArgument);
    }
    let is_dir = |d: &Dentry| d.get_inode().is_some_and(|i| i.mode().is_dir());
    if is_dir(&mp.dentry) != is_dir(&old.dentry) {
        return Err(KernelError::NotDirectory);
    }
    let _l = lock_mountpoint(mp)?;
    let _ns = NAMESPACE_SEM.write();
    // Out of a shared parent (Linux: EINVAL); an unbindable tree not
    // under a shared mount
    let shared = |m: &Mount| m.group.load(Ordering::SeqCst) != 0;
    if old.mnt.get_parent().is_some_and(|p| shared(&p))
        || (shared(&mp.mnt)
            && super::pnode::subtree(&old.mnt)
                .iter()
                .any(|m| m.flags() & MNT_UNBINDABLE != 0))
    {
        return Err(KernelError::InvalidArgument);
    }
    if is_path_reachable(mp, old) {
        return Err(KernelError::TooManySymlinks);
    }
    detach_mnt(&old.mnt);
    graft(&old.mnt, mp);
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
    let ns = NAMESPACE_SEM.write();
    // Nothing moves under a shared mount here without propagating
    // (Linux: put_old's mount, new's parent, root's parent not shared)
    let shared = |m: Option<Arc<Mount>>| m.is_some_and(|m| m.group.load(Ordering::SeqCst) != 0);
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
    if Arc::ptr_eq(&new.mnt, &root.mnt) || Arc::ptr_eq(&put_old.mnt, &root.mnt) {
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
    detach_mnt(&new.mnt);
    detach_mnt(&root.mnt);
    if root.mnt.flags() & MNT_LOCKED != 0 {
        new.mnt.mark(MNT_LOCKED, true);
        root.mnt.mark(MNT_LOCKED, false);
    }
    attach_mnt(&root.mnt, put_old);
    attach_mnt(&new.mnt, &Path::new(root_parent, root_mp));
    drop(ns);
    chroot_fs_refs(&root, &Path::new(new.mnt.clone(), new.mnt.root.clone()));
    Ok(())
}

/// Every task whose root or cwd is `old` moves to `new` (Linux
/// chroot_fs_refs)
fn chroot_fs_refs(old: &Path, new: &Path) {
    let tids: Vec<crate::task::Tid> = crate::task::percpu::TASKLIST
        .read()
        .iter()
        .map(|t| t.task.tid())
        .collect();
    for tid in tids {
        let Some(fs) = super::get_task_fs(tid) else {
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

impl Drop for Mount {
    /// A mount dropped without an umount (a namespace going away) still
    /// had its mountpoint counted
    fn drop(&mut self) {
        if let Some(mp) = self.mountpoint.get_mut().take() {
            note_mp(&mp, -1);
        }
        mnt_free_id(self.mnt_id);
    }
}

/// Something is mounted on `d` in the caller's mount namespace (Linux
/// is_local_mountpoint): a walk of the namespace's mounts for one whose
/// mountpoint is the dentry `d`
pub fn is_local_mountpoint(d: &Arc<Dentry>) -> bool {
    // Nothing is mounted on this dentry (or an alias) anywhere: no walk
    if !may_be_mountpoint(d) {
        return false;
    }
    let Some(root) = crate::ns::current_mnt_ns().get_root() else {
        return false;
    };
    let mut todo = alloc::vec![root];
    while let Some(m) = todo.pop() {
        for c in m.children.read().iter() {
            if c.get_mountpoint().is_some_and(|mp| same_place(&mp, d)) {
                return true;
            }
            todo.push(c.clone());
        }
    }
    false
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
/// mountpoint is the place `p.dentry` names
fn lookup_mnt(p: &Path) -> Option<Arc<Mount>> {
    p.mnt
        .children
        .read()
        .iter()
        .find(|c| {
            c.get_mountpoint()
                .is_some_and(|mp| same_place(&mp, &p.dentry))
        })
        .cloned()
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
