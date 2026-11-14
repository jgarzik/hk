//! Superblock - filesystem instance representation
//!
//! Each mounted filesystem has a superblock that holds filesystem-wide
//! state and provides operations for managing inodes.

use alloc::sync::Arc;

use crate::sync::spin::{Mutex, RwLock};
use crate::sync::{LockedBy, UniqueOwner};
use crate::util::list::{Adapter, Link, WeakList};
use ::core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::sync;

use super::KernelError;
use super::dentry::DentryRef;
use super::inode::{Inode, InodeId, InodeMode, InodeOps};
use crate::util::kalloc::try_arc;

/// Superblock operations trait - filesystem-specific behavior
pub trait SuperOps: Send + Sync {
    /// Allocate a new inode
    fn alloc_inode(
        &self,
        sb: &Arc<SuperBlock>,
        mode: InodeMode,
        i_op: &'static dyn InodeOps,
    ) -> Result<Arc<Inode>, KernelError>;

    /// Called when inode is no longer referenced
    fn drop_inode(&self, _inode: &Inode) {}

    /// Sync filesystem to backing store (no-op for in-memory fs)
    fn sync_fs(&self) -> Result<(), KernelError> {
        Ok(())
    }

    /// Get filesystem statistics
    fn statfs(&self, _sb: &SuperBlock) -> StatFs {
        StatFs::default()
    }

    /// The options string of a remount (Linux ->reconfigure), before
    /// the flags change; an error changes nothing. Default: ignored.
    fn remount(&self, sb: &SuperBlock, data: &[u8]) -> Result<(), KernelError> {
        let _ = (sb, data);
        Ok(())
    }

    /// This filesystem's own options in /proc/mounts, each as ",name"
    /// (Linux ->show_options). Default none.
    fn show_options(&self, sb: &SuperBlock, out: &mut alloc::vec::Vec<u8>) {
        let _ = (sb, out);
    }
}

/// Linux vfs_parse_sb_flag: generic words every filesystem takes in its
/// options (their effect comes from mount(2)'s flags)
pub fn sb_flag_word(w: &[u8]) -> bool {
    matches!(
        w,
        b"ro"
            | b"rw"
            | b"sync"
            | b"async"
            | b"dirsync"
            | b"lazytime"
            | b"nolazytime"
            | b"mand"
            | b"nomand"
            | b"posixacl"
    )
}

/// Filesystem statistics (like Linux statfs)
#[derive(Debug, Clone, Default)]
pub struct StatFs {
    /// Filesystem type magic number
    pub f_type: u64,
    /// Optimal transfer block size
    pub f_bsize: u64,
    /// Total data blocks
    pub f_blocks: u64,
    /// Free blocks
    pub f_bfree: u64,
    /// Free blocks available to unprivileged user
    pub f_bavail: u64,
    /// Total inodes
    pub f_files: u64,
    /// Free inodes
    pub f_ffree: u64,
    /// Maximum filename length
    pub f_namelen: u64,
}

// ============================================================================
// Filesystem Magic Numbers (from Linux include/uapi/linux/magic.h)
// ============================================================================

/// Ramfs filesystem magic number
pub const RAMFS_MAGIC: u64 = 0x858458f6;
/// Tmpfs filesystem magic number
pub const TMPFS_MAGIC: u64 = 0x01021994;
/// Procfs filesystem magic number
pub const PROC_SUPER_MAGIC: u64 = 0x9fa0;
/// FAT/VFAT filesystem magic number
pub const MSDOS_SUPER_MAGIC: u64 = 0x4d44;

// ============================================================================
// Linux ABI statfs Structure
// ============================================================================

/// Linux statfs structure (64-bit ABI)
///
/// This matches the Linux kernel's `struct statfs` for 64-bit architectures.
/// Total size: 120 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LinuxStatFs {
    /// Filesystem type magic number
    pub f_type: i64,
    /// Optimal transfer block size
    pub f_bsize: i64,
    /// Total data blocks in filesystem
    pub f_blocks: i64,
    /// Free blocks in filesystem
    pub f_bfree: i64,
    /// Free blocks available to unprivileged user
    pub f_bavail: i64,
    /// Total file nodes (inodes) in filesystem
    pub f_files: i64,
    /// Free file nodes in filesystem
    pub f_ffree: i64,
    /// Filesystem ID
    pub f_fsid: [i32; 2],
    /// Maximum length of filenames
    pub f_namelen: i64,
    /// Fragment size (same as f_bsize for most filesystems)
    pub f_frsize: i64,
    /// Mount flags (ST_RDONLY, ST_NOSUID, etc.)
    pub f_flags: i64,
    /// Padding for future use
    pub f_spare: [i64; 4],
}
crate::pod!(LinuxStatFs {
    f_type,
    f_bsize,
    f_blocks,
    f_bfree,
    f_bavail,
    f_files,
    f_ffree,
    f_fsid,
    f_namelen,
    f_frsize,
    f_flags,
    f_spare
});

impl StatFs {
    /// Convert internal StatFs to Linux ABI format
    pub fn to_linux(&self, dev_id: u64, st_flags: u64) -> LinuxStatFs {
        LinuxStatFs {
            f_type: self.f_type as i64,
            f_bsize: self.f_bsize as i64,
            f_blocks: self.f_blocks as i64,
            f_bfree: self.f_bfree as i64,
            f_bavail: self.f_bavail as i64,
            f_files: self.f_files as i64,
            f_ffree: self.f_ffree as i64,
            f_fsid: [(dev_id & 0xFFFFFFFF) as i32, (dev_id >> 32) as i32],
            f_namelen: self.f_namelen as i64,
            f_frsize: self.f_bsize as i64, // Same as bsize for simplicity
            f_flags: st_flags as i64,
            f_spare: [0; 4],
        }
    }
}

use super::file::FileOps;

use crate::block::BlockDevice;

/// Mount function type for pseudo-filesystems (no backing device)
/// `opts`: the mount data string (comma-separated options, empty for
/// none)
pub type MountFn =
    fn(fs_type: &'static FileSystemType, opts: &[u8]) -> Result<Arc<SuperBlock>, KernelError>;

/// Mount function type for device-backed filesystems (ext4, vfat, etc.)
pub type MountDevFn = fn(
    fs_type: &'static FileSystemType,
    bdev: Arc<BlockDevice>,
    opts: &[u8],
) -> Result<Arc<SuperBlock>, KernelError>;

/// Filesystem type descriptor
pub struct FileSystemType {
    /// Filesystem name (e.g., "ramfs", "procfs", "vfat")
    pub name: &'static str,

    /// Mount flags
    pub fs_flags: u32,

    /// Create a new superblock for this filesystem type (pseudo-filesystems)
    pub mount: MountFn,

    /// Create a new superblock with a backing block device (disk-backed filesystems)
    /// None for pseudo-filesystems like ramfs/procfs
    pub mount_dev: Option<MountDevFn>,

    /// Default file operations for files on this filesystem
    pub file_ops: &'static dyn FileOps,

    /// The next registered type (Linux file_system_type.next, under
    /// file_systems_lock): `FsNext::new(None)`
    pub next: FsNext,

    /// Its superblocks (Linux fs_supers, the sbs' s_instances, under
    /// sb_lock): `FsSupers::new(WeakList::new())`
    pub fs_supers: FsSupers,
}

/// [`FileSystemType::next`]
pub type FsNext = LockedBy<Option<&'static FileSystemType>, FsList>;
/// [`FileSystemType::fs_supers`]
pub type FsSupers = LockedBy<WeakList<SInstanceA>, SbLists>;

/// Filesystem type flags
pub mod fs_flags {
    /// Filesystem is in-memory (no backing device needed)
    pub const FS_IN_MEMORY: u32 = 0;
    /// Filesystem is pseudo (procfs, sysfs, etc.)
    pub const FS_PSEUDO: u32 = 1;
    /// Filesystem requires a backing block device
    pub const FS_REQUIRES_DEV: u32 = 2;
}

/// Global counter for unique device IDs per superblock
static NEXT_DEV_ID: AtomicU64 = AtomicU64::new(1);

/// The superblock structure - represents a mounted filesystem instance
/// Read-only file system (Linux SB_RDONLY)
pub const SB_RDONLY: u32 = 1;
/// Writes are synchronous (Linux SB_SYNCHRONOUS)
pub const SB_SYNCHRONOUS: u32 = 16;
/// Directory changes are synchronous (Linux SB_DIRSYNC)
pub const SB_DIRSYNC: u32 = 128;

/// The hold bit of a writer count (Linux WRITE_HOLD): while set, new
/// writers wait; it shares the count's word, so one atomic operation
/// orders a writer against a holder
pub(super) const WRITE_HOLD: u64 = 1 << 63;

/// Take write access on a writer count (Linux mnt_get_write_access):
/// count first, wait out a hold (spinning: a holder holds MOUNT_LOCK and
/// never waits for writers), then check read-only state, which a holder
/// sets before it releases the hold
pub(super) fn get_write(w: &AtomicU64, readonly: impl Fn() -> bool) -> Result<(), KernelError> {
    if w.fetch_add(1, Ordering::SeqCst) & WRITE_HOLD != 0 {
        while w.load(Ordering::Acquire) & WRITE_HOLD != 0 {
            core::hint::spin_loop();
        }
    }
    if readonly() {
        w.fetch_sub(1, Ordering::SeqCst);
        return Err(KernelError::ReadOnlyFs);
    }
    Ok(())
}

/// Hold new writers off (Linux mnt_hold_writers): true if none holds
/// write access now
pub(super) fn hold_writers(w: &AtomicU64) -> bool {
    w.fetch_or(WRITE_HOLD, Ordering::SeqCst) & !WRITE_HOLD == 0
}

/// Let writers in again (Linux mnt_unhold_writers): after the read-only
/// state they must see
pub(super) fn unhold_writers(w: &AtomicU64) {
    w.fetch_and(!WRITE_HOLD, Ordering::Release);
}

/// Write access to a file system (from `SuperBlock::want_write` for an
/// object without a mount, `Mount::want_write` otherwise), released on
/// drop (Linux mnt_drop_write); `none()` for objects without a
/// superblock
pub struct WriteAccess {
    sb: Option<Arc<SuperBlock>>,
    /// The mount's write access too (Linux mnt_want_write on a path)
    mnt: Option<super::mount::MountRef>,
}

impl WriteAccess {
    /// No file system to hold
    pub const fn none() -> Self {
        Self {
            sb: None,
            mnt: None,
        }
    }

    /// `mnt`'s write count (taken by the caller)
    pub(super) fn mnt(mnt: super::mount::MountRef) -> Self {
        Self {
            sb: None,
            mnt: Some(mnt),
        }
    }
}

impl Drop for WriteAccess {
    fn drop(&mut self) {
        if let Some(sb) = &self.sb {
            sb.s_writers.fetch_sub(1, Ordering::SeqCst);
        }
        if let Some(m) = &self.mnt {
            m.put_write();
        }
    }
}

crate::adapter!(pub SListA, SuperBlock, s_list);
crate::adapter!(pub SInstanceA, SuperBlock, s_instances);
crate::adapter!(pub MntInstanceA, super::mount::Mount, mnt_instance);

/// What sb_lock guards (Linux sb_lock): the list of every superblock
/// (Linux super_blocks) and, through [`FsSupers`], each type's
/// instances. Entries hold a `Weak` and leave in the superblock's
/// teardown (Linux __put_super, generic_shutdown_super).
pub struct SbLists {
    supers: WeakList<SListA>,
}

// SAFETY: one instance, `SB_LOCK`'s, made here (the field is private)
unsafe impl UniqueOwner for SbLists {}

/// Linux sb_lock: a spin leaf, thread context only; under it only
/// list changes and `sget`'s test. Walkers drop it per superblock.
static SB_LOCK: Mutex<SbLists> = Mutex::new(SbLists {
    supers: WeakList::new(),
});

impl Drop for SuperBlock {
    /// What the filesystem had cached goes with it (Linux
    /// generic_shutdown_super: shrink_dcache_for_umount, then
    /// fsnotify_sb_delete: its watches get IN_UNMOUNT and go). First it
    /// leaves super_blocks and its type's fs_supers (the lists' contract,
    /// `WeakList`): no walker reaches it once its fields start to go.
    fn drop(&mut self) {
        let weaks = {
            let mut l = SB_LOCK.lock();
            let me: &Self = self;
            let inst = me.fs_type.fs_supers.access_mut(&mut l);
            // SAFETY: a linked s_instances link is on its type's list
            let a = me
                .s_instances
                .is_linked()
                .then(|| unsafe { inst.remove(me) });
            // SAFETY: a linked s_list link is on super_blocks
            let b = me
                .s_list
                .is_linked()
                .then(|| unsafe { l.supers.remove(me) });
            (a, b)
        };
        drop(weaks);
        super::inode::sb_list_drain(&self.s_inodes);
        if let Some(root) = self.root.get_mut().take() {
            super::dentry::d_drop_tree(&root);
        }
        self.s_fsnotify.sb_delete();
    }
}

/// List a new superblock (Linux sget_fc's insert: super_blocks tail,
/// fs_supers head)
fn sb_add(l: &mut SbLists, sb: &Arc<SuperBlock>) {
    sb.fs_type.fs_supers.access_mut(l).push_front(sb);
    l.supers.push_back(sb);
}

/// The live superblock after `cur` (the first if None) on the list `on`
/// picks, taken under sb_lock (Linux __iterate_supers' step: skip the
/// dying, refcount_inc_not_zero); `cur` is held, so still listed
fn next_live<A: Adapter<Item = SuperBlock>>(
    cur: Option<&Arc<SuperBlock>>,
    on: impl Fn(&SbLists) -> &WeakList<A>,
) -> Option<Arc<SuperBlock>> {
    let l = SB_LOCK.lock();
    let list = on(&l);
    let mut it = match cur {
        // SAFETY: `c` is alive (held), so its teardown has not unlinked
        // it, and only that teardown does
        Some(c) => unsafe { list.iter_after(c) },
        None => list.iter(),
    };
    it.find_map(|e| e.upgrade())
}

/// `f` on every superblock (Linux iterate_supers): each taken under
/// sb_lock and held while `f` runs with no lock, released after the
/// next one is taken; `f` may sleep. Superblocks listed meanwhile may
/// be missed.
pub fn iterate_supers(f: impl FnMut(&Arc<SuperBlock>)) {
    walk(f, |l| &l.supers);
}

/// `f` on every superblock of `fs_type` (Linux iterate_supers_type)
pub fn iterate_supers_type(fs_type: &'static FileSystemType, f: impl FnMut(&Arc<SuperBlock>)) {
    walk(f, |l| fs_type.fs_supers.access(l));
}

fn walk<A: Adapter<Item = SuperBlock>>(
    mut f: impl FnMut(&Arc<SuperBlock>),
    on: impl Fn(&SbLists) -> &WeakList<A>,
) {
    let mut cur: Option<Arc<SuperBlock>> = None;
    while let Some(sb) = next_live(cur.as_ref(), &on) {
        f(&sb);
        // The previous one goes with sb_lock released (Linux put_super
        // outside it): its last reference's teardown takes the lock
        cur = Some(sb);
    }
}

/// The superblock of `fs_type` that `test` accepts, else a new one
/// (Linux sget_fc). `test` runs under sb_lock (a spin lock: it must not
/// sleep) and may see a superblock in its teardown, which is then
/// skipped (Linux grab_super of a dying sb). `make` builds a complete
/// superblock with [`SuperBlock::alloc`] and no lock held; if another
/// mounter listed one `test` accepts meanwhile, that one is returned and
/// the new one dropped unlisted.
pub fn sget(
    fs_type: &'static FileSystemType,
    test: impl Fn(&SuperBlock) -> bool,
    make: impl FnOnce() -> Result<Arc<SuperBlock>, KernelError>,
) -> Result<Arc<SuperBlock>, KernelError> {
    let find = |l: &SbLists| {
        fs_type
            .fs_supers
            .access(l)
            .iter()
            .filter(|e| test(e.get()))
            .find_map(|e| e.upgrade())
    };
    let found = find(&SB_LOCK.lock());
    if let Some(sb) = found {
        return Ok(sb);
    }
    let new = make()?;
    let mut l = SB_LOCK.lock();
    if let Some(old) = find(&l) {
        drop(l);
        return Ok(old);
    }
    sb_add(&mut l, &new);
    drop(l);
    Ok(new)
}

pub struct SuperBlock {
    /// Filesystem type
    pub fs_type: &'static FileSystemType,

    /// On super_blocks (Linux s_list, under sb_lock)
    s_list: Link,
    /// On its type's fs_supers (Linux s_instances, under sb_lock)
    s_instances: Link,

    /// Root dentry of this filesystem
    pub root: RwLock<Option<DentryRef>>,

    /// Superblock operations
    pub s_op: &'static dyn SuperOps,

    /// SB_* flags (Linux s_flags): SB_RDONLY, SB_SYNCHRONOUS, SB_DIRSYNC
    s_flags: AtomicU32,

    /// Holders of write access to objects without a mount (internal
    /// files), and the WRITE_HOLD bit (see get_write); writes through a
    /// mount count on the mount
    s_writers: AtomicU64,
    /// Its mounts (Linux s_mounts, through `Mount.mnt_instance`), for a
    /// read-only remount to hold their writers: a spin leaf, added to
    /// under MOUNT_LOCK; a mount leaves it in its teardown
    pub(super) s_mounts: Mutex<WeakList<MntInstanceA>>,

    /// Next inode number to allocate
    next_ino: AtomicU64,

    /// Mounts whose mountpoint is a dentry of this filesystem, in any
    /// namespace: 0 lets unlink/rmdir/rename skip the mountpoint walk
    /// (Linux checks DCACHE_MOUNTED first). Never low; a stale high
    /// count only costs the walk.
    mounted_on: AtomicU32,

    /// Unique device ID for this filesystem instance (for stat st_dev)
    pub dev_id: u64,

    /// Largest file size (Linux s_maxbytes): writes are cut short at it,
    /// growing past it is EFBIG. Set by the filesystem at mount.
    s_maxbytes: AtomicU64,

    /// Filesystem-specific private data
    pub private: RwLock<Option<Arc<dyn SuperBlockData>>>,

    /// The block device a device filesystem is mounted from, held open
    /// while the superblock lives (Linux s_bdev_file)
    s_bdev: spin::Once<crate::block::blkdev::BdevHandle>,

    /// Its inodes (Linux s_inodes, under inode_sb_list_lock)
    pub(super) s_inodes: super::inode::SbInodes,

    /// Its inodes that have had inotify watches (Linux s_fsnotify_info)
    pub s_fsnotify: crate::io::inotify::SbMarks,

    /// Mutex for cross-directory renames (like Linux s_vfs_rename_mutex)
    ///
    /// Serializes all cross-directory renames on this filesystem to
    /// prevent races during ancestor relationship checks. Same-directory
    /// renames don't need this mutex.
    pub s_vfs_rename_mutex: sync::Mutex<()>,
    /// Remount and other changes of the superblock's state (Linux
    /// s_umount, a sleeping rw_semaphore): inside namespace_sem
    pub s_umount: sync::RwSem<()>,
    /// Writeback errors of its files, reported once to each open file by
    /// syncfs (Linux s_wb_err)
    pub s_wb_err: crate::util::errseq::ErrSeq,
}

use super::inode::AsAny;

/// Largest file offset on a 64-bit kernel (Linux MAX_LFS_FILESIZE,
/// LLONG_MAX): the default `s_maxbytes`
pub const MAX_LFS_FILESIZE: u64 = i64::MAX as u64;

/// Trait for filesystem-specific superblock data
pub trait SuperBlockData: Send + Sync + AsAny {}

impl SuperBlock {
    /// A mount was put on (`+1`) or taken off (`-1`) one of this
    /// filesystem's dentries
    pub fn note_mounted_on(&self, delta: i32) {
        if delta > 0 {
            self.mounted_on.fetch_add(1, Ordering::AcqRel);
        } else {
            self.mounted_on.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// Something may be mounted on a dentry of this filesystem
    pub fn has_mounts_on(&self) -> bool {
        self.mounted_on.load(Ordering::Acquire) != 0
    }

    /// Create a new superblock, listed on super_blocks and its type's
    /// fs_supers (Linux sget_fc with no test)
    pub fn new(
        fs_type: &'static FileSystemType,
        s_op: &'static dyn SuperOps,
        flags: u32,
    ) -> Result<Arc<Self>, KernelError> {
        let sb = Self::alloc(fs_type, s_op, flags)?;
        sb_add(&mut SB_LOCK.lock(), &sb);
        Ok(sb)
    }

    /// Create a superblock not listed yet (Linux alloc_super), for
    /// [`sget`]'s `make`
    pub fn alloc(
        fs_type: &'static FileSystemType,
        s_op: &'static dyn SuperOps,
        flags: u32,
    ) -> Result<Arc<Self>, KernelError> {
        try_arc(Self {
            fs_type,
            s_list: Link::new(),
            s_instances: Link::new(),
            root: RwLock::new(None),
            s_op,
            s_flags: AtomicU32::new(flags),
            mounted_on: AtomicU32::new(0),
            s_writers: AtomicU64::new(0),
            s_mounts: Mutex::new(WeakList::new()),
            next_ino: AtomicU64::new(1), // Start inode numbers at 1
            dev_id: NEXT_DEV_ID.fetch_add(1, Ordering::Relaxed),
            s_maxbytes: AtomicU64::new(MAX_LFS_FILESIZE),
            private: RwLock::new(None),
            s_bdev: spin::Once::new(),
            s_inodes: super::inode::SbInodes::new(WeakList::new()),
            s_fsnotify: crate::io::inotify::SbMarks::default(),
            s_vfs_rename_mutex: sync::Mutex::new(()),
            s_wb_err: crate::util::errseq::ErrSeq::new(),
            s_umount: sync::RwSem::new(()),
        })
    }

    /// Largest file size on this filesystem (Linux s_maxbytes)
    pub fn maxbytes(&self) -> u64 {
        self.s_maxbytes.load(Ordering::Relaxed)
    }

    /// Set the largest file size (at mount)
    pub fn set_maxbytes(&self, max: u64) {
        self.s_maxbytes.store(max, Ordering::Relaxed);
    }

    /// True if mounted read-only (Linux sb_rdonly)
    pub fn rdonly(&self) -> bool {
        self.s_flags.load(Ordering::SeqCst) & SB_RDONLY != 0
    }

    /// The SB_* flags
    pub fn flags(&self) -> u32 {
        self.s_flags.load(Ordering::Relaxed)
    }

    /// True if writes are synchronous (Linux IS_SYNC of the superblock)
    pub fn synchronous(&self) -> bool {
        self.s_flags.load(Ordering::Relaxed) & SB_SYNCHRONOUS != 0
    }

    /// True if directory changes are synchronous (Linux IS_DIRSYNC of
    /// the superblock: SB_SYNCHRONOUS implies it)
    pub fn dirsync(&self) -> bool {
        self.s_flags.load(Ordering::Relaxed) & (SB_SYNCHRONOUS | SB_DIRSYNC) != 0
    }

    /// Replace SB_SYNCHRONOUS and SB_DIRSYNC with `f` (mount, remount)
    pub fn set_sync_flags(&self, f: u32) {
        let mask = SB_SYNCHRONOUS | SB_DIRSYNC;
        let _ = self
            .s_flags
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                Some((v & !mask) | (f & mask))
            });
    }

    /// Take write access to an object reached without a mount (internal
    /// files): EROFS on a read-only file system. Held until the
    /// returned guard drops. Writes through a mount count on the mount
    /// instead (`Mount::want_write`), as Linux.
    pub fn want_write(self: &Arc<Self>) -> Result<WriteAccess, KernelError> {
        get_write(&self.s_writers, || self.rdonly())?;
        Ok(WriteAccess {
            sb: Some(self.clone()),
            mnt: None,
        })
    }

    /// Note a new mount of this superblock (Linux clone_mnt adds to
    /// sb->s_mounts under lock_mount_hash): under MOUNT_LOCK, so a
    /// read-only remount either sees it and holds its writers, or ran
    /// before it existed (its writers then see SB_RDONLY)
    pub(super) fn add_mount(&self, m: &Arc<super::mount::Mount>) {
        let _ml = super::mount::MOUNT_LOCK.write();
        self.s_mounts.lock().push_back(m);
    }

    /// Some mount of it is alive
    pub fn is_mounted(&self) -> bool {
        // A mount whose last reference went may wait for its teardown,
        // still on the list: not mounted
        self.s_mounts.lock().iter().any(|e| e.get().is_live())
    }

    /// Make the file system read-only (Linux sb_prepare_remount_readonly,
    /// then SB_RDONLY): under MOUNT_LOCK every writable mount of it, and
    /// its mountless writers, are held; with no writer anywhere it goes
    /// read-only before the holds are released, else EBUSY and nothing
    /// changed (no window where a writer sees a read-only file system
    /// that then stays writable)
    pub fn make_rdonly(&self) -> Result<(), KernelError> {
        if self.rdonly() {
            return Ok(());
        }
        // Linux walks sb->s_mounts under lock_mount_hash: no reference
        // is taken (a mount in its teardown has no writers and waits for
        // s_mounts to unlink it), and the writable set cannot change
        // between the two passes (mnt_flags is written under MOUNT_LOCK)
        let _ml = super::mount::MOUNT_LOCK.write();
        let mounts = self.s_mounts.lock();
        let rw = || {
            mounts
                .iter()
                .map(|e| e.get())
                .filter(|m| m.flags() & super::mount::MNT_READONLY == 0)
        };
        let mut free = hold_writers(&self.s_writers);
        for m in rw() {
            free &= m.hold_writers();
        }
        if free {
            self.s_flags.fetch_or(SB_RDONLY, Ordering::SeqCst);
        }
        for m in rw() {
            m.unhold_writers();
        }
        unhold_writers(&self.s_writers);
        if free { Ok(()) } else { Err(KernelError::Busy) }
    }

    /// Make the file system read-write
    pub fn make_rdwr(&self) {
        self.s_flags.fetch_and(!SB_RDONLY, Ordering::SeqCst);
    }

    /// Set the root dentry
    pub fn set_root(&self, root: DentryRef) {
        *self.root.write() = Some(root);
    }

    /// Get the root dentry
    pub fn get_root(&self) -> Option<DentryRef> {
        self.root.read().clone()
    }

    /// Allocate the next inode number
    pub fn alloc_ino(&self) -> InodeId {
        self.next_ino.fetch_add(1, Ordering::Relaxed)
    }

    /// Hold the block device open for the superblock's life
    pub fn set_bdev(&self, h: crate::block::blkdev::BdevHandle) {
        self.s_bdev.call_once(|| h);
    }

    /// The block device the filesystem is mounted from
    pub fn bdev(&self) -> Option<&Arc<crate::block::BlockDevice>> {
        self.s_bdev.get().map(|h| h.bdev())
    }

    /// Set filesystem-specific private data
    pub fn set_private(&self, data: Arc<dyn SuperBlockData>) {
        *self.private.write() = Some(data);
    }

    /// Get filesystem-specific private data
    pub fn get_private(&self) -> Option<Arc<dyn SuperBlockData>> {
        self.private.read().clone()
    }
}

/// Null superblock ops - minimal implementation
pub struct NullSuperOps;

impl SuperOps for NullSuperOps {
    fn alloc_inode(
        &self,
        _sb: &Arc<SuperBlock>,
        _mode: InodeMode,
        _i_op: &'static dyn InodeOps,
    ) -> Result<Arc<Inode>, KernelError> {
        Err(KernelError::OperationNotSupported)
    }
}

/// Static null superblock ops
pub static NULL_SUPER_OPS: NullSuperOps = NullSuperOps;

// ============================================================================
// Filesystem Type Registry
// ============================================================================

/// What file_systems_lock guards (Linux file_systems): the head of the
/// registered types, linked through [`FileSystemType::next`] in
/// registration order
pub struct FsList {
    head: Option<&'static FileSystemType>,
}

// SAFETY: one instance, `FILE_SYSTEMS`'s, made here (the field is private)
unsafe impl UniqueOwner for FsList {}

/// Linux file_systems_lock: a spin rwlock leaf, thread context only
static FILE_SYSTEMS: RwLock<FsList> = RwLock::new(FsList { head: None });

/// The registered types, in registration order
fn types(l: &FsList) -> impl Iterator<Item = &'static FileSystemType> + '_ {
    core::iter::successors(l.head, |t| *t.next.access(l))
}

/// Register a filesystem type (Linux register_filesystem): appended to
/// the list; EBUSY if one of that name is registered
pub fn register_filesystem(fs_type: &'static FileSystemType) -> Result<(), KernelError> {
    let mut l = FILE_SYSTEMS.write();
    assert!(fs_type.next.access(&l).is_none(), "fs type relinked");
    if types(&l).any(|t| t.name == fs_type.name) {
        return Err(KernelError::Busy);
    }
    match types(&l).last() {
        Some(t) => *t.next.access_mut(&mut l) = Some(fs_type),
        None => l.head = Some(fs_type),
    }
    Ok(())
}

/// Find a filesystem type by name (Linux get_fs_type)
pub fn find_filesystem(name: &str) -> Option<&'static FileSystemType> {
    types(&FILE_SYSTEMS.read()).find(|t| t.name == name)
}

/// Initialize the filesystem type registry with built-in types
///
/// Should be called during VFS initialization before any mounts.
pub fn init_fs_registry() {
    for t in [
        &super::ramfs::RAMFS_TYPE,
        &super::ramfs::tmpfs::TMPFS_TYPE,
        &super::proc::PROCFS_TYPE,
        &super::vfat::VFAT_TYPE,
        &crate::cgroup::cgroupfs::CGROUPFS_TYPE,
    ] {
        register_filesystem(t).expect("built-in fs type");
    }
}
