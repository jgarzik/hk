//! Superblock - filesystem instance representation
//!
//! Each mounted filesystem has a superblock that holds filesystem-wide
//! state and provides operations for managing inodes.

use alloc::sync::{Arc, Weak};

use crate::sync::rcu::{RcuOnceArc, RcuReadGuard};
use crate::sync::spin::{Mutex, RwLock};
use crate::sync::{LockedBy, UniqueOwner};
use crate::util::list::{Adapter, Link, WeakList};
use ::core::mem::ManuallyDrop;
use ::core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::sync;

use super::KernelError;
use super::dentry::DentryRef;
use super::inode::{Inode, InodeId, InodeMode, InodeOps, InodeRef};
use crate::util::kalloc::try_arc;

/// Superblock operations trait - filesystem-specific behavior
pub trait SuperOps: Send + Sync {
    /// Allocate a new inode
    fn alloc_inode(
        &self,
        sb: &Arc<SuperBlock>,
        mode: InodeMode,
        i_op: &'static dyn InodeOps,
    ) -> Result<InodeRef, KernelError>;

    /// Called when inode is no longer referenced
    fn drop_inode(&self, _inode: &Inode) {}

    /// Write a dirty inode's metadata (Linux ->write_inode): called by
    /// writeback, fsync and the write-back before an eviction, after
    /// its pages, for an inode marked dirty other than by its pages;
    /// `wbc` says how (a WB_SYNC_ALL caller waits through
    /// `sync_inode_metadata` for what it marks I_METADATA_WRITEBACK).
    /// Default nothing (no metadata of its own on a device).
    fn write_inode(
        &self,
        _inode: &Inode,
        _wbc: &super::pageio::fs_writeback::WritebackControl,
    ) -> Result<(), KernelError> {
        Ok(())
    }

    /// Wait for the metadata `write_inode` put in flight (Linux
    /// ->sync_inode_metadata): called by a data-integrity write
    /// (WB_SYNC_ALL, not sync(2)'s) of an inode marked
    /// I_METADATA_WRITEBACK, which only a filesystem having this sets.
    /// Default nothing.
    fn sync_inode_metadata(
        &self,
        _inode: &Inode,
        _wbc: &super::pageio::fs_writeback::WritebackControl,
    ) -> Result<(), KernelError> {
        Ok(())
    }

    /// The filesystem's own teardown, after its inodes are evicted
    /// (Linux ->put_super, from generic_shutdown_super)
    fn put_super(&self, _sb: &SuperBlock) {}

    /// Sync filesystem to backing store (no-op for in-memory fs)
    fn sync_fs(&self) -> Result<(), KernelError> {
        Ok(())
    }

    /// Filesystem statistics (Linux ->statfs: an error fails statfs(2))
    fn statfs(&self, _sb: &SuperBlock) -> Result<StatFs, KernelError> {
        Ok(StatFs::default())
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

    /// Its file handle operations (Linux s_export_op); None: handles
    /// are file ids only (AT_HANDLE_FID). Default None.
    fn export_op(&self) -> Option<&'static dyn super::exportfs::ExportOps> {
        None
    }

    /// Its positive dentries are its directory entries and stay cached
    /// until removed (Linux DCACHE_PERSISTENT, d_make_persistent):
    /// the shrinker leaves them. Default false.
    fn d_persistent(&self) -> bool {
        false
    }

    /// The root path mountinfo shows for a mount rooted at `root`
    /// (Linux ->show_path); None: the dentry's path. Default None.
    fn show_path(&self, root: &crate::fs::Dentry) -> Option<alloc::vec::Vec<u8>> {
        let _ = root;
        None
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

/// What a mount asks of a filesystem (Linux struct fs_context, the
/// part hk uses): the type, the SB_* flags a new superblock starts with
/// (Linux fc->sb_flags), the source (a device path for a device
/// filesystem) and the mount data (comma-separated options)
pub struct FsContext<'a> {
    pub fs_type: &'static FileSystemType,
    pub sb_flags: u32,
    pub source: &'a [u8],
    pub data: &'a [u8],
}

impl<'a> FsContext<'a> {
    /// A kernel mount's context: no flags, no source (Linux
    /// fs_context_for_mount for vfs_kern_mount)
    pub fn new(fs_type: &'static FileSystemType, data: &'a [u8]) -> Self {
        Self {
            fs_type,
            sb_flags: 0,
            source: b"",
            data,
        }
    }
}

/// A filesystem's mount (Linux ->get_tree): its superblock, new or
/// shared, set up, with an active reference and s_umount held for
/// writing ([`SbLocked`])
pub type MountFn = fn(fc: &FsContext<'_>) -> Result<SbLocked, KernelError>;

/// s_umount held for writing, as a superblock's shutdown gets it
pub type SbUmount<'a> = sync::RwSemWriteGuard<'a, ()>;

/// A filesystem's kill_sb (Linux ->kill_sb): it ends in
/// generic_shutdown_super, which releases s_umount
pub type KillSbFn = for<'a> fn(&'a SuperBlock, SbUmount<'a>);

/// Filesystem type descriptor
pub struct FileSystemType {
    /// Filesystem name (e.g., "ramfs", "procfs", "vfat")
    pub name: &'static str,

    /// Mount flags
    pub fs_flags: u32,

    /// Its superblock for a mount (Linux ->get_tree)
    pub mount: MountFn,

    /// Its superblock's shutdown, the last active reference's, called
    /// with s_umount held for writing (Linux ->kill_sb: kill_anon_super,
    /// kill_block_super, or the filesystem's own around one of them)
    pub kill_sb: KillSbFn,

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
    /// A bit with the kind above: a new mount in a mount namespace of
    /// another user namespace needs one already fully visible there
    /// (Linux FS_USERNS_MOUNT_RESTRICTED, SB_I_USERNS_VISIBLE): procfs
    /// and sysfs
    pub const FS_USERNS_MOUNT_RESTRICTED: u32 = 0x100;
}

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
/// instances. Entries hold a `Weak` and leave at the superblock's last
/// passive put (Linux put_super).
pub struct SbLists {
    supers: WeakList<SListA>,
}

// SAFETY: one instance, `SB_LOCK`'s, made here (the field is private)
unsafe impl UniqueOwner for SbLists {}

/// Linux sb_lock: a spin lock, thread context only; under it only list
/// changes, `sget`'s test, and setting SB_DEAD with its wakeup (the
/// flags' wait queue lock). Walkers drop it per superblock; no
/// reference to a superblock is dropped under it.
static SB_LOCK: Mutex<SbLists> = Mutex::new(SbLists {
    supers: WeakList::new(),
});

/// Its shutdown has begun: no new active reference, walkers skip it
/// (Linux SB_DYING)
const SB_DYING: u32 = 1 << 24;
/// Its filesystem's kill_sb is done: `sget` no longer tests it (Linux
/// SB_DEAD)
const SB_DEAD: u32 = 1 << 21;
/// Set up by its mount (Linux SB_BORN, set by vfs_get_tree): walkers
/// wait for it or for SB_DYING
const SB_BORN: u32 = 1 << 29;
/// Filled (Linux SB_ACTIVE): set after fill_super, cleared by the
/// shutdown
const SB_ACTIVE: u32 = 1 << 30;

/// The last passive reference is gone (Linux put_super's final part):
/// off super_blocks and its type's fs_supers (the lists' contract,
/// `WeakList`: no walker reaches it once its fields start to go), then
/// its memory. The filesystem was shut down already, by its last
/// active reference ([`SbActive`]), its ->put_super or ->kill_sb
/// releasing `s_fs_info` (Linux), so nothing here sleeps; it takes
/// sb_lock, so a passive reference is never dropped under it. Only a
/// superblock never listed (`destroy_unused_super`: sget's set failed)
/// still holds its data, dropped here in sget's thread context.
impl Drop for SuperBlock {
    fn drop(&mut self) {
        debug_assert!(
            self.super_flags(SB_DEAD),
            "superblock: freed without its shutdown"
        );
        debug_assert!(
            self.s_fs_info.is_none() || !self.s_list.is_linked(),
            "superblock: fs info outlived its kill_sb"
        );
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
    }
}

/// An active reference to a superblock (Linux s_active): what keeps its
/// filesystem running. Each mount holds one (Linux mnt_sb), as does a
/// kernel instance kept without a mount (devtmpfs); the last one's drop
/// shuts the filesystem down (Linux deactivate_super), in thread
/// context with nothing atomic held. It derefs to the passive reference
/// (`Arc`, Linux s_passive), which keeps only the memory: an `Arc` taken
/// from an inode's or dentry's `Weak` never runs the shutdown.
pub struct SbActive(Arc<SuperBlock>);

/// A superblock with an active reference and s_umount held for
/// writing (Linux: what sget_fc and ->get_tree hand back; the mounter
/// releases s_umount once the superblock is set up and born). Dropped
/// without [`SbLocked::unlock`] (an error path) it goes as Linux
/// deactivate_locked_super.
pub struct SbLocked(ManuallyDrop<Arc<SuperBlock>>);

impl SbLocked {
    /// # Safety
    /// The caller holds one of `sb`'s active references and its
    /// s_umount for writing through a leaked guard, and hands both over.
    unsafe fn new(sb: Arc<SuperBlock>) -> Self {
        Self(ManuallyDrop::new(sb))
    }

    /// Release s_umount, keeping the active reference (Linux
    /// up_write(&sb->s_umount) after vfs_get_tree)
    pub fn unlock(self) -> SbActive {
        let mut me = ManuallyDrop::new(self);
        // SAFETY: taken once; `me` is never dropped
        let sb = unsafe { ManuallyDrop::take(&mut me.0) };
        // SAFETY: held, by the type's contract
        drop(unsafe { sb.s_umount.write_held() });
        SbActive(sb)
    }
}

impl SbActive {
    /// Another active reference to `sb` unless its last one went (Linux
    /// atomic_inc_not_zero(&sb->s_active))
    pub fn try_get(sb: &Arc<SuperBlock>) -> Option<Self> {
        sb.s_active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                (v != 0).then(|| v + 1)
            })
            .ok()
            .map(|_| Self(sb.clone()))
    }

    /// Take s_umount for writing, this active reference kept (Linux
    /// atomic_inc(&sb->s_active) then down_write(&sb->s_umount), as
    /// devtmpfs_get_tree)
    pub fn lock(self) -> SbLocked {
        let me = ManuallyDrop::new(self);
        // SAFETY: read once; `me` is never dropped, so the active
        // reference moves
        let sb = unsafe { core::ptr::read(&raw const me.0) };
        sb.s_umount.write().leak();
        // SAFETY: the active reference moved in, s_umount leaked
        unsafe { SbLocked::new(sb) }
    }
}

impl core::ops::Deref for SbLocked {
    type Target = Arc<SuperBlock>;
    fn deref(&self) -> &Arc<SuperBlock> {
        &self.0
    }
}

impl Drop for SbLocked {
    fn drop(&mut self) {
        // SAFETY: taken once, here
        let sb = unsafe { ManuallyDrop::take(&mut self.0) };
        // SAFETY: held, by the type's contract
        let g = unsafe { sb.s_umount.write_held() };
        deactivate_locked_super(&sb, g);
    }
}

impl Clone for SbActive {
    /// Another active reference, one being held (Linux
    /// atomic_inc(&sb->s_active): clone_mnt, a get_tree_single reuse)
    fn clone(&self) -> Self {
        self.0.s_active.fetch_add(1, Ordering::Relaxed);
        Self(self.0.clone())
    }
}

impl core::ops::Deref for SbActive {
    type Target = Arc<SuperBlock>;
    fn deref(&self) -> &Arc<SuperBlock> {
        &self.0
    }
}

impl Drop for SbActive {
    /// Linux deactivate_super: a put that leaves others is a decrement;
    /// the last one takes s_umount for writing and shuts the filesystem
    /// down (deactivate_locked_super), then the passive reference goes
    fn drop(&mut self) {
        let sb = &self.0;
        // atomic_add_unless(&s_active, -1, 1)
        let more = sb
            .s_active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                (v > 1).then(|| v - 1)
            })
            .is_ok();
        if more {
            return;
        }
        // The shutdown sleeps (s_umount, writeback, the device's
        // open_mutex): a last active reference dropped in atomic context
        // is reported here
        crate::sync::might_sleep();
        deactivate_locked_super(sb, sb.s_umount.write());
    }
}

/// Drop an active reference with s_umount held for writing (Linux
/// deactivate_locked_super): the last one shuts the filesystem down;
/// the lock is released either way
fn deactivate_locked_super(sb: &SuperBlock, g: sync::RwSemWriteGuard<'_, ()>) {
    if sb.s_active.fetch_sub(1, Ordering::AcqRel) != 1 {
        return;
    }
    (sb.fs_type.kill_sb)(sb, g);
    kill_super_notify(sb);
}

/// The kill_sb of a filesystem with an anonymous device number (Linux
/// kill_anon_super): the generic shutdown, SB_DEAD, the number freed
pub fn kill_anon_super(sb: &SuperBlock, g: SbUmount<'_>) {
    let dev = sb.dev();
    generic_shutdown_super(sb, g);
    kill_super_notify(sb);
    free_anon_bdev(dev);
}

/// The kill_sb of a device filesystem (Linux kill_block_super): the
/// generic shutdown (s_umount released), then the device written back
/// and released
pub fn kill_block_super(sb: &SuperBlock, g: SbUmount<'_>) {
    generic_shutdown_super(sb, g);
    if let Some(b) = sb.bdev() {
        let _ = crate::block::blkdev::sync_blockdev(b);
    }
    let file = sb.s_bdev_file.lock().take();
    drop(file);
}

/// Anonymous device numbers (Linux unnamed_dev_ida): minors of major 0
static UNNAMED_DEV_IDA: crate::util::ida::Ida = crate::util::ida::Ida::new();

/// Bits of a device number's minor (Linux MINORBITS)
const MINORBITS: u32 = 20;

/// An anonymous device number (Linux get_anon_bdev): the lowest free
/// minor of major 0 from 1 (an fsid of 0 counts as invalid), EMFILE once
/// they are all taken. Called under sb_lock: the bitmap grows atomically
/// (Linux GFP_ATOMIC).
fn get_anon_bdev() -> Result<u32, KernelError> {
    use crate::mm::page_alloc::Gfp;
    use crate::util::kalloc::with_gfp;
    let dev = with_gfp(Gfp::ATOMIC, || UNNAMED_DEV_IDA.try_alloc_min(1))?;
    if dev >= 1 << MINORBITS {
        UNNAMED_DEV_IDA.free(dev);
        return Err(KernelError::ProcessFileLimit);
    }
    Ok(dev)
}

/// Give an anonymous device number back (Linux free_anon_bdev)
fn free_anon_bdev(dev: u32) {
    UNNAMED_DEV_IDA.free(dev & ((1 << MINORBITS) - 1));
}

/// A new superblock's identity, an anonymous device number (Linux
/// set_anon_super): `sget`'s `set`, under sb_lock
pub fn set_anon_super(sb: &SuperBlock) -> Result<(), KernelError> {
    sb.s_dev.store(get_anon_bdev()?, Ordering::Relaxed);
    Ok(())
}

/// A device superblock's identity, its device's number (Linux
/// set_bdev_super)
fn set_bdev_super(sb: &SuperBlock, dev: u32) -> Result<(), KernelError> {
    sb.s_dev.store(dev, Ordering::Relaxed);
    Ok(())
}

/// Change `sb` to read-only or read-write with the options `data`
/// (Linux reconfigure_super; the caller holds s_umount for writing):
/// going read-only refuses writers first (EBUSY while any holds write
/// access, nothing changed), then the filesystem's ->reconfigure runs
/// (vfat's writes what is dirty back: Linux fat_reconfigure's
/// sync_filesystem, while SB_RDONLY is still clear), then the flag
/// changes. An error from ->reconfigure changes nothing.
pub fn reconfigure_super(sb: &SuperBlock, ro: bool, data: &[u8]) -> Result<(), KernelError> {
    let was_ro = sb.rdonly();
    if ro && !was_ro {
        sb.prepare_remount_ro()?;
    } else if !ro && was_ro {
        // Linux sb_start_ro_state_change: writers stay refused until
        // the change ends
        sb.s_readonly_remount.store(true, Ordering::SeqCst);
    }
    let r = sb.s_op.remount(sb, data);
    if r.is_ok() {
        sb.set_rdonly(ro);
    }
    // Linux sb_end_ro_state_change
    sb.s_readonly_remount.store(false, Ordering::SeqCst);
    r
}

/// What every filesystem's shutdown does (Linux generic_shutdown_super),
/// under s_umount held for writing, which it releases: inotify watches
/// get IN_UNMOUNT and go (fsnotify_sb_delete), the dentry tree is
/// dropped (shrink_dcache_for_umount), what is dirty is written back
/// while the device is still open (sync_filesystem), SB_ACTIVE is
/// cleared (an inode put from then on is written back with wait
/// before its eviction, `inode::iput_final`) and the inodes leave
/// s_inodes (evict_inodes); then SB_DYING tells walkers and mounters
pub fn generic_shutdown_super(sb: &SuperBlock, g: SbUmount<'_>) {
    let root = sb.root.write().take();
    if let Some(root) = root {
        crate::io::inotify::sb_delete(sb);
        super::dentry::d_drop_tree(&root);
        drop(root);
        // Linux ignores sync_filesystem's error here too
        let _ = super::pageio::sync::sync_filesystem(sb);
        sb.s_flags.fetch_and(!SB_ACTIVE, Ordering::Relaxed);
        super::inode::sb_list_drain(&sb.s_inodes);
        sb.s_op.put_super(sb);
    } else {
        sb.s_flags.fetch_and(!SB_ACTIVE, Ordering::Relaxed);
        // A fill that failed before its root may have made inodes that
        // outlive it: unlinked all the same, so their eviction never
        // reaches this superblock's list once its memory goes
        super::inode::sb_list_drain(&sb.s_inodes);
    }
    sb.super_wake(SB_DYING);
    drop(g);
}

/// Its kill_sb is done (Linux kill_super_notify): SB_DEAD is set under
/// sb_lock, so no `sget` test runs on it from then on, and a mounter
/// waiting for it (`grab_super`) is woken; once (kill_anon_super
/// notifies before freeing its number, deactivate_locked_super after)
fn kill_super_notify(sb: &SuperBlock) {
    if sb.super_flags(SB_DEAD) {
        return;
    }
    let _l = SB_LOCK.lock();
    sb.super_wake(SB_DEAD);
}

/// List a new superblock (Linux sget_fc's insert: super_blocks tail,
/// fs_supers head)
fn sb_add(l: &mut SbLists, sb: &Arc<SuperBlock>) {
    sb.fs_type.fs_supers.access_mut(l).push_front(sb);
    l.supers.push_back(sb);
}

/// The next superblock after `cur` (the first if None) on the list `on`
/// picks that is not dying, taken (passive) under sb_lock (Linux
/// __iterate_supers' step: skip SB_DYING, refcount_inc_not_zero); `cur`
/// is held, so still listed. A dying one is skipped before any
/// reference is taken: none is dropped under the lock.
fn next_live<A: Adapter<Item = SuperBlock>>(
    cur: Option<&Arc<SuperBlock>>,
    on: impl Fn(&SbLists) -> &WeakList<A>,
) -> Option<Arc<SuperBlock>> {
    let l = SB_LOCK.lock();
    let list = on(&l);
    let it = match cur {
        // SAFETY: `c` is alive (held), so its last put has not unlinked
        // it, and only that put does
        Some(c) => unsafe { list.iter_after(c) },
        None => list.iter(),
    };
    it.filter(|e| !e.get().super_flags(SB_DYING))
        .find_map(|e| e.upgrade())
}

/// `f` on every superblock that is set up and not shutting down (Linux
/// iterate_supers): each taken (passive) under sb_lock, then, with no
/// lock, s_umount taken for reading once it is born (Linux
/// super_lock_shared: one that died meanwhile is skipped) and held
/// while `f` runs; `f` may sleep. Superblocks listed meanwhile may be
/// missed.
pub fn iterate_supers(f: impl FnMut(&Arc<SuperBlock>)) {
    walk(f, |l| &l.supers, super_lock_shared);
}

/// `f` on every superblock of `fs_type` (Linux iterate_supers_type)
pub fn iterate_supers_type(fs_type: &'static FileSystemType, f: impl FnMut(&Arc<SuperBlock>)) {
    walk(f, |l| fs_type.fs_supers.access(l), super_lock_shared);
}

/// `f` on every running superblock of `fs_type`, each held by an active
/// reference taken without s_umount (Linux proc_invalidate_siblings_dcache:
/// atomic_inc_not_zero(&sb->s_active), then deactivate_super): no wait
/// for a superblock being filled, remounted or shut down; `f` may sleep,
/// and so may the put of a last active reference after it
pub fn iterate_supers_type_active(fs_type: &'static FileSystemType, mut f: impl FnMut(&SbActive)) {
    let mut cur: Option<Arc<SuperBlock>> = None;
    while let Some(sb) = next_live(cur.as_ref(), |l| fs_type.fs_supers.access(l)) {
        if let Some(a) = SbActive::try_get(&sb) {
            f(&a);
        }
        cur = Some(sb);
    }
}

/// [`iterate_supers`] for reclaim, which may run under any s_umount and
/// must not wait: a superblock whose s_umount is not free for reading
/// at once is skipped (Linux super_cache_scan's super_trylock_shared)
pub fn iterate_supers_trylock(f: impl FnMut(&Arc<SuperBlock>)) {
    walk(f, |l| &l.supers, super_trylock_shared);
}

fn walk<A: Adapter<Item = SuperBlock>>(
    mut f: impl FnMut(&Arc<SuperBlock>),
    on: impl Fn(&SbLists) -> &WeakList<A>,
    lock: for<'a> fn(&'a SuperBlock) -> Option<sync::RwSemReadGuard<'a, ()>>,
) {
    let mut cur: Option<Arc<SuperBlock>> = None;
    while let Some(sb) = next_live(cur.as_ref(), &on) {
        if let Some(g) = lock(&sb) {
            f(&sb);
            drop(g);
        }
        // The previous one goes with sb_lock released (Linux put_super
        // outside it): its last passive put takes the lock
        cur = Some(sb);
    }
}

/// Wait until `sb` is born or dying, then take s_umount for reading
/// unless it is dying (Linux super_lock_shared); the caller holds a
/// passive reference
fn super_lock_shared(sb: &SuperBlock) -> Option<sync::RwSemReadGuard<'_, ()>> {
    sb.wait_flags(SB_BORN | SB_DYING);
    if sb.super_flags(SB_DYING) {
        return None;
    }
    let g = sb.s_umount.read();
    // Shut down meanwhile (the shutdown sets SB_DYING under s_umount)
    (!sb.super_flags(SB_DYING)).then_some(g)
}

/// [`super_lock_shared`] for writing (Linux super_lock_excl)
fn super_lock_excl(sb: &SuperBlock) -> Option<sync::RwSemWriteGuard<'_, ()>> {
    sb.wait_flags(SB_BORN | SB_DYING);
    if sb.super_flags(SB_DYING) {
        return None;
    }
    let g = sb.s_umount.write();
    (!sb.super_flags(SB_DYING)).then_some(g)
}

/// s_umount for reading if free at once, on a superblock born and not
/// dying (Linux super_trylock_shared)
fn super_trylock_shared(sb: &SuperBlock) -> Option<sync::RwSemReadGuard<'_, ()>> {
    let g = sb.s_umount.try_read()?;
    (sb.super_flags(SB_BORN) && !sb.super_flags(SB_DYING)).then_some(g)
}

/// Trade a passive reference to a listed superblock for an active one
/// with s_umount held for writing (Linux grab_super): once it is born,
/// unless it is dying; a dying one is waited for until its kill_sb is
/// done (SB_DEAD), so a new mount never overlaps the old one's shutdown
/// (the device it releases), and None returned
fn grab_super(sb: Arc<SuperBlock>) -> Option<SbLocked> {
    let got = super_lock_excl(&sb).is_some_and(|g| {
        let got = sb
            .s_active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                (v != 0).then(|| v + 1)
            })
            .is_ok();
        if got {
            g.leak();
        }
        got
    });
    if got {
        // SAFETY: the active reference just taken, s_umount leaked
        return Some(unsafe { SbLocked::new(sb) });
    }
    sb.wait_flags(SB_DEAD);
    None
}

/// A new superblock (Linux alloc_super): not listed, with SB_* flags
/// `sb_flags`, one active reference and s_umount held for writing
/// (leaked: no one else can reach it yet, so it is free)
fn alloc_super(
    fs_type: &'static FileSystemType,
    s_op: &'static dyn SuperOps,
    sb_flags: u32,
) -> Result<Arc<SuperBlock>, KernelError> {
    let sb = try_arc(SuperBlock::init(fs_type, s_op, sb_flags))?;
    sb.s_umount.write().leak();
    Ok(sb)
}

/// Free a superblock `alloc_super` made and nothing listed (Linux
/// destroy_unused_super): nothing was set up on it, so no shutdown
fn destroy_unused_super(sb: Arc<SuperBlock>) {
    sb.s_flags.fetch_or(SB_DYING | SB_DEAD, Ordering::Release);
    sb.s_active.store(0, Ordering::Relaxed);
    // SAFETY: `alloc_super` leaked the hold; this is its release
    drop(unsafe { sb.s_umount.write_held() });
}

/// The superblock of `fc`'s type that `test` accepts (None: always a
/// new one), else a new one listed for it, with an active reference and
/// s_umount held for writing (Linux sget_fc). `test` runs under sb_lock
/// (a spin lock: it must not sleep), on any superblock not yet dead,
/// and takes no reference; a match is taken by `grab_super`, and one
/// that turns out dying is waited for and the search repeated. A new
/// superblock is allocated with no lock held, given its identity by
/// `set` under sb_lock (Linux set_anon_super, set_bdev_super: it must
/// not sleep), listed, and returned not yet born: the caller fills it
/// (Linux fill_super) with s_umount held, while walkers and other
/// mounters wait for SB_BORN.
pub fn sget(
    fc: &FsContext<'_>,
    s_op: &'static dyn SuperOps,
    test: Option<&dyn Fn(&SuperBlock) -> bool>,
    set: &dyn Fn(&SuperBlock) -> Result<(), KernelError>,
) -> Result<SbLocked, KernelError> {
    let mut s: Option<Arc<SuperBlock>> = None;
    loop {
        let mut l = SB_LOCK.lock();
        if let Some(test) = test {
            let old = fc
                .fs_type
                .fs_supers
                .access(&l)
                .iter()
                .filter(|e| {
                    let x = e.get();
                    !x.super_flags(SB_DEAD) && test(x)
                })
                .find_map(|e| e.upgrade());
            if let Some(old) = old {
                drop(l);
                let Some(a) = grab_super(old) else {
                    continue;
                };
                if let Some(s) = s {
                    destroy_unused_super(s);
                }
                return Ok(a);
            }
        }
        let Some(new) = s.take() else {
            drop(l);
            s = Some(alloc_super(fc.fs_type, s_op, fc.sb_flags)?);
            continue;
        };
        if let Err(e) = set(&new) {
            drop(l);
            destroy_unused_super(new);
            return Err(e);
        }
        sb_add(&mut l, &new);
        drop(l);
        // SAFETY: `alloc_super`'s active reference and leaked s_umount
        return Ok(unsafe { SbLocked::new(new) });
    }
}

/// The superblock `test` picks (None: a new one), filled by `fill` if
/// new (Linux get_tree_super: sget_fc, then fill_super under s_umount;
/// SB_ACTIVE once filled). A failed fill shuts the new superblock down
/// (deactivate_locked_super).
pub fn get_tree_super(
    fc: &FsContext<'_>,
    s_op: &'static dyn SuperOps,
    test: Option<&dyn Fn(&SuperBlock) -> bool>,
    fill: impl FnOnce(&Arc<SuperBlock>) -> Result<(), KernelError>,
) -> Result<SbLocked, KernelError> {
    let sb = sget(fc, s_op, test, &set_anon_super)?;
    if !sb.has_root() {
        fill(&sb)?;
        sb.set_active();
    }
    Ok(sb)
}

/// A new superblock for every mount (Linux get_tree_nodev)
pub fn get_tree_nodev(
    fc: &FsContext<'_>,
    s_op: &'static dyn SuperOps,
    fill: impl FnOnce(&Arc<SuperBlock>) -> Result<(), KernelError>,
) -> Result<SbLocked, KernelError> {
    get_tree_super(fc, s_op, None, fill)
}

/// One superblock for every mount of the type (Linux get_tree_single)
pub fn get_tree_single(
    fc: &FsContext<'_>,
    s_op: &'static dyn SuperOps,
    fill: impl FnOnce(&Arc<SuperBlock>) -> Result<(), KernelError>,
) -> Result<SbLocked, KernelError> {
    get_tree_super(fc, s_op, Some(&|_| true), fill)
}

/// The block device at `path` (Linux lookup_bdev): ENOTBLK for
/// anything else, ENODEV for a device number no disk has
fn lookup_bdev(path: &[u8]) -> Result<Arc<BlockDevice>, KernelError> {
    let d = super::namei::lookup_path(path)?;
    let inode = d.get_inode().ok_or(KernelError::NotFound)?;
    if inode.mode().file_type() != Some(super::inode::FileType::BlockDev) {
        return Err(KernelError::NotBlockDevice);
    }
    crate::block::get_blkdev(inode.rdev).ok_or(KernelError::NoDevice)
}

/// The superblock on the block device `fc.source` names (Linux
/// get_tree_bdev): one per device (sget_dev, test_bdev_super), shared
/// by every mount of it; a mount that would change its read-only state
/// is EBUSY. A new one holds the device open and claimed for its
/// exclusive use (setup_bdev_super: holder the superblock; EBUSY if
/// another holder has it; under the disk's open_mutex, failing for a
/// removed device; a rescan sees it in use), then `fill`
pub fn get_tree_bdev(
    fc: &FsContext<'_>,
    s_op: &'static dyn SuperOps,
    fill: impl FnOnce(&Arc<SuperBlock>) -> Result<(), KernelError>,
) -> Result<SbLocked, KernelError> {
    if fc.source.is_empty() {
        return Err(KernelError::InvalidArgument);
    }
    let bdev = lookup_bdev(fc.source)?;
    let dev = bdev.dev.encode();
    let test = |sb: &SuperBlock| sb.s_dev.load(Ordering::Relaxed) == dev;
    let sb = sget(fc, s_op, Some(&test), &|sb| set_bdev_super(sb, dev))?;
    if sb.has_root() {
        // Don't summarily change the RO/RW state (Linux): the active
        // reference grab_super took goes (deactivate_locked_super)
        if (fc.sb_flags ^ sb.s_flags.load(Ordering::Relaxed)) & SB_RDONLY != 0 {
            return Err(KernelError::Busy);
        }
        return Ok(sb);
    }
    // A writable mount of a read-only device is EACCES (Linux
    // setup_bdev_super: a write open of a bdev_read_only device)
    if fc.sb_flags & SB_RDONLY == 0 && bdev.ro() {
        return Err(KernelError::PermissionDenied);
    }
    sb.set_bdev(bdev.open_handle(Some(sb.bdev_holder()))?);
    fill(&sb)?;
    sb.set_active();
    Ok(sb)
}

/// The mountable superblock of `fc` (Linux vfs_get_tree): its type's
/// ->get_tree, then SB_BORN; returned with s_umount held, which the
/// mounter releases ([`SbLocked::unlock`]) before making the mount
pub fn vfs_get_tree(fc: &FsContext<'_>) -> Result<SbLocked, KernelError> {
    let sb = (fc.fs_type.mount)(fc)?;
    sb.set_born();
    Ok(sb)
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

    /// SB_* flags (Linux s_flags): SB_RDONLY, SB_SYNCHRONOUS, SB_DIRSYNC,
    /// and its life's SB_BORN, SB_DYING, SB_DEAD (set once each, waited
    /// for through `var_waitqueue`)
    s_flags: AtomicU32,
    /// Its active references (Linux s_active, [`SbActive`]); its
    /// passive ones are the `Arc`'s count (Linux s_passive). Zero once
    /// the last active one went: never raised again.
    s_active: AtomicU32,

    /// Holders of write access to objects without a mount (internal
    /// files), and the WRITE_HOLD bit (see get_write); writes through a
    /// mount count on the mount
    s_writers: AtomicU64,
    /// A read-only state change is in progress (Linux
    /// s_readonly_remount): writers are refused, as on a read-only
    /// file system, from the holders' check until the change ends
    s_readonly_remount: AtomicBool,
    /// Its mounts (Linux s_mounts, through `Mount.mnt_instance`), for a
    /// read-only remount to hold their writers: a spin leaf, added to
    /// under MOUNT_LOCK; a mount leaves it in its teardown
    pub(super) s_mounts: Mutex<WeakList<MntInstanceA>>,

    /// Inode numbers, handed out in per-CPU batches (Linux shmem's
    /// ino_batch, get_next_ino)
    next_ino: crate::util::id_batch::IdBatch,

    /// Name hashing and comparison for its dentries, if names match
    /// more than their bytes (Linux s_d_op): set before its root
    /// dentry is made
    s_d_op: spin::Once<&'static super::dentry::DentryOps>,

    /// Its device number (Linux s_dev, a kernel dev_t: major << 20 |
    /// minor): the device's for a device filesystem, else an anonymous
    /// one; set by `sget`'s `set` before it is listed, fixed after
    s_dev: AtomicU32,

    /// Largest file size (Linux s_maxbytes): writes are cut short at it,
    /// growing past it is EFBIG. Set by the filesystem at mount.
    s_maxbytes: AtomicU64,

    /// log2 of its block size (Linux s_blocksize_bits; s_blocksize is
    /// 1 << it): what its new inodes' i_blkbits start as. A page by
    /// default (Linux: what the pseudo and memory file systems set); a
    /// device filesystem sets it at mount (`sb_set_blocksize`), before
    /// it makes inodes. Read lock-free.
    s_blocksize_bits: core::sync::atomic::AtomicU8,

    /// Its filesystem's data (Linux s_fs_info): set once, by its fill
    /// or sget's set; released by the filesystem's ->put_super or
    /// ->kill_sb (or its failed fill) in thread context, a grace period
    /// after it leaves the cell (`kill_fs_info`). Read under an RCU
    /// guard or as a reference ([`SuperBlock::fs_info`]): once released
    /// it reads as None (EIO to a filesystem's late callers)
    s_fs_info: RcuOnceArc<FsInfo>,

    /// The block device a device filesystem is mounted from (Linux
    /// s_bdev): a reference to the device, not an open
    s_bdev: spin::Once<Arc<BlockDevice>>,
    /// The device held open until its shutdown's kill_sb releases it
    /// (Linux s_bdev_file): a spin leaf, taken to set and to take it
    s_bdev_file: Mutex<Option<crate::block::blkdev::BdevHandle>>,

    /// Its inodes (Linux s_inodes, under inode_sb_list_lock)
    pub(super) s_inodes: super::inode::SbInodes,

    /// Mutex for cross-directory renames (like Linux s_vfs_rename_mutex)
    ///
    /// Serializes all cross-directory renames on this filesystem to
    /// prevent races during ancestor relationship checks. Same-directory
    /// renames don't need this mutex.
    pub s_vfs_rename_mutex: sync::Mutex<()>,
    /// Remount and other changes of the superblock's state, and its
    /// shutdown (Linux s_umount, a sleeping rw_semaphore): written by
    /// remount and by the last active reference's shutdown, read by
    /// superblock walks and bind remount; inside namespace_sem
    pub s_umount: sync::RwSem<()>,
    /// Writeback errors of its files, reported once to each open file by
    /// syncfs (Linux s_wb_err)
    pub s_wb_err: crate::util::errseq::ErrSeq,
}

/// A superblock's `s_wb_err` stays a valid atomic after the value is
/// dropped (its last passive reference), while a `Weak` keeps the
/// memory: `sb_wb_err_set`
const _: () = assert!(!core::mem::needs_drop::<crate::util::errseq::ErrSeq>());

/// Record a writeback error on the superblock `sb` names, taking no
/// reference (Linux errseq_set(&inode->i_sb->s_wb_err), any context: a
/// bio's completion in hardirq, where dropping a reference could free
/// the superblock). An inode names its superblock by such a `Weak`,
/// which keeps the memory until the inode's teardown drops it; a
/// superblock already shut down takes the error harmlessly. A `Weak`
/// of no superblock (`Weak::new`) does nothing.
pub fn sb_wb_err_set(sb: &Weak<SuperBlock>, e: KernelError) {
    if Weak::ptr_eq(sb, &Weak::new()) {
        return;
    }
    let p = Weak::as_ptr(sb);
    // SAFETY: the live `Weak` keeps the allocation (ArcInner) of a real
    // superblock; `s_wb_err` is an atomic with no drop glue (asserted
    // above), so its bytes stay a valid `ErrSeq` even once the value was
    // dropped, and only atomic operations touch it
    let err = unsafe { &(*p).s_wb_err };
    err.set(e);
}

/// Largest file offset on a 64-bit kernel (Linux MAX_LFS_FILESIZE,
/// LLONG_MAX): the default `s_maxbytes`
pub const MAX_LFS_FILESIZE: u64 = i64::MAX as u64;

/// Trait for filesystem-specific superblock data
pub trait SuperBlockData: core::any::Any + Send + Sync {}

impl SuperBlock {
    /// Its dentries hash and compare names with `op` (Linux
    /// set_default_d_op): before the root dentry is made
    pub fn set_d_op(&self, op: &'static super::dentry::DentryOps) {
        self.s_d_op.call_once(|| op);
    }

    /// Its dentries' name operations (Linux s_d_op)
    pub fn d_op(&self) -> Option<&'static super::dentry::DentryOps> {
        self.s_d_op.get().copied()
    }

    /// A superblock's fields, before `alloc_super` puts it in its `Arc`
    /// (Linux alloc_super's initialisation): one active reference
    fn init(fs_type: &'static FileSystemType, s_op: &'static dyn SuperOps, flags: u32) -> Self {
        Self {
            fs_type,
            s_list: Link::new(),
            s_instances: Link::new(),
            root: RwLock::new(None),
            s_op,
            s_flags: AtomicU32::new(flags),
            s_active: AtomicU32::new(1),
            s_d_op: spin::Once::new(),
            s_writers: AtomicU64::new(0),
            s_readonly_remount: AtomicBool::new(false),
            s_mounts: Mutex::new(WeakList::new()),
            next_ino: crate::util::id_batch::IdBatch::new(),
            s_dev: AtomicU32::new(0),
            s_maxbytes: AtomicU64::new(MAX_LFS_FILESIZE),
            s_blocksize_bits: core::sync::atomic::AtomicU8::new(crate::mm::page::PAGE_SHIFT as u8),
            s_fs_info: RcuOnceArc::none(),
            s_bdev: spin::Once::new(),
            s_bdev_file: Mutex::new(None),
            s_inodes: super::inode::sb_inodes(),
            s_vfs_rename_mutex: sync::Mutex::new(()),
            s_wb_err: crate::util::errseq::ErrSeq::new(),
            s_umount: sync::RwSem::new(()),
        }
    }

    /// Filled (Linux sb->s_flags |= SB_ACTIVE after fill_super)
    pub fn set_active(&self) {
        self.s_flags.fetch_or(SB_ACTIVE, Ordering::Relaxed);
    }

    /// Filled and not yet shut down (Linux SB_ACTIVE)
    pub fn active(&self) -> bool {
        self.s_flags.load(Ordering::Relaxed) & SB_ACTIVE != 0
    }

    /// Its device number (Linux s_dev)
    pub fn dev(&self) -> u32 {
        self.s_dev.load(Ordering::Relaxed)
    }

    /// Its device number's major and minor (Linux MAJOR, MINOR)
    pub fn dev_major_minor(&self) -> (u32, u32) {
        let d = self.dev();
        (d >> MINORBITS, d & ((1 << MINORBITS) - 1))
    }

    /// Its device number as st_dev (Linux new_encode_dev)
    pub fn st_dev(&self) -> u64 {
        let (ma, mi) = self.dev_major_minor();
        let (ma, mi) = (u64::from(ma), u64::from(mi));
        (mi & 0xff) | (ma << 8) | ((mi & !0xff) << 12)
    }

    /// It has its root dentry: filled (Linux sb->s_root set)
    pub fn has_root(&self) -> bool {
        self.root.read().is_some()
    }

    /// Any of `f`'s SB_BORN/SB_DYING/SB_DEAD bits is set (Linux
    /// super_flags: acquire, pairs with `super_wake`)
    fn super_flags(&self, f: u32) -> bool {
        self.s_flags.load(Ordering::Acquire) & f != 0
    }

    /// Set `flag` and wake its waiters (Linux super_wake: release, so a
    /// waiter seeing it sees what came before)
    fn super_wake(&self, flag: u32) {
        self.s_flags.fetch_or(flag, Ordering::Release);
        core::sync::atomic::fence(Ordering::SeqCst);
        self.flags_wq().wake_all();
    }

    /// Sleep until one of `f`'s bits is set (Linux wait_var_event on
    /// s_flags)
    fn wait_flags(&self, f: u32) {
        if !self.super_flags(f) {
            self.flags_wq().wait_event(|| self.super_flags(f));
        }
    }

    fn flags_wq(&self) -> &'static crate::sync::waitqueue::WaitQueue {
        crate::sync::waitqueue::var_waitqueue((&raw const self.s_flags).addr())
    }

    /// Its mount set it up (Linux vfs_get_tree's SB_BORN): walkers and
    /// mounters waiting for it go on
    pub fn set_born(&self) {
        self.super_wake(SB_BORN);
    }

    /// Largest file size on this filesystem (Linux s_maxbytes)
    pub fn maxbytes(&self) -> u64 {
        self.s_maxbytes.load(Ordering::Relaxed)
    }

    /// Set the largest file size (at mount)
    pub fn set_maxbytes(&self, max: u64) {
        self.s_maxbytes.store(max, Ordering::Relaxed);
    }

    /// log2 of its block size (Linux s_blocksize_bits)
    pub fn s_blocksize_bits(&self) -> u8 {
        self.s_blocksize_bits.load(Ordering::Relaxed)
    }

    /// Its block size (Linux s_blocksize)
    pub fn s_blocksize(&self) -> u32 {
        1 << self.s_blocksize_bits()
    }

    /// Set its block size (`sb_set_blocksize`, at mount)
    pub(crate) fn set_s_blocksize(&self, size: u32) {
        debug_assert!(size.is_power_of_two());
        self.s_blocksize_bits
            .store(size.trailing_zeros() as u8, Ordering::Relaxed);
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
        get_write(&self.s_writers, || self.readonly_or_remounting())?;
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

    /// Read-only, or a read-only state change in progress (Linux
    /// mnt_is_readonly's superblock part: s_readonly_remount, then
    /// sb_rdonly)
    pub fn readonly_or_remounting(&self) -> bool {
        self.s_readonly_remount.load(Ordering::SeqCst) || self.rdonly()
    }

    /// Refuse writers for a read-only remount (Linux
    /// sb_prepare_remount_readonly): under MOUNT_LOCK every writable
    /// mount of it, and its mountless writers, are held; with no writer
    /// anywhere the change starts (`s_readonly_remount`) before the
    /// holds are released, else EBUSY and nothing changed
    fn prepare_remount_ro(&self) -> Result<(), KernelError> {
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
            self.s_readonly_remount.store(true, Ordering::SeqCst);
        }
        for m in rw() {
            m.unhold_writers();
        }
        unhold_writers(&self.s_writers);
        if free { Ok(()) } else { Err(KernelError::Busy) }
    }

    /// Set or clear SB_RDONLY
    fn set_rdonly(&self, ro: bool) {
        if ro {
            self.s_flags.fetch_or(SB_RDONLY, Ordering::SeqCst);
        } else {
            self.s_flags.fetch_and(!SB_RDONLY, Ordering::SeqCst);
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

    /// Allocate the next inode number
    pub fn alloc_ino(&self) -> InodeId {
        self.next_ino.next()
    }

    /// Its claim of its block device (Linux holder sb): its address
    pub fn bdev_holder(&self) -> crate::block::claim::Holder {
        core::ptr::from_ref(self) as usize
    }

    /// The block device it is mounted from, held open until its
    /// shutdown (Linux s_bdev, s_bdev_file); once, at mount
    pub fn set_bdev(&self, h: crate::block::blkdev::BdevHandle) {
        self.s_bdev.call_once(|| h.bdev().clone());
        let old = self.s_bdev_file.lock().replace(h);
        debug_assert!(old.is_none(), "superblock: device set twice");
    }

    /// The block device the filesystem is mounted from
    pub fn bdev(&self) -> Option<&Arc<crate::block::BlockDevice>> {
        self.s_bdev.get()
    }

    /// Give it its filesystem's data (Linux sb->s_fs_info = ...): once,
    /// by its fill or sget's set, before anything reads it
    pub fn set_fs_info(&self, data: Arc<FsInfo>) {
        let set = self.s_fs_info.set(data);
        debug_assert!(set.is_ok(), "superblock: fs info set twice");
    }

    /// A reference to its filesystem's data as a `T` (Linux
    /// MSDOS_SB(sb) etc.); None once its put_super or kill_sb released
    /// it, or for another type. Dropped in thread context: the last
    /// reference may be the one that frees it
    pub fn fs_info<T: SuperBlockData>(&self) -> Option<Arc<T>> {
        let a: Arc<dyn core::any::Any + Send + Sync> = self.fs_info_arc()?;
        a.downcast::<T>().ok()
    }

    /// Its filesystem's data as a `T`, borrowed for the RCU read `g`
    /// (Linux rcu_dereference(sb->s_fs_info): sget's tests)
    pub fn fs_info_rcu<'a, T: SuperBlockData>(&'a self, g: &'a RcuReadGuard) -> Option<&'a T> {
        let d: &dyn core::any::Any = &*self.s_fs_info.read(g)?.0;
        d.downcast_ref::<T>()
    }

    /// A reference to its filesystem's data (an inode's RCU-read copy
    /// of procfs's options)
    pub fn fs_info_arc(&self) -> Option<Arc<dyn SuperBlockData>> {
        let g = crate::sync::rcu::read_lock();
        let d = self.s_fs_info.read(&g).map(|d| d.0.clone());
        drop(g);
        d
    }

    /// Release its filesystem's data (Linux the free of s_fs_info by
    /// ->put_super, ->kill_sb or a failed fill_super): out of the cell,
    /// then after a grace period (its RCU readers) its reference goes,
    /// here, in thread context (the data's drop may sleep: an inode's
    /// put, a namespace's); a reference still held elsewhere frees it
    /// at its own drop
    pub fn kill_fs_info(&self) {
        drop(self.s_fs_info.take());
    }
}

/// What `SuperBlock.s_fs_info` holds: sized, so an RCU pointer names
/// it; made before `set_fs_info` (which may run under sb_lock)
pub struct FsInfo(Arc<dyn SuperBlockData>);

impl FsInfo {
    pub fn new(data: Arc<dyn SuperBlockData>) -> Result<Arc<Self>, KernelError> {
        try_arc(Self(data))
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
    ) -> Result<InodeRef, KernelError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::dentry::Dentry;
    use core::sync::atomic::AtomicUsize;

    /// Evictions of `T1`'s inodes
    static EVICTS: AtomicUsize = AtomicUsize::new(0);

    /// Checks the context its inodes are evicted in: the shutdown of a
    /// last active reference, s_umount held for writing, with its
    /// superblock's memory intact (a passive reference can be taken,
    /// and dropped, harmlessly)
    struct EvictOps;

    impl InodeOps for EvictOps {
        fn lookup(&self, _dir: &Inode, _name: &[u8]) -> Result<InodeRef, KernelError> {
            Err(KernelError::NotFound)
        }

        fn evict_inode(&self, inode: &Inode) {
            let sb = inode
                .superblock()
                .expect("evicted after its superblock's memory");
            assert!(
                sb.s_umount.try_read().is_none(),
                "evicted outside the shutdown"
            );
            assert_eq!(sb.s_active.load(Ordering::Relaxed), 0);
            EVICTS.fetch_add(1, Ordering::Relaxed);
        }
    }

    static EVICT_OPS: EvictOps = EvictOps;

    /// A buffer write error reaches s_wb_err through the inode's `Weak`
    /// with no reference taken (syncfs reports it), and harmlessly once
    /// the superblock's last passive reference went
    #[test]
    fn wb_err_through_weak() {
        let sb = alloc_super(&T1, &NULL_SUPER_OPS, 0).unwrap();
        let since = sb.s_wb_err.sample();
        let w = Arc::downgrade(&sb);
        sb_wb_err_set(&w, KernelError::Io);
        assert_eq!(sb.s_wb_err.check(since), Some(KernelError::Io));
        assert_eq!(Arc::strong_count(&sb), 1);
        destroy_unused_super(sb);
        sb_wb_err_set(&w, KernelError::Io);
        sb_wb_err_set(&Weak::new(), KernelError::Io);
    }

    /// A root directory whose eviction `EvictOps` checks
    fn t_fill(sb: &Arc<SuperBlock>, ops: &'static dyn InodeOps) -> Result<(), KernelError> {
        let root = Inode::alloc(Inode::new(
            1,
            InodeMode::directory(0o755),
            0,
            0,
            0,
            crate::time::TIMEKEEPER.current_time(),
            Arc::downgrade(sb),
            ops,
        ))?;
        sb.set_root(DentryRef::new(Dentry::new_root(root, Arc::downgrade(sb)))?);
        Ok(())
    }

    fn t1_mount(fc: &FsContext<'_>) -> Result<SbLocked, KernelError> {
        get_tree_nodev(fc, &NULL_SUPER_OPS, |sb| t_fill(sb, &EVICT_OPS))
    }

    static T1: FileSystemType = FileSystemType {
        name: "sbtest1",
        fs_flags: 0,
        mount: t1_mount,
        kill_sb: kill_anon_super,
        file_ops: &crate::fs::RAMFS_FILE_OPS,
        next: FsNext::new(None),
        fs_supers: FsSupers::new(WeakList::new()),
    };

    /// One superblock shared by every mount (Linux get_tree_single); its
    /// fill checks it runs as Linux fill_super: listed, s_umount held
    /// for writing, not yet born; it fails while `T2_FAIL` is set
    fn t2_mount(fc: &FsContext<'_>) -> Result<SbLocked, KernelError> {
        get_tree_single(fc, &NULL_SUPER_OPS, |sb| {
            assert!(sb.s_umount.try_read().is_none());
            assert!(!sb.super_flags(SB_BORN));
            assert!(sb.s_list.is_linked() && sb.s_instances.is_linked());
            if T2_FAIL.load(Ordering::Relaxed) {
                return Err(KernelError::Io);
            }
            T2_FILLS.fetch_add(1, Ordering::Relaxed);
            t_fill(sb, &crate::fs::inode::NULL_INODE_OPS)
        })
    }

    static T2_FAIL: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    static T2_FILLS: AtomicUsize = AtomicUsize::new(0);

    static T2: FileSystemType = FileSystemType {
        name: "sbtest2",
        fs_flags: 0,
        mount: t2_mount,
        kill_sb: kill_anon_super,
        file_ops: &crate::fs::RAMFS_FILE_OPS,
        next: FsNext::new(None),
        fs_supers: FsSupers::new(WeakList::new()),
    };

    /// An inode a failing fill made and kept, and a passive reference
    /// to its superblock (`T3`)
    static T3_KEPT: std::sync::Mutex<Option<(InodeRef, Arc<SuperBlock>)>> =
        std::sync::Mutex::new(None);

    /// A fill that makes an inode, keeps it, and fails before setting
    /// a root
    fn t3_mount(fc: &FsContext<'_>) -> Result<SbLocked, KernelError> {
        get_tree_nodev(fc, &NULL_SUPER_OPS, |sb| {
            let inode = Inode::alloc(Inode::new(
                2,
                InodeMode::regular(0o644),
                0,
                0,
                0,
                crate::time::TIMEKEEPER.current_time(),
                Arc::downgrade(sb),
                &crate::fs::inode::NULL_INODE_OPS,
            ))?;
            *T3_KEPT.lock().unwrap() = Some((inode, Arc::clone(sb)));
            Err(KernelError::Io)
        })
    }

    static T3: FileSystemType = FileSystemType {
        name: "sbtest3",
        fs_flags: 0,
        mount: t3_mount,
        kill_sb: kill_anon_super,
        file_ops: &crate::fs::RAMFS_FILE_OPS,
        next: FsNext::new(None),
        fs_supers: FsSupers::new(WeakList::new()),
    };

    /// Drops of `T4Data`
    static T4_DROPS: AtomicUsize = AtomicUsize::new(0);

    /// A filesystem's data that counts its drop
    struct T4Data;

    impl SuperBlockData for T4Data {}

    impl Drop for T4Data {
        fn drop(&mut self) {
            T4_DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Another type's data
    struct NullData;

    impl SuperBlockData for NullData {}

    fn t4_mount(fc: &FsContext<'_>) -> Result<SbLocked, KernelError> {
        let info = FsInfo::new(try_arc(T4Data)?)?;
        get_tree_nodev(fc, &NULL_SUPER_OPS, |sb| {
            sb.set_fs_info(info);
            t_fill(sb, &crate::fs::inode::NULL_INODE_OPS)
        })
    }

    /// Linux kernfs_kill_sb's shape: kill_anon_super, then the data
    fn t4_kill_sb(sb: &SuperBlock, g: SbUmount<'_>) {
        kill_anon_super(sb, g);
        sb.kill_fs_info();
    }

    static T4: FileSystemType = FileSystemType {
        name: "sbtest4",
        fs_flags: 0,
        mount: t4_mount,
        kill_sb: t4_kill_sb,
        file_ops: &crate::fs::RAMFS_FILE_OPS,
        next: FsNext::new(None),
        fs_supers: FsSupers::new(WeakList::new()),
    };

    fn get(t: &'static FileSystemType) -> Result<SbActive, KernelError> {
        vfs_get_tree(&FsContext::new(t, b"")).map(SbLocked::unlock)
    }

    /// A temporary passive reference (an `evict_inode`'s upgrade, a
    /// walker's) that outlives the last active one (the umount): the
    /// shutdown runs in the active put, under s_umount, and the
    /// passive put afterwards only frees the memory
    #[test]
    fn passive_ref_outliving_umount_runs_no_shutdown() {
        let active = get(&T1).unwrap();
        let passive = Arc::clone(&active);
        let other = active.clone();
        drop(active);
        assert!(
            other.get_root().is_some(),
            "shut down with an active reference left"
        );
        assert_eq!(EVICTS.load(Ordering::Relaxed), 0);
        drop(other);
        // The last active put shut it down, though `passive` lives on
        assert!(passive.get_root().is_none());
        assert!(passive.super_flags(SB_DYING) && passive.super_flags(SB_DEAD));
        assert_eq!(EVICTS.load(Ordering::Relaxed), 1);
        // Walkers no longer reach it
        let mut seen = false;
        iterate_supers_type(&T1, |sb| seen |= Arc::ptr_eq(sb, &passive));
        assert!(!seen);
        let gone = Arc::downgrade(&passive);
        drop(passive);
        assert!(gone.upgrade().is_none());
        assert_eq!(EVICTS.load(Ordering::Relaxed), 1);
    }

    /// A fill that fails before its root leaves no inode on the
    /// superblock's list once shut down (under INODE_SB_LIST_LOCK, not
    /// by the list's drop with the memory, which an eviction racing it
    /// would reach): checked while a passive reference keeps the memory
    #[test]
    fn failed_fill_unlinks_its_inodes() {
        assert!(matches!(get(&T3), Err(KernelError::Io)));
        let (inode, sb) = T3_KEPT.lock().unwrap().take().unwrap();
        assert!(sb.super_flags(SB_DEAD));
        assert!(!inode.i_sb_list.is_linked(), "left on s_inodes");
        drop(sb);
        drop(inode);
    }

    /// `sget` shares a live superblock (Linux grab_super: one more
    /// active reference) and never a dead one, even while a passive
    /// reference keeps it listed; a new one is filled once, listed and
    /// locked, born only after; a failed fill shuts the new one down
    /// (deactivate_locked_super)
    #[test]
    fn sget_shares_live_not_dead() {
        T2_FAIL.store(true, Ordering::Relaxed);
        assert!(matches!(get(&T2), Err(KernelError::Io)));
        T2_FAIL.store(false, Ordering::Relaxed);
        let a = get(&T2).unwrap();
        assert!(a.super_flags(SB_BORN) && a.super_flags(SB_ACTIVE));
        let b = get(&T2).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(T2_FILLS.load(Ordering::Relaxed), 1);
        assert_eq!(a.s_active.load(Ordering::Relaxed), 2);
        let passive = Arc::clone(&a);
        drop((a, b));
        assert!(passive.super_flags(SB_DEAD));
        let c = get(&T2).unwrap();
        assert!(!Arc::ptr_eq(&c, &passive));
        assert_eq!(c.s_active.load(Ordering::Relaxed), 1);
        assert_eq!(T2_FILLS.load(Ordering::Relaxed), 2);
    }

    /// s_fs_info goes at the filesystem's kill_sb (Linux: in thread
    /// context, the shutdown's), not with the superblock's memory: a
    /// passive reference outliving the umount finds none; a reference
    /// taken before keeps the data until it drops
    #[test]
    fn fs_info_goes_at_kill_sb() {
        let active = get(&T4).unwrap();
        let passive = Arc::clone(&active);
        let held = active.fs_info::<T4Data>().unwrap();
        assert!(active.fs_info::<NullData>().is_none());
        drop(active);
        assert!(passive.fs_info::<T4Data>().is_none());
        assert!(passive.s_fs_info.is_none());
        assert_eq!(T4_DROPS.load(Ordering::Relaxed), 0);
        drop(held);
        assert_eq!(T4_DROPS.load(Ordering::Relaxed), 1);
        drop(passive);
        assert_eq!(T4_DROPS.load(Ordering::Relaxed), 1);
    }
}
