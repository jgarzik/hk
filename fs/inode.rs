//! Inode - file/directory object representation
//!
//! Following Linux VFS design, an inode represents a file object
//! independent of its name(s) in the directory tree.

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use core::mem::ManuallyDrop;
use core::ptr::NonNull;

use crate::sync::rcu::RcuHead;
use crate::sync::spin::{Mutex, MutexGuard, RwLock};
use crate::sync::{LockedBy, UniqueOwner};
use crate::util::kalloc::try_box_uninit;
use crate::util::list;
use ::core::sync::atomic::{AtomicI64, AtomicU16, AtomicU32, AtomicU64, Ordering};

use crate::sync::RwSem;
use crate::sync::waitqueue::var_waitqueue;

use super::KernelError;
use super::superblock::SuperBlock;

// Re-export device types from chardev module
pub use crate::fs::chardev::{DevId, DeviceType};

use crate::task::Cred;
/// Re-export credential types from task module
pub use crate::task::{Gid, Uid};

/// Re-export Timespec from time module
pub use crate::time::Timespec;

/// Unique inode identifier within a filesystem
pub type InodeId = u64;

/// File type bits (matches Linux S_IFMT)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum FileType {
    /// Regular file
    Regular = 0o100000,
    /// Directory
    Directory = 0o040000,
    /// Symbolic link
    Symlink = 0o120000,
    /// Character device
    CharDev = 0o020000,
    /// Block device
    BlockDev = 0o060000,
    /// FIFO (named pipe)
    Fifo = 0o010000,
    /// Socket
    Socket = 0o140000,
}

impl FileType {
    /// Convert from raw mode bits
    pub fn from_mode(mode: u16) -> Option<Self> {
        match mode & 0o170000 {
            0o100000 => Some(FileType::Regular),
            0o040000 => Some(FileType::Directory),
            0o120000 => Some(FileType::Symlink),
            0o020000 => Some(FileType::CharDev),
            0o060000 => Some(FileType::BlockDev),
            0o010000 => Some(FileType::Fifo),
            0o140000 => Some(FileType::Socket),
            _ => None,
        }
    }
}

/// Inode mode (file type + permissions)
#[derive(Debug, Clone, Copy)]
pub struct InodeMode(pub u16);

impl InodeMode {
    /// Create mode for a regular file with given permissions
    pub fn regular(perm: u16) -> Self {
        Self((FileType::Regular as u16) | (perm & 0o7777))
    }

    /// Create mode for a directory with given permissions
    pub fn directory(perm: u16) -> Self {
        Self((FileType::Directory as u16) | (perm & 0o7777))
    }

    /// Create mode for a symlink
    pub fn symlink() -> Self {
        Self((FileType::Symlink as u16) | 0o777)
    }

    /// Get the file type
    pub fn file_type(&self) -> Option<FileType> {
        FileType::from_mode(self.0)
    }

    /// Check if this is a directory
    pub fn is_dir(&self) -> bool {
        self.file_type() == Some(FileType::Directory)
    }

    /// Check if this is a regular file
    pub fn is_file(&self) -> bool {
        self.file_type() == Some(FileType::Regular)
    }

    /// Check if this is a symlink
    pub fn is_symlink(&self) -> bool {
        self.file_type() == Some(FileType::Symlink)
    }

    /// Check if this is a character device
    pub fn is_chrdev(&self) -> bool {
        self.file_type() == Some(FileType::CharDev)
    }

    /// Check if this is a block device
    pub fn is_blkdev(&self) -> bool {
        self.file_type() == Some(FileType::BlockDev)
    }

    /// Check if this is a FIFO (named pipe)
    pub fn is_fifo(&self) -> bool {
        self.file_type() == Some(FileType::Fifo)
    }

    /// Check if this is a socket
    pub fn is_socket(&self) -> bool {
        self.file_type() == Some(FileType::Socket)
    }

    /// Check if this is any device (char or block)
    pub fn is_device(&self) -> bool {
        self.is_chrdev() || self.is_blkdev()
    }

    /// Create mode for a character device with given permissions
    pub fn chardev(perm: u16) -> Self {
        Self((FileType::CharDev as u16) | (perm & 0o7777))
    }

    /// Create mode for a block device with given permissions
    pub fn blockdev(perm: u16) -> Self {
        Self((FileType::BlockDev as u16) | (perm & 0o7777))
    }

    /// Create mode for a FIFO (named pipe) with given permissions
    pub fn fifo(perm: u16) -> Self {
        Self((FileType::Fifo as u16) | (perm & 0o7777))
    }

    /// Create mode for a socket with given permissions
    pub fn socket(perm: u16) -> Self {
        Self((FileType::Socket as u16) | (perm & 0o7777))
    }

    /// Get permission bits (lower 12 bits)
    pub fn perm(&self) -> u16 {
        self.0 & 0o7777
    }

    /// Get raw mode value
    pub fn raw(&self) -> u16 {
        self.0
    }
}

/// What following a symlink gives (Linux ->get_link)
pub enum Link {
    /// The path to walk on with
    Text(alloc::vec::Vec<u8>),
    /// The object a magic link leads to (Linux nd_jump_link)
    Jump(super::Path),
}

/// What a directory's lookup found (Linux ->lookup's d_splice_alias
/// of the dentry it was given, with its d_time / d_fsdata set first)
pub struct Found {
    /// The inode; None: no such name, kept as a negative dentry
    pub inode: Option<InodeRef>,
    /// The new dentry's `d_time`, what the filesystem's d_revalidate
    /// checks (vfat's directory version, kernfs's revision)
    pub d_time: u64,
}

/// Inode operations trait - filesystem-specific behavior
pub trait InodeOps: Send + Sync {
    /// Look up a child entry in a directory inode
    fn lookup(&self, dir: &Inode, name: &[u8]) -> Result<InodeRef, KernelError>;

    /// [`InodeOps::lookup`] as the dcache asks it (Linux ->lookup): a
    /// filesystem that keeps negative dentries (one its d_revalidate
    /// can tell is stale) answers a missing name with `inode` None,
    /// both stamped with `d_time`. Default: `lookup`, ENOENT caching
    /// nothing (Linux procfs's ERR_PTR(-ENOENT); a negative dentry
    /// killed at its last put, ramfs's always_delete_dentry).
    fn lookup_neg(&self, dir: &Inode, name: &[u8]) -> Result<Found, KernelError> {
        Ok(Found {
            inode: Some(self.lookup(dir, name)?),
            d_time: 0,
        })
    }

    /// A directory that is permanently empty (Linux is_empty_dir_inode:
    /// make_empty_dir_inode's operations), so a mount on it hides
    /// nothing. Default no.
    fn is_empty_dir(&self, _inode: &Inode) -> bool {
        false
    }

    /// Access check for `mask` (MAY_* bits) by `cred` (Linux
    /// ->permission). With MAY_NOT_BLOCK an RCU walk asks, as for
    /// `DentryOps::d_revalidate`'s LOOKUP_RCU. Default: generic_permission (mode bits plus
    /// capability overrides); /proc/sys overrides it with sysctl_perm.
    fn permission(&self, inode: &Inode, cred: &Cred, mask: u32) -> Result<(), KernelError> {
        super::dac::generic_permission(cred, inode, mask)
    }

    /// Whether attributes may change at all (Linux ->setattr refusing
    /// before setattr_prepare): chmod, chown and utimes ask first.
    /// Default yes; the shared anonymous inode refuses (EOPNOTSUPP).
    fn setattr_ok(&self, inode: &Inode) -> Result<(), KernelError> {
        let _ = inode;
        Ok(())
    }

    /// A time update (Linux ->update_time, else generic_update_time):
    /// atime, or mtime and ctime, become `now`. A filesystem with
    /// coarser times or times of its own on disk overrides it (vfat).
    fn update_time(&self, inode: &Inode, what: TimeUpdate, now: Timespec) {
        generic_update_time(inode, what, now);
    }

    /// A setattr's end (Linux ->setattr: utimes, truncate, chmod, chown),
    /// under i_rwsem, after the VFS's checks and its changes of mode,
    /// ids and size: the times it computed (ATTR_ATIME, ATTR_MTIME,
    /// ATTR_CTIME) set, and the inode kept (a filesystem with its own
    /// copy saves it: kernfs's kn->iattr; vfat marks it dirty). Default
    /// setattr_copy's times.
    fn setattr(
        &self,
        inode: &Inode,
        atime: Option<Timespec>,
        mtime: Option<Timespec>,
        ctime: Option<Timespec>,
    ) {
        setattr_copy_times(inode, atime, mtime, ctime);
    }

    /// Create a new file in a directory
    fn create(&self, dir: &Inode, name: &[u8], mode: InodeMode) -> Result<InodeRef, KernelError> {
        let _ = (dir, name, mode);
        Err(KernelError::OperationNotSupported)
    }

    /// chmod to `perm` may change the mode (after the owner check; Linux
    /// ->setattr refusing ATTR_MODE); default yes
    fn chmod_ok(&self, inode: &Inode, perm: u16) -> Result<(), KernelError> {
        let _ = (inode, perm);
        Ok(())
    }

    /// chown may change the owner or group (after the owner checks;
    /// Linux ->setattr refusing ATTR_UID / ATTR_GID); default yes
    fn chown_ok(&self, inode: &Inode) -> Result<(), KernelError> {
        let _ = inode;
        Ok(())
    }

    /// chown is about to set the owner (`uid`) and/or the group (`gid`),
    /// under i_rwsem, before it does (Linux ->setattr seeing ATTR_UID /
    /// ATTR_GID ahead of simple_setattr: tracefs pins them). Default
    /// nothing.
    fn setattr_ids(&self, inode: &Inode, uid: bool, gid: bool) {
        let _ = (inode, uid, gid);
    }

    /// A new regular file of `dir`'s file system with no name (nlink 0)
    /// for O_TMPFILE (Linux ->tmpfile); default EOPNOTSUPP
    fn tmpfile(&self, dir: &Inode, mode: InodeMode) -> Result<InodeRef, KernelError> {
        let _ = (dir, mode);
        Err(KernelError::OperationNotSupported)
    }

    /// Create a new directory
    fn mkdir(&self, dir: &Inode, name: &[u8], mode: InodeMode) -> Result<InodeRef, KernelError> {
        let _ = (dir, name, mode);
        Err(KernelError::OperationNotSupported)
    }

    /// Create a character or block device node (Linux i_op->mknod)
    fn mknod(
        &self,
        dir: &Inode,
        name: &[u8],
        mode: InodeMode,
        rdev: DevId,
    ) -> Result<InodeRef, KernelError> {
        let _ = (dir, name, mode, rdev);
        Err(KernelError::OperationNotSupported)
    }

    /// Remove file `name`, whose dentry is `d` (Linux ->unlink(dir,
    /// dentry): a file system may stamp the dentry, which the VFS then
    /// makes negative or drops)
    fn unlink(
        &self,
        dir: &Inode,
        name: &[u8],
        d: &super::dentry::Dentry,
    ) -> Result<(), KernelError> {
        let _ = (dir, name, d);
        Err(KernelError::OperationNotSupported)
    }

    /// Remove directory `name`, whose dentry is `d` (Linux ->rmdir, as
    /// [`InodeOps::unlink`])
    fn rmdir(
        &self,
        dir: &Inode,
        name: &[u8],
        d: &super::dentry::Dentry,
    ) -> Result<(), KernelError> {
        let _ = (dir, name, d);
        Err(KernelError::OperationNotSupported)
    }

    /// Read the target of a symbolic link
    fn readlink(&self, inode: &Inode) -> Result<alloc::vec::Vec<u8>, KernelError> {
        let _ = inode;
        Err(KernelError::OperationNotSupported)
    }

    /// Follow symlink `inode` (Linux ->get_link; never asked of one
    /// with an `i_link`): its text, or for a magic link the object it
    /// jumps to (nd_jump_link), which RESOLVE_NO_MAGICLINKS refuses
    /// (ELOOP) and a scoped walk never takes (EXDEV). With `rcu` an RCU
    /// walk asks (Linux get_link with a NULL dentry): `inode` is
    /// borrowed as for `DentryOps::d_revalidate`'s LOOKUP_RCU, nothing may
    /// sleep, and
    /// ECHILD sends the walk to ref mode to ask again. Default: ECHILD
    /// in RCU mode, else the text `readlink` gives; procfs's fd, cwd,
    /// root, exe and namespace links jump.
    fn get_link(&self, inode: &Inode, rcu: bool) -> Result<Link, KernelError> {
        if rcu {
            return Err(KernelError::NoChild);
        }
        Ok(Link::Text(self.readlink(inode)?))
    }

    /// Create a symbolic link
    fn symlink(&self, dir: &Inode, name: &[u8], target: &[u8]) -> Result<InodeRef, KernelError> {
        let _ = (dir, name, target);
        Err(KernelError::OperationNotSupported)
    }

    /// Create a hard link (new directory entry pointing to existing inode)
    fn link(&self, dir: &Inode, name: &[u8], inode: &InodeRef) -> Result<(), KernelError> {
        let _ = (dir, name, inode);
        Err(KernelError::OperationNotSupported)
    }

    /// Rename a file or directory
    ///
    /// Moves the entry named `old_name` from `old_dir` to `new_dir` with name `new_name`.
    /// If `new_name` already exists in `new_dir`, it is replaced (unless flags prevent it).
    ///
    /// # Arguments
    /// * `old_dir` - Source directory inode
    /// * `old_name` - Name of entry to rename
    /// * `new_dir` - Destination directory inode
    /// * `new_name` - New name for the entry
    /// * `flags` - RENAME_* flags (NOREPLACE, EXCHANGE, etc.)
    fn rename(
        &self,
        old_dir: &Inode,
        old_name: &[u8],
        new_dir: &InodeRef,
        new_name: &[u8],
        flags: u32,
    ) -> Result<(), KernelError> {
        let _ = (old_dir, old_name, new_dir, new_name, flags);
        Err(KernelError::OperationNotSupported)
    }

    /// Preallocate or punch a range (Linux f_op->fallocate), called by
    /// sys_fallocate under i_rwsem after vfs_fallocate's checks.
    /// Default: not supported (EOPNOTSUPP), as Linux for a filesystem
    /// without the op.
    fn fallocate(
        &self,
        inode: &InodeRef,
        mode: i32,
        offset: u64,
        len: u64,
    ) -> Result<(), KernelError> {
        let _ = (inode, mode, offset, len);
        Err(KernelError::OperationNotSupported)
    }

    /// Truncate or extend a file to a specified length
    ///
    /// If the file was larger than length, the extra data is discarded.
    /// If the file was shorter, it is extended with null bytes.
    fn truncate(&self, inode: &InodeRef, length: u64) -> Result<(), KernelError> {
        let _ = (inode, length);
        Err(KernelError::OperationNotSupported)
    }

    /// MAP_SHARED mappings of the file map its page cache (`i_data`,
    /// `filemap::fault`) rather than private copies
    fn maps_cache(&self) -> bool {
        false
    }

    /// The last reference to the inode is gone (Linux ->evict_inode):
    /// release what the object still owns, e.g. the blocks of an
    /// unlinked file. Called from the inode's teardown (`evict`), where
    /// the last reference goes: a context that may sleep (Linux iput's
    /// might_sleep), so it may do I/O.
    fn evict_inode(&self, inode: &Inode) {
        let _ = inode;
    }

    /// Whether stat may report on the inode at all (the error a Linux
    /// ->getattr returns before filling anything). Default yes; procfs
    /// hides a hidepid=invisible process (ENOENT).
    fn getattr_ok(&self, inode: &Inode) -> Result<(), KernelError> {
        let _ = inode;
        Ok(())
    }

    /// The attributes stat reports (Linux ->getattr); default
    /// `generic_fillattr`
    fn getattr(&self, inode: &Inode) -> InodeAttr {
        generic_fillattr(inode)
    }

    // =========================================================================
    // Extended attribute operations
    // =========================================================================

    /// Get an extended attribute value
    ///
    /// # Arguments
    /// * `inode` - The inode to get the attribute from
    /// * `name` - The attribute name (e.g., "user.foo")
    /// * `value` - Buffer to store the attribute value (empty to query size)
    ///
    /// # Returns
    /// The size of the attribute value on success.
    /// If `value` is empty, returns the size that would be needed.
    fn getxattr(&self, inode: &Inode, name: &[u8], value: &mut [u8]) -> Result<usize, KernelError> {
        let _ = (inode, name, value);
        Err(KernelError::OperationNotSupported)
    }

    /// Set an extended attribute value
    ///
    /// # Arguments
    /// * `inode` - The inode to set the attribute on
    /// * `name` - The attribute name (e.g., "user.foo")
    /// * `value` - The attribute value
    /// * `flags` - XATTR_CREATE (fail if exists) or XATTR_REPLACE (fail if not exists)
    fn setxattr(
        &self,
        inode: &Inode,
        name: &[u8],
        value: &[u8],
        flags: u32,
    ) -> Result<(), KernelError> {
        let _ = (inode, name, value, flags);
        Err(KernelError::OperationNotSupported)
    }

    /// List extended attribute names
    ///
    /// # Arguments
    /// * `inode` - The inode to list attributes from
    /// * `list` - Buffer to store null-separated attribute names (empty to query size)
    ///
    /// # Returns
    /// The total size of all attribute names (including null terminators).
    /// If `list` is empty, returns the size that would be needed.
    fn listxattr(&self, inode: &Inode, list: &mut [u8]) -> Result<usize, KernelError> {
        let _ = (inode, list);
        Err(KernelError::OperationNotSupported)
    }

    /// Remove an extended attribute
    ///
    /// # Arguments
    /// * `inode` - The inode to remove the attribute from
    /// * `name` - The attribute name to remove
    fn removexattr(&self, inode: &Inode, name: &[u8]) -> Result<(), KernelError> {
        let _ = (inode, name);
        Err(KernelError::OperationNotSupported)
    }
}

/// Inode attributes returned by getattr
#[derive(Debug, Clone)]
pub struct InodeAttr {
    pub ino: InodeId,
    pub mode: InodeMode,
    pub uid: Uid,
    pub gid: Gid,
    pub size: u64,
    pub nlink: u32,
    /// Device ID for character/block devices (major/minor)
    pub rdev: DevId,
    /// Last access time
    pub atime: Timespec,
    /// Last modification time
    pub mtime: Timespec,
    /// Last status change time
    pub ctime: Timespec,
    /// Preferred I/O size (Linux kstat.blksize)
    pub blksize: u32,
    /// 512-byte blocks allocated (Linux kstat.blocks)
    pub blocks: u64,
}

/// The attributes as the inode holds them (Linux generic_fillattr);
/// timestamps read lock-free. The block size is the page size, every hk
/// file system's i_blocksize; the blocks are the size's.
pub fn generic_fillattr(inode: &Inode) -> InodeAttr {
    InodeAttr {
        ino: inode.ino,
        mode: inode.mode(),
        uid: inode.uid(),
        gid: inode.gid(),
        size: inode.get_size(),
        nlink: inode.get_nlink(),
        rdev: inode.rdev,
        atime: inode.atime(),
        mtime: inode.mtime(),
        ctime: inode.ctime(),
        blksize: crate::mm::PAGE_SIZE as u32,
        // No hk file system keeps i_blocks: the size's 512-byte blocks
        blocks: inode.get_size().div_ceil(512),
    }
}

/// Filesystem-specific data attached to an inode
pub trait InodeData: Send + Sync + AsAny {}

/// Trait for downcasting to concrete types
pub trait AsAny: Send + Sync {
    fn as_any(&self) -> &dyn core::any::Any;
}

/// One inode timestamp (Linux i_{a,m,c}time_sec / _nsec): two atomics,
/// read lock-free; a reader racing a writer can see the new seconds with
/// the old nanoseconds, as on Linux
struct InodeTime {
    sec: AtomicI64,
    nsec: AtomicU32,
}

impl InodeTime {
    fn new(t: Timespec) -> Self {
        Self {
            sec: AtomicI64::new(t.sec),
            nsec: AtomicU32::new(t.nsec),
        }
    }

    fn get(&self) -> Timespec {
        Timespec {
            sec: self.sec.load(Ordering::Relaxed),
            nsec: self.nsec.load(Ordering::Relaxed),
        }
    }

    fn set(&self, t: Timespec) {
        self.sec.store(t.sec, Ordering::Relaxed);
        self.nsec.store(t.nsec, Ordering::Relaxed);
    }
}

/// Bits of `Inode.i_flags`
pub mod iflags {
    /// A removed directory (Linux S_DEAD): set by rmdir, or a rename
    /// replacing it, under its i_rwsem; mount refuses it
    pub const S_DEAD: u32 = 1 << 4;
    /// An active swap area (Linux S_SWAPFILE)
    pub const S_SWAPFILE: u32 = 1 << 8;
    /// linkat may name it though it has no link (Linux I_LINKABLE, an
    /// i_state bit there)
    pub const I_LINKABLE: u32 = 1 << 16;
}

/// Bits of `Inode.i_state` (Linux i_state, the same values), each set
/// and cleared under `i_lock`
pub mod istate {
    /// Its writeback is running (Linux I_SYNC): set by the writer, which
    /// pins the inode, cleared with a wakeup of its waiters
    /// (`fs_writeback`)
    pub const I_SYNC: u32 = 1 << 1;
    /// Metadata fdatasync may skip is dirty: times (Linux I_DIRTY_SYNC)
    pub const I_DIRTY_SYNC: u32 = 1 << 4;
    /// Metadata the data needs is dirty: size, clusters (Linux
    /// I_DIRTY_DATASYNC)
    pub const I_DIRTY_DATASYNC: u32 = 1 << 5;
    /// A page of its cache is dirty (Linux I_DIRTY_PAGES)
    pub const I_DIRTY_PAGES: u32 = 1 << 6;
    /// The last reference went and the inode is being written back
    /// before its eviction (Linux I_WILL_FREE)
    pub const I_WILL_FREE: u32 = 1 << 7;
    /// The last reference went and the inode is being evicted and freed
    /// (Linux I_FREEING)
    pub const I_FREEING: u32 = 1 << 8;
    /// On a writeback pass's `b_io` or `b_more_io` (Linux
    /// I_SYNC_QUEUED): a dirtying leaves it there for the pass to
    /// requeue
    pub const I_SYNC_QUEUED: u32 = 1 << 17;
    /// Its ->write_inode put metadata in flight that a data-integrity
    /// write must wait for through ->sync_inode_metadata (Linux
    /// I_METADATA_WRITEBACK)
    pub const I_METADATA_WRITEBACK: u32 = 1 << 19;
    /// Linux I_DIRTY_INODE
    pub const I_DIRTY_INODE: u32 = I_DIRTY_SYNC | I_DIRTY_DATASYNC;
    /// Linux I_DIRTY
    pub const I_DIRTY: u32 = I_DIRTY_INODE | I_DIRTY_PAGES;
    /// Linux I_DIRTY_ALL: I_DIRTY, there being no lazytime
    /// (I_DIRTY_TIME)
    pub const I_DIRTY_ALL: u32 = I_DIRTY;
}

use istate::{I_FREEING, I_WILL_FREE};

/// A counted reference to an inode (Linux an igrab'd or ihold'd
/// `struct inode *`): a clone takes one (ihold), a drop puts it (iput);
/// the last put evicts the inode (Linux iput_final -> evict ->
/// destroy_inode) and frees its memory a grace period later (i_callback)
///
/// # Invariants
/// Holds one of its inode's `i_count` references, which keep it live.
pub struct InodeRef(NonNull<Inode>);

// SAFETY: a counted reference to a Sync inode, usable from any thread
unsafe impl Send for InodeRef {}
// SAFETY: as above; `&InodeRef` only reads the inode
unsafe impl Sync for InodeRef {}

impl InodeRef {
    /// Both are the same inode
    pub fn ptr_eq(a: &Self, b: &Self) -> bool {
        a.0 == b.0
    }

    /// The inode's address (its identity)
    pub fn as_ptr(this: &Self) -> *const Inode {
        this.0.as_ptr()
    }

    /// Its references (Linux icount_read): exact only where none can be
    /// taken or put meanwhile
    pub fn count(this: &Self) -> u32 {
        this.i_count.load(Ordering::Acquire)
    }

    /// Give the reference up as a pointer, for [`InodeRef::from_raw`]
    pub fn into_raw(this: Self) -> *const Inode {
        ManuallyDrop::new(this).0.as_ptr()
    }

    /// Take back a reference [`InodeRef::into_raw`] gave up
    ///
    /// # Safety
    /// `p` came from `into_raw`, and is taken back once.
    pub unsafe fn from_raw(p: *const Inode) -> Self {
        // SAFETY: from `into_raw` (the caller), never null
        Self(unsafe { NonNull::new_unchecked(p.cast_mut()) })
    }
}

impl Clone for InodeRef {
    /// ihold: the caller's reference keeps the count above zero
    fn clone(&self) -> Self {
        let n = self.i_count.fetch_add(1, Ordering::Relaxed);
        debug_assert!(n >= 1, "inode: ihold of a dead inode");
        Self(self.0)
    }
}

impl core::ops::Deref for InodeRef {
    type Target = Inode;
    fn deref(&self) -> &Inode {
        // SAFETY: the type invariant keeps the inode live
        unsafe { self.0.as_ref() }
    }
}

impl Drop for InodeRef {
    /// iput
    fn drop(&mut self) {
        // SAFETY: the reference this handle holds, given up once
        unsafe { iput(self.0) };
    }
}

/// Put one unless it is the last (Linux atomic_add_unless(c, -1, 1)):
/// false if the count is one
fn put_unless_last(c: &AtomicU32) -> bool {
    let mut n = c.load(Ordering::Relaxed);
    loop {
        debug_assert!(n >= 1, "inode: iput of a dead inode");
        if n == 1 {
            return false;
        }
        // Release: every access through this reference before it goes
        match c.compare_exchange_weak(n, n - 1, Ordering::Release, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(v) => n = v,
        }
    }
}

/// Take one unless none is left (Linux atomic_add_unless(c, 1, 0))
fn get_unless_zero(c: &AtomicU32) -> bool {
    let mut n = c.load(Ordering::Relaxed);
    while n != 0 {
        // Acquire: what the holders did before (Linux: a full fence)
        match c.compare_exchange_weak(n, n + 1, Ordering::Acquire, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(v) => n = v,
        }
    }
    false
}

/// Put a reference to the inode at `p` (Linux iput): one that is not
/// the last only counts down; the last is dropped under `i_lock`, where
/// a racing [`Inode::igrab`] takes its own, and evicts the inode
/// (`iput_final`). May sleep: the eviction may write the inode back and
/// free its blocks (Linux iput's might_sleep).
///
/// # Safety
/// `p` is an inode the caller holds a reference to, given up here.
unsafe fn iput(p: NonNull<Inode>) {
    crate::sync::might_sleep();
    // SAFETY: the caller's reference keeps it live until it is put
    let i = unsafe { p.as_ref() };
    debug_assert!(
        i.state() & (I_FREEING | I_WILL_FREE) == 0,
        "inode: iput of a freed inode"
    );
    if put_unless_last(&i.i_count) {
        return;
    }
    let l = i.i_lock.lock();
    // AcqRel: every other holder's accesses before the teardown
    if i.i_count.fetch_sub(1, Ordering::AcqRel) != 1 {
        return;
    }
    // SAFETY: the count reached zero under `i_lock`, held: the last put
    unsafe { iput_final(p, l) };
}

/// The last reference to the inode at `p` went, under its `i_lock`
/// (`l`) (Linux iput_final): it is marked I_FREEING under the lock, so
/// no igrab or cache lookup takes a reference from now on, then
/// evicted. hk keeps no unused inode (no LRU, `fs::icache`): one Linux
/// would keep cached (linked and hashed, inode_generic_drop false) is
/// written back first under I_WILL_FREE (write_inode_now, as Linux for
/// one it does not keep), then evicted all the same.
///
/// # Safety
/// `p`'s count reached zero under `l`, its `i_lock`; called once.
unsafe fn iput_final(p: NonNull<Inode>, l: MutexGuard<'_, ILocked>) {
    // SAFETY: live until `evict` queues its free
    let i = unsafe { p.as_ref() };
    let drop = i.get_nlink() == 0 || !i.i_hash_node.is_linked();
    if drop {
        i.set_state(&l, I_FREEING);
        core::mem::drop(l);
    } else {
        i.set_state(&l, I_WILL_FREE);
        core::mem::drop(l);
        let _ = super::fs_writeback::write_inode_now(i, true);
        let l = i.i_lock.lock();
        i.i_state
            .store((i.state() & !I_WILL_FREE) | I_FREEING, Ordering::Release);
        core::mem::drop(l);
    }
    // SAFETY: I_FREEING with no reference left: its one eviction
    unsafe { evict(p) };
}

/// A list of inodes that holds no reference to them (Linux s_inodes,
/// an inode_hashtable chain, wb->b_dirty and b_io: list_heads through
/// the inode): an inode is linked by a holder of a reference and
/// unlinked at the latest by its eviction, which takes the list's lock
/// to do so before its memory can go. So under that lock every linked
/// inode is live memory: a walker reads it and takes a reference with
/// [`Inode::igrab`] (Linux __iget under i_lock), which fails once its
/// last reference went.
///
/// # Invariants
/// Every inode on `list` is live memory; each is unlinked, under the
/// lock that guards the list, before its memory is freed.
pub struct InodeList<A: list::Adapter<Item = Inode>> {
    list: list::List<A>,
}

impl<A: list::Adapter<Item = Inode>> InodeList<A> {
    /// An empty list
    ///
    /// # Safety
    /// The inodes' eviction unlinks each from this list under the lock
    /// that guards it (`evict`), whatever else took it off meanwhile.
    pub const unsafe fn new() -> Self {
        Self {
            list: list::List::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Append `inode`, borrowed with no reference (Linux list_move_tail
    /// of an inode found on a list under its lock)
    ///
    /// # Safety
    /// `inode` is unlinked here, and its eviction has not yet unlinked
    /// it under this list's lock, which the caller holds (a reference is
    /// held, or it is not I_FREEING under its `i_lock`).
    pub unsafe fn push_back_unref(&mut self, inode: &Inode) {
        // SAFETY: live and unlinked (the caller)
        unsafe { self.list.push_back(core::ptr::from_ref(inode)) };
    }

    /// The last inode, live while the list is borrowed
    pub fn back(&self) -> Option<&Inode> {
        // SAFETY: linked, so live (type invariant) while the list's lock
        // (the borrow) is held
        self.list.back().map(|p| unsafe { &*p })
    }

    /// Append `inode` (Linux list_add_tail); panics if it is on a list
    /// through this link
    pub fn push_back(&mut self, inode: &InodeRef) {
        assert!(!A::link(inode).is_linked(), "inode: already listed");
        // SAFETY: a reference is held, so its eviction (which unlinks
        // it under this list's lock, the type's contract) has not run;
        // unlinked (checked under the lock)
        unsafe { self.list.push_back(InodeRef::as_ptr(inode)) };
    }

    /// Prepend `inode` (Linux list_add / hlist_add_head)
    pub fn push_front(&mut self, inode: &InodeRef) {
        assert!(!A::link(inode).is_linked(), "inode: already listed");
        // SAFETY: as in push_back
        unsafe { self.list.push_front(InodeRef::as_ptr(inode)) };
    }

    /// Unlink `inode` (Linux list_del_init)
    ///
    /// # Safety
    /// `inode` is on this list.
    pub unsafe fn remove(&mut self, inode: &Inode) {
        // SAFETY: on this list (the caller)
        unsafe { self.list.remove(inode) };
    }

    /// The first inode, live while the list is borrowed
    pub fn front(&self) -> Option<&Inode> {
        // SAFETY: linked, so live (type invariant) while the list's lock
        // (the borrow) is held
        self.list.front().map(|p| unsafe { &*p })
    }

    /// Unlink the first inode, if any
    pub fn pop_front(&mut self) {
        let _ = self.list.pop_front();
    }

    /// Unlink every inode (a superblock's shutdown)
    pub fn clear(&mut self) {
        while self.list.pop_front().is_some() {}
    }

    /// The inodes, front to back, live while the list is borrowed
    pub fn iter(&self) -> list::Iter<'_, A> {
        self.list.iter()
    }

    /// The inodes after `inode` (Linux list_for_each_entry_continue)
    ///
    /// # Safety
    /// `inode` is on this list.
    pub unsafe fn iter_after(&self, inode: &Inode) -> impl Iterator<Item = &Inode> + '_ {
        // SAFETY: on this list (the caller)
        let first = unsafe { self.list.next(inode) };
        // SAFETY: each is on this list, which the borrow keeps unchanged
        core::iter::successors(first, move |&p| unsafe { self.list.next(p) })
            // SAFETY: linked, so live (type invariant) while borrowed
            .map(|p| unsafe { &*p })
    }

    /// Move every inode `f` picks to the tail of `to`, in order (Linux
    /// move_expired_inodes' list_move); both under the one lock
    pub fn move_if(&mut self, to: &mut Self, mut f: impl FnMut(&Inode) -> bool) {
        let mut cur = self.list.front();
        while let Some(p) = cur {
            // SAFETY: `p` is on this list; its successor is read before
            // `p` may leave it
            cur = unsafe { self.list.next(p) };
            // SAFETY: linked, so live (type invariant)
            if f(unsafe { &*p }) {
                // SAFETY: on this list, then on none; `to` is under the
                // same lock and eviction contract
                unsafe {
                    self.list.remove(p);
                    to.list.push_back(p);
                }
            }
        }
    }
}

/// A FIFO inode's pipe and its open count (`Inode.i_pipe`)
pub type PipeSlot = Option<(Arc<crate::io::pipe::Pipe>, usize)>;

/// The inode structure - represents a file object (Linux struct inode)
///
/// Made only by [`Inode::alloc`], in place in its own allocation, and
/// held through [`InodeRef`] (Linux i_count). Its last reference tears
/// it down where it goes (`iput`: Linux iput_final -> evict ->
/// destroy_inode), and its memory is freed a grace period later (Linux
/// i_callback), so an RCU reader that reached it with no reference (a
/// dentry's `d_inode`) may read its atomics and fixed fields (`ino`,
/// `i_op`, mode, owner, ...) until its guard ends, after the teardown
/// included. Every field with drop glue is `ManuallyDrop`, dropped by
/// `destroy_inode` and `i_callback` through raw pointers; the others
/// have none (`no_glue` below), so nothing writes a byte a reader reads
/// before the free.
pub struct Inode {
    /// References (Linux i_count, [`InodeRef`]): above zero while it is
    /// held; the last put drops it to zero under `i_lock` and marks it
    /// I_FREEING there, after which none is taken again
    i_count: AtomicU32,
    /// `istate::*` (Linux i_state): written under `i_lock`, read
    /// lock-free
    i_state: AtomicU32,
    /// The deferred free (Linux i_rcu)
    i_rcu: RcuHead,

    /// Inode number (unique within filesystem)
    pub ino: InodeId,

    /// File mode (type + permissions) - atomic for chmod support
    mode: AtomicU16,

    /// Owner user ID - atomic for chown support
    uid: AtomicU32,

    /// Owner group ID - atomic for chown support
    gid: AtomicU32,

    /// File size in bytes (Linux i_size): written under i_rwsem with
    /// Release, read lock-free with Acquire, through `set_size`/`get_size`
    size: AtomicU64,

    /// log2 of its block size (Linux i_blkbits): from its superblock's
    /// s_blocksize_bits at creation; a block device inode's is the
    /// device's soft block size (BLKBSZGET), changed by `set_blocksize`
    /// under i_rwsem and at the first open under the disk's open_mutex,
    /// read lock-free (READ_ONCE)
    i_blkbits: core::sync::atomic::AtomicU8,

    /// Link count (atomic for thread-safe hard link management)
    pub nlink: AtomicU32,

    /// Its generation (Linux i_generation): with the number, tells a
    /// file handle's object from a later one that reuses the number;
    /// set by the filesystem before the inode is shared, then fixed
    pub i_generation: u32,

    /// Change counter (Linux i_version, inode_inc_iversion): bumped by
    /// a filesystem that keeps one when the inode changes (vfat: a
    /// directory's entries, under its i_rwsem), read with no lock
    i_version: AtomicU64,

    /// `iflags::*` bits (Linux i_flags' S_DEAD, S_SWAPFILE, and
    /// i_state's I_LINKABLE): each set or cleared under the lock its
    /// Linux bit is (i_rwsem; swapon/swapoff's), read lock-free; one
    /// word, changed with fetch_or / fetch_and (bits of different
    /// writers share it, Linux inode_set_flags' cmpxchg)
    i_flags: core::sync::atomic::AtomicU32,

    /// Device ID for character/block devices (major/minor)
    /// For non-device files, this is DevId::null()
    pub rdev: DevId,

    /// Last access time
    atime: InodeTime,

    /// Last modification time
    mtime: InodeTime,

    /// Last status change time
    ctime: InodeTime,

    /// Pointer back to superblock
    pub sb: ManuallyDrop<Weak<SuperBlock>>,

    /// Inode operations (filesystem-specific)
    pub i_op: &'static dyn InodeOps,

    /// Directory operation semaphore (like Linux i_rwsem)
    ///
    /// This lock serializes directory operations: create, mkdir, unlink,
    /// rmdir, link, symlink, rename, and lookup. Following Linux's i_rwsem
    /// pattern, VFS acquires this lock before calling filesystem ops.
    ///
    /// For rename operations involving two directories, use lock_rename()
    /// instead which handles proper lock ordering.
    i_rwsem: RwSem,

    /// Direct I/Os in flight (Linux i_dio_count): `inode_dio_begin` /
    /// `inode_dio_end`, waited for by `inode_dio_wait`
    i_dio_count: AtomicU32,

    /// Filesystem-specific private data
    pub private: ManuallyDrop<RwLock<Option<Arc<dyn InodeData>>>>,

    /// A FIFO's pipe while it is open, and how many files have it open
    /// (Linux inode->i_pipe and pipe->files)
    pub i_pipe: ManuallyDrop<Mutex<PipeSlot>>,

    /// The file's page cache (Linux i_data)
    pub i_data: ManuallyDrop<crate::mm::filemap::AddressSpace>,

    /// The inotify watches on it (Linux i_fsnotify_marks)
    pub fsnotify: ManuallyDrop<crate::io::inotify::Marks>,

    /// When it went from clean to dirty, monotonic ns (Linux
    /// dirtied_when): written under its wb's list_lock and `i_lock` as
    /// it is queued on `b_dirty` or requeued, read under the list lock
    /// by a pass (vm.dirty_expire_centisecs)
    pub(crate) dirtied_when: AtomicU64,
    /// On its device's `b_dirty`, `b_io` or `b_more_io` (Linux
    /// i_io_list, under the
    /// wb's list_lock), which hold no reference to it: its eviction takes
    /// it off (Linux evict's inode_io_list_del)
    pub(crate) i_io_list: list::Link,
    /// Which of them (`fs_writeback::ON_*`), changed with the link
    /// under the wb's list_lock
    pub(crate) i_io_on: core::sync::atomic::AtomicU8,
    /// The writeback state it was queued on (Linux inode->i_wb), set
    /// the first time and never changed
    pub(crate) i_wb: ManuallyDrop<spin::Once<Arc<crate::mm::writeback::BdiWriteback>>>,

    /// Writers (> 0) or executions denying them (< 0) (Linux
    /// i_writecount; `get_write_access`, `deny_write`)
    i_writecount: core::sync::atomic::AtomicI32,

    /// Its flock and POSIX locks (Linux i_flctx; `fs::locks`)
    pub i_flctx: ManuallyDrop<super::locks::FileLockCtx>,

    /// The inode cache key it is hashed under (`fs::icache`)
    pub(super) i_hash: AtomicU64,
    /// On its inode-cache bucket (Linux i_hash, under inode_hash_lock;
    /// linked: !inode_unhashed)
    pub(super) i_hash_node: list::Link,
    /// Identity for shared futex keys (Linux i_sequence)
    pub(crate) i_sequence: crate::task::futex::KeySeq,
    /// On its superblock's `s_inodes` (Linux i_sb_list), from
    /// [`Inode::alloc`] to its eviction
    pub(super) i_sb_list: list::Link,
    /// A symlink's target, set before the inode is visible and fixed
    /// from then on (Linux i_link, inode_set_cached_link: tmpfs's
    /// short symlinks, procfs's fixed ones), so an RCU walk follows it
    /// with no reference; freed with the inode's memory, a grace period
    /// after its teardown (Linux ->free_inode: `i_callback`)
    i_link: ManuallyDrop<spin::Once<alloc::boxed::Box<[u8]>>>,
    /// File system data an RCU walk reads with no reference (Linux: the
    /// fields of a file system's inode its ->free_inode releases, as
    /// proc_inode's pid): set once before the inode is visible, dropped
    /// by `i_callback` a grace period after the teardown, so its drop
    /// must be fit for an RCU callback (no sleep; spin leaves only)
    i_private_rcu: ManuallyDrop<spin::Once<Arc<dyn InodeData>>>,
    /// Linux i_lock: a spin lock over its dentries and the `i_state`
    /// writes, taken before any d_lock (`fs::dentry`)
    pub(super) i_lock: Mutex<ILocked>,
}

/// What `Inode.i_lock` guards
pub(super) struct ILocked {
    /// Its dentries (Linux i_dentry): every live dentry whose inode it
    /// is, linked through `Dentry.d_alias`
    pub(super) i_dentry: list::List<super::dentry::AliasA>,
}

crate::adapter!(pub SbInodeA, Inode, i_sb_list);

/// What `INODE_SB_LIST_LOCK` guards: every superblock's `s_inodes`
pub struct InodeSbLists(());

// SAFETY: one instance, `INODE_SB_LIST_LOCK`'s, made here (the field is
// private)
unsafe impl UniqueOwner for InodeSbLists {}

/// A superblock's inodes (Linux s_inodes): an [`InodeList`] through
/// `Inode.i_sb_list`
pub type SbInodes = LockedBy<InodeList<SbInodeA>, InodeSbLists>;

/// A superblock's empty `s_inodes`
pub fn sb_inodes() -> SbInodes {
    // SAFETY: an inode's eviction unlinks it under INODE_SB_LIST_LOCK
    // (`sb_list_del`), unless the superblock's shutdown drained it
    LockedBy::new(unsafe { InodeList::new() })
}

/// Linux inode_sb_list_lock (one lock for every superblock's s_inodes,
/// as Linux had before s_inode_list_lock went per superblock): an
/// inode holds only a `Weak` to its superblock (Linux i_sb, a pointer
/// the shutdown keeps valid by evicting first) and may be evicted after
/// the superblock's shutdown (`generic_shutdown_super`), which drains
/// its list under this lock; an inode still linked under it therefore
/// has a superblock whose fields are intact. A spin leaf, thread context
/// only: an inode's last reference never goes in an interrupt handler
/// (pinned pages and files are released in thread context:
/// `PinnedPages`, `fput`), and lockdep reports a tracked spin lock taken
/// in one.
static INODE_SB_LIST_LOCK: Mutex<InodeSbLists> = Mutex::new(InodeSbLists(()));

/// List a new inode on its superblock (Linux inode_sb_list_add)
fn sb_list_add(sb: &SuperBlock, inode: &InodeRef) {
    let mut l = INODE_SB_LIST_LOCK.lock();
    sb.s_inodes.access_mut(&mut l).push_front(inode);
}

/// Take an evicted inode off its superblock's list (Linux
/// inode_sb_list_del), unless the superblock's shutdown drained it
fn sb_list_del(inode: &Inode) {
    let mut l = INODE_SB_LIST_LOCK.lock();
    if !inode.i_sb_list.is_linked() {
        return;
    }
    // SAFETY: linked, so `sb` is the superblock `alloc` listed it on
    // (alive then), whose shutdown drains s_inodes under this lock
    // before its last passive put frees any field: they are intact,
    // and the inode's Weak keeps the allocation
    let sb = unsafe { &*inode.sb.as_ptr() };
    // SAFETY: linked on its superblock's list
    unsafe { sb.s_inodes.access_mut(&mut l).remove(inode) }
}

/// Unlink every inode of a superblock in its shutdown (Linux
/// evict_inodes' list walk; here an inode may outlive its superblock's
/// shutdown, so its later eviction finds itself unlinked)
pub(super) fn sb_list_drain(list: &SbInodes) {
    let mut l = INODE_SB_LIST_LOCK.lock();
    list.access_mut(&mut l).clear();
}

/// `f` on each live inode of `sb` until it returns false (Linux
/// drop_pagecache_sb's walk): each taken under `INODE_SB_LIST_LOCK`
/// and held while `f` runs with no lock, released after the next one is
/// taken; allocates nothing. False if `f` stopped the walk.
pub fn for_each_sb_inode(sb: &SuperBlock, f: &mut dyn FnMut(&InodeRef) -> bool) -> bool {
    let mut cur: Option<InodeRef> = None;
    loop {
        let next = {
            let l = INODE_SB_LIST_LOCK.lock();
            let list = sb.s_inodes.access(&l);
            match &cur {
                // SAFETY: `c` is alive (held) and `sb` too (the caller's
                // reference, or its shutdown before the drain): neither
                // its eviction nor the drain has unlinked it, and nothing
                // else does
                Some(c) => unsafe { list.iter_after(c) }.find_map(Inode::igrab),
                None => list.iter().find_map(Inode::igrab),
            }
        };
        // The previous one goes with the lock released: its last
        // reference's eviction takes it
        drop(cur.take());
        let Some(i) = next else {
            return true;
        };
        if !f(&i) {
            return false;
        }
        cur = Some(i);
    }
}

impl Inode {
    /// A reference to an inode borrowed with none (under an RCU read
    /// guard: a dentry's `d_inode_rcu`; or under the lock of a list it
    /// is on: `InodeList`), unless its last one went and it is being
    /// torn down or freed (Linux igrab: I_FREEING / I_WILL_FREE). A
    /// count above zero is taken lock-free: those bits are set only
    /// once it reached zero, under `i_lock`, which the slow path takes.
    pub fn igrab(&self) -> Option<InodeRef> {
        if !get_unless_zero(&self.i_count) {
            let _l = self.i_lock.lock();
            if self.state() & (I_FREEING | I_WILL_FREE) != 0 {
                return None;
            }
            // Linux __iget
            self.i_count.fetch_add(1, Ordering::Relaxed);
        }
        // INVARIANT: the reference just taken
        Some(InodeRef(NonNull::from(self)))
    }

    /// `istate::*` (Linux inode_state_read_once)
    pub fn state(&self) -> u32 {
        self.i_state.load(Ordering::Acquire)
    }

    /// Panics unless `l` is this inode's `i_lock` data, which is
    /// borrowed only through a guard of it (Rust-for-Linux LockedBy's
    /// owner check): so `l` proves its `i_lock` held
    pub(super) fn assert_locked(&self, l: &ILocked) {
        assert!(
            core::ptr::eq(l, self.i_lock.data_ptr()),
            "inode: another inode's i_lock"
        );
    }

    /// Set `bits` of `i_state`, under `i_lock` (`l`)
    pub(super) fn set_state(&self, l: &ILocked, bits: u32) {
        self.assert_locked(l);
        self.i_state.fetch_or(bits, Ordering::Release);
    }

    /// Clear `bits` of `i_state`, under `i_lock` (`l`)
    pub(super) fn clear_state(&self, l: &ILocked, bits: u32) {
        self.assert_locked(l);
        self.i_state.fetch_and(!bits, Ordering::Release);
    }

    /// The address of `i_state`, keying its waiters' queue (Linux
    /// inode_bit_waitqueue)
    pub(super) fn state_addr(&self) -> usize {
        core::ptr::from_ref(&self.i_state) as usize
    }

    /// A reference to an inode borrowed with none, under its `i_lock`
    /// (`l`) with neither I_FREEING nor I_WILL_FREE set, so its count
    /// is above zero (Linux __iget: those bits are set in the hold that
    /// drops it to zero; its callers test them first). Panics if `l` is
    /// not its `i_lock` or either bit is set.
    pub(super) fn __iget(&self, l: &ILocked) -> InodeRef {
        self.assert_locked(l);
        assert!(
            self.state() & (I_FREEING | I_WILL_FREE) == 0,
            "inode: __iget of a freed inode"
        );
        self.i_count.fetch_add(1, Ordering::Relaxed);
        // INVARIANT: the reference just taken
        InodeRef(NonNull::from(self))
    }

    /// What a new inode starts with (Linux new_inode's caller filling
    /// in i_mode, i_uid, ...), for [`Inode::alloc`]
    ///
    /// # Arguments
    /// * `mtime` - Modification time (atime and ctime are initialized to same value)
    // The inode itself is built in place by `alloc` (it is too large to
    // pass by value)
    #[expect(clippy::too_many_arguments, clippy::new_ret_no_self)]
    pub fn new(
        ino: InodeId,
        mode: InodeMode,
        uid: Uid,
        gid: Gid,
        size: u64,
        mtime: Timespec,
        sb: Weak<SuperBlock>,
        i_op: &'static dyn InodeOps,
    ) -> InodeInit {
        InodeInit {
            ino,
            mode,
            uid,
            gid,
            size,
            rdev: DevId::null(),
            mtime,
            sb,
            i_op,
            i_generation: 0,
        }
    }

    /// A new device inode's start, for [`Inode::alloc`]
    ///
    /// # Arguments
    /// * `rdev` - Device ID (major/minor numbers)
    /// * `mtime` - Modification time
    #[expect(clippy::too_many_arguments)]
    pub fn new_device(
        ino: InodeId,
        mode: InodeMode,
        uid: Uid,
        gid: Gid,
        rdev: DevId,
        mtime: Timespec,
        sb: Weak<SuperBlock>,
        i_op: &'static dyn InodeOps,
    ) -> InodeInit {
        InodeInit {
            rdev,
            ..Self::new(ino, mode, uid, gid, 0, mtime, sb, i_op)
        }
    }

    /// Make an inode in place in its own allocation, its one reference
    /// the caller's (Linux alloc_inode: i_count 1), and list it on its
    /// superblock's `s_inodes` (inode_sb_list_add); one with no
    /// superblock stays unlisted. Its memory is freed a grace period
    /// after its last reference's teardown (`i_callback`).
    pub fn alloc(init: InodeInit) -> Result<InodeRef, KernelError> {
        let sb = init.sb.upgrade();
        // Linux inode_init_always: i_blkbits = sb->s_blocksize_bits
        let blkbits = sb
            .as_ref()
            .map_or(crate::mm::page::PAGE_SHIFT as u8, |s| s.s_blocksize_bits());
        let p = Box::into_raw(try_box_uninit::<Self>()?).cast::<Self>();
        // SAFETY: `p` is the new block, unshared and not yet initialized
        unsafe { Self::init_at(p, init, blkbits) };
        // INVARIANT: `init_at` wrote every field, `i_count` 1: this
        // reference; the block is freed only by `i_callback`
        // SAFETY: from `Box::into_raw`, never null
        let i = InodeRef(unsafe { NonNull::new_unchecked(p) });
        if let Some(sb) = &sb {
            sb_list_add(sb, &i);
        }
        Ok(i)
    }

    /// Write every field of a new inode at `p`, one at a time, so the
    /// inode never sits on the stack whole (it is large; arm64 kernel
    /// stacks are 16 KiB)
    ///
    /// # Safety
    /// `p` is valid for writes of an `Inode`, unshared.
    unsafe fn init_at(p: *mut Self, i: InodeInit, blkbits: u8) {
        // Each field written once, and every field: the pattern names
        // the same list without `..`, so a field missed or named twice
        // fails to build
        macro_rules! init {
            ($($f:ident: $v:expr),* $(,)?) => {
                $(
                    // SAFETY: `p` is valid for writes of an `Inode` (the
                    // caller's contract); a field write drops nothing
                    unsafe { (&raw mut (*p).$f).write($v) };
                )*
                let _ = |i: &Self| {
                    let Self { $($f: _),* } = i;
                };
            };
        }
        let t = i.mtime;
        init! {
            i_count: AtomicU32::new(1),
            i_state: AtomicU32::new(0),
            i_rcu: RcuHead::new(),
            ino: i.ino,
            mode: AtomicU16::new(i.mode.0),
            uid: AtomicU32::new(i.uid),
            gid: AtomicU32::new(i.gid),
            size: AtomicU64::new(i.size),
            i_blkbits: core::sync::atomic::AtomicU8::new(blkbits),
            nlink: AtomicU32::new(1),
            i_generation: i.i_generation,
            i_version: AtomicU64::new(0),
            i_flags: core::sync::atomic::AtomicU32::new(0),
            rdev: i.rdev,
            atime: InodeTime::new(t),
            mtime: InodeTime::new(t),
            ctime: InodeTime::new(t),
            sb: ManuallyDrop::new(i.sb),
            i_op: i.i_op,
            i_rwsem: RwSem::new(()),
            i_dio_count: AtomicU32::new(0),
            private: ManuallyDrop::new(RwLock::new(None)),
            i_pipe: ManuallyDrop::new(Mutex::new(None)),
            i_data: ManuallyDrop::new(crate::mm::filemap::AddressSpace::new()),
            fsnotify: ManuallyDrop::new(crate::io::inotify::Marks::default()),
            dirtied_when: AtomicU64::new(0),
            i_io_list: list::Link::new(),
            i_io_on: core::sync::atomic::AtomicU8::new(0),
            i_wb: ManuallyDrop::new(spin::Once::new()),
            i_writecount: core::sync::atomic::AtomicI32::new(0),
            i_flctx: ManuallyDrop::new(super::locks::FileLockCtx::new()),
            i_hash: AtomicU64::new(0),
            i_hash_node: list::Link::new(),
            i_sequence: crate::task::futex::KeySeq::new(),
            i_sb_list: list::Link::new(),
            i_link: ManuallyDrop::new(spin::Once::new()),
            i_private_rcu: ManuallyDrop::new(spin::Once::new()),
            i_lock: Mutex::new(ILocked {
                i_dentry: list::List::new(),
            }),
        }
    }

    /// Give a new symlink its target (Linux inode_set_cached_link),
    /// before the inode is visible to any lookup; once
    pub fn set_link(&self, target: alloc::boxed::Box<[u8]>) {
        let mut t = Some(target);
        self.i_link.call_once(|| t.take().expect("inode: set_link"));
        debug_assert!(t.is_none(), "inode: a symlink's target set twice");
    }

    /// Give a new inode its RCU-readable data ([`Inode::private_rcu`]),
    /// before it is visible to any lookup; once
    pub fn set_private_rcu(&self, d: Arc<dyn InodeData>) {
        let mut d = Some(d);
        self.i_private_rcu
            .call_once(|| d.take().expect("inode: set_private_rcu"));
        debug_assert!(d.is_none(), "inode: RCU data set twice");
    }

    /// Its RCU-readable file system data: readable by any borrower of
    /// the inode, an RCU walk's too, since it is fixed and freed only
    /// with the memory
    pub fn private_rcu(&self) -> Option<&dyn InodeData> {
        self.i_private_rcu.get().map(|a| &**a)
    }

    /// Its change counter (Linux inode_query_iversion)
    pub fn iversion(&self) -> u64 {
        self.i_version.load(Ordering::Acquire)
    }

    /// Count a change (Linux inode_inc_iversion)
    pub fn inc_iversion(&self) {
        self.i_version.fetch_add(1, Ordering::AcqRel);
    }

    /// The symlink's target, if it is kept in the inode (Linux
    /// inode->i_link): readable by any borrower of the inode, an RCU
    /// walk's too, since it is fixed and freed only with the memory
    pub fn i_link(&self) -> Option<&[u8]> {
        self.i_link.get().map(|b| &**b)
    }

    fn iflag(&self, f: u32) -> bool {
        self.i_flags.load(Ordering::Acquire) & f != 0
    }

    fn set_iflag(&self, f: u32, on: bool) {
        if on {
            self.i_flags.fetch_or(f, Ordering::Release);
        } else {
            self.i_flags.fetch_and(!f, Ordering::Release);
        }
    }

    /// Mark a removed directory dead (caller holds its i_rwsem)
    pub fn set_dead(&self) {
        self.set_iflag(iflags::S_DEAD, true);
    }

    /// Removed directory (Linux IS_DEADDIR)
    pub fn is_dead(&self) -> bool {
        self.iflag(iflags::S_DEAD)
    }

    /// An active swap area (Linux IS_SWAPFILE): writes and truncates are
    /// ETXTBSY
    pub fn is_swapfile(&self) -> bool {
        self.iflag(iflags::S_SWAPFILE)
    }

    /// swapon / swapoff (under the inode's i_rwsem)
    pub fn set_swapfile(&self, on: bool) {
        self.set_iflag(iflags::S_SWAPFILE, on);
    }

    /// An O_TMPFILE file not opened O_EXCL: linkat may give it its first
    /// name though it has no link (Linux I_LINKABLE)
    pub fn is_linkable(&self) -> bool {
        self.iflag(iflags::I_LINKABLE)
    }

    pub fn set_linkable(&self, on: bool) {
        self.set_iflag(iflags::I_LINKABLE, on);
    }

    /// Get file mode (type + permissions)
    pub fn mode(&self) -> InodeMode {
        InodeMode(self.mode.load(Ordering::Acquire))
    }

    /// Set file mode permission bits (preserves file type)
    ///
    /// Only updates the permission bits (lower 12 bits), preserving the
    /// file type bits (S_IFMT). This is what chmod does.
    pub fn set_mode_perm(&self, perm: u16) {
        loop {
            let old = self.mode.load(Ordering::Acquire);
            let file_type = old & 0o170000; // Preserve file type
            let new = file_type | (perm & 0o7777); // Set new permissions
            if self
                .mode
                .compare_exchange_weak(old, new, Ordering::Release, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
    }

    /// Clear mode bits (set-id removal on write, truncate, chown)
    pub fn clear_mode_bits(&self, bits: u16) {
        self.mode.fetch_and(!(bits & 0o7777), Ordering::AcqRel);
    }

    /// Get owner user ID
    pub fn uid(&self) -> Uid {
        self.uid.load(Ordering::Acquire)
    }

    /// Get owner group ID
    pub fn gid(&self) -> Gid {
        self.gid.load(Ordering::Acquire)
    }

    /// Set owner user ID (for chown)
    pub fn set_uid(&self, uid: Uid) {
        self.uid.store(uid, Ordering::Release);
    }

    /// Set owner group ID (for chown)
    pub fn set_gid(&self, gid: Gid) {
        self.gid.store(gid, Ordering::Release);
    }

    /// Get last access time
    /// (lock-free, like Linux inode_get_*time)
    pub fn atime(&self) -> Timespec {
        self.atime.get()
    }

    /// Get last modification time
    /// (lock-free, like Linux inode_get_*time)
    pub fn mtime(&self) -> Timespec {
        self.mtime.get()
    }

    /// Get last status change time
    /// (lock-free, like Linux inode_get_*time)
    pub fn ctime(&self) -> Timespec {
        self.ctime.get()
    }

    /// Set last access time (for utimensat)
    ///
    /// Writers hold `i_rwsem` exclusive (Linux notify_change / inode_set_*time)
    pub fn set_atime(&self, time: Timespec) {
        self.atime.set(time);
    }

    /// Set last modification time (for utimensat)
    ///
    /// Writers hold `i_rwsem` exclusive (Linux notify_change / inode_set_*time)
    pub fn set_mtime(&self, time: Timespec) {
        self.mtime.set(time);
    }

    /// Set last status change time
    ///
    /// Note: ctime is automatically updated by the kernel, not directly settable by user.
    ///
    /// Writers hold `i_rwsem` exclusive (Linux notify_change / inode_set_*time)
    pub fn set_ctime(&self, time: Timespec) {
        self.ctime.set(time);
    }

    /// mtime and ctime become the current time (Linux
    /// inode_set_mtime_to_ts(inode, inode_set_ctime_current(inode))).
    /// Callers normally hold `i_rwsem` (else a reader may see a mix of
    /// two updates, as on Linux).
    pub fn touch_mc(&self) {
        let now = crate::time::TIMEKEEPER.current_time();
        self.ctime.set(now);
        self.mtime.set(now);
    }

    /// A write changed the file (Linux file_update_time): mtime and ctime
    /// become the current time through its filesystem (->update_time),
    /// unless they are that already (inode_needs_update_time)
    pub fn file_update_time(&self) {
        let now = crate::time::TIMEKEEPER.current_time();
        let same = |t: Timespec| (t.sec, t.nsec) == (now.sec, now.nsec);
        if same(self.mtime()) && same(self.ctime()) {
            return;
        }
        self.i_op.update_time(self, TimeUpdate::CMtime, now);
    }

    /// Times from a setattr (utimes, truncate, chmod, chown) through the
    /// filesystem (Linux notify_change -> ->setattr), under i_rwsem
    pub fn set_times(
        &self,
        atime: Option<Timespec>,
        mtime: Option<Timespec>,
        ctime: Option<Timespec>,
    ) {
        self.i_op.setattr(self, atime, mtime, ctime);
    }

    /// An access through `mnt` (Linux touch_atime): atime becomes the
    /// current time unless the mount is read-only, noatime (nodiratime
    /// for a directory), or relatime and the atime is newer than mtime
    /// and ctime and under a day old. The update (which a filesystem
    /// may write to its device) holds write access to the mount, and is
    /// skipped if refused (a read-only remount since the check). Linux
    /// takes sb_start_write_trylock first; hk has no freezing. Unlocked,
    /// as Linux.
    pub fn touch_atime(&self, mnt: &super::mount::Mount) {
        let Some(now) = self.atime_update(mnt) else {
            return;
        };
        // Linux mnt_get_write_access, then inode_update_time(S_ATIME)
        if mnt.get_write().is_err() {
            return;
        }
        self.i_op.update_time(self, TimeUpdate::Atime, now);
        mnt.put_write();
    }

    /// An access through `mnt` would change the atime (Linux
    /// atime_needs_update)
    pub fn atime_needs_update(&self, mnt: &super::mount::Mount) -> bool {
        self.atime_update(mnt).is_some()
    }

    /// The new atime an access through `mnt` sets, if any
    fn atime_update(&self, mnt: &super::mount::Mount) -> Option<Timespec> {
        use super::mount::{MNT_NOATIME, MNT_NODIRATIME, MNT_RELATIME};
        let f = mnt.flags();
        if f & MNT_NOATIME != 0
            || (f & MNT_NODIRATIME != 0 && self.mode().is_dir())
            || mnt.is_readonly()
        {
            return None;
        }
        let now = crate::time::TIMEKEEPER.current_time();
        let atime = self.atime();
        let stale = |t: Timespec| (t.sec, t.nsec) >= (atime.sec, atime.nsec);
        let relatime_ok = stale(self.mtime())
            || stale(self.ctime())
            || now.sec.wrapping_sub(atime.sec) >= 24 * 60 * 60;
        if (f & MNT_RELATIME != 0 && !relatime_ok) || (now.sec, now.nsec) == (atime.sec, atime.nsec)
        {
            return None;
        }
        Some(now)
    }

    /// ctime becomes the current time (Linux inode_set_ctime_current).
    /// Callers normally hold `i_rwsem` (else a reader may see a mix of
    /// two updates, as on Linux).
    pub fn touch_c(&self) {
        self.ctime.set(crate::time::TIMEKEEPER.current_time());
    }

    /// Get the superblock this inode belongs to
    pub fn superblock(&self) -> Option<Arc<SuperBlock>> {
        self.sb.upgrade()
    }

    /// Its writes are synchronous (Linux IS_SYNC): a synchronous mount
    /// (SB_SYNCHRONOUS; there is no per-inode S_SYNC, chattr +S)
    pub fn is_sync(&self) -> bool {
        self.superblock().is_some_and(|sb| sb.synchronous())
    }

    /// Set filesystem-specific private data
    pub fn set_private(&self, data: Arc<dyn InodeData>) {
        *self.private.write() = Some(data);
    }

    /// Get filesystem-specific private data
    pub fn get_private(&self) -> Option<Arc<dyn InodeData>> {
        self.private.read().clone()
    }

    /// Largest size this inode's filesystem allows (s_maxbytes)
    pub fn maxbytes(&self) -> u64 {
        self.sb
            .upgrade()
            .map_or(super::superblock::MAX_LFS_FILESIZE, |sb| sb.maxbytes())
    }

    /// Cut a write of `count` bytes at `pos` to the limits (Linux
    /// generic_write_check_limits): RLIMIT_FSIZE (at or past it SIGXFSZ
    /// and EFBIG, else a short write up to it), then s_maxbytes (EFBIG
    /// at or past it, else short)
    pub fn write_limit(&self, pos: u64, count: usize) -> Result<usize, KernelError> {
        use crate::task::rlimit::{RLIM_INFINITY, RLIMIT_FSIZE, rlimit};
        let mut count = count as u64;
        let limit = rlimit(RLIMIT_FSIZE);
        if limit != RLIM_INFINITY {
            if pos >= limit {
                let _ = crate::signal::send_signal(
                    &crate::task::percpu::current(),
                    crate::signal::SIGXFSZ,
                );
                return Err(KernelError::FileTooLarge);
            }
            count = count.min(limit - pos);
        }
        let max = self.maxbytes();
        if pos >= max {
            return Err(KernelError::FileTooLarge);
        }
        Ok(count.min(max - pos) as usize)
    }

    /// A file may grow to `size` (Linux inode_newsize_ok): past
    /// s_maxbytes is EFBIG, past RLIMIT_FSIZE SIGXFSZ and EFBIG;
    /// shrinking an active swap file is ETXTBSY
    pub fn newsize_ok(&self, size: u64) -> Result<(), KernelError> {
        use crate::task::rlimit::{RLIM_INFINITY, RLIMIT_FSIZE, rlimit};
        if size > self.get_size() {
            // RLIMIT_FSIZE first (SIGXFSZ), then the filesystem's largest
            // file (EFBIG, no signal), in Linux inode_newsize_ok's order
            let limit = rlimit(RLIMIT_FSIZE);
            if limit != RLIM_INFINITY && size > limit {
                let _ = crate::signal::send_signal(
                    &crate::task::percpu::current(),
                    crate::signal::SIGXFSZ,
                );
                return Err(KernelError::FileTooLarge);
            }
            if size > self.maxbytes() {
                return Err(KernelError::FileTooLarge);
            }
        } else if self.is_swapfile() {
            return Err(KernelError::TextBusy);
        }
        Ok(())
    }

    /// Update file size (Linux i_size_write: smp_store_release). The
    /// caller holds i_rwsem; what the new size covers (page contents)
    /// is visible before the size is
    pub fn set_size(&self, size: u64) {
        self.size.store(size, Ordering::Release);
    }

    /// Get current file size (Linux i_size_read: smp_load_acquire, pairs
    /// with `set_size`): bytes below it are seen as written
    pub fn get_size(&self) -> u64 {
        self.size.load(Ordering::Acquire)
    }

    /// log2 of its block size (Linux READ_ONCE(inode->i_blkbits))
    pub fn blkbits(&self) -> u32 {
        u32::from(self.i_blkbits.load(Ordering::Relaxed))
    }

    /// Its block size in bytes (Linux i_blocksize)
    pub fn blocksize(&self) -> u32 {
        1 << self.blkbits()
    }

    /// Set its block size's log2 (Linux inode->i_blkbits = ...): the
    /// caller holds what its user documents (a block device inode:
    /// i_rwsem or, at the first open, the disk's open_mutex)
    pub fn set_blkbits(&self, bits: u32) {
        debug_assert!((9..=16).contains(&bits));
        self.i_blkbits.store(bits as u8, Ordering::Relaxed);
    }

    /// Get current link count
    pub fn get_nlink(&self) -> u32 {
        self.nlink.load(Ordering::Relaxed)
    }

    /// Increment link count (for hard links)
    pub fn inc_nlink(&self) {
        self.nlink.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement link count (Linux drop_nlink), returns new value; one
    /// already 0 is a bug (Linux WARN_ON) and stays 0
    pub fn dec_nlink(&self) -> u32 {
        match (self.nlink).try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1)) {
            Ok(n) => n - 1,
            Err(_) => {
                crate::printkln!("WARNING: drop_nlink: inode {} has no link", self.ino);
                0
            }
        }
    }

    // ========================================================================
    // Directory locking (Linux i_rwsem pattern)
    // ========================================================================

    /// Take i_rwsem for writing (Linux inode_lock): directory changes,
    /// truncate, attribute changes; held until the guard drops. For two
    /// directories (rename) use `lock_rename`.
    #[inline]
    pub fn lock(&self) -> InodeLock<'_> {
        self.i_rwsem.down_write();
        InodeLock(self)
    }

    /// Take i_rwsem shared (Linux inode_lock_shared): lookup and readdir
    /// exclude directory changes but not each other
    #[inline]
    pub fn lock_shared(&self) -> InodeLockShared<'_> {
        self.i_rwsem.down_read();
        InodeLockShared(self)
    }
}

/// An inode's i_rwsem held for writing ([`Inode::lock`]); a forgotten
/// guard only leaves it locked (doc/UNSAFE.md rule 9)
#[must_use]
pub struct InodeLock<'a>(&'a Inode);

impl Drop for InodeLock<'_> {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: taken in `Inode::lock`, released once (this drop)
        unsafe { self.0.i_rwsem.up_write() };
    }
}

impl Inode {
    /// A direct I/O on the inode starts (Linux inode_dio_begin)
    pub fn inode_dio_begin(&self) {
        self.i_dio_count.fetch_add(1, Ordering::Relaxed);
    }

    /// A direct I/O on the inode is done, its last bio completed (Linux
    /// inode_dio_end); the last one wakes `inode_dio_wait`. Any context:
    /// the wakeup takes only the wait queue's IrqSpinlock.
    pub fn inode_dio_end(&self) {
        if self.i_dio_count.fetch_sub(1, Ordering::AcqRel) == 1 {
            var_waitqueue(self.dio_key()).wake_all();
        }
    }

    /// Sleep until no direct I/O is in flight (Linux inode_dio_wait).
    /// The caller holds i_rwsem exclusive, so no new one can start on a
    /// filesystem whose direct I/O takes it (vfat) before what it frees.
    pub fn inode_dio_wait(&self) {
        if self.dio_count() != 0 {
            var_waitqueue(self.dio_key()).wait_event(|| self.dio_count() == 0);
        }
    }

    /// Direct I/Os in flight (Linux inode_dio_finished's count)
    pub fn dio_count(&self) -> u32 {
        self.i_dio_count.load(Ordering::Acquire)
    }

    /// `inode_dio_begin` now, `inode_dio_end` when the guard drops
    pub fn dio_guard(&self) -> DioGuard<'_> {
        self.inode_dio_begin();
        DioGuard(self)
    }

    /// The key of the shared wait queue `inode_dio_wait` sleeps on (Linux
    /// wake_up_var(&inode->i_dio_count))
    fn dio_key(&self) -> usize {
        core::ptr::from_ref(&self.i_dio_count) as usize
    }
}

/// A direct I/O counted in `Inode.i_dio_count` until dropped
#[must_use]
pub struct DioGuard<'a>(&'a Inode);

impl Drop for DioGuard<'_> {
    fn drop(&mut self) {
        self.0.inode_dio_end();
    }
}

/// [`InodeLock`] owning its inode reference ([`Inode::lock_arc`])
#[must_use]
pub struct InodeLockArc(InodeRef);

impl Drop for InodeLockArc {
    fn drop(&mut self) {
        // SAFETY: taken in `Inode::lock_arc`, released once (this drop)
        unsafe { self.0.i_rwsem.up_write() };
    }
}

/// An inode's i_rwsem held shared ([`Inode::lock_shared`])
#[must_use]
pub struct InodeLockShared<'a>(&'a Inode);

impl Drop for InodeLockShared<'_> {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: taken in `Inode::lock_shared`, released once
        unsafe { self.0.i_rwsem.up_read() };
    }
}

/// Null inode ops - returns errors for all operations
pub struct NullInodeOps;

impl InodeOps for NullInodeOps {
    fn lookup(&self, _dir: &Inode, _name: &[u8]) -> Result<InodeRef, KernelError> {
        Err(KernelError::OperationNotSupported)
    }
}

/// Static null inode ops instance
pub static NULL_INODE_OPS: NullInodeOps = NullInodeOps;

/// Which times a time update sets (Linux S_ATIME, S_MTIME | S_CTIME)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TimeUpdate {
    Atime,
    CMtime,
}

/// Linux setattr_copy's times: those given are set
pub fn setattr_copy_times(
    inode: &Inode,
    atime: Option<Timespec>,
    mtime: Option<Timespec>,
    ctime: Option<Timespec>,
) {
    if let Some(t) = atime {
        inode.set_atime(t);
    }
    if let Some(t) = mtime {
        inode.set_mtime(t);
    }
    if let Some(t) = ctime {
        inode.set_ctime(t);
    }
}

/// Linux generic_update_time: the times `what` names become `now`
pub fn generic_update_time(inode: &Inode, what: TimeUpdate, now: Timespec) {
    match what {
        TimeUpdate::Atime => inode.set_atime(now),
        TimeUpdate::CMtime => {
            inode.set_ctime(now);
            inode.set_mtime(now);
        }
    }
}

/// Write access to an inode, held by a file open for writing and by a
/// truncate (Linux get_write_access / put_write_access)
pub struct InodeWrite(InodeRef);

impl InodeRef {
    /// As [`Inode::lock`], the guard owning a reference to the inode (for
    /// an inode looked up while locking, as `lock_rename` does)
    pub fn lock_arc(&self) -> InodeLockArc {
        self.i_rwsem.down_write();
        InodeLockArc(self.clone())
    }

    /// Take write access (Linux get_write_access): ETXTBSY while the
    /// file is being executed
    pub fn get_write_access(&self) -> Result<InodeWrite, KernelError> {
        let c = &self.i_writecount;
        let mut v = c.load(Ordering::Relaxed);
        loop {
            if v < 0 {
                return Err(KernelError::TextBusy);
            }
            match c.compare_exchange_weak(v, v + 1, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return Ok(InodeWrite(self.clone())),
                Err(now) => v = now,
            }
        }
    }
}

impl Inode {
    /// Deny writes while executing it (Linux exe_file_deny_write_access
    /// on its inode): ETXTBSY while it is open for writing. Taken and
    /// released through a file ([`super::file::DenyWrite`]).
    pub(super) fn deny_write(&self) -> Result<(), KernelError> {
        let c = &self.i_writecount;
        let mut v = c.load(Ordering::Relaxed);
        loop {
            if v > 0 {
                return Err(KernelError::TextBusy);
            }
            match c.compare_exchange_weak(v, v - 1, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return Ok(()),
                Err(now) => v = now,
            }
        }
    }

    /// Another denial while one is held (fork's copy of it)
    pub(super) fn deny_write_again(&self) {
        self.i_writecount.fetch_sub(1, Ordering::AcqRel);
    }

    /// Release a denial (Linux exe_file_allow_write_access)
    pub(super) fn allow_write(&self) {
        self.i_writecount.fetch_add(1, Ordering::AcqRel);
    }
}

impl Drop for InodeWrite {
    fn drop(&mut self) {
        self.0.i_writecount.fetch_sub(1, Ordering::AcqRel);
    }
}

/// What a new inode starts with ([`Inode::new`], [`Inode::new_device`]):
/// [`Inode::alloc`] builds the inode from it in place
pub struct InodeInit {
    pub ino: InodeId,
    pub mode: InodeMode,
    pub uid: Uid,
    pub gid: Gid,
    pub size: u64,
    pub rdev: DevId,
    pub mtime: Timespec,
    pub sb: Weak<SuperBlock>,
    pub i_op: &'static dyn InodeOps,
    /// Set by the filesystem before [`Inode::alloc`] (Linux
    /// i_generation)
    pub i_generation: u32,
}

/// Linux evict: the inode, I_FREEING with no reference left, leaves the
/// writeback and superblock lists (the lists' contract, `InodeList`),
/// its filesystem releases what it still owns while it is still hashed
/// and it is unhashed, the cache's waiters woken (`icache::evict`);
/// then its fields go (`destroy_inode`) and its memory is freed a grace
/// period later (`i_callback`).
///
/// # Safety
/// `p` is I_FREEING with its count at zero; called once.
unsafe fn evict(p: NonNull<Inode>) {
    {
        // SAFETY: live until the free queued below
        let i = unsafe { p.as_ref() };
        super::fs_writeback::inode_io_list_del(i);
        // Linux evict: inode_wait_for_writeback (a writer holds a
        // reference here, so none is left to wait for)
        drop(super::fs_writeback::inode_wait_for_writeback(
            i,
            i.i_lock.lock(),
        ));
        sb_list_del(i);
        super::icache::evict(i);
    }
    // SAFETY: evicted, no borrow of it left here; called once
    unsafe { destroy_inode(p.as_ptr()) };
}

/// Drop the `ManuallyDrop` field at `f`
///
/// # Safety
/// `f` points at a live field, valid for writes, that nothing uses or
/// borrows again.
unsafe fn drop_field<T>(f: *mut ManuallyDrop<T>) {
    // SAFETY: `ManuallyDrop<T>` is `repr(transparent)` over `T`; the
    // caller's contract
    unsafe { core::ptr::drop_in_place(f.cast::<T>()) }
}

/// Release what an evicted inode still holds, synchronously: every
/// field with drop glue (Linux evict's truncate_inode_pages_final, then
/// destroy_inode: __destroy_inode's fsnotify_inode_delete,
/// locks_free_lock_context, inode_detach_wb; ->destroy_inode's
/// filesystem data; the superblock reference last, as Linux reads
/// i_sb->s_op there); then the free is queued (call_rcu(&i_rcu,
/// i_callback)), or done at once where no RCU reader can stand on it
///
/// # Safety
/// `i` is an evicted inode whose count reached zero, not borrowed;
/// called once.
unsafe fn destroy_inode(i: *mut Inode) {
    // SAFETY: (each) a field of `i`, dropped once, unborrowed (the
    // caller's contract)
    unsafe { drop_field(&raw mut (*i).i_data) };
    // SAFETY: as above
    unsafe { drop_field(&raw mut (*i).fsnotify) };
    // SAFETY: as above
    unsafe { drop_field(&raw mut (*i).i_flctx) };
    // SAFETY: as above
    unsafe { drop_field(&raw mut (*i).i_wb) };
    // SAFETY: as above
    unsafe { drop_field(&raw mut (*i).private) };
    // SAFETY: as above
    unsafe { drop_field(&raw mut (*i).i_pipe) };
    // SAFETY: as above
    unsafe { drop_field(&raw mut (*i).sb) };
    let p = i.cast_const().cast::<()>();
    if crate::sync::rcu::can_queue() {
        // SAFETY: `i_rcu` is in the inode, whose memory nothing frees
        // before `i_callback` runs; `i_callback` only drops fields fit
        // for any context and frees the block
        unsafe { crate::sync::rcu::call_rcu(&(*i).i_rcu, i_callback, p) };
    } else {
        // SAFETY: no reader can stand on it (host tests; early boot,
        // one CPU, no RCU yet)
        unsafe { i_callback(p) };
    }
}

/// (`no_glue`) No field of `Inode` has drop glue, and so neither has
/// `Inode`: nothing but `destroy_inode` and `i_callback` writes an
/// inode before its free, and the free (a `Box<Inode>` dropped) only
/// releases the block. Checked per field, on the field's own type; the
/// pattern names every field (no `..`), so a field added fails to build
/// until it is listed here. One with glue fails the assertion: make it
/// `ManuallyDrop` and drop it in `destroy_inode` (or `i_callback`, for
/// one an RCU reader may read).
const _: () = {
    /// No drop glue in the type `f` points at
    const fn glue_free<T>(_: *const T) -> bool {
        !core::mem::needs_drop::<T>()
    }
    macro_rules! no_glue {
        ($($f:ident),* $(,)?) => {
            let u = core::mem::MaybeUninit::<Inode>::uninit();
            let p = u.as_ptr();
            $(
                // SAFETY: a field place of `u`, named, never read
                let f = unsafe { &raw const (*p).$f };
                assert!(glue_free(f), concat!("Inode.", stringify!($f), " has drop glue"));
            )*
            let _ = |i: &Inode| {
                let Inode { $($f: _),* } = i;
            };
        };
    }
    no_glue!(
        i_count,
        i_state,
        i_rcu,
        ino,
        mode,
        uid,
        gid,
        size,
        i_blkbits,
        nlink,
        i_generation,
        i_version,
        i_flags,
        rdev,
        atime,
        mtime,
        ctime,
        sb,
        i_op,
        i_rwsem,
        i_dio_count,
        private,
        i_pipe,
        i_data,
        fsnotify,
        dirtied_when,
        i_io_list,
        i_io_on,
        i_wb,
        i_writecount,
        i_flctx,
        i_hash,
        i_hash_node,
        i_sequence,
        i_sb_list,
        i_link,
        i_private_rcu,
        i_lock,
    );
    assert!(!core::mem::needs_drop::<Inode>());
};

/// The inode's memory, a grace period after its teardown (Linux
/// i_callback -> ->free_inode): a symlink's `i_link` and the RCU data
/// (procfs's pid), then the block
///
/// # Safety
/// `p` is an inode `destroy_inode` tore down, freed once, a grace period
/// after (no RCU reader still on it).
unsafe fn i_callback(p: *const ()) {
    let i = p.cast::<Inode>().cast_mut();
    // SAFETY: the inode's memory, still allocated; its teardown left
    // `i_link` alone and no reader stands on it a grace period later;
    // dropped once, here
    unsafe { drop_field(&raw mut (*i).i_link) };
    // SAFETY: as above
    unsafe { drop_field(&raw mut (*i).i_private_rcu) };
    // SAFETY: the block `Inode::alloc` made (`Box::into_raw`), freed
    // once; `Inode` has no drop glue (`no_glue`), so this only frees it
    drop(unsafe { Box::from_raw(i) });
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestOps;

    impl InodeOps for TestOps {
        fn lookup(&self, _dir: &Inode, _name: &[u8]) -> Result<InodeRef, KernelError> {
            Err(KernelError::NotFound)
        }
    }

    static TEST_OPS: TestOps = TestOps;

    /// Evictions `CountOps` saw
    static EVICTS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

    /// Counts its evictions, each checked to run I_FREEING with no
    /// reference to take (Linux evict after iput_final)
    struct CountOps;

    impl InodeOps for CountOps {
        fn lookup(&self, _dir: &Inode, _name: &[u8]) -> Result<InodeRef, KernelError> {
            Err(KernelError::NotFound)
        }

        fn evict_inode(&self, inode: &Inode) {
            assert!(inode.state() & I_FREEING != 0);
            assert!(inode.igrab().is_none(), "igrab of a freeing inode");
            EVICTS.fetch_add(1, Ordering::Relaxed);
        }
    }

    static COUNT_OPS: CountOps = CountOps;

    /// ihold and igrab count up, iput down; only the last put evicts,
    /// once, and from then on igrab refuses it
    #[test]
    fn last_iput_evicts_once() {
        let i = Inode::alloc(Inode::new(
            1,
            InodeMode::regular(0o644),
            0,
            0,
            0,
            Timespec::ZERO,
            Weak::new(),
            &COUNT_OPS,
        ))
        .unwrap();
        assert_eq!(InodeRef::count(&i), 1);
        let held = i.clone();
        let grabbed = i.igrab().unwrap();
        assert!(InodeRef::ptr_eq(&grabbed, &i) && InodeRef::count(&i) == 3);
        drop((held, grabbed));
        assert_eq!(InodeRef::count(&i), 1);
        assert_eq!(i.state(), 0);
        assert_eq!(EVICTS.load(Ordering::Relaxed), 0);
        drop(i);
        assert_eq!(EVICTS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn dio_count() {
        let i = Inode::alloc(Inode::new(
            1,
            InodeMode::regular(0o644),
            0,
            0,
            0,
            Timespec::ZERO,
            Weak::new(),
            &TEST_OPS,
        ))
        .unwrap();
        // None in flight: no wait
        i.inode_dio_wait();
        i.inode_dio_begin();
        {
            let _g = i.dio_guard();
            assert_eq!(i.dio_count(), 2);
        }
        assert_eq!(i.dio_count(), 1);
        i.inode_dio_end();
        assert_eq!(i.dio_count(), 0);
        i.inode_dio_wait();
        // The wakeup's queue is the variable's, the same every time
        assert!(core::ptr::eq(
            var_waitqueue(i.dio_key()),
            var_waitqueue(i.dio_key())
        ));
    }
}
