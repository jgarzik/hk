//! Inode - file/directory object representation
//!
//! Following Linux VFS design, an inode represents a file object
//! independent of its name(s) in the directory tree.

use alloc::sync::{Arc, Weak};

use ::core::cell::Cell;
use ::core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering};
use spin::{Mutex, RwLock};

use super::FsError;
use super::superblock::SuperBlock;

// Re-export device types from chardev module
pub use crate::chardev::{DevId, DeviceType};

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

    /// Get permission bits (lower 12 bits)
    pub fn perm(&self) -> u16 {
        self.0 & 0o7777
    }

    /// Get raw mode value
    pub fn raw(&self) -> u16 {
        self.0
    }

    /// Check if given uid/gid has the requested access permission
    ///
    /// # Arguments
    /// * `uid` - User ID of the requesting process (fsuid)
    /// * `gid` - Group ID of the requesting process (fsgid)
    /// * `inode_uid` - Owner user ID of the inode
    /// * `inode_gid` - Owner group ID of the inode
    /// * `mask` - Permission mask (MAY_READ=4, MAY_WRITE=2, MAY_EXEC=1)
    ///
    /// # Returns
    /// `true` if access is allowed, `false` otherwise
    ///
    /// Note: Root (uid=0) bypasses all permission checks - this should be
    /// handled by the caller before calling this method.
    pub fn check_permission(
        &self,
        uid: Uid,
        gid: Gid,
        inode_uid: Uid,
        inode_gid: Gid,
        mask: u32,
    ) -> bool {
        let perm = self.perm();
        let bits = if uid == inode_uid {
            // Owner bits (bits 6-8)
            (perm >> 6) & 0o7
        } else if gid == inode_gid {
            // Group bits (bits 3-5)
            (perm >> 3) & 0o7
        } else {
            // Other bits (bits 0-2)
            perm & 0o7
        };

        (bits as u32 & mask) == mask
    }
}

/// Inode operations trait - filesystem-specific behavior
pub trait InodeOps: Send + Sync {
    /// Look up a child entry in a directory inode
    fn lookup(&self, dir: &Inode, name: &str) -> Result<Arc<Inode>, FsError>;

    /// Create a new file in a directory
    fn create(&self, dir: &Inode, name: &str, mode: InodeMode) -> Result<Arc<Inode>, FsError> {
        let _ = (dir, name, mode);
        Err(FsError::NotSupported)
    }

    /// Create a new directory
    fn mkdir(&self, dir: &Inode, name: &str, mode: InodeMode) -> Result<Arc<Inode>, FsError> {
        let _ = (dir, name, mode);
        Err(FsError::NotSupported)
    }

    /// Remove a file
    fn unlink(&self, dir: &Inode, name: &str) -> Result<(), FsError> {
        let _ = (dir, name);
        Err(FsError::NotSupported)
    }

    /// Remove a directory
    fn rmdir(&self, dir: &Inode, name: &str) -> Result<(), FsError> {
        let _ = (dir, name);
        Err(FsError::NotSupported)
    }

    /// Read the target of a symbolic link
    fn readlink(&self, inode: &Inode) -> Result<alloc::string::String, FsError> {
        let _ = inode;
        Err(FsError::NotSupported)
    }

    /// Create a symbolic link
    fn symlink(&self, dir: &Inode, name: &str, target: &str) -> Result<Arc<Inode>, FsError> {
        let _ = (dir, name, target);
        Err(FsError::NotSupported)
    }

    /// Create a hard link (new directory entry pointing to existing inode)
    fn link(&self, dir: &Inode, name: &str, inode: &Arc<Inode>) -> Result<(), FsError> {
        let _ = (dir, name, inode);
        Err(FsError::NotSupported)
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
        old_name: &str,
        new_dir: &Arc<Inode>,
        new_name: &str,
        flags: u32,
    ) -> Result<(), FsError> {
        let _ = (old_dir, old_name, new_dir, new_name, flags);
        Err(FsError::NotSupported)
    }

    /// Truncate or extend a file to a specified length
    ///
    /// If the file was larger than length, the extra data is discarded.
    /// If the file was shorter, it is extended with null bytes.
    fn truncate(&self, inode: &Inode, length: u64) -> Result<(), FsError> {
        let _ = (inode, length);
        Err(FsError::NotSupported)
    }

    /// Read a page of data from a file
    /// Returns the number of bytes read (may be less than PAGE_SIZE at EOF)
    fn readpage(&self, inode: &Inode, page_offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let _ = (inode, page_offset, buf);
        Err(FsError::NotSupported)
    }

    /// Write a page of data to a file
    fn writepage(&self, inode: &Inode, page_offset: u64, buf: &[u8]) -> Result<usize, FsError> {
        let _ = (inode, page_offset, buf);
        Err(FsError::NotSupported)
    }

    /// Get file size (may be dynamically computed for procfs)
    ///
    /// Acquires inode.lock in read mode to safely read timestamps
    /// (Linux i_rwsem pattern - caller provides serialization).
    fn getattr(&self, inode: &Inode) -> InodeAttr {
        // Acquire read lock for timestamp access (Linux i_rwsem pattern)
        let _guard = inode.lock.read();
        InodeAttr {
            ino: inode.ino,
            mode: inode.mode(),
            uid: inode.uid(),
            gid: inode.gid(),
            size: inode.size.load(Ordering::Relaxed),
            nlink: inode.get_nlink(),
            rdev: inode.rdev,
            atime: inode.atime(),
            mtime: inode.mtime(),
            ctime: inode.ctime(),
        }
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
}

/// Filesystem-specific data attached to an inode
pub trait InodeData: Send + Sync + AsAny {}

/// Trait for downcasting to concrete types
pub trait AsAny: Send + Sync {
    fn as_any(&self) -> &dyn core::any::Any;
}

/// The inode structure - represents a file object
pub struct Inode {
    /// Inode number (unique within filesystem)
    pub ino: InodeId,

    /// File mode (type + permissions) - atomic for chmod support
    mode: AtomicU16,

    /// Owner user ID - atomic for chown support
    uid: AtomicU32,

    /// Owner group ID - atomic for chown support
    gid: AtomicU32,

    /// File size in bytes
    pub size: AtomicU64,

    /// Link count (atomic for thread-safe hard link management)
    pub nlink: AtomicU32,

    /// Device ID for character/block devices (major/minor)
    /// For non-device files, this is DevId::null()
    pub rdev: DevId,

    /// Last access time - Cell for interior mutability (utimensat)
    atime: Cell<Timespec>,

    /// Last modification time - Cell for interior mutability (utimensat)
    mtime: Cell<Timespec>,

    /// Last status change time - Cell for interior mutability (utimensat)
    ctime: Cell<Timespec>,

    /// Pointer back to superblock
    pub sb: Weak<SuperBlock>,

    /// Inode operations (filesystem-specific)
    pub i_op: &'static dyn InodeOps,

    /// Per-inode lock for metadata protection
    /// Lock ordering: parent inode lock before child inode lock
    pub lock: RwLock<()>,

    /// Directory operation semaphore (like Linux i_rwsem)
    ///
    /// This lock serializes directory operations: create, mkdir, unlink,
    /// rmdir, link, symlink, rename, and lookup. Following Linux's i_rwsem
    /// pattern, VFS acquires this lock before calling filesystem ops.
    ///
    /// For rename operations involving two directories, use lock_rename()
    /// instead which handles proper lock ordering.
    i_rwsem: Mutex<()>,

    /// Filesystem-specific private data
    pub private: RwLock<Option<Arc<dyn InodeData>>>,
}

impl Inode {
    /// Create a new inode
    ///
    /// # Arguments
    /// * `mtime` - Modification time (atime and ctime are initialized to same value)
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ino: InodeId,
        mode: InodeMode,
        uid: Uid,
        gid: Gid,
        size: u64,
        mtime: Timespec,
        sb: Weak<SuperBlock>,
        i_op: &'static dyn InodeOps,
    ) -> Self {
        Self {
            ino,
            mode: AtomicU16::new(mode.0),
            uid: AtomicU32::new(uid),
            gid: AtomicU32::new(gid),
            size: AtomicU64::new(size),
            nlink: AtomicU32::new(1),
            rdev: DevId::null(),
            atime: Cell::new(mtime),
            mtime: Cell::new(mtime),
            ctime: Cell::new(mtime),
            sb,
            i_op,
            lock: RwLock::new(()),
            i_rwsem: Mutex::new(()),
            private: RwLock::new(None),
        }
    }

    /// Create a new device inode
    ///
    /// # Arguments
    /// * `rdev` - Device ID (major/minor numbers)
    /// * `mtime` - Modification time
    #[allow(clippy::too_many_arguments)]
    pub fn new_device(
        ino: InodeId,
        mode: InodeMode,
        uid: Uid,
        gid: Gid,
        rdev: DevId,
        mtime: Timespec,
        sb: Weak<SuperBlock>,
        i_op: &'static dyn InodeOps,
    ) -> Self {
        Self {
            ino,
            mode: AtomicU16::new(mode.0),
            uid: AtomicU32::new(uid),
            gid: AtomicU32::new(gid),
            size: AtomicU64::new(0),
            nlink: AtomicU32::new(1),
            rdev,
            atime: Cell::new(mtime),
            mtime: Cell::new(mtime),
            ctime: Cell::new(mtime),
            sb,
            i_op,
            lock: RwLock::new(()),
            i_rwsem: Mutex::new(()),
            private: RwLock::new(None),
        }
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
    ///
    /// # Locking
    /// Caller must hold `inode.lock` in read mode before calling this method.
    /// This follows Linux's i_rwsem pattern where callers provide serialization.
    pub fn atime(&self) -> Timespec {
        self.atime.get()
    }

    /// Get last modification time
    ///
    /// # Locking
    /// Caller must hold `inode.lock` in read mode before calling this method.
    /// This follows Linux's i_rwsem pattern where callers provide serialization.
    pub fn mtime(&self) -> Timespec {
        self.mtime.get()
    }

    /// Get last status change time
    ///
    /// # Locking
    /// Caller must hold `inode.lock` in read mode before calling this method.
    /// This follows Linux's i_rwsem pattern where callers provide serialization.
    pub fn ctime(&self) -> Timespec {
        self.ctime.get()
    }

    /// Set last access time (for utimensat)
    ///
    /// # Locking
    /// Caller must hold `inode.lock` in write mode before calling this method.
    /// This follows Linux's i_rwsem pattern where callers provide serialization.
    pub fn set_atime(&self, time: Timespec) {
        self.atime.set(time);
    }

    /// Set last modification time (for utimensat)
    ///
    /// # Locking
    /// Caller must hold `inode.lock` in write mode before calling this method.
    /// This follows Linux's i_rwsem pattern where callers provide serialization.
    pub fn set_mtime(&self, time: Timespec) {
        self.mtime.set(time);
    }

    /// Set last status change time
    ///
    /// Note: ctime is automatically updated by the kernel, not directly settable by user.
    ///
    /// # Locking
    /// Caller must hold `inode.lock` in write mode before calling this method.
    /// This follows Linux's i_rwsem pattern where callers provide serialization.
    pub fn set_ctime(&self, time: Timespec) {
        self.ctime.set(time);
    }

    /// Get the superblock this inode belongs to
    pub fn superblock(&self) -> Option<Arc<SuperBlock>> {
        self.sb.upgrade()
    }

    /// Set filesystem-specific private data
    pub fn set_private(&self, data: Arc<dyn InodeData>) {
        *self.private.write() = Some(data);
    }

    /// Get filesystem-specific private data
    pub fn get_private(&self) -> Option<Arc<dyn InodeData>> {
        self.private.read().clone()
    }

    /// Update file size
    pub fn set_size(&self, size: u64) {
        self.size.store(size, Ordering::Relaxed);
    }

    /// Get current file size
    pub fn get_size(&self) -> u64 {
        self.size.load(Ordering::Relaxed)
    }

    /// Get current link count
    pub fn get_nlink(&self) -> u32 {
        self.nlink.load(Ordering::Relaxed)
    }

    /// Increment link count (for hard links)
    pub fn inc_nlink(&self) {
        self.nlink.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement link count, returns new value
    pub fn dec_nlink(&self) -> u32 {
        self.nlink.fetch_sub(1, Ordering::Relaxed) - 1
    }

    // ========================================================================
    // Directory locking (Linux i_rwsem pattern)
    // ========================================================================

    /// Acquire exclusive lock on directory for operations
    ///
    /// This implements Linux's inode_lock() pattern. VFS calls this before
    /// invoking filesystem directory operations (create, mkdir, unlink, etc.).
    /// The lock serializes directory modifications to prevent races.
    ///
    /// # Safety
    /// Caller must ensure inode_unlock() is called to release the lock.
    /// For operations on two directories (rename), use lock_rename() instead.
    pub fn inode_lock(&self) {
        let guard = self.i_rwsem.lock();
        core::mem::forget(guard);
    }

    /// Release exclusive lock on directory
    ///
    /// # Safety
    /// Must only be called after a successful inode_lock() call.
    /// The lock must have been acquired by this thread.
    pub unsafe fn inode_unlock(&self) {
        unsafe { self.i_rwsem.force_unlock() };
    }
}

// Inode is Send + Sync because all interior mutability is through atomic or lock
unsafe impl Send for Inode {}
unsafe impl Sync for Inode {}

/// Null inode ops - returns errors for all operations
pub struct NullInodeOps;

impl InodeOps for NullInodeOps {
    fn lookup(&self, _dir: &Inode, _name: &str) -> Result<Arc<Inode>, FsError> {
        Err(FsError::NotSupported)
    }
}

/// Static null inode ops instance
pub static NULL_INODE_OPS: NullInodeOps = NullInodeOps;
