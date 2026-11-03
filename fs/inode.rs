//! Inode - file/directory object representation
//!
//! Following Linux VFS design, an inode represents a file object
//! independent of its name(s) in the directory tree.

use alloc::sync::{Arc, Weak};

use crate::sync::spin::RwLock;
use ::core::sync::atomic::{AtomicI64, AtomicU16, AtomicU32, AtomicU64, Ordering};

use crate::sync::RwSem;

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

/// Inode operations trait - filesystem-specific behavior
pub trait InodeOps: Send + Sync {
    /// Look up a child entry in a directory inode
    fn lookup(&self, dir: &Inode, name: &[u8]) -> Result<Arc<Inode>, KernelError>;

    /// A cached dentry of this inode is still good for the walk (Linux
    /// d_revalidate): false drops it and the walk looks the name up
    /// again. Default yes; procfs says no once its task or fd is gone.
    fn revalidate(&self, _inode: &Inode) -> bool {
        true
    }

    /// Access check for `mask` (MAY_* bits) by `cred` (Linux
    /// ->permission). Default: generic_permission (mode bits plus
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

    /// Create a new file in a directory
    fn create(&self, dir: &Inode, name: &[u8], mode: InodeMode) -> Result<Arc<Inode>, KernelError> {
        let _ = (dir, name, mode);
        Err(KernelError::OperationNotSupported)
    }

    /// Create a new directory
    fn mkdir(&self, dir: &Inode, name: &[u8], mode: InodeMode) -> Result<Arc<Inode>, KernelError> {
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
    ) -> Result<Arc<Inode>, KernelError> {
        let _ = (dir, name, mode, rdev);
        Err(KernelError::OperationNotSupported)
    }

    /// Remove a file
    fn unlink(&self, dir: &Inode, name: &[u8]) -> Result<(), KernelError> {
        let _ = (dir, name);
        Err(KernelError::OperationNotSupported)
    }

    /// Remove a directory
    fn rmdir(&self, dir: &Inode, name: &[u8]) -> Result<(), KernelError> {
        let _ = (dir, name);
        Err(KernelError::OperationNotSupported)
    }

    /// Read the target of a symbolic link
    fn readlink(&self, inode: &Inode) -> Result<alloc::vec::Vec<u8>, KernelError> {
        let _ = inode;
        Err(KernelError::OperationNotSupported)
    }

    /// Create a symbolic link
    fn symlink(&self, dir: &Inode, name: &[u8], target: &[u8]) -> Result<Arc<Inode>, KernelError> {
        let _ = (dir, name, target);
        Err(KernelError::OperationNotSupported)
    }

    /// Create a hard link (new directory entry pointing to existing inode)
    fn link(&self, dir: &Inode, name: &[u8], inode: &Arc<Inode>) -> Result<(), KernelError> {
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
        new_dir: &Arc<Inode>,
        new_name: &[u8],
        flags: u32,
    ) -> Result<(), KernelError> {
        let _ = (old_dir, old_name, new_dir, new_name, flags);
        Err(KernelError::OperationNotSupported)
    }

    /// Truncate or extend a file to a specified length
    ///
    /// If the file was larger than length, the extra data is discarded.
    /// If the file was shorter, it is extended with null bytes.
    fn truncate(&self, inode: &Arc<Inode>, length: u64) -> Result<(), KernelError> {
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
    /// unlinked file. Called from `Drop for Inode` in any context:
    /// must not sleep (defer I/O to a workqueue).
    fn evict_inode(&self, inode: &Inode) {
        let _ = inode;
    }

    /// Get file size (may be dynamically computed for procfs)
    ///
    /// Timestamps are read lock-free (Linux generic_fillattr).
    fn getattr(&self, inode: &Inode) -> InodeAttr {
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
    fn getxattr(&self, inode: &Inode, name: &str, value: &mut [u8]) -> Result<usize, KernelError> {
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
        name: &str,
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
    fn removexattr(&self, inode: &Inode, name: &str) -> Result<(), KernelError> {
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

    /// A removed directory (Linux S_DEAD): set by rmdir, or a rename
    /// replacing it, under its i_rwsem; mount refuses it
    dead: core::sync::atomic::AtomicBool,

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
    pub sb: Weak<SuperBlock>,

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

    /// Filesystem-specific private data
    pub private: RwLock<Option<Arc<dyn InodeData>>>,

    /// A FIFO's pipe while it is open, and how many files have it open
    /// (Linux inode->i_pipe and pipe->files)
    pub i_pipe: crate::sync::spin::Mutex<Option<(Arc<crate::io::pipe::Pipe>, usize)>>,

    /// The file's page cache (Linux i_data)
    pub i_data: crate::mm::filemap::AddressSpace,

    /// On its superblock's dirty list (Linux I_DIRTY_PAGES; fs_writeback)
    pub(crate) i_dirty: core::sync::atomic::AtomicBool,

    /// Writers (> 0) or executions denying them (< 0) (Linux
    /// i_writecount; `get_write_access`, `deny_write_access`)
    i_writecount: core::sync::atomic::AtomicI32,

    /// An active swap area (Linux S_SWAPFILE): writes and truncates are
    /// ETXTBSY
    pub i_swapfile: core::sync::atomic::AtomicBool,

    /// Its flock and POSIX locks (Linux i_flctx; `fs::locks`)
    pub i_flctx: super::locks::FileLockCtx,

    /// The inode cache key it is hashed under (`fs::icache`)
    pub(super) i_hash: AtomicU64,
    /// Hashed in the inode cache (Linux !inode_unhashed)
    pub(super) i_hashed: core::sync::atomic::AtomicBool,
    /// Identity for shared futex keys (Linux i_sequence)
    pub(crate) i_sequence: crate::task::futex::KeySeq,
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
            dead: core::sync::atomic::AtomicBool::new(false),
            rdev: DevId::null(),
            atime: InodeTime::new(mtime),
            mtime: InodeTime::new(mtime),
            ctime: InodeTime::new(mtime),
            sb,
            i_op,
            i_rwsem: RwSem::new(()),
            private: RwLock::new(None),
            i_pipe: crate::sync::spin::Mutex::new(None),
            i_hash: AtomicU64::new(0),
            i_hashed: core::sync::atomic::AtomicBool::new(false),
            i_data: crate::mm::filemap::AddressSpace::new(),
            i_dirty: core::sync::atomic::AtomicBool::new(false),
            i_writecount: core::sync::atomic::AtomicI32::new(0),
            i_swapfile: core::sync::atomic::AtomicBool::new(false),
            i_flctx: super::locks::FileLockCtx::new(),
            i_sequence: crate::task::futex::KeySeq::new(),
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
            dead: core::sync::atomic::AtomicBool::new(false),
            rdev,
            atime: InodeTime::new(mtime),
            mtime: InodeTime::new(mtime),
            ctime: InodeTime::new(mtime),
            sb,
            i_op,
            i_rwsem: RwSem::new(()),
            private: RwLock::new(None),
            i_pipe: crate::sync::spin::Mutex::new(None),
            i_hash: AtomicU64::new(0),
            i_hashed: core::sync::atomic::AtomicBool::new(false),
            i_data: crate::mm::filemap::AddressSpace::new(),
            i_dirty: core::sync::atomic::AtomicBool::new(false),
            i_writecount: core::sync::atomic::AtomicI32::new(0),
            i_swapfile: core::sync::atomic::AtomicBool::new(false),
            i_flctx: super::locks::FileLockCtx::new(),
            i_sequence: crate::task::futex::KeySeq::new(),
        }
    }

    /// Mark a removed directory dead (caller holds its i_rwsem)
    pub fn set_dead(&self) {
        self.dead.store(true, Ordering::Release);
    }

    /// Removed directory (Linux IS_DEADDIR)
    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Acquire)
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

    /// Take i_rwsem for writing (Linux inode_lock): directory changes,
    /// truncate, attribute changes; held until the guard drops. For two
    /// directories (rename) use `lock_rename`.
    #[inline]
    pub fn lock(&self) -> InodeLock<'_> {
        self.i_rwsem.down_write();
        InodeLock(self)
    }

    /// As [`Inode::lock`], the guard owning a reference to the inode (for
    /// an inode looked up while locking, as `lock_rename` does)
    pub fn lock_arc(self: &Arc<Self>) -> InodeLockArc {
        self.i_rwsem.down_write();
        InodeLockArc(self.clone())
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

/// [`InodeLock`] owning its inode reference ([`Inode::lock_arc`])
#[must_use]
pub struct InodeLockArc(Arc<Inode>);

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
    fn lookup(&self, _dir: &Inode, _name: &[u8]) -> Result<Arc<Inode>, KernelError> {
        Err(KernelError::OperationNotSupported)
    }
}

/// Static null inode ops instance
pub static NULL_INODE_OPS: NullInodeOps = NullInodeOps;

/// Write access to an inode, held by a file open for writing and by a
/// truncate (Linux get_write_access / put_write_access)
pub struct InodeWrite(Arc<Inode>);

/// Writes denied while a program runs from the inode (Linux
/// deny_write_access / allow_write_access, held by the address space)
pub struct DenyWrite(Arc<Inode>);

impl Inode {
    /// Take write access (Linux get_write_access): ETXTBSY while the
    /// file is being executed
    pub fn get_write_access(self: &Arc<Self>) -> Result<InodeWrite, KernelError> {
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

    /// Deny writes while executing it (Linux exe_file_deny_write_access):
    /// ETXTBSY while it is open for writing
    pub fn deny_write_access(self: &Arc<Self>) -> Result<DenyWrite, KernelError> {
        let c = &self.i_writecount;
        let mut v = c.load(Ordering::Relaxed);
        loop {
            if v > 0 {
                return Err(KernelError::TextBusy);
            }
            match c.compare_exchange_weak(v, v - 1, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return Ok(DenyWrite(self.clone())),
                Err(now) => v = now,
            }
        }
    }
}

impl Drop for InodeWrite {
    fn drop(&mut self) {
        self.0.i_writecount.fetch_sub(1, Ordering::AcqRel);
    }
}

impl DenyWrite {
    /// The inode executed
    pub fn inode(&self) -> &Arc<Inode> {
        &self.0
    }
}

/// fork's copy of the address space denies writes again
impl Clone for DenyWrite {
    fn clone(&self) -> Self {
        self.0.i_writecount.fetch_sub(1, Ordering::AcqRel);
        DenyWrite(self.0.clone())
    }
}

impl Drop for DenyWrite {
    fn drop(&mut self) {
        self.0.i_writecount.fetch_add(1, Ordering::AcqRel);
    }
}

impl Drop for Inode {
    fn drop(&mut self) {
        super::icache::evict(self);
    }
}
