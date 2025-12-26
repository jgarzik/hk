//! Superblock - filesystem instance representation
//!
//! Each mounted filesystem has a superblock that holds filesystem-wide
//! state and provides operations for managing inodes.

use alloc::sync::Arc;

use ::core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

use super::KernelError;
use super::dentry::Dentry;
use super::inode::{Inode, InodeId, InodeMode, InodeOps};

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
    fn statfs(&self) -> StatFs {
        StatFs::default()
    }
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

impl StatFs {
    /// Convert internal StatFs to Linux ABI format
    pub fn to_linux(&self, dev_id: u64, mount_flags: u32) -> LinuxStatFs {
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
            f_flags: Self::mount_flags_to_st_flags(mount_flags) as i64,
            f_spare: [0; 4],
        }
    }

    /// Convert internal mount flags to ST_* flags for userspace
    fn mount_flags_to_st_flags(_mnt_flags: u32) -> u64 {
        // ST_RDONLY = 1, ST_NOSUID = 2, ST_NODEV = 4, etc.
        // For now return 0; can expand when mount flags are implemented
        0
    }
}

use super::file::FileOps;

use crate::storage::BlockDevice;

/// Mount function type for pseudo-filesystems (no backing device)
pub type MountFn = fn(fs_type: &'static FileSystemType) -> Result<Arc<SuperBlock>, KernelError>;

/// Mount function type for device-backed filesystems (ext4, vfat, etc.)
pub type MountDevFn = fn(
    fs_type: &'static FileSystemType,
    bdev: Arc<BlockDevice>,
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
}

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
pub struct SuperBlock {
    /// Filesystem type
    pub fs_type: &'static FileSystemType,

    /// Root dentry of this filesystem
    pub root: RwLock<Option<Arc<Dentry>>>,

    /// Superblock operations
    pub s_op: &'static dyn SuperOps,

    /// Mount flags
    pub flags: u32,

    /// Next inode number to allocate
    next_ino: AtomicU64,

    /// Unique device ID for this filesystem instance (for stat st_dev)
    pub dev_id: u64,

    /// Filesystem-specific private data
    pub private: RwLock<Option<Arc<dyn SuperBlockData>>>,

    /// Mutex for cross-directory renames (like Linux s_vfs_rename_mutex)
    ///
    /// Serializes all cross-directory renames on this filesystem to
    /// prevent races during ancestor relationship checks. Same-directory
    /// renames don't need this mutex.
    pub s_vfs_rename_mutex: Mutex<()>,
}

use super::inode::AsAny;

/// Trait for filesystem-specific superblock data
pub trait SuperBlockData: Send + Sync + AsAny {}

impl SuperBlock {
    /// Create a new superblock
    pub fn new(
        fs_type: &'static FileSystemType,
        s_op: &'static dyn SuperOps,
        flags: u32,
    ) -> Arc<Self> {
        Arc::new(Self {
            fs_type,
            root: RwLock::new(None),
            s_op,
            flags,
            next_ino: AtomicU64::new(1), // Start inode numbers at 1
            dev_id: NEXT_DEV_ID.fetch_add(1, Ordering::Relaxed),
            private: RwLock::new(None),
            s_vfs_rename_mutex: Mutex::new(()),
        })
    }

    /// Set the root dentry
    pub fn set_root(&self, root: Arc<Dentry>) {
        *self.root.write() = Some(root);
    }

    /// Get the root dentry
    pub fn get_root(&self) -> Option<Arc<Dentry>> {
        self.root.read().clone()
    }

    /// Allocate the next inode number
    pub fn alloc_ino(&self) -> InodeId {
        self.next_ino.fetch_add(1, Ordering::Relaxed)
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

// SuperBlock is Send + Sync because all interior mutability is through atomic or lock
unsafe impl Send for SuperBlock {}
unsafe impl Sync for SuperBlock {}

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

use alloc::collections::BTreeMap;
use spin::Mutex;

/// Global filesystem type registry
static FS_TYPES: Mutex<BTreeMap<&'static str, &'static FileSystemType>> =
    Mutex::new(BTreeMap::new());

/// Register a filesystem type
///
/// Makes the filesystem type available for mounting by name.
pub fn register_filesystem(fs_type: &'static FileSystemType) {
    FS_TYPES.lock().insert(fs_type.name, fs_type);
}

/// Find a filesystem type by name
///
/// Returns the filesystem type if registered, None otherwise.
pub fn find_filesystem(name: &str) -> Option<&'static FileSystemType> {
    FS_TYPES.lock().get(name).copied()
}

/// Initialize the filesystem type registry with built-in types
///
/// Should be called during VFS initialization before any mounts.
pub fn init_fs_registry() {
    register_filesystem(&super::ramfs::RAMFS_TYPE);
    register_filesystem(&super::procfs::PROCFS_TYPE);
    register_filesystem(&super::vfat::VFAT_TYPE);
}
