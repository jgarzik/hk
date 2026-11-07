//! nullfs: the immutable, permanently empty filesystem
//!
//! Linux reference: fs/nullfs.c (7.0, 576ee5dfd459; multi-instance
//! since 7.3, e435696d5759).
//!
//! The true root of every mount tree: the namespace root is a nullfs
//! mount and the mutable rootfs is mounted on it ([`crate::ns`]), so
//! pivot_root and unmounting work from the initramfs. Kernel threads
//! start in a private instance of their own (Linux knullfs). Each mount
//! is a new instance. Not registered: mount(2) cannot name it (Linux
//! SB_NOUSER).
//!
//! One inode, a directory with no entries that nothing can change
//! (Linux make_empty_dir_inode plus S_IMMUTABLE): lookups find nothing,
//! creating or changing anything is EPERM.

use alloc::sync::Arc;

use super::KernelError;
use super::dac::MAY_WRITE;
use super::dentry::Dentry;
use super::file::{DirContext, DirEntry, File, FileOps, RwFlags};
use super::inode::{FileType, Inode, InodeMode, InodeOps};
use super::iov_iter::{IovDest, IovSource};
use super::superblock::{FileSystemType, StatFs, SuperBlock, SuperOps};
use crate::task::Cred;
use crate::util::kalloc::try_arc;

/// statfs f_type (Linux NULL_FS_MAGIC, "NULL")
pub const NULL_FS_MAGIC: u64 = 0x4E55_4C4C;

struct NullfsSuperOps;

impl SuperOps for NullfsSuperOps {
    fn alloc_inode(
        &self,
        _sb: &Arc<SuperBlock>,
        _mode: InodeMode,
        _i_op: &'static dyn InodeOps,
    ) -> Result<Arc<Inode>, KernelError> {
        Err(KernelError::NotPermitted)
    }

    /// Linux simple_statfs
    fn statfs(&self) -> StatFs {
        StatFs {
            f_type: NULL_FS_MAGIC,
            f_bsize: 4096,
            f_namelen: 255,
            ..StatFs::default()
        }
    }
}

static NULLFS_SUPER_OPS: NullfsSuperOps = NullfsSuperOps;

struct NullfsInodeOps;

impl InodeOps for NullfsInodeOps {
    /// Empty: every name is negative
    fn lookup(&self, _dir: &Inode, _name: &[u8]) -> Result<Arc<Inode>, KernelError> {
        Err(KernelError::NotFound)
    }

    /// S_IMMUTABLE: no write access (Linux inode_permission: EPERM)
    fn permission(&self, inode: &Inode, cred: &Cred, mask: u32) -> Result<(), KernelError> {
        if mask & MAY_WRITE != 0 {
            return Err(KernelError::NotPermitted);
        }
        super::dac::generic_permission(cred, inode, mask)
    }

    /// S_IMMUTABLE: no chmod, chown or utimes, so no atime either
    fn setattr_ok(&self, _inode: &Inode) -> Result<(), KernelError> {
        Err(KernelError::NotPermitted)
    }
}

static NULLFS_INODE_OPS: NullfsInodeOps = NullfsInodeOps;

struct NullfsFileOps;

impl FileOps for NullfsFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    /// No poll (Linux nullfs_dir_operations)
    fn can_poll(&self, _file: &File) -> bool {
        false
    }

    /// A directory (Linux generic_read_dir)
    fn read_iter(
        &self,
        _file: &File,
        _to: &mut IovDest<'_>,
        _at: Option<u64>,
        _flags: RwFlags,
    ) -> Result<usize, KernelError> {
        Err(KernelError::IsDirectory)
    }

    /// No write op
    fn write_iter(
        &self,
        _file: &File,
        _from: &mut IovSource<'_>,
        _at: Option<u64>,
        _flags: RwFlags,
    ) -> Result<usize, KernelError> {
        Err(KernelError::OperationNotSupported)
    }

    /// "." and ".." only, both the root (Linux empty_dir_readdir)
    fn readdir(&self, file: &File, ctx: &mut DirContext<'_>) -> Result<(), KernelError> {
        let ino = file.get_inode().map_or(1, |i| i.ino);
        for (at, name) in [(0, &b"."[..]), (1, b"..")] {
            let e = DirEntry {
                ino,
                file_type: FileType::Directory,
                name: name.to_vec(),
            };
            if !ctx.emit_at(at, e) {
                break;
            }
        }
        Ok(())
    }
}

static NULLFS_FILE_OPS: NullfsFileOps = NullfsFileOps;

/// A new instance (Linux nullfs_fs_fill_super): the root is inode 1,
/// mode 0555, owned by root
fn mount(fs_type: &'static FileSystemType, _opts: &[u8]) -> Result<Arc<SuperBlock>, KernelError> {
    let sb = SuperBlock::new(fs_type, &NULLFS_SUPER_OPS, 0)?;
    let root = try_arc(Inode::new(
        1,
        InodeMode::directory(0o555),
        0,
        0,
        0,
        crate::time::TIMEKEEPER.current_time(),
        Arc::downgrade(&sb),
        &NULLFS_INODE_OPS,
    ))?;
    sb.set_root(try_arc(Dentry::new_root(root, Arc::downgrade(&sb)))?);
    Ok(sb)
}

/// The nullfs filesystem type; mounted only by the kernel
pub static NULLFS_TYPE: FileSystemType = FileSystemType {
    name: "nullfs",
    fs_flags: super::superblock::fs_flags::FS_PSEUDO,
    mount,
    mount_dev: None,
    file_ops: &NULLFS_FILE_OPS,
};
