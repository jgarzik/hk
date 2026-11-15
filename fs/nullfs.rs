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
//! creating or changing anything is EPERM. The kernel's private
//! instance also has an empty regular file outside its tree
//! ([`new_file`], Linux nullfs_new_file): reads find nothing, writes
//! are taken and dropped, its mode and owner never change. It stands
//! in for a locked file mount an umount left covered (Linux
//! knullfs_file).

use alloc::sync::Arc;

use super::KernelError;
use super::dac::MAY_WRITE;
use super::dentry::Dentry;
use super::file::{DirContext, DirEntry, File, FileOps, RwFlags};
use super::inode::{FileType, Inode, InodeMode, InodeOps};
use super::iov_iter::{IovDest, IovSource};
use super::superblock::{FileSystemType, StatFs, SuperBlock, SuperOps};
use crate::task::Cred;

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
    fn statfs(&self, _sb: &SuperBlock) -> Result<StatFs, KernelError> {
        Ok({
            StatFs {
                f_type: NULL_FS_MAGIC,
                f_bsize: 4096,
                f_namelen: 255,
                ..StatFs::default()
            }
        })
    }
}

static NULLFS_SUPER_OPS: NullfsSuperOps = NullfsSuperOps;

struct NullfsInodeOps;

impl InodeOps for NullfsInodeOps {
    /// Empty: every name is negative
    fn lookup(&self, _dir: &Inode, _name: &[u8]) -> Result<Arc<Inode>, KernelError> {
        Err(KernelError::NotFound)
    }

    fn is_empty_dir(&self, _inode: &Inode) -> bool {
        true
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

    /// A directory (Linux generic_read_dir); the file is empty (Linux
    /// nullfs_file_read_iter)
    fn read_iter(
        &self,
        file: &File,
        _to: &mut IovDest<'_>,
        _at: Option<u64>,
        _flags: RwFlags,
    ) -> Result<usize, KernelError> {
        if is_file(file) {
            return Ok(0);
        }
        Err(KernelError::IsDirectory)
    }

    /// No write op for the directory; the file takes everything and
    /// keeps nothing (Linux nullfs_file_write_iter)
    fn write_iter(
        &self,
        file: &File,
        from: &mut IovSource<'_>,
        _at: Option<u64>,
        _flags: RwFlags,
    ) -> Result<usize, KernelError> {
        if is_file(file) {
            return Ok(from.len());
        }
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

/// `file` is the regular file of [`new_file`], not the directory
fn is_file(file: &File) -> bool {
    file.get_inode().is_some_and(|i| !i.mode().is_dir())
}

/// The file's inode operations (Linux nullfs_file_inode_operations):
/// its mode and owner never change, its times may
struct NullfsFileInodeOps;

impl InodeOps for NullfsFileInodeOps {
    fn lookup(&self, _dir: &Inode, _name: &[u8]) -> Result<Arc<Inode>, KernelError> {
        Err(KernelError::NotDirectory)
    }

    /// Linux nullfs_file_setattr: ATTR_MODE is EPERM
    fn chmod_ok(&self, _inode: &Inode, _perm: u16) -> Result<(), KernelError> {
        Err(KernelError::NotPermitted)
    }

    /// Linux nullfs_file_setattr: ATTR_UID / ATTR_GID are EPERM
    fn chown_ok(&self, _inode: &Inode) -> Result<(), KernelError> {
        Err(KernelError::NotPermitted)
    }
}

static NULLFS_FILE_INODE_OPS: NullfsFileInodeOps = NullfsFileInodeOps;

/// An empty regular file on the nullfs `sb` (inode 2, mode 0666), a
/// dentry of its own that no lookup finds (Linux nullfs_new_file)
pub fn new_file(sb: &Arc<SuperBlock>) -> Result<crate::fs::DentryRef, KernelError> {
    let inode = Inode::alloc(Inode::new(
        2,
        InodeMode::regular(0o666),
        0,
        0,
        0,
        crate::time::TIMEKEEPER.current_time(),
        Arc::downgrade(sb),
        &NULLFS_FILE_INODE_OPS,
    ))?;
    crate::fs::DentryRef::new(Dentry::new_root(inode, Arc::downgrade(sb)))
}

/// A new instance (Linux nullfs_fs_fill_super): the root is inode 1,
/// mode 0555, owned by root
fn mount(
    fc: &crate::fs::superblock::FsContext<'_>,
) -> Result<crate::fs::superblock::SbLocked, KernelError> {
    crate::fs::superblock::get_tree_nodev(fc, &NULLFS_SUPER_OPS, fill)
}

/// Linux nullfs_fs_fill_super
fn fill(sb: &Arc<SuperBlock>) -> Result<(), KernelError> {
    let root = Inode::alloc(Inode::new(
        1,
        InodeMode::directory(0o555),
        0,
        0,
        0,
        crate::time::TIMEKEEPER.current_time(),
        Arc::downgrade(sb),
        &NULLFS_INODE_OPS,
    ))?;
    sb.set_root(crate::fs::DentryRef::new(Dentry::new_root(
        root,
        Arc::downgrade(sb),
    ))?);
    Ok(())
}

/// The nullfs filesystem type; mounted only by the kernel
pub static NULLFS_TYPE: FileSystemType = FileSystemType {
    name: "nullfs",
    fs_flags: super::superblock::fs_flags::FS_PSEUDO,
    mount,
    kill_sb: crate::fs::superblock::kill_anon_super,
    file_ops: &NULLFS_FILE_OPS,
    next: crate::fs::superblock::FsNext::new(None),
    fs_supers: crate::fs::superblock::FsSupers::new(crate::util::list::WeakList::new()),
};
