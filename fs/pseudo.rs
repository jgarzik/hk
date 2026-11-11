//! Pseudo filesystems (Linux init_pseudo + kern_mount): pipefs, sockfs,
//! anon_inodefs and nsfs
//!
//! Each is one internal superblock and mount, in no mount namespace
//! (mount(2) cannot name them, Linux SB_NOUSER), made at boot in Linux's
//! order (nsfs in start_kernel, sockfs a core initcall, pipefs and
//! anon_inodefs fs initcalls). A pipe, socket, anonymous-inode or
//! namespace file's path is that mount and a dentry outside any tree
//! (Linux d_alloc_pseudo), so a /proc/<pid>/fd link jumps to it and an
//! open of it goes by its inode's rules: a pipe joins the pipe (Linux
//! fifo_open on i_pipe), a socket or anonymous inode is ENXIO (Linux
//! sock_no_open, no_open_fops). /proc shows each by its fs's name for it
//! ([`dname`], Linux d_dname).

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::KernelError;
use super::dentry::Dentry;
use super::file::{File, FileOps};
use super::inode::{Inode, InodeMode, NULL_INODE_OPS};
use super::mount::{MNT_NODEV, MNT_NOEXEC, Mount};
use super::path_ref::Path;
use super::superblock::{FileSystemType, StatFs, SuperBlock, SuperOps, fs_flags};
use crate::util::kalloc::try_arc;

/// statfs f_type of each (Linux include/uapi/linux/magic.h)
const PIPEFS_MAGIC: u64 = 0x5049_5045;
const SOCKFS_MAGIC: u64 = 0x534F_434B;
const ANON_INODE_FS_MAGIC: u64 = 0x0904_1934;
const NSFS_MAGIC: u64 = 0x6e73_6673;

/// One pseudo filesystem: its type, statfs magic and kernel mount
pub struct Pseudo {
    ty: FileSystemType,
    ops: PseudoSuperOps,
    mnt: spin::Once<Arc<Mount>>,
}

struct PseudoSuperOps {
    magic: u64,
}

impl SuperOps for PseudoSuperOps {
    fn alloc_inode(
        &self,
        _sb: &Arc<SuperBlock>,
        _mode: InodeMode,
        _i_op: &'static dyn super::inode::InodeOps,
    ) -> Result<Arc<Inode>, KernelError> {
        Err(KernelError::NotPermitted)
    }

    /// Linux simple_statfs
    fn statfs(&self, _sb: &SuperBlock) -> StatFs {
        StatFs {
            f_type: self.magic,
            f_bsize: 4096,
            f_namelen: 255,
            ..StatFs::default()
        }
    }
}

/// The file operations an open of a pseudo inode without its own gets
/// (Linux no_open_fops): ENXIO
struct NoOpen;

impl FileOps for NoOpen {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn open(&self, _file: &File) -> Result<(), KernelError> {
        Err(KernelError::NoDeviceOrAddress)
    }
}

static NO_OPEN: NoOpen = NoOpen;

/// A namespace file's operations (Linux ns_file_operations): it opens,
/// and has no read or write (EINVAL)
struct NsFileOps;

impl FileOps for NsFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

static NS_FILE_OPS: NsFileOps = NsFileOps;

const fn pseudo(name: &'static str, magic: u64, file_ops: &'static dyn FileOps) -> Pseudo {
    Pseudo {
        ty: FileSystemType {
            name,
            fs_flags: fs_flags::FS_PSEUDO,
            mount: pseudo_mount,
            mount_dev: None,
            file_ops,
        },
        ops: PseudoSuperOps { magic },
        mnt: spin::Once::new(),
    }
}

pub static PIPEFS: Pseudo = pseudo("pipefs", PIPEFS_MAGIC, &NO_OPEN);
pub static SOCKFS: Pseudo = pseudo("sockfs", SOCKFS_MAGIC, &NO_OPEN);
pub static ANON_INODEFS: Pseudo = pseudo("anon_inodefs", ANON_INODE_FS_MAGIC, &NO_OPEN);
pub static NSFS: Pseudo = pseudo("nsfs", NSFS_MAGIC, &NS_FILE_OPS);

const ALL: [&Pseudo; 4] = [&PIPEFS, &SOCKFS, &ANON_INODEFS, &NSFS];

/// The pseudo filesystem of type `ty`
fn of_type(ty: &FileSystemType) -> Option<&'static Pseudo> {
    ALL.into_iter().find(|p| core::ptr::eq(&raw const p.ty, ty))
}

/// A superblock with its root, a directory only the kernel uses (Linux
/// init_pseudo: S_IFDIR | 0600, inode 1)
fn pseudo_mount(ty: &'static FileSystemType, _opts: &[u8]) -> Result<Arc<SuperBlock>, KernelError> {
    let p = of_type(ty).ok_or(KernelError::InvalidArgument)?;
    let sb = SuperBlock::new(ty, &p.ops, 0)?;
    let root = try_arc(Inode::new(
        1,
        InodeMode::directory(0o600),
        0,
        0,
        0,
        crate::time::TIMEKEEPER.current_time(),
        Arc::downgrade(&sb),
        &NULL_INODE_OPS,
    ))?;
    sb.set_root(try_arc(Dentry::new_root(root, Arc::downgrade(&sb)))?);
    Ok(sb)
}

impl Pseudo {
    /// Mount it for the kernel (Linux kern_mount: SB_I_NOEXEC and
    /// SB_I_NODEV as mount flags)
    pub fn init(&'static self) -> Result<(), KernelError> {
        let sb = (self.ty.mount)(&self.ty, b"")?;
        let root = sb.get_root().ok_or(KernelError::Io)?;
        let name = self.ty.name.as_bytes().into();
        let m = Mount::new(sb, root, MNT_NOEXEC | MNT_NODEV, name)?;
        self.mnt.call_once(|| m);
        Ok(())
    }

    /// Its mount (ENODEV before boot made it)
    pub fn mnt(&self) -> Result<Arc<Mount>, KernelError> {
        self.mnt.get().cloned().ok_or(KernelError::NoDevice)
    }

    /// Its superblock, for the inodes made on it
    pub fn sb(&self) -> Result<Arc<SuperBlock>, KernelError> {
        Ok(self.mnt()?.sb.clone())
    }

    /// A dentry `name` for `inode` outside any tree (Linux
    /// d_alloc_pseudo) and its path
    pub fn path(&self, name: &str, inode: Arc<Inode>) -> Result<Path, KernelError> {
        let mnt = self.mnt()?;
        let d = Dentry::new_pseudo(name.as_bytes(), inode, &mnt.sb)?;
        Ok(Path::new(mnt, try_arc(d)?))
    }
}

/// What /proc/<pid>/fd shows for a file on a pseudo filesystem (Linux
/// d_dname: pipefs_dname, sockfs_dname, anon_inodefs_dname, nsfs's
/// ns_dname); None for any other
pub fn dname(dentry: &Dentry) -> Option<Vec<u8>> {
    let sb = dentry.superblock()?;
    let p = of_type(sb.fs_type)?;
    let ino = dentry.get_inode().map_or(0, |i| i.ino);
    Some(match p.ty.name {
        "pipefs" => alloc::format!("pipe:[{ino}]").into_bytes(),
        "sockfs" => alloc::format!("socket:[{ino}]").into_bytes(),
        "anon_inodefs" => [b"anon_inode:".as_slice(), &dentry.name()].concat(),
        _ => dentry.name().to_vec(),
    })
}
