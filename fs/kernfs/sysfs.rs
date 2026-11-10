//! sysfs: the kernfs tree mounted at /sys (Linux fs/sysfs)
//!
//! One tree; each network namespace's mounts share one superblock, which
//! shows the nodes tagged with that namespace (net devices) besides the
//! untagged ones (Linux sysfs_get_tree: kobj_ns_grab_current(NET)).
//! Subsystems hang their directories off `root()` as they initialize.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use spin::Once;

use crate::fs::KernelError;
use crate::fs::dentry::Dentry;
use crate::fs::inode::{Inode, InodeMode, InodeOps};
use crate::fs::kernfs::{self, KNode};
use crate::fs::superblock::{FileSystemType, StatFs, SuperBlock, SuperOps, fs_flags};
use crate::sync::spin::Mutex;
use crate::util::kalloc::try_arc;

/// Linux SYSFS_MAGIC
pub const SYSFS_MAGIC: u64 = 0x6265_6572;

static ROOT: Once<Arc<KNode>> = Once::new();
/// Superblock of each network namespace's mounts, by namespace id
/// (spin leaf)
static SBS: Mutex<Vec<(u64, Weak<SuperBlock>)>> = Mutex::new(Vec::new());

/// The root of /sys
pub fn root() -> &'static Arc<KNode> {
    ROOT.call_once(KNode::new_root)
}

/// Top-level directory `name`, made on first use (Linux
/// kobject_create_and_add(name, NULL))
pub fn top_dir(name: &[u8]) -> Arc<KNode> {
    let r = root();
    match r.create_dir(name, 0o755) {
        Ok(d) => d,
        Err(_) => r.find(name).expect("sysfs top-level directory"),
    }
}

struct SysfsSops;

impl SuperOps for SysfsSops {
    fn alloc_inode(
        &self,
        _sb: &Arc<SuperBlock>,
        _mode: InodeMode,
        _i_op: &'static dyn InodeOps,
    ) -> Result<Arc<Inode>, KernelError> {
        Err(KernelError::OperationNotSupported)
    }

    fn statfs(&self, _sb: &SuperBlock) -> StatFs {
        StatFs {
            f_type: SYSFS_MAGIC,
            f_bsize: 4096,
            f_namelen: 255,
            ..StatFs::default()
        }
    }
}

static SYSFS_SOPS: SysfsSops = SysfsSops;

fn mount(t: &'static FileSystemType, _opts: &[u8]) -> Result<Arc<SuperBlock>, KernelError> {
    let ns = crate::net::current_net_ns().id;
    let mut sbs = SBS.lock();
    sbs.retain(|(_, w)| w.strong_count() > 0);
    if let Some(sb) = sbs
        .iter()
        .find(|(n, _)| *n == ns)
        .and_then(|(_, w)| w.upgrade())
    {
        return Ok(sb);
    }
    let sb = SuperBlock::new(t, &SYSFS_SOPS, 0)?;
    sb.set_private(try_arc(kernfs::vfs::KfSuper { ns })?);
    let ri = kernfs::vfs::inode(&sb, root())?;
    sb.set_root(try_arc(Dentry::new_root(ri, Arc::downgrade(&sb)))?);
    sbs.push((ns, Arc::downgrade(&sb)));
    Ok(sb)
}

pub static SYSFS_TYPE: FileSystemType = FileSystemType {
    name: "sysfs",
    fs_flags: fs_flags::FS_PSEUDO,
    mount,
    mount_dev: None,
    file_ops: &kernfs::vfs::KERNFS_FOPS,
};

/// Linux sysfs_init + mnt_init's fs_kobj: the root, /sys/fs, the type;
/// /sys/fs/cgroup as cgroup_init makes it
pub fn init() {
    let fs = top_dir(b"fs");
    mount_point(&fs, b"cgroup");
    crate::fs::superblock::register_filesystem(&SYSFS_TYPE);
}

/// An empty directory something else mounts on (Linux
/// sysfs_create_mount_point)
pub fn mount_point(parent: &Arc<KNode>, name: &[u8]) {
    let _ = parent.create_dir(name, 0o755);
}
