//! sysfs: the kernfs tree mounted at /sys (Linux fs/sysfs)
//!
//! One tree; each network namespace's mounts share one superblock, which
//! shows the nodes tagged with that namespace (net devices) besides the
//! untagged ones (Linux sysfs_get_tree: kobj_ns_grab_current(NET)).
//! Subsystems hang their directories off `root()` as they initialize.

use alloc::sync::Arc;

use spin::Once;

use crate::fs::KernelError;
use crate::fs::dentry::Dentry;
use crate::fs::inode::{InodeMode, InodeOps, InodeRef};
use crate::fs::kernfs::{self, KNode};
use crate::fs::superblock::{FileSystemType, StatFs, SuperBlock, SuperOps, fs_flags};
use crate::util::kalloc::try_arc;

/// Linux SYSFS_MAGIC
pub const SYSFS_MAGIC: u64 = 0x6265_6572;

static ROOT: Once<Arc<KNode>> = Once::new();

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
    ) -> Result<InodeRef, KernelError> {
        Err(KernelError::OperationNotSupported)
    }

    fn statfs(&self, _sb: &SuperBlock) -> Result<StatFs, KernelError> {
        Ok({
            StatFs {
                f_type: SYSFS_MAGIC,
                f_bsize: 4096,
                f_namelen: 255,
                ..StatFs::default()
            }
        })
    }
}

static SYSFS_SOPS: SysfsSops = SysfsSops;

/// The network namespace a sysfs superblock shows (Linux
/// kernfs_test_super's info->ns)
fn sb_ns(sb: &SuperBlock) -> Option<u64> {
    sb.fs_info_as::<kernfs::vfs::KfSuper>().map(|k| k.ns)
}

/// The namespace's superblock, shared by its mounts (Linux
/// kernfs_get_tree: sget_fc with kernfs_test_super and
/// kernfs_set_super, then kernfs_fill_super if new)
fn mount(
    fc: &crate::fs::superblock::FsContext<'_>,
) -> Result<crate::fs::superblock::SbLocked, KernelError> {
    let ns = crate::net::current_net_ns().id;
    let info: Arc<dyn crate::fs::superblock::SuperBlockData> =
        try_arc(kernfs::vfs::KfSuper { ns })?;
    let sb =
        crate::fs::superblock::sget(fc, &SYSFS_SOPS, Some(&|sb| sb_ns(sb) == Some(ns)), &|sb| {
            // Linux kernfs_set_super
            sb.set_fs_info(info.clone());
            crate::fs::superblock::set_anon_super(sb)
        })?;
    if !sb.has_root() {
        // Linux kernfs_fill_super: sb->s_d_op = &kernfs_dops
        sb.set_d_op(&kernfs::vfs::KERNFS_DOPS);
        let ri = kernfs::vfs::inode(&sb, root())?;
        sb.set_root(crate::fs::DentryRef::new(Dentry::new_root(
            ri,
            Arc::downgrade(&sb),
        ))?);
        sb.set_active();
    }
    Ok(sb)
}

/// sysfs's kill_sb (Linux sysfs_kill_sb -> kernfs_kill_sb:
/// kill_anon_super; the kernfs info goes with the superblock's memory)
fn sysfs_kill_sb(sb: &SuperBlock, g: crate::fs::superblock::SbUmount<'_>) {
    crate::fs::superblock::kill_anon_super(sb, g);
}

pub static SYSFS_TYPE: FileSystemType = FileSystemType {
    name: "sysfs",
    fs_flags: fs_flags::FS_PSEUDO | fs_flags::FS_USERNS_MOUNT_RESTRICTED,
    mount,
    kill_sb: sysfs_kill_sb,
    file_ops: &kernfs::vfs::KERNFS_FOPS,
    next: crate::fs::superblock::FsNext::new(None),
    fs_supers: crate::fs::superblock::FsSupers::new(crate::util::list::WeakList::new()),
};

/// Linux sysfs_init + mnt_init's fs_kobj: the root, /sys/fs, the type;
/// /sys/fs/cgroup as cgroup_init makes it
pub fn init() {
    let fs = top_dir(b"fs");
    mount_point(&fs, b"cgroup");
    crate::fs::superblock::register_filesystem(&SYSFS_TYPE).expect("sysfs type");
}

/// A permanently empty directory something else mounts on (Linux
/// sysfs_create_mount_point)
pub fn mount_point(parent: &Arc<KNode>, name: &[u8]) {
    let _ = parent.create_empty_dir(name);
}
