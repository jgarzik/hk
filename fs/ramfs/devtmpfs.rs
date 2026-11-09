//! devtmpfs-lite: device nodes created by the kernel as devices register
//!
//! Linux reference: drivers/base/devtmpfs.c.
//!
//! One internal tmpfs superblock (mode=0755, tmpfs's default limits;
//! Linux internal_fs_type with CONFIG_TMPFS) holds a node for every
//! device passed to [`device_add`]; each mount of "devtmpfs" shows that
//! same superblock (Linux devtmpfs_get_tree): its options are tmpfs's,
//! parsed (EINVAL) and dropped (Linux 6.15+; before, reconfigure_single
//! applied them). A remount reconfigures the superblock (tmpfs's
//! reconfigure). [`init`] runs in driver_init, before any device
//! registers.
//!
//! ## Locking
//!
//! Nodes are made and removed under the devtmpfs root's `i_rwsem`, like any directory
//! operation. Linux hands node updates to the devtmpfsd thread; here they
//! run in the caller (device probe, partition rescan under the disk's
//! `open_mutex`): no path holding a directory `i_rwsem` ever takes
//! `open_mutex` (a block device is opened after the walk), so the order
//! `open_mutex -> i_rwsem` cannot invert (doc/LOCKING.md 3.10).

use alloc::sync::Arc;

use spin::Once;

use crate::fs::chardev::DevId;

use crate::fs::KernelError;
use crate::fs::dentry::Dentry;
use crate::fs::superblock::{FileSystemType, SuperBlock};

/// The internal superblock
static DEVTMPFS: Once<Arc<SuperBlock>> = Once::new();

fn root() -> Option<Arc<Dentry>> {
    DEVTMPFS.get()?.get_root()
}

/// A mount: the one superblock; `opts` only parsed (a bad option fails
/// the mount)
fn mount(_t: &'static FileSystemType, opts: &[u8]) -> Result<Arc<SuperBlock>, KernelError> {
    crate::fs::tmpfs::check_opts(opts)?;
    DEVTMPFS.get().cloned().ok_or(KernelError::NoDevice)
}

/// The devtmpfs filesystem type
pub static DEVTMPFS_TYPE: FileSystemType = FileSystemType {
    name: "devtmpfs",
    fs_flags: 0,
    mount,
    mount_dev: None,
    file_ops: &super::TMPFS_FILE_OPS,
};

/// Create the node `name` for a device (Linux device_add ->
/// devtmpfs_create_node; nothing before devtmpfs is initialized)
pub fn device_add(name: &str, dev: DevId, blk: bool, mode: u16) {
    let Some(root) = root() else { return };
    let Some(dir) = root.get_inode() else { return };
    let lock = dir.lock();
    let r = if blk {
        super::ramfs_create_blkdev(&root, name.as_bytes(), dev, mode)
    } else {
        super::ramfs_create_chrdev(&root, name.as_bytes(), dev, mode)
    };
    drop(lock);
    if let Err(e) = r {
        crate::printkln!("devtmpfs: {}: {:?}", name, e);
    }
}

/// Remove the node `name` (Linux device_del -> devtmpfs_delete_node)
pub fn device_del(name: &str) {
    let Some(r) = root() else { return };
    let Some(dir) = r.get_inode() else { return };
    let _lock = dir.lock();
    if dir.i_op.unlink(&dir, name.as_bytes()).is_ok() {
        r.remove_child(name.as_bytes());
    }
}

/// Create the superblock (Linux devtmpfs_init, in driver_init)
pub fn init() {
    match crate::fs::tmpfs::tmpfs_mount(&DEVTMPFS_TYPE, b"mode=0755") {
        Ok(sb) => {
            DEVTMPFS.call_once(|| sb);
        }
        Err(e) => {
            crate::printkln!("devtmpfs: {:?}", e);
            return;
        }
    }
    crate::fs::superblock::register_filesystem(&DEVTMPFS_TYPE);
}
