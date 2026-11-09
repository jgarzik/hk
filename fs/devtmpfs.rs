//! devtmpfs-lite: device nodes created by the kernel as devices register
//!
//! Linux reference: drivers/base/devtmpfs.c.
//!
//! One internal tmpfs superblock (mode=0755, tmpfs's default limits;
//! Linux internal_fs_type with CONFIG_TMPFS) holds a node for every
//! device passed to [`device_add`]; each mount of "devtmpfs" shows that
//! same superblock, and its options (tmpfs's) are applied to it as a
//! remount's would be (Linux public_dev_mount, reconfigure_single, as in
//! the 6.8 reference and Debian's 6.12; 6.15 parses and drops them). A
//! remount reconfigures it likewise. [`init`] runs in driver_init,
//! before any device registers.
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

use super::KernelError;
use super::dentry::Dentry;
use super::superblock::{FileSystemType, SuperBlock};

/// The internal superblock
static DEVTMPFS: Once<Arc<SuperBlock>> = Once::new();

fn root() -> Option<Arc<Dentry>> {
    DEVTMPFS.get()?.get_root()
}

/// A mount: the one superblock, reconfigured with `opts` under its
/// s_umount (a bad option or a refused limit fails the mount, nothing
/// changed)
fn mount(_t: &'static FileSystemType, opts: &[u8]) -> Result<Arc<SuperBlock>, KernelError> {
    let sb = DEVTMPFS.get().cloned().ok_or(KernelError::NoDevice)?;
    let s = sb.s_umount.write();
    sb.s_op.remount(&sb, opts)?;
    drop(s);
    Ok(sb)
}

/// The devtmpfs filesystem type
pub static DEVTMPFS_TYPE: FileSystemType = FileSystemType {
    name: "devtmpfs",
    fs_flags: 0,
    mount,
    mount_dev: None,
    file_ops: &super::ramfs::TMPFS_FILE_OPS,
};

/// Create the node `name` for a device (Linux device_add ->
/// devtmpfs_create_node; nothing before devtmpfs is initialized)
pub fn device_add(name: &str, dev: DevId, blk: bool, mode: u16) {
    let Some(root) = root() else { return };
    let Some(dir) = root.get_inode() else { return };
    let lock = dir.lock();
    let r = if blk {
        super::ramfs::ramfs_create_blkdev(&root, name.as_bytes(), dev, mode)
    } else {
        super::ramfs::ramfs_create_chrdev(&root, name.as_bytes(), dev, mode)
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
    match super::tmpfs::tmpfs_mount(&DEVTMPFS_TYPE, b"mode=0755") {
        Ok(sb) => {
            DEVTMPFS.call_once(|| sb);
        }
        Err(e) => {
            crate::printkln!("devtmpfs: {:?}", e);
            return;
        }
    }
    super::superblock::register_filesystem(&DEVTMPFS_TYPE);
}
