//! devtmpfs-lite: device nodes created by the kernel as devices register
//!
//! Linux reference: drivers/base/devtmpfs.c.
//!
//! One internal ramfs superblock holds a node for every device passed to
//! [`device_add`]; each mount of "devtmpfs" shows that same superblock
//! (Linux mount_single). Devices added before the VFS is up (bus
//! enumeration runs first) are queued and created by [`init`].
//!
//! ## Locking
//!
//! `PENDING` (spin `Mutex`, leaf) holds the early queue. Nodes are made
//! and removed under the devtmpfs root's `i_rwsem`, like any directory
//! operation. Linux hands node updates to the devtmpfsd thread; here they
//! run in the caller (device probe, partition rescan under the disk's
//! `open_mutex`): no path holding a directory `i_rwsem` ever takes
//! `open_mutex` (a block device is opened after the walk), so the order
//! `open_mutex -> i_rwsem` cannot invert (doc/LOCKING.md 3.10).

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use spin::Once;

use crate::chardev::DevId;
use crate::sync::spin::Mutex;

use super::KernelError;
use super::dentry::Dentry;
use super::superblock::{FileSystemType, SuperBlock};

/// The internal superblock
static DEVTMPFS: Once<Arc<SuperBlock>> = Once::new();

/// A node to create once devtmpfs exists
struct Node {
    name: String,
    dev: DevId,
    blk: bool,
    mode: u16,
}

static PENDING: Mutex<Vec<Node>> = Mutex::new(Vec::new());

fn root() -> Option<Arc<Dentry>> {
    DEVTMPFS.get()?.get_root()
}

fn mount(_t: &'static FileSystemType) -> Result<Arc<SuperBlock>, KernelError> {
    DEVTMPFS.get().cloned().ok_or(KernelError::NoDevice)
}

/// The devtmpfs filesystem type
pub static DEVTMPFS_TYPE: FileSystemType = FileSystemType {
    name: "devtmpfs",
    fs_flags: 0,
    mount,
    mount_dev: None,
    file_ops: &super::ramfs::RAMFS_FILE_OPS,
};

fn create(root: &Arc<Dentry>, n: &Node) {
    let Some(dir) = root.get_inode() else { return };
    dir.inode_lock();
    let r = if n.blk {
        super::ramfs::ramfs_create_blkdev(root, &n.name, n.dev, n.mode)
    } else {
        super::ramfs::ramfs_create_chrdev(root, &n.name, n.dev, n.mode)
    };
    unsafe { dir.inode_unlock() };
    if let Err(e) = r {
        crate::printkln!("devtmpfs: {}: {:?}", n.name, e);
    }
}

/// Create the node `name` for a device (Linux device_add ->
/// devtmpfs_create_node); queued until devtmpfs is initialized
pub fn device_add(name: &str, dev: DevId, blk: bool, mode: u16) {
    let n = Node {
        name: String::from(name),
        dev,
        blk,
        mode,
    };
    // Checked under PENDING: `init` publishes the root under it too
    let mut p = PENDING.lock();
    let Some(r) = root() else {
        p.push(n);
        return;
    };
    drop(p);
    create(&r, &n);
}

/// Remove the node `name` (Linux device_del -> devtmpfs_delete_node)
pub fn device_del(name: &str) {
    PENDING.lock().retain(|n| n.name != name);
    let Some(r) = root() else { return };
    let Some(dir) = r.get_inode() else { return };
    dir.inode_lock();
    if dir.i_op.unlink(&dir, name).is_ok() {
        r.remove_child(name);
    }
    unsafe { dir.inode_unlock() };
}

/// Create the superblock and the nodes queued so far (VFS init)
pub fn init() {
    let sb = match super::ramfs::ramfs_mount(&DEVTMPFS_TYPE) {
        Ok(sb) => sb,
        Err(e) => {
            crate::printkln!("devtmpfs: {:?}", e);
            return;
        }
    };
    let pending = {
        let mut p = PENDING.lock();
        DEVTMPFS.call_once(|| sb);
        core::mem::take(&mut *p)
    };
    super::superblock::register_filesystem(&DEVTMPFS_TYPE);
    let Some(r) = root() else { return };
    for n in &pending {
        create(&r, n);
    }
}
