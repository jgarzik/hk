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

use spin::Once;

use crate::fs::chardev::DevId;

use crate::fs::KernelError;
use crate::fs::dentry::DentryRef;
use crate::fs::superblock::FileSystemType;

/// The kernel's mount of the internal superblock (Linux devtmpfs.c
/// mnt)
static DEVTMPFS: Once<crate::fs::mount::MountRef> = Once::new();

fn root() -> Option<DentryRef> {
    Some(DEVTMPFS.get()?.root.clone())
}

/// The internal type (Linux internal_fs_type: tmpfs's mount under the
/// name devtmpfs, not registered)
static INTERNAL_TYPE: FileSystemType = FileSystemType {
    name: "devtmpfs",
    fs_flags: 0,
    mount: crate::fs::ramfs::tmpfs::tmpfs_mount,
    kill_sb: crate::fs::superblock::kill_anon_super,
    file_ops: &super::TMPFS_FILE_OPS,
    next: crate::fs::superblock::FsNext::new(None),
    fs_supers: crate::fs::superblock::FsSupers::new(crate::util::list::WeakList::new()),
};

/// A mount: the one internal superblock, another active reference with
/// s_umount held (Linux devtmpfs_get_tree); the options are parsed (a
/// bad one fails the mount) but change nothing on the shared
/// superblock, as Linux 6.15+
fn mount(
    fc: &crate::fs::superblock::FsContext<'_>,
) -> Result<crate::fs::superblock::SbLocked, KernelError> {
    crate::fs::ramfs::tmpfs::check_opts(fc.data)?;
    let m = DEVTMPFS.get().ok_or(KernelError::NoDevice)?;
    Ok((*m.sb).clone().lock())
}

/// The devtmpfs filesystem type
pub static DEVTMPFS_TYPE: FileSystemType = FileSystemType {
    name: "devtmpfs",
    fs_flags: 0,
    mount,
    kill_sb: crate::fs::superblock::kill_anon_super,
    file_ops: &super::TMPFS_FILE_OPS,
    next: crate::fs::superblock::FsNext::new(None),
    fs_supers: crate::fs::superblock::FsSupers::new(crate::util::list::WeakList::new()),
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
    // Its dentry, as Linux handle_remove's lookup gives it to vfs_unlink
    let none = crate::fs::dentry::LookupBits::empty();
    let Ok(d) = crate::fs::lookup_one(&r, name.as_bytes(), none) else {
        return;
    };
    if dir.i_op.unlink(&dir, name.as_bytes(), &d).is_ok() {
        r.remove_child(name.as_bytes());
    }
}

/// Mount the internal superblock (Linux devtmpfs_init, in driver_init:
/// vfs_kern_mount of the internal type)
pub fn init() {
    let fc = crate::fs::superblock::FsContext::new(&INTERNAL_TYPE, b"mode=0755");
    let m = crate::fs::superblock::vfs_get_tree(&fc).and_then(|sb| {
        let sb = sb.unlock();
        let root = sb.get_root().ok_or(KernelError::Io)?;
        crate::fs::mount::Mount::alloc(sb, root, 0, b"devtmpfs".as_slice().into())
    });
    match m {
        Ok(m) => {
            // A kernel mount (Linux vfs_kern_mount)
            m.set_internal();
            DEVTMPFS.call_once(|| m);
        }
        Err(e) => {
            crate::printkln!("devtmpfs: {:?}", e);
            return;
        }
    }
    crate::fs::superblock::register_filesystem(&DEVTMPFS_TYPE).expect("devtmpfs type");
}
