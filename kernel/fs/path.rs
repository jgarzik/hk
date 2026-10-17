//! Path resolution (namei)
//!
//! Resolves path strings to dentries by walking the directory tree. Every
//! directory a name is looked up in needs search (MAY_EXEC) permission
//! for the caller (Linux may_lookup), including for "." and "..".

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::KernelError;
use super::dac::{MAY_EXEC, cred, permission_as};
use super::dentry::Dentry;
use super::inode::Inode;
use super::mount::{current_mnt_ns, follow_mount};
use super::path_ref::Path;
use crate::task::Cred;

/// Maximum number of symlinks to follow (prevent infinite loops)
const MAX_SYMLINK_DEPTH: usize = 40;

/// Path lookup flags
#[derive(Debug, Clone, Copy, Default)]
pub struct LookupFlags {
    /// Follow symlinks in the final component
    pub follow: bool,
    /// The final component must be a directory
    pub directory: bool,
    /// Create the final component if it doesn't exist
    pub create: bool,
    /// Don't cross mount points
    pub no_xdev: bool,
}

impl LookupFlags {
    /// Default flags for open()
    pub fn open() -> Self {
        Self {
            follow: true,
            directory: false,
            create: false,
            no_xdev: false,
        }
    }

    /// Flags for opendir()
    pub fn opendir() -> Self {
        Self {
            follow: true,
            directory: true,
            create: false,
            no_xdev: false,
        }
    }
}

/// Look up an absolute path, or a path relative to the current directory
pub fn lookup_path(path: &str) -> Result<Arc<Dentry>, KernelError> {
    lookup_path_flags(path, LookupFlags::open())
}

/// Look up a path relative to the current directory with specific flags
pub fn lookup_path_flags(path: &str, flags: LookupFlags) -> Result<Arc<Dentry>, KernelError> {
    lookup_path_at(crate::task::percpu::current_cwd(), path, flags)
}

/// Look up a path relative to a starting path
///
/// The core of open() and the *at() syscalls: relative paths start at
/// `start` (root when None), absolute paths at the namespace root.
pub fn lookup_path_at(
    start: Option<Path>,
    path: &str,
    flags: LookupFlags,
) -> Result<Arc<Dentry>, KernelError> {
    walk(&cred(), start, path, flags, 0)
}

/// Child `name` of directory `parent`: the dcache, else the file system
/// (the new dentry is cached). Permission is the caller's business.
pub fn lookup_one(parent: &Arc<Dentry>, name: &str) -> Result<Arc<Dentry>, KernelError> {
    if let Some(child) = parent.lookup_child(name) {
        return Ok(child);
    }
    let dir = parent.get_inode().ok_or(KernelError::NotFound)?;
    let inode = dir.i_op.lookup(&dir, name)?;
    let child = Arc::new(Dentry::new(
        String::from(name),
        Some(inode),
        parent.sb.clone(),
    ));
    child.set_parent(parent);
    parent.add_child(child.clone());
    Ok(child)
}

/// Path-walk lookup (Linux lookup_fast + lookup_slow): a dcache hit
/// needs no lock; a miss asks the file system under the directory's
/// shared inode lock, so it cannot race a create/unlink/rename there
fn lookup_slow(parent: &Arc<Dentry>, name: &str) -> Result<Arc<Dentry>, KernelError> {
    if let Some(child) = parent.lookup_child(name) {
        return Ok(child);
    }
    let dir = parent.get_inode().ok_or(KernelError::NotFound)?;
    dir.inode_lock_shared();
    let r = lookup_one(parent, name);
    // SAFETY: taken above by this thread
    unsafe { dir.inode_unlock_shared() };
    r
}

/// may_lookup: `dir` must be a searchable directory
fn may_lookup(c: &Cred, dir: &Dentry) -> Result<(), KernelError> {
    let inode = dir.get_inode().ok_or(KernelError::NotFound)?;
    if !inode.mode().is_dir() {
        return Err(KernelError::NotDirectory);
    }
    permission_as(c, &inode, MAY_EXEC)
}

fn walk(
    c: &Cred,
    start: Option<Path>,
    path: &str,
    flags: LookupFlags,
    depth: usize,
) -> Result<Arc<Dentry>, KernelError> {
    if depth > MAX_SYMLINK_DEPTH {
        return Err(KernelError::TooManySymlinks);
    }
    let mnt_ns = current_mnt_ns();
    let mut cur = match start {
        Some(p) if !path.starts_with('/') => p.dentry.clone(),
        _ => mnt_ns.get_root_dentry().ok_or(KernelError::NotFound)?,
    };
    let comps: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    for (i, name) in comps.iter().enumerate() {
        may_lookup(c, &cur)?;
        match *name {
            "." => continue,
            ".." => {
                // At the root, ".." stays at the root
                if let Some(parent) = cur.get_parent() {
                    cur = parent;
                }
                continue;
            }
            _ => {}
        }
        let child = lookup_slow(&cur, name)?;
        let child = if flags.no_xdev {
            child
        } else {
            follow_mount(&child)
        };
        let last = i + 1 == comps.len();
        if (!last || flags.follow) && child.get_inode().is_some_and(|n| n.mode().is_symlink()) {
            return follow_link(c, &cur, &child, &comps[i + 1..], flags, depth);
        }
        cur = child;
    }
    if flags.directory && cur.get_inode().is_some_and(|n| !n.mode().is_dir()) {
        return Err(KernelError::NotDirectory);
    }
    Ok(cur)
}

/// Continue a walk through symlink `link` found in `dir`, with the
/// components `rest` still to resolve after it
fn follow_link(
    c: &Cred,
    dir: &Arc<Dentry>,
    link: &Dentry,
    rest: &[&str],
    flags: LookupFlags,
    depth: usize,
) -> Result<Arc<Dentry>, KernelError> {
    let inode = link.get_inode().ok_or(KernelError::NotFound)?;
    let target = inode.i_op.readlink(&inode)?;
    let path = if rest.is_empty() {
        target
    } else {
        alloc::format!("{}/{}", target, rest.join("/"))
    };
    walk(c, Path::from_dentry(dir.clone()), &path, flags, depth + 1)
}

/// Create entry `name` in directory `parent` (Linux filename_create +
/// vfs_mkdir/mknod/symlink/link) under the parent's lock: EEXIST first,
/// then may_create (write+search), then `make` builds the inode with the
/// caller's credentials; the new dentry is cached
pub fn create_entry(
    parent: &Arc<Dentry>,
    name: &str,
    make: impl FnOnce(&Arc<Inode>, &Cred) -> Result<Arc<Inode>, KernelError>,
) -> Result<Arc<Dentry>, KernelError> {
    let dir = parent.get_inode().ok_or(KernelError::NotFound)?;
    if !dir.mode().is_dir() {
        return Err(KernelError::NotDirectory);
    }
    let c = cred();
    // filename_create: write access first, its EROFS reported after EEXIST
    let w = super::dac::want_write(&dir);
    dir.inode_lock();
    let r = (|| {
        if lookup_one(parent, name).is_ok() {
            return Err(KernelError::AlreadyExists);
        }
        let _w = w?;
        super::dac::may_create(&c, &dir)?;
        let inode = make(&dir, &c)?;
        let d = Arc::new(Dentry::new(
            String::from(name),
            Some(inode),
            parent.sb.clone(),
        ));
        d.set_parent(parent);
        parent.add_child(d.clone());
        Ok(d)
    })();
    unsafe { dir.inode_unlock() };
    r
}

/// Remove entry `name` from directory `parent` (Linux vfs_unlink /
/// vfs_rmdir) under the parent's lock: may_delete (write+search, sticky
/// rule, type vs `isdir`), then the file system's unlink or rmdir with
/// the victim's lock held too
pub fn delete_entry(parent: &Arc<Dentry>, name: &str, isdir: bool) -> Result<(), KernelError> {
    let dir = parent.get_inode().ok_or(KernelError::NotFound)?;
    let _w = super::dac::want_write(&dir)?;
    let c = cred();
    dir.inode_lock();
    let r = (|| {
        let victim = lookup_one(parent, name)?;
        let inode = victim.get_inode().ok_or(KernelError::NotFound)?;
        super::dac::may_delete(&c, &dir, &inode, isdir)?;
        // The victim's lock, inside the parent's (Linux vfs_unlink /
        // vfs_rmdir): its link count never drops under a link of it
        inode.inode_lock();
        let r = if isdir {
            dir.i_op.rmdir(&dir, name)
        } else {
            dir.i_op.unlink(&dir, name)
        };
        unsafe { inode.inode_unlock() };
        r?;
        parent.remove_child(name);
        Ok(())
    })();
    unsafe { dir.inode_unlock() };
    r
}
