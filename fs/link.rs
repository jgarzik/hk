//! File linking syscalls (symlink, readlink, link, unlink, rename)
//!
//! This module contains syscalls for creating, reading, and removing
//! filesystem links, as well as renaming files.

use alloc::sync::Arc;

use crate::arch::Uaccess;
use crate::fs::dentry::{d_exchange, d_move};
use crate::fs::namei::{
    Last, Parent, create_entry, delete_entry, filename_create, filename_lookup, filename_parentat,
    getname,
};
use crate::fs::{
    Inode, KernelError, LookupFlags, MAY_WRITE, Path, dac, is_subdir, lock_rename,
    lock_two_nondirs, lookup_one,
};
use crate::uaccess::copy_to_user;

use super::file::flags::{AT_EMPTY_PATH, AT_FDCWD, AT_REMOVEDIR, AT_SYMLINK_FOLLOW};

// =============================================================================
// symlink, symlinkat syscalls
// =============================================================================

/// sys_symlink - create a symbolic link
///
/// Creates a symbolic link named linkpath pointing to target.
///
/// # Arguments
/// * `target_ptr` - User pointer to target path string
/// * `linkpath_ptr` - User pointer to link path string
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_symlink(target_ptr: u64, linkpath_ptr: u64) -> i64 {
    sys_symlinkat(target_ptr, AT_FDCWD, linkpath_ptr)
}

/// sys_symlinkat - create a symbolic link relative to directory fd
///
/// # Arguments
/// * `target_ptr` - User pointer to target path string
/// * `newdirfd` - Directory fd for linkpath, or AT_FDCWD
/// * `linkpath_ptr` - User pointer to link path string
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_symlinkat(target_ptr: u64, newdirfd: i32, linkpath_ptr: u64) -> i64 {
    match do_symlinkat(target_ptr, newdirfd, linkpath_ptr) {
        Ok(()) => 0,
        Err(KernelError::OperationNotSupported) => KernelError::NotPermitted.sysret(),
        Err(e) => e.sysret(),
    }
}

/// Linux do_symlinkat: the target is a name too (ENOENT if empty), the
/// link a new name (filename_create)
fn do_symlinkat(target_ptr: u64, newdirfd: i32, linkpath_ptr: u64) -> Result<(), KernelError> {
    let target = getname(target_ptr, false)?;
    let p = filename_create(newdirfd, &getname(linkpath_ptr, false)?, false)?;
    create_entry(&p, |dir, _| dir.i_op.symlink(dir, &p.name, &target))?;
    Ok(())
}

// =============================================================================
// readlink, readlinkat syscalls
// =============================================================================

/// sys_readlink - read value of a symbolic link
///
/// Reads the target of a symbolic link into a buffer.
///
/// # Arguments
/// * `path_ptr` - User pointer to path string
/// * `buf_ptr` - User buffer to store the target
/// * `bufsiz` - Size of the buffer
///
/// # Returns
/// Number of bytes placed in buffer (not null-terminated), negative errno on error
pub fn sys_readlink(path_ptr: u64, buf_ptr: u64, bufsiz: u64) -> i64 {
    sys_readlinkat(AT_FDCWD, path_ptr, buf_ptr, bufsiz)
}

/// sys_readlinkat - read value of a symbolic link relative to directory fd
///
/// # Arguments
/// * `dirfd` - Directory fd for relative paths, or AT_FDCWD
/// * `path_ptr` - User pointer to path string
/// * `buf_ptr` - User buffer to store the target
/// * `bufsiz` - Size of the buffer
///
/// # Returns
/// Number of bytes placed in buffer (not null-terminated), negative errno on error
pub fn sys_readlinkat(dirfd: i32, path_ptr: u64, buf_ptr: u64, bufsiz: u64) -> i64 {
    match do_readlinkat(dirfd, path_ptr, buf_ptr, bufsiz as i32) {
        Ok(n) => n as i64,
        Err(e) => e.sysret(),
    }
}

/// Linux do_readlinkat: bufsiz is an int (<= 0 is EINVAL); an empty path
/// names dirfd itself (an O_PATH symlink), which if no symlink is ENOENT,
/// any other non-symlink EINVAL; the target is copied unterminated
fn do_readlinkat(dirfd: i32, path_ptr: u64, buf: u64, bufsiz: i32) -> Result<usize, KernelError> {
    if bufsiz <= 0 {
        return Err(KernelError::InvalidArgument);
    }
    let path = getname(path_ptr, true)?;
    let dentry = filename_lookup(
        dirfd,
        &path,
        LookupFlags::at(super::file::flags::AT_SYMLINK_NOFOLLOW),
    )?;
    let inode = dentry.get_inode().ok_or(KernelError::NotFound)?;
    if !inode.mode().is_symlink() {
        return Err(if path.is_empty() {
            KernelError::NotFound
        } else {
            KernelError::InvalidArgument
        });
    }
    // e.g. /proc/<pid>/exe: EACCES, ENOENT (Linux returns the get_link
    // error)
    let target = match inode.i_op.readlink(&inode) {
        Err(KernelError::OperationNotSupported) => return Err(KernelError::InvalidArgument),
        r => r?,
    };
    let n = target.len().min(bufsiz as usize);
    copy_to_user::<Uaccess>(buf, &target[..n]).map_err(|_| KernelError::BadAddress)?;
    Ok(n)
}

// =============================================================================
// link, linkat syscalls
// =============================================================================

/// sys_link - create a hard link
///
/// Creates a new name for an existing file.
///
/// # Arguments
/// * `oldpath_ptr` - User pointer to existing path
/// * `newpath_ptr` - User pointer to new path
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_link(oldpath_ptr: u64, newpath_ptr: u64) -> i64 {
    sys_linkat(AT_FDCWD, oldpath_ptr, AT_FDCWD, newpath_ptr, 0)
}

/// vfs_link's part under the source inode's lock, itself inside the new
/// parent's: an inode with no links left is not linked again (ENOENT),
/// and no unlink can drop its last link between that check and the link
/// (Linux vfs_link: inode_lock(inode), i_nlink == 0 -> ENOENT)
fn link_locked(dir: &Arc<Inode>, name: &[u8], inode: &Arc<Inode>) -> Result<(), KernelError> {
    let _lock = inode.lock();
    if inode.get_nlink() == 0 {
        Err(KernelError::NotFound)
    } else {
        dir.i_op.link(dir, name, inode)
    }
}

/// The dentry linkat links to (Linux 6.8 do_linkat): AT_EMPTY_PATH at
/// all takes CAP_DAC_READ_SEARCH (else ENOENT, whatever the path), so
/// a descriptor passed to an unprivileged process cannot be linked back
/// into the tree; an empty path with it names `dirfd` itself; the final
/// symlink is followed only with AT_SYMLINK_FOLLOW
fn link_source(dirfd: i32, path_ptr: u64, flags: i32) -> Result<Path, KernelError> {
    let path = getname(path_ptr, flags & AT_EMPTY_PATH != 0);
    if flags & AT_EMPTY_PATH != 0 && !crate::task::capable(crate::task::CAP_DAC_READ_SEARCH) {
        return Err(KernelError::NotFound);
    }
    let lf = LookupFlags {
        follow: flags & AT_SYMLINK_FOLLOW != 0,
        ..LookupFlags::open()
    };
    filename_lookup(dirfd, &path?, lf)
}

/// sys_linkat - create a hard link relative to directory fds
///
/// # Arguments
/// * `olddirfd` - Directory fd for oldpath, or AT_FDCWD
/// * `oldpath_ptr` - User pointer to existing path
/// * `newdirfd` - Directory fd for newpath, or AT_FDCWD
/// * `newpath_ptr` - User pointer to new path
/// * `flags` - AT_SYMLINK_FOLLOW to follow a final symlink in oldpath,
///   AT_EMPTY_PATH to link `olddirfd` itself
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_linkat(
    olddirfd: i32,
    oldpath_ptr: u64,
    newdirfd: i32,
    newpath_ptr: u64,
    flags: i32,
) -> i64 {
    if flags & !(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH) != 0 {
        return KernelError::InvalidArgument.sysret();
    }
    let old = match link_source(olddirfd, oldpath_ptr, flags) {
        Ok(d) => d,
        Err(e) => return e.sysret(),
    };
    let Some(old_inode) = old.dentry.get_inode() else {
        return KernelError::NotFound.sysret();
    };
    let p = match getname(newpath_ptr, false).and_then(|n| filename_create(newdirfd, &n, false)) {
        Ok(p) => p,
        Err(e) => return e.sysret(),
    };
    // EXDEV across mounts, even of one superblock
    if !Arc::ptr_eq(&old.mnt, &p.mnt) {
        return KernelError::CrossDevice.sysret();
    }

    // vfs_link: may_create on the new parent, then no directories
    // (fs.protected_hardlinks is not implemented: its kernel default is 0)
    let r = create_entry(&p, |dir, _| {
        if old_inode.mode().is_dir() {
            return Err(KernelError::NotPermitted);
        }
        link_locked(dir, &p.name, &old_inode)?;
        Ok(old_inode.clone())
    });
    match r {
        Ok(_) => 0,
        Err(KernelError::OperationNotSupported) => KernelError::NotPermitted.sysret(),
        Err(e) => e.sysret(),
    }
}

// =============================================================================
// unlink, unlinkat syscalls
// =============================================================================

/// sys_unlink - delete a name from the filesystem
///
/// Removes a directory entry for a file. If this was the last link to the file
/// and no processes have it open, the file is deleted.
///
/// # Arguments
/// * `pathname_ptr` - User pointer to path string
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_unlink(pathname_ptr: u64) -> i64 {
    sys_unlinkat(AT_FDCWD, pathname_ptr, 0)
}

/// sys_unlinkat - delete a name relative to a directory file descriptor
///
/// If AT_REMOVEDIR is specified in flags, performs rmdir instead of unlink.
///
/// # Arguments
/// * `dirfd` - Directory file descriptor, or AT_FDCWD for current directory
/// * `pathname_ptr` - User pointer to path string
/// * `flags` - Flags (AT_REMOVEDIR to remove directory)
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_unlinkat(dirfd: i32, pathname_ptr: u64, flags: i32) -> i64 {
    match do_unlinkat(dirfd, pathname_ptr, flags) {
        Ok(()) => 0,
        Err(e) => e.sysret(),
    }
}

/// Linux unlinkat + do_unlinkat: only AT_REMOVEDIR is a flag; a last
/// name of "/", "." or ".." is EISDIR
fn do_unlinkat(dirfd: i32, pathname_ptr: u64, flags: i32) -> Result<(), KernelError> {
    if flags & !AT_REMOVEDIR != 0 {
        return Err(KernelError::InvalidArgument);
    }
    let path = getname(pathname_ptr, false)?;
    if flags & AT_REMOVEDIR != 0 {
        return super::dir::do_rmdir(dirfd, &path);
    }
    let p = filename_parentat(dirfd, &path)?;
    if p.last != Last::Norm {
        return Err(KernelError::IsDirectory);
    }
    delete_entry(&p, false)
}

// =============================================================================
// rename, renameat, renameat2 syscalls
// =============================================================================

/// renameat2 flags (Linux include/uapi/linux/fs.h)
pub const RENAME_NOREPLACE: u32 = 1 << 0;
pub const RENAME_EXCHANGE: u32 = 1 << 1;
pub const RENAME_WHITEOUT: u32 = 1 << 2;

/// Flag check of renameat2, before anything else (Linux
/// filename_renameat2): unknown flags, and EXCHANGE with NOREPLACE or
/// WHITEOUT, are EINVAL. Whether a file system takes a flag (no hk file
/// system makes whiteouts) is up to its rename.
fn rename_flags_ok(flags: u32) -> bool {
    flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT) == 0
        && !(flags & (RENAME_NOREPLACE | RENAME_WHITEOUT) != 0 && flags & RENAME_EXCHANGE != 0)
}

/// sys_rename - rename a file
///
/// # Arguments
/// * `oldpath_ptr` - User pointer to existing path
/// * `newpath_ptr` - User pointer to new path
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_rename(oldpath_ptr: u64, newpath_ptr: u64) -> i64 {
    sys_renameat2(AT_FDCWD, oldpath_ptr, AT_FDCWD, newpath_ptr, 0)
}

/// sys_renameat - rename a file relative to directory fds
///
/// # Arguments
/// * `olddirfd` - Directory fd for oldpath, or AT_FDCWD
/// * `oldpath_ptr` - User pointer to existing path
/// * `newdirfd` - Directory fd for newpath, or AT_FDCWD
/// * `newpath_ptr` - User pointer to new path
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_renameat(olddirfd: i32, oldpath_ptr: u64, newdirfd: i32, newpath_ptr: u64) -> i64 {
    sys_renameat2(olddirfd, oldpath_ptr, newdirfd, newpath_ptr, 0)
}

/// sys_renameat2 - rename a file with flags
///
/// # Arguments
/// * `olddirfd` - Directory fd for oldpath, or AT_FDCWD
/// * `oldpath_ptr` - User pointer to existing path
/// * `newdirfd` - Directory fd for newpath, or AT_FDCWD
/// * `newpath_ptr` - User pointer to new path
/// * `flags` - RENAME_NOREPLACE, RENAME_EXCHANGE, etc.
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_renameat2(
    olddirfd: i32,
    oldpath_ptr: u64,
    newdirfd: i32,
    newpath_ptr: u64,
    flags: u32,
) -> i64 {
    match do_renameat2(olddirfd, oldpath_ptr, newdirfd, newpath_ptr, flags) {
        Ok(()) => 0,
        Err(KernelError::OperationNotSupported) => KernelError::InvalidArgument.sysret(),
        Err(e) => e.sysret(),
    }
}

/// Linux filename_renameat2: both parents walked, EXDEV, then a last
/// name of "/", "." or ".." is EBUSY (the new one EEXIST under
/// RENAME_NOREPLACE), write access, then the rename with both parents
/// locked
fn do_renameat2(
    olddirfd: i32,
    oldpath_ptr: u64,
    newdirfd: i32,
    newpath_ptr: u64,
    flags: u32,
) -> Result<(), KernelError> {
    if !rename_flags_ok(flags) {
        return Err(KernelError::InvalidArgument);
    }
    let newpath = getname(newpath_ptr, false);
    let old = filename_parentat(olddirfd, &getname(oldpath_ptr, false)?)?;
    let new = filename_parentat(newdirfd, &newpath?)?;
    if !Arc::ptr_eq(&old.mnt, &new.mnt) {
        return Err(KernelError::CrossDevice);
    }
    if old.last != Last::Norm {
        return Err(KernelError::Busy);
    }
    if new.last != Last::Norm {
        return Err(if flags & RENAME_NOREPLACE != 0 {
            KernelError::AlreadyExists
        } else {
            KernelError::Busy
        });
    }
    let odir = old.dir.get_inode().ok_or(KernelError::NotFound)?;
    let ndir = new.dir.get_inode().ok_or(KernelError::NotFound)?;
    let _w = old.mnt.want_write()?;
    let _locks = lock_rename(&old.dir, &new.dir);
    rename_locked((&old, &odir), (&new, &ndir), flags)
}

/// One side of a rename: the split path and its parent's inode
type Side<'a> = (&'a Parent, &'a Arc<Inode>);

/// The rename itself with both parents locked (Linux do_renameat2 trap
/// check + vfs_rename): may_delete of the source, may_create or
/// may_delete of the target, and write permission on a directory that
/// changes parent (its ".." is rewritten)
fn rename_locked(old: Side, new: Side, flags: u32) -> Result<(), KernelError> {
    let ((op, oname), odir) = ((&old.0.dir, old.0.name.as_slice()), old.1);
    let ((np, nname), ndir) = ((&new.0.dir, new.0.name.as_slice()), new.1);
    let src = lookup_one(op, oname)?;
    let sinode = src.get_inode().ok_or(KernelError::NotFound)?;
    let dst = lookup_one(np, nname)
        .ok()
        .filter(|d| d.get_inode().is_some());
    let dinode = dst.as_ref().and_then(|d| d.get_inode());
    let is_dir = sinode.mode().is_dir();

    // The target must exist for EXCHANGE and must not for NOREPLACE
    // (Linux __start_renaming)
    if flags & RENAME_EXCHANGE != 0 && dinode.is_none() {
        return Err(KernelError::NotFound);
    }
    if flags & RENAME_NOREPLACE != 0 && dinode.is_some() {
        return Err(KernelError::AlreadyExists);
    }

    // lock_rename's trap (Linux __start_renaming): the source may not
    // be an ancestor of the new parent (moving a directory into its own
    // subtree), nor the target one of the old parent (an exchange would
    // move it under itself; a plain rename would replace a non-empty
    // ancestor). Both would cut a cycle out of the tree.
    if is_subdir(np, &src) {
        return Err(KernelError::InvalidArgument);
    }
    if dst.as_ref().is_some_and(|d| is_subdir(op, d)) {
        return Err(if flags & RENAME_EXCHANGE != 0 {
            KernelError::InvalidArgument
        } else {
            KernelError::DirectoryNotEmpty
        });
    }
    // Unless the source is a directory, trailing slashes are ENOTDIR (on
    // the target too unless exchanging, where its own type decides)
    let exchange = flags & RENAME_EXCHANGE != 0;
    if exchange && new.0.slash && dinode.as_ref().is_some_and(|d| !d.mode().is_dir()) {
        return Err(KernelError::NotDirectory);
    }
    if !is_dir && (old.0.slash || (!exchange && new.0.slash)) {
        return Err(KernelError::NotDirectory);
    }
    // Same inode: nothing to do (vfs_rename "source == target")
    if dinode.as_ref().is_some_and(|d| d.ino == sinode.ino) {
        return Ok(());
    }

    let c = dac::cred();
    dac::may_delete(&c, odir, &sinode, is_dir)?;
    match &dinode {
        None => dac::may_create(&c, ndir)?,
        Some(d) => dac::may_delete(
            &c,
            ndir,
            d,
            if exchange { d.mode().is_dir() } else { is_dir },
        )?,
    }
    if !Arc::ptr_eq(odir, ndir) {
        if is_dir {
            dac::permission_as(&c, &sinode, MAY_WRITE)?;
        }
        if let Some(d) = dinode.as_ref().filter(|d| exchange && d.mode().is_dir()) {
            dac::permission_as(&c, d, MAY_WRITE)?;
        }
    }

    // The link counts that change, under their inodes' locks (Linux
    // lock_two_nondirectories); a directory being replaced is locked
    // too (Linux vfs_rename), so a mount on it is either seen here or
    // refused for the dead directory
    let dead = dinode.as_ref().filter(|d| !exchange && d.mode().is_dir());
    let nondirs = lock_two_nondirs(Some(&sinode), dinode.as_ref());
    let dead_lock = dead.map(|d| d.lock());
    // Linux vfs_rename: neither side may be a mountpoint here
    let r = if super::mount::is_local_mountpoint(&src)
        || dst.as_ref().is_some_and(super::mount::is_local_mountpoint)
    {
        Err(KernelError::Busy)
    } else {
        odir.i_op.rename(odir, oname, ndir, nname, flags)
    };
    if let Some(d) = dead
        && r.is_ok()
    {
        d.set_dead();
    }
    drop(dead_lock);
    drop(nondirs);
    r?;
    // The dentries follow the rename: whoever holds one (a cwd, an fd,
    // a mountpoint) sees the new place
    match &dst {
        Some(d) if exchange => d_exchange(&src, d),
        _ => d_move(&src, np, nname),
    }
    Ok(())
}
