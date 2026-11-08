//! File permission, ownership, and timestamp syscalls
//!
//! This module contains syscalls for checking and modifying file attributes:
//! - access, faccessat, faccessat2 (permission checking)
//! - chmod, fchmod, fchmodat, fchmodat2 (mode modification)
//! - chown, lchown, fchown, fchownat (ownership modification)
//! - umask (file creation mask)
//! - utime, utimes, utimensat, futimens (timestamp modification)

use alloc::sync::Arc;

use crate::fs::dac::{self, MAY_ACCESS};
use crate::fs::{Dentry, Inode, KernelError, LookupFlags, Path};
use crate::time::time_syscall::{LinuxTimespec, Timeval};
use crate::uaccess::UserPtr;
use crate::util::error::KernelResult;

use super::file::flags::{AT_EACCESS, AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW};
use super::io::fget;
use super::namei::user_path_at;

// =============================================================================
// access, faccessat, faccessat2 syscalls
// =============================================================================

// access() mode flags - what permissions to check
/// Check if file exists
const F_OK: i32 = 0;
/// Check execute permission
const X_OK: i32 = 1;
/// Check write permission
const W_OK: i32 = 2;
/// Check read permission
const R_OK: i32 = 4;

/// Resolve `dirfd` + user path for the *at() attribute syscalls:
/// AT_EMPTY_PATH (when `empty_ok`) names dirfd itself, AT_SYMLINK_NOFOLLOW
/// stops at a final symlink
fn resolve(dirfd: i32, path_ptr: UserPtr<u8>, flags: i32, empty_ok: bool) -> KernelResult<Path> {
    let empty_ok = empty_ok && flags & AT_EMPTY_PATH != 0;
    user_path_at(dirfd, path_ptr, LookupFlags::at(flags), empty_ok)
}

fn inode_of(d: &Dentry) -> KernelResult<Arc<Inode>> {
    d.get_inode().ok_or(KernelError::NotFound)
}

/// Common helper for access/faccessat/faccessat2 (Linux do_faccessat):
/// without AT_EACCESS the check uses the real uid/gid
/// (access_override_creds), with it the current fs ids
fn do_faccessat(dirfd: i32, path_ptr: UserPtr<u8>, mode: i32, flags: i32) -> KernelResult<()> {
    if mode & !(F_OK | R_OK | W_OK | X_OK) != 0 {
        return Err(KernelError::InvalidArgument);
    }
    if flags & !(AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(KernelError::InvalidArgument);
    }
    let d = resolve(dirfd, path_ptr, flags, true)?;
    let inode = inode_of(&d.dentry)?;
    let cur = dac::cred();
    let c = if flags & AT_EACCESS != 0 {
        cur
    } else {
        dac::access_cred(&cur)
    };
    // R_OK/W_OK/X_OK are MAY_READ/MAY_WRITE/MAY_EXEC
    dac::permission_as(&c, &inode, mode as u32 | MAY_ACCESS)?;
    // SuS: W_OK of a file on a read-only mount is EROFS (devices,
    // FIFOs and sockets are fine)
    let special = inode.mode().is_device() || inode.mode().is_fifo() || inode.mode().is_socket();
    if mode & W_OK != 0 && !special && d.mnt.is_readonly() {
        return Err(KernelError::ReadOnlyFs);
    }
    Ok(())
}

/// sys_access - check file access permissions
pub fn sys_access(path_ptr: UserPtr<u8>, mode: i32) -> KernelResult<()> {
    do_faccessat(AT_FDCWD, path_ptr, mode, 0)
}

/// sys_faccessat - check file access relative to directory fd (no flags
/// argument: that is faccessat2)
pub fn sys_faccessat(dirfd: i32, path_ptr: UserPtr<u8>, mode: i32) -> KernelResult<()> {
    do_faccessat(dirfd, path_ptr, mode, 0)
}

/// sys_faccessat2 - check file access with flags
pub fn sys_faccessat2(
    dirfd: i32,
    path_ptr: UserPtr<u8>,
    mode: i32,
    flags: i32,
) -> KernelResult<()> {
    do_faccessat(dirfd, path_ptr, mode, flags)
}

// =============================================================================
// chmod, fchmod, fchmodat, fchmodat2 syscalls
// =============================================================================

/// Internal helper for fchmodat/fchmodat2
fn do_fchmodat(dirfd: i32, pathname: UserPtr<u8>, mode: u32, flags: i32) -> KernelResult<()> {
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(KernelError::InvalidArgument);
    }
    dac::chmod(
        &resolve(dirfd, pathname, flags, true)?,
        (mode & 0o7777) as u16,
    )
}

/// sys_fchmodat - change file permissions relative to directory fd
pub fn sys_fchmodat(dirfd: i32, pathname: UserPtr<u8>, mode: u32, _flags: i32) -> KernelResult<()> {
    do_fchmodat(dirfd, pathname, mode, 0)
}

/// sys_fchmodat2 - change file permissions with flags support
pub fn sys_fchmodat2(dirfd: i32, pathname: UserPtr<u8>, mode: u32, flags: i32) -> KernelResult<()> {
    do_fchmodat(dirfd, pathname, mode, flags)
}

/// sys_chmod - change file permissions
pub fn sys_chmod(pathname: UserPtr<u8>, mode: u32) -> KernelResult<()> {
    sys_fchmodat(AT_FDCWD, pathname, mode, 0)
}

/// Path of an open fd
fn fd_path(fd: i32) -> KernelResult<Path> {
    fget(fd)?.f_path().ok_or(KernelError::BadFd)
}

/// sys_fchmod - change file permissions by fd
pub fn sys_fchmod(fd: i32, mode: u32) -> KernelResult<()> {
    dac::chmod(&fd_path(fd)?, (mode & 0o7777) as u16)
}

// =============================================================================
// chown, lchown, fchown, fchownat syscalls
// =============================================================================

/// -1 leaves an id unchanged
fn id(v: u32) -> Option<u32> {
    (v != u32::MAX).then_some(v)
}

/// sys_fchownat - change file ownership relative to directory fd
pub fn sys_fchownat(
    dirfd: i32,
    pathname: UserPtr<u8>,
    owner: u32,
    group: u32,
    flags: i32,
) -> KernelResult<()> {
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(KernelError::InvalidArgument);
    }
    dac::chown(
        &resolve(dirfd, pathname, flags, true)?,
        id(owner),
        id(group),
    )
}

/// sys_chown - change file ownership (follows symlinks)
pub fn sys_chown(pathname: UserPtr<u8>, owner: u32, group: u32) -> KernelResult<()> {
    sys_fchownat(AT_FDCWD, pathname, owner, group, 0)
}

/// sys_lchown - change ownership of a symbolic link (does NOT follow)
pub fn sys_lchown(pathname: UserPtr<u8>, owner: u32, group: u32) -> KernelResult<()> {
    sys_fchownat(AT_FDCWD, pathname, owner, group, AT_SYMLINK_NOFOLLOW)
}

/// sys_fchown - change file ownership by fd
pub fn sys_fchown(fd: i32, owner: u32, group: u32) -> KernelResult<()> {
    dac::chown(&fd_path(fd)?, id(owner), id(group))
}

// =============================================================================
// umask syscall
// =============================================================================

/// sys_umask - set file creation mask; the old one
pub fn sys_umask(mask: u32) -> KernelResult<u32> {
    let new_mask = (mask & 0o7777) as u16;

    if let Some(fs) = crate::task::percpu::current_fs() {
        Ok(u32::from(fs.set_umask(new_mask)))
    } else {
        Ok(0o022)
    }
}

// =============================================================================
// Timestamp modification syscalls
// =============================================================================

/// Special nsec value: set time to current time
const UTIME_NOW: i64 = 0x3fffffff;
/// Special nsec value: don't change this time
const UTIME_OMIT: i64 = 0x3ffffffe;

/// Linux struct utimbuf (utime)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Utimbuf {
    actime: i64,
    modtime: i64,
}
crate::pod!(Utimbuf { actime, modtime });

/// Get current time from timekeeper
fn current_time() -> crate::time::Timespec {
    use crate::time::TIMEKEEPER;
    TIMEKEEPER.current_time()
}

/// Linux vfs_utimes: `times` None (or both UTIME_NOW) is a "touch" that
/// needs ownership or write permission; anything else is an explicit
/// update that needs ownership or CAP_FOWNER. A NULL `pathname` means
/// dirfd.
fn do_utimes(
    dirfd: i32,
    pathname: UserPtr<u8>,
    times: Option<[LinuxTimespec; 2]>,
    flags: i32,
) -> KernelResult<()> {
    let valid = |n: i64| (0..1_000_000_000).contains(&n) || n == UTIME_NOW || n == UTIME_OMIT;
    if let Some(t) = times
        && !(valid(t[0].tv_nsec) && valid(t[1].tv_nsec))
    {
        return Err(KernelError::InvalidArgument);
    }
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(KernelError::InvalidArgument);
    }
    let path = if pathname.is_null() {
        if dirfd == AT_FDCWD {
            return Err(KernelError::InvalidArgument);
        }
        fd_path(dirfd)?
    } else {
        resolve(dirfd, pathname, flags, true)?
    };
    let inode = inode_of(&path.dentry)?;
    let times = times.filter(|t| !(t[0].tv_nsec == UTIME_NOW && t[1].tv_nsec == UTIME_NOW));
    // vfs_utimes: write access first (EROFS), held across the update
    let _w = path.mnt.want_write()?;
    // notify_change under i_rwsem (Linux vfs_utimes: inode_lock), its
    // checks too (setattr_prepare: owner, CAP_FOWNER or write access),
    // so a racing chown cannot leave the old owner's decision standing
    let lock = inode.lock();
    inode.i_op.setattr_ok(&inode)?;
    dac::may_utimes(&inode, times.is_some())?;
    // The time is taken in the hold, so ctime never goes backwards
    // between racing updates (Linux notify_change under inode_lock)
    let now = current_time();
    let pick = |t: &LinuxTimespec| match t.tv_nsec {
        UTIME_OMIT => None,
        UTIME_NOW => Some(now),
        n => Some(crate::time::Timespec {
            sec: t.tv_sec,
            nsec: n as u32,
        }),
    };
    let (atime, mtime) = match &times {
        None => (Some(now), Some(now)),
        Some(t) => (pick(&t[0]), pick(&t[1])),
    };
    if let Some(t) = atime {
        inode.set_atime(t);
    }
    if let Some(t) = mtime {
        inode.set_mtime(t);
    }
    inode.set_ctime(now);
    inode.i_op.setattr_done(&inode);
    drop(lock);
    Ok(())
}

/// The `T` at `ptr`, None for NULL
fn read_opt<T: crate::util::pod::FromBytes>(ptr: UserPtr<T>) -> KernelResult<Option<T>> {
    if ptr.is_null() {
        return Ok(None);
    }
    Ok(Some(ptr.read()?))
}

/// sys_utimensat - change file timestamps with nanosecond precision
pub fn sys_utimensat(
    dirfd: i32,
    pathname: UserPtr<u8>,
    times: UserPtr<[LinuxTimespec; 2]>,
    flags: i32,
) -> KernelResult<()> {
    let ts = read_opt(times)?;
    // Nothing to do: not even the path is checked
    if ts.is_some_and(|t| t[0].tv_nsec == UTIME_OMIT && t[1].tv_nsec == UTIME_OMIT) {
        return Ok(());
    }
    do_utimes(dirfd, pathname, ts, flags)
}

/// sys_futimens - change file timestamps by fd
pub fn sys_futimens(fd: i32, times: UserPtr<[LinuxTimespec; 2]>) -> KernelResult<()> {
    sys_utimensat(fd, UserPtr::new(0), times, 0)
}

/// sys_utimes - change file timestamps (microsecond precision)
pub fn sys_utimes(pathname: UserPtr<u8>, times: UserPtr<[Timeval; 2]>) -> KernelResult<()> {
    let ts = match read_opt(times)? {
        None => None,
        Some(tv) => {
            if tv.iter().any(|t| !(0..1_000_000).contains(&t.tv_usec)) {
                return Err(KernelError::InvalidArgument);
            }
            Some(tv.map(|t| LinuxTimespec {
                tv_sec: t.tv_sec,
                tv_nsec: t.tv_usec * 1000,
            }))
        }
    };
    do_utimes(AT_FDCWD, pathname, ts, 0)
}

/// sys_utime - change file timestamps (second precision)
pub fn sys_utime(pathname: UserPtr<u8>, times: UserPtr<Utimbuf>) -> KernelResult<()> {
    let at = |sec| LinuxTimespec {
        tv_sec: sec,
        tv_nsec: 0,
    };
    let ts = read_opt(times)?.map(|b| [at(b.actime), at(b.modtime)]);
    do_utimes(AT_FDCWD, pathname, ts, 0)
}
