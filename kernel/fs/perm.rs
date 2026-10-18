//! File permission, ownership, and timestamp syscalls
//!
//! This module contains syscalls for checking and modifying file attributes:
//! - access, faccessat, faccessat2 (permission checking)
//! - chmod, fchmod, fchmodat, fchmodat2 (mode modification)
//! - chown, lchown, fchown, fchownat (ownership modification)
//! - umask (file creation mask)
//! - utime, utimes, utimensat, futimens (timestamp modification)

use crate::arch::Uaccess;
use alloc::sync::Arc;

use crate::fs::dac::{self, MAY_ACCESS};
use crate::fs::{Dentry, Inode, KernelError, LookupFlags, Path, lookup_path_at};
use crate::uaccess::{UaccessArch, copy_val_from_user, strncpy_from_user};

use super::syscall::{AT_FDCWD, PATH_MAX, current_fd_table};

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

// faccessat() flags - how to perform the check
/// Use effective uid/gid instead of real uid/gid
const AT_EACCESS: i32 = 0x200;
/// Don't follow symbolic links
const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
/// If pathname is empty, check dirfd itself
const AT_EMPTY_PATH: i32 = 0x1000;

/// Resolve `dirfd` + user path for the *at() attribute syscalls:
/// AT_EMPTY_PATH (when `empty_ok`) names dirfd itself, AT_SYMLINK_NOFOLLOW
/// stops at a final symlink
fn resolve(
    dirfd: i32,
    path_ptr: u64,
    flags: i32,
    empty_ok: bool,
) -> Result<Arc<Dentry>, KernelError> {
    let path =
        strncpy_from_user::<Uaccess>(path_ptr, PATH_MAX).map_err(|_| KernelError::BadAddress)?;
    if path.is_empty() {
        if !empty_ok || flags & AT_EMPTY_PATH == 0 {
            return Err(KernelError::NotFound);
        }
        if dirfd == AT_FDCWD {
            return crate::task::percpu::current_cwd()
                .map(|p| p.dentry.clone())
                .ok_or(KernelError::NotFound);
        }
        let file = current_fd_table()
            .lock()
            .get(dirfd)
            .ok_or(KernelError::BadFd)?;
        return Ok(file.dentry.clone());
    }
    let start: Option<Path> = if path.starts_with('/') {
        None
    } else if dirfd == AT_FDCWD {
        crate::task::percpu::current_cwd()
    } else {
        let file = current_fd_table()
            .lock()
            .get(dirfd)
            .ok_or(KernelError::BadFd)?;
        if !file.is_dir() {
            return Err(KernelError::NotDirectory);
        }
        Path::from_dentry(file.dentry.clone())
    };
    let mut lf = LookupFlags::open();
    if flags & AT_SYMLINK_NOFOLLOW != 0 {
        lf.follow = false;
    }
    lookup_path_at(start, &path, lf)
}

fn inode_of(d: &Dentry) -> Result<Arc<Inode>, KernelError> {
    d.get_inode().ok_or(KernelError::NotFound)
}

fn ret(r: Result<(), KernelError>) -> i64 {
    match r {
        Ok(()) => 0,
        Err(e) => e.sysret(),
    }
}

/// Common helper for access/faccessat/faccessat2 (Linux do_faccessat):
/// without AT_EACCESS the check uses the real uid/gid
/// (access_override_creds), with it the current fs ids
fn do_faccessat(dirfd: i32, path_ptr: u64, mode: i32, flags: i32) -> i64 {
    if mode & !(F_OK | R_OK | W_OK | X_OK) != 0 {
        return KernelError::InvalidArgument.sysret();
    }
    if flags & !(AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return KernelError::InvalidArgument.sysret();
    }
    let r = resolve(dirfd, path_ptr, flags, true).and_then(|d| {
        let inode = inode_of(&d)?;
        let cur = dac::cred();
        let c = if flags & AT_EACCESS != 0 {
            cur
        } else {
            dac::access_cred(&cur)
        };
        // R_OK/W_OK/X_OK are MAY_READ/MAY_WRITE/MAY_EXEC
        dac::permission_as(&c, &inode, mode as u32 | MAY_ACCESS)
    });
    ret(r)
}

/// sys_access - check file access permissions
pub fn sys_access(path_ptr: u64, mode: i32) -> i64 {
    do_faccessat(AT_FDCWD, path_ptr, mode, 0)
}

/// sys_faccessat - check file access relative to directory fd (no flags
/// argument: that is faccessat2)
pub fn sys_faccessat(dirfd: i32, path_ptr: u64, mode: i32) -> i64 {
    do_faccessat(dirfd, path_ptr, mode, 0)
}

/// sys_faccessat2 - check file access with flags
pub fn sys_faccessat2(dirfd: i32, path_ptr: u64, mode: i32, flags: i32) -> i64 {
    do_faccessat(dirfd, path_ptr, mode, flags)
}

// =============================================================================
// chmod, fchmod, fchmodat, fchmodat2 syscalls
// =============================================================================

/// Internal helper for fchmodat/fchmodat2
fn do_fchmodat(dirfd: i32, pathname: u64, mode: u32, flags: i32) -> i64 {
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return KernelError::InvalidArgument.sysret();
    }
    ret(resolve(dirfd, pathname, flags, true)
        .and_then(|d| dac::chmod(&*inode_of(&d)?, (mode & 0o7777) as u16)))
}

/// sys_fchmodat - change file permissions relative to directory fd
pub fn sys_fchmodat(dirfd: i32, pathname: u64, mode: u32, _flags: i32) -> i64 {
    do_fchmodat(dirfd, pathname, mode, 0)
}

/// sys_fchmodat2 - change file permissions with flags support
pub fn sys_fchmodat2(dirfd: i32, pathname: u64, mode: u32, flags: i32) -> i64 {
    do_fchmodat(dirfd, pathname, mode, flags)
}

/// sys_chmod - change file permissions
pub fn sys_chmod(pathname: u64, mode: u32) -> i64 {
    sys_fchmodat(AT_FDCWD, pathname, mode, 0)
}

/// Inode of an open fd
fn fd_inode(fd: i32) -> Result<Arc<Inode>, KernelError> {
    let file = current_fd_table()
        .lock()
        .get(fd)
        .ok_or(KernelError::BadFd)?;
    file.get_inode().ok_or(KernelError::BadFd)
}

/// sys_fchmod - change file permissions by fd
pub fn sys_fchmod(fd: i32, mode: u32) -> i64 {
    ret(fd_inode(fd).and_then(|i| dac::chmod(&i, (mode & 0o7777) as u16)))
}

// =============================================================================
// chown, lchown, fchown, fchownat syscalls
// =============================================================================

/// -1 leaves an id unchanged
fn id(v: u32) -> Option<u32> {
    (v != u32::MAX).then_some(v)
}

/// sys_fchownat - change file ownership relative to directory fd
pub fn sys_fchownat(dirfd: i32, pathname: u64, owner: u32, group: u32, flags: i32) -> i64 {
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return KernelError::InvalidArgument.sysret();
    }
    ret(resolve(dirfd, pathname, flags, true)
        .and_then(|d| dac::chown(&*inode_of(&d)?, id(owner), id(group))))
}

/// sys_chown - change file ownership (follows symlinks)
pub fn sys_chown(pathname: u64, owner: u32, group: u32) -> i64 {
    sys_fchownat(AT_FDCWD, pathname, owner, group, 0)
}

/// sys_lchown - change ownership of a symbolic link (does NOT follow)
pub fn sys_lchown(pathname: u64, owner: u32, group: u32) -> i64 {
    sys_fchownat(AT_FDCWD, pathname, owner, group, AT_SYMLINK_NOFOLLOW)
}

/// sys_fchown - change file ownership by fd
pub fn sys_fchown(fd: i32, owner: u32, group: u32) -> i64 {
    ret(fd_inode(fd).and_then(|i| dac::chown(&i, id(owner), id(group))))
}

// =============================================================================
// umask syscall
// =============================================================================

/// sys_umask - set file creation mask
pub fn sys_umask(mask: u32) -> i64 {
    let new_mask = (mask & 0o7777) as u16;

    if let Some(fs) = crate::task::percpu::current_fs() {
        fs.set_umask(new_mask) as i64
    } else {
        0o022
    }
}

// =============================================================================
// Timestamp modification syscalls
// =============================================================================

/// Special nsec value: set time to current time
const UTIME_NOW: i64 = 0x3fffffff;
/// Special nsec value: don't change this time
const UTIME_OMIT: i64 = 0x3ffffffe;

/// Userspace timespec structure
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UserTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

/// Get current time from timekeeper
fn current_time() -> crate::time::Timespec {
    use crate::time::TIMEKEEPER;
    TIMEKEEPER.current_time()
}

/// Linux vfs_utimes: `times` None (or both UTIME_NOW) is a "touch" that
/// needs ownership or write permission; anything else is an explicit
/// update that needs ownership or CAP_FOWNER. `pathname` 0 means dirfd.
fn do_utimes(dirfd: i32, pathname: u64, times: Option<[UserTimespec; 2]>, flags: i32) -> i64 {
    let valid = |n: i64| (0..1_000_000_000).contains(&n) || n == UTIME_NOW || n == UTIME_OMIT;
    if let Some(t) = times
        && !(valid(t[0].tv_nsec) && valid(t[1].tv_nsec))
    {
        return KernelError::InvalidArgument.sysret();
    }
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return KernelError::InvalidArgument.sysret();
    }
    let inode = if pathname == 0 {
        if dirfd == AT_FDCWD {
            return KernelError::InvalidArgument.sysret();
        }
        fd_inode(dirfd)
    } else {
        resolve(dirfd, pathname, flags, true).and_then(|d| inode_of(&d))
    };
    let inode = match inode {
        Ok(i) => i,
        Err(e) => return e.sysret(),
    };
    let times = times.filter(|t| !(t[0].tv_nsec == UTIME_NOW && t[1].tv_nsec == UTIME_NOW));
    // vfs_utimes: write access first (EROFS), held across the update
    let _w = match dac::want_write(&inode) {
        Ok(w) => w,
        Err(e) => return e.sysret(),
    };
    if let Err(e) = dac::may_utimes(&inode, times.is_some()) {
        return e.sysret();
    }

    let now = current_time();
    let pick = |t: &UserTimespec| match t.tv_nsec {
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
    // notify_change under i_rwsem (Linux vfs_utimes: inode_lock)
    inode.inode_lock();
    if let Some(t) = atime {
        inode.set_atime(t);
    }
    if let Some(t) = mtime {
        inode.set_mtime(t);
    }
    inode.set_ctime(now);
    // SAFETY: taken above by this thread
    unsafe { inode.inode_unlock() };
    0
}

/// Copy a user array of two `T`
fn copy_pair<T: Copy + Default>(ptr: u64) -> Result<[T; 2], KernelError> {
    if !Uaccess::access_ok(ptr, core::mem::size_of::<[T; 2]>()) {
        return Err(KernelError::BadAddress);
    }
    copy_val_from_user::<Uaccess, [T; 2]>(ptr).map_err(|_| KernelError::BadAddress)
}

/// sys_utimensat - change file timestamps with nanosecond precision
pub fn sys_utimensat(dirfd: i32, pathname: u64, times: u64, flags: i32) -> i64 {
    let ts = if times == 0 {
        None
    } else {
        match copy_pair::<UserTimespec>(times) {
            Ok(t) => Some(t),
            Err(e) => return e.sysret(),
        }
    };
    // Nothing to do: not even the path is checked
    if ts.is_some_and(|t| t[0].tv_nsec == UTIME_OMIT && t[1].tv_nsec == UTIME_OMIT) {
        return 0;
    }
    do_utimes(dirfd, pathname, ts, flags)
}

/// sys_futimens - change file timestamps by fd
pub fn sys_futimens(fd: i32, times: u64) -> i64 {
    sys_utimensat(fd, 0, times, 0)
}

/// sys_utimes - change file timestamps (microsecond precision)
pub fn sys_utimes(pathname: u64, times: u64) -> i64 {
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Timeval {
        tv_sec: i64,
        tv_usec: i64,
    }
    let ts = if times == 0 {
        None
    } else {
        let tv = match copy_pair::<Timeval>(times) {
            Ok(t) => t,
            Err(e) => return e.sysret(),
        };
        if tv.iter().any(|t| !(0..1_000_000).contains(&t.tv_usec)) {
            return KernelError::InvalidArgument.sysret();
        }
        Some(tv.map(|t| UserTimespec {
            tv_sec: t.tv_sec,
            tv_nsec: t.tv_usec * 1000,
        }))
    };
    do_utimes(AT_FDCWD, pathname, ts, 0)
}

/// sys_utime - change file timestamps (second precision)
pub fn sys_utime(pathname: u64, times: u64) -> i64 {
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Utimbuf {
        actime: i64,
        modtime: i64,
    }
    let ts = if times == 0 {
        None
    } else {
        if !Uaccess::access_ok(times, core::mem::size_of::<Utimbuf>()) {
            return KernelError::BadAddress.sysret();
        }
        let b = match copy_val_from_user::<Uaccess, Utimbuf>(times) {
            Ok(v) => v,
            Err(_) => return KernelError::BadAddress.sysret(),
        };
        let at = |sec| UserTimespec {
            tv_sec: sec,
            tv_nsec: 0,
        };
        Some([at(b.actime), at(b.modtime)])
    };
    do_utimes(AT_FDCWD, pathname, ts, 0)
}
