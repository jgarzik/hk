//! File permission, ownership, and timestamp syscalls
//!
//! This module contains syscalls for checking and modifying file attributes:
//! - access, faccessat, faccessat2 (permission checking)
//! - chmod, fchmod, fchmodat, fchmodat2 (mode modification)
//! - chown, lchown, fchown, fchownat (ownership modification)
//! - umask (file creation mask)
//! - utime, utimes, utimensat, futimens (timestamp modification)

use crate::arch::Uaccess;
use crate::fs::{KernelError, LookupFlags, Path, lookup_path_at};
use crate::uaccess::{UaccessArch, strncpy_from_user};

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

/// Common helper for access/faccessat/faccessat2
fn do_faccessat(dirfd: i32, path_ptr: u64, mode: i32, flags: i32) -> i64 {
    // Validate mode - only F_OK, R_OK, W_OK, X_OK are allowed
    if mode & !(F_OK | R_OK | W_OK | X_OK) != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Validate flags
    let valid_flags = AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;
    if flags & !valid_flags != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Read path from user space
    let path_str = match strncpy_from_user::<Uaccess>(path_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Handle AT_EMPTY_PATH
    if path_str.is_empty() {
        if flags & AT_EMPTY_PATH == 0 {
            return KernelError::NotFound.sysret();
        }
        return KernelError::InvalidArgument.sysret();
    }

    // Determine starting path for relative paths
    let start: Option<Path> = if path_str.starts_with('/') {
        None
    } else if dirfd == AT_FDCWD {
        crate::task::percpu::current_cwd()
    } else {
        let file = match current_fd_table().lock().get(dirfd) {
            Some(f) => f,
            None => return KernelError::BadFd.sysret(),
        };
        if !file.is_dir() {
            return KernelError::NotDirectory.sysret();
        }
        Path::from_dentry(file.dentry.clone())
    };

    // Set up lookup flags
    let mut lookup_flags = LookupFlags::open();
    if flags & AT_SYMLINK_NOFOLLOW != 0 {
        lookup_flags.follow = false;
    }

    // Look up the path
    let dentry = match lookup_path_at(start, &path_str, lookup_flags) {
        Ok(d) => d,
        Err(KernelError::NotFound) => return KernelError::NotFound.sysret(),
        Err(KernelError::NotDirectory) => return KernelError::NotDirectory.sysret(),
        Err(KernelError::PermissionDenied) => return KernelError::PermissionDenied.sysret(),
        Err(_) => return KernelError::InvalidArgument.sysret(),
    };

    // F_OK just checks existence - path lookup succeeded
    if mode == F_OK {
        return 0;
    }

    // Get inode for permission check
    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return KernelError::NotFound.sysret(),
    };

    // Get credentials - use effective if AT_EACCESS, else real
    let cred = crate::task::percpu::current_cred();
    let (uid, gid) = if flags & AT_EACCESS != 0 {
        (cred.euid, cred.egid)
    } else {
        (cred.uid, cred.gid)
    };

    // Convert mode to permission mask
    let mut mask: u32 = 0;
    if mode & R_OK != 0 {
        mask |= super::MAY_READ;
    }
    if mode & W_OK != 0 {
        mask |= super::MAY_WRITE;
    }
    if mode & X_OK != 0 {
        mask |= super::MAY_EXEC;
    }

    // Check permissions
    match super::inode_permission(&inode, uid, gid, mask) {
        Ok(()) => 0,
        Err(_) => KernelError::PermissionDenied.sysret(),
    }
}

/// sys_access - check file access permissions
pub fn sys_access(path_ptr: u64, mode: i32) -> i64 {
    do_faccessat(AT_FDCWD, path_ptr, mode, 0)
}

/// sys_faccessat - check file access relative to directory fd
pub fn sys_faccessat(dirfd: i32, path_ptr: u64, mode: i32, flags: i32) -> i64 {
    do_faccessat(dirfd, path_ptr, mode, flags)
}

/// sys_faccessat2 - check file access (same as faccessat)
pub fn sys_faccessat2(dirfd: i32, path_ptr: u64, mode: i32, flags: i32) -> i64 {
    do_faccessat(dirfd, path_ptr, mode, flags)
}

// =============================================================================
// chmod, fchmod, fchmodat, fchmodat2 syscalls
// =============================================================================

/// Internal helper for fchmodat/fchmodat2
fn do_fchmodat(dirfd: i32, pathname: u64, mode: u32, flags: i32) -> i64 {
    const FCHMODAT_VALID_FLAGS: i32 = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;
    if (flags & !FCHMODAT_VALID_FLAGS) != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    let path_str = match strncpy_from_user::<Uaccess>(pathname, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Handle AT_EMPTY_PATH - operate on dirfd itself
    let dentry = if path_str.is_empty() && (flags & AT_EMPTY_PATH) != 0 {
        if dirfd < 0 {
            return KernelError::BadFd.sysret();
        }
        match current_fd_table().lock().get(dirfd) {
            Some(f) => f.dentry.clone(),
            None => return KernelError::BadFd.sysret(),
        }
    } else {
        let start: Option<Path> = if path_str.starts_with('/') {
            None
        } else if dirfd == AT_FDCWD {
            crate::task::percpu::current_cwd()
        } else {
            let file = match current_fd_table().lock().get(dirfd) {
                Some(f) => f,
                None => return KernelError::BadFd.sysret(),
            };
            if !file.is_dir() {
                return KernelError::NotDirectory.sysret();
            }
            Path::from_dentry(file.dentry.clone())
        };

        let lookup_flags = if (flags & AT_SYMLINK_NOFOLLOW) != 0 {
            LookupFlags {
                follow: false,
                ..LookupFlags::open()
            }
        } else {
            LookupFlags::open()
        };

        match lookup_path_at(start, &path_str, lookup_flags) {
            Ok(d) => d,
            Err(KernelError::NotFound) => return KernelError::NotFound.sysret(),
            Err(KernelError::NotDirectory) => return KernelError::NotDirectory.sysret(),
            Err(_) => return KernelError::InvalidArgument.sysret(),
        }
    };

    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return KernelError::NotFound.sysret(),
    };

    inode.set_mode_perm((mode & 0o7777) as u16);
    0
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

/// sys_fchmod - change file permissions by fd
pub fn sys_fchmod(fd: i32, mode: u32) -> i64 {
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    let inode = match file.get_inode() {
        Some(i) => i,
        None => return KernelError::BadFd.sysret(),
    };

    inode.set_mode_perm((mode & 0o7777) as u16);
    0
}

// =============================================================================
// chown, lchown, fchown, fchownat syscalls
// =============================================================================

/// sys_fchownat - change file ownership relative to directory fd
pub fn sys_fchownat(dirfd: i32, pathname: u64, owner: u32, group: u32, flags: i32) -> i64 {
    let path_str = match strncpy_from_user::<Uaccess>(pathname, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    let start: Option<Path> = if path_str.starts_with('/') {
        None
    } else if dirfd == AT_FDCWD {
        crate::task::percpu::current_cwd()
    } else {
        let file = match current_fd_table().lock().get(dirfd) {
            Some(f) => f,
            None => return KernelError::BadFd.sysret(),
        };
        if !file.is_dir() {
            return KernelError::NotDirectory.sysret();
        }
        Path::from_dentry(file.dentry.clone())
    };

    let lookup_flags = if (flags & AT_SYMLINK_NOFOLLOW) != 0 {
        LookupFlags {
            follow: false,
            ..LookupFlags::open()
        }
    } else {
        LookupFlags::open()
    };

    let dentry = match lookup_path_at(start, &path_str, lookup_flags) {
        Ok(d) => d,
        Err(KernelError::NotFound) => return KernelError::NotFound.sysret(),
        Err(KernelError::NotDirectory) => return KernelError::NotDirectory.sysret(),
        Err(_) => return KernelError::InvalidArgument.sysret(),
    };

    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return KernelError::NotFound.sysret(),
    };

    if owner != 0xFFFFFFFF {
        inode.set_uid(owner);
    }
    if group != 0xFFFFFFFF {
        inode.set_gid(group);
    }

    0
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
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    let inode = match file.get_inode() {
        Some(i) => i,
        None => return KernelError::BadFd.sysret(),
    };

    if owner != 0xFFFFFFFF {
        inode.set_uid(owner);
    }
    if group != 0xFFFFFFFF {
        inode.set_gid(group);
    }

    0
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
struct UserTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

/// Get current time from timekeeper
fn current_time() -> crate::time::Timespec {
    use crate::time::TIMEKEEPER;
    TIMEKEEPER.current_time()
}

/// sys_utimensat - change file timestamps with nanosecond precision
pub fn sys_utimensat(dirfd: i32, pathname: u64, times: u64, flags: i32) -> i64 {
    let inode = if pathname == 0 {
        if dirfd == AT_FDCWD {
            return KernelError::InvalidArgument.sysret();
        }
        let file = match current_fd_table().lock().get(dirfd) {
            Some(f) => f,
            None => return KernelError::BadFd.sysret(),
        };
        match file.get_inode() {
            Some(i) => i,
            None => return KernelError::BadFd.sysret(),
        }
    } else {
        let path_str = match strncpy_from_user::<Uaccess>(pathname, PATH_MAX) {
            Ok(p) => p,
            Err(_) => return KernelError::BadAddress.sysret(),
        };

        let start: Option<Path> = if path_str.starts_with('/') {
            None
        } else if dirfd == AT_FDCWD {
            crate::task::percpu::current_cwd()
        } else {
            let file = match current_fd_table().lock().get(dirfd) {
                Some(f) => f,
                None => return KernelError::BadFd.sysret(),
            };
            if !file.is_dir() {
                return KernelError::NotDirectory.sysret();
            }
            Path::from_dentry(file.dentry.clone())
        };

        let lookup_flags = if (flags & AT_SYMLINK_NOFOLLOW) != 0 {
            LookupFlags {
                follow: false,
                ..LookupFlags::open()
            }
        } else {
            LookupFlags::open()
        };

        let dentry = match lookup_path_at(start, &path_str, lookup_flags) {
            Ok(d) => d,
            Err(KernelError::NotFound) => return KernelError::NotFound.sysret(),
            Err(KernelError::NotDirectory) => return KernelError::NotDirectory.sysret(),
            Err(_) => return KernelError::InvalidArgument.sysret(),
        };

        match dentry.get_inode() {
            Some(i) => i,
            None => return KernelError::NotFound.sysret(),
        }
    };

    let now = current_time();

    let (new_atime, new_mtime) = if times == 0 {
        (Some(now), Some(now))
    } else {
        let size = core::mem::size_of::<[UserTimespec; 2]>();
        if !Uaccess::access_ok(times, size) {
            return KernelError::BadAddress.sysret();
        }
        let ts: [UserTimespec; 2] = unsafe {
            Uaccess::user_access_begin();
            let val = core::ptr::read(times as *const [UserTimespec; 2]);
            Uaccess::user_access_end();
            val
        };

        let atime = if ts[0].tv_nsec == UTIME_OMIT {
            None
        } else if ts[0].tv_nsec == UTIME_NOW {
            Some(now)
        } else {
            Some(crate::time::Timespec {
                sec: ts[0].tv_sec,
                nsec: ts[0].tv_nsec as u32,
            })
        };

        let mtime = if ts[1].tv_nsec == UTIME_OMIT {
            None
        } else if ts[1].tv_nsec == UTIME_NOW {
            Some(now)
        } else {
            Some(crate::time::Timespec {
                sec: ts[1].tv_sec,
                nsec: ts[1].tv_nsec as u32,
            })
        };

        (atime, mtime)
    };

    {
        let _guard = inode.lock.write();
        if let Some(atime) = new_atime {
            inode.set_atime(atime);
        }
        if let Some(mtime) = new_mtime {
            inode.set_mtime(mtime);
        }
        inode.set_ctime(now);
    }

    0
}

/// sys_futimens - change file timestamps by fd
pub fn sys_futimens(fd: i32, times: u64) -> i64 {
    sys_utimensat(fd, 0, times, 0)
}

/// sys_utimes - change file timestamps (microsecond precision)
pub fn sys_utimes(pathname: u64, times: u64) -> i64 {
    if times == 0 {
        return sys_utimensat(AT_FDCWD, pathname, 0, 0);
    }

    #[repr(C)]
    struct Timeval {
        tv_sec: i64,
        tv_usec: i64,
    }

    let size = core::mem::size_of::<[Timeval; 2]>();
    if !Uaccess::access_ok(times, size) {
        return KernelError::BadAddress.sysret();
    }
    let tv: [Timeval; 2] = unsafe {
        Uaccess::user_access_begin();
        let val = core::ptr::read(times as *const [Timeval; 2]);
        Uaccess::user_access_end();
        val
    };

    let ts: [UserTimespec; 2] = [
        UserTimespec {
            tv_sec: tv[0].tv_sec,
            tv_nsec: tv[0].tv_usec * 1000,
        },
        UserTimespec {
            tv_sec: tv[1].tv_sec,
            tv_nsec: tv[1].tv_usec * 1000,
        },
    ];

    let path_str = match strncpy_from_user::<Uaccess>(pathname, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    let start = crate::task::percpu::current_cwd();
    let dentry = match lookup_path_at(start, &path_str, LookupFlags::open()) {
        Ok(d) => d,
        Err(KernelError::NotFound) => return KernelError::NotFound.sysret(),
        Err(KernelError::NotDirectory) => return KernelError::NotDirectory.sysret(),
        Err(_) => return KernelError::InvalidArgument.sysret(),
    };

    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return KernelError::NotFound.sysret(),
    };

    let now = current_time();

    {
        let _guard = inode.lock.write();
        inode.set_atime(crate::time::Timespec {
            sec: ts[0].tv_sec,
            nsec: ts[0].tv_nsec as u32,
        });
        inode.set_mtime(crate::time::Timespec {
            sec: ts[1].tv_sec,
            nsec: ts[1].tv_nsec as u32,
        });
        inode.set_ctime(now);
    }

    0
}

/// sys_utime - change file timestamps (second precision)
pub fn sys_utime(pathname: u64, times: u64) -> i64 {
    if times == 0 {
        return sys_utimensat(AT_FDCWD, pathname, 0, 0);
    }

    #[repr(C)]
    struct Utimbuf {
        actime: i64,
        modtime: i64,
    }

    let size = core::mem::size_of::<Utimbuf>();
    if !Uaccess::access_ok(times, size) {
        return KernelError::BadAddress.sysret();
    }
    let buf: Utimbuf = unsafe {
        Uaccess::user_access_begin();
        let val = core::ptr::read(times as *const Utimbuf);
        Uaccess::user_access_end();
        val
    };

    let path_str = match strncpy_from_user::<Uaccess>(pathname, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    let start = crate::task::percpu::current_cwd();
    let dentry = match lookup_path_at(start, &path_str, LookupFlags::open()) {
        Ok(d) => d,
        Err(KernelError::NotFound) => return KernelError::NotFound.sysret(),
        Err(KernelError::NotDirectory) => return KernelError::NotDirectory.sysret(),
        Err(_) => return KernelError::InvalidArgument.sysret(),
    };

    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return KernelError::NotFound.sysret(),
    };

    let now = current_time();

    {
        let _guard = inode.lock.write();
        inode.set_atime(crate::time::Timespec::from_secs(buf.actime));
        inode.set_mtime(crate::time::Timespec::from_secs(buf.modtime));
        inode.set_ctime(now);
    }

    0
}
