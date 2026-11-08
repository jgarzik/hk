//! File descriptor manipulation syscalls
//!
//! This module contains syscalls for file descriptor operations:
//! - dup, dup2, dup3 (file descriptor duplication)
//! - fcntl (file control operations)
//! - truncate, ftruncate (file size modification)
//! - pipe, pipe2 (pipe creation)

use alloc::sync::Arc;

use crate::arch::Uaccess;
use crate::fs::{KernelError, LookupFlags};
use crate::task::percpu::current_tid;
use crate::uaccess::{copy_val_from_user, copy_val_to_user, put_user};

use super::file::File;
use super::posix_lock::{Flock, posix_getlk, posix_setlk, posix_setlkw};
use super::syscall::{current_fd_table, get_nofile_limit};

// =============================================================================
// truncate, ftruncate syscalls
// =============================================================================

/// Helper to perform truncate on an inode with RLIMIT and error handling.
/// `times` (ftruncate: Linux ATTR_MTIME | ATTR_CTIME): mtime and ctime
/// are set even when the size stays; without it only a size change
/// sets them (the file system's setattr, as ext4, tmpfs and vfat).
fn do_truncate(inode: &Arc<super::Inode>, length: u64, times: bool) -> i64 {
    // Check RLIMIT_FSIZE when extending the file
    let current_size = inode.get_size();
    // RLIMIT_FSIZE (SIGXFSZ), then the filesystem's largest file (Linux
    // inode_newsize_ok's order)
    if length > current_size {
        let limit = crate::task::rlimit::rlimit(crate::task::rlimit::RLIMIT_FSIZE);
        if limit != crate::task::rlimit::RLIM_INFINITY && length > limit {
            let tid = current_tid();
            crate::signal::send_signal(tid, crate::signal::SIGXFSZ);
            return KernelError::FileTooLarge.sysret();
        }
        if length > inode.maxbytes() {
            return KernelError::FileTooLarge.sysret();
        }
    }

    // Write access first (Linux vfs_truncate / do_sys_ftruncate):
    // ETXTBSY while the file runs
    let _w = match inode.get_write_access() {
        Ok(w) => w,
        Err(e) => return e.sysret(),
    };
    // Under i_rwsem, like Linux do_truncate: atomic with writes; an
    // active swap area (set by swapon under i_rwsem) is ETXTBSY
    let lock = inode.lock();
    let r = if inode.i_swapfile.load(core::sync::atomic::Ordering::Acquire) {
        Err(KernelError::TextBusy)
    } else {
        // The set-id kill with the size change (Linux do_truncate:
        // ATTR_KILL_* in the same notify_change)
        super::dac::remove_privs(inode);
        let changed = inode.get_size() != length;
        inode.i_op.truncate(inode, length).inspect(|()| {
            if times || changed {
                inode.touch_mc();
            }
        })
    };
    drop(lock);
    match r {
        Ok(()) => 0,
        Err(KernelError::IsDirectory) => KernelError::IsDirectory.sysret(),
        Err(KernelError::OperationNotSupported) => KernelError::InvalidArgument.sysret(),
        Err(KernelError::PermissionDenied) => KernelError::PermissionDenied.sysret(),
        Err(KernelError::FileTooLarge) => KernelError::FileTooLarge.sysret(),
        Err(KernelError::TextBusy) => KernelError::TextBusy.sysret(),
        Err(_) => KernelError::InvalidArgument.sysret(),
    }
}

/// sys_ftruncate - truncate a file to a specified length
///
/// Truncates the file referred to by fd to the specified length.
/// If the file was larger, the extra data is discarded.
/// If the file was shorter, it is extended with null bytes.
///
/// # Arguments
/// * `fd` - File descriptor (must be open for writing)
/// * `length` - New file length
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_ftruncate(fd: i32, length: i64) -> i64 {
    if length < 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Get file from fd table
    let Some(file) = current_fd_table().lock().get(fd) else {
        return KernelError::BadFd.sysret();
    };

    // Get the inode
    let Some(inode) = file.get_inode() else {
        return KernelError::BadFd.sysret();
    };

    // Linux do_ftruncate: a regular file open for writing, else EINVAL
    if !file.is_writable() || !inode.mode().is_file() {
        return KernelError::InvalidArgument.sysret();
    }

    do_truncate(&inode, length as u64, true)
}

/// sys_truncate - truncate a file to a specified length by path
///
/// # Arguments
/// * `path_ptr` - User pointer to path string
/// * `length` - New file length
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_truncate(path_ptr: u64, length: i64) -> i64 {
    if length < 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Read path from user space
    let path = match crate::fs::namei::getname(path_ptr, false) {
        Ok(p) => p,
        Err(e) => return e.sysret(),
    };

    if path.is_empty() {
        return KernelError::NotFound.sysret();
    }

    // Look up the file (follow symlinks for truncate)
    let fpath = match crate::fs::namei::path_lookupat(
        crate::task::percpu::current_cwd(),
        &path,
        LookupFlags::open(),
    ) {
        Ok(p) => p,
        Err(e) => return e.sysret(),
    };
    let dentry = fpath.dentry.clone();

    // Get the inode
    let Some(inode) = dentry.get_inode() else {
        return KernelError::NotFound.sysret();
    };

    // vfs_truncate: EISDIR / EINVAL, write access (EROFS), write
    // permission, then set-id removal
    let m = inode.mode();
    if m.is_dir() {
        return KernelError::IsDirectory.sysret();
    }
    if !m.is_file() {
        return KernelError::InvalidArgument.sysret();
    }
    let _w = match fpath.mnt.want_write() {
        Ok(w) => w,
        Err(e) => return e.sysret(),
    };
    if let Err(e) = super::dac::may_truncate(&inode) {
        return e.sysret();
    }
    do_truncate(&inode, length as u64, false)
}

// =============================================================================
// dup, dup2, dup3 syscalls
// =============================================================================

/// sys_dup - duplicate a file descriptor
///
/// Creates a copy of the file descriptor oldfd, using the lowest-numbered
/// unused file descriptor for the new descriptor.
///
/// # Arguments
/// * `oldfd` - File descriptor to duplicate
///
/// # Returns
/// New file descriptor on success, negative errno on error.
pub fn sys_dup(oldfd: i32) -> i64 {
    let fd_table = current_fd_table();
    let mut table = fd_table.lock();
    let Some(file) = table.get(oldfd) else {
        return KernelError::BadFd.sysret();
    };

    // Allocate fd (RLIMIT_NOFILE enforced inside alloc)
    match table.alloc(file, get_nofile_limit()) {
        Ok(newfd) => i64::from(newfd),
        Err(e) => -i64::from(e),
    }
}

/// sys_dup2 - duplicate a file descriptor to a specific number
///
/// Makes newfd be a copy of oldfd, closing newfd first if necessary.
/// If oldfd == newfd, just checks that oldfd is valid.
///
/// # Arguments
/// * `oldfd` - File descriptor to duplicate
/// * `newfd` - Target file descriptor number
///
/// # Returns
/// newfd on success, negative errno on error.
pub fn sys_dup2(oldfd: i32, newfd: i32) -> i64 {
    // If oldfd == newfd, just verify oldfd is valid
    if oldfd == newfd {
        let fd_table = current_fd_table();
        let table = fd_table.lock();
        return if table.is_valid(oldfd) {
            i64::from(newfd)
        } else {
            KernelError::BadFd.sysret()
        };
    }
    dup_to(oldfd, newfd, 0)
}

/// sys_dup3 - duplicate a file descriptor with flags
///
/// Like dup2, but with additional flags. Currently only O_CLOEXEC is supported.
/// Unlike dup2, returns EINVAL if oldfd == newfd.
///
/// # Arguments
/// * `oldfd` - File descriptor to duplicate
/// * `newfd` - Target file descriptor number
/// * `flags` - Flags (only O_CLOEXEC supported)
///
/// # Returns
/// newfd on success, negative errno on error.
pub fn sys_dup3(oldfd: i32, newfd: i32, flags: u32) -> i64 {
    // Only O_CLOEXEC is valid for dup3
    if flags & !super::file::flags::O_CLOEXEC != 0 {
        return KernelError::InvalidArgument.sysret();
    }
    // dup3 requires oldfd != newfd (unlike dup2)
    if oldfd == newfd {
        return KernelError::InvalidArgument.sysret();
    }
    let fd_flags = if flags & super::file::flags::O_CLOEXEC != 0 {
        crate::task::FD_CLOEXEC
    } else {
        0
    };
    dup_to(oldfd, newfd, fd_flags)
}

/// Make `newfd` a copy of `oldfd` (Linux ksys_dup3 + do_dup2): a newfd
/// at or past RLIMIT_NOFILE or fs.nr_open is EBADF, and every check,
/// including room for newfd, comes before newfd is closed
fn dup_to(oldfd: i32, newfd: i32, fd_flags: u32) -> i64 {
    let nofile = get_nofile_limit();
    // Linux takes newfd unsigned: a negative one is past any limit
    if u64::from(newfd as u32) >= nofile {
        return KernelError::BadFd.sysret();
    }
    let fd_table = current_fd_table();
    let mut table = fd_table.lock();
    let room = table.expand(newfd);
    let Some(file) = table.get(oldfd) else {
        return KernelError::BadFd.sysret();
    };
    match room {
        Ok(()) => {}
        Err(24) => return KernelError::BadFd.sysret(), // EMFILE
        Err(e) => return -i64::from(e),
    }
    table.close(newfd);
    match table.alloc_at_with_flags(newfd, file, fd_flags, nofile) {
        Ok(()) => i64::from(newfd),
        Err(e) => -i64::from(e),
    }
}

// =============================================================================
// pipe, pipe2 syscalls
// =============================================================================

/// pipe - create a pipe
///
/// Creates a pipe, a unidirectional data channel that can be used for
/// interprocess communication. The array pipefd is used to return two
/// file descriptors referring to the ends of the pipe.
///
/// # Arguments
/// * `pipefd` - Pointer to int[2] array. pipefd[0] = read end, pipefd[1] = write end
///
/// # Returns
/// * 0 on success
/// * -EFAULT if pipefd is invalid
/// * -EMFILE if too many file descriptors
pub fn sys_pipe(pipefd: u64) -> i64 {
    sys_pipe2(pipefd, 0)
}

/// pipe2 - create a pipe with flags
///
/// Like pipe(), but additionally allows flags to be specified.
///
/// # Arguments
/// * `pipefd` - Pointer to int[2] array
/// * `flags` - O_CLOEXEC | O_NONBLOCK
///
/// # Returns
/// * 0 on success
/// * -EFAULT if pipefd is invalid
/// * -EINVAL if invalid flags
/// * -EMFILE if too many file descriptors
pub fn sys_pipe2(pipefd: u64, flags: u32) -> i64 {
    use crate::fs::file::flags::{O_CLOEXEC, O_NONBLOCK};
    use crate::io::pipe::{FD_CLOEXEC, create_pipe};

    // Validate flags - only O_CLOEXEC and O_NONBLOCK are allowed
    const VALID_FLAGS: u32 = O_CLOEXEC | O_NONBLOCK;
    if flags & !VALID_FLAGS != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Validate user pointer
    if pipefd == 0 {
        return KernelError::BadAddress.sysret();
    }

    // Create the pipe
    let Ok((read_file, write_file)) = create_pipe(flags & O_NONBLOCK) else {
        return KernelError::OutOfMemory.sysret();
    };

    // Allocate file descriptors (RLIMIT_NOFILE enforced inside alloc)
    // Following Linux pattern: each get_unused_fd_flags() call checks limit
    let fd_table = current_fd_table();
    let mut table = fd_table.lock();
    let nofile = get_nofile_limit();

    // Determine fd flags
    let fd_flags = if flags & O_CLOEXEC != 0 {
        FD_CLOEXEC
    } else {
        0
    };

    let read_fd = match table.alloc_with_flags(read_file, fd_flags, nofile) {
        Ok(fd) => fd,
        Err(e) => return -i64::from(e),
    };

    let write_fd = match table.alloc_with_flags(write_file, fd_flags, nofile) {
        Ok(fd) => fd,
        Err(e) => {
            // Clean up read fd on failure
            table.close(read_fd);
            return -i64::from(e);
        }
    };

    drop(table);

    // Write file descriptors to user space
    match put_user::<Uaccess, [i32; 2]>(pipefd, [read_fd, write_fd]) {
        Ok(()) => 0,
        Err(_) => {
            // Clean up on error
            let mut table = fd_table.lock();
            table.close(read_fd);
            table.close(write_fd);
            KernelError::BadAddress.sysret()
        }
    }
}

// =============================================================================
// fcntl syscall
// =============================================================================

/// fcntl command constants
mod fcntl_cmd {
    pub const F_DUPFD: i32 = 0;
    pub const F_GETFD: i32 = 1;
    pub const F_SETFD: i32 = 2;
    pub const F_GETFL: i32 = 3;
    pub const F_SETFL: i32 = 4;
    // POSIX advisory lock commands
    pub const F_GETLK: i32 = 5;
    pub const F_SETLK: i32 = 6;
    pub const F_SETLKW: i32 = 7;
    // Async I/O owner commands
    pub const F_SETOWN: i32 = 8;
    pub const F_GETOWN: i32 = 9;
    pub const F_SETSIG: i32 = 10;
    pub const F_GETSIG: i32 = 11;
    pub const F_SETOWN_EX: i32 = 15;
    pub const F_GETOWN_EX: i32 = 16;
    pub const F_DUPFD_CLOEXEC: i32 = 1030;
}

/// Lock `flock` was just set through `fd`: if a close (by another
/// thread) took the descriptor away meanwhile, its release came too
/// early, so that range is unlocked now; the process's other locks
/// stay (Linux fcntl_setlk rechecks with files_lookup_fd and sets
/// F_UNLCK over the same, already resolved, region)
fn setlk_recheck(fd: i32, file: &Arc<crate::fs::File>, flock: &Flock, range: (u64, u64)) {
    use crate::fs::posix_lock::{F_UNLCK, posix_unlock};
    let same = current_fd_table()
        .lock()
        .get(fd)
        .is_some_and(|f| Arc::ptr_eq(&f, file));
    if !same && flock.l_type != F_UNLCK {
        posix_unlock(file, range);
    }
}

/// sys_fcntl - file control operations
///
/// Performs various operations on file descriptors.
///
/// # Arguments
/// * `fd` - File descriptor to operate on
/// * `cmd` - Operation to perform (F_DUPFD, F_GETFD, etc.)
/// * `arg` - Optional argument (meaning depends on cmd)
///
/// # Returns
/// * F_DUPFD/F_DUPFD_CLOEXEC: new fd on success
/// * F_GETFD: fd flags (FD_CLOEXEC)
/// * F_GETFL: file status flags
/// * F_SETFD/F_SETFL: 0 on success
/// * negative errno on error
pub fn sys_fcntl(fd: i32, cmd: i32, arg: u64) -> i64 {
    use fcntl_cmd::*;

    let fd_table = current_fd_table();
    let mut table = fd_table.lock();

    let nofile = get_nofile_limit();

    match cmd {
        F_DUPFD => {
            // Duplicate fd to lowest available >= arg
            let Some(file) = table.get(fd) else {
                return KernelError::BadFd.sysret();
            };
            let min_fd = arg as i32;
            if min_fd < 0 {
                return KernelError::InvalidArgument.sysret();
            }
            // Linux: if (from >= nofile) return -EINVAL
            if (min_fd as u64) >= nofile {
                return KernelError::InvalidArgument.sysret();
            }
            // RLIMIT_NOFILE enforced inside alloc_at_or_above
            match table.alloc_at_or_above(file, min_fd, 0, nofile) {
                Ok(new_fd) => i64::from(new_fd),
                Err(e) => -i64::from(e),
            }
        }

        F_DUPFD_CLOEXEC => {
            // Duplicate fd with FD_CLOEXEC set
            let Some(file) = table.get(fd) else {
                return KernelError::BadFd.sysret();
            };
            let min_fd = arg as i32;
            if min_fd < 0 {
                return KernelError::InvalidArgument.sysret();
            }
            // Linux: if (from >= nofile) return -EINVAL
            if (min_fd as u64) >= nofile {
                return KernelError::InvalidArgument.sysret();
            }
            // RLIMIT_NOFILE enforced inside alloc_at_or_above
            match table.alloc_at_or_above(file, min_fd, crate::task::FD_CLOEXEC, nofile) {
                Ok(new_fd) => i64::from(new_fd),
                Err(e) => -i64::from(e),
            }
        }

        F_GETFD => {
            // Get fd flags (FD_CLOEXEC)
            if !table.is_valid(fd) {
                return KernelError::BadFd.sysret();
            }
            i64::from(table.get_fd_flags(fd))
        }

        F_SETFD => {
            // Set fd flags (only FD_CLOEXEC is valid)
            if !table.set_fd_flags(fd, arg as u32) {
                return KernelError::BadFd.sysret();
            }
            0
        }

        F_GETFL => {
            // Get file status flags
            let Some(file) = table.get(fd) else {
                return KernelError::BadFd.sysret();
            };
            i64::from(file.get_flags())
        }

        F_SETFL => {
            let Some(file) = table.get(fd) else {
                return KernelError::BadFd.sysret();
            };
            // ->fasync takes sleeping locks
            drop(table);
            match setfl(fd, &file, arg as u32) {
                Ok(()) => 0,
                Err(e) => e.sysret(),
            }
        }

        F_GETLK => {
            // Get lock info - test if a lock would block
            let Some(file) = table.get(fd) else {
                return KernelError::BadFd.sysret();
            };
            drop(table); // Release FD table lock before copying

            // Copy flock from user
            let Ok(mut flock) = copy_val_from_user::<Uaccess, Flock>(arg) else {
                return KernelError::BadAddress.sysret();
            };

            // Do the getlk
            if let Err(e) = posix_getlk(&file, &mut flock) {
                return e.sysret();
            }

            // Copy result back
            if copy_val_to_user::<Uaccess, Flock>(arg, &flock).is_err() {
                return KernelError::BadAddress.sysret();
            }

            0
        }

        F_SETLK => {
            // Set lock (non-blocking)
            let Some(file) = table.get(fd) else {
                return KernelError::BadFd.sysret();
            };
            drop(table);

            // Copy flock from user
            let Ok(flock) = copy_val_from_user::<Uaccess, Flock>(arg) else {
                return KernelError::BadAddress.sysret();
            };

            match posix_setlk(&file, &flock) {
                Ok(range) => {
                    setlk_recheck(fd, &file, &flock, range);
                    0
                }
                Err(e) => e.sysret(),
            }
        }

        F_SETLKW => {
            // Set lock (blocking - but we don't actually block, like flock)
            let Some(file) = table.get(fd) else {
                return KernelError::BadFd.sysret();
            };
            drop(table);

            // Copy flock from user
            let Ok(flock) = copy_val_from_user::<Uaccess, Flock>(arg) else {
                return KernelError::BadAddress.sysret();
            };

            match posix_setlkw(&file, &flock) {
                Ok(range) => {
                    setlk_recheck(fd, &file, &flock, range);
                    0
                }
                Err(e) => e.sysret(),
            }
        }

        F_SETOWN | F_GETOWN | F_SETOWN_EX | F_GETOWN_EX | F_SETSIG | F_GETSIG => {
            let Some(file) = table.get(fd) else {
                return KernelError::BadFd.sysret();
            };
            // They allocate and copy to and from the user
            drop(table);
            fcntl_owner(&file, cmd, arg)
        }

        _ => KernelError::InvalidArgument.sysret(),
    }
}

/// Linux setfl: O_NOATIME needs the owner or CAP_FOWNER; a change of
/// O_ASYNC goes through ->fasync, which sets the bit (a file without one
/// keeps it clear), before the other flags change
fn setfl(fd: i32, file: &File, arg: u32) -> Result<(), KernelError> {
    use crate::fs::flags::O_ASYNC;
    let noatime = super::dac::O_NOATIME;
    if arg & noatime != 0
        && file.get_flags() & noatime == 0
        && !file
            .get_inode()
            .is_some_and(|i| super::dac::owner_or_capable(&super::dac::cred(), &i))
    {
        return Err(KernelError::NotPermitted);
    }
    if (arg ^ file.get_flags()) & O_ASYNC != 0
        && let Some(r) = file.fasync(fd, arg & O_ASYNC != 0)
    {
        r?;
    }
    file.set_status_flags(arg);
    Ok(())
}

/// The SIGIO owner commands (Linux do_fcntl); F_GETOWN of a process
/// group is negative, returned as a value, not an error
fn fcntl_owner(file: &File, cmd: i32, arg: u64) -> i64 {
    use crate::io::fasync;
    use fcntl_cmd::*;
    let r = match cmd {
        F_SETOWN => fasync::f_setown(file, arg as i32, true),
        F_GETOWN => return i64::from(fasync::f_getown(file)),
        F_SETOWN_EX => fasync::f_setown_ex(file, arg),
        F_GETOWN_EX => fasync::f_getown_ex(file, arg),
        F_SETSIG => fasync::f_setsig(file, arg),
        _ => return i64::from(fasync::f_getsig(file)),
    };
    match r {
        Ok(()) => 0,
        Err(e) => e.sysret(),
    }
}
