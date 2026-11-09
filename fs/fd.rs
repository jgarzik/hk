//! File descriptor manipulation syscalls
//!
//! This module contains syscalls for file descriptor operations:
//! - dup, dup2, dup3 (file descriptor duplication)
//! - fcntl (file control operations)
//! - truncate, ftruncate (file size modification)
//! - pipe, pipe2 (pipe creation)

use alloc::sync::Arc;

use crate::fs::{KernelError, LookupFlags};
use crate::uaccess::UserPtr;
use crate::util::error::KernelResult;

use super::file::File;
use super::io::fget;
use super::posix_lock::{Flock, posix_getlk, posix_setlk, posix_setlkw};
use super::syscall::{current_fd_table, get_nofile_limit};

// =============================================================================
// truncate, ftruncate syscalls
// =============================================================================

/// Helper to perform truncate on an inode with RLIMIT and error handling.
/// `times` (ftruncate: Linux ATTR_MTIME | ATTR_CTIME): mtime and ctime
/// are set even when the size stays; without it only a size change
/// sets them (the file system's setattr, as ext4, tmpfs and vfat).
fn do_truncate(inode: &Arc<super::Inode>, length: u64, times: bool) -> KernelResult<()> {
    // Check RLIMIT_FSIZE when extending the file
    let current_size = inode.get_size();
    // RLIMIT_FSIZE (SIGXFSZ), then the filesystem's largest file (Linux
    // inode_newsize_ok's order)
    if length > current_size {
        let limit = crate::task::rlimit::rlimit(crate::task::rlimit::RLIMIT_FSIZE);
        if limit != crate::task::rlimit::RLIM_INFINITY && length > limit {
            let _ =
                crate::signal::send_signal(&crate::task::percpu::current(), crate::signal::SIGXFSZ);
            return Err(KernelError::FileTooLarge);
        }
        if length > inode.maxbytes() {
            return Err(KernelError::FileTooLarge);
        }
    }

    // Write access first (Linux vfs_truncate / do_sys_ftruncate):
    // ETXTBSY while the file runs
    let _w = inode.get_write_access()?;
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
    // A file system without truncate: EINVAL; else its own error (Linux
    // do_truncate returns notify_change's)
    r.map_err(|e| match e {
        KernelError::OperationNotSupported => KernelError::InvalidArgument,
        e => e,
    })
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
pub fn sys_ftruncate(fd: i32, length: i64) -> KernelResult<()> {
    if length < 0 {
        return Err(KernelError::InvalidArgument);
    }
    let file = fget(fd)?;
    let inode = file.get_inode().ok_or(KernelError::BadFd)?;

    // Linux do_ftruncate: a regular file open for writing, else EINVAL
    if !file.is_writable() || !inode.mode().is_file() {
        return Err(KernelError::InvalidArgument);
    }

    do_truncate(&inode, length as u64, true)
}

/// sys_truncate - truncate a file to a specified length by path
///
/// # Arguments
/// * `path_ptr` - User pointer to path string
/// * `length` - New file length
///
pub fn sys_truncate(path_ptr: UserPtr<u8>, length: i64) -> KernelResult<()> {
    if length < 0 {
        return Err(KernelError::InvalidArgument);
    }
    let path = crate::fs::namei::getname(path_ptr, false)?;

    // Look up the file (follow symlinks for truncate)
    let fpath = crate::fs::namei::path_lookupat(
        crate::task::percpu::current_cwd(),
        &path,
        LookupFlags::open(),
    )?;
    let inode = fpath.dentry.get_inode().ok_or(KernelError::NotFound)?;

    // vfs_truncate: EISDIR / EINVAL, write access (EROFS), write
    // permission, then set-id removal
    let m = inode.mode();
    if m.is_dir() {
        return Err(KernelError::IsDirectory);
    }
    if !m.is_file() {
        return Err(KernelError::InvalidArgument);
    }
    let _w = fpath.mnt.want_write()?;
    super::dac::may_truncate(&inode)?;
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
/// The new file descriptor
pub fn sys_dup(oldfd: i32) -> KernelResult<i32> {
    let fd_table = current_fd_table();
    let mut table = fd_table.lock();
    let file = table.get(oldfd).ok_or(KernelError::BadFd)?;

    // Allocate fd (RLIMIT_NOFILE enforced inside alloc)
    table.alloc(file, get_nofile_limit())
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
/// newfd
pub fn sys_dup2(oldfd: i32, newfd: i32) -> KernelResult<i32> {
    // If oldfd == newfd, just verify oldfd is valid
    if oldfd == newfd {
        return if current_fd_table().lock().is_valid(oldfd) {
            Ok(newfd)
        } else {
            Err(KernelError::BadFd)
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
/// newfd
pub fn sys_dup3(oldfd: i32, newfd: i32, flags: u32) -> KernelResult<i32> {
    // Only O_CLOEXEC is valid for dup3; dup3 requires oldfd != newfd
    // (unlike dup2)
    if flags & !super::file::flags::O_CLOEXEC != 0 || oldfd == newfd {
        return Err(KernelError::InvalidArgument);
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
fn dup_to(oldfd: i32, newfd: i32, fd_flags: u32) -> KernelResult<i32> {
    let nofile = get_nofile_limit();
    // Linux takes newfd unsigned: a negative one is past any limit
    if u64::from(newfd as u32) >= nofile {
        return Err(KernelError::BadFd);
    }
    let fd_table = current_fd_table();
    let mut table = fd_table.lock();
    let room = table.expand(newfd);
    let file = table.get(oldfd).ok_or(KernelError::BadFd)?;
    // Past fs.nr_open: EBADF, not EMFILE (Linux ksys_dup3)
    room.map_err(|e| match e {
        KernelError::ProcessFileLimit => KernelError::BadFd,
        e => e,
    })?;
    table.close(newfd);
    table.alloc_at_with_flags(newfd, file, fd_flags, nofile)?;
    Ok(newfd)
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
pub fn sys_pipe(pipefd: UserPtr<[i32; 2]>) -> KernelResult<()> {
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
pub fn sys_pipe2(pipefd: UserPtr<[i32; 2]>, flags: u32) -> KernelResult<()> {
    use crate::fs::file::flags::{O_CLOEXEC, O_NONBLOCK};
    use crate::io::pipe::{FD_CLOEXEC, create_pipe};

    // Validate flags - only O_CLOEXEC and O_NONBLOCK are allowed
    const VALID_FLAGS: u32 = O_CLOEXEC | O_NONBLOCK;
    if flags & !VALID_FLAGS != 0 {
        return Err(KernelError::InvalidArgument);
    }

    // Validate user pointer
    if pipefd.is_null() {
        return Err(KernelError::BadAddress);
    }

    let (read_file, write_file) = create_pipe(flags & O_NONBLOCK)?;

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

    let read_fd = table.alloc_with_flags(read_file, fd_flags, nofile)?;

    let write_fd = match table.alloc_with_flags(write_file, fd_flags, nofile) {
        Ok(fd) => fd,
        Err(e) => {
            // Clean up read fd on failure
            table.close(read_fd);
            return Err(e);
        }
    };

    drop(table);

    // Write file descriptors to user space
    pipefd.write(&[read_fd, write_fd]).map_err(|e| {
        // Clean up on error
        let mut table = fd_table.lock();
        table.close(read_fd);
        table.close(write_fd);
        e.into()
    })
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
/// # Returns
/// * F_DUPFD/F_DUPFD_CLOEXEC: the new fd
/// * F_GETFD: fd flags (FD_CLOEXEC)
/// * F_GETFL: file status flags
/// * F_GETOWN: the owner (a process group negative)
/// * others: 0
pub fn sys_fcntl(fd: i32, cmd: i32, arg: u64) -> KernelResult<i64> {
    use fcntl_cmd::*;

    let fd_table = current_fd_table();
    let mut table = fd_table.lock();

    match cmd {
        F_DUPFD | F_DUPFD_CLOEXEC => {
            // Duplicate fd to lowest available >= arg
            let file = table.get(fd).ok_or(KernelError::BadFd)?;
            let nofile = get_nofile_limit();
            let min_fd = arg as i32;
            // Linux: if (from >= nofile) return -EINVAL
            if min_fd < 0 || (min_fd as u64) >= nofile {
                return Err(KernelError::InvalidArgument);
            }
            let fl = if cmd == F_DUPFD_CLOEXEC {
                crate::task::FD_CLOEXEC
            } else {
                0
            };
            // RLIMIT_NOFILE enforced inside alloc_at_or_above
            let new_fd = table.alloc_at_or_above(file, min_fd, fl, nofile)?;
            Ok(i64::from(new_fd))
        }

        F_GETFD => {
            // Get fd flags (FD_CLOEXEC)
            if !table.is_valid(fd) {
                return Err(KernelError::BadFd);
            }
            Ok(i64::from(table.get_fd_flags(fd)))
        }

        F_SETFD => {
            // Set fd flags (only FD_CLOEXEC is valid)
            if !table.set_fd_flags(fd, arg as u32) {
                return Err(KernelError::BadFd);
            }
            Ok(0)
        }

        F_GETFL => {
            let file = table.get(fd).ok_or(KernelError::BadFd)?;
            Ok(i64::from(file.get_flags()))
        }

        F_SETFL => {
            let file = table.get(fd).ok_or(KernelError::BadFd)?;
            // ->fasync takes sleeping locks
            drop(table);
            setfl(fd, &file, arg as u32)?;
            Ok(0)
        }

        F_GETLK => {
            // Get lock info - test if a lock would block
            let file = table.get(fd).ok_or(KernelError::BadFd)?;
            drop(table); // Release FD table lock before copying
            let uflock = UserPtr::<Flock>::new(arg);
            let mut flock = uflock.read()?;
            posix_getlk(&file, &mut flock)?;
            uflock.write(&flock)?;
            Ok(0)
        }

        F_SETLK | F_SETLKW => {
            // F_SETLKW: blocking - but we don't actually block, like flock
            let file = table.get(fd).ok_or(KernelError::BadFd)?;
            drop(table);
            let flock = UserPtr::<Flock>::new(arg).read()?;
            let range = if cmd == F_SETLK {
                posix_setlk(&file, &flock)?
            } else {
                posix_setlkw(&file, &flock)?
            };
            setlk_recheck(fd, &file, &flock, range);
            Ok(0)
        }

        crate::mm::memfd::F_ADD_SEALS | crate::mm::memfd::F_GET_SEALS => {
            let file = table.get(fd).ok_or(KernelError::BadFd)?;
            // Adding takes the inode's sleeping lock
            drop(table);
            crate::mm::memfd::fcntl(&file, cmd, arg)
        }

        F_SETOWN | F_GETOWN | F_SETOWN_EX | F_GETOWN_EX | F_SETSIG | F_GETSIG => {
            let file = table.get(fd).ok_or(KernelError::BadFd)?;
            // They allocate and copy to and from the user
            drop(table);
            fcntl_owner(&file, cmd, arg)
        }

        _ => Err(KernelError::InvalidArgument),
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
fn fcntl_owner(file: &File, cmd: i32, arg: u64) -> KernelResult<i64> {
    use crate::io::fasync;
    use fcntl_cmd::*;
    match cmd {
        F_SETOWN => fasync::f_setown(file, arg as i32, true)?,
        F_GETOWN => return Ok(i64::from(fasync::f_getown(file))),
        F_SETOWN_EX => fasync::f_setown_ex(file, arg)?,
        F_GETOWN_EX => fasync::f_getown_ex(file, arg)?,
        F_SETSIG => fasync::f_setsig(file, arg)?,
        _ => return Ok(i64::from(fasync::f_getsig(file))),
    }
    Ok(0)
}
