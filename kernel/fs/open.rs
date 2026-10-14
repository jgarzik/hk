//! File open/close syscalls

use alloc::string::String;
use alloc::sync::Arc;

use crate::arch::Uaccess;
use crate::fs::{
    Dentry, File, InodeMode, KernelError, LookupFlags, Path, RAMFS_FILE_OPS, dac, lookup_one,
    lookup_path_at,
};
use crate::uaccess::strncpy_from_user;

use super::flags::{O_CLOEXEC, O_CREAT, O_DIRECTORY, O_EXCL, O_NOFOLLOW, O_RDWR, O_TRUNC};
use super::mount::{MNT_NODEV, mnt_flags_of};
use super::syscall::{AT_FDCWD, PATH_MAX, current_fd_table, get_nofile_limit};
use crate::task::FD_CLOEXEC;

/// Create regular file `name` in `parent` for O_CREAT (Linux
/// lookup_open + may_o_create) under the parent's lock: an entry that
/// appeared meanwhile is returned as is (created = false); otherwise
/// write+search on the parent, the mode gets the umask and SGID
/// stripping, the owner comes from init_owner
fn create_in(
    parent: &Arc<Dentry>,
    name: &str,
    mode: u32,
) -> Result<(Arc<Dentry>, bool), KernelError> {
    let dir = parent.get_inode().ok_or(KernelError::NotFound)?;
    if !dir.mode().is_dir() {
        return Err(KernelError::NotDirectory);
    }
    let c = dac::cred();
    dir.inode_lock();
    let r = (|| {
        if let Ok(d) = lookup_one(parent, name) {
            return Ok((d, false));
        }
        dac::may_create(&c, &dir)?;
        let perm = dac::create_mode(&c, &dir, (mode & 0o7777) as u16);
        let inode = dir.i_op.create(&dir, name, InodeMode::regular(perm))?;
        let d = Arc::new(Dentry::new(
            String::from(name),
            Some(inode),
            parent.sb.clone(),
        ));
        d.set_parent(parent);
        parent.add_child(d.clone());
        Ok((d, true))
    })();
    unsafe { dir.inode_unlock() };
    r
}

/// Split `path` into its parent and final component (Linux
/// filename_parentat); the parent is walked with search checks
fn parent_of(start: Option<Path>, path: &str) -> Result<(Arc<Dentry>, &str), KernelError> {
    let path = path.trim_end_matches('/');
    let (dir, name) = match path.rfind('/') {
        Some(0) => ("/", &path[1..]),
        Some(pos) => (&path[..pos], &path[pos + 1..]),
        None => (".", path),
    };
    if name.is_empty() || name == "." || name == ".." {
        return Err(KernelError::IsDirectory);
    }
    Ok((lookup_path_at(start, dir, LookupFlags::opendir())?, name))
}

/// sys_open - open a file
///
/// Returns a file descriptor on success, negative errno on error.
/// This is a wrapper around sys_openat with AT_FDCWD.
pub fn sys_open(path_ptr: u64, flags: u32, mode: u32) -> i64 {
    sys_openat(AT_FDCWD, path_ptr, flags, mode)
}

/// Resolve the open target: an existing file, or (O_CREAT) a newly
/// created one; the bool says it was created by this call
fn open_target(
    start: Option<Path>,
    path: &str,
    flags: u32,
    mode: u32,
) -> Result<(Arc<Dentry>, bool), KernelError> {
    let mut lf = LookupFlags::open();
    if flags & O_DIRECTORY != 0 {
        lf.directory = true;
    }
    // O_CREAT|O_EXCL never follows a final symlink (it is EEXIST)
    if flags & O_NOFOLLOW != 0 || flags & (O_CREAT | O_EXCL) == O_CREAT | O_EXCL {
        lf.follow = false;
    }
    if flags & O_CREAT == 0 {
        return Ok((lookup_path_at(start, path, lf)?, false));
    }
    let (d, created) = match lookup_path_at(start.clone(), path, lf) {
        Ok(d) => (d, false),
        Err(KernelError::NotFound) => {
            let (parent, name) = parent_of(start, path)?;
            create_in(&parent, name, mode)?
        }
        Err(e) => return Err(e),
    };
    if !created && flags & O_EXCL != 0 {
        return Err(KernelError::AlreadyExists);
    }
    if !created && d.get_inode().is_some_and(|i| i.mode().is_dir()) {
        return Err(KernelError::IsDirectory);
    }
    Ok((d, created))
}

/// sys_openat - open a file relative to a directory file descriptor
///
/// # Arguments
/// * `dirfd` - Directory file descriptor, or AT_FDCWD for current directory
/// * `path_ptr` - User pointer to path string
/// * `flags` - Open flags (O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, etc.)
/// * `mode` - File mode for O_CREAT (permission bits)
///
/// # Returns
/// File descriptor on success, negative errno on error.
pub fn sys_openat(dirfd: i32, path_ptr: u64, flags: u32, mode: u32) -> i64 {
    match do_openat(dirfd, path_ptr, flags, mode) {
        Ok(fd) => fd,
        Err(e) => e.sysret(),
    }
}

fn do_openat(dirfd: i32, path_ptr: u64, flags: u32, mode: u32) -> Result<i64, KernelError> {
    let path =
        strncpy_from_user::<Uaccess>(path_ptr, PATH_MAX).map_err(|_| KernelError::BadAddress)?;
    if path.is_empty() {
        return Err(KernelError::NotFound);
    }

    // Starting point for relative paths
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

    let file = filp_open(start, &path, flags, mode)?;

    // Allocate file descriptor (RLIMIT_NOFILE enforced inside alloc)
    let fd_flags = if flags & O_CLOEXEC != 0 {
        FD_CLOEXEC
    } else {
        0
    };
    let fd_table = current_fd_table();
    let mut table = fd_table.lock();
    match table.alloc_with_flags(file, fd_flags, get_nofile_limit()) {
        Ok(fd) => Ok(fd as i64),
        Err(e) => Ok(-(e as i64)),
    }
}

/// Open `path` (relative to `start`) as a new file (Linux do_filp_open):
/// resolve or create the target, may_open, O_TRUNC, then the file object
fn filp_open(
    start: Option<Path>,
    path: &str,
    flags: u32,
    mode: u32,
) -> Result<Arc<File>, KernelError> {
    let (dentry, created) = open_target(start, path, flags, mode)?;
    let inode = dentry.get_inode().ok_or(KernelError::NotFound)?;

    // may_open_dev: device nodes on a nodev mount cannot be opened
    let m = inode.mode();
    if (m.is_chrdev() || m.is_blkdev()) && mnt_flags_of(&dentry) & MNT_NODEV != 0 {
        return Err(KernelError::PermissionDenied);
    }

    // O_NOFOLLOW on a trailing symlink: ELOOP (may_open's symlink case)
    let acc = if created { 0 } else { dac::acc_mode(flags) };
    dac::may_open(&dac::cred(), &inode, acc, flags)?;

    // O_TRUNC of an existing regular file (Linux handle_truncate)
    if flags & O_TRUNC != 0 && !created && inode.mode().is_file() {
        inode.inode_lock();
        dac::remove_privs(&inode);
        inode.i_op.truncate(&inode, 0).ok();
        // SAFETY: taken above by this thread
        unsafe { inode.inode_unlock() };
    }

    // Get the file operations based on inode type
    let f_op: &'static dyn super::FileOps = if inode.mode().is_blkdev() {
        &super::BLOCK_FILE_OPS
    } else if inode.mode().is_chrdev() {
        &super::CHAR_FILE_OPS
    } else {
        dentry
            .superblock()
            .map(|sb| sb.fs_type.file_ops)
            .unwrap_or(&RAMFS_FILE_OPS)
    };

    Ok(Arc::new(File::new(dentry, flags, f_op)))
}

/// Give init /dev/console as stdin, stdout and stderr (Linux
/// console_on_rootfs); call in init's context before it runs
pub fn console_on_rootfs() {
    let file = match filp_open(None, "/dev/console", O_RDWR, 0) {
        Ok(f) => f,
        Err(_) => {
            crate::printkln!("Warning: unable to open an initial console.");
            return;
        }
    };
    let table = current_fd_table();
    let mut t = table.lock();
    for fd in 0..3 {
        t.alloc_at(fd, file.clone());
    }
}

/// sys_close - close a file descriptor
///
/// Returns 0 on success, negative errno on error.
pub fn sys_close(fd: i32) -> i64 {
    match current_fd_table().lock().close(fd) {
        Some(_) => 0,
        None => KernelError::BadFd.sysret(),
    }
}
