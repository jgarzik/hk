//! File open/close syscalls

use alloc::sync::Arc;

use crate::fs::namei::{Last, filename_lookup, filename_parentat, getname, path_lookupat};
use crate::fs::{
    Dentry, File, InodeMode, KernelError, LookupFlags, Path, RAMFS_FILE_OPS, dac, lookup_one,
};

use super::file::flags::AT_FDCWD;
use super::flags::{
    O_ACCMODE, O_CLOEXEC, O_CREAT, O_DIRECTORY, O_EXCL, O_NOFOLLOW, O_RDONLY, O_RDWR, O_TRUNC,
};
use super::mount::MNT_NODEV;
use super::syscall::{current_fd_table, get_nofile_limit};
use crate::task::FD_CLOEXEC;
use crate::uaccess::UserPtr;
use crate::util::error::KernelResult;
use crate::util::kalloc::try_arc;

/// Create regular file `name` in `parent` for O_CREAT (Linux
/// lookup_open + may_o_create) under the parent's lock: an entry that
/// appeared meanwhile is returned as is (created = false); otherwise
/// write+search on the parent, the mode gets the umask and SGID
/// stripping, the owner comes from init_owner
fn create_in(
    mnt: &Arc<super::mount::Mount>,
    parent: &Arc<Dentry>,
    name: &[u8],
    mode: u32,
) -> Result<(Arc<Dentry>, bool), KernelError> {
    let dir = parent.get_inode().ok_or(KernelError::NotFound)?;
    if !dir.mode().is_dir() {
        return Err(KernelError::NotDirectory);
    }
    let c = dac::cred();
    // lookup_open: write access is needed only to create
    let w = mnt.want_write();
    let _dir_lock = dir.lock();
    (|| {
        if let Ok(d) = lookup_one(parent, name) {
            return Ok((d, false));
        }
        let _w = w?;
        dac::may_create(&c, &dir)?;
        let perm = dac::create_mode(&c, &dir, (mode & 0o7777) as u16);
        // The dentry first, so an ENOMEM leaves no file made
        let d = Dentry::prealloc(parent, name)?;
        let inode = dir.i_op.create(&dir, name, InodeMode::regular(perm))?;
        dir.touch_mc();
        Ok((Dentry::add(parent, d, Some(inode)), true))
    })()
}

/// sys_open - open a file: sys_openat with AT_FDCWD
pub fn sys_open(path: UserPtr<u8>, flags: u32, mode: u32) -> KernelResult<i32> {
    sys_openat(AT_FDCWD, path, flags, mode)
}

/// Resolve the open target: an existing file, or (O_CREAT) a newly
/// created one; the bool says it was created by this call
fn open_target(
    dirfd: i32,
    path: &[u8],
    flags: u32,
    mode: u32,
) -> Result<(Path, bool), KernelError> {
    let mut lf = LookupFlags::open();
    if flags & O_DIRECTORY != 0 {
        lf.directory = true;
    }
    // O_CREAT|O_EXCL never follows a final symlink (it is EEXIST)
    if flags & O_NOFOLLOW != 0 || flags & (O_CREAT | O_EXCL) == O_CREAT | O_EXCL {
        lf.follow = false;
    }
    if flags & O_CREAT == 0 {
        return Ok((filename_lookup(dirfd, path, lf)?, false));
    }
    // O_CREAT (Linux open_last_lookups): the parent is walked, then a
    // last name of "/", "." or ".." (a directory) or one with a trailing
    // slash is EISDIR, existing or not
    let p = filename_parentat(dirfd, path)?;
    if p.last != Last::Norm || p.slash {
        return Err(KernelError::IsDirectory);
    }
    // A final symlink is followed to where the file is (or is made),
    // a dangling one included
    let p = if lf.follow {
        super::namei::resolve_last_links(p)?
    } else {
        p
    };
    let dir = Path::new(p.mnt.clone(), p.dir.clone());
    let (d, created) = match path_lookupat(Some(dir), &p.name, lf) {
        Ok(d) => (d, false),
        Err(KernelError::NotFound) => {
            let (d, c) = create_in(&p.mnt, &p.dir, &p.name, mode)?;
            (Path::new(p.mnt.clone(), d), c)
        }
        Err(e) => return Err(e),
    };
    if !created && flags & O_EXCL != 0 {
        return Err(KernelError::AlreadyExists);
    }
    if !created && d.get_inode().is_some_and(|i| i.mode().is_dir()) {
        return Err(KernelError::IsDirectory);
    }
    // An existing file opened O_CREAT in a sticky directory (Linux
    // may_create_in_sticky: fs.protected_fifos / _regular)
    // The directory is the one holding the file the walk ended on, after
    // a final symlink (Linux nd->dir_mode after the follow)
    let parent = d.dentry.get_parent().unwrap_or_else(|| p.dir.clone());
    if !created && let (Some(dir), Some(inode)) = (parent.get_inode(), d.get_inode()) {
        super::dac::may_create_in_sticky(&crate::task::current_cred(), &dir, &inode)?;
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
/// The new file descriptor
pub fn sys_openat(dirfd: i32, path_ptr: UserPtr<u8>, flags: u32, mode: u32) -> KernelResult<i32> {
    let path = getname(path_ptr, false)?;
    let file = filp_open(dirfd, &path, flags, mode)?;

    // Allocate file descriptor (RLIMIT_NOFILE enforced inside alloc)
    let fd_flags = if flags & O_CLOEXEC != 0 {
        FD_CLOEXEC
    } else {
        0
    };
    current_fd_table()
        .lock()
        .alloc_with_flags(file, fd_flags, get_nofile_limit())
}

/// Open `path` (relative to `start`) as a new file (Linux do_filp_open):
/// resolve or create the target, may_open, O_TRUNC, then the file object
fn filp_open(dirfd: i32, path: &[u8], flags: u32, mode: u32) -> Result<Arc<File>, KernelError> {
    let (path, created) = open_target(dirfd, path, flags, mode)?;
    let dentry = path.dentry.clone();
    let inode = dentry.get_inode().ok_or(KernelError::NotFound)?;

    // may_open_dev: device nodes on a nodev mount cannot be opened
    let m = inode.mode();
    if (m.is_chrdev() || m.is_blkdev()) && path.mnt.flags() & MNT_NODEV != 0 {
        return Err(KernelError::PermissionDenied);
    }

    // O_NOFOLLOW on a trailing symlink: ELOOP (may_open's symlink case)
    let acc = if created { 0 } else { dac::acc_mode(flags) };
    dac::may_open(&dac::cred(), &inode, acc, flags)?;

    // A socket inode cannot be opened (Linux no_open_fops): ENXIO
    if m.is_socket() {
        return Err(KernelError::NoDeviceOrAddress);
    }

    // An open for writing holds write access until the file is released
    // (Linux FMODE_WRITER); O_TRUNC needs it too (handle_truncate)
    let writer = flags & O_ACCMODE != O_RDONLY || flags & O_TRUNC != 0;
    let w = if writer && inode.mode().is_file() {
        Some(path.mnt.want_write()?)
    } else {
        None
    };
    // And the inode's: ETXTBSY while it is being executed (Linux
    // do_dentry_open -> file_get_write_access)
    let iw = if writer && inode.mode().is_file() {
        Some(inode.get_write_access()?)
    } else {
        None
    };

    // O_TRUNC of an existing regular file (Linux handle_truncate)
    if flags & O_TRUNC != 0 && !created && inode.mode().is_file() {
        let _lock = inode.lock();
        // An active swap file (S_SWAPFILE, set under i_rwsem): ETXTBSY
        if inode.i_swapfile.load(core::sync::atomic::Ordering::Acquire) {
            return Err(KernelError::TextBusy);
        }
        dac::remove_privs(&inode);
        // ATTR_MTIME | ATTR_CTIME, also for a file already empty
        if inode.i_op.truncate(&inode, 0).is_ok() {
            inode.touch_mc();
        }
    }

    // Get the file operations based on inode type
    let f_op: &'static dyn super::FileOps = if inode.mode().is_blkdev() {
        &super::BLOCK_FILE_OPS
    } else if inode.mode().is_fifo() {
        &crate::io::pipe::FIFO_FOPS
    } else if inode.mode().is_chrdev() {
        crate::fs::chardev::get_chardev(inode.rdev)
            .and_then(|d| d.fops())
            .unwrap_or(&super::CHAR_FILE_OPS)
    } else {
        dentry
            .superblock()
            .map(|sb| sb.fs_type.file_ops)
            .unwrap_or(&RAMFS_FILE_OPS)
    };

    let mut file = File::new(dentry, Some(path.mnt.clone()), flags, f_op);
    if flags & O_ACCMODE != O_RDONLY {
        file.write_access = w;
        file.i_write = iw;
    }
    f_op.open(&file)?;
    try_arc(file)
}

/// Give init /dev/console as stdin, stdout and stderr (Linux
/// console_on_rootfs); call in init's context before it runs
pub fn console_on_rootfs() {
    let Ok(file) = filp_open(AT_FDCWD, b"/dev/console", O_RDWR, 0) else {
        crate::printkln!("Warning: unable to open an initial console.");
        return;
    };
    let table = current_fd_table();
    let mut t = table.lock();
    for fd in 0..3 {
        t.alloc_at(fd, file.clone());
    }
}

/// sys_close - close a file descriptor
pub fn sys_close(fd: i32) -> KernelResult<()> {
    if current_fd_table().lock().close(fd) {
        Ok(())
    } else {
        Err(KernelError::BadFd)
    }
}

/// close_range(2) flags
pub const CLOSE_RANGE_UNSHARE: u32 = 1 << 1;
pub const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;

/// close_range(fd, max_fd, flags) (Linux fs/file.c): close, or with
/// CLOSE_RANGE_CLOEXEC mark close-on-exec, the open descriptors in
/// fd..=max_fd; CLOSE_RANGE_UNSHARE first gives the caller a private
/// table, so threads sharing the old one keep their descriptors
pub fn sys_close_range(fd: u32, max_fd: u32, flags: u32) -> KernelResult<()> {
    if flags & !(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC) != 0 || fd > max_fd {
        return Err(KernelError::InvalidArgument);
    }
    let files = if flags & CLOSE_RANGE_UNSHARE != 0 {
        crate::task::fdtable::unshare_task_fd(crate::task::percpu::current_tid())?
    } else {
        current_fd_table()
    };
    // Descriptors are i32: nothing is open above i32::MAX
    let Ok(lo) = i32::try_from(fd) else {
        return Ok(());
    };
    let hi = i32::try_from(max_fd).unwrap_or(i32::MAX);
    let mut t = files.lock();
    if flags & CLOSE_RANGE_CLOEXEC != 0 {
        t.cloexec_range(lo, hi);
    } else {
        t.close_range(lo, hi);
    }
    Ok(())
}
