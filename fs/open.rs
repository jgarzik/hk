//! File open/close syscalls

use alloc::sync::Arc;

use super::file::EMPTY_FOPS;
use crate::fs::namei::{CreateAt, Last, Nd, filename_lookup, getname, path_start};
use crate::fs::{
    Dentry, File, InodeMode, KernelError, LookupFlags, Path, RAMFS_FILE_OPS, dac, lookup_one,
};

use super::file::flags::AT_FDCWD;
use super::flags::{
    __O_SYNC, __O_TMPFILE, O_ACCMODE, O_CLOEXEC, O_CREAT, O_DIRECT, O_DIRECTORY, O_DSYNC,
    O_EMPTYPATH, O_EXCL, O_LARGEFILE, O_NOCTTY, O_NOFOLLOW, O_PATH, O_PATH_FLAGS, O_RDONLY, O_RDWR,
    O_TRUNC, VALID_OPEN_FLAGS,
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

/// Permission bits a new file may get (Linux S_IALLUGO)
const S_IALLUGO: u64 = 0o7777;

/// An open's request (Linux struct open_how, include/uapi/linux/openat2.h)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenHow {
    pub flags: u64,
    pub mode: u64,
    pub resolve: u64,
}
crate::pod!(OpenHow {
    flags,
    mode,
    resolve
});

/// open_how.flags: only a regular file opens (EFTYPE); in the upper
/// half, which open(2)'s int cannot reach (Linux OPENAT2_REGULAR)
pub const OPENAT2_REGULAR: u64 = 1 << 32;

/// open_how.resolve (Linux include/uapi/linux/openat2.h)
pub mod resolve {
    /// No mount crossing, symlinks and magic links included
    pub const RESOLVE_NO_XDEV: u64 = 0x01;
    /// No /proc-style magic links
    pub const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    /// No symlinks at all (magic links included)
    pub const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    /// Never leave dirfd (EXDEV)
    pub const RESOLVE_BENEATH: u64 = 0x08;
    /// dirfd is the root, as if chrooted there
    pub const RESOLVE_IN_ROOT: u64 = 0x10;
    /// Only what the dcache holds, else EAGAIN
    pub const RESOLVE_CACHED: u64 = 0x20;
    /// Every flag (Linux VALID_RESOLVE_FLAGS)
    pub const VALID: u64 = 0x3f;
}

/// The first published open_how (Linux OPEN_HOW_SIZE_VER0)
const OPEN_HOW_SIZE_VER0: usize = 24;

/// What an open does (Linux struct open_flags, fs/internal.h)
pub struct OpenFlags {
    /// The new file's f_flags before do_dentry_open's strip (O_CLOEXEC
    /// is the descriptor's, not the file's)
    flags: u32,
    /// Permission bits of a file this open creates
    mode: u32,
    /// MAY_* the open asks of an existing file
    acc: u32,
    lookup: LookupFlags,
    /// OPENAT2_REGULAR (Linux __O_REGULAR, never in f_flags)
    regular: bool,
}

/// The request of open(2)/openat(2) (Linux build_open_how): unknown
/// flags are dropped, the mode counts only for a create
pub fn build_open_how(flags: u32, mode: u32) -> OpenHow {
    let mut flags = flags & VALID_OPEN_FLAGS;
    // O_PATH beats everything else
    if flags & O_PATH != 0 {
        flags &= O_PATH_FLAGS;
    }
    let mode = if will_create(flags) {
        u64::from(mode) & S_IALLUGO
    } else {
        0
    };
    OpenHow {
        flags: u64::from(flags),
        mode,
        resolve: 0,
    }
}

/// O_CREAT or O_TMPFILE: the open may make a file (Linux WILL_CREATE)
fn will_create(flags: u32) -> bool {
    flags & (O_CREAT | __O_TMPFILE) != 0
}

/// MAY_* of an access mode (Linux ACC_MODE)
fn acc_bits(flags: u32) -> u32 {
    dac::acc_mode(flags & O_ACCMODE)
}

/// Check `how` and work out the open (Linux build_open_flags)
pub fn build_open_flags(how: &OpenHow) -> Result<OpenFlags, KernelError> {
    use resolve::*;
    let flags = how.flags & !u64::from(O_CLOEXEC);
    let regular = flags & OPENAT2_REGULAR != 0;
    let mut flags = u32::try_from(flags & !OPENAT2_REGULAR)
        .ok()
        .filter(|f| f & !VALID_OPEN_FLAGS == 0)
        .ok_or(KernelError::InvalidArgument)?;
    if how.resolve & !VALID != 0 {
        return Err(KernelError::InvalidArgument);
    }
    // The scoping flags exclude each other
    if how.resolve & (RESOLVE_BENEATH | RESOLVE_IN_ROOT) == RESOLVE_BENEATH | RESOLVE_IN_ROOT {
        return Err(KernelError::InvalidArgument);
    }
    let mode = if will_create(flags) {
        if how.mode & !S_IALLUGO != 0 {
            return Err(KernelError::InvalidArgument);
        }
        how.mode as u32 // S_IALLUGO bits: lossless
    } else if how.mode != 0 {
        return Err(KernelError::InvalidArgument);
    } else {
        0
    };
    if flags & (O_DIRECTORY | O_CREAT) == O_DIRECTORY | O_CREAT {
        return Err(KernelError::InvalidArgument);
    }
    if flags & __O_TMPFILE != 0
        && (flags & O_DIRECTORY == 0 || acc_bits(flags) & dac::MAY_WRITE == 0)
    {
        return Err(KernelError::InvalidArgument);
    }
    // A directory and a regular file at once is contradictory
    if regular && flags & O_DIRECTORY != 0 {
        return Err(KernelError::InvalidArgument);
    }
    let path = flags & O_PATH != 0;
    if path && (regular || flags & !O_PATH_FLAGS != 0) {
        return Err(KernelError::InvalidArgument);
    }
    // O_SYNC is __O_SYNC|O_DSYNC: syncing code looks at O_DSYNC only
    if flags & __O_SYNC != 0 {
        flags |= O_DSYNC;
    }
    // Not even tried for a create, truncate or tmpfile open
    if how.resolve & RESOLVE_CACHED != 0 && flags & (O_TRUNC | O_CREAT | __O_TMPFILE) != 0 {
        return Err(KernelError::WouldBlock);
    }
    Ok(OpenFlags {
        flags,
        mode,
        acc: if path { 0 } else { dac::acc_mode(flags) },
        lookup: open_lookup(flags, how.resolve),
        regular,
    })
}

/// The walk of an open (Linux build_open_flags' lookup_flags):
/// O_CREAT|O_EXCL never follows a final symlink (it is EEXIST); the
/// RESOLVE_* restrictions
fn open_lookup(flags: u32, res: u64) -> LookupFlags {
    use resolve::*;
    let excl = flags & (O_CREAT | O_EXCL) == O_CREAT | O_EXCL;
    LookupFlags {
        directory: flags & O_DIRECTORY != 0,
        follow: flags & O_NOFOLLOW == 0 && !excl,
        no_xdev: res & RESOLVE_NO_XDEV != 0,
        no_magiclinks: res & RESOLVE_NO_MAGICLINKS != 0,
        no_symlinks: res & RESOLVE_NO_SYMLINKS != 0,
        beneath: res & RESOLVE_BENEATH != 0,
        in_root: res & RESOLVE_IN_ROOT != 0,
        cached: res & RESOLVE_CACHED != 0,
        ..LookupFlags::default()
    }
}

/// Resolve the open target: an existing file, or (O_CREAT) a newly
/// created one; the bool says it was created by this call
fn open_target(dirfd: i32, path: &[u8], op: &OpenFlags) -> Result<(Path, bool), KernelError> {
    let (flags, lf) = (op.flags, op.lookup);
    if flags & O_CREAT == 0 {
        return Ok((filename_lookup(dirfd, path, lf)?, false));
    }
    // O_CREAT|O_EMPTYPATH of an empty name: dirfd's own file; there is
    // no last name, so no parent's sticky check (Linux nd->dir_mode is 0)
    if path.is_empty() {
        return creat_existing(filename_lookup(dirfd, path, lf)?, flags);
    }
    // O_CREAT (Linux open_last_lookups): the parent is walked, then a
    // last name of "/", "." or ".." (a directory) or one with a trailing
    // slash is EISDIR, existing or not; one lookup (Nd) throughout, so
    // RESOLVE_* holds for the parent, the symlinks and the last name
    let start = path_start(dirfd, path, lf)?;
    let nd = Nd::new(&start, lf)?;
    let p = nd.parentat(start, path, lf)?;
    if p.last != Last::Norm || p.slash {
        return Err(KernelError::IsDirectory);
    }
    // A final symlink is followed to where the file is (or is made),
    // a dangling one included
    let p = if lf.follow {
        nd.last_links(p, lf)?
    } else {
        CreateAt::Name(p)
    };
    let p = match p {
        CreateAt::Name(p) => p,
        // A magic link's object (Linux nd_jump_link): no name to make
        CreateAt::Object(d) => return creat_existing(d, flags),
    };
    let dir = Path::new(p.mnt.clone(), p.dir.clone());
    let (d, created) = match nd.lookup(Some(dir), &p.name, lf) {
        Ok(d) => (d, false),
        Err(KernelError::NotFound) => {
            let (d, c) = create_in(&p.mnt, &p.dir, &p.name, op.mode)?;
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

/// O_CREAT landing on an existing object with no name to create (an
/// empty name with O_EMPTYPATH, a magic link): do_open's O_CREAT checks
/// (EEXIST with O_EXCL, EISDIR)
fn creat_existing(d: Path, flags: u32) -> Result<(Path, bool), KernelError> {
    if flags & O_EXCL != 0 {
        return Err(KernelError::AlreadyExists);
    }
    if d.get_inode().is_some_and(|i| i.mode().is_dir()) {
        return Err(KernelError::IsDirectory);
    }
    Ok((d, false))
}

/// sys_openat - open a file relative to a directory file descriptor
/// (64-bit: every file is O_LARGEFILE, Linux force_o_largefile)
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
    do_sys_openat2(dirfd, path_ptr, &build_open_how(flags | O_LARGEFILE, mode))
}

/// sys_openat2 - openat with a size-versioned `struct open_how` (Linux
/// openat2): every field checked (EINVAL), a struct shorter than the
/// first version EINVAL, one over a page or with unknown nonzero
/// fields E2BIG; O_LARGEFILE unless O_PATH
pub fn sys_openat2(dirfd: i32, path_ptr: UserPtr<u8>, how: u64, usize: usize) -> KernelResult<i32> {
    if usize < OPEN_HOW_SIZE_VER0 {
        return Err(KernelError::InvalidArgument);
    }
    if usize as u64 > crate::mm::PAGE_SIZE {
        return Err(KernelError::ArgListTooLong);
    }
    let mut how = match crate::uaccess::copy_struct_from_user::<OpenHow>(how, usize) {
        Ok(h) => h,
        Err(None) => return Err(KernelError::ArgListTooLong),
        Err(Some(_)) => return Err(KernelError::BadAddress),
    };
    if how.flags & u64::from(O_PATH) == 0 {
        how.flags |= u64::from(O_LARGEFILE);
    }
    do_sys_openat2(dirfd, path_ptr, &how)
}

/// Open as `how` asks and install the file (Linux do_sys_openat2): the
/// request is checked before the name is copied in
fn do_sys_openat2(dirfd: i32, path_ptr: UserPtr<u8>, how: &OpenHow) -> KernelResult<i32> {
    let op = build_open_flags(how)?;
    // O_EMPTYPATH: an empty name is dirfd itself (Linux LOOKUP_EMPTY)
    let path = getname(path_ptr, op.flags & O_EMPTYPATH != 0)?;
    let file = filp_open(dirfd, &path, &op)?;
    // RLIMIT_NOFILE enforced inside alloc
    let fd_flags = if how.flags & u64::from(O_CLOEXEC) != 0 {
        FD_CLOEXEC
    } else {
        0
    };
    current_fd_table()
        .lock()
        .alloc_with_flags(file, fd_flags, get_nofile_limit())
}

/// O_TMPFILE (Linux do_tmpfile, vfs_tmpfile): an unnamed regular file in
/// the directory `path`; ENOTDIR or ENOENT from the walk, EROFS, then
/// write and search on the directory (EACCES), EOPNOTSUPP from a file
/// system without tmpfile. Linkable unless O_EXCL.
fn tmpfile_open(dirfd: i32, path: &[u8], op: &OpenFlags) -> Result<Arc<File>, KernelError> {
    let lf = LookupFlags {
        directory: true,
        ..op.lookup
    };
    let dir = filename_lookup(dirfd, path, lf)?;
    let dir_inode = dir.dentry.get_inode().ok_or(KernelError::NotFound)?;
    let w = dir.mnt.want_write()?;
    let c = dac::cred();
    dac::may_create(&c, &dir_inode)?;
    let perm = dac::create_mode(&c, &dir_inode, (op.mode & 0o7777) as u16);
    let inode = dir_inode
        .i_op
        .tmpfile(&dir_inode, InodeMode::regular(perm))?;
    if op.flags & O_EXCL == 0 {
        inode
            .i_linkable
            .store(true, core::sync::atomic::Ordering::Relaxed);
    }
    let dentry = Dentry::tmpfile(&dir.dentry, inode.clone())?;
    let iw = inode.get_write_access()?;
    let f_op = dentry
        .superblock()
        .map(|sb| sb.fs_type.file_ops)
        .unwrap_or(&RAMFS_FILE_OPS);
    let mut file = File::new(dentry, Some(dir.mnt.clone()), op.flags, f_op);
    file.write_access = Some(w);
    file.i_write = Some(iw);
    dentry_open(file)
}

/// O_PATH (Linux do_o_path + do_dentry_open's FMODE_PATH branch): the
/// walk alone (a final symlink with O_NOFOLLOW is the link itself,
/// O_DIRECTORY is ENOTDIR on anything else), with no permission check,
/// device or FIFO open, write access or ->open; the file does no I/O
fn do_o_path(dirfd: i32, path: &[u8], op: &OpenFlags) -> Result<Arc<File>, KernelError> {
    let p = filename_lookup(dirfd, path, op.lookup)?;
    let file = File::new(p.dentry.clone(), Some(p.mnt.clone()), op.flags, &EMPTY_FOPS);
    try_arc(file)
}

/// The end of an open (Linux do_dentry_open): `->open`, then the flags
/// that only steered the open leave f_flags; O_DIRECT on a file that
/// cannot take it is EINVAL, after `->open` (the file is released)
fn dentry_open(mut file: File) -> Result<Arc<File>, KernelError> {
    file.f_op.open(&file)?;
    file.set_can_odirect();
    file.clear_flags(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);
    if file.get_flags() & O_DIRECT != 0 && !file.can_odirect() {
        return Err(KernelError::InvalidArgument);
    }
    try_arc(file)
}

/// Open `path` (relative to `start`) as a new file (Linux do_filp_open):
/// resolve or create the target, may_open, O_TRUNC, then the file object
fn filp_open(dirfd: i32, path: &[u8], op: &OpenFlags) -> Result<Arc<File>, KernelError> {
    let flags = op.flags;
    if flags & O_PATH != 0 {
        return do_o_path(dirfd, path, op);
    }
    if flags & __O_TMPFILE != 0 {
        return tmpfile_open(dirfd, path, op);
    }
    let (path, created) = open_target(dirfd, path, op)?;
    let dentry = path.dentry.clone();
    let inode = dentry.get_inode().ok_or(KernelError::NotFound)?;

    // OPENAT2_REGULAR (Linux do_open): after O_CREAT's checks, before
    // may_open's
    if op.regular && !inode.mode().is_file() {
        return Err(KernelError::WrongFileType);
    }

    // may_open_dev: device nodes on a nodev mount cannot be opened
    let m = inode.mode();
    if (m.is_chrdev() || m.is_blkdev()) && path.mnt.flags() & MNT_NODEV != 0 {
        return Err(KernelError::PermissionDenied);
    }

    // O_NOFOLLOW on a trailing symlink: ELOOP (may_open's symlink case)
    let acc = if created { 0 } else { op.acc };
    dac::may_open(&dac::cred(), &inode, acc, flags)?;

    // A socket inode cannot be opened (Linux sock_no_open): ENXIO; nor
    // a file of no filesystem (an mqueue: Linux opens it through the
    // mqueue mount, which hk lacks)
    if m.is_socket() || dentry.superblock().is_none() {
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
        // ATTR_MTIME | ATTR_CTIME, also for a file already empty; a
        // refusal (a sealed memfd: EPERM) fails the open
        match inode.i_op.truncate(&inode, 0) {
            Ok(()) => inode.touch_mc(),
            Err(KernelError::OperationNotSupported) => {}
            Err(e) => return Err(e),
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
    dentry_open(file)
}

/// Give init /dev/console as stdin, stdout and stderr (Linux
/// console_on_rootfs); call in init's context before it runs
pub fn console_on_rootfs() {
    let op = build_open_flags(&build_open_how(O_RDWR, 0));
    let Ok(file) = op.and_then(|op| filp_open(AT_FDCWD, b"/dev/console", &op)) else {
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
        crate::task::fdtable::unshare_task_fd()?
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
