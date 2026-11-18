//! File open/close syscalls

use super::dentry::LookupBits;
use super::file::EMPTY_FOPS;
use crate::fs::FileRef;
use crate::fs::namei::{
    Dfd, Nd, filename_lookup, filename_lookup_from, filename_lookup_start, getname, path_start,
};
use crate::fs::{Dentry, File, InodeMode, KernelError, LookupFlags, Path, RAMFS_FILE_OPS, dac};
use core::cell::Cell;

use super::file::flags::AT_FDCWD;
use super::flags::{
    __O_SYNC, __O_TMPFILE, O_ACCMODE, O_CLOEXEC, O_CREAT, O_DIRECT, O_DIRECTORY, O_DSYNC,
    O_EMPTYPATH, O_EXCL, O_LARGEFILE, O_NOCTTY, O_NOFOLLOW, O_PATH, O_PATH_FLAGS, O_RDONLY, O_RDWR,
    O_TRUNC, VALID_OPEN_FLAGS,
};
use super::mount::MNT_NODEV;
use super::syscall::current_fd_table;
use crate::task::FD_CLOEXEC;
use crate::uaccess::UserPtr;
use crate::util::error::KernelResult;

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
pub const OPEN_HOW_SIZE_VER0: usize = 24;

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
    // op->intent: LOOKUP_OPEN but for O_PATH, LOOKUP_CREATE with O_CREAT,
    // LOOKUP_EXCL with O_EXCL too
    let mut intent = LookupBits::empty();
    intent.set(LookupBits::OPEN, flags & O_PATH == 0);
    intent.set(LookupBits::CREATE, flags & O_CREAT != 0);
    intent.set(LookupBits::EXCL, excl);
    LookupFlags {
        directory: flags & O_DIRECTORY != 0,
        follow: flags & O_NOFOLLOW == 0 && !excl,
        no_xdev: res & RESOLVE_NO_XDEV != 0,
        no_magiclinks: res & RESOLVE_NO_MAGICLINKS != 0,
        no_symlinks: res & RESOLVE_NO_SYMLINKS != 0,
        beneath: res & RESOLVE_BENEATH != 0,
        in_root: res & RESOLVE_IN_ROOT != 0,
        cached: res & RESOLVE_CACHED != 0,
        intent,
        ..LookupFlags::default()
    }
}

/// Where an open's walk starts (Linux nameidata: a dirfd, or the root
/// path file_open_root gives with LOOKUP_ROOT)
#[derive(Clone, Copy)]
enum OpenAt<'a> {
    Fd(i32),
    Root(&'a Path),
}

impl OpenAt<'_> {
    /// The walk's start (Linux path_init), held for the lookup
    fn start(self, path: &[u8], lf: LookupFlags) -> Result<Dfd, KernelError> {
        match self {
            Self::Fd(fd) => path_start(fd, path, lf),
            Self::Root(r) => {
                // Linux path_init under ND_ROOT_PRESET: a name to walk
                // needs a directory to walk it in
                if !path.is_empty() && !r.get_inode().is_some_and(|i| i.mode().is_dir()) {
                    return Err(KernelError::NotDirectory);
                }
                Ok(Dfd::Preset(r.clone()))
            }
        }
    }

    /// Resolve `path` (Linux filename_lookup); an empty one names the
    /// start
    fn lookup(self, path: &[u8], lf: LookupFlags) -> Result<Path, KernelError> {
        match self {
            Self::Fd(fd) => filename_lookup(fd, path, lf),
            Self::Root(r) => filename_lookup_from(Some(r.clone()), path, lf),
        }
    }
}

/// Resolve the open target: an existing file, or (O_CREAT) a newly
/// created one; the bool says it was created by this call. Walked in
/// RCU mode first, again in ref mode if that is ECHILD (Linux
/// do_filp_open's retry of path_openat), which comes before anything
/// is created; the only RCU-to-ref retry, as every walk below is one
/// try in the mode given. (Linux's third try, LOOKUP_REVAL on ESTALE,
/// has no case here: no walk returns ESTALE.) The symlink count is the
/// open's, carried into the retry (Linux nameidata, set once by
/// do_filp_open).
fn open_target(at: OpenAt<'_>, path: &[u8], op: &OpenFlags) -> Result<(Path, bool), KernelError> {
    let links = Cell::new(0);
    match open_target_nd(at, path, op, true, &links) {
        Err(KernelError::NoChild) => open_target_nd(at, path, op, false, &links),
        r => r,
    }
}

/// [`open_target`], its lookup's walks starting in RCU mode if `rcu`
/// (Linux path_openat): one walk, its last name looked up with the
/// open's intent (a trailing symlink followed unless O_NOFOLLOW or
/// O_EXCL, its body walked the same way), on a miss under the parent's
/// lock and with O_CREAT made there (open_last_lookups, lookup_open)
fn open_target_nd(
    at: OpenAt<'_>,
    path: &[u8],
    op: &OpenFlags,
    rcu: bool,
    links: &Cell<usize>,
) -> Result<(Path, bool), KernelError> {
    let (flags, lf) = (op.flags, op.lookup);
    let start = at.start(path, lf)?;
    let s = start.start();
    // An empty name (O_EMPTYPATH): dirfd's own file, no walk; with
    // O_CREAT there is no last name, so no parent's sticky check (Linux
    // nd->dir_mode is 0)
    if path.is_empty() {
        let p = filename_lookup_start(s, path, lf)?;
        if flags & O_CREAT == 0 {
            return Ok((p, false));
        }
        return creat_existing(p, flags);
    }
    let nd = Nd::new(s, lf, rcu, links)?.open(flags, op.mode);
    let d = nd.lookup(s, path, lf)?;
    if flags & O_CREAT == 0 {
        return Ok((d, false));
    }
    let created = nd.created();
    // do_open's O_CREAT checks
    if !created && flags & O_EXCL != 0 {
        return Err(KernelError::AlreadyExists);
    }
    if d.get_inode().is_some_and(|i| i.mode().is_dir()) {
        return Err(KernelError::IsDirectory);
    }
    // In a sticky directory (fs.protected_fifos / _regular): the one the
    // last name was looked up in (nd->dir_mode, nd->dir_vfsuid)
    if let Some(inode) = d.get_inode() {
        let (dmode, duid) = nd.dir();
        dac::may_create_in_sticky(&dac::cred(), dmode, duid, &inode)?;
    }
    Ok((d, created))
}

/// O_CREAT of an empty name with O_EMPTYPATH, dirfd's own file:
/// do_open's O_CREAT checks (EEXIST with O_EXCL, EISDIR)
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
    // Linux openat2: EINVAL below the first version (copy_open_how), then
    // E2BIG past a page
    if usize as u64 > crate::mm::PAGE_SIZE {
        return Err(KernelError::ArgListTooLong);
    }
    let mut how = copy_open_how(how, usize)?;
    force_largefile(&mut how);
    do_sys_openat2(dirfd, path_ptr, &how)
}

/// O_LARGEFILE unless O_PATH (Linux openat2 and io_openat_prep:
/// force_o_largefile on 64-bit)
pub fn force_largefile(how: &mut OpenHow) {
    if how.flags & u64::from(O_PATH) == 0 {
        how.flags |= u64::from(O_LARGEFILE);
    }
}

/// The `struct open_how` of `usize` bytes at `how` (Linux openat2's and
/// io_openat2_prep's checks and copy_struct_from_user): EINVAL below the
/// first version, E2BIG for unknown nonzero fields, EFAULT
pub fn copy_open_how(how: u64, usize: usize) -> KernelResult<OpenHow> {
    if usize < OPEN_HOW_SIZE_VER0 {
        return Err(KernelError::InvalidArgument);
    }
    match crate::uaccess::copy_struct_from_user::<OpenHow>(how, usize) {
        Ok(h) => Ok(h),
        Err(None) => Err(KernelError::ArgListTooLong),
        Err(Some(_)) => Err(KernelError::BadAddress),
    }
}

/// Open `name` (already copied in) relative to `dirfd` as `how` asks
/// (Linux build_open_flags + do_file_open): the file, not installed
pub fn open_file(dirfd: i32, name: &[u8], how: &OpenHow) -> KernelResult<FileRef> {
    let op = build_open_flags(how)?;
    filp_open(OpenAt::Fd(dirfd), name, &op)
}

/// [`open_file`] at a descriptor reserved first below `nofile` (Linux
/// FD_ADD: get_unused_fd_flags, then do_file_open; EMFILE first, the
/// descriptor released if the open fails; io_openat2 passes the prep's
/// RLIMIT_NOFILE); the descriptor
pub fn open_install(dirfd: i32, name: &[u8], how: &OpenHow, nofile: u64) -> KernelResult<i32> {
    let op = build_open_flags(how)?;
    let fd_flags = if how.flags & u64::from(O_CLOEXEC) != 0 {
        FD_CLOEXEC
    } else {
        0
    };
    let fd = super::io::get_unused_fd_nofile(fd_flags, nofile)?;
    let file = filp_open(OpenAt::Fd(dirfd), name, &op)?;
    Ok(fd.install(file))
}

/// Open as `how` asks and install the file (Linux do_sys_openat2): the
/// request is checked before the name is copied in
fn do_sys_openat2(dirfd: i32, path_ptr: UserPtr<u8>, how: &OpenHow) -> KernelResult<i32> {
    let op = build_open_flags(how)?;
    // O_EMPTYPATH: an empty name is dirfd itself (Linux LOOKUP_EMPTY)
    let path = getname(path_ptr, op.flags & O_EMPTYPATH != 0)?;
    open_install(dirfd, &path, how, super::syscall::get_nofile_limit())
}

/// Open `root` itself with open(2) `flags` (Linux file_open_root with an
/// empty name, do_file_open_root): the flags checked as open(2) would
/// (unknown ones dropped), a symlink ELOOP unless O_PATH
pub fn file_open_root(root: &Path, flags: u32) -> Result<FileRef, KernelError> {
    let op = build_open_flags(&build_open_how(flags, 0))?;
    if op.flags & O_PATH == 0 && root.get_inode().is_some_and(|i| i.mode().is_symlink()) {
        return Err(KernelError::TooManySymlinks);
    }
    filp_open(OpenAt::Root(root), b"", &op)
}

/// O_TMPFILE (Linux do_tmpfile, vfs_tmpfile): an unnamed regular file in
/// the directory `path`; ENOTDIR or ENOENT from the walk, EROFS, then
/// write and search on the directory (EACCES), EOPNOTSUPP from a file
/// system without tmpfile. Linkable unless O_EXCL.
fn tmpfile_open(at: OpenAt<'_>, path: &[u8], op: &OpenFlags) -> Result<FileRef, KernelError> {
    // Linux do_tmpfile: path_lookupat with the lookup flags alone, no
    // intent
    let lf = LookupFlags {
        directory: true,
        intent: LookupBits::empty(),
        ..op.lookup
    };
    let dir = at.lookup(path, lf)?;
    let dir_inode = dir.dentry.get_inode().ok_or(KernelError::NotFound)?;
    let w = dir.mnt.want_write()?;
    let c = dac::cred();
    dac::may_create(&c, &dir_inode)?;
    let perm = dac::create_mode(&c, &dir_inode, (op.mode & 0o7777) as u16);
    let inode = dir_inode
        .i_op()
        .tmpfile(&dir_inode, InodeMode::regular(perm))?;
    if op.flags & O_EXCL == 0 {
        inode.set_linkable(true);
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
fn do_o_path(at: OpenAt<'_>, path: &[u8], op: &OpenFlags) -> Result<FileRef, KernelError> {
    let p = at.lookup(path, op.lookup)?;
    let file = File::new(p.dentry.clone(), Some(p.mnt.clone()), op.flags, &EMPTY_FOPS);
    file.alloc()
}

/// The end of an open (Linux do_dentry_open): `->open`, then the flags
/// that only steered the open leave f_flags; O_DIRECT on a file that
/// cannot take it is EINVAL, after `->open` (the file is released)
fn dentry_open(mut file: File) -> Result<FileRef, KernelError> {
    file.f_op.open(&file)?;
    file.sample_wb_err();
    file.set_can_odirect();
    file.clear_flags(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);
    if file.get_flags() & O_DIRECT != 0 && !file.can_odirect() {
        return Err(KernelError::InvalidArgument);
    }
    file.alloc()
}

/// Open `path` (relative to `start`) as a new file (Linux do_filp_open):
/// resolve or create the target, may_open, O_TRUNC, then the file object
fn filp_open(at: OpenAt<'_>, path: &[u8], op: &OpenFlags) -> Result<FileRef, KernelError> {
    let flags = op.flags;
    if flags & O_PATH != 0 {
        return do_o_path(at, path, op);
    }
    if flags & __O_TMPFILE != 0 {
        return tmpfile_open(at, path, op);
    }
    let (path, created) = open_target(at, path, op)?;
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
        if inode.is_swapfile() {
            return Err(KernelError::TextBusy);
        }
        dac::remove_privs(&inode);
        // ATTR_MTIME | ATTR_CTIME, also for a file already empty; a
        // refusal (a sealed memfd: EPERM) fails the open
        match inode.i_op().truncate(&inode, 0) {
            Ok(()) => {
                let now = crate::time::TIMEKEEPER.current_time();
                inode.set_times(None, Some(now), Some(now));
            }
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
    let Ok(file) = op.and_then(|op| filp_open(OpenAt::Fd(AT_FDCWD), b"/dev/console", &op)) else {
        crate::printkln!("Warning: unable to open an initial console.");
        return;
    };
    // Linux init_dup: descriptors 0, 1 and 2, the lowest free
    for _ in 0..3 {
        let _ = super::io::fd_install(file.clone(), 0);
    }
}

/// close(2) (Linux fs/open.c): the descriptor goes under the table
/// lock; after it the file is flushed, the caller's POSIX locks on it
/// go, and the last reference releases it before the call returns
/// (`fput_close_sync`)
pub fn sys_close(fd: i32) -> KernelResult<()> {
    let files = current_fd_table();
    let file = files.close_fd(fd).ok_or(KernelError::BadFd)?;
    crate::fs::file::filp_flush(&file, files.id());
    crate::fs::file::fput_close_sync(file);
    Ok(())
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
    // Only descriptors below the table's size are visited
    let (lo, hi) = (fd as usize, max_fd as usize);
    if flags & CLOSE_RANGE_CLOEXEC != 0 {
        files.range_cloexec(lo, hi);
    } else {
        files.range_close(lo, hi);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::DentryRef;
    use crate::fs::dentry::DentryOps;
    use crate::fs::inode::{Inode, NULL_INODE_OPS, Timespec};
    use alloc::sync::Weak;
    use core::sync::atomic::{AtomicU32, Ordering};

    /// The inode whose revalidations are counted
    const SEEN: u64 = 77;
    static CALLS: AtomicU32 = AtomicU32::new(0);
    static BITS: AtomicU32 = AtomicU32::new(0);

    /// Every entry is valid; `SEEN`'s revalidations are counted, the
    /// last one's flags kept
    fn reval(_: &Inode, _: &Dentry, i: Option<&Inode>, f: LookupBits) -> Result<bool, KernelError> {
        if i.is_some_and(|i| i.ino == SEEN) {
            CALLS.fetch_add(1, Ordering::Relaxed);
            BITS.store(f.bits(), Ordering::Relaxed);
        }
        Ok(true)
    }

    static OPS: DentryOps = DentryOps {
        d_revalidate: Some(reval),
        ..DentryOps::NONE
    };

    fn inode(ino: u64, mode: InodeMode) -> crate::fs::InodeRef {
        let t = Timespec::from_secs(0);
        Inode::alloc(Inode::new(ino, mode, 0, 0, 0, t, None, &NULL_INODE_OPS)).unwrap()
    }

    /// An O_CREAT open of an existing file is answered by the RCU walk
    /// alone (Linux open_last_lookups: lookup_fast under LOOKUP_RCU,
    /// step_into; no lookup_open, no i_rwsem), its one revalidation
    /// seeing nd->flags: LOOKUP_FOLLOW and the open's intent. A walk a
    /// concurrent mount change sent to ref mode is tried again.
    #[test]
    // The walk reads the current task, an aarch64 per-CPU register a
    // host (EL0) test cannot read
    #[cfg_attr(target_arch = "aarch64", ignore)]
    fn creat_existing_rcu() {
        let root = DentryRef::new(Dentry::new_root_op(
            inode(1, InodeMode::directory(0o755)),
            &OPS,
        ))
        .unwrap();
        let d = Dentry::alloc(&root, b"d", Some(inode(2, InodeMode::directory(0o755)))).unwrap();
        let _x = Dentry::alloc(&d, b"x", Some(inode(SEEN, InodeMode::regular(0o644)))).unwrap();
        let top = Path::new(crate::fs::mount::test_mnt_root(root.clone()), root);
        let op = build_open_flags(&build_open_how(O_CREAT | O_RDWR, 0o644)).unwrap();
        let want = LookupBits::RCU | LookupBits::FOLLOW | LookupBits::OPEN | LookupBits::CREATE;
        let mut seen = (0, 0);
        for _ in 0..1000 {
            CALLS.store(0, Ordering::Relaxed);
            let links = Cell::new(0);
            let r = open_target_nd(OpenAt::Root(&top), b"d/x", &op, true, &links);
            seen = (CALLS.load(Ordering::Relaxed), BITS.load(Ordering::Relaxed));
            if r.is_ok_and(|(p, made)| !made && p.get_inode().is_some_and(|i| i.ino == SEEN))
                && seen == (1, want.bits())
            {
                return;
            }
        }
        panic!("revalidations {} flags {:#x}", seen.0, seen.1);
    }

    /// The symlink count is the open's, not one try's (Linux
    /// nd->total_link_count, set once by do_filp_open): each followed
    /// link adds to it, and a try that starts with MAXSYMLINKS counted
    /// already, as a ref-mode retry after an RCU try that followed them
    /// would, is ELOOP at its first link
    #[test]
    // The walk reads the current task, an aarch64 per-CPU register a
    // host (EL0) test cannot read
    #[cfg_attr(target_arch = "aarch64", ignore)]
    fn link_count_is_the_opens() {
        let root = DentryRef::new(Dentry::new_root_op(
            inode(1, InodeMode::directory(0o755)),
            &OPS,
        ))
        .unwrap();
        let _f = Dentry::alloc(&root, b"f", Some(inode(5, InodeMode::regular(0o644)))).unwrap();
        let l = inode(6, InodeMode::symlink());
        l.set_link(b"f".as_slice().into());
        let _l = Dentry::alloc(&root, b"l", Some(l)).unwrap();
        let top = Path::new(crate::fs::mount::test_mnt_root(root.clone()), root);
        let op = build_open_flags(&build_open_how(O_RDONLY, 0)).unwrap();
        // One try from `n` links counted: its answer (an RCU try a
        // concurrent mount change made ECHILD is tried again) and the
        // count after it
        let try_from = |rcu: bool, n: usize| loop {
            let links = Cell::new(n);
            let r = open_target_nd(OpenAt::Root(&top), b"l", &op, rcu, &links);
            if !matches!(r, Err(KernelError::NoChild)) {
                return (r.map(|(p, _)| p.get_inode().map(|i| i.ino)), links.get());
            }
        };
        for rcu in [true, false] {
            assert_eq!(try_from(rcu, 0), (Ok(Some(5)), 1), "rcu {rcu}");
            let (r, n) = try_from(rcu, 40);
            assert_eq!((r.err(), n), (Some(KernelError::TooManySymlinks), 40));
        }
    }
}
