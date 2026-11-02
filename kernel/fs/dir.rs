//! Directory syscalls (getdents, getdents64, mkdir, mkdirat, rmdir, mknod, mknodat)

use crate::arch::Uaccess;
use crate::fs::path::{create_entry, delete_entry};
use alloc::vec::Vec;

use crate::fs::{DevId, DirContext, DirEntry, FileType, InodeMode, KernelError, dac};
use crate::task::CAP_MKNOD;
use crate::uaccess::{UaccessArch, copy_to_user, strncpy_from_user};

use super::syscall::{AT_FDCWD, MAX_RW_COUNT, PATH_MAX, current_fd_table, lookup_parent_at};

/// Linux dirent64 structure for getdents64
#[repr(C, packed)]
struct LinuxDirent64 {
    d_ino: u64,
    d_off: i64,
    d_reclen: u16,
    d_type: u8,
    // d_name follows (variable length, null-terminated)
}

/// Directory entry types (DT_* values)
const DT_FIFO: u8 = 1;
const DT_CHR: u8 = 2;
const DT_DIR: u8 = 4;
const DT_BLK: u8 = 6;
const DT_REG: u8 = 8;
const DT_LNK: u8 = 10;
const DT_SOCK: u8 = 12;

/// d_type of a file type
fn dt(t: FileType) -> u8 {
    match t {
        FileType::Regular => DT_REG,
        FileType::Directory => DT_DIR,
        FileType::Symlink => DT_LNK,
        FileType::CharDev => DT_CHR,
        FileType::BlockDev => DT_BLK,
        FileType::Fifo => DT_FIFO,
        FileType::Socket => DT_SOCK,
    }
}

/// Header size of a linux_dirent64 (name follows)
const DIRENT_HDR: usize = core::mem::size_of::<LinuxDirent64>();

/// Most bytes of records one getdents64 call gathers (a short read is
/// fine: callers loop until 0)
const GETDENTS_CHUNK: usize = 32 * 1024;

/// Record format of a getdents call
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fmt {
    /// struct linux_dirent64 (getdents64)
    Dirent64,
    /// Legacy struct linux_dirent (getdents, x86-64 only): d_ino, d_off,
    /// d_reclen, d_name, then d_type in the record's last byte
    Dirent,
}

/// Offset of d_name in a legacy linux_dirent
const OLD_NAME_OFF: usize = 18;

/// Append one record for `e` to `buf` if it fits in `limit` bytes
/// (Linux filldir64 / filldir)
fn put_dirent(buf: &mut Vec<u8>, limit: usize, e: &DirEntry, d_off: u64, fmt: Fmt) -> bool {
    let name_len = e.name.len().min(255);
    let (name_off, reclen) = match fmt {
        Fmt::Dirent64 => (DIRENT_HDR, (DIRENT_HDR + name_len + 1 + 7) & !7),
        Fmt::Dirent => (OLD_NAME_OFF, (OLD_NAME_OFF + name_len + 2 + 7) & !7),
    };
    if buf.len() + reclen > limit {
        return false;
    }
    let start = buf.len();
    buf.resize(start + reclen, 0);
    let r = &mut buf[start..];
    r[0..8].copy_from_slice(&e.ino.to_ne_bytes());
    r[8..16].copy_from_slice(&d_off.to_ne_bytes());
    r[16..18].copy_from_slice(&(reclen as u16).to_ne_bytes());
    match fmt {
        Fmt::Dirent64 => r[18] = dt(e.file_type),
        Fmt::Dirent => r[reclen - 1] = dt(e.file_type),
    }
    r[name_off..name_off + name_len].copy_from_slice(&e.name[..name_len]);
    true
}

/// sys_getdents64 - get directory entries (Linux getdents64 +
/// iterate_dir): resumes at the file position, which ends up just past
/// the last entry returned (the d_off cookie); 0 at the end. EINVAL if
/// `count` cannot hold the next entry.
pub fn sys_getdents64(fd: i32, dirp: u64, count: u64) -> i64 {
    getdents(fd, dirp, count, Fmt::Dirent64)
}

/// sys_getdents - legacy getdents with struct linux_dirent (x86-64)
pub fn sys_getdents(fd: i32, dirp: u64, count: u64) -> i64 {
    getdents(fd, dirp, count, Fmt::Dirent)
}

/// File systems emit entries while holding their directory locks
/// (spinlocks in hk), so records are gathered into a kernel buffer of
/// at most GETDENTS_CHUNK bytes and copied to user space only after
/// `readdir` returned and every lock is dropped.
fn getdents(fd: i32, dirp: u64, count: u64, fmt: Fmt) -> i64 {
    let count = core::cmp::min(count as usize, MAX_RW_COUNT);
    if !Uaccess::access_ok(dirp, count) {
        return KernelError::BadAddress.sysret();
    }
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };
    if !file.is_dir() {
        return KernelError::NotDirectory.sysret();
    }

    let _pos = file.pos_lock();
    let limit = count.min(GETDENTS_CHUNK);
    let mut buf = Vec::new();
    let mut full = false;
    let mut actor = |e: &DirEntry, d_off: u64| {
        full = !put_dirent(&mut buf, limit, e, d_off, fmt);
        !full
    };
    let mut ctx = DirContext::new(file.get_pos(), &mut actor);
    // Linux iterate_dir: the directory's inode lock, shared
    let dir = file.get_inode();
    if let Some(d) = &dir {
        d.inode_lock_shared();
    }
    let r = file.readdir(&mut ctx);
    if let Some(d) = &dir {
        // SAFETY: taken above by this thread
        unsafe { d.inode_unlock_shared() };
    }
    let pos = ctx.pos;

    if buf.is_empty() {
        return match r {
            Err(e) => e.sysret(),
            // The next entry does not fit in `count`
            Ok(()) if full => KernelError::InvalidArgument.sysret(),
            Ok(()) => 0,
        };
    }
    if copy_to_user::<Uaccess>(dirp, &buf).is_err() {
        return KernelError::BadAddress.sysret();
    }
    // Entries already gathered win over a later error (Linux)
    file.set_pos(pos);
    buf.len() as i64
}

/// sys_mkdir - create a directory
///
/// Creates a new directory at the given path.
///
/// # Arguments
/// * `pathname_ptr` - User pointer to path string
/// * `mode` - Permission bits for the new directory
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_mkdir(pathname_ptr: u64, mode: u32) -> i64 {
    sys_mkdirat(AT_FDCWD, pathname_ptr, mode)
}

/// sys_mkdirat - create a directory relative to directory fd
///
/// # Arguments
/// * `dirfd` - Directory fd for relative paths, or AT_FDCWD
/// * `pathname_ptr` - User pointer to path string
/// * `mode` - Permission bits for the new directory
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_mkdirat(dirfd: i32, pathname_ptr: u64, mode: u32) -> i64 {
    let path = match strncpy_from_user::<Uaccess>(pathname_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };
    if path.is_empty() {
        return KernelError::NotFound.sysret();
    }
    let (parent, name) = match lookup_parent_at(dirfd, &path) {
        Ok(p) => p,
        Err(e) => return e,
    };
    // vfs_mkdir: permission and sticky bits only, then umask; init_owner
    // adds S_ISGID under a SGID parent
    let r = create_entry(&parent, &name, |dir, c| {
        let perm = dac::create_mode(c, dir, (mode & 0o1777) as u16);
        dir.i_op.mkdir(dir, &name, InodeMode::directory(perm))
    });
    match r {
        Ok(_) => 0,
        Err(KernelError::OperationNotSupported) => KernelError::NotPermitted.sysret(),
        Err(e) => e.sysret(),
    }
}

/// sys_rmdir - remove an empty directory
pub fn sys_rmdir(pathname_ptr: u64) -> i64 {
    let path = match strncpy_from_user::<Uaccess>(pathname_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };
    do_rmdir(AT_FDCWD, &path)
}

/// rmdir / unlinkat(AT_REMOVEDIR) (Linux do_rmdir): "." is EINVAL,
/// ".." ENOTEMPTY, then may_delete and the file system's rmdir
pub fn do_rmdir(dirfd: i32, path: &str) -> i64 {
    if path.is_empty() {
        return KernelError::NotFound.sysret();
    }
    let (parent, name) = match lookup_parent_at(dirfd, path) {
        Ok(p) => p,
        Err(e) => return e,
    };
    match name.as_str() {
        "." => return KernelError::InvalidArgument.sysret(),
        ".." => return KernelError::DirectoryNotEmpty.sysret(),
        _ => {}
    }
    match delete_entry(&parent, &name, true) {
        Ok(()) => 0,
        Err(e) => e.sysret(),
    }
}

/// sys_mknod - create a special or ordinary file
pub fn sys_mknod(pathname_ptr: u64, mode: u32, dev: u64) -> i64 {
    sys_mknodat(AT_FDCWD, pathname_ptr, mode, dev)
}

/// sys_mknodat - create a special or ordinary file relative to directory fd
///
/// Device nodes need CAP_MKNOD (checked after the parent's permission,
/// like vfs_mknod). Sockets get an S_IFSOCK inode (connectable only
/// once an AF_UNIX socket binds it, so a mknod'ed one refuses
/// connections); FIFOs are created as regular files for now.
pub fn sys_mknodat(dirfd: i32, pathname_ptr: u64, mode: u32, dev: u64) -> i64 {
    const S_IFREG: u32 = 0o100000;
    const S_IFCHR: u32 = 0o020000;
    const S_IFBLK: u32 = 0o060000;
    const S_IFIFO: u32 = 0o010000;
    const S_IFSOCK: u32 = 0o140000;
    const S_IFDIR: u32 = 0o040000;
    const S_IFMT: u32 = 0o170000;

    let path = match strncpy_from_user::<Uaccess>(pathname_ptr, PATH_MAX) {
        Ok(p) => p,
        Err(_) => return KernelError::BadAddress.sysret(),
    };
    if path.is_empty() {
        return KernelError::NotFound.sysret();
    }

    // may_mknod: file type validity
    let ty = mode & S_IFMT;
    let is_dev = match ty {
        S_IFREG | 0 | S_IFIFO | S_IFSOCK => false,
        S_IFCHR | S_IFBLK => true,
        S_IFDIR => return KernelError::NotPermitted.sysret(),
        _ => return KernelError::InvalidArgument.sysret(),
    };

    let (parent, name) = match lookup_parent_at(dirfd, &path) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let r = create_entry(&parent, &name, |dir, c| {
        if is_dev && !dac::capable(c, CAP_MKNOD) {
            return Err(KernelError::NotPermitted);
        }
        let perm = dac::create_mode(c, dir, (mode & 0o7777) as u16);
        match ty {
            S_IFCHR => dir
                .i_op
                .mknod(dir, &name, InodeMode::chardev(perm), DevId::from_user(dev)),
            S_IFBLK => dir
                .i_op
                .mknod(dir, &name, InodeMode::blockdev(perm), DevId::from_user(dev)),
            S_IFSOCK => dir
                .i_op
                .mknod(dir, &name, InodeMode::socket(perm), DevId::from_user(0)),
            S_IFIFO => dir
                .i_op
                .mknod(dir, &name, InodeMode::fifo(perm), DevId::from_user(0)),
            _ => dir.i_op.create(dir, &name, InodeMode::regular(perm)),
        }
    });
    match r {
        Ok(_) => 0,
        Err(KernelError::OperationNotSupported) => KernelError::NotPermitted.sysret(),
        Err(e) => e.sysret(),
    }
}

/// Create the socket inode an AF_UNIX bind names (Linux unix_bind_bsd:
/// filename_create at AT_FDCWD + vfs_mknod(S_IFSOCK)): `perm` is
/// reduced by the umask, DAC on the parent applies, an existing name is
/// EEXIST; returns the new dentry
pub fn mknod_sock(path: &str, perm: u16) -> Result<alloc::sync::Arc<super::Dentry>, KernelError> {
    let (parent, name) = lookup_parent_at(AT_FDCWD, path)
        .map_err(|e| KernelError::from_errno(-e as i32).unwrap_or(KernelError::Io))?;
    let r = create_entry(&parent, &name, |dir, c| {
        let perm = dac::create_mode(c, dir, perm);
        dir.i_op
            .mknod(dir, &name, InodeMode::socket(perm), DevId::from_user(0))
    });
    match r {
        Err(KernelError::OperationNotSupported) => Err(KernelError::NotPermitted),
        r => r,
    }
}

/// Remove the entry `mknod_sock` created when the bind then failed
/// (Linux unix_bind_bsd out_unlink)
pub fn unlink_sock(path: &str) {
    if let Ok((parent, name)) = lookup_parent_at(AT_FDCWD, path) {
        let _ = delete_entry(&parent, &name, false);
    }
}
