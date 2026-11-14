//! Miscellaneous filesystem syscalls
//!
//! This module contains:
//! - mount, umount2, pivot_root (filesystem mounting)
//! - ioctl (device control)
//! - xattr syscalls (extended attributes)
//! - readahead (file readahead)

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fs::{Inode, KernelError, LookupFlags, lookup_path_flags};
use crate::uaccess::{
    UaccessError, UserPtr, access_ok, copy_to_user, strncpy_from_user, strncpy_from_user_str,
};
use crate::util::error::KernelResult;

use super::io::fget;
use super::syscall::{PATH_MAX, current_fd_table};

// ============================================================================
// mount, umount2 syscalls
// ============================================================================

/// mount(2) flags (Linux uapi/linux/mount.h)
mod ms {
    pub const RDONLY: u64 = 1;
    pub const NOSUID: u64 = 2;
    pub const NODEV: u64 = 4;
    pub const NOEXEC: u64 = 8;
    pub const SYNCHRONOUS: u64 = 16;
    pub const REMOUNT: u64 = 32;
    pub const DIRSYNC: u64 = 128;
    pub const NOSYMFOLLOW: u64 = 256;
    pub const BIND: u64 = 4096;
    pub const MOVE: u64 = 8192;
    pub const MANDLOCK: u64 = 64;
    pub const NOATIME: u64 = 1 << 10;
    pub const NODIRATIME: u64 = 1 << 11;
    pub const REC: u64 = 1 << 14;
    pub const SILENT: u64 = 1 << 15;
    pub const POSIXACL: u64 = 1 << 16;
    pub const UNBINDABLE: u64 = 1 << 17;
    pub const PRIVATE: u64 = 1 << 18;
    pub const SLAVE: u64 = 1 << 19;
    pub const SHARED: u64 = 1 << 20;
    pub const RELATIME: u64 = 1 << 21;
    pub const I_VERSION: u64 = 1 << 23;
    pub const STRICTATIME: u64 = 1 << 24;
    pub const LAZYTIME: u64 = 1 << 25;
    pub const NOUSER: u64 = 1 << 31;
    pub const MGC_VAL: u64 = 0xC0ED_0000;
    pub const MGC_MSK: u64 = 0xffff_0000;

    /// Flags hk honors, or may accept without effect because hk
    /// already behaves that way (no mandatory locks); everything else
    /// is EINVAL instead of being ignored
    pub const KNOWN: u64 = RDONLY
        | SYNCHRONOUS
        | DIRSYNC
        | NOSYMFOLLOW
        | BIND
        | MOVE
        | NOSUID
        | NODEV
        | NOEXEC
        | REMOUNT
        | MANDLOCK
        | NOATIME
        | NODIRATIME
        | REC
        | SILENT
        | POSIXACL
        | UNBINDABLE
        | PRIVATE
        | SLAVE
        | SHARED
        | RELATIME
        | I_VERSION
        | STRICTATIME
        | LAZYTIME;
}

/// Per-mount MNT_* flags of mount(2) flags (Linux path_mount): relatime
/// unless noatime or strictatime
fn mnt_flags(flags: u64) -> u32 {
    use super::mount::{
        MNT_NOATIME, MNT_NODEV, MNT_NODIRATIME, MNT_NOEXEC, MNT_NOSUID, MNT_NOSYMFOLLOW,
        MNT_READONLY, MNT_RELATIME,
    };
    let mut f = 0;
    if flags & ms::NOATIME == 0 {
        f |= MNT_RELATIME;
    }
    if flags & ms::NOATIME != 0 {
        f |= MNT_NOATIME;
    }
    if flags & ms::NODIRATIME != 0 {
        f |= MNT_NODIRATIME;
    }
    if flags & ms::STRICTATIME != 0 {
        f &= !(MNT_RELATIME | MNT_NOATIME);
    }
    if flags & ms::RDONLY != 0 {
        f |= MNT_READONLY;
    }
    if flags & ms::NOSUID != 0 {
        f |= MNT_NOSUID;
    }
    if flags & ms::NODEV != 0 {
        f |= MNT_NODEV;
    }
    if flags & ms::NOEXEC != 0 {
        f |= MNT_NOEXEC;
    }
    if flags & ms::NOSYMFOLLOW != 0 {
        f |= MNT_NOSYMFOLLOW;
    }
    f
}

/// A remount's MNT_* flags: with no atime flag given, `old`'s atime
/// flags are kept (Linux path_mount)
fn remount_flags(flags: u64, old: u32) -> u32 {
    use super::mount::MNT_ATIME_MASK;
    let f = mnt_flags(flags);
    let atime = ms::NOATIME | ms::NODIRATIME | ms::RELATIME | ms::STRICTATIME;
    if flags & atime != 0 {
        return f;
    }
    (f & !MNT_ATIME_MASK) | (old & MNT_ATIME_MASK)
}

/// SB_SYNCHRONOUS / SB_DIRSYNC of mount(2) flags
fn sb_sync_flags(flags: u64) -> u32 {
    use super::superblock::{SB_DIRSYNC, SB_SYNCHRONOUS};
    let mut f = 0;
    if flags & ms::SYNCHRONOUS != 0 {
        f |= SB_SYNCHRONOUS;
    }
    if flags & ms::DIRSYNC != 0 {
        f |= SB_DIRSYNC;
    }
    f
}

/// MS_REMOUNT (Linux do_remount): the mount's flags become exactly the
/// requested set. The read-only switch goes first and is all-or-nothing
/// (EBUSY while files are open for writing or changes are in progress,
/// with nothing changed); only then the per-mount flags are replaced.
fn remount(m: &super::mount::MountRef, flags: u64, data: &[u8]) -> Result<(), KernelError> {
    let _s = m.sb.s_umount.write();
    // Read-only first (EBUSY changes nothing), then the filesystem's
    // options; their error undoes the switch (Linux reconfigure_super:
    // sb_prepare_remount_readonly, ->reconfigure, cancel on error)
    let was_ro = m.sb.rdonly();
    if flags & ms::RDONLY != 0 {
        m.sb.make_rdonly()?;
    }
    if let Err(e) = m.sb.s_op.remount(&m.sb, data) {
        if !was_ro && m.sb.rdonly() {
            m.sb.make_rdwr();
        }
        return Err(e);
    }
    if flags & ms::RDONLY == 0 {
        m.sb.make_rdwr();
    }
    m.sb.set_sync_flags(sb_sync_flags(flags));
    m.set_flags(remount_flags(flags, m.flags()))
}

/// MS_REMOUNT|MS_BIND (Linux do_reconfigure_mnt): this mount's flags
/// only, read-only included; the superblock is untouched
fn reconfigure_mnt(m: &super::mount::MountRef, flags: u64) -> Result<(), KernelError> {
    // s_umount shared, as Linux do_reconfigure_mnt: the superblock does
    // not change, MOUNT_LOCK serializes the flag writers
    let _s = m.sb.s_umount.read();
    m.set_flags(remount_flags(flags, m.flags()))
}

/// MS_SHARED / MS_SLAVE / MS_PRIVATE / MS_UNBINDABLE (Linux
/// do_change_type): exactly one type (else EINVAL), for the subtree
/// with MS_REC
fn change_type(m: &super::mount::MountRef, flags: u64) -> Result<(), KernelError> {
    use super::pnode::{Prop, change_mnt_propagation, invent_group_ids};
    let p = match flags & !(ms::REC | ms::SILENT) {
        ms::SHARED => Prop::Shared,
        ms::SLAVE => Prop::Slave,
        ms::PRIVATE => Prop::Private,
        ms::UNBINDABLE => Prop::Unbindable,
        _ => return Err(KernelError::InvalidArgument),
    };
    let mut ns = super::mount::namespace_lock();
    // Mounted in some namespace, not a kernel mount (Linux
    // may_change_propagation's IS_ERR_OR_NULL(mnt_ns): not necessarily
    // the caller's)
    if !m.is_mounted() {
        return Err(KernelError::InvalidArgument);
    }
    let rec = flags & ms::REC != 0;
    if p == Prop::Shared {
        invent_group_ids(&mut ns, m, rec)?;
    }
    if rec {
        super::mount::for_each_mut(&mut ns, m, |ns, t| change_mnt_propagation(ns, t, p));
    } else {
        change_mnt_propagation(&mut ns, m, p);
    }
    Ok(())
}

/// The caller's mount (Linux check_mnt) whose root `target` is (Linux
/// path_mounted), else EINVAL: what remount works on
fn own_mount_at(target: &super::Path) -> Result<super::mount::MountRef, KernelError> {
    if !super::mount::check_mnt(&target.mnt) {
        return Err(KernelError::InvalidArgument);
    }
    mount_at(target)
}

/// Mount whose root `target` is (Linux path_mounted), else EINVAL
fn mount_at(target: &super::Path) -> Result<super::mount::MountRef, KernelError> {
    if super::DentryRef::ptr_eq(&target.dentry, &target.mnt.root) {
        Ok(target.mnt.clone())
    } else {
        Err(KernelError::InvalidArgument)
    }
}

/// sys_mount - mount a filesystem (Linux do_mount + path_mount)
///
/// Order as in Linux: strings and the target are looked up first, then
/// MS_NOUSER (EINVAL) and CAP_SYS_ADMIN (EPERM), then path_mount's
/// dispatch: MS_REMOUNT|MS_BIND, MS_REMOUNT, MS_BIND, the propagation
/// types, MS_MOVE, else a new mount. Unsupported flags are EINVAL.
pub fn sys_mount(
    source_ptr: UserPtr<u8>,
    target_ptr: UserPtr<u8>,
    fstype_ptr: UserPtr<u8>,
    mut flags: u64,
    data_ptr: UserPtr<u8>,
) -> KernelResult<()> {
    // Linux copy_mount_string (strndup_user): EFAULT, EINVAL if too long;
    // type, then source, then the target as a path name. Source and type
    // may be absent for remount / propagation changes; a type is a name
    // of a registered filesystem: not text, no such one
    let too_long = |e| match e {
        UaccessError::TooLong => KernelError::InvalidArgument,
        _ => KernelError::BadAddress,
    };
    let fstype = if !fstype_ptr.is_null() {
        match strncpy_from_user_str(fstype_ptr.addr(), PATH_MAX) {
            Ok(s) => s,
            Err(UaccessError::Encoding) => return Err(KernelError::NoDevice),
            Err(e) => return Err(too_long(e)),
        }
    } else {
        Default::default()
    };
    let source = if !source_ptr.is_null() {
        strncpy_from_user(source_ptr.addr(), PATH_MAX).map_err(too_long)?
    } else {
        Default::default()
    };
    // Linux copy_mount_options: the options string, within a page
    let data = if !data_ptr.is_null() {
        strncpy_from_user(data_ptr.addr(), 4096).map_err(too_long)?
    } else {
        Default::default()
    };
    let target = crate::fs::namei::getname(target_ptr, false)?;
    // A mount may cover a file (bind): the target is only followed
    let mp = crate::fs::namei::path_lookupat(
        crate::task::percpu::current_cwd(),
        &target,
        LookupFlags::open(),
    )?;

    if flags & ms::MGC_MSK == ms::MGC_VAL {
        flags &= !ms::MGC_MSK;
    }
    if flags & ms::NOUSER != 0 {
        return Err(KernelError::InvalidArgument);
    }
    if !crate::task::capable(crate::task::CAP_SYS_ADMIN) {
        return Err(KernelError::NotPermitted);
    }
    if flags & !ms::KNOWN != 0 {
        return Err(KernelError::InvalidArgument);
    }
    // Linux path_mount's order
    if flags & (ms::REMOUNT | ms::BIND) == ms::REMOUNT | ms::BIND {
        return reconfigure_mnt(&own_mount_at(&mp)?, flags);
    }
    if flags & ms::REMOUNT != 0 {
        return remount(&own_mount_at(&mp)?, flags, &data);
    }
    if flags & ms::BIND != 0 {
        let old = crate::fs::namei::path_lookupat(
            crate::task::percpu::current_cwd(),
            &source,
            LookupFlags::open(),
        );
        if source.is_empty() {
            return Err(KernelError::NotFound);
        }
        return super::mount::do_loopback(&old?, &mp, flags & ms::REC != 0);
    }
    if flags & (ms::SHARED | ms::SLAVE | ms::PRIVATE | ms::UNBINDABLE) != 0 {
        return change_type(&mount_at(&mp)?, flags);
    }
    if flags & ms::MOVE != 0 {
        let old = crate::fs::namei::path_lookupat(
            crate::task::percpu::current_cwd(),
            &source,
            LookupFlags::open(),
        );
        if source.is_empty() {
            return Err(KernelError::NotFound);
        }
        return super::mount::do_move(&old?, &mp);
    }
    new_mount(&source, &fstype, mp, flags, &data)
}

/// Mount a new instance of `fstype` on `mp` (Linux do_new_mount)
fn new_mount(
    source: &[u8],
    fstype: &str,
    mp: super::Path,
    flags: u64,
    data: &[u8],
) -> Result<(), KernelError> {
    let fs_type = super::superblock::find_filesystem(fstype).ok_or(KernelError::NoDevice)?;
    if !mp
        .dentry
        .get_inode()
        .ok_or(KernelError::NotFound)?
        .mode()
        .is_dir()
    {
        return Err(KernelError::NotDirectory);
    }
    // Flags are set before the mount becomes visible (Linux do_new_mount)
    let sb = if fs_type.mount_dev.is_some() && !source.is_empty() {
        super::mount::dev_super(fs_type, source, data)
    } else {
        (fs_type.mount)(fs_type, data)
    };
    let r = sb.and_then(|sb| {
        // A superblock already mounted elsewhere (sysfs of a namespace)
        // keeps its flags (Linux: only a new one gets the mount's)
        if !sb.is_mounted() {
            sb.set_sync_flags(sb_sync_flags(flags));
        }
        // Linux: no source is "none"
        let devname = if source.is_empty() {
            b"none".as_slice()
        } else {
            source
        };
        super::mount::attach(
            sb,
            Some(mp),
            mnt_flags(flags),
            flags & ms::RDONLY != 0,
            devname.into(),
        )
    });
    match r {
        Ok(_) => Ok(()),
        Err(
            e @ (KernelError::NotBlockDevice
            | KernelError::NoDevice
            | KernelError::Busy
            | KernelError::NotFound
            | KernelError::Io
            | KernelError::OutOfMemory),
        ) => Err(e),
        Err(_) => Err(KernelError::InvalidArgument),
    }
}

/// sys_umount2 (Linux ksys_umount): flags, the target (a mount's root,
/// followed unless UMOUNT_NOFOLLOW), CAP_SYS_ADMIN after the lookup,
/// then do_umount
pub fn sys_umount2(target_ptr: UserPtr<u8>, flags: i32) -> KernelResult<()> {
    use super::mount::umount_flags::{MNT_DETACH, MNT_EXPIRE, MNT_FORCE, UMOUNT_NOFOLLOW};
    if flags & !(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW) != 0 {
        return Err(KernelError::InvalidArgument);
    }
    let target = crate::fs::namei::getname(target_ptr, false)?;
    let lf = LookupFlags {
        follow: flags & UMOUNT_NOFOLLOW == 0,
        ..LookupFlags::open()
    };
    let target = crate::fs::namei::path_lookupat(crate::task::percpu::current_cwd(), &target, lf)?;
    if !crate::task::capable(crate::task::CAP_SYS_ADMIN) {
        return Err(KernelError::NotPermitted);
    }
    // The lookup is not a use that clears an MNT_EXPIRE mark (Linux
    // path_umount: mntput_no_expire)
    let m = mount_at(&target)?;
    drop(target.into_mnt_noexpire());
    super::mount::do_umount(m, flags)
}

/// pivot_root(new_root, put_old) (Linux: may_mount, both paths as
/// directories, then the mount rules of do_pivot_root)
pub fn sys_pivot_root(new_root_ptr: UserPtr<u8>, put_old_ptr: UserPtr<u8>) -> KernelResult<()> {
    if !crate::task::capable(crate::task::CAP_SYS_ADMIN) {
        return Err(KernelError::NotPermitted);
    }
    let dir = |p: UserPtr<u8>| {
        let name = crate::fs::namei::getname(p, false)?;
        crate::fs::namei::path_lookupat(
            crate::task::percpu::current_cwd(),
            &name,
            LookupFlags::opendir(),
        )
    };
    let new = dir(new_root_ptr)?;
    let old = dir(put_old_ptr)?;
    super::mount::do_pivot_root(&new, &old)
}

/// sys_ioctl - device control
///
/// Performs device-specific control operations.
///
/// # Arguments
/// * `fd` - File descriptor
/// * `cmd` - Ioctl command number
/// * `arg` - Command-specific argument (often a pointer)
///
/// # Returns
/// The command's value (0 for most)
pub fn sys_ioctl(fd: i32, cmd: u32, arg: u64) -> KernelResult<i64> {
    // Generic ioctl constants (work on any fd)
    const FIONBIO: u32 = 0x5421; // Set/clear non-blocking mode
    const FIOASYNC: u32 = 0x5452; // Enable async I/O notification
    const FIOCLEX: u32 = 0x5451; // Set close-on-exec flag
    const FIONCLEX: u32 = 0x5450; // Clear close-on-exec flag
    use crate::fs::file::FIONREAD;

    let file = fget(fd)?;

    // Handle generic ioctls first (work on any fd type)
    match cmd {
        FIONBIO => {
            // Set/clear non-blocking mode
            if arg == 0 {
                return Err(KernelError::BadAddress);
            }
            let enable = UserPtr::<i32>::new(arg).read()?;
            let current_flags = file.get_flags();
            if enable != 0 {
                file.set_status_flags(current_flags | crate::fs::flags::O_NONBLOCK);
            } else {
                file.set_status_flags(current_flags & !crate::fs::flags::O_NONBLOCK);
            }
            return Ok(0);
        }
        // Linux ioctl_fioasync: a change of O_ASYNC goes through
        // ->fasync, ENOTTY without one
        FIOASYNC => {
            let on = UserPtr::<i32>::new(arg).read()? != 0;
            let async_now = file.get_flags() & crate::fs::flags::O_ASYNC != 0;
            if on == async_now {
                return Ok(0);
            }
            file.fasync(fd, on).ok_or(KernelError::NotTty)??;
            return Ok(0);
        }
        FIOCLEX => {
            // Set close-on-exec flag
            current_fd_table()
                .lock()
                .set_fd_flags(fd, crate::task::FD_CLOEXEC);
            return Ok(0);
        }
        FIONCLEX => {
            // Clear close-on-exec flag
            current_fd_table().lock().set_fd_flags(fd, 0);
            return Ok(0);
        }
        // A regular file: size - position (Linux do_vfs_ioctl); the
        // rest is the file's own (pipes, sockets, ttys, inotify), ENOTTY
        // without
        FIONREAD => {
            if let Some(i) = file.get_inode().filter(|i| i.mode().is_file()) {
                let n = i.get_size() as i64 - file.get_pos() as i64;
                return crate::fs::file::put_fionread(arg, n);
            }
        }
        _ => {} // Fall through to device-specific handling
    }

    // Everything else is the file's own (Linux vfs_ioctl ->
    // f_op->unlocked_ioctl): devices, sockets, ...
    file.ops().ioctl(&file, cmd, arg)
}

// =============================================================================
// Extended attributes (xattr) syscalls
// =============================================================================

/// XATTR_CREATE - set value, fail if attr already exists
pub const XATTR_CREATE: u32 = 0x1;
/// XATTR_REPLACE - set value, fail if attr doesn't exist
pub const XATTR_REPLACE: u32 = 0x2;
/// Maximum attribute name length
pub const XATTR_NAME_MAX: usize = 255;
/// Maximum attribute value size (64KB)
pub const XATTR_SIZE_MAX: usize = 65536;

/// Largest listxattr buffer (Linux XATTR_LIST_MAX)
pub const XATTR_LIST_MAX: usize = 65536;

/// errno of a failed xattr inode op: the ones a caller can act on as
/// they are, EACCES as EPERM, anything else EINVAL
fn xattr_err(e: KernelError) -> KernelError {
    match e {
        KernelError::NotFound
        | KernelError::NoData
        | KernelError::AlreadyExists
        | KernelError::Range
        | KernelError::OperationNotSupported
        | KernelError::Io => e,
        KernelError::PermissionDenied => KernelError::NotPermitted,
        // A file system out of xattr space or memory (Linux: ENOSPC,
        // ENOMEM from the handler)
        KernelError::NoSpace | KernelError::OutOfMemory => e,
        _ => KernelError::InvalidArgument,
    }
}

/// An xattr name, any bytes but NUL (Linux import_xattr_name): empty
/// or without a NUL in XATTR_NAME_MAX + 1 bytes is ERANGE, a fault
/// EFAULT
fn xattr_name(ptr: UserPtr<u8>) -> KernelResult<Vec<u8>> {
    match strncpy_from_user(ptr.addr(), XATTR_NAME_MAX + 1) {
        Ok(name) if name.is_empty() => Err(KernelError::Range),
        Ok(name) => Ok(name),
        Err(UaccessError::TooLong) => Err(KernelError::Range),
        Err(_) => Err(KernelError::BadAddress),
    }
}

/// Lookup flags of the path xattr calls (the l* ones do not follow)
fn xattr_lookup(follow: bool) -> LookupFlags {
    LookupFlags {
        follow,
        ..LookupFlags::open()
    }
}

/// Copy xattr value from user space
fn copy_xattr_value_from_user(value_ptr: UserPtr<u8>, size: u64) -> KernelResult<Vec<u8>> {
    use crate::uaccess::copy_from_user;

    // Linux setxattr_copy: E2BIG
    if size > XATTR_SIZE_MAX as u64 {
        return Err(KernelError::ArgListTooLong);
    }

    if size == 0 {
        return Ok(Vec::new());
    }

    // Validate user buffer (EFAULT before ENOMEM)
    if !access_ok(value_ptr.addr(), size as usize) {
        return Err(KernelError::BadAddress);
    }

    // Allocate (ENOMEM, Linux kvmalloc) and copy value from user space
    let mut value = crate::util::kmem::try_vec(size as usize, 0u8)?;
    copy_from_user(&mut value, value_ptr.addr(), size as usize)?;
    Ok(value)
}

/// Linux vfs_setxattr, write access already held: the permission
/// check, then the file system's op
fn setxattr_inode(inode: &Arc<Inode>, name: &[u8], value: &[u8], flags: i32) -> KernelResult<()> {
    super::dac::xattr_permission(inode, name, super::dac::MAY_WRITE)?;
    inode
        .i_op
        .setxattr(inode, name, value, flags as u32)
        .map_err(xattr_err)
}

/// XATTR_CREATE / XATTR_REPLACE only
fn xattr_flags_ok(flags: i32) -> KernelResult<()> {
    if flags as u32 & !(XATTR_CREATE | XATTR_REPLACE) != 0 {
        return Err(KernelError::InvalidArgument);
    }
    Ok(())
}

/// sys_setxattr - set an extended attribute value
///
/// # Arguments
/// * `path_ptr` - User pointer to path string
/// * `name_ptr` - User pointer to attribute name string
/// * `value_ptr` - User pointer to attribute value
/// * `size` - Size of the value
/// * `flags` - XATTR_CREATE or XATTR_REPLACE
pub fn sys_setxattr(
    path_ptr: UserPtr<u8>,
    name_ptr: UserPtr<u8>,
    value_ptr: UserPtr<u8>,
    size: u64,
    flags: i32,
) -> KernelResult<()> {
    do_setxattr(path_ptr, name_ptr, value_ptr, size, flags, true)
}

/// sys_lsetxattr - set an extended attribute value (don't follow symlinks)
pub fn sys_lsetxattr(
    path_ptr: UserPtr<u8>,
    name_ptr: UserPtr<u8>,
    value_ptr: UserPtr<u8>,
    size: u64,
    flags: i32,
) -> KernelResult<()> {
    do_setxattr(path_ptr, name_ptr, value_ptr, size, flags, false)
}

/// Internal helper for setxattr/lsetxattr
fn do_setxattr(
    path_ptr: UserPtr<u8>,
    name_ptr: UserPtr<u8>,
    value_ptr: UserPtr<u8>,
    size: u64,
    flags: i32,
    follow: bool,
) -> KernelResult<()> {
    xattr_flags_ok(flags)?;
    let path = crate::fs::namei::getname(path_ptr, false)?;
    let name = xattr_name(name_ptr)?;
    let value = copy_xattr_value_from_user(value_ptr, size)?;
    let fpath = crate::fs::namei::path_lookupat(
        crate::task::percpu::current_cwd(),
        &path,
        xattr_lookup(follow),
    )?;
    let inode = fpath.dentry.get_inode().ok_or(KernelError::NotFound)?;
    // setxattr/removexattr: write access first (EROFS), held across
    let _w = fpath.mnt.want_write()?;
    setxattr_inode(&inode, &name, &value, flags)
}

/// sys_fsetxattr - set an extended attribute value on a file descriptor
pub fn sys_fsetxattr(
    fd: i32,
    name_ptr: UserPtr<u8>,
    value_ptr: UserPtr<u8>,
    size: u64,
    flags: i32,
) -> KernelResult<()> {
    xattr_flags_ok(flags)?;
    let file = fget(fd)?;
    let name = xattr_name(name_ptr)?;
    let value = copy_xattr_value_from_user(value_ptr, size)?;
    let inode = file.get_inode().ok_or(KernelError::BadFd)?;
    // setxattr/removexattr: write access first (EROFS), held across
    let _w = file.want_write()?;
    setxattr_inode(&inode, &name, &value, flags)
}

/// Linux do_getxattr: the permission check, then the value into the
/// `size`-byte user buffer (size 0: only its length); ERANGE from the
/// file system when the buffer is too small
fn getxattr_inode(
    inode: &Arc<Inode>,
    name: &[u8],
    value_ptr: UserPtr<u8>,
    size: u64,
) -> KernelResult<usize> {
    super::dac::xattr_permission(inode, name, super::dac::MAY_READ)?;
    if size == 0 {
        return inode.i_op.getxattr(inode, name, &mut []).map_err(xattr_err);
    }
    // A larger buffer is clamped (Linux do_getxattr): no value is longer
    let size = size.min(XATTR_SIZE_MAX as u64) as usize;
    // Allocate kernel buffer (ENOMEM, Linux kvzalloc); the user buffer
    // is only touched by the copy
    let mut value = crate::util::kmem::try_vec(size, 0u8)?;
    let n = inode
        .i_op
        .getxattr(inode, name, &mut value)
        .map_err(|e| too_big(xattr_err(e), size, XATTR_SIZE_MAX))?;
    copy_out(value_ptr, &value[..n])
}

/// ERANGE for a buffer of the largest size: what the file system has
/// cannot be returned at all (Linux do_getxattr, listxattr: E2BIG)
fn too_big(e: KernelError, size: usize, max: usize) -> KernelError {
    if e == KernelError::Range && size >= max {
        KernelError::ArgListTooLong
    } else {
        e
    }
}

/// The `n` bytes of `buf` to user `ptr`, none touched when `n` is 0
fn copy_out(ptr: UserPtr<u8>, buf: &[u8]) -> KernelResult<usize> {
    if !buf.is_empty() {
        copy_to_user(ptr.addr(), buf)?;
    }
    Ok(buf.len())
}

/// sys_getxattr - get an extended attribute value
///
/// # Arguments
/// * `path_ptr` - User pointer to path string
/// * `name_ptr` - User pointer to attribute name string
/// * `value_ptr` - User pointer to buffer for attribute value
/// * `size` - Size of the buffer (0 to query size needed)
///
/// # Returns
/// Size of attribute value
pub fn sys_getxattr(
    path_ptr: UserPtr<u8>,
    name_ptr: UserPtr<u8>,
    value_ptr: UserPtr<u8>,
    size: u64,
) -> KernelResult<usize> {
    do_getxattr(path_ptr, name_ptr, value_ptr, size, true)
}

/// sys_lgetxattr - get an extended attribute value (don't follow symlinks)
pub fn sys_lgetxattr(
    path_ptr: UserPtr<u8>,
    name_ptr: UserPtr<u8>,
    value_ptr: UserPtr<u8>,
    size: u64,
) -> KernelResult<usize> {
    do_getxattr(path_ptr, name_ptr, value_ptr, size, false)
}

/// Internal helper for getxattr/lgetxattr
fn do_getxattr(
    path_ptr: UserPtr<u8>,
    name_ptr: UserPtr<u8>,
    value_ptr: UserPtr<u8>,
    size: u64,
    follow: bool,
) -> KernelResult<usize> {
    let path = crate::fs::namei::getname(path_ptr, false)?;
    let name = xattr_name(name_ptr)?;
    let dentry = lookup_path_flags(&path, xattr_lookup(follow))?;
    let inode = dentry.get_inode().ok_or(KernelError::NotFound)?;
    getxattr_inode(&inode, &name, value_ptr, size)
}

/// sys_fgetxattr - get an extended attribute value from a file descriptor
pub fn sys_fgetxattr(
    fd: i32,
    name_ptr: UserPtr<u8>,
    value_ptr: UserPtr<u8>,
    size: u64,
) -> KernelResult<usize> {
    let file = fget(fd)?;
    let name = xattr_name(name_ptr)?;
    let inode = file.get_inode().ok_or(KernelError::BadFd)?;
    getxattr_inode(&inode, &name, value_ptr, size)
}

/// Linux listxattr: the NUL-separated names into the `size`-byte user
/// buffer (size 0: only their length)
fn listxattr_inode(inode: &Arc<Inode>, list_ptr: UserPtr<u8>, size: u64) -> KernelResult<usize> {
    if size == 0 {
        return inode.i_op.listxattr(inode, &mut []).map_err(xattr_err);
    }
    // At most XATTR_LIST_MAX (Linux listxattr), a fallible buffer; the
    // user buffer is only touched by the copy
    let size = size.min(XATTR_LIST_MAX as u64) as usize;
    let mut list = crate::util::kmem::try_vec(size, 0u8)?;
    let n = inode
        .i_op
        .listxattr(inode, &mut list)
        .map_err(|e| too_big(xattr_err(e), size, XATTR_LIST_MAX))?;
    copy_out(list_ptr, &list[..n])
}

/// sys_listxattr - list extended attribute names
///
/// # Arguments
/// * `path_ptr` - User pointer to path string
/// * `list_ptr` - User pointer to buffer for null-separated attribute names
/// * `size` - Size of the buffer (0 to query size needed)
///
/// # Returns
/// Total size of attribute names
pub fn sys_listxattr(
    path_ptr: UserPtr<u8>,
    list_ptr: UserPtr<u8>,
    size: u64,
) -> KernelResult<usize> {
    do_listxattr(path_ptr, list_ptr, size, true)
}

/// sys_llistxattr - list extended attribute names (don't follow symlinks)
pub fn sys_llistxattr(
    path_ptr: UserPtr<u8>,
    list_ptr: UserPtr<u8>,
    size: u64,
) -> KernelResult<usize> {
    do_listxattr(path_ptr, list_ptr, size, false)
}

/// Internal helper for listxattr/llistxattr
fn do_listxattr(
    path_ptr: UserPtr<u8>,
    list_ptr: UserPtr<u8>,
    size: u64,
    follow: bool,
) -> KernelResult<usize> {
    let path = crate::fs::namei::getname(path_ptr, false)?;
    let dentry = lookup_path_flags(&path, xattr_lookup(follow))?;
    let inode = dentry.get_inode().ok_or(KernelError::NotFound)?;
    listxattr_inode(&inode, list_ptr, size)
}

/// sys_flistxattr - list extended attribute names from a file descriptor
pub fn sys_flistxattr(fd: i32, list_ptr: UserPtr<u8>, size: u64) -> KernelResult<usize> {
    let inode = fget(fd)?.get_inode().ok_or(KernelError::BadFd)?;
    listxattr_inode(&inode, list_ptr, size)
}

/// Linux vfs_removexattr, write access already held
fn removexattr_inode(inode: &Arc<Inode>, name: &[u8]) -> KernelResult<()> {
    super::dac::xattr_permission(inode, name, super::dac::MAY_WRITE)?;
    inode.i_op.removexattr(inode, name).map_err(xattr_err)
}

/// sys_removexattr - remove an extended attribute
///
/// # Arguments
/// * `path_ptr` - User pointer to path string
/// * `name_ptr` - User pointer to attribute name string
pub fn sys_removexattr(path_ptr: UserPtr<u8>, name_ptr: UserPtr<u8>) -> KernelResult<()> {
    do_removexattr(path_ptr, name_ptr, true)
}

/// sys_lremovexattr - remove an extended attribute (don't follow symlinks)
pub fn sys_lremovexattr(path_ptr: UserPtr<u8>, name_ptr: UserPtr<u8>) -> KernelResult<()> {
    do_removexattr(path_ptr, name_ptr, false)
}

/// Internal helper for removexattr/lremovexattr
fn do_removexattr(path_ptr: UserPtr<u8>, name_ptr: UserPtr<u8>, follow: bool) -> KernelResult<()> {
    let path = crate::fs::namei::getname(path_ptr, false)?;
    let name = xattr_name(name_ptr)?;
    let fpath = crate::fs::namei::path_lookupat(
        crate::task::percpu::current_cwd(),
        &path,
        xattr_lookup(follow),
    )?;
    let inode = fpath.dentry.get_inode().ok_or(KernelError::NotFound)?;
    // setxattr/removexattr: write access first (EROFS), held across
    let _w = fpath.mnt.want_write()?;
    removexattr_inode(&inode, &name)
}

/// sys_fremovexattr - remove an extended attribute from a file descriptor
pub fn sys_fremovexattr(fd: i32, name_ptr: UserPtr<u8>) -> KernelResult<()> {
    let file = fget(fd)?;
    let name = xattr_name(name_ptr)?;
    let inode = file.get_inode().ok_or(KernelError::BadFd)?;
    // setxattr/removexattr: write access first (EROFS), held across
    let _w = file.want_write()?;
    removexattr_inode(&inode, &name)
}

// =============================================================================
// readahead syscall
// =============================================================================

// =============================================================================
// fallocate syscall
// =============================================================================

/// Mode flags for fallocate (from include/uapi/linux/falloc.h)
pub mod falloc_mode {
    /// Don't extend file size even if offset + len > size
    pub const FALLOC_FL_KEEP_SIZE: i32 = 0x01;
    /// Deallocate range (punch hole) - must be combined with KEEP_SIZE
    pub const FALLOC_FL_PUNCH_HOLE: i32 = 0x02;
    /// Reserved for future use
    pub const FALLOC_FL_NO_HIDE_STALE: i32 = 0x04;
    /// Collapse range, removing a hole
    pub const FALLOC_FL_COLLAPSE_RANGE: i32 = 0x08;
    /// Zero range without doing I/O
    pub const FALLOC_FL_ZERO_RANGE: i32 = 0x10;
    /// Insert range, creating a hole
    pub const FALLOC_FL_INSERT_RANGE: i32 = 0x20;
    /// Write zeroes to the range, allocating it (Linux 6.17+)
    pub const FALLOC_FL_WRITE_ZEROES: i32 = 0x80;
    /// Unshare shared blocks (for reflinked files)
    pub const FALLOC_FL_UNSHARE_RANGE: i32 = 0x40;
}

/// sys_fallocate - manipulate file space
///
/// Preallocates or deallocates space in a file without doing I/O.
///
/// # Arguments
/// * `fd` - File descriptor (must be open for writing)
/// * `mode` - Operation mode (0 = allocate, or FALLOC_FL_* flags)
/// * `offset` - Starting offset in file
/// * `len` - Length of region to manipulate
///
/// # Errors
/// * -EBADF: fd is not a valid file descriptor or not open for writing
/// * -EINVAL: Invalid mode, offset, or len
/// * -ENODEV: fd does not refer to a regular file
/// * -ESPIPE: fd refers to a pipe or socket
/// * -ENOSPC: Not enough space on device
/// * -EOPNOTSUPP: Filesystem does not support this operation
///
/// Linux ksys_fallocate + vfs_fallocate: the argument and file checks in
/// Linux's order, then the filesystem's op under i_rwsem
pub fn sys_fallocate(fd: i32, mode: i32, offset: i64, len: i64) -> KernelResult<()> {
    let file = fget(fd)?;
    vfs_fallocate(&file, mode, offset, len)
}

/// Linux vfs_fallocate on an open file (fallocate(2), MADV_REMOVE)
pub fn vfs_fallocate(file: &super::File, mode: i32, offset: i64, len: i64) -> KernelResult<()> {
    use falloc_mode::*;
    if offset < 0 || len <= 0 {
        return Err(KernelError::InvalidArgument);
    }
    const MODES: i32 = FALLOC_FL_PUNCH_HOLE
        | FALLOC_FL_COLLAPSE_RANGE
        | FALLOC_FL_ZERO_RANGE
        | FALLOC_FL_INSERT_RANGE
        | FALLOC_FL_UNSHARE_RANGE
        | FALLOC_FL_WRITE_ZEROES;
    if mode & !(MODES | FALLOC_FL_KEEP_SIZE) != 0 {
        return Err(KernelError::OperationNotSupported);
    }
    let keep = mode & FALLOC_FL_KEEP_SIZE != 0;
    match mode & MODES {
        0 | FALLOC_FL_UNSHARE_RANGE | FALLOC_FL_ZERO_RANGE => {}
        FALLOC_FL_PUNCH_HOLE if keep => {}
        FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_INSERT_RANGE | FALLOC_FL_WRITE_ZEROES if !keep => {}
        _ => return Err(KernelError::OperationNotSupported),
    }
    if !file.is_writable() {
        return Err(KernelError::BadFd);
    }
    let inode = file.get_inode().ok_or(KernelError::BadFd)?;
    if inode.i_swapfile.load(core::sync::atomic::Ordering::Acquire) {
        return Err(KernelError::TextBusy);
    }
    let m = inode.mode();
    if m.is_fifo() {
        return Err(KernelError::IllegalSeek);
    }
    if m.is_dir() {
        return Err(KernelError::IsDirectory);
    }
    if !m.is_file() && !m.is_blkdev() {
        return Err(KernelError::NoDevice);
    }
    offset.checked_add(len).ok_or(KernelError::FileTooLarge)?;
    let _lock = inode.lock();
    inode
        .i_op
        .fallocate(&inode, mode, offset as u64, len as u64)
}
