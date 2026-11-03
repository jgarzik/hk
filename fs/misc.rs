//! Miscellaneous filesystem syscalls
//!
//! This module contains:
//! - mount, umount2, pivot_root (filesystem mounting)
//! - ioctl (device control)
//! - xattr syscalls (extended attributes)
//! - readahead (file readahead)

use alloc::sync::Arc;
use alloc::vec;

use crate::arch::Uaccess;
use crate::fs::{KernelError, LookupFlags, lookup_path_flags};
use crate::uaccess::{
    UaccessArch, copy_to_user, put_user, strncpy_from_user, strncpy_from_user_str,
};

use super::syscall::{PATH_MAX, current_fd_table};

// ============================================================================
// mount, umount2 syscalls
// ============================================================================

/// Block device required
pub const ENOTBLK: i64 = -15;
/// Resource busy
pub const EBUSY: i64 = -16;
/// No such device or filesystem type
pub const ENODEV: i64 = -19;

/// mount(2) flags (Linux uapi/linux/mount.h)
mod ms {
    pub const RDONLY: u64 = 1;
    pub const NOSUID: u64 = 2;
    pub const NODEV: u64 = 4;
    pub const NOEXEC: u64 = 8;
    pub const REMOUNT: u64 = 32;
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
    /// already behaves that way (no atime updates, no mandatory locks);
    /// everything else (MS_SYNCHRONOUS, MS_DIRSYNC, MS_NOSYMFOLLOW, ...)
    /// is EINVAL instead of being ignored
    pub const KNOWN: u64 = RDONLY
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

/// Per-mount MNT_* flags of mount(2) flags
fn mnt_flags(flags: u64) -> u32 {
    use super::mount::{MNT_NODEV, MNT_NOEXEC, MNT_NOSUID, MNT_READONLY};
    let mut f = 0;
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
    f
}

/// MS_REMOUNT (Linux do_remount): the mount's flags become exactly the
/// requested set. The read-only switch goes first and is all-or-nothing
/// (EBUSY while files are open for writing or changes are in progress,
/// with nothing changed); only then the per-mount flags are replaced.
fn remount(m: &Arc<super::mount::Mount>, flags: u64) -> Result<(), KernelError> {
    let _s = m.sb.s_umount.write();
    if flags & ms::RDONLY != 0 {
        m.sb.make_rdonly()?;
    } else {
        m.sb.make_rdwr();
    }
    m.set_flags(mnt_flags(flags))
}

/// MS_REMOUNT|MS_BIND (Linux do_reconfigure_mnt): this mount's flags
/// only, read-only included; the superblock is untouched
fn reconfigure_mnt(m: &Arc<super::mount::Mount>, flags: u64) -> Result<(), KernelError> {
    let _s = m.sb.s_umount.write();
    m.set_flags(mnt_flags(flags))
}

/// MS_SHARED / MS_SLAVE / MS_PRIVATE / MS_UNBINDABLE (Linux
/// do_change_type): exactly one type (else EINVAL), for the subtree
/// with MS_REC
fn change_type(m: &Arc<super::mount::Mount>, flags: u64) -> Result<(), KernelError> {
    use super::pnode::{Prop, change_propagation, subtree};
    let p = match flags & !(ms::REC | ms::SILENT) {
        ms::SHARED => Prop::Shared,
        ms::SLAVE => Prop::Slave,
        ms::PRIVATE => Prop::Private,
        ms::UNBINDABLE => Prop::Unbindable,
        _ => return Err(KernelError::InvalidArgument),
    };
    let _ns = super::mount::NAMESPACE_SEM.write();
    let targets = if flags & ms::REC != 0 {
        subtree(m)
    } else {
        alloc::vec![m.clone()]
    };
    for t in targets {
        change_propagation(&t, p);
    }
    Ok(())
}

/// Mount whose root `target` is (Linux path_mounted), else EINVAL
fn mount_at(target: &super::Path) -> Result<Arc<super::mount::Mount>, KernelError> {
    if Arc::ptr_eq(&target.dentry, &target.mnt.root) {
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
pub fn sys_mount(source_ptr: u64, target_ptr: u64, fstype_ptr: u64, flags: u64, _data: u64) -> i64 {
    match path_mount(source_ptr, target_ptr, fstype_ptr, flags) {
        Ok(()) => 0,
        Err(e) => e.sysret(),
    }
}

fn path_mount(
    source_ptr: u64,
    target_ptr: u64,
    fstype_ptr: u64,
    mut flags: u64,
) -> Result<(), KernelError> {
    use crate::uaccess::UaccessError;
    // Linux copy_mount_string (strndup_user): EFAULT, EINVAL if too long;
    // type, then source, then the target as a path name. Source and type
    // may be absent for remount / propagation changes; a type is a name
    // of a registered filesystem: not text, no such one
    let too_long = |e| match e {
        UaccessError::TooLong => KernelError::InvalidArgument,
        _ => KernelError::BadAddress,
    };
    let fstype = if fstype_ptr != 0 {
        match strncpy_from_user_str::<Uaccess>(fstype_ptr, PATH_MAX) {
            Ok(s) => s,
            Err(UaccessError::Encoding) => return Err(KernelError::NoDevice),
            Err(e) => return Err(too_long(e)),
        }
    } else {
        Default::default()
    };
    let source = if source_ptr != 0 {
        strncpy_from_user::<Uaccess>(source_ptr, PATH_MAX).map_err(too_long)?
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
        return reconfigure_mnt(&mount_at(&mp)?, flags);
    }
    if flags & ms::REMOUNT != 0 {
        return remount(&mount_at(&mp)?, flags);
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
    new_mount(&source, &fstype, mp, flags)
}

/// Mount a new instance of `fstype` on `mp` (Linux do_new_mount)
fn new_mount(source: &[u8], fstype: &str, mp: super::Path, flags: u64) -> Result<(), KernelError> {
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
        super::mount::dev_super(fs_type, source)
    } else {
        (fs_type.mount)(fs_type)
    };
    let r = sb.and_then(|sb| {
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
            | KernelError::NotFound),
        ) => Err(e),
        Err(_) => Err(KernelError::InvalidArgument),
    }
}

/// sys_umount2 (Linux ksys_umount): flags, the target (a mount's root,
/// followed unless UMOUNT_NOFOLLOW), CAP_SYS_ADMIN after the lookup,
/// then do_umount
pub fn sys_umount2(target_ptr: u64, flags: i32) -> i64 {
    use super::mount::umount_flags::{MNT_DETACH, MNT_EXPIRE, MNT_FORCE, UMOUNT_NOFOLLOW};
    let r = (|| {
        if flags & !(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW) != 0 {
            return Err(KernelError::InvalidArgument);
        }
        let target = crate::fs::namei::getname(target_ptr, false)?;
        let lf = LookupFlags {
            follow: flags & UMOUNT_NOFOLLOW == 0,
            ..LookupFlags::open()
        };
        let target =
            crate::fs::namei::path_lookupat(crate::task::percpu::current_cwd(), &target, lf)?;
        if !crate::task::capable(crate::task::CAP_SYS_ADMIN) {
            return Err(KernelError::NotPermitted);
        }
        super::mount::do_umount(mount_at(&target)?, flags)
    })();
    match r {
        Ok(()) => 0,
        Err(e) => e.sysret(),
    }
}

/// pivot_root(new_root, put_old) (Linux: may_mount, both paths as
/// directories, then the mount rules of do_pivot_root)
pub fn sys_pivot_root(new_root_ptr: u64, put_old_ptr: u64) -> i64 {
    let r = (|| {
        if !crate::task::capable(crate::task::CAP_SYS_ADMIN) {
            return Err(KernelError::NotPermitted);
        }
        let cwd = crate::task::percpu::current_cwd;
        let new = crate::fs::namei::getname(new_root_ptr, false)?;
        let new = crate::fs::namei::path_lookupat(cwd(), &new, LookupFlags::opendir())?;
        let old = crate::fs::namei::getname(put_old_ptr, false)?;
        let old = crate::fs::namei::path_lookupat(cwd(), &old, LookupFlags::opendir())?;
        super::mount::do_pivot_root(&new, &old)
    })();
    match r {
        Ok(()) => 0,
        Err(e) => e.sysret(),
    }
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
/// 0 on success, negative errno on error.
pub fn sys_ioctl(fd: i32, cmd: u32, arg: u64) -> i64 {
    use crate::uaccess::get_user;

    // Generic ioctl constants (work on any fd)
    const FIONBIO: u32 = 0x5421; // Set/clear non-blocking mode
    const FIOASYNC: u32 = 0x5452; // Enable async I/O notification
    const FIOCLEX: u32 = 0x5451; // Set close-on-exec flag
    const FIONCLEX: u32 = 0x5450; // Clear close-on-exec flag
    const FIONREAD: u32 = 0x541B; // Get bytes available for read

    // Get file from fd
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f.clone(),
        None => return KernelError::BadFd.sysret(),
    };

    // Handle generic ioctls first (work on any fd type)
    match cmd {
        FIONBIO => {
            // Set/clear non-blocking mode
            if arg == 0 {
                return KernelError::BadAddress.sysret();
            }
            let enable: i32 = match get_user::<Uaccess, i32>(arg) {
                Ok(v) => v,
                Err(_) => return KernelError::BadAddress.sysret(),
            };
            let current_flags = file.get_flags();
            if enable != 0 {
                file.set_status_flags(current_flags | crate::fs::flags::O_NONBLOCK);
            } else {
                file.set_status_flags(current_flags & !crate::fs::flags::O_NONBLOCK);
            }
            return 0;
        }
        FIOASYNC => {
            // Set/clear O_ASYNC flag
            if arg == 0 {
                return KernelError::BadAddress.sysret();
            }
            let enable: i32 = match get_user::<Uaccess, i32>(arg) {
                Ok(v) => v,
                Err(_) => return KernelError::BadAddress.sysret(),
            };
            let current_flags = file.get_flags();
            if enable != 0 {
                file.set_status_flags(current_flags | crate::fs::flags::O_ASYNC);
            } else {
                file.set_status_flags(current_flags & !crate::fs::flags::O_ASYNC);
            }
            return 0;
        }
        FIOCLEX => {
            // Set close-on-exec flag
            current_fd_table()
                .lock()
                .set_fd_flags(fd, crate::task::FD_CLOEXEC);
            return 0;
        }
        FIONCLEX => {
            // Clear close-on-exec flag
            current_fd_table().lock().set_fd_flags(fd, 0);
            return 0;
        }
        FIONREAD if file.get_inode().is_some_and(|i| i.mode().is_socket()) => {
            // Sockets answer FIONREAD/SIOCINQ themselves
            return match file.f_op.ioctl(&file, cmd, arg) {
                Ok(v) => v,
                Err(e) => e.sysret(),
            };
        }
        FIONREAD => {
            // Get bytes available for reading
            if arg == 0 {
                return KernelError::BadAddress.sysret();
            }
            // For most file types, return 0 (would need file-type specific handling)
            // Pipes, sockets, etc. would have buffered data
            let available: i32 = 0;
            if put_user::<Uaccess, i32>(arg, available).is_err() {
                return KernelError::BadAddress.sysret();
            }
            return 0;
        }
        _ => {} // Fall through to device-specific handling
    }

    // Get the inode to check file type
    let inode = match file.get_inode() {
        Some(i) => i,
        None => return KernelError::BadFd.sysret(),
    };

    // Block devices answer through their file (Linux blkdev_ioctl)
    if inode.mode().is_blkdev() {
        match file.ops().ioctl(&file, cmd, arg) {
            Ok(v) => v,
            Err(e) => e.sysret(),
        }
    } else if inode.mode().is_chrdev() {
        // Character device ioctls - route to CharDevice::ioctl()
        use crate::fs::chardev::get_chardev;

        let device = match get_chardev(inode.rdev) {
            Some(d) => d,
            None => return KernelError::NoDeviceOrAddress.sysret(),
        };

        match device.ioctl(cmd, arg) {
            Ok(result) => result,
            Err(crate::fs::chardev::DeviceError::NotTty) => KernelError::NotTty.sysret(),
            Err(crate::fs::chardev::DeviceError::InvalidArg) => {
                KernelError::InvalidArgument.sysret()
            }
            Err(crate::fs::chardev::DeviceError::NotSupported) => KernelError::NotTty.sysret(),
            Err(crate::fs::chardev::DeviceError::Fault) => KernelError::BadAddress.sysret(),
            Err(_) => KernelError::Io.sysret(),
        }
    } else {
        // Other files (sockets, ...): the file's own ioctl
        match file.ops().ioctl(&file, cmd, arg) {
            Ok(v) => v,
            Err(e) => e.sysret(),
        }
    }
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

/// Helper to convert KernelError to errno for xattr operations
fn xattr_error_to_errno(e: KernelError) -> i64 {
    match e {
        KernelError::NotFound => KernelError::NotFound.sysret(),
        KernelError::NoData => KernelError::NoData.sysret(),
        KernelError::AlreadyExists => KernelError::AlreadyExists.sysret(),
        KernelError::Range => KernelError::Range.sysret(),
        KernelError::OperationNotSupported => KernelError::OperationNotSupported.sysret(),
        KernelError::PermissionDenied => KernelError::NotPermitted.sysret(),
        KernelError::Io => KernelError::Io.sysret(),
        _ => KernelError::InvalidArgument.sysret(),
    }
}

/// Copy xattr value from user space
fn copy_xattr_value_from_user(value_ptr: u64, size: u64) -> Result<alloc::vec::Vec<u8>, i64> {
    use crate::uaccess::copy_from_user;

    if size > XATTR_SIZE_MAX as u64 {
        return Err(KernelError::Range.sysret());
    }

    if size == 0 {
        return Ok(alloc::vec::Vec::new());
    }

    // Validate user buffer
    if !Uaccess::access_ok(value_ptr, size as usize) {
        return Err(KernelError::BadAddress.sysret());
    }

    // Allocate and copy value from user space
    let mut value = vec![0u8; size as usize];
    if copy_from_user::<Uaccess>(&mut value, value_ptr, size as usize).is_err() {
        return Err(KernelError::BadAddress.sysret());
    }
    Ok(value)
}

/// sys_setxattr - set an extended attribute value
///
/// # Arguments
/// * `path_ptr` - User pointer to path string
/// * `name_ptr` - User pointer to attribute name string
/// * `value_ptr` - User pointer to attribute value
/// * `size` - Size of the value
/// * `flags` - XATTR_CREATE or XATTR_REPLACE
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_setxattr(path_ptr: u64, name_ptr: u64, value_ptr: u64, size: u64, flags: i32) -> i64 {
    do_setxattr(path_ptr, name_ptr, value_ptr, size, flags, true)
}

/// sys_lsetxattr - set an extended attribute value (don't follow symlinks)
pub fn sys_lsetxattr(path_ptr: u64, name_ptr: u64, value_ptr: u64, size: u64, flags: i32) -> i64 {
    do_setxattr(path_ptr, name_ptr, value_ptr, size, flags, false)
}

/// Internal helper for setxattr/lsetxattr
fn do_setxattr(
    path_ptr: u64,
    name_ptr: u64,
    value_ptr: u64,
    size: u64,
    flags: i32,
    follow_symlinks: bool,
) -> i64 {
    // Validate flags
    if flags as u32 & !(XATTR_CREATE | XATTR_REPLACE) != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Copy path from user
    let path = match crate::fs::namei::getname(path_ptr, false) {
        Ok(p) => p,
        Err(e) => return e.sysret(),
    };

    // Copy attribute name from user
    let name = match strncpy_from_user_str::<Uaccess>(name_ptr, XATTR_NAME_MAX + 1) {
        Ok(n) => n,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Validate name length
    if name.is_empty() || name.len() > XATTR_NAME_MAX {
        return KernelError::Range.sysret();
    }

    // Copy value from user
    let value = match copy_xattr_value_from_user(value_ptr, size) {
        Ok(v) => v,
        Err(e) => return e,
    };

    // Lookup path
    let lookup_flags = if follow_symlinks {
        LookupFlags::open()
    } else {
        LookupFlags {
            follow: false,
            ..LookupFlags::open()
        }
    };

    let fpath = match crate::fs::namei::path_lookupat(
        crate::task::percpu::current_cwd(),
        &path,
        lookup_flags,
    ) {
        Ok(p) => p,
        Err(e) => return e.sysret(),
    };
    let dentry = fpath.dentry.clone();

    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return KernelError::NotFound.sysret(),
    };

    // setxattr/removexattr: write access first (EROFS), held across
    let _w = match fpath.mnt.want_write() {
        Ok(w) => w,
        Err(e) => return e.sysret(),
    };
    if let Err(e) = super::dac::xattr_permission(&inode, &name, super::dac::MAY_WRITE) {
        return e.sysret();
    }

    // Call inode operation
    match inode.i_op.setxattr(&inode, &name, &value, flags as u32) {
        Ok(()) => 0,
        Err(e) => xattr_error_to_errno(e),
    }
}

/// sys_fsetxattr - set an extended attribute value on a file descriptor
pub fn sys_fsetxattr(fd: i32, name_ptr: u64, value_ptr: u64, size: u64, flags: i32) -> i64 {
    // Validate flags
    if flags as u32 & !(XATTR_CREATE | XATTR_REPLACE) != 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    // Copy attribute name from user
    let name = match strncpy_from_user_str::<Uaccess>(name_ptr, XATTR_NAME_MAX + 1) {
        Ok(n) => n,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Validate name length
    if name.is_empty() || name.len() > XATTR_NAME_MAX {
        return KernelError::Range.sysret();
    }

    // Copy value from user
    let value = match copy_xattr_value_from_user(value_ptr, size) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let inode = match file.get_inode() {
        Some(i) => i,
        None => return KernelError::BadFd.sysret(),
    };

    // setxattr/removexattr: write access first (EROFS), held across
    let _w = match file.want_write() {
        Ok(w) => w,
        Err(e) => return e.sysret(),
    };
    if let Err(e) = super::dac::xattr_permission(&inode, &name, super::dac::MAY_WRITE) {
        return e.sysret();
    }

    // Call inode operation
    match inode.i_op.setxattr(&inode, &name, &value, flags as u32) {
        Ok(()) => 0,
        Err(e) => xattr_error_to_errno(e),
    }
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
/// Size of attribute value on success, negative errno on error
pub fn sys_getxattr(path_ptr: u64, name_ptr: u64, value_ptr: u64, size: u64) -> i64 {
    do_getxattr(path_ptr, name_ptr, value_ptr, size, true)
}

/// sys_lgetxattr - get an extended attribute value (don't follow symlinks)
pub fn sys_lgetxattr(path_ptr: u64, name_ptr: u64, value_ptr: u64, size: u64) -> i64 {
    do_getxattr(path_ptr, name_ptr, value_ptr, size, false)
}

/// Internal helper for getxattr/lgetxattr
fn do_getxattr(
    path_ptr: u64,
    name_ptr: u64,
    value_ptr: u64,
    size: u64,
    follow_symlinks: bool,
) -> i64 {
    // Copy path from user
    let path = match crate::fs::namei::getname(path_ptr, false) {
        Ok(p) => p,
        Err(e) => return e.sysret(),
    };

    // Copy attribute name from user
    let name = match strncpy_from_user_str::<Uaccess>(name_ptr, XATTR_NAME_MAX + 1) {
        Ok(n) => n,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Validate name length
    if name.is_empty() || name.len() > XATTR_NAME_MAX {
        return KernelError::Range.sysret();
    }

    // Lookup path
    let lookup_flags = if follow_symlinks {
        LookupFlags::open()
    } else {
        LookupFlags {
            follow: false,
            ..LookupFlags::open()
        }
    };

    let dentry = match lookup_path_flags(&path, lookup_flags) {
        Ok(d) => d,
        Err(e) => return e.sysret(),
    };

    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return KernelError::NotFound.sysret(),
    };

    if let Err(e) = super::dac::xattr_permission(&inode, &name, super::dac::MAY_READ) {
        return e.sysret();
    }

    // If size is 0, query the size needed
    if size == 0 {
        let mut empty_buf: [u8; 0] = [];
        match inode.i_op.getxattr(&inode, &name, &mut empty_buf) {
            Ok(attr_size) => return attr_size as i64,
            Err(e) => return xattr_error_to_errno(e),
        }
    }

    // Validate size
    if size > XATTR_SIZE_MAX as u64 {
        return KernelError::Range.sysret();
    }

    // Validate user buffer
    if !Uaccess::access_ok(value_ptr, size as usize) {
        return KernelError::BadAddress.sysret();
    }

    // Allocate kernel buffer
    let mut value = vec![0u8; size as usize];

    // Get the attribute
    match inode.i_op.getxattr(&inode, &name, &mut value) {
        Ok(attr_size) => {
            // Copy to user
            if copy_to_user::<Uaccess>(value_ptr, &value[..attr_size]).is_err() {
                return KernelError::BadAddress.sysret();
            }
            attr_size as i64
        }
        Err(e) => xattr_error_to_errno(e),
    }
}

/// sys_fgetxattr - get an extended attribute value from a file descriptor
pub fn sys_fgetxattr(fd: i32, name_ptr: u64, value_ptr: u64, size: u64) -> i64 {
    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    // Copy attribute name from user
    let name = match strncpy_from_user_str::<Uaccess>(name_ptr, XATTR_NAME_MAX + 1) {
        Ok(n) => n,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Validate name length
    if name.is_empty() || name.len() > XATTR_NAME_MAX {
        return KernelError::Range.sysret();
    }

    let inode = match file.get_inode() {
        Some(i) => i,
        None => return KernelError::BadFd.sysret(),
    };

    if let Err(e) = super::dac::xattr_permission(&inode, &name, super::dac::MAY_READ) {
        return e.sysret();
    }

    // If size is 0, query the size needed
    if size == 0 {
        let mut empty_buf: [u8; 0] = [];
        match inode.i_op.getxattr(&inode, &name, &mut empty_buf) {
            Ok(attr_size) => return attr_size as i64,
            Err(e) => return xattr_error_to_errno(e),
        }
    }

    // Validate size
    if size > XATTR_SIZE_MAX as u64 {
        return KernelError::Range.sysret();
    }

    // Validate user buffer
    if !Uaccess::access_ok(value_ptr, size as usize) {
        return KernelError::BadAddress.sysret();
    }

    // Allocate kernel buffer
    let mut value = vec![0u8; size as usize];

    // Get the attribute
    match inode.i_op.getxattr(&inode, &name, &mut value) {
        Ok(attr_size) => {
            // Copy to user
            if copy_to_user::<Uaccess>(value_ptr, &value[..attr_size]).is_err() {
                return KernelError::BadAddress.sysret();
            }
            attr_size as i64
        }
        Err(e) => xattr_error_to_errno(e),
    }
}

/// sys_listxattr - list extended attribute names
///
/// # Arguments
/// * `path_ptr` - User pointer to path string
/// * `list_ptr` - User pointer to buffer for null-separated attribute names
/// * `size` - Size of the buffer (0 to query size needed)
///
/// # Returns
/// Total size of attribute names on success, negative errno on error
pub fn sys_listxattr(path_ptr: u64, list_ptr: u64, size: u64) -> i64 {
    do_listxattr(path_ptr, list_ptr, size, true)
}

/// sys_llistxattr - list extended attribute names (don't follow symlinks)
pub fn sys_llistxattr(path_ptr: u64, list_ptr: u64, size: u64) -> i64 {
    do_listxattr(path_ptr, list_ptr, size, false)
}

/// Internal helper for listxattr/llistxattr
fn do_listxattr(path_ptr: u64, list_ptr: u64, size: u64, follow_symlinks: bool) -> i64 {
    // Copy path from user
    let path = match crate::fs::namei::getname(path_ptr, false) {
        Ok(p) => p,
        Err(e) => return e.sysret(),
    };

    // Lookup path
    let lookup_flags = if follow_symlinks {
        LookupFlags::open()
    } else {
        LookupFlags {
            follow: false,
            ..LookupFlags::open()
        }
    };

    let dentry = match lookup_path_flags(&path, lookup_flags) {
        Ok(d) => d,
        Err(e) => return e.sysret(),
    };

    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return KernelError::NotFound.sysret(),
    };

    // If size is 0, query the size needed
    if size == 0 {
        let mut empty_buf: [u8; 0] = [];
        match inode.i_op.listxattr(&inode, &mut empty_buf) {
            Ok(list_size) => return list_size as i64,
            Err(e) => return xattr_error_to_errno(e),
        }
    }

    // Validate user buffer
    if !Uaccess::access_ok(list_ptr, size as usize) {
        return KernelError::BadAddress.sysret();
    }

    // At most XATTR_LIST_MAX (Linux listxattr), a fallible buffer
    let mut list = match crate::util::kmem::try_vec(size.min(XATTR_LIST_MAX as u64) as usize, 0u8) {
        Ok(l) => l,
        Err(e) => return e.sysret(),
    };

    // Get the list
    match inode.i_op.listxattr(&inode, &mut list) {
        Ok(list_size) => {
            // Copy to user
            if copy_to_user::<Uaccess>(list_ptr, &list[..list_size]).is_err() {
                return KernelError::BadAddress.sysret();
            }
            list_size as i64
        }
        Err(e) => xattr_error_to_errno(e),
    }
}

/// sys_flistxattr - list extended attribute names from a file descriptor
pub fn sys_flistxattr(fd: i32, list_ptr: u64, size: u64) -> i64 {
    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    let inode = match file.get_inode() {
        Some(i) => i,
        None => return KernelError::BadFd.sysret(),
    };

    // If size is 0, query the size needed
    if size == 0 {
        let mut empty_buf: [u8; 0] = [];
        match inode.i_op.listxattr(&inode, &mut empty_buf) {
            Ok(list_size) => return list_size as i64,
            Err(e) => return xattr_error_to_errno(e),
        }
    }

    // Validate user buffer
    if !Uaccess::access_ok(list_ptr, size as usize) {
        return KernelError::BadAddress.sysret();
    }

    // At most XATTR_LIST_MAX (Linux listxattr), a fallible buffer
    let mut list = match crate::util::kmem::try_vec(size.min(XATTR_LIST_MAX as u64) as usize, 0u8) {
        Ok(l) => l,
        Err(e) => return e.sysret(),
    };

    // Get the list
    match inode.i_op.listxattr(&inode, &mut list) {
        Ok(list_size) => {
            // Copy to user
            if copy_to_user::<Uaccess>(list_ptr, &list[..list_size]).is_err() {
                return KernelError::BadAddress.sysret();
            }
            list_size as i64
        }
        Err(e) => xattr_error_to_errno(e),
    }
}

/// sys_removexattr - remove an extended attribute
///
/// # Arguments
/// * `path_ptr` - User pointer to path string
/// * `name_ptr` - User pointer to attribute name string
///
/// # Returns
/// 0 on success, negative errno on error
pub fn sys_removexattr(path_ptr: u64, name_ptr: u64) -> i64 {
    do_removexattr(path_ptr, name_ptr, true)
}

/// sys_lremovexattr - remove an extended attribute (don't follow symlinks)
pub fn sys_lremovexattr(path_ptr: u64, name_ptr: u64) -> i64 {
    do_removexattr(path_ptr, name_ptr, false)
}

/// Internal helper for removexattr/lremovexattr
fn do_removexattr(path_ptr: u64, name_ptr: u64, follow_symlinks: bool) -> i64 {
    // Copy path from user
    let path = match crate::fs::namei::getname(path_ptr, false) {
        Ok(p) => p,
        Err(e) => return e.sysret(),
    };

    // Copy attribute name from user
    let name = match strncpy_from_user_str::<Uaccess>(name_ptr, XATTR_NAME_MAX + 1) {
        Ok(n) => n,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Validate name length
    if name.is_empty() || name.len() > XATTR_NAME_MAX {
        return KernelError::Range.sysret();
    }

    // Lookup path
    let lookup_flags = if follow_symlinks {
        LookupFlags::open()
    } else {
        LookupFlags {
            follow: false,
            ..LookupFlags::open()
        }
    };

    let fpath = match crate::fs::namei::path_lookupat(
        crate::task::percpu::current_cwd(),
        &path,
        lookup_flags,
    ) {
        Ok(p) => p,
        Err(e) => return e.sysret(),
    };
    let dentry = fpath.dentry.clone();

    let inode = match dentry.get_inode() {
        Some(i) => i,
        None => return KernelError::NotFound.sysret(),
    };

    // setxattr/removexattr: write access first (EROFS), held across
    let _w = match fpath.mnt.want_write() {
        Ok(w) => w,
        Err(e) => return e.sysret(),
    };
    if let Err(e) = super::dac::xattr_permission(&inode, &name, super::dac::MAY_WRITE) {
        return e.sysret();
    }

    // Call inode operation
    match inode.i_op.removexattr(&inode, &name) {
        Ok(()) => 0,
        Err(e) => xattr_error_to_errno(e),
    }
}

/// sys_fremovexattr - remove an extended attribute from a file descriptor
pub fn sys_fremovexattr(fd: i32, name_ptr: u64) -> i64 {
    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f,
        None => return KernelError::BadFd.sysret(),
    };

    // Copy attribute name from user
    let name = match strncpy_from_user_str::<Uaccess>(name_ptr, XATTR_NAME_MAX + 1) {
        Ok(n) => n,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Validate name length
    if name.is_empty() || name.len() > XATTR_NAME_MAX {
        return KernelError::Range.sysret();
    }

    let inode = match file.get_inode() {
        Some(i) => i,
        None => return KernelError::BadFd.sysret(),
    };

    // setxattr/removexattr: write access first (EROFS), held across
    let _w = match file.want_write() {
        Ok(w) => w,
        Err(e) => return e.sysret(),
    };
    if let Err(e) = super::dac::xattr_permission(&inode, &name, super::dac::MAY_WRITE) {
        return e.sysret();
    }

    // Call inode operation
    match inode.i_op.removexattr(&inode, &name) {
        Ok(()) => 0,
        Err(e) => xattr_error_to_errno(e),
    }
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
    #[allow(dead_code)]
    pub const FALLOC_FL_NO_HIDE_STALE: i32 = 0x04;
    /// Collapse range, removing a hole
    pub const FALLOC_FL_COLLAPSE_RANGE: i32 = 0x08;
    /// Zero range without doing I/O
    pub const FALLOC_FL_ZERO_RANGE: i32 = 0x10;
    /// Insert range, creating a hole
    pub const FALLOC_FL_INSERT_RANGE: i32 = 0x20;
    /// Unshare shared blocks (for reflinked files)
    #[allow(dead_code)]
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
/// # Returns
/// 0 on success, negative errno on error:
/// * -EBADF: fd is not a valid file descriptor or not open for writing
/// * -EINVAL: Invalid mode, offset, or len
/// * -ENODEV: fd does not refer to a regular file
/// * -ESPIPE: fd refers to a pipe or socket
/// * -ENOSPC: Not enough space on device
/// * -EOPNOTSUPP: Filesystem does not support this operation
pub fn sys_fallocate(fd: i32, mode: i32, offset: i64, len: i64) -> i64 {
    use falloc_mode::*;

    // Validate offset and len
    if offset < 0 || len <= 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // Check for overflow
    if offset.checked_add(len).is_none() {
        return KernelError::InvalidArgument.sysret();
    }

    // Validate mode - check for unknown flags
    let known_flags = FALLOC_FL_KEEP_SIZE
        | FALLOC_FL_PUNCH_HOLE
        | FALLOC_FL_COLLAPSE_RANGE
        | FALLOC_FL_ZERO_RANGE
        | FALLOC_FL_INSERT_RANGE;

    if mode & !known_flags != 0 {
        return KernelError::OperationNotSupported.sysret();
    }

    // PUNCH_HOLE requires KEEP_SIZE
    if mode & FALLOC_FL_PUNCH_HOLE != 0 && mode & FALLOC_FL_KEEP_SIZE == 0 {
        return KernelError::InvalidArgument.sysret();
    }

    // COLLAPSE_RANGE and INSERT_RANGE are mutually exclusive with other flags
    if mode & FALLOC_FL_COLLAPSE_RANGE != 0 && mode != FALLOC_FL_COLLAPSE_RANGE {
        return KernelError::InvalidArgument.sysret();
    }
    if mode & FALLOC_FL_INSERT_RANGE != 0 && mode != FALLOC_FL_INSERT_RANGE {
        return KernelError::InvalidArgument.sysret();
    }

    // Get file from fd table
    let file = match current_fd_table().lock().get(fd) {
        Some(f) => f.clone(),
        None => return KernelError::BadFd.sysret(),
    };

    // Must be open for writing
    if !file.is_writable() {
        return KernelError::BadFd.sysret();
    }

    // Get inode
    let inode = match file.get_inode() {
        Some(i) => i,
        None => return KernelError::BadFd.sysret(),
    };

    // Must be a regular file
    if !inode.mode().is_file() {
        if inode.mode().is_dir() {
            return KernelError::IsDirectory.sysret();
        }
        // Pipe or socket
        return KernelError::IllegalSeek.sysret();
    }

    let offset_u64 = offset as u64;
    let len_u64 = len as u64;
    let current_size = inode.get_size();

    // Handle different modes
    if mode == 0 {
        // Default mode: allocate space, extend file if needed
        let new_size = offset_u64 + len_u64;
        if new_size > current_size {
            inode.set_size(new_size);
        }
        // For ramfs, no actual allocation needed (memory is allocated on write)
        0
    } else if mode & FALLOC_FL_KEEP_SIZE != 0 && mode & FALLOC_FL_PUNCH_HOLE != 0 {
        // Punch hole: deallocate space (zero the range for ramfs)
        // For ramfs, this is effectively a no-op since we don't track holes
        0
    } else if mode == FALLOC_FL_KEEP_SIZE {
        // Allocate but don't extend size
        // For ramfs, this is a no-op
        0
    } else if mode & FALLOC_FL_ZERO_RANGE != 0 {
        // Zero range: zero the specified range
        // For ramfs, we would need to write zeros to the range
        // For now, treat as no-op (data will be zero when read if not written)
        let keep_size = mode & FALLOC_FL_KEEP_SIZE != 0;
        if !keep_size {
            let new_size = offset_u64 + len_u64;
            if new_size > current_size {
                inode.set_size(new_size);
            }
        }
        0
    } else if mode == FALLOC_FL_COLLAPSE_RANGE {
        // Collapse range: remove a hole, shift data left
        // Requires more complex implementation
        KernelError::OperationNotSupported.sysret()
    } else if mode == FALLOC_FL_INSERT_RANGE {
        // Insert range: create hole, shift data right
        // Requires more complex implementation
        KernelError::OperationNotSupported.sysret()
    } else {
        KernelError::OperationNotSupported.sysret()
    }
}
