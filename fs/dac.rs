//! Discretionary access control (Linux fs/namei.c generic_permission,
//! may_open, may_create, may_delete; fs/attr.c setattr_prepare)
//!
//! The identity for file system checks is the caller's fsuid/fsgid; there
//! is no uid 0 bypass: privilege comes only from effective capabilities
//! (CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_FOWNER, CAP_CHOWN,
//! CAP_FSETID). Group membership is the fsgid or a supplementary group
//! (Linux in_group_p).
//!
//! Kernel-internal lookups and opens (boot, init exec) run with the root
//! credentials of the boot context and so pass every check here.

use super::KernelError;
use super::file::flags::{O_ACCMODE, O_APPEND, O_TRUNC};
use super::inode::{Gid, Inode, InodeMode, Uid};
use super::superblock::WriteAccess;
use crate::task::{
    CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_EMPTY_SET, CAP_FOWNER, CAP_FSETID,
    CAP_SYS_ADMIN, Cred,
};

/// Permission mask: may execute / search
pub const MAY_EXEC: u32 = 1;
/// Permission mask: may write
pub const MAY_WRITE: u32 = 2;
/// Permission mask: may read
pub const MAY_READ: u32 = 4;
/// Permission mask: write is an append
pub const MAY_APPEND: u32 = 8;
/// Permission mask: check comes from access()
pub const MAY_ACCESS: u32 = 16;
/// Permission mask: check comes from open()
pub const MAY_OPEN: u32 = 32;
/// Permission mask: check comes from chdir()
pub const MAY_CHDIR: u32 = 64;

/// O_NOATIME (same value on every arch)
pub const O_NOATIME: u32 = 0o1000000;

const S_ISUID: u16 = 0o4000;
const S_ISGID: u16 = 0o2000;
const S_ISVTX: u16 = 0o1000;
const S_IXGRP: u16 = 0o010;
const S_IXUGO: u16 = 0o111;

/// Credentials of the current task
pub fn cred() -> Cred {
    crate::task::current_cred()
}

/// Effective capability check against explicit credentials (the
/// caller's, or its override credentials: capable_wrt_inode_uidgid; hk
/// has a single user namespace); a granted one marks the task
/// PF_SUPERPRIV, as Linux ns_capable_common
pub fn capable(c: &Cred, cap: u32) -> bool {
    let ok = c.cap_effective.has(cap);
    if ok {
        crate::task::percpu::current().set_flag(crate::task::pf::SUPERPRIV);
    }
    ok
}

/// in_group_p: the fsgid or a supplementary group
pub fn in_group(c: &Cred, gid: Gid) -> bool {
    c.fsgid == gid || c.groups.contains(gid)
}

/// in_group_or_capable: may keep or set S_ISGID for group `gid`
pub fn in_group_or_capable(c: &Cred, gid: Gid) -> bool {
    in_group(c, gid) || capable(c, CAP_FSETID)
}

/// inode_owner_or_capable
pub fn owner_or_capable(c: &Cred, inode: &Inode) -> bool {
    c.fsuid == inode.uid() || capable(c, CAP_FOWNER)
}

/// acl_permission_check: only the caller's class (owner, group, other)
/// of mode bits counts
fn mode_ok(c: &Cred, uid: Uid, gid: Gid, perm: u16, mask: u32) -> bool {
    let m = u32::from(perm);
    let bits = if c.fsuid == uid {
        m >> 6
    } else if in_group(c, gid) {
        m >> 3
    } else {
        m
    };
    mask & !bits & 7 == 0
}

/// generic_permission: mode bits, then capability overrides.
/// CAP_DAC_READ_SEARCH reads files and reads/searches directories;
/// CAP_DAC_OVERRIDE grants everything except exec of a file with no
/// x bit at all.
pub fn generic_permission(c: &Cred, inode: &Inode, mask: u32) -> Result<(), KernelError> {
    let mode = inode.mode();
    permission_ids(
        c,
        inode.uid(),
        inode.gid(),
        mode.perm(),
        mode.is_dir(),
        mask,
    )
}

/// `generic_permission` for an object described by its owner, group and
/// mode bits rather than an inode (POSIX message queues, which Linux
/// keeps as mqueue-fs inodes)
pub fn permission_ids(
    c: &Cred,
    uid: Uid,
    gid: Gid,
    perm: u16,
    is_dir: bool,
    mask: u32,
) -> Result<(), KernelError> {
    let mask = mask & (MAY_READ | MAY_WRITE | MAY_EXEC);
    if mode_ok(c, uid, gid, perm, mask) {
        return Ok(());
    }
    if is_dir {
        if mask & MAY_WRITE == 0 && capable(c, CAP_DAC_READ_SEARCH) {
            return Ok(());
        }
        if capable(c, CAP_DAC_OVERRIDE) {
            return Ok(());
        }
        return Err(KernelError::PermissionDenied);
    }
    if mask == MAY_READ && capable(c, CAP_DAC_READ_SEARCH) {
        return Ok(());
    }
    if (mask & MAY_EXEC == 0 || perm & S_IXUGO != 0) && capable(c, CAP_DAC_OVERRIDE) {
        return Ok(());
    }
    Err(KernelError::PermissionDenied)
}

/// mnt_want_write on the file system of `inode`: EROFS if read-only;
/// hold the guard across the modification
pub fn want_write(inode: &Inode) -> Result<WriteAccess, KernelError> {
    match inode.superblock() {
        Some(sb) => sb.want_write(),
        None => Ok(WriteAccess::none()),
    }
}

/// sb_permission: writing a regular file, directory or symlink of a
/// read-only file system is EROFS (devices, FIFOs, sockets are fine)
fn sb_permission(inode: &Inode, mask: u32) -> Result<(), KernelError> {
    let m = inode.mode();
    let ro = inode.superblock().is_some_and(|sb| sb.rdonly());
    if mask & MAY_WRITE != 0 && ro && (m.is_file() || m.is_dir() || m.is_symlink()) {
        return Err(KernelError::ReadOnlyFs);
    }
    Ok(())
}

/// inode_permission with explicit credentials: sb_permission, then the
/// inode's InodeOps::permission (generic_permission unless overridden)
pub fn permission_as(c: &Cred, inode: &Inode, mask: u32) -> Result<(), KernelError> {
    sb_permission(inode, mask)?;
    inode.i_op.permission(inode, c, mask)
}

/// inode_permission for the current task
pub fn permission(inode: &Inode, mask: u32) -> Result<(), KernelError> {
    permission_as(&cred(), inode, mask)
}

/// access_override_creds: access()/faccessat() without AT_EACCESS check
/// with the real ids; capabilities follow the real uid (root keeps its
/// permitted set, anyone else has none)
pub fn access_cred(c: &Cred) -> Cred {
    let mut o = c.clone();
    o.fsuid = c.uid;
    o.fsgid = c.gid;
    o.cap_effective = if c.uid == 0 {
        c.cap_permitted
    } else {
        CAP_EMPTY_SET
    };
    o
}

/// ACC_MODE of open flags (O_TRUNC needs write, O_APPEND is noted)
pub fn acc_mode(flags: u32) -> u32 {
    let mut m = match flags & O_ACCMODE {
        0 => MAY_READ,
        1 => MAY_WRITE,
        _ => MAY_READ | MAY_WRITE,
    };
    if flags & O_TRUNC != 0 {
        m |= MAY_WRITE;
    }
    if flags & O_APPEND != 0 {
        m |= MAY_APPEND;
    }
    m
}

/// may_open: file type rules, then permission for `acc` (0 for a file
/// this open just created), then the O_NOATIME owner rule
pub fn may_open(c: &Cred, inode: &Inode, acc: u32, flags: u32) -> Result<(), KernelError> {
    let mode = inode.mode();
    if mode.is_symlink() {
        return Err(KernelError::TooManySymlinks);
    }
    if mode.is_dir() {
        if acc & MAY_WRITE != 0 {
            return Err(KernelError::IsDirectory);
        }
        if acc & MAY_EXEC != 0 {
            return Err(KernelError::PermissionDenied);
        }
    } else if !mode.is_file() && acc & MAY_EXEC != 0 {
        return Err(KernelError::PermissionDenied);
    }
    permission_as(c, inode, MAY_OPEN | acc)?;
    if flags & O_NOATIME != 0 && !owner_or_capable(c, inode) {
        return Err(KernelError::NotPermitted);
    }
    Ok(())
}

/// may_create: write and search on the parent (callers report EEXIST
/// first, like Linux)
pub fn may_create(c: &Cred, dir: &Inode) -> Result<(), KernelError> {
    permission_as(c, dir, MAY_WRITE | MAY_EXEC)
}

/// check_sticky: in a sticky directory only the owner of the entry or of
/// the directory (or CAP_FOWNER) may remove or replace it
fn sticky(c: &Cred, dir: &Inode, inode: &Inode) -> bool {
    dir.mode().perm() & S_ISVTX != 0
        && c.fsuid != inode.uid()
        && c.fsuid != dir.uid()
        && !capable(c, CAP_FOWNER)
}

/// may_delete: write and search on the parent, the sticky rule, then the
/// victim's type against `isdir` (ENOTDIR / EISDIR)
pub fn may_delete(c: &Cred, dir: &Inode, victim: &Inode, isdir: bool) -> Result<(), KernelError> {
    permission_as(c, dir, MAY_WRITE | MAY_EXEC)?;
    if sticky(c, dir, victim) {
        return Err(KernelError::NotPermitted);
    }
    // An active swap file is neither unlinked nor renamed (Linux
    // vfs_unlink / vfs_rename: IS_SWAPFILE -> EPERM)
    if victim
        .i_swapfile
        .load(core::sync::atomic::Ordering::Acquire)
    {
        return Err(KernelError::NotPermitted);
    }
    let is_dir = victim.mode().is_dir();
    if isdir && !is_dir {
        return Err(KernelError::NotDirectory);
    }
    if !isdir && is_dir {
        return Err(KernelError::IsDirectory);
    }
    Ok(())
}

/// Mode for a new inode in `dir` (vfs_prepare_mode): the umask, then
/// mode_strip_sgid (a group-executable SGID file only in a SGID
/// directory whose group the caller is in, or with CAP_FSETID)
pub fn create_mode(c: &Cred, dir: &Inode, mode: u16) -> u16 {
    let umask = crate::task::percpu::current_fs().map_or(0o022, |fs| fs.get_umask());
    let mode = mode & !umask;
    let ty = InodeMode(mode);
    if mode & (S_ISGID | S_IXGRP) != (S_ISGID | S_IXGRP)
        || ty.is_dir()
        || dir.mode().perm() & S_ISGID == 0
        || in_group_or_capable(c, dir.gid())
    {
        return mode;
    }
    mode & !S_ISGID
}

/// inode_init_owner: owner is the fsuid; the group is the fsgid, or the
/// parent's group under a SGID parent (whose subdirectories inherit
/// S_ISGID)
pub fn init_owner(dir: &Inode, mode: InodeMode) -> (Uid, Gid, InodeMode) {
    let c = cred();
    if dir.mode().perm() & S_ISGID == 0 {
        return (c.fsuid, c.fsgid, mode);
    }
    let mode = if mode.is_dir() {
        InodeMode(mode.0 | S_ISGID)
    } else {
        mode
    };
    (c.fsuid, dir.gid(), mode)
}

// =============================================================================
// Attribute changes (setattr_prepare and friends)
// =============================================================================

/// setattr_should_drop_suidgid: set-id bits a write or truncate by `c`
/// must clear (SUID always, SGID if group-executable or the caller is
/// outside the group; nothing with CAP_FSETID; regular files only)
pub fn kill_bits(c: &Cred, inode: &Inode) -> u16 {
    let mode = inode.mode();
    if !mode.is_file() || capable(c, CAP_FSETID) {
        return 0;
    }
    let p = mode.perm();
    let mut kill = p & S_ISUID;
    if p & S_ISGID != 0 && (p & S_IXGRP != 0 || !in_group_or_capable(c, inode.gid())) {
        kill |= S_ISGID;
    }
    kill
}

/// file_remove_privs: drop set-id bits before data changes; the caller
/// holds i_rwsem (write, truncate), as chmod and chown do
pub fn remove_privs(inode: &Inode) {
    if inode.mode().perm() & (S_ISUID | S_ISGID) == 0 {
        return;
    }
    let kill = kill_bits(&cred(), inode);
    if kill != 0 {
        inode.clear_mode_bits(kill);
    }
}

/// chmod: owner or CAP_FOWNER; S_ISGID silently dropped unless the
/// caller is in the file's group or has CAP_FSETID. The check and the
/// change are one step under i_rwsem (Linux chmod_common: inode_lock
/// around notify_change), so a racing chown or write cannot slip
/// between them.
pub fn chmod(p: &super::Path, perm: u16) -> Result<(), KernelError> {
    let inode = &*p.dentry.get_inode().ok_or(KernelError::NotFound)?;
    let _w = p.mnt.want_write()?;
    let _l = inode.lock();
    inode.i_op.setattr_ok(inode)?;
    let c = cred();
    if !owner_or_capable(&c, inode) {
        return Err(KernelError::NotPermitted);
    }
    let mut perm = perm & 0o7777;
    if !in_group_or_capable(&c, inode.gid()) {
        perm &= !S_ISGID;
    }
    inode.set_mode_perm(perm);
    inode.set_ctime(crate::time::TIMEKEEPER.current_time());
    inode.i_op.setattr_done(inode);
    Ok(())
}

/// chown_ok: CAP_CHOWN, or the owner "changing" the owner to itself
fn chown_ok(c: &Cred, inode: &Inode, uid: Uid) -> bool {
    (c.fsuid == inode.uid() && uid == inode.uid()) || capable(c, CAP_CHOWN)
}

/// chgrp_ok: CAP_CHOWN, or the owner moving the file to its own group
/// or to a group it is in
fn chgrp_ok(c: &Cred, inode: &Inode, gid: Gid) -> bool {
    (c.fsuid == inode.uid() && (gid == inode.gid() || in_group(c, gid))) || capable(c, CAP_CHOWN)
}

/// chown_common + notify_change: permission per id, then for
/// non-directories S_ISUID is always cleared and S_ISGID when
/// group-executable or the caller could not keep it (even for root).
/// Under i_rwsem across the checks, the kill computed from the current
/// mode, and the id, mode and ctime changes (Linux chown_common).
pub fn chown(p: &super::Path, uid: Option<Uid>, gid: Option<Gid>) -> Result<(), KernelError> {
    let inode = &*p.dentry.get_inode().ok_or(KernelError::NotFound)?;
    let _w = p.mnt.want_write()?;
    let _l = inode.lock();
    inode.i_op.setattr_ok(inode)?;
    let c = cred();
    if uid.is_some_and(|u| !chown_ok(&c, inode, u)) || gid.is_some_and(|g| !chgrp_ok(&c, inode, g))
    {
        return Err(KernelError::NotPermitted);
    }
    let mode = inode.mode();
    let p = mode.perm();
    let mut kill = 0;
    if !mode.is_dir() {
        kill = p & S_ISUID;
        if p & S_ISGID != 0 && (p & S_IXGRP != 0 || !in_group_or_capable(&c, inode.gid())) {
            kill |= S_ISGID;
        }
    }
    // The implied mode change is itself a setattr ATTR_MODE
    if kill != 0 && !owner_or_capable(&c, inode) {
        return Err(KernelError::NotPermitted);
    }
    if let Some(u) = uid {
        inode.set_uid(u);
    }
    if let Some(g) = gid {
        inode.set_gid(g);
    }
    if kill != 0 {
        inode.clear_mode_bits(kill);
    }
    // chown_common: ATTR_CTIME even when no id changes
    inode.set_ctime(crate::time::TIMEKEEPER.current_time());
    inode.i_op.setattr_done(inode);
    Ok(())
}

/// Timestamp updates: explicit times need ownership (or CAP_FOWNER);
/// "now" needs ownership or write permission
pub fn may_utimes(inode: &Inode, explicit: bool) -> Result<(), KernelError> {
    let c = cred();
    if owner_or_capable(&c, inode) {
        return Ok(());
    }
    if explicit {
        return Err(KernelError::NotPermitted);
    }
    permission_as(&c, inode, MAY_WRITE)
}

/// vfs_truncate checks by path: directories EISDIR, other non-regular
/// files EINVAL, then write permission
pub fn may_truncate(inode: &Inode) -> Result<(), KernelError> {
    let mode = inode.mode();
    if mode.is_dir() {
        return Err(KernelError::IsDirectory);
    }
    if !mode.is_file() {
        return Err(KernelError::InvalidArgument);
    }
    permission(inode, MAY_WRITE)
}

/// xattr_permission: security.* and system.* are left to the file
/// system, trusted.* needs CAP_SYS_ADMIN, user.* only exists on regular
/// files, directories and sockets (sticky directories: owner only for
/// writes); then plain permission. Denials that hide a name are ENODATA
/// for reads.
pub fn xattr_permission(inode: &Inode, name: &str, mask: u32) -> Result<(), KernelError> {
    let c = cred();
    let hidden = if mask & MAY_WRITE != 0 {
        KernelError::NotPermitted
    } else {
        KernelError::NoData
    };
    if name.starts_with("security.") || name.starts_with("system.") {
        return Ok(());
    }
    if name.starts_with("trusted.") {
        return if capable(&c, CAP_SYS_ADMIN) {
            Ok(())
        } else {
            Err(hidden)
        };
    }
    if name.starts_with("user.") {
        let mode = inode.mode();
        if mode.is_dir() {
            if mode.perm() & S_ISVTX != 0 && mask & MAY_WRITE != 0 && !owner_or_capable(&c, inode) {
                return Err(KernelError::NotPermitted);
            }
        } else if !mode.is_file() && !mode.is_socket() {
            return Err(hidden);
        }
    }
    permission_as(&c, inode, mask)
}

// fs.protected_* (Linux fs/namei.c sysctl_protected_*): kernel defaults
// 0, as on Linux (distributions raise them at boot)
static PROTECTED_SYMLINKS: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
static PROTECTED_HARDLINKS: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
static PROTECTED_FIFOS: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
static PROTECTED_REGULAR: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

fn knob(k: &core::sync::atomic::AtomicU8) -> u8 {
    k.load(core::sync::atomic::Ordering::Relaxed)
}

macro_rules! protected_ctl {
    ($path:literal, $k:ident, $max:literal) => {
        crate::sysctl::Ctl {
            path: $path,
            mode: 0o600,
            show: || alloc::vec![i64::from(knob(&$k))],
            store: |v| {
                crate::sysctl::range(v[0], 0, $max)?;
                $k.store(v[0] as u8, core::sync::atomic::Ordering::Relaxed);
                Ok(())
            },
            text: None,
        }
    };
}

/// /proc/sys/fs/protected_* (mode 0600, as Linux)
pub static PROTECTED_CTLS: &[crate::sysctl::Ctl] = &[
    protected_ctl!("fs/protected_symlinks", PROTECTED_SYMLINKS, 1),
    protected_ctl!("fs/protected_hardlinks", PROTECTED_HARDLINKS, 1),
    protected_ctl!("fs/protected_fifos", PROTECTED_FIFOS, 2),
    protected_ctl!("fs/protected_regular", PROTECTED_REGULAR, 2),
];

const S_IWOTH: u16 = 0o002;
const S_IWGRP: u16 = 0o020;

/// Following symlink `link` found in `dir` (Linux may_follow_link): with
/// fs.protected_symlinks, a link in a sticky world-writable directory
/// is followed only by its owner or when the directory's owner owns it
/// (EACCES)
pub fn may_follow_link(c: &Cred, dir: &Inode, link: &Inode) -> Result<(), KernelError> {
    if knob(&PROTECTED_SYMLINKS) == 0 || link.uid() == c.fsuid {
        return Ok(());
    }
    let mode = dir.mode().raw();
    if mode & (S_ISVTX | S_IWOTH) != S_ISVTX | S_IWOTH || dir.uid() == link.uid() {
        return Ok(());
    }
    Err(KernelError::PermissionDenied)
}

/// Hard-linking `inode` (Linux may_linkat): with fs.protected_hardlinks
/// only its owner (or CAP_FOWNER) may, unless it is a safe source: a
/// regular file, not set-user-ID, not set-group-ID-executable, that the
/// caller may read and write (EPERM)
pub fn may_linkat(c: &Cred, inode: &Inode) -> Result<(), KernelError> {
    if knob(&PROTECTED_HARDLINKS) == 0 || owner_or_capable(c, inode) {
        return Ok(());
    }
    let mode = inode.mode();
    let raw = mode.raw();
    let safe = mode.is_file()
        && raw & S_ISUID == 0
        && raw & (S_ISGID | S_IXGRP) != S_ISGID | S_IXGRP
        && permission_as(c, inode, MAY_READ | MAY_WRITE).is_ok();
    if safe {
        Ok(())
    } else {
        Err(KernelError::NotPermitted)
    }
}

/// An O_CREAT open of the existing `inode` in `dir` (Linux
/// may_create_in_sticky): with fs.protected_fifos / _regular, a FIFO or
/// regular file in a sticky directory owned by neither the directory's
/// owner nor the caller is refused if the directory is world-writable
/// (level 1), or group-writable (level 2) (EACCES)
pub fn may_create_in_sticky(c: &Cred, dir: &Inode, inode: &Inode) -> Result<(), KernelError> {
    let dmode = dir.mode().raw();
    let mode = inode.mode();
    let level = if mode.is_file() {
        knob(&PROTECTED_REGULAR)
    } else if mode.is_fifo() {
        knob(&PROTECTED_FIFOS)
    } else {
        return Ok(());
    };
    if dmode & S_ISVTX == 0 || level == 0 {
        return Ok(());
    }
    if inode.uid() == dir.uid() || inode.uid() == c.fsuid {
        return Ok(());
    }
    if dmode & S_IWOTH != 0 || (dmode & S_IWGRP != 0 && level >= 2) {
        return Err(KernelError::PermissionDenied);
    }
    Ok(())
}
