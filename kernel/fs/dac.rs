//! Discretionary access control (Linux fs/namei.c generic_permission,
//! may_open, may_create, may_delete; fs/attr.c setattr_prepare)
//!
//! The identity for file system checks is the caller's fsuid/fsgid; there
//! is no uid 0 bypass: privilege comes only from effective capabilities
//! (CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_FOWNER, CAP_CHOWN,
//! CAP_FSETID). hk has no supplementary groups, so group membership is
//! the fsgid alone.
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

/// Effective capability check against explicit credentials
/// (capable_wrt_inode_uidgid: hk has a single user namespace)
pub fn capable(c: &Cred, cap: u32) -> bool {
    c.cap_effective.has(cap)
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
fn mode_ok(c: &Cred, inode: &Inode, mask: u32) -> bool {
    let m = inode.mode().perm() as u32;
    let bits = if c.fsuid == inode.uid() {
        m >> 6
    } else if in_group(c, inode.gid()) {
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
    let mask = mask & (MAY_READ | MAY_WRITE | MAY_EXEC);
    if mode_ok(c, inode, mask) {
        return Ok(());
    }
    let mode = inode.mode();
    if mode.is_dir() {
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
    if (mask & MAY_EXEC == 0 || mode.perm() & S_IXUGO != 0) && capable(c, CAP_DAC_OVERRIDE) {
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

/// file_remove_privs: drop set-id bits before data changes
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
/// caller is in the file's group or has CAP_FSETID
pub fn chmod(inode: &Inode, perm: u16) -> Result<(), KernelError> {
    let _w = want_write(inode)?;
    let c = cred();
    if !owner_or_capable(&c, inode) {
        return Err(KernelError::NotPermitted);
    }
    let mut perm = perm & 0o7777;
    if !in_group_or_capable(&c, inode.gid()) {
        perm &= !S_ISGID;
    }
    inode.set_mode_perm(perm);
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
/// group-executable or the caller could not keep it (even for root)
pub fn chown(inode: &Inode, uid: Option<Uid>, gid: Option<Gid>) -> Result<(), KernelError> {
    let _w = want_write(inode)?;
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
