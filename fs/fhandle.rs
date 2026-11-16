//! File handles (Linux fs/fhandle.c): name_to_handle_at encodes a path's
//! object as a `struct file_handle`, open_by_handle_at opens it again
//! on the filesystem of a mount fd (`fs::exportfs` does the encoding
//! and decoding)
//!
//! struct file_handle is a header, `handle_bytes` (u32: the room on the
//! way in, the size on the way out) and `handle_type` (i32: the
//! filesystem's type in the low 8 bits, user flags in the top 16), then
//! up to MAX_HANDLE_SZ bytes of `f_handle`.

use super::exportfs::{
    self, EXPORT_FH_CONNECTABLE, EXPORT_FH_DIR_ONLY, EXPORT_FH_FID, FILEID_INVALID,
    FILEID_IS_CONNECTABLE, FILEID_IS_DIR, FILEID_USER_FLAGS_MASK, FILEID_VALID_USER_FLAGS,
    HANDLE_CHECK_SUBTREE, HandleCtx, MAX_HANDLE_SZ,
};
use super::flags::{AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_FOLLOW, O_CLOEXEC, O_LARGEFILE};
use super::namei::{filename_lookup, getname};
use super::{DentryRef, FileRef, KernelError, LookupFlags, Path};
use crate::task::FD_CLOEXEC;
use crate::uaccess::{UserPtr, copy_from_user, copy_to_user, get_user, put_user};
use crate::util::error::KernelResult;

/// name_to_handle_at: a file id that need not decode (Linux
/// AT_HANDLE_FID)
const AT_HANDLE_FID: i32 = 0x200;
/// name_to_handle_at: the mount id is the u64 unique one (Linux
/// AT_HANDLE_MNT_ID_UNIQUE)
const AT_HANDLE_MNT_ID_UNIQUE: i32 = 0x001;
/// name_to_handle_at: a handle that decodes to a connected path (Linux
/// AT_HANDLE_CONNECTABLE)
const AT_HANDLE_CONNECTABLE: i32 = 0x002;

/// open_by_handle_at's mount fd for the root of nsfs (Linux
/// FD_NSFS_ROOT; FD_PIDFS_ROOT, -10002, names pidfs's)
const FD_NSFS_ROOT: i32 = -10003;

/// Bytes of struct file_handle before f_handle
const HDR: usize = 8;
/// Words of the largest f_handle
const MAX_DWORDS: usize = MAX_HANDLE_SZ / 4;

/// The header of the user's struct file_handle at `ufh`: EFAULT
fn read_hdr(ufh: u64) -> Result<(u32, i32), KernelError> {
    let bytes = get_user::<u32>(ufh).map_err(|_| KernelError::BadAddress)?;
    let ty = get_user::<i32>(ufh.checked_add(4).ok_or(KernelError::BadAddress)?)
        .map_err(|_| KernelError::BadAddress)?;
    Ok((bytes, ty))
}

/// sys_name_to_handle_at (Linux): the handle of the object `name` names
/// from `dfd` (a final symlink followed only with AT_SYMLINK_FOLLOW, an
/// empty name allowed with AT_EMPTY_PATH) into `ufh`, and its mount's
/// id into `mnt_id` (an int, or with AT_HANDLE_MNT_ID_UNIQUE the u64
/// unique id). EINVAL for unknown flags or AT_HANDLE_CONNECTABLE with
/// AT_HANDLE_FID or AT_EMPTY_PATH; the walk's errors; EOPNOTSUPP if the
/// filesystem cannot make that kind of handle; EOVERFLOW, with the size
/// needed in handle_bytes, if `ufh` is too small.
pub fn sys_name_to_handle_at(
    dfd: i32,
    name: UserPtr<u8>,
    ufh: u64,
    mnt_id: u64,
    flag: i32,
) -> KernelResult<i32> {
    let known = AT_SYMLINK_FOLLOW
        | AT_EMPTY_PATH
        | AT_HANDLE_FID
        | AT_HANDLE_MNT_ID_UNIQUE
        | AT_HANDLE_CONNECTABLE;
    if flag & !known != 0 {
        return Err(KernelError::InvalidArgument);
    }
    // A file id is not meant to decode, a connectable handle is; and a
    // descriptor's object may have no known parent
    let fh_flags = if flag & AT_HANDLE_CONNECTABLE != 0 {
        if flag & (AT_HANDLE_FID | AT_EMPTY_PATH) != 0 {
            return Err(KernelError::InvalidArgument);
        }
        EXPORT_FH_CONNECTABLE
    } else if flag & AT_HANDLE_FID != 0 {
        EXPORT_FH_FID
    } else {
        0
    };
    let lf = LookupFlags {
        follow: flag & AT_SYMLINK_FOLLOW != 0,
        ..LookupFlags::default()
    };
    let path = filename_lookup(dfd, &getname(name, flag & AT_EMPTY_PATH != 0)?, lf)?;
    let unique = flag & AT_HANDLE_MNT_ID_UNIQUE != 0;
    name_to_handle(&path, ufh, mnt_id, unique, fh_flags)
}

/// Encode `path`'s object into the user's handle (Linux
/// do_sys_name_to_handle): the header is read, the handle encoded in
/// the room it gives, then the mount id and the handle written back
fn name_to_handle(
    path: &Path,
    ufh: u64,
    mnt_id: u64,
    unique: bool,
    fh_flags: u32,
) -> KernelResult<i32> {
    if !exportfs::can_encode_fh(exportfs::export_op(&path.dentry), fh_flags) {
        return Err(KernelError::OperationNotSupported);
    }
    let (room, _) = read_hdr(ufh)?;
    let room = usize::try_from(room)
        .ok()
        .filter(|&r| r <= MAX_HANDLE_SZ)
        .ok_or(KernelError::InvalidArgument)?;
    let mut fh = [0u32; MAX_DWORDS];
    let (ty, words, ret) = match exportfs::encode_fh(&path.dentry, &mut fh[..room / 4], fh_flags)? {
        Ok((ty, words)) => (handle_type(&path.dentry, ty, fh_flags), words, Ok(0)),
        // Only the header goes back, with the size needed
        Err(need) => (FILEID_INVALID, need, Err(KernelError::Overflow)),
    };
    let id_ok = if unique {
        put_user(mnt_id, path.mnt.mnt_id_unique)
    } else {
        // Linux mnt_id is an int
        put_user(mnt_id, path.mnt.mnt_id as i32)
    };
    id_ok.map_err(|_| KernelError::BadAddress)?;
    let len = words * 4;
    let mut out = [0u8; HDR + MAX_HANDLE_SZ];
    let len32 = u32::try_from(len).unwrap_or(u32::MAX);
    out[..4].copy_from_slice(&len32.to_ne_bytes());
    out[4..HDR].copy_from_slice(&ty.to_ne_bytes());
    let body = if ret.is_ok() { len } else { 0 };
    for (d, w) in out[HDR..HDR + body]
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .zip(&fh)
    {
        *d = w.to_ne_bytes();
    }
    copy_to_user(ufh, &out[..HDR + body]).map_err(|_| KernelError::BadAddress)?;
    ret
}

/// A decodable handle's type as the user sees it: a connectable one
/// says so, and whether it is a directory's, for the decode (Linux
/// do_sys_name_to_handle's FILEID_IS_CONNECTABLE, FILEID_IS_DIR)
fn handle_type(dentry: &DentryRef, ty: u8, fh_flags: u32) -> i32 {
    let mut t = i32::from(ty);
    if fh_flags & EXPORT_FH_CONNECTABLE != 0 {
        t |= FILEID_IS_CONNECTABLE;
        if dentry.get_inode().is_some_and(|i| i.mode().is_dir()) {
            t |= FILEID_IS_DIR;
        }
    }
    t
}

/// The mount fd's path (Linux get_path_anchor): a descriptor's path
/// (any open file, O_PATH included), the cwd, or nsfs's root; EBADF
/// otherwise. FD_PIDFS_ROOT is EBADF: hk has no pidfs (BUGS.md).
fn path_anchor(fd: i32) -> Result<Path, KernelError> {
    if fd >= 0 {
        return super::io::fget_raw(fd)?.f_path().ok_or(KernelError::BadFd);
    }
    match fd {
        AT_FDCWD => crate::task::percpu::current_cwd().ok_or(KernelError::NotFound),
        FD_NSFS_ROOT => {
            let m = super::pseudo::NSFS.mnt()?;
            let root = m.root.clone();
            Ok(Path::new(m, root))
        }
        // FD_PIDFS_ROOT among them: no pidfs
        _ => Err(KernelError::BadFd),
    }
}

/// The default check of who may decode a handle on the mount fd's
/// filesystem (Linux may_decode_fh): CAP_DAC_READ_SEARCH. Linux also
/// lets an O_DIRECTORY open through for a caller with CAP_SYS_ADMIN
/// over the filesystem's or the mount namespace's user namespace that
/// has CAP_DAC_READ_SEARCH in its own (setting HANDLE_CHECK_PERMS, and
/// HANDLE_CHECK_SUBTREE for a bind mount's subtree, and
/// EXPORT_FH_DIR_ONLY); hk's capabilities ignore user namespaces
/// (BUGS.md), where that last check is this first one again: EPERM.
fn may_decode_fh(_ctx: &mut HandleCtx, _o_flags: u32) -> Result<(), KernelError> {
    if crate::task::capable(crate::task::CAP_DAC_READ_SEARCH) {
        return Ok(());
    }
    Err(KernelError::NotPermitted)
}

/// The ids of `d`'s inode map into the caller's user namespace through
/// the mount (Linux privileged_wrt_inode_uidgid): hk has one user
/// namespace mapping every id and no idmapped mounts
fn privileged_wrt_inode(_d: &DentryRef) -> bool {
    true
}

/// A decoded dentry is acceptable to open_by_handle_at (Linux
/// vfs_dentry_acceptable): always under the old model (no
/// HANDLE_CHECK_* flags); else every inode from it up to the mount fd's
/// directory or the filesystem's root has mapped ids, and with
/// HANDLE_CHECK_SUBTREE the walk must reach the mount fd's directory
fn acceptable(ctx: &HandleCtx, dentry: &DentryRef) -> bool {
    if ctx.flags == 0 {
        return true;
    }
    if !privileged_wrt_inode(dentry) {
        return false;
    }
    let root = &ctx.root.dentry;
    let mut d = dentry.clone();
    while !DentryRef::ptr_eq(&d, root) {
        let Some(p) = d.get_parent() else {
            break;
        };
        if !privileged_wrt_inode(&p) {
            return false;
        }
        d = p;
    }
    ctx.flags & HANDLE_CHECK_SUBTREE == 0 || DentryRef::ptr_eq(&d, root)
}

/// The path the user's handle names on the mount fd's filesystem (Linux
/// handle_to_path): EFAULT, EINVAL for a size of 0 or past
/// MAX_HANDLE_SZ, a negative type or unknown user flags, EBADF for the
/// mount fd, the permission check's error, then ESTALE for a handle
/// that names nothing there (ENOMEM stays)
fn handle_to_path(mountdirfd: i32, ufh: u64, o_flags: u32) -> Result<Path, KernelError> {
    let (bytes, ty) = read_hdr(ufh)?;
    let len = usize::try_from(bytes)
        .ok()
        .filter(|&b| b != 0 && b <= MAX_HANDLE_SZ)
        .ok_or(KernelError::InvalidArgument)?;
    let user_flags = ty & FILEID_USER_FLAGS_MASK;
    if ty < 0 || user_flags & !FILEID_VALID_USER_FLAGS != 0 {
        return Err(KernelError::InvalidArgument);
    }
    let mut ctx = HandleCtx {
        root: path_anchor(mountdirfd)?,
        flags: 0,
        fh_flags: 0,
    };
    let nop = ctx.root.mnt.sb.s_op.export_op();
    match nop.and_then(|op| op.permission(&mut ctx, o_flags)) {
        Some(r) => r?,
        None => may_decode_fh(&mut ctx, o_flags)?,
    }
    let mut raw = [0u8; MAX_HANDLE_SZ];
    let body = ufh.checked_add(HDR as u64).ok_or(KernelError::BadAddress)?;
    copy_from_user(&mut raw[..len], body, len).map_err(|_| KernelError::BadAddress)?;
    // Encoded connectable: decode to a path below the mount fd
    if ty & FILEID_IS_CONNECTABLE != 0 {
        ctx.fh_flags |= EXPORT_FH_CONNECTABLE;
        ctx.flags |= HANDLE_CHECK_SUBTREE;
    }
    if ty & FILEID_IS_DIR != 0 {
        ctx.fh_flags |= EXPORT_FH_DIR_ONLY;
    }
    // The filesystem never sees the user flags; whole words only
    let mut fh = [0u32; MAX_DWORDS];
    for (w, b) in fh.iter_mut().zip(raw[..len].as_chunks::<4>().0) {
        *w = u32::from_ne_bytes(*b);
    }
    let fh = &fh[..len / 4];
    let mnt = ctx.root.mnt.clone();
    let d = exportfs::decode_fh(
        &mnt,
        fh,
        ty & !FILEID_USER_FLAGS_MASK,
        ctx.fh_flags,
        &mut |d| acceptable(&ctx, d),
    )
    .map_err(|e| match e {
        KernelError::OutOfMemory => e,
        _ => KernelError::StaleHandle,
    })?;
    Ok(Path::new(mnt, d))
}

/// sys_open_by_handle_at (Linux): open the object the user's handle
/// names on `mountdirfd`'s filesystem, with open(2) `flags` (O_LARGEFILE
/// added on 64-bit, Linux force_o_largefile); the descriptor is
/// reserved after the decode (Linux FD_ADD)
pub fn sys_open_by_handle_at(mountdirfd: i32, ufh: u64, flags: i32) -> KernelResult<i32> {
    // The open(2) flag word, bits as given
    let flags = flags as u32 | O_LARGEFILE;
    let path = handle_to_path(mountdirfd, ufh, flags)?;
    let fd_flags = if flags & O_CLOEXEC != 0 {
        FD_CLOEXEC
    } else {
        0
    };
    let fd = super::io::get_unused_fd_flags(fd_flags)?;
    let file = file_open_handle(&path, flags)?;
    Ok(fd.install(file))
}

/// Open a decoded path (Linux file_open_handle): the filesystem's own
/// open, else file_open_root with an empty name
fn file_open_handle(path: &Path, flags: u32) -> Result<FileRef, KernelError> {
    match path
        .mnt
        .sb
        .s_op
        .export_op()
        .and_then(|op| op.open(path, flags))
    {
        Some(r) => r,
        None => super::open::file_open_root(path, flags),
    }
}
