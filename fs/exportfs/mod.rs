//! File handles of a filesystem's objects (Linux include/linux/exportfs.h,
//! fs/exportfs/expfs.c): how name_to_handle_at encodes an object and
//! open_by_handle_at finds it again (`fs::fhandle`)
//!
//! A filesystem that can decode handles gives its superblocks export
//! operations ([`ExportOps`], Linux sb->s_export_op, here
//! `SuperOps::export_op`): tmpfs (Linux shmem_export_ops). Any other
//! filesystem still encodes a non-decodable file id on request
//! (AT_HANDLE_FID: inode number and generation, Linux
//! exportfs_encode_ino64_fid), as Linux does for one without export
//! operations (ramfs, procfs, sysfs, pipefs...).
//!
//! hk never makes a disconnected dentry (Linux DCACHE_DISCONNECTED,
//! d_obtain_alias): a decode returns one of the object's own dentries,
//! so no directory is ever reconnected (reconnect_path, ->get_parent,
//! ->get_name do not exist here).

use alloc::sync::Arc;

use super::dentry::{DentryRef, d_find_alias_by};
use super::inode::Inode;
use super::mount::MountRef;
use super::path_ref::Path;
use super::superblock::SuperBlock;
use super::{FileRef, KernelError};

/// The most bytes of a handle (Linux MAX_HANDLE_SZ, NFSv4's size)
pub const MAX_HANDLE_SZ: usize = 128;

/// Handle types (Linux enum fid_type): a filesystem uses the low 8 bits,
/// never 0 or 0xff
/// 32-bit inode number, 32-bit generation (tmpfs's, whatever the
/// inode number's size)
pub const FILEID_INO32_GEN: u8 = 1;
/// 64-bit inode number, 32-bit generation
pub const FILEID_INO64_GEN: u8 = 0x81;
/// The type of a handle that did not fit
pub const FILEID_INVALID: i32 = 0xff;

/// What a handle is asked to be (Linux EXPORT_FH_*): with its parent
pub const EXPORT_FH_CONNECTABLE: u32 = 0x1;
/// Possibly not decodable
pub const EXPORT_FH_FID: u32 = 0x2;
/// Decoded only to a directory
pub const EXPORT_FH_DIR_ONLY: u32 = 0x4;

/// The bits of handle_type name_to_handle_at gives user flags (Linux
/// FILEID_USER_FLAGS_MASK)
pub const FILEID_USER_FLAGS_MASK: i32 = 0xffff_0000_u32 as i32;
/// Encoded connectable (Linux FILEID_IS_CONNECTABLE)
pub const FILEID_IS_CONNECTABLE: i32 = 0x1_0000;
/// Encoded of a directory (Linux FILEID_IS_DIR)
pub const FILEID_IS_DIR: i32 = 0x2_0000;
/// The user flags a handle may carry (Linux FILEID_VALID_USER_FLAGS)
pub const FILEID_VALID_USER_FLAGS: i32 = FILEID_IS_CONNECTABLE | FILEID_IS_DIR;

/// How open_by_handle_at checks a decoded dentry (Linux enum
/// handle_to_path_flags): the ids on the way to it must be mapped
pub const HANDLE_CHECK_PERMS: u32 = 1 << 0;
/// It must be below the mount fd's directory
pub const HANDLE_CHECK_SUBTREE: u32 = 1 << 1;

/// One open_by_handle_at's decode (Linux struct handle_to_path_ctx):
/// the mount fd's path, the `HANDLE_CHECK_*` checks and the
/// `EXPORT_FH_*` flags of the decode
pub struct HandleCtx {
    pub root: Path,
    pub flags: u32,
    pub fh_flags: u32,
}

/// What [`ExportOps::encode_fh`] made: the type and the words used, or
/// (Err) the words it needs (Linux: FILEID_INVALID with *max_len set)
pub type Encoded = Result<(u8, usize), usize>;

/// A filesystem's file handle operations (Linux struct
/// export_operations). A filesystem with them decodes handles; the
/// optional hooks are for special filesystems (nsfs, pidfs) and nfsd
/// does not exist here.
pub trait ExportOps: Sync {
    /// Encode `inode` into `fh` (its length is the room: Linux
    /// ->encode_fh's *max_len, in 32-bit words)
    fn encode_fh(&self, inode: &Arc<Inode>, fh: &mut [u32]) -> Encoded;

    /// A dentry of the object `fh` (of type `ty`) names on `sb`; None if
    /// it is gone (Linux ->fh_to_dentry: NULL, ESTALE to the caller)
    fn fh_to_dentry(
        &self,
        sb: &Arc<SuperBlock>,
        fh: &[u32],
        ty: i32,
    ) -> Result<Option<DentryRef>, KernelError>;

    /// open_by_handle_at's own permission check for a mount fd on this
    /// filesystem (Linux ->permission); None: the default
    /// (`fhandle::may_decode_fh`)
    fn permission(&self, ctx: &mut HandleCtx, oflags: u32) -> Option<Result<(), KernelError>> {
        let _ = (ctx, oflags);
        None
    }

    /// open_by_handle_at's own open of a decoded path (Linux ->open);
    /// None: the default (`file_open_root`)
    fn open(&self, path: &Path, oflags: u32) -> Option<Result<FileRef, KernelError>> {
        let _ = (path, oflags);
        None
    }
}

/// The export operations of `dentry`'s filesystem (Linux
/// d_sb->s_export_op)
pub fn export_op(dentry: &DentryRef) -> Option<&'static dyn ExportOps> {
    dentry.superblock().and_then(|sb| sb.s_op.export_op())
}

/// A handle of the kind `fh_flags` asks can be made with `nop` (Linux
/// exportfs_can_encode_fh): a file id by any filesystem (every
/// `ExportOps` has encode_fh, and one without uses the default), a
/// decodable handle only with export operations, a connectable one
/// only by a filesystem that also decodes a parent (->fh_to_parent:
/// vfat in Linux, not here: BUGS.md)
pub fn can_encode_fh(nop: Option<&dyn ExportOps>, fh_flags: u32) -> bool {
    if fh_flags & EXPORT_FH_FID != 0 {
        return true;
    }
    nop.is_some() && fh_flags & EXPORT_FH_CONNECTABLE == 0
}

/// Words of the default file id (Linux FILEID_INO64_GEN_LEN)
const FILEID_INO64_GEN_LEN: usize = 3;

/// The default file id of a filesystem without export operations
/// (Linux exportfs_encode_ino64_fid): struct fid's packed i64 {ino,
/// gen}, as the little-endian words hk's CPUs store it in
fn encode_ino64_fid(inode: &Inode, fh: &mut [u32]) -> Encoded {
    let Some(w) = fh.get_mut(..FILEID_INO64_GEN_LEN) else {
        return Err(FILEID_INO64_GEN_LEN);
    };
    // Low and high halves of the inode number: truncation intended
    w[0] = inode.ino as u32;
    w[1] = (inode.ino >> 32) as u32;
    w[2] = inode.i_generation;
    Ok((FILEID_INO64_GEN, FILEID_INO64_GEN_LEN))
}

/// Encode `dentry`'s object into `fh` (Linux exportfs_encode_fh,
/// exportfs_encode_inode_fh): EOPNOTSUPP if its filesystem cannot make
/// that kind of handle
pub fn encode_fh(
    dentry: &DentryRef,
    fh: &mut [u32],
    fh_flags: u32,
) -> Result<Encoded, KernelError> {
    let inode = dentry.get_inode().ok_or(KernelError::NotFound)?;
    let nop = export_op(dentry);
    if !can_encode_fh(nop, fh_flags) {
        return Err(KernelError::OperationNotSupported);
    }
    Ok(match nop {
        Some(op) => op.encode_fh(&inode, fh),
        None => encode_ino64_fid(&inode, fh),
    })
}

/// `result` or another dentry of its inode that `acceptable` takes
/// (Linux find_acceptable_alias)
fn find_acceptable_alias(
    result: DentryRef,
    acceptable: &mut dyn FnMut(&DentryRef) -> bool,
) -> Option<DentryRef> {
    if acceptable(&result) {
        return Some(result);
    }
    let inode = result.get_inode()?;
    d_find_alias_by(&inode, |d| !DentryRef::ptr_eq(d, &result) && acceptable(d))
}

/// The dentry `fh` (type `ty`, its user flags stripped) names on
/// `mnt`'s filesystem, if `acceptable` takes it (Linux
/// exportfs_decode_fh_raw): ESTALE without export operations or for an
/// object gone, ENOTDIR for a non-directory under EXPORT_FH_DIR_ONLY,
/// EACCES for a directory not acceptable, ESTALE for a file none of
/// whose dentries is (no filesystem here decodes a parent to look
/// further, Linux ->fh_to_parent)
pub fn decode_fh(
    mnt: &MountRef,
    fh: &[u32],
    ty: i32,
    fh_flags: u32,
    acceptable: &mut dyn FnMut(&DentryRef) -> bool,
) -> Result<DentryRef, KernelError> {
    if ty < 0 || ty & FILEID_USER_FLAGS_MASK != 0 {
        return Err(KernelError::InvalidArgument);
    }
    let nop = mnt.sb.s_op.export_op().ok_or(KernelError::StaleHandle)?;
    let result = nop
        .fh_to_dentry(&mnt.sb, fh, ty)?
        .ok_or(KernelError::StaleHandle)?;
    let is_dir = result.get_inode().is_some_and(|i| i.mode().is_dir());
    if fh_flags & EXPORT_FH_DIR_ONLY != 0 && !is_dir {
        return Err(KernelError::NotDirectory);
    }
    if is_dir {
        // A directory has one dentry, connected (never disconnected
        // here: nothing to reconnect)
        if !acceptable(&result) {
            return Err(KernelError::PermissionDenied);
        }
        return Ok(result);
    }
    find_acceptable_alias(result, acceptable).ok_or(KernelError::StaleHandle)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file id is open to every filesystem; a decodable or connectable
    /// handle needs export operations (and a parent decoder, which none
    /// has)
    #[test]
    fn can_encode() {
        struct Ops;
        impl ExportOps for Ops {
            fn encode_fh(&self, _: &Arc<Inode>, _: &mut [u32]) -> Encoded {
                Err(0)
            }
            fn fh_to_dentry(
                &self,
                _: &Arc<SuperBlock>,
                _: &[u32],
                _: i32,
            ) -> Result<Option<DentryRef>, KernelError> {
                Ok(None)
            }
        }
        assert!(can_encode_fh(None, EXPORT_FH_FID));
        assert!(!can_encode_fh(None, 0));
        assert!(can_encode_fh(Some(&Ops), 0));
        assert!(!can_encode_fh(Some(&Ops), EXPORT_FH_CONNECTABLE));
    }
}
