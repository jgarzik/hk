//! Keyring syscall implementations
//!
//! This module implements the three keyring syscalls:
//! - add_key: Create a new key and add it to a keyring
//! - request_key: Search for a key, optionally requesting construction
//! - keyctl: Multiplex control operations on keys

use crate::task::percpu;
use crate::uaccess::{UserPtr, UserSlice, strncpy_from_user_str};
use crate::util::error::{KernelError, KernelResult};
use crate::util::kalloc::try_arc;

use super::key::{KEY_DEFAULT_PERM, Key};
use super::keyring::{keyring_link, resolve_special_keyring, search_process_keyrings};
use super::types::get_key_type;
use super::{alloc_serial, register_key};

/// Maximum type name length
pub(super) const MAX_TYPE_LEN: usize = 256;
/// Maximum description length
pub(super) const MAX_DESC_LEN: usize = 4096;
/// Maximum payload size (1MB - 1)
const MAX_PAYLOAD_SIZE: usize = 1024 * 1024 - 1;

/// A type name or description from user space: any failure, an
/// over-long string included, is EFAULT here (Linux: EINVAL when too
/// long)
pub(super) fn user_str(p: UserPtr<u8>, max: usize) -> KernelResult<alloc::string::String> {
    strncpy_from_user_str(p.addr(), max).map_err(|_| KernelError::BadAddress)
}

/// add_key(type, description, payload, plen, keyring): a new key of
/// `type` linked into `keyring`; its serial
pub fn sys_add_key(
    type_ptr: UserPtr<u8>,
    desc_ptr: UserPtr<u8>,
    payload_ptr: UserPtr<u8>,
    plen: u64,
    keyring: i32,
) -> KernelResult<i32> {
    if plen > MAX_PAYLOAD_SIZE as u64 {
        return Err(KernelError::InvalidArgument);
    }
    let type_name = user_str(type_ptr, MAX_TYPE_LEN)?;
    let description = user_str(desc_ptr, MAX_DESC_LEN)?;
    let key_type = get_key_type(&type_name).ok_or(KernelError::InvalidArgument)?;

    let payload = if plen > 0 && !payload_ptr.is_null() {
        let mut buf = crate::util::kmem::try_vec(plen as usize, 0u8)?;
        UserSlice::new(payload_ptr.addr(), buf.len())
            .reader()
            .read_slice(&mut buf)?;
        buf
    } else {
        alloc::vec::Vec::new()
    };

    let cred = percpu::current_cred();
    // Resolve destination keyring (create if needed for special IDs)
    let dest_keyring =
        resolve_special_keyring(keyring, true, &percpu::current(), cred.uid, cred.gid)?;
    if !dest_keyring.is_keyring() {
        return Err(KernelError::NotDirectory);
    }
    // WRITE on the destination keyring (Linux key_create_or_update ->
    // lookup_user_key KEY_NEED_WRITE)
    if !super::key::check_key_permission(&dest_keyring, super::key::KEY_NEED_WRITE) {
        return Err(KernelError::PermissionDenied);
    }

    // Charge the user's key quota (Linux key_alloc), EDQUOT past it
    let charge = description.len() + 1 + payload.len();
    super::key_user_charge(cred.fsuid, charge)?;

    let serial = alloc_serial();
    // Owned by the fsuid and fsgid (Linux key_create_or_update ->
    // key_alloc)
    let key = Key::new(
        serial,
        key_type.clone(),
        description,
        cred.fsuid,
        cred.fsgid,
        KEY_DEFAULT_PERM,
    );
    // Record the charge so a later failure (or invalidate) returns it
    key.set_quota(cred.fsuid, charge);
    let key = try_arc(key)?;
    key_type.instantiate(&key, &payload)?;
    register_key(&key);
    // Link to destination keyring; on failure the key is freed here
    keyring_link(&dest_keyring, &key)?;
    Ok(serial)
}

/// request_key(type, description, callout_info, dest_keyring): the
/// serial of a key the caller's keyrings hold, linked into
/// `dest_keyring` if non-zero; ENOKEY if there is none (no upcall)
pub fn sys_request_key(
    type_ptr: UserPtr<u8>,
    desc_ptr: UserPtr<u8>,
    _callout_info_ptr: UserPtr<u8>,
    dest_keyring: i32,
) -> KernelResult<i32> {
    let type_name = user_str(type_ptr, MAX_TYPE_LEN)?;
    let description = user_str(desc_ptr, MAX_DESC_LEN)?;
    let cred = percpu::current_cred();
    let me = percpu::current();
    let key = search_process_keyrings(&type_name, &description, &me).ok_or(KernelError::NoKey)?;
    if key.is_revoked() {
        return Err(KernelError::KeyRevoked);
    }
    // Linking into the destination needs LINK on the key and WRITE
    // on the destination (Linux request_key -> construct_get_dest_keyring
    // / lookup_user_key)
    if dest_keyring != 0
        && let Ok(dest) = resolve_special_keyring(dest_keyring, false, &me, cred.uid, cred.gid)
        && super::key::check_key_permission(&key, super::key::KEY_NEED_LINK)
        && super::key::check_key_permission(&dest, super::key::KEY_NEED_WRITE)
    {
        let _ = keyring_link(&dest, &key);
    }
    Ok(key.serial)
}

/// keyctl(cmd, arg2, arg3, arg4, arg5): the KEYCTL_* operations
pub fn sys_keyctl(cmd: i32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> KernelResult<i64> {
    use super::keyctl::*;
    use super::*;
    let ptr = UserPtr::<u8>::new;
    let done = |r: KernelResult<()>| r.map(|()| 0);
    let serial = |r: KernelResult<i32>| r.map(i64::from);
    let size = |r: KernelResult<usize>| r.map(|n| n as i64);
    match cmd {
        KEYCTL_GET_KEYRING_ID => serial(keyctl_get_keyring_id(arg2 as i32, arg3 != 0)),
        KEYCTL_UPDATE => done(keyctl_update(arg2 as i32, ptr(arg3), arg4 as usize)),
        KEYCTL_REVOKE => done(keyctl_revoke(arg2 as i32)),
        KEYCTL_CHOWN => done(keyctl_chown(arg2 as i32, arg3 as i32, arg4 as i32)),
        KEYCTL_SETPERM => done(keyctl_setperm(arg2 as i32, arg3 as u32)),
        KEYCTL_DESCRIBE => size(keyctl_describe(arg2 as i32, ptr(arg3), arg4 as usize)),
        KEYCTL_CLEAR => done(keyctl_clear(arg2 as i32)),
        KEYCTL_LINK => done(keyctl_link(arg2 as i32, arg3 as i32)),
        KEYCTL_UNLINK => done(keyctl_unlink(arg2 as i32, arg3 as i32)),
        KEYCTL_SEARCH => serial(keyctl_search(
            arg2 as i32,
            ptr(arg3),
            ptr(arg4),
            arg5 as i32,
        )),
        KEYCTL_READ => size(keyctl_read(arg2 as i32, ptr(arg3), arg4 as usize)),
        KEYCTL_INVALIDATE => done(keyctl_invalidate(arg2 as i32)),
        _ => Err(KernelError::OperationNotSupported),
    }
}
