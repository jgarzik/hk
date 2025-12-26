//! Keyring syscall implementations
//!
//! This module implements the three keyring syscalls:
//! - add_key: Create a new key and add it to a keyring
//! - request_key: Search for a key, optionally requesting construction
//! - keyctl: Multiplex control operations on keys

use alloc::vec;

use crate::arch::Uaccess;
use crate::task::percpu;
use crate::uaccess::{copy_from_user, strncpy_from_user};

use super::key::{KEY_DEFAULT_PERM, Key};
use super::keyring::{keyring_link, resolve_special_keyring, search_process_keyrings};
use super::types::get_key_type;
use super::{EFAULT, EINVAL, ENOKEY};
use super::{alloc_serial, register_key, remove_key};

/// Maximum type name length
const MAX_TYPE_LEN: usize = 256;
/// Maximum description length
const MAX_DESC_LEN: usize = 4096;
/// Maximum payload size (1MB - 1)
const MAX_PAYLOAD_SIZE: usize = 1024 * 1024 - 1;

/// add_key syscall
///
/// Create a new key of the specified type with the given description and
/// payload, and link it to the destination keyring.
///
/// # Arguments
/// * `type_ptr` - Pointer to NUL-terminated key type name (e.g., "user")
/// * `desc_ptr` - Pointer to NUL-terminated key description
/// * `payload_ptr` - Pointer to payload data
/// * `plen` - Payload length in bytes
/// * `keyring` - Destination keyring (special ID or serial)
///
/// # Returns
/// * Positive key serial on success
/// * Negative errno on failure
pub fn sys_add_key(type_ptr: u64, desc_ptr: u64, payload_ptr: u64, plen: u64, keyring: i32) -> i64 {
    // Validate payload size
    if plen > MAX_PAYLOAD_SIZE as u64 {
        return EINVAL;
    }

    // Copy type string from userspace
    let type_name = match strncpy_from_user::<Uaccess>(type_ptr, MAX_TYPE_LEN) {
        Ok(s) => s,
        Err(_) => return EFAULT,
    };

    // Copy description from userspace
    let description = match strncpy_from_user::<Uaccess>(desc_ptr, MAX_DESC_LEN) {
        Ok(s) => s,
        Err(_) => return EFAULT,
    };

    // Look up the key type
    let key_type = match get_key_type(&type_name) {
        Some(kt) => kt,
        None => return EINVAL,
    };

    // Copy payload from userspace (if any)
    let payload = if plen > 0 && payload_ptr != 0 {
        let mut buf = vec![0u8; plen as usize];
        if copy_from_user::<Uaccess>(&mut buf, payload_ptr, plen as usize).is_err() {
            return EFAULT;
        }
        buf
    } else {
        alloc::vec::Vec::new()
    };

    // Get current credentials
    let cred = percpu::current_cred();
    let tid = percpu::current_tid() as u64;
    let uid = cred.uid;
    let gid = cred.gid;

    // Resolve destination keyring (create if needed for special IDs)
    let dest_keyring = match resolve_special_keyring(keyring, true, tid, uid, gid) {
        Ok(kr) => kr,
        Err(e) => return e,
    };

    // Check if destination is actually a keyring
    if !dest_keyring.is_keyring() {
        return super::ENOTDIR;
    }

    // Allocate new key
    let serial = alloc_serial();
    let key = Key::new(
        serial,
        key_type.clone(),
        description,
        uid,
        gid,
        KEY_DEFAULT_PERM,
    );

    // Instantiate the key with payload
    if let Err(e) = key_type.instantiate(&key, &payload) {
        return e;
    }

    // Register in global database
    register_key(key.clone());

    // Link to destination keyring
    if let Err(e) = keyring_link(&dest_keyring, &key) {
        // Cleanup on failure
        remove_key(serial);
        return e;
    }

    serial as i64
}

/// request_key syscall
///
/// Search for a key of the specified type and description. If found, link it
/// to the destination keyring (if specified). If not found and callout_info
/// is provided, a userspace helper would be invoked (not implemented here).
///
/// # Arguments
/// * `type_ptr` - Pointer to NUL-terminated key type name
/// * `desc_ptr` - Pointer to NUL-terminated key description
/// * `callout_info_ptr` - Pointer to callout info (not used, can be NULL)
/// * `dest_keyring` - Destination keyring to link found key (or 0/negative)
///
/// # Returns
/// * Positive key serial on success
/// * Negative errno on failure
pub fn sys_request_key(
    type_ptr: u64,
    desc_ptr: u64,
    _callout_info_ptr: u64,
    dest_keyring: i32,
) -> i64 {
    // Copy type string from userspace
    let type_name = match strncpy_from_user::<Uaccess>(type_ptr, MAX_TYPE_LEN) {
        Ok(s) => s,
        Err(_) => return EFAULT,
    };

    // Copy description from userspace
    let description = match strncpy_from_user::<Uaccess>(desc_ptr, MAX_DESC_LEN) {
        Ok(s) => s,
        Err(_) => return EFAULT,
    };

    // Get current credentials
    let cred = percpu::current_cred();
    let tid = percpu::current_tid() as u64;
    let uid = cred.uid;
    let gid = cred.gid;

    // Search process keyrings for the key
    if let Some(key) = search_process_keyrings(&type_name, &description, tid) {
        // Check if key is valid
        if key.is_revoked() {
            return super::EKEYREVOKED;
        }

        // Link to destination keyring if specified
        if dest_keyring != 0
            && let Ok(dest) = resolve_special_keyring(dest_keyring, false, tid, uid, gid)
        {
            let _ = keyring_link(&dest, &key);
        }

        return key.serial as i64;
    }

    // Key not found (we don't support userspace upcall)
    ENOKEY
}

/// keyctl syscall
///
/// Multiplex control operations on keys and keyrings.
///
/// # Arguments
/// * `cmd` - Operation code (KEYCTL_*)
/// * `arg2-arg5` - Operation-specific arguments
///
/// # Returns
/// * Operation-specific return value on success
/// * Negative errno on failure
pub fn sys_keyctl(cmd: i32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> i64 {
    use super::keyctl::*;
    use super::*;

    match cmd {
        KEYCTL_GET_KEYRING_ID => keyctl_get_keyring_id(arg2 as i32, arg3 != 0),
        KEYCTL_UPDATE => keyctl_update(arg2 as i32, arg3, arg4 as usize),
        KEYCTL_REVOKE => keyctl_revoke(arg2 as i32),
        KEYCTL_CHOWN => keyctl_chown(arg2 as i32, arg3 as i32, arg4 as i32),
        KEYCTL_SETPERM => keyctl_setperm(arg2 as i32, arg3 as u32),
        KEYCTL_DESCRIBE => keyctl_describe(arg2 as i32, arg3, arg4 as usize),
        KEYCTL_CLEAR => keyctl_clear(arg2 as i32),
        KEYCTL_LINK => keyctl_link(arg2 as i32, arg3 as i32),
        KEYCTL_UNLINK => keyctl_unlink(arg2 as i32, arg3 as i32),
        KEYCTL_SEARCH => keyctl_search(arg2 as i32, arg3, arg4, arg5 as i32),
        KEYCTL_READ => keyctl_read(arg2 as i32, arg3, arg4 as usize),
        KEYCTL_INVALIDATE => keyctl_invalidate(arg2 as i32),
        _ => EOPNOTSUPP,
    }
}
