//! Keyctl subcommand implementations
//!
//! This module implements the various KEYCTL_* operations for the keyctl syscall.

use alloc::vec;

use crate::arch::Uaccess;
use crate::task::percpu;
use crate::uaccess::{copy_from_user, copy_to_user, strncpy_from_user};

use super::key::{
    KEY_NEED_READ, KEY_NEED_SETATTR, KEY_NEED_VIEW, KEY_NEED_WRITE, check_key_permission,
};
use super::keyring::{keyring_link, keyring_unlink, resolve_special_keyring};
use super::{EACCES, EFAULT, EKEYREVOKED, ENOKEY, ENOTDIR, EPERM};
use super::{lookup_key, remove_key};

/// Maximum buffer sizes
const MAX_TYPE_LEN: usize = 256;
const MAX_DESC_LEN: usize = 4096;

/// Helper to get current credentials
fn current_cred() -> (u64, u32, u32, bool) {
    let cred = percpu::current_cred();
    let tid = percpu::current_tid() as u64;
    let uid = cred.uid;
    let gid = cred.gid;
    let is_root = cred.euid == 0;
    (tid, uid, gid, is_root)
}

/// KEYCTL_GET_KEYRING_ID - Get the ID of a special keyring
///
/// # Arguments
/// * `special_id` - Special keyring ID (KEY_SPEC_*)
/// * `create` - Whether to create the keyring if it doesn't exist
///
/// # Returns
/// * Keyring serial number on success
/// * Negative errno on failure
pub fn keyctl_get_keyring_id(special_id: i32, create: bool) -> i64 {
    let (tid, uid, gid, _) = current_cred();

    match resolve_special_keyring(special_id, create, tid, uid, gid) {
        Ok(keyring) => keyring.serial as i64,
        Err(e) => e,
    }
}

/// KEYCTL_UPDATE - Update a key's payload
///
/// # Arguments
/// * `key_serial` - Key serial number
/// * `payload_ptr` - Pointer to new payload data
/// * `plen` - Payload length
///
/// # Returns
/// * 0 on success
/// * Negative errno on failure
pub fn keyctl_update(key_serial: i32, payload_ptr: u64, plen: usize) -> i64 {
    let (tid, uid, gid, is_root) = current_cred();

    // Look up the key
    let key = match resolve_special_keyring(key_serial, false, tid, uid, gid) {
        Ok(k) => k,
        Err(_) => match lookup_key(key_serial) {
            Some(k) => k,
            None => return ENOKEY,
        },
    };

    // Check permission
    if !check_key_permission(&key, KEY_NEED_WRITE, uid, gid, is_root) {
        return EACCES;
    }

    // Check if revoked
    if key.is_revoked() {
        return EKEYREVOKED;
    }

    // Copy payload from userspace
    let payload = if plen > 0 && payload_ptr != 0 {
        let mut buf = vec![0u8; plen];
        if copy_from_user::<Uaccess>(&mut buf, payload_ptr, plen).is_err() {
            return EFAULT;
        }
        buf
    } else {
        alloc::vec::Vec::new()
    };

    // Update via key type
    match key.key_type().update(&key, &payload) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// KEYCTL_REVOKE - Revoke a key
///
/// # Arguments
/// * `key_serial` - Key serial number
///
/// # Returns
/// * 0 on success
/// * Negative errno on failure
pub fn keyctl_revoke(key_serial: i32) -> i64 {
    let (_tid, uid, gid, is_root) = current_cred();

    let key = match lookup_key(key_serial) {
        Some(k) => k,
        None => return ENOKEY,
    };

    // Check permission (need SETATTR to revoke)
    if !check_key_permission(&key, KEY_NEED_SETATTR, uid, gid, is_root) {
        return EACCES;
    }

    key.revoke();
    0
}

/// KEYCTL_CHOWN - Change a key's ownership
///
/// # Arguments
/// * `key_serial` - Key serial number
/// * `new_uid` - New UID (-1 to keep current)
/// * `new_gid` - New GID (-1 to keep current)
///
/// # Returns
/// * 0 on success
/// * Negative errno on failure
pub fn keyctl_chown(key_serial: i32, _new_uid: i32, _new_gid: i32) -> i64 {
    let (_tid, _uid, _gid, is_root) = current_cred();

    let _key = match lookup_key(key_serial) {
        Some(k) => k,
        None => return ENOKEY,
    };

    // Only root can change ownership
    if !is_root {
        return EPERM;
    }

    // Note: In a full implementation, we would modify the key's uid/gid here.
    // Since Key fields are not mutable after creation in our simple impl,
    // we just succeed if root. A real implementation would use interior mutability.
    0
}

/// KEYCTL_SETPERM - Set a key's permissions
///
/// # Arguments
/// * `key_serial` - Key serial number
/// * `perm` - New permission mask
///
/// # Returns
/// * 0 on success
/// * Negative errno on failure
pub fn keyctl_setperm(key_serial: i32, perm: u32) -> i64 {
    let (_tid, uid, gid, is_root) = current_cred();

    let key = match lookup_key(key_serial) {
        Some(k) => k,
        None => return ENOKEY,
    };

    // Check permission
    if !check_key_permission(&key, KEY_NEED_SETATTR, uid, gid, is_root) {
        return EACCES;
    }

    key.set_perm(perm);
    0
}

/// KEYCTL_DESCRIBE - Describe a key
///
/// # Arguments
/// * `key_serial` - Key serial number
/// * `buffer_ptr` - Pointer to output buffer
/// * `buflen` - Buffer length
///
/// # Returns
/// * Description length (including NUL) on success
/// * Negative errno on failure
pub fn keyctl_describe(key_serial: i32, buffer_ptr: u64, buflen: usize) -> i64 {
    let (tid, uid, gid, is_root) = current_cred();

    let key = match resolve_special_keyring(key_serial, false, tid, uid, gid) {
        Ok(k) => k,
        Err(_) => match lookup_key(key_serial) {
            Some(k) => k,
            None => return ENOKEY,
        },
    };

    // Check permission
    if !check_key_permission(&key, KEY_NEED_VIEW, uid, gid, is_root) {
        return EACCES;
    }

    // Get description string
    let desc = key.key_type().describe(&key);
    let desc_bytes = desc.as_bytes();
    let total_len = desc_bytes.len() + 1; // +1 for NUL

    // If buffer is 0, just return required size
    if buflen == 0 || buffer_ptr == 0 {
        return total_len as i64;
    }

    // Copy description to buffer
    let copy_len = core::cmp::min(desc_bytes.len(), buflen.saturating_sub(1));
    if copy_len > 0 {
        if copy_to_user::<Uaccess>(buffer_ptr, &desc_bytes[..copy_len]).is_err() {
            return EFAULT;
        }
    }

    // Write NUL terminator if there's space
    if copy_len < buflen {
        if copy_to_user::<Uaccess>(buffer_ptr + copy_len as u64, &[0u8]).is_err() {
            return EFAULT;
        }
    }

    total_len as i64
}

/// KEYCTL_CLEAR - Clear a keyring
///
/// # Arguments
/// * `keyring_serial` - Keyring serial number
///
/// # Returns
/// * 0 on success
/// * Negative errno on failure
pub fn keyctl_clear(keyring_serial: i32) -> i64 {
    let (tid, uid, gid, is_root) = current_cred();

    let keyring = match resolve_special_keyring(keyring_serial, false, tid, uid, gid) {
        Ok(k) => k,
        Err(_) => match lookup_key(keyring_serial) {
            Some(k) => k,
            None => return ENOKEY,
        },
    };

    if !keyring.is_keyring() {
        return ENOTDIR;
    }

    // Check permission
    if !check_key_permission(&keyring, KEY_NEED_WRITE, uid, gid, is_root) {
        return EACCES;
    }

    match keyring.keyring_clear() {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// KEYCTL_LINK - Link a key to a keyring
///
/// # Arguments
/// * `key_serial` - Key serial number
/// * `keyring_serial` - Keyring serial number
///
/// # Returns
/// * 0 on success
/// * Negative errno on failure
pub fn keyctl_link(key_serial: i32, keyring_serial: i32) -> i64 {
    let (tid, uid, gid, is_root) = current_cred();

    // Look up the key
    let key = match lookup_key(key_serial) {
        Some(k) => k,
        None => return ENOKEY,
    };

    // Look up the keyring
    let keyring = match resolve_special_keyring(keyring_serial, false, tid, uid, gid) {
        Ok(k) => k,
        Err(_) => match lookup_key(keyring_serial) {
            Some(k) => k,
            None => return ENOKEY,
        },
    };

    if !keyring.is_keyring() {
        return ENOTDIR;
    }

    // Check WRITE permission on keyring
    if !check_key_permission(&keyring, KEY_NEED_WRITE, uid, gid, is_root) {
        return EACCES;
    }

    match keyring_link(&keyring, &key) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// KEYCTL_UNLINK - Unlink a key from a keyring
///
/// # Arguments
/// * `key_serial` - Key serial number
/// * `keyring_serial` - Keyring serial number
///
/// # Returns
/// * 0 on success
/// * Negative errno on failure
pub fn keyctl_unlink(key_serial: i32, keyring_serial: i32) -> i64 {
    let (tid, uid, gid, is_root) = current_cred();

    // Look up the key
    let key = match lookup_key(key_serial) {
        Some(k) => k,
        None => return ENOKEY,
    };

    // Look up the keyring
    let keyring = match resolve_special_keyring(keyring_serial, false, tid, uid, gid) {
        Ok(k) => k,
        Err(_) => match lookup_key(keyring_serial) {
            Some(k) => k,
            None => return ENOKEY,
        },
    };

    if !keyring.is_keyring() {
        return ENOTDIR;
    }

    // Check WRITE permission on keyring
    if !check_key_permission(&keyring, KEY_NEED_WRITE, uid, gid, is_root) {
        return EACCES;
    }

    match keyring_unlink(&keyring, &key) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// KEYCTL_SEARCH - Search a keyring for a key
///
/// # Arguments
/// * `keyring_serial` - Keyring to search
/// * `type_ptr` - Pointer to key type name
/// * `desc_ptr` - Pointer to key description
/// * `dest_keyring` - Destination keyring to link found key (0 for none)
///
/// # Returns
/// * Key serial on success
/// * Negative errno on failure
pub fn keyctl_search(keyring_serial: i32, type_ptr: u64, desc_ptr: u64, dest_keyring: i32) -> i64 {
    let (tid, uid, gid, _is_root) = current_cred();

    // Copy type and description from userspace
    let type_name = match strncpy_from_user::<Uaccess>(type_ptr, MAX_TYPE_LEN) {
        Ok(s) => s,
        Err(_) => return EFAULT,
    };

    let description = match strncpy_from_user::<Uaccess>(desc_ptr, MAX_DESC_LEN) {
        Ok(s) => s,
        Err(_) => return EFAULT,
    };

    // Look up the keyring to search
    let keyring = match resolve_special_keyring(keyring_serial, false, tid, uid, gid) {
        Ok(k) => k,
        Err(_) => match lookup_key(keyring_serial) {
            Some(k) => k,
            None => return ENOKEY,
        },
    };

    if !keyring.is_keyring() {
        return ENOTDIR;
    }

    // Search the keyring recursively
    if let Some(serial) = keyring.keyring_search_recursive(&type_name, &description) {
        if let Some(key) = lookup_key(serial) {
            // Check if key is valid
            if key.is_revoked() {
                return EKEYREVOKED;
            }

            // Link to destination keyring if specified
            if dest_keyring != 0 {
                if let Ok(dest) = resolve_special_keyring(dest_keyring, false, tid, uid, gid) {
                    let _ = keyring_link(&dest, &key);
                }
            }

            return serial as i64;
        }
    }

    ENOKEY
}

/// KEYCTL_READ - Read a key's payload
///
/// # Arguments
/// * `key_serial` - Key serial number
/// * `buffer_ptr` - Pointer to output buffer
/// * `buflen` - Buffer length
///
/// # Returns
/// * Payload length on success (may be larger than buflen if truncated)
/// * Negative errno on failure
pub fn keyctl_read(key_serial: i32, buffer_ptr: u64, buflen: usize) -> i64 {
    let (tid, uid, gid, is_root) = current_cred();

    let key = match resolve_special_keyring(key_serial, false, tid, uid, gid) {
        Ok(k) => k,
        Err(_) => match lookup_key(key_serial) {
            Some(k) => k,
            None => return ENOKEY,
        },
    };

    // Check permission
    if !check_key_permission(&key, KEY_NEED_READ, uid, gid, is_root) {
        return EACCES;
    }

    // Check if revoked
    if key.is_revoked() {
        return EKEYREVOKED;
    }

    // Query mode: just return size needed
    if buflen == 0 || buffer_ptr == 0 {
        return match key.key_type().read(&key, &mut []) {
            Ok(size) => size as i64,
            Err(e) => e,
        };
    }

    // Read into buffer
    let mut buffer = vec![0u8; buflen];
    match key.key_type().read(&key, &mut buffer) {
        Ok(actual_len) => {
            let copy_len = core::cmp::min(actual_len, buflen);
            if copy_len > 0 {
                if copy_to_user::<Uaccess>(buffer_ptr, &buffer[..copy_len]).is_err() {
                    return EFAULT;
                }
            }
            actual_len as i64
        }
        Err(e) => e,
    }
}

/// KEYCTL_INVALIDATE - Invalidate a key
///
/// # Arguments
/// * `key_serial` - Key serial number
///
/// # Returns
/// * 0 on success
/// * Negative errno on failure
pub fn keyctl_invalidate(key_serial: i32) -> i64 {
    let (_tid, uid, gid, is_root) = current_cred();

    let key = match lookup_key(key_serial) {
        Some(k) => k,
        None => return ENOKEY,
    };

    // Check permission (need SEARCH to invalidate)
    // Note: Linux uses different permission checks; we simplify here
    if !check_key_permission(&key, KEY_NEED_SETATTR, uid, gid, is_root) {
        return EACCES;
    }

    key.invalidate();

    // Remove from global database
    remove_key(key_serial);

    0
}
