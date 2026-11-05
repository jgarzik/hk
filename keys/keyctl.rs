//! Keyctl subcommand implementations
//!
//! This module implements the various KEYCTL_* operations for the keyctl syscall.

use alloc::vec;

use crate::arch::Uaccess;
use crate::task::percpu;
use crate::uaccess::{copy_from_user, copy_to_user, strncpy_from_user_str};
use crate::util::error::KernelError;

use super::key::{
    KEY_NEED_LINK, KEY_NEED_READ, KEY_NEED_SEARCH, KEY_NEED_SETATTR, KEY_NEED_VIEW, KEY_NEED_WRITE,
    check_key_permission,
};
use super::keyring::{keyring_link, keyring_unlink, resolve_special_keyring};
use super::{lookup_key, remove_key};

/// Maximum buffer sizes
const MAX_TYPE_LEN: usize = 256;
const MAX_DESC_LEN: usize = 4096;

/// The caller's tid and real uid and gid (the user keyrings belong to
/// the real uid, Linux cred->user)
fn current_cred() -> (u64, u32, u32) {
    let cred = percpu::current_cred();
    let tid = percpu::current_tid() as u64;
    (tid, cred.uid, cred.gid)
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
    let (tid, uid, gid) = current_cred();

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
    let (tid, uid, gid) = current_cred();

    // Look up the key
    let key = match resolve_special_keyring(key_serial, false, tid, uid, gid) {
        Ok(k) => k,
        Err(_) => match lookup_key(key_serial) {
            Some(k) => k,
            None => return KernelError::NoKey.sysret(),
        },
    };

    // Check permission
    if !check_key_permission(&key, KEY_NEED_WRITE) {
        return KernelError::PermissionDenied.sysret();
    }

    // Check if revoked
    if key.is_revoked() {
        return KernelError::KeyRevoked.sysret();
    }

    // Copy payload from userspace (at most a page, Linux keyctl_update)
    if plen > crate::mm::PAGE_SIZE as usize {
        return KernelError::InvalidArgument.sysret();
    }
    let payload = if plen > 0 && payload_ptr != 0 {
        let mut buf = vec![0u8; plen];
        if copy_from_user::<Uaccess>(&mut buf, payload_ptr, plen).is_err() {
            return KernelError::BadAddress.sysret();
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
    let key = match lookup_key(key_serial) {
        Some(k) => k,
        None => return KernelError::NoKey.sysret(),
    };

    // Check permission (need SETATTR to revoke)
    if !check_key_permission(&key, KEY_NEED_SETATTR) {
        return KernelError::PermissionDenied.sysret();
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
pub fn keyctl_chown(key_serial: i32, new_uid: i32, new_gid: i32) -> i64 {
    // Linux keyctl_chown_key: -1 leaves an id alone
    let uid = (new_uid != -1).then_some(new_uid as u32);
    let gid = (new_gid != -1).then_some(new_gid as u32);
    if uid.is_none() && gid.is_none() {
        return 0;
    }
    let key = match lookup_key(key_serial) {
        Some(k) => k,
        None => return KernelError::NoKey.sysret(),
    };
    if !check_key_permission(&key, KEY_NEED_SETATTR) {
        return KernelError::PermissionDenied.sysret();
    }
    // Another owner, or a group the caller is not in, takes
    // CAP_SYS_ADMIN (EACCES); decided under the key's lock
    let cred = percpu::current_cred();
    let r = key.chown(uid, gid, |cur_uid, cur_gid| {
        let privileged = uid.is_some_and(|u| u != cur_uid)
            || gid.is_some_and(|g| g != cur_gid && !crate::fs::dac::in_group(&cred, g));
        if privileged && !crate::task::capable(crate::task::CAP_SYS_ADMIN) {
            return Err(KernelError::PermissionDenied);
        }
        Ok(())
    });
    match r {
        Ok(()) => 0,
        Err(e) => e.sysret(),
    }
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
    // Linux keyctl_setperm_key: only the four permission bytes
    use super::key::{KEY_GRP_ALL, KEY_OTH_ALL, KEY_POS_ALL, KEY_USR_ALL};
    if perm & !(KEY_POS_ALL | KEY_USR_ALL | KEY_GRP_ALL | KEY_OTH_ALL) != 0 {
        return KernelError::InvalidArgument.sysret();
    }
    let key = match lookup_key(key_serial) {
        Some(k) => k,
        None => return KernelError::NoKey.sysret(),
    };
    if !check_key_permission(&key, KEY_NEED_SETATTR) {
        return KernelError::PermissionDenied.sysret();
    }
    // The owner (fsuid) or CAP_SYS_ADMIN, else EACCES; decided under
    // the key's lock
    let fsuid = percpu::current_cred().fsuid;
    let r = key.setperm(perm, |owner| {
        if owner != fsuid && !crate::task::capable(crate::task::CAP_SYS_ADMIN) {
            return Err(KernelError::PermissionDenied);
        }
        Ok(())
    });
    match r {
        Ok(()) => 0,
        Err(e) => e.sysret(),
    }
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
    let (tid, uid, gid) = current_cred();

    let key = match resolve_special_keyring(key_serial, false, tid, uid, gid) {
        Ok(k) => k,
        Err(_) => match lookup_key(key_serial) {
            Some(k) => k,
            None => return KernelError::NoKey.sysret(),
        },
    };

    // Check permission
    if !check_key_permission(&key, KEY_NEED_VIEW) {
        return KernelError::PermissionDenied.sysret();
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
    if copy_len > 0 && copy_to_user::<Uaccess>(buffer_ptr, &desc_bytes[..copy_len]).is_err() {
        return KernelError::BadAddress.sysret();
    }

    // Write NUL terminator if there's space
    if copy_len < buflen && copy_to_user::<Uaccess>(buffer_ptr + copy_len as u64, &[0u8]).is_err() {
        return KernelError::BadAddress.sysret();
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
    let (tid, uid, gid) = current_cred();

    let keyring = match resolve_special_keyring(keyring_serial, false, tid, uid, gid) {
        Ok(k) => k,
        Err(_) => match lookup_key(keyring_serial) {
            Some(k) => k,
            None => return KernelError::NoKey.sysret(),
        },
    };

    if !keyring.is_keyring() {
        return KernelError::NotDirectory.sysret();
    }

    // Check permission
    if !check_key_permission(&keyring, KEY_NEED_WRITE) {
        return KernelError::PermissionDenied.sysret();
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
    let (tid, uid, gid) = current_cred();

    // Look up the key
    let key = match lookup_key(key_serial) {
        Some(k) => k,
        None => return KernelError::NoKey.sysret(),
    };

    // Look up the keyring
    let keyring = match resolve_special_keyring(keyring_serial, false, tid, uid, gid) {
        Ok(k) => k,
        Err(_) => match lookup_key(keyring_serial) {
            Some(k) => k,
            None => return KernelError::NoKey.sysret(),
        },
    };

    if !keyring.is_keyring() {
        return KernelError::NotDirectory.sysret();
    }

    // WRITE on the keyring, and LINK on the key being linked (Linux
    // lookup_user_key: KEY_NEED_LINK), else any user could link another
    // user's key into its own keyring and then possess it
    if !check_key_permission(&keyring, KEY_NEED_WRITE) || !check_key_permission(&key, KEY_NEED_LINK)
    {
        return KernelError::PermissionDenied.sysret();
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
    let (tid, uid, gid) = current_cred();

    // Look up the key
    let key = match lookup_key(key_serial) {
        Some(k) => k,
        None => return KernelError::NoKey.sysret(),
    };

    // Look up the keyring
    let keyring = match resolve_special_keyring(keyring_serial, false, tid, uid, gid) {
        Ok(k) => k,
        Err(_) => match lookup_key(keyring_serial) {
            Some(k) => k,
            None => return KernelError::NoKey.sysret(),
        },
    };

    if !keyring.is_keyring() {
        return KernelError::NotDirectory.sysret();
    }

    // Check WRITE permission on keyring
    if !check_key_permission(&keyring, KEY_NEED_WRITE) {
        return KernelError::PermissionDenied.sysret();
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
    let (tid, uid, gid) = current_cred();

    // Copy type and description from userspace
    let type_name = match strncpy_from_user_str::<Uaccess>(type_ptr, MAX_TYPE_LEN) {
        Ok(s) => s,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    let description = match strncpy_from_user_str::<Uaccess>(desc_ptr, MAX_DESC_LEN) {
        Ok(s) => s,
        Err(_) => return KernelError::BadAddress.sysret(),
    };

    // Look up the keyring to search
    let keyring = match resolve_special_keyring(keyring_serial, false, tid, uid, gid) {
        Ok(k) => k,
        Err(_) => match lookup_key(keyring_serial) {
            Some(k) => k,
            None => return KernelError::NoKey.sysret(),
        },
    };

    if !keyring.is_keyring() {
        return KernelError::NotDirectory.sysret();
    }

    // SEARCH on the keyring being searched (Linux lookup_user_key
    // KEY_NEED_SEARCH)
    if !check_key_permission(&keyring, KEY_NEED_SEARCH) {
        return KernelError::PermissionDenied.sysret();
    }

    // Search the keyring recursively
    let key = match keyring.keyring_search_recursive(&type_name, &description) {
        Ok(k) => k,
        Err(e) => return e.sysret(),
    };
    if key.is_revoked() {
        return KernelError::KeyRevoked.sysret();
    }

    // Linking the found key needs LINK on it and WRITE on the
    // destination (Linux keyctl_keyring_search)
    if dest_keyring != 0 {
        if !check_key_permission(&key, KEY_NEED_LINK) {
            return KernelError::PermissionDenied.sysret();
        }
        if let Ok(dest) = resolve_special_keyring(dest_keyring, false, tid, uid, gid) {
            if !check_key_permission(&dest, KEY_NEED_WRITE) {
                return KernelError::PermissionDenied.sysret();
            }
            let _ = keyring_link(&dest, &key);
        }
    }
    key.serial as i64
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
    let (tid, uid, gid) = current_cred();

    let key = match resolve_special_keyring(key_serial, false, tid, uid, gid) {
        Ok(k) => k,
        Err(_) => match lookup_key(key_serial) {
            Some(k) => k,
            None => return KernelError::NoKey.sysret(),
        },
    };

    // Check permission
    if !check_key_permission(&key, KEY_NEED_READ) {
        return KernelError::PermissionDenied.sysret();
    }

    // Check if revoked
    if key.is_revoked() {
        return KernelError::KeyRevoked.sysret();
    }

    // Query mode: just return size needed
    if buflen == 0 || buffer_ptr == 0 {
        return match key.key_type().read(&key, &mut []) {
            Ok(size) => size as i64,
            Err(e) => e,
        };
    }

    // Read into a buffer no larger than the payload (Linux
    // keyctl_read_key sizes it by the key)
    let need = match key.key_type().read(&key, &mut []) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let mut buffer = match crate::util::kmem::try_vec(buflen.min(need), 0u8) {
        Ok(b) => b,
        Err(e) => return e.sysret(),
    };
    match key.key_type().read(&key, &mut buffer) {
        Ok(actual_len) => {
            // The payload may have grown since it was sized: copy only
            // what the buffer holds
            let copy_len = actual_len.min(buffer.len());
            if copy_len > 0 && copy_to_user::<Uaccess>(buffer_ptr, &buffer[..copy_len]).is_err() {
                return KernelError::BadAddress.sysret();
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
    let key = match lookup_key(key_serial) {
        Some(k) => k,
        None => return KernelError::NoKey.sysret(),
    };

    // Check permission (need SEARCH to invalidate)
    // Note: Linux uses different permission checks; we simplify here
    if !check_key_permission(&key, KEY_NEED_SETATTR) {
        return KernelError::PermissionDenied.sysret();
    }

    key.invalidate();

    // Lookups no longer find it, and no keyring links it: it is freed
    // with its last reference (Linux: the key GC unlinks invalidated keys)
    remove_key(key_serial);
    crate::keys::unlink_everywhere(key_serial);

    0
}
