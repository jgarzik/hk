//! Keyctl subcommand implementations
//!
//! This module implements the various KEYCTL_* operations for the keyctl syscall.

use alloc::sync::Arc;
use alloc::vec;

use crate::task::percpu;
use crate::uaccess::{UserPtr, UserSlice};
use crate::util::error::{KernelError, KernelResult};

use super::key::{
    KEY_NEED_LINK, KEY_NEED_READ, KEY_NEED_SEARCH, KEY_NEED_SETATTR, KEY_NEED_VIEW, KEY_NEED_WRITE,
    Key, check_key_permission,
};
use super::keyring::{keyring_link, keyring_unlink, resolve_special_keyring};
use super::syscall::{MAX_DESC_LEN, MAX_TYPE_LEN, user_str};
use super::{lookup_key, remove_key};

/// The caller's tid and real uid and gid (the user keyrings belong to
/// the real uid, Linux cred->user)
fn current_cred() -> (u64, u32, u32) {
    let cred = percpu::current_cred();
    let tid = percpu::current_tid() as u64;
    (tid, cred.uid, cred.gid)
}

/// The key `serial` names: a special keyring id (not created) or a
/// key serial; ENOKEY
fn find_key(serial: i32) -> KernelResult<Arc<Key>> {
    let (tid, uid, gid) = current_cred();
    resolve_special_keyring(serial, false, tid, uid, gid)
        .or_else(|_| lookup_key(serial).ok_or(KernelError::NoKey))
}

/// [`find_key`] for a keyring: ENOTDIR for another key
fn find_keyring(serial: i32) -> KernelResult<Arc<Key>> {
    let keyring = find_key(serial)?;
    if !keyring.is_keyring() {
        return Err(KernelError::NotDirectory);
    }
    Ok(keyring)
}

/// `key` grants `perm` to the caller, else EACCES
fn need(key: &Key, perm: u32) -> KernelResult<()> {
    if check_key_permission(key, perm) {
        Ok(())
    } else {
        Err(KernelError::PermissionDenied)
    }
}

/// KEYCTL_GET_KEYRING_ID: the serial of special keyring `special_id`,
/// created first if `create`
pub fn keyctl_get_keyring_id(special_id: i32, create: bool) -> KernelResult<i32> {
    let (tid, uid, gid) = current_cred();
    Ok(resolve_special_keyring(special_id, create, tid, uid, gid)?.serial)
}

/// KEYCTL_UPDATE: a new payload of `plen` bytes for key `key_serial`
pub fn keyctl_update(key_serial: i32, payload_ptr: UserPtr<u8>, plen: usize) -> KernelResult<()> {
    let key = find_key(key_serial)?;
    need(&key, KEY_NEED_WRITE)?;
    if key.is_revoked() {
        return Err(KernelError::KeyRevoked);
    }
    // At most a page (Linux keyctl_update)
    if plen > crate::mm::PAGE_SIZE as usize {
        return Err(KernelError::InvalidArgument);
    }
    let payload = if plen > 0 && !payload_ptr.is_null() {
        let mut buf = vec![0u8; plen];
        UserSlice::new(payload_ptr.addr(), plen)
            .reader()
            .read_slice(&mut buf)?;
        buf
    } else {
        alloc::vec::Vec::new()
    };
    key.key_type().update(&key, &payload)
}

/// KEYCTL_REVOKE: revoke key `key_serial` (SETATTR)
pub fn keyctl_revoke(key_serial: i32) -> KernelResult<()> {
    let key = lookup_key(key_serial).ok_or(KernelError::NoKey)?;
    need(&key, KEY_NEED_SETATTR)?;
    key.revoke();
    Ok(())
}

/// KEYCTL_CHOWN: a new owner and/or group for key `key_serial` (-1
/// leaves an id alone, Linux keyctl_chown_key)
pub fn keyctl_chown(key_serial: i32, new_uid: i32, new_gid: i32) -> KernelResult<()> {
    let uid = (new_uid != -1).then_some(new_uid as u32);
    let gid = (new_gid != -1).then_some(new_gid as u32);
    if uid.is_none() && gid.is_none() {
        return Ok(());
    }
    let key = lookup_key(key_serial).ok_or(KernelError::NoKey)?;
    need(&key, KEY_NEED_SETATTR)?;
    // Another owner, or a group the caller is not in, takes
    // CAP_SYS_ADMIN (EACCES); decided under the key's lock
    let cred = percpu::current_cred();
    key.chown(uid, gid, |cur_uid, cur_gid| {
        let privileged = uid.is_some_and(|u| u != cur_uid)
            || gid.is_some_and(|g| g != cur_gid && !crate::fs::dac::in_group(&cred, g));
        if privileged && !crate::task::capable(crate::task::CAP_SYS_ADMIN) {
            return Err(KernelError::PermissionDenied);
        }
        Ok(())
    })
}

/// KEYCTL_SETPERM: a new permission mask for key `key_serial`
pub fn keyctl_setperm(key_serial: i32, perm: u32) -> KernelResult<()> {
    // Linux keyctl_setperm_key: only the four permission bytes
    use super::key::{KEY_GRP_ALL, KEY_OTH_ALL, KEY_POS_ALL, KEY_USR_ALL};
    if perm & !(KEY_POS_ALL | KEY_USR_ALL | KEY_GRP_ALL | KEY_OTH_ALL) != 0 {
        return Err(KernelError::InvalidArgument);
    }
    let key = lookup_key(key_serial).ok_or(KernelError::NoKey)?;
    need(&key, KEY_NEED_SETATTR)?;
    // The owner (fsuid) or CAP_SYS_ADMIN, else EACCES; decided under
    // the key's lock
    let fsuid = percpu::current_cred().fsuid;
    key.setperm(perm, |owner| {
        if owner != fsuid && !crate::task::capable(crate::task::CAP_SYS_ADMIN) {
            return Err(KernelError::PermissionDenied);
        }
        Ok(())
    })
}

/// KEYCTL_DESCRIBE: "type;uid;gid;perm;description" into `buffer`
/// (truncated, NUL-terminated if room); its full size with the NUL
pub fn keyctl_describe(key_serial: i32, buffer: UserPtr<u8>, buflen: usize) -> KernelResult<usize> {
    let key = find_key(key_serial)?;
    need(&key, KEY_NEED_VIEW)?;
    let desc = key.key_type().describe(&key);
    let desc_bytes = desc.as_bytes();
    let total_len = desc_bytes.len() + 1;
    // No buffer: just the size needed
    if buflen == 0 || buffer.is_null() {
        return Ok(total_len);
    }
    let copy_len = desc_bytes.len().min(buflen - 1);
    let mut w = UserSlice::new(buffer.addr(), buflen).writer();
    if copy_len > 0 {
        w.write_slice(&desc_bytes[..copy_len])?;
    }
    if copy_len < buflen {
        w.write_slice(&[0u8])?;
    }
    Ok(total_len)
}

/// KEYCTL_CLEAR: unlink every key from keyring `keyring_serial`
pub fn keyctl_clear(keyring_serial: i32) -> KernelResult<()> {
    let keyring = find_keyring(keyring_serial)?;
    need(&keyring, KEY_NEED_WRITE)?;
    keyring.keyring_clear()
}

/// KEYCTL_LINK: link key `key_serial` into keyring `keyring_serial`
pub fn keyctl_link(key_serial: i32, keyring_serial: i32) -> KernelResult<()> {
    let key = lookup_key(key_serial).ok_or(KernelError::NoKey)?;
    let keyring = find_keyring(keyring_serial)?;
    // WRITE on the keyring, and LINK on the key being linked (Linux
    // lookup_user_key: KEY_NEED_LINK), else any user could link another
    // user's key into its own keyring and then possess it
    need(&keyring, KEY_NEED_WRITE)?;
    need(&key, KEY_NEED_LINK)?;
    keyring_link(&keyring, &key)
}

/// KEYCTL_UNLINK: unlink key `key_serial` from keyring `keyring_serial`
pub fn keyctl_unlink(key_serial: i32, keyring_serial: i32) -> KernelResult<()> {
    let key = lookup_key(key_serial).ok_or(KernelError::NoKey)?;
    let keyring = find_keyring(keyring_serial)?;
    need(&keyring, KEY_NEED_WRITE)?;
    keyring_unlink(&keyring, &key)
}

/// KEYCTL_SEARCH: the serial of a key of `type` and `description` that
/// keyring `keyring_serial` reaches, linked into `dest_keyring` if
/// non-zero
pub fn keyctl_search(
    keyring_serial: i32,
    type_ptr: UserPtr<u8>,
    desc_ptr: UserPtr<u8>,
    dest_keyring: i32,
) -> KernelResult<i32> {
    let (tid, uid, gid) = current_cred();
    let type_name = user_str(type_ptr, MAX_TYPE_LEN)?;
    let description = user_str(desc_ptr, MAX_DESC_LEN)?;
    let keyring = find_keyring(keyring_serial)?;
    // SEARCH on the keyring being searched (Linux lookup_user_key
    // KEY_NEED_SEARCH)
    need(&keyring, KEY_NEED_SEARCH)?;
    let key = keyring.keyring_search_recursive(&type_name, &description)?;
    if key.is_revoked() {
        return Err(KernelError::KeyRevoked);
    }
    // Linking the found key needs LINK on it and WRITE on the
    // destination (Linux keyctl_keyring_search)
    if dest_keyring != 0 {
        need(&key, KEY_NEED_LINK)?;
        if let Ok(dest) = resolve_special_keyring(dest_keyring, false, tid, uid, gid) {
            need(&dest, KEY_NEED_WRITE)?;
            let _ = keyring_link(&dest, &key);
        }
    }
    Ok(key.serial)
}

/// KEYCTL_READ: key `key_serial`'s payload into `buffer`, truncated;
/// the payload's full size
pub fn keyctl_read(key_serial: i32, buffer: UserPtr<u8>, buflen: usize) -> KernelResult<usize> {
    let key = find_key(key_serial)?;
    need(&key, KEY_NEED_READ)?;
    if key.is_revoked() {
        return Err(KernelError::KeyRevoked);
    }
    // Sized first: query mode returns just that; the read goes to a
    // buffer no larger than the payload (Linux keyctl_read_key sizes
    // it by the key)
    let need = key.key_type().read(&key, &mut [])?;
    if buflen == 0 || buffer.is_null() {
        return Ok(need);
    }
    let mut kbuf = crate::util::kmem::try_vec(buflen.min(need), 0u8)?;
    let actual_len = key.key_type().read(&key, &mut kbuf)?;
    // The payload may have grown since it was sized: copy only what
    // the buffer holds
    let copy_len = actual_len.min(kbuf.len());
    if copy_len > 0 {
        UserSlice::new(buffer.addr(), copy_len)
            .writer()
            .write_slice(&kbuf[..copy_len])?;
    }
    Ok(actual_len)
}

/// KEYCTL_INVALIDATE: make key `key_serial` unfindable and unlink it
/// everywhere
pub fn keyctl_invalidate(key_serial: i32) -> KernelResult<()> {
    let key = lookup_key(key_serial).ok_or(KernelError::NoKey)?;
    // SETATTR (Linux checks KEY_NEED_SEARCH plus a special case)
    need(&key, KEY_NEED_SETATTR)?;
    key.invalidate();
    // Lookups no longer find it, and no keyring links it: it is freed
    // with its last reference (Linux: the key GC unlinks invalidated keys)
    remove_key(key_serial);
    crate::keys::unlink_everywhere(key_serial);
    Ok(())
}
