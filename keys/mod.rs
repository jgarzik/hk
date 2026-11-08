//! Linux Keyring Subsystem
//!
//! This module implements the Linux keyring syscalls (add_key, request_key, keyctl)
//! for managing cryptographic keys and other security-related data.
//!
//! # Overview
//!
//! Keys are organized into keyrings (which are themselves a special type of key).
//! Each process has access to several keyrings:
//! - Thread keyring: per-thread, cleared on exec
//! - Process keyring: shared by all threads in a process
//! - Session keyring: inherited from parent, shared with children
//! - User keyring: shared by all processes of a user
//!
//! # Key Types
//!
//! - "user": arbitrary binary data (most common)
//! - "keyring": container for other keys

pub mod key;
pub mod keyctl;
pub mod keyring;
pub mod syscall;
pub mod types;

pub use key::{Key, KeyPerm, KeySerial, KeyState};
pub use keyctl::*;
pub use keyring::*;
pub use syscall::{sys_add_key, sys_keyctl, sys_request_key};
pub use types::{KeyType, KeyringKeyType, UserKeyType};

use crate::sync::spin::RwLock;
use crate::util::error::KernelError;
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

// =============================================================================
// Special keyring IDs (negative values, Linux ABI compatible)
// =============================================================================

/// Thread-specific keyring
pub const KEY_SPEC_THREAD_KEYRING: i32 = -1;
/// Process-specific keyring (shared by all threads)
pub const KEY_SPEC_PROCESS_KEYRING: i32 = -2;
/// Session keyring (inherited from parent)
pub const KEY_SPEC_SESSION_KEYRING: i32 = -3;
/// User-specific keyring
pub const KEY_SPEC_USER_KEYRING: i32 = -4;
/// Default session keyring for user
pub const KEY_SPEC_USER_SESSION_KEYRING: i32 = -5;
/// Group keyring
pub const KEY_SPEC_GROUP_KEYRING: i32 = -6;
/// Auth key for request_key
pub const KEY_SPEC_REQKEY_AUTH_KEY: i32 = -7;
/// Requestor keyring
pub const KEY_SPEC_REQUESTOR_KEYRING: i32 = -8;

// =============================================================================
// Keyctl commands (Linux ABI compatible)
// =============================================================================

/// Get the ID of a special keyring
pub const KEYCTL_GET_KEYRING_ID: i32 = 0;
/// Join or create a named session keyring
pub const KEYCTL_JOIN_SESSION_KEYRING: i32 = 1;
/// Update a key's payload
pub const KEYCTL_UPDATE: i32 = 2;
/// Revoke a key
pub const KEYCTL_REVOKE: i32 = 3;
/// Change a key's ownership
pub const KEYCTL_CHOWN: i32 = 4;
/// Set a key's permissions
pub const KEYCTL_SETPERM: i32 = 5;
/// Describe a key
pub const KEYCTL_DESCRIBE: i32 = 6;
/// Clear a keyring
pub const KEYCTL_CLEAR: i32 = 7;
/// Link a key to a keyring
pub const KEYCTL_LINK: i32 = 8;
/// Unlink a key from a keyring
pub const KEYCTL_UNLINK: i32 = 9;
/// Search a keyring
pub const KEYCTL_SEARCH: i32 = 10;
/// Read a key's payload
pub const KEYCTL_READ: i32 = 11;
/// Instantiate a partially constructed key
pub const KEYCTL_INSTANTIATE: i32 = 12;
/// Negate a partially constructed key
pub const KEYCTL_NEGATE: i32 = 13;
/// Set the default keyring for request_key
pub const KEYCTL_SET_REQKEY_KEYRING: i32 = 14;
/// Set a key's timeout
pub const KEYCTL_SET_TIMEOUT: i32 = 15;
/// Assume authority to instantiate a key
pub const KEYCTL_ASSUME_AUTHORITY: i32 = 16;
/// Get the security label of a key
pub const KEYCTL_GET_SECURITY: i32 = 17;
/// Apply session keyring to parent process
pub const KEYCTL_SESSION_TO_PARENT: i32 = 18;
/// Reject a key with specific error
pub const KEYCTL_REJECT: i32 = 19;
/// Instantiate a key with iovec data
pub const KEYCTL_INSTANTIATE_IOV: i32 = 20;
/// Invalidate a key
pub const KEYCTL_INVALIDATE: i32 = 21;
/// Get persistent keyring for a user
pub const KEYCTL_GET_PERSISTENT: i32 = 22;

// =============================================================================
// Global key database
// =============================================================================

/// Every live key by serial number (Linux key_serial_tree). Entries are
/// weak: links and task/user keyring slots own keys, and a key removes
/// its entry when it is freed. Nothing drops an `Arc<Key>` under this
/// lock (lookups upgrade after releasing it), so a key's Drop may take it.
static KEY_DATABASE: RwLock<BTreeMap<KeySerial, Weak<Key>>> = RwLock::new(BTreeMap::new());

/// Reserve a new key serial number (Linux key_alloc_serial): a random
/// start, never below 3, moved up past serials in use (wrapping back to
/// 3). It is taken under the database lock by a placeholder entry, which
/// `register_key` replaces or the key's Drop removes.
pub fn alloc_serial() -> KeySerial {
    let mut serial = loop {
        // Negative serials are not permitted (Linux: random >> 1)
        let r = (crate::random::get_random_u32() >> 1) as KeySerial;
        if r >= 3 {
            break r;
        }
    };
    let mut db = KEY_DATABASE.write();
    while db.contains_key(&serial) {
        serial = serial.checked_add(1).unwrap_or(3);
    }
    db.insert(serial, Weak::new());
    serial
}

/// Register a key in the global database
pub fn register_key(key: &Arc<Key>) {
    KEY_DATABASE.write().insert(key.serial, Arc::downgrade(key));
}

/// Look up a live key by serial number
pub fn lookup_key(serial: KeySerial) -> Option<Arc<Key>> {
    let w = KEY_DATABASE.read().get(&serial).cloned()?;
    w.upgrade()
}

/// Take a key out of the database (invalidate): lookups no longer find
/// it; it is freed when its links and references go
pub fn remove_key(serial: KeySerial) {
    let w = KEY_DATABASE.write().remove(&serial);
    drop(w);
}

/// A freed key (`key`, its `Drop`) leaves the database, unless the
/// serial names another entry by then
fn unregister_key(serial: KeySerial, key: *const Key) {
    let mut db = KEY_DATABASE.write();
    // Its own entry, or the placeholder of a key never registered
    if db
        .get(&serial)
        .is_some_and(|w| core::ptr::eq(w.as_ptr(), key) || w.ptr_eq(&Weak::new()))
    {
        db.remove(&serial);
    }
}

/// Every live keyring (for invalidation's unlinking)
fn all_keyrings() -> Vec<Arc<Key>> {
    let all: Vec<Weak<Key>> = KEY_DATABASE.read().values().cloned().collect();
    all.iter()
        .filter_map(Weak::upgrade)
        .filter(|k| k.is_keyring())
        .collect()
}

/// Unlink `serial` from every keyring (Linux key_gc_keyring for an
/// invalidated key)
pub fn unlink_everywhere(serial: KeySerial) {
    for r in all_keyrings() {
        let _ = r.keyring_remove(serial);
    }
}

/// Per-user key accounting (Linux key_user): bounds how many keys and
/// bytes of payload one user can pin, so keys cannot exhaust the heap.
#[derive(Default)]
struct KeyUser {
    nkeys: usize,
    nbytes: usize,
}

static KEY_USERS: RwLock<BTreeMap<u32, KeyUser>> = RwLock::new(BTreeMap::new());

/// Linux root/non-root key quota (key.c): maxkeys / maxbytes
const KEY_MAXKEYS: usize = 200;
const KEY_MAXBYTES: usize = 20000;
const KEY_ROOT_MAXKEYS: usize = 1_000_000;
const KEY_ROOT_MAXBYTES: usize = 25_000_000;

/// Charge one key of `bytes` to `uid`, or EDQUOT past its limit (Linux
/// key_alloc / key_payload_reserve)
pub fn key_user_charge(uid: u32, bytes: usize) -> Result<(), KernelError> {
    let (maxk, maxb) = if uid == 0 {
        (KEY_ROOT_MAXKEYS, KEY_ROOT_MAXBYTES)
    } else {
        (KEY_MAXKEYS, KEY_MAXBYTES)
    };
    let mut users = KEY_USERS.write();
    let u = users.entry(uid).or_default();
    if u.nkeys + 1 > maxk || u.nbytes.saturating_add(bytes) > maxb {
        return Err(KernelError::QuotaExceeded);
    }
    u.nkeys += 1;
    u.nbytes += bytes;
    Ok(())
}

/// Change a key's byte charge from `old` to `new` (Linux
/// key_payload_reserve): EDQUOT if growing passes `uid`'s maxbytes
pub fn key_user_resize(uid: u32, old: usize, new: usize) -> Result<(), KernelError> {
    let maxb = if uid == 0 {
        KEY_ROOT_MAXBYTES
    } else {
        KEY_MAXBYTES
    };
    let mut users = KEY_USERS.write();
    let u = users.entry(uid).or_default();
    let n = u.nbytes.saturating_sub(old).saturating_add(new);
    if new > old && n > maxb {
        return Err(KernelError::QuotaExceeded);
    }
    u.nbytes = n;
    Ok(())
}

/// Return a key's charge when it is freed (Key's drop)
pub fn key_user_uncharge(uid: u32, bytes: usize) {
    let mut users = KEY_USERS.write();
    if let Some(u) = users.get_mut(&uid) {
        u.nkeys = u.nkeys.saturating_sub(1);
        u.nbytes = u.nbytes.saturating_sub(bytes);
    }
}

/// Get the number of keys in the database (for testing/debugging)
pub fn key_count() -> usize {
    KEY_DATABASE.read().len()
}
