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

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicI32, Ordering};
use spin::RwLock;

// =============================================================================
// Error codes for keyring operations (Linux ABI compatible)
// =============================================================================

/// Required key not available
pub const ENOKEY: i64 = -126;
/// Key has expired
pub const EKEYEXPIRED: i64 = -127;
/// Key has been revoked
pub const EKEYREVOKED: i64 = -128;
/// Key was rejected by service
pub const EKEYREJECTED: i64 = -129;

// Common error codes
pub const EINVAL: i64 = -22;
pub const ENOENT: i64 = -2;
pub const ENOMEM: i64 = -12;
pub const EFAULT: i64 = -14;
pub const EACCES: i64 = -13;
pub const EPERM: i64 = -1;
pub const EDQUOT: i64 = -122;
pub const ENOTDIR: i64 = -20;
pub const EEXIST: i64 = -17;
pub const EOPNOTSUPP: i64 = -95;

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

/// Global key database indexed by serial number
static KEY_DATABASE: RwLock<BTreeMap<KeySerial, Arc<Key>>> = RwLock::new(BTreeMap::new());

/// Next serial number to allocate (keys start at serial 3)
static NEXT_SERIAL: AtomicI32 = AtomicI32::new(3);

/// Allocate a new unique key serial number
pub fn alloc_serial() -> KeySerial {
    NEXT_SERIAL.fetch_add(1, Ordering::Relaxed)
}

/// Register a key in the global database
pub fn register_key(key: Arc<Key>) {
    let mut db = KEY_DATABASE.write();
    db.insert(key.serial, key);
}

/// Look up a key by serial number
pub fn lookup_key(serial: KeySerial) -> Option<Arc<Key>> {
    KEY_DATABASE.read().get(&serial).cloned()
}

/// Remove a key from the database
pub fn remove_key(serial: KeySerial) -> Option<Arc<Key>> {
    KEY_DATABASE.write().remove(&serial)
}

/// Get the number of keys in the database (for testing/debugging)
pub fn key_count() -> usize {
    KEY_DATABASE.read().len()
}
