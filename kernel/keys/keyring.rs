//! Per-process keyring management
//!
//! Each process has access to several keyrings:
//! - Thread keyring: per-thread, cleared on exec
//! - Process keyring: shared by all threads in a process
//! - Session keyring: inherited from parent, shared with children
//! - User keyring: shared by all processes of a user
//!
//! This module manages the per-task keyring references and provides
//! functions to resolve special keyring IDs to actual key serials.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use spin::RwLock;

use super::key::{KEYRING_DEFAULT_PERM, Key, KeySerial};
use super::types::keyring_key_type;
use super::{
    ENOKEY, KEY_SPEC_PROCESS_KEYRING, KEY_SPEC_SESSION_KEYRING, KEY_SPEC_THREAD_KEYRING,
    KEY_SPEC_USER_KEYRING, KEY_SPEC_USER_SESSION_KEYRING,
};
use super::{alloc_serial, lookup_key, register_key};

/// Per-task keyring references
#[derive(Clone, Default)]
pub struct TaskKeyrings {
    /// Thread keyring (KEY_SPEC_THREAD_KEYRING = -1)
    pub thread_keyring: Option<KeySerial>,
    /// Process keyring (KEY_SPEC_PROCESS_KEYRING = -2) - shared by all threads
    pub process_keyring: Option<KeySerial>,
    /// Session keyring (KEY_SPEC_SESSION_KEYRING = -3) - inherited from parent
    pub session_keyring: Option<KeySerial>,
}

/// Global map of task keyrings indexed by TID
static TASK_KEYRINGS: RwLock<BTreeMap<u64, TaskKeyrings>> = RwLock::new(BTreeMap::new());

/// Per-user keyring tracking
static USER_KEYRINGS: RwLock<BTreeMap<u32, UserKeyrings>> = RwLock::new(BTreeMap::new());

/// Per-user keyring references
#[derive(Clone, Default)]
struct UserKeyrings {
    /// User keyring (KEY_SPEC_USER_KEYRING = -4)
    user_keyring: Option<KeySerial>,
    /// User session keyring (KEY_SPEC_USER_SESSION_KEYRING = -5)
    user_session_keyring: Option<KeySerial>,
}

/// Get or create the keyrings for a task
pub fn get_task_keyrings(tid: u64) -> TaskKeyrings {
    let keyrings = TASK_KEYRINGS.read();
    keyrings.get(&tid).cloned().unwrap_or_default()
}

/// Set the keyrings for a task
pub fn set_task_keyrings(tid: u64, keyrings: TaskKeyrings) {
    TASK_KEYRINGS.write().insert(tid, keyrings);
}

/// Remove keyrings when a task exits
pub fn remove_task_keyrings(tid: u64) {
    TASK_KEYRINGS.write().remove(&tid);
}

/// Create a new keyring with the given description
pub fn create_keyring(description: &str, uid: u32, gid: u32) -> Arc<Key> {
    let serial = alloc_serial();
    let key = Key::new(
        serial,
        keyring_key_type(),
        String::from(description),
        uid,
        gid,
        KEYRING_DEFAULT_PERM,
    );
    // Mark as instantiated since keyrings don't need payload
    key.set_payload(alloc::vec![]);
    register_key(key.clone());
    key
}

/// Resolve a special keyring ID to an actual keyring, optionally creating it
pub fn resolve_special_keyring(
    special_id: i32,
    create: bool,
    tid: u64,
    uid: u32,
    gid: u32,
) -> Result<Arc<Key>, i64> {
    match special_id {
        KEY_SPEC_THREAD_KEYRING => {
            let mut all_keyrings = TASK_KEYRINGS.write();
            let keyrings = all_keyrings.entry(tid).or_default();

            if let Some(serial) = keyrings.thread_keyring
                && let Some(key) = lookup_key(serial)
            {
                return Ok(key);
            }

            if create {
                let keyring = create_keyring("_tid", uid, gid);
                keyrings.thread_keyring = Some(keyring.serial);
                Ok(keyring)
            } else {
                Err(ENOKEY)
            }
        }

        KEY_SPEC_PROCESS_KEYRING => {
            let mut all_keyrings = TASK_KEYRINGS.write();
            let keyrings = all_keyrings.entry(tid).or_default();

            if let Some(serial) = keyrings.process_keyring
                && let Some(key) = lookup_key(serial)
            {
                return Ok(key);
            }

            if create {
                let keyring = create_keyring("_pid", uid, gid);
                keyrings.process_keyring = Some(keyring.serial);
                Ok(keyring)
            } else {
                Err(ENOKEY)
            }
        }

        KEY_SPEC_SESSION_KEYRING => {
            let mut all_keyrings = TASK_KEYRINGS.write();
            let keyrings = all_keyrings.entry(tid).or_default();

            if let Some(serial) = keyrings.session_keyring
                && let Some(key) = lookup_key(serial)
            {
                return Ok(key);
            }

            if create {
                let keyring = create_keyring("_ses", uid, gid);
                keyrings.session_keyring = Some(keyring.serial);
                Ok(keyring)
            } else {
                Err(ENOKEY)
            }
        }

        KEY_SPEC_USER_KEYRING => {
            let mut user_keyrings = USER_KEYRINGS.write();
            let keyrings = user_keyrings.entry(uid).or_default();

            if let Some(serial) = keyrings.user_keyring
                && let Some(key) = lookup_key(serial)
            {
                return Ok(key);
            }

            if create {
                let keyring = create_keyring("_uid", uid, gid);
                keyrings.user_keyring = Some(keyring.serial);
                Ok(keyring)
            } else {
                Err(ENOKEY)
            }
        }

        KEY_SPEC_USER_SESSION_KEYRING => {
            let mut user_keyrings = USER_KEYRINGS.write();
            let keyrings = user_keyrings.entry(uid).or_default();

            if let Some(serial) = keyrings.user_session_keyring
                && let Some(key) = lookup_key(serial)
            {
                return Ok(key);
            }

            if create {
                let keyring = create_keyring("_uid_ses", uid, gid);
                keyrings.user_session_keyring = Some(keyring.serial);
                Ok(keyring)
            } else {
                Err(ENOKEY)
            }
        }

        // Positive serial: look up directly
        serial if serial > 0 => lookup_key(serial).ok_or(ENOKEY),

        // Invalid special ID
        _ => Err(ENOKEY),
    }
}

/// Link a key to a keyring
pub fn keyring_link(keyring: &Key, key: &Key) -> Result<(), i64> {
    keyring.keyring_add(key.serial)
}

/// Unlink a key from a keyring
pub fn keyring_unlink(keyring: &Key, key: &Key) -> Result<(), i64> {
    keyring.keyring_remove(key.serial)
}

/// Search all process keyrings for a key
pub fn search_process_keyrings(type_name: &str, description: &str, tid: u64) -> Option<Arc<Key>> {
    let keyrings = get_task_keyrings(tid);

    // Search thread keyring
    if let Some(serial) = keyrings.thread_keyring
        && let Some(keyring) = lookup_key(serial)
        && let Some(found) = keyring.keyring_search_recursive(type_name, description)
    {
        return lookup_key(found);
    }

    // Search process keyring
    if let Some(serial) = keyrings.process_keyring
        && let Some(keyring) = lookup_key(serial)
        && let Some(found) = keyring.keyring_search_recursive(type_name, description)
    {
        return lookup_key(found);
    }

    // Search session keyring
    if let Some(serial) = keyrings.session_keyring
        && let Some(keyring) = lookup_key(serial)
        && let Some(found) = keyring.keyring_search_recursive(type_name, description)
    {
        return lookup_key(found);
    }

    None
}
