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

use crate::sync::spin::RwLock;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;

use crate::task::Task;
use crate::util::error::KernelError;

use super::key::{KEYRING_DEFAULT_PERM, Key, KeySerial};
use super::types::keyring_key_type;
use super::{
    KEY_SPEC_PROCESS_KEYRING, KEY_SPEC_SESSION_KEYRING, KEY_SPEC_THREAD_KEYRING,
    KEY_SPEC_USER_KEYRING, KEY_SPEC_USER_SESSION_KEYRING,
};
use super::{alloc_key, alloc_key_nofail, lookup_key, register_key};

/// Per-task keyrings (Linux cred->thread/process/session_keyring): the
/// task holds a reference to each
#[derive(Clone, Default)]
pub struct TaskKeyrings {
    /// Thread keyring (KEY_SPEC_THREAD_KEYRING = -1)
    pub thread_keyring: Option<Arc<Key>>,
    /// Process keyring (KEY_SPEC_PROCESS_KEYRING = -2) - shared by all threads
    pub process_keyring: Option<Arc<Key>>,
    /// Session keyring (KEY_SPEC_SESSION_KEYRING = -3) - inherited from parent
    pub session_keyring: Option<Arc<Key>>,
}

impl TaskKeyrings {
    pub const fn new() -> Self {
        Self {
            thread_keyring: None,
            process_keyring: None,
            session_keyring: None,
        }
    }
}

/// Per-user keyring tracking
static USER_KEYRINGS: RwLock<BTreeMap<u32, UserKeyrings>> = RwLock::new(BTreeMap::new());

/// Per-user keyrings, which live as long as the system (Linux keeps them
/// with the user namespace's key_user)
#[derive(Clone, Default)]
struct UserKeyrings {
    /// User keyring (KEY_SPEC_USER_KEYRING = -4)
    user_keyring: Option<Arc<Key>>,
    /// User session keyring (KEY_SPEC_USER_SESSION_KEYRING = -5)
    user_session_keyring: Option<Arc<Key>>,
}

/// The keyrings of task `t` (`Task.keyrings`, Linux cred keyrings)
pub fn get_task_keyrings(t: &Task) -> TaskKeyrings {
    t.keyrings.lock().clone()
}

/// Set the keyrings of task `t`; the old ones are dropped after the
/// task's lock
pub fn set_task_keyrings(t: &Task, keyrings: TaskKeyrings) {
    let old = core::mem::replace(&mut *t.keyrings.lock(), keyrings);
    drop(old);
}

/// The keyrings of a new task (Linux copy_creds): the session keyring
/// always; the process keyring only for a thread of the same process;
/// a thread keyring of its own for a thread whose creator has one
pub fn fork_keyrings(parent: &TaskKeyrings, thread: bool, uid: u32, gid: u32) -> TaskKeyrings {
    TaskKeyrings {
        session_keyring: parent.session_keyring.clone(),
        process_keyring: parent.process_keyring.clone().filter(|_| thread),
        // Linux copy_creds can fail here; do_clone cannot yet
        thread_keyring: (thread && parent.thread_keyring.is_some()).then(|| {
            let k = alloc_key_nofail(|s| keyring_key(s, "_tid", uid, gid));
            publish_keyring(&k);
            k
        }),
    }
}

/// At exec's point of no return (Linux prepare_exec_creds): `t`'s
/// thread and process keyrings go, the session keyring stays
pub fn exec_keyrings(t: &Task) {
    let mut k = get_task_keyrings(t);
    k.thread_keyring = None;
    k.process_keyring = None;
    set_task_keyrings(t, k);
}

/// Create a new keyring with the given description
pub fn create_keyring(description: &str, uid: u32, gid: u32) -> Result<Arc<Key>, KernelError> {
    let key = alloc_key(|s| keyring_key(s, description, uid, gid))?;
    publish_keyring(&key);
    Ok(key)
}

/// A new keyring with `serial`, not yet registered
fn keyring_key(serial: KeySerial, description: &str, uid: u32, gid: u32) -> Key {
    Key::new(
        serial,
        keyring_key_type(),
        String::from(description),
        uid,
        gid,
        KEYRING_DEFAULT_PERM,
    )
}

/// Instantiate and register a new keyring
fn publish_keyring(key: &Arc<Key>) {
    // Mark as instantiated since keyrings don't need payload
    let _ = key.instantiate(alloc::vec![]);
    register_key(key);
}

/// The keyring in `slot`, made (as `name`) if `create` and none is there
fn slot_keyring(
    slot: &mut Option<Arc<Key>>,
    create: bool,
    name: &str,
    uid: u32,
    gid: u32,
) -> Result<Arc<Key>, KernelError> {
    if let Some(k) = slot.as_ref().filter(|k| k.state() != super::KeyState::Dead) {
        return Ok(k.clone());
    }
    if !create {
        return Err(KernelError::NoKey);
    }
    let k = create_keyring(name, uid, gid)?;
    // An invalidated keyring the slot held is dropped after the caller's
    // lock (returned to it below by replace)
    let _old = slot.replace(k.clone());
    Ok(k)
}

/// Resolve a special keyring ID of task `t` to an actual keyring,
/// optionally creating it
pub fn resolve_special_keyring(
    special_id: i32,
    create: bool,
    t: &Task,
    uid: u32,
    gid: u32,
) -> Result<Arc<Key>, KernelError> {
    let task_slot = |pick: fn(&mut TaskKeyrings) -> &mut Option<Arc<Key>>, name| {
        let mut k = t.keyrings.lock();
        slot_keyring(pick(&mut k), create, name, uid, gid)
    };
    let user_slot = |pick: fn(&mut UserKeyrings) -> &mut Option<Arc<Key>>, name| {
        let mut users = USER_KEYRINGS.write();
        slot_keyring(pick(users.entry(uid).or_default()), create, name, uid, gid)
    };
    match special_id {
        KEY_SPEC_THREAD_KEYRING => task_slot(|k| &mut k.thread_keyring, "_tid"),
        KEY_SPEC_PROCESS_KEYRING => task_slot(|k| &mut k.process_keyring, "_pid"),
        KEY_SPEC_SESSION_KEYRING => task_slot(|k| &mut k.session_keyring, "_ses"),
        KEY_SPEC_USER_KEYRING => user_slot(|k| &mut k.user_keyring, "_uid"),
        KEY_SPEC_USER_SESSION_KEYRING => user_slot(|k| &mut k.user_session_keyring, "_uid_ses"),
        // Positive serial: look up directly
        serial if serial > 0 => lookup_key(serial).ok_or(KernelError::NoKey),
        // Invalid special ID
        _ => Err(KernelError::NoKey),
    }
}

/// Link a key to a keyring
pub fn keyring_link(keyring: &Key, key: &Arc<Key>) -> Result<(), KernelError> {
    keyring.keyring_add(key)
}

/// Unlink a key from a keyring
pub fn keyring_unlink(keyring: &Key, key: &Key) -> Result<(), KernelError> {
    keyring.keyring_remove(key.serial)
}

/// Whether task `t` possesses `key` (Linux: lookup_user_key finds it
/// through search_process_keyrings): it is, or is reachable from, the
/// thread, process or session keyring, or the user-session keyring when
/// there is no session keyring
pub fn possessed(key: &Key, t: &Task) -> bool {
    use super::key::KEYRING_SEARCH_MAX_DEPTH;
    let k = get_task_keyrings(t);
    let session = k.session_keyring.clone().or_else(|| {
        let uid = crate::task::percpu::current_cred().uid;
        USER_KEYRINGS
            .read()
            .get(&uid)
            .and_then(|u| u.user_session_keyring.clone())
    });
    [k.thread_keyring, k.process_keyring, session]
        .into_iter()
        .flatten()
        .any(|r| r.keyring_reaches(key.serial, KEYRING_SEARCH_MAX_DEPTH))
}

/// Search all of task `t`'s process keyrings for a key
pub fn search_process_keyrings(type_name: &str, description: &str, t: &Task) -> Option<Arc<Key>> {
    let k = get_task_keyrings(t);
    [k.thread_keyring, k.process_keyring, k.session_keyring]
        .into_iter()
        .flatten()
        .find_map(|r| r.keyring_search_recursive(type_name, description).ok())
}
