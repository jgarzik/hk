//! Core key structure and related types
//!
//! This module defines the Key struct which represents a security key
//! in the Linux keyring subsystem.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::RwLock;

use super::types::KeyType;

/// Key serial number type (positive i32, >= 3)
pub type KeySerial = i32;

/// Key permission mask (Linux ABI compatible)
pub type KeyPerm = u32;

// =============================================================================
// Key permission bits (Linux ABI compatible)
// =============================================================================

// Possessor permissions (bits 24-29)
/// Possessor can view key attributes
pub const KEY_POS_VIEW: u32 = 0x01000000;
/// Possessor can read key payload
pub const KEY_POS_READ: u32 = 0x02000000;
/// Possessor can update key payload
pub const KEY_POS_WRITE: u32 = 0x04000000;
/// Possessor can search keyring
pub const KEY_POS_SEARCH: u32 = 0x08000000;
/// Possessor can link key to keyring
pub const KEY_POS_LINK: u32 = 0x10000000;
/// Possessor can change key attributes
pub const KEY_POS_SETATTR: u32 = 0x20000000;
/// All possessor permissions
pub const KEY_POS_ALL: u32 = 0x3f000000;

// User (owner) permissions (bits 16-21)
/// Owner can view key attributes
pub const KEY_USR_VIEW: u32 = 0x00010000;
/// Owner can read key payload
pub const KEY_USR_READ: u32 = 0x00020000;
/// Owner can update key payload
pub const KEY_USR_WRITE: u32 = 0x00040000;
/// Owner can search keyring
pub const KEY_USR_SEARCH: u32 = 0x00080000;
/// Owner can link key to keyring
pub const KEY_USR_LINK: u32 = 0x00100000;
/// Owner can change key attributes
pub const KEY_USR_SETATTR: u32 = 0x00200000;
/// All owner permissions
pub const KEY_USR_ALL: u32 = 0x003f0000;

// Group permissions (bits 8-13)
/// Group can view key attributes
pub const KEY_GRP_VIEW: u32 = 0x00000100;
/// Group can read key payload
pub const KEY_GRP_READ: u32 = 0x00000200;
/// Group can update key payload
pub const KEY_GRP_WRITE: u32 = 0x00000400;
/// Group can search keyring
pub const KEY_GRP_SEARCH: u32 = 0x00000800;
/// Group can link key to keyring
pub const KEY_GRP_LINK: u32 = 0x00001000;
/// Group can change key attributes
pub const KEY_GRP_SETATTR: u32 = 0x00002000;
/// All group permissions
pub const KEY_GRP_ALL: u32 = 0x00003f00;

// Other permissions (bits 0-5)
/// Others can view key attributes
pub const KEY_OTH_VIEW: u32 = 0x00000001;
/// Others can read key payload
pub const KEY_OTH_READ: u32 = 0x00000002;
/// Others can update key payload
pub const KEY_OTH_WRITE: u32 = 0x00000004;
/// Others can search keyring
pub const KEY_OTH_SEARCH: u32 = 0x00000008;
/// Others can link key to keyring
pub const KEY_OTH_LINK: u32 = 0x00000010;
/// Others can change key attributes
pub const KEY_OTH_SETATTR: u32 = 0x00000020;
/// All other permissions
pub const KEY_OTH_ALL: u32 = 0x0000003f;

// =============================================================================
// Permission checking constants
// =============================================================================

/// Need VIEW permission
pub const KEY_NEED_VIEW: u32 = 0x01;
/// Need READ permission
pub const KEY_NEED_READ: u32 = 0x02;
/// Need WRITE permission
pub const KEY_NEED_WRITE: u32 = 0x04;
/// Need SEARCH permission
pub const KEY_NEED_SEARCH: u32 = 0x08;
/// Need LINK permission
pub const KEY_NEED_LINK: u32 = 0x10;
/// Need SETATTR permission
pub const KEY_NEED_SETATTR: u32 = 0x20;

/// Key state enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum KeyState {
    /// Key is being constructed
    Uninstantiated = 0,
    /// Key is valid and usable
    Instantiated = 1,
    /// Key has been revoked
    Revoked = 2,
    /// Key is dead (to be garbage collected)
    Dead = 3,
}

impl From<u32> for KeyState {
    fn from(value: u32) -> Self {
        match value {
            0 => KeyState::Uninstantiated,
            1 => KeyState::Instantiated,
            2 => KeyState::Revoked,
            3 => KeyState::Dead,
            _ => KeyState::Dead,
        }
    }
}

/// Core key structure
///
/// Represents a key in the Linux keyring subsystem. Keys can be:
/// - Regular keys: contain a payload (e.g., "user" type)
/// - Keyrings: contain links to other keys (e.g., "keyring" type)
pub struct Key {
    /// Unique serial number (positive, >= 3)
    pub serial: KeySerial,

    /// Key type name (e.g., "user", "keyring")
    pub type_name: String,

    /// Key description (user-visible identifier)
    pub description: String,

    /// Key payload (type-specific data) - None for keyrings
    payload: RwLock<Option<Vec<u8>>>,

    /// Owner UID
    pub uid: u32,

    /// Owner GID
    pub gid: u32,

    /// Permission mask
    perm: AtomicU32,

    /// State (uninstantiated, instantiated, revoked, dead)
    state: AtomicU32,

    /// For keyrings: contained keys (by serial number)
    keyring_keys: RwLock<Vec<KeySerial>>,

    /// Key type reference for polymorphic operations
    key_type: Arc<dyn KeyType>,
}

// Safety: Key uses atomic operations and RwLock for synchronization
unsafe impl Send for Key {}
unsafe impl Sync for Key {}

impl Key {
    /// Create a new key
    pub fn new(
        serial: KeySerial,
        key_type: Arc<dyn KeyType>,
        description: String,
        uid: u32,
        gid: u32,
        perm: KeyPerm,
    ) -> Arc<Self> {
        Arc::new(Self {
            serial,
            type_name: String::from(key_type.name()),
            description,
            payload: RwLock::new(None),
            uid,
            gid,
            perm: AtomicU32::new(perm),
            state: AtomicU32::new(KeyState::Uninstantiated as u32),
            keyring_keys: RwLock::new(Vec::new()),
            key_type,
        })
    }

    /// Set the key's payload and mark it as instantiated
    pub fn set_payload(&self, data: Vec<u8>) {
        let mut payload = self.payload.write();
        *payload = Some(data);
        self.state
            .store(KeyState::Instantiated as u32, Ordering::Release);
    }

    /// Read the key's payload
    pub fn read_payload(&self) -> Option<Vec<u8>> {
        self.payload.read().clone()
    }

    /// Get the payload length (without copying)
    pub fn payload_len(&self) -> usize {
        self.payload.read().as_ref().map(|p| p.len()).unwrap_or(0)
    }

    /// Get the key's current state
    pub fn state(&self) -> KeyState {
        KeyState::from(self.state.load(Ordering::Acquire))
    }

    /// Check if key is instantiated (valid)
    pub fn is_instantiated(&self) -> bool {
        self.state() == KeyState::Instantiated
    }

    /// Check if key is revoked
    pub fn is_revoked(&self) -> bool {
        self.state() == KeyState::Revoked
    }

    /// Check if key is dead
    pub fn is_dead(&self) -> bool {
        self.state() == KeyState::Dead
    }

    /// Revoke the key
    pub fn revoke(&self) {
        self.state
            .store(KeyState::Revoked as u32, Ordering::Release);
    }

    /// Invalidate the key (mark as dead)
    pub fn invalidate(&self) {
        self.state.store(KeyState::Dead as u32, Ordering::Release);
    }

    /// Check if this key is a keyring
    pub fn is_keyring(&self) -> bool {
        self.type_name == "keyring"
    }

    /// Get the permission mask
    pub fn perm(&self) -> KeyPerm {
        self.perm.load(Ordering::Relaxed)
    }

    /// Set the permission mask
    pub fn set_perm(&self, perm: KeyPerm) {
        self.perm.store(perm, Ordering::Relaxed);
    }

    /// Get the key type
    pub fn key_type(&self) -> &Arc<dyn KeyType> {
        &self.key_type
    }

    // ==========================================================================
    // Keyring-specific operations
    // ==========================================================================

    /// Add a key to this keyring (if this is a keyring)
    pub fn keyring_add(&self, key_serial: KeySerial) -> Result<(), i64> {
        if !self.is_keyring() {
            return Err(super::ENOTDIR);
        }

        let mut keys = self.keyring_keys.write();

        // Check if already linked
        if keys.contains(&key_serial) {
            return Ok(()); // Already linked, success
        }

        keys.push(key_serial);
        Ok(())
    }

    /// Remove a key from this keyring
    pub fn keyring_remove(&self, key_serial: KeySerial) -> Result<(), i64> {
        if !self.is_keyring() {
            return Err(super::ENOTDIR);
        }

        let mut keys = self.keyring_keys.write();
        if let Some(pos) = keys.iter().position(|&s| s == key_serial) {
            keys.remove(pos);
            Ok(())
        } else {
            Err(super::ENOENT)
        }
    }

    /// Clear all keys from this keyring
    pub fn keyring_clear(&self) -> Result<(), i64> {
        if !self.is_keyring() {
            return Err(super::ENOTDIR);
        }

        self.keyring_keys.write().clear();
        Ok(())
    }

    /// Get the list of key serials in this keyring
    pub fn keyring_keys(&self) -> Vec<KeySerial> {
        self.keyring_keys.read().clone()
    }

    /// Get the number of keys in this keyring
    pub fn keyring_count(&self) -> usize {
        self.keyring_keys.read().len()
    }

    /// Search this keyring for a key by type and description
    pub fn keyring_search(&self, type_name: &str, description: &str) -> Option<KeySerial> {
        if !self.is_keyring() {
            return None;
        }

        let keys = self.keyring_keys.read();
        for &serial in keys.iter() {
            if let Some(key) = super::lookup_key(serial)
                && key.type_name == type_name
                && key.description == description
                && key.is_instantiated()
                && !key.is_revoked()
            {
                return Some(serial);
            }
        }
        None
    }

    /// Recursively search this keyring and all nested keyrings
    pub fn keyring_search_recursive(
        &self,
        type_name: &str,
        description: &str,
    ) -> Option<KeySerial> {
        if !self.is_keyring() {
            return None;
        }

        // Clone the keys while holding the lock, then release before recursion
        let keys = self.keyring_keys.read().clone();

        for serial in keys {
            if let Some(key) = super::lookup_key(serial) {
                // Check if this key matches
                if key.type_name == type_name
                    && key.description == description
                    && key.is_instantiated()
                    && !key.is_revoked()
                {
                    return Some(serial);
                }
                // Recursively search nested keyrings
                if key.is_keyring()
                    && let Some(found) = key.keyring_search_recursive(type_name, description)
                {
                    return Some(found);
                }
            }
        }
        None
    }
}

/// Check if the current task has the required permission on a key
pub fn check_key_permission(key: &Key, needed: u32, uid: u32, gid: u32, is_root: bool) -> bool {
    // Root can do anything
    if is_root {
        return true;
    }

    let perm = key.perm();

    // Check owner permissions
    if key.uid == uid {
        let shift = 16; // KEY_USR_* is in bits 16-21
        if (perm >> shift) & needed == needed {
            return true;
        }
    }

    // Check group permissions
    if key.gid == gid {
        let shift = 8; // KEY_GRP_* is in bits 8-13
        if (perm >> shift) & needed == needed {
            return true;
        }
    }

    // Check other permissions
    (perm & needed) == needed
}

/// Default permissions for new keys
pub const KEY_DEFAULT_PERM: KeyPerm = KEY_POS_ALL | KEY_USR_ALL;

/// Default permissions for new keyrings
pub const KEYRING_DEFAULT_PERM: KeyPerm = KEY_POS_ALL | KEY_USR_ALL | KEY_USR_SEARCH;
