//! Core key structure and related types
//!
//! This module defines the Key struct which represents a security key
//! in the Linux keyring subsystem.

use crate::sync::spin::RwLock;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::util::error::KernelError;

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

    /// Owner UID and GID (Linux key->uid/gid: changed under key->sem,
    /// here the payload lock, by KEYCTL_CHOWN; read lock-free by the
    /// permission checks and describe)
    uid: AtomicU32,
    gid: AtomicU32,

    /// Permission mask
    perm: AtomicU32,

    /// State (uninstantiated, instantiated, revoked, dead)
    state: AtomicU32,

    /// For keyrings: contained keys (by serial number)
    keyring_keys: RwLock<Vec<KeySerial>>,

    /// Key type reference for polymorphic operations
    key_type: Arc<dyn KeyType>,
}

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
            uid: AtomicU32::new(uid),
            gid: AtomicU32::new(gid),
            perm: AtomicU32::new(perm),
            state: AtomicU32::new(KeyState::Uninstantiated as u32),
            keyring_keys: RwLock::new(Vec::new()),
            key_type,
        })
    }

    /// Give an uninstantiated key its payload (Linux
    /// __key_instantiate_and_link): under the payload lock (key->sem),
    /// and only from Uninstantiated (EBUSY otherwise), so a revoked or
    /// invalidated key is never brought back
    pub fn instantiate(&self, data: Vec<u8>) -> Result<(), KernelError> {
        let mut payload = self.payload.write();
        if self.state() != KeyState::Uninstantiated {
            return Err(KernelError::Busy);
        }
        *payload = Some(data);
        self.state
            .store(KeyState::Instantiated as u32, Ordering::Release);
        Ok(())
    }

    /// Replace the payload (Linux key_update under key->sem): a key
    /// revoked or invalidated meanwhile is refused under the same lock
    /// (EKEYREVOKED), never revived
    pub fn update(&self, data: Vec<u8>) -> Result<(), KernelError> {
        let mut payload = self.payload.write();
        match self.state() {
            KeyState::Revoked | KeyState::Dead => return Err(KernelError::KeyRevoked),
            _ => {}
        }
        *payload = Some(data);
        self.state
            .store(KeyState::Instantiated as u32, Ordering::Release);
        Ok(())
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

    /// Revoke the key (Linux key_revoke, under key->sem): an
    /// invalidated key stays dead
    pub fn revoke(&self) {
        let _sem = self.payload.write();
        if self.state() != KeyState::Dead {
            self.state
                .store(KeyState::Revoked as u32, Ordering::Release);
        }
    }

    /// Invalidate the key (mark as dead; Linux key_invalidate, under
    /// key->sem)
    pub fn invalidate(&self) {
        let _sem = self.payload.write();
        self.state.store(KeyState::Dead as u32, Ordering::Release);
    }

    /// Check if this key is a keyring
    pub fn is_keyring(&self) -> bool {
        self.type_name == "keyring"
    }

    /// Owner UID
    pub fn uid(&self) -> u32 {
        self.uid.load(Ordering::Relaxed)
    }

    /// Owner GID
    pub fn gid(&self) -> u32 {
        self.gid.load(Ordering::Relaxed)
    }

    /// Change the owner and/or group (Linux keyctl_chown_key, under
    /// key->sem: the payload lock): `allow` decides on the owner and
    /// group as they are in that hold, so a racing chown cannot change
    /// what the decision was about
    pub fn chown(
        &self,
        uid: Option<u32>,
        gid: Option<u32>,
        allow: impl FnOnce(u32, u32) -> Result<(), KernelError>,
    ) -> Result<(), KernelError> {
        let _sem = self.payload.write();
        allow(self.uid(), self.gid())?;
        if let Some(u) = uid {
            self.uid.store(u, Ordering::Relaxed);
        }
        if let Some(g) = gid {
            self.gid.store(g, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Whether `serial` is this keyring or reachable from it through
    /// nested keyrings, at most `depth` levels (Linux
    /// KEYRING_SEARCH_MAX_DEPTH)
    pub fn keyring_reaches(&self, serial: KeySerial, depth: u32) -> bool {
        if self.serial == serial {
            return true;
        }
        if !self.is_keyring() || depth == 0 {
            return false;
        }
        let keys = self.keyring_keys.read().clone();
        keys.into_iter().any(|s| {
            s == serial
                || super::lookup_key(s).is_some_and(|k| k.keyring_reaches(serial, depth - 1))
        })
    }

    /// Get the permission mask
    pub fn perm(&self) -> KeyPerm {
        self.perm.load(Ordering::Relaxed)
    }

    /// Set the permission mask (Linux keyctl_setperm_key, under
    /// key->sem): `allow` decides on the owner as it is in that hold,
    /// so the old owner's change cannot land after a chown
    pub fn setperm(
        &self,
        perm: KeyPerm,
        allow: impl FnOnce(u32) -> Result<(), KernelError>,
    ) -> Result<(), KernelError> {
        let _sem = self.payload.write();
        allow(self.uid())?;
        self.perm.store(perm, Ordering::Relaxed);
        Ok(())
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
            return Err(KernelError::NotDirectory.sysret());
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
            return Err(KernelError::NotDirectory.sysret());
        }

        let mut keys = self.keyring_keys.write();
        if let Some(pos) = keys.iter().position(|&s| s == key_serial) {
            keys.remove(pos);
            Ok(())
        } else {
            Err(KernelError::NotFound.sysret())
        }
    }

    /// Clear all keys from this keyring
    pub fn keyring_clear(&self) -> Result<(), i64> {
        if !self.is_keyring() {
            return Err(KernelError::NotDirectory.sysret());
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

/// Whether the current task may do `needed` (KEY_NEED_* bits) to `key`
/// (Linux key_task_permission): one class of bits by the fsuid, the
/// fsgid or a supplementary group (only if the key grants any group
/// bits), else other's; a key the caller possesses (reachable from its
/// thread, process or session keyring) adds the possessor bits. No root
/// bypass: privileged operations check their own capability.
pub fn check_key_permission(key: &Key, needed: u32) -> bool {
    let c = crate::task::percpu::current_cred();
    let perm = key.perm();
    let gid = key.gid();
    let mut k = if key.uid() == c.fsuid {
        perm >> 16
    } else if gid != u32::MAX && perm & KEY_GRP_ALL != 0 && crate::fs::dac::in_group(&c, gid) {
        perm >> 8
    } else {
        perm
    };
    // The keyring walk only when the class bits are not enough
    if k & needed & 0xff == needed {
        return true;
    }
    if super::keyring::possessed(key, crate::task::percpu::current_tid()) {
        k |= perm >> 24;
    }
    k & needed & 0xff == needed
}

/// Default permissions for new keys
pub const KEY_DEFAULT_PERM: KeyPerm = KEY_POS_ALL | KEY_USR_ALL;

/// Default permissions for new keyrings
pub const KEYRING_DEFAULT_PERM: KeyPerm = KEY_POS_ALL | KEY_USR_ALL | KEY_USR_SEARCH;
