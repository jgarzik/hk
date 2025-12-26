//! Key type trait and built-in key types
//!
//! This module defines the KeyType trait for pluggable key types and provides
//! implementations for the built-in "user" and "keyring" key types.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;

use super::key::Key;
use super::{EKEYREVOKED, EOPNOTSUPP};

/// Trait for pluggable key types
///
/// Each key type defines how payloads are stored, read, and updated.
pub trait KeyType: Send + Sync {
    /// Get the type name (e.g., "user", "keyring")
    fn name(&self) -> &'static str;

    /// Instantiate a key with the given payload
    fn instantiate(&self, key: &Key, data: &[u8]) -> Result<(), i64>;

    /// Read the key's payload into the buffer
    ///
    /// Returns the total payload size (may be larger than buffer if truncated)
    fn read(&self, key: &Key, buffer: &mut [u8]) -> Result<usize, i64>;

    /// Update the key's payload
    fn update(&self, key: &Key, data: &[u8]) -> Result<(), i64>;

    /// Get the key's description string for KEYCTL_DESCRIBE
    ///
    /// Format: "type;uid;gid;perm;description"
    fn describe(&self, key: &Key) -> String;

    /// Called when the key is being destroyed
    fn destroy(&self, _key: &Key) {}
}

// =============================================================================
// Built-in "user" key type
// =============================================================================

/// The "user" key type stores arbitrary binary data
///
/// This is the most common key type, used for storing passwords, tokens,
/// encryption keys, and other security-related data.
pub struct UserKeyType;

impl KeyType for UserKeyType {
    fn name(&self) -> &'static str {
        "user"
    }

    fn instantiate(&self, key: &Key, data: &[u8]) -> Result<(), i64> {
        key.set_payload(data.to_vec());
        Ok(())
    }

    fn read(&self, key: &Key, buffer: &mut [u8]) -> Result<usize, i64> {
        if key.is_revoked() {
            return Err(EKEYREVOKED);
        }

        if let Some(payload) = key.read_payload() {
            let len = core::cmp::min(buffer.len(), payload.len());
            buffer[..len].copy_from_slice(&payload[..len]);
            Ok(payload.len())
        } else {
            Ok(0)
        }
    }

    fn update(&self, key: &Key, data: &[u8]) -> Result<(), i64> {
        if key.is_revoked() {
            return Err(EKEYREVOKED);
        }
        key.set_payload(data.to_vec());
        Ok(())
    }

    fn describe(&self, key: &Key) -> String {
        format!(
            "user;{};{};{:08x};{}",
            key.uid,
            key.gid,
            key.perm(),
            key.description
        )
    }
}

/// Get a reference to the "user" key type
pub fn user_key_type() -> Arc<dyn KeyType> {
    Arc::new(UserKeyType)
}

// =============================================================================
// Built-in "keyring" key type
// =============================================================================

/// The "keyring" key type is a container for other keys
///
/// Keyrings can contain links to other keys (including other keyrings),
/// allowing hierarchical organization of keys.
pub struct KeyringKeyType;

impl KeyType for KeyringKeyType {
    fn name(&self) -> &'static str {
        "keyring"
    }

    fn instantiate(&self, _key: &Key, _data: &[u8]) -> Result<(), i64> {
        // Keyrings don't have payloads - just mark as instantiated
        // The key's state is set by the Key::set_payload or directly
        Ok(())
    }

    fn read(&self, key: &Key, buffer: &mut [u8]) -> Result<usize, i64> {
        if key.is_revoked() {
            return Err(EKEYREVOKED);
        }

        // Return list of key serial numbers as i32 array
        let keys = key.keyring_keys();
        let needed = keys.len() * 4; // 4 bytes per i32 serial

        if !buffer.is_empty() && buffer.len() >= needed {
            for (i, &serial) in keys.iter().enumerate() {
                let bytes = serial.to_ne_bytes();
                buffer[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
            }
        }

        Ok(needed)
    }

    fn update(&self, _key: &Key, _data: &[u8]) -> Result<(), i64> {
        // Keyrings cannot be updated via KEYCTL_UPDATE
        Err(EOPNOTSUPP)
    }

    fn describe(&self, key: &Key) -> String {
        format!(
            "keyring;{};{};{:08x};{}",
            key.uid,
            key.gid,
            key.perm(),
            key.description
        )
    }
}

/// Get a reference to the "keyring" key type
pub fn keyring_key_type() -> Arc<dyn KeyType> {
    Arc::new(KeyringKeyType)
}

// =============================================================================
// Key type registry
// =============================================================================

/// Look up a key type by name
pub fn get_key_type(name: &str) -> Option<Arc<dyn KeyType>> {
    match name {
        "user" => Some(user_key_type()),
        "keyring" => Some(keyring_key_type()),
        _ => None,
    }
}
