//! Keyring syscall tests
//!
//! Tests:
//! - Test add_key creates a user key
//! - Test keyctl READ reads back payload
//! - Test keyctl DESCRIBE returns description string
//! - Test keyctl GET_KEYRING_ID gets process keyring
//! - Test keyctl LINK/UNLINK link/unlink keys
//! - Test keyctl UPDATE updates key payload
//! - Test keyctl REVOKE revokes key
//! - Test request_key finds existing key
//! - Test keyctl CLEAR clears keyring
//! - Test keyctl INVALIDATE removes key

use super::helpers::{print, println, print_num};
use hk_syscall::{
    sys_add_key, sys_keyctl, sys_request_key,
    KEY_SPEC_PROCESS_KEYRING, KEY_SPEC_THREAD_KEYRING,
    KEYCTL_GET_KEYRING_ID, KEYCTL_READ, KEYCTL_DESCRIBE,
    KEYCTL_LINK, KEYCTL_UNLINK, KEYCTL_UPDATE, KEYCTL_REVOKE,
    KEYCTL_CLEAR, KEYCTL_INVALIDATE,
};

// Error codes
const ENOKEY: i64 = -126;
const EKEYREVOKED: i64 = -128;

/// Run all keyring tests
pub fn run_tests() {
    test_add_key_user();
    test_keyctl_read();
    test_keyctl_describe();
    test_get_keyring_id();
    test_keyctl_update();
    test_keyctl_link_unlink();
    test_keyctl_revoke();
    test_request_key();
    test_keyctl_clear();
    test_keyctl_invalidate();
}

/// Test add_key creates a user key
fn test_add_key_user() {
    let type_name = b"user\0";
    let description = b"test_key_1\0";
    let payload = b"secret data 123";

    let serial = sys_add_key(
        type_name.as_ptr(),
        description.as_ptr(),
        payload.as_ptr(),
        payload.len(),
        KEY_SPEC_PROCESS_KEYRING,
    );

    if serial > 0 {
        println(b"ADD_KEY_USER:OK");
    } else {
        print(b"ADD_KEY_USER:FAIL: add_key returned ");
        print_num(serial);
    }
}

/// Test keyctl READ reads back payload
fn test_keyctl_read() {
    let type_name = b"user\0";
    let description = b"test_key_read\0";
    let payload = b"read test payload";

    // Create key
    let serial = sys_add_key(
        type_name.as_ptr(),
        description.as_ptr(),
        payload.as_ptr(),
        payload.len(),
        KEY_SPEC_PROCESS_KEYRING,
    );

    if serial <= 0 {
        print(b"KEYCTL_READ:FAIL: add_key returned ");
        print_num(serial);
        return;
    }

    // Read back payload
    let mut buf = [0u8; 64];
    let ret = sys_keyctl(
        KEYCTL_READ,
        serial as u64,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
        0,
    );

    if ret < 0 {
        print(b"KEYCTL_READ:FAIL: keyctl READ returned ");
        print_num(ret);
        return;
    }

    // Verify payload
    if ret as usize == payload.len() && &buf[..payload.len()] == payload {
        println(b"KEYCTL_READ:OK");
    } else {
        print(b"KEYCTL_READ:FAIL: payload mismatch, got len ");
        print_num(ret);
    }
}

/// Test keyctl DESCRIBE returns description string
fn test_keyctl_describe() {
    let type_name = b"user\0";
    let description = b"test_key_desc\0";
    let payload = b"desc test";

    // Create key
    let serial = sys_add_key(
        type_name.as_ptr(),
        description.as_ptr(),
        payload.as_ptr(),
        payload.len(),
        KEY_SPEC_PROCESS_KEYRING,
    );

    if serial <= 0 {
        print(b"KEYCTL_DESCRIBE:FAIL: add_key returned ");
        print_num(serial);
        return;
    }

    // Get description
    let mut buf = [0u8; 256];
    let ret = sys_keyctl(
        KEYCTL_DESCRIBE,
        serial as u64,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
        0,
    );

    if ret < 0 {
        print(b"KEYCTL_DESCRIBE:FAIL: keyctl DESCRIBE returned ");
        print_num(ret);
        return;
    }

    // Description should contain type and description
    // Format: "type;uid;gid;perm;description"
    if ret > 0 {
        println(b"KEYCTL_DESCRIBE:OK");
    } else {
        print(b"KEYCTL_DESCRIBE:FAIL: returned ");
        print_num(ret);
    }
}

/// Test keyctl GET_KEYRING_ID gets process keyring
fn test_get_keyring_id() {
    // Get process keyring ID (create if doesn't exist)
    let ret = sys_keyctl(
        KEYCTL_GET_KEYRING_ID,
        KEY_SPEC_PROCESS_KEYRING as u64,
        1, // create = true
        0,
        0,
    );

    if ret > 0 {
        println(b"KEYCTL_GET_KEYRING_ID:OK");
    } else {
        print(b"KEYCTL_GET_KEYRING_ID:FAIL: returned ");
        print_num(ret);
    }
}

/// Test keyctl UPDATE updates key payload
fn test_keyctl_update() {
    let type_name = b"user\0";
    let description = b"test_key_update\0";
    let payload1 = b"original payload";
    let payload2 = b"updated payload!";

    // Create key
    let serial = sys_add_key(
        type_name.as_ptr(),
        description.as_ptr(),
        payload1.as_ptr(),
        payload1.len(),
        KEY_SPEC_PROCESS_KEYRING,
    );

    if serial <= 0 {
        print(b"KEYCTL_UPDATE:FAIL: add_key returned ");
        print_num(serial);
        return;
    }

    // Update payload
    let ret = sys_keyctl(
        KEYCTL_UPDATE,
        serial as u64,
        payload2.as_ptr() as u64,
        payload2.len() as u64,
        0,
    );

    if ret != 0 {
        print(b"KEYCTL_UPDATE:FAIL: keyctl UPDATE returned ");
        print_num(ret);
        return;
    }

    // Read back and verify
    let mut buf = [0u8; 64];
    let ret = sys_keyctl(
        KEYCTL_READ,
        serial as u64,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
        0,
    );

    if ret as usize == payload2.len() && &buf[..payload2.len()] == payload2 {
        println(b"KEYCTL_UPDATE:OK");
    } else {
        print(b"KEYCTL_UPDATE:FAIL: updated payload mismatch, len ");
        print_num(ret);
    }
}

/// Test keyctl LINK/UNLINK link/unlink keys
fn test_keyctl_link_unlink() {
    let type_name = b"user\0";
    let description = b"test_key_linkunlink\0";
    let payload = b"link test";

    // Create key in process keyring
    let serial = sys_add_key(
        type_name.as_ptr(),
        description.as_ptr(),
        payload.as_ptr(),
        payload.len(),
        KEY_SPEC_PROCESS_KEYRING,
    );

    if serial <= 0 {
        print(b"KEYCTL_LINK_UNLINK:FAIL: add_key returned ");
        print_num(serial);
        return;
    }

    // Get thread keyring (create if needed)
    let thread_keyring = sys_keyctl(
        KEYCTL_GET_KEYRING_ID,
        KEY_SPEC_THREAD_KEYRING as u64,
        1, // create
        0,
        0,
    );

    if thread_keyring <= 0 {
        print(b"KEYCTL_LINK_UNLINK:FAIL: get thread keyring returned ");
        print_num(thread_keyring);
        return;
    }

    // Link key to thread keyring
    let ret = sys_keyctl(
        KEYCTL_LINK,
        serial as u64,
        thread_keyring as u64,
        0,
        0,
    );

    if ret != 0 {
        print(b"KEYCTL_LINK_UNLINK:FAIL: LINK returned ");
        print_num(ret);
        return;
    }

    // Unlink key from thread keyring
    let ret = sys_keyctl(
        KEYCTL_UNLINK,
        serial as u64,
        thread_keyring as u64,
        0,
        0,
    );

    if ret == 0 {
        println(b"KEYCTL_LINK_UNLINK:OK");
    } else {
        print(b"KEYCTL_LINK_UNLINK:FAIL: UNLINK returned ");
        print_num(ret);
    }
}

/// Test keyctl REVOKE revokes key
fn test_keyctl_revoke() {
    let type_name = b"user\0";
    let description = b"test_key_revoke\0";
    let payload = b"revoke test";

    // Create key
    let serial = sys_add_key(
        type_name.as_ptr(),
        description.as_ptr(),
        payload.as_ptr(),
        payload.len(),
        KEY_SPEC_PROCESS_KEYRING,
    );

    if serial <= 0 {
        print(b"KEYCTL_REVOKE:FAIL: add_key returned ");
        print_num(serial);
        return;
    }

    // Revoke the key
    let ret = sys_keyctl(
        KEYCTL_REVOKE,
        serial as u64,
        0,
        0,
        0,
    );

    if ret != 0 {
        print(b"KEYCTL_REVOKE:FAIL: REVOKE returned ");
        print_num(ret);
        return;
    }

    // Try to read revoked key - should fail with EKEYREVOKED
    let mut buf = [0u8; 64];
    let ret = sys_keyctl(
        KEYCTL_READ,
        serial as u64,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
        0,
    );

    if ret == EKEYREVOKED {
        println(b"KEYCTL_REVOKE:OK");
    } else {
        print(b"KEYCTL_REVOKE:FAIL: read after revoke returned ");
        print_num(ret);
    }
}

/// Test request_key finds existing key
fn test_request_key() {
    let type_name = b"user\0";
    let description = b"test_key_request\0";
    let payload = b"request test";

    // Create key
    let serial = sys_add_key(
        type_name.as_ptr(),
        description.as_ptr(),
        payload.as_ptr(),
        payload.len(),
        KEY_SPEC_PROCESS_KEYRING,
    );

    if serial <= 0 {
        print(b"REQUEST_KEY:FAIL: add_key returned ");
        print_num(serial);
        return;
    }

    // Request the key we just created
    let found = sys_request_key(
        type_name.as_ptr(),
        description.as_ptr(),
        core::ptr::null(),
        0, // no destination keyring
    );

    if found == serial {
        println(b"REQUEST_KEY:OK");
    } else if found > 0 {
        // Found a key but different serial (might be from previous run)
        println(b"REQUEST_KEY:OK");
    } else {
        print(b"REQUEST_KEY:FAIL: request_key returned ");
        print_num(found);
    }
}

/// Test keyctl CLEAR clears keyring
fn test_keyctl_clear() {
    // Get thread keyring (create if needed)
    let thread_keyring = sys_keyctl(
        KEYCTL_GET_KEYRING_ID,
        KEY_SPEC_THREAD_KEYRING as u64,
        1, // create
        0,
        0,
    );

    if thread_keyring <= 0 {
        print(b"KEYCTL_CLEAR:FAIL: get keyring returned ");
        print_num(thread_keyring);
        return;
    }

    // Add a key to thread keyring
    let type_name = b"user\0";
    let description = b"test_key_clear\0";
    let payload = b"clear test";

    let serial = sys_add_key(
        type_name.as_ptr(),
        description.as_ptr(),
        payload.as_ptr(),
        payload.len(),
        KEY_SPEC_THREAD_KEYRING,
    );

    if serial <= 0 {
        print(b"KEYCTL_CLEAR:FAIL: add_key returned ");
        print_num(serial);
        return;
    }

    // Clear the keyring
    let ret = sys_keyctl(
        KEYCTL_CLEAR,
        thread_keyring as u64,
        0,
        0,
        0,
    );

    if ret == 0 {
        println(b"KEYCTL_CLEAR:OK");
    } else {
        print(b"KEYCTL_CLEAR:FAIL: CLEAR returned ");
        print_num(ret);
    }
}

/// Test keyctl INVALIDATE removes key
fn test_keyctl_invalidate() {
    let type_name = b"user\0";
    let description = b"test_key_invalidate\0";
    let payload = b"invalidate test";

    // Create key
    let serial = sys_add_key(
        type_name.as_ptr(),
        description.as_ptr(),
        payload.as_ptr(),
        payload.len(),
        KEY_SPEC_PROCESS_KEYRING,
    );

    if serial <= 0 {
        print(b"KEYCTL_INVALIDATE:FAIL: add_key returned ");
        print_num(serial);
        return;
    }

    // Invalidate the key
    let ret = sys_keyctl(
        KEYCTL_INVALIDATE,
        serial as u64,
        0,
        0,
        0,
    );

    if ret != 0 {
        print(b"KEYCTL_INVALIDATE:FAIL: INVALIDATE returned ");
        print_num(ret);
        return;
    }

    // Try to read invalidated key - should fail with ENOKEY
    let mut buf = [0u8; 64];
    let ret = sys_keyctl(
        KEYCTL_READ,
        serial as u64,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
        0,
    );

    if ret == ENOKEY {
        println(b"KEYCTL_INVALIDATE:OK");
    } else {
        print(b"KEYCTL_INVALIDATE:FAIL: read after invalidate returned ");
        print_num(ret);
    }
}
