//! Extended attributes (xattr) tests
//!
//! Tests:
//! - Test setxattr and getxattr basic functionality
//! - Test getxattr on non-existent attr returns ENODATA
//! - Test setxattr with XATTR_CREATE flag
//! - Test setxattr with XATTR_REPLACE flag
//! - Test fsetxattr and fgetxattr (fd-based operations)
//! - Test fgetxattr with bad fd returns EBADF
//! - Test listxattr returns list of attributes
//! - Test listxattr with size=0 returns needed size
//! - Test removexattr removes attribute
//! - Test removexattr on non-existent attr returns ENODATA
//! - Test xattr on directories
//! - Test getxattr with buffer too small returns ERANGE

use super::helpers::{print, println, print_num};
use hk_syscall::{
    sys_close, sys_open, sys_setxattr, sys_getxattr, sys_listxattr, sys_removexattr,
    sys_fsetxattr, sys_fgetxattr, sys_mkdir, XATTR_CREATE, XATTR_REPLACE, O_RDWR, O_CREAT,
};

// Error codes
const ENODATA: i64 = -61;
const EEXIST: i64 = -17;
const ERANGE: i64 = -34;
const EBADF: i64 = -9;

/// Run all xattr tests
pub fn run_tests() {
    test_setxattr_getxattr();
    test_getxattr_enodata();
    test_setxattr_create_flag();
    test_setxattr_replace_flag();
    test_fsetxattr_fgetxattr();
    test_fgetxattr_ebadf();
    test_listxattr();
    test_listxattr_size_query();
    test_removexattr();
    test_removexattr_enodata();
    test_xattr_on_directory();
    test_getxattr_erange();
}

/// Test basic setxattr and getxattr
fn test_setxattr_getxattr() {
    let path = b"/tmp/xattr_test_file\0";
    let attr_name = b"user.test\0";
    let attr_value = b"hello world";

    // Create test file
    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT, 0o644);
    if fd < 0 {
        print(b"SETXATTR_GETXATTR:FAIL: open returned ");
        print_num(fd);
        return;
    }
    sys_close(fd as u64);

    // Set attribute
    let ret = sys_setxattr(
        path.as_ptr(),
        attr_name.as_ptr(),
        attr_value.as_ptr(),
        attr_value.len(),
        0,
    );
    if ret != 0 {
        print(b"SETXATTR_GETXATTR:FAIL: setxattr returned ");
        print_num(ret);
        return;
    }

    // Get attribute
    let mut buf = [0u8; 64];
    let ret = sys_getxattr(
        path.as_ptr(),
        attr_name.as_ptr(),
        buf.as_mut_ptr(),
        buf.len(),
    );
    if ret < 0 {
        print(b"SETXATTR_GETXATTR:FAIL: getxattr returned ");
        print_num(ret);
        return;
    }

    // Verify value
    if ret as usize == attr_value.len() && &buf[..attr_value.len()] == attr_value {
        println(b"SETXATTR_GETXATTR:OK");
    } else {
        print(b"SETXATTR_GETXATTR:FAIL: value mismatch, got len ");
        print_num(ret);
    }
}

/// Test getxattr on non-existent attribute returns ENODATA
fn test_getxattr_enodata() {
    let path = b"/tmp/xattr_test_file\0";
    let attr_name = b"user.nonexistent\0";

    let mut buf = [0u8; 64];
    let ret = sys_getxattr(
        path.as_ptr(),
        attr_name.as_ptr(),
        buf.as_mut_ptr(),
        buf.len(),
    );

    if ret == ENODATA {
        println(b"GETXATTR_ENODATA:OK");
    } else {
        print(b"GETXATTR_ENODATA:FAIL: expected -61, got ");
        print_num(ret);
    }
}

/// Test setxattr with XATTR_CREATE flag (fails if attr exists)
fn test_setxattr_create_flag() {
    let path = b"/tmp/xattr_create_test\0";
    let attr_name = b"user.create_test\0";
    let attr_value = b"value1";

    // Create test file
    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT, 0o644);
    if fd < 0 {
        print(b"SETXATTR_CREATE:FAIL: open returned ");
        print_num(fd);
        return;
    }
    sys_close(fd as u64);

    // First set should succeed with XATTR_CREATE
    let ret = sys_setxattr(
        path.as_ptr(),
        attr_name.as_ptr(),
        attr_value.as_ptr(),
        attr_value.len(),
        XATTR_CREATE,
    );
    if ret != 0 {
        print(b"SETXATTR_CREATE:FAIL: first set returned ");
        print_num(ret);
        return;
    }

    // Second set with XATTR_CREATE should fail with EEXIST
    let ret = sys_setxattr(
        path.as_ptr(),
        attr_name.as_ptr(),
        attr_value.as_ptr(),
        attr_value.len(),
        XATTR_CREATE,
    );
    if ret == EEXIST {
        println(b"SETXATTR_CREATE:OK");
    } else {
        print(b"SETXATTR_CREATE:FAIL: expected -17, got ");
        print_num(ret);
    }
}

/// Test setxattr with XATTR_REPLACE flag (fails if attr doesn't exist)
fn test_setxattr_replace_flag() {
    let path = b"/tmp/xattr_replace_test\0";
    let attr_name = b"user.replace_test\0";
    let attr_value = b"value1";

    // Create test file
    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT, 0o644);
    if fd < 0 {
        print(b"SETXATTR_REPLACE:FAIL: open returned ");
        print_num(fd);
        return;
    }
    sys_close(fd as u64);

    // First set with XATTR_REPLACE should fail with ENODATA (attr doesn't exist)
    let ret = sys_setxattr(
        path.as_ptr(),
        attr_name.as_ptr(),
        attr_value.as_ptr(),
        attr_value.len(),
        XATTR_REPLACE,
    );
    if ret == ENODATA {
        println(b"SETXATTR_REPLACE:OK");
    } else {
        print(b"SETXATTR_REPLACE:FAIL: expected -61, got ");
        print_num(ret);
    }
}

/// Test fsetxattr and fgetxattr (fd-based operations)
fn test_fsetxattr_fgetxattr() {
    let path = b"/tmp/fxattr_test\0";
    let attr_name = b"user.ftest\0";
    let attr_value = b"fd-based value";

    // Open test file
    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT, 0o644);
    if fd < 0 {
        print(b"FSETXATTR_FGETXATTR:FAIL: open returned ");
        print_num(fd);
        return;
    }

    // Set attribute via fd
    let ret = sys_fsetxattr(
        fd as i32,
        attr_name.as_ptr(),
        attr_value.as_ptr(),
        attr_value.len(),
        0,
    );
    if ret != 0 {
        print(b"FSETXATTR_FGETXATTR:FAIL: fsetxattr returned ");
        print_num(ret);
        sys_close(fd as u64);
        return;
    }

    // Get attribute via fd
    let mut buf = [0u8; 64];
    let ret = sys_fgetxattr(fd as i32, attr_name.as_ptr(), buf.as_mut_ptr(), buf.len());
    if ret < 0 {
        print(b"FSETXATTR_FGETXATTR:FAIL: fgetxattr returned ");
        print_num(ret);
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);

    // Verify value
    if ret as usize == attr_value.len() && &buf[..attr_value.len()] == attr_value {
        println(b"FSETXATTR_FGETXATTR:OK");
    } else {
        print(b"FSETXATTR_FGETXATTR:FAIL: value mismatch, got len ");
        print_num(ret);
    }
}

/// Test fgetxattr with bad fd returns EBADF
fn test_fgetxattr_ebadf() {
    let attr_name = b"user.test\0";
    let mut buf = [0u8; 64];

    let ret = sys_fgetxattr(9999, attr_name.as_ptr(), buf.as_mut_ptr(), buf.len());
    if ret == EBADF {
        println(b"FGETXATTR_EBADF:OK");
    } else {
        print(b"FGETXATTR_EBADF:FAIL: expected -9, got ");
        print_num(ret);
    }
}

/// Test listxattr returns list of attributes
fn test_listxattr() {
    let path = b"/tmp/listxattr_test\0";
    let attr1_name = b"user.attr1\0";
    let attr2_name = b"user.attr2\0";
    let attr_value = b"value";

    // Create test file
    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT, 0o644);
    if fd < 0 {
        print(b"LISTXATTR:FAIL: open returned ");
        print_num(fd);
        return;
    }
    sys_close(fd as u64);

    // Set two attributes
    sys_setxattr(
        path.as_ptr(),
        attr1_name.as_ptr(),
        attr_value.as_ptr(),
        attr_value.len(),
        0,
    );
    sys_setxattr(
        path.as_ptr(),
        attr2_name.as_ptr(),
        attr_value.as_ptr(),
        attr_value.len(),
        0,
    );

    // List attributes
    let mut buf = [0u8; 256];
    let ret = sys_listxattr(path.as_ptr(), buf.as_mut_ptr(), buf.len());
    if ret < 0 {
        print(b"LISTXATTR:FAIL: listxattr returned ");
        print_num(ret);
        return;
    }

    // Should have at least 2 null-terminated strings totaling at least 22 bytes
    // "user.attr1\0user.attr2\0"
    if ret >= 22 {
        println(b"LISTXATTR:OK");
    } else {
        print(b"LISTXATTR:FAIL: expected >= 22, got ");
        print_num(ret);
    }
}

/// Test listxattr with size=0 returns needed size
fn test_listxattr_size_query() {
    let path = b"/tmp/listxattr_test\0";

    // Query size (size=0, null buffer)
    let ret = sys_listxattr(path.as_ptr(), core::ptr::null_mut(), 0);
    if ret < 0 {
        print(b"LISTXATTR_SIZE_QUERY:FAIL: listxattr returned ");
        print_num(ret);
        return;
    }

    // Should return positive size indicating the list length
    if ret >= 22 {
        println(b"LISTXATTR_SIZE_QUERY:OK");
    } else {
        print(b"LISTXATTR_SIZE_QUERY:FAIL: expected >= 22, got ");
        print_num(ret);
    }
}

/// Test removexattr removes attribute
fn test_removexattr() {
    let path = b"/tmp/removexattr_test\0";
    let attr_name = b"user.removeme\0";
    let attr_value = b"value";

    // Create test file
    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT, 0o644);
    if fd < 0 {
        print(b"REMOVEXATTR:FAIL: open returned ");
        print_num(fd);
        return;
    }
    sys_close(fd as u64);

    // Set attribute
    sys_setxattr(
        path.as_ptr(),
        attr_name.as_ptr(),
        attr_value.as_ptr(),
        attr_value.len(),
        0,
    );

    // Remove attribute
    let ret = sys_removexattr(path.as_ptr(), attr_name.as_ptr());
    if ret != 0 {
        print(b"REMOVEXATTR:FAIL: removexattr returned ");
        print_num(ret);
        return;
    }

    // Verify it's gone (getxattr should return ENODATA)
    let mut buf = [0u8; 64];
    let ret = sys_getxattr(
        path.as_ptr(),
        attr_name.as_ptr(),
        buf.as_mut_ptr(),
        buf.len(),
    );
    if ret == ENODATA {
        println(b"REMOVEXATTR:OK");
    } else {
        print(b"REMOVEXATTR:FAIL: getxattr after remove returned ");
        print_num(ret);
    }
}

/// Test removexattr on non-existent attribute returns ENODATA
fn test_removexattr_enodata() {
    let path = b"/tmp/removexattr_test\0";
    let attr_name = b"user.nonexistent\0";

    let ret = sys_removexattr(path.as_ptr(), attr_name.as_ptr());
    if ret == ENODATA {
        println(b"REMOVEXATTR_ENODATA:OK");
    } else {
        print(b"REMOVEXATTR_ENODATA:FAIL: expected -61, got ");
        print_num(ret);
    }
}

/// Test xattr on directories
fn test_xattr_on_directory() {
    let path = b"/tmp/xattr_dir\0";
    let attr_name = b"user.dirattr\0";
    let attr_value = b"directory xattr";

    // Create test directory
    let ret = sys_mkdir(path.as_ptr(), 0o755);
    if ret != 0 && ret != -17 {
        // -17 = EEXIST, ok if already exists
        print(b"XATTR_DIR:FAIL: mkdir returned ");
        print_num(ret);
        return;
    }

    // Set attribute on directory
    let ret = sys_setxattr(
        path.as_ptr(),
        attr_name.as_ptr(),
        attr_value.as_ptr(),
        attr_value.len(),
        0,
    );
    if ret != 0 {
        print(b"XATTR_DIR:FAIL: setxattr returned ");
        print_num(ret);
        return;
    }

    // Get attribute from directory
    let mut buf = [0u8; 64];
    let ret = sys_getxattr(
        path.as_ptr(),
        attr_name.as_ptr(),
        buf.as_mut_ptr(),
        buf.len(),
    );
    if ret < 0 {
        print(b"XATTR_DIR:FAIL: getxattr returned ");
        print_num(ret);
        return;
    }

    if ret as usize == attr_value.len() && &buf[..attr_value.len()] == attr_value {
        println(b"XATTR_DIR:OK");
    } else {
        print(b"XATTR_DIR:FAIL: value mismatch, got len ");
        print_num(ret);
    }
}

/// Test getxattr with buffer too small returns ERANGE
fn test_getxattr_erange() {
    let path = b"/tmp/xattr_test_file\0";
    let attr_name = b"user.test\0";

    // Get attribute with tiny buffer (smaller than value "hello world")
    let mut buf = [0u8; 3]; // Too small
    let ret = sys_getxattr(path.as_ptr(), attr_name.as_ptr(), buf.as_mut_ptr(), buf.len());

    if ret == ERANGE {
        println(b"GETXATTR_ERANGE:OK");
    } else {
        print(b"GETXATTR_ERANGE:FAIL: expected -34, got ");
        print_num(ret);
    }
}
