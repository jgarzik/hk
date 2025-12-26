//! Sync tests
//!
//! Tests:
//! - Test 63: sync() - synchronize all filesystems
//! - Test 64: fsync() - synchronize a file's state to storage
//! - Test 65: fsync() on invalid fd
//! - Test 66: fdatasync() - synchronize file data to storage
//! - Test 67: fdatasync() on invalid fd
//! - Test 68: syncfs() - synchronize filesystem containing a file
//! - Test 69: syncfs() on invalid fd
//! - Test: membarrier() - memory barrier syscall
//! - Test: readahead() - file readahead syscall

use super::helpers::{print, println, print_num};
use hk_syscall::{
    sys_close, sys_fdatasync, sys_fsync, sys_membarrier, sys_open, sys_readahead, sys_sync,
    sys_syncfs, sys_unlink, sys_write, MEMBARRIER_CMD_GLOBAL, MEMBARRIER_CMD_PRIVATE_EXPEDITED,
    MEMBARRIER_CMD_QUERY, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, O_CREAT, O_RDONLY, O_WRONLY,
};

/// Run all sync tests
pub fn run_tests() {
    test_sync();
    test_fsync();
    test_fsync_ebadf();
    test_fdatasync();
    test_fdatasync_ebadf();
    test_syncfs();
    test_syncfs_ebadf();
    test_membarrier();
    test_readahead();
}

/// Test 63: sync() - synchronize all filesystems
fn test_sync() {

    let ret = sys_sync();
    if ret == 0 {
        println(b"SYNC:OK");
    } else {
        print(b"SYNC:FAIL: expected 0, got ");
        print_num(ret);
    }
}

/// Test 64: fsync() - synchronize a file's state to storage
fn test_fsync() {

    let fsync_file = b"/fsync_test.txt\0";
    let fd = sys_open(fsync_file.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    if fd < 0 {
        print(b"FSYNC:FAIL: open returned ");
        print_num(fd);
    } else {
        // Write some data
        sys_write(fd as u64, b"fsync test data".as_ptr(), 15);

        // Call fsync on the fd
        let ret = sys_fsync(fd as i32);
        if ret == 0 {
            println(b"FSYNC:OK");
        } else {
            print(b"FSYNC:FAIL: expected 0, got ");
            print_num(ret);
        }
        sys_close(fd as u64);
        sys_unlink(fsync_file.as_ptr());
    }
}

/// Test 65: fsync() on invalid fd should fail with EBADF
fn test_fsync_ebadf() {

    let ret = sys_fsync(999);
    if ret == -9 {
        // EBADF
        println(b"FSYNC_EBADF:OK");
    } else {
        print(b"FSYNC_EBADF:FAIL: expected -9 (EBADF), got ");
        print_num(ret);
    }
}

/// Test 66: fdatasync() - synchronize file data to storage
fn test_fdatasync() {

    let fdatasync_file = b"/fdatasync_test.txt\0";
    let fd = sys_open(fdatasync_file.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    if fd < 0 {
        print(b"FDATASYNC:FAIL: open returned ");
        print_num(fd);
    } else {
        // Write some data
        sys_write(fd as u64, b"fdatasync test data".as_ptr(), 19);

        // Call fdatasync on the fd
        let ret = sys_fdatasync(fd as i32);
        if ret == 0 {
            println(b"FDATASYNC:OK");
        } else {
            print(b"FDATASYNC:FAIL: expected 0, got ");
            print_num(ret);
        }
        sys_close(fd as u64);
        sys_unlink(fdatasync_file.as_ptr());
    }
}

/// Test 67: fdatasync() on invalid fd should fail with EBADF
fn test_fdatasync_ebadf() {

    let ret = sys_fdatasync(999);
    if ret == -9 {
        // EBADF
        println(b"FDATASYNC_EBADF:OK");
    } else {
        print(b"FDATASYNC_EBADF:FAIL: expected -9 (EBADF), got ");
        print_num(ret);
    }
}

/// Test 68: syncfs() - synchronize filesystem containing a file
fn test_syncfs() {

    let syncfs_file = b"/syncfs_test.txt\0";
    let fd = sys_open(syncfs_file.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    if fd < 0 {
        print(b"SYNCFS:FAIL: open returned ");
        print_num(fd);
    } else {
        // Write some data
        sys_write(fd as u64, b"syncfs test data".as_ptr(), 16);

        // Call syncfs on the fd
        let ret = sys_syncfs(fd as i32);
        if ret == 0 {
            println(b"SYNCFS:OK");
        } else {
            print(b"SYNCFS:FAIL: expected 0, got ");
            print_num(ret);
        }
        sys_close(fd as u64);
        sys_unlink(syncfs_file.as_ptr());
    }
}

/// Test 69: syncfs() on invalid fd should fail with EBADF
fn test_syncfs_ebadf() {

    let ret = sys_syncfs(999);
    if ret == -9 {
        // EBADF
        println(b"SYNCFS_EBADF:OK");
    } else {
        print(b"SYNCFS_EBADF:FAIL: expected -9 (EBADF), got ");
        print_num(ret);
    }
}

/// Test: membarrier() - memory barrier syscall
fn test_membarrier() {
    // Query supported commands
    let ret = sys_membarrier(MEMBARRIER_CMD_QUERY, 0, 0);
    if ret < 0 {
        print(b"MEMBARRIER:FAIL: QUERY returned error ");
        print_num(ret);
        return;
    }

    // Check that GLOBAL and PRIVATE_EXPEDITED are supported
    let supported = ret as i32;
    if supported & MEMBARRIER_CMD_GLOBAL == 0 {
        println(b"MEMBARRIER:FAIL: CMD_GLOBAL not supported");
        return;
    }
    if supported & MEMBARRIER_CMD_PRIVATE_EXPEDITED == 0 {
        println(b"MEMBARRIER:FAIL: CMD_PRIVATE_EXPEDITED not supported");
        return;
    }

    // Register for private expedited
    let ret = sys_membarrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0, 0);
    if ret != 0 {
        print(b"MEMBARRIER:FAIL: REGISTER_PRIVATE_EXPEDITED returned ");
        print_num(ret);
        return;
    }

    // Execute a global barrier
    let ret = sys_membarrier(MEMBARRIER_CMD_GLOBAL, 0, 0);
    if ret != 0 {
        print(b"MEMBARRIER:FAIL: CMD_GLOBAL returned ");
        print_num(ret);
        return;
    }

    // Execute a private expedited barrier
    let ret = sys_membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0);
    if ret != 0 {
        print(b"MEMBARRIER:FAIL: CMD_PRIVATE_EXPEDITED returned ");
        print_num(ret);
        return;
    }

    println(b"MEMBARRIER:OK");
}

/// Test: readahead() - file readahead syscall
fn test_readahead() {
    // Create a test file first
    let readahead_file = b"/readahead_test.txt\0";
    let fd = sys_open(readahead_file.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    if fd < 0 {
        print(b"READAHEAD:FAIL: open for write returned ");
        print_num(fd);
        return;
    }

    // Write some data
    let test_data = b"This is test data for readahead syscall testing.";
    sys_write(fd as u64, test_data.as_ptr(), test_data.len() as u64);
    sys_close(fd as u64);

    // Reopen for reading
    let fd = sys_open(readahead_file.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        print(b"READAHEAD:FAIL: open for read returned ");
        print_num(fd);
        sys_unlink(readahead_file.as_ptr());
        return;
    }

    // Call readahead - should succeed (hint to the kernel)
    let ret = sys_readahead(fd as i32, 0, 4096);
    if ret != 0 {
        print(b"READAHEAD:FAIL: readahead returned ");
        print_num(ret);
        sys_close(fd as u64);
        sys_unlink(readahead_file.as_ptr());
        return;
    }

    // Test readahead on invalid fd - should fail
    let ret = sys_readahead(999, 0, 4096);
    if ret != -9 {
        // EBADF
        print(b"READAHEAD:FAIL: expected -9 for bad fd, got ");
        print_num(ret);
        sys_close(fd as u64);
        sys_unlink(readahead_file.as_ptr());
        return;
    }

    sys_close(fd as u64);
    sys_unlink(readahead_file.as_ptr());
    println(b"READAHEAD:OK");
}
