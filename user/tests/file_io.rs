//! File I/O tests
//!
//! Tests:
//! - Test 22: writev() - gather write to stdout
//! - Test 23: readv() - scatter read from file
//! - Test 24: writev() with zero-length iovec
//! - Test 25: readv() with invalid iovcnt
//! - Test 26: pread64() - positioned read without changing file position
//! - Test 27: pwrite64() - positioned write without changing file position
//! - Test 28: preadv() - positioned scatter read without changing file position
//! - Test 29: pwritev() - positioned gather write without changing file position
//! - Test 30: fcntl(F_DUPFD) - duplicate fd to lowest available >= arg
//! - Test 31: fcntl(F_GETFD/F_SETFD) - get/set fd flags (FD_CLOEXEC)
//! - Test 32: fcntl(F_DUPFD_CLOEXEC) - duplicate with cloexec
//! - Test 33: fcntl() with invalid fd returns -EBADF
//! - Test 34: getrandom() - get random bytes
//! - Test 35: getrandom() with invalid flags returns -EINVAL
//! - Test 36: ioctl() with invalid fd returns -EBADF
//! - Test 37: ioctl() on regular file returns -ENOTTY

use super::helpers::{print, println, print_num};
use crate::syscall::{
    sys_close, sys_fcntl, sys_getrandom, sys_ioctl, sys_lseek, sys_open, sys_pread64, sys_preadv,
    sys_pwrite64, sys_pwritev, sys_read, sys_readv, sys_write, sys_writev, IoVec, O_CREAT,
    O_RDONLY, O_RDWR, O_TRUNC,
};

// fcntl commands
const F_DUPFD: i32 = 0;
const F_GETFD: i32 = 1;
const F_SETFD: i32 = 2;
const F_DUPFD_CLOEXEC: i32 = 1030;

// fd flags
const FD_CLOEXEC: u64 = 1;

/// Run all file I/O tests
pub fn run_tests() {
    println(b"FILE_IO_TESTS_START");
    test_writev();
    test_readv();
    test_writev_zero_len();
    test_readv_invalid_iovcnt();
    test_pread64();
    test_pwrite64();
    test_preadv();
    test_pwritev();
    test_fcntl_dupfd();
    test_fcntl_cloexec();
    test_fcntl_dupfd_cloexec();
    test_fcntl_ebadf();
    test_getrandom();
    test_getrandom_einval();
    test_ioctl_ebadf();
    test_ioctl_enotty();
}

/// Test 22: writev() - gather write to stdout
fn test_writev() {

    let msg1 = b"Hello, ";
    let msg2 = b"writev ";
    let msg3 = b"world!\n";

    let iov: [IoVec; 3] = [
        IoVec { iov_base: msg1.as_ptr(), iov_len: msg1.len() },
        IoVec { iov_base: msg2.as_ptr(), iov_len: msg2.len() },
        IoVec { iov_base: msg3.as_ptr(), iov_len: msg3.len() },
    ];

    let ret = sys_writev(1, iov.as_ptr(), 3);
    let expected_len = (msg1.len() + msg2.len() + msg3.len()) as i64;
    if ret == expected_len {
        println(b"WRITEV:OK");
    } else {
        print(b"WRITEV:FAIL: expected ");
        print_num(expected_len);
        print(b", got ");
        print_num(ret);
    }
}

/// Test 23: readv() - scatter read from file
fn test_readv() {

    let path = b"/test.txt\0";
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        print(b"ERROR: open(/test.txt) failed: ");
        print_num(fd);
        println(b"READV:FAIL");
    } else {
        let mut buf1 = [0u8; 5];
        let mut buf2 = [0u8; 6];
        let mut buf3 = [0u8; 20];

        let iov_read: [IoVec; 3] = [
            IoVec { iov_base: buf1.as_mut_ptr(), iov_len: buf1.len() },
            IoVec { iov_base: buf2.as_mut_ptr(), iov_len: buf2.len() },
            IoVec { iov_base: buf3.as_mut_ptr(), iov_len: buf3.len() },
        ];

        let ret = sys_readv(fd as u64, iov_read.as_ptr(), 3);
        if ret > 0 {
            print(b"readv() read ");
            print_num(ret);
            println(b" bytes total");

            // Print what we read (first buffer should have "Hello")
            print(b"buf1: ");
            sys_write(1, buf1.as_ptr(), 5);
            print(b"buf2: ");
            sys_write(1, buf2.as_ptr(), 6);

            // Check that we read the expected content
            // /test.txt contains "Hello from ramfs!" (17 bytes, no trailing newline)
            if ret == 17 && buf1[0] == b'H' && buf1[4] == b'o' {
                println(b"READV:OK");
            } else {
                println(b"READV:FAIL");
            }
        } else {
            print(b"READV:FAIL: readv returned ");
            print_num(ret);
        }
        sys_close(fd as u64);
    }
}

/// Test 24: writev() with zero-length iovec
fn test_writev_zero_len() {

    let msg_before = b"Before";
    let msg_after = b"After\n";

    let iov_zero: [IoVec; 3] = [
        IoVec { iov_base: msg_before.as_ptr(), iov_len: msg_before.len() },
        IoVec { iov_base: core::ptr::null(), iov_len: 0 },  // zero-length
        IoVec { iov_base: msg_after.as_ptr(), iov_len: msg_after.len() },
    ];

    let ret = sys_writev(1, iov_zero.as_ptr(), 3);
    let expected = (msg_before.len() + msg_after.len()) as i64;
    if ret == expected {
        println(b"WRITEV_ZERO_LEN:OK");
    } else {
        print(b"WRITEV_ZERO_LEN:FAIL: expected ");
        print_num(expected);
        print(b", got ");
        print_num(ret);
    }
}

/// Test 25: readv() with invalid iovcnt
fn test_readv_invalid_iovcnt() {

    let ret_neg = sys_readv(0, core::ptr::null(), (-1i64) as u64);
    if ret_neg == -22 {  // EINVAL
        println(b"READV_INVALID_IOVCNT:OK");
    } else {
        print(b"READV_INVALID_IOVCNT:FAIL: expected -22, got ");
        print_num(ret_neg);
    }
}

/// Test 26: pread64() - positioned read without changing file position
fn test_pread64() {
    // Open /test.txt which contains "Hello from ramfs!" (17 bytes)
    let path = b"/test.txt\0";
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        print(b"PREAD64:FAIL: open failed: ");
        print_num(fd);
        println(b"");
        return;
    }

    // Read first 5 bytes with normal read() to set position
    let mut buf1 = [0u8; 5];
    let ret = sys_read(fd as u64, buf1.as_mut_ptr(), 5);
    if ret != 5 {
        print(b"PREAD64:FAIL: initial read failed: ");
        print_num(ret);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Current position should be 5, verify with lseek
    let pos1 = sys_lseek(fd as i32, 0, 1); // SEEK_CUR=1
    if pos1 != 5 {
        print(b"PREAD64:FAIL: position after read should be 5, got ");
        print_num(pos1);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Use pread64 to read "from" starting at offset 6 (after "Hello ")
    let mut buf2 = [0u8; 4];
    let pret = sys_pread64(fd as i32, buf2.as_mut_ptr(), 4, 6);
    if pret != 4 {
        print(b"PREAD64:FAIL: pread64 returned ");
        print_num(pret);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Verify we read "from"
    if buf2[0] != b'f' || buf2[1] != b'r' || buf2[2] != b'o' || buf2[3] != b'm' {
        print(b"PREAD64:FAIL: expected 'from', got ");
        sys_write(1, buf2.as_ptr(), 4);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Verify file position is UNCHANGED (still 5, not 10)
    let pos2 = sys_lseek(fd as i32, 0, 1); // SEEK_CUR=1
    if pos2 != 5 {
        print(b"PREAD64:FAIL: position should still be 5 after pread64, got ");
        print_num(pos2);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    println(b"PREAD64:OK");
}

/// Test 27: pwrite64() - positioned write without changing file position
fn test_pwrite64() {
    // Create a test file in root (ramfs)
    let path = b"/pwrite_test.txt\0";
    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    if fd < 0 {
        print(b"PWRITE64:FAIL: open failed: ");
        print_num(fd);
        println(b"");
        return;
    }

    // Write initial content: "AAAABBBBCCCC" (12 bytes)
    let initial = b"AAAABBBBCCCC";
    let ret = sys_write(fd as u64, initial.as_ptr(), 12);
    if ret != 12 {
        print(b"PWRITE64:FAIL: initial write failed: ");
        print_num(ret);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Position is now 12, seek to position 4
    let _ = sys_lseek(fd as i32, 4, 0); // SEEK_SET=0

    // Current position should be 4
    let pos1 = sys_lseek(fd as i32, 0, 1); // SEEK_CUR=1
    if pos1 != 4 {
        print(b"PWRITE64:FAIL: position should be 4, got ");
        print_num(pos1);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Use pwrite64 to write "XXXX" at offset 0 (replacing "AAAA")
    let new_data = b"XXXX";
    let pret = sys_pwrite64(fd as i32, new_data.as_ptr(), 4, 0);
    if pret != 4 {
        print(b"PWRITE64:FAIL: pwrite64 returned ");
        print_num(pret);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Verify file position is UNCHANGED (still 4)
    let pos2 = sys_lseek(fd as i32, 0, 1); // SEEK_CUR=1
    if pos2 != 4 {
        print(b"PWRITE64:FAIL: position should still be 4 after pwrite64, got ");
        print_num(pos2);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Verify the file content is now "XXXXBBBBCCCC"
    let _ = sys_lseek(fd as i32, 0, 0); // SEEK_SET to beginning
    let mut verify = [0u8; 12];
    let vret = sys_read(fd as u64, verify.as_mut_ptr(), 12);
    if vret != 12 {
        print(b"PWRITE64:FAIL: verify read failed: ");
        print_num(vret);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Check content
    if verify[0] != b'X' || verify[1] != b'X' || verify[2] != b'X' || verify[3] != b'X' {
        print(b"PWRITE64:FAIL: expected 'XXXX' at start, got ");
        sys_write(1, verify.as_ptr(), 4);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    if verify[4] != b'B' || verify[8] != b'C' {
        print(b"PWRITE64:FAIL: rest of file corrupted: ");
        sys_write(1, verify.as_ptr(), 12);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    println(b"PWRITE64:OK");
}

/// Test 28: preadv() - positioned scatter read without changing file position
fn test_preadv() {
    // Open /test.txt which contains "Hello from ramfs!" (17 bytes)
    let path = b"/test.txt\0";
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        print(b"PREADV:FAIL: open failed: ");
        print_num(fd);
        println(b"");
        return;
    }

    // Read first 5 bytes with normal read() to set position
    let mut initial_buf = [0u8; 5];
    let ret = sys_read(fd as u64, initial_buf.as_mut_ptr(), 5);
    if ret != 5 {
        print(b"PREADV:FAIL: initial read failed: ");
        print_num(ret);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Current position should be 5
    let pos1 = sys_lseek(fd as i32, 0, 1); // SEEK_CUR=1
    if pos1 != 5 {
        print(b"PREADV:FAIL: position after read should be 5, got ");
        print_num(pos1);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Use preadv to read "from ramfs!" starting at offset 6 into multiple buffers
    // "from ramfs!" = 11 bytes: "from" (4), " " (1), "ramfs!" (6)
    let mut buf1 = [0u8; 4]; // "from"
    let mut buf2 = [0u8; 1]; // " "
    let mut buf3 = [0u8; 6]; // "ramfs!"

    let iov: [IoVec; 3] = [
        IoVec { iov_base: buf1.as_mut_ptr(), iov_len: buf1.len() },
        IoVec { iov_base: buf2.as_mut_ptr(), iov_len: buf2.len() },
        IoVec { iov_base: buf3.as_mut_ptr(), iov_len: buf3.len() },
    ];

    let pret = sys_preadv(fd as i32, iov.as_ptr(), 3, 6);
    if pret != 11 {
        print(b"PREADV:FAIL: preadv returned ");
        print_num(pret);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Verify we read "from" into buf1
    if buf1[0] != b'f' || buf1[1] != b'r' || buf1[2] != b'o' || buf1[3] != b'm' {
        print(b"PREADV:FAIL: expected 'from' in buf1, got ");
        sys_write(1, buf1.as_ptr(), 4);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Verify we read " " into buf2
    if buf2[0] != b' ' {
        print(b"PREADV:FAIL: expected ' ' in buf2, got ");
        sys_write(1, buf2.as_ptr(), 1);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Verify we read "ramfs!" into buf3
    if buf3[0] != b'r' || buf3[5] != b'!' {
        print(b"PREADV:FAIL: expected 'ramfs!' in buf3, got ");
        sys_write(1, buf3.as_ptr(), 6);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Verify file position is UNCHANGED (still 5)
    let pos2 = sys_lseek(fd as i32, 0, 1); // SEEK_CUR=1
    if pos2 != 5 {
        print(b"PREADV:FAIL: position should still be 5 after preadv, got ");
        print_num(pos2);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    println(b"PREADV:OK");
}

/// Test 29: pwritev() - positioned gather write without changing file position
fn test_pwritev() {
    // Create a test file
    let path = b"/pwritev_test.txt\0";
    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    if fd < 0 {
        print(b"PWRITEV:FAIL: open failed: ");
        print_num(fd);
        println(b"");
        return;
    }

    // Write initial content: "AAAA____CCCC" (12 bytes)
    let initial = b"AAAA____CCCC";
    let ret = sys_write(fd as u64, initial.as_ptr(), 12);
    if ret != 12 {
        print(b"PWRITEV:FAIL: initial write failed: ");
        print_num(ret);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Seek to position 2
    let _ = sys_lseek(fd as i32, 2, 0); // SEEK_SET=0

    // Current position should be 2
    let pos1 = sys_lseek(fd as i32, 0, 1); // SEEK_CUR=1
    if pos1 != 2 {
        print(b"PWRITEV:FAIL: position should be 2, got ");
        print_num(pos1);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Use pwritev to write "BBBB" at offset 4 (replacing "____")
    let data1 = b"BB";
    let data2 = b"BB";

    let iov: [IoVec; 2] = [
        IoVec { iov_base: data1.as_ptr() as *const u8, iov_len: data1.len() },
        IoVec { iov_base: data2.as_ptr() as *const u8, iov_len: data2.len() },
    ];

    let pret = sys_pwritev(fd as i32, iov.as_ptr(), 2, 4);
    if pret != 4 {
        print(b"PWRITEV:FAIL: pwritev returned ");
        print_num(pret);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Verify file position is UNCHANGED (still 2)
    let pos2 = sys_lseek(fd as i32, 0, 1); // SEEK_CUR=1
    if pos2 != 2 {
        print(b"PWRITEV:FAIL: position should still be 2 after pwritev, got ");
        print_num(pos2);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Verify the file content is now "AAAABBBBCCCC"
    let _ = sys_lseek(fd as i32, 0, 0); // SEEK_SET to beginning
    let mut verify = [0u8; 12];
    let vret = sys_read(fd as u64, verify.as_mut_ptr(), 12);
    if vret != 12 {
        print(b"PWRITEV:FAIL: verify read failed: ");
        print_num(vret);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Check content: "AAAA" at [0..4], "BBBB" at [4..8], "CCCC" at [8..12]
    if verify[0] != b'A' || verify[3] != b'A' {
        print(b"PWRITEV:FAIL: expected 'AAAA' at start, got ");
        sys_write(1, verify.as_ptr(), 4);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    if verify[4] != b'B' || verify[7] != b'B' {
        print(b"PWRITEV:FAIL: expected 'BBBB' at offset 4, got ");
        sys_write(1, verify[4..8].as_ptr(), 4);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    if verify[8] != b'C' || verify[11] != b'C' {
        print(b"PWRITEV:FAIL: expected 'CCCC' at offset 8, got ");
        sys_write(1, verify[8..12].as_ptr(), 4);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    println(b"PWRITEV:OK");
}

/// Test 30: fcntl(F_DUPFD) - duplicate fd to lowest available >= arg
fn test_fcntl_dupfd() {
    // Open /test.txt
    let path = b"/test.txt\0";
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        print(b"FCNTL_DUPFD:FAIL: open failed: ");
        print_num(fd);
        println(b"");
        return;
    }

    // Duplicate fd to >= 10
    let new_fd = sys_fcntl(fd as i32, F_DUPFD, 10);
    if new_fd < 0 {
        print(b"FCNTL_DUPFD:FAIL: fcntl returned ");
        print_num(new_fd);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Verify new_fd >= 10
    if new_fd < 10 {
        print(b"FCNTL_DUPFD:FAIL: expected new_fd >= 10, got ");
        print_num(new_fd);
        println(b"");
        sys_close(fd as u64);
        sys_close(new_fd as u64);
        return;
    }

    // Verify the duplicated fd works by reading from it
    let mut buf = [0u8; 5];
    let ret = sys_read(new_fd as u64, buf.as_mut_ptr(), 5);
    if ret != 5 {
        print(b"FCNTL_DUPFD:FAIL: read from new_fd failed: ");
        print_num(ret);
        println(b"");
        sys_close(fd as u64);
        sys_close(new_fd as u64);
        return;
    }

    // Verify we read "Hello"
    if buf[0] != b'H' || buf[4] != b'o' {
        print(b"FCNTL_DUPFD:FAIL: expected 'Hello', got ");
        sys_write(1, buf.as_ptr(), 5);
        println(b"");
        sys_close(fd as u64);
        sys_close(new_fd as u64);
        return;
    }

    sys_close(fd as u64);
    sys_close(new_fd as u64);
    println(b"FCNTL_DUPFD:OK");
}

/// Test 31: fcntl(F_GETFD/F_SETFD) - get/set fd flags (FD_CLOEXEC)
fn test_fcntl_cloexec() {
    // Open /test.txt
    let path = b"/test.txt\0";
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        print(b"FCNTL_CLOEXEC:FAIL: open failed: ");
        print_num(fd);
        println(b"");
        return;
    }

    // Get initial fd flags (should be 0)
    let initial_flags = sys_fcntl(fd as i32, F_GETFD, 0);
    if initial_flags < 0 {
        print(b"FCNTL_CLOEXEC:FAIL: F_GETFD returned ");
        print_num(initial_flags);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    if initial_flags != 0 {
        print(b"FCNTL_CLOEXEC:FAIL: expected initial flags=0, got ");
        print_num(initial_flags);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Set FD_CLOEXEC
    let ret = sys_fcntl(fd as i32, F_SETFD, FD_CLOEXEC);
    if ret < 0 {
        print(b"FCNTL_CLOEXEC:FAIL: F_SETFD returned ");
        print_num(ret);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Verify FD_CLOEXEC is set
    let new_flags = sys_fcntl(fd as i32, F_GETFD, 0);
    if new_flags < 0 {
        print(b"FCNTL_CLOEXEC:FAIL: F_GETFD after set returned ");
        print_num(new_flags);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    if (new_flags as u64) & FD_CLOEXEC == 0 {
        print(b"FCNTL_CLOEXEC:FAIL: FD_CLOEXEC not set, flags=");
        print_num(new_flags);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    println(b"FCNTL_CLOEXEC:OK");
}

/// Test 32: fcntl(F_DUPFD_CLOEXEC) - duplicate with cloexec
fn test_fcntl_dupfd_cloexec() {
    // Open /test.txt
    let path = b"/test.txt\0";
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        print(b"FCNTL_DUPFD_CLOEXEC:FAIL: open failed: ");
        print_num(fd);
        println(b"");
        return;
    }

    // Duplicate fd with cloexec
    let new_fd = sys_fcntl(fd as i32, F_DUPFD_CLOEXEC, 0);
    if new_fd < 0 {
        print(b"FCNTL_DUPFD_CLOEXEC:FAIL: fcntl returned ");
        print_num(new_fd);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    // Verify new_fd has FD_CLOEXEC set
    let flags = sys_fcntl(new_fd as i32, F_GETFD, 0);
    if flags < 0 {
        print(b"FCNTL_DUPFD_CLOEXEC:FAIL: F_GETFD returned ");
        print_num(flags);
        println(b"");
        sys_close(fd as u64);
        sys_close(new_fd as u64);
        return;
    }

    if (flags as u64) & FD_CLOEXEC == 0 {
        print(b"FCNTL_DUPFD_CLOEXEC:FAIL: FD_CLOEXEC not set on new_fd, flags=");
        print_num(flags);
        println(b"");
        sys_close(fd as u64);
        sys_close(new_fd as u64);
        return;
    }

    // Original fd should NOT have FD_CLOEXEC
    let orig_flags = sys_fcntl(fd as i32, F_GETFD, 0);
    if (orig_flags as u64) & FD_CLOEXEC != 0 {
        print(b"FCNTL_DUPFD_CLOEXEC:FAIL: original fd has FD_CLOEXEC, flags=");
        print_num(orig_flags);
        println(b"");
        sys_close(fd as u64);
        sys_close(new_fd as u64);
        return;
    }

    sys_close(fd as u64);
    sys_close(new_fd as u64);
    println(b"FCNTL_DUPFD_CLOEXEC:OK");
}

/// Test 33: fcntl() with invalid fd returns -EBADF
fn test_fcntl_ebadf() {
    // Use a clearly invalid fd
    let ret = sys_fcntl(9999, F_GETFD, 0);
    if ret == -9 {
        // EBADF = 9
        println(b"FCNTL_EBADF:OK");
    } else {
        print(b"FCNTL_EBADF:FAIL: expected -9 (EBADF), got ");
        print_num(ret);
        println(b"");
    }
}

/// Test 34: getrandom() - get random bytes
fn test_getrandom() {
    let mut buf = [0u8; 32];

    // Get random bytes
    let ret = sys_getrandom(buf.as_mut_ptr(), buf.len(), 0);
    if ret < 0 {
        print(b"GETRANDOM:FAIL: returned ");
        print_num(ret);
        println(b"");
        return;
    }

    if ret != 32 {
        print(b"GETRANDOM:FAIL: expected 32 bytes, got ");
        print_num(ret);
        println(b"");
        return;
    }

    // Verify not all zeros (statistically almost impossible for 32 random bytes)
    let mut all_zero = true;
    for b in &buf {
        if *b != 0 {
            all_zero = false;
            break;
        }
    }

    if all_zero {
        println(b"GETRANDOM:FAIL: all bytes are zero");
        return;
    }

    // Verify not all same value
    let first = buf[0];
    let mut all_same = true;
    for b in &buf {
        if *b != first {
            all_same = false;
            break;
        }
    }

    if all_same {
        println(b"GETRANDOM:FAIL: all bytes are identical");
        return;
    }

    println(b"GETRANDOM:OK");
}

/// Test 35: getrandom() with invalid flags returns -EINVAL
fn test_getrandom_einval() {
    let mut buf = [0u8; 8];

    // Use invalid flags (all bits set except valid ones)
    let invalid_flags = 0xFFF8u32; // Invalid flag bits
    let ret = sys_getrandom(buf.as_mut_ptr(), buf.len(), invalid_flags);

    if ret == -22 {
        // EINVAL = 22
        println(b"GETRANDOM_EINVAL:OK");
    } else {
        print(b"GETRANDOM_EINVAL:FAIL: expected -22 (EINVAL), got ");
        print_num(ret);
        println(b"");
    }
}

/// Test 36: ioctl() with invalid fd returns -EBADF
fn test_ioctl_ebadf() {
    // Use a clearly invalid fd
    let ret = sys_ioctl(9999, 0, 0);
    if ret == -9 {
        // EBADF = 9
        println(b"IOCTL_EBADF:OK");
    } else {
        print(b"IOCTL_EBADF:FAIL: expected -9 (EBADF), got ");
        print_num(ret);
        println(b"");
    }
}

/// Test 37: ioctl() on regular file returns -ENOTTY
fn test_ioctl_enotty() {
    // Open a regular file
    let path = b"/test.txt\0";
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        print(b"IOCTL_ENOTTY:FAIL: open failed: ");
        print_num(fd);
        println(b"");
        return;
    }

    // ioctl on regular file should return ENOTTY
    let ret = sys_ioctl(fd as i32, 0, 0);
    sys_close(fd as u64);

    if ret == -25 {
        // ENOTTY = 25
        println(b"IOCTL_ENOTTY:OK");
    } else {
        print(b"IOCTL_ENOTTY:FAIL: expected -25 (ENOTTY), got ");
        print_num(ret);
        println(b"");
    }
}
