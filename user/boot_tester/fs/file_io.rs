//! File I/O tests
//!
//! Tests:
//! - writev() - gather write to stdout
//! - readv() - scatter read from file
//! - writev() with zero-length iovec
//! - readv() with invalid iovcnt
//! - pread64() - positioned read without changing file position
//! - pwrite64() - positioned write without changing file position
//! - preadv() - positioned scatter read without changing file position
//! - pwritev() - positioned gather write without changing file position
//! - fcntl(F_DUPFD) - duplicate fd to lowest available >= arg
//! - fcntl(F_GETFD/F_SETFD) - get/set fd flags (FD_CLOEXEC)
//! - fcntl(F_DUPFD_CLOEXEC) - duplicate with cloexec
//! - fcntl() with invalid fd returns -EBADF
//! - getrandom() - get random bytes
//! - GETRANDOM_STREAM: a 64KB read is whole and evenly spread
//! - getrandom() with invalid flags returns -EINVAL
//! - ioctl() with invalid fd returns -EBADF
//! - ioctl() on regular file returns -ENOTTY
//! - preadv2() - basic positioned scatter read with flags=0
//! - pwritev2() - basic positioned gather write with flags=0
//! - preadv2() with offset=-1 uses current file position
//! - pwritev2() with offset=-1 uses current file position
//! - pwritev2() with RWF_APPEND appends to file
//! - preadv2() with invalid flags returns -EOPNOTSUPP
//! - preadv2() with RWF_NOWAIT on ramfs returns -EOPNOTSUPP
//! - WRITE_OWN_MAP: a write sourced from a mapping of the page it writes
//! - IOV_PARTIAL_FAULT: writev/readv stop at a bad segment with the
//!   bytes done
//! - SYSCTL_PARTIAL_FAULT: a sysctl write whose data faults partway is
//!   EFAULT and stores nothing
//! - RWF_NOWAIT_STREAMS: preadv2 RWF_NOWAIT on an empty eventfd, timerfd
//!   (Linux 6.10+) or socket is EAGAIN (Linux FMODE_NOWAIT), not EOPNOTSUPP
//! - RW_STRADDLE: read/write with one buffer running off mapped memory
//!   mid-page move the mapped part and return its length

use crate::harness::{fail_num, pass};
use crate::helpers::{host_mode, print, print_num, println};
use hk_syscall::{
    AT_EMPTY_PATH, AT_FDCWD, FIOCLEX, FIONBIO, FIONCLEX, IoVec, LinuxStatFs, MAP_ANONYMOUS,
    MAP_PRIVATE, MAP_SHARED, O_CREAT, O_NONBLOCK, O_RDONLY, O_RDWR, O_TRUNC, PROC_SUPER_MAGIC,
    PROT_READ, RAMFS_MAGIC, STATX_BASIC_STATS, Statx, sys_close, sys_fcntl, sys_fstatfs,
    sys_ftruncate, sys_getrandom, sys_ioctl, sys_lseek, sys_mmap, sys_munmap, sys_open, sys_pipe2,
    sys_pread64, sys_preadv, sys_preadv2, sys_pwrite64, sys_pwritev, sys_pwritev2, sys_read,
    sys_readv, sys_statfs, sys_statx, sys_unlink, sys_write, sys_writev,
};

// RWF flags for preadv2/pwritev2
const RWF_NOWAIT: i32 = 0x08;
const TMPFS_MAGIC: i64 = 0x0102_1994;
const RWF_APPEND: i32 = 0x10;

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
    test_trunc_tail();
    test_write_own_map();
    test_iov_partial_fault();
    test_rw_straddle();
    test_rwf_nowait_streams();
    test_sysctl_partial_fault();
    test_getrandom();
    test_getrandom_einval();
    test_getrandom_stream();
    test_ioctl_ebadf();
    test_ioctl_enotty();
    // preadv2/pwritev2 tests
    test_preadv2_basic();
    test_pwritev2_basic();
    test_preadv2_offset_minus_one();
    test_pwritev2_offset_minus_one();
    test_pwritev2_rwf_append();
    test_preadv2_invalid_flags();
    test_preadv2_rwf_nowait();
    test_preadv2_rwf_nowait_pipe_eagain();
    // statfs/fstatfs/statx tests
    test_statfs_root();
    test_statfs_proc();
    test_statfs_enoent();
    test_fstatfs();
    test_statx_basic();
    test_statx_at_empty_path();
    // Generic ioctl tests
    test_ioctl_fionbio();
    test_ioctl_fioclex();
}

/// writev() - gather write to stdout
fn test_writev() {
    let msg1 = b"Hello, ";
    let msg2 = b"writev ";
    let msg3 = b"world!\n";

    let iov: [IoVec; 3] = [
        IoVec {
            iov_base: msg1.as_ptr(),
            iov_len: msg1.len(),
        },
        IoVec {
            iov_base: msg2.as_ptr(),
            iov_len: msg2.len(),
        },
        IoVec {
            iov_base: msg3.as_ptr(),
            iov_len: msg3.len(),
        },
    ];

    let ret = sys_writev(1, iov.as_ptr(), 3);
    let expected_len = (msg1.len() + msg2.len() + msg3.len()) as i64;
    if ret == expected_len {
        pass(b"WRITEV");
    } else {
        print(b"WRITEV:FAIL: expected ");
        print_num(expected_len);
        print(b", got ");
        print_num(ret);
    }
}

/// readv() - scatter read from file
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
            IoVec {
                iov_base: buf1.as_mut_ptr(),
                iov_len: buf1.len(),
            },
            IoVec {
                iov_base: buf2.as_mut_ptr(),
                iov_len: buf2.len(),
            },
            IoVec {
                iov_base: buf3.as_mut_ptr(),
                iov_len: buf3.len(),
            },
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
                pass(b"READV");
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

/// writev() with zero-length iovec
fn test_writev_zero_len() {
    let msg_before = b"Before";
    let msg_after = b"After\n";

    let iov_zero: [IoVec; 3] = [
        IoVec {
            iov_base: msg_before.as_ptr(),
            iov_len: msg_before.len(),
        },
        IoVec {
            iov_base: core::ptr::null(),
            iov_len: 0,
        }, // zero-length
        IoVec {
            iov_base: msg_after.as_ptr(),
            iov_len: msg_after.len(),
        },
    ];

    let ret = sys_writev(1, iov_zero.as_ptr(), 3);
    let expected = (msg_before.len() + msg_after.len()) as i64;
    if ret == expected {
        pass(b"WRITEV_ZERO_LEN");
    } else {
        print(b"WRITEV_ZERO_LEN:FAIL: expected ");
        print_num(expected);
        print(b", got ");
        print_num(ret);
    }
}

/// readv() with invalid iovcnt
fn test_readv_invalid_iovcnt() {
    let ret_neg = sys_readv(0, core::ptr::null(), (-1i64) as u64);
    if ret_neg == -22 {
        // EINVAL
        pass(b"READV_INVALID_IOVCNT");
    } else {
        print(b"READV_INVALID_IOVCNT:FAIL: expected -22, got ");
        print_num(ret_neg);
    }
}

/// pread64() - positioned read without changing file position
fn test_pread64() {
    // Open /test.txt which contains "Hello from ramfs!" (17 bytes)
    let path = b"/test.txt\0";
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        fail_num(b"PREAD64:FAIL: open failed: ", fd);
        return;
    }

    // Read first 5 bytes with normal read() to set position
    let mut buf1 = [0u8; 5];
    let ret = sys_read(fd as u64, buf1.as_mut_ptr(), 5);
    if ret != 5 {
        fail_num(b"PREAD64:FAIL: initial read failed: ", ret);
        sys_close(fd as u64);
        return;
    }

    // Current position should be 5, verify with lseek
    let pos1 = sys_lseek(fd as i32, 0, 1); // SEEK_CUR=1
    if pos1 != 5 {
        fail_num(b"PREAD64:FAIL: position after read should be 5, got ", pos1);
        sys_close(fd as u64);
        return;
    }

    // Use pread64 to read "from" starting at offset 6 (after "Hello ")
    let mut buf2 = [0u8; 4];
    let pret = sys_pread64(fd as i32, buf2.as_mut_ptr(), 4, 6);
    if pret != 4 {
        fail_num(b"PREAD64:FAIL: pread64 returned ", pret);
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
        fail_num(
            b"PREAD64:FAIL: position should still be 5 after pread64, got ",
            pos2,
        );
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    pass(b"PREAD64");
}

/// pwrite64() - positioned write without changing file position
fn test_pwrite64() {
    // Create a test file in root (ramfs)
    let path = b"/pwrite_test.txt\0";
    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    if fd < 0 {
        fail_num(b"PWRITE64:FAIL: open failed: ", fd);
        return;
    }

    // Write initial content: "AAAABBBBCCCC" (12 bytes)
    let initial = b"AAAABBBBCCCC";
    let ret = sys_write(fd as u64, initial.as_ptr(), 12);
    if ret != 12 {
        fail_num(b"PWRITE64:FAIL: initial write failed: ", ret);
        sys_close(fd as u64);
        return;
    }

    // Position is now 12, seek to position 4
    let _ = sys_lseek(fd as i32, 4, 0); // SEEK_SET=0

    // Current position should be 4
    let pos1 = sys_lseek(fd as i32, 0, 1); // SEEK_CUR=1
    if pos1 != 4 {
        fail_num(b"PWRITE64:FAIL: position should be 4, got ", pos1);
        sys_close(fd as u64);
        return;
    }

    // Use pwrite64 to write "XXXX" at offset 0 (replacing "AAAA")
    let new_data = b"XXXX";
    let pret = sys_pwrite64(fd as i32, new_data.as_ptr(), 4, 0);
    if pret != 4 {
        fail_num(b"PWRITE64:FAIL: pwrite64 returned ", pret);
        sys_close(fd as u64);
        return;
    }

    // Verify file position is UNCHANGED (still 4)
    let pos2 = sys_lseek(fd as i32, 0, 1); // SEEK_CUR=1
    if pos2 != 4 {
        fail_num(
            b"PWRITE64:FAIL: position should still be 4 after pwrite64, got ",
            pos2,
        );
        sys_close(fd as u64);
        return;
    }

    // Verify the file content is now "XXXXBBBBCCCC"
    let _ = sys_lseek(fd as i32, 0, 0); // SEEK_SET to beginning
    let mut verify = [0u8; 12];
    let vret = sys_read(fd as u64, verify.as_mut_ptr(), 12);
    if vret != 12 {
        fail_num(b"PWRITE64:FAIL: verify read failed: ", vret);
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
    pass(b"PWRITE64");
}

/// preadv() - positioned scatter read without changing file position
fn test_preadv() {
    // Open /test.txt which contains "Hello from ramfs!" (17 bytes)
    let path = b"/test.txt\0";
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        fail_num(b"PREADV:FAIL: open failed: ", fd);
        return;
    }

    // Read first 5 bytes with normal read() to set position
    let mut initial_buf = [0u8; 5];
    let ret = sys_read(fd as u64, initial_buf.as_mut_ptr(), 5);
    if ret != 5 {
        fail_num(b"PREADV:FAIL: initial read failed: ", ret);
        sys_close(fd as u64);
        return;
    }

    // Current position should be 5
    let pos1 = sys_lseek(fd as i32, 0, 1); // SEEK_CUR=1
    if pos1 != 5 {
        fail_num(b"PREADV:FAIL: position after read should be 5, got ", pos1);
        sys_close(fd as u64);
        return;
    }

    // Use preadv to read "from ramfs!" starting at offset 6 into multiple buffers
    // "from ramfs!" = 11 bytes: "from" (4), " " (1), "ramfs!" (6)
    let mut buf1 = [0u8; 4]; // "from"
    let mut buf2 = [0u8; 1]; // " "
    let mut buf3 = [0u8; 6]; // "ramfs!"

    let iov: [IoVec; 3] = [
        IoVec {
            iov_base: buf1.as_mut_ptr(),
            iov_len: buf1.len(),
        },
        IoVec {
            iov_base: buf2.as_mut_ptr(),
            iov_len: buf2.len(),
        },
        IoVec {
            iov_base: buf3.as_mut_ptr(),
            iov_len: buf3.len(),
        },
    ];

    let pret = sys_preadv(fd as i32, iov.as_ptr(), 3, 6);
    if pret != 11 {
        fail_num(b"PREADV:FAIL: preadv returned ", pret);
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
        fail_num(
            b"PREADV:FAIL: position should still be 5 after preadv, got ",
            pos2,
        );
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    pass(b"PREADV");
}

/// pwritev() - positioned gather write without changing file position
fn test_pwritev() {
    // Create a test file
    let path = b"/pwritev_test.txt\0";
    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    if fd < 0 {
        fail_num(b"PWRITEV:FAIL: open failed: ", fd);
        return;
    }

    // Write initial content: "AAAA____CCCC" (12 bytes)
    let initial = b"AAAA____CCCC";
    let ret = sys_write(fd as u64, initial.as_ptr(), 12);
    if ret != 12 {
        fail_num(b"PWRITEV:FAIL: initial write failed: ", ret);
        sys_close(fd as u64);
        return;
    }

    // Seek to position 2
    let _ = sys_lseek(fd as i32, 2, 0); // SEEK_SET=0

    // Current position should be 2
    let pos1 = sys_lseek(fd as i32, 0, 1); // SEEK_CUR=1
    if pos1 != 2 {
        fail_num(b"PWRITEV:FAIL: position should be 2, got ", pos1);
        sys_close(fd as u64);
        return;
    }

    // Use pwritev to write "BBBB" at offset 4 (replacing "____")
    let data1 = b"BB";
    let data2 = b"BB";

    let iov: [IoVec; 2] = [
        IoVec {
            iov_base: data1.as_ptr() as *const u8,
            iov_len: data1.len(),
        },
        IoVec {
            iov_base: data2.as_ptr() as *const u8,
            iov_len: data2.len(),
        },
    ];

    let pret = sys_pwritev(fd as i32, iov.as_ptr(), 2, 4);
    if pret != 4 {
        fail_num(b"PWRITEV:FAIL: pwritev returned ", pret);
        sys_close(fd as u64);
        return;
    }

    // Verify file position is UNCHANGED (still 2)
    let pos2 = sys_lseek(fd as i32, 0, 1); // SEEK_CUR=1
    if pos2 != 2 {
        fail_num(
            b"PWRITEV:FAIL: position should still be 2 after pwritev, got ",
            pos2,
        );
        sys_close(fd as u64);
        return;
    }

    // Verify the file content is now "AAAABBBBCCCC"
    let _ = sys_lseek(fd as i32, 0, 0); // SEEK_SET to beginning
    let mut verify = [0u8; 12];
    let vret = sys_read(fd as u64, verify.as_mut_ptr(), 12);
    if vret != 12 {
        fail_num(b"PWRITEV:FAIL: verify read failed: ", vret);
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
    pass(b"PWRITEV");
}

/// fcntl(F_DUPFD) - duplicate fd to lowest available >= arg
fn test_fcntl_dupfd() {
    // Open /test.txt
    let path = b"/test.txt\0";
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        fail_num(b"FCNTL_DUPFD:FAIL: open failed: ", fd);
        return;
    }

    // Duplicate fd to >= 10
    let new_fd = sys_fcntl(fd as i32, F_DUPFD, 10);
    if new_fd < 0 {
        fail_num(b"FCNTL_DUPFD:FAIL: fcntl returned ", new_fd);
        sys_close(fd as u64);
        return;
    }

    // Verify new_fd >= 10
    if new_fd < 10 {
        fail_num(b"FCNTL_DUPFD:FAIL: expected new_fd >= 10, got ", new_fd);
        sys_close(fd as u64);
        sys_close(new_fd as u64);
        return;
    }

    // Verify the duplicated fd works by reading from it
    let mut buf = [0u8; 5];
    let ret = sys_read(new_fd as u64, buf.as_mut_ptr(), 5);
    if ret != 5 {
        fail_num(b"FCNTL_DUPFD:FAIL: read from new_fd failed: ", ret);
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
    pass(b"FCNTL_DUPFD");
}

/// fcntl(F_GETFD/F_SETFD) - get/set fd flags (FD_CLOEXEC)
fn test_fcntl_cloexec() {
    // Open /test.txt
    let path = b"/test.txt\0";
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        fail_num(b"FCNTL_CLOEXEC:FAIL: open failed: ", fd);
        return;
    }

    // Get initial fd flags (should be 0)
    let initial_flags = sys_fcntl(fd as i32, F_GETFD, 0);
    if initial_flags < 0 {
        fail_num(b"FCNTL_CLOEXEC:FAIL: F_GETFD returned ", initial_flags);
        sys_close(fd as u64);
        return;
    }

    if initial_flags != 0 {
        fail_num(
            b"FCNTL_CLOEXEC:FAIL: expected initial flags=0, got ",
            initial_flags,
        );
        sys_close(fd as u64);
        return;
    }

    // Set FD_CLOEXEC
    let ret = sys_fcntl(fd as i32, F_SETFD, FD_CLOEXEC);
    if ret < 0 {
        fail_num(b"FCNTL_CLOEXEC:FAIL: F_SETFD returned ", ret);
        sys_close(fd as u64);
        return;
    }

    // Verify FD_CLOEXEC is set
    let new_flags = sys_fcntl(fd as i32, F_GETFD, 0);
    if new_flags < 0 {
        fail_num(
            b"FCNTL_CLOEXEC:FAIL: F_GETFD after set returned ",
            new_flags,
        );
        sys_close(fd as u64);
        return;
    }

    if (new_flags as u64) & FD_CLOEXEC == 0 {
        fail_num(b"FCNTL_CLOEXEC:FAIL: FD_CLOEXEC not set, flags=", new_flags);
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    pass(b"FCNTL_CLOEXEC");
}

/// fcntl(F_DUPFD_CLOEXEC) - duplicate with cloexec
fn test_fcntl_dupfd_cloexec() {
    // Open /test.txt
    let path = b"/test.txt\0";
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        fail_num(b"FCNTL_DUPFD_CLOEXEC:FAIL: open failed: ", fd);
        return;
    }

    // Duplicate fd with cloexec
    let new_fd = sys_fcntl(fd as i32, F_DUPFD_CLOEXEC, 0);
    if new_fd < 0 {
        fail_num(b"FCNTL_DUPFD_CLOEXEC:FAIL: fcntl returned ", new_fd);
        sys_close(fd as u64);
        return;
    }

    // Verify new_fd has FD_CLOEXEC set
    let flags = sys_fcntl(new_fd as i32, F_GETFD, 0);
    if flags < 0 {
        fail_num(b"FCNTL_DUPFD_CLOEXEC:FAIL: F_GETFD returned ", flags);
        sys_close(fd as u64);
        sys_close(new_fd as u64);
        return;
    }

    if (flags as u64) & FD_CLOEXEC == 0 {
        fail_num(
            b"FCNTL_DUPFD_CLOEXEC:FAIL: FD_CLOEXEC not set on new_fd, flags=",
            flags,
        );
        sys_close(fd as u64);
        sys_close(new_fd as u64);
        return;
    }

    // Original fd should NOT have FD_CLOEXEC
    let orig_flags = sys_fcntl(fd as i32, F_GETFD, 0);
    if (orig_flags as u64) & FD_CLOEXEC != 0 {
        fail_num(
            b"FCNTL_DUPFD_CLOEXEC:FAIL: original fd has FD_CLOEXEC, flags=",
            orig_flags,
        );
        sys_close(fd as u64);
        sys_close(new_fd as u64);
        return;
    }

    sys_close(fd as u64);
    sys_close(new_fd as u64);
    pass(b"FCNTL_DUPFD_CLOEXEC");
}

/// fcntl() with invalid fd returns -EBADF
fn test_fcntl_ebadf() {
    // Use a clearly invalid fd
    let ret = sys_fcntl(9999, F_GETFD, 0);
    if ret == -9 {
        // EBADF = 9
        pass(b"FCNTL_EBADF");
    } else {
        fail_num(b"FCNTL_EBADF:FAIL: expected -9 (EBADF), got ", ret);
    }
}

/// getrandom() - get random bytes
fn test_getrandom() {
    let mut buf = [0u8; 32];

    // Get random bytes
    let ret = sys_getrandom(buf.as_mut_ptr(), buf.len(), 0);
    if ret < 0 {
        fail_num(b"GETRANDOM:FAIL: returned ", ret);
        return;
    }

    if ret != 32 {
        fail_num(b"GETRANDOM:FAIL: expected 32 bytes, got ", ret);
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

    pass(b"GETRANDOM");
}

/// getrandom() with invalid flags returns -EINVAL
fn test_getrandom_einval() {
    let mut buf = [0u8; 8];

    // Use invalid flags (all bits set except valid ones)
    let invalid_flags = 0xFFF8u32; // Invalid flag bits
    let ret = sys_getrandom(buf.as_mut_ptr(), buf.len(), invalid_flags);

    if ret == -22 {
        // EINVAL = 22
        pass(b"GETRANDOM_EINVAL");
    } else {
        fail_num(b"GETRANDOM_EINVAL:FAIL: expected -22 (EINVAL), got ", ret);
    }
}

/// GETRANDOM_STREAM: a 64KB read is one fast-key-erased ChaCha20
/// stream: every byte value turns up near 256 times (none under 150 or
/// over 380), two reads differ, and GRND_INSECURE|GRND_RANDOM is EINVAL
fn test_getrandom_stream() {
    const GRND_RANDOM: u32 = 2;
    const GRND_INSECURE: u32 = 4;
    static mut BUF: [u8; 65536] = [0; 65536];
    // SAFETY: the boot tester is single-threaded here
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    let n = sys_getrandom(buf.as_mut_ptr(), buf.len(), 0);
    sys_getrandom(a.as_mut_ptr(), 32, 0);
    sys_getrandom(b.as_mut_ptr(), 32, GRND_RANDOM);
    let mut count = [0u32; 256];
    for &x in buf.iter() {
        count[x as usize] += 1;
    }
    let lo = *count.iter().min().unwrap();
    let hi = *count.iter().max().unwrap();
    let both = sys_getrandom(a.as_mut_ptr(), 1, GRND_INSECURE | GRND_RANDOM);
    let why: &[u8] = if n != buf.len() as i64 {
        b"short read"
    } else if lo < 150 || hi > 380 {
        b"skewed bytes"
    } else if a == b {
        b"repeated output"
    } else if both != -22 {
        b"INSECURE|RANDOM not EINVAL"
    } else {
        b""
    };
    if why.is_empty() {
        pass(b"GETRANDOM_STREAM");
    } else {
        print(b"GETRANDOM_STREAM:FAIL ");
        println(why);
    }
}

/// ioctl() with invalid fd returns -EBADF
fn test_ioctl_ebadf() {
    // Use a clearly invalid fd
    let ret = sys_ioctl(9999, 0, 0);
    if ret == -9 {
        // EBADF = 9
        pass(b"IOCTL_EBADF");
    } else {
        fail_num(b"IOCTL_EBADF:FAIL: expected -9 (EBADF), got ", ret);
    }
}

/// ioctl() on regular file returns -ENOTTY
fn test_ioctl_enotty() {
    // Open a regular file
    let path = b"/test.txt\0";
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        fail_num(b"IOCTL_ENOTTY:FAIL: open failed: ", fd);
        return;
    }

    // ioctl on regular file should return ENOTTY
    let ret = sys_ioctl(fd as i32, 0, 0);
    sys_close(fd as u64);

    if ret == -25 {
        // ENOTTY = 25
        pass(b"IOCTL_ENOTTY");
    } else {
        fail_num(b"IOCTL_ENOTTY:FAIL: expected -25 (ENOTTY), got ", ret);
    }
}

// =============================================================================
// preadv2/pwritev2 tests
// =============================================================================

/// preadv2() - basic positioned scatter read with flags=0
fn test_preadv2_basic() {
    // Open /test.txt which should contain "Hello from ramfs!"
    let path = b"/test.txt\0";
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        fail_num(b"PREADV2_BASIC:FAIL: open failed: ", fd);
        return;
    }

    // Read "from" starting at offset 6 with flags=0
    let mut buf = [0u8; 4];
    let iov: [IoVec; 1] = [IoVec {
        iov_base: buf.as_mut_ptr(),
        iov_len: buf.len(),
    }];

    let ret = sys_preadv2(fd as i32, iov.as_ptr(), 1, 6, 0);
    if ret != 4 {
        fail_num(b"PREADV2_BASIC:FAIL: expected 4 bytes, got ", ret);
        sys_close(fd as u64);
        return;
    }

    // Verify we read "from"
    if buf[0] != b'f' || buf[1] != b'r' || buf[2] != b'o' || buf[3] != b'm' {
        print(b"PREADV2_BASIC:FAIL: expected 'from', got ");
        sys_write(1, buf.as_ptr(), 4);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    pass(b"PREADV2_BASIC");
}

/// pwritev2() - basic positioned gather write with flags=0
fn test_pwritev2_basic() {
    // Create a test file
    let path = b"/pwritev2_test.txt\0";
    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    if fd < 0 {
        fail_num(b"PWRITEV2_BASIC:FAIL: open failed: ", fd);
        return;
    }

    // Write "test" at offset 0 with flags=0
    let data = b"test";
    let iov: [IoVec; 1] = [IoVec {
        iov_base: data.as_ptr(),
        iov_len: data.len(),
    }];

    let ret = sys_pwritev2(fd as i32, iov.as_ptr(), 1, 0, 0);
    if ret != 4 {
        fail_num(b"PWRITEV2_BASIC:FAIL: expected 4 bytes written, got ", ret);
        sys_close(fd as u64);
        return;
    }

    // Verify by reading back
    let mut buf = [0u8; 4];
    let read_ret = sys_pread64(fd as i32, buf.as_mut_ptr(), 4, 0);
    if read_ret != 4 || buf[0] != b't' || buf[3] != b't' {
        print(b"PWRITEV2_BASIC:FAIL: readback failed");
        println(b"");
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    pass(b"PWRITEV2_BASIC");
}

/// preadv2() with offset=-1 uses current file position
fn test_preadv2_offset_minus_one() {
    let path = b"/test.txt\0";
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        fail_num(b"PREADV2_OFFSET_NEG1:FAIL: open failed: ", fd);
        return;
    }

    // Seek to offset 6
    let pos = sys_lseek(fd as i32, 6, 0); // SEEK_SET=0
    if pos != 6 {
        fail_num(b"PREADV2_OFFSET_NEG1:FAIL: lseek failed: ", pos);
        sys_close(fd as u64);
        return;
    }

    // Read with offset=-1 (should use current position)
    let mut buf = [0u8; 4];
    let iov: [IoVec; 1] = [IoVec {
        iov_base: buf.as_mut_ptr(),
        iov_len: buf.len(),
    }];

    let ret = sys_preadv2(fd as i32, iov.as_ptr(), 1, -1, 0);
    if ret != 4 {
        fail_num(b"PREADV2_OFFSET_NEG1:FAIL: expected 4 bytes, got ", ret);
        sys_close(fd as u64);
        return;
    }

    // Should have read "from" (at offset 6)
    if buf[0] != b'f' || buf[1] != b'r' || buf[2] != b'o' || buf[3] != b'm' {
        print(b"PREADV2_OFFSET_NEG1:FAIL: expected 'from', got ");
        sys_write(1, buf.as_ptr(), 4);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    pass(b"PREADV2_OFFSET_NEG1");
}

/// pwritev2() with offset=-1 uses current file position
fn test_pwritev2_offset_minus_one() {
    let path = b"/pwritev2_neg1.txt\0";
    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    if fd < 0 {
        fail_num(b"PWRITEV2_OFFSET_NEG1:FAIL: open failed: ", fd);
        return;
    }

    // Write "AAAA" to establish file
    let data1 = b"AAAA";
    sys_write(fd as u64, data1.as_ptr(), 4);

    // Seek to position 2
    let pos = sys_lseek(fd as i32, 2, 0); // SEEK_SET=0
    if pos != 2 {
        fail_num(b"PWRITEV2_OFFSET_NEG1:FAIL: lseek failed: ", pos);
        sys_close(fd as u64);
        return;
    }

    // Write "BB" with offset=-1 (should use current position = 2)
    let data2 = b"BB";
    let iov: [IoVec; 1] = [IoVec {
        iov_base: data2.as_ptr(),
        iov_len: data2.len(),
    }];

    let ret = sys_pwritev2(fd as i32, iov.as_ptr(), 1, -1, 0);
    if ret != 2 {
        fail_num(
            b"PWRITEV2_OFFSET_NEG1:FAIL: expected 2 bytes written, got ",
            ret,
        );
        sys_close(fd as u64);
        return;
    }

    // Verify: file should be "AABB"
    let mut buf = [0u8; 4];
    let read_ret = sys_pread64(fd as i32, buf.as_mut_ptr(), 4, 0);
    if read_ret != 4 || buf[0] != b'A' || buf[1] != b'A' || buf[2] != b'B' || buf[3] != b'B' {
        print(b"PWRITEV2_OFFSET_NEG1:FAIL: expected 'AABB', got ");
        sys_write(1, buf.as_ptr(), 4);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    pass(b"PWRITEV2_OFFSET_NEG1");
}

/// pwritev2() with RWF_APPEND appends to file
fn test_pwritev2_rwf_append() {
    let path = b"/pwritev2_append.txt\0";
    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    if fd < 0 {
        fail_num(b"PWRITEV2_RWF_APPEND:FAIL: open failed: ", fd);
        return;
    }

    // Write "Hello" first
    let data1 = b"Hello";
    sys_write(fd as u64, data1.as_ptr(), 5);

    // Use pwritev2 with RWF_APPEND to append "World"
    // Even though offset=0, RWF_APPEND should append at end
    let data2 = b"World";
    let iov: [IoVec; 1] = [IoVec {
        iov_base: data2.as_ptr(),
        iov_len: data2.len(),
    }];

    let ret = sys_pwritev2(fd as i32, iov.as_ptr(), 1, 0, RWF_APPEND);
    if ret != 5 {
        fail_num(
            b"PWRITEV2_RWF_APPEND:FAIL: expected 5 bytes written, got ",
            ret,
        );
        sys_close(fd as u64);
        return;
    }

    // Verify: file should be "HelloWorld" (10 bytes)
    let mut buf = [0u8; 10];
    let read_ret = sys_pread64(fd as i32, buf.as_mut_ptr(), 10, 0);
    if read_ret != 10 {
        fail_num(
            b"PWRITEV2_RWF_APPEND:FAIL: expected 10 bytes, got ",
            read_ret,
        );
        sys_close(fd as u64);
        return;
    }

    // Check content
    if buf[0] != b'H' || buf[4] != b'o' || buf[5] != b'W' || buf[9] != b'd' {
        print(b"PWRITEV2_RWF_APPEND:FAIL: expected 'HelloWorld', got ");
        sys_write(1, buf.as_ptr(), 10);
        println(b"");
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    pass(b"PWRITEV2_RWF_APPEND");
}

/// preadv2() with invalid flags returns -EOPNOTSUPP
fn test_preadv2_invalid_flags() {
    let path = b"/test.txt\0";
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        fail_num(b"PREADV2_INVALID_FLAGS:FAIL: open failed: ", fd);
        return;
    }

    let mut buf = [0u8; 4];
    let iov: [IoVec; 1] = [IoVec {
        iov_base: buf.as_mut_ptr(),
        iov_len: buf.len(),
    }];

    // Use invalid flag (bit not in RWF_SUPPORTED)
    let invalid_flags = 0x1000; // Not a valid RWF flag
    let ret = sys_preadv2(fd as i32, iov.as_ptr(), 1, 0, invalid_flags);

    sys_close(fd as u64);

    if ret == -95 {
        // EOPNOTSUPP = 95
        pass(b"PREADV2_INVALID_FLAGS");
    } else {
        fail_num(
            b"PREADV2_INVALID_FLAGS:FAIL: expected -95 (EOPNOTSUPP), got ",
            ret,
        );
    }
}

/// preadv2() with RWF_NOWAIT on a ramfs file is EOPNOTSUPP:
/// ramfs/tmpfs files lack FMODE_NOWAIT (Linux kiocb_set_rw_flags)
fn test_preadv2_rwf_nowait() {
    let path = b"/test.txt\0";
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        fail_num(b"PREADV2_RWF_NOWAIT:FAIL: open failed: ", fd);
        return;
    }

    let mut buf = [0u8; 4];
    let iov: [IoVec; 1] = [IoVec {
        iov_base: buf.as_mut_ptr(),
        iov_len: buf.len(),
    }];
    let ret = sys_preadv2(fd as i32, iov.as_ptr(), 1, 0, RWF_NOWAIT);
    sys_close(fd as u64);

    if ret == -95 {
        pass(b"PREADV2_RWF_NOWAIT");
    } else {
        fail_num(
            b"PREADV2_RWF_NOWAIT:FAIL: expected -95 (EOPNOTSUPP), got ",
            ret,
        );
    }
}

/// preadv2() with RWF_NOWAIT on empty pipe returns EAGAIN
fn test_preadv2_rwf_nowait_pipe_eagain() {
    // Create a pipe
    let mut pipefds = [0i32; 2];
    let ret = sys_pipe2(pipefds.as_mut_ptr(), 0);
    if ret < 0 {
        fail_num(b"PREADV2_NOWAIT_PIPE:FAIL: pipe2 failed: ", ret);
        return;
    }

    let read_fd = pipefds[0];
    let write_fd = pipefds[1];

    // Try to read from empty pipe with RWF_NOWAIT
    let mut buf = [0u8; 4];
    let iov: [IoVec; 1] = [IoVec {
        iov_base: buf.as_mut_ptr(),
        iov_len: buf.len(),
    }];

    // Use offset=-1 for pipe (pipes don't support positioned I/O)
    let ret = sys_preadv2(read_fd, iov.as_ptr(), 1, -1, RWF_NOWAIT);

    sys_close(read_fd as u64);
    sys_close(write_fd as u64);

    // Should return EAGAIN (-11) since pipe is empty
    if ret == -11 {
        pass(b"PREADV2_NOWAIT_PIPE");
    } else if ret == -95 {
        print(b"PREADV2_NOWAIT_PIPE:FAIL: got EOPNOTSUPP, but pipe should support NOWAIT");
        println(b"");
    } else {
        fail_num(
            b"PREADV2_NOWAIT_PIPE:FAIL: expected -11 (EAGAIN), got ",
            ret,
        );
    }
}

// =============================================================================
// statfs/fstatfs/statx tests
// =============================================================================

/// statfs() on root filesystem
fn test_statfs_root() {
    let mut buf: LinuxStatFs = unsafe { core::mem::zeroed() };
    let path = b"/\0";

    let ret = sys_statfs(path.as_ptr(), &mut buf);
    if ret != 0 {
        fail_num(b"STATFS_ROOT:FAIL: statfs returned ", ret);
        return;
    }

    // Verify we got valid data (ramfs magic; Linux's initramfs root is tmpfs)
    if buf.f_type != RAMFS_MAGIC && !(host_mode() && buf.f_type == TMPFS_MAGIC) {
        print(b"STATFS_ROOT:FAIL: expected ramfs magic ");
        print_num(RAMFS_MAGIC);
        print(b", got ");
        print_num(buf.f_type);
        println(b"");
        return;
    }

    // Block size should be positive
    if buf.f_bsize <= 0 {
        fail_num(b"STATFS_ROOT:FAIL: invalid block size ", buf.f_bsize);
        return;
    }

    // Max filename length should be positive
    if buf.f_namelen <= 0 {
        fail_num(b"STATFS_ROOT:FAIL: invalid namelen ", buf.f_namelen);
        return;
    }

    pass(b"STATFS_ROOT");
}

/// statfs() on /proc filesystem
fn test_statfs_proc() {
    let mut buf: LinuxStatFs = unsafe { core::mem::zeroed() };
    let path = b"/proc\0";

    let ret = sys_statfs(path.as_ptr(), &mut buf);
    if ret != 0 {
        fail_num(b"STATFS_PROC:FAIL: statfs returned ", ret);
        return;
    }

    // Verify we got procfs magic
    if buf.f_type != PROC_SUPER_MAGIC {
        print(b"STATFS_PROC:FAIL: expected procfs magic ");
        print_num(PROC_SUPER_MAGIC);
        print(b", got ");
        print_num(buf.f_type);
        println(b"");
        return;
    }

    pass(b"STATFS_PROC");
}

/// statfs() on nonexistent path returns -ENOENT
fn test_statfs_enoent() {
    let mut buf: LinuxStatFs = unsafe { core::mem::zeroed() };
    let path = b"/nonexistent_path_12345\0";

    let ret = sys_statfs(path.as_ptr(), &mut buf);
    if ret == -2 {
        // ENOENT = 2
        pass(b"STATFS_ENOENT");
    } else {
        fail_num(b"STATFS_ENOENT:FAIL: expected -2 (ENOENT), got ", ret);
    }
}

/// fstatfs() on open file descriptor
fn test_fstatfs() {
    // Open a file
    let path = b"/test.txt\0";
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        fail_num(b"FSTATFS:FAIL: open failed: ", fd);
        return;
    }

    let mut buf: LinuxStatFs = unsafe { core::mem::zeroed() };
    let ret = sys_fstatfs(fd as i32, &mut buf);
    sys_close(fd as u64);

    if ret != 0 {
        fail_num(b"FSTATFS:FAIL: fstatfs returned ", ret);
        return;
    }

    // Verify we got ramfs magic (root fs; tmpfs on a Linux host)
    if buf.f_type != RAMFS_MAGIC && !(host_mode() && buf.f_type == TMPFS_MAGIC) {
        fail_num(b"FSTATFS:FAIL: expected ramfs magic, got ", buf.f_type);
        return;
    }

    pass(b"FSTATFS");
}

/// statx() basic usage
fn test_statx_basic() {
    let mut buf: Statx = unsafe { core::mem::zeroed() };
    let path = b"/test.txt\0";

    let ret = sys_statx(AT_FDCWD, path.as_ptr(), 0, STATX_BASIC_STATS, &mut buf);
    if ret != 0 {
        fail_num(b"STATX_BASIC:FAIL: statx returned ", ret);
        return;
    }

    // Verify basic stats returned
    if buf.stx_mask & STATX_BASIC_STATS == 0 {
        fail_num(
            b"STATX_BASIC:FAIL: stx_mask missing BASIC_STATS: ",
            buf.stx_mask as i64,
        );
        return;
    }

    // Size should be positive (test.txt has content)
    if buf.stx_size == 0 {
        println(b"STATX_BASIC:FAIL: stx_size is 0");
        return;
    }

    // Inode should be non-zero
    if buf.stx_ino == 0 {
        println(b"STATX_BASIC:FAIL: stx_ino is 0");
        return;
    }

    // Mode should indicate regular file (S_IFREG = 0o100000)
    let s_ifreg: u16 = 0o100000;
    if buf.stx_mode & s_ifreg != s_ifreg {
        fail_num(
            b"STATX_BASIC:FAIL: not a regular file, mode=",
            buf.stx_mode as i64,
        );
        return;
    }

    pass(b"STATX_BASIC");
}

/// statx() with AT_EMPTY_PATH on fd
fn test_statx_at_empty_path() {
    // Open a file
    let path = b"/test.txt\0";
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        fail_num(b"STATX_EMPTY_PATH:FAIL: open failed: ", fd);
        return;
    }

    let mut buf: Statx = unsafe { core::mem::zeroed() };
    let empty = b"\0";

    // statx on the fd itself using AT_EMPTY_PATH
    let ret = sys_statx(
        fd as i32,
        empty.as_ptr(),
        AT_EMPTY_PATH,
        STATX_BASIC_STATS,
        &mut buf,
    );
    sys_close(fd as u64);

    if ret != 0 {
        fail_num(b"STATX_EMPTY_PATH:FAIL: statx returned ", ret);
        return;
    }

    // Verify we got stats
    if buf.stx_mask & STATX_BASIC_STATS == 0 {
        fail_num(
            b"STATX_EMPTY_PATH:FAIL: stx_mask missing BASIC_STATS: ",
            buf.stx_mask as i64,
        );
        return;
    }

    // Size should be positive
    if buf.stx_size == 0 {
        println(b"STATX_EMPTY_PATH:FAIL: stx_size is 0");
        return;
    }

    pass(b"STATX_EMPTY_PATH");
}

/// Test ioctl FIONBIO - set non-blocking mode
fn test_ioctl_fionbio() {
    // Create a pipe to test on (pipes support non-blocking mode)
    let mut pipefd: [i32; 2] = [0; 2];
    let ret = sys_pipe2(pipefd.as_mut_ptr(), 0);
    if ret < 0 {
        fail_num(b"IOCTL_FIONBIO:FAIL: pipe2 returned ", ret);
        return;
    }

    // Get initial flags
    let flags = sys_fcntl(pipefd[0], 3, 0); // F_GETFL = 3
    if flags < 0 {
        sys_close(pipefd[0] as u64);
        sys_close(pipefd[1] as u64);
        fail_num(b"IOCTL_FIONBIO:FAIL: fcntl(F_GETFL) returned ", flags);
        return;
    }

    // Set non-blocking mode via FIONBIO
    let enable: i32 = 1;
    let ret = sys_ioctl(pipefd[0], FIONBIO as u64, &enable as *const i32 as u64);
    if ret != 0 {
        sys_close(pipefd[0] as u64);
        sys_close(pipefd[1] as u64);
        fail_num(b"IOCTL_FIONBIO:FAIL: ioctl(FIONBIO, 1) returned ", ret);
        return;
    }

    // Verify via fcntl that O_NONBLOCK is set
    let new_flags = sys_fcntl(pipefd[0], 3, 0); // F_GETFL = 3
    let has_nonblock = (new_flags as u32 & O_NONBLOCK) != 0;

    // Clear non-blocking mode
    let disable: i32 = 0;
    let ret = sys_ioctl(pipefd[0], FIONBIO as u64, &disable as *const i32 as u64);

    // Verify O_NONBLOCK is cleared
    let final_flags = sys_fcntl(pipefd[0], 3, 0); // F_GETFL = 3
    let still_has_nonblock = (final_flags as u32 & O_NONBLOCK) != 0;

    sys_close(pipefd[0] as u64);
    sys_close(pipefd[1] as u64);

    if has_nonblock && !still_has_nonblock && ret == 0 {
        pass(b"IOCTL_FIONBIO");
    } else {
        print(b"IOCTL_FIONBIO:FAIL: has_nb=");
        print_num(has_nonblock as i64);
        print(b", still_has_nb=");
        print_num(still_has_nonblock as i64);
        println(b"");
    }
}

/// Test ioctl FIOCLEX/FIONCLEX - set/clear close-on-exec
fn test_ioctl_fioclex() {
    // Create a pipe to test on (avoids file system dependencies)
    let mut pipefd: [i32; 2] = [0; 2];
    let ret = sys_pipe2(pipefd.as_mut_ptr(), 0);
    if ret < 0 {
        fail_num(b"IOCTL_FIOCLEX:FAIL: pipe2 returned ", ret);
        return;
    }
    let fd = pipefd[0] as i64; // Use read end of pipe

    // Get initial fd flags (should not have FD_CLOEXEC)
    let flags1 = sys_fcntl(fd as i32, F_GETFD, 0);
    let initially_cloexec = (flags1 as u64 & FD_CLOEXEC) != 0;

    // Set close-on-exec via FIOCLEX
    let ret = sys_ioctl(fd as i32, FIOCLEX as u64, 0);
    if ret != 0 {
        sys_close(fd as u64);
        fail_num(b"IOCTL_FIOCLEX:FAIL: ioctl(FIOCLEX) returned ", ret);
        return;
    }

    // Verify FD_CLOEXEC is set
    let flags2 = sys_fcntl(fd as i32, F_GETFD, 0);
    let has_cloexec = (flags2 as u64 & FD_CLOEXEC) != 0;

    // Clear close-on-exec via FIONCLEX
    let ret = sys_ioctl(fd as i32, FIONCLEX as u64, 0);
    if ret != 0 {
        sys_close(fd as u64);
        fail_num(b"IOCTL_FIOCLEX:FAIL: ioctl(FIONCLEX) returned ", ret);
        return;
    }

    // Verify FD_CLOEXEC is cleared
    let flags3 = sys_fcntl(fd as i32, F_GETFD, 0);
    let still_cloexec = (flags3 as u64 & FD_CLOEXEC) != 0;

    sys_close(fd as u64);
    sys_close(pipefd[1] as u64);

    if !initially_cloexec && has_cloexec && !still_cloexec {
        pass(b"IOCTL_FIOCLEX");
    } else {
        print(b"IOCTL_FIOCLEX:FAIL: init=");
        print_num(initially_cloexec as i64);
        print(b", has=");
        print_num(has_cloexec as i64);
        print(b", still=");
        print_num(still_cloexec as i64);
        println(b"");
    }
}

/// Shrinking a file then growing it again reads zeros where the cut
/// data was, also inside the last page kept (Linux truncate_setsize
/// zeroes the partial page)
fn test_trunc_tail() {
    let path = b"/tmp/trunc_tail\0";
    let fd = sys_open(path.as_ptr(), O_CREAT | O_RDWR | O_TRUNC, 0o644) as i32;
    let mut buf = [b'a'; 8192];
    let w = sys_pwrite64(fd, buf.as_ptr(), buf.len() as u64, 0);
    let t1 = sys_ftruncate(fd, 100);
    let t2 = sys_ftruncate(fd, 8192);
    buf.fill(b'x');
    let n = sys_pread64(fd, buf.as_mut_ptr(), buf.len() as u64, 0);
    sys_close(fd as u64);
    sys_unlink(path.as_ptr());
    let ok = w == 8192
        && t1 == 0
        && t2 == 0
        && n == 8192
        && buf[..100].iter().all(|&c| c == b'a')
        && buf[100..].iter().all(|&c| c == 0);
    if ok {
        pass(b"TRUNC_TAIL_ZERO");
    } else {
        print(b"TRUNC_TAIL_ZERO:FAIL n=");
        print_num(n);
        print(b" byte100=");
        print_num(buf[100] as i64);
        println(b"");
    }
}

/// A write whose source is a not yet faulted-in shared mapping of the
/// very page it writes (and then of another page of the file): the
/// source fault must not wait on the page lock the write holds (Linux
/// generic_perform_write faults the source in before locking)
fn test_write_own_map() {
    let path = b"/tmp/write_own_map\0";
    let fd = sys_open(path.as_ptr(), O_CREAT | O_RDWR | O_TRUNC, 0o644) as i32;
    let mut buf = [b'a'; 8192];
    buf[4096..].fill(b'b');
    let w = sys_pwrite64(fd, buf.as_ptr(), 8192, 0);
    let map = sys_mmap(0, 8192, PROT_READ, MAP_SHARED, fd, 0);
    let (w1, w2) = if map > 0 {
        let m = map as u64;
        let w1 = sys_pwrite64(fd, m as *const u8, 4096, 0);
        let w2 = sys_pwrite64(fd, (m + 4096) as *const u8, 4096, 0);
        sys_munmap(m, 8192);
        (w1, w2)
    } else {
        (map, map)
    };
    buf.fill(0);
    let n = sys_pread64(fd, buf.as_mut_ptr(), 8192, 0);
    sys_close(fd as u64);
    sys_unlink(path.as_ptr());
    if w == 8192 && w1 == 4096 && w2 == 4096 && n == 8192 && buf.iter().all(|&c| c == b'b') {
        pass(b"WRITE_OWN_MAP");
    } else {
        print(b"WRITE_OWN_MAP:FAIL w1=");
        print_num(w1);
        print(b" w2=");
        print_num(w2);
        print(b" n=");
        print_num(n);
        println(b"");
    }
}

/// writev/readv whose second segment is unreadable/unwritable memory
/// move the first segment and return its length; readv advances the
/// position by just that
fn test_iov_partial_fault() {
    let path = b"/tmp/iov_partial\0";
    let fd = sys_open(path.as_ptr(), O_CREAT | O_RDWR | O_TRUNC, 0o644) as i32;
    let bad = sys_mmap(0, 4096, 0, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    let data = [b'c'; 10];
    let mut back = [0u8; 10];
    let mut w = -1;
    let mut r = -1;
    let mut pos = -1;
    if bad > 0 {
        let iov = [
            IoVec {
                iov_base: data.as_ptr(),
                iov_len: data.len(),
            },
            IoVec {
                iov_base: bad as *const u8,
                iov_len: 100,
            },
        ];
        w = sys_writev(fd as u64, iov.as_ptr(), 2);
        let pad = [b'd'; 100];
        sys_write(fd as u64, pad.as_ptr(), pad.len() as u64);
        sys_lseek(fd, 0, 0);
        let iov = [
            IoVec {
                iov_base: back.as_mut_ptr(),
                iov_len: back.len(),
            },
            IoVec {
                iov_base: bad as *const u8,
                iov_len: 100,
            },
        ];
        r = sys_readv(fd as u64, iov.as_ptr(), 2);
        pos = sys_lseek(fd, 0, 1);
        sys_munmap(bad as u64, 4096);
    }
    sys_close(fd as u64);
    sys_unlink(path.as_ptr());
    if w == 10 && r == 10 && pos == 10 && back == data {
        pass(b"IOV_PARTIAL_FAULT");
    } else {
        print(b"IOV_PARTIAL_FAULT:FAIL w=");
        print_num(w);
        print(b" r=");
        print_num(r);
        print(b" pos=");
        print_num(pos);
        println(b"");
    }
}

/// read and write whose single buffer starts 2048 bytes before an
/// unmapped page: the mapped 2048 bytes move and that count returns
/// (Linux copy_to_iter / copy_page_from_iter_atomic report partial
/// copies). A pipe read is EFAULT instead and consumes nothing (Linux
/// pipe_read): the data is still there for a good buffer
fn test_rw_straddle() {
    let path = b"/tmp/rw_straddle\0";
    let fd = sys_open(path.as_ptr(), O_CREAT | O_RDWR | O_TRUNC, 0o644) as i32;
    let fill = [b'x'; 8192];
    sys_write(fd as u64, fill.as_ptr(), fill.len() as u64);
    let base = sys_mmap(0, 8192, 3, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    let (mut r, mut w, mut pr) = (-1, -1, -1);
    if base > 0 {
        sys_munmap(base as u64 + 4096, 4096);
        let p = (base as u64 + 2048) as *mut u8;
        sys_lseek(fd, 0, 0);
        r = sys_read(fd as u64, p, 4096);
        // SAFETY: p..p+2048 is mapped
        let got = unsafe { core::slice::from_raw_parts(p, 2048) };
        if !got.iter().all(|&b| b == b'x') {
            r = -100;
        }
        sys_lseek(fd, 0, 0);
        w = sys_write(fd as u64, p, 4096);
        let mut pfd = [0i32; 2];
        if sys_pipe2(pfd.as_mut_ptr(), 0) == 0 {
            sys_write(pfd[1] as u64, fill.as_ptr(), 4096);
            pr = sys_read(pfd[0] as u64, p, 4096);
            let mut good = [0u8; 4096];
            if sys_read(pfd[0] as u64, good.as_mut_ptr(), 4096) != 4096 {
                pr = -200;
            }
            sys_close(pfd[0] as u64);
            sys_close(pfd[1] as u64);
        }
        sys_munmap(base as u64, 4096);
    }
    sys_close(fd as u64);
    sys_unlink(path.as_ptr());
    if r == 2048 && w == 2048 && pr == -14 {
        pass(b"RW_STRADDLE");
    } else {
        print(b"RW_STRADDLE:FAIL read=");
        print_num(r);
        print(b" write=");
        print_num(w);
        print(b" pipe read=");
        print_num(pr);
        println(b"");
    }
}

/// writev to a sysctl whose second segment is unmapped: Linux copies a
/// store's data whole or not at all (EFAULT), so "12" alone is never
/// stored
fn test_sysctl_partial_fault() {
    let path = b"/proc/sys/vm/dirty_expire_centisecs\0";
    let fd = sys_open(path.as_ptr(), O_RDWR, 0) as i32;
    let mut before = [0u8; 32];
    let nb = sys_read(fd as u64, before.as_mut_ptr(), 32);
    let bad = sys_mmap(0, 4096, 0, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    let head = *b"12";
    let iov = [
        IoVec {
            iov_base: head.as_ptr(),
            iov_len: 2,
        },
        IoVec {
            iov_base: bad as *const u8,
            iov_len: 3,
        },
    ];
    let w = sys_writev(fd as u64, iov.as_ptr(), 2);
    let mut after = [0u8; 32];
    sys_lseek(fd, 0, 0);
    let na = sys_read(fd as u64, after.as_mut_ptr(), 32);
    sys_munmap(bad as u64, 4096);
    sys_close(fd as u64);
    if fd >= 0 && w == -14 && nb > 0 && na == nb && before == after {
        pass(b"SYSCTL_PARTIAL_FAULT");
    } else {
        print(b"SYSCTL_PARTIAL_FAULT:FAIL writev=");
        print_num(w);
        print(b" before/after len ");
        print_num(nb);
        print(b" ");
        print_num(na);
        println(b"");
    }
}

/// RWF_NOWAIT on files Linux marks FMODE_NOWAIT (eventfd, timerfd,
/// sockets): an empty one is EAGAIN without blocking
fn test_rwf_nowait_streams() {
    let mut buf = [0u8; 8];
    let iov = [IoVec {
        iov_base: buf.as_mut_ptr(),
        iov_len: 8,
    }];
    let efd = hk_syscall::sys_eventfd2(0, 0);
    let e = sys_preadv2(efd as i32, iov.as_ptr(), 1, -1, RWF_NOWAIT);
    sys_close(efd as u64);
    let tfd = hk_syscall::sys_timerfd_create(1, 0);
    let t = sys_preadv2(tfd as i32, iov.as_ptr(), 1, -1, RWF_NOWAIT);
    sys_close(tfd as u64);
    let mut sv = [0i32; 2];
    hk_syscall::sys_socketpair(1, 1, 0, &mut sv);
    let k = sys_preadv2(sv[0], iov.as_ptr(), 1, -1, RWF_NOWAIT);
    sys_close(sv[0] as u64);
    sys_close(sv[1] as u64);
    // timerfd took RWF_NOWAIT in Linux 6.10 (read_iter); before, the
    // flag is EOPNOTSUPP there (hk follows current Linux)
    let t_want = if crate::helpers::linux_at_least(6, 10) {
        -11
    } else {
        -95
    };
    if e == -11 && t == t_want && k == -11 {
        pass(b"RWF_NOWAIT_STREAMS");
    } else {
        print(b"RWF_NOWAIT_STREAMS:FAIL eventfd ");
        print_num(e);
        print(b" timerfd ");
        print_num(t);
        print(b" socket ");
        print_num(k);
        println(b"");
    }
}
