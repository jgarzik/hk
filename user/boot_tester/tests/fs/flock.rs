//! flock, fallocate, and copy_file_range tests
//!
//! Tests:
//! - Test flock with LOCK_EX and LOCK_UN
//! - Test flock with LOCK_SH
//! - Test flock with LOCK_NB on locked file
//! - Test flock returns EBADF for invalid fd
//! - FLOCK_RELEASE_EXIT: a lock is gone once its holder exits (the last
//!   descriptor of its open file closes, Linux locks_remove_file)
//! - FLOCK_OFD: the lock belongs to the open file description: a forked
//!   child's inherited descriptor holds it too, a separate open in the
//!   child conflicts
//! - FLOCK_HARDLINK: a lock taken through one name of a file conflicts
//!   with one through a hard link to it (Linux keys flock on the inode)
//! - Test fallocate extends file
//! - Test fallocate with FALLOC_FL_KEEP_SIZE
//! - Test fallocate returns EBADF for invalid fd
//! - Test copy_file_range basic copy
//! - Test copy_file_range with offset pointers
//! - Test copy_file_range returns EBADF for invalid fd

use crate::tests::helpers::{print, print_num, println};
use hk_syscall::{
    O_CREAT, O_RDWR, O_TRUNC, SEEK_END, SEEK_SET, sys_close, sys_copy_file_range, sys_fallocate,
    sys_flock, sys_lseek, sys_mkdir, sys_open, sys_read, sys_write,
};

// flock operations (from Linux include/uapi/asm-generic/fcntl.h)
const LOCK_SH: i32 = 1; // Shared lock
const LOCK_EX: i32 = 2; // Exclusive lock
const LOCK_NB: i32 = 4; // Non-blocking
const LOCK_UN: i32 = 8; // Unlock

// fallocate modes (from Linux include/uapi/linux/falloc.h)
const FALLOC_FL_KEEP_SIZE: i32 = 0x01;

// Error codes
const EBADF: i64 = -9;

/// Run all flock/fallocate/copy_file_range tests
pub fn run_tests() {
    // Create /tmp directory for test files (ignore error if exists)
    let _ = sys_mkdir(b"/tmp\0".as_ptr(), 0o755);

    test_flock_exclusive();
    test_flock_shared();
    test_flock_nonblock();
    test_flock_release_exit();
    test_flock_ofd();
    test_flock_hardlink();
    test_flock_ebadf();
    test_fallocate_extend();
    test_fallocate_keep_size();
    test_fallocate_ebadf();
    test_copy_file_range_basic();
    test_copy_file_range_with_offsets();
    test_copy_file_range_ebadf();
}

/// Test flock with LOCK_EX and LOCK_UN
fn test_flock_exclusive() {
    let path = b"/tmp/flock_test\0";

    // Create test file
    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    if fd < 0 {
        print(b"FLOCK_EXCLUSIVE:FAIL: open returned ");
        print_num(fd);
        return;
    }

    // Acquire exclusive lock
    let ret = sys_flock(fd as i32, LOCK_EX);
    if ret != 0 {
        print(b"FLOCK_EXCLUSIVE:FAIL: flock(LOCK_EX) returned ");
        print_num(ret);
        sys_close(fd as u64);
        return;
    }

    // Release lock
    let ret = sys_flock(fd as i32, LOCK_UN);
    if ret != 0 {
        print(b"FLOCK_EXCLUSIVE:FAIL: flock(LOCK_UN) returned ");
        print_num(ret);
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    println(b"FLOCK_EXCLUSIVE:OK");
}

/// Test flock with LOCK_SH
fn test_flock_shared() {
    let path = b"/tmp/flock_shared_test\0";

    // Create test file
    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    if fd < 0 {
        print(b"FLOCK_SHARED:FAIL: open returned ");
        print_num(fd);
        return;
    }

    // Acquire shared lock
    let ret = sys_flock(fd as i32, LOCK_SH);
    if ret != 0 {
        print(b"FLOCK_SHARED:FAIL: flock(LOCK_SH) returned ");
        print_num(ret);
        sys_close(fd as u64);
        return;
    }

    // Release lock
    let ret = sys_flock(fd as i32, LOCK_UN);
    if ret != 0 {
        print(b"FLOCK_SHARED:FAIL: flock(LOCK_UN) returned ");
        print_num(ret);
        sys_close(fd as u64);
        return;
    }

    sys_close(fd as u64);
    println(b"FLOCK_SHARED:OK");
}

/// Test flock with LOCK_NB on locked file
fn test_flock_nonblock() {
    let path = b"/tmp/flock_nb_test\0";

    // Create test file
    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    if fd < 0 {
        print(b"FLOCK_NONBLOCK:FAIL: open returned ");
        print_num(fd);
        return;
    }

    // Acquire exclusive lock
    let ret = sys_flock(fd as i32, LOCK_EX);
    if ret != 0 {
        print(b"FLOCK_NONBLOCK:FAIL: flock(LOCK_EX) returned ");
        print_num(ret);
        sys_close(fd as u64);
        return;
    }

    // Try to acquire exclusive lock again with LOCK_NB - should succeed (same process)
    let ret = sys_flock(fd as i32, LOCK_EX | LOCK_NB);
    if ret != 0 {
        print(b"FLOCK_NONBLOCK:FAIL: flock(LOCK_EX|LOCK_NB) on same fd returned ");
        print_num(ret);
        sys_close(fd as u64);
        return;
    }

    // Release lock
    let _ = sys_flock(fd as i32, LOCK_UN);
    sys_close(fd as u64);
    println(b"FLOCK_NONBLOCK:OK");
}

/// Test flock returns EBADF for invalid fd
fn test_flock_ebadf() {
    let ret = sys_flock(9999, LOCK_EX);
    if ret == EBADF {
        println(b"FLOCK_EBADF:OK");
    } else {
        print(b"FLOCK_EBADF:FAIL: expected -9, got ");
        print_num(ret);
    }
}

/// Test fallocate extends file
fn test_fallocate_extend() {
    let path = b"/tmp/fallocate_test\0";

    // Create test file
    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    if fd < 0 {
        print(b"FALLOCATE_EXTEND:FAIL: open returned ");
        print_num(fd);
        return;
    }

    // Allocate 1024 bytes starting at offset 0
    let ret = sys_fallocate(fd as i32, 0, 0, 1024);
    if ret != 0 {
        print(b"FALLOCATE_EXTEND:FAIL: fallocate returned ");
        print_num(ret);
        sys_close(fd as u64);
        return;
    }

    // Check file size using lseek to SEEK_END
    let size = sys_lseek(fd as i32, 0, SEEK_END);
    if size < 0 {
        print(b"FALLOCATE_EXTEND:FAIL: lseek returned ");
        print_num(size);
        sys_close(fd as u64);
        return;
    }

    if size == 1024 {
        println(b"FALLOCATE_EXTEND:OK");
    } else {
        print(b"FALLOCATE_EXTEND:FAIL: expected size 1024, got ");
        print_num(size);
    }

    sys_close(fd as u64);
}

/// Test fallocate with FALLOC_FL_KEEP_SIZE
fn test_fallocate_keep_size() {
    let path = b"/tmp/fallocate_keep_size_test\0";

    // Create test file with some data
    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    if fd < 0 {
        print(b"FALLOCATE_KEEP_SIZE:FAIL: open returned ");
        print_num(fd);
        return;
    }

    // Write some initial data
    let data = b"hello";
    let ret = sys_write(fd as u64, data.as_ptr(), data.len() as u64);
    if ret < 0 {
        print(b"FALLOCATE_KEEP_SIZE:FAIL: write returned ");
        print_num(ret);
        sys_close(fd as u64);
        return;
    }

    // Allocate more space but keep size
    let ret = sys_fallocate(fd as i32, FALLOC_FL_KEEP_SIZE, 0, 1024);
    if ret != 0 {
        print(b"FALLOCATE_KEEP_SIZE:FAIL: fallocate returned ");
        print_num(ret);
        sys_close(fd as u64);
        return;
    }

    // Check file size using lseek to SEEK_END (should still be 5, not 1024)
    let size = sys_lseek(fd as i32, 0, SEEK_END);
    if size < 0 {
        print(b"FALLOCATE_KEEP_SIZE:FAIL: lseek returned ");
        print_num(size);
        sys_close(fd as u64);
        return;
    }

    if size == 5 {
        println(b"FALLOCATE_KEEP_SIZE:OK");
    } else {
        print(b"FALLOCATE_KEEP_SIZE:FAIL: expected size 5, got ");
        print_num(size);
    }

    sys_close(fd as u64);
}

/// Test fallocate returns EBADF for invalid fd
fn test_fallocate_ebadf() {
    let ret = sys_fallocate(9999, 0, 0, 1024);
    if ret == EBADF {
        println(b"FALLOCATE_EBADF:OK");
    } else {
        print(b"FALLOCATE_EBADF:FAIL: expected -9, got ");
        print_num(ret);
    }
}

/// Test copy_file_range basic copy
fn test_copy_file_range_basic() {
    let src_path = b"/tmp/copy_src\0";
    let dst_path = b"/tmp/copy_dst\0";
    let test_data = b"Hello, copy_file_range!";

    // Create source file with test data
    let src_fd = sys_open(src_path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    if src_fd < 0 {
        print(b"COPY_FILE_RANGE_BASIC:FAIL: open src returned ");
        print_num(src_fd);
        return;
    }

    let ret = sys_write(src_fd as u64, test_data.as_ptr(), test_data.len() as u64);
    if ret < 0 {
        print(b"COPY_FILE_RANGE_BASIC:FAIL: write returned ");
        print_num(ret);
        sys_close(src_fd as u64);
        return;
    }

    // Reset src position to start
    sys_lseek(src_fd as i32, 0, SEEK_SET);

    // Create destination file
    let dst_fd = sys_open(dst_path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    if dst_fd < 0 {
        print(b"COPY_FILE_RANGE_BASIC:FAIL: open dst returned ");
        print_num(dst_fd);
        sys_close(src_fd as u64);
        return;
    }

    // Copy data using copy_file_range (NULL offsets = use file positions)
    let ret = sys_copy_file_range(
        src_fd as i32,
        core::ptr::null_mut(),
        dst_fd as i32,
        core::ptr::null_mut(),
        test_data.len(),
        0,
    );

    if ret < 0 {
        print(b"COPY_FILE_RANGE_BASIC:FAIL: copy_file_range returned ");
        print_num(ret);
        sys_close(src_fd as u64);
        sys_close(dst_fd as u64);
        return;
    }

    if ret as usize != test_data.len() {
        print(b"COPY_FILE_RANGE_BASIC:FAIL: expected ");
        print_num(test_data.len() as i64);
        print(b" bytes, got ");
        print_num(ret);
        sys_close(src_fd as u64);
        sys_close(dst_fd as u64);
        return;
    }

    // Read back from destination
    let mut buf = [0u8; 32];
    sys_lseek(dst_fd as i32, 0, SEEK_SET);
    let ret = sys_read(dst_fd as u64, buf.as_mut_ptr(), buf.len() as u64);
    if ret < 0 {
        print(b"COPY_FILE_RANGE_BASIC:FAIL: read returned ");
        print_num(ret);
        sys_close(src_fd as u64);
        sys_close(dst_fd as u64);
        return;
    }

    if ret as usize == test_data.len() && &buf[..test_data.len()] == test_data {
        println(b"COPY_FILE_RANGE_BASIC:OK");
    } else {
        print(b"COPY_FILE_RANGE_BASIC:FAIL: data mismatch, read ");
        print_num(ret);
        print(b" bytes\n");
    }

    sys_close(src_fd as u64);
    sys_close(dst_fd as u64);
}

/// Test copy_file_range with offset pointers
fn test_copy_file_range_with_offsets() {
    let src_path = b"/tmp/copy_off_src\0";
    let dst_path = b"/tmp/copy_off_dst\0";
    let test_data = b"ABCDEFGHIJKLMNOP";

    // Create source file with test data
    let src_fd = sys_open(src_path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    if src_fd < 0 {
        print(b"COPY_FILE_RANGE_OFFSETS:FAIL: open src returned ");
        print_num(src_fd);
        return;
    }

    let ret = sys_write(src_fd as u64, test_data.as_ptr(), test_data.len() as u64);
    if ret < 0 {
        print(b"COPY_FILE_RANGE_OFFSETS:FAIL: write returned ");
        print_num(ret);
        sys_close(src_fd as u64);
        return;
    }

    // Create destination file
    let dst_fd = sys_open(dst_path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    if dst_fd < 0 {
        print(b"COPY_FILE_RANGE_OFFSETS:FAIL: open dst returned ");
        print_num(dst_fd);
        sys_close(src_fd as u64);
        return;
    }

    // Copy 8 bytes starting at offset 4 in source
    let mut off_in: u64 = 4;
    let mut off_out: u64 = 0;
    let ret = sys_copy_file_range(
        src_fd as i32,
        &mut off_in as *mut u64,
        dst_fd as i32,
        &mut off_out as *mut u64,
        8,
        0,
    );

    if ret < 0 {
        print(b"COPY_FILE_RANGE_OFFSETS:FAIL: copy_file_range returned ");
        print_num(ret);
        sys_close(src_fd as u64);
        sys_close(dst_fd as u64);
        return;
    }

    if ret != 8 {
        print(b"COPY_FILE_RANGE_OFFSETS:FAIL: expected 8 bytes, got ");
        print_num(ret);
        sys_close(src_fd as u64);
        sys_close(dst_fd as u64);
        return;
    }

    // Check that offsets were updated
    if off_in != 12 || off_out != 8 {
        print(b"COPY_FILE_RANGE_OFFSETS:FAIL: offsets not updated, off_in=");
        print_num(off_in as i64);
        print(b" off_out=");
        print_num(off_out as i64);
        sys_close(src_fd as u64);
        sys_close(dst_fd as u64);
        return;
    }

    // Read back from destination - should be "EFGHIJKL"
    let mut buf = [0u8; 16];
    sys_lseek(dst_fd as i32, 0, SEEK_SET);
    let ret = sys_read(dst_fd as u64, buf.as_mut_ptr(), 8);
    if ret < 0 {
        print(b"COPY_FILE_RANGE_OFFSETS:FAIL: read returned ");
        print_num(ret);
        sys_close(src_fd as u64);
        sys_close(dst_fd as u64);
        return;
    }

    if &buf[..8] == b"EFGHIJKL" {
        println(b"COPY_FILE_RANGE_OFFSETS:OK");
    } else {
        print(b"COPY_FILE_RANGE_OFFSETS:FAIL: data mismatch\n");
    }

    sys_close(src_fd as u64);
    sys_close(dst_fd as u64);
}

/// Test copy_file_range returns EBADF for invalid fd
fn test_copy_file_range_ebadf() {
    let ret = sys_copy_file_range(
        9999,
        core::ptr::null_mut(),
        9998,
        core::ptr::null_mut(),
        100,
        0,
    );
    if ret == EBADF {
        println(b"COPY_FILE_RANGE_EBADF:OK");
    } else {
        print(b"COPY_FILE_RANGE_EBADF:FAIL: expected -9, got ");
        print_num(ret);
    }
}

fn test_flock_release_exit() {
    use hk_syscall::{sys_exit, sys_fork, sys_wait4};
    let path = b"/tmp/flock_exit_test\0";
    let pid = sys_fork();
    if pid == 0 {
        let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT, 0o644);
        sys_exit(if fd >= 0 && sys_flock(fd as i32, LOCK_EX) == 0 {
            0
        } else {
            1
        });
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT, 0o644);
    let r = sys_flock(fd as i32, LOCK_EX | LOCK_NB);
    sys_close(fd as u64);
    if st == 0 && r == 0 {
        println(b"FLOCK_RELEASE_EXIT:OK");
    } else {
        print(b"FLOCK_RELEASE_EXIT:FAIL got ");
        print_num(r);
        println(b"");
    }
}

fn test_flock_ofd() {
    use hk_syscall::{sys_exit, sys_fork, sys_wait4};
    const EWOULDBLOCK: i64 = -11;
    let path = b"/tmp/flock_ofd_test\0";
    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    if fd < 0 || sys_flock(fd as i32, LOCK_EX) != 0 {
        sys_close(fd as u64);
        println(b"FLOCK_OFD:FAIL setup");
        return;
    }
    let pid = sys_fork();
    if pid == 0 {
        let same = sys_flock(fd as i32, LOCK_EX | LOCK_NB);
        let other = sys_open(path.as_ptr(), O_RDWR, 0);
        let conflict = sys_flock(other as i32, LOCK_EX | LOCK_NB);
        sys_exit(if same != 0 {
            1
        } else if conflict != EWOULDBLOCK {
            2
        } else {
            0
        });
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    sys_flock(fd as i32, LOCK_UN);
    sys_close(fd as u64);
    if st == 0 {
        println(b"FLOCK_OFD:OK");
    } else {
        print(b"FLOCK_OFD:FAIL status ");
        print_num(st as i64);
        println(b"");
    }
}

fn test_flock_hardlink() {
    use hk_syscall::{sys_link, sys_unlink};
    const EWOULDBLOCK: i64 = -11;
    let a = b"/tmp/flock_hl_a\0";
    let b = b"/tmp/flock_hl_b\0";
    sys_unlink(b.as_ptr());
    let fa = sys_open(a.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    let linked = sys_link(a.as_ptr(), b.as_ptr());
    let fb = sys_open(b.as_ptr(), O_RDWR, 0);
    let ex = sys_flock(fa as i32, LOCK_EX);
    let other = sys_flock(fb as i32, LOCK_EX | LOCK_NB);
    sys_flock(fa as i32, LOCK_UN);
    sys_close(fa as u64);
    sys_close(fb as u64);
    sys_unlink(a.as_ptr());
    sys_unlink(b.as_ptr());
    if linked == 0 && ex == 0 && other == EWOULDBLOCK {
        println(b"FLOCK_HARDLINK:OK");
    } else {
        print(b"FLOCK_HARDLINK:FAIL got ");
        print_num(other);
        println(b"");
    }
}
