//! Permission tests
//!
//! Tests:
//! - Test 51: chmod() - change file permissions by path
//! - Test 52: fchmod() - change file permissions by fd
//! - Test 53: fchmod() on invalid fd
//! - Test 54: chown() - change file ownership by path
//! - Test 55: fchown() - change file ownership by fd
//! - Test 56: fchown() on invalid fd
//! - Test 57: lchown() - change symlink ownership
//! - Test 58: chown() with -1 to keep existing value
//! - Test 59: umask() - set file creation mask
//! - Test 60: utimensat() - update file timestamps

use super::helpers::{print, println, print_num};
use crate::syscall::{
    sys_chmod, sys_chown, sys_close, sys_fchmod, sys_fchown, sys_lchown, sys_lstat, sys_open,
    sys_stat, sys_symlink, sys_umask, sys_unlink, sys_utimensat, Stat, Timespec, O_CREAT, O_RDONLY,
    O_RDWR, O_WRONLY, UTIME_NOW, UTIME_OMIT,
};

/// Run all permission tests
pub fn run_tests() {
    test_chmod();
    test_fchmod();
    test_fchmod_ebadf();
    test_chown();
    test_fchown();
    test_fchown_ebadf();
    test_lchown();
    test_chown_minus1();
    test_umask();
    test_utimensat();
}

/// Test 51: chmod() - change file permissions by path
fn test_chmod() {

    let chmod_test_file = b"/chmod_test_file\0";
    // Create file with 0644 permissions using O_CREAT
    let fd = sys_open(chmod_test_file.as_ptr(), O_CREAT | O_RDWR, 0o644);
    if fd < 0 {
        print(b"chmod test setup failed: open returned ");
        print_num(fd);
    } else {
        sys_close(fd as u64);

        // Change permissions to 0755
        let ret = sys_chmod(chmod_test_file.as_ptr(), 0o755);
        if ret != 0 {
            print(b"CHMOD:FAIL: chmod returned ");
            print_num(ret);
        } else {
            // Verify with stat
            let mut statbuf: Stat = unsafe { core::mem::zeroed() };
            let ret = sys_stat(chmod_test_file.as_ptr(), &mut statbuf as *mut Stat);
            if ret != 0 {
                print(b"CHMOD:FAIL: stat returned ");
                print_num(ret);
            } else {
                // Check permission bits (lower 12 bits of st_mode)
                let perm = statbuf.st_mode & 0o7777;
                if perm == 0o755 {
                    println(b"CHMOD:OK");
                } else {
                    print(b"CHMOD:FAIL: expected mode 0755, got ");
                    print_num(perm as i64);
                }
            }
        }
        sys_unlink(chmod_test_file.as_ptr());
    }
}

/// Test 52: fchmod() - change file permissions by fd
fn test_fchmod() {

    let fchmod_test_file = b"/fchmod_test_file\0";
    // Create file with 0644 permissions
    let fd = sys_open(fchmod_test_file.as_ptr(), O_CREAT | O_RDWR, 0o644);
    if fd < 0 {
        print(b"fchmod test setup failed: open returned ");
        print_num(fd);
    } else {
        // Change permissions to 0700 via fd
        let ret = sys_fchmod(fd as i32, 0o700);
        if ret != 0 {
            print(b"FCHMOD:FAIL: fchmod returned ");
            print_num(ret);
        } else {
            // Verify with stat
            let mut statbuf: Stat = unsafe { core::mem::zeroed() };
            let ret = sys_stat(fchmod_test_file.as_ptr(), &mut statbuf as *mut Stat);
            if ret != 0 {
                print(b"FCHMOD:FAIL: stat returned ");
                print_num(ret);
            } else {
                // Check permission bits
                let perm = statbuf.st_mode & 0o7777;
                if perm == 0o700 {
                    println(b"FCHMOD:OK");
                } else {
                    print(b"FCHMOD:FAIL: expected mode 0700, got ");
                    print_num(perm as i64);
                }
            }
        }
        sys_close(fd as u64);
        sys_unlink(fchmod_test_file.as_ptr());
    }
}

/// Test 53: fchmod() on invalid fd should fail with EBADF
fn test_fchmod_ebadf() {

    let ret = sys_fchmod(999, 0o755);
    if ret == -9 {
        // EBADF
        println(b"FCHMOD_EBADF:OK");
    } else {
        print(b"FCHMOD_EBADF:FAIL: expected -9 (EBADF), got ");
        print_num(ret);
    }
}

/// Test 54: chown() - change file ownership by path
fn test_chown() {

    let chown_test_file = b"/chown_test_file\0";
    // Create test file
    let fd = sys_open(chown_test_file.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    if fd >= 0 {
        sys_close(fd as u64);

        // Change ownership to uid=1000, gid=1000
        let ret = sys_chown(chown_test_file.as_ptr(), 1000, 1000);
        if ret != 0 {
            print(b"CHOWN:FAIL: chown returned ");
            print_num(ret);
        } else {
            // Verify with stat
            let mut stat_buf: Stat = unsafe { core::mem::zeroed() };
            let ret = sys_stat(chown_test_file.as_ptr(), &mut stat_buf as *mut Stat);
            if ret != 0 {
                print(b"CHOWN:FAIL: stat returned ");
                print_num(ret);
            } else if stat_buf.st_uid == 1000 && stat_buf.st_gid == 1000 {
                println(b"CHOWN:OK");
            } else {
                print(b"CHOWN:FAIL: expected uid=1000 gid=1000, got uid=");
                print_num(stat_buf.st_uid as i64);
                print(b" gid=");
                print_num(stat_buf.st_gid as i64);
            }
        }
        sys_unlink(chown_test_file.as_ptr());
    }
}

/// Test 55: fchown() - change file ownership by fd
fn test_fchown() {

    let fchown_test_file = b"/fchown_test_file\0";
    let fd = sys_open(fchown_test_file.as_ptr(), O_CREAT | O_RDWR, 0o644);
    if fd >= 0 {
        // Change ownership to uid=2000, gid=2000
        let ret = sys_fchown(fd as i32, 2000, 2000);
        if ret != 0 {
            print(b"FCHOWN:FAIL: fchown returned ");
            print_num(ret);
        } else {
            // Verify with stat
            let mut stat_buf: Stat = unsafe { core::mem::zeroed() };
            let ret = sys_stat(fchown_test_file.as_ptr(), &mut stat_buf as *mut Stat);
            if ret != 0 {
                print(b"FCHOWN:FAIL: stat returned ");
                print_num(ret);
            } else if stat_buf.st_uid == 2000 && stat_buf.st_gid == 2000 {
                println(b"FCHOWN:OK");
            } else {
                print(b"FCHOWN:FAIL: expected uid=2000 gid=2000, got uid=");
                print_num(stat_buf.st_uid as i64);
                print(b" gid=");
                print_num(stat_buf.st_gid as i64);
            }
        }
        sys_close(fd as u64);
        sys_unlink(fchown_test_file.as_ptr());
    }
}

/// Test 56: fchown() on invalid fd should fail with EBADF
fn test_fchown_ebadf() {

    let ret = sys_fchown(999, 1000, 1000);
    if ret == -9 {
        // EBADF
        println(b"FCHOWN_EBADF:OK");
    } else {
        print(b"FCHOWN_EBADF:FAIL: expected -9 (EBADF), got ");
        print_num(ret);
    }
}

/// Test 57: lchown() - change symlink ownership (not target)
fn test_lchown() {

    let lchown_target = b"/lchown_target\0";
    let lchown_link = b"/lchown_link\0";

    // Create target file
    let fd = sys_open(lchown_target.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    if fd >= 0 {
        sys_close(fd as u64);

        // Create symlink to target
        let ret = sys_symlink(lchown_target.as_ptr(), lchown_link.as_ptr());
        if ret == 0 {
            // Change symlink ownership (should change symlink, not target)
            let ret = sys_lchown(lchown_link.as_ptr(), 3000, 3000);
            if ret != 0 {
                print(b"LCHOWN:FAIL: lchown returned ");
                print_num(ret);
            } else {
                // Use lstat to check symlink ownership
                let mut stat_buf: Stat = unsafe { core::mem::zeroed() };
                let ret = sys_lstat(lchown_link.as_ptr(), &mut stat_buf as *mut Stat);
                if ret != 0 {
                    print(b"LCHOWN:FAIL: lstat returned ");
                    print_num(ret);
                } else if stat_buf.st_uid == 3000 && stat_buf.st_gid == 3000 {
                    println(b"LCHOWN:OK");
                } else {
                    print(b"LCHOWN:FAIL: expected uid=3000 gid=3000, got uid=");
                    print_num(stat_buf.st_uid as i64);
                    print(b" gid=");
                    print_num(stat_buf.st_gid as i64);
                }
            }
            sys_unlink(lchown_link.as_ptr());
        }
        sys_unlink(lchown_target.as_ptr());
    }
}

/// Test 58: chown() with -1 to keep existing value
fn test_chown_minus1() {

    let chown_minus1_file = b"/chown_minus1_test\0";
    let fd = sys_open(chown_minus1_file.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    if fd >= 0 {
        sys_close(fd as u64);

        // First set to known values
        sys_chown(chown_minus1_file.as_ptr(), 100, 200);

        // Change only uid (gid = -1 means keep existing)
        let ret = sys_chown(chown_minus1_file.as_ptr(), 150, 0xFFFFFFFF);
        if ret != 0 {
            print(b"CHOWN_MINUS1:FAIL: chown returned ");
            print_num(ret);
        } else {
            let mut stat_buf: Stat = unsafe { core::mem::zeroed() };
            let ret = sys_stat(chown_minus1_file.as_ptr(), &mut stat_buf as *mut Stat);
            if ret != 0 {
                print(b"CHOWN_MINUS1:FAIL: stat returned ");
                print_num(ret);
            } else if stat_buf.st_uid == 150 && stat_buf.st_gid == 200 {
                println(b"CHOWN_MINUS1:OK");
            } else {
                print(b"CHOWN_MINUS1:FAIL: expected uid=150 gid=200, got uid=");
                print_num(stat_buf.st_uid as i64);
                print(b" gid=");
                print_num(stat_buf.st_gid as i64);
            }
        }
        sys_unlink(chown_minus1_file.as_ptr());
    }
}

/// Test 59: umask() - set file creation mask
fn test_umask() {

    // Get the current umask (default should be 0o022)
    let old_mask = sys_umask(0o077);
    if old_mask < 0 {
        print(b"UMASK:FAIL: first umask() returned ");
        print_num(old_mask);
    } else {
        // Set it back and verify we get 0o077 back
        let new_mask = sys_umask(old_mask as u32);
        if new_mask == 0o077 {
            println(b"UMASK:OK");
        } else {
            print(b"UMASK:FAIL: expected 0o077, got ");
            print_num(new_mask);
        }
    }
}

/// Test 60: utimensat() - update file timestamps
fn test_utimensat() {

    // Create a test file
    let utimensat_file = b"/utimensat_test.txt\0";
    let fd = sys_open(utimensat_file.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    if fd < 0 {
        print(b"UTIMENSAT:FAIL: create file failed: ");
        print_num(fd);
    } else {
        sys_close(fd as u64);

        // Test 1: Set specific timestamps
        let times: [Timespec; 2] = [
            Timespec { tv_sec: 1000, tv_nsec: 0 },       // atime
            Timespec { tv_sec: 2000, tv_nsec: 500000 },  // mtime
        ];
        let ret = sys_utimensat(-100, utimensat_file.as_ptr(), times.as_ptr(), 0);
        if ret < 0 {
            print(b"UTIMENSAT:FAIL: set times failed: ");
            print_num(ret);
        } else {
            // Test 2: Use UTIME_NOW for atime, UTIME_OMIT for mtime
            let times_now: [Timespec; 2] = [
                Timespec { tv_sec: 0, tv_nsec: UTIME_NOW },   // atime = now
                Timespec { tv_sec: 0, tv_nsec: UTIME_OMIT },  // mtime = unchanged
            ];
            let ret2 = sys_utimensat(-100, utimensat_file.as_ptr(), times_now.as_ptr(), 0);
            if ret2 < 0 {
                print(b"UTIMENSAT:FAIL: UTIME_NOW failed: ");
                print_num(ret2);
            } else {
                // Test 3: NULL times should set both to current time
                let ret3 = sys_utimensat(-100, utimensat_file.as_ptr(), core::ptr::null(), 0);
                if ret3 < 0 {
                    print(b"UTIMENSAT:FAIL: NULL times failed: ");
                    print_num(ret3);
                } else {
                    println(b"UTIMENSAT:OK");
                }
            }
        }
        sys_unlink(utimensat_file.as_ptr());
    }
}
