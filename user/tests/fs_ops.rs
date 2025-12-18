//! Filesystem operations tests
//!
//! This module runs:
//! 1. Normalized tests on ramfs (via fs_common)
//! 2. Ramfs-specific tests (symlinks, hardlinks)
//! 3. Mount/umount tests
//! 4. Normalized tests on vfat (via fs_common)
//! 5. VFAT-specific tests

use super::fs_common;
use super::helpers::{print, print_num, println};
use crate::syscall::{
    sys_close, sys_link, sys_lseek, sys_mkdir, sys_mknod, sys_mount, sys_open, sys_read,
    sys_readlink, sys_rename, sys_rmdir, sys_symlink, sys_truncate, sys_umount2, sys_unlink,
    sys_write, O_CREAT, O_RDONLY, O_WRONLY, SEEK_SET,
};

/// Run all filesystem ops tests
pub fn run_tests() {
    // ========================================
    // Part 1: Normalized tests on ramfs (root)
    // ========================================
    fs_common::run_normalized_tests(b"", b"RAMFS");

    // ========================================
    // Part 2: Ramfs-specific tests
    // ========================================
    println(b"=== Ramfs-specific tests ===");

    // Symlink tests (VFAT doesn't support symlinks)
    test_symlink();
    test_readlink();
    test_symlink_read();
    test_symlink_eexist();
    test_readlink_einval();

    // Hard link tests (VFAT doesn't support hard links)
    test_link();
    test_link_dir_eperm();
    test_unlink_hardlink_persistence();

    // Other ramfs-specific edge cases
    test_unlink_eisdir();
    test_lseek_invalid_whence();
    test_lseek_negative_pos();
    test_truncate_eisdir();
    test_rename_cycle();

    // ========================================
    // Part 3: Mount/umount tests
    // ========================================
    test_mount_umount();

    // ========================================
    // Part 4: VFAT mount and normalized tests
    // ========================================
    if !mount_vfat() {
        println(b"VFAT mount failed, skipping VFAT tests");
        return;
    }

    fs_common::run_normalized_tests(b"/vfat_test", b"VFAT");

    // ========================================
    // Part 5: VFAT-specific tests
    // ========================================
    println(b"=== VFAT-specific tests ===");
    test_vfat_case_insensitive();

    // Cleanup: unmount VFAT
    unmount_vfat();
}

// ============================================================================
// Ramfs-specific tests (symlinks, hardlinks)
// ============================================================================

/// Test: symlink() - create a symbolic link
fn test_symlink() {

    let symlink_target = b"/test.txt\0";
    let symlink_path = b"/link_to_test\0";
    let ret = sys_symlink(symlink_target.as_ptr(), symlink_path.as_ptr());
    if ret == 0 {
        println(b"SYMLINK:OK");
    } else {
        print(b"SYMLINK:FAIL: symlink returned ");
        print_num(ret);
    }
}

/// Test: readlink() - read symbolic link target
fn test_readlink() {

    let symlink_path = b"/link_to_test\0";
    let mut readlink_buf: [u8; 64] = [0; 64];
    let ret = sys_readlink(symlink_path.as_ptr(), readlink_buf.as_mut_ptr(), 64);
    if ret == 9 {
        // "/test.txt" is 9 bytes
        println(b"READLINK:OK");
    } else {
        print(b"READLINK:FAIL: expected 9, got ");
        print_num(ret);
    }
}

/// Test: Open and read through symlink
fn test_symlink_read() {

    let symlink_path = b"/link_to_test\0";
    let fd = sys_open(symlink_path.as_ptr(), O_RDONLY, 0);
    if fd >= 0 {
        let mut buf: [u8; 64] = [0; 64];
        let bytes_read = sys_read(fd as u64, buf.as_mut_ptr(), 64);
        sys_close(fd as u64);
        if bytes_read == 17 {
            println(b"SYMLINK_READ:OK");
        } else {
            print(b"SYMLINK_READ:FAIL: expected 17 bytes, got ");
            print_num(bytes_read);
        }
    } else {
        print(b"SYMLINK_READ:FAIL: open returned ");
        print_num(fd);
    }
}

/// Test: symlink() with existing name should fail with EEXIST
fn test_symlink_eexist() {

    let symlink_target = b"/test.txt\0";
    let existing_path = b"/test.txt\0";
    let ret = sys_symlink(symlink_target.as_ptr(), existing_path.as_ptr());
    if ret == -17 {
        // EEXIST
        println(b"SYMLINK_EEXIST:OK");
    } else {
        print(b"SYMLINK_EEXIST:FAIL: expected -17 (EEXIST), got ");
        print_num(ret);
    }
}

/// Test: readlink() on non-symlink should fail with EINVAL
fn test_readlink_einval() {

    let regular_file = b"/test.txt\0";
    let mut buf: [u8; 64] = [0; 64];
    let ret = sys_readlink(regular_file.as_ptr(), buf.as_mut_ptr(), 64);
    if ret == -22 {
        // EINVAL
        println(b"READLINK_EINVAL:OK");
    } else {
        print(b"READLINK_EINVAL:FAIL: expected -22 (EINVAL), got ");
        print_num(ret);
    }
}

/// Test: link() - create a hard link
fn test_link() {

    let hardlink_oldpath = b"/test.txt\0";
    let hardlink_newpath = b"/hardlink_test\0";
    let ret = sys_link(hardlink_oldpath.as_ptr(), hardlink_newpath.as_ptr());
    if ret == 0 {
        let fd = sys_open(hardlink_newpath.as_ptr(), O_RDONLY, 0);
        if fd >= 0 {
            let mut buf: [u8; 64] = [0; 64];
            let bytes_read = sys_read(fd as u64, buf.as_mut_ptr(), 64);
            sys_close(fd as u64);
            if bytes_read == 17 {
                println(b"LINK:OK");
            } else {
                print(b"LINK:FAIL: read through hardlink got ");
                print_num(bytes_read);
                println(b" bytes");
            }
        } else {
            print(b"LINK:FAIL: could not open hardlink, fd = ");
            print_num(fd);
        }
    } else {
        print(b"LINK:FAIL: link returned ");
        print_num(ret);
    }
}

/// Test: link() to directory should fail with EPERM
fn test_link_dir_eperm() {

    let dir_path = b"/proc\0";
    let dir_link = b"/proc_link\0";
    let ret = sys_link(dir_path.as_ptr(), dir_link.as_ptr());
    if ret == -1 {
        // EPERM
        println(b"LINK_DIR_EPERM:OK");
    } else {
        print(b"LINK_DIR_EPERM:FAIL: expected -1 (EPERM), got ");
        print_num(ret);
    }
}

/// Test: unlink() removes hardlink but file persists
fn test_unlink_hardlink_persistence() {

    let hardlink_test = b"/hardlink_target\0";
    let hardlink_link = b"/hardlink_link\0";

    let ret = sys_mknod(hardlink_test.as_ptr(), 0o100644, 0);
    if ret != 0 {
        print(b"hardlink test setup failed: mknod returned ");
        print_num(ret);
        return;
    }

    let ret = sys_link(hardlink_test.as_ptr(), hardlink_link.as_ptr());
    if ret != 0 {
        print(b"hardlink test setup failed: link returned ");
        print_num(ret);
        return;
    }

    let ret = sys_unlink(hardlink_test.as_ptr());
    if ret != 0 {
        print(b"unlink original failed: ");
        print_num(ret);
        return;
    }

    let fd = sys_open(hardlink_link.as_ptr(), O_RDONLY, 0);
    if fd >= 0 {
        println(b"UNLINK_HARDLINK_PERSISTENCE:OK");
        sys_close(fd as u64);
        sys_unlink(hardlink_link.as_ptr());
    } else {
        print(b"UNLINK_HARDLINK_PERSISTENCE:FAIL: file gone after unlink, fd=");
        print_num(fd);
    }
}

/// Test: unlink() on directory should return EISDIR
fn test_unlink_eisdir() {

    let test_dir = b"/unlink_test_dir\0";
    let ret = sys_mkdir(test_dir.as_ptr(), 0o755);
    if ret != 0 {
        print(b"unlink dir test setup failed: mkdir returned ");
        print_num(ret);
        return;
    }

    let ret = sys_unlink(test_dir.as_ptr());
    if ret == -21 {
        // EISDIR
        println(b"UNLINK_EISDIR:OK");
    } else {
        print(b"UNLINK_EISDIR:FAIL: expected -21 (EISDIR), got ");
        print_num(ret);
    }
    sys_rmdir(test_dir.as_ptr());
}

/// Test: lseek() with invalid whence
fn test_lseek_invalid_whence() {

    let test_file = b"/test.txt\0";
    let fd = sys_open(test_file.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        print(b"lseek invalid whence test setup failed: open returned ");
        print_num(fd);
        return;
    }

    let pos = sys_lseek(fd as i32, 0, 99);
    if pos == -22 {
        // EINVAL
        println(b"LSEEK_INVALID_WHENCE:OK");
    } else {
        print(b"LSEEK_INVALID_WHENCE:FAIL: expected -22 (EINVAL), got ");
        print_num(pos);
    }
    sys_close(fd as u64);
}

/// Test: lseek() negative position should fail
fn test_lseek_negative_pos() {

    let test_file = b"/test.txt\0";
    let fd = sys_open(test_file.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        print(b"lseek negative position test setup failed: open returned ");
        print_num(fd);
        return;
    }

    let pos = sys_lseek(fd as i32, -1, SEEK_SET);
    if pos == -22 {
        // EINVAL
        println(b"LSEEK_NEGATIVE_POS:OK");
    } else {
        print(b"LSEEK_NEGATIVE_POS:FAIL: expected -22 (EINVAL), got ");
        print_num(pos);
    }
    sys_close(fd as u64);
}

/// Test: truncate() on directory should fail with EISDIR
fn test_truncate_eisdir() {

    let test_dir = b"/trunc_dir_test\0";
    let ret = sys_mkdir(test_dir.as_ptr(), 0o755);
    if ret != 0 {
        print(b"truncate dir test setup failed: mkdir returned ");
        print_num(ret);
        return;
    }

    let ret = sys_truncate(test_dir.as_ptr(), 0);
    if ret == -21 {
        // EISDIR
        println(b"TRUNCATE_EISDIR:OK");
    } else {
        print(b"TRUNCATE_EISDIR:FAIL: expected -21 (EISDIR), got ");
        print_num(ret);
    }
    sys_rmdir(test_dir.as_ptr());
}

/// Test: rename() cycle detection
fn test_rename_cycle() {

    let cycle_a = b"/cycle_a\0";
    let cycle_b = b"/cycle_a/cycle_b\0";

    let ret = sys_mkdir(cycle_a.as_ptr(), 0o755);
    if ret != 0 {
        print(b"CYCLE_DETECTION:FAIL: mkdir cycle_a returned ");
        print_num(ret);
        return;
    }

    let ret = sys_mkdir(cycle_b.as_ptr(), 0o755);
    if ret != 0 {
        print(b"CYCLE_DETECTION:FAIL: mkdir cycle_b returned ");
        print_num(ret);
        sys_rmdir(cycle_a.as_ptr());
        return;
    }

    // Try to rename /cycle_a to /cycle_a/cycle_b/cycle_a (would create a cycle)
    let cycle_into = b"/cycle_a/cycle_b/cycle_a\0";
    let ret = sys_rename(cycle_a.as_ptr(), cycle_into.as_ptr());
    if ret == -22 {
        // EINVAL
        println(b"CYCLE_DETECTION:OK");
    } else if ret == 0 {
        println(b"CYCLE_DETECTION:FAIL: rename succeeded (should have failed with EINVAL)");
    } else {
        print(b"CYCLE_DETECTION:FAIL: expected -22 (EINVAL), got ");
        print_num(ret);
    }

    sys_rmdir(cycle_b.as_ptr());
    sys_rmdir(cycle_a.as_ptr());
}

// ============================================================================
// Mount/umount tests
// ============================================================================

/// Helper: Read and print /proc/mounts
fn print_proc_mounts() {
    let path = b"/proc/mounts\0";
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        print(b"  Failed to open /proc/mounts: ");
        print_num(fd);
        return;
    }
    let mut buf = [0u8; 256];
    let n = sys_read(fd as u64, buf.as_mut_ptr(), buf.len() as u64);
    if n > 0 {
        sys_write(1, buf.as_ptr(), n as u64);
    }
    sys_close(fd as u64);
}

/// Test: mount/umount
fn test_mount_umount() {
    let source = b"none\0";
    let target = b"/mnt\0";
    let fstype = b"ramfs\0";

    print(b"Mounting ramfs at /mnt... ");
    let ret = sys_mount(source.as_ptr(), target.as_ptr(), fstype.as_ptr(), 0, 0);
    if ret == 0 {
        println(b"OK");
    } else {
        print(b"FAILED (");
        print_num(ret);
        println(b")");
        return;
    }

    println(b"/proc/mounts after mount:");
    print_proc_mounts();

    // Test invalid fstype returns ENODEV (-19)
    let bad_fstype = b"nosuchfs\0";
    let ret = sys_mount(source.as_ptr(), target.as_ptr(), bad_fstype.as_ptr(), 0, 0);
    if ret == -19 {
        println(b"Invalid fstype test: ENODEV as expected");
    } else {
        print(b"Invalid fstype test: unexpected return ");
        print_num(ret);
    }

    print(b"Unmounting /mnt... ");
    let ret = sys_umount2(target.as_ptr(), 0);
    if ret == 0 {
        println(b"OK");
    } else {
        print(b"FAILED (");
        print_num(ret);
        println(b")");
        return;
    }

    println(b"/proc/mounts after umount:");
    print_proc_mounts();

    println(b"MOUNT_UMOUNT_TEST_PASSED");
}

// ============================================================================
// VFAT mount/unmount helpers
// ============================================================================

/// Mount VFAT from /dev/sd0 at /vfat_test
/// Returns true on success, false on failure
fn mount_vfat() -> bool {
    let source = b"/dev/sd0\0";
    let target = b"/vfat_test\0";
    let fstype = b"vfat\0";

    print(b"Mounting /dev/sd0 at /vfat_test... ");
    let ret = sys_mount(source.as_ptr(), target.as_ptr(), fstype.as_ptr(), 0, 0);
    if ret == 0 {
        println(b"OK");
    } else {
        print(b"FAILED (");
        print_num(ret);
        println(b")");
        return false;
    }

    // Verify by reading /vfat_test/HELLO.TXT
    let hello_path = b"/vfat_test/HELLO.TXT\0";
    let fd = sys_open(hello_path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        print(b"Warning: HELLO.TXT not found: ");
        print_num(fd);
    } else {
        let mut buf = [0u8; 64];
        let n = sys_read(fd as u64, buf.as_mut_ptr(), 64);
        if n > 0 {
            print(b"HELLO.TXT contents: ");
            sys_write(1, buf.as_ptr(), n as u64);
        }
        sys_close(fd as u64);
    }

    println(b"VFAT_MOUNT:OK");
    true
}

/// Unmount VFAT from /vfat_test
fn unmount_vfat() {
    let target = b"/vfat_test\0";
    let ret = sys_umount2(target.as_ptr(), 0);
    if ret == 0 {
        println(b"VFAT_UNMOUNT:OK");
    } else {
        print(b"VFAT_UNMOUNT:FAIL (");
        print_num(ret);
        println(b")");
    }
}

// ============================================================================
// VFAT-specific tests
// ============================================================================

/// Test: VFAT case-insensitive filename matching
fn test_vfat_case_insensitive() {

    // Create a file with lowercase name
    let lowercase = b"/vfat_test/testfile.txt\0";
    let fd = sys_open(lowercase.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    if fd < 0 {
        print(b"VFAT_CASE_INSENSITIVE:FAIL: create lowercase failed: ");
        print_num(fd);
        return;
    }
    sys_write(fd as u64, b"case test".as_ptr(), 9);
    sys_close(fd as u64);

    // Try to open with uppercase name
    let uppercase = b"/vfat_test/TESTFILE.TXT\0";
    let fd = sys_open(uppercase.as_ptr(), O_RDONLY, 0);
    if fd >= 0 {
        let mut buf = [0u8; 20];
        let n = sys_read(fd as u64, buf.as_mut_ptr(), 20);
        sys_close(fd as u64);
        if n == 9 && &buf[..9] == b"case test" {
            println(b"VFAT_CASE_INSENSITIVE:OK");
        } else {
            println(b"VFAT_CASE_INSENSITIVE:FAIL: data mismatch");
        }
    } else {
        print(b"VFAT_CASE_INSENSITIVE:FAIL: open uppercase failed: ");
        print_num(fd);
    }

    // Cleanup
    sys_unlink(lowercase.as_ptr());
}
