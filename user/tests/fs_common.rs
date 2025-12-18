//! Common filesystem tests that run on any filesystem
//!
//! These tests are parameterized by a mount point prefix, allowing them
//! to run identically on ramfs, vfat, or any other filesystem.

use super::helpers::{print, print_cstr, print_num, println};
use crate::syscall::{
    sys_close, sys_ftruncate, sys_mkdir, sys_mknod, sys_open, sys_read, sys_rename, sys_rmdir,
    sys_lseek, sys_unlink, sys_write, O_CREAT, O_DIRECTORY, O_RDONLY, O_RDWR, O_WRONLY,
    SEEK_CUR, SEEK_END, SEEK_SET,
};

/// Build a path from prefix + suffix into the provided buffer.
/// Returns a slice containing the null-terminated path.
///
/// Example: make_path(b"/vfat_test", b"testdir", buf) -> "/vfat_test/testdir\0"
fn make_path<'a>(prefix: &[u8], suffix: &[u8], buf: &'a mut [u8; 128]) -> &'a [u8] {
    let mut i = 0;

    // Copy prefix (skip null terminator if present)
    for &b in prefix {
        if b == 0 {
            break;
        }
        buf[i] = b;
        i += 1;
    }

    // Add separator if prefix doesn't end with / and suffix doesn't start with /
    if i > 0 && buf[i - 1] != b'/' && !suffix.is_empty() && suffix[0] != b'/' {
        buf[i] = b'/';
        i += 1;
    }

    // Copy suffix (skip null terminator if present)
    for &b in suffix {
        if b == 0 {
            break;
        }
        buf[i] = b;
        i += 1;
    }

    // Null terminate
    buf[i] = 0;
    &buf[..=i]
}

/// Print test marker in format: "{FS_NAME}_{TEST_NAME}:OK" or ":FAIL"
fn print_marker(fs_name: &[u8], test_name: &[u8], success: bool) {
    print_cstr(fs_name);
    print(b"_");
    print_cstr(test_name);
    if success {
        println(b":OK");
    } else {
        println(b":FAIL");
    }
}

/// Run all normalized filesystem tests on the given mount point.
///
/// # Arguments
/// * `prefix` - Base path (e.g., "" for root, "/vfat_test" for mounted vfat)
/// * `fs_name` - Filesystem name for test output (e.g., "RAMFS", "VFAT")
pub fn run_normalized_tests(prefix: &[u8], fs_name: &[u8]) {
    print(b"=== Running normalized tests on ");
    print_cstr(fs_name);
    println(b" ===");

    test_mkdir(prefix, fs_name);
    test_rmdir(prefix, fs_name);
    test_rmdir_nonempty(prefix, fs_name);
    test_create_write_read(prefix, fs_name);
    test_unlink(prefix, fs_name);
    test_unlink_enoent(prefix, fs_name);
    test_lseek_set(prefix, fs_name);
    test_lseek_cur(prefix, fs_name);
    test_lseek_end(prefix, fs_name);
    test_ftruncate_shrink(prefix, fs_name);
    test_ftruncate_extend(prefix, fs_name);
    test_rename(prefix, fs_name);
    test_rename_overwrite(prefix, fs_name);
}

/// Test: mkdir - create a directory
fn test_mkdir(prefix: &[u8], fs_name: &[u8]) {
    let mut path_buf = [0u8; 128];
    let test_dir = make_path(prefix, b"norm_testdir", &mut path_buf);

    let ret = sys_mkdir(test_dir.as_ptr(), 0o755);
    if ret == 0 {
        // Verify by opening as directory
        let fd = sys_open(test_dir.as_ptr(), O_DIRECTORY, 0);
        if fd >= 0 {
            sys_close(fd as u64);
            print_marker(fs_name, b"MKDIR", true);
        } else {
            print(b"  mkdir succeeded but open failed: ");
            print_num(fd);
            print_marker(fs_name, b"MKDIR", false);
        }
        // Cleanup
        sys_rmdir(test_dir.as_ptr());
    } else {
        print(b"  mkdir returned ");
        print_num(ret);
        print_marker(fs_name, b"MKDIR", false);
    }
}

/// Test: rmdir - remove empty directory
fn test_rmdir(prefix: &[u8], fs_name: &[u8]) {
    let mut path_buf = [0u8; 128];
    let test_dir = make_path(prefix, b"norm_rmdir_test", &mut path_buf);

    // Create directory first
    let ret = sys_mkdir(test_dir.as_ptr(), 0o755);
    if ret != 0 {
        print(b"  setup failed: mkdir returned ");
        print_num(ret);
        print_marker(fs_name, b"RMDIR", false);
        return;
    }

    // Remove it
    let ret = sys_rmdir(test_dir.as_ptr());
    if ret == 0 {
        // Verify it's gone (open should fail with ENOENT)
        let fd = sys_open(test_dir.as_ptr(), O_DIRECTORY, 0);
        if fd == -2 {
            // ENOENT
            print_marker(fs_name, b"RMDIR", true);
        } else {
            print(b"  rmdir succeeded but dir still exists, fd=");
            print_num(fd);
            if fd >= 0 {
                sys_close(fd as u64);
            }
            print_marker(fs_name, b"RMDIR", false);
        }
    } else {
        print(b"  rmdir returned ");
        print_num(ret);
        print_marker(fs_name, b"RMDIR", false);
    }
}

/// Test: rmdir on non-empty directory should fail with ENOTEMPTY
fn test_rmdir_nonempty(prefix: &[u8], fs_name: &[u8]) {
    let mut parent_buf = [0u8; 128];
    let mut child_buf = [0u8; 128];
    let parent_dir = make_path(prefix, b"norm_nonempty", &mut parent_buf);

    // Create parent directory
    let ret = sys_mkdir(parent_dir.as_ptr(), 0o755);
    if ret != 0 {
        print(b"  setup failed: mkdir parent returned ");
        print_num(ret);
        print_marker(fs_name, b"RMDIR_NONEMPTY", false);
        return;
    }

    // Create a file inside
    let child_file = make_path(prefix, b"norm_nonempty/file", &mut child_buf);
    let ret = sys_mknod(child_file.as_ptr(), 0o100644, 0);
    if ret != 0 {
        print(b"  setup failed: mknod child returned ");
        print_num(ret);
        sys_rmdir(parent_dir.as_ptr());
        print_marker(fs_name, b"RMDIR_NONEMPTY", false);
        return;
    }

    // Try to remove parent - should fail with ENOTEMPTY (-39)
    let ret = sys_rmdir(parent_dir.as_ptr());
    if ret == -39 {
        print_marker(fs_name, b"RMDIR_NONEMPTY", true);
    } else {
        print(b"  expected -39 (ENOTEMPTY), got ");
        print_num(ret);
        print_marker(fs_name, b"RMDIR_NONEMPTY", false);
    }

    // Cleanup
    sys_unlink(child_file.as_ptr());
    sys_rmdir(parent_dir.as_ptr());
}

/// Test: create file, write data, read back, verify
fn test_create_write_read(prefix: &[u8], fs_name: &[u8]) {
    let mut path_buf = [0u8; 128];
    let test_file = make_path(prefix, b"norm_write_test.txt", &mut path_buf);
    let test_data = b"Hello from normalized test!";

    // Create and write
    let fd = sys_open(test_file.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    if fd < 0 {
        print(b"  open for write failed: ");
        print_num(fd);
        print_marker(fs_name, b"WRITE_READ", false);
        return;
    }

    let written = sys_write(fd as u64, test_data.as_ptr(), test_data.len() as u64);
    sys_close(fd as u64);

    if written != test_data.len() as i64 {
        print(b"  write returned ");
        print_num(written);
        print(b", expected ");
        print_num(test_data.len() as i64);
        sys_unlink(test_file.as_ptr());
        print_marker(fs_name, b"WRITE_READ", false);
        return;
    }

    // Read back and verify
    let fd = sys_open(test_file.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        print(b"  open for read failed: ");
        print_num(fd);
        sys_unlink(test_file.as_ptr());
        print_marker(fs_name, b"WRITE_READ", false);
        return;
    }

    let mut buf = [0u8; 64];
    let n = sys_read(fd as u64, buf.as_mut_ptr(), 64);
    sys_close(fd as u64);

    if n == test_data.len() as i64 && &buf[..test_data.len()] == test_data {
        print_marker(fs_name, b"WRITE_READ", true);
    } else {
        print(b"  read returned ");
        print_num(n);
        print(b" bytes, data mismatch");
        print_marker(fs_name, b"WRITE_READ", false);
    }

    // Cleanup
    sys_unlink(test_file.as_ptr());
}

/// Test: unlink - delete a file
fn test_unlink(prefix: &[u8], fs_name: &[u8]) {
    let mut path_buf = [0u8; 128];
    let test_file = make_path(prefix, b"norm_unlink_test", &mut path_buf);

    // Create file first
    let ret = sys_mknod(test_file.as_ptr(), 0o100644, 0);
    if ret != 0 {
        print(b"  setup failed: mknod returned ");
        print_num(ret);
        print_marker(fs_name, b"UNLINK", false);
        return;
    }

    // Delete it
    let ret = sys_unlink(test_file.as_ptr());
    if ret == 0 {
        // Verify it's gone
        let fd = sys_open(test_file.as_ptr(), O_RDONLY, 0);
        if fd == -2 {
            // ENOENT
            print_marker(fs_name, b"UNLINK", true);
        } else {
            print(b"  unlink succeeded but file still exists");
            if fd >= 0 {
                sys_close(fd as u64);
            }
            print_marker(fs_name, b"UNLINK", false);
        }
    } else {
        print(b"  unlink returned ");
        print_num(ret);
        print_marker(fs_name, b"UNLINK", false);
    }
}

/// Test: unlink on non-existent file should return ENOENT
fn test_unlink_enoent(prefix: &[u8], fs_name: &[u8]) {
    let mut path_buf = [0u8; 128];
    let test_file = make_path(prefix, b"norm_nonexistent_xyz", &mut path_buf);

    let ret = sys_unlink(test_file.as_ptr());
    if ret == -2 {
        // ENOENT
        print_marker(fs_name, b"UNLINK_ENOENT", true);
    } else {
        print(b"  expected -2 (ENOENT), got ");
        print_num(ret);
        print_marker(fs_name, b"UNLINK_ENOENT", false);
    }
}

/// Test: lseek SEEK_SET
fn test_lseek_set(prefix: &[u8], fs_name: &[u8]) {
    print(b"  [lseek_set: starting ");
    print_cstr(fs_name);
    println(b"]");

    let mut path_buf = [0u8; 128];
    let test_file = make_path(prefix, b"norm_lseek_test.txt", &mut path_buf);
    let test_data = b"0123456789ABCDEF";

    println(b"  [lseek_set: creating file]");
    // Create file with test data
    let fd = sys_open(test_file.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    if fd < 0 {
        print(b"  setup failed: open returned ");
        print_num(fd);
        print_marker(fs_name, b"LSEEK_SET", false);
        return;
    }
    sys_write(fd as u64, test_data.as_ptr(), test_data.len() as u64);
    sys_close(fd as u64);

    // Open for read and seek
    let fd = sys_open(test_file.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        print(b"  open for read failed: ");
        print_num(fd);
        sys_unlink(test_file.as_ptr());
        print_marker(fs_name, b"LSEEK_SET", false);
        return;
    }

    let pos = sys_lseek(fd as i32, 10, SEEK_SET);
    if pos == 10 {
        let mut buf = [0u8; 10];
        let n = sys_read(fd as u64, buf.as_mut_ptr(), 6);
        if n == 6 && &buf[..6] == b"ABCDEF" {
            print_marker(fs_name, b"LSEEK_SET", true);
        } else {
            print(b"  read after seek got wrong data");
            print_marker(fs_name, b"LSEEK_SET", false);
        }
    } else {
        print(b"  lseek returned ");
        print_num(pos);
        print(b", expected 10");
        print_marker(fs_name, b"LSEEK_SET", false);
    }

    sys_close(fd as u64);
    sys_unlink(test_file.as_ptr());
}

/// Test: lseek SEEK_CUR
fn test_lseek_cur(prefix: &[u8], fs_name: &[u8]) {
    let mut path_buf = [0u8; 128];
    let test_file = make_path(prefix, b"norm_lseek_cur.txt", &mut path_buf);
    let test_data = b"0123456789ABCDEF";

    // Create file with test data
    let fd = sys_open(test_file.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    if fd < 0 {
        print_marker(fs_name, b"LSEEK_CUR", false);
        return;
    }
    sys_write(fd as u64, test_data.as_ptr(), test_data.len() as u64);
    sys_close(fd as u64);

    // Open and read 5 bytes, then seek forward 3
    let fd = sys_open(test_file.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        sys_unlink(test_file.as_ptr());
        print_marker(fs_name, b"LSEEK_CUR", false);
        return;
    }

    let mut buf = [0u8; 10];
    sys_read(fd as u64, buf.as_mut_ptr(), 5); // Now at position 5

    let pos = sys_lseek(fd as i32, 3, SEEK_CUR); // Should be at 8
    if pos == 8 {
        let n = sys_read(fd as u64, buf.as_mut_ptr(), 4);
        if n == 4 && &buf[..4] == b"89AB" {
            print_marker(fs_name, b"LSEEK_CUR", true);
        } else {
            print_marker(fs_name, b"LSEEK_CUR", false);
        }
    } else {
        print(b"  lseek SEEK_CUR returned ");
        print_num(pos);
        print_marker(fs_name, b"LSEEK_CUR", false);
    }

    sys_close(fd as u64);
    sys_unlink(test_file.as_ptr());
}

/// Test: lseek SEEK_END
fn test_lseek_end(prefix: &[u8], fs_name: &[u8]) {
    let mut path_buf = [0u8; 128];
    let test_file = make_path(prefix, b"norm_lseek_end.txt", &mut path_buf);
    let test_data = b"0123456789ABCDEF"; // 16 bytes

    // Create file with test data
    let fd = sys_open(test_file.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    if fd < 0 {
        print_marker(fs_name, b"LSEEK_END", false);
        return;
    }
    sys_write(fd as u64, test_data.as_ptr(), test_data.len() as u64);
    sys_close(fd as u64);

    // Open and seek to 4 bytes before end
    let fd = sys_open(test_file.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        sys_unlink(test_file.as_ptr());
        print_marker(fs_name, b"LSEEK_END", false);
        return;
    }

    let pos = sys_lseek(fd as i32, -4, SEEK_END); // Should be at 12
    if pos == 12 {
        let mut buf = [0u8; 10];
        let n = sys_read(fd as u64, buf.as_mut_ptr(), 10);
        if n == 4 && &buf[..4] == b"CDEF" {
            print_marker(fs_name, b"LSEEK_END", true);
        } else {
            print_marker(fs_name, b"LSEEK_END", false);
        }
    } else {
        print(b"  lseek SEEK_END returned ");
        print_num(pos);
        print_marker(fs_name, b"LSEEK_END", false);
    }

    sys_close(fd as u64);
    sys_unlink(test_file.as_ptr());
}

/// Test: ftruncate to shrink file
fn test_ftruncate_shrink(prefix: &[u8], fs_name: &[u8]) {
    let mut path_buf = [0u8; 128];
    let test_file = make_path(prefix, b"norm_ftrunc_shrink.txt", &mut path_buf);

    // Create file with data
    let fd = sys_open(test_file.as_ptr(), O_CREAT | O_RDWR, 0o644);
    if fd < 0 {
        print_marker(fs_name, b"FTRUNCATE_SHRINK", false);
        return;
    }

    let data = b"Hello World!"; // 12 bytes
    sys_write(fd as u64, data.as_ptr(), 12);

    // Truncate to 5 bytes
    let ret = sys_ftruncate(fd as i32, 5);
    if ret != 0 {
        print(b"  ftruncate returned ");
        print_num(ret);
        sys_close(fd as u64);
        sys_unlink(test_file.as_ptr());
        print_marker(fs_name, b"FTRUNCATE_SHRINK", false);
        return;
    }

    // Seek to start and read
    sys_lseek(fd as i32, 0, SEEK_SET);
    let mut buf = [0u8; 20];
    let n = sys_read(fd as u64, buf.as_mut_ptr(), 20);
    sys_close(fd as u64);

    if n == 5 && &buf[..5] == b"Hello" {
        print_marker(fs_name, b"FTRUNCATE_SHRINK", true);
    } else {
        print(b"  read ");
        print_num(n);
        print(b" bytes after truncate");
        print_marker(fs_name, b"FTRUNCATE_SHRINK", false);
    }

    sys_unlink(test_file.as_ptr());
}

/// Test: ftruncate to extend file with zeros
fn test_ftruncate_extend(prefix: &[u8], fs_name: &[u8]) {
    let mut path_buf = [0u8; 128];
    let test_file = make_path(prefix, b"norm_ftrunc_extend.txt", &mut path_buf);

    // Create file with data
    let fd = sys_open(test_file.as_ptr(), O_CREAT | O_RDWR, 0o644);
    if fd < 0 {
        print_marker(fs_name, b"FTRUNCATE_EXTEND", false);
        return;
    }

    let data = b"Hi"; // 2 bytes
    sys_write(fd as u64, data.as_ptr(), 2);

    // Extend to 6 bytes
    let ret = sys_ftruncate(fd as i32, 6);
    if ret != 0 {
        print(b"  ftruncate returned ");
        print_num(ret);
        sys_close(fd as u64);
        sys_unlink(test_file.as_ptr());
        print_marker(fs_name, b"FTRUNCATE_EXTEND", false);
        return;
    }

    // Seek to start and read
    sys_lseek(fd as i32, 0, SEEK_SET);
    let mut buf = [0u8; 20];
    let n = sys_read(fd as u64, buf.as_mut_ptr(), 20);
    sys_close(fd as u64);

    // Should be "Hi" followed by 4 zero bytes
    if n == 6 && &buf[..2] == b"Hi" && buf[2] == 0 && buf[3] == 0 && buf[4] == 0 && buf[5] == 0 {
        print_marker(fs_name, b"FTRUNCATE_EXTEND", true);
    } else {
        print(b"  read ");
        print_num(n);
        print(b" bytes, expected zeros");
        print_marker(fs_name, b"FTRUNCATE_EXTEND", false);
    }

    sys_unlink(test_file.as_ptr());
}

/// Test: rename a file
fn test_rename(prefix: &[u8], fs_name: &[u8]) {
    let mut old_buf = [0u8; 128];
    let mut new_buf = [0u8; 128];
    let old_path = make_path(prefix, b"norm_rename_old.txt", &mut old_buf);
    let new_path = make_path(prefix, b"norm_rename_new.txt", &mut new_buf);

    // Create file with data
    let fd = sys_open(old_path.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    if fd < 0 {
        print_marker(fs_name, b"RENAME", false);
        return;
    }
    let data = b"rename test";
    sys_write(fd as u64, data.as_ptr(), data.len() as u64);
    sys_close(fd as u64);

    // Rename
    let ret = sys_rename(old_path.as_ptr(), new_path.as_ptr());
    if ret != 0 {
        print(b"  rename returned ");
        print_num(ret);
        sys_unlink(old_path.as_ptr());
        print_marker(fs_name, b"RENAME", false);
        return;
    }

    // Verify old is gone
    let fd_old = sys_open(old_path.as_ptr(), O_RDONLY, 0);
    if fd_old >= 0 {
        sys_close(fd_old as u64);
        print(b"  old file still exists after rename");
        sys_unlink(new_path.as_ptr());
        print_marker(fs_name, b"RENAME", false);
        return;
    }

    // Verify new exists with correct content
    let fd_new = sys_open(new_path.as_ptr(), O_RDONLY, 0);
    if fd_new < 0 {
        print(b"  new file not found after rename");
        print_marker(fs_name, b"RENAME", false);
        return;
    }

    let mut buf = [0u8; 20];
    let n = sys_read(fd_new as u64, buf.as_mut_ptr(), 20);
    sys_close(fd_new as u64);

    if n == data.len() as i64 && &buf[..data.len()] == data {
        print_marker(fs_name, b"RENAME", true);
    } else {
        print(b"  content mismatch after rename");
        print_marker(fs_name, b"RENAME", false);
    }

    sys_unlink(new_path.as_ptr());
}

/// Test: rename overwriting an existing file
fn test_rename_overwrite(prefix: &[u8], fs_name: &[u8]) {
    let mut src_buf = [0u8; 128];
    let mut dst_buf = [0u8; 128];
    let src_path = make_path(prefix, b"norm_rename_src.txt", &mut src_buf);
    let dst_path = make_path(prefix, b"norm_rename_dst.txt", &mut dst_buf);

    // Create source file
    let fd = sys_open(src_path.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    if fd < 0 {
        print_marker(fs_name, b"RENAME_OVERWRITE", false);
        return;
    }
    let src_data = b"source data";
    sys_write(fd as u64, src_data.as_ptr(), src_data.len() as u64);
    sys_close(fd as u64);

    // Create destination file (to be overwritten)
    let fd = sys_open(dst_path.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    if fd < 0 {
        sys_unlink(src_path.as_ptr());
        print_marker(fs_name, b"RENAME_OVERWRITE", false);
        return;
    }
    let dst_data = b"old destination";
    sys_write(fd as u64, dst_data.as_ptr(), dst_data.len() as u64);
    sys_close(fd as u64);

    // Rename src to dst (overwriting dst)
    let ret = sys_rename(src_path.as_ptr(), dst_path.as_ptr());
    if ret != 0 {
        print(b"  rename returned ");
        print_num(ret);
        sys_unlink(src_path.as_ptr());
        sys_unlink(dst_path.as_ptr());
        print_marker(fs_name, b"RENAME_OVERWRITE", false);
        return;
    }

    // Verify source is gone and destination has source content
    let fd_src = sys_open(src_path.as_ptr(), O_RDONLY, 0);
    if fd_src >= 0 {
        sys_close(fd_src as u64);
        print(b"  source still exists");
        sys_unlink(dst_path.as_ptr());
        print_marker(fs_name, b"RENAME_OVERWRITE", false);
        return;
    }

    let fd_dst = sys_open(dst_path.as_ptr(), O_RDONLY, 0);
    if fd_dst < 0 {
        print(b"  destination not found");
        print_marker(fs_name, b"RENAME_OVERWRITE", false);
        return;
    }

    let mut buf = [0u8; 20];
    let n = sys_read(fd_dst as u64, buf.as_mut_ptr(), 20);
    sys_close(fd_dst as u64);

    if n == src_data.len() as i64 && &buf[..src_data.len()] == src_data {
        print_marker(fs_name, b"RENAME_OVERWRITE", true);
    } else {
        print(b"  destination has wrong content");
        print_marker(fs_name, b"RENAME_OVERWRITE", false);
    }

    sys_unlink(dst_path.as_ptr());
}
