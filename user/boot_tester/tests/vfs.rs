//! VFS tests
//!
//! Tests the VFS by:
//! 1. Reading /test.txt from ramfs
//! 2. Reading /proc/version from procfs
//! 3. Listing /proc directory with getdents64

use super::helpers::{print, println, print_num};
use hk_syscall::{sys_close, sys_getdents64, sys_open, sys_read, sys_write, O_DIRECTORY, O_RDONLY};

/// Run all VFS tests
pub fn run_tests() {
    println(b"=== VFS Test ===");
    test_read_file();
    test_read_proc_version();
    test_list_proc_dir();
    println(b"=== VFS Test Complete ===");
}

/// Test 1: Read /test.txt from ramfs
fn test_read_file() {
    let path = b"/test.txt\0";
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        print(b"ERROR: open(/test.txt) failed: ");
        print_num(fd);
    } else {
        print(b"Opened /test.txt, fd=");
        print_num(fd);

        let mut buf = [0u8; 256];
        let n = sys_read(fd as u64, buf.as_mut_ptr(), buf.len() as u64);
        if n < 0 {
            print(b"ERROR: read() failed: ");
            print_num(n);
        } else {
            print(b"Read ");
            print_num(n);
            print(b" bytes: ");
            sys_write(1, buf.as_ptr(), n as u64);
        }
        sys_close(fd as u64);
    }
}

/// Test 2: Read /proc/version from procfs
fn test_read_proc_version() {
    let path = b"/proc/version\0";
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        print(b"ERROR: open(/proc/version) failed: ");
        print_num(fd);
    } else {
        print(b"Opened /proc/version, fd=");
        print_num(fd);

        let mut buf = [0u8; 256];
        let n = sys_read(fd as u64, buf.as_mut_ptr(), buf.len() as u64);
        if n < 0 {
            print(b"ERROR: read() failed: ");
            print_num(n);
        } else {
            print(b"Read ");
            print_num(n);
            print(b" bytes: ");
            sys_write(1, buf.as_ptr(), n as u64);
        }
        sys_close(fd as u64);
    }
}

/// Test 3: List /proc directory
fn test_list_proc_dir() {
    let path = b"/proc\0";
    let fd = sys_open(path.as_ptr(), O_RDONLY | O_DIRECTORY, 0);
    if fd < 0 {
        print(b"ERROR: open(/proc) failed: ");
        print_num(fd);
    } else {
        print(b"Opened /proc as directory, fd=");
        print_num(fd);

        let mut buf = [0u8; 1024];
        let n = sys_getdents64(fd as u64, buf.as_mut_ptr(), buf.len() as u64);
        if n < 0 {
            print(b"ERROR: getdents64() failed: ");
            print_num(n);
        } else {
            print(b"getdents64 returned ");
            print_num(n);
            println(b" bytes");

            // Parse directory entries
            let mut offset = 0usize;
            let total = n as usize;

            println(b"Directory entries:");
            while offset < total {
                // Need at least 19 bytes for the header
                if offset + 19 > total {
                    break;
                }

                // Read d_reclen field at offset+16 (after d_ino and d_off)
                let reclen_lo = buf[offset + 16] as usize;
                let reclen_hi = buf[offset + 17] as usize;
                let reclen = reclen_lo | (reclen_hi << 8);

                // Validate reclen
                if reclen < 20 || reclen > 256 || offset + reclen > total {
                    break;
                }

                // Get name starting at offset+19 (after d_ino/d_off/d_reclen/d_type)
                print(b"  ");
                let name_start = offset + 19;
                let name_end = offset + reclen;
                let mut name_idx = name_start;
                while name_idx < name_end && name_idx < buf.len() {
                    let c = buf[name_idx];
                    if c == 0 {
                        break;
                    }
                    sys_write(1, &c as *const u8, 1);
                    name_idx += 1;
                }

                offset += reclen;
            }
        }
        sys_close(fd as u64);
    }
}
