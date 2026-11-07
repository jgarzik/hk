//! Sync tests
//!
//! Tests:
//! - sync() - synchronize all filesystems
//! - fsync() - synchronize a file's state to storage
//! - fsync() on invalid fd
//! - fdatasync() - synchronize file data to storage
//! - fdatasync() on invalid fd
//! - syncfs() - synchronize filesystem containing a file
//! - syncfs() on invalid fd
//! - Test: membarrier() - memory barrier syscall
//! - Test: readahead() - file readahead syscall

use crate::tests::harness::{T, pass};
use crate::tests::helpers::{add_fails, fail_count, print, print_num, println};
use hk_syscall::{
    MEMBARRIER_CMD_FLAG_CPU, MEMBARRIER_CMD_GET_REGISTRATIONS, MEMBARRIER_CMD_GLOBAL,
    MEMBARRIER_CMD_GLOBAL_EXPEDITED, MEMBARRIER_CMD_PRIVATE_EXPEDITED,
    MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, MEMBARRIER_CMD_QUERY,
    MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED,
    MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE, O_CREAT, O_RDONLY, O_WRONLY, sys_close,
    sys_fdatasync, sys_fsync, sys_membarrier, sys_open, sys_readahead, sys_sync, sys_syncfs,
    sys_unlink, sys_write,
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
    test_membarrier_reg();
    test_membarrier();
    test_readahead();
    test_dirty_sysctls();
    test_sync_file_range();
    test_fadvise();
    test_fadvise_ramfs();
}

/// DONTNEED on a ramfs file keeps its data (the cache is its only
/// copy, Linux skips unevictable mappings), and huge ranges are fine
/// (readahead's count past i64::MAX is a negative length: EINVAL)
fn test_fadvise_ramfs() {
    use hk_syscall::{sys_fadvise64, sys_pread64, sys_readahead, sys_sync_file_range};
    let (fd, p) = file_and_pipe();
    let a = sys_fadvise64(fd, 0, 0, 4);
    let b = sys_readahead(fd, 0, usize::MAX);
    let c = sys_fadvise64(fd, 1, i64::MAX, 4);
    let d = sys_sync_file_range(fd, 1, i64::MAX - 1, 2);
    let mut back = [0u8; 8192];
    let n = sys_pread64(fd, back.as_mut_ptr(), 8192, 0);
    close_both(fd, p);
    let ok = a == 0 && b == -22 && c == 0 && d == 0 && n == 8192 && back.iter().all(|&x| x == 7);
    verdict(
        b"FADVISE_DONTNEED_RAMFS",
        ok,
        [a, b, c, d, n, back[0] as i64],
    );
}

fn verdict(name: &[u8], ok: bool, got: [i64; 6]) {
    print(name);
    if ok {
        println(b":OK");
        return;
    }
    print(b":FAIL");
    for g in got {
        print(b" ");
        print_num(g);
    }
    println(b"");
}

/// A temp file with 8KB written, and a pipe: (file, pipe read end)
fn file_and_pipe() -> (i32, i32) {
    use hk_syscall::{O_CREAT, O_RDWR, O_TRUNC, sys_open, sys_pipe2, sys_pwrite64};
    let fd = sys_open(
        b"/tmp/sfr_test\0".as_ptr(),
        O_CREAT | O_RDWR | O_TRUNC,
        0o600,
    ) as i32;
    let buf = [7u8; 8192];
    sys_pwrite64(fd, buf.as_ptr(), 8192, 0);
    let mut p = [0i32; 2];
    sys_pipe2(p.as_mut_ptr(), 0);
    hk_syscall::sys_close(p[1] as u64);
    (fd, p[0])
}

fn close_both(fd: i32, p: i32) {
    hk_syscall::sys_close(fd as u64);
    hk_syscall::sys_close(p as u64);
    hk_syscall::sys_unlink(b"/tmp/sfr_test\0".as_ptr());
}

/// sync_file_range (Linux ksys_sync_file_range): unknown flags, a
/// negative offset or length are EINVAL; a pipe ESPIPE; a closed fd
/// EBADF; a range of a file 0
fn test_sync_file_range() {
    use hk_syscall::sys_sync_file_range as sfr;
    let (fd, p) = file_and_pipe();
    let got = [
        sfr(fd, 0, 0, 8),
        sfr(fd, -1, 0, 2),
        sfr(fd, 0, -1, 2),
        sfr(p, 0, 0, 2),
        sfr(9999, 0, 0, 2),
        sfr(fd, 0, 4096, 7),
    ];
    close_both(fd, p);
    let ok = got == [-22, -22, -22, -29, -9, 0];
    verdict(b"SYNC_FILE_RANGE_ERRNO", ok, got);
}

/// fadvise64 (Linux generic_fadvise): a pipe is ESPIPE, an unknown
/// advice or a negative length EINVAL, a closed fd EBADF; WILLNEED,
/// DONTNEED and SEQUENTIAL on a file 0
fn test_fadvise() {
    use hk_syscall::sys_fadvise64 as fa;
    let (fd, p) = file_and_pipe();
    let got = [
        fa(p, 0, 0, 0),
        fa(fd, 0, 0, 9),
        fa(fd, 0, -1, 0),
        fa(9999, 0, 0, 0),
        fa(fd, 0, 0, 3) + fa(fd, 0, 0, 4),
        fa(fd, 0, 4096, 2),
    ];
    close_both(fd, p);
    let ok = got == [-29, -22, -22, -9, 0, 0];
    verdict(b"FADVISE_ERRNO", ok, got);
}

/// vm.dirty_* (Linux page-writeback.c): defaults 20/10 percent; setting
/// dirty_bytes clears dirty_ratio and setting the ratio clears the bytes
fn test_dirty_sysctls() {
    use crate::tests::helpers::read_file;
    use hk_syscall::{O_WRONLY, sys_close, sys_open, sys_write};
    let get = |p: &[u8]| {
        let mut b = [0u8; 32];
        let n = read_file(p, &mut b);
        let mut v = 0i64;
        for &c in &b[..n.max(0) as usize] {
            if c.is_ascii_digit() {
                v = v * 10 + (c - b'0') as i64;
            }
        }
        if n > 0 { v } else { -1 }
    };
    let put = |p: &[u8], v: &[u8]| {
        let fd = sys_open(p.as_ptr(), O_WRONLY, 0);
        let r = sys_write(fd as u64, v.as_ptr(), v.len() as u64);
        sys_close(fd as u64);
        r
    };
    let ratio = b"/proc/sys/vm/dirty_ratio\0";
    let bytes = b"/proc/sys/vm/dirty_bytes\0";
    let (r0, b0) = (get(ratio), get(b"/proc/sys/vm/dirty_background_ratio\0"));
    let w1 = put(bytes, b"67108864\n");
    let (r1, y1) = (get(ratio), get(bytes));
    let w2 = put(ratio, b"20\n");
    let (r2, y2) = (get(ratio), get(bytes));
    let ok = r0 == 20
        && b0 == 10
        && w1 > 0
        && r1 == 0
        && y1 == 67108864
        && w2 > 0
        && r2 == 20
        && y2 == 0;
    if ok {
        pass(b"VM_DIRTY_SYSCTLS");
    } else {
        // Each step's values: defaults, after dirty_bytes, after the ratio
        print(b"VM_DIRTY_SYSCTLS:FAIL ratio,bg=");
        print_num(r0);
        print(b",");
        print_num(b0);
        print(b" after-bytes w,ratio,bytes=");
        print_num(w1);
        print(b",");
        print_num(r1);
        print(b",");
        print_num(y1);
        print(b" after-ratio w,ratio,bytes=");
        print_num(w2);
        print(b",");
        print_num(r2);
        print(b",");
        print_num(y2);
        println(b"");
    }
}

/// sync() - synchronize all filesystems
fn test_sync() {
    let ret = sys_sync();
    if ret == 0 {
        pass(b"SYNC");
    } else {
        print(b"SYNC:FAIL: expected 0, got ");
        print_num(ret);
    }
}

/// fsync() - synchronize a file's state to storage
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
            pass(b"FSYNC");
        } else {
            print(b"FSYNC:FAIL: expected 0, got ");
            print_num(ret);
        }
        sys_close(fd as u64);
        sys_unlink(fsync_file.as_ptr());
    }
}

/// fsync() on invalid fd should fail with EBADF
fn test_fsync_ebadf() {
    let ret = sys_fsync(999);
    if ret == -9 {
        // EBADF
        pass(b"FSYNC_EBADF");
    } else {
        print(b"FSYNC_EBADF:FAIL: expected -9 (EBADF), got ");
        print_num(ret);
    }
}

/// fdatasync() - synchronize file data to storage
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
            pass(b"FDATASYNC");
        } else {
            print(b"FDATASYNC:FAIL: expected 0, got ");
            print_num(ret);
        }
        sys_close(fd as u64);
        sys_unlink(fdatasync_file.as_ptr());
    }
}

/// fdatasync() on invalid fd should fail with EBADF
fn test_fdatasync_ebadf() {
    let ret = sys_fdatasync(999);
    if ret == -9 {
        // EBADF
        pass(b"FDATASYNC_EBADF");
    } else {
        print(b"FDATASYNC_EBADF:FAIL: expected -9 (EBADF), got ");
        print_num(ret);
    }
}

/// syncfs() - synchronize filesystem containing a file
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
            pass(b"SYNCFS");
        } else {
            print(b"SYNCFS:FAIL: expected 0, got ");
            print_num(ret);
        }
        sys_close(fd as u64);
        sys_unlink(syncfs_file.as_ptr());
    }
}

/// syncfs() on invalid fd should fail with EBADF
fn test_syncfs_ebadf() {
    let ret = sys_syncfs(999);
    if ret == -9 {
        // EBADF
        pass(b"SYNCFS_EBADF");
    } else {
        print(b"SYNCFS_EBADF:FAIL: expected -9 (EBADF), got ");
        print_num(ret);
    }
}

/// MEMBARRIER_REG: registration rules (Linux kernel/sched/membarrier.c),
/// in a child of a fresh exec-less fork of init, before init registers:
/// the expedited private commands need their own registration (EPERM
/// before), GLOBAL_EXPEDITED needs none, the SYNC_CORE registration
/// also reports the private one, FLAG_CPU is for the RSEQ command only,
/// and a fork child inherits what its parent registered
fn test_membarrier_reg() {
    use hk_syscall::{sys_exit, sys_fork, sys_wait4};
    let before = fail_count();
    let pid = sys_fork();
    if pid == 0 {
        let mut t = T::new(b"MEMBARRIER_REG");
        let q = sys_membarrier(MEMBARRIER_CMD_QUERY, 0, 0);
        let want = MEMBARRIER_CMD_GLOBAL_EXPEDITED
            | MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED
            | MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE
            | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE
            | MEMBARRIER_CMD_GET_REGISTRATIONS;
        t.ok(b"query", q >= 0 && q as i32 & want == want, q);
        t.eq(
            b"regs none",
            sys_membarrier(MEMBARRIER_CMD_GET_REGISTRATIONS, 0, 0),
            0,
        );
        t.eq(
            b"private unreg",
            sys_membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0),
            -1,
        );
        t.eq(
            b"sync_core unreg",
            sys_membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0),
            -1,
        );
        t.eq(
            b"global exp",
            sys_membarrier(MEMBARRIER_CMD_GLOBAL_EXPEDITED, 0, 0),
            0,
        );
        t.eq(
            b"flag cpu",
            sys_membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, MEMBARRIER_CMD_FLAG_CPU, 0),
            -22,
        );
        t.eq(b"bad cmd", sys_membarrier(1 << 12, 0, 0), -22);
        t.eq(
            b"reg sync_core",
            sys_membarrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0),
            0,
        );
        t.eq(
            b"sync_core",
            sys_membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0),
            0,
        );
        // Registering SYNC_CORE marks the private state but not its
        // readiness (Linux sets PRIVATE_EXPEDITED, not its _READY)
        t.eq(
            b"private after sync",
            sys_membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0),
            -1,
        );
        t.eq(
            b"regs sync",
            sys_membarrier(MEMBARRIER_CMD_GET_REGISTRATIONS, 0, 0),
            (MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED
                | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE) as i64,
        );
        t.eq(
            b"reg global",
            sys_membarrier(MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED, 0, 0),
            0,
        );
        t.eq(
            b"reg private",
            sys_membarrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0, 0),
            0,
        );
        t.eq(
            b"private",
            sys_membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0),
            0,
        );
        let all = (MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED
            | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED
            | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE) as i64;
        t.eq(
            b"regs all",
            sys_membarrier(MEMBARRIER_CMD_GET_REGISTRATIONS, 0, 0),
            all,
        );
        let c = sys_fork();
        if c == 0 {
            let r = sys_membarrier(MEMBARRIER_CMD_GET_REGISTRATIONS, 0, 0);
            sys_exit(if r == all { 0 } else { 1 });
        }
        let mut st = 0i32;
        sys_wait4(c, &mut st, 0, 0);
        t.eq(b"fork inherits", st as i64, 0);
        t.done();
        sys_exit((fail_count() - before).min(255) as u64);
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    add_fails(((st >> 8) & 0xff) as u32);
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

    pass(b"MEMBARRIER");
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
    pass(b"READAHEAD");
}
