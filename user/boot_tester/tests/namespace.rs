//! Namespace tests
//!
//! Tests for namespace-related syscalls:
//! - unshare(2) - create new namespace(s) for current process
//! - setns(2) - join existing namespace via file descriptor

use super::helpers::{linux_at_least, print, print_num, println};
use hk_syscall::{
    CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUSER, CLONE_NEWUTS, O_CREAT, O_RDONLY,
    O_WRONLY, Stat, UtsName, sys_chdir, sys_close, sys_exit, sys_fork, sys_mkdir, sys_mount,
    sys_open, sys_pivot_root, sys_sethostname, sys_setns, sys_stat, sys_umount2, sys_uname,
    sys_unshare, sys_wait4,
};

const EINVAL: i64 = -22;
const MNT_DETACH: u64 = 2;

/// Run all namespace tests
pub fn run_tests() {
    println(b"[NAMESPACE TESTS]");
    test_unshare_noop();
    test_unshare_newuts();
    test_unshare_newnet();
    test_unshare_newpid();
    test_unshare_newuser();
    test_unshare_newns();
    test_setns_ebadf();
    test_setns_uts();
    test_pivot_root_enoent();
    test_pivot_root_enotdir();
    test_pivot_root_einval();
    in_child(b"PIVOT_ROOT_ROOTFS", pivot_rootfs);
    in_child(b"UMOUNT_ROOTFS_DETACH", umount_rootfs);
}

/// Run `f` in a child with a mount namespace of its own; its exit
/// status is the result (0 OK, else which step failed)
fn in_child(name: &[u8], f: fn() -> i32) {
    print(name);
    let pid = sys_fork();
    if pid == 0 {
        if sys_unshare(CLONE_NEWNS) != 0 {
            sys_exit(100);
        }
        sys_exit(f() as u64);
    }
    let mut ws: i32 = 0;
    if pid < 0 || sys_wait4(pid, &mut ws, 0, 0) != pid {
        print(b":FAIL fork/wait ");
        print_num(pid);
        println(b"");
        return;
    }
    let st = (ws >> 8) & 0xff;
    if ws & 0x7f == 0 && st == 0 {
        println(b":OK");
    } else {
        print(b":FAIL step ");
        print_num(if ws & 0x7f != 0 {
            -(ws as i64 & 0x7f)
        } else {
            st as i64
        });
        println(b"");
    }
}

/// Did `want` come back: 0 when the initramfs has a parent (Linux 7.0+:
/// the rootfs is mounted on nullfs), else EINVAL ("absolute root")
fn rootfs_ret() -> i64 {
    if linux_at_least(7, 0) { 0 } else { EINVAL }
}

/// The switch_root of Linux 7.0's ramfs-rootfs-initramfs.rst, from the
/// initramfs: chdir to the new root, pivot_root(".", "."), unmount the
/// old root stacked on it. The new root's file is then at "/".
fn pivot_rootfs() -> i32 {
    let dir = b"/tmp/pivot_new\0";
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777);
    sys_mkdir(dir.as_ptr(), 0o755);
    if sys_mount(b"none\0".as_ptr(), dir.as_ptr(), b"ramfs\0".as_ptr(), 0, 0) != 0 {
        return 1;
    }
    let fd = sys_open(
        b"/tmp/pivot_new/marker\0".as_ptr(),
        O_CREAT | O_WRONLY,
        0o644,
    );
    if fd < 0 {
        return 2;
    }
    sys_close(fd as u64);
    if sys_chdir(dir.as_ptr()) != 0 {
        return 3;
    }
    let r = sys_pivot_root(b".\0".as_ptr(), b".\0".as_ptr());
    if r != rootfs_ret() {
        return 4;
    }
    if r != 0 {
        return 0;
    }
    if sys_umount2(b".\0".as_ptr(), MNT_DETACH) != 0 {
        return 5;
    }
    if !exists(b"/marker\0") {
        return 6;
    }
    // The old root is gone: nothing of the initramfs is left
    if exists(b"/tmp\0") {
        return 7;
    }
    0
}

fn exists(path: &[u8]) -> bool {
    // SAFETY: Stat is plain integers, valid all-zero
    let mut st: Stat = unsafe { core::mem::zeroed() };
    sys_stat(path.as_ptr(), &mut st) == 0
}

/// umount2("/", MNT_DETACH) takes the rootfs off its nullfs parent
/// (7.0+); the absolute root is EINVAL
fn umount_rootfs() -> i32 {
    if sys_umount2(b"/\0".as_ptr(), MNT_DETACH) != rootfs_ret() {
        return 1;
    }
    // Root and cwd still hold the detached rootfs
    if !exists(b"/proc\0") {
        return 2;
    }
    0
}

/// Test: unshare(0) should succeed (no-op)
fn test_unshare_noop() {
    let ret = sys_unshare(0);
    if ret == 0 {
        println(b"UNSHARE_NOOP:OK");
    } else {
        print(b"UNSHARE_NOOP:FAIL ret=");
        print_num(ret);
        println(b"");
    }
}

/// Test: unshare(CLONE_NEWUTS) creates new UTS namespace
fn test_unshare_newuts() {
    let pid = sys_fork();
    if pid < 0 {
        print(b"UNSHARE_NEWUTS:FAIL fork failed ");
        print_num(pid);
        println(b"");
        return;
    }

    if pid == 0 {
        // Child: unshare UTS namespace
        let ret = sys_unshare(CLONE_NEWUTS);
        if ret != 0 {
            sys_exit(1);
        }

        // Set hostname in new namespace
        let new_name = b"nstest\0";
        let ret = sys_sethostname(new_name.as_ptr(), 6);
        if ret != 0 {
            sys_exit(2);
        }

        // Verify hostname changed
        let mut uts = UtsName::default();
        let ret = sys_uname(&mut uts);
        if ret != 0 {
            sys_exit(3);
        }

        // Check if nodename starts with "nstest"
        if uts.nodename[0] == b'n'
            && uts.nodename[1] == b's'
            && uts.nodename[2] == b't'
            && uts.nodename[3] == b'e'
            && uts.nodename[4] == b's'
            && uts.nodename[5] == b't'
        {
            sys_exit(0);
        }
        sys_exit(4);
    } else {
        // Parent: wait for child
        let mut wstatus: i32 = 0;
        sys_wait4(pid, &mut wstatus, 0, 0);

        let exit_status = (wstatus >> 8) & 0xff;
        if exit_status == 0 {
            println(b"UNSHARE_NEWUTS:OK");
        } else {
            print(b"UNSHARE_NEWUTS:FAIL exit_status=");
            print_num(exit_status as i64);
            println(b"");
        }
    }
}

/// Test: unshare(CLONE_NEWNET) creates new network namespace
fn test_unshare_newnet() {
    // Must fork first so unshare happens in child, not main boot_tester process
    // (otherwise subsequent tests lose network config)
    let pid = sys_fork();
    if pid < 0 {
        print(b"UNSHARE_NEWNET:FAIL fork failed ");
        print_num(pid);
        println(b"");
        return;
    }

    if pid == 0 {
        // Child: unshare network namespace
        let ret = sys_unshare(CLONE_NEWNET);
        if ret != 0 {
            sys_exit(1);
        }

        // Success - we created a new network namespace
        // The new namespace has only loopback device
        sys_exit(0);
    } else {
        // Parent: wait for child
        let mut wstatus: i32 = 0;
        sys_wait4(pid, &mut wstatus, 0, 0);

        let exit_status = (wstatus >> 8) & 0xff;
        if exit_status == 0 {
            println(b"UNSHARE_NEWNET:OK");
        } else {
            print(b"UNSHARE_NEWNET:FAIL exit_status=");
            print_num(exit_status as i64);
            println(b"");
        }
    }
}

/// Test: unshare(CLONE_NEWPID) creates new PID namespace
fn test_unshare_newpid() {
    let pid = sys_fork();
    if pid < 0 {
        print(b"UNSHARE_NEWPID:FAIL fork failed ");
        print_num(pid);
        println(b"");
        return;
    }

    if pid == 0 {
        // Child: just call unshare(CLONE_NEWPID) and exit
        // This tests that the syscall doesn't crash
        let ret = sys_unshare(CLONE_NEWPID);
        if ret == 0 {
            sys_exit(0);
        } else {
            sys_exit(1);
        }
    } else {
        // Parent: wait for child
        let mut wstatus: i32 = 0;
        sys_wait4(pid, &mut wstatus, 0, 0);

        let exit_status = (wstatus >> 8) & 0xff;
        if exit_status == 0 {
            println(b"UNSHARE_NEWPID:OK");
        } else {
            print(b"UNSHARE_NEWPID:FAIL exit_status=");
            print_num(exit_status as i64);
            println(b"");
        }
    }
}

/// Test: unshare(CLONE_NEWUSER) creates new user namespace
fn test_unshare_newuser() {
    let pid = sys_fork();
    if pid < 0 {
        print(b"UNSHARE_NEWUSER:FAIL fork failed ");
        print_num(pid);
        println(b"");
        return;
    }

    if pid == 0 {
        // Child: unshare user namespace
        let ret = sys_unshare(CLONE_NEWUSER);
        if ret != 0 {
            print(b"UNSHARE_NEWUSER child: unshare failed ");
            print_num(ret);
            println(b"");
            sys_exit(1);
        }

        // Success - we created a new user namespace
        sys_exit(0);
    } else {
        // Parent: wait for child
        let mut wstatus: i32 = 0;
        sys_wait4(pid, &mut wstatus, 0, 0);

        let exit_status = (wstatus >> 8) & 0xff;
        if exit_status == 0 {
            println(b"UNSHARE_NEWUSER:OK");
        } else {
            print(b"UNSHARE_NEWUSER:FAIL exit_status=");
            print_num(exit_status as i64);
            println(b"");
        }
    }
}

/// Test: setns with invalid fd returns EBADF
fn test_setns_ebadf() {
    // Use an invalid file descriptor
    let ret = sys_setns(9999, 0);
    if ret == -9 {
        // -EBADF
        println(b"SETNS_EBADF:OK");
    } else {
        print(b"SETNS_EBADF:FAIL ret=");
        print_num(ret);
        println(b"");
    }
}

/// Test: setns to join UTS namespace via /proc/<pid>/ns/uts
fn test_setns_uts() {
    // Simpler test: open our own /proc/self/ns/uts and setns to it
    // This should be a no-op but verifies the mechanism works
    use hk_syscall::sys_getpid;

    let my_pid = sys_getpid();

    // Build path: /proc/<pid>/ns/uts
    let mut path_buf = [0u8; 32];
    let prefix = b"/proc/";
    let suffix = b"/ns/uts";

    // Copy prefix
    let mut i = 0;
    while i < prefix.len() {
        path_buf[i] = prefix[i];
        i += 1;
    }

    // Convert PID to string
    let mut pid_str = [0u8; 10];
    let mut pid_len = 0;
    let mut temp_pid = my_pid as i64;
    if temp_pid == 0 {
        pid_str[0] = b'0';
        pid_len = 1;
    } else {
        while temp_pid > 0 {
            pid_str[pid_len] = b'0' + (temp_pid % 10) as u8;
            temp_pid /= 10;
            pid_len += 1;
        }
        // Reverse
        let mut j = 0;
        while j < pid_len / 2 {
            let tmp = pid_str[j];
            pid_str[j] = pid_str[pid_len - 1 - j];
            pid_str[pid_len - 1 - j] = tmp;
            j += 1;
        }
    }

    // Copy PID string
    let mut j = 0;
    while j < pid_len {
        path_buf[i] = pid_str[j];
        i += 1;
        j += 1;
    }

    // Copy suffix
    j = 0;
    while j < suffix.len() {
        path_buf[i] = suffix[j];
        i += 1;
        j += 1;
    }
    path_buf[i] = 0; // NUL terminate

    // Try to open our own namespace file
    let fd = sys_open(path_buf.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        print(b"SETNS_UTS:SKIP (cannot open ns file, ret=");
        print_num(fd);
        println(b")");
        return;
    }

    // Get hostname before
    let mut uts_before = UtsName::default();
    sys_uname(&mut uts_before);

    // Try setns to our own namespace (should be no-op)
    let ret = sys_setns(fd as i32, CLONE_NEWUTS as i32);
    sys_close(fd as u64);

    if ret != 0 {
        print(b"SETNS_UTS:FAIL setns ret=");
        print_num(ret);
        println(b"");
        return;
    }

    // Get hostname after
    let mut uts_after = UtsName::default();
    sys_uname(&mut uts_after);

    // Hostname should be the same (we joined our own namespace)
    let mut match_count = 0;
    for k in 0..10 {
        if uts_before.nodename[k] == uts_after.nodename[k] {
            match_count += 1;
        }
    }

    if match_count == 10 {
        println(b"SETNS_UTS:OK");
    } else {
        print(b"SETNS_UTS:FAIL hostname changed after setns to self, before[0]=");
        print_num(uts_before.nodename[0] as i64);
        print(b" after[0]=");
        print_num(uts_after.nodename[0] as i64);
        println(b"");
    }
}

/// Test: unshare(CLONE_NEWNS) creates new mount namespace
fn test_unshare_newns() {
    let pid = sys_fork();
    if pid < 0 {
        print(b"UNSHARE_NEWNS:FAIL fork failed ");
        print_num(pid);
        println(b"");
        return;
    }

    if pid == 0 {
        // Child: unshare mount namespace
        let ret = sys_unshare(CLONE_NEWNS);
        if ret != 0 {
            sys_exit(1);
        }

        // Success - we created a new mount namespace with cloned mount tree
        sys_exit(0);
    } else {
        // Parent: wait for child
        let mut wstatus: i32 = 0;
        sys_wait4(pid, &mut wstatus, 0, 0);

        let exit_status = (wstatus >> 8) & 0xff;
        if exit_status == 0 {
            println(b"UNSHARE_NEWNS:OK");
        } else {
            print(b"UNSHARE_NEWNS:FAIL exit_status=");
            print_num(exit_status as i64);
            println(b"");
        }
    }
}

/// Test: pivot_root with non-existent paths returns ENOENT
fn test_pivot_root_enoent() {
    let ret = sys_pivot_root(
        b"/nonexistent_path_for_pivot\0".as_ptr(),
        b"/also_nonexistent\0".as_ptr(),
    );
    if ret == -2 {
        // ENOENT
        println(b"PIVOT_ROOT_ENOENT:OK");
    } else {
        print(b"PIVOT_ROOT_ENOENT:FAIL ret=");
        print_num(ret);
        println(b"");
    }
}

/// Test: pivot_root with non-directory returns ENOTDIR
fn test_pivot_root_enotdir() {
    // /dev/null is a character device, not a directory
    let ret = sys_pivot_root(b"/dev/null\0".as_ptr(), b"/tmp\0".as_ptr());
    if ret == -20 {
        // ENOTDIR
        println(b"PIVOT_ROOT_ENOTDIR:OK");
    } else {
        print(b"PIVOT_ROOT_ENOTDIR:FAIL ret=");
        print_num(ret);
        println(b"");
    }
}

/// Test: pivot_root with valid directories that aren't mountpoints returns EINVAL
fn test_pivot_root_einval() {
    // /proc/sys is a directory but not a mount point: EINVAL. Not on
    // the root's mount, which is EBUSY first when the initramfs has a
    // parent (Linux 7.0+: rootfs mounted on nullfs, path_pivot_root)
    let ret = sys_pivot_root(b"/proc/sys\0".as_ptr(), b"/proc/sys\0".as_ptr());
    if ret == -22 {
        // EINVAL (not a mountpoint)
        println(b"PIVOT_ROOT_EINVAL:OK");
    } else {
        print(b"PIVOT_ROOT_EINVAL:FAIL ret=");
        print_num(ret);
        println(b"");
    }
}
