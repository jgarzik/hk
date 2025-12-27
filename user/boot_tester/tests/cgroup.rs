//! Cgroup tests
//!
//! Tests the cgroup v2 implementation by:
//! 1. Mounting cgroupfs at /sys/fs/cgroup
//! 2. Creating a child cgroup via mkdir
//! 3. Reading control files (cgroup.controllers, cgroup.procs)
//! 4. Reading /proc/self/cgroup
//! 5. Writing to control files (pids.max)
//! 6. Cleaning up with rmdir

use super::helpers::{print, print_num, println};
use hk_syscall::{
    sys_close, sys_mkdir, sys_mount, sys_open, sys_read, sys_rmdir, sys_write, O_RDONLY, O_RDWR,
};

/// Run all cgroup tests
pub fn run_tests() {
    println(b"=== Cgroup Test ===");
    test_mount_cgroupfs();
    test_proc_self_cgroup();
    test_create_cgroup();
    test_read_control_files();
    test_write_pids_max();
    test_cleanup_cgroup();
    println(b"=== Cgroup Test Complete ===");
}

/// Test 1: Mount cgroupfs at /sys/fs/cgroup
fn test_mount_cgroupfs() {
    // First create /sys if it doesn't exist
    let sys_path = b"/sys\0";
    let _ = sys_mkdir(sys_path.as_ptr(), 0o755);

    // Create /sys/fs if it doesn't exist
    let sys_fs_path = b"/sys/fs\0";
    let _ = sys_mkdir(sys_fs_path.as_ptr(), 0o755);

    // Create /sys/fs/cgroup
    let cgroup_path = b"/sys/fs/cgroup\0";
    let mkdir_ret = sys_mkdir(cgroup_path.as_ptr(), 0o755);
    if mkdir_ret < 0 && mkdir_ret != -17 {
        // -17 is EEXIST
        print(b"ERROR: mkdir /sys/fs/cgroup failed: ");
        print_num(mkdir_ret);
        return;
    }

    // Mount cgroup2 filesystem
    let source = b"none\0";
    let fstype = b"cgroup2\0";
    let ret = sys_mount(
        source.as_ptr(),
        cgroup_path.as_ptr(),
        fstype.as_ptr(),
        0,
        0,
    );
    if ret < 0 && ret != -16 {
        // -16 is EBUSY (already mounted)
        print(b"ERROR: mount cgroup2 failed: ");
        print_num(ret);
    } else {
        println(b"Mounted cgroup2 at /sys/fs/cgroup");
    }
}

/// Test 2: Read /proc/self/cgroup
fn test_proc_self_cgroup() {
    let path = b"/proc/self/cgroup\0";
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        print(b"ERROR: open /proc/self/cgroup failed: ");
        print_num(fd);
        return;
    }

    print(b"Opened /proc/self/cgroup, fd=");
    print_num(fd);

    let mut buf = [0u8; 256];
    let n = sys_read(fd as u64, buf.as_mut_ptr(), buf.len() as u64);
    if n < 0 {
        print(b"ERROR: read /proc/self/cgroup failed: ");
        print_num(n);
    } else {
        print(b"Read ");
        print_num(n);
        print(b" bytes: ");
        sys_write(1, buf.as_ptr(), n as u64);
    }
    sys_close(fd as u64);
}

/// Test 3: Create a child cgroup via mkdir
fn test_create_cgroup() {
    let test_cgroup = b"/sys/fs/cgroup/test_cgroup\0";
    let ret = sys_mkdir(test_cgroup.as_ptr(), 0o755);
    if ret < 0 && ret != -17 {
        // EEXIST
        print(b"ERROR: mkdir test_cgroup failed: ");
        print_num(ret);
    } else {
        println(b"Created /sys/fs/cgroup/test_cgroup");
    }
}

/// Test 4: Read control files
fn test_read_control_files() {
    // Read cgroup.controllers
    let controllers_path = b"/sys/fs/cgroup/cgroup.controllers\0";
    let fd = sys_open(controllers_path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        print(b"ERROR: open cgroup.controllers failed: ");
        print_num(fd);
    } else {
        print(b"cgroup.controllers: ");
        let mut buf = [0u8; 256];
        let n = sys_read(fd as u64, buf.as_mut_ptr(), buf.len() as u64);
        if n > 0 {
            sys_write(1, buf.as_ptr(), n as u64);
        } else {
            println(b"(empty)");
        }
        sys_close(fd as u64);
    }

    // Read cgroup.procs
    let procs_path = b"/sys/fs/cgroup/cgroup.procs\0";
    let fd = sys_open(procs_path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        print(b"ERROR: open cgroup.procs failed: ");
        print_num(fd);
    } else {
        print(b"cgroup.procs: ");
        let mut buf = [0u8; 256];
        let n = sys_read(fd as u64, buf.as_mut_ptr(), buf.len() as u64);
        if n > 0 {
            sys_write(1, buf.as_ptr(), n as u64);
        } else {
            println(b"(empty)");
        }
        sys_close(fd as u64);
    }

    // Read pids.max from test_cgroup
    let pids_max_path = b"/sys/fs/cgroup/test_cgroup/pids.max\0";
    let fd = sys_open(pids_max_path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        print(b"pids.max not available (expected if pids controller not enabled): ");
        print_num(fd);
    } else {
        print(b"test_cgroup/pids.max: ");
        let mut buf = [0u8; 64];
        let n = sys_read(fd as u64, buf.as_mut_ptr(), buf.len() as u64);
        if n > 0 {
            sys_write(1, buf.as_ptr(), n as u64);
        }
        sys_close(fd as u64);
    }
}

/// Test 5: Write to pids.max
fn test_write_pids_max() {
    // First enable pids controller in subtree_control
    let subtree_control_path = b"/sys/fs/cgroup/cgroup.subtree_control\0";
    let fd = sys_open(subtree_control_path.as_ptr(), O_RDWR, 0);
    if fd >= 0 {
        let enable_pids = b"+pids";
        let ret = sys_write(fd as u64, enable_pids.as_ptr(), enable_pids.len() as u64);
        if ret < 0 {
            print(b"Note: enabling pids controller returned: ");
            print_num(ret);
        } else {
            println(b"Enabled pids controller in subtree_control");
        }
        sys_close(fd as u64);
    }

    // Now try to write pids.max in test_cgroup
    let pids_max_path = b"/sys/fs/cgroup/test_cgroup/pids.max\0";
    let fd = sys_open(pids_max_path.as_ptr(), O_RDWR, 0);
    if fd < 0 {
        print(b"Cannot open pids.max for writing: ");
        print_num(fd);
        return;
    }

    // Set pids.max to 100
    let limit = b"100";
    let ret = sys_write(fd as u64, limit.as_ptr(), limit.len() as u64);
    if ret < 0 {
        print(b"ERROR: write pids.max failed: ");
        print_num(ret);
    } else {
        println(b"Set pids.max=100");
    }
    sys_close(fd as u64);

    // Verify by reading back
    let fd = sys_open(pids_max_path.as_ptr(), O_RDONLY, 0);
    if fd >= 0 {
        print(b"Verify pids.max: ");
        let mut buf = [0u8; 64];
        let n = sys_read(fd as u64, buf.as_mut_ptr(), buf.len() as u64);
        if n > 0 {
            sys_write(1, buf.as_ptr(), n as u64);
        }
        sys_close(fd as u64);
    }
}

/// Test 6: Cleanup - remove test cgroup
fn test_cleanup_cgroup() {
    let test_cgroup = b"/sys/fs/cgroup/test_cgroup\0";
    let ret = sys_rmdir(test_cgroup.as_ptr());
    if ret < 0 {
        // May fail if cgroup is not empty or still in use
        print(b"Note: rmdir test_cgroup returned: ");
        print_num(ret);
    } else {
        println(b"Removed /sys/fs/cgroup/test_cgroup");
    }
}
