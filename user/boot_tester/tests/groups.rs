//! Supplementary groups (Linux kernel/groups.c, in_group_p)
//!
//! Tests (in a child, so init keeps its groups):
//! - GROUPS_SET_GET: setgroups stores the list sorted; getgroups(0)
//!   counts, a short size is EINVAL; /proc/self/status shows
//!   `Groups:\t5 50 100 `; a forked child inherits them
//! - GROUPS_LIMITS: gid -1 and more than NGROUPS_MAX are EINVAL;
//!   without CAP_SETGID setgroups is EPERM
//! - GROUPS_DAC: a file readable only by its group (0640, group 4242)
//!   opens for a uid-1000 process holding 4242 as a supplementary group,
//!   and is EACCES for one that does not

use super::helpers::{print, print_num, println};
use hk_syscall::{
    O_CREAT, O_RDONLY, O_WRONLY, sys_chmod, sys_chown, sys_close, sys_exit, sys_fork,
    sys_getgroups, sys_open, sys_read, sys_setgroups, sys_setresgid, sys_setresuid, sys_unlink,
    sys_wait4,
};

const EINVAL: i64 = -22;
const EPERM: i64 = -1;
const EACCES: i64 = -13;
const FILE: &[u8] = b"/grp_test\0";

pub fn run_tests() {
    in_child(b"GROUPS_SET_GET", set_get);
    in_child(b"GROUPS_LIMITS", limits);
    dac();
}

fn report(name: &[u8], step: i64) {
    print(name);
    if step == 0 {
        println(b":OK");
    } else {
        print(b":FAIL step ");
        print_num(step);
        println(b"");
    }
}

/// Run `f` in a child; its exit status is the failed step (0: passed)
fn in_child(name: &[u8], f: fn() -> u64) {
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(f());
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    let step = if st & 0x7f == 0 { (st >> 8) & 0xff } else { 100 };
    report(name, step as i64);
}

fn find(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn set_get() -> u64 {
    let set = [100u32, 5, 50];
    if sys_setgroups(3, set.as_ptr()) != 0 {
        return 1;
    }
    if sys_getgroups(0, core::ptr::null_mut()) != 3 {
        return 2;
    }
    let mut got = [0u32; 8];
    if sys_getgroups(8, got.as_mut_ptr()) != 3 || got[..3] != [5, 50, 100] {
        return 3;
    }
    if sys_getgroups(2, got.as_mut_ptr()) != EINVAL {
        return 4;
    }
    let mut buf = [0u8; 2048];
    let fd = sys_open(b"/proc/self/status\0".as_ptr(), O_RDONLY, 0);
    let n = sys_read(fd as u64, buf.as_mut_ptr(), buf.len() as u64);
    sys_close(fd as u64);
    if n <= 0 || !find(&buf[..n as usize], b"\nGroups:\t5 50 100 \n") {
        return 5;
    }
    let pid = sys_fork();
    if pid == 0 {
        let ok = sys_getgroups(8, got.as_mut_ptr()) == 3 && got[..3] == [5, 50, 100];
        sys_exit(if ok { 0 } else { 1 });
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    if st != 0 {
        return 6;
    }
    // Empty again
    if sys_setgroups(0, core::ptr::null()) != 0 || sys_getgroups(0, core::ptr::null_mut()) != 0 {
        return 7;
    }
    0
}

fn limits() -> u64 {
    let bad = [7u32, u32::MAX];
    if sys_setgroups(2, bad.as_ptr()) != EINVAL {
        return 1;
    }
    if sys_setgroups(65537, bad.as_ptr()) != EINVAL {
        return 2;
    }
    if sys_setresuid(65534, 65534, 65534) != 0 {
        return 3;
    }
    let one = [7u32];
    if sys_setgroups(1, one.as_ptr()) != EPERM {
        return 4;
    }
    0
}

/// Child: hold `groups` (none if empty), become uid/gid 1000, open FILE
fn open_as(groups: &[u32]) -> u64 {
    if sys_setgroups(groups.len() as i32, groups.as_ptr()) != 0 {
        return 1;
    }
    if sys_setresgid(1000, 1000, 1000) != 0 || sys_setresuid(1000, 1000, 1000) != 0 {
        return 2;
    }
    let fd = sys_open(FILE.as_ptr(), O_RDONLY, 0);
    if fd >= 0 {
        sys_close(fd as u64);
        return 0;
    }
    if fd == EACCES { 10 } else { 3 }
}

fn dac() {
    let fd = sys_open(FILE.as_ptr(), O_CREAT | O_WRONLY, 0o640);
    sys_close(fd as u64);
    if fd < 0 || sys_chown(FILE.as_ptr(), 0, 4242) != 0 || sys_chmod(FILE.as_ptr(), 0o640) != 0 {
        report(b"GROUPS_DAC", 90);
        return;
    }
    let with = run(|| open_as(&[4242]));
    let without = run(|| open_as(&[]));
    sys_unlink(FILE.as_ptr());
    let step = if with != 0 {
        with
    } else if without != 10 {
        20 + without
    } else {
        0
    };
    report(b"GROUPS_DAC", step);
}

fn run(f: fn() -> u64) -> i64 {
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(f());
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    if st & 0x7f == 0 { ((st >> 8) & 0xff) as i64 } else { 100 }
}
