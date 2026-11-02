//! The descriptor cap fs.nr_open (Linux fs/file.c sysctl_nr_open,
//! expand_files, ksys_dup3; kernel/sys.c do_prlimit)
//!
//! Tests:
//! - NR_OPEN_DEFAULT: fs.nr_open is 1048576 and init starts with
//!   RLIMIT_NOFILE 1024 soft, 4096 hard (INR_OPEN_CUR, INR_OPEN_MAX)
//! - NR_OPEN_SYSCTL: writes outside 64..=2147483584 are EINVAL; the top
//!   of the range is accepted
//! - NR_OPEN_RLIMIT: a RLIMIT_NOFILE hard limit above fs.nr_open, or
//!   RLIM_INFINITY, is EPERM even for root (setrlimit and prlimit64);
//!   fs.nr_open itself is allowed
//! - NR_OPEN_ALLOC: with fs.nr_open lowered under RLIMIT_NOFILE, a new
//!   descriptor past it is EMFILE (F_DUPFD) and dup3 to one is EBADF
//! - DUP3_RLIMIT: dup3 to a descriptor at or past RLIMIT_NOFILE is
//!   EBADF and leaves that descriptor open
//!
//! fs.nr_open is global: every test puts 1048576 back.

use super::helpers::{print, print_num, println};
use super::sysctl::{read_file, write_file};
use core::ptr;
use hk_syscall::{
    O_RDONLY, RLIM_INFINITY, RLIMIT_NOFILE, RLimit, sys_close, sys_dup3, sys_fcntl, sys_getrlimit,
    sys_open, sys_prlimit64, sys_setrlimit,
};

const PATH: &[u8] = b"/proc/sys/fs/nr_open\0";
const DEFAULT: u64 = 1048576;
const EBADF: i64 = -9;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;
const EPERM: i64 = -1;
const F_DUPFD: i32 = 0;
const F_GETFD: i32 = 1;

pub fn run_tests() {
    report(b"NR_OPEN_DEFAULT", default());
    report(b"NR_OPEN_SYSCTL", sysctl());
    report(b"NR_OPEN_RLIMIT", rlimit());
    report(b"NR_OPEN_ALLOC", alloc());
    report(b"DUP3_RLIMIT", dup3_rlimit());
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

/// fs.nr_open, or -1
fn nr_open() -> i64 {
    let mut b = [0u8; 32];
    let n = read_file(PATH, &mut b);
    let mut v = -1i64;
    for &c in &b[..n.max(0) as usize] {
        if !c.is_ascii_digit() {
            break;
        }
        v = v.max(0) * 10 + (c - b'0') as i64;
    }
    v
}

fn restore() {
    write_file(PATH, b"1048576\n");
}

fn set_nofile(cur: u64, max: u64) -> i64 {
    let r = RLimit {
        rlim_cur: cur,
        rlim_max: max,
    };
    sys_setrlimit(RLIMIT_NOFILE, &r)
}

fn default() -> i64 {
    if nr_open() != DEFAULT as i64 {
        return 1;
    }
    let mut r = RLimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if sys_prlimit64(1, RLIMIT_NOFILE, ptr::null(), &mut r) != 0 {
        return 2;
    }
    if r.rlim_cur != 1024 || r.rlim_max != 4096 {
        return 3;
    }
    0
}

fn sysctl() -> i64 {
    let step = if write_file(PATH, b"63\n") != EINVAL {
        1
    } else if write_file(PATH, b"2147483647\n") != EINVAL {
        2
    } else if write_file(PATH, b"-1\n") != EINVAL {
        3
    } else if write_file(PATH, b"2147483584\n") != 11 || nr_open() != 2147483584 {
        4
    } else if write_file(PATH, b"64\n") != 3 || nr_open() != 64 {
        5
    } else {
        0
    };
    restore();
    step
}

fn rlimit() -> i64 {
    let mut old = RLimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    sys_getrlimit(RLIMIT_NOFILE, &mut old);
    let over = RLimit {
        rlim_cur: 1024,
        rlim_max: DEFAULT + 1,
    };
    let step = if set_nofile(1024, DEFAULT + 1) != EPERM {
        1
    } else if set_nofile(1024, RLIM_INFINITY) != EPERM {
        2
    } else if sys_prlimit64(0, RLIMIT_NOFILE, &over, ptr::null_mut()) != EPERM {
        3
    } else if set_nofile(DEFAULT, DEFAULT) != 0 {
        4
    } else {
        0
    };
    sys_setrlimit(RLIMIT_NOFILE, &old);
    step
}

fn alloc() -> i64 {
    let mut old = RLimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    sys_getrlimit(RLIMIT_NOFILE, &mut old);
    let fd = sys_open(b"/\0".as_ptr(), O_RDONLY, 0);
    if fd < 0 || set_nofile(DEFAULT, DEFAULT) != 0 {
        sys_close(fd as u64);
        return 1;
    }
    if write_file(PATH, b"1024\n") != 5 {
        restore();
        sys_close(fd as u64);
        return 2;
    }
    let dupfd = sys_fcntl(fd as i32, F_DUPFD, 100000);
    let dup3 = sys_dup3(fd as i32, 100000, 0);
    let low = sys_fcntl(fd as i32, F_DUPFD, 0);
    restore();
    for r in [dupfd, dup3, low] {
        if r >= 0 {
            sys_close(r as u64);
        }
    }
    sys_close(fd as u64);
    sys_setrlimit(RLIMIT_NOFILE, &old);
    if dupfd != EMFILE {
        3
    } else if dup3 != EBADF {
        4
    } else if low < 0 {
        5
    } else {
        0
    }
}

fn dup3_rlimit() -> i64 {
    let mut old = RLimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    sys_getrlimit(RLIMIT_NOFILE, &mut old);
    let fd = sys_open(b"/\0".as_ptr(), O_RDONLY, 0);
    if fd < 0 || sys_dup3(fd as i32, 100, 0) != 100 {
        sys_close(fd as u64);
        return 1;
    }
    let step = if set_nofile(64, old.rlim_max) != 0 {
        2
    } else if sys_dup3(fd as i32, 100, 0) != EBADF {
        3
    } else if sys_dup3(fd as i32, 64, 0) != EBADF {
        4
    } else if sys_fcntl(100, F_GETFD, 0) < 0 {
        5
    } else {
        0
    };
    sys_setrlimit(RLIMIT_NOFILE, &old);
    sys_close(100);
    sys_close(fd as u64);
    step
}
