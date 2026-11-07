//! Path lookup errors reach the caller unchanged (Linux user_path_at /
//! filp_open return the walk's error)
//!
//! Tests:
//! - ERRNO_PASSTHROUGH: a path with a component longer than NAME_MAX is
//!   ENAMETOOLONG from inotify_add_watch, fanotify_mark and acct, not
//!   EINVAL

use crate::helpers::{print, print_num, println};
use hk_syscall::{
    sys_acct, sys_close, sys_fanotify_init, sys_fanotify_mark, sys_inotify_add_watch,
    sys_inotify_init1,
};

const ENAMETOOLONG: i64 = -36;
const AT_FDCWD: i32 = -100;
const IN_ALL_EVENTS: u32 = 0xfff;
const FAN_MARK_ADD: u32 = 1;
const FAN_OPEN: u64 = 0x20;

pub fn run_tests() {
    // "/" + 300 x 'a' + NUL
    let mut path = [b'a'; 302];
    path[0] = b'/';
    path[301] = 0;

    let ifd = sys_inotify_init1(0);
    let i = sys_inotify_add_watch(ifd as i32, path.as_ptr(), IN_ALL_EVENTS);
    sys_close(ifd as u64);

    let ffd = sys_fanotify_init(0, 0);
    let f = sys_fanotify_mark(ffd as i32, FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, path.as_ptr());
    sys_close(ffd as u64);

    let a = sys_acct(path.as_ptr());

    print(b"ERRNO_PASSTHROUGH");
    if i == ENAMETOOLONG && f == ENAMETOOLONG && a == ENAMETOOLONG {
        println(b":OK");
    } else {
        print(b":FAIL inotify ");
        print_num(i);
        print(b" fanotify ");
        print_num(f);
        print(b" acct ");
        print_num(a);
        println(b"");
    }
}
