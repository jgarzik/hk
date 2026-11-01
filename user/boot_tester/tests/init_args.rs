//! What pid 1 (this boot tester) was started with (Linux init/main.c
//! run_init_process): the kernel execs it like any program
//!
//! Tests:
//! - INIT_ARGV: /proc/1/cmdline is just its path, /bin/init (the boot
//!   command lines carry only parameters the kernel takes itself)
//! - INIT_ENV: /proc/1/environ is HOME=/ and TERM=linux

use super::helpers::{print, println};
use hk_syscall::{O_RDONLY, sys_close, sys_open, sys_read};

pub fn run_tests() {
    check(b"INIT_ARGV", b"/proc/1/cmdline\0", b"/bin/init\0");
    check(b"INIT_ENV", b"/proc/1/environ\0", b"HOME=/\0TERM=linux\0");
}

fn check(name: &[u8], path: &[u8], want: &[u8]) {
    let mut buf = [0u8; 256];
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    let n = if fd >= 0 {
        let n = sys_read(fd as u64, buf.as_mut_ptr(), buf.len() as u64);
        sys_close(fd as u64);
        n
    } else {
        fd
    };
    print(name);
    if n >= 0 && &buf[..n as usize] == want {
        println(b":OK");
    } else {
        print(b":FAIL got ");
        println(&buf[..n.max(0) as usize]);
    }
}
