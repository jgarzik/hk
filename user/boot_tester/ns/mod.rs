//! Namespace file (nsfs) tests

pub mod listns;
pub mod mntns;
pub mod nsfs;

use hk_syscall::{Stat, sys_exit, sys_fork, sys_wait4};

/// "<pre><pid><post>" NUL-terminated in `b`
pub fn pid_path<'a>(b: &'a mut [u8; 64], pre: &[u8], pid: i64, post: &[u8]) -> &'a [u8] {
    let mut n = 0;
    for &c in pre {
        b[n] = c;
        n += 1;
    }
    let mut d = [0u8; 20];
    let mut k = 0;
    let mut v = pid.unsigned_abs();
    loop {
        d[k] = b'0' + (v % 10) as u8;
        k += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    while k > 0 {
        k -= 1;
        b[n] = d[k];
        n += 1;
    }
    for &c in post {
        b[n] = c;
        n += 1;
    }
    b[n] = 0;
    &b[..=n]
}

/// The number in "<ty>:[<n>]", what readlink of `path` (NUL-terminated)
/// gives for a namespace link of type `ty`; 0 if it is not that
pub fn ns_link(path: &[u8], ty: &[u8]) -> u64 {
    let mut b = [0u8; 64];
    let n = hk_syscall::sys_readlink(path.as_ptr(), b.as_mut_ptr(), b.len() as u64);
    if n <= 0 {
        return 0;
    }
    let s = &b[..n as usize];
    if s.len() < ty.len() + 4
        || &s[..ty.len()] != ty
        || &s[ty.len()..ty.len() + 2] != b":["
        || s[s.len() - 1] != b']'
    {
        return 0;
    }
    let mut v = 0u64;
    for &c in &s[ty.len() + 2..s.len() - 1] {
        if !c.is_ascii_digit() {
            return 0;
        }
        v = v * 10 + u64::from(c - b'0');
    }
    v
}

/// stat(2) of `path`, None on error
pub fn stat(path: &[u8]) -> Option<Stat> {
    let mut st = Stat::default();
    (hk_syscall::sys_stat(path.as_ptr(), &mut st) == 0).then_some(st)
}

/// fstat(2) of `fd`, None on error
pub fn fstat(fd: i64) -> Option<Stat> {
    let mut st = Stat::default();
    (hk_syscall::sys_fstat(fd as i32, &mut st) == 0).then_some(st)
}

/// The first of `steps` that is false, numbered from 1; 0 if none
pub fn first_bad(steps: &[bool]) -> u8 {
    steps.iter().position(|ok| !ok).map_or(0, |i| i as u8 + 1)
}

/// Run `f` in a child; its exit status (0: passed, else the failed
/// step), or 200 if the fork or wait failed, 128+sig if it was killed
pub fn in_child(f: fn() -> u8) -> i64 {
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(u64::from(f()));
    }
    let mut ws = 0i32;
    if pid < 0 || sys_wait4(pid, &mut ws, 0, 0) != pid {
        return 200;
    }
    if ws & 0x7f != 0 {
        return 128 + i64::from(ws & 0x7f);
    }
    i64::from((ws >> 8) & 0xff)
}

pub fn run_tests() {
    nsfs::run_tests();
    mntns::run_tests();
    listns::run_tests();
}
