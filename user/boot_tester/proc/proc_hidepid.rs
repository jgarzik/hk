//! procfs mount options (Linux fs/proc/root.c): hidepid= hides other
//! users' processes (noaccess: their directories refuse entry, EPERM;
//! invisible: absent, ENOENT, and not listed), gid= exempts a group,
//! subset=pid leaves only the processes and self; options show in
//! /proc/self/mounts, a remount changes them (a failed one does not),
//! an unknown one is EINVAL
//!
//! - PROC_HIDEPID: one line, the first failed step

use crate::harness::{R, check};
use crate::helpers::{print, print_num, println};
use hk_syscall::{
    O_DIRECTORY, O_RDONLY, O_WRONLY, Stat, sys_close, sys_exit, sys_fork, sys_getdents64,
    sys_getpid, sys_mkdir, sys_mount, sys_open, sys_rmdir, sys_setresgid, sys_setresuid, sys_stat,
    sys_umount2, sys_wait4,
};

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const EINVAL: i64 = -22;
const EBUSY: i64 = -16;
const MS_RDONLY: u64 = 1;
const MS_REMOUNT: u64 = 32;
const MP: &[u8] = b"/tmp/ph\0";
const GID: u32 = 4242;
const UID: u32 = 5000;

pub fn run_tests() {
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777);
    sys_mkdir(MP.as_ptr(), 0o755);
    let r = run();
    sys_umount2(MP.as_ptr(), 0);
    sys_rmdir(MP.as_ptr());
    print(b"PROC_HIDEPID");
    match r {
        Ok(()) => println(b":OK"),
        Err((what, v)) => {
            print(b":FAIL ");
            print(what);
            print(b" got ");
            print_num(v);
            println(b"");
        }
    }
}

fn mount(flags: u64, opts: &[u8]) -> i64 {
    sys_mount(
        b"proc\0".as_ptr(),
        MP.as_ptr(),
        b"proc\0".as_ptr(),
        flags,
        opts.as_ptr() as u64,
    )
}

fn stat(p: &[u8]) -> i64 {
    // SAFETY: Stat is plain integers
    let mut st: Stat = unsafe { core::mem::zeroed() };
    sys_stat(p.as_ptr(), &mut st)
}

/// The /proc/self/mounts options of MP contain `opt`
fn shows(opt: &[u8]) -> bool {
    let mut b = [0u8; 8192];
    let len = crate::helpers::read_file(b"/proc/self/mounts\0", &mut b);
    b[..len.max(0) as usize]
        .split(|&c| c == b'\n')
        .filter(|l| l.split(|&c| c == b' ').nth(1) == Some(&MP[..MP.len() - 1]))
        .any(|l| l.windows(opt.len()).any(|w| w == opt))
}

/// getdents of MP lists `name`
fn lists(name: &[u8]) -> bool {
    let fd = sys_open(MP.as_ptr(), O_RDONLY | O_DIRECTORY, 0);
    if fd < 0 {
        return false;
    }
    let mut buf = [0u8; 4096];
    let mut found = false;
    loop {
        let n = sys_getdents64(fd as u64, buf.as_mut_ptr(), buf.len() as u64);
        if n <= 0 {
            break;
        }
        let mut off = 0;
        while off < n as usize {
            let reclen = u16::from_ne_bytes([buf[off + 16], buf[off + 17]]) as usize;
            let nm = &buf[off + 19..off + reclen];
            let end = nm.iter().position(|&c| c == 0).unwrap_or(nm.len());
            found |= &nm[..end] == name;
            off += reclen;
        }
    }
    sys_close(fd as u64);
    found
}

/// In a child with gid `gid` and uid UID: `f`'s step number (0: all
/// good) is the exit code
fn as_user(gid: u32, f: fn() -> i32) -> i64 {
    let pid = sys_fork();
    if pid == 0 {
        if sys_setresgid(gid, gid, gid) != 0 || sys_setresuid(UID, UID, UID) != 0 {
            sys_exit(99);
        }
        sys_exit(f() as u64);
    }
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    i64::from((st >> 8) & 0xff)
}

/// hidepid=invisible: pid 1 (root) is absent and unlisted; the caller's
/// own process is there
fn invisible() -> i32 {
    if stat(b"/tmp/ph/1\0") != ENOENT {
        return 1;
    }
    if lists(b"1") {
        return 2;
    }
    let mut p = [0u8; 32];
    if stat(own(&mut p)) != 0 {
        return 3;
    }
    0
}

/// /tmp/ph/<own pid>
fn own(buf: &mut [u8; 32]) -> &[u8] {
    let pre = b"/tmp/ph/";
    buf[..pre.len()].copy_from_slice(pre);
    let mut n = sys_getpid() as u64;
    let mut d = [0u8; 20];
    let mut i = 0;
    loop {
        d[i] = b'0' + (n % 10) as u8;
        i += 1;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    for j in 0..i {
        buf[pre.len() + j] = d[i - 1 - j];
    }
    buf[pre.len() + i] = 0;
    &buf[..pre.len() + i + 1]
}

/// gid= member: pid 1 is there
fn exempt() -> i32 {
    if stat(b"/tmp/ph/1\0") != 0 { 1 } else { 0 }
}

/// hidepid=noaccess: pid 1 is listed and its directory exists, but its
/// files refuse (EPERM)
fn noaccess() -> i32 {
    if stat(b"/tmp/ph/1\0") != 0 {
        return 1;
    }
    if !lists(b"1") {
        return 2;
    }
    if stat(b"/tmp/ph/1/status\0") != EPERM {
        return 3;
    }
    0
}

fn run() -> R {
    let r = mount(0, b"bogus=1\0");
    check(b"unknown option", r == EINVAL, r)?;
    let r = mount(0, b"hidepid=invisible,gid=4242\0");
    check(b"mount", r == 0, r)?;
    check(b"mounts shows", shows(b",gid=4242,hidepid=invisible"), 0)?;
    check(b"root sees pid 1", stat(b"/tmp/ph/1\0") == 0, 0)?;
    let v = as_user(UID, invisible);
    check(b"invisible", v == 0, v)?;
    let v = as_user(GID, exempt);
    check(b"gid exempt", v == 0, v)?;
    let r = mount(MS_REMOUNT, b"hidepid=noaccess\0");
    check(b"remount", r == 0, r)?;
    check(b"remount shows", shows(b",gid=4242,hidepid=noaccess"), 0)?;
    let v = as_user(UID, noaccess);
    check(b"noaccess", v == 0, v)?;
    // A remount that fails (read-only while a file is open for writing)
    // changes nothing, its options included (Linux reconfigure_super)
    let w = sys_open(b"/tmp/ph/sys/vm/drop_caches\0".as_ptr(), O_WRONLY, 0);
    let r = mount(MS_REMOUNT | MS_RDONLY, b"hidepid=invisible\0");
    if w >= 0 {
        sys_close(w as u64);
    }
    check(b"busy remount", w >= 0 && r == EBUSY, r)?;
    check(b"busy remount kept options", shows(b",hidepid=noaccess"), 0)?;
    sys_umount2(MP.as_ptr(), 0);
    let r = mount(0, b"subset=pid\0");
    check(b"subset mount", r == 0, r)?;
    check(b"subset shows", shows(b",subset=pid"), 0)?;
    let v = stat(b"/tmp/ph/version\0");
    check(b"subset hides version", v == ENOENT, v)?;
    check(b"subset keeps self", stat(b"/tmp/ph/self\0") == 0, 0)?;
    check(b"subset keeps pid 1", stat(b"/tmp/ph/1\0") == 0, 0)?;
    check(b"subset lists no version", !lists(b"version"), 0)
}
