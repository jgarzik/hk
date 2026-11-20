//! Allocation failure injection (Linux fail-nth, CONFIG_FAULT_INJECTION)
//!
//! For each syscall, /proc/self/fail-nth makes its 1st, 2nd, ...
//! allocation fail in turn until it completes without reaching one: every
//! ENOMEM path of the call runs. Each run must return (no panic, no hang)
//! and leave no descriptor behind. Skipped where the kernel has no
//! fail-nth (a Linux build without fault injection). failslab's
//! ignore-gfp-wait is N meanwhile (`Reach`), so GFP_KERNEL allocations
//! fail too (Linux's default skips them).
//!
//! - FAULT_INJECT_<CALL>: one line per syscall, with the paths it ran
//! - FAULT_INJECT_XATTR: setxattr/getxattr value buffers fail with
//!   ENOMEM (Linux kvmalloc), no panic
//! - FAULT_INJECT_CGROUP_MKDIR: after each failed mkdir of a cgroup the
//!   name is still free (nothing half made)
//! - FAULT_INJECT_KNOBS: the debugfs knobs (failslab/ignore-gfp-wait,
//!   fail_page_alloc/{ignore-gfp-wait,ignore-gfp-highmem,min-order})
//!   read Linux's defaults and take writes; skipped without them

use crate::helpers::{print, print_num, println, skip};
use hk_syscall::{
    EpollEvent, O_CREAT, O_RDONLY, O_RDWR, sys_close, sys_epoll_create1, sys_epoll_ctl,
    sys_eventfd2, sys_exit, sys_fork, sys_inotify_init1, sys_lseek, sys_mkdir, sys_mount, sys_open,
    sys_pipe2, sys_read, sys_rmdir, sys_signalfd4, sys_socket, sys_socketpair, sys_timerfd_create,
    sys_umount2, sys_unlink, sys_wait4, sys_write,
};

/// Most failure points one call is tried with
const MAX_NTH: u32 = 400;

pub fn run_tests() {
    knobs();
    let path = b"/proc/self/fail-nth\0";
    let fd = sys_open(path.as_ptr(), O_RDWR, 0);
    if fd < 0 {
        skip(b"FAULT_INJECT", b"no /proc/self/fail-nth");
        return;
    }
    let fd = fd as i32;
    let reach = Reach::new(false);
    let calls: [(&[u8], fn() -> i64, fn(i64)); 10] = [
        (b"SOCKETPAIR", socketpair, close_pair),
        (b"SOCKET_INET", || sys_socket(2, 1, 0), close_one),
        (b"PIPE2", pipe2, close_pair),
        (b"EVENTFD", || sys_eventfd2(0, 0), close_one),
        (b"EPOLL", epoll, close_pair),
        (b"TIMERFD", || sys_timerfd_create(1, 0), close_one),
        (b"SIGNALFD", signalfd, close_one),
        (b"INOTIFY", || sys_inotify_init1(0), close_one),
        (b"CREAT", creat, close_one),
        (b"XATTR", xattr, |_| {}),
    ];
    for (name, call, undo) in calls {
        run(fd, name, call, undo);
    }
    run(fd, b"FORK", fork, |_| {});
    cgroup_mkdir(fd);
    set(fd, 0);
    drop(reach);
    sys_close(fd as u64);
}

/// mkdir in a cgroup2 mount with the 1st, 2nd, ... allocation failing:
/// after a failure, the same mkdir without injection succeeds (a leaked
/// cgroup would make it EEXIST)
fn cgroup_mkdir(fd: i32) {
    let mp = b"/tmp/cgfi\0";
    let d = b"/tmp/cgfi/x\0";
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777);
    sys_mkdir(mp.as_ptr(), 0o755);
    sys_mount(b"none\0".as_ptr(), mp.as_ptr(), b"cgroup2\0".as_ptr(), 0, 0);
    let mut nth = 1;
    let mut done = false;
    let mut leaked = 0;
    while nth <= MAX_NTH {
        set(fd, nth);
        let r = sys_mkdir(d.as_ptr(), 0o755);
        let left = get(fd);
        set(fd, 0);
        if r != 0 && sys_mkdir(d.as_ptr(), 0o755) != 0 {
            leaked = nth;
        }
        sys_rmdir(d.as_ptr());
        if left != 0 {
            done = true;
            break;
        }
        nth += 1;
    }
    sys_umount2(mp.as_ptr(), 0);
    sys_rmdir(mp.as_ptr());
    print(b"FAULT_INJECT_CGROUP_MKDIR");
    if done && leaked == 0 {
        print(b":OK (");
        print_num(i64::from(nth - 1));
        println(b" failure points)");
    } else {
        print(b":FAIL done=");
        print_num(i64::from(done));
        print(b" leaked at ");
        print_num(i64::from(leaked));
        println(b"");
    }
}

/// Inject the 1st, 2nd, ... allocation failure into `call` until it gets
/// through; `undo` releases a success. Reports the failure points run.
fn run(fd: i32, name: &[u8], call: fn() -> i64, undo: fn(i64)) {
    let before = lowest_free_fd();
    let socks = unix_sockets();
    let mut nth = 1;
    let mut done = false;
    while nth <= MAX_NTH {
        set(fd, nth);
        let r = call();
        let left = get(fd);
        set(fd, 0);
        if r >= 0 {
            undo(r);
        }
        if left != 0 {
            // It finished before its nth allocation
            done = true;
            break;
        }
        nth += 1;
    }
    let after = lowest_free_fd();
    let socks_after = unix_sockets();
    print(b"FAULT_INJECT_");
    print(name);
    if done && before == after && socks == socks_after {
        print(b":OK (");
        print_num(i64::from(nth - 1));
        println(b" failure points)");
    } else {
        print(b":FAIL done=");
        print_num(i64::from(done));
        print(b" fds before ");
        print_num(before);
        print(b" after ");
        print_num(after);
        print(b", unix sockets before ");
        print_num(socks);
        print(b" after ");
        print_num(socks_after);
        println(b"");
    }
}

pub fn set(fd: i32, n: u32) {
    let mut b = [0u8; 12];
    let len = fmt_u32(n, &mut b);
    sys_lseek(fd, 0, 0);
    sys_write(fd as u64, b.as_ptr(), len as u64);
}

pub fn get(fd: i32) -> u32 {
    let mut b = [0u8; 16];
    sys_lseek(fd, 0, 0);
    let n = sys_read(fd as u64, b.as_mut_ptr(), b.len() as u64);
    b[..n.max(0) as usize]
        .iter()
        .take_while(|c| c.is_ascii_digit())
        .fold(0u32, |v, c| v * 10 + u32::from(c - b'0'))
}

fn fmt_u32(mut n: u32, out: &mut [u8; 12]) -> usize {
    let mut tmp = [0u8; 12];
    let mut i = 0;
    loop {
        tmp[i] = b'0' + (n % 10) as u8;
        i += 1;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    for j in 0..i {
        out[j] = tmp[i - 1 - j];
    }
    i
}

/// Lines of /proc/net/unix: a socket left behind shows as one more
fn unix_sockets() -> i64 {
    let fd = sys_open(b"/proc/net/unix\0".as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        return -1;
    }
    let mut lines = 0;
    let mut b = [0u8; 512];
    loop {
        let n = sys_read(fd as u64, b.as_mut_ptr(), b.len() as u64);
        if n <= 0 {
            break;
        }
        lines += b[..n as usize].iter().filter(|&&c| c == b'\n').count() as i64;
    }
    sys_close(fd as u64);
    lines
}

/// The descriptor the next open gets: a leak shows as a higher one
fn lowest_free_fd() -> i64 {
    let fd = sys_open(b"/dev/null\0".as_ptr(), O_RDONLY, 0);
    sys_close(fd as u64);
    fd
}

fn close_one(fd: i64) {
    sys_close(fd as u64);
}

/// Pairs come back packed as (a << 32) | b
fn close_pair(p: i64) {
    sys_close((p >> 32) as u64);
    sys_close((p & 0xffff_ffff) as u64);
}

fn pack(a: i32, b: i32) -> i64 {
    (i64::from(a) << 32) | i64::from(b as u32)
}

fn socketpair() -> i64 {
    let mut sv = [0i32; 2];
    let r = sys_socketpair(1, 1, 0, &mut sv);
    if r < 0 { r } else { pack(sv[0], sv[1]) }
}

fn pipe2() -> i64 {
    let mut p = [0i32; 2];
    let r = sys_pipe2(p.as_mut_ptr(), 0);
    if r < 0 { r } else { pack(p[0], p[1]) }
}

/// An epoll instance watching an eventfd
fn epoll() -> i64 {
    let ep = sys_epoll_create1(0);
    if ep < 0 {
        return ep;
    }
    let efd = sys_eventfd2(0, 0);
    if efd < 0 {
        sys_close(ep as u64);
        return efd;
    }
    let ev = EpollEvent { events: 1, data: 0 };
    sys_epoll_ctl(ep as i32, 1, efd as i32, &ev);
    pack(ep as i32, efd as i32)
}

fn signalfd() -> i64 {
    let mask: u64 = 1 << 9; // SIGUSR1
    sys_signalfd4(-1, &mask, 8, 0)
}

fn creat() -> i64 {
    let p = b"/tmp/fault_inject\0";
    let fd = sys_open(p.as_ptr(), O_CREAT | O_RDWR, 0o600);
    sys_unlink(p.as_ptr());
    fd
}

/// fork; the child exits at once
fn fork() -> i64 {
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(0);
    }
    if pid > 0 {
        let mut st = 0;
        sys_wait4(pid, &mut st, 0, 0);
    }
    pid
}

/// setxattr then getxattr of a 64-byte user.* value on a scratch file
fn xattr() -> i64 {
    let p = b"/tmp/fault_xattr\0";
    let fd = sys_open(p.as_ptr(), O_CREAT | O_RDWR, 0o600);
    sys_close(fd as u64);
    let v = [b'v'; 64];
    let r = hk_syscall::sys_setxattr(p.as_ptr(), b"user.t\0".as_ptr(), v.as_ptr(), 64, 0);
    let mut b = [0u8; 64];
    let g = hk_syscall::sys_getxattr(p.as_ptr(), b"user.t\0".as_ptr(), b.as_mut_ptr(), 64);
    sys_unlink(p.as_ptr());
    if r < 0 { r } else { g.min(0) }
}

/// FAULT_INJECT_KNOBS: Linux's defaults (Y, Y, Y, 1), a bool written
/// as "N" and "on" read back as N and Y, min-order written in hex read
/// back in decimal (debugfs_create_bool / debugfs_create_u32); each
/// restored
fn knobs() {
    const N: &[u8] = b"FAULT_INJECT_KNOBS";
    let mut st = hk_syscall::Stat::default();
    let mounted = hk_syscall::sys_stat(KNOBS[0].as_ptr(), &mut st) < 0
        && sys_mount(
            b"debugfs\0".as_ptr(),
            DEBUGFS.as_ptr(),
            b"debugfs\0".as_ptr(),
            0,
            0,
        ) == 0;
    let hm = b"/sys/kernel/debug/fail_page_alloc/ignore-gfp-highmem\0";
    let files: [(&[u8], &[u8]); 4] = [
        (KNOBS[0], b"Y\n"),
        (KNOBS[1], b"Y\n"),
        (hm, b"Y\n"),
        (KNOBS[2], b"1\n"),
    ];
    let mut why: Option<(&[u8], i64)> = None;
    for (i, (p, want)) in files.iter().enumerate() {
        let (b, n) = knob(p, b"");
        if n < 0 {
            if mounted {
                sys_umount2(DEBUGFS.as_ptr(), 0);
            }
            // A host kernel may lack CONFIG_FAILSLAB / FAIL_PAGE_ALLOC;
            // hk always has them
            if crate::helpers::host_mode() {
                return skip(N, b"no fault-injection debugfs knobs");
            }
            why = Some((b"knob missing", i as i64));
            break;
        }
        if &b[..n as usize] != *want && why.is_none() {
            why = Some((b"default", i as i64));
        }
    }
    let steps: [(&[u8], &[u8], &[u8]); 3] = [
        (KNOBS[1], b"N", b"N\n"),
        (KNOBS[1], b"on", b"Y\n"),
        (KNOBS[2], b"0x2\n", b"2\n"),
    ];
    for (i, (p, w, want)) in steps.iter().enumerate() {
        let (old, n) = knob(p, w);
        let (b, m) = knob(p, &old[..n.max(0) as usize]);
        if &b[..m.max(0) as usize] != *want && why.is_none() {
            why = Some((b"written", i as i64));
        }
    }
    if mounted {
        sys_umount2(DEBUGFS.as_ptr(), 0);
    }
    match why {
        Some((w, v)) => crate::harness::fail_why(N, w, v),
        None => crate::harness::pass(N),
    }
}

/// The debugfs knob files `Reach` sets
const KNOBS: [&[u8]; 3] = [
    b"/sys/kernel/debug/failslab/ignore-gfp-wait\0",
    b"/sys/kernel/debug/fail_page_alloc/ignore-gfp-wait\0",
    b"/sys/kernel/debug/fail_page_alloc/min-order\0",
];
const DEBUGFS: &[u8] = b"/sys/kernel/debug\0";

/// What fail-nth reaches, widened for a test (Linux's knobs by default
/// skip allocations that may sleep, and single pages): failslab's
/// ignore-gfp-wait N and, with `pages`, fail_page_alloc's ignore-gfp-wait
/// N and min-order 0, as Documentation/fault-injection's fail-nth
/// example sets them. debugfs is mounted at /sys/kernel/debug if it is
/// not. Dropping it restores the knobs (and unmounts what it mounted);
/// a kernel without them is left as it is.
pub struct Reach {
    saved: [([u8; 16], i64); 3],
    mounted: bool,
}

impl Reach {
    pub fn new(pages: bool) -> Self {
        let mut st = hk_syscall::Stat::default();
        let mounted = hk_syscall::sys_stat(KNOBS[0].as_ptr(), &mut st) < 0
            && sys_mount(
                b"debugfs\0".as_ptr(),
                DEBUGFS.as_ptr(),
                b"debugfs\0".as_ptr(),
                0,
                0,
            ) == 0;
        let mut r = Self {
            saved: [([0; 16], -1); 3],
            mounted,
        };
        let want: [&[u8]; 3] = [b"N", b"N", b"0"];
        let n = if pages { 3 } else { 1 };
        for i in 0..n {
            r.saved[i] = knob(KNOBS[i], want[i]);
        }
        r
    }
}

impl Drop for Reach {
    fn drop(&mut self) {
        for (i, (b, n)) in self.saved.iter().enumerate() {
            if *n > 0 {
                knob(KNOBS[i], &b[..*n as usize]);
            }
        }
        if self.mounted {
            sys_umount2(DEBUGFS.as_ptr(), 0);
        }
    }
}

/// Knob `path`'s old value and its length (-1 if it cannot be read),
/// `set` written to it (if not empty)
fn knob(path: &[u8], set: &[u8]) -> ([u8; 16], i64) {
    let mut b = [0u8; 16];
    let fd = sys_open(path.as_ptr(), O_RDWR, 0);
    if fd < 0 {
        return (b, -1);
    }
    let fd = fd as i32;
    let n = sys_read(fd as u64, b.as_mut_ptr(), b.len() as u64);
    if !set.is_empty() {
        sys_lseek(fd, 0, 0);
        sys_write(fd as u64, set.as_ptr(), set.len() as u64);
    }
    sys_close(fd as u64);
    (b, n)
}
