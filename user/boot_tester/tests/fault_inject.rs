//! Allocation failure injection (Linux fail-nth, CONFIG_FAULT_INJECTION)
//!
//! For each syscall, /proc/self/fail-nth makes its 1st, 2nd, ...
//! allocation fail in turn until it completes without reaching one: every
//! ENOMEM path of the call runs. Each run must return (no panic, no hang)
//! and leave no descriptor behind. Skipped where the kernel has no
//! fail-nth (a Linux build without fault injection).
//!
//! - FAULT_INJECT_<CALL>: one line per syscall, with the paths it ran
//! - FAULT_INJECT_CGROUP_MKDIR: after each failed mkdir of a cgroup the
//!   name is still free (nothing half made)

use super::helpers::{print, print_num, println, skip};
use hk_syscall::{
    EpollEvent, O_CREAT, O_RDONLY, O_RDWR, sys_close, sys_epoll_create1, sys_epoll_ctl,
    sys_eventfd2, sys_exit, sys_fork, sys_inotify_init1, sys_lseek, sys_mkdir, sys_mount, sys_open,
    sys_pipe2, sys_read, sys_rmdir, sys_signalfd4, sys_socket, sys_socketpair, sys_timerfd_create,
    sys_umount2, sys_unlink, sys_wait4, sys_write,
};

/// Most failure points one call is tried with
const MAX_NTH: u32 = 400;

pub fn run_tests() {
    let path = b"/proc/self/fail-nth\0";
    let fd = sys_open(path.as_ptr(), O_RDWR, 0);
    if fd < 0 {
        skip(b"FAULT_INJECT", b"no /proc/self/fail-nth");
        return;
    }
    let fd = fd as i32;
    let calls: [(&[u8], fn() -> i64, fn(i64)); 9] = [
        (b"SOCKETPAIR", socketpair, close_pair),
        (b"SOCKET_INET", || sys_socket(2, 1, 0), close_one),
        (b"PIPE2", pipe2, close_pair),
        (b"EVENTFD", || sys_eventfd2(0, 0), close_one),
        (b"EPOLL", epoll, close_pair),
        (b"TIMERFD", || sys_timerfd_create(1, 0), close_one),
        (b"SIGNALFD", signalfd, close_one),
        (b"INOTIFY", || sys_inotify_init1(0), close_one),
        (b"CREAT", creat, close_one),
    ];
    for (name, call, undo) in calls {
        run(fd, name, call, undo);
    }
    run(fd, b"FORK", fork, |_| {});
    cgroup_mkdir(fd);
    set(fd, 0);
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

fn set(fd: i32, n: u32) {
    let mut b = [0u8; 12];
    let len = fmt_u32(n, &mut b);
    sys_lseek(fd, 0, 0);
    sys_write(fd as u64, b.as_ptr(), len as u64);
}

fn get(fd: i32) -> u32 {
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
