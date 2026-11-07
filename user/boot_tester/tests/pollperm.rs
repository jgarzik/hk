//! epoll on files Linux cannot poll, edge-triggered wake keys
//!
//! - EPOLL_CTL_ADD of a regular file, a directory, /dev/null, a block
//!   device, a sysfs directory or a per-process /proc file is EPERM
//!   (Linux file_can_poll: no f_op->poll), before the epoll checks and
//!   for every op; /proc/meminfo, /proc/self/mounts, a sysctl, a sysfs
//!   attribute and /dev/random can be added; poll and select still see
//!   a regular file ready
//! - an edge-triggered item is not reported again by a wakeup of an
//!   event it does not wait for (eventfd read, SO_SNDBUF)

use super::helpers::{find_blkdev, print, print_num, println};
use hk_syscall::{
    AF_UNIX, EFD_NONBLOCK, EFD_SEMAPHORE, EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLLET, EPOLLIN,
    EpollEvent, FdSet, O_CREAT, O_DIRECTORY, O_NONBLOCK, O_RDONLY, O_RDWR, POLLIN, POLLOUT, PollFd,
    SOCK_STREAM, Timeval, sys_close, sys_epoll_create1, sys_epoll_ctl, sys_epoll_wait,
    sys_eventfd2, sys_open, sys_poll, sys_read, sys_select, sys_setsockopt, sys_socketpair,
    sys_unlink, sys_write,
};

const EPERM: i64 = -1;
const SOL_SOCKET: i32 = 1;
const SO_SNDBUF: i32 = 7;

pub fn run_tests() {
    test_epoll_eperm();
    test_eperm_order();
    test_poll_regular();
    test_epoll_et_key();
}

fn add(ep: i32, fd: i32, events: u32) -> i64 {
    let ev = EpollEvent { events, data: 0 };
    sys_epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev)
}

/// EPOLL_CTL_ADD of `path`; the result
fn add_path(ep: i32, path: &[u8], flags: u32) -> i64 {
    let fd = sys_open(path.as_ptr(), flags, 0o644);
    if fd < 0 {
        return 1000 + fd;
    }
    let r = add(ep, fd as i32, EPOLLIN);
    sys_close(fd as u64);
    r
}

/// EPOLL_CTL_ADD of the first block device (EPERM if there is none)
fn add_blk(ep: i32) -> i64 {
    let Some(d) = find_blkdev(b"", 0) else {
        return EPERM;
    };
    let mut buf = [0u8; 48];
    add_path(ep, d.path(&mut buf), O_RDONLY | O_NONBLOCK)
}

fn test_epoll_eperm() {
    let ep = sys_epoll_create1(0) as i32;
    let no = [
        add_path(ep, b"/tmp/pollperm_file\0", O_RDWR | O_CREAT),
        add_path(ep, b"/tmp\0", O_RDONLY | O_DIRECTORY),
        add_path(ep, b"/dev/null\0", O_RDWR),
        add_path(ep, b"/dev/urandom\0", O_RDONLY),
        add_blk(ep),
        add_path(ep, b"/sys/class/mem\0", O_RDONLY | O_DIRECTORY),
        add_path(ep, b"/proc\0", O_RDONLY | O_DIRECTORY),
        add_path(ep, b"/proc/self/status\0", O_RDONLY),
    ];
    let yes = [
        add_path(ep, b"/proc/meminfo\0", O_RDONLY),
        add_path(ep, b"/proc/self/mounts\0", O_RDONLY),
        add_path(
            ep,
            b"/proc/sys/kernel/unprivileged_bpf_disabled\0",
            O_RDONLY,
        ),
        add_path(ep, b"/sys/class/mem/null/dev\0", O_RDONLY),
        add_path(ep, b"/dev/random\0", O_RDONLY),
    ];
    sys_close(ep as u64);
    sys_unlink(b"/tmp/pollperm_file\0".as_ptr());
    if no.iter().all(|&r| r == EPERM) && yes.iter().all(|&r| r == 0) {
        println(b"EPOLL_NOPOLL_EPERM:OK");
    } else {
        print(b"EPOLL_NOPOLL_EPERM:FAIL no=");
        for r in no {
            print_num(r);
            print(b",");
        }
        print(b" yes=");
        for r in yes {
            print_num(r);
            print(b",");
        }
        println(b"");
    }
}

/// EPERM comes first: on EPOLL_CTL_DEL too, and before the EINVAL of a
/// non-epoll (here the target itself) as the epoll fd
fn test_eperm_order() {
    let fd = sys_open(b"/tmp/pollperm_ord\0".as_ptr(), O_RDWR | O_CREAT, 0o644) as i32;
    let ep = sys_epoll_create1(0) as i32;
    let ev = EpollEvent { events: 0, data: 0 };
    let del = sys_epoll_ctl(ep, EPOLL_CTL_DEL, fd, &ev);
    let selfadd = add(fd, fd, EPOLLIN);
    sys_close(ep as u64);
    sys_close(fd as u64);
    sys_unlink(b"/tmp/pollperm_ord\0".as_ptr());
    if del == EPERM && selfadd == EPERM {
        println(b"EPOLL_EPERM_FIRST:OK");
    } else {
        print(b"EPOLL_EPERM_FIRST:FAIL del=");
        print_num(del);
        print(b" self=");
        print_num(selfadd);
        println(b"");
    }
}

/// poll and select see a regular file readable and writable at once
fn test_poll_regular() {
    let fd = sys_open(b"/tmp/pollperm_poll\0".as_ptr(), O_RDWR | O_CREAT, 0o644) as i32;
    let mut pfd = [PollFd::new(fd, POLLIN | POLLOUT)];
    let p = sys_poll(pfd.as_mut_ptr(), 1, 0);
    let mut r = FdSet::new();
    let mut w = FdSet::new();
    r.zero();
    w.zero();
    r.set(fd);
    w.set(fd);
    let mut tv = Timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let s = sys_select(fd + 1, &mut r, &mut w, core::ptr::null_mut(), &mut tv);
    sys_close(fd as u64);
    sys_unlink(b"/tmp/pollperm_poll\0".as_ptr());
    let rev = pfd[0].revents;
    if p == 1 && rev == POLLIN | POLLOUT && s == 2 && r.is_set(fd) && w.is_set(fd) {
        println(b"POLL_REGULAR_READY:OK");
    } else {
        print(b"POLL_REGULAR_READY:FAIL poll=");
        print_num(p);
        print(b" revents=");
        print_num(rev as i64);
        print(b" select=");
        print_num(s);
        println(b"");
    }
}

/// Events reported by an immediate epoll_wait
fn wait0(ep: i32) -> i64 {
    let mut evs = [EpollEvent { events: 0, data: 0 }; 4];
    sys_epoll_wait(ep, evs.as_mut_ptr(), 4, 0)
}

/// EPOLLIN|EPOLLET on a semaphore eventfd holding 2: one event; a read
/// (count 1 left, a wakeup keyed POLLOUT) reports nothing new
fn et_eventfd() -> (i64, i64) {
    let efd = sys_eventfd2(2, EFD_SEMAPHORE | EFD_NONBLOCK) as i32;
    let ep = sys_epoll_create1(0) as i32;
    add(ep, efd, EPOLLIN | EPOLLET);
    let first = wait0(ep);
    let mut v = 0u64;
    sys_read(efd as u64, &mut v as *mut u64 as *mut u8, 8);
    let second = wait0(ep);
    sys_close(ep as u64);
    sys_close(efd as u64);
    (first, second)
}

/// EPOLLIN|EPOLLET on a readable stream socket: one event; SO_SNDBUF
/// (a write-space wakeup) reports nothing new
fn et_sndbuf() -> (i64, i64) {
    let mut sv = [0i32; 2];
    sys_socketpair(AF_UNIX, SOCK_STREAM, 0, &mut sv);
    sys_write(sv[1] as u64, b"x".as_ptr(), 1);
    let ep = sys_epoll_create1(0) as i32;
    add(ep, sv[0], EPOLLIN | EPOLLET);
    let first = wait0(ep);
    let v: i32 = 65536;
    sys_setsockopt(
        sv[0],
        SOL_SOCKET,
        SO_SNDBUF,
        &v as *const i32 as *const u8,
        4,
    );
    let second = wait0(ep);
    sys_close(ep as u64);
    sys_close(sv[0] as u64);
    sys_close(sv[1] as u64);
    (first, second)
}

fn test_epoll_et_key() {
    let (ef1, ef2) = et_eventfd();
    let (sk1, sk2) = et_sndbuf();
    if (ef1, ef2, sk1, sk2) == (1, 0, 1, 0) {
        println(b"EPOLL_ET_WAKE_KEY:OK");
    } else {
        print(b"EPOLL_ET_WAKE_KEY:FAIL eventfd=");
        print_num(ef1);
        print(b",");
        print_num(ef2);
        print(b" sndbuf=");
        print_num(sk1);
        print(b",");
        print_num(sk2);
        println(b"");
    }
}
