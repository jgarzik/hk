//! epoll on files Linux cannot poll, edge-triggered wake keys, FIONREAD
//!
//! - EPOLL_CTL_ADD of a regular file, a directory, /dev/null, a block
//!   device, a sysfs directory or a per-process /proc file is EPERM
//!   (Linux file_can_poll: no f_op->poll), before the epoll checks and
//!   for every op; /proc/meminfo, /proc/self/mounts, a sysctl, a sysfs
//!   attribute and /dev/random can be added; poll and select still see
//!   a regular file ready
//! - an edge-triggered item is not reported again by a wakeup of an
//!   event it does not wait for (eventfd read, SO_SNDBUF)
//! - FIONREAD: a pipe's or FIFO's buffered bytes, a regular file's
//!   size - pos, inotify's queued bytes (IN_IGNORED), ENOTTY on an eventfd

use crate::tests::helpers::{find_blkdev, print, print_num, println};
use hk_syscall::{
    AF_UNIX, EFD_NONBLOCK, EFD_SEMAPHORE, EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLLET, EPOLLIN,
    EpollEvent, FIONREAD, FdSet, IN_CREATE, IN_NONBLOCK, O_CREAT, O_DIRECTORY, O_NONBLOCK,
    O_RDONLY, O_RDWR, POLLIN, POLLOUT, PollFd, SOCK_STREAM, Timeval, sys_close, sys_epoll_create1,
    sys_epoll_ctl, sys_epoll_wait, sys_eventfd2, sys_inotify_add_watch, sys_inotify_init1,
    sys_inotify_rm_watch, sys_ioctl, sys_lseek, sys_mknod, sys_open, sys_pipe2, sys_poll, sys_read,
    sys_select, sys_setsockopt, sys_socketpair, sys_unlink, sys_write,
};

const EPERM: i64 = -1;
const ENOTTY: i64 = -25;
const SOL_SOCKET: i32 = 1;
const SO_SNDBUF: i32 = 7;

pub fn run_tests() {
    test_epoll_eperm();
    test_eperm_order();
    test_poll_regular();
    test_epoll_et_key();
    test_fionread();
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

fn fionread(fd: i32) -> i64 {
    let mut n = -1i32;
    let r = sys_ioctl(fd, FIONREAD as u64, &mut n as *mut i32 as u64);
    if r < 0 { r } else { n as i64 }
}

fn fionread_pipe() -> i64 {
    let mut p = [0i32; 2];
    sys_pipe2(p.as_mut_ptr(), 0);
    sys_write(p[1] as u64, b"hello".as_ptr(), 5);
    let n = fionread(p[0]);
    sys_close(p[0] as u64);
    sys_close(p[1] as u64);
    n
}

fn fionread_fifo() -> i64 {
    let path = b"/tmp/pollperm_fifo\0";
    sys_mknod(path.as_ptr(), 0o010644, 0);
    let fd = sys_open(path.as_ptr(), O_RDWR | O_NONBLOCK, 0) as i32;
    sys_write(fd as u64, b"abc".as_ptr(), 3);
    let n = fionread(fd);
    sys_close(fd as u64);
    sys_unlink(path.as_ptr());
    n
}

fn fionread_file() -> i64 {
    let path = b"/tmp/pollperm_size\0";
    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT, 0o644) as i32;
    let buf = [0u8; 100];
    sys_write(fd as u64, buf.as_ptr(), 100);
    sys_lseek(fd, 30, 0);
    let n = fionread(fd);
    sys_close(fd as u64);
    sys_unlink(path.as_ptr());
    n
}

/// The IN_IGNORED event of a removed watch (a bare 16-byte header;
/// hk queues no file events yet)
fn fionread_inotify() -> i64 {
    let ifd = sys_inotify_init1(IN_NONBLOCK) as i32;
    let wd = sys_inotify_add_watch(ifd, b"/tmp\0".as_ptr(), IN_CREATE) as i32;
    let empty = fionread(ifd);
    sys_inotify_rm_watch(ifd, wd);
    let n = fionread(ifd);
    sys_close(ifd as u64);
    if empty == 0 { n } else { 1000 + empty }
}

fn test_fionread() {
    let pipe = fionread_pipe();
    let fifo = fionread_fifo();
    let file = fionread_file();
    let ino = fionread_inotify();
    let efd = sys_eventfd2(0, 0) as i32;
    let ev = fionread(efd);
    sys_close(efd as u64);
    if (pipe, fifo, file, ino, ev) == (5, 3, 70, 16, ENOTTY) {
        println(b"FIONREAD_KINDS:OK");
    } else {
        print(b"FIONREAD_KINDS:FAIL pipe=");
        print_num(pipe);
        print(b" fifo=");
        print_num(fifo);
        print(b" file=");
        print_num(file);
        print(b" inotify=");
        print_num(ino);
        print(b" eventfd=");
        print_num(ev);
        println(b"");
    }
}
