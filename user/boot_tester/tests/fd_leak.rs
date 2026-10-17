//! Per-object state of anonymous files (pipes, eventfd, epoll, ...) is
//! freed with the last close: creating and closing many must neither run
//! out of kernel memory nor grow the kernel heap (hk reports it as
//! meminfo Slab)

use super::helpers::{host_mode, print, print_num, println};
use super::mm_life::meminfo;
use hk_syscall::{
    IoUringParams, MqAttr, O_CREAT, O_RDWR, sys_close, sys_epoll_create1, sys_eventfd2,
    sys_getpid, sys_inotify_init1, sys_io_uring_setup, sys_mq_open, sys_mq_unlink,
    sys_pidfd_open, sys_pipe2, sys_signalfd4, sys_timerfd_create,
};

const O_CLOEXEC: u32 = 0o2000000;

pub fn run_tests() {
    leak(b"FD_LEAK_PIPE", 20000, pipe_cycle);
    leak(b"FD_LEAK_EVENTFD", 4000, || fd_cycle(sys_eventfd2(0, 0)));
    leak(b"FD_LEAK_EPOLL", 4000, || fd_cycle(sys_epoll_create1(0)));
    leak(b"FD_LEAK_TIMERFD", 4000, || fd_cycle(sys_timerfd_create(1, 0)));
    leak(b"FD_LEAK_SIGNALFD", 4000, signalfd_cycle);
    leak(b"FD_LEAK_INOTIFY", 4000, || fd_cycle(sys_inotify_init1(0)));
    leak(b"FD_LEAK_PIDFD", 4000, || fd_cycle(sys_pidfd_open(sys_getpid() as i32, 0)));
    leak(b"FD_LEAK_IO_URING", 1000, io_uring_cycle);
    leak(b"FD_LEAK_MQUEUE", 2000, mq_cycle);
}

/// Close `fd` if the call creating it succeeded; its errno if not
fn fd_cycle(fd: i64) -> i64 {
    if fd < 0 {
        return fd;
    }
    sys_close(fd as u64);
    0
}

fn signalfd_cycle() -> i64 {
    let mask: u64 = 1 << (10 - 1); // SIGUSR1
    fd_cycle(sys_signalfd4(-1, &mask, 8, 0))
}

fn io_uring_cycle() -> i64 {
    let mut params = IoUringParams::default();
    fd_cycle(sys_io_uring_setup(4, &mut params))
}

fn mq_cycle() -> i64 {
    let name = b"fd_leak_mq\0";
    let attr = MqAttr::new(4, 64);
    let fd = sys_mq_open(name.as_ptr(), (O_RDWR | O_CREAT) as i32, 0o600, &attr);
    sys_mq_unlink(name.as_ptr());
    fd_cycle(fd)
}

fn report(name: &[u8], ok: bool, detail: i64) {
    print(name);
    if ok {
        println(b":OK");
    } else {
        print(b":FAIL ");
        print_num(detail);
        println(b"");
    }
}

/// One pipe, opened and closed; the errno on failure
fn pipe_cycle() -> i64 {
    let mut fds = [0i32; 2];
    let r = sys_pipe2(fds.as_mut_ptr(), O_CLOEXEC);
    if r < 0 {
        return r;
    }
    sys_close(fds[0] as u64);
    sys_close(fds[1] as u64);
    0
}

/// Run `f` `n` times: every step must succeed, and on hk the heap
/// (Slab) must come back to within 64 kB of where it was (it grew by
/// ~600 B per pipe when pipe state leaked). Linux slab caches keep
/// freed objects, so there only the steps are checked.
fn leak(name: &[u8], n: u32, f: fn() -> i64) {
    for _ in 0..16 {
        f();
    }
    let before = meminfo(b"Slab:");
    for i in 0..n {
        let r = f();
        if r < 0 {
            print(name);
            print(b":FAIL step ");
            print_num(i as i64);
            print(b" errno ");
            print_num(-r);
            println(b"");
            return;
        }
    }
    if host_mode() {
        report(name, true, 0);
        return;
    }
    let grew = meminfo(b"Slab:") - before;
    report(name, before >= 0 && grew <= 64, grew);
}
