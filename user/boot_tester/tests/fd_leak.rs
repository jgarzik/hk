//! Per-object state of anonymous files (pipes, ...) is freed with the
//! last close: creating and closing many must neither run out of kernel
//! memory nor grow the kernel heap (hk reports it as meminfo Slab)

use super::helpers::{host_mode, print, print_num, println};
use super::mm_life::meminfo;
use hk_syscall::{sys_close, sys_pipe2};

const O_CLOEXEC: u32 = 0o2000000;

pub fn run_tests() {
    leak(b"FD_LEAK_PIPE", 20000, pipe_cycle);
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
