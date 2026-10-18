//! Thread-group exit (Linux do_group_exit, zap_other_threads,
//! delay_group_leader, de_thread): exit_group and a fatal signal to any
//! thread end every thread, blocked ones included; the leader is reaped
//! only once all threads are gone; execve from any thread ends the
//! others. Each child's threads hold the write end of a pipe (in their
//! shared descriptor table): EOF on it after the reap shows that none
//! is left.

use super::fork_mm::spawn_thread;
use super::helpers::{print, print_num, println};
use hk_syscall::{
    Timespec, sys_close, sys_execve, sys_exit, sys_exit_group, sys_fork, sys_kill,
    sys_nanosleep, sys_pipe2, sys_read, sys_tgkill, sys_wait4, sys_write,
};

const SIGKILL: u32 = 9;
const SIGTERM: u32 = 15;
const WNOHANG: i32 = 1;
const O_NONBLOCK: u32 = 0o4000;
const BB: &[u8] = b"/bin/busybox\0";

pub fn run_tests() {
    test_exit_group();
    test_fatal_signal();
    test_leader_delay();
    test_kill_zombie_leader();
    test_exec_leader();
    test_exec_thread();
}

fn report(name: &[u8], ok: bool, v: i64) {
    print(name);
    if ok {
        println(b":OK");
    } else {
        print(b":FAIL got ");
        print_num(v);
        println(b"");
    }
}

fn sleep_ms(ms: i64) {
    let ts = Timespec {
        tv_sec: ms / 1000,
        tv_nsec: (ms % 1000) * 1_000_000,
    };
    sys_nanosleep(&ts, core::ptr::null_mut());
}

#[repr(C, align(16))]
struct Stack([u8; 16384]);
static mut STACKS: [Stack; 3] = [const { Stack([0; 16384]) }; 3];
static mut CTIDS: [u32; 3] = [0; 3];

/// Start `f(arg)` on stack `i` (in the calling process); the tid
fn start(i: usize, f: extern "C" fn(u64) -> !, arg: u64) -> i64 {
    unsafe {
        let top = (&raw mut STACKS[i] as *mut u8).add(16384) as u64;
        let ctid = &raw mut CTIDS[i];
        spawn_thread(top, f, arg, ctid)
    }
}

/// Block in read() on `fd` (a pipe nobody writes), then exit the thread
extern "C" fn reader(fd: u64) -> ! {
    let mut c = [0u8; 1];
    sys_read(fd, c.as_mut_ptr(), 1);
    sys_exit(0)
}

/// Sleep for a minute, then exit the thread
extern "C" fn sleeper(_: u64) -> ! {
    sleep_ms(60_000);
    sys_exit(0)
}

/// A child's pipes: `hold` (the threads keep its write end), `block`
/// (readers block on it), `tids` (thread ids sent to the parent)
struct Pipes {
    hold: [i32; 2],
    block: [i32; 2],
    tids: [i32; 2],
}

fn pipes() -> Pipes {
    let mut p = Pipes {
        hold: [0; 2],
        block: [0; 2],
        tids: [0; 2],
    };
    sys_pipe2(p.hold.as_mut_ptr(), O_NONBLOCK);
    sys_pipe2(p.block.as_mut_ptr(), 0);
    sys_pipe2(p.tids.as_mut_ptr(), 0);
    p
}

/// In the child: a reader and a sleeper thread, their tids sent up
fn spawn_blocked(p: &Pipes) {
    send_tids(p, [start(0, reader, p.block[0] as u64), start(1, sleeper, 0)]);
    // Let them block
    sleep_ms(50);
}

/// In the child: tell the parent its thread ids
fn send_tids(p: &Pipes, tids: [i64; 2]) {
    sys_write(p.tids[1] as u64, tids.as_ptr() as *const u8, 16);
}

/// In the parent: the child's thread ids, the child's ends closed
fn parent_side(p: &Pipes) -> [i64; 2] {
    let mut tids = [0i64; 2];
    sys_read(p.tids[0] as u64, tids.as_mut_ptr() as *mut u8, 16);
    sys_close(p.hold[1] as u64);
    sys_close(p.tids[0] as u64);
    sys_close(p.tids[1] as u64);
    tids
}

/// Reap `pid` within 5 s: its wait status, or None (it is then killed
/// and reaped anyway); then whether every thread is gone (EOF on the
/// hold pipe). The pipes are closed.
fn reap(pid: i64, p: &Pipes) -> (Option<i32>, bool) {
    let mut st = 0i32;
    let mut got = None;
    for _ in 0..500 {
        if sys_wait4(pid, &mut st, WNOHANG, 0) == pid {
            got = Some(st);
            break;
        }
        sleep_ms(10);
    }
    let mut c = [0u8; 1];
    let gone = sys_read(p.hold[0] as u64, c.as_mut_ptr(), 1) == 0;
    if got.is_none() {
        sys_kill(pid, SIGKILL);
        sys_wait4(pid, &mut st, 0, 0);
    }
    for fd in [p.hold[0], p.block[0], p.block[1]] {
        sys_close(fd as u64);
    }
    (got, gone)
}

/// exit_group from the main thread ends blocked siblings; the status
/// is the group's
fn test_exit_group() {
    let p = pipes();
    let pid = sys_fork();
    if pid == 0 {
        spawn_blocked(&p);
        sys_exit_group(7);
    }
    parent_side(&p);
    let (st, gone) = reap(pid, &p);
    report(
        b"GROUP_EXIT_ALL_THREADS",
        st == Some(7 << 8) && gone,
        st.unwrap_or(-1) as i64 * if gone { 1 } else { -1 },
    );
}

/// A fatal signal sent to one (non-leader) thread kills the group,
/// the main thread blocked in read() included
fn test_fatal_signal() {
    let p = pipes();
    let pid = sys_fork();
    if pid == 0 {
        spawn_blocked(&p);
        reader(p.block[0] as u64);
    }
    let tids = parent_side(&p);
    sleep_ms(50);
    sys_tgkill(pid, tids[1], SIGTERM);
    let (st, gone) = reap(pid, &p);
    report(
        b"GROUP_FATAL_SIGNAL",
        st == Some(SIGTERM as i32) && gone,
        st.unwrap_or(-1) as i64 * if gone { 1 } else { -1 },
    );
}

/// Wait for a byte, then exit_group(9)
extern "C" fn late_exit(fd: u64) -> ! {
    let mut c = [0u8; 1];
    sys_read(fd, c.as_mut_ptr(), 1);
    sys_exit_group(9)
}

/// The main thread exits alone (exit, not exit_group): the process is
/// not reaped while its other thread runs; that thread's exit_group
/// sets the status
fn test_leader_delay() {
    let p = pipes();
    let pid = sys_fork();
    if pid == 0 {
        send_tids(&p, [start(0, late_exit, p.block[0] as u64), 0]);
        sleep_ms(20);
        sys_exit(4);
    }
    parent_side(&p);
    sleep_ms(100);
    let mut st = 0i32;
    let early = sys_wait4(pid, &mut st, WNOHANG, 0);
    sys_write(p.block[1] as u64, b"x".as_ptr(), 1);
    let (st, gone) = reap(pid, &p);
    report(
        b"GROUP_LEADER_DELAY",
        early == 0 && st == Some(9 << 8) && gone,
        if early != 0 {
            -1000 - early
        } else {
            st.unwrap_or(-1) as i64
        },
    );
}

/// SIGKILL to a process whose main thread has exited reaches the
/// thread still running
fn test_kill_zombie_leader() {
    let p = pipes();
    let pid = sys_fork();
    if pid == 0 {
        send_tids(&p, [start(0, reader, p.block[0] as u64), 0]);
        sleep_ms(20);
        sys_exit(0);
    }
    parent_side(&p);
    sleep_ms(100);
    sys_kill(pid, SIGKILL);
    let (st, gone) = reap(pid, &p);
    report(
        b"GROUP_KILL_ZOMBIE_LEADER",
        st == Some(SIGKILL as i32) && gone,
        st.unwrap_or(-1) as i64 * if gone { 1 } else { -1 },
    );
}

/// exec `busybox sh -c "exit <code>"`
fn exec_exit(code: &[u8]) -> ! {
    let argv: [*const u8; 5] = [
        BB.as_ptr(),
        b"sh\0".as_ptr(),
        b"-c\0".as_ptr(),
        code.as_ptr(),
        core::ptr::null(),
    ];
    let envp: [*const u8; 1] = [core::ptr::null()];
    sys_execve(BB.as_ptr(), argv.as_ptr(), envp.as_ptr());
    sys_exit_group(127)
}

/// execve from the main thread ends its blocked siblings
fn test_exec_leader() {
    let p = pipes();
    let pid = sys_fork();
    if pid == 0 {
        spawn_blocked(&p);
        exec_exit(b"exit 3\0");
    }
    parent_side(&p);
    let (st, gone) = reap(pid, &p);
    report(
        b"GROUP_EXEC_LEADER",
        st == Some(3 << 8) && gone,
        st.unwrap_or(-1) as i64 * if gone { 1 } else { -1 },
    );
}

extern "C" fn exec_thread(_: u64) -> ! {
    exec_exit(b"exit 5\0")
}

/// execve from a non-leader thread ends the main thread (blocked in
/// read) and takes over the process: the parent reaps the new image
fn test_exec_thread() {
    let p = pipes();
    let pid = sys_fork();
    if pid == 0 {
        send_tids(&p, [start(0, exec_thread, 0), 0]);
        reader(p.block[0] as u64);
    }
    parent_side(&p);
    let (st, gone) = reap(pid, &p);
    report(
        b"GROUP_EXEC_THREAD",
        st == Some(5 << 8) && gone,
        st.unwrap_or(-1) as i64 * if gone { 1 } else { -1 },
    );
}
