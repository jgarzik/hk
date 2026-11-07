//! Which task the scheduling syscalls act on, and who may (Linux
//! kernel/sched/syscalls.c: pid 0 is current, the calling thread;
//! check_same_owner or CAP_SYS_NICE; kernel/sys.c setpriority;
//! block/ioprio.c ioprio_check_cap)
//!
//! In a child running as nobody, with a second thread:
//! - SCHED_PID0_THREAD: setpriority(PRIO_PROCESS, 0, 19) from the second
//!   thread changes that thread's nice only, not the main thread's
//! - AFFINITY_SELF_NONROOT: that thread sets its own affinity by its
//!   tid (pthread_setaffinity_np)
//! - IOPRIO_IDLE_NONROOT: the idle I/O class needs no privilege
//! - PRIO_USER: getpriority(PRIO_USER, 0) covers the caller's tasks

use crate::tests::helpers::{print, print_num, println};
use crate::tests::mm::fork_mm::{join, spawn_thread};
use core::sync::atomic::{AtomicI64, Ordering};
use hk_syscall::{
    sys_exit, sys_fork, sys_getpriority, sys_gettid, sys_ioprio_set, sys_sched_setaffinity,
    sys_setpriority, sys_setresuid, sys_wait4,
};

const PRIO_PROCESS: i32 = 0;
const PRIO_USER: i32 = 2;
const IOPRIO_WHO_PROCESS: i32 = 1;
const IOPRIO_CLASS_IDLE: i32 = 3;

#[repr(C, align(16))]
struct Stack([u8; 16384]);
static mut STACK: Stack = Stack([0; 16384]);
static mut CTID: u32 = 0;
static T_TID: AtomicI64 = AtomicI64::new(0);
static T_PRIO: AtomicI64 = AtomicI64::new(-1);
static T_AFF: AtomicI64 = AtomicI64::new(-1);

extern "C" fn worker(_: u64) -> ! {
    T_TID.store(sys_gettid(), Ordering::Release);
    // Nice 19: lowering one's own priority needs no privilege
    let set = sys_setpriority(PRIO_PROCESS, 0, 19);
    // 20 - nice of this thread after the set
    let mine = sys_getpriority(PRIO_PROCESS, 0);
    T_PRIO.store(if set == 0 { mine } else { -1000 + set }, Ordering::Release);
    let mask: u64 = 1;
    T_AFF.store(
        sys_sched_setaffinity(sys_gettid(), 8, &mask),
        Ordering::Release,
    );
    sys_exit(0)
}

const NAMES: [&[u8]; 4] = [
    b"SCHED_PID0_THREAD",
    b"AFFINITY_SELF_NONROOT",
    b"IOPRIO_IDLE_NONROOT",
    b"PRIO_USER",
];

pub fn run_tests() {
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(child());
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    // Exit code: one bit per failed check; 0x80 setup failed
    let bits = if st & 0x7f != 0 {
        0xff
    } else {
        (st >> 8) & 0xff
    };
    for (i, n) in NAMES.iter().enumerate() {
        print(n);
        if bits & (1 << i) == 0 && bits & 0x80 == 0 {
            println(b":OK");
        } else {
            print(b":FAIL status ");
            print_num(st as i64);
            println(b"");
        }
    }
}

/// One bit per failed check (bit i for NAMES[i]); 0x80 if setup failed
fn child() -> u64 {
    if sys_setresuid(65534, 65534, 65534) != 0 {
        return 0x80;
    }
    // Inherited from the boot tester, whose nice earlier tests changed
    let base = sys_getpriority(PRIO_PROCESS, 0);
    unsafe {
        let top = (&raw mut STACK as *mut u8).add(16384) as u64;
        let ctid = &raw mut CTID;
        core::ptr::write_volatile(ctid, 1);
        if spawn_thread(top, worker, 0, ctid) <= 0 || !join(ctid) {
            return 0x80;
        }
    }
    let mut bits = 0;
    // The thread's nice became 19 (20 - 19 = 1), the main thread's stayed
    if T_PRIO.load(Ordering::Acquire) != 1 || sys_getpriority(PRIO_PROCESS, 0) != base {
        bits |= 1;
    }
    if T_AFF.load(Ordering::Acquire) != 0 {
        bits |= 2;
    }
    if sys_ioprio_set(IOPRIO_WHO_PROCESS, 0, IOPRIO_CLASS_IDLE << 13) != 0 {
        bits |= 4;
    }
    if sys_getpriority(PRIO_USER, 0) <= 0 {
        bits |= 8;
    }
    bits
}
