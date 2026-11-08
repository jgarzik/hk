//! process_vm_readv / process_vm_writev syscall tests
//!
//! Tests for cross-process memory access syscalls.

use crate::harness::{T, fail_num};
use crate::helpers::{print, print_num, println};
use crate::mm::fork_mm::{join, spawn_thread};
use core::sync::atomic::{AtomicI64, Ordering};
use hk_syscall::{
    IoVec, sys_exit, sys_fork, sys_getpid, sys_prctl, sys_process_vm_readv, sys_process_vm_writev,
    sys_setresgid, sys_setresuid, sys_wait4,
};

const ESRCH: i64 = -3;
const EINVAL: i64 = -22;

/// Run all process_vm tests
pub fn run_tests() {
    println(b"=== process_vm Tests ===");

    test_process_vm_readv_self();
    test_process_vm_writev_self();
    test_process_vm_invalid_pid();
    test_process_vm_invalid_flags();
    test_process_vm_zero_iovecs();
    test_process_vm_sibling();
    test_process_vm_iov_limits();
}

static SIB_RESULT: AtomicI64 = AtomicI64::new(0);
static SIB_DATA: [u8; 8] = *b"sibling!";

#[repr(C, align(16))]
struct SibStack([u8; 16384]);
static mut SIB_STACK: SibStack = SibStack([0; 16384]);
static mut SIB_CTID: u32 = 0;

/// Thread body: read the process's own memory by pid
extern "C" fn sib_reader(_: u64) -> ! {
    let mut dest = [0u8; 8];
    let local = IoVec {
        iov_base: dest.as_mut_ptr() as *const u8,
        iov_len: 8,
    };
    let remote = IoVec {
        iov_base: SIB_DATA.as_ptr(),
        iov_len: 8,
    };
    let r = sys_process_vm_readv(sys_getpid() as i32, &local, 1, &remote, 1, 0);
    let ok = r == 8 && dest == SIB_DATA;
    SIB_RESULT.store(if ok { 1 } else { r.min(-1) }, Ordering::Relaxed);
    sys_exit(0)
}

/// PROCESS_VM_SIBLING: a non-dumpable uid-1000 process's second thread
/// reads its own process by pid (Linux mm_access exempts the caller's
/// own mm, whatever the thread)
fn test_process_vm_sibling() {
    const PR_SET_DUMPABLE: i32 = 4;
    let pid = sys_fork();
    if pid == 0 {
        if sys_setresgid(1000, 1000, 1000) != 0 || sys_setresuid(1000, 1000, 1000) != 0 {
            sys_exit(2);
        }
        sys_prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
        unsafe {
            let top = (&raw mut SIB_STACK as *mut u8).add(16384) as u64;
            let ctid = &raw mut SIB_CTID;
            core::ptr::write_volatile(ctid, 1);
            if spawn_thread(top, sib_reader, 0, ctid) < 0 || !join(ctid) {
                sys_exit(3);
            }
        }
        sys_exit(if SIB_RESULT.load(Ordering::Relaxed) == 1 {
            0
        } else {
            1
        });
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    print(b"PROCESS_VM_SIBLING");
    if st == 0 {
        println(b":OK");
    } else {
        fail_num(b":FAIL ", (st >> 8) as i64);
    }
}

/// Test: Read own memory using process_vm_readv (pid = getpid())
fn test_process_vm_readv_self() {
    print(b"  process_vm_readv self: ");

    // Source buffer with known data
    let source: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    // Destination buffer
    let mut dest: [u8; 16] = [0; 16];

    let local_iov = IoVec {
        iov_base: dest.as_mut_ptr() as *const u8,
        iov_len: 16,
    };
    let remote_iov = IoVec {
        iov_base: source.as_ptr(),
        iov_len: 16,
    };

    let pid = sys_getpid() as i32;
    let ret = sys_process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);

    if ret == 16 && dest == source {
        println(b"PASS");
    } else if ret < 0 {
        print(b"FAIL (error ");
        print_num(ret);
        println(b")");
    } else {
        print(b"FAIL (read ");
        print_num(ret);
        print(b" bytes, data mismatch)");
        println(b"");
    }
}

/// Test: Write own memory using process_vm_writev (pid = getpid())
fn test_process_vm_writev_self() {
    print(b"  process_vm_writev self: ");

    // Source buffer with known data
    let source: [u8; 16] = [
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0x00,
    ];
    // Destination buffer (initially zeros)
    let mut dest: [u8; 16] = [0; 16];

    let local_iov = IoVec {
        iov_base: source.as_ptr(),
        iov_len: 16,
    };
    let remote_iov = IoVec {
        iov_base: dest.as_mut_ptr() as *const u8,
        iov_len: 16,
    };

    let pid = sys_getpid() as i32;
    let ret = sys_process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);

    if ret == 16 && dest == source {
        println(b"PASS");
    } else if ret < 0 {
        print(b"FAIL (error ");
        print_num(ret);
        println(b")");
    } else {
        print(b"FAIL (wrote ");
        print_num(ret);
        print(b" bytes, data mismatch)");
        println(b"");
    }
}

/// Test: Invalid PID should return ESRCH
fn test_process_vm_invalid_pid() {
    print(b"  process_vm_readv invalid PID: ");

    let mut dest: [u8; 8] = [0; 8];
    let local_iov = IoVec {
        iov_base: dest.as_mut_ptr() as *const u8,
        iov_len: 8,
    };
    let remote_iov = IoVec {
        iov_base: 0x1000 as *const u8,
        iov_len: 8,
    };

    // Use an absurdly high PID that shouldn't exist
    let ret = sys_process_vm_readv(99999999, &local_iov, 1, &remote_iov, 1, 0);

    if ret == ESRCH {
        println(b"PASS");
    } else {
        print(b"FAIL (expected ESRCH=");
        print_num(ESRCH);
        print(b", got ");
        print_num(ret);
        println(b")");
    }
}

/// Test: Non-zero flags should return EINVAL
fn test_process_vm_invalid_flags() {
    print(b"  process_vm_readv invalid flags: ");

    let mut dest: [u8; 8] = [0; 8];
    let source: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    let local_iov = IoVec {
        iov_base: dest.as_mut_ptr() as *const u8,
        iov_len: 8,
    };
    let remote_iov = IoVec {
        iov_base: source.as_ptr(),
        iov_len: 8,
    };

    let pid = sys_getpid() as i32;
    // Use non-zero flags (should fail)
    let ret = sys_process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 1);

    if ret == EINVAL {
        println(b"PASS");
    } else {
        print(b"FAIL (expected EINVAL=");
        print_num(EINVAL);
        print(b", got ");
        print_num(ret);
        println(b")");
    }
}

/// Test: Zero iovecs should return 0
fn test_process_vm_zero_iovecs() {
    print(b"  process_vm_readv zero iovecs: ");

    let local_iov = IoVec {
        iov_base: core::ptr::null(),
        iov_len: 0,
    };
    let remote_iov = IoVec {
        iov_base: core::ptr::null(),
        iov_len: 0,
    };

    let pid = sys_getpid() as i32;
    let ret = sys_process_vm_readv(pid, &local_iov, 0, &remote_iov, 0, 0);

    if ret == 0 {
        println(b"PASS");
    } else {
        print(b"FAIL (expected 0, got ");
        print_num(ret);
        println(b")");
    }
}

/// PROCESS_VM_IOV_LIMITS: the iovecs are checked as Linux
/// process_vm_rw does: a length negative as ssize_t is EINVAL, local or
/// remote; the local count is an unsigned int (2^32 + 1 is 1); no
/// remote byte to copy is 0 before the pid is looked up
fn test_process_vm_iov_limits() {
    let mut t = T::new(b"PROCESS_VM_IOV_LIMITS");
    let src: [u8; 8] = *b"iovlimit";
    let mut dst = [0u8; 8];
    let iov = |p: *const u8, n: usize| IoVec {
        iov_base: p,
        iov_len: n,
    };
    let local = iov(dst.as_mut_ptr(), 8);
    let remote = iov(src.as_ptr(), 8);
    let neg = 1usize << 63;
    let me = sys_getpid() as i32;
    let r = sys_process_vm_readv(me, &iov(dst.as_mut_ptr(), neg), 1, &remote, 1, 0);
    t.eq(b"negative local len", r, EINVAL);
    let r = sys_process_vm_readv(me, &local, 1, &iov(src.as_ptr(), neg), 1, 0);
    t.eq(b"negative remote len", r, EINVAL);
    let r = sys_process_vm_writev(me, &local, 1, &iov(dst.as_mut_ptr(), neg), 1, 0);
    t.eq(b"writev negative remote len", r, EINVAL);
    let r = sys_process_vm_readv(me, &local, 1, &remote, 1025, 0);
    t.eq(b"remote count past IOV_MAX", r, EINVAL);
    let r = sys_process_vm_readv(me, &local, (1 << 32) + 1, &remote, 1, 0);
    t.eq(b"local count 2^32 + 1", r, 8);
    t.ok(b"bytes copied", dst == src, 0);
    let r = sys_process_vm_readv(99999999, &local, 1, &iov(src.as_ptr(), 0), 1, 0);
    t.eq(b"no remote byte, no such pid", r, 0);
    t.done();
}
