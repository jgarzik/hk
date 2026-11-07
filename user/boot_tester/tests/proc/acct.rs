//! Process accounting (acct) tests
//!
//! Tests:
//! - Test acct enable/disable
//! - Test acct with invalid path
//! - Test acct capability requirement
//! - ACCT_GROUP_ONCE: a process of 8 threads that dies at once (exit_group)
//!   writes one acct_v3 record, not one per thread (Linux acct_process
//!   runs for the group's last thread); switching accounting off writes
//!   the caller's record (Linux acct_pin_kill)
//! - ACCT_ASU: ASU marks a process that used a capability (Linux
//!   PF_SUPERPRIV), not one that ran as root; AFORK one that forked and
//!   never exec'd (PF_FORKNOEXEC)

use crate::tests::harness::{fail_num, pass};
use crate::tests::helpers::{print, print_num, println};
use crate::tests::mm::fork_mm::spawn_thread;
use core::ptr;
use hk_syscall::{
    O_CREAT, O_RDONLY, O_TRUNC, O_WRONLY, Timespec, sys_acct, sys_close, sys_exit_group, sys_fork,
    sys_getpid, sys_nanosleep, sys_open, sys_read, sys_unlink, sys_wait4,
};

/// Run all acct tests
pub fn run_tests() {
    test_acct_disable();
    test_acct_invalid_path();
    test_acct_group_once();
    test_acct_asu();
}

const THREADS: usize = 7;

#[repr(C, align(16))]
struct ThreadStack([u8; 16384]);
static mut STACKS: [ThreadStack; THREADS] = [const { ThreadStack([0; 16384]) }; THREADS];
static mut CTIDS: [u32; THREADS] = [0; THREADS];

/// A thread that sleeps until its group dies
extern "C" fn sleeper(_: u64) -> ! {
    let ts = Timespec {
        tv_sec: 60,
        tv_nsec: 0,
    };
    loop {
        sys_nanosleep(&ts, ptr::null_mut());
    }
}

/// A group of 8 threads exiting together leaves one 64-byte record
fn test_acct_group_once() {
    let path = b"/tmp/acct_group\0";
    let fd = sys_open(path.as_ptr(), O_CREAT | O_WRONLY | O_TRUNC, 0o600);
    sys_close(fd as u64);
    if sys_acct(path.as_ptr()) != 0 {
        print(b"ACCT_GROUP_ONCE:FAIL acct on");
        println(b"");
        return;
    }
    let pid = sys_fork();
    if pid == 0 {
        for i in 0..THREADS {
            // SAFETY: each thread gets its own static stack and tid word
            unsafe {
                let top = (&raw mut STACKS[i] as *mut u8).add(16384) as u64;
                spawn_thread(top, sleeper, 0, &raw mut CTIDS[i]);
            }
        }
        let ts = Timespec {
            tv_sec: 0,
            tv_nsec: 20_000_000,
        };
        sys_nanosleep(&ts, ptr::null_mut());
        sys_exit_group(0);
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    sys_acct(ptr::null());
    // acct_v3 records: ac_pid at byte 16 of each 64
    let mut buf = [0u8; 512];
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    let n = sys_read(fd as u64, buf.as_mut_ptr(), buf.len() as u64).max(0) as usize;
    sys_close(fd as u64);
    sys_unlink(path.as_ptr());
    let pid_of = |r: &[u8]| u32::from_ne_bytes([r[16], r[17], r[18], r[19]]) as i64;
    let recs = buf[..n - n % 64].chunks(64);
    let child = recs.clone().filter(|r| pid_of(r) == pid).count();
    let me = recs.filter(|r| pid_of(r) == sys_getpid()).count();
    if n == 128 && child == 1 && me == 1 {
        pass(b"ACCT_GROUP_ONCE");
    } else {
        print(b"ACCT_GROUP_ONCE:FAIL bytes ");
        print_num(n as i64);
        print(b" child records ");
        print_num(child as i64);
        print(b" own ");
        print_num(me as i64);
        println(b"");
    }
}

/// Test acct disable (NULL filename)
fn test_acct_disable() {
    // Disable accounting (should work if already disabled)
    let ret = sys_acct(ptr::null());
    // This might return EPERM (-1) if we don't have CAP_SYS_PACCT
    // or 0 if we have the capability
    if ret != 0 && ret != -1 {
        fail_num(b"ACCT_DISABLE:FAIL: expected 0 or -1 (EPERM), got ", ret);
        return;
    }

    pass(b"ACCT_DISABLE");
}

/// Test acct with non-existent file (needs capability)
fn test_acct_invalid_path() {
    let path = b"/nonexistent/acct/file\0";
    let ret = sys_acct(path.as_ptr());

    // This should return either:
    // -1 (EPERM) if we don't have CAP_SYS_PACCT
    // -2 (ENOENT) if file doesn't exist and we have capability
    if ret != -1 && ret != -2 {
        fail_num(
            b"ACCT_INVALID_PATH:FAIL: expected -1 (EPERM) or -2 (ENOENT), got ",
            ret,
        );
        return;
    }

    pass(b"ACCT_INVALID_PATH");
}

const AFORK: u8 = 0x01;
const ASU: u8 = 0x02;

/// Two root children, one that uses a capability (setuid(0):
/// CAP_SETUID) and one that does not: only the first is ASU, both AFORK
fn test_acct_asu() {
    let path = b"/tmp/acct_asu\0";
    let fd = sys_open(path.as_ptr(), O_CREAT | O_WRONLY | O_TRUNC, 0o600);
    sys_close(fd as u64);
    if sys_acct(path.as_ptr()) != 0 {
        println(b"ACCT_ASU:FAIL acct on");
        return;
    }
    let plain = sys_fork();
    if plain == 0 {
        sys_exit_group(0);
    }
    let mut st = 0i32;
    sys_wait4(plain, &mut st, 0, 0);
    let privileged = sys_fork();
    if privileged == 0 {
        hk_syscall::sys_setuid(0);
        sys_exit_group(0);
    }
    sys_wait4(privileged, &mut st, 0, 0);
    // Root, but nothing it does needs a capability: ids set to what they
    // are, a limit lowered (Linux asks only when a change needs it)
    let unneeded = sys_fork();
    if unneeded == 0 {
        hk_syscall::sys_setresuid(0, 0, 0);
        hk_syscall::sys_setreuid(0, u32::MAX);
        let low = hk_syscall::RLimit {
            rlim_cur: 64,
            rlim_max: 64,
        };
        hk_syscall::sys_setrlimit(7, &low); // RLIMIT_NOFILE
        sys_exit_group(0);
    }
    sys_wait4(unneeded, &mut st, 0, 0);
    sys_acct(ptr::null());
    let mut buf = [0u8; 512];
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    let n = sys_read(fd as u64, buf.as_mut_ptr(), buf.len() as u64).max(0) as usize;
    sys_close(fd as u64);
    sys_unlink(path.as_ptr());
    let pid_of = |r: &[u8]| u32::from_ne_bytes([r[16], r[17], r[18], r[19]]) as i64;
    let flag_of = |pid| {
        buf[..n - n % 64]
            .chunks(64)
            .find(|r| pid_of(r) == pid)
            .map_or(0xff, |r| r[0])
    };
    let (p, q, u) = (flag_of(plain), flag_of(privileged), flag_of(unneeded));
    if p & (AFORK | ASU) == AFORK && q & (AFORK | ASU) == AFORK | ASU && u & (AFORK | ASU) == AFORK
    {
        pass(b"ACCT_ASU");
    } else {
        print(b"ACCT_ASU:FAIL plain ");
        print_num(p as i64);
        print(b" privileged ");
        print_num(q as i64);
        print(b" unneeded ");
        print_num(u as i64);
        println(b"");
    }
}
