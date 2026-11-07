//! Signal queue (Linux struct sigqueue) tests
//!
//! - /proc/self/status SigQ is queued/RLIMIT_SIGPENDING, the limit set
//!   at boot (half of max_threads) and inherited
//! - at RLIMIT_SIGPENDING (lowered, even for root) a user-queued RT
//!   signal fails with EAGAIN; kill() of it and a queued non-RT signal
//!   still arrive, without info

use super::helpers::{print, print_num, println, read_file};
use hk_syscall::{
    RLIMIT_SIGPENDING, RLimit, SigInfo, sys_getpid, sys_getrlimit, sys_kill, sys_rt_sigprocmask,
    sys_rt_sigqueueinfo, sys_rt_sigtimedwait, sys_setrlimit,
};

const SIG_BLOCK: i32 = 0;
const SIG_SETMASK: i32 = 2;
const SIGUSR1: u32 = 10;
const SIGRT: u32 = 40;
const SI_QUEUE: i32 = -1;
const EAGAIN: i64 = -11;

pub fn run_tests() {
    test_sigq_limit();
    test_eagain();
}

fn bit(sig: u32) -> u64 {
    1 << (sig - 1)
}

/// Block `mask`, returning the old mask
fn block(mask: u64) -> u64 {
    let mut old = 0u64;
    sys_rt_sigprocmask(
        SIG_BLOCK,
        &mask as *const u64 as u64,
        &mut old as *mut u64 as u64,
        8,
    );
    old
}

fn setmask(mask: u64) {
    sys_rt_sigprocmask(SIG_SETMASK, &mask as *const u64 as u64, 0, 8);
}

fn zeroed() -> SigInfo {
    // SAFETY: SigInfo is plain integers
    unsafe { core::mem::zeroed() }
}

/// sigtimedwait for `mask` with a timeout in seconds; the signal or -errno
fn wait_sig(mask: u64, secs: i64, info: &mut SigInfo) -> i64 {
    let ts = [secs, 0i64];
    sys_rt_sigtimedwait(
        &mask as *const u64 as u64,
        info as *mut SigInfo as u64,
        ts.as_ptr() as u64,
        8,
    )
}

/// rt_sigqueueinfo to self with si_value = `val` (SI_QUEUE)
fn queue_self(sig: u32, val: i32) -> i64 {
    let mut info = zeroed();
    info.si_signo = sig as i32;
    info.si_code = SI_QUEUE;
    info.si_pid = sys_getpid() as i32;
    // sigval_t follows si_pid/si_uid in _rt (si_status's slot)
    info.si_status = val;
    sys_rt_sigqueueinfo(sys_getpid(), sig, &info as *const SigInfo as u64)
}

/// How many `sig` are pending (taken by sigtimedwait until EAGAIN)
fn drain(sig: u32) -> i64 {
    let mut n = 0;
    let mut info = zeroed();
    while wait_sig(bit(sig), 0, &mut info) == sig as i64 {
        n += 1;
    }
    n
}

/// Parse a decimal number at the start of `s`
fn num(s: &[u8]) -> (i64, usize) {
    let mut v = 0i64;
    let mut n = 0;
    for &c in s {
        if !c.is_ascii_digit() {
            break;
        }
        v = v * 10 + (c - b'0') as i64;
        n += 1;
    }
    (v, n)
}

/// /proc/self/status SigQ: (queued, limit), or (-1, -1)
fn sigq() -> (i64, i64) {
    let mut buf = [0u8; 2048];
    let n = read_file(b"/proc/self/status\0", &mut buf);
    if n <= 0 {
        return (-1, -1);
    }
    let s = &buf[..n as usize];
    let key = b"SigQ:\t";
    let Some(at) = s.windows(key.len()).position(|w| w == key) else {
        return (-1, -1);
    };
    let s = &s[at + key.len()..];
    let (q, len) = num(s);
    if s.get(len) != Some(&b'/') {
        return (-1, -1);
    }
    (q, num(&s[len + 1..]).0)
}

/// RLIMIT_SIGPENDING is set (soft = hard, non-zero) and SigQ shows it
fn test_sigq_limit() {
    let mut r = RLimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = sys_getrlimit(RLIMIT_SIGPENDING, &mut r);
    let (q, lim) = sigq();
    if rc == 0 && r.rlim_cur > 0 && r.rlim_cur == r.rlim_max && lim == r.rlim_cur as i64 && q >= 0
    {
        println(b"SIGQUEUE_LIMIT:OK");
    } else {
        print(b"SIGQUEUE_LIMIT:FAIL rlim=");
        print_num(r.rlim_cur as i64);
        print(b"/");
        print_num(r.rlim_max as i64);
        print(b" sigq=");
        print_num(q);
        print(b"/");
        print_num(lim);
        println(b"");
    }
}

/// RLIMIT_SIGPENDING two above what root has queued: two RT signals
/// queue, the third is EAGAIN; kill() of it is 0 but adds no instance,
/// a queued SIGUSR1 is 0 and pending; SigQ counts the two
fn test_eagain() {
    let old = block(bit(SIGRT) | bit(SIGUSR1));
    let mut lim = RLimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    sys_getrlimit(RLIMIT_SIGPENDING, &mut lim);
    let (q0, _) = sigq();
    let low = RLimit {
        rlim_cur: q0 as u64 + 2,
        rlim_max: lim.rlim_max,
    };
    let set = sys_setrlimit(RLIMIT_SIGPENDING, &low);
    let r = [queue_self(SIGRT, 1), queue_self(SIGRT, 2), queue_self(SIGRT, 3)];
    let rk = sys_kill(sys_getpid(), SIGRT);
    let ru = queue_self(SIGUSR1, 4);
    let (q, _) = sigq();
    let n = drain(SIGRT);
    let nu = drain(SIGUSR1);
    sys_setrlimit(RLIMIT_SIGPENDING, &lim);
    setmask(old);
    if set == 0 && r == [0, 0, EAGAIN] && rk == 0 && ru == 0 && q == q0 + 2 && n == 2 && nu == 1 {
        println(b"SIGQUEUE_EAGAIN:OK");
    } else {
        print(b"SIGQUEUE_EAGAIN:FAIL set=");
        print_num(set);
        print(b" queue=");
        for v in r {
            print_num(v);
            print(b",");
        }
        print(b" kill=");
        print_num(rk);
        print(b" usr1=");
        print_num(ru);
        print(b" sigq=");
        print_num(q - q0);
        print(b" rt=");
        print_num(n);
        print(b" usr1n=");
        print_num(nu);
        println(b"");
    }
}
