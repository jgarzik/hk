//! Signal queue (Linux struct sigqueue) tests
//!
//! - /proc/self/status SigQ is queued/RLIMIT_SIGPENDING, the limit set
//!   at boot (half of max_threads) and inherited
//! - at RLIMIT_SIGPENDING (lowered, even for root) a user-queued RT
//!   signal fails with EAGAIN; kill() of it and a queued non-RT signal
//!   still arrive, without info
//! - RT signals queue every instance, in order, each with its own info
//! - a non-RT signal pending once more is not queued again
//! - kill() info carries the sender's pid and uid (SI_USER)
//! - a child's exit sends SIGCHLD with CLD_EXITED, pid and status
//! - /proc/self/status SigQ counts the queued signals
//! - a signalfd read gives the queued info (ssi_code, ssi_pid, ssi_int)
//! - an SA_SIGINFO handler gets the queued info (si_code, si_pid,
//!   si_value)

use super::helpers::{host_mode, print, print_num, println, read_file, skip};
use hk_syscall::{
    RLIMIT_SIGPENDING, RLimit, SA_RESTORER, SA_SIGINFO, SFD_NONBLOCK, SIG_DFL, SigInfo, sys_close,
    sys_exit, sys_fork, sys_getpid, sys_getrlimit, sys_kill, sys_read, sys_rt_sigaction,
    sys_rt_sigprocmask, sys_rt_sigqueueinfo, sys_rt_sigtimedwait, sys_setrlimit, sys_signalfd4,
    sys_wait4,
};

const SIG_BLOCK: i32 = 0;
const SIG_SETMASK: i32 = 2;
const SIGUSR1: u32 = 10;
const SIGCHLD: u32 = 17;
const SIGRT: u32 = 40;
const SI_USER: i32 = 0;
const SI_QUEUE: i32 = -1;
const CLD_EXITED: i32 = 1;
const EAGAIN: i64 = -11;

pub fn run_tests() {
    test_sigq_limit();
    test_eagain();
    test_rt_queue();
    test_legacy_collapse();
    test_kill_info();
    test_sigchld_exit();
    test_signalfd_info();
    test_handler_info();
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

/// Three queued RT signals: three deliveries, in order, with their values
fn test_rt_queue() {
    let old = block(bit(SIGRT));
    let (q0, _) = sigq();
    let mut fail = 0;
    for v in 1..=3 {
        if queue_self(SIGRT, v * 11) != 0 {
            fail = 1;
        }
    }
    let q = sigq().0 - q0;
    let mut got = [0i32; 3];
    for g in got.iter_mut() {
        let mut info = zeroed();
        if wait_sig(bit(SIGRT), 0, &mut info) == SIGRT as i64 && info.si_code == SI_QUEUE {
            *g = info.si_status;
        }
    }
    let mut info = zeroed();
    let fourth = wait_sig(bit(SIGRT), 0, &mut info);
    setmask(old);
    if fail == 0 && q == 3 && got == [11, 22, 33] && fourth == EAGAIN {
        println(b"SIGQUEUE_RT_ORDER:OK");
    } else {
        print(b"SIGQUEUE_RT_ORDER:FAIL sigq=");
        print_num(q);
        print(b" values=");
        for g in got {
            print_num(g as i64);
            print(b",");
        }
        print(b" fourth=");
        print_num(fourth);
        println(b"");
    }
}

/// A non-RT signal sent twice while blocked is delivered once, with the
/// first sender's info
fn test_legacy_collapse() {
    let old = block(bit(SIGUSR1));
    queue_self(SIGUSR1, 5);
    queue_self(SIGUSR1, 6);
    let mut a = zeroed();
    let first = wait_sig(bit(SIGUSR1), 0, &mut a);
    let mut b = zeroed();
    let second = wait_sig(bit(SIGUSR1), 0, &mut b);
    setmask(old);
    if first == SIGUSR1 as i64 && a.si_status == 5 && second == EAGAIN {
        println(b"SIGQUEUE_LEGACY:OK");
    } else {
        print(b"SIGQUEUE_LEGACY:FAIL first=");
        print_num(first);
        print(b" value=");
        print_num(a.si_status as i64);
        print(b" second=");
        print_num(second);
        println(b"");
    }
}

/// kill() from the parent: the child's info has SI_USER, the parent's
/// pid and uid 0
fn test_kill_info() {
    let old = block(bit(SIGUSR1));
    let parent = sys_getpid();
    let child = sys_fork();
    if child == 0 {
        let mut info = zeroed();
        let r = wait_sig(bit(SIGUSR1), 10, &mut info);
        let ok = r == SIGUSR1 as i64
            && info.si_code == SI_USER
            && info.si_pid as i64 == parent
            && info.si_uid == 0;
        sys_exit(if ok { 0 } else { 1 });
    }
    sys_kill(child, SIGUSR1);
    let mut status = 0i32;
    sys_wait4(child, &mut status, 0, 0);
    setmask(old);
    if status == 0 {
        println(b"SIGQUEUE_KILL_INFO:OK");
    } else {
        print(b"SIGQUEUE_KILL_INFO:FAIL status=");
        print_num(status as i64);
        println(b"");
    }
}

/// A child's exit: SIGCHLD with CLD_EXITED, its pid and exit status
fn test_sigchld_exit() {
    if !host_mode() {
        skip(
            b"SIGQUEUE_SIGCHLD",
            b"no do_notify_parent: a child's exit sends no SIGCHLD",
        );
        return;
    }
    let old = block(bit(SIGCHLD));
    let child = sys_fork();
    if child == 0 {
        sys_exit(7);
    }
    let mut info = zeroed();
    let r = wait_sig(bit(SIGCHLD), 10, &mut info);
    let mut status = 0i32;
    sys_wait4(child, &mut status, 0, 0);
    setmask(old);
    if r == SIGCHLD as i64
        && info.si_code == CLD_EXITED
        && info.si_pid as i64 == child
        && info.si_status == 7
    {
        println(b"SIGQUEUE_SIGCHLD:OK");
    } else {
        print(b"SIGQUEUE_SIGCHLD:FAIL r=");
        print_num(r);
        print(b" code=");
        print_num(info.si_code as i64);
        print(b" pid=");
        print_num(info.si_pid as i64);
        print(b" status=");
        print_num(info.si_status as i64);
        println(b"");
    }
}

/// u32 at `at` of a signalfd_siginfo
fn ssi_u32(b: &[u8; 128], at: usize) -> u32 {
    u32::from_ne_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// A signalfd read of a queued RT signal and of a kill(): ssi_code,
/// ssi_pid, ssi_uid, and ssi_int / ssi_ptr from the sigval
fn test_signalfd_info() {
    let old = block(bit(SIGRT) | bit(SIGUSR1));
    let mask = bit(SIGRT) | bit(SIGUSR1);
    let fd = sys_signalfd4(-1, &mask, 8, SFD_NONBLOCK);
    let me = sys_getpid() as u32;
    queue_self(SIGRT, 99);
    sys_kill(sys_getpid(), SIGUSR1);
    let mut a = [0u8; 128];
    let mut b = [0u8; 128];
    let ra = sys_read(fd as u64, a.as_mut_ptr(), 128);
    let rb = sys_read(fd as u64, b.as_mut_ptr(), 128);
    sys_close(fd as u64);
    setmask(old);
    // ssi_signo 0, ssi_code 8, ssi_pid 12, ssi_uid 16, ssi_int 44,
    // ssi_ptr 48; SIGUSR1 is lower, so it is read first
    let usr1 = ssi_u32(&b, 0) == SIGRT
        && ssi_u32(&a, 0) == SIGUSR1
        && ssi_u32(&a, 8) as i32 == SI_USER
        && ssi_u32(&a, 12) == me;
    let rt = ssi_u32(&b, 8) as i32 == SI_QUEUE
        && ssi_u32(&b, 12) == me
        && ssi_u32(&b, 16) == 0
        && ssi_u32(&b, 44) == 99
        && ssi_u32(&b, 48) == 99;
    if fd >= 0 && ra == 128 && rb == 128 && usr1 && rt {
        println(b"SIGQUEUE_SIGNALFD:OK");
    } else {
        print(b"SIGQUEUE_SIGNALFD:FAIL fd=");
        print_num(fd);
        print(b" reads=");
        print_num(ra);
        print(b",");
        print_num(rb);
        for (n, at) in [(0, 0), (0, 8), (0, 12), (1, 0), (1, 8), (1, 12), (1, 44)] {
            print(b" ");
            print_num(ssi_u32(if n == 0 { &a } else { &b }, at) as i64);
        }
        println(b"");
    }
}

/// What the SA_SIGINFO handler saw: si_code, si_pid, si_value, calls
static mut SEEN: [i32; 4] = [0; 4];

extern "C" fn info_handler(_sig: i32, info: *const SigInfo, _uc: *const u8) {
    // SAFETY: the kernel passes a valid siginfo; SEEN is only touched
    // by this thread, the handler running between its own statements
    unsafe {
        let i = &*info;
        let seen = &raw mut SEEN;
        (*seen)[0] = i.si_code;
        (*seen)[1] = i.si_pid;
        (*seen)[2] = i.si_status;
        (*seen)[3] += 1;
    }
}

/// An SA_SIGINFO handler of a queued RT signal gets its info
fn test_handler_info() {
    let sig = SIGRT + 1;
    let act: [u64; 4] = [
        info_handler as *const () as u64,
        SA_SIGINFO | SA_RESTORER,
        super::signals::restorer_addr(),
        0,
    ];
    let dfl: [u64; 4] = [SIG_DFL, 0, 0, 0];
    let old = block(bit(sig));
    let r = sys_rt_sigaction(sig, act.as_ptr() as u64, 0, 8);
    queue_self(sig, 1234);
    // Unblocked, it is delivered on the way out of this syscall
    setmask(old);
    sys_rt_sigaction(sig, dfl.as_ptr() as u64, 0, 8);
    // SAFETY: the handler has run (or not); nothing else writes SEEN
    let seen = unsafe { core::ptr::read_volatile(&raw const SEEN) };
    let me = sys_getpid() as i32;
    if r == 0 && seen == [SI_QUEUE, me, 1234, 1] {
        println(b"SIGQUEUE_HANDLER_INFO:OK");
    } else {
        print(b"SIGQUEUE_HANDLER_INFO:FAIL seen=");
        for v in seen {
            print_num(v as i64);
            print(b",");
        }
        println(b"");
    }
}
