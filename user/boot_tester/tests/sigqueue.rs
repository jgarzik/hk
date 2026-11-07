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
//! - an mq_notify signal is SI_MESGQ from the sender with the
//!   registrant's sigev_value
//! - a tracee's ptrace stop sends its tracer SIGCHLD with CLD_TRAPPED,
//!   its pid and the stop signal
//! - sigaction to SIG_IGN, or SIG_DFL of an ignore-default signal,
//!   discards it pending, blocked or not, queued instances included
//! - a process-directed signal the leader blocks is taken by another
//!   thread (Linux shared_pending, complete_signal's thread choice)
//! - a POSIX timer's signal is SI_TIMER with si_tid and si_value; an
//!   interval timer's one queued signal counts the periods it missed in
//!   si_overrun (= timer_getoverrun); settime and delete drop a queued
//!   one; SIGEV_THREAD_ID signals that thread; ITIMER_REAL's SIGALRM is
//!   SI_KERNEL and the interval rearms when it is taken
//! - SIGCHLD SIG_IGN or SA_NOCLDWAIT: a child is reaped at its exit
//!   (wait is ECHILD); with SA_NOCLDWAIT SIGCHLD still comes
//! - a child's pdeath_signal comes when its parent exits, from it
//! - a SIGEV_THREAD_ID timer whose thread has exited sends nothing
//! - a child's custom exit signal becomes SIGCHLD once its parent
//!   exec'd (parent_exec_id) or it is reparented (reparent_leader)
//! - a tracer reads a signal-delivery stop's siginfo
//!   (PTRACE_GETSIGINFO), its tracee's queued ones
//!   (PTRACE_PEEKSIGINFO, shared), and changes what is delivered
//!   (PTRACE_SETSIGINFO)
//! - arm64: a handler set without SA_RESTORER returns through the
//!   kernel's trampoline (Linux: the vDSO sigtramp), a mapping of its
//!   own in /proc/self/maps ([sigpage]; Linux [vdso])

use super::helpers::{print, print_num, println, read_file, skip};
use hk_syscall::{
    MqAttr, O_CREAT, O_RDWR, SigEvent, SigVal, sys_mq_notify, sys_mq_open, sys_mq_timedsend,
    sys_mq_unlink, sys_ptrace,
};
use hk_syscall::{
    RLIMIT_SIGPENDING, RLimit, SA_RESTORER, SA_SIGINFO, SFD_NONBLOCK, SIG_DFL, SigInfo, sys_close,
    sys_exit, sys_fork, sys_getpid, sys_getrlimit, sys_kill, sys_read, sys_rt_sigaction,
    sys_rt_sigpending, sys_rt_sigprocmask, sys_rt_sigqueueinfo, sys_rt_sigtimedwait, sys_setrlimit, sys_signalfd4,
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
    test_mq_info();
    test_trapped_info();
    test_ignore_flush();
    test_group_thread();
    test_timer_info();
    test_timer_overrun();
    test_timer_drop();
    test_itimer_real();
    test_autoreap();
    test_pdeath();
    test_timer_gone();
    test_exit_signal_exec();
    test_exit_signal_reparent();
    test_ptrace_siginfo();
    #[cfg(target_arch = "aarch64")]
    test_no_restorer();
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

/// mq_notify(SIGEV_SIGNAL, SIGRT, value 777), then a send: the signal's
/// info is SI_MESGQ from this process with that value
fn test_mq_info() {
    const SI_MESGQ: i32 = -3;
    let name = b"sigqueue_mq\0";
    let attr = MqAttr::new(4, 16);
    let fd = sys_mq_open(name.as_ptr(), O_RDWR as i32 | O_CREAT as i32, 0o600, &attr) as i32;
    let old = block(bit(SIGRT));
    let sev = SigEvent {
        sigev_value: SigVal { sival_int: 777 },
        sigev_signo: SIGRT as i32,
        sigev_notify: 0, // SIGEV_SIGNAL
        ..SigEvent::default()
    };
    let n = sys_mq_notify(fd, &sev);
    let msg = *b"hi";
    let snd = sys_mq_timedsend(fd, msg.as_ptr(), 2, 0, core::ptr::null());
    let mut info = zeroed();
    let r = wait_sig(bit(SIGRT), 1, &mut info);
    setmask(old);
    sys_close(fd as u64);
    sys_mq_unlink(name.as_ptr());
    if fd >= 0
        && n == 0
        && snd == 0
        && r == SIGRT as i64
        && info.si_code == SI_MESGQ
        && info.si_pid as i64 == sys_getpid()
        && info.si_status == 777
    {
        println(b"SIGQUEUE_MQ_INFO:OK");
    } else {
        print(b"SIGQUEUE_MQ_INFO:FAIL fd=");
        print_num(fd as i64);
        print(b" notify=");
        print_num(n);
        print(b" send=");
        print_num(snd);
        print(b" r=");
        print_num(r);
        print(b" code=");
        print_num(info.si_code as i64);
        print(b" value=");
        print_num(info.si_status as i64);
        println(b"");
    }
}

/// A PTRACE_TRACEME child stops on its SIGSTOP: the tracer's SIGCHLD is
/// CLD_TRAPPED with the child's pid and SIGSTOP as status
fn test_trapped_info() {
    const PTRACE_TRACEME: i64 = 0;
    const SIGSTOP: u32 = 19;
    const SIGKILL: u32 = 9;
    const CLD_TRAPPED: i32 = 4;
    let old = block(bit(SIGCHLD));
    let child = sys_fork();
    if child == 0 {
        sys_ptrace(PTRACE_TRACEME, 0, 0, 0);
        sys_kill(sys_getpid(), SIGSTOP);
        sys_exit(0);
    }
    let mut info = zeroed();
    let r = wait_sig(bit(SIGCHLD), 10, &mut info);
    sys_kill(child, SIGKILL);
    let mut st = 0i32;
    sys_wait4(child, &mut st, 0, 0);
    // The kill's SIGCHLD, if any, is not this test's
    let mut rest = zeroed();
    wait_sig(bit(SIGCHLD), 0, &mut rest);
    setmask(old);
    if r == SIGCHLD as i64
        && info.si_code == CLD_TRAPPED
        && info.si_pid as i64 == child
        && info.si_status == SIGSTOP as i32
    {
        println(b"SIGQUEUE_TRAPPED_INFO:OK");
    } else {
        print(b"SIGQUEUE_TRAPPED_INFO:FAIL r=");
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

fn pending() -> u64 {
    let mut set = 0u64;
    sys_rt_sigpending(&mut set as *mut u64 as u64, 8);
    set
}

/// Two queued RT signals and a SIGCHLD, blocked: SIG_IGN on the RT one
/// and SIG_DFL on SIGCHLD discard both (SigQ drops by the two), the
/// blocked SIGUSR1 stays
fn test_ignore_flush() {
    const SIG_IGN: u64 = 1;
    let mask = bit(SIGRT) | bit(SIGUSR1) | bit(SIGCHLD);
    let old = block(mask);
    let (q0, _) = sigq();
    queue_self(SIGRT, 1);
    queue_self(SIGRT, 2);
    sys_kill(sys_getpid(), SIGUSR1);
    sys_kill(sys_getpid(), SIGCHLD);
    let before = pending() & mask;
    let ign: [u64; 4] = [SIG_IGN, 0, 0, 0];
    let dfl: [u64; 4] = [SIG_DFL, 0, 0, 0];
    sys_rt_sigaction(SIGRT, ign.as_ptr() as u64, 0, 8);
    sys_rt_sigaction(SIGRT, dfl.as_ptr() as u64, 0, 8);
    sys_rt_sigaction(SIGCHLD, dfl.as_ptr() as u64, 0, 8);
    let after = pending() & mask;
    let q = sigq().0 - q0;
    let usr1 = drain(SIGUSR1);
    setmask(old);
    if before == mask && after == bit(SIGUSR1) && q == 1 && usr1 == 1 {
        println(b"SIGQUEUE_IGN_FLUSH:OK");
    } else {
        print(b"SIGQUEUE_IGN_FLUSH:FAIL before=");
        print_num(before as i64);
        print(b" after=");
        print_num(after as i64);
        print(b" sigq=");
        print_num(q);
        println(b"");
    }
}

static GROUP_GOT: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(0);
static GROUP_UP: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(0);
static mut GROUP_CTID: u32 = 0;
#[repr(C, align(16))]
struct GroupStack([u8; 16384]);
static mut GROUP_STACK: GroupStack = GroupStack([0; 16384]);

extern "C" fn group_handler(_: i32) {
    GROUP_GOT.store(hk_syscall::sys_gettid(), core::sync::atomic::Ordering::Release);
}

/// The second thread: SIGUSR1 unblocked, it waits for a signal until
/// the handler ran
extern "C" fn group_waiter(_: u64) -> ! {
    use core::sync::atomic::Ordering;
    GROUP_UP.store(hk_syscall::sys_gettid(), Ordering::Release);
    let none = 0u64;
    while GROUP_GOT.load(Ordering::Acquire) == 0 {
        hk_syscall::sys_rt_sigsuspend(&none as *const u64 as u64, 8);
    }
    sys_exit(0)
}

/// In a child: the leader blocks SIGUSR1, a second thread does not;
/// kill() of the process runs the handler on that thread
fn test_group_thread() {
    use core::sync::atomic::Ordering;
    let child = sys_fork();
    if child == 0 {
        let act: [u64; 4] = [
            group_handler as *const () as u64,
            SA_RESTORER,
            super::signals::restorer_addr(),
            0,
        ];
        sys_rt_sigaction(SIGUSR1, act.as_ptr() as u64, 0, 8);
        // SAFETY: the thread's own stack and tid word, used by it alone
        let tid = unsafe {
            let top = (&raw mut GROUP_STACK as *mut u8).add(16384) as u64;
            let ctid = &raw mut GROUP_CTID;
            core::ptr::write_volatile(ctid, 1);
            super::fork_mm::spawn_thread(top, group_waiter, 0, ctid)
        };
        block(bit(SIGUSR1));
        while GROUP_UP.load(Ordering::Acquire) == 0 {
            hk_syscall::sys_sched_yield();
        }
        sys_kill(sys_getpid(), SIGUSR1);
        let t0 = super::sk::now_ms();
        while GROUP_GOT.load(Ordering::Acquire) == 0 {
            if super::sk::now_ms() - t0 > 5000 {
                hk_syscall::sys_exit_group(2);
            }
            hk_syscall::sys_sched_yield();
        }
        let ok = GROUP_GOT.load(Ordering::Acquire) == tid && super::fork_mm::join(&raw mut GROUP_CTID);
        hk_syscall::sys_exit_group(if ok { 0 } else { 1 });
    }
    let mut st = 0i32;
    sys_wait4(child, &mut st, 0, 0);
    if st == 0 {
        println(b"SIGQUEUE_GROUP_THREAD:OK");
    } else {
        print(b"SIGQUEUE_GROUP_THREAD:FAIL status=");
        print_num(st as i64);
        println(b"");
    }
}

fn ts(sec: i64, nsec: i64) -> hk_syscall::Timespec {
    hk_syscall::Timespec {
        tv_sec: sec,
        tv_nsec: nsec,
    }
}

fn sleep_ms(ms: i64) {
    let t = ts(ms / 1000, (ms % 1000) * 1_000_000);
    hk_syscall::sys_nanosleep(&t, core::ptr::null_mut());
}

/// timer_create on CLOCK_MONOTONIC signalling `sig` with `value` (as
/// `notify`, to thread `tid`): its id, or -errno
fn timer(sig: u32, value: i32, notify: i32, tid: i32) -> i32 {
    let sev = SigEvent {
        sigev_value: SigVal { sival_int: value },
        sigev_signo: sig as i32,
        sigev_notify: notify,
        sigev_notify_thread_id: tid,
        ..SigEvent::default()
    };
    let mut id = -1i32;
    let r = hk_syscall::sys_timer_create(1, &sev, &mut id);
    if r < 0 { r as i32 } else { id }
}

fn arm(id: i32, value_ms: i64, interval_ms: i64) {
    let spec = hk_syscall::ITimerSpec {
        it_interval: ts(0, interval_ms * 1_000_000),
        it_value: ts(0, value_ms * 1_000_000),
    };
    hk_syscall::sys_timer_settime(id, 0, &spec, core::ptr::null_mut());
}

/// si_tid (offset 16) and si_overrun (20) of a timer's siginfo
fn tid_overrun(i: &SigInfo) -> (i32, i32) {
    (i.si_pid, i.si_uid as i32)
}

/// A one-shot timer: SI_TIMER, its id, overrun 0, its value; a
/// SIGEV_THREAD_ID one reaches this thread the same way
fn test_timer_info() {
    const SI_TIMER: i32 = -2;
    let old = block(bit(SIGRT) | bit(SIGRT + 1));
    let a = timer(SIGRT, 4242, 0, 0);
    let me = hk_syscall::sys_gettid() as i32;
    let b = timer(SIGRT + 1, 77, 4, me); // SIGEV_THREAD_ID
    arm(a, 10, 0);
    arm(b, 10, 0);
    let mut ia = zeroed();
    let ra = wait_sig(bit(SIGRT), 2, &mut ia);
    let mut ib = zeroed();
    let rb = wait_sig(bit(SIGRT + 1), 2, &mut ib);
    hk_syscall::sys_timer_delete(a);
    hk_syscall::sys_timer_delete(b);
    setmask(old);
    let ok_a = ra == SIGRT as i64
        && ia.si_code == SI_TIMER
        && tid_overrun(&ia) == (a, 0)
        && ia.si_status == 4242;
    let ok_b = rb == (SIGRT + 1) as i64 && ib.si_code == SI_TIMER && ib.si_status == 77;
    if a >= 0 && b >= 0 && ok_a && ok_b {
        println(b"SIGQUEUE_TIMER_INFO:OK");
    } else {
        print(b"SIGQUEUE_TIMER_INFO:FAIL ids=");
        print_num(a as i64);
        print(b",");
        print_num(b as i64);
        print(b" r=");
        print_num(ra);
        print(b",");
        print_num(rb);
        print(b" code=");
        print_num(ia.si_code as i64);
        print(b" tid=");
        print_num(tid_overrun(&ia).0 as i64);
        print(b" value=");
        print_num(ia.si_status as i64);
        println(b"");
    }
}

/// A 10 ms interval timer left 105 ms with its signal blocked: one
/// signal, si_overrun the periods after the first (about 9),
/// timer_getoverrun the same; then nothing more is pending
fn test_timer_overrun() {
    let old = block(bit(SIGRT));
    let id = timer(SIGRT, 1, 0, 0);
    arm(id, 10, 10);
    sleep_ms(105);
    let mut i = zeroed();
    let r = wait_sig(bit(SIGRT), 1, &mut i);
    let over = tid_overrun(&i).1;
    let get = hk_syscall::sys_timer_getoverrun(id);
    let mut j = zeroed();
    let again = wait_sig(bit(SIGRT), 0, &mut j);
    hk_syscall::sys_timer_delete(id);
    let mut k = zeroed();
    wait_sig(bit(SIGRT), 0, &mut k);
    setmask(old);
    if r == SIGRT as i64 && (5..=20).contains(&over) && get == over as i64 && again == EAGAIN {
        println(b"SIGQUEUE_TIMER_OVERRUN:OK");
    } else {
        print(b"SIGQUEUE_TIMER_OVERRUN:FAIL r=");
        print_num(r);
        print(b" overrun=");
        print_num(over as i64);
        print(b" getoverrun=");
        print_num(get);
        print(b" again=");
        print_num(again);
        println(b"");
    }
}

/// A queued timer signal is dropped by timer_settime and timer_delete
/// (Linux 6.13 on: it_signal_seq; before, it was still delivered)
fn test_timer_drop() {
    if !super::helpers::linux_at_least(6, 13) {
        skip(b"SIGQUEUE_TIMER_DROP", b"host Linux before 6.13 delivers it");
        return;
    }
    let old = block(bit(SIGRT));
    let a = timer(SIGRT, 1, 0, 0);
    arm(a, 1, 0);
    sleep_ms(20);
    arm(a, 0, 0); // disarm: the queued signal goes
    let mut i = zeroed();
    let ra = wait_sig(bit(SIGRT), 0, &mut i);
    arm(a, 1, 0);
    sleep_ms(20);
    hk_syscall::sys_timer_delete(a);
    let rb = wait_sig(bit(SIGRT), 0, &mut i);
    setmask(old);
    if ra == EAGAIN && rb == EAGAIN {
        println(b"SIGQUEUE_TIMER_DROP:OK");
    } else {
        print(b"SIGQUEUE_TIMER_DROP:FAIL settime=");
        print_num(ra);
        print(b" delete=");
        print_num(rb);
        println(b"");
    }
}

/// ITIMER_REAL every 10 ms: SIGALRM is SI_KERNEL; taking it rearms the
/// timer, so a second one comes
fn test_itimer_real() {
    const SIGALRM: u32 = 14;
    const SI_KERNEL: i32 = 0x80;
    let old = block(bit(SIGALRM));
    let tv = |us| hk_syscall::Timeval {
        tv_sec: 0,
        tv_usec: us,
    };
    let it = hk_syscall::ITimerVal {
        it_interval: tv(10_000),
        it_value: tv(10_000),
    };
    hk_syscall::sys_setitimer(0, &it, core::ptr::null_mut());
    let mut a = zeroed();
    let ra = wait_sig(bit(SIGALRM), 2, &mut a);
    let mut b = zeroed();
    let rb = wait_sig(bit(SIGALRM), 2, &mut b);
    let off = hk_syscall::ITimerVal {
        it_interval: tv(0),
        it_value: tv(0),
    };
    hk_syscall::sys_setitimer(0, &off, core::ptr::null_mut());
    let mut c = zeroed();
    wait_sig(bit(SIGALRM), 0, &mut c);
    setmask(old);
    if ra == SIGALRM as i64 && a.si_code == SI_KERNEL && rb == SIGALRM as i64 {
        println(b"SIGQUEUE_ITIMER_REAL:OK");
    } else {
        print(b"SIGQUEUE_ITIMER_REAL:FAIL r=");
        print_num(ra);
        print(b",");
        print_num(rb);
        print(b" code=");
        print_num(a.si_code as i64);
        println(b"");
    }
}

/// Fork a child that exits 3 at once; the wait4 result for it
fn child_exits_wait() -> (i64, i64) {
    let c = sys_fork();
    if c == 0 {
        sys_exit(3);
    }
    let mut st = 0i32;
    (c, sys_wait4(c, &mut st, 0, 0))
}

/// SIGCHLD ignored: the child is gone without a zombie (ECHILD); with
/// SA_NOCLDWAIT and a handler, SIGCHLD (CLD_EXITED) still comes and the
/// child is reaped too
fn test_autoreap() {
    const SIG_IGN: u64 = 1;
    const SA_NOCLDWAIT: u64 = 2;
    const ECHILD: i64 = -10;
    let ign: [u64; 4] = [SIG_IGN, 0, 0, 0];
    let dfl: [u64; 4] = [SIG_DFL, 0, 0, 0];
    sys_rt_sigaction(SIGCHLD, ign.as_ptr() as u64, 0, 8);
    let (_, w1) = child_exits_wait();
    let old = block(bit(SIGCHLD));
    let nowait: [u64; 4] = [
        group_handler as *const () as u64,
        SA_RESTORER | SA_NOCLDWAIT,
        super::signals::restorer_addr(),
        0,
    ];
    sys_rt_sigaction(SIGCHLD, nowait.as_ptr() as u64, 0, 8);
    let (c2, w2) = child_exits_wait();
    let mut info = zeroed();
    let r = wait_sig(bit(SIGCHLD), 2, &mut info);
    sys_rt_sigaction(SIGCHLD, dfl.as_ptr() as u64, 0, 8);
    setmask(old);
    if w1 == ECHILD
        && w2 == ECHILD
        && r == SIGCHLD as i64
        && info.si_code == CLD_EXITED
        && info.si_pid as i64 == c2
        && info.si_status == 3
    {
        println(b"SIGQUEUE_AUTOREAP:OK");
    } else {
        print(b"SIGQUEUE_AUTOREAP:FAIL ign=");
        print_num(w1);
        print(b" nocldwait=");
        print_num(w2);
        print(b" sig=");
        print_num(r);
        print(b" code=");
        print_num(info.si_code as i64);
        println(b"");
    }
}

/// A grandchild with PR_SET_PDEATHSIG SIGUSR1 gets it, from its parent's
/// pid, when that parent exits; it is then this (init) process's child
fn test_pdeath() {
    const PR_SET_PDEATHSIG: i32 = 1;
    let mut fds = [0i32; 2];
    hk_syscall::sys_pipe(fds.as_mut_ptr());
    let old = block(bit(SIGUSR1));
    let a = sys_fork();
    if a == 0 {
        let b = sys_fork();
        if b == 0 {
            hk_syscall::sys_prctl(PR_SET_PDEATHSIG, SIGUSR1 as u64, 0, 0, 0);
            let pid = (sys_getpid() as u32).to_ne_bytes();
            hk_syscall::sys_write(fds[1] as u64, pid.as_ptr(), 4);
            let mut info = zeroed();
            let r = wait_sig(bit(SIGUSR1), 10, &mut info);
            let parent = hk_syscall::sys_getppid();
            let ok = r == SIGUSR1 as i64 && info.si_code == SI_USER && parent == 1;
            sys_exit(if ok { 0 } else { 1 });
        }
        // Exit once the grandchild has set its pdeath signal
        let mut buf = [0u8; 4];
        hk_syscall::sys_read(fds[0] as u64, buf.as_mut_ptr(), 4);
        hk_syscall::sys_write(fds[1] as u64, buf.as_ptr(), 4);
        sys_exit(0);
    }
    let mut st = 0i32;
    sys_wait4(a, &mut st, 0, 0);
    let mut buf = [0u8; 4];
    hk_syscall::sys_read(fds[0] as u64, buf.as_mut_ptr(), 4);
    let b = i64::from(u32::from_ne_bytes(buf));
    let mut sb = -1i32;
    let w = sys_wait4(b, &mut sb, 0, 0);
    sys_close(fds[0] as u64);
    sys_close(fds[1] as u64);
    setmask(old);
    if w == b && sb == 0 {
        println(b"SIGQUEUE_PDEATH:OK");
    } else {
        print(b"SIGQUEUE_PDEATH:FAIL wait=");
        print_num(w);
        print(b" status=");
        print_num(sb as i64);
        println(b"");
    }
}

#[cfg(target_arch = "aarch64")]
static NR_HIT: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(0);

#[cfg(target_arch = "aarch64")]
extern "C" fn nr_handler(_: i32) {
    use core::sync::atomic::Ordering;
    // load+store: RMW atomics on aarch64 need libc's getauxval
    NR_HIT.store(NR_HIT.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
}

/// In a child: SIGUSR1 with a handler set without SA_RESTORER runs it
/// and returns to the code it interrupted
#[cfg(target_arch = "aarch64")]
fn test_no_restorer() {
    use core::sync::atomic::Ordering;
    let c = sys_fork();
    if c == 0 {
        let act: [u64; 4] = [nr_handler as *const () as u64, 0, 0, 0];
        sys_rt_sigaction(SIGUSR1, act.as_ptr() as u64, 0, 8);
        sys_kill(sys_getpid(), SIGUSR1);
        sys_kill(sys_getpid(), SIGUSR1);
        // The trampoline's mapping: hk's [sigpage], Linux's [vdso]
        let mut buf = [0u8; 4096];
        let n = read_file(b"/proc/self/maps\0", &mut buf).max(0) as usize;
        let name: &[u8] = if super::helpers::host_mode() {
            b"[vdso]"
        } else {
            b"[sigpage]"
        };
        let shown = buf[..n].windows(name.len()).any(|w| w == name);
        let ok = NR_HIT.load(Ordering::Relaxed) == 2 && shown;
        sys_exit(if ok { 0 } else { 1 });
    }
    let mut st = 0i32;
    sys_wait4(c, &mut st, 0, 0);
    if st == 0 {
        println(b"SIGQUEUE_NO_RESTORER:OK");
    } else {
        print(b"SIGQUEUE_NO_RESTORER:FAIL status=");
        print_num(st as i64);
        println(b"");
    }
}

static mut GONE_CTID: u32 = 0;
static mut GONE_STACK: GroupStack = GroupStack([0; 16384]);

extern "C" fn gone_thread(_: u64) -> ! {
    sys_exit(0)
}

/// In a child: a timer for a thread that then exits fires into
/// nothing: no signal pending for the process or the caller
fn test_timer_gone() {
    let c = sys_fork();
    if c == 0 {
        let old = block(bit(SIGRT));
        // SAFETY: the thread's own stack and tid word
        let tid = unsafe {
            let top = (&raw mut GONE_STACK as *mut u8).add(16384) as u64;
            let ctid = &raw mut GONE_CTID;
            core::ptr::write_volatile(ctid, 1);
            super::fork_mm::spawn_thread(top, gone_thread, 0, ctid)
        };
        let id = timer(SIGRT, 5, 4, tid as i32);
        let joined = super::fork_mm::join(&raw mut GONE_CTID);
        arm(id, 5, 0);
        sleep_ms(50);
        let mut info = zeroed();
        let r = wait_sig(bit(SIGRT), 0, &mut info);
        let p = pending() & bit(SIGRT);
        setmask(old);
        let ok = id >= 0 && joined && r == EAGAIN && p == 0;
        hk_syscall::sys_exit_group(if ok { 0 } else { 1 });
    }
    let mut st = 0i32;
    sys_wait4(c, &mut st, 0, 0);
    if st == 0 {
        println(b"SIGQUEUE_TIMER_GONE:OK");
    } else {
        print(b"SIGQUEUE_TIMER_GONE:FAIL status=");
        print_num(st as i64);
        println(b"");
    }
}

/// clone(SIGUSR1): a child whose exit signal is SIGUSR1; it exits after
/// `ms`
fn usr1_child(ms: i64) -> i64 {
    let c = hk_syscall::sys_clone(SIGUSR1 as u64, 0, 0, 0, 0);
    if c == 0 {
        sleep_ms(ms);
        sys_exit(0);
    }
    c
}

/// In a child: make a SIGUSR1-exit child, then exec boot_tester2, which
/// waits for the signal it sends: SIGCHLD, not SIGUSR1
fn test_exit_signal_exec() {
    let p = sys_fork();
    if p == 0 {
        block(bit(SIGCHLD) | bit(SIGUSR1));
        usr1_child(300);
        let argv: [*const u8; 3] = [
            b"boot_tester2\0".as_ptr(),
            b"chldsig\0".as_ptr(),
            core::ptr::null(),
        ];
        let envp: [*const u8; 1] = [core::ptr::null()];
        hk_syscall::sys_execve(b"/bin/boot_tester2\0".as_ptr(), argv.as_ptr(), envp.as_ptr());
        sys_exit(99);
    }
    let mut st = 0i32;
    sys_wait4(p, &mut st, 0, 0);
    let got = (st >> 8) & 0xff;
    if st & 0x7f == 0 && got == SIGCHLD as i32 {
        println(b"SIGQUEUE_EXIT_SIGNAL_EXEC:OK");
    } else {
        print(b"SIGQUEUE_EXIT_SIGNAL_EXEC:FAIL status=");
        print_num(st as i64);
        println(b"");
    }
}

/// A SIGUSR1-exit child whose parent exits is this (init) process's
/// now: its exit sends SIGCHLD, not SIGUSR1
fn test_exit_signal_reparent() {
    let old = block(bit(SIGCHLD) | bit(SIGUSR1));
    let mut fds = [0i32; 2];
    hk_syscall::sys_pipe(fds.as_mut_ptr());
    let p = sys_fork();
    if p == 0 {
        let c = usr1_child(300);
        let b = (c as u32).to_ne_bytes();
        hk_syscall::sys_write(fds[1] as u64, b.as_ptr(), 4);
        sys_exit(0);
    }
    let mut st = 0i32;
    sys_wait4(p, &mut st, 0, 0);
    let mut buf = [0u8; 4];
    hk_syscall::sys_read(fds[0] as u64, buf.as_mut_ptr(), 4);
    let c = i64::from(u32::from_ne_bytes(buf));
    // SIGCHLDs of others may come first: wait for the child's
    let mut got = 0i64;
    for _ in 0..20 {
        let mut info = zeroed();
        let r = wait_sig(bit(SIGCHLD) | bit(SIGUSR1), 2, &mut info);
        if r < 0 || info.si_pid as i64 == c {
            got = r;
            break;
        }
    }
    let mut sc = 0i32;
    sys_wait4(c, &mut sc, 0x4000_0000, 0);
    let mut rest = zeroed();
    while wait_sig(bit(SIGCHLD) | bit(SIGUSR1), 0, &mut rest) > 0 {}
    sys_close(fds[0] as u64);
    sys_close(fds[1] as u64);
    setmask(old);
    if got == SIGCHLD as i64 {
        println(b"SIGQUEUE_EXIT_SIGNAL_REPARENT:OK");
    } else {
        print(b"SIGQUEUE_EXIT_SIGNAL_REPARENT:FAIL sig=");
        print_num(got);
        println(b"");
    }
}

static PT_SEEN: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(0);

extern "C" fn pt_handler(_: i32, info: *const SigInfo, _: *const u8) {
    // SAFETY: the kernel's siginfo for this handler
    let v = unsafe { (*info).si_status };
    PT_SEEN.store(i64::from(v), core::sync::atomic::Ordering::Relaxed);
}

/// A traced child queues two SIGRT (blocked, the group's) and SIGUSR1
/// with value 55: at its signal-delivery stop the tracer reads SIGUSR1's
/// info, peeks the two SIGRT, sets the value to 99 and resumes with
/// SIGUSR1; the child's handler sees 99
fn test_ptrace_siginfo() {
    use core::sync::atomic::Ordering;
    const PTRACE_TRACEME: i64 = 0;
    const PTRACE_CONT: i64 = 7;
    const PTRACE_GETSIGINFO: i64 = 0x4202;
    const PTRACE_SETSIGINFO: i64 = 0x4203;
    const PTRACE_PEEKSIGINFO: i64 = 0x4209;
    let c = sys_fork();
    if c == 0 {
        let act: [u64; 4] = [
            pt_handler as *const () as u64,
            SA_SIGINFO | SA_RESTORER,
            super::signals::restorer_addr(),
            0,
        ];
        sys_rt_sigaction(SIGUSR1, act.as_ptr() as u64, 0, 8);
        block(bit(SIGRT));
        sys_ptrace(PTRACE_TRACEME, 0, 0, 0);
        queue_self(SIGRT, 1);
        queue_self(SIGRT, 2);
        queue_self(SIGUSR1, 55);
        sys_exit(if PT_SEEN.load(Ordering::Relaxed) == 99 { 0 } else { 1 });
    }
    let mut st = 0i32;
    sys_wait4(c, &mut st, 0, 0);
    let stopped = st & 0xff == 0x7f && (st >> 8) & 0xff == SIGUSR1 as i32;
    let mut info = zeroed();
    let g = sys_ptrace(PTRACE_GETSIGINFO, c, 0, &mut info as *mut SigInfo as u64);
    let got = g == 0 && info.si_signo == SIGUSR1 as i32 && info.si_code == SI_QUEUE && info.si_status == 55;
    // struct ptrace_peeksiginfo_args: off 0, flags SHARED, nr 4
    let args: [u32; 4] = [0, 0, 1, 4];
    let mut peek = [zeroed(), zeroed(), zeroed(), zeroed()];
    let n = sys_ptrace(PTRACE_PEEKSIGINFO, c, args.as_ptr() as u64, peek.as_mut_ptr() as u64);
    let peeked = n == 2 && peek[0].si_status == 1 && peek[1].si_status == 2;
    info.si_status = 99;
    let s = sys_ptrace(PTRACE_SETSIGINFO, c, 0, &info as *const SigInfo as u64);
    sys_ptrace(PTRACE_CONT, c, 0, SIGUSR1 as u64);
    let mut st2 = 0i32;
    sys_wait4(c, &mut st2, 0, 0);
    if stopped && got && peeked && s == 0 && st2 == 0 {
        println(b"SIGQUEUE_PTRACE_SIGINFO:OK");
    } else {
        print(b"SIGQUEUE_PTRACE_SIGINFO:FAIL stop=");
        print_num(st as i64);
        print(b" get=");
        print_num(g);
        print(b",");
        print_num(info.si_code as i64);
        print(b" peek=");
        print_num(n);
        print(b" set=");
        print_num(s);
        print(b" exit=");
        print_num(st2 as i64);
        println(b"");
    }
}
