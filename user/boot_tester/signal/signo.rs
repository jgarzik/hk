//! Where a bad signal number is caught (run on hk and real Linux)
//!
//! Linux judges a kill-family signal number in check_kill_permission,
//! after the receiver is found: no receiver is ESRCH whatever the
//! number, and signal 0 is a probe for every one of them.
//!
//! - SIGNO_KILL: kill and tgkill/tkill of no task with signal 99 are
//!   ESRCH; to the caller EINVAL
//! - SIGNO_SIGQUEUE: rt_sigqueueinfo and rt_tgsigqueueinfo read the
//!   info first (EFAULT), then find the receiver (ESRCH), then check
//!   the number (EINVAL); signal 0 probes
//! - SIGNO_SIGACTION: rt_sigaction reads the new action (EFAULT) before
//!   it checks the number (EINVAL)
//! - SIGNO_PIDFD: pidfd_send_signal finds the pidfd (EBADF) before it
//!   checks the number (EINVAL); signal 0 probes
//! - SIGNO_PDEATHSIG: PR_SET_PDEATHSIG takes 0..=_NSIG of the whole
//!   unsigned long (EINVAL past it); PR_GET_PDEATHSIG reads it back, 0
//!   once cleared

use crate::harness::T;
use hk_syscall::{
    sys_close, sys_getpid, sys_gettid, sys_getuid, sys_kill, sys_pidfd_open, sys_pidfd_send_signal,
    sys_rt_sigaction, sys_rt_sigqueueinfo, sys_rt_tgsigqueueinfo, sys_tgkill, sys_tkill,
};

const ESRCH: i64 = -3;
const EBADF: i64 = -9;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
/// No signal has this number
const BAD: u32 = 99;
/// No task has this number
const NOBODY: i64 = 99999;
/// An address no process maps
const UNMAPPED: u64 = 8;

pub fn run_tests() {
    test_kill();
    test_sigqueue();
    test_sigaction();
    test_pidfd();
    test_pdeathsig();
}

fn test_kill() {
    let mut t = T::new(b"SIGNO_KILL");
    let me = sys_getpid();
    t.eq(b"kill nobody", sys_kill(NOBODY, BAD), ESRCH);
    t.eq(b"kill no group", sys_kill(-NOBODY, BAD), ESRCH);
    t.eq(b"kill self", sys_kill(me, BAD), EINVAL);
    t.eq(b"kill self -1", sys_kill(me, u32::MAX), EINVAL);
    t.eq(b"tgkill nobody", sys_tgkill(me, NOBODY, BAD), ESRCH);
    t.eq(b"tkill nobody", sys_tkill(NOBODY, BAD), ESRCH);
    t.eq(b"tgkill self", sys_tgkill(me, sys_gettid(), BAD), EINVAL);
    t.done();
}

/// A user's SI_QUEUE siginfo for `sig` from the caller
fn queue_info(sig: u32) -> [i32; 32] {
    const SI_QUEUE: i32 = -1;
    let mut i = [0i32; 32];
    i[0] = sig as i32;
    i[2] = SI_QUEUE;
    i[4] = sys_getpid() as i32;
    i[5] = sys_getuid() as i32;
    i
}

fn test_sigqueue() {
    let mut t = T::new(b"SIGNO_SIGQUEUE");
    let (me, tid) = (sys_getpid(), sys_gettid());
    let probe = queue_info(0);
    let bad = queue_info(BAD);
    let at = |i: &[i32; 32]| i.as_ptr() as u64;
    t.eq(b"probe", sys_rt_sigqueueinfo(me, 0, at(&probe)), 0);
    t.eq(b"nobody", sys_rt_sigqueueinfo(NOBODY, BAD, at(&bad)), ESRCH);
    t.eq(b"efault", sys_rt_sigqueueinfo(me, BAD, UNMAPPED), EFAULT);
    t.eq(b"einval", sys_rt_sigqueueinfo(me, BAD, at(&bad)), EINVAL);
    let tg = |tgid, tid, sig, info| sys_rt_tgsigqueueinfo(tgid, tid, sig, info);
    t.eq(b"tg probe", tg(me, tid, 0, at(&probe)), 0);
    t.eq(b"tg nobody", tg(me, NOBODY, BAD, at(&bad)), ESRCH);
    t.eq(b"tg efault first", tg(0, 0, BAD, UNMAPPED), EFAULT);
    t.eq(b"tg einval", tg(me, tid, BAD, at(&bad)), EINVAL);
    t.done();
}

fn test_sigaction() {
    let mut t = T::new(b"SIGNO_SIGACTION");
    t.eq(b"efault", sys_rt_sigaction(BAD, UNMAPPED, 0, 8), EFAULT);
    t.eq(b"einval", sys_rt_sigaction(BAD, 0, 0, 8), EINVAL);
    t.eq(b"zero", sys_rt_sigaction(0, 0, 0, 8), EINVAL);
    t.done();
}

fn test_pidfd() {
    let mut t = T::new(b"SIGNO_PIDFD");
    let none = core::ptr::null();
    t.eq(b"ebadf", sys_pidfd_send_signal(9999, 99, none, 0), EBADF);
    let fd = sys_pidfd_open(sys_getpid() as i32, 0);
    if t.ok(b"pidfd_open", fd >= 0, fd) {
        let fd32 = fd as i32;
        t.eq(b"einval", sys_pidfd_send_signal(fd32, 99, none, 0), EINVAL);
        t.eq(
            b"negative",
            sys_pidfd_send_signal(fd32, -1, none, 0),
            EINVAL,
        );
        t.eq(b"probe", sys_pidfd_send_signal(fd32, 0, none, 0), 0);
        sys_close(fd as u64);
    }
    t.done();
}

fn test_pdeathsig() {
    use hk_syscall::sys_prctl;
    const PR_SET_PDEATHSIG: i32 = 1;
    const PR_GET_PDEATHSIG: i32 = 2;
    let mut t = T::new(b"SIGNO_PDEATHSIG");
    let get = || {
        let mut v = -1i32;
        let r = sys_prctl(PR_GET_PDEATHSIG, &mut v as *mut i32 as u64, 0, 0, 0);
        if r == 0 { i64::from(v) } else { r }
    };
    t.eq(
        b"high bits",
        sys_prctl(PR_SET_PDEATHSIG, 1 << 32 | 1, 0, 0, 0),
        EINVAL,
    );
    t.eq(b"65", sys_prctl(PR_SET_PDEATHSIG, 65, 0, 0, 0), EINVAL);
    t.eq(b"unchanged", get(), 0);
    t.eq(b"set 64", sys_prctl(PR_SET_PDEATHSIG, 64, 0, 0, 0), 0);
    t.eq(b"get 64", get(), 64);
    t.eq(b"clear", sys_prctl(PR_SET_PDEATHSIG, 0, 0, 0, 0), 0);
    t.eq(b"get 0", get(), 0);
    t.done();
}
