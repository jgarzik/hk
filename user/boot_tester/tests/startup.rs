//! Process startup ABI a static glibc program relies on: the initial
//! stack and auxiliary vector, /proc/self/exe, the TLS register across
//! fork, newfstatat and interval timers.

use super::helpers::{print, print_num, println};
use hk_syscall::{
    sys_execve, sys_exit, sys_fork, sys_fstatat, sys_getitimer, sys_rt_sigprocmask,
    sys_rt_sigtimedwait, sys_setitimer, sys_wait4, ITimerVal, Stat, Timespec, Timeval,
    ITIMER_REAL,
};

const AT_FDCWD: i32 = -100;
const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
const SIGALRM: u64 = 14;
const SIG_BLOCK: i32 = 0;
const SIG_UNBLOCK: i32 = 1;

pub fn run_tests() {
    test_exec_mode(b"EXEC_AUXV", b"auxv\0");
    test_exec_mode(b"PROC_SELF_EXE", b"exe\0");
    test_fork_tls();
    test_tls_switch();
    test_newfstatat();
    test_itimer_real();
    #[cfg(target_arch = "x86_64")]
    test_alarm();
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

/// Exit status of a child running `f`
fn in_child(f: fn() -> !) -> i32 {
    let pid = sys_fork();
    if pid == 0 {
        f();
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    st
}

/// `/bin/boot_tester2 <mode>` exits 0 when its checks pass
fn test_exec_mode(name: &[u8], mode: &'static [u8]) {
    static mut MODE: &[u8] = b"";
    unsafe { MODE = mode };
    let st = in_child(|| {
        let argv: [*const u8; 3] = [
            b"boot_tester2\0".as_ptr(),
            unsafe { MODE }.as_ptr(),
            core::ptr::null(),
        ];
        let envp: [*const u8; 2] = [b"HK=1\0".as_ptr(), core::ptr::null()];
        sys_execve(b"/bin/boot_tester2\0".as_ptr(), argv.as_ptr(), envp.as_ptr());
        sys_exit(99);
    });
    report(name, st == 0, (st >> 8) as i64);
}

/// The value the TLS register is set to before forking
const TLS_MAGIC: u64 = 0x5eed_7150_c0de_0001;

static mut TLS_BLOCK: [u64; 2] = [TLS_MAGIC, 0];

/// Set the TLS register (FS base / TPIDR_EL0) to `v`
fn set_tls(v: u64) {
    #[cfg(target_arch = "x86_64")]
    hk_syscall::sys_arch_prctl(hk_syscall::ARCH_SET_FS, v);
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("msr tpidr_el0, {}", in(reg) v)
    };
}

/// The TLS register as user code sees it
fn tls_ok() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        let v: u64;
        unsafe { core::arch::asm!("mov {}, fs:[0]", out(reg) v) };
        v == TLS_MAGIC
    }
    #[cfg(target_arch = "aarch64")]
    {
        let v: u64;
        unsafe { core::arch::asm!("mrs {}, tpidr_el0", out(reg) v) };
        v == &raw const TLS_BLOCK as u64
    }
}

/// A forked child keeps its parent's TLS register (Linux copy_thread)
fn test_fork_tls() {
    let st = in_child(|| {
        set_tls(&raw const TLS_BLOCK as u64);
        let pid = sys_fork();
        if pid == 0 {
            sys_exit(if tls_ok() { 0 } else { 1 });
        }
        let mut st = 0i32;
        sys_wait4(pid, &mut st, 0, 0);
        sys_exit(if st == 0 { 0 } else { 2 });
    });
    report(b"FORK_INHERITS_TLS", st == 0, (st >> 8) as i64);
}

static mut TLS_B: [u64; 2] = [TLS_MAGIC ^ 1, 0];

/// TLS register value as seen by user code (fs:[0] on x86, the register
/// itself on arm64): what each task must keep across context switches
fn tls_word() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let v: u64;
        unsafe { core::arch::asm!("mov {}, fs:[0]", out(reg) v) };
        v
    }
    #[cfg(target_arch = "aarch64")]
    {
        let v: u64;
        unsafe { core::arch::asm!("mrs {}, tpidr_el0", out(reg) v) };
        v
    }
}

/// Two processes with different TLS registers switching back and forth
/// each keep their own (the switch saves the outgoing task's register)
fn test_tls_switch() {
    fn run(block: u64) -> ! {
        set_tls(block);
        let want = tls_word();
        let ts = Timespec { tv_sec: 0, tv_nsec: 2_000_000 };
        for _ in 0..30 {
            hk_syscall::sys_nanosleep(&ts, core::ptr::null_mut());
            if tls_word() != want {
                sys_exit(1);
            }
        }
        sys_exit(0);
    }
    let a = sys_fork();
    if a == 0 {
        run(&raw const TLS_BLOCK as u64);
    }
    let b = sys_fork();
    if b == 0 {
        run(&raw const TLS_B as u64);
    }
    let (mut sa, mut sb) = (0i32, 0i32);
    sys_wait4(a, &mut sa, 0, 0);
    sys_wait4(b, &mut sb, 0, 0);
    report(b"TLS_SURVIVES_SWITCH", sa == 0 && sb == 0, (sa | sb) as i64);
}

/// newfstatat (fstatat on arm64) on a directory and a missing path
fn test_newfstatat() {
    let mut st: Stat = unsafe { core::mem::zeroed() };
    let r = sys_fstatat(AT_FDCWD, b"/\0".as_ptr(), &mut st, 0);
    let dir = r == 0 && st.st_mode & 0o170000 == 0o040000;
    let r2 = sys_fstatat(AT_FDCWD, b"/\0".as_ptr(), &mut st, AT_SYMLINK_NOFOLLOW);
    let r3 = sys_fstatat(AT_FDCWD, b"/no/such/file\0".as_ptr(), &mut st, 0);
    report(b"NEWFSTATAT", dir && r2 == 0 && r3 == -2, r3);
}

/// Block SIGALRM, then wait up to 2s for it; true if it arrived
fn alrm_arrives() -> bool {
    let set: u64 = 1 << (SIGALRM - 1);
    let ts = Timespec { tv_sec: 2, tv_nsec: 0 };
    sys_rt_sigtimedwait(&set as *const u64 as u64, 0, &ts as *const Timespec as u64, 8)
        == SIGALRM as i64
}

fn block_alrm(how: i32) {
    let set: u64 = 1 << (SIGALRM - 1);
    sys_rt_sigprocmask(how, &set as *const u64 as u64, 0, 8);
}

/// setitimer(ITIMER_REAL) fires SIGALRM once; getitimer reports the
/// time left; disarming reads back as zero
fn test_itimer_real() {
    block_alrm(SIG_BLOCK);
    let tv = |s, us| Timeval { tv_sec: s, tv_usec: us };
    let it = ITimerVal { it_interval: tv(0, 0), it_value: tv(0, 200_000) };
    let r = sys_setitimer(ITIMER_REAL, &it, core::ptr::null_mut());
    let mut cur = ITimerVal::default();
    sys_getitimer(ITIMER_REAL, &mut cur);
    let left = cur.it_value.tv_sec * 1_000_000 + cur.it_value.tv_usec;
    let fired = alrm_arrives();
    let mut after = ITimerVal::default();
    sys_getitimer(ITIMER_REAL, &mut after);
    let idle = after.it_value.tv_sec == 0 && after.it_value.tv_usec == 0;
    let bad = sys_setitimer(7, &it, core::ptr::null_mut());
    block_alrm(SIG_UNBLOCK);
    let ok = r == 0 && left > 0 && left <= 200_000 && fired && idle && bad == -22;
    report(b"ITIMER_REAL", ok, left);
}

/// alarm returns the seconds left on the previous alarm and fires
/// SIGALRM (x86-64 only; arm64 has no alarm syscall)
#[cfg(target_arch = "x86_64")]
fn test_alarm() {
    use hk_syscall::sys_alarm;
    block_alrm(SIG_BLOCK);
    let a = sys_alarm(5);
    let b = sys_alarm(1);
    let fired = alrm_arrives();
    let c = sys_alarm(0);
    block_alrm(SIG_UNBLOCK);
    let ok = a == 0 && b == 5 && fired && c == 0;
    report(b"ALARM", ok, b);
}
