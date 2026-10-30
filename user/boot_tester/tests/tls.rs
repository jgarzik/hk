//! User TLS base range checks: x86-64 refuses an FS (or GS) base at or
//! above TASK_SIZE_MAX (Linux do_arch_prctl_64: EPERM, also for
//! CLONE_SETTLS through set_new_tls; ptrace putreg: EIO); arm64 takes
//! any TPIDR_EL0 value.

use super::helpers::{print, print_num, println};
#[cfg(target_arch = "x86_64")]
use super::helpers::host_mode;
use hk_syscall::{sys_clone, sys_exit, sys_wait4};

const SIGCHLD: u64 = 17;
const CLONE_SETTLS: u64 = 0x0008_0000;
/// Non-canonical, a kernel address, and TASK_SIZE_MAX itself (hk's,
/// 4-level paging; Linux with LA57 takes it)
#[cfg(target_arch = "x86_64")]
const BAD: [u64; 3] = [0x8000_0000_0000_0000, 0xffff_8000_0000_0000, 0x7fff_ffff_f000];

/// The bad bases this kernel must refuse
#[cfg(target_arch = "x86_64")]
fn bad_bases() -> &'static [u64] {
    if host_mode() { &BAD[..2] } else { &BAD }
}

pub fn run_tests() {
    #[cfg(target_arch = "x86_64")]
    {
        test_set_fs();
        test_ptrace_regs();
    }
    test_clone_settls();
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

/// ARCH_SET_FS of a bad base: EPERM, the old base kept
#[cfg(target_arch = "x86_64")]
fn test_set_fs() {
    use hk_syscall::{ARCH_GET_FS, ARCH_SET_FS, sys_arch_prctl};
    let mut old = 0u64;
    sys_arch_prctl(ARCH_GET_FS, &raw mut old as u64);
    let mut bad = 0;
    for &v in bad_bases() {
        let r = sys_arch_prctl(ARCH_SET_FS, v);
        if r != -1 {
            print_num(r);
            bad += 1;
        }
    }
    let mut now = 0u64;
    sys_arch_prctl(ARCH_GET_FS, &raw mut now as u64);
    report(b"TLS_SET_FS_RANGE", bad == 0 && now == old, bad);
}

/// SETREGS with a bad fs_base or gs_base: EIO; a valid one is taken
#[cfg(target_arch = "x86_64")]
fn test_ptrace_regs() {
    use hk_syscall::{sys_fork, sys_getpid, sys_kill, sys_ptrace};
    const TRACEME: i64 = 0;
    const GETREGS: i64 = 12;
    const SETREGS: i64 = 13;
    const FS_BASE: usize = 21;
    const GS_BASE: usize = 22;
    let pid = sys_fork();
    if pid == 0 {
        sys_ptrace(TRACEME, 0, 0, 0);
        sys_kill(sys_getpid(), 19); // SIGSTOP
        sys_exit(0);
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    let mut regs = [0u64; 27];
    let mut r = sys_ptrace(GETREGS, pid, 0, regs.as_mut_ptr() as u64);
    let mut bad = (r != 0) as i64;
    let good = regs;
    for idx in [FS_BASE, GS_BASE] {
        for &v in bad_bases() {
            regs = good;
            regs[idx] = v;
            r = sys_ptrace(SETREGS, pid, 0, regs.as_ptr() as u64);
            if r != -5 {
                bad += 1;
            }
        }
    }
    regs = good;
    regs[FS_BASE] = 0x1000;
    if sys_ptrace(SETREGS, pid, 0, regs.as_ptr() as u64) != 0 {
        bad += 100;
    }
    regs = [0; 27];
    sys_ptrace(GETREGS, pid, 0, regs.as_mut_ptr() as u64);
    if regs[FS_BASE] != 0x1000 {
        bad += 1000;
    }
    sys_kill(pid, 9);
    sys_wait4(pid, &mut st, 0, 0);
    report(b"TLS_PTRACE_RANGE", bad == 0 && st & 0x7f == 9, bad);
}

/// CLONE_SETTLS of a bad base: EPERM (x86-64); arm64 takes any value
fn test_clone_settls() {
    #[cfg(target_arch = "x86_64")]
    {
        let mut bad = 0;
        for &v in bad_bases() {
            let pid = sys_clone(SIGCHLD | CLONE_SETTLS, 0, 0, 0, v);
            if pid == 0 {
                sys_exit(1);
            }
            if pid > 0 {
                let mut st = 0i32;
                sys_wait4(pid, &mut st, 0, 0);
            }
            if pid != -1 {
                bad += 1;
            }
        }
        report(b"TLS_CLONE_RANGE", bad == 0, bad);
    }
    #[cfg(target_arch = "aarch64")]
    {
        const V: u64 = 0x8000_0000_0000_0000;
        let pid = sys_clone(SIGCHLD | CLONE_SETTLS, 0, 0, 0, V);
        if pid == 0 {
            let t: u64;
            unsafe { core::arch::asm!("mrs {}, tpidr_el0", out(reg) t) };
            sys_exit((t != V) as u64);
        }
        let mut st = 0i32;
        sys_wait4(pid, &mut st, 0, 0);
        report(b"TLS_CLONE_RANGE", pid > 0 && st == 0, st as i64);
    }
}
