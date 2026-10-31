//! A task running only user code (no syscalls, no faults) is still
//! preempted and still takes signals: the timer tick (or a kick IPI)
//! interrupts it and the interrupt's return to user mode does the work
//! (Linux exit_to_user_mode_loop).
//!
//! Tests:
//! - SIGKILL_SPIN: a child spins; the parent kills it after 50ms and
//!   must see WIFSIGNALED(SIGKILL) within 2s.
//! - TIMESLICE: two children pinned to one CPU spin, counting; both make
//!   progress (within 1:10 of each other over 300ms), and the parent's
//!   nanosleep(20ms) meanwhile returns within 1s.
//! - SMP_SPREAD: with two or more CPUs, spinning children forked one
//!   after the other run on at least two CPUs at once.
//! - ASYNC_SIG_REGS: every general register (rcx/r11 on x86, x0-x30 on
//!   arm64) holds its value across a SIGUSR1 handler that interrupts a
//!   spin loop; on x86 the loop runs with DF set (`std`), which the
//!   kernel must not inherit (backward string copies) and sigreturn
//!   must give back.

use super::helpers::{print, print_num, println};
use hk_syscall::{
    CLOCK_MONOTONIC, MAP_ANONYMOUS, MAP_SHARED, PROT_READ, PROT_WRITE, SA_RESTORER, SIG_DFL,
    SIGKILL, SIGUSR1, Timespec, sys_clock_gettime, sys_exit, sys_fork, sys_getcpu, sys_kill,
    sys_mmap, sys_munmap, sys_nanosleep, sys_rt_sigaction, sys_sched_getaffinity,
    sys_sched_setaffinity, sys_wait4,
};

const WNOHANG: i32 = 1;

/// Run the user-mode preemption tests
pub fn run_tests() {
    test_sigkill_spin();
    test_timeslice();
    test_smp_spread();
    test_async_sig_regs();
}

/// CPUs the caller may run on (sched_getaffinity, up to 1024 CPUs)
pub fn ncpus_allowed() -> u32 {
    let mut mask = [0u64; 16];
    let n = sys_sched_getaffinity(0, core::mem::size_of_val(&mask), mask.as_mut_ptr());
    if n <= 0 {
        return 1;
    }
    mask.iter().map(|w| w.count_ones()).sum()
}

/// SMP_SPREAD: spinners forked one after another run on distinct CPUs
/// (fork places a child on the least loaded CPU, Linux
/// sched_balance_find_dst_cpu); each publishes the CPU it runs on
fn test_smp_spread() {
    let ncpu = ncpus_allowed();
    if ncpu < 2 {
        println(b"SMP_SPREAD:SKIP (one CPU)");
        return;
    }
    let n = ncpu.min(4) as usize;
    let page = sys_mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if page < 0 {
        print(b"SMP_SPREAD:FAIL mmap ");
        print_num(page);
        println(b"");
        return;
    }
    let slots = page as *mut u32;
    let mut pids = [0i64; 4];
    for (i, pid) in pids.iter_mut().enumerate().take(n) {
        // SAFETY: slot i of the shared page; u32::MAX = not yet running
        unsafe { slots.add(i).write_volatile(u32::MAX) };
        *pid = sys_fork();
        if *pid == 0 {
            loop {
                let mut cpu = 0u32;
                sys_getcpu(&mut cpu, core::ptr::null_mut());
                // SAFETY: as above
                unsafe { slots.add(i).write_volatile(cpu) };
            }
        }
    }
    sleep_ms(300);
    let mut seen = 0u64;
    for i in 0..n {
        // SAFETY: as above
        let cpu = unsafe { slots.add(i).read_volatile() };
        if cpu < 64 {
            seen |= 1 << cpu;
        }
    }
    for pid in pids.iter().take(n) {
        reap(*pid);
    }
    sys_munmap(page as u64, 4096);
    if seen.count_ones() >= 2 {
        println(b"SMP_SPREAD:OK");
    } else {
        print(b"SMP_SPREAD:FAIL children on cpus mask ");
        print_num(seen as i64);
        print(b" of ");
        print_num(n as i64);
        println(b" children");
    }
}

/// CLOCK_MONOTONIC in ms
fn now_ms() -> i64 {
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    sys_clock_gettime(CLOCK_MONOTONIC, &mut ts);
    ts.tv_sec * 1000 + ts.tv_nsec / 1_000_000
}

fn sleep_ms(ms: i64) {
    let ts = Timespec {
        tv_sec: ms / 1000,
        tv_nsec: (ms % 1000) * 1_000_000,
    };
    sys_nanosleep(&ts, core::ptr::null_mut());
}

/// Spin in user mode forever
fn spin() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// Wait for `pid` to exit, polling for up to `ms`; its wait status, or
/// None if it is still running then
fn wait_for(pid: i64, ms: i64) -> Option<i32> {
    let end = now_ms() + ms;
    loop {
        let mut status: i32 = 0;
        if sys_wait4(pid, &mut status, WNOHANG, 0) == pid {
            return Some(status);
        }
        if now_ms() > end {
            return None;
        }
        sleep_ms(10);
    }
}

/// Kill and reap a child that did not finish
fn reap(pid: i64) {
    sys_kill(pid, SIGKILL);
    let mut status: i32 = 0;
    sys_wait4(pid, &mut status, 0, 0);
}

/// SIGKILL_SPIN: a spinning child dies of SIGKILL within 2s
fn test_sigkill_spin() {
    let pid = sys_fork();
    if pid == 0 {
        spin();
    }
    sleep_ms(50);
    let t0 = now_ms();
    sys_kill(pid, SIGKILL);
    match wait_for(pid, 2000) {
        Some(st) if st & 0x7f == SIGKILL as i32 => println(b"SIGKILL_SPIN:OK"),
        Some(st) => {
            print(b"SIGKILL_SPIN:FAIL status ");
            print_num(st as i64);
            println(b"");
        }
        None => {
            print(b"SIGKILL_SPIN:FAIL still running after ");
            print_num(now_ms() - t0);
            println(b" ms");
            reap(pid);
        }
    }
}

/// A child pinned to CPU 0 counting in `counter` forever
fn counter_child(counter: *mut u64) -> i64 {
    let pid = sys_fork();
    if pid == 0 {
        let mask: u64 = 1;
        sys_sched_setaffinity(0, 8, &mask);
        loop {
            // SAFETY: the shared page the parent mapped
            unsafe { counter.write_volatile(counter.read_volatile() + 1) };
        }
    }
    pid
}

/// TIMESLICE: two pinned spinners share their CPU, and a sleeper still
/// wakes up in time
fn test_timeslice() {
    let page = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0,
    );
    if page < 0 {
        print(b"TIMESLICE:FAIL mmap ");
        print_num(page);
        println(b"");
        return;
    }
    let counters = page as *mut u64;
    let a = counter_child(counters);
    // SAFETY: the second counter of the page
    let b = counter_child(unsafe { counters.add(1) });

    // Both started; a short sleep must not take long with them spinning
    sleep_ms(20);
    let t0 = now_ms();
    sleep_ms(20);
    let slept = now_ms() - t0;
    sleep_ms(260);
    // SAFETY: the page mapped above
    let (ca, cb) = unsafe { (counters.read_volatile(), counters.add(1).read_volatile()) };
    reap(a);
    reap(b);
    sys_munmap(page as u64, 4096);

    let (lo, hi) = (ca.min(cb), ca.max(cb));
    if lo == 0 || hi / lo > 10 || slept > 1000 {
        print(b"TIMESLICE:FAIL counts ");
        print_num(ca as i64);
        print(b" ");
        print_num(cb as i64);
        print(b" nanosleep(20ms) took ");
        print_num(slept);
        println(b" ms");
    } else {
        println(b"TIMESLICE:OK");
    }
}

/// Registers checked (x86: all but RSP; arm64: x0-x30)
#[cfg(target_arch = "x86_64")]
const NREG: usize = 15;

/// Slots of the register image (x86: then RFLAGS)
#[cfg(target_arch = "x86_64")]
const NOUT: usize = NREG + 1;
#[cfg(target_arch = "aarch64")]
const NOUT: usize = NREG;
#[cfg(target_arch = "aarch64")]
const NREG: usize = 31;

/// The value register `i` holds in the spin loop
const fn pattern(i: usize) -> u64 {
    0x0101_0101_0101_0101u64.wrapping_mul(i as u64 + 1) ^ 0x8000_0000_0000_0000
}

static PATTERNS: [u64; NREG] = {
    let mut p = [0u64; NREG];
    let mut i = 0;
    while i < NREG {
        p[i] = pattern(i);
        i += 1;
    }
    p
};

/// Set by the SIGUSR1 handler (x86: the spin loop tests it in memory)
#[cfg(target_arch = "x86_64")]
static mut SIG_FLAG: u8 = 0;

/// The spin loop's flag slot on its stack (arm64: a load needs a base
/// register, only SP is free; the loop compares the slot as an f64)
#[cfg(target_arch = "aarch64")]
static mut SIG_FLAG_PTR: *mut f64 = core::ptr::null_mut();

extern "C" fn sig_regs_handler(_sig: i32) {
    // SAFETY: the child's own flag; the spin loop only reads it
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::ptr::write_volatile(&raw mut SIG_FLAG, 1)
    };
    // SAFETY: the slot of the spin loop this handler interrupted
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::ptr::write_volatile(SIG_FLAG_PTR, 1.0)
    };
}

/// Load every register with its pattern, spin until the handler sets
/// SIG_FLAG, store the registers in `out`
#[cfg(target_arch = "x86_64")]
fn spin_with_patterns(out: &mut [u64; NOUT]) {
    // Order of `out`: rax rbx rcx rdx rsi rdi rbp r8 .. r15
    // SAFETY: rbx, rbp, r12-r15 saved and restored around the loop
    unsafe {
        core::arch::asm!(
            "push rbx",
            "push rbp",
            "push r12",
            "push r13",
            "push r14",
            "push r15",
            "push rdi",
            "mov rax, [rip + {p}]",
            "mov rbx, [rip + {p} + 8]",
            "mov rcx, [rip + {p} + 16]",
            "mov rdx, [rip + {p} + 24]",
            "mov rsi, [rip + {p} + 32]",
            "mov rdi, [rip + {p} + 40]",
            "mov rbp, [rip + {p} + 48]",
            "mov r8, [rip + {p} + 56]",
            "mov r9, [rip + {p} + 64]",
            "mov r10, [rip + {p} + 72]",
            "mov r11, [rip + {p} + 80]",
            "mov r12, [rip + {p} + 88]",
            "mov r13, [rip + {p} + 96]",
            "mov r14, [rip + {p} + 104]",
            "mov r15, [rip + {p} + 112]",
            "std",
            "2:",
            "cmp byte ptr [rip + {flag}], 0",
            "je 2b",
            // out (saved rdi) on top of the stack
            "xchg rdi, [rsp]",
            "mov [rdi], rax",
            "mov [rdi + 8], rbx",
            "mov [rdi + 16], rcx",
            "mov [rdi + 24], rdx",
            "mov [rdi + 32], rsi",
            "pop rax",
            "mov [rdi + 40], rax",
            "mov [rdi + 48], rbp",
            "mov [rdi + 56], r8",
            "mov [rdi + 64], r9",
            "mov [rdi + 72], r10",
            "mov [rdi + 80], r11",
            "mov [rdi + 88], r12",
            "mov [rdi + 96], r13",
            "mov [rdi + 104], r14",
            "mov [rdi + 112], r15",
            "pushfq",
            "pop rax",
            "mov [rdi + 120], rax",
            "cld",
            "pop r15",
            "pop r14",
            "pop r13",
            "pop r12",
            "pop rbp",
            "pop rbx",
            p = sym PATTERNS,
            flag = sym SIG_FLAG,
            inout("rdi") out.as_mut_ptr() => _,
            clobber_abi("C"),
        );
    }
}

/// Load every register with its pattern, spin until the handler sets
/// the flag, store the registers in `out`. The flag is a stack slot the
/// loop reads into an FP register (`fcmp`: no general register is free);
/// the handler finds it through SIG_FLAG_PTR.
#[cfg(target_arch = "aarch64")]
fn spin_with_patterns(out: &mut [u64; NOUT]) {
    // Stack: [0, 248) the register image, [256, 360) x18-x30, 360 out,
    // 368 the flag
    // SAFETY: x18-x30 saved and restored around the loop
    unsafe {
        core::arch::asm!(
            "sub sp, sp, #384",
            "stp x18, x19, [sp, #256]",
            "stp x20, x21, [sp, #272]",
            "stp x22, x23, [sp, #288]",
            "stp x24, x25, [sp, #304]",
            "stp x26, x27, [sp, #320]",
            "stp x28, x29, [sp, #336]",
            "str x30, [sp, #352]",
            "str x0, [sp, #360]",
            "str xzr, [sp, #368]",
            "add x1, sp, #368",
            "adrp x2, {fp}",
            "str x1, [x2, :lo12:{fp}]",
            "adrp x30, {p}",
            "add x30, x30, :lo12:{p}",
            "ldp x0, x1, [x30, #0]",
            "ldp x2, x3, [x30, #16]",
            "ldp x4, x5, [x30, #32]",
            "ldp x6, x7, [x30, #48]",
            "ldp x8, x9, [x30, #64]",
            "ldp x10, x11, [x30, #80]",
            "ldp x12, x13, [x30, #96]",
            "ldp x14, x15, [x30, #112]",
            "ldp x16, x17, [x30, #128]",
            "ldp x18, x19, [x30, #144]",
            "ldp x20, x21, [x30, #160]",
            "ldp x22, x23, [x30, #176]",
            "ldp x24, x25, [x30, #192]",
            "ldp x26, x27, [x30, #208]",
            "ldp x28, x29, [x30, #224]",
            "ldr x30, [x30, #240]",
            "2:",
            "ldr d0, [sp, #368]",
            "fcmp d0, #0.0",
            "b.eq 2b",
            "stp x0, x1, [sp, #0]",
            "stp x2, x3, [sp, #16]",
            "stp x4, x5, [sp, #32]",
            "stp x6, x7, [sp, #48]",
            "stp x8, x9, [sp, #64]",
            "stp x10, x11, [sp, #80]",
            "stp x12, x13, [sp, #96]",
            "stp x14, x15, [sp, #112]",
            "stp x16, x17, [sp, #128]",
            "stp x18, x19, [sp, #144]",
            "stp x20, x21, [sp, #160]",
            "stp x22, x23, [sp, #176]",
            "stp x24, x25, [sp, #192]",
            "stp x26, x27, [sp, #208]",
            "stp x28, x29, [sp, #224]",
            "str x30, [sp, #240]",
            "ldr x0, [sp, #360]",
            "mov x1, #0",
            "3:",
            "ldr x2, [sp, x1, lsl #3]",
            "str x2, [x0, x1, lsl #3]",
            "add x1, x1, #1",
            "cmp x1, #31",
            "b.ne 3b",
            "ldp x18, x19, [sp, #256]",
            "ldp x20, x21, [sp, #272]",
            "ldp x22, x23, [sp, #288]",
            "ldp x24, x25, [sp, #304]",
            "ldp x26, x27, [sp, #320]",
            "ldp x28, x29, [sp, #336]",
            "ldr x30, [sp, #352]",
            "add sp, sp, #384",
            p = sym PATTERNS,
            fp = sym SIG_FLAG_PTR,
            inout("x0") out.as_mut_ptr() => _,
            clobber_abi("C"),
        );
    }
}

/// ASYNC_SIG_REGS: a handler interrupting a register-only spin loop
/// leaves every register as it was
fn test_async_sig_regs() {
    let pid = sys_fork();
    if pid == 0 {
        let action: [u64; 4] = [
            sig_regs_handler as *const () as u64,
            SA_RESTORER,
            super::signals::restorer_addr(),
            0,
        ];
        if sys_rt_sigaction(SIGUSR1, action.as_ptr() as u64, 0, 8) != 0 {
            sys_exit(100);
        }
        let mut out = [0u64; NOUT];
        spin_with_patterns(&mut out);
        let bad = (0..NREG).find(|&i| out[i] != pattern(i));
        // x86: DF is still set (exit code 50 otherwise)
        #[cfg(target_arch = "x86_64")]
        if bad.is_none() && out[NREG] & 0x400 == 0 {
            sys_exit(50);
        }
        sys_exit(bad.map_or(0, |i| i as u64 + 1));
    }
    // Long enough for the child to be in its loop
    sleep_ms(100);
    sys_kill(pid, SIGUSR1);
    match wait_for(pid, 2000) {
        Some(0) => println(b"ASYNC_SIG_REGS:OK"),
        Some(st) => {
            // exit code i + 1: register i lost its value
            print(b"ASYNC_SIG_REGS:FAIL status ");
            print_num(st as i64);
            println(b"");
        }
        None => {
            println(b"ASYNC_SIG_REGS:FAIL the handler never ran");
            reap(pid);
        }
    }
    let dfl: [u64; 4] = [SIG_DFL, 0, 0, 0];
    sys_rt_sigaction(SIGUSR1, dfl.as_ptr() as u64, 0, 8);
}
