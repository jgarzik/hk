//! Address-space concurrency and interrupts during syscalls (P3: the
//! mmap_lock, page-table locks, IRQs-on syscalls): threads faulting
//! while another changes protections, a shootdown while a thread
//! blocks in read(), timer ticks counted through a long syscall, SIGKILL
//! of threads hammering the mmap_lock, remote writes racing
//! MADV_DONTNEED on a private file mapping, and user registers kept
//! across syscalls, signals and context switches. Each passes on Linux
//! too.

use core::sync::atomic::{AtomicU64, Ordering};

use super::fork_mm::{join, spawn_thread};
use super::helpers::{print, print_num, println};
use hk_syscall::{
    CLOCK_MONOTONIC, IoVec, MADV_DONTNEED, MAP_ANONYMOUS, MAP_PRIVATE, O_CREAT, O_RDONLY, O_RDWR,
    O_TRUNC, PROT_EXEC, PROT_READ, PROT_WRITE, SA_RESTART, SA_RESTORER, Timespec,
    sys_clock_gettime, sys_close, sys_exit, sys_fork, sys_getpid, sys_kill, sys_madvise, sys_mmap,
    sys_mprotect, sys_munmap, sys_nanosleep, sys_open, sys_pipe2, sys_pread64,
    sys_process_vm_writev, sys_pwrite64, sys_read, sys_rt_sigaction, sys_sched_yield, sys_tgkill,
    sys_times, sys_unlink, sys_wait4, sys_write,
};

const PAGE: u64 = 4096;
const RW: u32 = PROT_READ | PROT_WRITE;
const SIGKILL: u32 = 9;
const SIGSEGV: i32 = 11;
const SIGUSR1: u32 = 10;
const WNOHANG: i32 = 1;
const SIG_UNBLOCK: i32 = 1;

pub fn run_tests() {
    test_ticks_long_syscall();
    test_fault_storm();
    test_shootdown_blocked_reader();
    test_kill_mmap_storm();
    test_remote_cow_race();
    test_regs_survive();
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

fn map(len: u64, prot: u32) -> u64 {
    let p = sys_mmap(0, len, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if p < 0 { 0 } else { p as u64 }
}

fn get(a: u64) -> u64 {
    unsafe { core::ptr::read_volatile(a as *const u64) }
}

fn put(a: u64, v: u64) {
    unsafe { core::ptr::write_volatile(a as *mut u64, v) }
}

/// Add `n` to an error/event counter shared by threads (load + store:
/// RMW atomics on aarch64 need libc's getauxval on Linux; a racing
/// bump may be lost, but the count never returns to zero)
fn bump(c: &AtomicU64, n: u64) {
    c.store(c.load(Ordering::Relaxed) + n, Ordering::Relaxed);
}

fn mono_ms() -> i64 {
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

/// One thread's stack
#[repr(C, align(16))]
struct Stack([u8; 16384]);
const THREADS: usize = 4;
static mut STACKS: [Stack; THREADS] = [const { Stack([0; 16384]) }; THREADS];
static mut CTIDS: [u32; THREADS] = [0; THREADS];

/// Start `f(arg)` on stack `i`; the tid, or -errno
fn start(i: usize, f: extern "C" fn(u64) -> !, arg: u64) -> i64 {
    unsafe {
        let top = (&raw mut STACKS[i] as *mut u8).add(16384) as u64;
        let ctid = &raw mut CTIDS[i];
        core::ptr::write_volatile(ctid, 1);
        spawn_thread(top, f, arg, ctid)
    }
}

fn wait_thread(i: usize) -> bool {
    join(unsafe { &raw mut CTIDS[i] })
}

/// Timer ticks keep coming while a syscall runs long without sleeping
/// (it reads /dev/zero into a large buffer): the tick count (times())
/// follows CLOCK_MONOTONIC. With interrupts off in syscalls the ticks
/// that fell inside one would be lost.
fn test_ticks_long_syscall() {
    const LEN: u64 = 32 << 20;
    let buf = map(LEN, RW);
    let fd = sys_open(b"/dev/zero\0".as_ptr(), O_RDONLY, 0);
    if buf == 0 || fd < 0 {
        report(b"IRQ_TICKS_LONG_SYSCALL", false, fd);
        return;
    }
    for i in (0..LEN).step_by(PAGE as usize) {
        put(buf + i, 1);
    }
    let t0 = sys_times(core::ptr::null_mut());
    let m0 = mono_ms();
    let mut n = 0;
    while n < 4 || mono_ms() - m0 < 200 {
        sys_read(fd as u64, buf as *mut u8, LEN);
        n += 1;
        if n > 1000 {
            break;
        }
    }
    let ticks_ms = (sys_times(core::ptr::null_mut()) - t0) * 10;
    let mono = mono_ms() - m0;
    sys_close(fd as u64);
    sys_munmap(buf, LEN);
    // Each end may be a tick (10 ms) off, and an emulator's timer may
    // drift from its TSC; lost ticks would leave about one per syscall
    let ok = ticks_ms * 2 + 30 >= mono;
    report(b"IRQ_TICKS_LONG_SYSCALL", ok, ticks_ms - mono);
}

// ---------------------------------------------------------------------
// Fault storm with concurrent mprotect
// ---------------------------------------------------------------------

const STORM_PAGES: u64 = 64;
const FAULTERS: u64 = 3;
static STORM_BASE: AtomicU64 = AtomicU64::new(0);
static STORM_STOP: AtomicU64 = AtomicU64::new(0);
static STORM_BAD: AtomicU64 = AtomicU64::new(0);

/// Faulter `idx`: write, check, drop (MADV_DONTNEED) and refault its
/// pages (every FAULTERS-th one) round after round
extern "C" fn faulter(idx: u64) -> ! {
    let base = STORM_BASE.load(Ordering::Relaxed);
    for round in 1..=150u64 {
        let mut pg = idx;
        while pg < STORM_PAGES {
            let a = base + pg * PAGE + idx * 8;
            put(a, round << 8 | idx);
            if get(a) != round << 8 | idx {
                bump(&STORM_BAD, 1);
            }
            if round % 3 == 0 {
                sys_madvise(base + pg * PAGE, PAGE, MADV_DONTNEED);
                if get(a) != 0 {
                    bump(&STORM_BAD, 1);
                }
            }
            pg += FAULTERS;
        }
        sys_sched_yield();
    }
    sys_exit(0)
}

/// Toggle the protection of sliding sub-ranges between RW and RWX:
/// VMAs split and merge, PTEs change, while the faulters run
extern "C" fn protector(_: u64) -> ! {
    let base = STORM_BASE.load(Ordering::Relaxed);
    let mut i = 0u64;
    while STORM_STOP.load(Ordering::Relaxed) == 0 {
        let start = (i * 7) % (STORM_PAGES - 8);
        let len = 1 + (i % 8);
        let prot = if i % 2 == 0 { RW | PROT_EXEC } else { RW };
        if sys_mprotect(base + start * PAGE, len * PAGE, prot) != 0 {
            bump(&STORM_BAD, 1000);
        }
        i += 1;
        sys_sched_yield();
    }
    sys_mprotect(base, STORM_PAGES * PAGE, RW);
    sys_exit(0)
}

/// Three threads fault, drop and refault pages while a fourth changes
/// protections over them (no permission is ever taken away): every
/// value written reads back, every dropped page reads zero
fn test_fault_storm() {
    let base = map(STORM_PAGES * PAGE, RW);
    STORM_BASE.store(base, Ordering::Relaxed);
    STORM_STOP.store(0, Ordering::Relaxed);
    STORM_BAD.store(0, Ordering::Relaxed);
    let mut ok = base != 0 && start(3, protector, 0) > 0;
    for i in 0..FAULTERS as usize {
        ok &= start(i, faulter, i as u64) > 0;
    }
    for i in 0..FAULTERS as usize {
        ok &= wait_thread(i);
    }
    STORM_STOP.store(1, Ordering::Relaxed);
    ok &= wait_thread(3);
    let bad = STORM_BAD.load(Ordering::Relaxed);
    sys_munmap(base, STORM_PAGES * PAGE);
    report(b"MM_FAULT_STORM", ok && bad == 0, bad as i64);
}

// ---------------------------------------------------------------------
// Shootdown while a thread blocks in read()
// ---------------------------------------------------------------------

static PIPE_RD: AtomicU64 = AtomicU64::new(0);

extern "C" fn blocked_reader(_: u64) -> ! {
    let mut c = [0u8; 1];
    sys_read(PIPE_RD.load(Ordering::Relaxed), c.as_mut_ptr(), 1);
    sys_exit(0)
}

/// A thread of the process blocks in read() on a pipe while another
/// unmaps a page it used: the unmap (and its TLB shootdown) completes
/// and the next access faults (SIGSEGV)
fn test_shootdown_blocked_reader() {
    let mut p = [0i32; 2];
    sys_pipe2(p.as_mut_ptr(), 0);
    let pid = sys_fork();
    if pid == 0 {
        sys_close(p[1] as u64);
        PIPE_RD.store(p[0] as u64, Ordering::Relaxed);
        let a = map(4 * PAGE, RW);
        for i in 0..4 {
            put(a + i * PAGE, i);
        }
        if start(0, blocked_reader, 0) <= 0 {
            sys_exit(1);
        }
        for _ in 0..20 {
            sys_sched_yield();
        }
        sys_munmap(a, 4 * PAGE);
        get(a + PAGE); // SIGSEGV
        sys_exit(2);
    }
    sys_close(p[0] as u64);
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    // EOF ends the reader if it outlived the fault (hk kills one thread
    // per fatal signal, BUGS.md)
    sys_close(p[1] as u64);
    report(
        b"TLB_SHOOTDOWN_BLOCKED_READER",
        st & 0x7f == SIGSEGV,
        st as i64,
    );
}

// ---------------------------------------------------------------------
// SIGKILL while threads hammer the mmap_lock
// ---------------------------------------------------------------------

/// mmap, touch and munmap 4MB regions forever (the mmap_lock taken for
/// writing again and again, held across each zap)
extern "C" fn map_churn(_: u64) -> ! {
    loop {
        let len = 4 << 20;
        let a = map(len, RW);
        if a != 0 {
            let mut i = 0;
            while i < len {
                put(a + i, i);
                i += PAGE;
            }
            sys_munmap(a, len);
        }
        // hk does not preempt user mode: let the killer run
        sys_sched_yield();
    }
}

/// Fault pages of a region in and drop them forever (read holds)
extern "C" fn fault_churn(base: u64) -> ! {
    let mut i = 0u64;
    loop {
        put(base + (i % 256) * PAGE, i);
        if i % 64 == 0 {
            sys_madvise(base, 256 * PAGE, MADV_DONTNEED);
            sys_sched_yield();
        }
        i += 1;
    }
}

/// SIGKILL reaches a process whose threads wait for its mmap_lock (as
/// readers and writers): it dies promptly
fn test_kill_mmap_storm() {
    let mut p = [0i32; 2];
    sys_pipe2(p.as_mut_ptr(), 0);
    let pid = sys_fork();
    if pid == 0 {
        let base = map(256 * PAGE, RW);
        let tids = [
            start(0, map_churn, 0),
            start(1, map_churn, 0),
            start(2, fault_churn, base),
        ];
        sys_write(p[1] as u64, tids.as_ptr() as *const u8, 24);
        fault_churn(base);
    }
    let mut tids = [0i64; 3];
    sys_read(p[0] as u64, tids.as_mut_ptr() as *mut u8, 24);
    sys_close(p[0] as u64);
    sys_close(p[1] as u64);
    sleep_ms(100);
    sys_kill(pid, SIGKILL);
    // hk delivers a fatal signal to one thread only (BUGS.md): the
    // others are killed one by one (on Linux already gone: ESRCH)
    for t in tids {
        if t > 0 {
            sys_tgkill(pid, t, SIGKILL);
        }
    }
    let t0 = mono_ms();
    let mut st = 0i32;
    let mut r = 0;
    while mono_ms() - t0 < 5000 {
        r = sys_wait4(pid, &mut st, WNOHANG, 0);
        if r != 0 {
            break;
        }
        sleep_ms(10);
    }
    if r == 0 {
        // Still alive: reap it anyway so the suite goes on
        sys_wait4(pid, &mut st, 0, 0);
    }
    report(
        b"MMLOCK_KILL",
        r == pid && st & 0x7f == SIGKILL as i32,
        st as i64,
    );
}

// ---------------------------------------------------------------------
// Remote writes racing MADV_DONTNEED on a private file mapping
// ---------------------------------------------------------------------

const COW_FILE: &[u8] = b"/tmp/mmlock_cow\0";
static COW_ADDR: AtomicU64 = AtomicU64::new(0);
static COW_STOP: AtomicU64 = AtomicU64::new(0);

/// Drop the private copy again and again: the next access maps the
/// file data afresh
extern "C" fn cow_dropper(_: u64) -> ! {
    let a = COW_ADDR.load(Ordering::Relaxed);
    while COW_STOP.load(Ordering::Relaxed) == 0 {
        sys_madvise(a, PAGE, MADV_DONTNEED);
        sys_sched_yield();
    }
    sys_exit(0)
}

/// A file the process may only read, mapped private and writable:
/// remote writes (process_vm_writev to itself, and on Linux pwrite to
/// /proc/self/mem) racing MADV_DONTNEED of the page must only ever
/// reach a private copy (CVE-2016-5195): the file stays unchanged
fn test_remote_cow_race() {
    let fd = sys_open(COW_FILE.as_ptr(), O_CREAT | O_RDWR | O_TRUNC, 0o644);
    if fd < 0 {
        report(b"MM_REMOTE_COW_RACE", false, fd);
        return;
    }
    let data = [b'A'; PAGE as usize];
    sys_write(fd as u64, data.as_ptr(), PAGE);
    sys_close(fd as u64);
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(cow_race_child());
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    let mut back = [0u8; PAGE as usize];
    let fd = sys_open(COW_FILE.as_ptr(), O_RDONLY, 0);
    let n = sys_pread64(fd as i32, back.as_mut_ptr(), PAGE, 0);
    sys_close(fd as u64);
    sys_unlink(COW_FILE.as_ptr());
    let same = n == PAGE as i64 && back.iter().all(|&c| c == b'A');
    report(b"MM_REMOTE_COW_RACE", st == 0 && same, (st >> 8) as i64);
}

fn cow_race_child() -> u64 {
    let fd = sys_open(COW_FILE.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        return 1;
    }
    let a = sys_mmap(0, PAGE, RW, MAP_PRIVATE, fd as i32, 0);
    if a < 0 {
        return 2;
    }
    let a = a as u64;
    COW_ADDR.store(a, Ordering::Relaxed);
    COW_STOP.store(0, Ordering::Relaxed);
    if start(0, cow_dropper, 0) <= 0 {
        return 3;
    }
    let me = sys_getpid() as i32;
    let mem = sys_open(b"/proc/self/mem\0".as_ptr(), O_RDWR, 0);
    let b = [b'B'; 8];
    for i in 0..2000u64 {
        let off = (i * 8) % PAGE;
        let local = IoVec {
            iov_base: b.as_ptr(),
            iov_len: 8,
        };
        let remote = IoVec {
            iov_base: (a + off) as *const u8,
            iov_len: 8,
        };
        sys_process_vm_writev(me, &local, 1, &remote, 1, 0);
        if mem >= 0 {
            sys_pwrite64(mem as i32, b.as_ptr(), 8, (a + off) as i64);
        }
        if i % 8 == 0 {
            sys_sched_yield();
        }
    }
    COW_STOP.store(1, Ordering::Relaxed);
    if !wait_thread(0) {
        return 4;
    }
    0
}

// ---------------------------------------------------------------------
// User registers survive syscalls, signals and switches
// ---------------------------------------------------------------------

static REG_BAD: AtomicU64 = AtomicU64::new(0);
static REG_TIDS: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
static REG_STOP: AtomicU64 = AtomicU64::new(0);
static SIGNALS: AtomicU64 = AtomicU64::new(0);

extern "C" fn count_signal(_: i32) {
    bump(&SIGNALS, 1);
}

/// Fill the registers the syscall ABI keeps (all but the return value
/// and, on x86, RCX/R11) with a pattern from `pat`, make `n`
/// sched_yield calls, then check them and the stack pointer: 0 if all
/// survived
#[cfg(target_arch = "x86_64")]
fn regs_loop(pat: u64, n: u64) -> u64 {
    let r: u64;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "push rbp",
            // [rsp + 16] pattern, [rsp + 8] the stack pointer then,
            // [rsp] the loop count
            "push {p}",
            "push rsp",
            "push {n}",
            "mov rbx, {p}",
            "lea rbp, [rbx + 1]",
            "lea r12, [rbx + 2]",
            "lea r13, [rbx + 3]",
            "lea r14, [rbx + 4]",
            "lea r15, [rbx + 5]",
            "lea rdi, [rbx + 6]",
            "lea rsi, [rbx + 7]",
            "lea r8, [rbx + 8]",
            "lea r9, [rbx + 9]",
            "lea r10, [rbx + 10]",
            "lea rdx, [rbx + 11]",
            "2:",
            "mov eax, 24", // sched_yield
            "syscall",
            "dec qword ptr [rsp]",
            "jnz 2b",
            "mov eax, 1",
            "lea rcx, [rsp + 16]",
            "cmp rcx, [rsp + 8]",
            "jne 3f",
            "cmp rbx, [rsp + 16]",
            "jne 3f",
            "lea rcx, [rbx + 1]",
            "cmp rcx, rbp",
            "jne 3f",
            "lea rcx, [rbx + 2]",
            "cmp rcx, r12",
            "jne 3f",
            "lea rcx, [rbx + 3]",
            "cmp rcx, r13",
            "jne 3f",
            "lea rcx, [rbx + 4]",
            "cmp rcx, r14",
            "jne 3f",
            "lea rcx, [rbx + 5]",
            "cmp rcx, r15",
            "jne 3f",
            "lea rcx, [rbx + 6]",
            "cmp rcx, rdi",
            "jne 3f",
            "lea rcx, [rbx + 7]",
            "cmp rcx, rsi",
            "jne 3f",
            "lea rcx, [rbx + 8]",
            "cmp rcx, r8",
            "jne 3f",
            "lea rcx, [rbx + 9]",
            "cmp rcx, r9",
            "jne 3f",
            "lea rcx, [rbx + 10]",
            "cmp rcx, r10",
            "jne 3f",
            "lea rcx, [rbx + 11]",
            "cmp rcx, rdx",
            "jne 3f",
            "xor eax, eax",
            "3:",
            "add rsp, 24",
            "pop rbp",
            "pop rbx",
            p = in(reg) pat,
            n = in(reg) n,
            lateout("rax") r,
            lateout("rcx") _,
            lateout("rdx") _,
            lateout("rdi") _,
            lateout("rsi") _,
            lateout("r8") _,
            lateout("r9") _,
            lateout("r10") _,
            lateout("r11") _,
            lateout("r12") _,
            lateout("r13") _,
            lateout("r14") _,
            lateout("r15") _,
        );
    }
    r
}

#[cfg(target_arch = "aarch64")]
fn regs_loop(pat: u64, n: u64) -> u64 {
    let r: u64;
    unsafe {
        core::arch::asm!(
            // [sp, #88] loop count, #96 pattern, #104 the stack pointer
            "sub sp, sp, #112",
            "str {n}, [sp, #88]",
            "str {p}, [sp, #96]",
            "stp x19, x20, [sp, #0]",
            "stp x21, x22, [sp, #16]",
            "stp x23, x24, [sp, #32]",
            "stp x25, x26, [sp, #48]",
            "stp x27, x28, [sp, #64]",
            "str x29, [sp, #80]",
            "mov x19, {p}",
            "mov x9, sp",
            "str x9, [sp, #104]",
            "add x20, x19, #1",
            "add x21, x19, #2",
            "add x22, x19, #3",
            "add x23, x19, #4",
            "add x24, x19, #5",
            "add x25, x19, #6",
            "add x26, x19, #7",
            "add x27, x19, #8",
            "add x28, x19, #9",
            "add x29, x19, #10",
            "add x1, x19, #11",
            "add x2, x19, #12",
            "add x3, x19, #13",
            "add x4, x19, #14",
            "add x5, x19, #15",
            "add x6, x19, #16",
            "add x7, x19, #17",
            "2:",
            "mov x8, #124", // sched_yield
            "svc 0",
            "ldr x9, [sp, #88]",
            "subs x9, x9, #1",
            "str x9, [sp, #88]",
            "b.ne 2b",
            "mov x0, #1",
            "mov x9, sp",
            "ldr x10, [sp, #104]",
            "cmp x9, x10",
            "b.ne 3f",
            "ldr x10, [sp, #96]",
            "cmp x10, x19",
            "b.ne 3f",
            "add x10, x19, #1",
            "cmp x10, x20",
            "b.ne 3f",
            "add x10, x19, #2",
            "cmp x10, x21",
            "b.ne 3f",
            "add x10, x19, #3",
            "cmp x10, x22",
            "b.ne 3f",
            "add x10, x19, #4",
            "cmp x10, x23",
            "b.ne 3f",
            "add x10, x19, #5",
            "cmp x10, x24",
            "b.ne 3f",
            "add x10, x19, #6",
            "cmp x10, x25",
            "b.ne 3f",
            "add x10, x19, #7",
            "cmp x10, x26",
            "b.ne 3f",
            "add x10, x19, #8",
            "cmp x10, x27",
            "b.ne 3f",
            "add x10, x19, #9",
            "cmp x10, x28",
            "b.ne 3f",
            "add x10, x19, #10",
            "cmp x10, x29",
            "b.ne 3f",
            "add x10, x19, #11",
            "cmp x10, x1",
            "b.ne 3f",
            "add x10, x19, #12",
            "cmp x10, x2",
            "b.ne 3f",
            "add x10, x19, #13",
            "cmp x10, x3",
            "b.ne 3f",
            "add x10, x19, #14",
            "cmp x10, x4",
            "b.ne 3f",
            "add x10, x19, #15",
            "cmp x10, x5",
            "b.ne 3f",
            "add x10, x19, #16",
            "cmp x10, x6",
            "b.ne 3f",
            "add x10, x19, #17",
            "cmp x10, x7",
            "b.ne 3f",
            "mov x0, #0",
            "3:",
            "ldp x19, x20, [sp, #0]",
            "ldp x21, x22, [sp, #16]",
            "ldp x23, x24, [sp, #32]",
            "ldp x25, x26, [sp, #48]",
            "ldp x27, x28, [sp, #64]",
            "ldr x29, [sp, #80]",
            "add sp, sp, #112",
            p = in(reg) pat,
            n = in(reg) n,
            lateout("x0") r,
            lateout("x1") _,
            lateout("x2") _,
            lateout("x3") _,
            lateout("x4") _,
            lateout("x5") _,
            lateout("x6") _,
            lateout("x7") _,
            lateout("x8") _,
            lateout("x9") _,
            lateout("x10") _,
        );
    }
    r
}

/// A pattern thread: rounds of `regs_loop`
extern "C" fn reg_worker(idx: u64) -> ! {
    // The boot tester may run with SIGUSR1 blocked
    let set = 1u64 << (SIGUSR1 - 1);
    hk_syscall::sys_rt_sigprocmask(SIG_UNBLOCK, &raw const set as u64, 0, 8);
    REG_TIDS[idx as usize].store(hk_syscall::sys_gettid() as u64, Ordering::Relaxed);
    let pat = 0x5a5a_0000_0000_0000 | (idx + 1) << 32;
    // At least 40 rounds, and on until signals have arrived
    let mut round = 0u64;
    while round < 40 || (SIGNALS.load(Ordering::Relaxed) < 4 && round < 4000) {
        if regs_loop(pat | (round & 0xff) << 8, 50) != 0 {
            bump(&REG_BAD, 1);
        }
        round += 1;
    }
    sys_exit(0)
}

/// Signal the pattern threads and unmap touched memory (TLB
/// shootdowns) until stopped
extern "C" fn reg_disturber(_: u64) -> ! {
    let pid = sys_getpid();
    while REG_STOP.load(Ordering::Relaxed) == 0 {
        for t in &REG_TIDS {
            let tid = t.load(Ordering::Relaxed);
            if tid != 0 {
                sys_tgkill(pid, tid as i64, SIGUSR1);
            }
        }
        let a = map(8 * PAGE, RW);
        if a != 0 {
            for i in 0..8 {
                put(a + i * PAGE, i);
            }
            sys_munmap(a, 8 * PAGE);
        }
        sys_sched_yield();
    }
    sys_exit(0)
}

/// Two threads keep patterns in every register the syscall ABI
/// preserves (and their stack pointer) through sched_yield loops while
/// a third signals them and unmaps memory: no register changes
fn test_regs_survive() {
    let act: [u64; 4] = [
        count_signal as *const () as u64,
        SA_RESTORER | SA_RESTART,
        super::signals::restorer_addr(),
        0,
    ];
    let mut old = [0u64; 4];
    sys_rt_sigaction(SIGUSR1, act.as_ptr() as u64, old.as_mut_ptr() as u64, 8);
    REG_BAD.store(0, Ordering::Relaxed);
    REG_STOP.store(0, Ordering::Relaxed);
    SIGNALS.store(0, Ordering::Relaxed);
    for t in &REG_TIDS {
        t.store(0, Ordering::Relaxed);
    }
    let mut ok = start(2, reg_disturber, 0) > 0;
    ok &= start(0, reg_worker, 0) > 0;
    ok &= start(1, reg_worker, 1) > 0;
    ok &= wait_thread(0) && wait_thread(1);
    REG_STOP.store(1, Ordering::Relaxed);
    ok &= wait_thread(2);
    sys_rt_sigaction(SIGUSR1, old.as_ptr() as u64, 0, 8);
    let bad = REG_BAD.load(Ordering::Relaxed);
    let sigs = SIGNALS.load(Ordering::Relaxed);
    report(
        b"REGS_SURVIVE_SYSCALLS",
        ok && bad == 0 && sigs > 0,
        (bad * 100 + sigs.min(99)) as i64 * if ok { 1 } else { -1 },
    );
}
