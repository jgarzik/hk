//! Address-space lifecycle: /proc/meminfo, and memory handed back when
//! processes exit or exec (Linux mmput/exit_mmap, exec_mmap)

use super::helpers::{host_mode, print, print_num, println};
use hk_syscall::{
    sys_clone, sys_close, sys_execve, sys_exit, sys_fork, sys_kill, sys_mmap,
    sys_munmap, sys_nanosleep, sys_open, sys_pread64, sys_read, sys_sched_yield, sys_vfork,
    sys_wait4, sys_waitid, SigInfo, Timespec, CLONE_SIGHAND, P_PID, WEXITED, CLONE_VM, MAP_ANONYMOUS, MAP_PRIVATE,
    O_RDONLY, PROT_READ, PROT_WRITE,
};

const CLONE_THREAD: u64 = 0x0001_0000;
const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
const SIGKILL: u32 = 9;
const PAGE: u64 = 4096;

pub fn run_tests() {
    meminfo_format();
    // An exiting thread clears and wakes its CLONE_CHILD_CLEARTID word
    // (Linux mm_release), before it leaves the address space
    report(b"MM_LIFE_CLEARTID", thread(), 0);
    leak(b"MM_LIFE_FORK_EXIT", 2000, fork_exit);
    leak(b"MM_LIFE_FORK_EXEC", 500, fork_exec);
    leak(b"MM_LIFE_VFORK_EXEC", 500, vfork_exec);
    leak(b"MM_LIFE_THREADS", 500, thread);
    leak(b"MM_LIFE_MMAP_CYCLE", 1000, mmap_cycle);
    leak(b"MM_LIFE_EXEC_CHAIN", 10, exec_chain);
    maps_after_exit();
}

/// Read /proc/meminfo into `buf`; its length (0 on error)
fn read_meminfo(buf: &mut [u8]) -> usize {
    let fd = sys_open(b"/proc/meminfo\0".as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        return 0;
    }
    let mut len = 0;
    while len < buf.len() {
        let n = sys_read(fd as u64, buf[len..].as_mut_ptr(), (buf.len() - len) as u64);
        if n <= 0 {
            break;
        }
        len += n as usize;
    }
    sys_close(fd as u64);
    len
}

/// The line of /proc/meminfo starting with `key` (e.g. b"MemFree:")
fn line<'a>(text: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    text.split(|&b| b == b'\n').find(|l| l.starts_with(key))
}

/// Value in kB of a /proc/meminfo field, -1 if missing
pub fn meminfo(key: &[u8]) -> i64 {
    let mut buf = [0u8; 4096];
    let len = read_meminfo(&mut buf);
    let Some(l) = line(&buf[..len], key) else {
        return -1;
    };
    let mut v: i64 = -1;
    for &b in &l[key.len()..] {
        if b.is_ascii_digit() {
            v = v.max(0) * 10 + (b - b'0') as i64;
        } else if v >= 0 {
            break;
        }
    }
    v
}

fn report(name: &[u8], ok: bool, detail: i64) {
    print(name);
    if ok {
        println(b":OK");
    } else {
        print(b":FAIL ");
        print_num(detail);
        println(b"");
    }
}

/// Linux layout: a 16-column label, the value, " kB"; free <= total
fn meminfo_format() {
    let mut buf = [0u8; 4096];
    let len = read_meminfo(&mut buf);
    let text = &buf[..len];
    let keys: [&[u8]; 3] = [b"MemTotal:", b"MemFree:", b"MemAvailable:"];
    let mut bad = 0;
    for (i, k) in keys.iter().enumerate() {
        let ok = line(text, k).is_some_and(|l| {
            l.len() > 19 && l[k.len()..16].iter().all(|&b| b == b' ') && l.ends_with(b" kB")
        });
        if !ok {
            bad = i as i64 + 1;
        }
    }
    let total = meminfo(b"MemTotal:");
    let free = meminfo(b"MemFree:");
    if bad == 0 && !(total > 0 && free > 0 && free <= total) {
        bad = 10;
    }
    report(b"MEMINFO_FORMAT", bad == 0, bad);
}

/// Allowed MemFree drop over a batch: hk accounts exactly (a few pages
/// may still wait for another CPU's switch); Linux has slab, per-CPU
/// page lists and RCU-deferred frees, so only gross leaks (hk leaked
/// ~60 kB per fork) are flagged there
fn tolerance_kb() -> i64 {
    if host_mode() {
        (meminfo(b"MemTotal:") / 8).max(32 * 1024)
    } else {
        128
    }
}

/// Run `f` `n` times after a warm-up; MemFree must come back to (near)
/// where it was. `f` returns false on a failed step.
fn leak(name: &[u8], n: u32, f: fn() -> bool) {
    for _ in 0..(n / 10).max(2) {
        if !f() {
            report(name, false, -1);
            return;
        }
    }
    settle();
    let before = meminfo(b"MemFree:");
    for i in 0..n {
        if !f() {
            report(name, false, -2 - i as i64);
            return;
        }
    }
    // Deferred frees (other CPUs' switches, Linux RCU) may lag a little
    let mut after = 0;
    for _ in 0..50 {
        settle();
        after = meminfo(b"MemFree:");
        if before - after <= tolerance_kb() {
            break;
        }
    }
    let lost = before - after;
    let ok = before > 0 && after > 0 && lost <= tolerance_kb();
    if !ok {
        print(name);
        print(b": MemFree before ");
        print_num(before);
        print(b" kB, after ");
        print_num(after);
        println(b" kB");
    }
    report(name, ok, lost);
}

/// Let exited tasks' CPUs switch away (their stacks are freed then)
fn settle() {
    let ts = Timespec { tv_sec: 0, tv_nsec: 20_000_000 };
    sys_nanosleep(&ts, core::ptr::null_mut());
}

/// Reap `pid`; true if it exited with status 0
fn reap_ok(pid: i64) -> bool {
    let mut st = 0i32;
    pid > 0 && sys_wait4(pid, &mut st, 0, 0) == pid && st == 0
}

/// A child that touches some memory (stack, a fresh page) and exits
fn fork_exit() -> bool {
    let pid = sys_fork();
    if pid == 0 {
        let p = sys_mmap(0, 8 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if p > 0 {
            unsafe { core::ptr::write_volatile(p as *mut u8, 1) };
        }
        sys_exit(0);
    }
    reap_ok(pid)
}

const BB: &[u8] = b"/bin/busybox\0";
const ENVP: [*const u8; 1] = [core::ptr::null()];

/// exec `busybox args...` (NUL-terminated), exit 127 if that fails
fn exec_bb(args: &[&[u8]]) -> ! {
    let mut argv: [*const u8; 96] = [core::ptr::null(); 96];
    argv[0] = BB.as_ptr();
    for (i, a) in args.iter().take(94).enumerate() {
        argv[i + 1] = a.as_ptr();
    }
    sys_execve(BB.as_ptr(), argv.as_ptr(), ENVP.as_ptr());
    sys_exit(127)
}

fn fork_exec() -> bool {
    let pid = sys_fork();
    if pid == 0 {
        exec_bb(&[b"true\0"]);
    }
    reap_ok(pid)
}

/// vfork child: shares the parent's address space until its exec
fn vfork_exec() -> bool {
    let argv: [*const u8; 3] = [BB.as_ptr(), b"true\0".as_ptr(), core::ptr::null()];
    let pid = sys_vfork();
    if pid == 0 {
        sys_execve(BB.as_ptr(), argv.as_ptr(), ENVP.as_ptr());
        sys_exit(127);
    }
    reap_ok(pid)
}

/// One process execs busybox 41 times: `env busybox env ... true`
fn exec_chain() -> bool {
    let pid = sys_fork();
    if pid == 0 {
        let mut args: [&[u8]; 81] = [b"\0"; 81];
        for i in 0..40 {
            args[2 * i] = b"env\0";
            args[2 * i + 1] = BB;
        }
        args[80] = b"true\0";
        exec_bb(&args);
    }
    reap_ok(pid)
}

/// A thread is created and exits; its user stack is reused only after
/// CLONE_CHILD_CLEARTID shows it gone
fn thread() -> bool {
    #[repr(C, align(16))]
    struct Stack([u8; 8192]);
    static mut STACK: Stack = Stack([0; 8192]);
    static mut CTID: u32 = 0;
    let top = unsafe { (&raw mut STACK as *mut u8).add(8192) } as u64;
    let ctid = &raw mut CTID;
    unsafe { core::ptr::write_volatile(ctid, 1) };
    let flags = CLONE_VM | CLONE_SIGHAND | CLONE_THREAD | CLONE_CHILD_CLEARTID;
    let r = sys_clone(flags, top, 0, ctid as u64, 0);
    if r == 0 {
        sys_exit(0); // exit(2): this thread only
    }
    if r < 0 {
        return false;
    }
    let mut spins = 0u32;
    while unsafe { core::ptr::read_volatile(ctid) } != 0 {
        spins += 1;
        if spins > 1_000_000 {
            return false;
        }
        sys_sched_yield();
    }
    true
}

/// 2MB anonymous mapping, every page touched, unmapped
fn mmap_cycle() -> bool {
    let len = 2 << 20;
    let p = sys_mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if p <= 0 {
        return false;
    }
    for off in (0..len).step_by(PAGE as usize) {
        unsafe { core::ptr::write_volatile((p as u64 + off) as *mut u8, 0x5a) };
    }
    sys_munmap(p as u64, len) == 0
}

/// A /proc/<pid>/maps fd held across the target's exit reads as empty
/// while it is a zombie (its mm is gone: mmget_not_zero fails) and
/// fails with ESRCH once it is reaped (Linux m_start); never crashes
fn maps_after_exit() {
    const WNOWAIT: i32 = 0x0100_0000;
    const ESRCH: i64 = -3;
    let pid = sys_fork();
    if pid == 0 {
        let ts = Timespec { tv_sec: 30, tv_nsec: 0 };
        sys_nanosleep(&ts, core::ptr::null_mut());
        sys_exit(0);
    }
    let path = proc_path(pid, b"maps");
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0) as i32;
    let mut buf = [0u8; 512];
    let mut read = || sys_pread64(fd, buf.as_mut_ptr(), 512, 0);
    let live = read();
    sys_kill(pid, SIGKILL);
    let mut info: SigInfo = unsafe { core::mem::zeroed() };
    sys_waitid(P_PID, pid as u64, &mut info, WEXITED | WNOWAIT, 0);
    let zombie = read();
    sys_wait4(pid, core::ptr::null_mut(), 0, 0);
    let reaped = read();
    sys_close(fd as u64);
    let bad = match () {
        _ if fd < 0 => fd as i64,
        _ if live <= 0 => 1,
        _ if zombie != 0 => 2,
        _ if reaped != ESRCH => 3,
        _ => 0,
    };
    report(b"MM_LIFE_MAPS_AFTER_EXIT", bad == 0, bad);
}

/// "/proc/<pid>/<name>\0"
fn proc_path(pid: i64, name: &[u8]) -> [u8; 48] {
    let mut digits = [0u8; 20];
    let mut n = pid;
    let mut d = 0;
    loop {
        digits[d] = b'0' + (n % 10) as u8;
        d += 1;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let mut path = [0u8; 48];
    path[..6].copy_from_slice(b"/proc/");
    for i in 0..d {
        path[6 + i] = digits[d - 1 - i];
    }
    path[6 + d] = b'/';
    path[7 + d..7 + d + name.len()].copy_from_slice(name);
    path
}
