//! Address-space lifecycle: /proc/meminfo, and memory handed back when
//! processes exit or exec (Linux mmput/exit_mmap, exec_mmap)

use super::helpers::{host_mode, print, print_num, println};
use hk_syscall::{
    CLONE_SIGHAND, CLONE_VM, MAP_ANONYMOUS, MAP_FIXED, MAP_PRIVATE, MREMAP_FIXED, MREMAP_MAYMOVE,
    O_RDONLY, P_PID, PROT_NONE, PROT_READ, PROT_WRITE, SigInfo, Timespec, WEXITED, sys_clone,
    sys_close, sys_execve, sys_exit, sys_fork, sys_kill, sys_mincore, sys_mmap, sys_mprotect,
    sys_mremap, sys_munmap, sys_nanosleep, sys_open, sys_pread64, sys_read, sys_sched_yield,
    sys_vfork, sys_wait4, sys_waitid,
};

const CLONE_THREAD: u64 = 0x0001_0000;
const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
const SIGKILL: u32 = 9;
const PAGE: u64 = 4096;
const ENOMEM: i64 = -12;

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
    leak(b"MM_LIFE_PGTABLE_MUNMAP", 400, pgtable_cycle);
    leak(b"MM_LIFE_EXEC_CHAIN", 10, exec_chain);
    leak(b"MM_LIFE_PROTNONE_MUNMAP", 200, protnone_munmap);
    leak(b"MM_LIFE_PROTNONE_EXIT", 200, protnone_exit);
    maps_after_exit();
    munmap_partial();
    map_fixed_replace();
    mremap_fixed_replace();
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

/// Free memory not counting the kernel heap: MemFree + Slab. These
/// tests check that user memory (pages, page tables) comes back; kernel
/// object leaks show in Slab and are tracked by the Slab tests (hk: the
/// known per-pid procfs dentry and zombie-thread leaks, BUGS.md)
fn user_free() -> i64 {
    meminfo(b"MemFree:") + meminfo(b"Slab:").max(0)
}

/// Run `f` `n` times after a warm-up; free memory must come back to
/// (near) where it was. `f` returns false on a failed step.
fn leak(name: &[u8], n: u32, f: fn() -> bool) {
    for _ in 0..(n / 10).max(2) {
        if !f() {
            report(name, false, -1);
            return;
        }
    }
    settle();
    let before = user_free();
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
        after = user_free();
        if before - after <= tolerance_kb() {
            break;
        }
    }
    let lost = before - after;
    let ok = before > 0 && after > 0 && lost <= tolerance_kb();
    if !ok {
        print(name);
        print(b": MemFree+Slab before ");
        print_num(before);
        print(b" kB, after ");
        print_num(after);
        println(b" kB");
    }
    report(name, ok, lost);
}

/// Let exited tasks' CPUs switch away (their stacks are freed then)
fn settle() {
    let ts = Timespec {
        tv_sec: 0,
        tv_nsec: 20_000_000,
    };
    sys_nanosleep(&ts, core::ptr::null_mut());
}

/// Reap `pid`; true if it exited with status 0
fn reap_ok(pid: i64) -> bool {
    let mut st = 0i32;
    pid > 0 && sys_wait4(pid, &mut st, 0, 0) == pid && st == 0
}

/// 64 pages written, then made PROT_NONE: their address
fn protnone_pages() -> Option<u64> {
    let len = 64 * PAGE;
    let p = sys_mmap(
        0,
        len,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if p < 0 {
        return None;
    }
    for a in (p as u64..p as u64 + len).step_by(PAGE as usize) {
        unsafe { core::ptr::write_volatile(a as *mut u8, 1) };
    }
    (sys_mprotect(p as u64, len, PROT_NONE) == 0).then_some(p as u64)
}

/// munmap of a PROT_NONE range gives its pages back
fn protnone_munmap() -> bool {
    protnone_pages().is_some_and(|p| sys_munmap(p, 64 * PAGE) == 0)
}

/// So does exit
fn protnone_exit() -> bool {
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(if protnone_pages().is_some() { 0 } else { 1 });
    }
    reap_ok(pid)
}

/// A child that touches some memory (stack, a fresh page) and exits
fn fork_exit() -> bool {
    let pid = sys_fork();
    if pid == 0 {
        let p = sys_mmap(
            0,
            8 * PAGE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );
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
    let p = sys_mmap(
        0,
        len,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if p <= 0 {
        return false;
    }
    for off in (0..len).step_by(PAGE as usize) {
        unsafe { core::ptr::write_volatile((p as u64 + off) as *mut u8, 0x5a) };
    }
    sys_munmap(p as u64, len) == 0
}

/// One page touched in a 1GB region never used before, then unmapped:
/// munmap frees the page tables it needed (Linux free_pgtables), so
/// sparse mappings do not pile up tables
fn pgtable_cycle() -> bool {
    use core::sync::atomic::{AtomicU64, Ordering};
    // A load and a store: no read-modify-write (outline atomics would
    // need getauxval on arm64); one thread runs this
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let gb = NEXT.load(Ordering::Relaxed);
    NEXT.store(gb + 1, Ordering::Relaxed);
    let addr = (1u64 << 40) + gb * (1 << 30);
    let p = sys_mmap(
        addr,
        PAGE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
        -1,
        0,
    );
    if p != addr as i64 {
        return false;
    }
    unsafe { core::ptr::write_volatile(addr as *mut u8, 0x5a) };
    sys_munmap(addr, PAGE) == 0
}

/// A /proc/<pid>/maps fd held across the target's exit reads as empty
/// while it is a zombie (its mm is gone: mmget_not_zero fails) and
/// fails with ESRCH once it is reaped (Linux m_start); never crashes
fn maps_after_exit() {
    const WNOWAIT: i32 = 0x0100_0000;
    const ESRCH: i64 = -3;
    let pid = sys_fork();
    if pid == 0 {
        let ts = Timespec {
            tv_sec: 30,
            tv_nsec: 0,
        };
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

/// munmap of the second page of two keeps the first mapped, with its
/// data (Linux splits the VMA): mincore 0 on it, ENOMEM on the hole
fn munmap_partial() {
    let p = sys_mmap(
        0,
        2 * PAGE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if p <= 0 {
        report(b"MM_LIFE_MUNMAP_PARTIAL", false, p);
        return;
    }
    let a = p as u64;
    unsafe {
        core::ptr::write_volatile(a as *mut u8, 0x11);
        core::ptr::write_volatile((a + PAGE) as *mut u8, 0x22);
    }
    let r = sys_munmap(a + PAGE, PAGE);
    let mut vec = [0u8; 1];
    let first = sys_mincore(a, PAGE, vec.as_mut_ptr());
    let hole = sys_mincore(a + PAGE, PAGE, vec.as_mut_ptr());
    let kept = unsafe { core::ptr::read_volatile(a as *const u8) };
    let bad = match () {
        _ if r != 0 => 1,
        _ if first != 0 => 2,
        _ if hole != ENOMEM => 3,
        _ if kept != 0x11 => 4,
        _ => 0,
    };
    sys_munmap(a, PAGE);
    report(b"MM_LIFE_MUNMAP_PARTIAL", bad == 0, bad);
}

/// MAP_FIXED over a written page gives a fresh zero page (the old one
/// is unmapped, Linux do_mmap -> do_vmi_munmap)
fn map_fixed_replace() {
    let prot = PROT_READ | PROT_WRITE;
    let p = sys_mmap(0, PAGE, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if p <= 0 {
        report(b"MM_LIFE_MAP_FIXED_REPLACE", false, p);
        return;
    }
    unsafe { core::ptr::write_volatile(p as *mut u8, 0xaa) };
    let q = sys_mmap(
        p as u64,
        PAGE,
        prot,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
        -1,
        0,
    );
    let v = unsafe { core::ptr::read_volatile(p as *const u8) };
    sys_munmap(p as u64, PAGE);
    report(b"MM_LIFE_MAP_FIXED_REPLACE", q == p && v == 0, v as i64);
}

/// mremap(MREMAP_FIXED) onto a written page replaces it with the moved
/// one and leaves a hole behind (Linux mremap_to unmaps the target)
fn mremap_fixed_replace() {
    let prot = PROT_READ | PROT_WRITE;
    let flags = MAP_PRIVATE | MAP_ANONYMOUS;
    let a = sys_mmap(0, PAGE, prot, flags, -1, 0);
    let b = sys_mmap(0, PAGE, prot, flags, -1, 0);
    if a <= 0 || b <= 0 {
        report(b"MM_LIFE_MREMAP_FIXED", false, -1);
        return;
    }
    unsafe {
        core::ptr::write_volatile(a as *mut u8, 0x11);
        core::ptr::write_volatile(b as *mut u8, 0x22);
    }
    let r = sys_mremap(
        a as u64,
        PAGE,
        PAGE,
        MREMAP_MAYMOVE | MREMAP_FIXED,
        b as u64,
    );
    let v = unsafe { core::ptr::read_volatile(b as *const u8) };
    let mut vec = [0u8; 1];
    let hole = sys_mincore(a as u64, PAGE, vec.as_mut_ptr());
    sys_munmap(b as u64, PAGE);
    let bad = match () {
        _ if r != b => 1,
        _ if v != 0x11 => 2,
        _ if hole != ENOMEM => 3,
        _ => 0,
    };
    report(b"MM_LIFE_MREMAP_FIXED", bad == 0, bad);
}
