//! Running out of memory (Linux VM_FAULT_OOM / pagefault_out_of_memory,
//! RLIMIT_AS)
//!
//! Tests:
//! - OOM_RLIMIT_AS: past RLIMIT_AS, mmap and mremap fail with ENOMEM and
//!   brk leaves the break where it was; mremap(MREMAP_DONTUNMAP), which
//!   keeps the old range, is charged the whole new one
//! - OOM_RLIMIT_MEMLOCK: an unprivileged process cannot grow an mlocked
//!   mapping with mremap past RLIMIT_MEMLOCK (EAGAIN)
//! - OOM_FAULT_KILL (hk only: on Linux the OOM killer's victim choice
//!   depends on the host): a process faulting in more anonymous memory
//!   than the machine has is killed by SIGKILL; the kernel and the test
//!   runner survive, its memory comes back and the next fork works
//! - OOM_SHARED_KILL (hk only): the same with shared anonymous memory
//! - OOM_SPARSE_KILL (hk only): the same touching one page per 2MB, so
//!   every touch also costs page tables: those stop at the same
//!   watermark as user pages, the kernel keeps its reserve (MemFree at
//!   least vm.min_free_kbytes afterwards) and the next fork works
//! - OOM_PIPE_RESERVE (hk only: Linux would OOM-kill): kernel objects
//!   driven by a user, pipes full of data, until memory runs out: pipe
//!   pages stop at the low watermark, so at that point MemFree is still
//!   at least vm.min_free_kbytes, nothing panics, and it all comes back
//! - OOM_MLOCK_EAGAIN (hk only: Linux would OOM-kill instead): mlock of
//!   more memory than there is fails with EAGAIN, and the memory comes
//!   back when the process exits

use super::helpers::{host_mode, print, print_num, println, skip};
use super::mm_life::meminfo;
use hk_syscall::{
    MAP_ANONYMOUS, MAP_PRIVATE, MAP_SHARED, MREMAP_DONTUNMAP, MREMAP_MAYMOVE, O_NONBLOCK, O_RDONLY,
    PROT_READ, PROT_WRITE, RLIMIT_AS, RLIMIT_MEMLOCK, RLIMIT_NOFILE, RLimit, Timespec, sys_brk,
    sys_close, sys_exit, sys_fork, sys_mlock, sys_mmap, sys_mremap, sys_munmap, sys_nanosleep,
    sys_open, sys_pipe2, sys_read, sys_setresuid, sys_setrlimit, sys_wait4, sys_write,
};

const MAP_NORESERVE: u32 = 0x4000;
const ENOMEM: i64 = -12;
const EAGAIN: i64 = -11;
const SIGKILL: i32 = 9;
const PAGE: u64 = 4096;
const MB: u64 = 1 << 20;

pub fn run_tests() {
    rlimit_as();
    rlimit_memlock();
    fault_kill(b"OOM_FAULT_KILL", hog);
    fault_kill(b"OOM_SHARED_KILL", hog_shared);
    fault_kill(b"OOM_SPARSE_KILL", hog_sparse);
    fault_kill(b"OOM_PIPE_RESERVE", pipe_hog);
    fault_kill(b"OOM_MLOCK_EAGAIN", mlock_hog);
}

/// Child: mlock more than the machine has; EAGAIN expected (exit 0x80
/// stands in for the SIGKILL the other children expect)
fn mlock_hog() -> u64 {
    let len = (meminfo(b"MemTotal:").max(0) as u64 * 1024 * 2) & !(PAGE - 1);
    let flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE;
    let p = sys_mmap(0, len, PROT_READ | PROT_WRITE, flags, -1, 0);
    if p < 0 {
        return 2;
    }
    if sys_mlock(p as u64, len) == -11 {
        0x80
    } else {
        3
    }
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

/// Run `f` in a child; its exit status (or 0x100 + signal if killed)
fn in_child(f: fn() -> u64) -> i64 {
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(f());
    }
    let mut st = 0i32;
    if pid < 0 || sys_wait4(pid, &mut st, 0, 0) != pid {
        return -1;
    }
    if st & 0x7f != 0 {
        return 0x100 + (st & 0x7f) as i64;
    }
    ((st >> 8) & 0xff) as i64
}

/// Parse a hex number at the start of `s`; (value, bytes used)
fn hex(s: &[u8]) -> (u64, usize) {
    let mut v = 0u64;
    let mut n = 0;
    for &b in s {
        let d = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            _ => break,
        };
        v = v * 16 + d as u64;
        n += 1;
    }
    (v, n)
}

/// Bytes mapped in user space, from /proc/self/maps
fn mapped_bytes() -> u64 {
    let mut buf = [0u8; 16384];
    let fd = sys_open(b"/proc/self/maps\0".as_ptr(), O_RDONLY, 0);
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
    let mut total = 0;
    for l in buf[..len].split(|&b| b == b'\n') {
        let (start, n) = hex(l);
        if n == 0 || l.get(n) != Some(&b'-') {
            continue;
        }
        let (end, _) = hex(&l[n + 1..]);
        // [vsyscall] is not part of the address space (total_vm)
        if end > start && end <= 1 << 48 && start < 0xffff_0000_0000_0000 {
            total += end - start;
        }
    }
    total
}

/// Child: limit the address space to what is mapped plus 16MB, then
/// grow past the limit three ways. Exit code: 0, or the failed step.
fn rlimit_as_child() -> u64 {
    let anon = MAP_PRIVATE | MAP_ANONYMOUS;
    let q = sys_mmap(0, 32 * MB, PROT_READ | PROT_WRITE, anon, -1, 0);
    if q < 0 {
        return 7;
    }
    let used = mapped_bytes();
    if used == 0 {
        return 1;
    }
    let lim = RLimit {
        rlim_cur: used + 16 * MB,
        rlim_max: used + 16 * MB,
    };
    if sys_setrlimit(RLIMIT_AS, &lim) != 0 {
        return 2;
    }
    let dontunmap = MREMAP_MAYMOVE | MREMAP_DONTUNMAP;
    if sys_mremap(q as u64, 32 * MB, 32 * MB, dontunmap, 0) != ENOMEM {
        return 8;
    }
    if sys_mmap(0, 64 * MB, PROT_READ | PROT_WRITE, anon, -1, 0) != ENOMEM {
        return 3;
    }
    let p = sys_mmap(0, 4 * MB, PROT_READ | PROT_WRITE, anon, -1, 0);
    if p < 0 {
        return 4;
    }
    if sys_mremap(p as u64, 4 * MB, 64 * MB, MREMAP_MAYMOVE, 0) != ENOMEM {
        return 5;
    }
    sys_munmap(p as u64, 4 * MB);
    let brk = sys_brk(0);
    if brk <= 0 || sys_brk(brk as u64 + 64 * MB) != brk {
        return 6;
    }
    0
}

/// Child: RLIMIT_MEMLOCK 64KB, no privileges, 16KB mlocked; growing
/// the locked mapping to 128KB is EAGAIN, moved or in place
fn rlimit_memlock_child() -> u64 {
    let lim = RLimit {
        rlim_cur: 64 * 1024,
        rlim_max: 64 * 1024,
    };
    if sys_setrlimit(RLIMIT_MEMLOCK, &lim) != 0 || sys_setresuid(65534, 65534, 65534) != 0 {
        return 1;
    }
    let p = sys_mmap(
        0,
        4 * PAGE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if p < 0 || sys_mlock(p as u64, 4 * PAGE) != 0 {
        return 2;
    }
    if sys_mremap(p as u64, 4 * PAGE, 32 * PAGE, MREMAP_MAYMOVE, 0) != EAGAIN {
        return 3;
    }
    if sys_mremap(p as u64, 4 * PAGE, 32 * PAGE, 0, 0) != EAGAIN {
        return 4;
    }
    0
}

fn rlimit_memlock() {
    let r = in_child(rlimit_memlock_child);
    report(b"OOM_RLIMIT_MEMLOCK", r == 0, r);
}

fn rlimit_as() {
    let r = in_child(rlimit_as_child);
    report(b"OOM_RLIMIT_AS", r == 0, r);
}

/// Child: fault in twice the machine's memory, one write per page; the
/// fault that finds no memory must kill it
fn hog() -> u64 {
    touch_all(MAP_PRIVATE)
}

/// Child: the same with shared anonymous memory
fn hog_shared() -> u64 {
    touch_all(MAP_SHARED)
}

/// Child: one page per 2MB of a mapping far larger than RAM's worth of
/// page tables
fn hog_sparse() -> u64 {
    const LEN: u64 = 512 << 30;
    const STEP: u64 = 2 * MB;
    let flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE;
    let p = sys_mmap(0, LEN, PROT_READ | PROT_WRITE, flags, -1, 0);
    if p < 0 {
        return 2;
    }
    let mut a = p as u64;
    while a < p as u64 + LEN {
        unsafe { core::ptr::write_volatile(a as *mut u8, 1) };
        a += STEP;
    }
    3
}

static PIPE_DATA: [u8; 65536] = [0x5a; 65536];

/// Child: fill pipes (64KB each) until writes come up short; exit 0x80
/// if free memory then is still at least min_free_kbytes
fn pipe_hog() -> u64 {
    let lim = RLimit {
        rlim_cur: 65536,
        rlim_max: 65536,
    };
    if sys_setrlimit(RLIMIT_NOFILE, &lim) != 0 {
        return 2;
    }
    // Fault in what the check below uses (stack, the readers) first:
    // a page fault at exhaustion would kill the child before it looks
    let min = read_int(b"/proc/sys/vm/min_free_kbytes\0");
    meminfo(b"MemFree:");
    let mut full = false;
    for _ in 0..32000 {
        let mut fds = [0i32; 2];
        if sys_pipe2(fds.as_mut_ptr(), O_NONBLOCK) < 0 {
            full = true;
            break;
        }
        let n = PIPE_DATA.len() as u64;
        if sys_write(fds[1] as u64, PIPE_DATA.as_ptr(), n) < n as i64 {
            full = true;
            break;
        }
    }
    if !full {
        return 4;
    }
    let free = meminfo(b"MemFree:");
    print(b"OOM_PIPE_RESERVE: MemFree at exhaustion ");
    print_num(free);
    println(b" kB");
    if min <= 0 || free < min {
        print(b"OOM_PIPE_RESERVE: MemFree ");
        print_num(free);
        print(b" kB at exhaustion, min_free_kbytes ");
        print_num(min);
        println(b"");
        return 5;
    }
    0x80
}

/// An integer file such as /proc/sys/vm/min_free_kbytes (-1 if none)
fn read_int(path: &[u8]) -> i64 {
    let mut buf = [0u8; 32];
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        return -1;
    }
    let n = sys_read(fd as u64, buf.as_mut_ptr(), buf.len() as u64);
    sys_close(fd as u64);
    let mut v = -1i64;
    for &b in &buf[..n.max(0) as usize] {
        if !b.is_ascii_digit() {
            break;
        }
        v = v.max(0) * 10 + (b - b'0') as i64;
    }
    v
}

fn touch_all(share: u32) -> u64 {
    let len = (meminfo(b"MemTotal:").max(0) as u64 * 1024 * 2) & !(PAGE - 1);
    let flags = share | MAP_ANONYMOUS | MAP_NORESERVE;
    let p = sys_mmap(0, len, PROT_READ | PROT_WRITE, flags, -1, 0);
    if p < 0 {
        return 2;
    }
    let mut a = p as u64;
    while a < p as u64 + len {
        unsafe { core::ptr::write_volatile(a as *mut u8, 1) };
        a += PAGE;
    }
    3
}

fn settle() {
    let ts = Timespec {
        tv_sec: 0,
        tv_nsec: 20_000_000,
    };
    sys_nanosleep(&ts, core::ptr::null_mut());
}

fn fault_kill(name: &[u8], f: fn() -> u64) {
    if host_mode() {
        skip(name, b"Linux OOM killer victim choice depends on the host");
        return;
    }
    settle();
    let before = meminfo(b"MemFree:");
    let r = in_child(f);
    if r != 0x100 + SIGKILL as i64 && r != 0x80 {
        report(name, false, r);
        return;
    }
    // Exact accounting on hk: everything comes back (a few pages may
    // wait for the exited task's CPU to switch away)
    let mut after = 0;
    for _ in 0..50 {
        settle();
        after = meminfo(b"MemFree:");
        if before - after <= 512 {
            break;
        }
    }
    if before <= 0 || before - after > 512 {
        print(name);
        print(b": MemFree before ");
        print_num(before);
        print(b" kB, after ");
        print_num(after);
        println(b" kB");
        report(name, false, -2);
        return;
    }
    // The kernel kept its reserve
    let min = read_int(b"/proc/sys/vm/min_free_kbytes\0");
    if min <= 0 || after < min {
        print(name);
        print(b": MemFree ");
        print_num(after);
        print(b" kB, min_free_kbytes ");
        print_num(min);
        println(b"");
        report(name, false, -4);
        return;
    }
    let again = in_child(|| 0);
    report(name, again == 0, -3);
}
