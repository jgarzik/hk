//! Address spaces across fork (Linux dup_mmap / copy_page_range)
//!
//! Tests (parent and child write a word in turn, in lock-step over pipes):
//! - FORK_SHARED_ANON: a MAP_SHARED|MAP_ANONYMOUS page written before fork
//!   stays shared: each side sees the other's write
//! - FORK_SHARED_ANON_LATE: so do shared pages first touched after fork
//! - SHMEM_DONTNEED / SHMEM_REMOVE: MADV_DONTNEED on shared anonymous
//!   memory keeps the data (it lives in the shared object); MADV_REMOVE
//!   frees it (reads zero)
//! - SHMEM_REMOVE_SHARED: MADV_REMOVE by one process zeroes the page
//!   for the other too, and the page stays shared
//! - SHMEM_REMOVE_PAST_SIZE: MADV_REMOVE of a range past the object
//!   (mapping grown by mremap) is harmless
//! - SHMEM_BEYOND_SIZE: shared anonymous memory keeps the size it was
//!   mapped with: a page past it (mapping grown by mremap) is SIGBUS
//! - FORK_PRIVATE_COW: a MAP_PRIVATE page is copy-on-write: neither side
//!   sees the other's write
//! - FORK_MPROTECT_COW: mprotect read-only then read-write after fork does
//!   not make the shared copy-on-write page writable
//! - FORK_RDONLY_COW: same for a page that was read-only at fork
//! - FORK_DONTFORK: a MADV_DONTFORK region is not mapped in the child
//!   (SIGSEGV), the parent keeps it
//! - FORK_WIPEONFORK: a MADV_WIPEONFORK region reads zero in the child
//! - FORK_THP: a MADV_HUGEPAGE (2MB page) region keeps its data in the
//!   child and is copy-on-write
//! - SHM_NATTCH_FORK: a SysV shm attachment is inherited: shm_nattch 1 ->
//!   2 after fork, back to 1 when the child exits, 0 after shmdt; the
//!   segment is shared both ways
//! - SHM_RMID_EXIT: a segment removed with IPC_RMID while attached by a
//!   process that exits without shmdt is destroyed: its id is gone and
//!   its memory comes back
//! - SHM_RDONLY_PERM: a SHM_RDONLY attachment cannot be made writable by
//!   mprotect nor emptied by MADV_REMOVE (EACCES); MADV_REMOVE of private
//!   anonymous memory is EINVAL
//! - SHM_ATTACH_ADDR: shmat outside user space (kernel half: ENOMEM,
//!   wrapping range: EINVAL) or SHM_REMAP without an address (EINVAL)
//! - SHM_STRESS: four processes fork, shmdt and exit attached while one
//!   removes the segment midway; at the end the id is gone and the
//!   memory comes back

use super::helpers::{host_mode, print, print_num, println};
use super::mm_life::meminfo;
use hk_syscall::{
    sys_close, sys_exit, sys_fork, sys_madvise, sys_mmap, sys_mprotect, sys_munmap,
    sys_mremap, sys_nanosleep, sys_pipe, sys_read, sys_shmat, sys_shmctl, sys_shmdt, sys_shmget, sys_wait4,
    sys_write, Timespec, IPC_CREAT, IPC_PRIVATE, IPC_RMID, IPC_STAT, MADV_DONTFORK, MADV_DONTNEED, MADV_REMOVE, MADV_WIPEONFORK,
    MAP_ANONYMOUS, MAP_PRIVATE, MAP_SHARED, MREMAP_MAYMOVE, PROT_READ, PROT_WRITE,
};

const MADV_HUGEPAGE: i32 = 14;
const PAGE: u64 = 4096;
const HUGE: u64 = 2 << 20;
const BEFORE: u64 = 0x1111_0000_0000_0001;
const CHILD: u64 = 0x2222_0000_0000_0002;
const PARENT: u64 = 0x3333_0000_0000_0003;
const SIGSEGV: i32 = 11;
const SIGBUS: i64 = 7;
const RW: u32 = PROT_READ | PROT_WRITE;

pub fn run_tests() {
    shared_anon();
    shared_anon_late();
    shmem_dontneed();
    shmem_beyond_size();
    shmem_remove_shared();
    shmem_remove_past_size();
    private_cow();
    mprotect_cow();
    rdonly_cow();
    dontfork();
    wipeonfork();
    thp();
    shm_nattch_fork();
    shm_rmid_exit();
    shm_rdonly_perm();
    shm_attach_addr();
    shm_stress();
}

fn report(name: &[u8], code: i64) {
    print(name);
    if code == 0 {
        println(b":OK");
    } else {
        print(b":FAIL ");
        print_num(code);
        println(b"");
    }
}

fn map(len: u64, flags: u32) -> u64 {
    let p = sys_mmap(0, len, RW, flags | MAP_ANONYMOUS, -1, 0);
    if p < 0 { 0 } else { p as u64 }
}

fn get(a: u64) -> u64 {
    unsafe { core::ptr::read_volatile(a as *const u64) }
}

fn put(a: u64, v: u64) {
    unsafe { core::ptr::write_volatile(a as *mut u64, v) }
}

/// A pipe: (read end, write end)
fn pipe() -> (u64, u64) {
    let mut fds = [0i32; 2];
    sys_pipe(fds.as_mut_ptr());
    (fds[0] as u64, fds[1] as u64)
}

fn send(fd: u64) {
    sys_write(fd, b"x".as_ptr(), 1);
}

fn recv(fd: u64) {
    let mut b = 0u8;
    sys_read(fd, &mut b, 1);
}

/// Reap `pid`: its exit code, 0x100 + signal if killed, -1 on error
fn reap(pid: i64) -> i64 {
    let mut st = 0i32;
    if pid <= 0 || sys_wait4(pid, &mut st, 0, 0) != pid {
        return -1;
    }
    if st & 0x7f != 0 {
        return 0x100 + (st & 0x7f) as i64;
    }
    ((st >> 8) & 0xff) as i64
}

/// The word at `a` holds BEFORE; fork. The child checks it, writes
/// CHILD; then the parent checks for CHILD (`shared`) or BEFORE, writes
/// PARENT; then the child checks for PARENT (`shared`) or CHILD. `prep`
/// runs on each side before its write. 0, or the failed step.
fn exchange(a: u64, shared: bool, prep: fn(u64)) -> i64 {
    put(a, BEFORE);
    let (to_child, from_parent) = pipe();
    let (to_parent, from_child) = pipe();
    let pid = sys_fork();
    if pid == 0 {
        let mut code = 0;
        if get(a) != BEFORE {
            code = 1;
        }
        prep(a);
        put(a, CHILD);
        send(from_child);
        recv(to_child);
        if get(a) != if shared { PARENT } else { CHILD } {
            code = 2;
        }
        sys_exit(code);
    }
    let mut code = 0;
    recv(to_parent);
    if get(a) != if shared { CHILD } else { BEFORE } {
        code = 3;
    }
    prep(a);
    put(a, PARENT);
    send(from_parent);
    let r = reap(pid);
    for fd in [to_child, from_parent, to_parent, from_child] {
        sys_close(fd);
    }
    if r != 0 {
        code = 10 + r;
    }
    code
}

fn nop(_: u64) {}

/// mprotect read-only then read-write: must not undo copy-on-write
fn ro_rw(a: u64) {
    sys_mprotect(a & !(PAGE - 1), PAGE, PROT_READ);
    sys_mprotect(a & !(PAGE - 1), PAGE, RW);
}

fn make_rw(a: u64) {
    sys_mprotect(a & !(PAGE - 1), PAGE, RW);
}

fn one_page(name: &[u8], flags: u32, f: fn(u64) -> i64) {
    let p = map(PAGE, flags);
    if p == 0 {
        report(name, -1);
        return;
    }
    report(name, f(p));
    sys_munmap(p, PAGE);
}

fn shared_anon() {
    one_page(b"FORK_SHARED_ANON", MAP_SHARED, |p| exchange(p + 8, true, nop));
}

fn shared_anon_late() {
    let p = map(2 * PAGE, MAP_SHARED);
    if p == 0 {
        report(b"FORK_SHARED_ANON_LATE", -1);
        return;
    }
    report(b"FORK_SHARED_ANON_LATE", shared_late(p));
    sys_munmap(p, 2 * PAGE);
}

/// Two shared pages at `p`, untouched before fork: page 1 first
/// touched by the child, page 0 by the parent; each sees the other's
fn shared_late(p: u64) -> i64 {
    let (to_child, from_parent) = pipe();
    let (to_parent, from_child) = pipe();
    let pid = sys_fork();
    if pid == 0 {
        // Page 1 is first touched here, page 0 by the parent
        put(p + PAGE, CHILD);
        send(from_child);
        recv(to_child);
        sys_exit(if get(p) == PARENT { 0 } else { 1 });
    }
    recv(to_parent);
    let mut code = if get(p + PAGE) == CHILD { 0 } else { 2 };
    put(p, PARENT);
    send(from_parent);
    let r = reap(pid);
    if r != 0 {
        code = 10 + r;
    }
    for fd in [to_child, from_parent, to_parent, from_child] {
        sys_close(fd);
    }
    code
}

fn shmem_dontneed() {
    one_page(b"SHMEM_DONTNEED", MAP_SHARED, |p| {
        put(p, BEFORE);
        if sys_madvise(p, PAGE, MADV_DONTNEED) != 0 || get(p) != BEFORE {
            return 1;
        }
        0
    });
    one_page(b"SHMEM_REMOVE", MAP_SHARED, |p| {
        put(p, BEFORE);
        if sys_madvise(p, PAGE, MADV_REMOVE) != 0 || get(p) != 0 {
            return 1;
        }
        0
    });
}

fn shmem_remove_shared() {
    one_page(b"SHMEM_REMOVE_SHARED", MAP_SHARED, |p| {
        put(p, BEFORE);
        let (to_child, from_parent) = pipe();
        let (to_parent, from_child) = pipe();
        let pid = sys_fork();
        if pid == 0 {
            let r = sys_madvise(p, PAGE, MADV_REMOVE);
            send(from_child);
            recv(to_child);
            sys_exit(if r == 0 && get(p) == PARENT { 0 } else { 1 });
        }
        recv(to_parent);
        let mut code = if get(p) == 0 { 0 } else { 2 };
        put(p, PARENT);
        send(from_parent);
        let r = reap(pid);
        if code == 0 && r != 0 {
            code = 10 + r;
        }
        for fd in [to_child, from_parent, to_parent, from_child] {
            sys_close(fd);
        }
        code
    });
}

fn shmem_remove_past_size() {
    const NAME: &[u8] = b"SHMEM_REMOVE_PAST_SIZE";
    let p = map(PAGE, MAP_SHARED);
    let q = sys_mremap(p, PAGE, 1100 * PAGE, MREMAP_MAYMOVE, 0);
    if p == 0 || q < 0 {
        report(NAME, -1);
        return;
    }
    let q = q as u64;
    let r = sys_madvise(q + 1024 * PAGE, PAGE, MADV_REMOVE);
    report(NAME, if r == 0 { 0 } else { 1000 - r });
    sys_munmap(q, 1100 * PAGE);
}

fn shmem_beyond_size() {
    const NAME: &[u8] = b"SHMEM_BEYOND_SIZE";
    let p = map(PAGE, MAP_SHARED);
    if p == 0 {
        report(NAME, -1);
        return;
    }
    put(p, BEFORE);
    let q = sys_mremap(p, PAGE, 2 * PAGE, MREMAP_MAYMOVE, 0);
    if q < 0 {
        report(NAME, -2);
        return;
    }
    let q = q as u64;
    let mut code = if get(q) == BEFORE { 0 } else { 1 };
    let pid = sys_fork();
    if pid == 0 {
        get(q + PAGE);
        sys_exit(0);
    }
    let r = reap(pid);
    if code == 0 && r != 0x100 + SIGBUS {
        code = 10 + r;
    }
    report(NAME, code);
    sys_munmap(q, 2 * PAGE);
}

fn private_cow() {
    one_page(b"FORK_PRIVATE_COW", MAP_PRIVATE, |p| exchange(p + 8, false, nop));
}

fn mprotect_cow() {
    one_page(b"FORK_MPROTECT_COW", MAP_PRIVATE, |p| exchange(p + 8, false, ro_rw));
}

fn rdonly_cow() {
    one_page(b"FORK_RDONLY_COW", MAP_PRIVATE, |p| {
        put(p + 8, BEFORE);
        sys_mprotect(p, PAGE, PROT_READ);
        let (to_child, from_parent) = pipe();
        let pid = sys_fork();
        if pid == 0 {
            recv(to_child);
            // The parent's write after fork must not show here
            let code = if get(p + 8) == BEFORE { 0 } else { 1 };
            make_rw(p);
            put(p + 8, CHILD);
            sys_exit(code);
        }
        make_rw(p);
        put(p + 8, PARENT);
        send(from_parent);
        let r = reap(pid);
        sys_close(to_child);
        sys_close(from_parent);
        if r != 0 {
            10 + r
        } else if get(p + 8) != PARENT {
            2
        } else {
            0
        }
    });
}

fn dontfork() {
    one_page(b"FORK_DONTFORK", MAP_PRIVATE, |p| {
        put(p, BEFORE);
        if sys_madvise(p, PAGE, MADV_DONTFORK) != 0 {
            return -2;
        }
        let pid = sys_fork();
        if pid == 0 {
            // Not mapped here: this read must kill the child
            get(p);
            sys_exit(0);
        }
        let r = reap(pid);
        if r != 0x100 + SIGSEGV as i64 {
            10 + r
        } else if get(p) != BEFORE {
            3
        } else {
            0
        }
    });
}

fn wipeonfork() {
    one_page(b"FORK_WIPEONFORK", MAP_PRIVATE, |p| {
        put(p, BEFORE);
        if sys_madvise(p, PAGE, MADV_WIPEONFORK) != 0 {
            return -2;
        }
        let pid = sys_fork();
        if pid == 0 {
            let code = if get(p) == 0 { 0 } else { 1 };
            put(p, CHILD);
            sys_exit(code);
        }
        let r = reap(pid);
        if r != 0 {
            10 + r
        } else if get(p) != BEFORE {
            3
        } else {
            0
        }
    });
}

/// Pattern word of the page at `a`
fn pattern(a: u64) -> u64 {
    a ^ 0x5a5a_5a5a_0000_0000
}

fn thp() {
    const NAME: &[u8] = b"FORK_THP";
    let p = map(2 * HUGE, MAP_PRIVATE);
    if p == 0 {
        report(NAME, -1);
        return;
    }
    let base = (p + HUGE - 1) & !(HUGE - 1);
    // EINVAL without THP support (Linux): still a valid fork test
    sys_madvise(base, HUGE, MADV_HUGEPAGE);
    for a in (base..base + HUGE).step_by(PAGE as usize) {
        put(a, pattern(a));
        put(a + PAGE - 8, pattern(a));
    }
    let pid = sys_fork();
    if pid == 0 {
        let ok = (base..base + HUGE)
            .step_by(PAGE as usize)
            .all(|a| get(a) == pattern(a) && get(a + PAGE - 8) == pattern(a));
        sys_exit(if ok { 0 } else { 1 });
    }
    let mut code = reap(pid);
    if code == 0 {
        code = exchange(base + HUGE / 2 + 16, false, nop);
    }
    if code == 0
        && !(base..base + HUGE)
            .step_by(PAGE as usize)
            .all(|a| get(a) == pattern(a))
    {
        code = 4;
    }
    report(NAME, code);
    sys_munmap(p, 2 * HUGE);
}

/// shm_nattch of segment `id` (shmid64_ds: offset 88), -errno
fn nattch(id: i32) -> i64 {
    let mut ds = [0u64; 14];
    let r = sys_shmctl(id, IPC_STAT, ds.as_mut_ptr() as u64);
    if r < 0 { r } else { ds[11] as i64 }
}

fn shm_nattch_fork() {
    const NAME: &[u8] = b"SHM_NATTCH_FORK";
    let id = sys_shmget(IPC_PRIVATE, PAGE as usize, IPC_CREAT | 0o600) as i32;
    let a = sys_shmat(id, 0, 0);
    if id < 0 || a < 0 {
        report(NAME, -1);
        return;
    }
    let a = a as u64;
    put(a, BEFORE);
    let (to_child, from_parent) = pipe();
    let (to_parent, from_child) = pipe();
    let pid = sys_fork();
    if pid == 0 {
        let code = if get(a) == BEFORE { 0 } else { 1 };
        put(a + 8, CHILD);
        send(from_child);
        recv(to_child);
        sys_exit(code);
    }
    let mut code = 0;
    recv(to_parent);
    if nattch(id) != 2 {
        code = 2;
    } else if get(a + 8) != CHILD {
        code = 3;
    }
    send(from_parent);
    let r = reap(pid);
    if code == 0 && r != 0 {
        code = 10 + r;
    }
    if code == 0 && nattch(id) != 1 {
        code = 4;
    }
    sys_shmdt(a);
    if code == 0 && nattch(id) != 0 {
        code = 5;
    }
    sys_shmctl(id, IPC_RMID, 0);
    if code == 0 && nattch(id) != -22 {
        code = 6;
    }
    for fd in [to_child, from_parent, to_parent, from_child] {
        sys_close(fd);
    }
    report(NAME, code);
}

/// Let exited tasks' CPUs switch away
fn settle() {
    let ts = Timespec { tv_sec: 0, tv_nsec: 20_000_000 };
    sys_nanosleep(&ts, core::ptr::null_mut());
}

fn shm_rmid_exit() {
    const NAME: &[u8] = b"SHM_RMID_EXIT";
    // Larger than the Linux MemFree noise allowed below
    const SIZE: u64 = 96 << 20;
    let tol = if host_mode() { 64 * 1024 } else { 512 };
    settle();
    let before = meminfo(b"MemFree:");
    let (to_parent, from_child) = pipe();
    let pid = sys_fork();
    if pid == 0 {
        let id = sys_shmget(IPC_PRIVATE, SIZE as usize, IPC_CREAT | 0o600) as i32;
        let a = sys_shmat(id, 0, 0);
        if id < 0 || a < 0 {
            sys_exit(1);
        }
        for p in (a as u64..a as u64 + SIZE).step_by(PAGE as usize) {
            put(p, p);
        }
        let ok = meminfo(b"MemFree:") < before - (SIZE as i64 >> 10) + tol;
        sys_shmctl(id, IPC_RMID, 0);
        sys_write(from_child, (&id as *const i32).cast(), 4);
        // Exit still attached: the exit's detach destroys it
        sys_exit(if ok { 0 } else { 2 });
    }
    let mut id = -1i32;
    sys_read(to_parent, (&mut id as *mut i32).cast(), 4);
    let mut code = reap(pid);
    if code == 0 && nattch(id) != -22 {
        code = 3;
    }
    let mut after = 0;
    for _ in 0..50 {
        settle();
        after = meminfo(b"MemFree:");
        if before - after <= tol {
            break;
        }
    }
    if code == 0 && before - after > tol {
        print(NAME);
        print(b": MemFree before ");
        print_num(before);
        print(b" kB, after ");
        print_num(after);
        println(b" kB");
        code = 4;
    }
    sys_close(to_parent);
    sys_close(from_child);
    report(NAME, code);
}

/// One stress worker: 20 rounds of forking a grandchild that touches
/// the segment and exits attached or detaches first; worker 0 removes
/// the segment after round 10; exits attached
fn stress_worker(id: i32, a: u64, size: u64, w: u64) -> u64 {
    for round in 0..20u64 {
        let pid = sys_fork();
        if pid == 0 {
            let off = ((w * 20 + round) * PAGE * 7) % size;
            put(a + off, off);
            if round % 2 == 0 {
                sys_shmdt(a);
            }
            sys_exit(0);
        }
        if reap(pid) != 0 {
            return 1;
        }
        if w == 0 && round == 10 {
            sys_shmctl(id, IPC_RMID, 0);
        }
    }
    0
}

fn shm_stress() {
    const NAME: &[u8] = b"SHM_STRESS";
    const SIZE: u64 = 96 << 20;
    let tol = if host_mode() { 64 * 1024 } else { 512 };
    settle();
    let before = meminfo(b"MemFree:");
    let id = sys_shmget(IPC_PRIVATE, SIZE as usize, IPC_CREAT | 0o600) as i32;
    let a = sys_shmat(id, 0, 0);
    if id < 0 || a < 0 {
        report(NAME, -1);
        return;
    }
    let a = a as u64;
    for p in (a..a + SIZE).step_by(PAGE as usize) {
        put(p, p);
    }
    let mut pids = [0i64; 4];
    for (w, pid) in pids.iter_mut().enumerate() {
        *pid = sys_fork();
        if *pid == 0 {
            sys_exit(stress_worker(id, a, SIZE, w as u64));
        }
    }
    let mut code = 0;
    for pid in pids {
        let r = reap(pid);
        if code == 0 && r != 0 {
            code = 10 + r;
        }
    }
    // Still attached here: the removed segment lives until this detach
    if code == 0 && get(a + 8 * PAGE) != a + 8 * PAGE {
        code = 2;
    }
    sys_shmdt(a);
    if code == 0 && nattch(id) != -22 {
        code = 3;
    }
    let mut after = 0;
    for _ in 0..50 {
        settle();
        after = meminfo(b"MemFree:");
        if before - after <= tol {
            break;
        }
    }
    if code == 0 && before - after > tol {
        print(NAME);
        print(b": MemFree before ");
        print_num(before);
        print(b" kB, after ");
        print_num(after);
        println(b" kB");
        code = 4;
    }
    report(NAME, code);
}

fn shm_rdonly_perm() {
    const SHM_RDONLY: i32 = 0o10000;
    const EACCES: i64 = -13;
    const EINVAL: i64 = -22;
    let id = sys_shmget(IPC_PRIVATE, PAGE as usize, IPC_CREAT | 0o600) as i32;
    let a = sys_shmat(id, 0, SHM_RDONLY);
    if id < 0 || a < 0 {
        report(b"SHM_RDONLY_PERM", -1);
        return;
    }
    let a = a as u64;
    let mut code = 0;
    let r = sys_mprotect(a, PAGE, RW);
    if r != EACCES {
        code = 1000 - r;
    }
    let r = sys_madvise(a, PAGE, MADV_REMOVE);
    if code == 0 && r != EACCES {
        code = 2000 - r;
    }
    sys_shmdt(a);
    sys_shmctl(id, IPC_RMID, 0);
    let p = map(PAGE, MAP_PRIVATE);
    let r = sys_madvise(p, PAGE, MADV_REMOVE);
    if code == 0 && r != EINVAL {
        code = 3000 - r;
    }
    sys_munmap(p, PAGE);
    report(b"SHM_RDONLY_PERM", code);
}

fn shm_attach_addr() {
    const SHM_REMAP: i32 = 0o40000;
    let id = sys_shmget(IPC_PRIVATE, PAGE as usize, IPC_CREAT | 0o600) as i32;
    if id < 0 {
        report(b"SHM_ATTACH_ADDR", -1);
        return;
    }
    #[cfg(target_arch = "x86_64")]
    let kernel: u64 = 0xffff_8880_0000_0000;
    #[cfg(target_arch = "aarch64")]
    let kernel: u64 = 0xffff_0000_0000_0000;
    let mut code = 0;
    let r = sys_shmat(id, kernel, 0);
    if r != -12 {
        code = 1000 - r;
    }
    let r = sys_shmat(id, 0u64.wrapping_sub(PAGE), 0);
    if code == 0 && r != -22 {
        code = 2000 - r;
    }
    let r = sys_shmat(id, 0, SHM_REMAP);
    if code == 0 && r != -22 {
        code = 3000 - r;
    }
    sys_shmctl(id, IPC_RMID, 0);
    report(b"SHM_ATTACH_ADDR", code);
}
