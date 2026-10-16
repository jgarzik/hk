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

use super::helpers::{print, print_num, println};
use hk_syscall::{
    sys_close, sys_exit, sys_fork, sys_madvise, sys_mmap, sys_mprotect, sys_munmap,
    sys_mremap, sys_pipe, sys_read, sys_wait4, sys_write, MADV_DONTFORK, MADV_DONTNEED,
    MADV_REMOVE, MADV_WIPEONFORK, MAP_ANONYMOUS, MAP_PRIVATE, MAP_SHARED, MREMAP_MAYMOVE,
    PROT_READ, PROT_WRITE,
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
    const NAME: &[u8] = b"FORK_SHARED_ANON_LATE";
    let p = map(2 * PAGE, MAP_SHARED);
    if p == 0 {
        report(NAME, -1);
        return;
    }
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
    report(NAME, code);
    sys_munmap(p, 2 * PAGE);
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
