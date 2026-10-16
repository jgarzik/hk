//! Address spaces across fork (Linux dup_mmap / copy_page_range)
//!
//! Tests (parent and child write a word in turn, in lock-step over pipes):
//! - FORK_SHARED_ANON: a MAP_SHARED|MAP_ANONYMOUS page written before fork
//!   stays shared: each side sees the other's write
//! - FORK_SHARED_ANON_LATE: so do shared pages first touched after fork
//! - SHMEM_DONTNEED / SHMEM_REMOVE: MADV_DONTNEED on shared anonymous
//!   memory keeps the data (it lives in the shared object); MADV_REMOVE
//!   frees it (reads zero)
//! - FILE_SHARED_FORK: the same for a MAP_SHARED mapping of a file
//! - FILE_SHARED_COHERENT: a shared file mapping, another mapping of the
//!   file and read()/write() all see the same data
//! - FILE_PRIVATE_RDONLY: a MAP_PRIVATE mapping of a read-only fd made
//!   writable by mprotect writes a private copy, never the file; a
//!   MAP_SHARED one cannot be made writable (EACCES)
//! - FILE_SHARED_EOF: a shared file mapping is SIGBUS past the page
//!   holding the end of the file
//! - SHMEM_REMOVE_SHARED: MADV_REMOVE by one process zeroes the page
//!   for the other too, and the page stays shared
//! - SHMEM_REMOVE_PAST_SIZE: MADV_REMOVE of a range past the object
//!   (mapping grown by mremap) is harmless
//! - SHMEM_MREMAP_DONTUNMAP: after mremap(MREMAP_DONTUNMAP) of shared
//!   anonymous memory both ranges map the same pages
//! - SHMEM_BEYOND_SIZE: shared anonymous memory keeps the size it was
//!   mapped with: a page past it (mapping grown by mremap) is SIGBUS
//! - FORK_PRIVATE_COW: a MAP_PRIVATE page is copy-on-write: neither side
//!   sees the other's write
//! - FORK_MPROTECT_COW: mprotect read-only then read-write after fork does
//!   not make the shared copy-on-write page writable
//! - FORK_RDONLY_COW: same for a page that was read-only at fork
//! - FORK_COW_RACE: threads keep writing private pages while another
//!   thread forks, and the parent writes right after each fork (hot TLB
//!   entry): every child sees only its pre-fork snapshot
//! - FAULT_MPROTECT_RACE: a thread keeps read-faulting pages in while
//!   the range is zapped and made read-only: afterwards no page has a
//!   writable entry left (a kernel write into each is EFAULT)
//! - FORK_REMOTE_WRITE_COW: process_vm_writev into the child's
//!   copy-on-write page changes the child's copy only
//! - REMOTE_WRITE_PERM: process_vm_writev into another user's process
//!   is EPERM
//! - REMOTE_WRITE_RDONLY: process_vm_writev into a read-only shared
//!   mapping is EFAULT
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

use core::sync::atomic::{AtomicU64, Ordering};

use super::helpers::{host_mode, print, print_num, println};
use super::mm_life::meminfo;
use hk_syscall::{
    sys_close, sys_exit, sys_fork, sys_ftruncate, sys_madvise, sys_mmap, sys_mprotect,
    sys_mremap, sys_munmap, sys_nanosleep, sys_open, sys_pipe, sys_pread64, sys_process_vm_writev, sys_pwrite64,
    sys_read, sys_sched_yield, sys_setresuid, sys_shmat, sys_shmctl, sys_shmdt, sys_shmget, sys_unlink,
    sys_wait4, sys_write, IoVec, Timespec, IPC_CREAT, IPC_PRIVATE, IPC_RMID, IPC_STAT,
    MADV_DONTFORK, MADV_DONTNEED, MADV_REMOVE, MADV_WIPEONFORK, MAP_ANONYMOUS, MAP_PRIVATE,
    MAP_SHARED, MREMAP_MAYMOVE, O_CREAT, O_RDONLY, O_RDWR, O_TRUNC, PROT_READ, PROT_WRITE,
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
    file_shared();
    shmem_dontneed();
    shmem_beyond_size();
    shmem_dontunmap();
    shmem_remove_shared();
    shmem_remove_past_size();
    private_cow();
    mprotect_cow();
    rdonly_cow();
    cow_race();
    mprotect_race();
    remote_write_cow();
    remote_write_perm();
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

const FILE: &[u8] = b"/tmp/fork_mm_shared\0";

/// A file of `size` bytes, MAP_SHARED over `len`: (fd, address)
fn map_file(size: i64, len: u64) -> Option<(i32, u64)> {
    let fd = sys_open(FILE.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o600) as i32;
    if fd < 0 || sys_ftruncate(fd, size) != 0 {
        return None;
    }
    let p = sys_mmap(0, len, RW, MAP_SHARED, fd, 0);
    if p < 0 {
        sys_close(fd as u64);
        return None;
    }
    Some((fd, p as u64))
}

fn unmap_file(fd: i32, p: u64, len: u64) {
    sys_munmap(p, len);
    sys_close(fd as u64);
    sys_unlink(FILE.as_ptr());
}

fn file_shared() {
    match map_file(2 * PAGE as i64, 2 * PAGE) {
        Some((fd, p)) => {
            report(b"FILE_SHARED_FORK", shared_late(p));
            unmap_file(fd, p, 2 * PAGE);
        }
        None => report(b"FILE_SHARED_FORK", -1),
    }
    match map_file(2 * PAGE as i64, 2 * PAGE) {
        Some((fd, p)) => {
            report(b"FILE_SHARED_COHERENT", file_coherent(fd, p));
            unmap_file(fd, p, 2 * PAGE);
        }
        None => report(b"FILE_SHARED_COHERENT", -1),
    }
    report(b"FILE_PRIVATE_RDONLY", file_private_rdonly());
    match map_file(100, 2 * PAGE) {
        Some((fd, p)) => {
            report(b"FILE_SHARED_EOF", file_eof(p));
            unmap_file(fd, p, 2 * PAGE);
        }
        None => report(b"FILE_SHARED_EOF", -1),
    }
}

/// Writes through the mapping, a second mapping and write() meet
fn file_coherent(fd: i32, p: u64) -> i64 {
    put(p + 16, BEFORE);
    let mut v = 0u64;
    sys_pread64(fd, (&mut v as *mut u64).cast(), 8, 16);
    if v != BEFORE {
        return 1;
    }
    let w = PARENT;
    sys_pwrite64(fd, (&w as *const u64).cast(), 8, PAGE as i64 + 24);
    if get(p + PAGE + 24) != PARENT {
        return 2;
    }
    let q = sys_mmap(0, PAGE, RW, MAP_SHARED, fd, 0);
    if q < 0 {
        return 3;
    }
    let q = q as u64;
    let code = if get(q + 16) != BEFORE {
        4
    } else {
        put(q + 32, CHILD);
        if get(p + 32) == CHILD { 0 } else { 5 }
    };
    sys_munmap(q, PAGE);
    code
}

/// Read-only fd: private mappings write copies, shared ones stay read-only
fn file_private_rdonly() -> i64 {
    let Some((fd, p)) = map_file(PAGE as i64, PAGE) else {
        return -1;
    };
    put(p + 40, BEFORE);
    sys_munmap(p, PAGE);
    sys_close(fd as u64);
    let fd = sys_open(FILE.as_ptr(), O_RDONLY, 0) as i32;
    let sh = sys_mmap(0, PAGE, PROT_READ, MAP_SHARED, fd, 0);
    let pv = sys_mmap(0, PAGE, PROT_READ, MAP_PRIVATE, fd, 0);
    let mut code = 0;
    if fd < 0 || sh < 0 || pv < 0 {
        code = 1;
    } else if sys_mprotect(sh as u64, PAGE, RW) != -13 {
        code = 2;
    } else {
        // Both read-faulted in before the mprotect: the private page must
        // be (or become) a copy, never the shared one made writable
        if get(sh as u64 + 40) != BEFORE
            || get(pv as u64 + 40) != BEFORE
            || sys_mprotect(pv as u64, PAGE, RW) != 0
        {
            code = 3;
        } else {
            put(pv as u64 + 40, CHILD);
            let mut v = 0u64;
            sys_pread64(fd, (&mut v as *mut u64).cast(), 8, 40);
            if v != BEFORE || get(sh as u64 + 40) != BEFORE {
                code = 4;
            }
        }
    }
    sys_munmap(sh as u64, PAGE);
    sys_munmap(pv as u64, PAGE);
    sys_close(fd as u64);
    sys_unlink(FILE.as_ptr());
    code
}

/// The page with the end of the file reads (zero past it), the next
/// one is SIGBUS
fn file_eof(p: u64) -> i64 {
    if get(p + 200) != 0 {
        return 1;
    }
    let pid = sys_fork();
    if pid == 0 {
        get(p + PAGE);
        sys_exit(0);
    }
    let r = reap(pid);
    if r == 0x100 + SIGBUS { 0 } else { 10 + r }
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

fn shmem_dontunmap() {
    const MREMAP_DONTUNMAP: u32 = 4;
    one_page(b"SHMEM_MREMAP_DONTUNMAP", MAP_SHARED, |p| {
        put(p, BEFORE);
        let q = sys_mremap(p, PAGE, PAGE, MREMAP_MAYMOVE | MREMAP_DONTUNMAP, 0);
        if q < 0 {
            return 1000 + q;
        }
        let q = q as u64;
        let mut code = if get(q) == BEFORE && get(p) == BEFORE { 0 } else { 1 };
        put(q + 8, CHILD);
        if code == 0 && get(p + 8) != CHILD {
            code = 2;
        }
        sys_munmap(q, PAGE);
        code
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

fn remote_write_cow() {
    one_page(b"FORK_REMOTE_WRITE_COW", MAP_PRIVATE, |p| {
        put(p + 8, BEFORE);
        let (to_child, from_parent) = pipe();
        let pid = sys_fork();
        if pid == 0 {
            recv(to_child);
            sys_exit(if get(p + 8) == CHILD { 0 } else { 1 });
        }
        let v = CHILD;
        let local = IoVec { iov_base: (&v as *const u64).cast(), iov_len: 8 };
        let remote = IoVec { iov_base: (p + 8) as *const u8, iov_len: 8 };
        let n = sys_process_vm_writev(pid as i32, &local, 1, &remote, 1, 0);
        send(from_parent);
        let r = reap(pid);
        sys_close(to_child);
        sys_close(from_parent);
        if n != 8 {
            1000 + n
        } else if r != 0 {
            10 + r
        } else if get(p + 8) != BEFORE {
            2
        } else {
            0
        }
    });
}

/// A child that waits on a pipe with a page at a known address (one
/// mmap with `prot`, `flags`); its pid, the page and the pipe to release
/// it. The child exits 0 once released.
fn parked_child(prot: u32, flags: u32) -> (i64, u64, u64) {
    let p = sys_mmap(0, PAGE, prot, flags | MAP_ANONYMOUS, -1, 0) as u64;
    let (to_child, from_parent) = pipe();
    let pid = sys_fork();
    if pid == 0 {
        recv(to_child);
        sys_exit(0);
    }
    sys_close(to_child);
    (pid, p, from_parent)
}

fn remote_write_perm() {
    let v = CHILD;
    let local = IoVec { iov_base: (&v as *const u64).cast(), iov_len: 8 };
    // Another user's process: EPERM
    let (pid, p, rel) = parked_child(RW, MAP_PRIVATE);
    let w = sys_fork();
    if w == 0 {
        if sys_setresuid(65534, 65534, 65534) != 0 {
            sys_exit(9);
        }
        let remote = IoVec { iov_base: p as *const u8, iov_len: 8 };
        let n = sys_process_vm_writev(pid as i32, &local, 1, &remote, 1, 0);
        sys_exit(if n == -1 { 0 } else { 1 });
    }
    let r = reap(w);
    send(rel);
    sys_close(rel);
    let r2 = reap(pid);
    sys_munmap(p, PAGE);
    report(b"REMOTE_WRITE_PERM", if r == 0 && r2 == 0 { 0 } else { r * 100 + r2 });
    // A read-only shared mapping: EFAULT
    let (pid, p, rel) = parked_child(PROT_READ, MAP_SHARED);
    let remote = IoVec { iov_base: p as *const u8, iov_len: 8 };
    let n = sys_process_vm_writev(pid as i32, &local, 1, &remote, 1, 0);
    send(rel);
    sys_close(rel);
    let r2 = reap(pid);
    sys_munmap(p, PAGE);
    report(b"REMOTE_WRITE_RDONLY", if n == -14 && r2 == 0 { 0 } else { 1000 - n });
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

// ---------------------------------------------------------------------
// FORK_COW_RACE: writer threads vs fork
// ---------------------------------------------------------------------

const CLONE_THREAD_FLAGS: u64 = 0x100 // CLONE_VM
    | 0x200 // CLONE_FS
    | 0x400 // CLONE_FILES
    | 0x800 // CLONE_SIGHAND
    | 0x1_0000 // CLONE_THREAD
    | 0x4_0000 // CLONE_SYSVSEM
    | 0x20_0000; // CLONE_CHILD_CLEARTID
const RACE_PAGES: u64 = 8;
const WRITERS: usize = 2;

static RACE_BASE: AtomicU64 = AtomicU64::new(0);
static RACE_STOP: AtomicU64 = AtomicU64::new(0);

#[repr(C, align(16))]
struct ThreadStack([u8; 16384]);
static mut STACKS: [ThreadStack; WRITERS] = [const { ThreadStack([0; 16384]) }; WRITERS];
static mut CTIDS: [u32; WRITERS] = [0; WRITERS];

/// Writer thread `idx`: bump its word (idx) of every page until stopped
/// (yielding now and then)
extern "C" fn writer(idx: u64) -> ! {
    let base = RACE_BASE.load(Ordering::Relaxed);
    let mut n = 1u64;
    while RACE_STOP.load(Ordering::Relaxed) == 0 {
        for pg in 0..RACE_PAGES {
            put(base + pg * PAGE + idx * 8, n);
        }
        n += 1;
        // hk does not preempt user mode: a busy thread would keep its CPU
        if n % 16 == 0 {
            sys_sched_yield();
        }
    }
    sys_exit(0)
}

/// Start a thread running `f(arg)` on `stack_top`; its tid word `ctid`
/// is cleared (and woken) when it exits. The tid, or -errno.
unsafe fn spawn_thread(stack_top: u64, f: extern "C" fn(u64) -> !, arg: u64, ctid: *mut u32) -> i64 {
    let ret: i64;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "syscall",
            "test rax, rax",
            "jnz 2f",
            "mov rdi, r12",
            "call r13",
            "ud2",
            "2:",
            inlateout("rax") 56i64 => ret,
            in("rdi") CLONE_THREAD_FLAGS,
            in("rsi") stack_top,
            in("rdx") 0u64,
            in("r10") ctid,
            in("r8") 0u64,
            in("r12") arg,
            in("r13") f,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "svc 0",
            "cbnz x0, 2f",
            "mov x0, x9",
            "blr x10",
            "brk #0",
            "2:",
            inlateout("x0") CLONE_THREAD_FLAGS as i64 => ret,
            in("x1") stack_top,
            in("x2") 0u64,
            in("x3") 0u64,
            in("x4") ctid,
            in("x8") 220u64,
            in("x9") arg,
            in("x10") f,
        );
    }
    ret
}

/// Wait (bounded) for the thread whose tid word is `ctid` to exit
fn join(ctid: *mut u32) -> bool {
    for _ in 0..2_000_000u32 {
        if unsafe { core::ptr::read_volatile(ctid) } == 0 {
            return true;
        }
        sys_sched_yield();
    }
    false
}

/// Child of one race round: its pages must not change (the writer
/// threads and the parent's post-fork write live in the parent only)
fn race_child(base: u64, round: u64) -> u64 {
    let mut snap = [0u64; RACE_PAGES as usize * WRITERS];
    for pg in 0..RACE_PAGES {
        for w in 0..WRITERS as u64 {
            snap[(pg * WRITERS as u64 + w) as usize] = get(base + pg * PAGE + w * 8);
        }
    }
    for _ in 0..200 {
        sys_sched_yield();
    }
    if get(base + 16 * 8) != round {
        return 1;
    }
    for pg in 0..RACE_PAGES {
        for w in 0..WRITERS as u64 {
            if get(base + pg * PAGE + w * 8) != snap[(pg * WRITERS as u64 + w) as usize] {
                return 2;
            }
        }
    }
    0
}

fn cow_race() {
    const NAME: &[u8] = b"FORK_COW_RACE";
    let base = map(RACE_PAGES * PAGE, MAP_PRIVATE);
    if base == 0 {
        report(NAME, -1);
        return;
    }
    for pg in 0..RACE_PAGES {
        put(base + pg * PAGE, 0);
    }
    RACE_BASE.store(base, Ordering::Relaxed);
    RACE_STOP.store(0, Ordering::Relaxed);
    let mut started = 0;
    for i in 0..WRITERS {
        let ctid = unsafe { &raw mut CTIDS[i] } as *mut u32;
        let top = unsafe { (&raw mut STACKS[i] as *mut u8).add(16384) } as u64;
        unsafe { core::ptr::write_volatile(ctid, 1) };
        if unsafe { spawn_thread(top, writer, i as u64, ctid) } > 0 {
            started += 1;
        }
    }
    let mut code = if started == WRITERS { 0 } else { -2 };
    let marker = base + 16 * 8;
    for round in 1..=20u64 {
        if code != 0 {
            break;
        }
        put(marker, round);
        let pid = sys_fork();
        if pid == 0 {
            sys_exit(race_child(base, round));
        }
        // Right after fork: the parent's TLB still holds the writable
        // entry it just used
        put(marker, round + 1000);
        let r = reap(pid);
        if r != 0 {
            code = round as i64 * 100 + r;
        }
    }
    RACE_STOP.store(1, Ordering::Relaxed);
    for i in 0..WRITERS {
        if !join(unsafe { &raw mut CTIDS[i] } as *mut u32) && code == 0 {
            code = -3;
        }
    }
    report(NAME, code);
    sys_munmap(base, RACE_PAGES * PAGE);
}

// ---------------------------------------------------------------------
// FAULT_MPROTECT_RACE: read faults vs MADV_DONTNEED + mprotect
// ---------------------------------------------------------------------

const MP_PAGES: u64 = 64;

/// Reader thread: read every page of the range until stopped
extern "C" fn reader(_: u64) -> ! {
    let base = RACE_BASE.load(Ordering::Relaxed);
    while RACE_STOP.load(Ordering::Relaxed) == 0 {
        for pg in 0..MP_PAGES {
            get(base + pg * PAGE);
        }
        sys_sched_yield();
    }
    sys_exit(0)
}

/// Pages of [base, +MP_PAGES) the kernel can still write into (should
/// be none: the range is read-only)
fn writable_pages(base: u64) -> i64 {
    let (r, w) = pipe();
    let mut bad = 0;
    for pg in 0..MP_PAGES {
        // On EFAULT the byte stays in the pipe (at most MP_PAGES pile up)
        send(w);
        if sys_read(r, (base + pg * PAGE + 8) as *mut u8, 1) != -14 {
            bad += 1;
        }
    }
    sys_close(r);
    sys_close(w);
    bad
}

fn mprotect_race() {
    const NAME: &[u8] = b"FAULT_MPROTECT_RACE";
    let base = map(MP_PAGES * PAGE, MAP_PRIVATE);
    if base == 0 {
        report(NAME, -1);
        return;
    }
    RACE_BASE.store(base, Ordering::Relaxed);
    RACE_STOP.store(0, Ordering::Relaxed);
    let ctid = unsafe { &raw mut CTIDS[0] } as *mut u32;
    let top = unsafe { (&raw mut STACKS[0] as *mut u8).add(16384) } as u64;
    unsafe { core::ptr::write_volatile(ctid, 1) };
    let mut code = if unsafe { spawn_thread(top, reader, 0, ctid) } > 0 { 0 } else { -2 };
    for round in 0..20 {
        if code != 0 {
            break;
        }
        sys_mprotect(base, MP_PAGES * PAGE, RW);
        sys_madvise(base, MP_PAGES * PAGE, MADV_DONTNEED);
        for _ in 0..4 {
            sys_sched_yield();
        }
        sys_mprotect(base, MP_PAGES * PAGE, PROT_READ);
        let bad = writable_pages(base);
        if bad != 0 {
            code = round * 1000 + bad;
        }
    }
    RACE_STOP.store(1, Ordering::Relaxed);
    if !join(ctid) && code == 0 {
        code = -3;
    }
    report(NAME, code);
    sys_munmap(base, MP_PAGES * PAGE);
}
