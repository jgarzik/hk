//! memfd_create and file seals (Linux mm/memfd.c, mm/shmem.c)
//!
//! - MEMFD_CREATE: "memfd:<name>" in /proc/self/fd, open O_RDWR |
//!   O_LARGEFILE, MFD_CLOEXEC, mode
//!   0777 by default (vm.memfd_noexec 0), MFD_NOEXEC_SEAL drops the exec
//!   bits and seals F_SEAL_EXEC; bad flags and long names EINVAL
//! - MEMFD_SEALS: F_GET_SEALS / F_ADD_SEALS (F_SEAL_SEAL without
//!   MFD_ALLOW_SEALING and on other tmpfs files, EINVAL on non-tmpfs,
//!   EPERM read-only); SHRINK and GROW in truncate, write and fallocate;
//!   WRITE: EBUSY while mapped shared writable (whatever unknown mmap
//!   flags came with the mapping), then write and writable
//!   shared mmap EPERM, a read-only shared map cannot become writable;
//!   FUTURE_WRITE leaves existing mappings writable; EXEC keeps the exec
//!   bits and implies the write seals
//! - MEMFD_NOEXEC_SYSCTL: vm.memfd_noexec per pid namespace: 1 makes
//!   MFD_NOEXEC_SEAL the default, 2 refuses anything else (EACCES)

use crate::harness::T;
use crate::helpers::read_file;
use hk_syscall::{
    MAP_PRIVATE, MAP_SHARED, O_RDONLY, PROT_READ, PROT_WRITE, Stat, sys_close, sys_exit,
    sys_fallocate, sys_fchmod, sys_fcntl, sys_fork, sys_fstat, sys_ftruncate, sys_memfd_create,
    sys_mmap, sys_mprotect, sys_munmap, sys_open, sys_pwrite64, sys_readlink, sys_wait4, sys_write,
};

const MFD_CLOEXEC: u32 = 1;
const MFD_ALLOW_SEALING: u32 = 2;
const MFD_HUGETLB: u32 = 4;
const MFD_NOEXEC_SEAL: u32 = 8;
const MFD_EXEC: u32 = 0x10;
const F_ADD_SEALS: i32 = 1033;
const F_GET_SEALS: i32 = 1034;
const F_GETFD: i32 = 1;
const F_GETFL: i32 = 3;
const SEAL: u64 = 1;
const SHRINK: u64 = 2;
const GROW: u64 = 4;
const WRITE: u64 = 8;
const FUTURE_WRITE: u64 = 0x10;
const EXEC: u64 = 0x20;
const EPERM: i64 = -1;
const EACCES: i64 = -13;
const EBUSY: i64 = -16;
const EINVAL: i64 = -22;
const ENOSYS: i64 = -38;

pub fn run_tests() {
    create();
    seals();
    noexec_sysctl();
}

/// "/proc/self/fd/<fd>" into `buf`, NUL-terminated
fn fd_path(fd: i64, buf: &mut [u8; 32]) -> &[u8] {
    buf[..14].copy_from_slice(b"/proc/self/fd/");
    let (mut d, mut n, mut v) = ([0u8; 12], 0, fd as u64);
    loop {
        d[n] = b'0' + (v % 10) as u8;
        n += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for i in 0..n {
        buf[14 + i] = d[n - 1 - i];
    }
    buf[14 + n] = 0;
    &buf[..15 + n]
}

fn mode(fd: i64) -> i64 {
    let mut s = Stat::default();
    sys_fstat(fd as i32, &mut s);
    i64::from(s.st_mode)
}

fn create() {
    let mut t = T::new(b"MEMFD_CREATE");
    let fd = sys_memfd_create(b"test\0".as_ptr(), MFD_CLOEXEC);
    if !t.ok(b"create", fd >= 0, fd) {
        return t.done();
    }
    t.eq(b"cloexec", sys_fcntl(fd as i32, F_GETFD, 0), 1);
    // O_RDWR | O_LARGEFILE (Linux memfd_alloc_file)
    let fl = sys_fcntl(fd as i32, F_GETFL, 0);
    t.ok(
        b"getfl",
        fl & 3 == 2 && fl & i64::from(hk_syscall::O_LARGEFILE) != 0,
        fl,
    );
    let mut p = [0u8; 32];
    let mut name = [0u8; 64];
    let n = sys_readlink(fd_path(fd, &mut p).as_ptr(), name.as_mut_ptr(), 64);
    t.ok(
        b"name",
        &name[..n.max(0) as usize] == b"/memfd:test (deleted)",
        n,
    );
    t.eq(b"mode", mode(fd), 0o100777);
    t.eq(b"write", sys_write(fd as u64, b"abc".as_ptr(), 3), 3);
    sys_close(fd as u64);

    let fd = sys_memfd_create(b"nx\0".as_ptr(), MFD_NOEXEC_SEAL);
    t.eq(b"noexec mode", mode(fd), 0o100666);
    t.eq(
        b"noexec seals",
        sys_fcntl(fd as i32, F_GET_SEALS, 0),
        EXEC as i64,
    );
    sys_close(fd as u64);

    let both = MFD_EXEC | MFD_NOEXEC_SEAL;
    t.eq(
        b"exec+noexec",
        sys_memfd_create(b"x\0".as_ptr(), both),
        EINVAL,
    );
    t.eq(
        b"bad flag",
        sys_memfd_create(b"x\0".as_ptr(), 0x100),
        EINVAL,
    );
    let mut long = [b'a'; 251];
    long[250] = 0;
    t.eq(b"name 250", sys_memfd_create(long.as_ptr(), 0), EINVAL);
    long[249] = 0;
    let fd = sys_memfd_create(long.as_ptr(), 0);
    t.ok(b"name 249", fd >= 0, fd);
    sys_close(fd as u64);
    // No hugetlbfs in hk (Linux hugetlb_file_setup without it: ENOSYS)
    if !crate::helpers::host_mode() {
        t.eq(
            b"hugetlb",
            sys_memfd_create(b"h\0".as_ptr(), MFD_HUGETLB),
            ENOSYS,
        );
    }
    t.done();
}

fn add(fd: i64, s: u64) -> i64 {
    sys_fcntl(fd as i32, F_ADD_SEALS, s)
}

fn get(fd: i64) -> i64 {
    sys_fcntl(fd as i32, F_GET_SEALS, 0)
}

fn map(fd: i64, prot: u32, flags: u32) -> i64 {
    sys_mmap(0, 4096, prot, flags, fd as i32, 0)
}

fn seals() {
    let mut t = T::new(b"MEMFD_SEALS");
    let rw = PROT_READ | PROT_WRITE;
    // Not sealable: sealed with F_SEAL_SEAL (also any tmpfs file)
    let fd = sys_memfd_create(b"s\0".as_ptr(), 0);
    t.eq(b"unsealable get", get(fd), SEAL as i64);
    t.eq(b"unsealable add", add(fd, GROW), EPERM);
    sys_close(fd as u64);
    let tf = sys_open(
        b"/tmp/memfd_plain\0".as_ptr(),
        hk_syscall::O_CREAT | hk_syscall::O_RDWR,
        0o644,
    );
    t.eq(b"tmpfs file", get(tf), SEAL as i64);
    sys_close(tf as u64);
    hk_syscall::sys_unlink(b"/tmp/memfd_plain\0".as_ptr());
    let pf = sys_open(b"/proc/self/status\0".as_ptr(), O_RDONLY, 0);
    t.eq(b"procfs", get(pf), EINVAL);
    sys_close(pf as u64);

    let fd = sys_memfd_create(b"s\0".as_ptr(), MFD_ALLOW_SEALING);
    t.eq(b"sealable", get(fd), 0);
    t.eq(b"bad seal", add(fd, 0x100), EINVAL);
    let mut p = [0u8; 32];
    let ro = sys_open(fd_path(fd, &mut p).as_ptr(), O_RDONLY, 0);
    t.eq(b"read-only add", add(ro, GROW), EPERM);
    sys_close(ro as u64);
    let buf = [7u8; 8192];
    t.eq(b"fill", sys_write(fd as u64, buf.as_ptr(), 8192), 8192);
    t.eq(b"shrink", add(fd, SHRINK), 0);
    t.eq(b"shrunk", sys_ftruncate(fd as i32, 4096), EPERM);
    t.eq(b"grown", sys_ftruncate(fd as i32, 12288), 0);
    t.eq(b"grow", add(fd, GROW), 0);
    t.eq(b"truncate up", sys_ftruncate(fd as i32, 16384), EPERM);
    t.eq(
        b"write past",
        sys_pwrite64(fd as i32, buf.as_ptr(), 1, 12288),
        EPERM,
    );
    t.eq(
        b"falloc past",
        sys_fallocate(fd as i32, 0, 12288, 4096),
        EPERM,
    );
    t.eq(
        b"write inside",
        sys_pwrite64(fd as i32, buf.as_ptr(), 1, 0),
        1,
    );

    let m = map(fd, rw, MAP_SHARED);
    t.ok(b"map", m > 0, m);
    t.eq(b"write busy", add(fd, WRITE), EBUSY);
    sys_munmap(m as u64, 4096);
    // Unknown high mmap flags (MAP_HUGE_* size bits without MAP_HUGETLB)
    // are ignored, never taken for kernel VMA state: still counted
    let hm = map(fd, rw, MAP_SHARED | 0x4000_0000);
    t.ok(b"map high bit", hm > 0, hm);
    t.eq(b"high bit busy", add(fd, WRITE), EBUSY);
    sys_munmap(hm as u64, 4096);
    t.eq(b"write seal", add(fd, WRITE), 0);
    t.eq(
        b"write sealed",
        sys_pwrite64(fd as i32, buf.as_ptr(), 1, 0),
        EPERM,
    );
    t.eq(b"map shared rw", map(fd, rw, MAP_SHARED), EPERM);
    let r = map(fd, PROT_READ, MAP_SHARED);
    t.ok(b"map shared ro", r > 0, r);
    t.eq(b"mprotect", sys_mprotect(r as u64, 4096, rw), EACCES);
    sys_munmap(r as u64, 4096);
    let pm = map(fd, rw, MAP_PRIVATE);
    t.ok(b"map private", pm > 0, pm);
    sys_munmap(pm as u64, 4096);
    t.eq(b"seals", get(fd), (SHRINK | GROW | WRITE) as i64);
    t.eq(b"seal seal", add(fd, SEAL), 0);
    t.eq(b"sealed", add(fd, EXEC), EPERM);
    sys_close(fd as u64);

    // FUTURE_WRITE: a mapping made before stays writable
    let fd = sys_memfd_create(b"f\0".as_ptr(), MFD_ALLOW_SEALING);
    sys_ftruncate(fd as i32, 4096);
    let m = map(fd, rw, MAP_SHARED);
    t.eq(b"future", add(fd, FUTURE_WRITE), 0);
    if m > 0 {
        // SAFETY: a shared mapping of 4096 bytes made above
        unsafe { (m as *mut u8).write_volatile(5) };
        sys_munmap(m as u64, 4096);
    }
    t.eq(
        b"future write",
        sys_write(fd as u64, buf.as_ptr(), 1),
        EPERM,
    );
    t.eq(b"future map", map(fd, rw, MAP_SHARED), EPERM);
    sys_close(fd as u64);

    // EXEC on an executable file implies the write seals
    let fd = sys_memfd_create(b"e\0".as_ptr(), MFD_ALLOW_SEALING);
    t.eq(b"exec", add(fd, EXEC), 0);
    t.eq(
        b"exec seals",
        get(fd),
        (EXEC | SHRINK | GROW | WRITE | FUTURE_WRITE) as i64,
    );
    t.eq(b"chmod -x", sys_fchmod(fd as i32, 0o666), EPERM);
    t.eq(b"chmod same x", sys_fchmod(fd as i32, 0o755), 0);
    sys_close(fd as u64);
    t.done();
}

/// Write `v` ("0\n"..) to vm.memfd_noexec: 0 or the errno
fn set_noexec(v: &[u8]) -> i64 {
    let fd = sys_open(
        b"/proc/sys/vm/memfd_noexec\0".as_ptr(),
        hk_syscall::O_WRONLY,
        0,
    );
    if fd < 0 {
        return fd;
    }
    let r = sys_write(fd as u64, v.as_ptr(), v.len() as u64);
    sys_close(fd as u64);
    r.min(0)
}

fn noexec_sysctl() {
    let mut t = T::new(b"MEMFD_NOEXEC_SYSCTL");
    let mut b = [0u8; 8];
    let n = read_file(b"/proc/sys/vm/memfd_noexec\0", &mut b);
    t.ok(b"read", n == 2 && &b[..2] == b"0\n", n);
    // In a new pid namespace, so the boot's stays 0
    let pid = sys_fork();
    if pid == 0 {
        if hk_syscall::sys_unshare(hk_syscall::CLONE_NEWPID) != 0 {
            sys_exit(1);
        }
        let c = sys_fork();
        if c == 0 {
            let code = if set_noexec(b"1\n") != 0 {
                2
            } else if mode(sys_memfd_create(b"d\0".as_ptr(), 0)) != 0o100666 {
                3
            } else if set_noexec(b"2\n") != 0 {
                4
            } else if sys_memfd_create(b"d\0".as_ptr(), MFD_EXEC) != EACCES {
                5
            } else if sys_memfd_create(b"d\0".as_ptr(), MFD_NOEXEC_SEAL) < 0 {
                6
            } else {
                0
            };
            sys_exit(code);
        }
        let mut st = 0i32;
        sys_wait4(c, &mut st, 0, 0);
        sys_exit(((st >> 8) & 0xff) as u64);
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    t.eq(b"child", i64::from((st >> 8) & 0xff), 0);
    let n = read_file(b"/proc/sys/vm/memfd_noexec\0", &mut b);
    t.ok(b"boot ns", n == 2 && &b[..2] == b"0\n", n);
    t.done();
}
