//! Private /proc/<pid>/ files (maps, exe, fd/) need ptrace-read access
//! to the process (Linux fs/proc/base.c, __ptrace_may_access with
//! PTRACE_MODE_READ_FSCREDS): same uid/gid on all ids and dumpable, or
//! CAP_SYS_PTRACE.

use super::helpers::{print, print_num, println};
use hk_syscall::{
    sys_close, sys_exit, sys_fork, sys_kill, sys_nanosleep, sys_open, sys_pipe2, sys_prctl,
    sys_execve, sys_pread64, sys_read, sys_readlink, sys_setresuid, sys_setuid, sys_wait4, sys_write, Timespec, O_DIRECTORY, O_RDONLY,
};

const EACCES: i64 = -13;
const NOBODY: u64 = 65534;
const PR_SET_DUMPABLE: i32 = 4;
const SIGKILL: u32 = 9;

pub fn run_tests() {
    test_root_reads_all();
    in_child(b"PROC_ACCESS_OTHER_UID_DENIED", other_uid_denied);
    test_nondumpable();
    test_suid_differs();
    test_maps_after_exec();
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

/// Run `f` in a child; its exit code 0 is a pass, else the failed step
fn in_child(name: &[u8], f: fn() -> u64) {
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(f());
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    report(name, st == 0, (st >> 8) as i64);
}

/// "/proc/<pid>/<what>\0" in `buf`
fn path<'a>(buf: &'a mut [u8; 64], pid: i64, what: &[u8]) -> &'a [u8] {
    let mut n = 0;
    for &c in b"/proc/" {
        buf[n] = c;
        n += 1;
    }
    let mut d = [0u8; 20];
    let mut k = 0;
    let mut v = pid as u64;
    loop {
        d[k] = b'0' + (v % 10) as u8;
        k += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    while k > 0 {
        k -= 1;
        buf[n] = d[k];
        n += 1;
    }
    buf[n] = b'/';
    n += 1;
    for &c in what {
        buf[n] = c;
        n += 1;
    }
    buf[n] = 0;
    &buf[..=n]
}

fn open_ret(p: &[u8], flags: u32) -> i64 {
    let fd = sys_open(p.as_ptr(), flags, 0);
    if fd >= 0 {
        sys_close(fd as u64);
    }
    fd
}

/// root (CAP_SYS_PTRACE) reads another process's maps, exe and fd/
fn test_root_reads_all() {
    let mut b = [0u8; 64];
    let mut l = [0u8; 64];
    let child = sys_fork();
    if child == 0 {
        let ts = Timespec { tv_sec: 5, tv_nsec: 0 };
        sys_nanosleep(&ts, core::ptr::null_mut());
        sys_exit(0);
    }
    let maps = open_ret(path(&mut b, child, b"maps"), O_RDONLY);
    let exe = sys_readlink(path(&mut b, child, b"exe").as_ptr(), l.as_mut_ptr(), 64);
    let fd = open_ret(path(&mut b, child, b"fd"), O_RDONLY | O_DIRECTORY);
    sys_kill(child, SIGKILL);
    sys_wait4(child, core::ptr::null_mut(), 0, 0);
    let ok = maps >= 0 && exe > 0 && fd >= 0;
    report(b"PROC_ACCESS_ROOT", ok, if maps < 0 { maps } else if exe <= 0 { exe } else { fd });
}

/// An unprivileged task cannot read root's (pid 1's) private files but
/// can read its own
fn other_uid_denied() -> u64 {
    if sys_setuid(NOBODY as u32) != 0 {
        return 1;
    }
    let mut b = [0u8; 64];
    let mut l = [0u8; 64];
    if open_ret(path(&mut b, 1, b"maps"), O_RDONLY) != EACCES {
        return 2;
    }
    if sys_readlink(path(&mut b, 1, b"exe").as_ptr(), l.as_mut_ptr(), 64) != EACCES {
        return 3;
    }
    if open_ret(path(&mut b, 1, b"fd"), O_RDONLY | O_DIRECTORY) != EACCES {
        return 4;
    }
    if open_ret(b"/proc/self/maps\0", O_RDONLY) < 0 {
        return 5;
    }
    0
}

/// A non-dumpable process's maps are closed to its own uid
fn test_nondumpable() {
    let mut p = [0i32; 2];
    sys_pipe2(p.as_mut_ptr(), 0);
    let a = sys_fork();
    if a == 0 {
        sys_setuid(NOBODY as u32);
        sys_prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
        sys_write(p[1] as u64, b"r".as_ptr(), 1);
        let ts = Timespec { tv_sec: 5, tv_nsec: 0 };
        sys_nanosleep(&ts, core::ptr::null_mut());
        sys_exit(0);
    }
    let mut c = [0u8; 1];
    sys_read(p[0] as u64, c.as_mut_ptr(), 1);
    let b = sys_fork();
    if b == 0 {
        sys_setuid(NOBODY as u32);
        let mut buf = [0u8; 64];
        let r = open_ret(path(&mut buf, a, b"maps"), O_RDONLY);
        sys_exit(if r == EACCES { 0 } else { 1 });
    }
    let mut st = 0i32;
    sys_wait4(b, &mut st, 0, 0);
    sys_kill(a, SIGKILL);
    sys_wait4(a, core::ptr::null_mut(), 0, 0);
    sys_close(p[0] as u64);
    sys_close(p[1] as u64);
    report(b"PROC_ACCESS_NONDUMPABLE", st == 0, (st >> 8) as i64);
}

/// A target whose saved uid differs from the reader's uid (a setuid
/// program that dropped privileges) is closed to that uid: all real,
/// effective and saved ids must match
fn test_suid_differs() {
    const UID: u32 = 1000;
    let mut p = [0i32; 2];
    sys_pipe2(p.as_mut_ptr(), 0);
    let a = sys_fork();
    if a == 0 {
        sys_setresuid(UID, UID, 0);
        sys_write(p[1] as u64, b"r".as_ptr(), 1);
        let ts = Timespec { tv_sec: 5, tv_nsec: 0 };
        sys_nanosleep(&ts, core::ptr::null_mut());
        sys_exit(0);
    }
    let mut c = [0u8; 1];
    sys_read(p[0] as u64, c.as_mut_ptr(), 1);
    let b = sys_fork();
    if b == 0 {
        sys_setuid(UID);
        let mut buf = [0u8; 64];
        let r = open_ret(path(&mut buf, a, b"maps"), O_RDONLY);
        sys_exit(if r == EACCES { 0 } else { 1 });
    }
    let mut st = 0i32;
    sys_wait4(b, &mut st, 0, 0);
    sys_kill(a, SIGKILL);
    sys_wait4(a, core::ptr::null_mut(), 0, 0);
    sys_close(p[0] as u64);
    sys_close(p[1] as u64);
    report(b"PROC_ACCESS_SUID_DIFFERS", st == 0, (st >> 8) as i64);
}

/// An open maps file keeps reading the address space it was opened on:
/// after the target execs, a read gives the old image, EOF or ESRCH
/// (Linux), never the new one
fn test_maps_after_exec() {
    let mut p = [0i32; 2];
    sys_pipe2(p.as_mut_ptr(), 0);
    let a = sys_fork();
    if a == 0 {
        let mut c = [0u8; 1];
        sys_read(p[0] as u64, c.as_mut_ptr(), 1);
        let argv: [*const u8; 2] = [b"boot_tester2\0".as_ptr(), core::ptr::null()];
        let envp: [*const u8; 1] = [core::ptr::null()];
        sys_execve(b"/bin/boot_tester2\0".as_ptr(), argv.as_ptr(), envp.as_ptr());
        sys_exit(99);
    }
    let mut b = [0u8; 64];
    let fd = sys_open(path(&mut b, a, b"maps").as_ptr(), O_RDONLY, 0);
    let mut before = [0u8; 2048];
    let n1 = sys_pread64(fd as i32, before.as_mut_ptr(), before.len() as u64, 0);
    sys_write(p[1] as u64, b"x".as_ptr(), 1);
    let mut st = 0i32;
    sys_wait4(a, &mut st, 0, 0);
    let mut after = [0u8; 2048];
    let n2 = sys_pread64(fd as i32, after.as_mut_ptr(), after.len() as u64, 0);
    sys_close(fd as u64);
    sys_close(p[0] as u64);
    sys_close(p[1] as u64);
    let same = n2 == n1 && (0..n1.max(0) as usize).all(|i| before[i] == after[i]);
    // Linux: ESRCH once the old address space is gone, EOF while it is
    // being torn down; hk keeps it alive and shows the old image
    const ESRCH: i64 = -3;
    let ok = fd >= 0 && n1 > 0 && (n2 == 0 || n2 == ESRCH || same) && (st >> 8) & 0xff == 123;
    report(b"PROC_MAPS_AFTER_EXEC", ok, n2);
}

