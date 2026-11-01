//! /proc/<pid>/{stat,status,cmdline,environ} (Linux fs/proc/array.c,
//! fs/proc/base.c), checked against the syscalls on both kernels:
//! stat's 52 fields, status lines, the argument and environment strings
//! of an exec'd child, and environ's access rule (mode 0400 owned by
//! the task, plus ptrace-read access; cmdline is world-readable)
//!
//! PROC_COMM_RAW: a name with a byte >= 0x80 (PR_SET_NAME "\xe9x") shows
//! as that raw byte in stat's (comm) and status's Name: (Linux
//! proc_task_name), not re-encoded

use super::exec_identity::proc_path;
use super::helpers::{print, print_num, println};
use hk_syscall::{
    O_RDONLY, Timespec, sys_clock_gettime, sys_close, sys_dup3, sys_execve, sys_exit, sys_fork,
    sys_getpgid, sys_getpid, sys_getppid, sys_getsid, sys_getuid, sys_kill, sys_open, sys_pipe2,
    sys_prctl, sys_read, sys_setresgid, sys_setresuid, sys_wait4,
};

const PR_GET_NAME: i32 = 16;
const CLOCK_MONOTONIC: i32 = 1;
const SIGKILL: u32 = 9;
const EACCES: i64 = -13;
const UID: u32 = 1000;

pub fn run_tests() {
    stat_self();
    status_self();
    exec_child();
    environ_perm();
    comm_raw();
}

/// In a child: name it "\xe9x", then find the raw bytes in stat and
/// status; exit status is the failed step
fn comm_raw() {
    const PR_SET_NAME: i32 = 15;
    let pid = sys_fork();
    if pid == 0 {
        let name = b"\xe9x\0";
        sys_prctl(PR_SET_NAME, name.as_ptr() as u64, 0, 0, 0);
        let mut buf = [0u8; 2048];
        let n = slurp(b"/proc/self/stat\0", &mut buf);
        if n <= 0 || !buf[..n as usize].windows(4).any(|w| w == b"(\xe9x)") {
            sys_exit(1);
        }
        let n = slurp(b"/proc/self/status\0", &mut buf);
        if n <= 0 || !buf[..n as usize].windows(9).any(|w| w == b"Name:\t\xe9x\n") {
            sys_exit(2);
        }
        sys_exit(0);
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    verdict(b"PROC_COMM_RAW", st == 0, (st >> 8) as i64);
}

fn verdict(name: &[u8], ok: bool, got: i64) {
    print(name);
    if ok {
        println(b":OK");
    } else {
        print(b":FAIL got ");
        print_num(got);
        println(b"");
    }
}

/// Read a whole file into `buf`: its length, or the open/read errno
fn slurp(path: &[u8], buf: &mut [u8]) -> i64 {
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        return fd;
    }
    let mut len = 0;
    while len < buf.len() {
        let n = sys_read(fd as u64, buf[len..].as_mut_ptr(), (buf.len() - len) as u64);
        if n < 0 {
            sys_close(fd as u64);
            return n;
        }
        if n == 0 {
            break;
        }
        len += n as usize;
    }
    sys_close(fd as u64);
    len as i64
}

/// Decimal value at the start of `s` (a leading '-' allowed)
fn num(s: &[u8]) -> i64 {
    let (neg, s) = match s.first() {
        Some(b'-') => (true, &s[1..]),
        _ => (false, s),
    };
    let mut v = 0i64;
    for &c in s.iter().take_while(|c| c.is_ascii_digit()) {
        v = v * 10 + (c - b'0') as i64;
    }
    if neg { -v } else { v }
}

/// This task's name (PR_GET_NAME), without the NUL
fn my_comm(out: &mut [u8; 16]) -> usize {
    sys_prctl(PR_GET_NAME, out.as_mut_ptr() as u64, 0, 0, 0);
    out.iter().position(|&b| b == 0).unwrap_or(16)
}

/// Clock ticks (USER_HZ) since boot
fn now_ticks() -> i64 {
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    sys_clock_gettime(CLOCK_MONOTONIC, &mut ts);
    ts.tv_sec * 100 + ts.tv_nsec / 10_000_000
}

/// stat of this process: `pid (comm) state` then 49 more fields
fn stat_self() {
    let mut buf = [0u8; 1024];
    let n = slurp(b"/proc/self/stat\0", &mut buf);
    if n <= 0 {
        verdict(b"PROC_PID_STAT", false, n);
        return;
    }
    let text = &buf[..n as usize];
    let open = text.iter().position(|&b| b == b'(').unwrap_or(0);
    let close = text.iter().rposition(|&b| b == b')').unwrap_or(0);
    let mut comm = [0u8; 16];
    let cn = my_comm(&mut comm);
    let comm_ok = close > open && text[open + 1..close] == comm[..cn];
    // Fields after ") ": state is field 3
    let rest = &text[(close + 2).min(text.len())..];
    let f: alloc_free::Fields = alloc_free::split(rest);
    let field = |k: usize| f.get(k - 3);
    let mut bad = 0;
    let checks: [(bool, i64); 9] = [
        (num(text) == sys_getpid(), 1),
        (comm_ok, 2),
        (field(3).first() == Some(&b'R'), 3),
        (num(field(4)) == sys_getppid(), 4),
        (num(field(5)) == sys_getpgid(0), 5),
        (num(field(6)) == sys_getsid(0), 6),
        (num(field(20)) == 1, 20),
        (num(field(22)) > 0 && num(field(22)) <= now_ticks() + 1, 22),
        (f.count + 2 == 52 && text.ends_with(b"\n"), 52),
    ];
    for (ok, id) in checks {
        if !ok && bad == 0 {
            bad = id;
        }
    }
    verdict(b"PROC_PID_STAT", bad == 0, bad);
}

/// Space-separated fields without an allocator
mod alloc_free {
    pub struct Fields<'a> {
        pub items: [&'a [u8]; 64],
        pub count: usize,
    }

    impl<'a> Fields<'a> {
        pub fn get(&self, i: usize) -> &'a [u8] {
            if i < self.count { self.items[i] } else { b"" }
        }
    }

    pub fn split(s: &[u8]) -> Fields<'_> {
        let mut f = Fields {
            items: [b""; 64],
            count: 0,
        };
        let s = s.strip_suffix(b"\n").unwrap_or(s);
        for w in s.split(|&b| b == b' ') {
            if f.count < 64 {
                f.items[f.count] = w;
                f.count += 1;
            }
        }
        f
    }
}

/// The value of status line `key` (after the tab)
fn status_line<'a>(text: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    text.split(|&b| b == b'\n')
        .find(|l| l.starts_with(key) && l.get(key.len()) == Some(&b':'))
        .map(|l| {
            let v = &l[key.len() + 1..];
            let skip = v.iter().take_while(|&&c| c == b'\t' || c == b' ').count();
            &v[skip..]
        })
}

/// status of this process: Name, Pid, PPid, Uid (all four), Threads,
/// VmRSS > 0
fn status_self() {
    let mut buf = [0u8; 4096];
    let n = slurp(b"/proc/self/status\0", &mut buf);
    if n <= 0 {
        verdict(b"PROC_PID_STATUS", false, n);
        return;
    }
    let t = &buf[..n as usize];
    let get = |k: &[u8]| status_line(t, k).unwrap_or(b"");
    let mut comm = [0u8; 16];
    let cn = my_comm(&mut comm);
    let uid = sys_getuid();
    let uids_ok = get(b"Uid").split(|&b| b == b'\t').all(|v| num(v) == uid)
        && get(b"Uid").split(|&b| b == b'\t').count() == 4;
    let checks: [(bool, i64); 7] = [
        (get(b"Name") == &comm[..cn], 1),
        (num(get(b"Pid")) == sys_getpid(), 2),
        (num(get(b"PPid")) == sys_getppid(), 3),
        (uids_ok, 4),
        (num(get(b"Threads")) == 1, 5),
        (num(get(b"VmRSS")) > 0 && get(b"VmRSS").ends_with(b" kB"), 6),
        (get(b"State").starts_with(b"R (running)"), 7),
    ];
    let bad = checks.iter().find(|c| !c.0).map_or(0, |c| c.1);
    verdict(b"PROC_PID_STATUS", bad == 0, bad);
}

/// A child exec'd as `boot_tester2 sleep "a b"` with a known
/// environment, ready (it wrote to fd 3) when this returns
fn spawn_sleeper(uid: Option<u32>) -> i64 {
    let mut p = [0i32; 2];
    sys_pipe2(p.as_mut_ptr(), 0);
    let pid = sys_fork();
    if pid == 0 {
        if let Some(u) = uid {
            sys_setresgid(u, u, u);
            sys_setresuid(u, u, u);
        }
        sys_dup3(p[1], 3, 0);
        let argv: [*const u8; 4] = [
            b"boot_tester2\0".as_ptr(),
            b"sleep\0".as_ptr(),
            b"a b\0".as_ptr(),
            core::ptr::null(),
        ];
        let envp: [*const u8; 3] = [
            b"HK_PROC=env42\0".as_ptr(),
            b"X=1\0".as_ptr(),
            core::ptr::null(),
        ];
        sys_execve(
            b"/bin/boot_tester2\0".as_ptr(),
            argv.as_ptr(),
            envp.as_ptr(),
        );
        sys_exit(99);
    }
    let mut b = [0u8; 1];
    sys_read(p[0] as u64, b.as_mut_ptr(), 1);
    sys_close(p[0] as u64);
    sys_close(p[1] as u64);
    pid
}

fn reap(pid: i64) {
    sys_kill(pid, SIGKILL);
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
}

const ARGS: &[u8] = b"boot_tester2\0sleep\0a b\0";
const ENV: &[u8] = b"HK_PROC=env42\0X=1\0";

/// cmdline and environ of an exec'd child are its argv and envp
/// strings; stat names it after the file
fn exec_child() {
    let pid = spawn_sleeper(None);
    let mut buf = [0u8; 256];
    let n = slurp(&proc_path(pid, b"cmdline\0"), &mut buf);
    verdict(b"PROC_PID_CMDLINE", n > 0 && &buf[..n as usize] == ARGS, n);
    let n = slurp(&proc_path(pid, b"environ\0"), &mut buf);
    verdict(b"PROC_PID_ENVIRON", n > 0 && &buf[..n as usize] == ENV, n);
    // The child may still be on its way to sleep on another CPU after
    // its write: give it up to a second to show S
    let want = b" (boot_tester2) S ";
    let (mut ok, mut n) = (false, 0);
    for _ in 0..100 {
        n = slurp(&proc_path(pid, b"stat\0"), &mut buf);
        ok = n > 0 && buf[..n as usize].windows(want.len()).any(|w| w == want);
        if ok {
            break;
        }
        let ts = hk_syscall::Timespec {
            tv_sec: 0,
            tv_nsec: 10_000_000,
        };
        hk_syscall::sys_nanosleep(&ts, core::ptr::null_mut());
    }
    verdict(b"PROC_PID_STAT_CHILD", ok, n);
    reap(pid);
}

/// environ of a uid-1000 process: readable by uid 1000, EACCES for uid
/// 1001; its cmdline is readable by both
fn environ_perm() {
    let pid = spawn_sleeper(Some(UID));
    static mut PID: i64 = 0;
    unsafe { PID = pid };
    let as_uid = |uid: u32, what: &'static [u8]| -> i32 {
        static mut WHAT: &[u8] = b"";
        unsafe { WHAT = what };
        let c = sys_fork();
        if c == 0 {
            sys_setresgid(uid, uid, uid);
            sys_setresuid(uid, uid, uid);
            let mut buf = [0u8; 256];
            let n = slurp(&proc_path(unsafe { PID }, unsafe { WHAT }), &mut buf);
            sys_exit(match n {
                EACCES => 1,
                n if n > 0 => 0,
                _ => 2,
            });
        }
        let mut st = 0;
        sys_wait4(c, &mut st, 0, 0);
        (st >> 8) & 0xff
    };
    let same = as_uid(UID, b"environ\0");
    let other = as_uid(UID + 1, b"environ\0");
    let cmd = as_uid(UID + 1, b"cmdline\0");
    reap(pid);
    let ok = same == 0 && other == 1 && cmd == 0;
    verdict(
        b"PROC_PID_ENVIRON_PERM",
        ok,
        (same * 100 + other * 10 + cmd) as i64,
    );
}
