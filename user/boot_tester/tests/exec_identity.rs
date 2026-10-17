//! A task's name and dumpability across fork and exec (Linux
//! begin_new_exec, copy_process / dup_mm): fork inherits both; exec
//! names the task after the file and makes it dumpable again unless its
//! effective ids differ from its real ones or it may not read the file
//! (would_dump): an execute-only program cannot be attached to or read
//! through /proc by its own uid

use super::helpers::{print, print_num, println};
use hk_syscall::{
    O_CREAT, O_RDONLY, O_TRUNC, O_WRONLY, sys_chmod, sys_close, sys_dup3, sys_execve, sys_exit,
    sys_fork, sys_kill, sys_open, sys_pipe2, sys_prctl, sys_ptrace, sys_read, sys_setresgid,
    sys_setresuid, sys_unlink, sys_wait4, sys_write,
};

const PR_SET_DUMPABLE: i32 = 4;
const PR_GET_DUMPABLE: i32 = 3;
const PR_SET_NAME: i32 = 15;
const PR_GET_NAME: i32 = 16;
const UID: u32 = 1000;

pub fn run_tests() {
    report(b"COMM_EXEC", in_child(|| exec(b"comm\0")), 0);
    report(b"COMM_FORK", in_child(comm_fork), 0);
    report(b"DUMPABLE_FORK", in_child(dumpable_fork), 0);
    // exec of a plain file with all ids equal: dumpable (1) again
    report(b"DUMPABLE_EXEC", in_child(dumpable_exec), 1);
    // euid differs from the real uid: stays non-dumpable (0)
    report(b"DUMPABLE_EXEC_EUID", in_child(dumpable_exec_euid), 0);
    // An image its uid may read is open to it; an execute-only one not
    let bin = b"/bin/boot_tester2\0";
    let ok = copy(bin, XONLY, 0o711) && copy(bin, READ, 0o755);
    if ok {
        report(b"DUMPABLE_EXEC_READABLE", in_child(|| probe_exec(READ)), 0);
        report(b"DUMPABLE_EXEC_XONLY", in_child(|| probe_exec(XONLY)), 1);
    } else {
        report(b"DUMPABLE_EXEC_COPY", 1 << 8, 0);
    }
    sys_unlink(XONLY.as_ptr());
    sys_unlink(READ.as_ptr());
    // A failed exec changes neither; a good one makes it dumpable (1)
    if write_bad_elf() {
        report(b"EXEC_BAD_KEEPS_IDENTITY", in_child(fail_then_exec), 1);
    } else {
        report(b"EXEC_BAD_ELF_WRITE", 1 << 8, 0);
    }
    sys_unlink(BAD.as_ptr());
}

const BAD: &[u8] = b"/tmp/bt2_bad_elf\0";

/// An executable file with an ELF magic and nothing valid after it
fn write_bad_elf() -> bool {
    let fd = sys_open(BAD.as_ptr(), O_WRONLY | O_CREAT | O_TRUNC, 0o755);
    if fd < 0 {
        return false;
    }
    let mut img = [0u8; 128];
    img[..4].copy_from_slice(b"\x7fELF");
    let ok = sys_write(fd as u64, img.as_ptr(), img.len() as u64) == 128;
    sys_close(fd as u64);
    ok
}

/// Non-dumpable and named hk_keep: an exec that fails (ENOEXEC) must
/// leave both, then a good exec reports its dumpability (1); exit 2/3
/// if the failed exec changed the dumpability or the name
fn fail_then_exec() -> ! {
    sys_prctl(PR_SET_NAME, b"hk_keep\0".as_ptr() as u64, 0, 0, 0);
    sys_prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    let argv: [*const u8; 2] = [BAD.as_ptr(), core::ptr::null()];
    let envp: [*const u8; 1] = [core::ptr::null()];
    let r = sys_execve(BAD.as_ptr(), argv.as_ptr(), envp.as_ptr());
    if r != -8 || sys_prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0 {
        sys_exit(2);
    }
    let mut name = [0u8; 16];
    sys_prctl(PR_GET_NAME, name.as_mut_ptr() as u64, 0, 0, 0);
    if name[..8] != *b"hk_keep\0" {
        sys_exit(3);
    }
    exec(b"dumpable\0");
}

const XONLY: &[u8] = b"/tmp/bt2_xonly\0";
const READ: &[u8] = b"/tmp/bt2_read\0";
const PTRACE_ATTACH: i64 = 16;
const PTRACE_DETACH: i64 = 17;
const SIGKILL: u32 = 9;

/// Copy `from` to a new file `to` with `mode`
fn copy(from: &[u8], to: &[u8], mode: u32) -> bool {
    let src = sys_open(from.as_ptr(), O_RDONLY, 0);
    let dst = sys_open(to.as_ptr(), O_WRONLY | O_CREAT | O_TRUNC, 0o700);
    if src < 0 || dst < 0 {
        return false;
    }
    let mut buf = [0u8; 4096];
    let mut ok = true;
    loop {
        let n = sys_read(src as u64, buf.as_mut_ptr(), buf.len() as u64);
        if n <= 0 {
            ok &= n == 0;
            break;
        }
        ok &= sys_write(dst as u64, buf.as_ptr(), n as u64) == n;
    }
    sys_close(src as u64);
    sys_close(dst as u64);
    ok && sys_chmod(to.as_ptr(), mode) == 0
}

/// As uid 1000, run `prog` in a child (a descendant, so Linux's Yama
/// allows the attach), then open its maps and environ and attach to it:
/// exit 0 if all work, 1 if all are refused, else 2
fn probe_exec(prog: &'static [u8]) -> ! {
    static mut PROG: &[u8] = b"";
    unsafe { PROG = prog };
    sys_setresgid(UID, UID, UID);
    sys_setresuid(UID, UID, UID);
    let mut p = [0i32; 2];
    sys_pipe2(p.as_mut_ptr(), 0);
    let pid = sys_fork();
    if pid == 0 {
        sys_dup3(p[1], 3, 0);
        let argv: [*const u8; 3] = [
            b"boot_tester2\0".as_ptr(),
            b"sleep\0".as_ptr(),
            core::ptr::null(),
        ];
        let envp: [*const u8; 1] = [core::ptr::null()];
        sys_execve(unsafe { PROG }.as_ptr(), argv.as_ptr(), envp.as_ptr());
        sys_exit(99);
    }
    let mut b = [0u8; 1];
    let r = sys_read(p[0] as u64, b.as_mut_ptr(), 1);
    let opens = |what: &[u8]| {
        let fd = sys_open(proc_path(pid, what).as_ptr(), O_RDONLY, 0);
        if fd >= 0 {
            sys_close(fd as u64);
        }
        fd >= 0
    };
    let maps = opens(b"maps");
    let environ = opens(b"environ");
    let at = sys_ptrace(PTRACE_ATTACH, pid, 0, 0);
    if at == 0 {
        sys_ptrace(PTRACE_DETACH, pid, 0, 0);
    }
    sys_kill(pid, SIGKILL);
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    let code = match (r == 1, maps, environ, at == 0) {
        (true, true, true, true) => 0,
        (true, false, false, false) => 1,
        _ => 2,
    };
    sys_exit(code);
}

/// "/proc/<pid>/<what>\0" (no leading zeros: Linux takes none)
pub fn proc_path(pid: i64, what: &[u8]) -> [u8; 48] {
    let mut out = [0u8; 48];
    out[..6].copy_from_slice(b"/proc/");
    let mut digits = [0u8; 20];
    let (mut n, mut v) = (0, pid as u64);
    loop {
        digits[n] = b'0' + (v % 10) as u8;
        n += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let mut k = 6;
    for i in (0..n).rev() {
        out[k] = digits[i];
        k += 1;
    }
    out[k] = b'/';
    out[k + 1..k + 1 + what.len()].copy_from_slice(what);
    out
}

fn report(name: &[u8], st: i32, want: i32) {
    print(name);
    if st & 0x7f == 0 && (st >> 8) & 0xff == want {
        println(b":OK");
    } else {
        print(b":FAIL status ");
        print_num(st as i64);
        println(b"");
    }
}

/// Wait status of a child running `f`
fn in_child(f: fn() -> !) -> i32 {
    let pid = sys_fork();
    if pid == 0 {
        f();
    }
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    st
}

/// Run `/bin/boot_tester2 <mode>`
fn exec(mode: &[u8]) -> ! {
    let argv: [*const u8; 3] = [b"boot_tester2\0".as_ptr(), mode.as_ptr(), core::ptr::null()];
    let envp: [*const u8; 1] = [core::ptr::null()];
    sys_execve(
        b"/bin/boot_tester2\0".as_ptr(),
        argv.as_ptr(),
        envp.as_ptr(),
    );
    sys_exit(99);
}

/// A child keeps its parent's name
fn comm_fork() -> ! {
    sys_prctl(PR_SET_NAME, b"hk_comm\0".as_ptr() as u64, 0, 0, 0);
    let pid = sys_fork();
    if pid == 0 {
        let mut name = [0u8; 16];
        sys_prctl(PR_GET_NAME, name.as_mut_ptr() as u64, 0, 0, 0);
        let ok = name[..8] == *b"hk_comm\0";
        sys_exit(if ok { 0 } else { 1 });
    }
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    sys_exit(((st >> 8) & 0xff) as u64);
}

/// A child of a non-dumpable process is non-dumpable
fn dumpable_fork() -> ! {
    sys_prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(sys_prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) as u64);
    }
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    sys_exit(((st >> 8) & 0xff) as u64);
}

/// The uid change makes the task non-dumpable; exec undoes that
fn dumpable_exec() -> ! {
    sys_setresuid(UID, UID, UID);
    if sys_prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0 {
        sys_exit(2);
    }
    exec(b"dumpable\0");
}

/// With euid != uid, exec leaves the task non-dumpable
fn dumpable_exec_euid() -> ! {
    sys_setresuid(UID, 0, 0);
    exec(b"dumpable\0");
}
