//! Process startup ABI a static glibc program relies on: the initial
//! stack and auxiliary vector and /proc/self/exe.

use super::helpers::{print, print_num, println};
use hk_syscall::{sys_execve, sys_exit, sys_fork, sys_wait4};

pub fn run_tests() {
    test_exec_mode(b"EXEC_AUXV", b"auxv\0");
    test_exec_mode(b"PROC_SELF_EXE", b"exe\0");
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

/// Exit status of a child running `f`
fn in_child(f: fn() -> !) -> i32 {
    let pid = sys_fork();
    if pid == 0 {
        f();
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    st
}

/// `/bin/boot_tester2 <mode>` exits 0 when its checks pass
fn test_exec_mode(name: &[u8], mode: &'static [u8]) {
    static mut MODE: &[u8] = b"";
    unsafe { MODE = mode };
    let st = in_child(|| {
        let argv: [*const u8; 3] = [
            b"boot_tester2\0".as_ptr(),
            unsafe { MODE }.as_ptr(),
            core::ptr::null(),
        ];
        let envp: [*const u8; 2] = [b"HK=1\0".as_ptr(), core::ptr::null()];
        sys_execve(b"/bin/boot_tester2\0".as_ptr(), argv.as_ptr(), envp.as_ptr());
        sys_exit(99);
    });
    report(name, st == 0, (st >> 8) as i64);
}
