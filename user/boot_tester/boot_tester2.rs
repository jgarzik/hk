//! boot_tester2 - Minimal execve validation program
//!
//! This program is executed by boot_tester via execve() to verify
//! that exec works correctly. It prints some diagnostic info and
//! exits with status 123, which the parent process validates.
//!
//! `boot_tester2 fdcheck`: exit 0 if fd 10 is closed (it was
//! close-on-exec) and fd 11 is open, else a nonzero code.

#![no_std]
#![no_main]

use core::ffi::c_void;
use core::panic::PanicInfo;

use hk_syscall::{sys_exit, sys_fcntl, sys_getpid, sys_getppid, sys_write};

/// Print a string to stdout
fn print(s: &[u8]) {
    sys_write(1, s.as_ptr(), s.len() as u64);
}

/// Print a string followed by newline
fn println(s: &[u8]) {
    print(s);
    print(b"\n");
}

/// Print a number in decimal
fn print_num(n: i64) {
    if n < 0 {
        print(b"-");
        print_num(-n);
        return;
    }
    if n >= 10 {
        print_num(n / 10);
    }
    let digit = b'0' + (n % 10) as u8;
    sys_write(1, &digit as *const u8, 1);
}

/// Process entry: pass the initial stack pointer (argc, argv...) on
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "xor ebp, ebp",
        "mov rdi, rsp",
        "and rsp, -16",
        "call {main}",
        "ud2",
        main = sym rust_start,
    )
}

#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov x29, xzr",
        "mov x30, xzr",
        "mov x0, sp",
        "bl {main}",
        "brk 0",
        main = sym rust_start,
    )
}

/// argv[1] as bytes (without NUL), if present
fn arg1(sp: *const u64) -> &'static [u8] {
    unsafe {
        if *sp < 2 {
            return b"";
        }
        let p = *sp.add(2) as *const u8;
        // volatile: a plain loop becomes a strlen call (no libc here)
        let mut n = 0;
        while n < 64 && core::ptr::read_volatile(p.add(n)) != 0 {
            n += 1;
        }
        core::slice::from_raw_parts(p, n)
    }
}

/// fdcheck mode: fd 10 must be gone after exec, fd 11 must remain
fn fdcheck() -> ! {
    const F_GETFD: i32 = 1;
    const EBADF: i64 = -9;
    if sys_fcntl(10, F_GETFD, 0) != EBADF {
        sys_exit(1);
    }
    if sys_fcntl(11, F_GETFD, 0) != 0 {
        sys_exit(2);
    }
    sys_exit(0);
}

extern "C" fn rust_start(sp: *const u64) -> ! {
    if arg1(sp) == b"fdcheck" {
        fdcheck();
    }

    // Print marker that we're running in boot_tester2
    println(b"EXEC_CHILD: Hello from boot_tester2!");

    // Print our PID
    let pid = sys_getpid();
    print(b"EXEC_CHILD: My PID is ");
    print_num(pid);
    println(b"");

    // Print our parent PID
    let ppid = sys_getppid();
    print(b"EXEC_CHILD: My parent PID is ");
    print_num(ppid);
    println(b"");

    // Exit with magic exit code 123 so parent can verify
    println(b"EXEC_CHILD: Exiting with status 123");
    sys_exit(123);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    println(b"PANIC in boot_tester2!");
    sys_exit(1);
}

// Compiler intrinsics required for no_std
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dest: *mut c_void, c: i32, n: usize) -> *mut c_void {
    let d = dest as *mut u8;
    unsafe {
        let mut i = 0;
        while i < n {
            *d.add(i) = c as u8;
            i += 1;
        }
    }
    dest
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    let d = dest as *mut u8;
    let s = src as *const u8;
    unsafe {
        let mut i = 0;
        while i < n {
            *d.add(i) = *s.add(i);
            i += 1;
        }
    }
    dest
}
