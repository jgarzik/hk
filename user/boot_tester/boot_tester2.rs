//! boot_tester2 - Minimal execve validation program
//!
//! This program is executed by boot_tester via execve() to verify
//! that exec works correctly. It prints some diagnostic info and
//! exits with status 123, which the parent process validates.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use hk_syscall::{sys_exit, sys_getpid, sys_getppid, sys_write};

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

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
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
pub unsafe extern "C" fn memset(dest: *mut u8, c: i32, n: usize) -> *mut u8 {
    unsafe {
        let mut i = 0;
        while i < n {
            *dest.add(i) = c as u8;
            i += 1;
        }
    }
    dest
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    unsafe {
        let mut i = 0;
        while i < n {
            *dest.add(i) = *src.add(i);
            i += 1;
        }
    }
    dest
}
