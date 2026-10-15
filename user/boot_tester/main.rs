//! Boot tester - Thin orchestrator for kernel test suite
//!
//! Calls modular test runners in tests/ directory

#![no_std]
#![no_main]

use core::ffi::c_void;
use core::panic::PanicInfo;

// Test modules
mod tests;

use hk_syscall::{sys_exit, sys_exit_group, sys_getpid, sys_reboot, LINUX_REBOOT_CMD_POWER_OFF, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2};
use tests::helpers::{fail_count, host_mode, host_setup, init_host_mode, loopback_up, println, print, print_num};

/// Process entry: the kernel enters with a 16-byte aligned sp and no return
/// address, so realign per the C ABI before calling into Rust.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "xor ebp, ebp",
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
        "bl {main}",
        "brk 0",
        main = sym rust_start,
    )
}

extern "C" fn rust_start() -> ! {
    init_host_mode();

    println(b"=== hk Boot Tester ===");
    if host_mode() {
        println(b"(host mode: running on a non-hk kernel)");
        host_setup();
    }
    loopback_up();
    println(b"");

    // Run all test categories
    tests::run_all_tests();

    // Print final marker
    println(b"");
    println(b"BOOT_COMPLETE");

    if host_mode() {
        print(b"Host mode: ");
        print_num(fail_count() as i64);
        println(b" failed checks"); // must not itself contain "FAIL"
        // Not init (run directly on a host): report via exit status
        if sys_getpid() != 1 {
            sys_exit_group((fail_count() != 0) as u64);
        }
    }

    // Shutdown the system via ACPI S5
    println(b"Powering off...");
    sys_reboot(LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, LINUX_REBOOT_CMD_POWER_OFF)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    print(b"PANIC!");
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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    let d = dest as *mut u8;
    let s = src as *const u8;
    unsafe {
        if s < d as *const u8 {
            let mut i = n;
            while i > 0 {
                i -= 1;
                *d.add(i) = *s.add(i);
            }
        } else {
            let mut i = 0;
            while i < n {
                *d.add(i) = *s.add(i);
                i += 1;
            }
        }
    }
    dest
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(s1: *const c_void, s2: *const c_void, n: usize) -> i32 {
    let p1 = s1 as *const u8;
    let p2 = s2 as *const u8;
    unsafe {
        let mut i = 0;
        while i < n {
            let a = *p1.add(i);
            let b = *p2.add(i);
            if a != b {
                return a as i32 - b as i32;
            }
            i += 1;
        }
        0
    }
}

// Newer LLVM lowers equality-only memcmp to bcmp
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bcmp(s1: *const c_void, s2: *const c_void, n: usize) -> i32 {
    unsafe { memcmp(s1, s2, n) }
}
