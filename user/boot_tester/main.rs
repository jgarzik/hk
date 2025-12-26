//! Boot tester - Thin orchestrator for kernel test suite
//!
//! Calls modular test runners in tests/ directory

#![no_std]
#![no_main]

use core::panic::PanicInfo;

// Test modules
mod tests;

use hk_syscall::{sys_exit, sys_reboot, LINUX_REBOOT_CMD_POWER_OFF, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2};
use tests::helpers::{println, print};

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    println(b"=== hk Boot Tester ===");
    println(b"");

    // Run all test categories
    tests::run_all_tests();

    // Print final marker
    println(b"");
    println(b"BOOT_COMPLETE");

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
pub unsafe extern "C" fn memset(dest: *mut u8, c: i32, n: usize) -> *mut u8 {
    unsafe {
        let mut i = 0;
        while i < n {
            *dest.add(i) = c as u8;
            i += 1;
        }
        dest
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    unsafe {
        let mut i = 0;
        while i < n {
            *dest.add(i) = *src.add(i);
            i += 1;
        }
        dest
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    unsafe {
        if src < dest as *const u8 {
            let mut i = n;
            while i > 0 {
                i -= 1;
                *dest.add(i) = *src.add(i);
            }
        } else {
            let mut i = 0;
            while i < n {
                *dest.add(i) = *src.add(i);
                i += 1;
            }
        }
        dest
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    unsafe {
        let mut i = 0;
        while i < n {
            let a = *s1.add(i);
            let b = *s2.add(i);
            if a != b {
                return a as i32 - b as i32;
            }
            i += 1;
        }
        0
    }
}
