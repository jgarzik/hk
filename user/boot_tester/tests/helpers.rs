//! Shared test utilities for boot_tester modules

use hk_syscall::sys_write;

pub const STDOUT: u64 = 1;

/// Print a byte slice to stdout
pub fn print(s: &[u8]) {
    sys_write(STDOUT, s.as_ptr(), s.len() as u64);
}

/// Print a byte slice followed by newline
pub fn println(s: &[u8]) {
    print(s);
    print(b"\n");
}

/// Print a number in decimal
pub fn print_num(n: i64) {
    if n < 0 {
        print(b"-");
        print_num(-n);
        return;
    }
    if n >= 10 {
        print_num(n / 10);
    }
    let digit = b'0' + (n % 10) as u8;
    sys_write(STDOUT, &digit as *const u8, 1);
}

/// Print a NUL-terminated C string (stops at first NUL byte)
pub fn print_cstr(s: &[u8]) {
    let len = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    sys_write(STDOUT, s.as_ptr(), len as u64);
}

/// Check if slice starts with prefix
pub fn starts_with(slice: &[u8], prefix: &[u8]) -> bool {
    if slice.len() < prefix.len() {
        return false;
    }
    let mut i = 0;
    while i < prefix.len() {
        if slice[i] != prefix[i] {
            return false;
        }
        i += 1;
    }
    true
}

