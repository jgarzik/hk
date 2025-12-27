//! TTY tests
//!
//! Tests:
//! - Test vhangup with capability succeeds

use super::helpers::{print, print_num, println};
use hk_syscall::sys_vhangup;

/// Run all TTY tests
pub fn run_tests() {
    test_vhangup();
}

/// Test vhangup syscall
///
/// Running as init (root), we should have CAP_SYS_TTY_CONFIG,
/// so vhangup should succeed (return 0).
fn test_vhangup() {
    let ret = sys_vhangup();

    if ret == 0 {
        println(b"VHANGUP:OK");
    } else {
        print(b"VHANGUP:FAIL: returned ");
        print_num(ret);
        println(b"");
    }
}
