//! reboot(2) Ctrl-Alt-Del modes (run on hk and real Linux)
//!
//! - REBOOT_CAD: LINUX_REBOOT_CMD_CAD_OFF and CAD_ON succeed and set
//!   kernel.ctrl-alt-del to 0 and 1; kernel.cad_pid names init (1);
//!   kernel.ctrl-alt-del is an int, read back as written (2); the mode
//!   that was set before is put back

use crate::harness::verdict;
use crate::proc::sysctl::{read_file, write_file};
use hk_syscall::sys_reboot_ret;

const MAGIC1: u64 = 0xfee1_dead;
const MAGIC2: u64 = 0x2812_1969;
const CAD_ON: u64 = 0x89ab_cdef;
const CAD_OFF: u64 = 0;
const CTRL_ALT_DEL: &[u8] = b"/proc/sys/kernel/ctrl-alt-del\0";
const CAD_PID: &[u8] = b"/proc/sys/kernel/cad_pid\0";

pub fn run_tests() {
    let r = cad();
    verdict(b"REBOOT_CAD", r == 0, r);
}

/// The first byte of `path`'s text, or 0
fn first(path: &[u8]) -> u8 {
    let mut b = [0u8; 16];
    if read_file(path, &mut b) > 0 { b[0] } else { 0 }
}

fn cad() -> i64 {
    let was = first(CTRL_ALT_DEL);
    if was != b'0' && was != b'1' {
        return 1;
    }
    if sys_reboot_ret(MAGIC1, MAGIC2, CAD_OFF) != 0 {
        return 2;
    }
    if first(CTRL_ALT_DEL) != b'0' {
        return 3;
    }
    if sys_reboot_ret(MAGIC1, MAGIC2, CAD_ON) != 0 {
        return 4;
    }
    if first(CTRL_ALT_DEL) != b'1' {
        return 5;
    }
    let mut b = [0u8; 16];
    let n = read_file(CAD_PID, &mut b);
    let mut r = if n != 2 || &b[..2] != b"1\n" { 6 } else { 0 };
    // Linux C_A_D is an int (proc_dointvec): any value reads back
    if r == 0 {
        write_file(CTRL_ALT_DEL, b"2");
        if first(CTRL_ALT_DEL) != b'2' {
            r = 7;
        }
    }
    write_file(CTRL_ALT_DEL, if was == b'1' { b"1" } else { b"0" });
    r
}
