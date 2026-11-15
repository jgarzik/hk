//! /proc/ioports (Linux kernel/resource.c ioports_proc_show)
//!
//! - PROC_IOPORTS: on x86 the two legacy serial ports' registers show
//!   (at any depth) as "03f8-03ff : serial" and "02f8-02ff : serial" (Linux
//!   serial8250_request_std_resource), the PC's legacy ranges as
//!   reserve_standard_io_resources names them ("0020-0021 : pic1"); a
//!   file opened without CAP_SYS_ADMIN shows every range as 0000-0000,
//!   one opened with it the ranges, whoever reads it (Linux r_show:
//!   file_ns_capable, the opener's credentials)

use crate::harness::verdict_detail;
use crate::helpers::{read_file, skip};
use hk_syscall::{
    CapUserData, CapUserHeader, O_RDONLY, sys_capget, sys_capset, sys_close, sys_exit, sys_fork,
    sys_open, sys_read, sys_wait4,
};

const CAP_SYS_ADMIN: u32 = 21;

/// A line without its depth's indent
fn trim(l: &[u8]) -> &[u8] {
    &l[l.iter().take_while(|&&c| c == b' ').count()..]
}

pub fn run_tests() {
    if !cfg!(target_arch = "x86_64") {
        return skip(b"PROC_IOPORTS", b"no legacy I/O ports");
    }
    let mut buf = [0u8; 4096];
    let n = read_file(b"/proc/ioports\0", &mut buf).max(0) as usize;
    let text = &buf[..n];
    // At any depth (Linux nests them in the PCI root bus's windows
    // from ACPI _CRS; without those they are top level)
    let has = |l: &[u8]| text.split(|&c| c == b'\n').any(|x| trim(x) == l);
    let mut bad = 0;
    for (i, l) in [
        &b"03f8-03ff : serial"[..],
        b"02f8-02ff : serial",
        b"0020-0021 : pic1",
        b"0040-0043 : timer0",
    ]
    .iter()
    .enumerate()
    {
        if bad == 0 && !has(l) {
            bad = i as i64 + 1;
        }
    }
    if bad == 0 {
        bad = unprivileged();
    }
    verdict_detail(b"PROC_IOPORTS", bad == 0, bad);
}

/// In a child without CAP_SYS_ADMIN: the serial range shows zeroed in
/// a file it opens, but not in one opened before it dropped the
/// capability; 0, else 10 + the failing step
fn unprivileged() -> i64 {
    let early = sys_open(b"/proc/ioports\0".as_ptr(), O_RDONLY, 0);
    if early < 0 {
        return 9;
    }
    let pid = sys_fork();
    if pid == 0 {
        let mut h = CapUserHeader {
            version: 0x2008_0522,
            pid: 0,
        };
        let mut d = [CapUserData::default(); 2];
        if sys_capget(&mut h, d.as_mut_ptr()) != 0 {
            sys_exit(1);
        }
        d[0].effective &= !(1 << CAP_SYS_ADMIN);
        if sys_capset(&h, d.as_ptr()) != 0 {
            sys_exit(2);
        }
        let mut buf = [0u8; 4096];
        let n = read_file(b"/proc/ioports\0", &mut buf).max(0) as usize;
        let text = &buf[..n];
        let zeroed = text
            .split(|&c| c == b'\n')
            .any(|x| trim(x) == b"0000-0000 : serial");
        let shown = text
            .split(|&c| c == b'\n')
            .any(|x| trim(x) == b"03f8-03ff : serial");
        if !zeroed || shown {
            sys_exit(3);
        }
        // The opener's capability, not the reader's
        let mut buf = [0u8; 4096];
        let n = sys_read(early as u64, buf.as_mut_ptr(), buf.len() as u64).max(0) as usize;
        let opener = buf[..n]
            .split(|&c| c == b'\n')
            .any(|x| trim(x) == b"03f8-03ff : serial");
        sys_exit(if opener { 0 } else { 4 });
    }
    sys_close(early as u64);
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    if st == 0 { 0 } else { 10 + i64::from(st >> 8) }
}
