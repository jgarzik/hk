//! tracefs (Linux fs/tracefs, kernel/trace/trace.c)
//!
//! - TRACEFS_TRACE: /sys/kernel/tracing is the directory to mount
//!   tracefs on; mounted, statfs shows TRACEFS_MAGIC and the `trace`
//!   file starts with the nop tracer's header

use crate::harness::{R, check, report_r};
use crate::helpers::{host_mode, read_file, skip};
use hk_syscall::{LinuxStatFs, sys_mount, sys_statfs, sys_umount2};

const NAME: &[u8] = b"TRACEFS_TRACE";
const MP: &[u8] = b"/sys/kernel/tracing\0";
const TRACEFS_MAGIC: i64 = 0x7472_6163;
const ENODEV: i64 = -19;
const ENOENT: i64 = -2;
const HEADER: &[u8] = b"# tracer: nop\n#\n# entries-in-buffer/entries-written: ";

pub fn run_tests() {
    let r = sys_mount(
        b"nodev\0".as_ptr(),
        MP.as_ptr(),
        b"tracefs\0".as_ptr(),
        0,
        0,
    );
    if (r == ENODEV || r == ENOENT) && host_mode() {
        skip(NAME, b"host kernel without tracefs");
        return;
    }
    let res = mounted(r);
    if r == 0 {
        sys_umount2(MP.as_ptr(), 0);
    }
    report_r(NAME, res);
}

fn mounted(r: i64) -> R {
    check(b"mount", r == 0, r)?;
    let mut st = LinuxStatFs::default();
    let s = sys_statfs(MP.as_ptr(), &mut st);
    check(b"statfs", s == 0, s)?;
    check(b"f_type", st.f_type == TRACEFS_MAGIC, st.f_type)?;
    let mut buf = [0u8; 256];
    let n = read_file(b"/sys/kernel/tracing/trace\0", &mut buf);
    check(b"read", n >= HEADER.len() as i64, n)?;
    check(b"header", buf.starts_with(HEADER), n)
}
