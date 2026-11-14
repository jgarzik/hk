//! tracefs (Linux fs/tracefs, kernel/trace/trace.c)
//!
//! - TRACEFS_TRACE: /sys/kernel/tracing is the directory to mount
//!   tracefs on; mounted, statfs shows TRACEFS_MAGIC and the `trace`
//!   file starts with the nop tracer's header
//! - TRACEFS_TRUNC: `trace` opens for writing; with O_TRUNC it empties
//!   the buffer (entries 0/0), a write is accepted (Linux tracing_open,
//!   tracing_write_stub)

use crate::harness::{R, check, report_r};
use crate::helpers::{host_mode, read_file, skip};
use hk_syscall::{
    LinuxStatFs, O_TRUNC, O_WRONLY, sys_close, sys_mount, sys_open, sys_statfs, sys_umount2,
    sys_write,
};

const MP: &[u8] = b"/sys/kernel/tracing\0";
const TRACE: &[u8] = b"/sys/kernel/tracing/trace\0";
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
        skip(b"TRACEFS_TRACE", b"host kernel without tracefs");
        skip(b"TRACEFS_TRUNC", b"host kernel without tracefs");
        return;
    }
    report_r(b"TRACEFS_TRACE", mounted(r));
    if r == 0 {
        report_r(b"TRACEFS_TRUNC", trunc());
        sys_umount2(MP.as_ptr(), 0);
    }
}

fn mounted(r: i64) -> R {
    check(b"mount", r == 0, r)?;
    let mut st = LinuxStatFs::default();
    let s = sys_statfs(MP.as_ptr(), &mut st);
    check(b"statfs", s == 0, s)?;
    check(b"f_type", st.f_type == TRACEFS_MAGIC, st.f_type)?;
    let mut buf = [0u8; 256];
    let n = read_file(TRACE, &mut buf);
    check(b"read", n >= HEADER.len() as i64, n)?;
    check(b"header", buf.starts_with(HEADER), n)
}

/// The `trace` file's entries-in-buffer/entries-written pair
pub fn entries() -> Option<(u64, u64)> {
    let mut buf = [0u8; 256];
    let n = read_file(TRACE, &mut buf);
    if n < HEADER.len() as i64 || !buf.starts_with(HEADER) {
        return None;
    }
    let rest = &buf[HEADER.len()..n as usize];
    let num = |s: &[u8]| -> (u64, usize) {
        let d = s.iter().take_while(|c| c.is_ascii_digit()).count();
        (
            s[..d].iter().fold(0, |v, c| v * 10 + u64::from(c - b'0')),
            d,
        )
    };
    let (a, d) = num(rest);
    if rest.get(d) != Some(&b'/') {
        return None;
    }
    let (b, _) = num(&rest[d + 1..]);
    Some((a, b))
}

/// Empty the buffer as `echo > trace` does: an O_TRUNC open for writing
pub fn truncate() -> i64 {
    let fd = sys_open(TRACE.as_ptr(), O_WRONLY | O_TRUNC, 0);
    if fd < 0 {
        return fd;
    }
    let w = sys_write(fd as u64, b"\n".as_ptr(), 1);
    sys_close(fd as u64);
    if w == 1 { 0 } else { w - 1000 }
}

fn trunc() -> R {
    let r = truncate();
    check(b"open-trunc+write", r == 0, r)?;
    let e = entries();
    check(
        b"entries",
        e == Some((0, 0)),
        e.map_or(-1, |(a, _)| a as i64),
    )
}
