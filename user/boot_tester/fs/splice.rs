//! splice limits (Linux fs/splice.c)
//!
//! Tests:
//! - SPLICE_PIPE_FILE_SHORT: a pipe-to-file splice shorter than the pipe
//!   buffer leaves the rest in the pipe (iter_file_splice_write)

use crate::harness::T;
use hk_syscall::{
    O_CREAT, O_RDWR, O_TRUNC, sys_close, sys_open, sys_pipe2, sys_pread64, sys_pwrite64,
    sys_splice, sys_unlink, sys_write,
};

const DST: &[u8] = b"/splice_dst\0";

pub fn run_tests() {
    pipe_file_short();
    sys_unlink(DST.as_ptr());
}

/// A fresh file at `path` holding `data`, open read-write (plus `extra`
/// flags)
fn file(path: &[u8], data: &[u8], extra: u32) -> i32 {
    let fd = sys_open(path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC | extra, 0o600) as i32;
    if fd >= 0 && !data.is_empty() {
        sys_pwrite64(fd, data.as_ptr(), data.len() as u64, 0);
    }
    fd
}

fn close(fd: i32) {
    sys_close(fd as u64);
}

fn pipe() -> [i32; 2] {
    let mut p = [-1i32; 2];
    sys_pipe2(p.as_mut_ptr(), 0);
    p
}

fn pipe_file_short() {
    let mut t = T::new(b"SPLICE_PIPE_FILE_SHORT");
    let null = core::ptr::null_mut();
    let p = pipe();
    let out = file(DST, b"", 0);
    sys_write(p[1] as u64, b"ABCDEFGH".as_ptr(), 8);
    close(p[1]);
    t.eq(b"first", sys_splice(p[0], null, out, null, 3, 0), 3);
    // The writer is gone: the rest, then EOF
    t.eq(b"second", sys_splice(p[0], null, out, null, 100, 0), 5);
    let mut buf = [0u8; 16];
    let n = sys_pread64(out, buf.as_mut_ptr(), 16, 0);
    t.ok(b"file", n == 8 && &buf[..8] == b"ABCDEFGH", n);
    close(p[0]);
    close(out);
    t.done();
}
