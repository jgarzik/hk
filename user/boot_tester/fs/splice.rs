//! splice, sendfile, vmsplice and copy_file_range limits (Linux
//! fs/splice.c, fs/read_write.c)
//!
//! Tests:
//! - SPLICE_PIPE_FILE_SHORT: a pipe-to-file splice shorter than the pipe
//!   buffer leaves the rest in the pipe (iter_file_splice_write)
//! - SPLICE_ARGS: unknown flags are EINVAL, an offset on a pipe-to-pipe
//!   splice is ESPIPE, an O_APPEND output is EINVAL, a file offset the
//!   splice would carry past the largest offset is EINVAL
//! - SENDFILE_ARGS: a zero count still checks the fds (EBADF), an
//!   offset the transfer would carry past the largest offset is EINVAL
//! - VMSPLICE_IOV: more than IOV_MAX segments and a length negative as
//!   ssize_t are EINVAL (import_iovec)
//! - COPY_FILE_RANGE_ARGS: a zero length still checks the fds (EBADF),
//!   a negative offset is EINVAL, an O_APPEND output is EBADF, an
//!   overlapping range of one file is EINVAL
//! - SPLICE_WAIT: a blocking splice (pipe to file, pipe to pipe) or tee
//!   on an empty pipe with a writer waits for data, and a blocking file
//!   to pipe splice on a full pipe waits for room (Linux
//!   splice_from_pipe_next, ipipe_prep, wait_for_space); to a pipe with
//!   no reader it is EPIPE (SIGPIPE ignored); nonblocking, tee on an
//!   empty pipe with a writer is EAGAIN and pipe to pipe from one with
//!   no writer is 0
//! - VMSPLICE_WAIT: vmsplice into a full pipe waits for room, into one
//!   with no reader is EPIPE (Linux wait_for_space), and takes a
//!   segment longer than a page whole (iter_to_pipe)

use crate::harness::T;
use hk_syscall::{
    IoVec, O_APPEND, O_CREAT, O_NONBLOCK, O_RDWR, O_TRUNC, SIG_DFL, SIG_IGN, SIGPIPE, Timespec,
    sys_close, sys_copy_file_range, sys_exit, sys_fcntl, sys_fork, sys_nanosleep, sys_open,
    sys_pipe2, sys_pread64, sys_pwrite64, sys_read, sys_rt_sigaction, sys_sendfile, sys_splice,
    sys_tee, sys_unlink, sys_vmsplice, sys_wait4, sys_write,
};

const SRC: &[u8] = b"/splice_src\0";
const DST: &[u8] = b"/splice_dst\0";
const EBADF: i64 = -9;
const EINVAL: i64 = -22;
const ESPIPE: i64 = -29;
const EAGAIN: i64 = -11;
const EPIPE: i64 = -32;
const SPLICE_F_NONBLOCK: u32 = 2;
const F_SETFL: i32 = 4;

pub fn run_tests() {
    pipe_file_short();
    splice_args();
    sendfile_args();
    vmsplice_iov();
    copy_file_range_args();
    splice_wait();
    vmsplice_wait();
    sys_unlink(SRC.as_ptr());
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

fn splice_args() {
    let mut t = T::new(b"SPLICE_ARGS");
    let null = core::ptr::null_mut();
    let a = pipe();
    let b = pipe();
    sys_write(a[1] as u64, b"xyz".as_ptr(), 3);
    t.eq(
        b"flags",
        sys_splice(a[0], null, b[1], null, 1, 0x10),
        EINVAL,
    );
    let mut off: i64 = 0;
    t.eq(
        b"p2p offset",
        sys_splice(a[0], &mut off, b[1], null, 1, 0),
        ESPIPE,
    );
    let app = file(DST, b"", O_APPEND);
    t.eq(b"append", sys_splice(a[0], null, app, null, 1, 0), EINVAL);
    close(app);
    let out = file(DST, b"", 0);
    let mut far: i64 = i64::MAX - 1;
    t.eq(
        b"far out",
        sys_splice(a[0], null, out, &mut far, 3, 0),
        EINVAL,
    );
    close(out);
    let src = file(SRC, b"data", 0);
    let mut far: i64 = i64::MAX - 1;
    t.eq(
        b"far in",
        sys_splice(src, &mut far, b[1], null, 3, 0),
        EINVAL,
    );
    close(src);
    for fd in [a[0], a[1], b[0], b[1]] {
        close(fd);
    }
    t.done();
}

fn sendfile_args() {
    let mut t = T::new(b"SENDFILE_ARGS");
    t.eq(
        b"zero count",
        sys_sendfile(-1, -1, core::ptr::null_mut(), 0),
        EBADF,
    );
    let src = file(SRC, b"data", 0);
    let out = file(DST, b"", 0);
    let mut far: i64 = i64::MAX - 1;
    t.eq(b"far", sys_sendfile(out, src, &mut far, 10), EINVAL);
    let mut off: i64 = 1;
    t.eq(b"ok", sys_sendfile(out, src, &mut off, 10), 3);
    t.eq(b"offset", off, 4);
    close(src);
    close(out);
    t.done();
}

fn vmsplice_iov() {
    let mut t = T::new(b"VMSPLICE_IOV");
    let p = pipe();
    let byte = 0u8;
    let iov = [IoVec {
        iov_base: &byte,
        iov_len: 1,
    }; 2];
    t.eq(
        b"iov_max",
        sys_vmsplice(p[1], iov.as_ptr(), 1025, 0),
        EINVAL,
    );
    let neg = [
        IoVec {
            iov_base: &byte,
            iov_len: 1,
        },
        IoVec {
            iov_base: &byte,
            iov_len: usize::MAX,
        },
    ];
    t.eq(b"neg len", sys_vmsplice(p[1], neg.as_ptr(), 2, 0), EINVAL);
    t.eq(b"ok", sys_vmsplice(p[1], iov.as_ptr(), 2, 0), 2);
    close(p[0]);
    close(p[1]);
    t.done();
}

fn copy_file_range_args() {
    let mut t = T::new(b"COPY_FILE_RANGE_ARGS");
    let null = core::ptr::null_mut();
    t.eq(
        b"zero len",
        sys_copy_file_range(-1, null, -1, null, 0, 0),
        EBADF,
    );
    let src = file(SRC, b"0123456789", 0);
    let out = file(DST, b"", 0);
    let mut neg = (-100i64) as u64;
    t.eq(
        b"neg off",
        sys_copy_file_range(src, &mut neg, out, null, 4, 0),
        EINVAL,
    );
    let app = file(DST, b"", O_APPEND);
    t.eq(
        b"append",
        sys_copy_file_range(src, null, app, null, 4, 0),
        EBADF,
    );
    close(app);
    let (mut i, mut o) = (0u64, 2u64);
    t.eq(
        b"overlap",
        sys_copy_file_range(src, &mut i, src, &mut o, 4, 0),
        EINVAL,
    );
    let (mut i, mut o) = (6u64, 0u64);
    t.eq(
        b"ok",
        sys_copy_file_range(src, &mut i, out, &mut o, 100, 0),
        4,
    );
    t.ok(b"offsets", i == 10 && o == 4, (i * 100 + o) as i64);
    close(src);
    close(out);
    t.done();
}

/// After 50 ms, in a child: write "XY" to `fd`, or read a page from it
/// if `drain`; the child's pid
fn later(fd: i32, drain: bool) -> i64 {
    let pid = sys_fork();
    if pid == 0 {
        let ts = Timespec {
            tv_sec: 0,
            tv_nsec: 50_000_000,
        };
        sys_nanosleep(&ts, core::ptr::null_mut());
        let mut buf = [0u8; 4096];
        if drain {
            sys_read(fd as u64, buf.as_mut_ptr(), 4096);
        } else {
            sys_write(fd as u64, b"XY".as_ptr(), 2);
        }
        sys_exit(0);
    }
    pid
}

fn reap(pid: i64) {
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
}

/// A pipe whose buffer is full (page writes until EAGAIN)
fn full_pipe() -> [i32; 2] {
    let p = pipe();
    let page = [b'p'; 4096];
    sys_fcntl(p[1], F_SETFL, u64::from(O_NONBLOCK));
    while sys_write(p[1] as u64, page.as_ptr(), 4096) > 0 {}
    sys_fcntl(p[1], F_SETFL, 0);
    p
}

/// SIGPIPE's disposition (kernel sigaction: handler, flags, restorer,
/// mask)
fn sigpipe(handler: u64) {
    let a = [handler, 0, 0, 0];
    sys_rt_sigaction(SIGPIPE, a.as_ptr() as u64, 0, 8);
}

fn splice_wait() {
    let mut t = T::new(b"SPLICE_WAIT");
    let null = core::ptr::null_mut();
    // Empty pipe, writer open: the data comes after the call started
    let p = pipe();
    let out = file(DST, b"", 0);
    let pid = later(p[1], false);
    t.eq(b"pipe->file", sys_splice(p[0], null, out, null, 16, 0), 2);
    reap(pid);
    let q = pipe();
    let pid = later(p[1], false);
    t.eq(b"pipe->pipe", sys_splice(p[0], null, q[1], null, 16, 0), 2);
    reap(pid);
    let pid = later(p[1], false);
    t.eq(b"tee", sys_tee(p[0], q[1], 16, 0), 2);
    reap(pid);
    // Nonblocking on the empty pipe (its writer still open): EAGAIN; the
    // other way round, from `q` with no writer once drained: 0
    let mut buf = [0u8; 16];
    sys_read(p[0] as u64, buf.as_mut_ptr(), 16);
    t.eq(
        b"tee nb",
        sys_tee(p[0], q[1], 16, SPLICE_F_NONBLOCK),
        EAGAIN,
    );
    sys_read(q[0] as u64, buf.as_mut_ptr(), 16);
    close(q[1]);
    t.eq(
        b"pipe->pipe nb eof",
        sys_splice(q[0], null, p[1], null, 16, SPLICE_F_NONBLOCK),
        0,
    );
    close(q[0]);
    // Full pipe: room comes after the call started
    let src = file(SRC, b"0123456789abcdef", 0);
    let f = full_pipe();
    let pid = later(f[0], true);
    t.eq(b"file->pipe", sys_splice(src, null, f[1], null, 16, 0), 16);
    reap(pid);
    // No reader: EPIPE
    close(f[0]);
    sigpipe(SIG_IGN);
    let off = &mut 0i64 as *mut i64;
    t.eq(
        b"file->pipe epipe",
        sys_splice(src, off, f[1], null, 16, 0),
        EPIPE,
    );
    sys_write(p[1] as u64, b"Z".as_ptr(), 1);
    t.eq(
        b"pipe->pipe epipe",
        sys_splice(p[0], null, f[1], null, 16, SPLICE_F_NONBLOCK),
        EPIPE,
    );
    sigpipe(SIG_DFL);
    for fd in [p[0], p[1], f[1], out, src] {
        close(fd);
    }
    t.done();
}

static mut VBUF: [u8; 8192] = [b'v'; 8192];

fn vmsplice_wait() {
    let mut t = T::new(b"VMSPLICE_WAIT");
    let iov = |len| IoVec {
        iov_base: (&raw const VBUF).cast::<u8>(),
        iov_len: len,
    };
    let f = full_pipe();
    let pid = later(f[0], true);
    t.eq(b"full", sys_vmsplice(f[1], &iov(16), 1, 0), 16);
    reap(pid);
    close(f[0]);
    sigpipe(SIG_IGN);
    t.eq(b"epipe", sys_vmsplice(f[1], &iov(16), 1, 0), EPIPE);
    sigpipe(SIG_DFL);
    close(f[1]);
    let p = pipe();
    t.eq(b"two pages", sys_vmsplice(p[1], &iov(8192), 1, 0), 8192);
    close(p[0]);
    close(p[1]);
    t.done();
}
