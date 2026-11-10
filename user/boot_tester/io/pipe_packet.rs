//! Pipe packet mode (Linux fs/pipe.c is_packetized, PIPE_BUF_FLAG_PACKET):
//! a write through a file with O_DIRECT (pipe2(O_DIRECT) gives it to the
//! write end only; F_SETFL may set it on a pipe) puts each page of data
//! in a packet buffer that no later write merges into; a read returns at
//! most one packet and drops the rest of it. A packet write still merges
//! into a previous ordinary buffer it fits in whole.

use crate::harness::{R, check, report_r};
use hk_syscall::{O_DIRECT, O_NONBLOCK, sys_close, sys_fcntl, sys_pipe2, sys_read, sys_write};

const EAGAIN: i64 = -11;
const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;

pub fn run_tests() {
    report_r(b"PIPE_PACKET", packets());
    report_r(b"PIPE_PACKET_BIG", big());
    report_r(b"PIPE_PACKET_SETFL", setfl());
}

/// A pipe with `flags`, closed on drop
struct Pipe([i32; 2]);

impl Pipe {
    fn new(flags: u32) -> Result<Self, (&'static [u8], i64)> {
        let mut fds = [0i32; 2];
        let r = sys_pipe2(fds.as_mut_ptr(), flags);
        check(b"pipe2", r == 0, r)?;
        Ok(Self(fds))
    }

    fn put(&self, b: &[u8]) -> i64 {
        sys_write(self.0[1] as u64, b.as_ptr(), b.len() as u64)
    }

    fn get(&self, b: &mut [u8]) -> i64 {
        sys_read(self.0[0] as u64, b.as_mut_ptr(), b.len() as u64)
    }

    fn getfl(&self, end: usize) -> i64 {
        sys_fcntl(self.0[end], F_GETFL, 0)
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        sys_close(self.0[0] as u64);
        sys_close(self.0[1] as u64);
    }
}

/// pipe2(O_DIRECT): only the write end has O_DIRECT; each write is a
/// packet, a read takes one, a short read drops the packet's rest
fn packets() -> R {
    let p = Pipe::new(O_DIRECT | O_NONBLOCK)?;
    let d = i64::from(O_DIRECT);
    check(b"write end", p.getfl(1) & d != 0, p.getfl(1))?;
    check(b"read end", p.getfl(0) & d == 0, p.getfl(0))?;
    check(b"write 1", p.put(b"abc") == 3, 0)?;
    check(b"write 2", p.put(b"defgh") == 5, 0)?;
    let mut b = [0u8; 64];
    let n = p.get(&mut b);
    check(b"read 1", n == 3 && &b[..3] == b"abc", n)?;
    let n = p.get(&mut b);
    check(b"read 2", n == 5 && &b[..5] == b"defgh", n)?;
    check(b"write 3", p.put(b"0123456789") == 10, 0)?;
    check(b"write 4", p.put(b"xy") == 2, 0)?;
    let n = p.get(&mut b[..4]);
    check(b"short read", n == 4 && &b[..4] == b"0123", n)?;
    let n = p.get(&mut b);
    check(b"rest dropped", n == 2 && &b[..2] == b"xy", n)?;
    let n = p.get(&mut b);
    check(b"empty", n == EAGAIN, n)
}

/// A packet write over a page is one packet per page
fn big() -> R {
    let p = Pipe::new(O_DIRECT | O_NONBLOCK)?;
    let src = [7u8; 5000];
    let n = p.put(&src);
    check(b"write", n == 5000, n)?;
    let mut b = [0u8; 8192];
    let n = p.get(&mut b);
    check(b"page packet", n == 4096, n)?;
    let n = p.get(&mut b);
    check(b"tail packet", n == 904, n)
}

/// F_SETFL turns packet writes on and off; a packet write merges into
/// an ordinary buffer it fits in
fn setfl() -> R {
    let p = Pipe::new(O_NONBLOCK)?;
    let fl = p.getfl(1) as u64;
    let on = |on: bool| {
        let f = if on { fl | u64::from(O_DIRECT) } else { fl };
        sys_fcntl(p.0[1], F_SETFL, f)
    };
    let r = on(true);
    check(b"setfl on", r == 0, r)?;
    check(b"getfl", p.getfl(1) & i64::from(O_DIRECT) != 0, p.getfl(1))?;
    check(b"packet 1", p.put(b"cd") == 2, 0)?;
    check(b"packet 2", p.put(b"ef") == 2, 0)?;
    let mut b = [0u8; 64];
    let n = p.get(&mut b);
    check(b"read 1", n == 2 && &b[..2] == b"cd", n)?;
    let n = p.get(&mut b);
    check(b"read 2", n == 2 && &b[..2] == b"ef", n)?;
    let r = on(false);
    check(b"setfl off", r == 0, r)?;
    check(b"plain", p.put(b"ab") == 2, 0)?;
    on(true);
    check(b"merging packet", p.put(b"xy") == 2, 0)?;
    let n = p.get(&mut b);
    check(b"merged", n == 4 && &b[..4] == b"abxy", n)?;
    on(false);
    check(b"plain 1", p.put(b"jk") == 2, 0)?;
    check(b"plain 2", p.put(b"lm") == 2, 0)?;
    let n = p.get(&mut b);
    check(b"stream", n == 4 && &b[..4] == b"jklm", n)
}
