//! AF_UNIX options (hk and Linux): SO_PEEK_OFF on stream, datagram and
//! seqpacket sockets (Linux selftests af_unix/so_peek_off.c).

use hk_syscall::{SOCK_DGRAM, SOCK_STREAM};

use crate::harness::T;
use crate::net::sk::*;
use crate::net::unix::pair;

const SOCK_SEQPACKET: i32 = 5;
const SO_PEEK_OFF: i32 = 42;

pub fn run_tests() {
    crate::helpers::println(b"=== AF_UNIX option Tests ===");
    for ty in [SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET] {
        test_peek_off(ty);
    }
}

/// Receive into a `len`-byte buffer: exactly the bytes `want`
fn recveq(fd: i32, len: usize, flags: i32, want: &[u8]) -> bool {
    let mut buf = [0u8; 128];
    let r = recv(fd, &mut buf[..len], flags);
    r == want.len() as i64 && &buf[..want.len()] == want
}

fn peek_off(fd: i32) -> i64 {
    let (r, v) = getint(fd, SOL_SOCKET, SO_PEEK_OFF);
    if r < 0 { r } else { v as i64 }
}

/// so_peek_off.c single_chunk, two_chunks and two_chunks_overlap: each
/// peek starts at the offset and moves it; reads move it back
fn test_peek_off(ty: i32) {
    let mut t = T::new(match ty {
        SOCK_STREAM => b"UNIX_PEEK_OFF_STREAM",
        SOCK_DGRAM => b"UNIX_PEEK_OFF_DGRAM",
        _ => b"UNIX_PEEK_OFF_SEQPACKET",
    });
    let (a, b) = pair(ty);
    t.eq(b"default off", peek_off(b), -1);
    t.eq(b"set", setint(b, SOL_SOCKET, SO_PEEK_OFF, 0), 0);
    t.eq(b"get", peek_off(b), 0);
    // single_chunk
    send(a, b"aaaabbbb", 0);
    t.ok(b"single peek 1", recveq(b, 4, MSG_PEEK, b"aaaa"), 0);
    t.eq(b"single off 1", peek_off(b), 4);
    t.ok(b"single peek 2", recveq(b, 100, MSG_PEEK, b"bbbb"), 0);
    t.eq(b"single off 2", peek_off(b), 8);
    t.ok(b"single read", recveq(b, 8, 0, b"aaaabbbb"), 0);
    t.eq(b"single off 0", peek_off(b), 0);
    // two_chunks
    send(a, b"aaaa", 0);
    send(a, b"bbbb", 0);
    t.ok(b"two peek 1", recveq(b, 4, MSG_PEEK, b"aaaa"), 0);
    t.eq(b"two off 1", peek_off(b), 4);
    t.ok(b"two peek 2", recveq(b, 100, MSG_PEEK, b"bbbb"), 0);
    t.eq(b"two off 2", peek_off(b), 8);
    t.ok(b"two read 1", recveq(b, 4, 0, b"aaaa"), 0);
    t.ok(b"two read 2", recveq(b, 4, 0, b"bbbb"), 0);
    t.eq(b"two off 0", peek_off(b), 0);
    // two_chunks_overlap
    send(a, b"aaaa", 0);
    t.ok(b"overlap peek", recveq(b, 2, MSG_PEEK, b"aa"), 0);
    t.eq(b"overlap off", peek_off(b), 2);
    send(a, b"bbbb", 0);
    if ty == SOCK_STREAM {
        // A stream fills the buffer
        t.ok(b"overlap peek 2", recveq(b, 4, MSG_PEEK, b"aabb"), 0);
        t.eq(b"overlap off 2", peek_off(b), 6);
        t.ok(b"overlap peek 3", recveq(b, 100, MSG_PEEK, b"bb"), 0);
    } else {
        // Datagrams end at the message boundary
        t.ok(b"overlap peek 2", recveq(b, 100, MSG_PEEK, b"aa"), 0);
        t.eq(b"overlap off 2", peek_off(b), 4);
        t.ok(b"overlap peek 3", recveq(b, 100, MSG_PEEK, b"bbbb"), 0);
    }
    t.eq(b"overlap off 3", peek_off(b), 8);
    t.ok(b"overlap read 1", recveq(b, 4, 0, b"aaaa"), 0);
    t.ok(b"overlap read 2", recveq(b, 4, 0, b"bbbb"), 0);
    t.eq(b"overlap off 0", peek_off(b), 0);
    // An offset past the queue: nothing to peek
    send(a, b"cc", 0);
    setint(b, SOL_SOCKET, SO_PEEK_OFF, 2);
    let mut buf = [0u8; 8];
    t.eq(
        b"peek past end",
        recv(b, &mut buf, MSG_PEEK | MSG_DONTWAIT),
        EAGAIN,
    );
    t.ok(b"read after", recveq(b, 8, 0, b"cc"), 0);
    close(a);
    close(b);
    t.done();
}
