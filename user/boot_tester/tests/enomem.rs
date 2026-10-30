//! Requests sized by user space (run on hk and real Linux)
//!
//! - ENOMEM_USER_SIZED: 1 GiB requests get a result or an error, never
//!   a kernel buffer that size: process_vm_readv of a 1 GiB iovec over
//!   a small source (a short count), listxattr with a 1 GiB buffer (the
//!   list's size or an error)

use super::sk::T;
use hk_syscall::{
    IoVec, MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE, sys_getpid, sys_listxattr, sys_mmap,
    sys_munmap, sys_process_vm_readv,
};

const GIB: u64 = 1 << 30;
const MAP_NORESERVE: u32 = 0x4000;

/// A source of known size followed by unmapped space or other data
static SRC: [u8; 65536] = [0x5a; 65536];

pub fn run_tests() {
    let mut t = T::new(b"ENOMEM_USER_SIZED");
    let flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE;
    let buf = sys_mmap(0, GIB, PROT_READ | PROT_WRITE, flags, -1, 0);
    if !t.ok(b"mmap 1GiB", buf > 0, buf) {
        return t.done();
    }
    // A 1 GiB copy from a 64 KiB source: whatever follows it is copied
    // until a fault, so at least 64 KiB, at most 1 GiB
    let local = IoVec {
        iov_base: buf as *mut u8,
        iov_len: GIB as usize,
    };
    let remote = IoVec {
        iov_base: SRC.as_ptr(),
        iov_len: GIB as usize,
    };
    let r = sys_process_vm_readv(sys_getpid() as i32, &local, 1, &remote, 1, 0);
    t.ok(b"process_vm_readv", (65536..=GIB as i64).contains(&r), r);
    // SAFETY: the copy landed in our mapping
    let first = unsafe { *(buf as *const u8) };
    t.eq(b"copied byte", first as i64, 0x5a);
    // listxattr with a 1 GiB buffer: a size (maybe 0) or an error
    let r = sys_listxattr(b"/\0".as_ptr(), buf as *mut u8, GIB as usize);
    t.ok(b"listxattr", r >= -95 && r < 65536, r);
    sys_munmap(buf as u64, GIB);
    t.done();
}
