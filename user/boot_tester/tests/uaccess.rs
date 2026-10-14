//! Bad user pointers in vectored I/O and mm syscalls
//!
//! A valid-range but unmapped user address passed as an iovec base, iovec
//! array, or output vector must fail the syscall with EFAULT (Linux
//! semantics) instead of faulting in the kernel. The address comes from an
//! mmap'd-then-munmap'd page so it is unmapped on both hk and Linux.

use super::helpers::{print, print_num, println};
use hk_syscall::{
    IoVec, MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE, sys_close, sys_mincore, sys_mmap,
    sys_munmap, sys_pipe, sys_readv, sys_vmsplice, sys_write, sys_writev,
};

const EFAULT: i64 = -14;
const PAGE: u64 = 4096;

pub fn run_tests() {
    let bad = match unmapped_page() {
        Some(a) => a,
        None => {
            println(b"UACCESS_SETUP:FAIL mmap/munmap");
            return;
        }
    };
    test_readv_bad_base(bad);
    test_writev_bad_base(bad);
    test_readv_bad_iov_array(bad);
    test_vmsplice_bad_base(bad);
    test_mincore_bad_vec();
}

/// Address of a page that was mapped and then unmapped
fn unmapped_page() -> Option<u64> {
    let a = sys_mmap(
        0,
        PAGE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if a < 0 || sys_munmap(a as u64, PAGE) != 0 {
        return None;
    }
    Some(a as u64)
}

fn report(name: &[u8], r: i64) {
    print(name);
    if r == EFAULT {
        println(b":OK");
    } else {
        print(b":FAIL returned ");
        print_num(r);
        println(b" (want -14 EFAULT)");
    }
}

fn pipe() -> Option<[i32; 2]> {
    let mut fds = [0i32; 2];
    if sys_pipe(fds.as_mut_ptr()) != 0 {
        return None;
    }
    Some(fds)
}

fn close_pipe(fds: [i32; 2]) {
    sys_close(fds[0] as u64);
    sys_close(fds[1] as u64);
}

/// readv into an unmapped iov_base
fn test_readv_bad_base(bad: u64) {
    let Some(fds) = pipe() else {
        println(b"READV_BAD_IOV_BASE_EFAULT:FAIL pipe");
        return;
    };
    sys_write(fds[1] as u64, b"data".as_ptr(), 4);
    let iov = IoVec {
        iov_base: bad as *const u8,
        iov_len: 4,
    };
    let r = sys_readv(fds[0] as u64, &iov, 1);
    close_pipe(fds);
    report(b"READV_BAD_IOV_BASE_EFAULT", r);
}

/// writev from an unmapped iov_base
fn test_writev_bad_base(bad: u64) {
    let Some(fds) = pipe() else {
        println(b"WRITEV_BAD_IOV_BASE_EFAULT:FAIL pipe");
        return;
    };
    let iov = IoVec {
        iov_base: bad as *const u8,
        iov_len: 4,
    };
    let r = sys_writev(fds[1] as u64, &iov, 1);
    close_pipe(fds);
    report(b"WRITEV_BAD_IOV_BASE_EFAULT", r);
}

/// readv with the iovec array itself unmapped
fn test_readv_bad_iov_array(bad: u64) {
    let Some(fds) = pipe() else {
        println(b"READV_BAD_IOV_ARRAY_EFAULT:FAIL pipe");
        return;
    };
    sys_write(fds[1] as u64, b"data".as_ptr(), 4);
    let r = sys_readv(fds[0] as u64, bad as *const IoVec, 1);
    close_pipe(fds);
    report(b"READV_BAD_IOV_ARRAY_EFAULT", r);
}

/// vmsplice from an unmapped iov_base into a pipe
fn test_vmsplice_bad_base(bad: u64) {
    let Some(fds) = pipe() else {
        println(b"VMSPLICE_BAD_IOV_BASE_EFAULT:FAIL pipe");
        return;
    };
    let iov = IoVec {
        iov_base: bad as *const u8,
        iov_len: 4,
    };
    let r = sys_vmsplice(fds[1], &iov, 1, 0);
    close_pipe(fds);
    report(b"VMSPLICE_BAD_IOV_BASE_EFAULT", r);
}

/// mincore with an unmapped output vector (the queried range is valid)
fn test_mincore_bad_vec() {
    let a = sys_mmap(
        0,
        PAGE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if a < 0 {
        println(b"MINCORE_BAD_VEC_EFAULT:FAIL mmap");
        return;
    }
    // Fresh unmapped page, taken after `a` so it cannot alias it
    let Some(bad) = unmapped_page() else {
        println(b"MINCORE_BAD_VEC_EFAULT:FAIL mmap/munmap");
        return;
    };
    let r = sys_mincore(a as u64, PAGE, bad as *mut u8);
    sys_munmap(a as u64, PAGE);
    report(b"MINCORE_BAD_VEC_EFAULT", r);
}
