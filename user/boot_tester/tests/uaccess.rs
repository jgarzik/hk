//! Bad user pointers in vectored I/O and mm syscalls
//!
//! A valid-range but unmapped user address passed as an iovec base, iovec
//! array, or output vector must fail the syscall with EFAULT (Linux
//! semantics) instead of faulting in the kernel. The address comes from an
//! mmap'd-then-munmap'd page so it is unmapped on both hk and Linux.
//!
//! UACCESS_UNALIGNED: an int read and written through a misaligned user
//! pointer (getsockopt's optlen, FIONREAD's result) works, as Linux's
//! get_user/put_user on x86-64 and arm64.

use super::helpers::{print, print_num, println};
use hk_syscall::{
    IoVec, MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE, sys_close, sys_getsockopt, sys_ioctl,
    sys_mincore, sys_mmap, sys_munmap, sys_pipe, sys_readv, sys_socketpair, sys_vmsplice,
    sys_write, sys_writev,
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
    test_unaligned();
}

fn test_unaligned() {
    const AF_UNIX: i32 = 1;
    const SOCK_STREAM: i32 = 1;
    const SOL_SOCKET: i32 = 1;
    const SO_TYPE: i32 = 3;
    const FIONREAD: u64 = 0x541B;
    let mut buf = [0u8; 16];
    // 1 past a 4-byte boundary inside `buf`
    let p = ((buf.as_mut_ptr() as u64 + 3) & !3) + 1;
    let mut sv = [0i32; 2];
    if sys_socketpair(AF_UNIX, SOCK_STREAM, 0, &mut sv) != 0 {
        println(b"UACCESS_UNALIGNED:FAIL socketpair");
        return;
    }
    // SAFETY: `p` and the 3 bytes after it lie inside `buf`
    unsafe { core::ptr::write_unaligned(p as *mut u32, 4) };
    let mut ty = 0i32;
    let r = sys_getsockopt(
        sv[0],
        SOL_SOCKET,
        SO_TYPE,
        &mut ty as *mut i32 as *mut u8,
        p as *mut u32,
    );
    // SAFETY: as above
    let len = unsafe { core::ptr::read_unaligned(p as *const u32) };
    let step = if r != 0 {
        r
    } else if ty != SOCK_STREAM || len != 4 {
        1
    } else {
        sys_write(sv[1] as u64, b"abc".as_ptr(), 3);
        let r = sys_ioctl(sv[0], FIONREAD, p);
        // SAFETY: as above
        let n = unsafe { core::ptr::read_unaligned(p as *const i32) };
        if r != 0 {
            r
        } else if n != 3 {
            2
        } else {
            0
        }
    };
    sys_close(sv[0] as u64);
    sys_close(sv[1] as u64);
    print(b"UACCESS_UNALIGNED");
    if step == 0 {
        println(b":OK");
    } else {
        print(b":FAIL step ");
        print_num(step);
        println(b"");
    }
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
