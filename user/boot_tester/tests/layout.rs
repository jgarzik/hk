//! User address space layout (Linux): all of the lower half belongs to
//! user space, nothing below vm.mmap_min_addr without CAP_SYS_RAWIO,
//! mmap top-down below the stack, the kernel half unreachable.

use super::helpers::{host_mode, print, print_num, println, skip};
use hk_syscall::{
    sys_brk, sys_close, sys_exit, sys_fork, sys_mmap, sys_munmap, sys_open, sys_read, sys_setuid,
    sys_wait4, MAP_ANONYMOUS, MAP_FIXED, MAP_FIXED_NOREPLACE, MAP_PRIVATE, O_RDONLY, PROT_READ, PROT_WRITE,
};

/// End of user space
#[cfg(target_arch = "x86_64")]
const TASK_SIZE: u64 = 0x0000_8000_0000_0000;
#[cfg(target_arch = "aarch64")]
const TASK_SIZE: u64 = 1 << 48;

/// A kernel-half address: the direct/linear map of the kernel image on
/// hk (mapped, supervisor-only), the same region on Linux
#[cfg(target_arch = "x86_64")]
pub const KERNEL_ADDR: u64 = 0xffff_8880_0010_0000;
#[cfg(target_arch = "aarch64")]
pub const KERNEL_ADDR: u64 = 0xffff_0000_4010_0000;

pub fn run_tests() {
    test_fixed(b"LAYOUT_MAP_FIXED_400000", 0x40_0000);
    test_fixed(b"LAYOUT_MAP_FIXED_10000", 0x1_0000);
    test_low_eperm();
    test_topdown();
    test_maps();
    test_kernel_read_sigsegv();
}

fn report(name: &[u8], ok: bool, v: i64) {
    print(name);
    if ok {
        println(b":OK");
    } else {
        print(b":FAIL got ");
        print_num(v);
        println(b"");
    }
}

/// A fixed mapping at a low address classic executables use works, and
/// the memory is usable. NOREPLACE: the Linux host build of this program
/// is itself a non-PIE executable at 0x400000 on arm64 (MAP_FIXED would
/// unmap init's own code)
fn test_fixed(name: &[u8], addr: u64) {
    const EEXIST: i64 = -17;
    let flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE;
    let r = sys_mmap(addr, 8192, PROT_READ | PROT_WRITE, flags, -1, 0);
    if r == EEXIST && host_mode() {
        skip(name, b"the host build of boot_tester is loaded there");
        return;
    }
    if r != addr as i64 {
        report(name, false, r);
        return;
    }
    let p = addr as *mut u64;
    unsafe {
        p.write_volatile(0x1234_5678);
        p.add(512).write_volatile(0x9abc);
    }
    let ok = unsafe { p.read_volatile() == 0x1234_5678 && p.add(512).read_volatile() == 0x9abc };
    sys_munmap(addr, 8192);
    report(name, ok, r);
}

/// Below vm.mmap_min_addr a task without CAP_SYS_RAWIO gets EPERM
fn test_low_eperm() {
    let pid = sys_fork();
    if pid == 0 {
        if sys_setuid(65534) != 0 {
            sys_exit(100);
        }
        let flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;
        let r = sys_mmap(0x1000, 4096, PROT_READ | PROT_WRITE, flags, -1, 0);
        sys_exit(if r == -1 { 0 } else { 101 });
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    report(b"LAYOUT_MAP_FIXED_LOW_EPERM", st == 0, st as i64);
}

/// mmap without a hint goes top-down, high above the program break
fn test_topdown() {
    let brk = sys_brk(0);
    let r = sys_mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    let ok = r > 0 && (r as u64) > (1 << 46) && (r as u64) < TASK_SIZE && r > brk;
    if r > 0 {
        sys_munmap(r as u64, 4096);
    }
    report(b"LAYOUT_MMAP_TOPDOWN", ok, r);
}

fn hex(s: &[u8]) -> Option<u64> {
    let mut v = 0u64;
    for &c in s {
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => return None,
        };
        v = v.checked_mul(16)? + d as u64;
    }
    (!s.is_empty()).then_some(v)
}

/// /proc/self/maps lists the program, heap and stack, all in the lower
/// half (Linux's legacy x86 [vsyscall] page is the one exception)
fn test_maps() {
    const N: &[u8] = b"LAYOUT_PROC_MAPS";
    let fd = sys_open(b"/proc/self/maps\0".as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        report(N, false, fd);
        return;
    }
    let mut buf = [0u8; 8192];
    let mut len = 0;
    loop {
        let n = sys_read(fd as u64, buf[len..].as_mut_ptr(), (buf.len() - len) as u64);
        if n <= 0 {
            break;
        }
        len += n as usize;
    }
    sys_close(fd as u64);
    let (mut lines, mut stack, mut bad) = (0, false, 0u64);
    for line in buf[..len].split(|&c| c == b'\n').filter(|l| !l.is_empty()) {
        lines += 1;
        if line.ends_with(b"[vsyscall]") {
            continue;
        }
        stack |= line.ends_with(b"[stack]");
        let range = line.split(|&c| c == b' ').next().unwrap_or(b"");
        let mut it = range.split(|&c| c == b'-');
        match (it.next().and_then(hex), it.next().and_then(hex)) {
            (Some(a), Some(b)) if a < b && b <= TASK_SIZE => {}
            (a, _) => bad = a.unwrap_or(u64::MAX),
        }
    }
    let ok = lines >= 3 && stack && bad == 0;
    if !ok {
        print(b"  maps: ");
        println(&buf[..len.min(600)]);
    }
    report(N, ok, bad as i64);
}

/// Reading a kernel address from user mode is SIGSEGV
fn test_kernel_read_sigsegv() {
    let pid = sys_fork();
    if pid == 0 {
        let v = unsafe { (KERNEL_ADDR as *const u64).read_volatile() };
        sys_exit(v as u64 & 0x7f);
    }
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    report(b"LAYOUT_KERNEL_READ_SIGSEGV", st & 0x7f == 11, st as i64);
}
