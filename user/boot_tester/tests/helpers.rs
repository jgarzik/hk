//! Shared test utilities for boot_tester modules

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use hk_syscall::{
    AF_INET, SOCK_DGRAM, UtsName, sys_close, sys_ioctl, sys_mkdir, sys_mount, sys_socket,
    sys_uname, sys_write,
};

pub const STDOUT: u64 = 1;

static HOST_MODE: AtomicBool = AtomicBool::new(false);
static FAIL_COUNT: AtomicU32 = AtomicU32::new(0);

/// Detect whether we run on hk or on a real Linux host (differential testing)
pub fn init_host_mode() {
    let mut uts: UtsName = unsafe { core::mem::zeroed() };
    let on_hk = sys_uname(&mut uts) == 0 && starts_with(&uts.sysname, b"hk\0");
    HOST_MODE.store(!on_hk, Ordering::Relaxed);
}

/// Linux leaves pseudo-filesystems to init; hk mounts /proc and /dev itself
pub fn host_setup() {
    sys_mkdir(b"/proc\0".as_ptr(), 0o555);
    sys_mount(
        b"proc\0".as_ptr(),
        b"/proc\0".as_ptr(),
        b"proc\0".as_ptr(),
        0,
        0,
    );
    sys_mkdir(b"/dev\0".as_ptr(), 0o755);
    sys_mount(
        b"devtmpfs\0".as_ptr(),
        b"/dev\0".as_ptr(),
        b"devtmpfs\0".as_ptr(),
        0,
        0,
    );
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777);
}

/// Bring up `lo` (both kernels start it down; up assigns 127.0.0.1/8)
pub fn loopback_up() {
    const SIOCGIFFLAGS: u64 = 0x8913;
    const SIOCSIFFLAGS: u64 = 0x8914;
    const IFF_UP: u16 = 0x1;

    // struct ifreq: char ifr_name[16]; union { short ifr_flags; ... } (24 bytes)
    let mut ifr = [0u8; 40];
    ifr[..2].copy_from_slice(b"lo");
    let fd = sys_socket(AF_INET, SOCK_DGRAM, 0);
    if fd < 0 {
        return;
    }
    let ifr_ptr = ifr.as_mut_ptr() as u64;
    if sys_ioctl(fd as i32, SIOCGIFFLAGS, ifr_ptr) == 0 {
        let flags = u16::from_ne_bytes([ifr[16], ifr[17]]) | IFF_UP;
        ifr[16..18].copy_from_slice(&flags.to_ne_bytes());
        sys_ioctl(fd as i32, SIOCSIFFLAGS, ifr_ptr);
    }
    sys_close(fd as u64);
}

/// True when running on a non-hk kernel; hk-only or host-unsafe tests skip
pub fn host_mode() -> bool {
    HOST_MODE.load(Ordering::Relaxed)
}

/// Number of printed chunks containing "FAIL" in this process
pub fn fail_count() -> u32 {
    FAIL_COUNT.load(Ordering::Relaxed)
}

/// Count failures reported by a child process
pub fn add_fails(n: u32) {
    FAIL_COUNT.store(FAIL_COUNT.load(Ordering::Relaxed) + n, Ordering::Relaxed);
}

/// Print a skip verdict: `NAME:SKIP (reason)`
pub fn skip(name: &[u8], reason: &[u8]) {
    print(name);
    print(b":SKIP (");
    print(reason);
    println(b")");
}

/// Print a byte slice to stdout
pub fn print(s: &[u8]) {
    if s.windows(4).any(|w| w == b"FAIL") {
        // load+store, not fetch_add: RMW atomics on aarch64 need libc's getauxval
        FAIL_COUNT.store(FAIL_COUNT.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
    }
    sys_write(STDOUT, s.as_ptr(), s.len() as u64);
}

/// Print a byte slice followed by newline
pub fn println(s: &[u8]) {
    print(s);
    print(b"\n");
}

/// Print a number in decimal
pub fn print_num(n: i64) {
    if n < 0 {
        print(b"-");
        print_num(-n);
        return;
    }
    if n >= 10 {
        print_num(n / 10);
    }
    let digit = b'0' + (n % 10) as u8;
    sys_write(STDOUT, &digit as *const u8, 1);
}

/// Print a NUL-terminated C string (stops at first NUL byte)
pub fn print_cstr(s: &[u8]) {
    let len = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    sys_write(STDOUT, s.as_ptr(), len as u64);
}

/// Check if slice starts with prefix
pub fn starts_with(slice: &[u8], prefix: &[u8]) -> bool {
    if slice.len() < prefix.len() {
        return false;
    }
    let mut i = 0;
    while i < prefix.len() {
        if slice[i] != prefix[i] {
            return false;
        }
        i += 1;
    }
    true
}
