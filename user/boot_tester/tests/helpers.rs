//! Shared test utilities for boot_tester modules

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use hk_syscall::{
    AF_INET, O_RDONLY, SOCK_DGRAM, UtsName, sys_close, sys_ioctl, sys_mkdir, sys_mount, sys_open,
    sys_read, sys_socket, sys_uname, sys_write,
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

/// Linux leaves pseudo-filesystems to init; hk mounts /proc itself
pub fn host_setup() {
    sys_mkdir(b"/proc\0".as_ptr(), 0o555);
    sys_mount(
        b"proc\0".as_ptr(),
        b"/proc\0".as_ptr(),
        b"proc\0".as_ptr(),
        0,
        0,
    );
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777);
}

/// devtmpfs on /dev, as init does on both kernels (device nodes of
/// every registered device, block devices included)
pub fn dev_setup() {
    sys_mkdir(b"/dev\0".as_ptr(), 0o755);
    let r = sys_mount(
        b"devtmpfs\0".as_ptr(),
        b"/dev\0".as_ptr(),
        b"devtmpfs\0".as_ptr(),
        0,
        0,
    );
    if r != 0 {
        print(b"DEVTMPFS_MOUNT:FAIL ");
        print_num(r);
        println(b"");
    }
}

/// Read all of `path` into `buf` (NUL-terminated path); bytes read or
/// a negative errno
pub fn read_file(path: &[u8], buf: &mut [u8]) -> i64 {
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        return fd;
    }
    let mut n = 0;
    while n < buf.len() {
        let r = sys_read(fd as u64, buf[n..].as_mut_ptr(), (buf.len() - n) as u64);
        if r <= 0 {
            break;
        }
        n += r as usize;
    }
    sys_close(fd as u64);
    n as i64
}

/// A block device from /proc/partitions
#[derive(Clone, Copy)]
pub struct BlkDev {
    pub major: u32,
    pub minor: u32,
    /// Size in KiB
    pub blocks: u64,
    pub name: [u8; 32],
    pub len: usize,
}

impl BlkDev {
    pub fn name(&self) -> &[u8] {
        &self.name[..self.len]
    }

    /// "/dev/<name>\0" in `buf`
    pub fn path<'a>(&self, buf: &'a mut [u8; 48]) -> &'a [u8] {
        buf[..5].copy_from_slice(b"/dev/");
        buf[5..5 + self.len].copy_from_slice(self.name());
        buf[5 + self.len] = 0;
        &buf[..6 + self.len]
    }
}

fn parse_num(f: &[u8]) -> u64 {
    f.iter()
        .take_while(|c| c.is_ascii_digit())
        .fold(0, |n, &c| n * 10 + (c - b'0') as u64)
}

/// One data line of /proc/partitions ("major minor #blocks name")
fn parse_part_line(line: &[u8]) -> Option<BlkDev> {
    let mut f = line.split(|&c| c == b' ').filter(|s| !s.is_empty());
    let (ma, mi, bl, nm) = (f.next()?, f.next()?, f.next()?, f.next()?);
    if !ma[0].is_ascii_digit() || nm.len() > 31 {
        return None;
    }
    let mut d = BlkDev {
        major: parse_num(ma) as u32,
        minor: parse_num(mi) as u32,
        blocks: parse_num(bl),
        name: [0; 32],
        len: nm.len(),
    };
    d.name[..nm.len()].copy_from_slice(nm);
    Some(d)
}

/// Find a block device in /proc/partitions: the first whose name
/// starts with `prefix` and whose size is `blocks` KiB (0: any size)
pub fn find_blkdev(prefix: &[u8], blocks: u64) -> Option<BlkDev> {
    let mut buf = [0u8; 4096];
    let n = read_file(b"/proc/partitions\0", &mut buf);
    if n <= 0 {
        return None;
    }
    buf[..n as usize]
        .split(|&c| c == b'\n')
        .filter_map(parse_part_line)
        .find(|d| starts_with(d.name(), prefix) && (blocks == 0 || d.blocks == blocks))
}

/// Major and minor of a user dev_t (glibc gnu_dev_major/minor)
pub fn dev_major(dev: u64) -> u32 {
    (((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff)) as u32
}

pub fn dev_minor(dev: u64) -> u32 {
    ((dev & 0xff) | ((dev >> 12) & !0xff)) as u32
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
