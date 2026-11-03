//! sysfs tests (hk and Linux): the mount, attribute files (seq_file
//! read semantics, open permission, lseek), directory link counts,
//! class devices, uevents.
//! Paths below /sys/devices differ between the kernels; tests use only
//! what both have.

use hk_syscall::{
    LinuxStatFs, O_DIRECTORY, O_RDONLY, O_WRONLY, Stat, sys_close, sys_getdents64, sys_lseek,
    sys_open, sys_read, sys_readlink, sys_stat, sys_statfs,
};

use super::helpers::{host_mode, print, print_num, println, read_file};
use super::nl::{nladdr, recv_creds};

const EACCES: i64 = -13;
const SYSFS_MAGIC: i64 = 0x6265_6572;
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const DT_DIR: u8 = 4;

pub fn run_tests() {
    println(b"=== sysfs Tests ===");
    test_basic();
    test_class_mem();
    test_uevent_synth();
    test_bus_platform();
    test_bus_pci();
}

fn fail(name: &[u8], why: &[u8], v: i64) {
    print(name);
    print(b":FAIL ");
    print(why);
    print(b" ");
    print_num(v);
    println(b"");
}

fn ok(name: &[u8]) {
    print(name);
    println(b":OK");
}

fn stat(path: &[u8]) -> Result<Stat, i64> {
    // SAFETY: Stat is plain data
    let mut st: Stat = unsafe { core::mem::zeroed() };
    let r = sys_stat(path.as_ptr(), &mut st);
    if r < 0 { Err(r) } else { Ok(st) }
}

/// Calls `f(name, d_type)` for each entry of directory `path`; entry
/// count or a negative errno
pub fn each_entry(path: &[u8], f: &mut dyn FnMut(&[u8], u8)) -> i64 {
    let fd = sys_open(path.as_ptr(), O_RDONLY | O_DIRECTORY, 0);
    if fd < 0 {
        return fd;
    }
    let mut buf = [0u8; 2048];
    let mut n = 0;
    loop {
        let r = sys_getdents64(fd as u64, buf.as_mut_ptr(), buf.len() as u64);
        if r <= 0 {
            sys_close(fd as u64);
            return if r < 0 { r } else { n };
        }
        let mut off = 0;
        while off < r as usize {
            let reclen = u16::from_ne_bytes([buf[off + 16], buf[off + 17]]) as usize;
            let ty = buf[off + 18];
            let name = &buf[off + 19..off + reclen];
            let len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
            let name = &name[..len];
            if name != b"." && name != b".." {
                f(name, ty);
                n += 1;
            }
            off += reclen;
        }
    }
}

/// Mount, attribute stat/read/lseek/open, directory nlink
fn test_basic() {
    const N: &[u8] = b"SYSFS_BASIC";
    // SAFETY: LinuxStatFs is plain data
    let mut sf: LinuxStatFs = unsafe { core::mem::zeroed() };
    let r = sys_statfs(b"/sys\0".as_ptr(), &mut sf);
    if r != 0 || sf.f_type != SYSFS_MAGIC {
        return fail(N, b"statfs magic", if r != 0 { r } else { sf.f_type });
    }
    let mut kernel = false;
    let mut fs = false;
    each_entry(b"/sys\0", &mut |name, ty| {
        kernel |= name == b"kernel" && ty == DT_DIR;
        fs |= name == b"fs" && ty == DT_DIR;
    });
    if !kernel || !fs {
        return fail(N, b"/sys lacks kernel or fs", 0);
    }
    match stat(b"/sys/fs/cgroup\0") {
        Ok(st) if st.st_mode & S_IFMT == S_IFDIR => {}
        _ => return fail(N, b"/sys/fs/cgroup", 0),
    }
    // Directory link count: subdirectories + 2
    let mut subdirs = 0;
    each_entry(b"/sys/kernel\0", &mut |_, ty| subdirs += (ty == DT_DIR) as i64);
    match stat(b"/sys/kernel\0") {
        Ok(st) if st.st_nlink as i64 == subdirs + 2 => {}
        Ok(st) => return fail(N, b"nlink", st.st_nlink as i64),
        Err(e) => return fail(N, b"stat /sys/kernel", e),
    }
    // Attributes: regular, mode 0444, size 4096
    let path = b"/sys/kernel/uevent_seqnum\0";
    match stat(path) {
        Ok(st) if st.st_mode == S_IFREG | 0o444 && st.st_size == 4096 => {}
        Ok(st) => return fail(N, b"attr mode", st.st_mode as i64),
        Err(e) => return fail(N, b"stat attr", e),
    }
    if let Err((why, v)) = attr_reads(path) {
        return fail(N, why, v);
    }
    // A read-only attribute refuses write opens, even to root
    let w = sys_open(path.as_ptr(), O_WRONLY, 0);
    if w >= 0 {
        sys_close(w as u64);
    }
    if w != EACCES {
        return fail(N, b"write open", w);
    }
    ok(N);
}

/// Split reads, re-read after lseek(0), SEEK_END from the 4096 size
fn attr_reads(path: &[u8]) -> Result<(), (&'static [u8], i64)> {
    let fd = sys_open(path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        return Err((b"open attr", fd));
    }
    let r = (|| {
        let mut a = [0u8; 64];
        let n1 = sys_read(fd as u64, a.as_mut_ptr(), 1);
        let n2 = sys_read(fd as u64, a[1..].as_mut_ptr(), 63);
        let n3 = sys_read(fd as u64, a.as_mut_ptr(), 8);
        if n1 != 1 || n2 < 1 || n3 != 0 {
            return Err((&b"split read"[..], n2));
        }
        let len = (1 + n2) as usize;
        if a[len - 1] != b'\n' || !a[..len - 1].iter().all(u8::is_ascii_digit) {
            return Err((&b"format"[..], len as i64));
        }
        if sys_lseek(fd as i32, 0, 0) != 0 {
            return Err((&b"lseek 0"[..], -1));
        }
        let mut b = [0u8; 64];
        let m = sys_read(fd as u64, b.as_mut_ptr(), 64);
        if m < 2 || b[m as usize - 1] != b'\n' {
            return Err((&b"re-read"[..], m));
        }
        let e = sys_lseek(fd as i32, 0, 2);
        if e != 4096 {
            return Err((&b"SEEK_END"[..], e));
        }
        Ok(())
    })();
    sys_close(fd as u64);
    r
}

/// `path` (NUL-terminated) holds exactly `want`
fn file_is(path: &[u8], want: &[u8]) -> bool {
    let mut b = [0u8; 256];
    let n = read_file(path, &mut b);
    n >= 0 && &b[..n as usize] == want
}

/// Symlink `path` points at `want`
fn link_is(path: &[u8], want: &[u8]) -> bool {
    let mut b = [0u8; 256];
    let n = sys_readlink(path.as_ptr(), b.as_mut_ptr(), b.len() as u64);
    n >= 0 && &b[..n as usize] == want
}

/// Class devices: dev, uevent, class/subsystem and /sys/dev links
fn test_class_mem() {
    const N: &[u8] = b"SYSFS_CLASS_MEM";
    let checks: [(&[u8], bool); 8] = [
        (b"dev", file_is(b"/sys/class/mem/null/dev\0", b"1:3\n")),
        (
            b"uevent",
            file_is(
                b"/sys/class/mem/null/uevent\0",
                b"MAJOR=1\nMINOR=3\nDEVNAME=null\nDEVMODE=0666\n",
            ),
        ),
        (
            b"class link",
            link_is(b"/sys/class/mem/null\0", b"../../devices/virtual/mem/null"),
        ),
        (
            b"subsystem",
            link_is(
                b"/sys/devices/virtual/mem/null/subsystem\0",
                b"../../../../class/mem",
            ),
        ),
        (
            b"/sys/dev/char",
            link_is(b"/sys/dev/char/1:3\0", b"../../devices/virtual/mem/null"),
        ),
        (
            b"tty uevent",
            file_is(
                b"/sys/class/tty/tty/uevent\0",
                b"MAJOR=5\nMINOR=0\nDEVNAME=tty\nDEVMODE=0666\n",
            ),
        ),
        (
            b"console uevent",
            file_is(
                b"/sys/class/tty/console/uevent\0",
                b"MAJOR=5\nMINOR=1\nDEVNAME=console\n",
            ),
        ),
        (b"console dev", file_is(b"/sys/class/tty/console/dev\0", b"5:1\n")),
    ];
    for (why, good) in checks {
        if !good {
            return fail(N, why, 0);
        }
    }
    ok(N);
}

const NETLINK_KOBJECT_UEVENT: i32 = 15;

/// A socket on uevent group 1 with SO_PASSCRED
fn uevent_sock() -> Option<i32> {
    use hk_syscall::{SOCK_CLOEXEC, SOCK_DGRAM, sys_bind, sys_setsockopt, sys_socket};
    let fd = sys_socket(16, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_KOBJECT_UEVENT);
    if fd < 0 {
        return None;
    }
    let fd = fd as i32;
    let a = nladdr(0, 1);
    let one: i32 = 1;
    let pc = sys_setsockopt(fd, 1, 16, &one as *const i32 as *const u8, 4);
    if sys_bind(fd, a.as_ptr(), 12) != 0 || pc != 0 {
        sys_close(fd as u64);
        return None;
    }
    Some(fd)
}

fn write_str(path: &[u8], data: &[u8]) -> i64 {
    let fd = sys_open(path.as_ptr(), O_WRONLY, 0);
    if fd < 0 {
        return fd;
    }
    let r = hk_syscall::sys_write(fd as u64, data.as_ptr(), data.len() as u64);
    sys_close(fd as u64);
    r
}

/// Receive into `buf` until a message with header `head` arrives
/// (skipping other devices' events): its length and the sender's
/// credentials
fn next_event(fd: i32, head: &[u8], buf: &mut [u8]) -> Option<(usize, (i32, u32, u32))> {
    for _ in 0..16 {
        let (n, c) = recv_creds(fd, buf);
        if n <= 0 {
            return None;
        }
        if vars(&buf[..n as usize]).next() == Some(head) {
            return Some((n as usize, c?));
        }
    }
    None
}

/// The NUL-separated strings of a uevent message (header first)
fn vars(m: &[u8]) -> impl Iterator<Item = &[u8]> {
    m.split(|&b| b == 0).filter(|p| !p.is_empty())
}

fn num(d: &[u8]) -> u64 {
    d.iter()
        .take_while(|d| d.is_ascii_digit())
        .fold(0u64, |a, &d| a * 10 + (d - b'0') as u64)
}

/// The variables after the header are exactly `want`, then SEQNUM;
/// returns its value
fn exact_vars(m: &[u8], want: &[&[u8]]) -> Option<u64> {
    let mut it = vars(m).skip(1);
    for w in want {
        if it.next()? != *w {
            return None;
        }
    }
    let seq = num(it.next()?.strip_prefix(b"SEQNUM=")?);
    if it.next().is_some() { None } else { Some(seq) }
}

/// Writing to a device's uevent file: the synthetic event's header,
/// variables in Linux order, root credentials, SEQNUM matching
/// /sys/kernel/uevent_seqnum; UUID arguments; malformed writes EINVAL
fn test_uevent_synth() {
    const N: &[u8] = b"UEVENT_SYNTH";
    let Some(fd) = uevent_sock() else {
        return fail(N, b"socket", 0);
    };
    let r = (|| {
        let ue = b"/sys/class/mem/null/uevent\0";
        if write_str(ue, b"add\n") != 4 {
            return Err((&b"write add"[..], 0));
        }
        let mut buf = [0u8; 2048];
        let Some((n, cred)) = next_event(fd, b"add@/devices/virtual/mem/null", &mut buf) else {
            return Err((&b"no add event"[..], 0));
        };
        let want: [&[u8]; 8] = [
            b"ACTION=add",
            b"DEVPATH=/devices/virtual/mem/null",
            b"SUBSYSTEM=mem",
            b"SYNTH_UUID=0",
            b"MAJOR=1",
            b"MINOR=3",
            b"DEVNAME=null",
            b"DEVMODE=0666",
        ];
        let Some(seq) = exact_vars(&buf[..n], &want) else {
            return Err((&b"variables"[..], n as i64));
        };
        if cred != (0, 0, 0) {
            return Err((&b"creds pid"[..], cred.0 as i64));
        }
        let mut b = [0u8; 32];
        let k = read_file(b"/sys/kernel/uevent_seqnum\0", &mut b);
        let cur = num(&b[..k.max(0) as usize]);
        if cur < seq {
            return Err((&b"uevent_seqnum"[..], cur as i64));
        }
        let arg = b"change 01234567-89ab-cdef-0123-456789abcdef A=1 bc=xy";
        if write_str(ue, arg) != arg.len() as i64 {
            return Err((&b"write change"[..], 0));
        }
        let head = b"change@/devices/virtual/mem/null";
        let Some((n, _)) = next_event(fd, head, &mut buf) else {
            return Err((&b"no change event"[..], 0));
        };
        let want: [&[u8]; 10] = [
            b"ACTION=change",
            b"DEVPATH=/devices/virtual/mem/null",
            b"SUBSYSTEM=mem",
            b"SYNTH_UUID=01234567-89ab-cdef-0123-456789abcdef",
            b"SYNTH_ARG_A=1",
            b"SYNTH_ARG_bc=xy",
            b"MAJOR=1",
            b"MINOR=3",
            b"DEVNAME=null",
            b"DEVMODE=0666",
        ];
        match exact_vars(&buf[..n], &want) {
            Some(s2) if s2 > seq => {}
            _ => return Err((&b"synth args"[..], n as i64)),
        }
        for bad in [&b"frob"[..], b"add zzz", b"add 01234567-89ab-cdef-0123-456789abcdef A"] {
            let r = write_str(ue, bad);
            if r != -22 {
                return Err((&b"malformed"[..], r));
            }
        }
        Ok(())
    })();
    sys_close(fd as u64);
    match r {
        Ok(()) => ok(N),
        Err((why, v)) => fail(N, why, v),
    }
}

/// Up to 32 names of at most 63 bytes
struct Names {
    n: usize,
    len: [u8; 32],
    buf: [[u8; 63]; 32],
}

impl Names {
    fn of(path: &[u8], want: u8) -> Self {
        let mut s = Names {
            n: 0,
            len: [0; 32],
            buf: [[0; 63]; 32],
        };
        each_entry(path, &mut |name, ty| {
            if ty == want && s.n < 32 && name.len() < 63 {
                s.buf[s.n][..name.len()].copy_from_slice(name);
                s.len[s.n] = name.len() as u8;
                s.n += 1;
            }
        });
        s
    }

    fn get(&self, i: usize) -> &[u8] {
        &self.buf[i][..self.len[i] as usize]
    }
}

/// `parts` joined, NUL-terminated, in `buf`
fn path<'a>(buf: &'a mut [u8; 256], parts: &[&[u8]]) -> &'a [u8] {
    let mut n = 0;
    for p in parts {
        buf[n..n + p.len()].copy_from_slice(p);
        n += p.len();
    }
    buf[n] = 0;
    &buf[..=n]
}

fn mode_of(p: &[u8]) -> u32 {
    stat(p).map_or(0, |st| st.st_mode)
}

const DT_LNK: u8 = 10;

/// /sys/bus/platform: bus files, driver bind/unbind, and each bound
/// device's driver link and DRIVER/MODALIAS uevent variables
fn test_bus_platform() {
    const N: &[u8] = b"SYSFS_BUS_PLATFORM";
    let base = b"/sys/bus/platform/";
    if !file_is(b"/sys/bus/platform/drivers_autoprobe\0", b"1\n") {
        return fail(N, b"drivers_autoprobe", 0);
    }
    for f in [&b"drivers_probe\0"[..], b"uevent\0"] {
        let mut b = [0u8; 256];
        if mode_of(path(&mut b, &[base, f])) != S_IFREG | 0o200 {
            return fail(N, b"bus write-only file", 0);
        }
    }
    let drivers = Names::of(b"/sys/bus/platform/drivers\0", DT_DIR);
    let mut bound = 0;
    for i in 0..drivers.n {
        let d = drivers.get(i);
        // Both write-only, or neither (Linux suppress_bind_attrs)
        let mut m = [0u32; 2];
        for (k, f) in [&b"/bind\0"[..], b"/unbind\0"].iter().enumerate() {
            let mut b = [0u8; 256];
            m[k] = mode_of(path(&mut b, &[base, b"drivers/", d, f]));
        }
        if m[0] != m[1] || (m[0] != 0 && m[0] != S_IFREG | 0o200) {
            return fail(N, b"driver bind/unbind mode", i as i64);
        }
        let mut db = [0u8; 256];
        let devs = Names::of(path(&mut db, &[base, b"drivers/", d, b"\0"]), DT_LNK);
        for j in 0..devs.n {
            let dev = devs.get(j);
            if dev == b"module" {
                continue;
            }
            // The device's driver link names this driver
            let mut lb = [0u8; 256];
            let mut t = [0u8; 256];
            let p = path(&mut lb, &[base, b"devices/", dev, b"/driver\0"]);
            let n = sys_readlink(p.as_ptr(), t.as_mut_ptr(), t.len() as u64);
            if n <= 0 || !t[..n as usize].ends_with(d) {
                return fail(N, b"driver link", j as i64);
            }
            let mut ub = [0u8; 256];
            let mut u = [0u8; 1024];
            let k = read_file(path(&mut ub, &[base, b"devices/", dev, b"/uevent\0"]), &mut u);
            let u = &u[..k.max(0) as usize];
            let mut has_drv = false;
            let mut has_alias = false;
            for line in u.split(|&c| c == b'\n') {
                has_drv |= line.strip_prefix(b"DRIVER=") == Some(d);
                has_alias |= line.starts_with(b"MODALIAS=");
            }
            if !has_drv || !has_alias {
                return fail(N, b"uevent DRIVER/MODALIAS", j as i64);
            }
            bound += 1;
        }
    }
    // hk binds its console UART; the Linux reference may use other buses
    if bound == 0 && !host_mode() {
        return fail(N, b"no bound device", 0);
    }
    ok(N);
}

/// Parse "0x<hex>\n" of exactly `digits` hex digits
fn hex_attr(b: &[u8], digits: usize) -> Option<u32> {
    let v = b.strip_prefix(b"0x")?.strip_suffix(b"\n")?;
    if v.len() != digits {
        return None;
    }
    v.iter().try_fold(0u32, |a, &c| Some(a * 16 + (c as char).to_digit(16)?))
}

fn upper_hex(v: u32, digits: usize, out: &mut [u8]) {
    for i in 0..digits {
        let d = (v >> (4 * (digits - 1 - i))) & 0xf;
        out[i] = b"0123456789ABCDEF"[d as usize];
    }
}

/// Every PCI function: vendor/device/class formats, config space
/// agreeing with them, modalias, uevent PCI_ID and PCI_SLOT_NAME
fn test_bus_pci() {
    const N: &[u8] = b"SYSFS_BUS_PCI";
    let devs = Names::of(b"/sys/bus/pci/devices\0", DT_LNK);
    if devs.n == 0 {
        return fail(N, b"no PCI devices", 0);
    }
    let base: &[u8] = b"/sys/bus/pci/devices/";
    for i in 0..devs.n {
        let d = devs.get(i);
        let attr = |name: &[u8], out: &mut [u8]| -> usize {
            let mut b = [0u8; 256];
            let n = read_file(path(&mut b, &[base, d, b"/", name, b"\0"]), out);
            n.max(0) as usize
        };
        let mut v = [0u8; 64];
        let n = attr(b"vendor", &mut v);
        let Some(vendor) = hex_attr(&v[..n], 4) else {
            return fail(N, b"vendor format", i as i64);
        };
        let n = attr(b"device", &mut v);
        let Some(device) = hex_attr(&v[..n], 4) else {
            return fail(N, b"device format", i as i64);
        };
        let n = attr(b"class", &mut v);
        if hex_attr(&v[..n], 6).is_none() {
            return fail(N, b"class format", i as i64);
        }
        let mut cfg = [0u8; 4];
        if attr(b"config", &mut cfg) != 4
            || u32::from_le_bytes(cfg) != vendor | device << 16
        {
            return fail(N, b"config id", i as i64);
        }
        let mut b = [0u8; 256];
        let sz = stat(path(&mut b, &[base, d, b"/config\0"])).map_or(0, |st| st.st_size);
        if sz != 256 && sz != 4096 {
            return fail(N, b"config size", sz);
        }
        // MODALIAS=pci:v0000VVVVd0000DDDD...
        let mut want = *b"pci:v0000XXXXd0000XXXX";
        upper_hex(vendor, 4, &mut want[9..13]);
        upper_hex(device, 4, &mut want[18..22]);
        let n = attr(b"modalias", &mut v);
        if !v[..n].starts_with(&want) {
            return fail(N, b"modalias", i as i64);
        }
        let mut id = *b"PCI_ID=XXXX:XXXX";
        upper_hex(vendor, 4, &mut id[7..11]);
        upper_hex(device, 4, &mut id[12..16]);
        let mut u = [0u8; 1024];
        let n = attr(b"uevent", &mut u);
        let (mut has_id, mut has_slot) = (false, false);
        for line in u[..n].split(|&c| c == b'\n') {
            has_id |= line == id;
            has_slot |= line.strip_prefix(b"PCI_SLOT_NAME=") == Some(d);
        }
        if !has_id || !has_slot {
            return fail(N, b"uevent PCI_ID/PCI_SLOT_NAME", i as i64);
        }
    }
    ok(N);
}
