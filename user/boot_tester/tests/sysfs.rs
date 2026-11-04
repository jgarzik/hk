//! sysfs tests (hk and Linux): the mount, attribute files (seq_file
//! read semantics, open permission, lseek), directory link counts,
//! class devices, uevents.
//! Paths below /sys/devices differ between the kernels; tests use only
//! what both have.

use hk_syscall::{
    LinuxStatFs, O_DIRECTORY, O_RDONLY, O_WRONLY, Stat, sys_close, sys_getdents64, sys_lseek,
    sys_open, sys_read, sys_readlink, sys_stat, sys_statfs,
};

use super::helpers::{host_mode, linux_at_least, print, print_num, println, read_file, skip};
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
    test_bus_virtio();
    test_block();
    test_net();
    test_cpu();
    test_console();
    test_new_id();
    test_bus_usb();
    test_unbind_usb();
    test_unbind_blk();
    test_unbind_net();
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
    each_entry(b"/sys/kernel\0", &mut |_, ty| {
        subdirs += (ty == DT_DIR) as i64
    });
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
        (
            b"console dev",
            file_is(b"/sys/class/tty/console/dev\0", b"5:1\n"),
        ),
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
        for bad in [
            &b"frob"[..],
            b"add zzz",
            b"add 01234567-89ab-cdef-0123-456789abcdef A",
        ] {
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
            let k = read_file(
                path(&mut ub, &[base, b"devices/", dev, b"/uevent\0"]),
                &mut u,
            );
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
    v.iter()
        .try_fold(0u32, |a, &c| Some(a * 16 + (c as char).to_digit(16)?))
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
        if attr(b"config", &mut cfg) != 4 || u32::from_le_bytes(cfg) != vendor | device << 16 {
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

/// Every virtio device: device/vendor formats agreeing with modalias
/// and the uevent, a 64-digit features line; hk binds its net and block
/// devices
fn test_bus_virtio() {
    const N: &[u8] = b"SYSFS_BUS_VIRTIO";
    let devs = Names::of(b"/sys/bus/virtio/devices\0", DT_LNK);
    let base: &[u8] = b"/sys/bus/virtio/devices/";
    let mut bound = 0;
    for i in 0..devs.n {
        let d = devs.get(i);
        let attr = |name: &[u8], out: &mut [u8]| -> usize {
            let mut b = [0u8; 256];
            let n = read_file(path(&mut b, &[base, d, b"/", name, b"\0"]), out);
            n.max(0) as usize
        };
        let mut v = [0u8; 256];
        let n = attr(b"device", &mut v);
        let Some(device) = hex_attr(&v[..n], 4) else {
            return fail(N, b"device format", i as i64);
        };
        let n = attr(b"vendor", &mut v);
        let Some(vendor) = hex_attr(&v[..n], 4) else {
            return fail(N, b"vendor format", i as i64);
        };
        let mut want = *b"virtio:dXXXXXXXXvXXXXXXXX\n";
        upper_hex(device, 8, &mut want[8..16]);
        upper_hex(vendor, 8, &mut want[17..25]);
        let n = attr(b"modalias", &mut v);
        if v[..n] != want {
            return fail(N, b"modalias", i as i64);
        }
        // VIRTIO_FEATURES_BITS digits: 128 since Linux 6.17, 64 before
        let bits = if linux_at_least(6, 17) { 128 } else { 64 };
        let n = attr(b"features", &mut v);
        if n != bits + 1 || v[bits] != b'\n' || !v[..bits].iter().all(|&c| c == b'0' || c == b'1') {
            return fail(N, b"features", n as i64);
        }
        let mut u = [0u8; 512];
        let n = attr(b"uevent", &mut u);
        let line = &want[..want.len() - 1];
        let has = u[..n]
            .split(|&c| c == b'\n')
            .any(|l| l.strip_prefix(b"MODALIAS=") == Some(line));
        if !has {
            return fail(N, b"uevent MODALIAS", i as i64);
        }
        let mut b = [0u8; 256];
        bound += stat(path(&mut b, &[base, d, b"/driver\0"])).is_ok() as i64;
    }
    if bound == 0 && !host_mode() {
        return fail(N, b"no bound virtio device", 0);
    }
    ok(N);
}

/// "M:m\n" -> (M, m)
fn majmin(b: &[u8]) -> Option<(u64, u64)> {
    let b = b.strip_suffix(b"\n")?;
    let c = b.iter().position(|&x| x == b':')?;
    let (ma, mi) = (&b[..c], &b[c + 1..]);
    if ma.is_empty() || mi.is_empty() || !ma.iter().chain(mi).all(u8::is_ascii_digit) {
        return None;
    }
    Some((num(ma), num(mi)))
}

/// /proc/partitions has (major, minor) with `blocks` 1K blocks
fn in_partitions(ma: u64, mi: u64, blocks: u64) -> bool {
    let mut p = [0u8; 4096];
    let n = read_file(b"/proc/partitions\0", &mut p).max(0) as usize;
    p[..n].split(|&c| c == b'\n').skip(2).any(|l| {
        let mut f = l.split(|&c| c == b' ').filter(|w| !w.is_empty());
        let (Some(a), Some(b), Some(c)) = (f.next(), f.next(), f.next()) else {
            return false;
        };
        num(a) == ma && num(b) == mi && num(c) == blocks
    })
}

/// uevent of `dir` (NUL-terminated path prefix parts) has `want` lines
fn uevent_has(parts: &[&[u8]], want: &[&[u8]]) -> bool {
    let mut b = [0u8; 256];
    let mut u = [0u8; 1024];
    let mut v: [&[u8]; 8] = [b""; 8];
    let k = parts.len();
    v[..k].copy_from_slice(parts);
    v[k] = b"/uevent\0";
    let n = read_file(path(&mut b, &v[..=k]), &mut u).max(0) as usize;
    want.iter().all(|w| {
        u[..n]
            .split(|&c| c == b'\n')
            .any(|l| l == *w || (w.ends_with(b"=") && l.starts_with(w)))
    })
}

/// /sys/block: each disk's dev and size agree with /proc/partitions,
/// uevent DEVTYPE=disk and DISKSEQ; its partitions' partition attribute
/// and uevent PARTN
fn test_block() {
    const N: &[u8] = b"SYSFS_BLOCK";
    let disks = Names::of(b"/sys/block\0", DT_LNK);
    if disks.n == 0 {
        return fail(N, b"no disks", 0);
    }
    let base: &[u8] = b"/sys/block/";
    for i in 0..disks.n {
        let d = disks.get(i);
        let rd = |parts: &[&[u8]], out: &mut [u8]| -> usize {
            let mut b = [0u8; 256];
            read_file(path(&mut b, parts), out).max(0) as usize
        };
        let mut v = [0u8; 64];
        let n = rd(&[base, d, b"/dev\0"], &mut v);
        let Some((ma, mi)) = majmin(&v[..n]) else {
            return fail(N, b"dev format", i as i64);
        };
        let n = rd(&[base, d, b"/size\0"], &mut v);
        let size = num(&v[..n]);
        if size != 0 && !in_partitions(ma, mi, size / 2) {
            return fail(N, b"size vs /proc/partitions", i as i64);
        }
        if !uevent_has(&[base, d], &[b"DEVTYPE=disk", b"DISKSEQ="]) {
            return fail(N, b"disk uevent", i as i64);
        }
        let n = rd(&[base, d, b"/queue/logical_block_size\0"], &mut v);
        if n < 2 || num(&v[..n]) < 512 {
            return fail(N, b"logical_block_size", i as i64);
        }
        // Partitions: subdirectories named after the disk
        let mut db = [0u8; 256];
        let parts = Names::of(path(&mut db, &[base, d, b"\0"]), DT_DIR);
        for j in 0..parts.n {
            let p = parts.get(j);
            if !p.starts_with(d) {
                continue;
            }
            let n = rd(&[base, d, b"/", p, b"/partition\0"], &mut v);
            let no = &v[..n.saturating_sub(1)];
            let mut want = [0u8; 32];
            want[..6].copy_from_slice(b"PARTN=");
            want[6..6 + no.len()].copy_from_slice(no);
            let w: &[u8] = &want[..6 + no.len()];
            if no.is_empty() || !uevent_has(&[base, d, b"/", p], &[b"DEVTYPE=partition", w]) {
                return fail(N, b"partition", j as i64);
            }
        }
    }
    ok(N);
}

/// `%04x\n` (Linux idVendor/idProduct)
fn hex4(b: &[u8]) -> Option<u32> {
    let v = b.strip_suffix(b"\n")?;
    if v.len() != 4 || v.iter().any(|c| c.is_ascii_uppercase()) {
        return None;
    }
    v.iter()
        .try_fold(0u32, |a, &c| Some(a * 16 + (c as char).to_digit(16)?))
}

/// `%x` of `v`, into `out`: its length
fn lower_hex(v: u32, out: &mut [u8; 8]) -> usize {
    let digits = (1..8).find(|&d| v >> (4 * d) == 0).unwrap_or(8);
    for i in 0..digits {
        let d = (v >> (4 * (digits - 1 - i))) & 0xf;
        out[i] = b"0123456789abcdef"[d as usize];
    }
    digits
}

/// The value of `key` ("KEY=") among uevent lines
fn uevent_var<'a>(u: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    u.split(|&c| c == b'\n').find_map(|l| l.strip_prefix(key))
}

/// /sys/bus/usb/devices: each usb_device's idVendor/idProduct (%04x)
/// agree with its uevent PRODUCT, BUSNUM/DEVNUM with busnum/devnum;
/// each interface's modalias names its device's ids (upper hex) and is
/// its uevent MODALIAS. On hk the root hub is 1d6b:0002 and the boot
/// disk's interface is bound to usb-storage; the Linux reference VM
/// may have no USB devices at all
fn test_bus_usb() {
    const N: &[u8] = b"SYSFS_BUS_USB";
    let base: &[u8] = b"/sys/bus/usb/devices/";
    let mut sb = [0u8; 256];
    if stat(path(&mut sb, &[base])).is_err() {
        if host_mode() {
            return skip(N, b"no /sys/bus/usb");
        }
        return fail(N, b"no /sys/bus/usb", 0);
    }
    let devs = Names::of(b"/sys/bus/usb/devices\0", DT_LNK);
    let attr = |d: &[u8], name: &[u8], out: &mut [u8]| -> usize {
        let mut b = [0u8; 256];
        read_file(path(&mut b, &[base, d, b"/", name]), out).max(0) as usize
    };
    let (mut root_hub, mut storage) = (false, false);
    for i in 0..devs.n {
        let d = devs.get(i);
        let mut u = [0u8; 1024];
        let un = attr(d, b"uevent", &mut u);
        let u = &u[..un];
        let mut v = [0u8; 128];
        match uevent_var(u, b"DEVTYPE=") {
            Some(b"usb_device") => {
                let n = attr(d, b"idVendor", &mut v);
                let Some(vendor) = hex4(&v[..n]) else {
                    return fail(N, b"idVendor format", i as i64);
                };
                let n = attr(d, b"idProduct", &mut v);
                let Some(product) = hex4(&v[..n]) else {
                    return fail(N, b"idProduct format", i as i64);
                };
                // PRODUCT=%x/%x/%x
                let mut want = [0u8; 18];
                let mut h = [0u8; 8];
                let a = lower_hex(vendor, &mut h);
                want[..a].copy_from_slice(&h[..a]);
                want[a] = b'/';
                let b = lower_hex(product, &mut h);
                want[a + 1..a + 1 + b].copy_from_slice(&h[..b]);
                want[a + 1 + b] = b'/';
                let p = uevent_var(u, b"PRODUCT=").unwrap_or(b"");
                if !p.starts_with(&want[..a + b + 2]) {
                    return fail(N, b"uevent PRODUCT", i as i64);
                }
                for (key, name) in [(&b"BUSNUM="[..], &b"busnum"[..]), (b"DEVNUM=", b"devnum")] {
                    let n = attr(d, name, &mut v);
                    let num = uevent_var(u, key).unwrap_or(b"");
                    let num = num
                        .strip_prefix(b"00")
                        .or(num.strip_prefix(b"0"))
                        .unwrap_or(num);
                    if num.is_empty() || v[..n].strip_suffix(b"\n") != Some(num) {
                        return fail(N, b"uevent BUSNUM/DEVNUM", i as i64);
                    }
                }
                let n = attr(d, b"version", &mut v);
                if n != 6 || v[2] != b'.' {
                    return fail(N, b"version format", n as i64);
                }
                root_hub |= d == b"usb1" && vendor == 0x1d6b && product == 2;
            }
            Some(b"usb_interface") => {
                // The device: the interface's parent directory (the root
                // hub's interfaces are 1-0:1.0 below usb1)
                let mut id = [0u8; 16];
                let n = attr(d, b"../idVendor", &mut id);
                let Some(vendor) = hex4(&id[..n]) else {
                    return fail(N, b"interface's idVendor", i as i64);
                };
                let mut want = *b"usb:vXXXX";
                upper_hex(vendor, 4, &mut want[5..]);
                let n = attr(d, b"modalias", &mut v);
                if !v[..n].starts_with(&want) {
                    return fail(N, b"modalias", i as i64);
                }
                let m = uevent_var(u, b"MODALIAS=").unwrap_or(b"");
                if v[..n].strip_suffix(b"\n") != Some(m) || uevent_var(u, b"INTERFACE=").is_none() {
                    return fail(N, b"uevent MODALIAS/INTERFACE", i as i64);
                }
                let mut lb = [0u8; 256];
                let mut t = [0u8; 256];
                let p = path(&mut lb, &[base, d, b"/driver\0"]);
                let n = sys_readlink(p.as_ptr(), t.as_mut_ptr(), t.len() as u64);
                storage |= n > 0 && t[..n as usize].ends_with(b"/usb-storage");
            }
            _ => return fail(N, b"uevent DEVTYPE", i as i64),
        }
    }
    if !host_mode() && !(root_hub && storage) {
        return fail(N, b"hk: root hub or usb-storage interface", 0);
    }
    ok(N);
}

/// /sys/class/net/lo: its virtual device link, attributes and uevent;
/// a new network namespace's sysfs mount shows only its own lo, while
/// the mount made before keeps the old namespace's devices
fn test_net() {
    const N: &[u8] = b"SYSFS_NET";
    use hk_syscall::{
        CLONE_NEWNET, sys_exit, sys_fork, sys_mkdir, sys_mount, sys_rmdir, sys_umount2,
        sys_unshare, sys_wait4,
    };
    if !link_is(b"/sys/class/net/lo\0", b"../../devices/virtual/net/lo") {
        return fail(N, b"lo link", 0);
    }
    let checks: [(&[u8], &[u8]); 5] = [
        (b"/sys/class/net/lo/ifindex\0", b"1\n"),
        (b"/sys/class/net/lo/type\0", b"772\n"),
        (b"/sys/class/net/lo/address\0", b"00:00:00:00:00:00\n"),
        (b"/sys/class/net/lo/addr_len\0", b"6\n"),
        (b"/sys/class/net/lo/uevent\0", b"INTERFACE=lo\nIFINDEX=1\n"),
    ];
    for (i, (p, want)) in checks.iter().enumerate() {
        if !file_is(p, want) {
            return fail(N, b"lo attribute", i as i64);
        }
    }
    let mut f = [0u8; 32];
    let n = read_file(b"/sys/class/net/lo/flags\0", &mut f).max(0) as usize;
    let flags = f[..n]
        .strip_prefix(b"0x")
        .and_then(|v| v.strip_suffix(b"\n"))
        .map(|v| {
            v.iter()
                .fold(0u32, |a, &c| a * 16 + (c as char).to_digit(16).unwrap_or(0))
        });
    // IFF_UP | IFF_LOOPBACK (boot_tester brought lo up)
    if flags.is_none_or(|fl| fl & 0x9 != 0x9) {
        return fail(N, b"lo flags", n as i64);
    }
    let before = Names::of(b"/sys/class/net\0", DT_LNK).n;
    let pid = sys_fork();
    if pid == 0 {
        if sys_unshare(CLONE_NEWNET) != 0 {
            sys_exit(2);
        }
        let dir = b"/tmp/sysfs_netns\0";
        sys_mkdir(dir.as_ptr(), 0o755);
        let r = sys_mount(b"sysfs\0".as_ptr(), dir.as_ptr(), b"sysfs\0".as_ptr(), 0, 0);
        if r != 0 {
            sys_exit(3);
        }
        let new = Names::of(b"/tmp/sysfs_netns/class/net\0", DT_LNK);
        let only_lo = new.n == 1 && new.get(0) == b"lo";
        let lo1 = file_is(b"/tmp/sysfs_netns/class/net/lo/ifindex\0", b"1\n");
        let old = Names::of(b"/sys/class/net\0", DT_LNK).n;
        sys_umount2(dir.as_ptr(), 0);
        sys_rmdir(dir.as_ptr());
        let code = if !only_lo {
            4
        } else if !lo1 {
            5
        } else if old != before {
            6
        } else {
            0
        };
        sys_exit(code);
    }
    let mut st: i32 = 0;
    sys_wait4(pid, &mut st, 0, 0);
    let code = (st >> 8) & 0xff;
    if st & 0x7f != 0 || code != 0 {
        return fail(N, b"netns child", code as i64);
    }
    ok(N);
}

/// Parse a range list ("0-3,5\n") into a 256-bit mask; None if malformed
fn parse_list(b: &[u8]) -> Option<[u64; 4]> {
    let b = b.strip_suffix(b"\n")?;
    let mut m = [0u64; 4];
    if b.is_empty() {
        return Some(m);
    }
    for part in b.split(|&c| c == b',') {
        let (lo, hi) = match part.iter().position(|&c| c == b'-') {
            Some(i) => (&part[..i], &part[i + 1..]),
            None => (part, part),
        };
        if lo.is_empty() || hi.is_empty() || !lo.iter().chain(hi).all(u8::is_ascii_digit) {
            return None;
        }
        for c in num(lo)..=num(hi) {
            if c >= 256 {
                return None;
            }
            m[(c / 64) as usize] |= 1 << (c % 64);
        }
    }
    Some(m)
}

fn list_of(p: &[u8]) -> Option<[u64; 4]> {
    let mut b = [0u8; 512];
    let n = read_file(p, &mut b);
    if n < 0 {
        return None;
    }
    parse_list(&b[..n as usize])
}

/// /sys/devices/system/cpu: online is the affinity set boot_tester runs
/// with, inside possible; cpu0 is a cpu-bus device; node0 lists CPUs
/// and links them
fn test_cpu() {
    const N: &[u8] = b"SYSFS_CPU";
    let (Some(online), Some(possible)) = (
        list_of(b"/sys/devices/system/cpu/online\0"),
        list_of(b"/sys/devices/system/cpu/possible\0"),
    ) else {
        return fail(N, b"online/possible format", 0);
    };
    let mut aff = [0u64; 16];
    let r = hk_syscall::sys_sched_getaffinity(0, 128, aff.as_mut_ptr());
    if r <= 0 {
        return fail(N, b"sched_getaffinity", r);
    }
    let aff_n: u32 = aff.iter().map(|w| w.count_ones()).sum();
    let on_n: u32 = online.iter().map(|w| w.count_ones()).sum();
    if on_n != aff_n || (0..4).any(|i| online[i] & !possible[i] != 0) {
        return fail(N, b"online vs affinity/possible", on_n as i64);
    }
    match stat(b"/sys/devices/system/cpu/cpu0\0") {
        Ok(st) if st.st_mode & S_IFMT == S_IFDIR => {}
        _ => return fail(N, b"cpu0", 0),
    }
    if !link_is(
        b"/sys/bus/cpu/devices/cpu0\0",
        b"../../../devices/system/cpu/cpu0",
    ) {
        return fail(N, b"bus link", 0);
    }
    let Some(nodes) = list_of(b"/sys/devices/system/node/online\0") else {
        return fail(N, b"node online", 0);
    };
    if nodes[0] & 1 == 0 {
        return fail(N, b"node0 offline", 0);
    }
    let Some(n0) = list_of(b"/sys/devices/system/node/node0/cpulist\0") else {
        return fail(N, b"node0 cpulist", 0);
    };
    if n0[0] & 1 != 0 && stat(b"/sys/devices/system/node/node0/cpu0\0").is_err() {
        return fail(N, b"node0/cpu0 link", 0);
    }
    ok(N);
}

/// Receive uevents until one with a header starting `act` and ending
/// `tail` arrives (other devices' events skipped)
fn event_ending(fd: i32, act: &[u8], tail: &[u8]) -> bool {
    let mut buf = [0u8; 2048];
    for _ in 0..64 {
        let (n, _) = recv_creds(fd, &mut buf);
        if n <= 0 {
            return false;
        }
        if let Some(h) = vars(&buf[..n as usize]).next()
            && h.starts_with(act)
            && h.ends_with(tail)
        {
            return true;
        }
    }
    false
}

/// The transport level: unbinding the PCI function from virtio-pci
/// deletes its virtio device `v` (and the disk `d` with it); binding it
/// back registers it again under the freed index, with the disk
fn unbind_pci(fd: i32, d: &[u8], v: &[u8], before: &[u8; 512]) -> Result<(), (&'static [u8], i64)> {
    // The function: the directory above the virtio device
    let mut lb = [0u8; 256];
    let mut t = [0u8; 256];
    let p = path(&mut lb, &[b"/sys/bus/virtio/devices/", v]);
    let n = sys_readlink(p.as_ptr(), t.as_mut_ptr(), t.len() as u64);
    if n <= 0 {
        return Err((b"virtio device link", n));
    }
    let t = &t[..n as usize];
    let up = &t[..t.iter().rposition(|&c| c == b'/').unwrap_or(0)];
    let f = &up[up.iter().rposition(|&c| c == b'/').map_or(0, |k| k + 1)..];
    let drv: &[u8] = b"/sys/bus/pci/drivers/virtio-pci/";
    let mut ub = [0u8; 256];
    let w = write_str(path(&mut ub, &[drv, b"unbind"]), f);
    if w != f.len() as i64 {
        return Err((b"pci unbind", w));
    }
    let mut tail = [0u8; 64];
    tail[0] = b'/';
    tail[1..=v.len()].copy_from_slice(v);
    if !event_ending(fd, b"remove@", &tail[..=v.len()]) {
        return Err((b"no virtio remove event", 0));
    }
    let mut sb = [0u8; 256];
    if stat(path(&mut sb, &[b"/sys/bus/virtio/devices/", v])).is_ok() {
        return Err((b"virtio device still there", 0));
    }
    let mut bb = [0u8; 256];
    let w = write_str(path(&mut bb, &[drv, b"bind"]), f);
    if w != f.len() as i64 {
        return Err((b"pci bind", w));
    }
    let mut sb = [0u8; 256];
    if stat(path(&mut sb, &[b"/sys/bus/virtio/devices/", v, b"/driver"])).is_err() {
        return Err((b"virtio device not back", 0));
    }
    let mut after = [0u8; 512];
    let r = sector0(d, &mut after);
    if r != 512 || after != *before {
        return Err((b"read after pci bind", r));
    }
    Ok(())
}

/// The first sector of /dev/<d>
fn sector0(d: &[u8], out: &mut [u8; 512]) -> i64 {
    let mut b = [0u8; 256];
    let fd = sys_open(path(&mut b, &[b"/dev/", d]).as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        return fd;
    }
    let n = hk_syscall::sys_pread64(fd as i32, out.as_mut_ptr(), 512, 0);
    sys_close(fd as u64);
    n
}

/// Unbinding the first virtio disk's device from virtio_blk removes the
/// disk (/sys/block, /dev, "remove" then "unbind" uevents) and fails
/// I/O on a file still open with EIO; binding it back brings the disk
/// back under its name with the same data. hk only: the Linux reference
/// VM may boot from its virtio disk
fn test_unbind_blk() {
    const N: &[u8] = b"SYSFS_UNBIND_BLK";
    if host_mode() {
        return skip(N, b"would remove the reference VM's disk");
    }
    let disks = Names::of(b"/sys/block\0", DT_LNK);
    let Some(i) = (0..disks.n).find(|&i| disks.get(i).starts_with(b"vd")) else {
        return fail(N, b"no virtio disk", 0);
    };
    let d = disks.get(i);
    // The virtio device: the last part of the disk's device link
    let mut lb = [0u8; 256];
    let mut t = [0u8; 256];
    let p = path(&mut lb, &[b"/sys/block/", d, b"/device"]);
    let n = sys_readlink(p.as_ptr(), t.as_mut_ptr(), t.len() as u64);
    if n <= 0 {
        return fail(N, b"device link", n);
    }
    let t = &t[..n as usize];
    let v = &t[t.iter().rposition(|&c| c == b'/').map_or(0, |k| k + 1)..];
    if !v.starts_with(b"virtio") {
        return fail(N, b"not a virtio device", 0);
    }
    let mut before = [0u8; 512];
    let r = sector0(d, &mut before);
    if r != 512 {
        return fail(N, b"read before", r);
    }
    let Some(fd) = uevent_sock() else {
        return fail(N, b"socket", 0);
    };
    let r = (|| {
        let mut nb = [0u8; 256];
        let node = path(&mut nb, &[b"/dev/", d]);
        let held = sys_open(node.as_ptr(), O_RDONLY, 0);
        if held < 0 {
            return Err((&b"open"[..], held));
        }
        let drv: &[u8] = b"/sys/bus/virtio/drivers/virtio_blk/";
        let mut ub = [0u8; 256];
        let w = write_str(path(&mut ub, &[drv, b"unbind"]), v);
        // Uncached data of the removed disk: EIO
        let mut x = [0u8; 512];
        let e = hk_syscall::sys_pread64(held as i32, x.as_mut_ptr(), 512, 1 << 20);
        sys_close(held as u64);
        if w != v.len() as i64 {
            return Err((&b"unbind"[..], w));
        }
        if e != -5 {
            return Err((&b"read of a removed disk"[..], e));
        }
        let mut tail = [0u8; 64];
        tail[0] = b'/';
        tail[1..=d.len()].copy_from_slice(d);
        if !event_ending(fd, b"remove@", &tail[..=d.len()]) {
            return Err((&b"no remove event"[..], 0));
        }
        tail[1..=v.len()].copy_from_slice(v);
        if !event_ending(fd, b"unbind@", &tail[..=v.len()]) {
            return Err((&b"no unbind event"[..], 0));
        }
        let mut sb = [0u8; 256];
        if stat(path(&mut sb, &[b"/sys/block/", d])).is_ok() || stat(node).is_ok() {
            return Err((&b"disk still there"[..], 0));
        }
        let mut bb = [0u8; 256];
        let w = write_str(path(&mut bb, &[drv, b"bind"]), v);
        if w != v.len() as i64 {
            return Err((&b"bind"[..], w));
        }
        if !event_ending(fd, b"bind@", &tail[..=v.len()]) {
            return Err((&b"no bind event"[..], 0));
        }
        let mut sb = [0u8; 256];
        if stat(path(&mut sb, &[b"/sys/block/", d])).is_err() {
            return Err((&b"disk not back"[..], 0));
        }
        let mut after = [0u8; 512];
        let r = sector0(d, &mut after);
        if r != 512 || after != before {
            return Err((&b"read after bind"[..], r));
        }
        unbind_pci(fd, d, v, &before)
    })();
    sys_close(fd as u64);
    match r {
        Ok(()) => ok(N),
        Err((why, v)) => fail(N, why, v),
    }
}

/// eth0's administrative flags (SIOCGIFFLAGS) or a negative errno
fn eth0_flags(set: Option<u16>) -> i64 {
    use hk_syscall::{sys_ioctl, sys_socket};
    const SIOCGIFFLAGS: u64 = 0x8913;
    const SIOCSIFFLAGS: u64 = 0x8914;
    let fd = sys_socket(2, 2, 0);
    if fd < 0 {
        return fd;
    }
    let mut ifr = [0u8; 40];
    ifr[..4].copy_from_slice(b"eth0");
    let mut r = sys_ioctl(fd as i32, SIOCGIFFLAGS, ifr.as_mut_ptr() as u64);
    if r == 0
        && let Some(f) = set
    {
        ifr[16..18].copy_from_slice(&f.to_ne_bytes());
        r = sys_ioctl(fd as i32, SIOCSIFFLAGS, ifr.as_mut_ptr() as u64);
    }
    sys_close(fd as u64);
    if r < 0 {
        r
    } else {
        u16::from_ne_bytes([ifr[16], ifr[17]]) as i64
    }
}

fn eth0_ifindex() -> u64 {
    let mut b = [0u8; 32];
    let n = read_file(b"/sys/class/net/eth0/ifindex\0", &mut b);
    num(&b[..n.max(0) as usize])
}

/// /proc/net/dev has an eth0 line
fn proc_has_eth0() -> bool {
    let mut b = [0u8; 4096];
    let n = read_file(b"/proc/net/dev\0", &mut b).max(0) as usize;
    b[..n]
        .split(|&c| c == b'\n')
        .any(|l| l.trim_ascii_start().starts_with(b"eth0:"))
}

/// "<action>@<devpath>" in `buf`
fn head<'a>(buf: &'a mut [u8; 256], action: &[u8], devpath: &[u8]) -> &'a [u8] {
    let n = path(buf, &[action, b"@", devpath]).len() - 1;
    &buf[..n]
}

/// The NIC behind eth0, unbound from its driver through sysfs and bound
/// back (Linux unbind_store -> driver remove -> unregister_netdev):
/// while unbound eth0 is gone from /sys/class/net and /proc/net/dev and
/// the device has no driver link; "remove" (eth0) and "unbind" (the
/// device) uevents arrive in that order, "add" and "bind" on rebind;
/// eth0 comes back with a new ifindex and goes up with its link. Runs
/// before the network tests configure eth0; its flags are restored
fn test_unbind_net() {
    const N: &[u8] = b"SYSFS_UNBIND_NET";
    let mut lk = [0u8; 256];
    let n = sys_readlink(b"/sys/class/net/eth0\0".as_ptr(), lk.as_mut_ptr(), 255);
    if n < 0 {
        return if host_mode() {
            skip(N, b"no eth0")
        } else {
            fail(N, b"no eth0", n)
        };
    }
    // ../../devices/<parent>/net/eth0
    let Some(devpath) = lk[..n as usize].strip_prefix(b"../..") else {
        return fail(N, b"class link", n);
    };
    let Some(parent) = devpath.strip_suffix(b"/net/eth0") else {
        return fail(N, b"not below its device", n);
    };
    let name = parent.rsplit(|&c| c == b'/').next().unwrap_or(b"");
    let mut dl = [0u8; 256];
    let k = sys_readlink(
        b"/sys/class/net/eth0/device/driver\0".as_ptr(),
        dl.as_mut_ptr(),
        255,
    );
    // .../bus/<bus>/drivers/<drv>
    let drv = &dl[..k.max(0) as usize];
    let Some(at) = drv.windows(5).position(|w| w == b"/bus/") else {
        return fail(N, b"driver link", k);
    };
    let drv = &drv[at..];
    let old = eth0_ifindex();
    let flags = eth0_flags(None);
    if flags < 0 {
        return fail(N, b"SIOCGIFFLAGS", flags);
    }
    // Up, so unregistering closes it too
    let r = eth0_flags(Some(flags as u16 | 1));
    if r < 0 {
        return fail(N, b"up", r);
    }
    let Some(fd) = uevent_sock() else {
        return fail(N, b"uevent socket", 0);
    };
    let r = unbind_rebind(fd, devpath, parent, name, drv);
    sys_close(fd as u64);
    if let Err((why, v)) = r {
        return fail(N, why, v);
    }
    let new = eth0_ifindex();
    if new <= old {
        return fail(N, b"ifindex not new", new as i64);
    }
    let r = eth0_flags(Some(flags as u16 | 1));
    if r < 0 {
        return fail(N, b"up again", r);
    }
    let ts = hk_syscall::Timespec {
        tv_sec: 0,
        tv_nsec: 10_000_000,
    };
    let mut up = false;
    for _ in 0..300 {
        up = file_is(b"/sys/class/net/eth0/operstate\0", b"up\n");
        if up {
            break;
        }
        hk_syscall::sys_nanosleep(&ts, core::ptr::null_mut());
    }
    let r = eth0_flags(Some(flags as u16));
    if !up {
        return fail(N, b"no link after rebind", 0);
    }
    if r < 0 {
        return fail(N, b"restore flags", r);
    }
    ok(N);
}

fn unbind_rebind(
    fd: i32,
    devpath: &[u8],
    parent: &[u8],
    name: &[u8],
    drv: &[u8],
) -> Result<(), (&'static [u8], i64)> {
    let mut p = [0u8; 256];
    let mut h = [0u8; 256];
    let mut buf = [0u8; 2048];
    let unbind = path(&mut p, &[b"/sys", drv, b"/unbind\0"]);
    let r = write_str(unbind, name);
    if r != name.len() as i64 {
        return Err((b"unbind", r));
    }
    if next_event(fd, head(&mut h, b"remove", devpath), &mut buf).is_none() {
        return Err((b"no remove event", 0));
    }
    if next_event(fd, head(&mut h, b"unbind", parent), &mut buf).is_none() {
        return Err((b"no unbind event", 0));
    }
    if stat(b"/sys/class/net/eth0\0").is_ok() {
        return Err((b"eth0 still in sysfs", 0));
    }
    if proc_has_eth0() {
        return Err((b"eth0 still in /proc/net/dev", 0));
    }
    if stat(path(&mut p, &[b"/sys", parent, b"/driver\0"])).is_ok() {
        return Err((b"driver link stays", 0));
    }
    let bind = path(&mut p, &[b"/sys", drv, b"/bind\0"]);
    let r = write_str(bind, name);
    if r != name.len() as i64 {
        return Err((b"bind", r));
    }
    if next_event(fd, head(&mut h, b"add", devpath), &mut buf).is_none() {
        return Err((b"no add event", 0));
    }
    if next_event(fd, head(&mut h, b"bind", parent), &mut buf).is_none() {
        return Err((b"no bind event", 0));
    }
    if !proc_has_eth0() {
        return Err((b"eth0 not back", 0));
    }
    Ok(())
}

/// The first bound device of driver directory `drv` (a link, not
/// `module`)
fn bound_dev(drv: &[u8]) -> Option<([u8; 63], usize)> {
    let devs = Names::of(drv, DT_LNK);
    let d = (0..devs.n).map(|i| devs.get(i)).find(|d| *d != b"module")?;
    let mut out = [0u8; 63];
    out[..d.len()].copy_from_slice(d);
    Some((out, d.len()))
}

/// Receive until an event whose header is `action` and ends in `tail`
fn wait_event(fd: i32, action: &[u8], tail: &[u8]) -> bool {
    let mut buf = [0u8; 2048];
    for _ in 0..64 {
        let (n, _) = recv_creds(fd, &mut buf);
        if n <= 0 {
            return false;
        }
        let head = vars(&buf[..n as usize]).next().unwrap_or(b"");
        if head.starts_with(action) && head.ends_with(tail) {
            return true;
        }
    }
    false
}

/// The first sector of /dev/sda
fn sda_sector() -> Option<[u8; 512]> {
    let fd = sys_open(b"/dev/sda\0".as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        return None;
    }
    let mut b = [0u8; 512];
    let n = sys_read(fd as u64, b.as_mut_ptr(), 512);
    sys_close(fd as u64);
    (n == 512).then_some(b)
}

/// An event's action and the end of its path
type Event = (&'static [u8], &'static [u8]);

/// Unbind `dev` from driver directory `drv` (with its trailing /) and
/// bind it back: sda must be gone after the `down` events, back after
/// the `up` ones (`dev` stands for an empty tail: the device's own
/// event), its first sector `sector` again
fn usb_unbind_rebind(
    fd: i32,
    drv: &[u8],
    dev: &[u8],
    down: &[Event],
    up: &[Event],
    sector: &[u8; 512],
) -> Result<(), (&'static [u8], i64)> {
    let tail = |t: &'static [u8]| if t.is_empty() { dev } else { t };
    let mut b = [0u8; 256];
    if write_str(path(&mut b, &[drv, b"unbind"]), dev) != dev.len() as i64 {
        return Err((b"unbind write", 0));
    }
    for (i, (a, t)) in down.iter().enumerate() {
        if !wait_event(fd, a, tail(*t)) {
            return Err((b"unbind event", i as i64));
        }
    }
    let gone: [&[u8]; 3] = [
        b"/sys/block/sda\0",
        b"/sys/class/block/sda\0",
        b"/dev/sda\0",
    ];
    for (i, p) in gone.iter().enumerate() {
        if stat(p).is_ok() {
            return Err((b"disk still there", i as i64));
        }
    }
    if stat(path(&mut b, &[drv, dev])).is_ok() {
        return Err((b"driver link left", 0));
    }
    if write_str(path(&mut b, &[drv, b"bind"]), dev) != dev.len() as i64 {
        return Err((b"bind write", 0));
    }
    for (i, (a, t)) in up.iter().enumerate() {
        if !wait_event(fd, a, tail(*t)) {
            return Err((b"bind event", i as i64));
        }
    }
    if sda_sector().as_ref() != Some(sector) {
        return Err((b"sda after bind", 0));
    }
    Ok(())
}

/// Driver unbind and rebind (hk): the usb-storage interface (its disk,
/// sda, goes with del_gendisk semantics and comes back the same), then
/// the xHCI (the whole USB tree goes and is enumerated again). The
/// reference VM has no USB
fn test_unbind_usb() {
    const N: &[u8] = b"SYSFS_UNBIND_USB";
    let Some((ib, il)) = bound_dev(b"/sys/bus/usb/drivers/usb-storage\0") else {
        if host_mode() {
            return skip(N, b"no USB storage on the reference VM");
        }
        return fail(N, b"no usb-storage interface", 0);
    };
    let Some((pb, pl)) = bound_dev(b"/sys/bus/pci/drivers/xhci_hcd\0") else {
        return fail(N, b"no xhci_hcd device", 0);
    };
    let Some(sector) = sda_sector() else {
        return fail(N, b"read sda", 0);
    };
    let Some(fd) = uevent_sock() else {
        return fail(N, b"socket", 0);
    };
    let r = usb_unbind_rebind(
        fd,
        b"/sys/bus/usb/drivers/usb-storage/",
        &ib[..il],
        &[(b"remove@", b"/block/sda"), (b"unbind@", b"")],
        &[(b"add@", b"/block/sda"), (b"bind@", b"")],
        &sector,
    )
    .and_then(|()| {
        usb_unbind_rebind(
            fd,
            b"/sys/bus/pci/drivers/xhci_hcd/",
            &pb[..pl],
            &[
                (b"remove@", b"/block/sda"),
                (b"remove@", b"/usb1"),
                (b"unbind@", b""),
            ],
            &[
                (b"add@", b"/usb1"),
                (b"add@", b"/block/sda"),
                (b"bind@", b""),
            ],
            &sector,
        )
        .map_err(|(why, v)| (why, v + 100))
    })
    .and_then(|()| match stat(b"/sys/bus/usb/devices/usb1\0") {
        Ok(_) => Ok(()),
        Err(e) => Err((&b"usb1 after bind"[..], e)),
    });
    sys_close(fd as u64);
    match r {
        Ok(()) => ok(N),
        Err((why, v)) => fail(N, why, v),
    }
}

/// /sys/class/tty/console/active: the console ttys, each a tty class
/// device
fn test_console() {
    const N: &[u8] = b"SYSFS_CONSOLE";
    let mut b = [0u8; 256];
    let n = read_file(b"/sys/class/tty/console/active\0", &mut b);
    if n < 2 || b[n as usize - 1] != b'\n' {
        return fail(N, b"active format", n);
    }
    let mut count = 0;
    for name in b[..n as usize - 1].split(|&c| c == b' ') {
        let mut p = [0u8; 256];
        if name.is_empty() || stat(path(&mut p, &[b"/sys/class/tty/", name, b"/dev\0"])).is_err() {
            return fail(N, b"console tty", count);
        }
        count += 1;
    }
    ok(N);
}

/// PCI and USB drivers' new_id/remove_id (Linux new_id_store,
/// remove_id_store, usb_store_new_id): ids an existing entry matches
/// are EEXIST, a removed one ENODEV on the second removal, malformed
/// writes EINVAL; device-level USB drivers have no new_id
fn test_new_id() {
    const N: &[u8] = b"SYSFS_NEW_ID";
    let pci = b"/sys/bus/pci/drivers/virtio-pci/";
    let mut b = [0u8; 256];
    if stat(path(&mut b, &[pci, b"new_id\0"])).is_err() {
        if host_mode() {
            return super::helpers::skip(N, b"no virtio-pci driver");
        }
        return fail(N, b"virtio-pci new_id", 0);
    }
    let w = |f: &[u8], d: &[u8]| {
        let mut b = [0u8; 256];
        write_str(path(&mut b, &[pci, f, b"\0"]), d)
    };
    let steps: [(&[u8], &[u8], i64); 7] = [
        (b"new_id", b"1af4 1000\n", -17),
        (b"new_id", b"1234 5678\n", 10),
        (b"new_id", b"1234 5678\n", -17),
        (b"new_id", b"1234 5679 ffffffff ffffffff 0 0 1\n", -22),
        (b"remove_id", b"1234 5678\n", 10),
        (b"remove_id", b"1234 5678\n", -19),
        (b"new_id", b"zz\n", -22),
    ];
    for (i, (f, d, want)) in steps.iter().enumerate() {
        let r = w(f, d);
        if r != *want {
            return fail(N, b"pci step", (i as i64) * 1000 + r);
        }
    }
    let usb = b"/sys/bus/usb/drivers/usb-storage/";
    if stat(path(&mut b, &[usb, b"new_id\0"])).is_ok() {
        let mut p = [0u8; 256];
        if write_str(path(&mut p, &[usb, b"new_id\0"]), b"1234 5678\n") != 10
            || write_str(path(&mut p, &[usb, b"remove_id\0"]), b"1234 5678\n") != 10
            || write_str(path(&mut p, &[usb, b"remove_id\0"]), b"1234\n") != -22
        {
            return fail(N, b"usb", 0);
        }
    } else if !host_mode() {
        return fail(N, b"usb-storage new_id", 0);
    }
    if stat(b"/sys/bus/usb/drivers/usb/new_id\0").is_ok() {
        return fail(N, b"usb generic new_id", 0);
    }
    ok(N);
}
