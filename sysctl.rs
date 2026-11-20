//! /proc/sys tables (Linux kernel/sysctl.c, fs/proc/proc_sysctl.c subset)
//!
//! A `Ctl` is one /proc/sys file: a path below /proc/sys, a mode and
//! show/store functions over a vector of integers (Linux proc_dointvec
//! family). Values live with their subsystem, so this module holds no
//! state and no locks. Network sysctls are per namespace
//! (`net::sysctl::NetCtl`, Linux net_sysctl_root): a /proc/sys/net file
//! is an [`Entry`] bound to the namespace its directory was looked up
//! in (Linux the inode's ctl_table_header, of that net->sysctls set).
//!
//! Writes follow Linux semantics: whitespace-separated decimal integers,
//! fewer values than the vector leaves the rest unchanged, anything
//! unparsable or out of range is EINVAL, writes at a non-zero file
//! offset are ignored (sysctl_writes_strict = 1).

use alloc::string::String;
use alloc::sync::Weak;
use alloc::vec::Vec;

use crate::net::sysctl::{CtlGrab, CtlRef};
use crate::net::{NetNamespace, NetRef};
use crate::util::error::KernelError;

/// One /proc/sys entry
pub struct Ctl {
    /// Path below /proc/sys ("net/ipv4/ip_local_port_range")
    pub path: &'static str,
    /// File mode bits (0644, 0444)
    pub mode: u16,
    /// Current value
    pub show: fn() -> Vec<i64>,
    /// Validate and store a value (as many integers as `show` returns;
    /// ones the writer left out are the current values)
    pub store: fn(&[i64]) -> Result<(), KernelError>,
    /// A string value instead (Linux proc_dostring users such as
    /// tcp_congestion_control): show, and store of the trimmed text
    pub text: Option<Text>,
}

/// Show / store of a string sysctl
pub struct Text {
    pub show: fn() -> String,
    pub store: fn(&str) -> Result<(), KernelError>,
}

/// What a /proc/sys file acts on (Linux an inode's ctl_table_header and
/// ctl_table entry): a global entry, or a network namespace's, bound to
/// the namespace whose tree it was found in by a weak reference (the
/// file does not keep the namespace: Linux's header outlives it,
/// unregistering) and that namespace's id
#[derive(Clone)]
pub enum Entry {
    Global(&'static Ctl),
    Net {
        ctl: CtlRef,
        net: Weak<NetNamespace>,
        id: u64,
        /// The entry's mode in that namespace (`NetCtl::mode_in`)
        mode: u16,
        set: alloc::sync::Arc<crate::net::sysctl::SysctlSet>,
    },
}

/// An entry in use (Linux sysctl_head_grab, use_table): a network one
/// holds its namespace active, so the namespace's teardown waits for it
/// (Linux start_unregistering waits for the users)
enum Grab {
    Global(&'static Ctl),
    Net(CtlGrab, NetRef),
}

/// What a permission check needs of an entry (Linux sysctl_perm: the
/// mode, and whether its root is net_sysctl_root, whose
/// net_ctl_permissions lets CAP_NET_ADMIN act as root)
#[derive(Clone, Copy)]
pub struct Perm {
    pub mode: u16,
    pub net: bool,
}

impl Entry {
    /// A network entry of `net`
    pub fn net(ctl: CtlRef, net: &alloc::sync::Arc<NetNamespace>) -> Self {
        Self::Net {
            mode: ctl.mode_in(net),
            ctl,
            net: alloc::sync::Arc::downgrade(net),
            id: net.id,
            set: net.sysctls.clone(),
        }
    }

    /// In use, or ENOENT once its namespace is going or its device's
    /// directory went (Linux sysctl_head_grab: -ENOENT while
    /// unregistering)
    fn grab(&self) -> Result<Grab, KernelError> {
        match self {
            Self::Global(c) => Ok(Grab::Global(c)),
            Self::Net { set, .. } if set.unregistering() => Err(KernelError::NotFound),
            Self::Net { ctl, net, .. } => {
                let n = net
                    .upgrade()
                    .and_then(|n| n.maybe_get())
                    .ok_or(KernelError::NotFound)?;
                Ok(Grab::Net(ctl.grab()?, n))
            }
        }
    }

    /// Its namespace's teardown started (Linux head->unregistering):
    /// a flag read, no reference taken
    pub fn unregistering(&self) -> bool {
        match self {
            Self::Global(_) => false,
            Self::Net { set, ctl, .. } => set.unregistering() || ctl.gone(),
        }
    }

    /// Its permission data
    pub fn perm(&self) -> Perm {
        match self {
            Self::Global(c) => Perm {
                mode: c.mode,
                net: false,
            },
            Self::Net { mode, .. } => Perm {
                mode: *mode,
                net: true,
            },
        }
    }

    /// A string sysctl (proc_dostring)
    pub fn is_text(&self) -> bool {
        match self {
            Self::Global(c) => c.text.is_some(),
            Self::Net { ctl, .. } => ctl.is_text(),
        }
    }

    /// The id of the network namespace it is bound to
    pub fn net_id(&self) -> Option<u64> {
        match self {
            Self::Global(_) => None,
            Self::Net { id, .. } => Some(*id),
        }
    }
}

impl Grab {
    fn show(&self) -> Vec<i64> {
        match self {
            Self::Global(c) => (c.show)(),
            Self::Net(c, n) => c.show(n),
        }
    }

    fn store(&self, v: &[i64]) -> Result<(), KernelError> {
        match self {
            Self::Global(c) => (c.store)(v),
            Self::Net(c, n) => c.store(n, v),
        }
    }

    /// A string sysctl's value
    fn text_show(&self) -> Option<String> {
        match self {
            Self::Global(c) => c.text.as_ref().map(|t| (t.show)()),
            Self::Net(c, n) => c.text().map(|t| (t.show)(n)),
        }
    }

    /// Store a string sysctl's value; None for a numeric one
    fn text_store(&self, s: &str) -> Option<Result<(), KernelError>> {
        match self {
            Self::Global(c) => c.text.as_ref().map(|t| (t.store)(s)),
            Self::Net(c, n) => c.text().map(|t| (t.store)(n, s)),
        }
    }
}

/// The entry is in use from an open on (Linux proc_sys_open:
/// sysctl_head_grab, ENOENT once unregistering)
pub fn open(e: &Entry) -> Result<(), KernelError> {
    e.grab().map(drop)
}

/// A read (`write` false) or write of `e` by the current task may go
/// ahead (Linux proc_sys_call_handler, before the handler: ENOENT once
/// its namespace is going, then sysctl_perm with MAY_READ / MAY_WRITE
/// on every call, EPERM)
pub fn call_check(e: &Entry, write: bool) -> Result<(), KernelError> {
    let _g = e.grab()?;
    let mask = if write {
        crate::fs::MAY_WRITE
    } else {
        crate::fs::MAY_READ
    };
    permission(e.perm(), &crate::task::current_cred(), mask).map_err(|_| KernelError::NotPermitted)
}

/// Current text of `e` (Linux proc_sys_call_handler: ENOENT once its
/// namespace is going)
pub fn read(e: &Entry) -> Result<Vec<u8>, KernelError> {
    let g = e.grab()?;
    Ok(match g.text_show() {
        Some(mut s) => {
            s.push('\n');
            s.into_bytes()
        }
        None => format(&g.show()),
    })
}

/// All global tables, mounted under /proc/sys (the network ones are
/// per namespace: `net::sysctl::registered`)
pub fn tables() -> &'static [&'static [Ctl]] {
    static TABLES: &[&[Ctl]] = &[
        crate::mm::frame_alloc::VM_CTLS,
        crate::mm::writeback::WB_CTLS,
        crate::mm::MM_CTLS,
        crate::mm::memfd::MEMFD_CTLS,
        crate::task::fdbits::FS_CTLS,
        crate::fs::dac::PROTECTED_CTLS,
        crate::io::pipe::PIPE_CTLS,
        crate::bpf::syscall::BPF_CTLS,
        crate::io::inotify::INOTIFY_CTLS,
        crate::io::aio::AIO_CTLS,
        crate::power::CAD_CTLS,
    ];
    TABLES
}

/// Text of a value: integers separated by tabs, newline-terminated
pub fn format(v: &[i64]) -> Vec<u8> {
    let mut s = String::new();
    for (i, x) in v.iter().enumerate() {
        if i > 0 {
            s.push('\t');
        }
        s.push_str(&alloc::format!("{}", x));
    }
    s.push('\n');
    s.into_bytes()
}

/// Linux TMPBUFLEN: proc_get_long reads a number from at most this
/// many bytes less one, and refuses one that fills them
const TMPBUFLEN: usize = 22;

/// One integer, a whitespace-separated word, as Linux proc_get_long:
/// an optional '-', then a digit, then base 0 (`0x` hex, a leading `0`
/// octal, else decimal, strtoul_lenient: no overflow); no '+', nothing
/// after it, shorter than TMPBUFLEN - 1
fn parse_long(tok: &str) -> Option<i64> {
    if tok.len() >= TMPBUFLEN - 1 {
        return None;
    }
    let tok = tok.as_bytes();
    let (neg, body) = match tok.strip_prefix(b"-") {
        Some(b) => (true, b),
        None => (false, tok),
    };
    if !body.first()?.is_ascii_digit() {
        return None;
    }
    let (v, rest) = crate::util::kstrtox::strtoull_lenient(body, 0).ok()?;
    if !rest.is_empty() {
        return None;
    }
    if neg {
        0i64.checked_sub_unsigned(v)
    } else {
        i64::try_from(v).ok()
    }
}

/// Parse a write over `cur` (Linux __do_proc_dointvec): up to `cur.len()`
/// integers; at least one
pub fn parse(buf: &[u8], cur: &[i64]) -> Result<Vec<i64>, KernelError> {
    let text = core::str::from_utf8(buf).map_err(|_| KernelError::InvalidArgument)?;
    let text = text.trim_end_matches('\0');
    let mut out = cur.to_vec();
    let mut n = 0;
    for tok in text.split_ascii_whitespace() {
        if n == out.len() {
            break;
        }
        out[n] = parse_long(tok).ok_or(KernelError::InvalidArgument)?;
        n += 1;
    }
    if n == 0 {
        return Err(KernelError::InvalidArgument);
    }
    Ok(out)
}

/// Write `buf` at file offset `pos` to `e`; returns bytes consumed
/// (ENOENT once its namespace is going)
pub fn write(e: &Entry, buf: &[u8], pos: u64) -> Result<usize, KernelError> {
    let g = e.grab()?;
    if pos != 0 {
        return Ok(buf.len());
    }
    if e.is_text() {
        let s = core::str::from_utf8(buf).map_err(|_| KernelError::InvalidArgument)?;
        let s = s.trim_end_matches('\0').trim();
        g.text_store(s)
            .unwrap_or(Err(KernelError::InvalidArgument))?;
        return Ok(buf.len());
    }
    let v = parse(buf, &g.show())?;
    g.store(&v)?;
    Ok(buf.len())
}

/// Linux sysctl_perm / net_ctl_permissions for credentials `c`: euid 0
/// or CAP_NET_ADMIN use the owner bits, egid 0 the group bits, others the
/// rest (no CAP_DAC_OVERRIDE: a read-only sysctl is read-only for root
/// too). `mask` holds MAY_READ / MAY_WRITE / MAY_EXEC bits.
pub fn permission(p: Perm, c: &crate::task::Cred, mask: u32) -> Result<(), KernelError> {
    let m = u32::from(p.mode);
    // Linux test_perm: root gets the owner bits; CAP_NET_ADMIN counts
    // as root only for the network namespace's own files
    // (net_ctl_permissions), never for vm/ and the rest
    let net_admin = p.net && c.cap_effective.has(crate::task::CAP_NET_ADMIN);
    let bits = if c.euid == 0 || net_admin {
        m >> 6
    } else if c.egid == 0 {
        m >> 3
    } else {
        m
    };
    if mask & !bits & 7 != 0 {
        return Err(KernelError::PermissionDenied);
    }
    Ok(())
}

/// Check an integer against an inclusive range (EINVAL outside)
pub fn range(v: i64, lo: i64, hi: i64) -> Result<(), KernelError> {
    if v < lo || v > hi {
        return Err(KernelError::InvalidArgument);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_vectors() {
        assert_eq!(parse(b"1 2\n", &[5, 6]).unwrap(), [1, 2]);
        assert_eq!(parse(b"  7\t", &[5, 6]).unwrap(), [7, 6]);
        assert_eq!(parse(b"1 2 3", &[5, 6]).unwrap(), [1, 2]);
        assert_eq!(parse(b"-4", &[5]).unwrap(), [-4]);
        assert!(parse(b"x", &[5]).is_err());
        // Base 0 as Linux proc_get_long; no '+'
        assert_eq!(parse(b"0x10 010 0", &[0, 0, 0]).unwrap(), [16, 8, 0]);
        assert_eq!(parse(b"-0x10", &[0]).unwrap(), [-16]);
        assert!(parse(b"+5", &[5]).is_err());
        assert!(parse(b"08", &[5]).is_err());
        assert!(parse(b"0x", &[5]).is_err());
        assert!(parse(b"-", &[5]).is_err());
        assert!(parse(b"1x", &[5]).is_err());
        assert!(parse(b"\n", &[5]).is_err());
        // u64::from_str_radix took a sign after the prefix; Linux not
        assert!(parse(b"0+5", &[5]).is_err());
        assert!(parse(b"0x-5", &[5]).is_err());
        // 21 bytes fill Linux's buffer: refused, however valid
        assert_eq!(parse(b"00000000000000000001", &[5]).unwrap(), [1]);
        assert!(parse(b"000000000000000000001", &[5]).is_err());
        assert!(parse(b"18446744073709551616", &[5]).is_err());
        assert_eq!(format(&[1, 0]), b"1\t0\n");
    }
}
