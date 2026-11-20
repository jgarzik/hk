//! /proc/sys tables (Linux kernel/sysctl.c, fs/proc/proc_sysctl.c subset)
//!
//! A `Ctl` is one /proc/sys file: a path below /proc/sys, a mode and
//! show/store functions over a vector of integers (Linux proc_dointvec
//! family). Values live with their subsystem (network sysctls are per
//! namespace atomics: the reader's/writer's namespace is used), so this
//! module holds no state and no locks.
//!
//! Writes follow Linux semantics: whitespace-separated decimal integers,
//! fewer values than the vector leaves the rest unchanged, anything
//! unparsable or out of range is EINVAL, writes at a non-zero file
//! offset are ignored (sysctl_writes_strict = 1).

use alloc::string::String;
use alloc::vec::Vec;

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

/// Current text of `ctl`
pub fn read(ctl: &Ctl) -> Vec<u8> {
    match &ctl.text {
        Some(t) => {
            let mut s = (t.show)();
            s.push('\n');
            s.into_bytes()
        }
        None => format(&(ctl.show)()),
    }
}

/// All tables, mounted under /proc/sys
pub fn tables() -> &'static [&'static [Ctl]] {
    static TABLES: &[&[Ctl]] = &[
        crate::net::sysctl::CTLS,
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

/// Write `buf` at file offset `pos` to `ctl`; returns bytes consumed
pub fn write(ctl: &Ctl, buf: &[u8], pos: u64) -> Result<usize, KernelError> {
    if pos != 0 {
        return Ok(buf.len());
    }
    if let Some(t) = &ctl.text {
        let s = core::str::from_utf8(buf).map_err(|_| KernelError::InvalidArgument)?;
        (t.store)(s.trim_end_matches('\0').trim())?;
        return Ok(buf.len());
    }
    let v = parse(buf, &(ctl.show)())?;
    (ctl.store)(&v)?;
    Ok(buf.len())
}

/// Linux sysctl_perm / net_ctl_permissions for credentials `c`: euid 0
/// or CAP_NET_ADMIN use the owner bits, egid 0 the group bits, others the
/// rest (no CAP_DAC_OVERRIDE: a read-only sysctl is read-only for root
/// too). `mask` holds MAY_READ / MAY_WRITE / MAY_EXEC bits.
pub fn permission(ctl: &Ctl, c: &crate::task::Cred, mask: u32) -> Result<(), KernelError> {
    let m = u32::from(ctl.mode);
    // Linux test_perm: root gets the owner bits; CAP_NET_ADMIN counts
    // as root only for the network namespace's own files
    // (net_ctl_permissions), never for vm/ and the rest
    let net_admin = ctl.path.starts_with("net/") && c.cap_effective.has(crate::task::CAP_NET_ADMIN);
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
