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

use crate::error::KernelError;

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
}

/// All tables, mounted under /proc/sys
pub fn tables() -> &'static [&'static [Ctl]] {
    static TABLES: &[&[Ctl]] = &[crate::net::sysctl::CTLS];
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
        out[n] = tok.parse().map_err(|_| KernelError::InvalidArgument)?;
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
    let v = parse(buf, &(ctl.show)())?;
    (ctl.store)(&v)?;
    Ok(buf.len())
}

/// Linux sysctl_perm / net_ctl_permissions: root or CAP_NET_ADMIN use
/// the owner bits, group root the group bits, others the rest (no
/// CAP_DAC_OVERRIDE: a read-only sysctl is read-only for root too).
/// `want` is MAY_READ (4) / MAY_WRITE (2) bits.
pub fn permission(ctl: &Ctl, want: u16) -> Result<(), KernelError> {
    let c = crate::task::current_cred();
    let m = ctl.mode;
    let bits = if c.euid == 0 || crate::task::capable(crate::task::CAP_NET_ADMIN) {
        (m >> 6) & 7
    } else if c.egid == 0 {
        (m >> 3) & 7
    } else {
        m & 7
    };
    if want & !bits & 7 != 0 {
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
        assert!(parse(b"\n", &[5]).is_err());
        assert_eq!(format(&[1, 0]), b"1\t0\n");
    }
}
