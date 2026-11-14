//! SNMP / Linux MIB counters: /proc/net/snmp and /proc/net/netstat
//! (hk and Linux)
//!
//! - SNMP_FORMAT: every header line is followed by a value line with
//!   the same tag and as many fields; Ip, Icmp, Tcp and Udp rows with
//!   the common fields, Tcp's RFC 2012 constants
//! - NETSTAT_FORMAT: TcpExt and IpExt row pairs, the common fields

use crate::harness::T;
use crate::helpers::{println, read_file};

const SNMP: &[u8] = b"/proc/net/snmp\0";
const NETSTAT: &[u8] = b"/proc/net/netstat\0";

pub fn run_tests() {
    println(b"=== SNMP Tests ===");
    test_snmp_format();
    test_netstat_format();
}

/// A /proc MIB file's text
struct Mib {
    buf: [u8; 8192],
    len: usize,
}

impl Mib {
    fn read(path: &[u8]) -> Option<Mib> {
        let mut m = Mib {
            buf: [0; 8192],
            len: 0,
        };
        let n = read_file(path, &mut m.buf);
        if n <= 0 || n as usize == m.buf.len() {
            return None;
        }
        m.len = n as usize;
        Some(m)
    }

    fn lines(&self) -> impl Iterator<Item = &[u8]> {
        self.buf[..self.len]
            .split(|&b| b == b'\n')
            .filter(|l| !l.is_empty())
    }

    /// Header/value line pairs: (tag, names, values)
    fn pairs(&self) -> impl Iterator<Item = (&[u8], &[u8], &[u8])> {
        let mut it = self.lines();
        core::iter::from_fn(move || {
            let h = it.next()?;
            let v = it.next().unwrap_or(b"");
            let tag = &h[..h.iter().position(|&b| b == b':').unwrap_or(0)];
            Some((tag, h, v))
        })
    }

    /// Field `name` of row `tag` (any of its line pairs; IcmpMsg has
    /// several, and lists only nonzero entries)
    fn get(&self, tag: &[u8], name: &[u8]) -> Option<i64> {
        for (t, h, v) in self.pairs() {
            if t != tag {
                continue;
            }
            if let Some(i) = words(h).position(|w| w == name) {
                return words(v).nth(i).and_then(num);
            }
        }
        None
    }

    /// `get`, with a missing field as 0
    fn val(&self, tag: &[u8], name: &[u8]) -> i64 {
        self.get(tag, name).unwrap_or(0)
    }
}

/// The fields after a line's `Tag:`
fn words(line: &[u8]) -> impl Iterator<Item = &[u8]> {
    let s = line.iter().position(|&b| b == b':').map_or(0, |p| p + 1);
    line[s..].split(|&b| b == b' ').filter(|w| !w.is_empty())
}

/// A decimal value, possibly negative (MaxConn)
fn num(w: &[u8]) -> Option<i64> {
    let (neg, d) = match w.split_first() {
        Some((b'-', rest)) => (true, rest),
        _ => (false, w),
    };
    if d.is_empty() || !d.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let v = d.iter().fold(0i64, |a, &c| {
        a.wrapping_mul(10).wrapping_add(i64::from(c - b'0'))
    });
    Some(if neg { -v } else { v })
}

/// Every line pairs with the next: same tag, as many values as names,
/// all decimal. Returns the failing pair's index.
fn pairs_ok(m: &Mib) -> Result<i64, i64> {
    let mut n = 0;
    for (tag, h, v) in m.pairs() {
        let vtag = &v[..v.iter().position(|&b| b == b':').unwrap_or(0)];
        let names = words(h).count();
        if tag.is_empty() || vtag != tag || names == 0 || words(v).count() != names {
            return Err(n as i64);
        }
        if words(v).any(|w| num(w).is_none()) {
            return Err(n as i64);
        }
        n += 1;
    }
    Ok(n as i64)
}

/// Every name of `names` is a field of row `tag`
fn has_all(t: &mut T, m: &Mib, tag: &[u8], names: &[&[u8]]) {
    for (i, n) in names.iter().enumerate() {
        t.ok(n, m.get(tag, n).is_some(), i as i64);
    }
}

fn test_snmp_format() {
    let mut t = T::new(b"SNMP_FORMAT");
    let Some(m) = Mib::read(SNMP) else {
        println(b"SNMP_FORMAT:FAIL read /proc/net/snmp");
        return;
    };
    t.ok(
        b"first line",
        m.buf.starts_with(b"Ip: Forwarding DefaultTTL InReceives "),
        0,
    );
    let pairs = pairs_ok(&m);
    t.ok(b"pairs", pairs.is_ok(), pairs.unwrap_or_else(|e| e));
    has_all(
        &mut t,
        &m,
        b"Ip",
        &[
            b"Forwarding",
            b"DefaultTTL",
            b"InReceives",
            b"InHdrErrors",
            b"InAddrErrors",
            b"InDelivers",
            b"OutRequests",
            b"OutNoRoutes",
            b"ReasmOKs",
            b"FragOKs",
        ],
    );
    has_all(
        &mut t,
        &m,
        b"Icmp",
        &[
            b"InMsgs",
            b"InErrors",
            b"InDestUnreachs",
            b"OutMsgs",
            b"OutDestUnreachs",
            b"OutEchoReps",
        ],
    );
    has_all(
        &mut t,
        &m,
        b"Tcp",
        &[
            b"ActiveOpens",
            b"PassiveOpens",
            b"AttemptFails",
            b"EstabResets",
            b"CurrEstab",
            b"InSegs",
            b"OutSegs",
            b"RetransSegs",
            b"InErrs",
            b"OutRsts",
            b"InCsumErrors",
        ],
    );
    has_all(
        &mut t,
        &m,
        b"Udp",
        &[
            b"InDatagrams",
            b"NoPorts",
            b"InErrors",
            b"OutDatagrams",
            b"RcvbufErrors",
            b"SndbufErrors",
        ],
    );
    // RFC 2012: Van Jacobson, 200 ms, 120 s, no limit (signed)
    t.eq(b"RtoAlgorithm", m.val(b"Tcp", b"RtoAlgorithm"), 1);
    t.eq(b"RtoMin", m.val(b"Tcp", b"RtoMin"), 200);
    t.eq(b"RtoMax", m.val(b"Tcp", b"RtoMax"), 120_000);
    t.eq(b"MaxConn", m.val(b"Tcp", b"MaxConn"), -1);
    t.done();
}

fn test_netstat_format() {
    let mut t = T::new(b"NETSTAT_FORMAT");
    let Some(m) = Mib::read(NETSTAT) else {
        println(b"NETSTAT_FORMAT:FAIL read /proc/net/netstat");
        return;
    };
    t.ok(
        b"first line",
        m.buf.starts_with(b"TcpExt: SyncookiesSent "),
        0,
    );
    let pairs = pairs_ok(&m);
    t.ok(b"pairs", pairs.is_ok(), pairs.unwrap_or_else(|e| e));
    has_all(
        &mut t,
        &m,
        b"TcpExt",
        &[
            b"EmbryonicRsts",
            b"TW",
            b"DelayedACKs",
            b"ListenOverflows",
            b"ListenDrops",
            b"TCPTimeouts",
            b"TCPAbortOnData",
            b"TCPAbortOnClose",
            b"TCPAbortOnTimeout",
            b"TCPBacklogDrop",
            b"TCPOrigDataSent",
        ],
    );
    has_all(
        &mut t,
        &m,
        b"IpExt",
        &[b"InOctets", b"OutOctets", b"InBcastPkts", b"InNoECTPkts"],
    );
    t.done();
}
