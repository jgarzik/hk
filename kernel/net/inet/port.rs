//! Local port rules shared by UDP and TCP (Linux inet_hashtables.c,
//! inet_connection_sock.c, udp.c): bind conflicts with SO_REUSEADDR /
//! SO_REUSEPORT, and ephemeral port selection over
//! `ip_local_port_range` with a keyed-hash offset (RFC 6056 algorithm
//! 4: SipHash of the flow plus a perturbation table), so port numbers
//! are not predictable across flows.
//!
//! Pure functions plus atomics: no locks (callers hold their table's
//! write lock while choosing and inserting).

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::net::ipv4::Ipv4Addr;

/// Linux net.ipv4.ip_local_port_range default
pub const PORT_LO: u16 = 32768;
pub const PORT_HI: u16 = 60999;

/// A namespace's ip_local_port_range (P5 makes it writable via /proc/sys)
pub struct PortRange {
    lo: AtomicU32,
    hi: AtomicU32,
}

impl Default for PortRange {
    fn default() -> Self {
        Self {
            lo: AtomicU32::new(PORT_LO as u32),
            hi: AtomicU32::new(PORT_HI as u32),
        }
    }
}

impl PortRange {
    pub fn get(&self) -> (u16, u16) {
        (
            self.lo.load(Ordering::Relaxed) as u16,
            self.hi.load(Ordering::Relaxed) as u16,
        )
    }

    pub fn set(&self, lo: u16, hi: u16) {
        self.lo.store(lo as u32, Ordering::Relaxed);
        self.hi.store(hi as u32, Ordering::Relaxed);
    }
}

/// What a bound socket looks like to the conflict rules
#[derive(Clone, Copy, Debug, Default)]
pub struct BindInfo {
    /// Bound (receive) address; 0.0.0.0 = wildcard
    pub addr: Ipv4Addr,
    /// SO_BINDTODEVICE ifindex (0 = any)
    pub dev: u32,
    pub reuse: bool,
    pub reuseport: bool,
    pub uid: u32,
    /// TCP: in LISTEN (SO_REUSEADDR does not share with a listener)
    pub listen: bool,
    /// TCP: a TIME_WAIT entry (SO_REUSEPORT shares it with any owner)
    pub tw: bool,
}

/// Linux inet_rcv_saddr_equal(match_wildcard = true)
fn addr_overlap(a: Ipv4Addr, b: Ipv4Addr) -> bool {
    a == b || a.is_unspecified() || b.is_unspecified()
}

fn dev_overlap(a: u32, b: u32) -> bool {
    a == 0 || b == 0 || a == b
}

/// Would `new` binding the port of `old` conflict? UDP (Linux
/// udp_lib_lport_inuse): shared when both set SO_REUSEADDR, or both set
/// SO_REUSEPORT with the same owner. TCP (inet_bind_conflict with
/// relax): shared when both set SO_REUSEADDR and `old` is not
/// listening, or both SO_REUSEPORT with the same owner (any owner for a
/// TIME_WAIT entry: Linux inet_bind_conflict).
pub fn conflict(new: &BindInfo, old: &BindInfo, tcp: bool) -> bool {
    if !dev_overlap(new.dev, old.dev) || !addr_overlap(new.addr, old.addr) {
        return false;
    }
    let reuse = new.reuse && old.reuse && !(tcp && old.listen);
    let reuseport = new.reuseport && old.reuseport && (old.tw || new.uid == old.uid);
    !(reuse || reuseport)
}

// ============================================================================
// Ephemeral ports
// ============================================================================

/// SipHash-2-4 of `words` under `key`
pub fn siphash(key: [u64; 2], words: &[u64]) -> u64 {
    let mut v = [
        key[0] ^ 0x736f_6d65_7073_6575,
        key[1] ^ 0x646f_7261_6e64_6f6d,
        key[0] ^ 0x6c79_6765_6e65_7261,
        key[1] ^ 0x7465_6462_7974_6573,
    ];
    fn round(v: &mut [u64; 4]) {
        v[0] = v[0].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(13) ^ v[0];
        v[0] = v[0].rotate_left(32);
        v[2] = v[2].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(16) ^ v[2];
        v[0] = v[0].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(21) ^ v[0];
        v[2] = v[2].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(17) ^ v[2];
        v[2] = v[2].rotate_left(32);
    }
    for &m in words {
        v[3] ^= m;
        round(&mut v);
        round(&mut v);
        v[0] ^= m;
    }
    let b = ((words.len() as u64 * 8) & 0xff) << 56;
    v[3] ^= b;
    round(&mut v);
    round(&mut v);
    v[0] ^= b;
    v[2] ^= 0xff;
    for _ in 0..4 {
        round(&mut v);
    }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

/// Boot-time secret (lazily drawn from the RNG)
static SECRET: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

#[cfg(test)]
fn secret() -> [u64; 2] {
    [1, 2]
}

#[cfg(not(test))]
fn secret() -> [u64; 2] {
    let k = [
        SECRET[0].load(Ordering::Relaxed),
        SECRET[1].load(Ordering::Relaxed),
    ];
    if k != [0, 0] {
        return k;
    }
    let r = |_| {
        ((crate::random::get_random_u32() as u64) << 32)
            | crate::random::get_random_u32() as u64
            | 1
    };
    let k = [r(0), r(1)];
    let _ = SECRET[0].compare_exchange(0, k[0], Ordering::Relaxed, Ordering::Relaxed);
    let _ = SECRET[1].compare_exchange(0, k[1], Ordering::Relaxed, Ordering::Relaxed);
    [
        SECRET[0].load(Ordering::Relaxed),
        SECRET[1].load(Ordering::Relaxed),
    ]
}

/// SipHash of `words` under the boot secret, separated by `domain`
/// (RFC 6528 initial sequence numbers and similar keyed hashes)
pub fn secure_hash(domain: u64, words: &[u64]) -> u64 {
    let k = secret();
    let mut w = alloc::vec::Vec::with_capacity(words.len() + 1);
    w.push(domain);
    w.extend_from_slice(words);
    siphash([k[0] ^ domain, k[1]], &w)
}

/// RFC 6056 algorithm 4 perturbation table
const TABLE: usize = 256;
static PERTURB: [AtomicU32; TABLE] = [const { AtomicU32::new(0) }; TABLE];

/// A flow for port selection: protocol, local and remote address and
/// remote port (0 when unknown, e.g. bind(port 0) or UDP autobind)
#[derive(Clone, Copy, Debug, Default)]
pub struct Flow {
    pub proto: u8,
    pub saddr: Ipv4Addr,
    pub daddr: Ipv4Addr,
    pub dport: u16,
}

/// First port of `range` for which `free(port)` holds, starting at the
/// flow's keyed offset; None if every port is taken (EADDRINUSE)
pub fn ephemeral(range: (u16, u16), f: Flow, mut free: impl FnMut(u16) -> bool) -> Option<u16> {
    let (lo, hi) = range;
    if hi < lo {
        return None;
    }
    let n = (hi - lo) as u32 + 1;
    let words = [
        f.proto as u64,
        ((f.saddr.0 as u64) << 32) | f.daddr.0 as u64,
        f.dport as u64,
    ];
    let k = secret();
    let offset = siphash(k, &words) as u32;
    let idx = (siphash([k[1], k[0]], &words) as usize) % TABLE;
    let start = offset.wrapping_add(PERTURB[idx].load(Ordering::Relaxed));
    for i in 0..n {
        let port = lo + (start.wrapping_add(i) % n) as u16;
        if free(port) {
            // Next selection for this flow starts further on
            PERTURB[idx].fetch_add(i + 1, Ordering::Relaxed);
            return Some(port);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(addr: u32, reuse: bool, reuseport: bool, uid: u32) -> BindInfo {
        BindInfo {
            addr: Ipv4Addr(addr),
            reuse,
            reuseport,
            uid,
            ..Default::default()
        }
    }

    #[test]
    fn udp_rules() {
        let any = 0;
        let lo = 0x7f00_0001;
        let other = 0x0a00_020f;
        assert!(conflict(
            &b(any, false, false, 0),
            &b(lo, false, false, 0),
            false
        ));
        assert!(!conflict(
            &b(lo, false, false, 0),
            &b(other, false, false, 0),
            false
        ));
        assert!(!conflict(
            &b(lo, true, false, 0),
            &b(lo, true, false, 0),
            false
        ));
        assert!(conflict(
            &b(lo, true, false, 0),
            &b(lo, false, false, 0),
            false
        ));
        assert!(!conflict(
            &b(lo, false, true, 5),
            &b(lo, false, true, 5),
            false
        ));
        assert!(conflict(
            &b(lo, false, true, 5),
            &b(lo, false, true, 6),
            false
        ));
        let mut d = b(lo, false, false, 0);
        d.dev = 2;
        let mut e = d;
        e.dev = 3;
        assert!(!conflict(&d, &e, false));
    }

    #[test]
    fn tcp_listen_rule() {
        let lo = 0x7f00_0001;
        let mut l = b(lo, true, false, 0);
        l.listen = true;
        assert!(conflict(&b(lo, true, false, 0), &l, true));
        assert!(!conflict(
            &b(lo, true, false, 0),
            &b(lo, true, false, 0),
            true
        ));
        let mut lp = b(lo, false, true, 0);
        lp.listen = true;
        assert!(!conflict(&b(lo, false, true, 0), &lp, true));
    }

    #[test]
    fn siphash_vector() {
        // Reference SipHash-2-4 vector: key 00..0f, empty message
        let k0 = u64::from_le_bytes([0, 1, 2, 3, 4, 5, 6, 7]);
        let k1 = u64::from_le_bytes([8, 9, 10, 11, 12, 13, 14, 15]);
        assert_eq!(siphash([k0, k1], &[]), 0x726f_db47_dd0e_0e31);
    }

    #[test]
    fn ephemeral_in_range_and_skips_busy() {
        let f = Flow::default();
        let p = ephemeral((40000, 40009), f, |p| p != 40000 && p % 2 == 1).unwrap();
        assert!((40000..=40009).contains(&p) && p % 2 == 1);
        assert!(ephemeral((40000, 40009), f, |_| false).is_none());
        assert_eq!(ephemeral((5, 5), f, |_| true), Some(5));
    }
}
