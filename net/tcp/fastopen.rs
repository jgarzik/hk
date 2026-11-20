//! TCP Fast Open keys and cookies (Linux v6.8 net/ipv4/tcp_fastopen.c,
//! proc_tcp_fastopen_key)
//!
//! A cookie is the siphash of the SYN's source and destination
//! addresses under a key of the listener (TCP_FASTOPEN_KEY) or, without
//! one, of its namespace (net.ipv4.tcp_fastopen_key, drawn at random
//! the first time Fast Open is enabled: tcp_fastopen_init_key_once). A
//! context holds a primary key and possibly a backup one; cookies made
//! with the backup still validate during key rotation.

use alloc::string::String;
use core::fmt::Write;

use super::cb::Foc;
use super::output::Tuple;
use crate::util::error::KernelError;

/// Bytes of one key (Linux TCP_FASTOPEN_KEY_LENGTH) and of a primary
/// and backup pair (TCP_FASTOPEN_KEY_BUF_LENGTH)
pub const KEY_LEN: usize = 16;
pub const KEY_BUF_LEN: usize = 2 * KEY_LEN;

/// A key context (Linux struct tcp_fastopen_context): `num` keys, the
/// first the primary
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ctx {
    pub key: [[u64; 2]; 2],
    pub num: usize,
}

impl Ctx {
    /// Linux tcp_fastopen_reset_cipher's context: each key two
    /// little-endian u64s from its 16 bytes
    pub fn new(primary: &[u8; KEY_LEN], backup: Option<&[u8; KEY_LEN]>) -> Self {
        let k = |b: &[u8; KEY_LEN]| {
            let (lo, hi) = b.split_at(8);
            [
                u64::from_le_bytes(lo.try_into().unwrap_or_default()),
                u64::from_le_bytes(hi.try_into().unwrap_or_default()),
            ]
        };
        Self {
            key: [k(primary), backup.map_or([0; 2], k)],
            num: 1 + usize::from(backup.is_some()),
        }
    }

    /// A random primary key (tcp_fastopen_init_key_once)
    pub fn random() -> Self {
        let mut b = [0u8; KEY_LEN];
        for c in b.chunks_mut(4) {
            c.copy_from_slice(&crate::random::get_random_u32().to_ne_bytes());
        }
        Self::new(&b, None)
    }

    /// The keys as bytes, primary first (Linux tcp_fastopen_get_cipher)
    pub fn bytes(&self) -> alloc::vec::Vec<u8> {
        let mut v = alloc::vec::Vec::new();
        for k in &self.key[..self.num] {
            v.extend_from_slice(&k[0].to_le_bytes());
            v.extend_from_slice(&k[1].to_le_bytes());
        }
        v
    }

    /// Linux tcp_fastopen_cookie_gen_check: which key made the cookie
    /// `f` of the SYN on `t` (1 primary, 2 backup), else 0
    pub fn check(&self, t: &Tuple, f: &Foc) -> usize {
        (0..self.num)
            .find(|&i| {
                let v = cookie(&self.key[i], t);
                f.len == v.len && f.val[..8] == v.val[..8]
            })
            .map_or(0, |i| i + 1)
    }
}

/// Linux __tcp_fastopen_cookie_gen_cipher: siphash of the SYN's source
/// and destination addresses as they lie in its IP header (from
/// `t.raddr` to `t.laddr`), 8 bytes little-endian
pub fn cookie(key: &[u64; 2], t: &Tuple) -> Foc {
    let mut b = [0u8; 8];
    b[..4].copy_from_slice(&t.raddr.0.to_be_bytes());
    b[4..].copy_from_slice(&t.laddr.0.to_be_bytes());
    let mut f = Foc {
        len: 8,
        ..Foc::default()
    };
    f.val[..8].copy_from_slice(&crate::util::siphash::siphash_bytes(*key, &b).to_le_bytes());
    f
}

/// Linux tcp_fastopen_active_disable: pause active Fast Open in the
/// namespace (unless tcp_fastopen_blackhole_timeout_sec is 0),
/// TCPFastOpenBlackhole
pub fn active_disable(net: &crate::net::NetNamespace, now: u64) {
    use core::sync::atomic::Ordering;
    if net
        .sysctl
        .tcp_fastopen_blackhole_timeout
        .load(Ordering::Relaxed)
        == 0
    {
        return;
    }
    net.tcp.tfo_disable_stamp.store(now, Ordering::Relaxed);
    // Release: the stamp before the count (smp_mb__before_atomic)
    net.tcp.tfo_disable_times.fetch_add(1, Ordering::Release);
    net.mib
        .net
        .inc(crate::net::mib::LINUX_MIB_TCPFASTOPENBLACKHOLE);
}

/// Linux tcp_fastopen_active_should_disable: still within the pause,
/// the timeout doubling with each (up to 2^6 times); past it, Some(())
/// asks the connection to check for success (syn_fastopen_ch)
pub fn active_should_disable(net: &crate::net::NetNamespace, now: u64) -> (bool, bool) {
    use core::sync::atomic::Ordering;
    let t = net
        .sysctl
        .tcp_fastopen_blackhole_timeout
        .load(Ordering::Relaxed);
    if t <= 0 {
        return (false, false);
    }
    let times = net.tcp.tfo_disable_times.load(Ordering::Acquire);
    if times == 0 {
        return (false, false);
    }
    let mult = 1u64 << (times - 1).min(6);
    let until = net.tcp.tfo_disable_stamp.load(Ordering::Relaxed) + mult * t as u64 * 1000;
    if now < until {
        return (true, false);
    }
    (false, true)
}

/// net.ipv4.tcp_fastopen_key as Linux prints it: each key as four
/// 32-bit words "%08x-%08x-%08x-%08x" (little-endian words of its
/// bytes), keys separated by commas; zeros without a context
pub fn key_show(c: Option<&Ctx>) -> String {
    let b = c.map_or_else(|| alloc::vec![0u8; KEY_LEN], Ctx::bytes);
    let mut s = String::new();
    for (i, k) in b.chunks(KEY_LEN).enumerate() {
        if i > 0 {
            s.push(',');
        }
        for (j, w) in k.chunks(4).enumerate() {
            let w = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
            let sep = if j == 0 { "" } else { "-" };
            let _ = write!(s, "{sep}{w:08x}");
        }
    }
    s
}

/// Linux sscanf_key: "%x-%x-%x-%x" into a key's bytes
fn key_parse(s: &str) -> Result<[u8; KEY_LEN], KernelError> {
    let mut b = [0u8; KEY_LEN];
    let mut it = s.trim().split('-');
    for c in b.chunks_mut(4) {
        let w = it.next().ok_or(KernelError::InvalidArgument)?;
        let w = u32::from_str_radix(w.trim(), 16).map_err(|_| KernelError::InvalidArgument)?;
        c.copy_from_slice(&w.to_le_bytes());
    }
    Ok(b)
}

/// The context a write of net.ipv4.tcp_fastopen_key names: a primary
/// key, then optionally a comma and the backup
pub fn key_store(s: &str) -> Result<Ctx, KernelError> {
    let s = s.trim_end_matches(['\n', '\0']);
    let (p, b) = match s.split_once(',') {
        Some((p, b)) => (p, Some(b)),
        None => (s, None),
    };
    let p = key_parse(p)?;
    let b = b.map(key_parse).transpose()?;
    Ok(Ctx::new(&p, b.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::ipv4::Ipv4Addr;

    /// The sysctl's text round-trips, the backup key after a comma
    #[test]
    fn key_text() {
        let c = key_store("00000001-00000002-00000003-00000004,a-b-c-d\n").unwrap();
        assert_eq!(c.num, 2);
        assert_eq!(c.bytes()[..4], [1, 0, 0, 0]);
        assert_eq!(
            key_show(Some(&c)),
            "00000001-00000002-00000003-00000004,0000000a-0000000b-0000000c-0000000d"
        );
        assert_eq!(key_show(None), "00000000-00000000-00000000-00000000");
        assert!(key_store("1-2-3").is_err());
    }

    /// A backup key's cookie still checks, as key 2
    #[test]
    fn backup_key_checks() {
        let t = Tuple {
            laddr: Ipv4Addr(0x7f00_0001),
            lport: 80,
            raddr: Ipv4Addr(0x7f00_0002),
            rport: 9,
        };
        let a = [7u8; KEY_LEN];
        let b = [9u8; KEY_LEN];
        let old = Ctx::new(&a, None);
        let f = cookie(&old.key[0], &t);
        let rotated = Ctx::new(&b, Some(&a));
        assert_eq!(old.check(&t, &f), 1);
        assert_eq!(rotated.check(&t, &f), 2);
        assert_eq!(Ctx::new(&b, None).check(&t, &f), 0);
    }
}
