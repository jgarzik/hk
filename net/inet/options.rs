//! IPv4 header options (Linux net/ipv4/ip_options.c)
//!
//! [`compile`] parses and checks a received header's options (filling
//! in record route and timestamp slots, as Linux does on local
//! delivery) or a sender's (IP_OPTIONS, the IP_RETOPTS control
//! message: [`get`]); [`build`] writes a sender's into an outgoing
//! header; [`echo`] makes the options a reply carries back (ICMP);
//! [`fragment`] blanks the options later fragments must not repeat;
//! [`undo`] reverts a compiled set to what the user gave.
//!
//! Offsets in [`OptMeta`] count from the start of the IP header, as
//! Linux's struct ip_options.

use crate::net::inet::fib::RouteType;
use crate::net::ipv4::Ipv4Addr;

pub const IPOPT_END: u8 = 0;
pub const IPOPT_NOOP: u8 = 1;
pub const IPOPT_SEC: u8 = 130;
pub const IPOPT_LSRR: u8 = 131;
pub const IPOPT_TIMESTAMP: u8 = 68;
pub const IPOPT_CIPSO: u8 = 134;
pub const IPOPT_RR: u8 = 7;
pub const IPOPT_SID: u8 = 136;
pub const IPOPT_SSRR: u8 = 137;
pub const IPOPT_RA: u8 = 148;
const IPOPT_TS_TSONLY: u8 = 0;
const IPOPT_TS_TSANDADDR: u8 = 1;
const IPOPT_TS_PRESPEC: u8 = 3;
/// Most option bytes a header holds
pub const MAX_OPTLEN: usize = 40;
const IPH: usize = 20;

/// Linux IPOPT_COPIED: the option is repeated in every fragment
fn copied(t: u8) -> bool {
    t & 0x80 != 0
}

/// Where a header's options are and what they need (Linux struct
/// ip_options without its data: IPCB(skb)->opt)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OptMeta {
    pub optlen: u8,
    pub srr: u8,
    pub rr: u8,
    pub ts: u8,
    pub router_alert: u8,
    pub cipso: u8,
    pub is_strictroute: bool,
    pub srr_is_hit: bool,
    pub is_changed: bool,
    pub rr_needaddr: bool,
    pub ts_needtime: bool,
    pub ts_needaddr: bool,
}

/// A set of options with their bytes (Linux struct ip_options with
/// __data): a socket's IP_OPTIONS, or a reply's echo
#[derive(Clone, Copy, Debug)]
pub struct IpOptions {
    pub m: OptMeta,
    /// First hop of a source route (Linux faddr)
    pub faddr: Ipv4Addr,
    pub data: [u8; MAX_OPTLEN],
}

impl Default for IpOptions {
    fn default() -> Self {
        Self {
            m: OptMeta::default(),
            faddr: Ipv4Addr::default(),
            data: [0; MAX_OPTLEN],
        }
    }
}

impl IpOptions {
    /// Its option bytes
    pub fn bytes(&self) -> &[u8] {
        &self.data[..usize::from(self.m.optlen)]
    }
}

/// What compiling a received header knows (Linux: the skb and its
/// route)
pub struct Rcv<'a> {
    /// The address recorded for us (Linux fib_compute_spec_dst)
    pub spec_dst: &'a dyn Fn() -> Ipv4Addr,
}

/// Compile options in `h` (an IP header, options from byte 20, `optlen`
/// bytes of them) for a received packet (`rcv`) or a sender (None;
/// `cap_raw`: the sender holds CAP_NET_RAW). `addr_type` classifies an
/// address in the namespace. The offset of the bad byte on error
/// (Linux __ip_options_compile's pp_ptr - iph).
fn compile_hdr(
    h: &mut [u8],
    optlen: usize,
    rcv: Option<&Rcv<'_>>,
    cap_raw: &dyn Fn() -> bool,
    addr_type: &dyn Fn(Ipv4Addr) -> RouteType,
    faddr: &mut Ipv4Addr,
) -> Result<OptMeta, u8> {
    let mut o = OptMeta {
        optlen: optlen as u8,
        ..Default::default()
    };
    let mut spec = None;
    let mut spec_dst = |r: &Rcv<'_>| *spec.get_or_insert_with(|| (r.spec_dst)());
    let mut i = IPH;
    let end = IPH + optlen;
    let err = |p: usize| Err(p as u8);
    while i < end {
        let l = end - i;
        match h[i] {
            IPOPT_END => {
                for b in &mut h[i + 1..end] {
                    if *b != IPOPT_END {
                        *b = IPOPT_END;
                        o.is_changed = true;
                    }
                }
                return Ok(o);
            }
            IPOPT_NOOP => {
                i += 1;
                continue;
            }
            _ => {}
        }
        if l < 2 {
            return err(i);
        }
        let olen = usize::from(h[i + 1]);
        if olen < 2 || olen > l {
            return err(i);
        }
        match h[i] {
            IPOPT_SSRR | IPOPT_LSRR => {
                if olen < 3 {
                    return err(i + 1);
                }
                if h[i + 2] < 4 {
                    return err(i + 2);
                }
                if o.srr != 0 {
                    return err(i);
                }
                if rcv.is_none() {
                    if h[i + 2] != 4 || olen < 7 || (olen - 3) & 3 != 0 {
                        return err(i + 1);
                    }
                    *faddr = Ipv4Addr::from_be_bytes([h[i + 3], h[i + 4], h[i + 5], h[i + 6]]);
                    if olen > 7 {
                        h.copy_within(i + 7..i + olen, i + 3);
                    }
                }
                o.is_strictroute = h[i] == IPOPT_SSRR;
                o.srr = i as u8;
            }
            IPOPT_RR => {
                if o.rr != 0 {
                    return err(i);
                }
                if olen < 3 {
                    return err(i + 1);
                }
                if h[i + 2] < 4 {
                    return err(i + 2);
                }
                let p = usize::from(h[i + 2]);
                if p <= olen {
                    if p + 3 > olen {
                        return err(i + 2);
                    }
                    if let Some(r) = rcv {
                        let a = spec_dst(r).to_be_bytes();
                        h[i + p - 1..i + p + 3].copy_from_slice(&a);
                        o.is_changed = true;
                    }
                    h[i + 2] += 4;
                    o.rr_needaddr = true;
                }
                o.rr = i as u8;
            }
            IPOPT_TIMESTAMP => {
                if o.ts != 0 {
                    return err(i);
                }
                if olen < 4 {
                    return err(i + 1);
                }
                if h[i + 2] < 5 {
                    return err(i + 2);
                }
                let p = usize::from(h[i + 2]);
                if p <= olen {
                    if p + 3 > olen {
                        return err(i + 2);
                    }
                    let mut timeptr = None;
                    match h[i + 3] & 0xf {
                        IPOPT_TS_TSONLY => {
                            if rcv.is_some() {
                                timeptr = Some(i + p - 1);
                            }
                            o.ts_needtime = true;
                            h[i + 2] += 4;
                        }
                        IPOPT_TS_TSANDADDR => {
                            if p + 7 > olen {
                                return err(i + 2);
                            }
                            if let Some(r) = rcv {
                                let a = spec_dst(r).to_be_bytes();
                                h[i + p - 1..i + p + 3].copy_from_slice(&a);
                                timeptr = Some(i + p + 3);
                            }
                            o.ts_needaddr = true;
                            o.ts_needtime = true;
                            h[i + 2] += 8;
                        }
                        IPOPT_TS_PRESPEC => {
                            if p + 7 > olen {
                                return err(i + 2);
                            }
                            let a = Ipv4Addr::from_be_bytes([
                                h[i + p - 1],
                                h[i + p],
                                h[i + p + 1],
                                h[i + p + 2],
                            ]);
                            if addr_type(a) != RouteType::Unicast {
                                if rcv.is_some() {
                                    timeptr = Some(i + p + 3);
                                }
                                o.ts_needtime = true;
                                h[i + 2] += 8;
                            }
                        }
                        _ => {
                            if rcv.is_none() && !cap_raw() {
                                return err(i + 3);
                            }
                        }
                    }
                    if let Some(t) = timeptr {
                        let now = crate::net::icmp::inet_current_timestamp().to_be_bytes();
                        h[t..t + 4].copy_from_slice(&now);
                        o.is_changed = true;
                    }
                } else if h[i + 3] & 0xf != IPOPT_TS_PRESPEC {
                    let overflow = h[i + 3] >> 4;
                    if overflow == 15 {
                        return err(i + 3);
                    }
                    if rcv.is_some() {
                        h[i + 3] = (h[i + 3] & 0xf) | ((overflow + 1) << 4);
                        o.is_changed = true;
                    }
                }
                o.ts = i as u8;
            }
            IPOPT_RA => {
                if olen < 4 {
                    return err(i + 1);
                }
                if h[i + 2] == 0 && h[i + 3] == 0 {
                    o.router_alert = i as u8;
                }
            }
            // hk has no CIPSO: a received one is refused as Linux's
            // cipso_v4_validate refuses it without a DOI configured
            IPOPT_CIPSO => return err(i),
            _ => {
                if rcv.is_none() && !cap_raw() {
                    return err(i);
                }
            }
        }
        i += olen;
    }
    Ok(o)
}

/// Compile a received header's options (Linux ip_options_compile with
/// the skb): slots for us filled in; the offset of the bad byte, for a
/// parameter problem, on error
pub fn compile(
    h: &mut [u8],
    rcv: &Rcv<'_>,
    addr_type: &dyn Fn(Ipv4Addr) -> RouteType,
) -> Result<OptMeta, u8> {
    let optlen = h.len().saturating_sub(IPH);
    let mut faddr = Ipv4Addr::default();
    compile_hdr(h, optlen, Some(rcv), &|| false, addr_type, &mut faddr)
}

/// A sender's options from `user` bytes (Linux ip_options_get, for
/// IP_OPTIONS and the IP_RETOPTS control message): padded to a
/// multiple of 4 with IPOPT_END and compiled; EINVAL when malformed or
/// longer than 40 bytes, EPERM for a source route without CAP_NET_RAW
pub fn get(
    user: &[u8],
    cap_raw: &dyn Fn() -> bool,
    addr_type: &dyn Fn(Ipv4Addr) -> RouteType,
) -> Result<IpOptions, crate::util::error::KernelError> {
    use crate::util::error::KernelError;
    if user.len() > MAX_OPTLEN {
        return Err(KernelError::InvalidArgument);
    }
    let mut o = IpOptions::default();
    o.data[..user.len()].copy_from_slice(user);
    let optlen = user.len().next_multiple_of(4);
    if optlen == 0 {
        return Ok(o);
    }
    let mut h = [0u8; IPH + MAX_OPTLEN];
    h[IPH..IPH + MAX_OPTLEN].copy_from_slice(&o.data);
    let m = compile_hdr(&mut h, optlen, None, cap_raw, addr_type, &mut o.faddr)
        .map_err(|_| KernelError::InvalidArgument)?;
    o.data.copy_from_slice(&h[IPH..]);
    o.m = m;
    if o.m.srr != 0 && !cap_raw() {
        return Err(KernelError::NotPermitted);
    }
    Ok(o)
}

/// Write `opt` into the header `h` (its options from byte 20):
/// the final destination `daddr` at the end of a source route, our
/// source `saddr` in record route and address timestamp slots, the
/// time in a timestamp slot (Linux ip_options_build; ip_rt_get_source
/// of an output route is the header's source)
pub fn build(h: &mut [u8], opt: &IpOptions, daddr: Ipv4Addr, saddr: Ipv4Addr) {
    let n = usize::from(opt.m.optlen);
    h[IPH..IPH + n].copy_from_slice(&opt.data[..n]);
    let m = &opt.m;
    let at = |h: &mut [u8], p: usize, v: [u8; 4]| h[p..p + 4].copy_from_slice(&v);
    if m.srr != 0 {
        let s = usize::from(m.srr);
        let p = s + usize::from(h[s + 1]) - 4;
        at(h, p, daddr.to_be_bytes());
    }
    if m.rr_needaddr {
        let r = usize::from(m.rr);
        let p = r + usize::from(h[r + 2]) - 5;
        at(h, p, saddr.to_be_bytes());
    }
    if m.ts_needaddr {
        let t = usize::from(m.ts);
        let p = t + usize::from(h[t + 2]) - 9;
        at(h, p, saddr.to_be_bytes());
    }
    if m.ts_needtime {
        let t = usize::from(m.ts);
        let p = t + usize::from(h[t + 2]) - 5;
        at(
            h,
            p,
            crate::net::icmp::inet_current_timestamp().to_be_bytes(),
        );
    }
}

/// The options a reply to the packet with header `h` and compiled
/// options `s` carries (Linux __ip_options_echo): record route and
/// timestamp copied with room for our entry, a source route reversed;
/// EINVAL for a slot that does not fit
pub fn echo(
    h: &[u8],
    s: &OptMeta,
    addr_type: &dyn Fn(Ipv4Addr) -> RouteType,
) -> Result<IpOptions, crate::util::error::KernelError> {
    use crate::util::error::KernelError;
    let mut d = IpOptions::default();
    if s.optlen == 0 {
        return Ok(d);
    }
    let mut dp = 0usize;
    let room = |dp: usize, n: usize| dp + n <= MAX_OPTLEN;
    if s.rr != 0 {
        let r = usize::from(s.rr);
        let olen = usize::from(h[r + 1]);
        let so = usize::from(h[r + 2]);
        if !room(dp, olen) {
            return Err(KernelError::InvalidArgument);
        }
        d.m.rr = (dp + IPH) as u8;
        d.data[dp..dp + olen].copy_from_slice(&h[r..r + olen]);
        if s.rr_needaddr && so <= olen {
            if so + 3 > olen {
                return Err(KernelError::InvalidArgument);
            }
            d.data[dp + 2] = (so + 4) as u8;
            d.m.rr_needaddr = true;
        }
        dp += olen;
    }
    if s.ts != 0 {
        let t = usize::from(s.ts);
        let olen = usize::from(h[t + 1]);
        let mut so = usize::from(h[t + 2]);
        if !room(dp, olen) {
            return Err(KernelError::InvalidArgument);
        }
        d.m.ts = (dp + IPH) as u8;
        d.data[dp..dp + olen].copy_from_slice(&h[t..t + olen]);
        if so <= olen {
            if s.ts_needaddr {
                if so + 3 > olen {
                    return Err(KernelError::InvalidArgument);
                }
                d.m.ts_needaddr = true;
                so += 4;
            }
            if s.ts_needtime {
                if so + 3 > olen {
                    return Err(KernelError::InvalidArgument);
                }
                if d.data[dp + 3] & 0xf != IPOPT_TS_PRESPEC {
                    d.m.ts_needtime = true;
                    so += 4;
                } else if so + 7 <= olen {
                    let b = &d.data[dp + so - 1..dp + so + 3];
                    let a = Ipv4Addr::from_be_bytes([b[0], b[1], b[2], b[3]]);
                    if addr_type(a) != RouteType::Unicast {
                        d.m.ts_needtime = true;
                        so += 8;
                    }
                }
            }
            d.data[dp + 2] = so as u8;
        }
        dp += olen;
    }
    if s.srr != 0 {
        let st = usize::from(s.srr);
        let olen = usize::from(h[st + 1]);
        let mut so = usize::from(h[st + 2]);
        let mut doff = 0usize;
        if so > olen {
            so = olen + 1;
        }
        so = so.saturating_sub(4);
        let mut faddr = Ipv4Addr::default();
        if so > 3 {
            let a = |p: usize| [h[st + p - 1], h[st + p], h[st + p + 1], h[st + p + 2]];
            faddr = Ipv4Addr::from_be_bytes(a(so));
            so -= 4;
            doff = 4;
            while so > 3 {
                if !room(dp, doff + 3) {
                    return Err(KernelError::InvalidArgument);
                }
                d.data[dp + doff - 1..dp + doff + 3].copy_from_slice(&a(so));
                so -= 4;
                doff += 4;
            }
            // RFC 1812: a route listing the sender itself is fixed
            if h[12..16] == a(so + 4) {
                doff -= 4;
            }
        }
        if doff > 3 {
            if !room(dp, doff + 3) {
                return Err(KernelError::InvalidArgument);
            }
            d.faddr = faddr;
            d.data[dp] = h[st];
            d.data[dp + 1] = (doff + 3) as u8;
            d.data[dp + 2] = 4;
            d.m.srr = (dp + IPH) as u8;
            dp += doff + 3;
            d.m.is_strictroute = s.is_strictroute;
        }
    }
    while dp & 3 != 0 {
        if !room(dp, 1) {
            return Err(KernelError::InvalidArgument);
        }
        d.data[dp] = IPOPT_END;
        dp += 1;
    }
    d.m.optlen = dp as u8;
    Ok(d)
}

/// Blank, in header `h` with options `m`, the options that are not
/// repeated in later fragments (Linux ip_options_fragment)
pub fn fragment(h: &mut [u8], m: &mut OptMeta) {
    let mut i = IPH;
    let end = IPH + usize::from(m.optlen);
    while i < end {
        match h[i] {
            IPOPT_END => return,
            IPOPT_NOOP => {
                i += 1;
                continue;
            }
            _ => {}
        }
        let Some(&ol) = h.get(i + 1) else { return };
        let ol = usize::from(ol);
        if ol < 2 || ol > end - i {
            return;
        }
        if !copied(h[i]) {
            h[i..i + ol].fill(IPOPT_NOOP);
        }
        i += ol;
    }
    m.ts = 0;
    m.rr = 0;
    m.rr_needaddr = false;
    m.ts_needaddr = false;
    m.ts_needtime = false;
}

/// Revert what compiling `o` changed (Linux ip_options_undo): the
/// source route's first hop back in front, the slots we would fill
/// emptied
pub fn undo(o: &mut IpOptions) {
    let d = &mut o.data;
    if o.m.srr != 0 {
        let p = usize::from(o.m.srr) - IPH;
        let n = usize::from(d[p + 1]);
        d.copy_within(p + 3..p + n - 4, p + 7);
        d[p + 3..p + 7].copy_from_slice(&o.faddr.to_be_bytes());
    }
    if o.m.rr_needaddr {
        let p = usize::from(o.m.rr) - IPH;
        d[p + 2] -= 4;
        let q = usize::from(d[p + 2]) - 1;
        d[p + q..p + q + 4].fill(0);
    }
    if o.m.ts != 0 {
        let p = usize::from(o.m.ts) - IPH;
        if o.m.ts_needtime {
            d[p + 2] -= 4;
            let q = usize::from(d[p + 2]) - 1;
            d[p + q..p + q + 4].fill(0);
            if d[p + 3] & 0xf == IPOPT_TS_PRESPEC {
                d[p + 2] -= 4;
            }
        }
        if o.m.ts_needaddr {
            d[p + 2] -= 4;
            let q = usize::from(d[p + 2]) - 1;
            d[p + q..p + q + 4].fill(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uni(_: Ipv4Addr) -> RouteType {
        RouteType::Unicast
    }

    /// A record route option with three slots: compiled for sending
    /// (one slot to fill), built with our source, undone back
    #[test]
    fn record_route_round_trip() {
        let user = [IPOPT_RR, 15, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut o = get(&user, &|| false, &uni).unwrap();
        assert_eq!(o.m.optlen, 16);
        assert_eq!(o.m.rr, 20);
        assert!(o.m.rr_needaddr);
        assert_eq!(o.data[2], 8);
        let mut h = [0u8; 36];
        build(
            &mut h,
            &o,
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
        );
        assert_eq!(&h[23..27], &[10, 0, 0, 1]);
        undo(&mut o);
        assert_eq!(&o.data[..15], &user);
    }

    /// Malformed and privileged options are refused as Linux
    #[test]
    fn refused() {
        assert!(get(&[IPOPT_RR, 1], &|| false, &uni).is_err());
        assert!(get(&[IPOPT_RR, 3, 2, 0], &|| false, &uni).is_err());
        assert!(get(&[0; 41], &|| false, &uni).is_err());
        // An unknown option needs CAP_NET_RAW
        assert!(get(&[99, 2], &|| false, &uni).is_err());
        assert!(get(&[99, 2], &|| true, &uni).is_ok());
        // A source route too (EPERM)
        let lsrr = [IPOPT_LSRR, 7, 4, 10, 0, 0, 9];
        assert_eq!(
            get(&lsrr, &|| false, &uni).unwrap_err(),
            crate::util::error::KernelError::NotPermitted
        );
        let o = get(&lsrr, &|| true, &uni).unwrap();
        assert_eq!(o.faddr, Ipv4Addr::new(10, 0, 0, 9));
    }

    /// A received record route is filled with our address and echoed
    /// with room for the reply's own entry
    #[test]
    fn receive_and_echo() {
        let mut h = [0u8; 32];
        h[0] = 0x48;
        h[12..16].copy_from_slice(&[10, 0, 0, 2]);
        h[20..32].copy_from_slice(&[IPOPT_RR, 11, 4, 0, 0, 0, 0, 0, 0, 0, 0, IPOPT_END]);
        let me = || Ipv4Addr::new(10, 0, 0, 1);
        let m = compile(&mut h, &Rcv { spec_dst: &me }, &uni).unwrap();
        assert!(m.is_changed && m.rr_needaddr);
        assert_eq!(&h[23..27], &[10, 0, 0, 1]);
        assert_eq!(h[22], 8);
        let e = echo(&h, &m, &uni).unwrap();
        assert_eq!(e.m.optlen, 12);
        assert_eq!(e.data[2], 12);
        assert!(e.m.rr_needaddr);
    }

    /// Later fragments lose the options not marked copied
    #[test]
    fn fragment_blanks() {
        let mut h = [0u8; 28];
        h[20..28].copy_from_slice(&[IPOPT_RR, 7, 4, 0, 0, 0, 0, IPOPT_NOOP]);
        let mut m = OptMeta {
            optlen: 8,
            rr: 20,
            rr_needaddr: true,
            ..Default::default()
        };
        fragment(&mut h, &mut m);
        assert_eq!(&h[20..27], &[IPOPT_NOOP; 7]);
        assert_eq!(m.rr, 0);
    }
}
