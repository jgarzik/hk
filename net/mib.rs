//! SNMP and Linux MIB counters of a network namespace (Linux
//! include/net/snmp.h, include/net/netns/mib.h; indices from
//! include/uapi/linux/snmp.h)
//!
//! Every MIB but IcmpMsg is per CPU (Linux DEFINE_SNMP_STAT +
//! alloc_percpu): an update adds to the calling CPU's word, a reader
//! sums every CPU's (snmp_fold_field). IcmpMsg is one atomic per entry
//! (Linux DEFINE_SNMP_STAT_ATOMIC). /proc/net/snmp and /proc/net/netstat
//! print them (`net::proc`).
//!
//! Locking: none. A word is an atomic updated with one relaxed RMW, so
//! an update is safe from any context (interrupts and softnet included,
//! Linux this_cpu_inc) and a task preempted and moved between choosing
//! its CPU's words and the add still counts exactly (on the other CPU's
//! words). Readers see each word whole but the sum is not a snapshot,
//! as in Linux.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::util::error::KernelError;

/// One CPU's words of a MIB, on cache lines of its own
#[repr(align(64))]
struct Part<const N: usize>([AtomicU64; N]);

/// A per-CPU MIB of `N` entries (Linux a `__percpu` struct *_mib)
pub struct Mib<const N: usize> {
    parts: Vec<Part<N>>,
}

impl<const N: usize> Mib<N> {
    /// All zero, a part per possible CPU (Linux alloc_percpu); ENOMEM
    fn new() -> Result<Self, KernelError> {
        let n = (crate::cpu::nr_cpu_ids() as usize).max(1);
        let mut v = crate::util::kmem::KVec::try_with_capacity(n)?;
        for _ in 0..n {
            v.try_push(Part([const { AtomicU64::new(0) }; N]))?;
        }
        Ok(Self {
            parts: v.into_vec(),
        })
    }

    /// The calling CPU's words, and whether they are its alone (a CPU
    /// past the parts, possible only for a MIB made before SMP bring-up,
    /// shares the first's)
    #[inline]
    fn part(&self) -> (&[AtomicU64; N], bool) {
        let cpu = crate::cpu::try_this_id().unwrap_or(0) as usize;
        match self.parts.get(cpu) {
            Some(p) => (&p.0, true),
            None => (&self.parts[0].0, false),
        }
    }

    /// Add `n` (two's complement for a decrement) to this CPU's word
    /// (Linux this_cpu_add: no lock prefix when the word is its own)
    #[inline]
    fn add_word(&self, field: usize, n: u64) {
        let (p, own) = self.part();
        if own {
            crate::cpu::LocalWord::local_add(&p[field], n as i64);
        } else {
            p[field].fetch_add(n, Ordering::Relaxed);
        }
    }

    /// Linux SNMP_ADD_STATS
    #[inline]
    pub fn add(&self, field: usize, n: u64) {
        self.add_word(field, n);
    }

    /// Linux SNMP_INC_STATS
    #[inline]
    pub fn inc(&self, field: usize) {
        self.add(field, 1);
    }

    /// Linux SNMP_DEC_STATS (a gauge: words may wrap, the sum does not)
    #[inline]
    pub fn dec(&self, field: usize) {
        self.add_word(field, u64::MAX);
    }

    /// Linux SNMP_UPD_PO_STATS: a packet at `pkts` and its bytes at
    /// `pkts + 1` (every *PKTS entry is followed by its *OCTETS one)
    #[inline]
    pub fn upd_po(&self, pkts: usize, octets: usize, len: usize) {
        self.add_word(pkts, 1);
        self.add_word(octets, len as u64);
    }

    /// Every CPU's word of `field`, summed (Linux snmp_fold_field)
    pub fn fold(&self, field: usize) -> u64 {
        self.parts.iter().fold(0u64, |s, p| {
            s.wrapping_add(p.0[field].load(Ordering::Relaxed))
        })
    }
}

/// Entries of IcmpMsg: In and Out for every 8-bit type (Linux
/// ICMPMSG_MIB_MAX)
pub const ICMPMSG_MIB_MAX: usize = 512;

/// /proc/net/sockstat gauges, per CPU (summed with `fold`): sockets
/// alive and hashed per protocol (Linux struct prot_inuse: `all`, the
/// protocols' sock_prot_inuse_add), TIME_WAIT entries (Linux
/// tcp_death_row.tw_refcount)
pub const INUSE_ALL: usize = 0;
pub const INUSE_TCP: usize = 1;
pub const INUSE_UDP: usize = 2;
pub const INUSE_RAW: usize = 3;
pub const INUSE_TW: usize = 4;
pub const INUSE_MAX: usize = 5;

/// A namespace's MIBs (Linux struct netns_mib, IPv4 part)
pub struct NetMib {
    pub ip: Mib<IPSTATS_MIB_MAX>,
    pub icmp: Mib<ICMP_MIB_MAX>,
    /// Messages by type: In at the type, Out at 256 + type
    pub icmpmsg: Box<[AtomicU64; ICMPMSG_MIB_MAX]>,
    pub tcp: Mib<TCP_MIB_MAX>,
    pub udp: Mib<UDP_MIB_MAX>,
    /// TcpExt (Linux net_statistics)
    pub net: Mib<LINUX_MIB_MAX>,
    /// `INUSE_*` gauges
    pub inuse: Mib<INUSE_MAX>,
}

impl NetMib {
    /// A new namespace's MIBs (Linux ipv4_mib_init_net); ENOMEM
    pub fn new() -> Result<Arc<Self>, KernelError> {
        let m = crate::util::kalloc::try_arc(Self {
            ip: Mib::new()?,
            icmp: Mib::new()?,
            icmpmsg: crate::util::kalloc::try_box([const { AtomicU64::new(0) }; ICMPMSG_MIB_MAX])?,
            tcp: Mib::new()?,
            udp: Mib::new()?,
            net: Mib::new()?,
            inuse: Mib::new()?,
        })?;
        m.tcp_init();
        Ok(m)
    }

    /// RFC 2012 constants (Linux tcp_mib_init): Van Jacobson's RTO,
    /// its bounds in ms, no connection limit
    fn tcp_init(&self) {
        use crate::net::tcp::cb::{RTO_MAX, RTO_MIN};
        self.tcp.add(TCP_MIB_RTOALGORITHM, 1);
        self.tcp.add(TCP_MIB_RTOMIN, RTO_MIN);
        self.tcp.add(TCP_MIB_RTOMAX, RTO_MAX);
        self.tcp.add(TCP_MIB_MAXCONN, u64::MAX); // -1
    }

    /// Gauge `f` up or down by one (Linux sock_prot_inuse_add)
    pub fn inuse_add(&self, f: usize, up: bool) {
        if up {
            self.inuse.inc(f);
        } else {
            self.inuse.dec(f);
        }
    }

    /// Gauge `f`, summed (Linux sock_prot_inuse_get: never below 0)
    pub fn inuse_get(&self, f: usize) -> u64 {
        (self.inuse.fold(f) as i64).max(0) as u64
    }

    /// Linux icmp_out_count
    pub fn icmp_out_count(&self, ty: u8) {
        self.icmpmsg[256 + usize::from(ty)].fetch_add(1, Ordering::Relaxed);
        self.icmp.inc(ICMP_MIB_OUTMSGS);
    }

    /// Linux ICMPMSGIN_INC_STATS
    pub fn icmpmsg_in(&self, ty: u8) {
        self.icmpmsg[usize::from(ty)].fetch_add(1, Ordering::Relaxed);
    }

    /// A socket's output route lookup failed with `e` (Linux udp,
    /// ping and tcp_v4_connect: OutNoRoutes on -ENETUNREACH)
    pub fn route_err(&self, e: &KernelError) {
        if matches!(e, KernelError::NetworkUnreachable) {
            self.ip.inc(IPSTATS_MIB_OUTNOROUTES);
        }
    }

    /// A datagram could not be built or sent (Linux __ip_append_data's
    /// error path, ip_send_skb)
    pub fn out_discard(&self) {
        self.ip.inc(IPSTATS_MIB_OUTDISCARDS);
    }

    /// An IcmpMsg entry
    pub fn icmpmsg(&self, i: usize) -> u64 {
        self.icmpmsg[i].load(Ordering::Relaxed)
    }
}

// ============================================================================
// Entries (Linux include/uapi/linux/snmp.h; those hk never reads or
// prints are left out, the others keep Linux's numbers)
// ============================================================================

pub const IPSTATS_MIB_INPKTS: usize = 1;
pub const IPSTATS_MIB_INOCTETS: usize = 2;
pub const IPSTATS_MIB_INDELIVERS: usize = 3;
pub const IPSTATS_MIB_NOECTPKTS: usize = 4;
pub const IPSTATS_MIB_ECT1PKTS: usize = 5;
pub const IPSTATS_MIB_ECT0PKTS: usize = 6;
pub const IPSTATS_MIB_CEPKTS: usize = 7;
pub const IPSTATS_MIB_OUTREQUESTS: usize = 8;
pub const IPSTATS_MIB_OUTPKTS: usize = 9;
pub const IPSTATS_MIB_OUTOCTETS: usize = 10;
pub const IPSTATS_MIB_OUTFORWDATAGRAMS: usize = 11;
pub const IPSTATS_MIB_INHDRERRORS: usize = 12;
pub const IPSTATS_MIB_INNOROUTES: usize = 14;
pub const IPSTATS_MIB_INADDRERRORS: usize = 15;
pub const IPSTATS_MIB_INUNKNOWNPROTOS: usize = 16;
pub const IPSTATS_MIB_INTRUNCATEDPKTS: usize = 17;
pub const IPSTATS_MIB_INDISCARDS: usize = 18;
pub const IPSTATS_MIB_OUTDISCARDS: usize = 19;
pub const IPSTATS_MIB_OUTNOROUTES: usize = 20;
pub const IPSTATS_MIB_REASMTIMEOUT: usize = 21;
pub const IPSTATS_MIB_REASMREQDS: usize = 22;
pub const IPSTATS_MIB_REASMOKS: usize = 23;
pub const IPSTATS_MIB_REASMFAILS: usize = 24;
pub const IPSTATS_MIB_FRAGOKS: usize = 25;
pub const IPSTATS_MIB_FRAGFAILS: usize = 26;
pub const IPSTATS_MIB_FRAGCREATES: usize = 27;
pub const IPSTATS_MIB_INMCASTPKTS: usize = 28;
pub const IPSTATS_MIB_OUTMCASTPKTS: usize = 29;
pub const IPSTATS_MIB_INBCASTPKTS: usize = 30;
pub const IPSTATS_MIB_OUTBCASTPKTS: usize = 31;
pub const IPSTATS_MIB_INMCASTOCTETS: usize = 32;
pub const IPSTATS_MIB_OUTMCASTOCTETS: usize = 33;
pub const IPSTATS_MIB_INBCASTOCTETS: usize = 34;
pub const IPSTATS_MIB_OUTBCASTOCTETS: usize = 35;
pub const IPSTATS_MIB_CSUMERRORS: usize = 36;
pub const IPSTATS_MIB_REASM_OVERLAPS: usize = 37;
/// Entries (Linux IPSTATS_MIB_MAX)
pub const IPSTATS_MIB_MAX: usize = 38;

pub const ICMP_MIB_INMSGS: usize = 1;
pub const ICMP_MIB_INERRORS: usize = 2;
pub const ICMP_MIB_OUTMSGS: usize = 14;
pub const ICMP_MIB_OUTERRORS: usize = 15;
pub const ICMP_MIB_CSUMERRORS: usize = 27;
pub const ICMP_MIB_RATELIMITGLOBAL: usize = 28;
pub const ICMP_MIB_RATELIMITHOST: usize = 29;
/// Entries (Linux ICMP_MIB_MAX)
pub const ICMP_MIB_MAX: usize = 30;

pub const TCP_MIB_RTOALGORITHM: usize = 1;
pub const TCP_MIB_RTOMIN: usize = 2;
pub const TCP_MIB_RTOMAX: usize = 3;
pub const TCP_MIB_MAXCONN: usize = 4;
pub const TCP_MIB_ACTIVEOPENS: usize = 5;
pub const TCP_MIB_PASSIVEOPENS: usize = 6;
pub const TCP_MIB_ATTEMPTFAILS: usize = 7;
pub const TCP_MIB_ESTABRESETS: usize = 8;
pub const TCP_MIB_CURRESTAB: usize = 9;
pub const TCP_MIB_INSEGS: usize = 10;
pub const TCP_MIB_OUTSEGS: usize = 11;
pub const TCP_MIB_RETRANSSEGS: usize = 12;
pub const TCP_MIB_INERRS: usize = 13;
pub const TCP_MIB_OUTRSTS: usize = 14;
pub const TCP_MIB_CSUMERRORS: usize = 15;
/// Entries (Linux TCP_MIB_MAX)
pub const TCP_MIB_MAX: usize = 16;

pub const UDP_MIB_INDATAGRAMS: usize = 1;
pub const UDP_MIB_NOPORTS: usize = 2;
pub const UDP_MIB_INERRORS: usize = 3;
pub const UDP_MIB_OUTDATAGRAMS: usize = 4;
pub const UDP_MIB_RCVBUFERRORS: usize = 5;
pub const UDP_MIB_SNDBUFERRORS: usize = 6;
pub const UDP_MIB_CSUMERRORS: usize = 7;
pub const UDP_MIB_IGNOREDMULTI: usize = 8;
pub const UDP_MIB_MEMERRORS: usize = 9;
/// Entries (Linux UDP_MIB_MAX)
pub const UDP_MIB_MAX: usize = 10;

pub const LINUX_MIB_SYNCOOKIESSENT: usize = 1;
pub const LINUX_MIB_SYNCOOKIESRECV: usize = 2;
pub const LINUX_MIB_SYNCOOKIESFAILED: usize = 3;
pub const LINUX_MIB_EMBRYONICRSTS: usize = 4;
pub const LINUX_MIB_PRUNECALLED: usize = 5;
pub const LINUX_MIB_RCVPRUNED: usize = 6;
pub const LINUX_MIB_OFOPRUNED: usize = 7;
pub const LINUX_MIB_OUTOFWINDOWICMPS: usize = 8;
pub const LINUX_MIB_LOCKDROPPEDICMPS: usize = 9;
pub const LINUX_MIB_ARPFILTER: usize = 10;
pub const LINUX_MIB_TIMEWAITED: usize = 11;
pub const LINUX_MIB_TIMEWAITRECYCLED: usize = 12;
pub const LINUX_MIB_TIMEWAITKILLED: usize = 13;
pub const LINUX_MIB_PAWSACTIVEREJECTED: usize = 14;
pub const LINUX_MIB_PAWSESTABREJECTED: usize = 15;
pub const LINUX_MIB_BEYOND_WINDOW: usize = 16;
pub const LINUX_MIB_TSECRREJECTED: usize = 17;
pub const LINUX_MIB_PAWS_OLD_ACK: usize = 18;
pub const LINUX_MIB_PAWS_TW_REJECTED: usize = 19;
pub const LINUX_MIB_DELAYEDACKS: usize = 20;
pub const LINUX_MIB_DELAYEDACKLOCKED: usize = 21;
pub const LINUX_MIB_DELAYEDACKLOST: usize = 22;
pub const LINUX_MIB_LISTENOVERFLOWS: usize = 23;
pub const LINUX_MIB_LISTENDROPS: usize = 24;
pub const LINUX_MIB_TCPHPHITS: usize = 25;
pub const LINUX_MIB_TCPPUREACKS: usize = 26;
pub const LINUX_MIB_TCPHPACKS: usize = 27;
pub const LINUX_MIB_TCPRENORECOVERY: usize = 28;
pub const LINUX_MIB_TCPSACKRECOVERY: usize = 29;
pub const LINUX_MIB_TCPSACKRENEGING: usize = 30;
pub const LINUX_MIB_TCPSACKREORDER: usize = 31;
pub const LINUX_MIB_TCPRENOREORDER: usize = 32;
pub const LINUX_MIB_TCPTSREORDER: usize = 33;
pub const LINUX_MIB_TCPFULLUNDO: usize = 34;
pub const LINUX_MIB_TCPPARTIALUNDO: usize = 35;
pub const LINUX_MIB_TCPDSACKUNDO: usize = 36;
pub const LINUX_MIB_TCPLOSSUNDO: usize = 37;
pub const LINUX_MIB_TCPLOSTRETRANSMIT: usize = 38;
pub const LINUX_MIB_TCPRENOFAILURES: usize = 39;
pub const LINUX_MIB_TCPSACKFAILURES: usize = 40;
pub const LINUX_MIB_TCPLOSSFAILURES: usize = 41;
pub const LINUX_MIB_TCPFASTRETRANS: usize = 42;
pub const LINUX_MIB_TCPSLOWSTARTRETRANS: usize = 43;
pub const LINUX_MIB_TCPTIMEOUTS: usize = 44;
pub const LINUX_MIB_TCPLOSSPROBES: usize = 45;
pub const LINUX_MIB_TCPLOSSPROBERECOVERY: usize = 46;
pub const LINUX_MIB_TCPRENORECOVERYFAIL: usize = 47;
pub const LINUX_MIB_TCPSACKRECOVERYFAIL: usize = 48;
pub const LINUX_MIB_TCPRCVCOLLAPSED: usize = 49;
pub const LINUX_MIB_TCPDSACKOLDSENT: usize = 50;
pub const LINUX_MIB_TCPDSACKOFOSENT: usize = 51;
pub const LINUX_MIB_TCPDSACKRECV: usize = 52;
pub const LINUX_MIB_TCPDSACKOFORECV: usize = 53;
pub const LINUX_MIB_TCPABORTONDATA: usize = 54;
pub const LINUX_MIB_TCPABORTONCLOSE: usize = 55;
pub const LINUX_MIB_TCPABORTONMEMORY: usize = 56;
pub const LINUX_MIB_TCPABORTONTIMEOUT: usize = 57;
pub const LINUX_MIB_TCPABORTONLINGER: usize = 58;
pub const LINUX_MIB_TCPABORTFAILED: usize = 59;
pub const LINUX_MIB_TCPMEMORYPRESSURES: usize = 60;
pub const LINUX_MIB_TCPMEMORYPRESSURESCHRONO: usize = 61;
pub const LINUX_MIB_TCPSACKDISCARD: usize = 62;
pub const LINUX_MIB_TCPDSACKIGNOREDOLD: usize = 63;
pub const LINUX_MIB_TCPDSACKIGNOREDNOUNDO: usize = 64;
pub const LINUX_MIB_TCPSPURIOUSRTOS: usize = 65;
pub const LINUX_MIB_TCPMD5NOTFOUND: usize = 66;
pub const LINUX_MIB_TCPMD5UNEXPECTED: usize = 67;
pub const LINUX_MIB_TCPMD5FAILURE: usize = 68;
pub const LINUX_MIB_SACKSHIFTED: usize = 69;
pub const LINUX_MIB_SACKMERGED: usize = 70;
pub const LINUX_MIB_SACKSHIFTFALLBACK: usize = 71;
pub const LINUX_MIB_TCPBACKLOGDROP: usize = 72;
pub const LINUX_MIB_PFMEMALLOCDROP: usize = 73;
pub const LINUX_MIB_TCPMINTTLDROP: usize = 74;
pub const LINUX_MIB_TCPDEFERACCEPTDROP: usize = 75;
pub const LINUX_MIB_IPRPFILTER: usize = 76;
pub const LINUX_MIB_TCPTIMEWAITOVERFLOW: usize = 77;
pub const LINUX_MIB_TCPREQQFULLDOCOOKIES: usize = 78;
pub const LINUX_MIB_TCPREQQFULLDROP: usize = 79;
pub const LINUX_MIB_TCPRETRANSFAIL: usize = 80;
pub const LINUX_MIB_TCPRCVCOALESCE: usize = 81;
pub const LINUX_MIB_TCPBACKLOGCOALESCE: usize = 82;
pub const LINUX_MIB_TCPOFOQUEUE: usize = 83;
pub const LINUX_MIB_TCPOFODROP: usize = 84;
pub const LINUX_MIB_TCPOFOMERGE: usize = 85;
pub const LINUX_MIB_TCPCHALLENGEACK: usize = 86;
pub const LINUX_MIB_TCPSYNCHALLENGE: usize = 87;
pub const LINUX_MIB_TCPFASTOPENACTIVE: usize = 88;
pub const LINUX_MIB_TCPFASTOPENACTIVEFAIL: usize = 89;
pub const LINUX_MIB_TCPFASTOPENPASSIVE: usize = 90;
pub const LINUX_MIB_TCPFASTOPENPASSIVEFAIL: usize = 91;
pub const LINUX_MIB_TCPFASTOPENLISTENOVERFLOW: usize = 92;
pub const LINUX_MIB_TCPFASTOPENCOOKIEREQD: usize = 93;
pub const LINUX_MIB_TCPFASTOPENBLACKHOLE: usize = 94;
pub const LINUX_MIB_TCPSPURIOUS_RTX_HOSTQUEUES: usize = 95;
pub const LINUX_MIB_BUSYPOLLRXPACKETS: usize = 96;
pub const LINUX_MIB_TCPAUTOCORKING: usize = 97;
pub const LINUX_MIB_TCPFROMZEROWINDOWADV: usize = 98;
pub const LINUX_MIB_TCPTOZEROWINDOWADV: usize = 99;
pub const LINUX_MIB_TCPWANTZEROWINDOWADV: usize = 100;
pub const LINUX_MIB_TCPSYNRETRANS: usize = 101;
pub const LINUX_MIB_TCPORIGDATASENT: usize = 102;
pub const LINUX_MIB_TCPHYSTARTTRAINDETECT: usize = 103;
pub const LINUX_MIB_TCPHYSTARTTRAINCWND: usize = 104;
pub const LINUX_MIB_TCPHYSTARTDELAYDETECT: usize = 105;
pub const LINUX_MIB_TCPHYSTARTDELAYCWND: usize = 106;
pub const LINUX_MIB_TCPACKSKIPPEDSYNRECV: usize = 107;
pub const LINUX_MIB_TCPACKSKIPPEDPAWS: usize = 108;
pub const LINUX_MIB_TCPACKSKIPPEDSEQ: usize = 109;
pub const LINUX_MIB_TCPACKSKIPPEDFINWAIT2: usize = 110;
pub const LINUX_MIB_TCPACKSKIPPEDTIMEWAIT: usize = 111;
pub const LINUX_MIB_TCPACKSKIPPEDCHALLENGE: usize = 112;
pub const LINUX_MIB_TCPWINPROBE: usize = 113;
pub const LINUX_MIB_TCPKEEPALIVE: usize = 114;
pub const LINUX_MIB_TCPMTUPFAIL: usize = 115;
pub const LINUX_MIB_TCPMTUPSUCCESS: usize = 116;
pub const LINUX_MIB_TCPDELIVERED: usize = 117;
pub const LINUX_MIB_TCPDELIVEREDCE: usize = 118;
pub const LINUX_MIB_TCPACKCOMPRESSED: usize = 119;
pub const LINUX_MIB_TCPZEROWINDOWDROP: usize = 120;
pub const LINUX_MIB_TCPRCVQDROP: usize = 121;
pub const LINUX_MIB_TCPWQUEUETOOBIG: usize = 122;
pub const LINUX_MIB_TCPFASTOPENPASSIVEALTKEY: usize = 123;
pub const LINUX_MIB_TCPTIMEOUTREHASH: usize = 124;
pub const LINUX_MIB_TCPDUPLICATEDATAREHASH: usize = 125;
pub const LINUX_MIB_TCPDSACKRECVSEGS: usize = 126;
pub const LINUX_MIB_TCPDSACKIGNOREDDUBIOUS: usize = 127;
pub const LINUX_MIB_TCPMIGRATEREQSUCCESS: usize = 128;
pub const LINUX_MIB_TCPMIGRATEREQFAILURE: usize = 129;
pub const LINUX_MIB_TCPPLBREHASH: usize = 130;
pub const LINUX_MIB_TCPAOREQUIRED: usize = 131;
pub const LINUX_MIB_TCPAOBAD: usize = 132;
pub const LINUX_MIB_TCPAOKEYNOTFOUND: usize = 133;
pub const LINUX_MIB_TCPAOGOOD: usize = 134;
pub const LINUX_MIB_TCPAODROPPEDICMPS: usize = 135;
/// Entries (Linux LINUX_MIB_MAX)
pub const LINUX_MIB_MAX: usize = 136;
