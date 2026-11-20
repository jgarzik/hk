//! /proc/net files, each generated for the network namespace its
//! /proc/<pid>/net directory shows (Linux proc_net.c)

use alloc::vec::Vec;
use core::fmt::Write;

/// `/proc/net/dev`: per-interface counters in Linux's format
/// (net/core/net-procfs.c dev_seq_show), the devices walked under RCU
/// into a fixed buffer (Linux dev_seq_start's rcu_read_lock)
pub fn proc_net_dev(net: &crate::net::NetNamespace) -> Vec<u8> {
    crate::fs::proc::seq::generate(|m| {
        let _ = m.write_str(concat!(
            "Inter-|   Receive                                                |  Transmit\n",
            " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n",
        ));
        let g = crate::sync::rcu::read_lock();
        for dev in net.devices_rcu(&g) {
            dev_seq_show(m, dev);
        }
    })
}

/// One device's line of `/proc/net/dev` (Linux dev_seq_printf_stats)
fn dev_seq_show(m: &mut crate::fs::proc::seq::SeqBuf, dev: &crate::net::device::NetDevice) {
    use crate::net::device::stat::*;
    let s = &dev.stats;
    let g = |f: usize| s.get(f);
    let _ = writeln!(
        m,
        "{:>6}:{:8} {:7} {:4} {:4} {:4} {:5} {:10} {:9} {:8} {:7} {:4} {:4} {:4} {:5} {:7} {:10}",
        dev.name(),
        g(RX_BYTES),
        g(RX_PACKETS),
        g(RX_ERRORS),
        g(RX_DROPPED),
        0, // fifo
        0, // frame
        0, // compressed
        g(MULTICAST),
        g(TX_BYTES),
        g(TX_PACKETS),
        g(TX_ERRORS),
        g(TX_DROPPED),
        0, // fifo
        g(COLLISIONS),
        0, // carrier
        0, // compressed
    );
}

/// `/proc/net/route`: the main table in Linux's legacy format
/// (net/ipv4/fib_trie.c fib_route_seq_show): addresses as the raw
/// network-order u32 in hex, every line padded to 127 columns; the
/// table walked under RCU into a fixed buffer
pub fn proc_net_route(net: &crate::net::NetNamespace) -> Vec<u8> {
    use crate::net::inet::fib::RT_TABLE_MAIN;
    crate::fs::proc::seq::generate(|m| {
        let _ = writeln!(
            m,
            "{:<127}",
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT"
        );
        let g = crate::sync::rcu::read_lock();
        if let Some(t) = net.fib.get_table(&g, RT_TABLE_MAIN) {
            for e in t.entries(&g) {
                route_seq_show(m, e);
            }
        }
    })
}

/// One route's line of `/proc/net/route` (Linux fib_route_seq_show)
fn route_seq_show(m: &mut crate::fs::proc::seq::SeqBuf, e: &crate::net::inet::fib::FibEntry) {
    use crate::net::inet::fib::RouteType;
    const RTF_UP: u32 = 0x0001;
    const RTF_GATEWAY: u32 = 0x0002;
    const RTF_HOST: u32 = 0x0004;
    const RTF_REJECT: u32 = 0x0200;
    if matches!(e.rtype, RouteType::Broadcast | RouteType::Multicast) {
        return;
    }
    let raw = |a: crate::net::Ipv4Addr| u32::from_ne_bytes(a.to_be_bytes());
    let mask = crate::net::inet::ifaddr::inet_make_mask(e.dst_len);
    let mut flags = RTF_UP;
    if matches!(e.rtype, RouteType::Unreachable | RouteType::Prohibit) {
        flags |= RTF_REJECT;
    }
    if e.gateway.is_some() {
        flags |= RTF_GATEWAY;
    }
    if e.dst_len == 32 {
        flags |= RTF_HOST;
    }
    m.setwidth(127);
    let _ = write!(
        m,
        "{}\t{:08X}\t{:08X}\t{:04X}\t{}\t{}\t{}\t{:08X}\t{}\t{}\t{}",
        e.dev.as_ref().map_or("*", |d| d.name()),
        raw(e.dst),
        raw(e.gateway.unwrap_or_default()),
        flags,
        0,
        0,
        e.priority as i32,
        raw(mask),
        0,
        0,
        0
    );
    m.pad('\n');
}

// ============================================================================
// /proc/net/snmp, /proc/net/netstat (Linux net/ipv4/proc.c)
// ============================================================================

use crate::net::mib::*;

/// Ip row of /proc/net/snmp after Forwarding and DefaultTTL (Linux
/// snmp4_ipstats_list)
const SNMP4_IPSTATS_LIST: [(&str, usize); 18] = [
    ("InReceives", IPSTATS_MIB_INPKTS),
    ("InHdrErrors", IPSTATS_MIB_INHDRERRORS),
    ("InAddrErrors", IPSTATS_MIB_INADDRERRORS),
    ("ForwDatagrams", IPSTATS_MIB_OUTFORWDATAGRAMS),
    ("InUnknownProtos", IPSTATS_MIB_INUNKNOWNPROTOS),
    ("InDiscards", IPSTATS_MIB_INDISCARDS),
    ("InDelivers", IPSTATS_MIB_INDELIVERS),
    ("OutRequests", IPSTATS_MIB_OUTREQUESTS),
    ("OutDiscards", IPSTATS_MIB_OUTDISCARDS),
    ("OutNoRoutes", IPSTATS_MIB_OUTNOROUTES),
    ("ReasmTimeout", IPSTATS_MIB_REASMTIMEOUT),
    ("ReasmReqds", IPSTATS_MIB_REASMREQDS),
    ("ReasmOKs", IPSTATS_MIB_REASMOKS),
    ("ReasmFails", IPSTATS_MIB_REASMFAILS),
    ("FragOKs", IPSTATS_MIB_FRAGOKS),
    ("FragFails", IPSTATS_MIB_FRAGFAILS),
    ("FragCreates", IPSTATS_MIB_FRAGCREATES),
    ("OutTransmits", IPSTATS_MIB_OUTPKTS),
];

/// IpExt row of /proc/net/netstat (Linux snmp4_ipextstats_list)
const SNMP4_IPEXTSTATS_LIST: [(&str, usize); 18] = [
    ("InNoRoutes", IPSTATS_MIB_INNOROUTES),
    ("InTruncatedPkts", IPSTATS_MIB_INTRUNCATEDPKTS),
    ("InMcastPkts", IPSTATS_MIB_INMCASTPKTS),
    ("OutMcastPkts", IPSTATS_MIB_OUTMCASTPKTS),
    ("InBcastPkts", IPSTATS_MIB_INBCASTPKTS),
    ("OutBcastPkts", IPSTATS_MIB_OUTBCASTPKTS),
    ("InOctets", IPSTATS_MIB_INOCTETS),
    ("OutOctets", IPSTATS_MIB_OUTOCTETS),
    ("InMcastOctets", IPSTATS_MIB_INMCASTOCTETS),
    ("OutMcastOctets", IPSTATS_MIB_OUTMCASTOCTETS),
    ("InBcastOctets", IPSTATS_MIB_INBCASTOCTETS),
    ("OutBcastOctets", IPSTATS_MIB_OUTBCASTOCTETS),
    // Non RFC4293 fields
    ("InCsumErrors", IPSTATS_MIB_CSUMERRORS),
    ("InNoECTPkts", IPSTATS_MIB_NOECTPKTS),
    ("InECT1Pkts", IPSTATS_MIB_ECT1PKTS),
    ("InECT0Pkts", IPSTATS_MIB_ECT0PKTS),
    ("InCEPkts", IPSTATS_MIB_CEPKTS),
    ("ReasmOverlaps", IPSTATS_MIB_REASM_OVERLAPS),
];

/// ICMP types with an In/Out column pair in the Icmp row (Linux
/// icmpmibmap)
const ICMPMIBMAP: [(&str, u8); 11] = [
    ("DestUnreachs", 3),
    ("TimeExcds", 11),
    ("ParmProbs", 12),
    ("SrcQuenchs", 4),
    ("Redirects", 5),
    ("Echos", 8),
    ("EchoReps", 0),
    ("Timestamps", 13),
    ("TimestampReps", 14),
    ("AddrMasks", 17),
    ("AddrMaskReps", 18),
];

/// Linux snmp4_tcp_list
const SNMP4_TCP_LIST: [(&str, usize); 15] = [
    ("RtoAlgorithm", TCP_MIB_RTOALGORITHM),
    ("RtoMin", TCP_MIB_RTOMIN),
    ("RtoMax", TCP_MIB_RTOMAX),
    ("MaxConn", TCP_MIB_MAXCONN),
    ("ActiveOpens", TCP_MIB_ACTIVEOPENS),
    ("PassiveOpens", TCP_MIB_PASSIVEOPENS),
    ("AttemptFails", TCP_MIB_ATTEMPTFAILS),
    ("EstabResets", TCP_MIB_ESTABRESETS),
    ("CurrEstab", TCP_MIB_CURRESTAB),
    ("InSegs", TCP_MIB_INSEGS),
    ("OutSegs", TCP_MIB_OUTSEGS),
    ("RetransSegs", TCP_MIB_RETRANSSEGS),
    ("InErrs", TCP_MIB_INERRS),
    ("OutRsts", TCP_MIB_OUTRSTS),
    ("InCsumErrors", TCP_MIB_CSUMERRORS),
];

/// Linux snmp4_udp_list
const SNMP4_UDP_LIST: [(&str, usize); 9] = [
    ("InDatagrams", UDP_MIB_INDATAGRAMS),
    ("NoPorts", UDP_MIB_NOPORTS),
    ("InErrors", UDP_MIB_INERRORS),
    ("OutDatagrams", UDP_MIB_OUTDATAGRAMS),
    ("RcvbufErrors", UDP_MIB_RCVBUFERRORS),
    ("SndbufErrors", UDP_MIB_SNDBUFERRORS),
    ("InCsumErrors", UDP_MIB_CSUMERRORS),
    ("IgnoredMulti", UDP_MIB_IGNOREDMULTI),
    ("MemErrors", UDP_MIB_MEMERRORS),
];

/// TcpExt row of /proc/net/netstat (Linux snmp4_net_list)
const SNMP4_NET_LIST: [(&str, usize); 135] = [
    ("SyncookiesSent", LINUX_MIB_SYNCOOKIESSENT),
    ("SyncookiesRecv", LINUX_MIB_SYNCOOKIESRECV),
    ("SyncookiesFailed", LINUX_MIB_SYNCOOKIESFAILED),
    ("EmbryonicRsts", LINUX_MIB_EMBRYONICRSTS),
    ("PruneCalled", LINUX_MIB_PRUNECALLED),
    ("RcvPruned", LINUX_MIB_RCVPRUNED),
    ("OfoPruned", LINUX_MIB_OFOPRUNED),
    ("OutOfWindowIcmps", LINUX_MIB_OUTOFWINDOWICMPS),
    ("LockDroppedIcmps", LINUX_MIB_LOCKDROPPEDICMPS),
    ("ArpFilter", LINUX_MIB_ARPFILTER),
    ("TW", LINUX_MIB_TIMEWAITED),
    ("TWRecycled", LINUX_MIB_TIMEWAITRECYCLED),
    ("TWKilled", LINUX_MIB_TIMEWAITKILLED),
    ("PAWSActive", LINUX_MIB_PAWSACTIVEREJECTED),
    ("PAWSEstab", LINUX_MIB_PAWSESTABREJECTED),
    ("BeyondWindow", LINUX_MIB_BEYOND_WINDOW),
    ("TSEcrRejected", LINUX_MIB_TSECRREJECTED),
    ("PAWSOldAck", LINUX_MIB_PAWS_OLD_ACK),
    ("PAWSTimewait", LINUX_MIB_PAWS_TW_REJECTED),
    ("DelayedACKs", LINUX_MIB_DELAYEDACKS),
    ("DelayedACKLocked", LINUX_MIB_DELAYEDACKLOCKED),
    ("DelayedACKLost", LINUX_MIB_DELAYEDACKLOST),
    ("ListenOverflows", LINUX_MIB_LISTENOVERFLOWS),
    ("ListenDrops", LINUX_MIB_LISTENDROPS),
    ("TCPHPHits", LINUX_MIB_TCPHPHITS),
    ("TCPPureAcks", LINUX_MIB_TCPPUREACKS),
    ("TCPHPAcks", LINUX_MIB_TCPHPACKS),
    ("TCPRenoRecovery", LINUX_MIB_TCPRENORECOVERY),
    ("TCPSackRecovery", LINUX_MIB_TCPSACKRECOVERY),
    ("TCPSACKReneging", LINUX_MIB_TCPSACKRENEGING),
    ("TCPSACKReorder", LINUX_MIB_TCPSACKREORDER),
    ("TCPRenoReorder", LINUX_MIB_TCPRENOREORDER),
    ("TCPTSReorder", LINUX_MIB_TCPTSREORDER),
    ("TCPFullUndo", LINUX_MIB_TCPFULLUNDO),
    ("TCPPartialUndo", LINUX_MIB_TCPPARTIALUNDO),
    ("TCPDSACKUndo", LINUX_MIB_TCPDSACKUNDO),
    ("TCPLossUndo", LINUX_MIB_TCPLOSSUNDO),
    ("TCPLostRetransmit", LINUX_MIB_TCPLOSTRETRANSMIT),
    ("TCPRenoFailures", LINUX_MIB_TCPRENOFAILURES),
    ("TCPSackFailures", LINUX_MIB_TCPSACKFAILURES),
    ("TCPLossFailures", LINUX_MIB_TCPLOSSFAILURES),
    ("TCPFastRetrans", LINUX_MIB_TCPFASTRETRANS),
    ("TCPSlowStartRetrans", LINUX_MIB_TCPSLOWSTARTRETRANS),
    ("TCPTimeouts", LINUX_MIB_TCPTIMEOUTS),
    ("TCPLossProbes", LINUX_MIB_TCPLOSSPROBES),
    ("TCPLossProbeRecovery", LINUX_MIB_TCPLOSSPROBERECOVERY),
    ("TCPRenoRecoveryFail", LINUX_MIB_TCPRENORECOVERYFAIL),
    ("TCPSackRecoveryFail", LINUX_MIB_TCPSACKRECOVERYFAIL),
    ("TCPRcvCollapsed", LINUX_MIB_TCPRCVCOLLAPSED),
    ("TCPBacklogCoalesce", LINUX_MIB_TCPBACKLOGCOALESCE),
    ("TCPDSACKOldSent", LINUX_MIB_TCPDSACKOLDSENT),
    ("TCPDSACKOfoSent", LINUX_MIB_TCPDSACKOFOSENT),
    ("TCPDSACKRecv", LINUX_MIB_TCPDSACKRECV),
    ("TCPDSACKOfoRecv", LINUX_MIB_TCPDSACKOFORECV),
    ("TCPAbortOnData", LINUX_MIB_TCPABORTONDATA),
    ("TCPAbortOnClose", LINUX_MIB_TCPABORTONCLOSE),
    ("TCPAbortOnMemory", LINUX_MIB_TCPABORTONMEMORY),
    ("TCPAbortOnTimeout", LINUX_MIB_TCPABORTONTIMEOUT),
    ("TCPAbortOnLinger", LINUX_MIB_TCPABORTONLINGER),
    ("TCPAbortFailed", LINUX_MIB_TCPABORTFAILED),
    ("TCPMemoryPressures", LINUX_MIB_TCPMEMORYPRESSURES),
    (
        "TCPMemoryPressuresChrono",
        LINUX_MIB_TCPMEMORYPRESSURESCHRONO,
    ),
    ("TCPSACKDiscard", LINUX_MIB_TCPSACKDISCARD),
    ("TCPDSACKIgnoredOld", LINUX_MIB_TCPDSACKIGNOREDOLD),
    ("TCPDSACKIgnoredNoUndo", LINUX_MIB_TCPDSACKIGNOREDNOUNDO),
    ("TCPSpuriousRTOs", LINUX_MIB_TCPSPURIOUSRTOS),
    ("TCPMD5NotFound", LINUX_MIB_TCPMD5NOTFOUND),
    ("TCPMD5Unexpected", LINUX_MIB_TCPMD5UNEXPECTED),
    ("TCPMD5Failure", LINUX_MIB_TCPMD5FAILURE),
    ("TCPSackShifted", LINUX_MIB_SACKSHIFTED),
    ("TCPSackMerged", LINUX_MIB_SACKMERGED),
    ("TCPSackShiftFallback", LINUX_MIB_SACKSHIFTFALLBACK),
    ("TCPBacklogDrop", LINUX_MIB_TCPBACKLOGDROP),
    ("PFMemallocDrop", LINUX_MIB_PFMEMALLOCDROP),
    ("TCPMinTTLDrop", LINUX_MIB_TCPMINTTLDROP),
    ("TCPDeferAcceptDrop", LINUX_MIB_TCPDEFERACCEPTDROP),
    ("IPReversePathFilter", LINUX_MIB_IPRPFILTER),
    ("TCPTimeWaitOverflow", LINUX_MIB_TCPTIMEWAITOVERFLOW),
    ("TCPReqQFullDoCookies", LINUX_MIB_TCPREQQFULLDOCOOKIES),
    ("TCPReqQFullDrop", LINUX_MIB_TCPREQQFULLDROP),
    ("TCPRetransFail", LINUX_MIB_TCPRETRANSFAIL),
    ("TCPRcvCoalesce", LINUX_MIB_TCPRCVCOALESCE),
    ("TCPOFOQueue", LINUX_MIB_TCPOFOQUEUE),
    ("TCPOFODrop", LINUX_MIB_TCPOFODROP),
    ("TCPOFOMerge", LINUX_MIB_TCPOFOMERGE),
    ("TCPChallengeACK", LINUX_MIB_TCPCHALLENGEACK),
    ("TCPSYNChallenge", LINUX_MIB_TCPSYNCHALLENGE),
    ("TCPFastOpenActive", LINUX_MIB_TCPFASTOPENACTIVE),
    ("TCPFastOpenActiveFail", LINUX_MIB_TCPFASTOPENACTIVEFAIL),
    ("TCPFastOpenPassive", LINUX_MIB_TCPFASTOPENPASSIVE),
    ("TCPFastOpenPassiveFail", LINUX_MIB_TCPFASTOPENPASSIVEFAIL),
    (
        "TCPFastOpenListenOverflow",
        LINUX_MIB_TCPFASTOPENLISTENOVERFLOW,
    ),
    ("TCPFastOpenCookieReqd", LINUX_MIB_TCPFASTOPENCOOKIEREQD),
    ("TCPFastOpenBlackhole", LINUX_MIB_TCPFASTOPENBLACKHOLE),
    (
        "TCPSpuriousRtxHostQueues",
        LINUX_MIB_TCPSPURIOUS_RTX_HOSTQUEUES,
    ),
    ("BusyPollRxPackets", LINUX_MIB_BUSYPOLLRXPACKETS),
    ("TCPAutoCorking", LINUX_MIB_TCPAUTOCORKING),
    ("TCPFromZeroWindowAdv", LINUX_MIB_TCPFROMZEROWINDOWADV),
    ("TCPToZeroWindowAdv", LINUX_MIB_TCPTOZEROWINDOWADV),
    ("TCPWantZeroWindowAdv", LINUX_MIB_TCPWANTZEROWINDOWADV),
    ("TCPSynRetrans", LINUX_MIB_TCPSYNRETRANS),
    ("TCPOrigDataSent", LINUX_MIB_TCPORIGDATASENT),
    ("TCPHystartTrainDetect", LINUX_MIB_TCPHYSTARTTRAINDETECT),
    ("TCPHystartTrainCwnd", LINUX_MIB_TCPHYSTARTTRAINCWND),
    ("TCPHystartDelayDetect", LINUX_MIB_TCPHYSTARTDELAYDETECT),
    ("TCPHystartDelayCwnd", LINUX_MIB_TCPHYSTARTDELAYCWND),
    ("TCPACKSkippedSynRecv", LINUX_MIB_TCPACKSKIPPEDSYNRECV),
    ("TCPACKSkippedPAWS", LINUX_MIB_TCPACKSKIPPEDPAWS),
    ("TCPACKSkippedSeq", LINUX_MIB_TCPACKSKIPPEDSEQ),
    ("TCPACKSkippedFinWait2", LINUX_MIB_TCPACKSKIPPEDFINWAIT2),
    ("TCPACKSkippedTimeWait", LINUX_MIB_TCPACKSKIPPEDTIMEWAIT),
    ("TCPACKSkippedChallenge", LINUX_MIB_TCPACKSKIPPEDCHALLENGE),
    ("TCPWinProbe", LINUX_MIB_TCPWINPROBE),
    ("TCPKeepAlive", LINUX_MIB_TCPKEEPALIVE),
    ("TCPMTUPFail", LINUX_MIB_TCPMTUPFAIL),
    ("TCPMTUPSuccess", LINUX_MIB_TCPMTUPSUCCESS),
    ("TCPDelivered", LINUX_MIB_TCPDELIVERED),
    ("TCPDeliveredCE", LINUX_MIB_TCPDELIVEREDCE),
    ("TCPAckCompressed", LINUX_MIB_TCPACKCOMPRESSED),
    ("TCPZeroWindowDrop", LINUX_MIB_TCPZEROWINDOWDROP),
    ("TCPRcvQDrop", LINUX_MIB_TCPRCVQDROP),
    ("TCPWqueueTooBig", LINUX_MIB_TCPWQUEUETOOBIG),
    (
        "TCPFastOpenPassiveAltKey",
        LINUX_MIB_TCPFASTOPENPASSIVEALTKEY,
    ),
    ("TcpTimeoutRehash", LINUX_MIB_TCPTIMEOUTREHASH),
    ("TcpDuplicateDataRehash", LINUX_MIB_TCPDUPLICATEDATAREHASH),
    ("TCPDSACKRecvSegs", LINUX_MIB_TCPDSACKRECVSEGS),
    ("TCPDSACKIgnoredDubious", LINUX_MIB_TCPDSACKIGNOREDDUBIOUS),
    ("TCPMigrateReqSuccess", LINUX_MIB_TCPMIGRATEREQSUCCESS),
    ("TCPMigrateReqFailure", LINUX_MIB_TCPMIGRATEREQFAILURE),
    ("TCPPLBRehash", LINUX_MIB_TCPPLBREHASH),
    ("TCPAORequired", LINUX_MIB_TCPAOREQUIRED),
    ("TCPAOBad", LINUX_MIB_TCPAOBAD),
    ("TCPAOKeyNotFound", LINUX_MIB_TCPAOKEYNOTFOUND),
    ("TCPAOGood", LINUX_MIB_TCPAOGOOD),
    ("TCPAODroppedIcmps", LINUX_MIB_TCPAODROPPEDICMPS),
];

/// `/proc/net/sockstat` of `net` (Linux sockstat_seq_show): sockets
/// alive, TCP's hashed, orphaned (every namespace's), TIME_WAIT, alive
/// (every namespace's) and memory in pages, UDP's and RAW's hashed,
/// reassembly queues and bytes
pub fn proc_net_sockstat(net: &crate::net::NetNamespace) -> Vec<u8> {
    use crate::net::mib::{INUSE_ALL, INUSE_RAW, INUSE_TCP, INUSE_TW, INUSE_UDP};
    use crate::net::tcp::mem;
    let m = &net.mib;
    let (frags, frag_mem) = net.frags.usage();
    crate::fs::proc::seq::generate(|s| {
        let _ = writeln!(s, "sockets: used {}", m.inuse_get(INUSE_ALL));
        let _ = writeln!(
            s,
            "TCP: inuse {} orphan {} tw {} alloc {} mem {}",
            m.inuse_get(INUSE_TCP),
            mem::orphans(),
            m.inuse_get(INUSE_TW),
            mem::sockets(),
            mem::allocated()
        );
        let _ = writeln!(
            s,
            "UDP: inuse {} mem {}",
            m.inuse_get(INUSE_UDP),
            crate::net::udp::mem::allocated()
        );
        let _ = writeln!(s, "RAW: inuse {}", m.inuse_get(INUSE_RAW));
        let _ = writeln!(s, "FRAG: inuse {} memory {}", frags, frag_mem);
    })
}

/// `/proc/net/snmp` of `net` (Linux snmp_seq_show; no
/// UdpLite rows: hk has no UDP-Lite, which Linux retired)
pub fn proc_net_snmp(net: &crate::net::NetNamespace) -> Vec<u8> {
    let mib = &net.mib;
    crate::fs::proc::seq::generate(|m| {
        ipstats_show(m, net, mib);
        icmp_put(m, mib);
        icmpmsg_put(m, mib);
        tcp_udp_show(m, mib);
    })
}

/// A header line of `names` led by `tag`, then the value line's tag
fn mib_head<'a>(
    m: &mut crate::fs::proc::seq::SeqBuf,
    tag: &str,
    names: impl Iterator<Item = &'a str>,
) {
    let _ = write!(m, "{}:", tag);
    for n in names {
        let _ = write!(m, " {}", n);
    }
    let _ = write!(m, "\n{}:", tag);
}

/// Linux snmp_seq_show_ipstats: Forwarding 1 with "all"'s forwarding
/// on, else 2; DefaultTTL the IP default
fn ipstats_show(
    m: &mut crate::fs::proc::seq::SeqBuf,
    net: &crate::net::NetNamespace,
    mib: &NetMib,
) {
    let _ = m.write_str("Ip: Forwarding DefaultTTL");
    for (n, _) in SNMP4_IPSTATS_LIST {
        let _ = write!(m, " {}", n);
    }
    let fwd = net
        .devconf_all
        .get(crate::net::inet::devconf::ci::FORWARDING);
    let fwd = if fwd != 0 { 1 } else { 2 };
    let _ = write!(m, "\nIp: {} {}", fwd, crate::net::ipv4::IP_DEFAULT_TTL);
    for (_, f) in SNMP4_IPSTATS_LIST {
        let _ = write!(m, " {}", mib.ip.fold(f));
    }
}

/// Linux icmp_put: the per-type columns come from IcmpMsg
fn icmp_put(m: &mut crate::fs::proc::seq::SeqBuf, mib: &NetMib) {
    let _ = m.write_str("\nIcmp: InMsgs InErrors InCsumErrors");
    for (n, _) in ICMPMIBMAP {
        let _ = write!(m, " In{}", n);
    }
    let _ = m.write_str(" OutMsgs OutErrors OutRateLimitGlobal OutRateLimitHost");
    for (n, _) in ICMPMIBMAP {
        let _ = write!(m, " Out{}", n);
    }
    let i = |f| mib.icmp.fold(f);
    let _ = write!(
        m,
        "\nIcmp: {} {} {}",
        i(ICMP_MIB_INMSGS),
        i(ICMP_MIB_INERRORS),
        i(ICMP_MIB_CSUMERRORS)
    );
    for (_, t) in ICMPMIBMAP {
        let _ = write!(m, " {}", mib.icmpmsg(usize::from(t)));
    }
    let _ = write!(
        m,
        " {} {} {} {}",
        i(ICMP_MIB_OUTMSGS),
        i(ICMP_MIB_OUTERRORS),
        i(ICMP_MIB_RATELIMITGLOBAL),
        i(ICMP_MIB_RATELIMITHOST)
    );
    for (_, t) in ICMPMIBMAP {
        let _ = write!(m, " {}", mib.icmpmsg(256 + usize::from(t)));
    }
}

/// Linux icmpmsg_put: the nonzero IcmpMsg entries, 16 to a line pair
fn icmpmsg_put(m: &mut crate::fs::proc::seq::SeqBuf, mib: &NetMib) {
    const PERLINE: usize = 16;
    let mut ent = [(0usize, 0u64); PERLINE];
    let mut count = 0;
    for i in 0..ICMPMSG_MIB_MAX {
        let v = mib.icmpmsg(i);
        if v != 0 {
            ent[count] = (i, v);
            count += 1;
        }
        if count == PERLINE {
            icmpmsg_put_line(m, &ent);
            count = 0;
        }
    }
    icmpmsg_put_line(m, &ent[..count]);
}

/// Linux icmpmsg_put_line
fn icmpmsg_put_line(m: &mut crate::fs::proc::seq::SeqBuf, ent: &[(usize, u64)]) {
    if ent.is_empty() {
        return;
    }
    let _ = m.write_str("\nIcmpMsg:");
    for &(t, _) in ent {
        let dir = if t & 0x100 != 0 { "Out" } else { "In" };
        let _ = write!(m, " {}Type{}", dir, t & 0xff);
    }
    let _ = m.write_str("\nIcmpMsg:");
    for &(_, v) in ent {
        let _ = write!(m, " {}", v);
    }
}

/// Linux snmp_seq_show_tcp_udp: MaxConn is signed (RFC 2012)
fn tcp_udp_show(m: &mut crate::fs::proc::seq::SeqBuf, mib: &NetMib) {
    let _ = m.write_char('\n');
    mib_head(m, "Tcp", SNMP4_TCP_LIST.iter().map(|e| e.0));
    for (_, f) in SNMP4_TCP_LIST {
        let v = mib.tcp.fold(f);
        if f == TCP_MIB_MAXCONN {
            // The word holds -1 (Linux prints it with %ld)
            let _ = write!(m, " {}", v as i64);
        } else {
            let _ = write!(m, " {}", v);
        }
    }
    let _ = m.write_char('\n');
    mib_head(m, "Udp", SNMP4_UDP_LIST.iter().map(|e| e.0));
    for (_, f) in SNMP4_UDP_LIST {
        let _ = write!(m, " {}", mib.udp.fold(f));
    }
    let _ = m.write_char('\n');
}

/// `/proc/net/netstat` of `net` (Linux
/// netstat_seq_show; no MPTcpExt rows: hk has no MPTCP, like a kernel
/// without CONFIG_MPTCP)
pub fn proc_net_netstat(net: &crate::net::NetNamespace) -> Vec<u8> {
    let mib = &net.mib;
    crate::fs::proc::seq::generate(|m| {
        mib_head(m, "TcpExt", SNMP4_NET_LIST.iter().map(|e| e.0));
        for (_, f) in SNMP4_NET_LIST {
            let _ = write!(m, " {}", mib.net.fold(f));
        }
        let _ = m.write_char('\n');
        mib_head(m, "IpExt", SNMP4_IPEXTSTATS_LIST.iter().map(|e| e.0));
        for (_, f) in SNMP4_IPEXTSTATS_LIST {
            let _ = write!(m, " {}", mib.ip.fold(f));
        }
        let _ = m.write_char('\n');
    })
}
