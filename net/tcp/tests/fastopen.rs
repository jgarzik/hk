//! A passive Fast Open child in SYN_RECEIVED and FIN_WAIT_1 (Linux
//! tcp_fastopen_create_child, tcp_rcv_state_process with fastopen_rsk)

use super::*;

/// A Fast Open child for a's SYN carrying `data`: (a, its SYN, b)
fn tfo_child(data: &[u8]) -> (TcpCb, Seg, TcpCb) {
    let mut a = TcpCb::new(cfg(), Default::default());
    let mut out = Out::default();
    a.connect(open(1000, 1460), 0, &mut out);
    let syn = wire(&out).remove(0);
    let mut s = seg_in(&syn);
    s.data = data;
    let mut b = TcpCb::new(cfg(), Default::default());
    let mut out = Out::default();
    b.fastopen_open(&s.hdr(), s.skb(), open(5000, 1460), 0, &mut out);
    assert_eq!(b.state, TcpState::SynReceived);
    (a, syn, b)
}

/// The peer's ACK of b's SYN-ACK and of `acked` bytes b sent after it
fn synack_ack(syn: &Seg, b: &TcpCb, rcv: u32, acked: u32) -> SegIn<'static> {
    SegIn {
        seq: rcv,
        ack: 5001 + acked,
        flags: flags::ACK,
        wnd: 1000,
        ts: syn.ts.map(|(v, _)| (v + 10, b.tsval())),
        ..Default::default()
    }
}

/// The handshake's ACK also covering data the child sent in
/// SYN_RECEIVED cleans it from the retransmit queue (Linux
/// tcp_rcv_state_process runs the full tcp_ack in SYN_RECV): nothing
/// left in flight, no retransmission timer
#[test]
fn synrecv_ack_covers_data() {
    let data = b"fast open data";
    let (_, syn, mut b) = tfo_child(data);
    assert_eq!(b.send(b"reply"), 5);
    let mut out = Out::default();
    b.output(10, &mut out);
    assert_eq!(b.packets_out, 1);
    let rcv = 1001 + data.len() as u32;
    let mut out = Out::default();
    b.feed(&synack_ack(&syn, &b, rcv, 5), 20, &mut out);
    assert_eq!(b.state, TcpState::Established);
    assert_eq!(b.snd_una, 5006);
    assert_eq!(b.packets_out, 0);
    assert_eq!(b.sndq_len(), 0);
    assert!(b.rtx.first().is_none());
    assert!(b.live.tmr.get().is_none());
}

/// A child shut down in SYN_RECEIVED goes to FIN_WAIT_1 with its
/// request (Linux fastopen_rsk); the ACK of its SYN-ACK there releases
/// it (tcp_rcv_state_process FIN_WAIT1: tcp_rcv_synrecv_state_fastopen),
/// so its timeouts follow the connection's rules from then on
#[test]
fn fin_wait1_ack_releases_request() {
    let data = b"fast open data";
    let (_, syn, mut b) = tfo_child(data);
    b.live.retransmits.set(1);
    let mut out = Out::default();
    assert!(b.shutdown_wr(10, &mut out));
    assert_eq!(b.state, TcpState::FinWait1);
    assert!(b.tfo);
    let rcv = 1001 + data.len() as u32;
    // An ACK not past the SYN-ACK is old (Linux tcp_ack's old_ack: not
    // acceptable, challenged): the request stays
    let mut old = synack_ack(&syn, &b, rcv, 0);
    old.ack = 5000;
    let mut out = Out::default();
    b.feed(&old, 15, &mut out);
    assert!(b.tfo);
    // The SYN-ACK acked, not the FIN
    let mut out = Out::default();
    b.feed(&synack_ack(&syn, &b, rcv, 0), 20, &mut out);
    assert_eq!(b.state, TcpState::FinWait1);
    assert!(!b.tfo);
    assert_eq!(b.snd_una, 5001);
    assert_eq!(b.live.retransmits.get(), 0);
    assert!(b.rtx_stamp.is_none());
    // The FIN acked
    let mut out = Out::default();
    b.feed(&synack_ack(&syn, &b, rcv, 1), 30, &mut out);
    assert_eq!(b.state, TcpState::FinWait2);
}

/// A retransmitted SYN reaching a child in FIN_WAIT_1 still holding its
/// request resends the SYN-ACK (Linux tcp_check_req runs for
/// fastopen_rsk in FIN_WAIT1 too)
#[test]
fn fin_wait1_request_resends_synack() {
    let data = b"fast open data";
    let (_, syn, mut b) = tfo_child(data);
    let mut out = Out::default();
    b.shutdown_wr(10, &mut out);
    let mut s = seg_in(&syn);
    s.data = data;
    let mut out = Out::default();
    b.feed(&s, 20, &mut out);
    let w = wire(&out);
    assert!(
        w.iter()
            .any(|x| x.has(flags::SYN) && x.has(flags::ACK) && x.seq == 5000)
    );
    assert_eq!(b.state, TcpState::FinWait1);
}

/// An ACK beyond SND.MAX to a child holding its request in FIN_WAIT_1
/// is not acceptable (Linux tcp_ack: after(ack, snd_nxt)) and changes
/// nothing: tcp_rcv_state_process sends a challenge ACK, the request
/// and the SYN-ACK's retransmission state stay
#[test]
fn fin_wait1_ack_beyond_snd_max() {
    let data = b"fast open data";
    let (_, syn, mut b) = tfo_child(data);
    let mut out = Out::default();
    b.shutdown_wr(10, &mut out);
    let rcv = 1001 + data.len() as u32;
    let bad = synack_ack(&syn, &b, rcv, 100);
    let mut out = Out::default();
    b.feed(&bad, 20, &mut out);
    assert_eq!(b.state, TcpState::FinWait1);
    assert!(b.tfo && b.syn_unacked);
    assert_eq!(b.snd_una, 5000);
    let w = wire(&out);
    assert_eq!(w.len(), 1);
    assert!(w[0].flags == flags::ACK && w[0].seq == b.snd_max && w[0].ack == rcv);
}

/// The SYN's data does not shrink the SYN-ACK's window: Linux keeps
/// rcv_wnd as a length, RCV.WUP moving with RCV.NXT past the data
/// (tcp_fastopen_create_child)
#[test]
fn syn_data_keeps_synack_window() {
    let wnd = |data: &[u8]| {
        let mut a = TcpCb::new(cfg(), Default::default());
        let mut out = Out::default();
        a.connect(open(1000, 1460), 0, &mut out);
        let syn = wire(&out).remove(0);
        let mut s = seg_in(&syn);
        s.data = data;
        let mut b = TcpCb::new(cfg(), Default::default());
        let mut out = Out::default();
        b.fastopen_open(&s.hdr(), s.skb(), open(5000, 1460), 0, &mut out);
        wire(&out)[0].wnd
    };
    assert_eq!(wnd(&[7; 100]), wnd(b""));
}

/// SYN data the SYN-ACK did not acknowledge is resent as a
/// non-congestion loss (Linux tcp_rcv_fastopen_synack ->
/// tcp_non_congestion_loss_retransmit, since 5dfe9d273932): in CA_Loss
/// the ACK of the resent data clears the retransmission stamp (here a
/// Reno peer: tcp_is_non_sack_preventing_reopen holds the state until
/// something above high_seq is acked, the stamp cleared with nothing
/// retransmitted left), so no stale stamp cuts a later RTO short
#[test]
fn active_syn_data_resend_clears_stamp() {
    use super::super::cb::{FoReq, Foc};
    use super::super::recovery::CaState;
    let mut a = TcpCb::new(cfg(), Default::default());
    a.connect_init(open(1000, 1460), 0);
    a.fastopen_prep(1460, 4);
    a.send(b"data");
    let fo = FoReq {
        ok: true,
        cookie: Some(Foc {
            len: 8,
            ..Foc::default()
        }),
        mss: 0,
    };
    let mut out = Out::default();
    a.connect_send(Some(fo), 0, &mut out);
    let synack = SegIn {
        seq: 7000,
        ack: 1001,
        flags: flags::SYN | flags::ACK,
        wnd: 5000,
        mss: Some(1460),
        ..Default::default()
    };
    let mut out = Out::default();
    a.feed(&synack, 10, &mut out);
    assert!(
        wire(&out)
            .iter()
            .any(|s| s.seq == 1001 && s.data == b"data")
    );
    assert_eq!(a.ca_state, CaState::Loss);
    let ack = SegIn {
        seq: 7001,
        ack: 1005,
        flags: flags::ACK,
        wnd: 5000,
        ..Default::default()
    };
    let mut out = Out::default();
    a.feed(&ack, 20, &mut out);
    assert_eq!(a.packets_out, 0);
    assert!(a.rtx_stamp.is_none());
    assert_eq!(a.ca_state, CaState::Loss);
}
