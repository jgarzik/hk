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
