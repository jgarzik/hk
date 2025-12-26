//! TCP Output Processing
//!
//! This module handles building and transmitting TCP segments.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::net::NetError;
use crate::net::ipv4::{self, IPPROTO_TCP, Ipv4Addr};
use crate::net::request_sock::RequestSock;
use crate::net::skb::SkBuff;
use crate::net::socket::Socket;
use crate::net::tcp::{TCP_HLEN_MIN, TcpSegment, TcpState, flags, tcp_checksum};

/// Send data over a TCP connection
pub fn tcp_sendmsg(socket: &Arc<Socket>, data: &[u8]) -> Result<usize, NetError> {
    let tcp = socket.tcp.as_ref().ok_or(NetError::InvalidArgument)?;

    // Check state
    if !tcp.state().is_connected() {
        return Err(NetError::NotSupported);
    }

    if tcp.state() != TcpState::Established && tcp.state() != TcpState::CloseWait {
        return Err(NetError::NotSupported);
    }

    let (local_addr, local_port) = socket.local_addr().ok_or(NetError::InvalidArgument)?;
    let (remote_addr, remote_port) = socket.remote_addr().ok_or(NetError::InvalidArgument)?;

    // Segment data into MSS-sized chunks
    let mss = tcp.mss as usize;
    let mut sent = 0;

    while sent < data.len() {
        // Check send window
        let snd_wnd = tcp.snd_wnd.load(Ordering::Acquire);
        if snd_wnd == 0 {
            // Window is closed - we'd need to wait
            if sent > 0 {
                return Ok(sent);
            }
            return Err(NetError::WouldBlock);
        }

        let chunk_len = (data.len() - sent).min(mss).min(snd_wnd as usize);
        let chunk = &data[sent..sent + chunk_len];

        // Build segment
        let seq = tcp.snd_nxt();
        let ack = tcp.rcv_nxt();
        let window = tcp.rcv_wnd.load(Ordering::Acquire) as u16;

        let mut skb = SkBuff::alloc_tx(chunk_len).ok_or(NetError::OutOfMemory)?;

        // Add payload
        skb.put_slice(chunk).ok_or(NetError::NoBufferSpace)?;

        // Build TCP header
        build_tcp_header(
            &mut skb,
            local_port,
            remote_port,
            seq,
            ack,
            flags::ACK | flags::PSH,
            window,
            local_addr,
            remote_addr,
        )?;

        // Update sequence number
        tcp.inc_snd_nxt(chunk_len as u32);

        // Add to retransmit queue
        {
            let mut rtx = tcp.retransmit_queue.lock();
            rtx.push(TcpSegment {
                seq,
                data: skb.data().to_vec(),
                sent_at: crate::time::current_ticks(),
                retries: 0,
            });
        }

        // Set addresses and transmit
        skb.saddr = Some(local_addr);
        skb.daddr = Some(remote_addr);

        ipv4::ip_queue_xmit(skb, IPPROTO_TCP)?;

        sent += chunk_len;
    }

    Ok(sent)
}

/// Send a SYN segment
pub fn tcp_send_syn(socket: &Arc<Socket>) -> Result<(), NetError> {
    let tcp = socket.tcp.as_ref().ok_or(NetError::InvalidArgument)?;
    let (local_addr, local_port) = socket.local_addr().ok_or(NetError::InvalidArgument)?;
    let (remote_addr, remote_port) = socket.remote_addr().ok_or(NetError::InvalidArgument)?;

    let seq = tcp.snd_nxt();
    let window = tcp.rcv_wnd.load(Ordering::Acquire) as u16;

    let mut skb = SkBuff::alloc_tx(0).ok_or(NetError::OutOfMemory)?;

    // Build TCP header with SYN flag
    build_tcp_header(
        &mut skb,
        local_port,
        remote_port,
        seq,
        0,
        flags::SYN,
        window,
        local_addr,
        remote_addr,
    )?;

    // SYN consumes one sequence number
    tcp.inc_snd_nxt(1);

    // Set addresses and transmit
    skb.saddr = Some(local_addr);
    skb.daddr = Some(remote_addr);

    ipv4::ip_queue_xmit(skb, IPPROTO_TCP)
}

/// Send an ACK segment
pub fn tcp_send_ack(socket: &Arc<Socket>) -> Result<(), NetError> {
    let tcp = socket.tcp.as_ref().ok_or(NetError::InvalidArgument)?;
    let (local_addr, local_port) = socket.local_addr().ok_or(NetError::InvalidArgument)?;
    let (remote_addr, remote_port) = socket.remote_addr().ok_or(NetError::InvalidArgument)?;

    let seq = tcp.snd_nxt();
    let ack = tcp.rcv_nxt();
    let window = tcp.rcv_wnd.load(Ordering::Acquire) as u16;

    let mut skb = SkBuff::alloc_tx(0).ok_or(NetError::OutOfMemory)?;

    build_tcp_header(
        &mut skb,
        local_port,
        remote_port,
        seq,
        ack,
        flags::ACK,
        window,
        local_addr,
        remote_addr,
    )?;

    skb.saddr = Some(local_addr);
    skb.daddr = Some(remote_addr);

    ipv4::ip_queue_xmit(skb, IPPROTO_TCP)
}

/// Send a FIN segment
pub fn tcp_send_fin(socket: &Arc<Socket>) -> Result<(), NetError> {
    let tcp = socket.tcp.as_ref().ok_or(NetError::InvalidArgument)?;
    let (local_addr, local_port) = socket.local_addr().ok_or(NetError::InvalidArgument)?;
    let (remote_addr, remote_port) = socket.remote_addr().ok_or(NetError::InvalidArgument)?;

    let seq = tcp.snd_nxt();
    let ack = tcp.rcv_nxt();
    let window = tcp.rcv_wnd.load(Ordering::Acquire) as u16;

    let mut skb = SkBuff::alloc_tx(0).ok_or(NetError::OutOfMemory)?;

    build_tcp_header(
        &mut skb,
        local_port,
        remote_port,
        seq,
        ack,
        flags::FIN | flags::ACK,
        window,
        local_addr,
        remote_addr,
    )?;

    // FIN consumes one sequence number
    tcp.inc_snd_nxt(1);

    skb.saddr = Some(local_addr);
    skb.daddr = Some(remote_addr);

    ipv4::ip_queue_xmit(skb, IPPROTO_TCP)
}

/// Send a SYN-ACK segment in response to a SYN on a listening socket
///
/// Following Linux's tcp_v4_send_synack() -> tcp_make_synack():
/// This is sent from a listening socket to a client that sent a SYN.
/// The RequestSock contains the connection parameters from the SYN.
pub fn tcp_send_synack(listener: &Arc<Socket>, req: &RequestSock) -> Result<(), NetError> {
    let mut skb = SkBuff::alloc_tx(0).ok_or(NetError::OutOfMemory)?;

    // SYN-ACK: seq = our ISS, ack = client's ISN + 1
    let seq = req.iss;
    let ack = req.irs.wrapping_add(1);
    let window = req.rcv_wnd;

    build_tcp_header(
        &mut skb,
        req.local_port,
        req.remote_port,
        seq,
        ack,
        flags::SYN | flags::ACK,
        window,
        req.local_addr,
        req.remote_addr,
    )?;

    skb.saddr = Some(req.local_addr);
    skb.daddr = Some(req.remote_addr);

    // Suppress unused warning for listener - we may use it later for options
    let _ = listener;

    ipv4::ip_queue_xmit(skb, IPPROTO_TCP)
}

/// Send a RST segment
pub fn tcp_send_rst(
    local_addr: Ipv4Addr,
    local_port: u16,
    remote_addr: Ipv4Addr,
    remote_port: u16,
    seq: u32,
) -> Result<(), NetError> {
    let mut skb = SkBuff::alloc_tx(0).ok_or(NetError::OutOfMemory)?;

    build_tcp_header(
        &mut skb,
        local_port,
        remote_port,
        seq,
        0,
        flags::RST,
        0,
        local_addr,
        remote_addr,
    )?;

    skb.saddr = Some(local_addr);
    skb.daddr = Some(remote_addr);

    ipv4::ip_queue_xmit(skb, IPPROTO_TCP)
}

/// Build a TCP header
#[allow(clippy::too_many_arguments)]
fn build_tcp_header(
    skb: &mut SkBuff,
    source_port: u16,
    dest_port: u16,
    seq: u32,
    ack: u32,
    tcp_flags: u8,
    window: u16,
    saddr: Ipv4Addr,
    daddr: Ipv4Addr,
) -> Result<(), NetError> {
    let _payload_len = skb.len();

    // Push TCP header
    let hdr = skb.push(TCP_HLEN_MIN).ok_or(NetError::NoBufferSpace)?;

    // Source port
    hdr[0..2].copy_from_slice(&source_port.to_be_bytes());
    // Destination port
    hdr[2..4].copy_from_slice(&dest_port.to_be_bytes());
    // Sequence number
    hdr[4..8].copy_from_slice(&seq.to_be_bytes());
    // Acknowledgment number
    hdr[8..12].copy_from_slice(&ack.to_be_bytes());
    // Data offset (5 = 20 bytes) + reserved
    hdr[12] = 0x50;
    // Flags
    hdr[13] = tcp_flags;
    // Window
    hdr[14..16].copy_from_slice(&window.to_be_bytes());
    // Checksum (compute later)
    hdr[16] = 0;
    hdr[17] = 0;
    // Urgent pointer
    hdr[18] = 0;
    hdr[19] = 0;

    // Compute checksum over entire TCP segment (header + data)
    let checksum = tcp_checksum(saddr, daddr, skb.data());
    skb.data_mut()[16..18].copy_from_slice(&checksum.to_be_bytes());

    Ok(())
}
