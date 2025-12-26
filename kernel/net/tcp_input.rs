//! TCP Input Processing
//!
//! This module handles incoming TCP segments.
//!
//! Following Linux's tcp_v4_rcv() -> tcp_v4_do_rcv() flow:
//! 1. Look up connection in established hash
//! 2. If not found, check listener hash for SYN
//! 3. Process based on connection state

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::net::ipv4::Ipv4Addr;
use crate::net::request_sock::RequestSock;
use crate::net::skb::SkBuff;
use crate::net::socket::{AddressFamily, Socket, SocketType};
use crate::net::tcp::{
    TCP_HLEN_MIN, TcpFourTuple, TcpHdr, TcpState, flags, tcp_checksum, tcp_lookup_connection,
    tcp_lookup_listener, tcp_register_connection,
};

/// Receive a TCP segment
///
/// Called by IP layer after demultiplexing.
/// Following Linux's tcp_v4_rcv() flow.
pub fn tcp_rcv(skb: SkBuff) {
    if skb.len() < TCP_HLEN_MIN {
        return;
    }

    // Get IP addresses from skb
    let saddr = match skb.saddr {
        Some(a) => a,
        None => return,
    };
    let daddr = match skb.daddr {
        Some(a) => a,
        None => return,
    };

    // Parse TCP header
    let hdr = unsafe { &*(skb.data().as_ptr() as *const TcpHdr) };
    let data_offset = hdr.data_offset();

    if data_offset < TCP_HLEN_MIN || data_offset > skb.len() {
        return;
    }

    // Verify checksum
    let checksum = tcp_checksum(saddr, daddr, skb.data());
    if checksum != 0 {
        return;
    }

    // Build four-tuple for lookup
    let tuple = TcpFourTuple {
        local_addr: daddr,
        local_port: hdr.dest_port(),
        remote_addr: saddr,
        remote_port: hdr.source_port(),
    };

    // First, try to find an established connection (like __inet_lookup_established)
    if let Some(socket) = tcp_lookup_connection(&tuple) {
        let tcp = match socket.tcp.as_ref() {
            Some(t) => t,
            None => return,
        };

        // Get payload
        let payload = &skb.data()[data_offset..];

        // Process based on state
        match tcp.state() {
            TcpState::SynSent => {
                process_syn_sent(&socket, hdr, payload);
            }
            TcpState::Established => {
                process_established(&socket, hdr, payload, saddr);
            }
            TcpState::FinWait1 => {
                process_fin_wait1(&socket, hdr, payload);
            }
            TcpState::FinWait2 => {
                process_fin_wait2(&socket, hdr, payload);
            }
            TcpState::CloseWait => {
                process_close_wait(&socket, hdr);
            }
            TcpState::LastAck => {
                process_last_ack(&socket, hdr);
            }
            TcpState::TimeWait => {
                // In TIME_WAIT, just ACK and restart timer
                if hdr.has_flag(flags::FIN) {
                    // Re-ACK the FIN
                }
            }
            _ => {}
        }
        return;
    }

    // No established connection - check for listening socket (like __inet_lookup_listener)
    if let Some(listener) = tcp_lookup_listener(hdr.dest_port()) {
        let tcp = match listener.tcp.as_ref() {
            Some(t) => t,
            None => return,
        };

        if tcp.state() != TcpState::Listen {
            return;
        }

        // Handle packet to listening socket
        process_listen(&listener, hdr, saddr, daddr);
        return;
    }

    // No connection and no listener - send RST if not RST
    if !hdr.has_flag(flags::RST) {
        // TODO: send RST for closed port
    }
}

/// Process packet to a listening socket
///
/// Following Linux's tcp_v4_conn_request() -> tcp_conn_request():
/// - SYN: Create request_sock, send SYN-ACK, add to SYN queue
/// - ACK: Complete 3WHS, create child socket, add to accept queue
fn process_listen(
    listener: &Arc<Socket>,
    hdr: &TcpHdr,
    remote_addr: Ipv4Addr,
    local_addr: Ipv4Addr,
) {
    // Get accept queue
    let accept_queue_guard = listener.accept_queue.lock();
    let accept_queue = match accept_queue_guard.as_ref() {
        Some(q) => q,
        None => return,
    };

    // Pure SYN (no ACK) - new connection request
    if hdr.has_flag(flags::SYN) && !hdr.has_flag(flags::ACK) {
        // Check if queue is full
        if accept_queue.syn_queue_is_full() {
            return; // Drop SYN
        }

        let local_port = hdr.dest_port();
        let remote_port = hdr.source_port();

        // Create request_sock (like tcp_conn_request -> reqsk_alloc)
        let req = RequestSock::new(
            remote_addr,
            remote_port,
            local_addr,
            local_port,
            hdr.seq(),    // IRS from client
            hdr.window(), // Client's receive window
        );

        // Add to SYN queue BEFORE sending SYN-ACK
        // This way, when the ACK arrives, it will find the req in the queue
        accept_queue.syn_queue_add(req.clone());

        // Drop the lock BEFORE sending SYN-ACK
        // The SYN-ACK will trigger a synchronous loopback delivery of the client's ACK,
        // which needs to acquire this lock in process_listen
        drop(accept_queue_guard);

        // Send SYN-ACK (like tcp_v4_send_synack)
        if crate::net::tcp_output::tcp_send_synack(listener, &req).is_err() {
            // Remove from SYN queue on failure
            let guard = listener.accept_queue.lock();
            if let Some(q) = guard.as_ref() {
                let _ = q.syn_queue_remove(remote_addr, remote_port);
            }
            return;
        }

        return;
    }

    // ACK (possibly completing 3WHS)
    if hdr.has_flag(flags::ACK) && !hdr.has_flag(flags::SYN) {
        let remote_port = hdr.source_port();

        // Look up pending request in SYN queue
        // Check if this ACK matches a pending request
        if let Some((_irs, iss)) = accept_queue.syn_queue_lookup(remote_addr, remote_port) {
            // Verify ACK number: should ACK our SYN-ACK (iss + 1)
            if hdr.ack_seq() != iss.wrapping_add(1) {
                // Bad ACK
                return;
            }

            // Remove from SYN queue
            if let Some(req) = accept_queue.syn_queue_remove(remote_addr, remote_port) {
                // Drop the lock before creating the child socket
                drop(accept_queue_guard);

                // Complete 3WHS - create child socket (like tcp_v4_syn_recv_sock)
                if let Some(child) = create_child_socket(listener, &req, hdr) {
                    // Add to accept queue
                    {
                        let accept_queue_guard = listener.accept_queue.lock();
                        if let Some(q) = accept_queue_guard.as_ref() {
                            q.accept_queue_add(child);
                        }
                    }
                    // Wake up accept() waiters on the Socket's WaitQueue
                    listener.accept_wake();
                }
            }
        }
    }

    // RST handling for connections in SYN_RECV state would go here
}

/// Create a child socket when 3-way handshake completes
///
/// Following Linux's tcp_v4_syn_recv_sock():
/// - Clone listener socket
/// - Set up TCP state for established connection
/// - Register in connection table
fn create_child_socket(
    _listener: &Arc<Socket>,
    req: &RequestSock,
    hdr: &TcpHdr,
) -> Option<Arc<Socket>> {
    // Create new socket (like inet_csk_clone_lock)
    let child = Socket::new(AddressFamily::Inet, SocketType::Stream, 0);

    // Set addresses
    child.set_local(req.local_addr, req.local_port);
    child.set_remote(req.remote_addr, req.remote_port);

    // Initialize TCP state for established connection
    let tcp = child.tcp.as_ref()?;

    // Set sequence numbers
    // Our ISS was req.iss, SYN-ACK consumed 1, so snd_una = snd_nxt = iss + 1
    tcp.snd_una
        .store(req.iss.wrapping_add(1), Ordering::Release);
    tcp.snd_nxt
        .store(req.iss.wrapping_add(1), Ordering::Release);

    // Their ISN was req.irs, SYN consumed 1, and we're now expecting seq after their ACK
    tcp.irs.store(req.irs, Ordering::Release);
    tcp.set_rcv_nxt(req.irs.wrapping_add(1));

    // Set window
    tcp.snd_wnd.store(hdr.window() as u32, Ordering::Release);
    tcp.rcv_wnd.store(65535, Ordering::Release);

    // Set state to established
    tcp.set_state(TcpState::Established);

    // Register in connection table
    let tuple = TcpFourTuple {
        local_addr: req.local_addr,
        local_port: req.local_port,
        remote_addr: req.remote_addr,
        remote_port: req.remote_port,
    };
    tcp_register_connection(tuple, Arc::clone(&child));

    Some(child)
}

/// Process segment in SYN-SENT state
fn process_syn_sent(socket: &Arc<Socket>, hdr: &TcpHdr, _payload: &[u8]) {
    let tcp = socket.tcp.as_ref().unwrap();

    // Expecting SYN-ACK
    if hdr.has_flag(flags::ACK) {
        // Check ACK validity
        let ack = hdr.ack_seq();
        let snd_nxt = tcp.snd_nxt();
        if ack != snd_nxt {
            // Invalid ACK
            if hdr.has_flag(flags::RST) {
                return;
            }
            // TODO: send RST
            return;
        }

        if hdr.has_flag(flags::RST) {
            // Connection refused
            tcp.set_state(TcpState::Closed);
            socket.set_error(-crate::net::libc::ECONNREFUSED);
            socket.wake_connect();
            return;
        }

        if hdr.has_flag(flags::SYN) {
            // SYN-ACK received - connection established
            tcp.irs
                .store(hdr.seq(), core::sync::atomic::Ordering::Release);
            tcp.set_rcv_nxt(hdr.seq().wrapping_add(1));
            tcp.snd_una
                .store(ack, core::sync::atomic::Ordering::Release);
            tcp.snd_wnd
                .store(hdr.window() as u32, core::sync::atomic::Ordering::Release);

            tcp.set_state(TcpState::Established);

            // Send ACK
            let _ = crate::net::tcp_output::tcp_send_ack(socket);

            // Wake up connect() caller
            socket.wake_connect();
        }
    }
}

/// Process segment in ESTABLISHED state
fn process_established(socket: &Arc<Socket>, hdr: &TcpHdr, payload: &[u8], _saddr: Ipv4Addr) {
    let tcp = socket.tcp.as_ref().unwrap();

    // Check RST
    if hdr.has_flag(flags::RST) {
        tcp.set_state(TcpState::Closed);
        socket.set_error(-crate::net::libc::ECONNRESET);
        socket.wake_all();
        return;
    }

    // Process ACK
    if hdr.has_flag(flags::ACK) {
        let ack = hdr.ack_seq();
        let snd_una = tcp.snd_una.load(core::sync::atomic::Ordering::Acquire);
        let snd_nxt = tcp.snd_nxt();

        // Valid ACK: snd_una < ack <= snd_nxt
        if ack.wrapping_sub(snd_una) <= snd_nxt.wrapping_sub(snd_una) {
            tcp.snd_una
                .store(ack, core::sync::atomic::Ordering::Release);

            // Remove acknowledged segments from retransmit queue
            let mut rtx_queue = tcp.retransmit_queue.lock();
            rtx_queue.retain(|seg| seg.seq.wrapping_add(seg.data.len() as u32) > ack);

            // Update send window
            tcp.snd_wnd
                .store(hdr.window() as u32, core::sync::atomic::Ordering::Release);

            // Wake writers if space available
            socket.wake_tx();
        }
    }

    // Process data
    if !payload.is_empty() {
        let seq = hdr.seq();
        let rcv_nxt = tcp.rcv_nxt();

        if seq == rcv_nxt {
            // In-order data
            socket.deliver_data(payload);
            tcp.set_rcv_nxt(rcv_nxt.wrapping_add(payload.len() as u32));

            // Check for out-of-order data that's now in order
            // TODO: process OOO queue

            // Send ACK
            let _ = crate::net::tcp_output::tcp_send_ack(socket);

            // Wake readers
            socket.wake_rx();
        } else if seq.wrapping_sub(rcv_nxt) < 0x80000000 {
            // Future data - queue for later
            let mut ooo = tcp.ooo_queue.lock();
            ooo.insert(seq, payload.to_vec());

            // Send duplicate ACK
            let _ = crate::net::tcp_output::tcp_send_ack(socket);
        }
        // Else: old data, ignore
    }

    // Process FIN
    if hdr.has_flag(flags::FIN) {
        let rcv_nxt = tcp.rcv_nxt();
        tcp.set_rcv_nxt(rcv_nxt.wrapping_add(1));

        tcp.set_state(TcpState::CloseWait);

        // Send ACK for FIN
        let _ = crate::net::tcp_output::tcp_send_ack(socket);

        // Signal EOF to readers
        socket.set_eof();
        socket.wake_rx();
    }
}

/// Process segment in FIN-WAIT-1 state
fn process_fin_wait1(socket: &Arc<Socket>, hdr: &TcpHdr, _payload: &[u8]) {
    let tcp = socket.tcp.as_ref().unwrap();

    // Check RST
    if hdr.has_flag(flags::RST) {
        tcp.set_state(TcpState::Closed);
        socket.wake_all();
        return;
    }

    // Process ACK of our FIN
    if hdr.has_flag(flags::ACK) {
        let ack = hdr.ack_seq();
        let snd_nxt = tcp.snd_nxt();

        if ack == snd_nxt {
            // Our FIN was ACKed
            tcp.set_state(TcpState::FinWait2);
        }
    }

    // Process their FIN
    if hdr.has_flag(flags::FIN) {
        let rcv_nxt = tcp.rcv_nxt();
        tcp.set_rcv_nxt(rcv_nxt.wrapping_add(1));

        if tcp.state() == TcpState::FinWait2 {
            tcp.set_state(TcpState::TimeWait);
        } else {
            tcp.set_state(TcpState::Closing);
        }

        // Send ACK for FIN
        let _ = crate::net::tcp_output::tcp_send_ack(socket);
        socket.set_eof();
        socket.wake_rx();
    }
}

/// Process segment in FIN-WAIT-2 state
fn process_fin_wait2(socket: &Arc<Socket>, hdr: &TcpHdr, _payload: &[u8]) {
    let tcp = socket.tcp.as_ref().unwrap();

    // Process FIN
    if hdr.has_flag(flags::FIN) {
        let rcv_nxt = tcp.rcv_nxt();
        tcp.set_rcv_nxt(rcv_nxt.wrapping_add(1));

        tcp.set_state(TcpState::TimeWait);

        // Send ACK for FIN
        let _ = crate::net::tcp_output::tcp_send_ack(socket);
        socket.set_eof();
        socket.wake_all();
    }
}

/// Process segment in CLOSE-WAIT state
fn process_close_wait(socket: &Arc<Socket>, hdr: &TcpHdr) {
    let tcp = socket.tcp.as_ref().unwrap();

    if hdr.has_flag(flags::RST) {
        tcp.set_state(TcpState::Closed);
        socket.wake_all();
    }
}

/// Process segment in LAST-ACK state
fn process_last_ack(socket: &Arc<Socket>, hdr: &TcpHdr) {
    let tcp = socket.tcp.as_ref().unwrap();

    if hdr.has_flag(flags::ACK) {
        // Our FIN was ACKed
        tcp.set_state(TcpState::Closed);
        socket.wake_all();
    }
}
