//! Request Socket Infrastructure
//!
//! This module implements request sockets (mini-sockets) for TCP connection
//! establishment, following Linux's request_sock design from
//! include/net/request_sock.h.
//!
//! During the 3-way handshake, before a full socket is created:
//! 1. Client sends SYN
//! 2. Server creates a RequestSock and sends SYN-ACK
//! 3. Client sends ACK
//! 4. Server creates full child socket and moves it to accept queue
//!
//! This avoids allocating full socket resources until the handshake completes,
//! providing protection against SYN flood attacks.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use spin::Mutex;

use crate::net::ipv4::Ipv4Addr;
use crate::net::socket::Socket;
use crate::waitqueue::WaitQueue;

/// Mini-socket representing a connection request in SYN_RECV state.
///
/// This is a lightweight structure that holds just enough information
/// to complete the 3-way handshake without allocating a full Socket.
/// Follows Linux's struct request_sock from include/net/request_sock.h.
#[derive(Clone)]
pub struct RequestSock {
    /// Remote (client) address from SYN
    pub remote_addr: Ipv4Addr,
    /// Remote (client) port from SYN
    pub remote_port: u16,
    /// Local (server) address
    pub local_addr: Ipv4Addr,
    /// Local (server) port
    pub local_port: u16,

    /// Initial receive sequence number (from client's SYN)
    pub irs: u32,
    /// Initial send sequence number (for our SYN-ACK)
    pub iss: u32,

    /// Maximum segment size (from SYN options, or default)
    pub mss: u16,
    /// Receive window advertised in SYN
    pub rcv_wnd: u16,

    /// Timestamp when SYN-ACK was sent (for retransmit timing)
    pub synack_sent_at: u64,
    /// Number of SYN-ACK retransmissions
    pub num_retrans: u8,
}

impl RequestSock {
    /// Create a new request socket from an incoming SYN
    pub fn new(
        remote_addr: Ipv4Addr,
        remote_port: u16,
        local_addr: Ipv4Addr,
        local_port: u16,
        irs: u32,
        rcv_wnd: u16,
    ) -> Self {
        // Generate ISS from random
        let iss = crate::random::get_random_u32();

        Self {
            remote_addr,
            remote_port,
            local_addr,
            local_port,
            irs,
            iss,
            mss: 1460, // Default MSS for Ethernet
            rcv_wnd,
            synack_sent_at: 0,
            num_retrans: 0,
        }
    }

    /// Check if an ACK matches this request (completes 3WHS)
    ///
    /// The ACK number should be iss + 1 (acknowledging our SYN-ACK)
    pub fn matches_ack(&self, ack_num: u32) -> bool {
        ack_num == self.iss.wrapping_add(1)
    }
}

/// Queue of request sockets for a listening socket.
///
/// Follows Linux's struct request_sock_queue from include/net/request_sock.h.
/// Contains two logical queues:
/// 1. SYN queue: RequestSock entries in SYN_RECV state (incomplete connections)
/// 2. Accept queue: Completed child sockets ready for accept()
pub struct RequestSockQueue {
    /// Queue of pending connections in SYN_RECV state
    /// Key: (remote_addr, remote_port) for lookup on ACK
    syn_queue: Mutex<VecDeque<RequestSock>>,
    /// Length of SYN queue (atomic for fast check)
    syn_queue_len: AtomicU32,

    /// Queue of completed connections (child sockets ready for accept)
    accept_queue: Mutex<VecDeque<Arc<Socket>>>,
    /// Length of accept queue (atomic for fast check)
    accept_queue_len: AtomicU32,

    /// Maximum backlog (from listen() call)
    max_backlog: AtomicU32,

    /// Wait queue for accept() blocking
    accept_wait: WaitQueue,
}

impl RequestSockQueue {
    /// Create a new request socket queue
    pub fn new(backlog: u32) -> Self {
        Self {
            syn_queue: Mutex::new(VecDeque::new()),
            syn_queue_len: AtomicU32::new(0),
            accept_queue: Mutex::new(VecDeque::new()),
            accept_queue_len: AtomicU32::new(0),
            max_backlog: AtomicU32::new(backlog.max(1)),
            accept_wait: WaitQueue::new(),
        }
    }

    /// Check if the SYN queue is full
    pub fn syn_queue_is_full(&self) -> bool {
        self.syn_queue_len.load(Ordering::Acquire) >= self.max_backlog.load(Ordering::Acquire)
    }

    /// Check if the accept queue is full
    pub fn accept_queue_is_full(&self) -> bool {
        self.accept_queue_len.load(Ordering::Acquire) >= self.max_backlog.load(Ordering::Acquire)
    }

    /// Check if the accept queue is empty
    pub fn accept_queue_is_empty(&self) -> bool {
        self.accept_queue_len.load(Ordering::Acquire) == 0
    }

    /// Add a request socket to the SYN queue (on receiving SYN)
    pub fn syn_queue_add(&self, req: RequestSock) {
        let mut queue = self.syn_queue.lock();
        queue.push_back(req);
        self.syn_queue_len.fetch_add(1, Ordering::Release);
    }

    /// Look up and remove a request socket by remote address/port
    /// Called when receiving ACK to complete 3WHS
    pub fn syn_queue_remove(&self, remote_addr: Ipv4Addr, remote_port: u16) -> Option<RequestSock> {
        let mut queue = self.syn_queue.lock();

        // Find matching request
        let pos = queue
            .iter()
            .position(|req| req.remote_addr == remote_addr && req.remote_port == remote_port)?;

        let req = queue.remove(pos)?;
        self.syn_queue_len.fetch_sub(1, Ordering::Release);
        Some(req)
    }

    /// Look up a request socket without removing it
    pub fn syn_queue_lookup(&self, remote_addr: Ipv4Addr, remote_port: u16) -> Option<(u32, u32)> {
        let queue = self.syn_queue.lock();

        queue
            .iter()
            .find(|req| req.remote_addr == remote_addr && req.remote_port == remote_port)
            .map(|req| (req.irs, req.iss))
    }

    /// Add a completed connection to the accept queue
    /// Called after 3WHS completes and child socket is created
    pub fn accept_queue_add(&self, socket: Arc<Socket>) {
        let mut queue = self.accept_queue.lock();
        queue.push_back(socket);
        self.accept_queue_len.fetch_add(1, Ordering::Release);

        // Wake up any waiting accept() calls
        self.accept_wait.wake_one();
    }

    /// Remove and return the next completed connection from accept queue
    /// Called by accept() syscall
    pub fn accept_queue_remove(&self) -> Option<Arc<Socket>> {
        let mut queue = self.accept_queue.lock();
        let socket = queue.pop_front()?;
        self.accept_queue_len.fetch_sub(1, Ordering::Release);
        Some(socket)
    }

    /// Wait for a connection to be available in accept queue
    pub fn wait(&self) {
        self.accept_wait.wait();
    }

    /// Get current SYN queue length
    pub fn syn_queue_len(&self) -> u32 {
        self.syn_queue_len.load(Ordering::Acquire)
    }

    /// Get current accept queue length
    pub fn accept_queue_len(&self) -> u32 {
        self.accept_queue_len.load(Ordering::Acquire)
    }
}
