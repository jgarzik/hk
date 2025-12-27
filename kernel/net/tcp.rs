//! TCP Protocol Implementation
//!
//! This module implements the TCP state machine and connection management.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};

use spin::Mutex;

use crate::net::KernelError;
use crate::net::ipv4::{self, IPPROTO_TCP, Ipv4Addr};
use crate::net::socket::Socket;

// Re-export submodules
pub use crate::net::tcp_input::tcp_rcv;
pub use crate::net::tcp_output::tcp_sendmsg;

/// TCP header length (without options)
pub const TCP_HLEN_MIN: usize = 20;

/// TCP header maximum length (with options)
pub const TCP_HLEN_MAX: usize = 60;

/// TCP flags
pub mod flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    pub const ECE: u8 = 0x40;
    pub const CWR: u8 = 0x80;
}

/// TCP states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TcpState {
    Closed = 0,
    Listen = 1,
    SynSent = 2,
    SynReceived = 3,
    Established = 4,
    FinWait1 = 5,
    FinWait2 = 6,
    CloseWait = 7,
    Closing = 8,
    LastAck = 9,
    TimeWait = 10,
}

impl TcpState {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => TcpState::Closed,
            1 => TcpState::Listen,
            2 => TcpState::SynSent,
            3 => TcpState::SynReceived,
            4 => TcpState::Established,
            5 => TcpState::FinWait1,
            6 => TcpState::FinWait2,
            7 => TcpState::CloseWait,
            8 => TcpState::Closing,
            9 => TcpState::LastAck,
            10 => TcpState::TimeWait,
            _ => TcpState::Closed,
        }
    }

    /// Check if connection is established or later
    pub fn is_connected(self) -> bool {
        matches!(
            self,
            TcpState::Established
                | TcpState::FinWait1
                | TcpState::FinWait2
                | TcpState::CloseWait
                | TcpState::Closing
                | TcpState::LastAck
        )
    }
}

/// TCP header structure
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TcpHdr {
    /// Source port (big-endian)
    pub source: [u8; 2],
    /// Destination port (big-endian)
    pub dest: [u8; 2],
    /// Sequence number (big-endian)
    pub seq: [u8; 4],
    /// Acknowledgment number (big-endian)
    pub ack_seq: [u8; 4],
    /// Data offset (4 bits) + reserved (4 bits)
    pub doff_reserved: u8,
    /// Flags
    pub flags: u8,
    /// Window size (big-endian)
    pub window: [u8; 2],
    /// Checksum (big-endian)
    pub check: [u8; 2],
    /// Urgent pointer (big-endian)
    pub urg_ptr: [u8; 2],
}

impl TcpHdr {
    pub fn source_port(&self) -> u16 {
        u16::from_be_bytes(self.source)
    }

    pub fn dest_port(&self) -> u16 {
        u16::from_be_bytes(self.dest)
    }

    pub fn seq(&self) -> u32 {
        u32::from_be_bytes(self.seq)
    }

    pub fn ack_seq(&self) -> u32 {
        u32::from_be_bytes(self.ack_seq)
    }

    pub fn data_offset(&self) -> usize {
        ((self.doff_reserved >> 4) as usize) * 4
    }

    pub fn window(&self) -> u16 {
        u16::from_be_bytes(self.window)
    }

    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.check)
    }

    pub fn has_flag(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
}

/// TCP connection four-tuple
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TcpFourTuple {
    pub local_addr: Ipv4Addr,
    pub local_port: u16,
    pub remote_addr: Ipv4Addr,
    pub remote_port: u16,
}

/// TCP socket control block
pub struct TcpSock {
    /// TCP state
    state: AtomicU8,

    /// Send sequence variables
    /// Initial send sequence number
    pub iss: u32,
    /// Send unacknowledged
    pub snd_una: AtomicU32,
    /// Send next
    pub snd_nxt: AtomicU32,
    /// Send window
    pub snd_wnd: AtomicU32,

    /// Receive sequence variables
    /// Initial receive sequence number
    pub irs: AtomicU32,
    /// Receive next (expected)
    pub rcv_nxt: AtomicU32,
    /// Receive window
    pub rcv_wnd: AtomicU32,

    /// Maximum segment size
    pub mss: u16,

    /// Retransmit timeout (in ms)
    pub rto: u32,

    /// Retransmit queue
    pub retransmit_queue: Mutex<Vec<TcpSegment>>,

    /// Out-of-order receive queue
    pub ooo_queue: Mutex<BTreeMap<u32, Vec<u8>>>,
}

/// Segment in retransmit queue
pub struct TcpSegment {
    /// Sequence number
    pub seq: u32,
    /// Segment data (includes TCP header)
    pub data: Vec<u8>,
    /// Timestamp when sent
    pub sent_at: u64,
    /// Retransmit count
    pub retries: u8,
}

impl TcpSock {
    /// Create a new TCP socket control block
    pub fn new() -> Self {
        // Generate initial sequence number from random
        let iss = crate::random::get_random_u32();

        Self {
            state: AtomicU8::new(TcpState::Closed as u8),
            iss,
            snd_una: AtomicU32::new(iss),
            snd_nxt: AtomicU32::new(iss),
            snd_wnd: AtomicU32::new(0),
            irs: AtomicU32::new(0),
            rcv_nxt: AtomicU32::new(0),
            rcv_wnd: AtomicU32::new(65535),
            mss: 1460,
            rto: 1000, // 1 second initial RTO
            retransmit_queue: Mutex::new(Vec::new()),
            ooo_queue: Mutex::new(BTreeMap::new()),
        }
    }

    /// Get current state
    pub fn state(&self) -> TcpState {
        TcpState::from_u8(self.state.load(Ordering::Acquire))
    }

    /// Set state
    pub fn set_state(&self, state: TcpState) {
        self.state.store(state as u8, Ordering::Release);
    }

    /// Get send next
    pub fn snd_nxt(&self) -> u32 {
        self.snd_nxt.load(Ordering::Acquire)
    }

    /// Increment send next
    pub fn inc_snd_nxt(&self, n: u32) {
        self.snd_nxt.fetch_add(n, Ordering::AcqRel);
    }

    /// Get receive next
    pub fn rcv_nxt(&self) -> u32 {
        self.rcv_nxt.load(Ordering::Acquire)
    }

    /// Set receive next
    pub fn set_rcv_nxt(&self, v: u32) {
        self.rcv_nxt.store(v, Ordering::Release);
    }
}

impl Default for TcpSock {
    fn default() -> Self {
        Self::new()
    }
}

/// Register a connection in the current namespace's table
pub fn tcp_register_connection(tuple: TcpFourTuple, socket: Arc<Socket>) {
    crate::net::current_net_ns().tcp_register(tuple, socket);
}

/// Remove a connection from the current namespace's table
pub fn tcp_unregister_connection(tuple: &TcpFourTuple) {
    crate::net::current_net_ns().tcp_unregister(tuple);
}

/// Look up a connection in the current namespace
pub fn tcp_lookup_connection(tuple: &TcpFourTuple) -> Option<Arc<Socket>> {
    crate::net::current_net_ns().tcp_lookup(tuple)
}

/// Allocate an ephemeral port in the current namespace
pub fn tcp_alloc_port() -> u16 {
    crate::net::current_net_ns().alloc_port()
}

/// Look up a listening socket by port in the current namespace
pub fn tcp_lookup_listener(local_port: u16) -> Option<Arc<Socket>> {
    crate::net::current_net_ns().tcp_lookup_listener(local_port)
}

/// Initiate a TCP connection (active open)
pub fn tcp_connect(
    socket: &Arc<Socket>,
    remote_addr: Ipv4Addr,
    remote_port: u16,
) -> Result<(), KernelError> {
    let tcp = socket.tcp.as_ref().ok_or(KernelError::InvalidArgument)?;
    let config = crate::net::get_config().ok_or(KernelError::InvalidArgument)?;

    // Allocate local port
    let local_port = tcp_alloc_port();

    // For loopback destinations, use loopback as local address
    let local_addr = if remote_addr.is_loopback() {
        remote_addr // Use same loopback address
    } else {
        config.ipv4_addr
    };

    // Set socket addresses
    socket.set_local(local_addr, local_port);
    socket.set_remote(remote_addr, remote_port);

    // Create connection tuple
    let tuple = TcpFourTuple {
        local_addr,
        local_port,
        remote_addr,
        remote_port,
    };

    // Register in connection table
    tcp_register_connection(tuple, Arc::clone(socket));

    // Set state to SYN-SENT
    tcp.set_state(TcpState::SynSent);

    // Send SYN
    crate::net::tcp_output::tcp_send_syn(socket)?;

    Ok(())
}

/// Close a TCP connection
pub fn tcp_close(socket: &Arc<Socket>) -> Result<(), KernelError> {
    let tcp = socket.tcp.as_ref().ok_or(KernelError::InvalidArgument)?;

    match tcp.state() {
        TcpState::Closed | TcpState::Listen => {
            tcp.set_state(TcpState::Closed);
        }
        TcpState::SynSent => {
            tcp.set_state(TcpState::Closed);
        }
        TcpState::SynReceived | TcpState::Established => {
            // Send FIN
            tcp.set_state(TcpState::FinWait1);
            crate::net::tcp_output::tcp_send_fin(socket)?;
        }
        TcpState::CloseWait => {
            // Send FIN
            tcp.set_state(TcpState::LastAck);
            crate::net::tcp_output::tcp_send_fin(socket)?;
        }
        _ => {
            // Already closing
        }
    }

    Ok(())
}

/// Compute TCP checksum
pub fn tcp_checksum(saddr: Ipv4Addr, daddr: Ipv4Addr, tcp_data: &[u8]) -> u16 {
    let len = tcp_data.len() as u16;

    // Start with pseudo-header
    let mut sum = ipv4::pseudo_header_checksum(saddr, daddr, IPPROTO_TCP, len);

    // Add TCP header and data
    let mut i = 0;
    while i + 1 < tcp_data.len() {
        sum += u16::from_be_bytes([tcp_data[i], tcp_data[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_data.len() {
        sum += (tcp_data[i] as u32) << 8;
    }

    // Fold and complement
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}
