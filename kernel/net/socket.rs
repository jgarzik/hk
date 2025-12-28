//! Socket Layer
//!
//! This module implements the socket abstraction for network I/O.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};

use spin::Mutex;

use crate::net::ipv4::Ipv4Addr;
use crate::net::request_sock::RequestSockQueue;
use crate::net::tcp::TcpSock;
use crate::waitqueue::WaitQueue;

/// Address family
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum AddressFamily {
    /// Unspecified
    Unspec = 0,
    /// Unix domain sockets
    Unix = 1,
    /// IPv4
    Inet = 2,
    /// IPv6
    Inet6 = 10,
}

impl AddressFamily {
    pub fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(AddressFamily::Unspec),
            1 => Some(AddressFamily::Unix),
            2 => Some(AddressFamily::Inet),
            10 => Some(AddressFamily::Inet6),
            _ => None,
        }
    }
}

/// Socket type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SocketType {
    /// Stream socket (TCP)
    Stream = 1,
    /// Datagram socket (UDP)
    Dgram = 2,
    /// Raw socket
    Raw = 3,
}

impl SocketType {
    pub fn from_i32(v: i32) -> Option<Self> {
        match v & 0xFF {
            1 => Some(SocketType::Stream),
            2 => Some(SocketType::Dgram),
            3 => Some(SocketType::Raw),
            _ => None,
        }
    }
}

/// Socket flags (from socket type parameter)
pub mod sock_flags {
    /// Non-blocking mode
    pub const SOCK_NONBLOCK: i32 = 0x800;
    /// Close on exec
    pub const SOCK_CLOEXEC: i32 = 0x80000;
}

/// sockaddr_in structure (IPv4)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockAddrIn {
    /// Address family (AF_INET)
    pub sin_family: u16,
    /// Port number (network byte order)
    pub sin_port: u16,
    /// IPv4 address (network byte order)
    pub sin_addr: u32,
    /// Padding
    pub sin_zero: [u8; 8],
}

impl SockAddrIn {
    pub fn new(addr: Ipv4Addr, port: u16) -> Self {
        Self {
            sin_family: AddressFamily::Inet as u16,
            sin_port: port.to_be(),
            sin_addr: addr.to_be(),
            sin_zero: [0; 8],
        }
    }

    pub fn addr(&self) -> Ipv4Addr {
        Ipv4Addr::from_be(self.sin_addr)
    }

    pub fn port(&self) -> u16 {
        u16::from_be(self.sin_port)
    }
}

/// Default receive buffer size
const DEFAULT_RCVBUF: usize = 65536;

/// Default send buffer size
const DEFAULT_SNDBUF: usize = 65536;

/// Default TCP keepalive idle time (seconds)
const DEFAULT_TCP_KEEPIDLE: u32 = 7200;
/// Default TCP keepalive interval (seconds)
const DEFAULT_TCP_KEEPINTVL: u32 = 75;
/// Default TCP keepalive count
const DEFAULT_TCP_KEEPCNT: u32 = 9;

/// SO_LINGER option structure
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Linger {
    /// Linger active (non-zero = enabled)
    pub l_onoff: i32,
    /// How long to linger for (seconds)
    pub l_linger: i32,
}

/// Socket options structure
///
/// Stores configurable socket options set via setsockopt().
pub struct SocketOptions {
    /// SO_REUSEADDR - allow local address reuse
    pub reuse_addr: AtomicBool,
    /// SO_KEEPALIVE - enable TCP keepalive
    pub keepalive: AtomicBool,
    /// SO_RCVBUF - receive buffer size
    pub recv_buf_size: AtomicU32,
    /// SO_SNDBUF - send buffer size
    pub send_buf_size: AtomicU32,
    /// TCP_NODELAY - disable Nagle's algorithm
    pub tcp_nodelay: AtomicBool,
    /// SO_BROADCAST - allow sending to broadcast addresses
    pub broadcast: AtomicBool,
    /// SO_DONTROUTE - bypass routing tables
    pub dontroute: AtomicBool,
    /// SO_LINGER - linger on close (packed: high 16 bits = l_onoff, low 16 = l_linger)
    pub linger: AtomicU32,
    /// TCP_KEEPIDLE - start keepalives after this period (seconds)
    pub tcp_keepidle: AtomicU32,
    /// TCP_KEEPINTVL - interval between keepalives (seconds)
    pub tcp_keepintvl: AtomicU32,
    /// TCP_KEEPCNT - number of keepalives before giving up
    pub tcp_keepcnt: AtomicU32,
}

impl SocketOptions {
    /// Create default socket options
    pub fn new() -> Self {
        Self {
            reuse_addr: AtomicBool::new(false),
            keepalive: AtomicBool::new(false),
            recv_buf_size: AtomicU32::new(DEFAULT_RCVBUF as u32),
            send_buf_size: AtomicU32::new(DEFAULT_SNDBUF as u32),
            tcp_nodelay: AtomicBool::new(false),
            broadcast: AtomicBool::new(false),
            dontroute: AtomicBool::new(false),
            linger: AtomicU32::new(0), // Linger disabled by default
            tcp_keepidle: AtomicU32::new(DEFAULT_TCP_KEEPIDLE),
            tcp_keepintvl: AtomicU32::new(DEFAULT_TCP_KEEPINTVL),
            tcp_keepcnt: AtomicU32::new(DEFAULT_TCP_KEEPCNT),
        }
    }
}

impl Default for SocketOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Socket structure
pub struct Socket {
    /// Address family
    pub family: AddressFamily,

    /// Socket type
    pub sock_type: SocketType,

    /// Protocol (0 = default for type)
    pub protocol: i32,

    /// Socket flags (O_NONBLOCK, etc.)
    pub flags: AtomicU32,

    /// Socket options (SO_REUSEADDR, etc.)
    pub options: SocketOptions,

    /// Local address
    pub(super) local_addr: Mutex<Option<(Ipv4Addr, u16)>>,

    /// Remote address (for connected sockets)
    pub(super) remote_addr: Mutex<Option<(Ipv4Addr, u16)>>,

    /// Receive buffer
    pub(super) rx_buffer: Mutex<VecDeque<u8>>,

    /// Receive buffer limit
    pub(super) rx_buffer_limit: usize,

    /// TCP control block (for SOCK_STREAM)
    pub tcp: Option<TcpSock>,

    /// Datagram receive queue (for SOCK_DGRAM)
    /// Each entry: (source_addr, source_port, data)
    pub(super) dgram_rx_queue: Mutex<VecDeque<(Ipv4Addr, u16, Vec<u8>)>>,

    /// Wait queue for readers
    pub(super) rx_wait: WaitQueue,

    /// Wait queue for writers
    pub(super) tx_wait: WaitQueue,

    /// Wait queue for connection events
    pub(super) connect_wait: WaitQueue,

    /// Error state
    pub(super) error: AtomicI32,

    /// EOF received
    pub(super) eof: AtomicBool,

    /// Accept queue for listening sockets (initialized by listen())
    /// None for non-listening sockets
    pub accept_queue: Mutex<Option<RequestSockQueue>>,

    /// Wait queue for accept() blocking - separate from accept_queue to avoid
    /// holding the Mutex while waiting (which would deadlock with tcp_rcv)
    pub accept_wait: WaitQueue,
}

impl Socket {
    /// Create a new socket
    pub fn new(family: AddressFamily, sock_type: SocketType, protocol: i32) -> Arc<Self> {
        let tcp = if sock_type == SocketType::Stream && family == AddressFamily::Inet {
            Some(TcpSock::new())
        } else {
            None
        };

        Arc::new(Self {
            family,
            sock_type,
            protocol,
            flags: AtomicU32::new(0),
            options: SocketOptions::new(),
            local_addr: Mutex::new(None),
            remote_addr: Mutex::new(None),
            rx_buffer: Mutex::new(VecDeque::with_capacity(DEFAULT_RCVBUF)),
            rx_buffer_limit: DEFAULT_RCVBUF,
            tcp,
            dgram_rx_queue: Mutex::new(VecDeque::new()),
            rx_wait: WaitQueue::new(),
            tx_wait: WaitQueue::new(),
            connect_wait: WaitQueue::new(),
            error: AtomicI32::new(0),
            eof: AtomicBool::new(false),
            accept_queue: Mutex::new(None),
            accept_wait: WaitQueue::new(),
        })
    }

    /// Get local address
    pub fn local_addr(&self) -> Option<(Ipv4Addr, u16)> {
        *self.local_addr.lock()
    }

    /// Get remote address
    pub fn remote_addr(&self) -> Option<(Ipv4Addr, u16)> {
        *self.remote_addr.lock()
    }

    /// Set local address
    pub fn set_local(&self, addr: Ipv4Addr, port: u16) {
        *self.local_addr.lock() = Some((addr, port));
    }

    /// Set remote address
    pub fn set_remote(&self, addr: Ipv4Addr, port: u16) {
        *self.remote_addr.lock() = Some((addr, port));
    }

    /// Check if socket is non-blocking
    pub fn is_nonblocking(&self) -> bool {
        self.flags.load(Ordering::Acquire) & crate::fs::file::flags::O_NONBLOCK != 0
    }

    /// Set non-blocking mode
    pub fn set_nonblocking(&self, enable: bool) {
        if enable {
            self.flags
                .fetch_or(crate::fs::file::flags::O_NONBLOCK, Ordering::Release);
        } else {
            self.flags
                .fetch_and(!crate::fs::file::flags::O_NONBLOCK, Ordering::Release);
        }
    }

    /// Get error state
    pub fn get_error(&self) -> i32 {
        self.error.swap(0, Ordering::AcqRel)
    }

    /// Set error state
    pub fn set_error(&self, err: i32) {
        self.error.store(err, Ordering::Release);
    }

    /// Check if EOF received
    pub fn is_eof(&self) -> bool {
        self.eof.load(Ordering::Acquire)
    }

    /// Set EOF flag
    pub fn set_eof(&self) {
        self.eof.store(true, Ordering::Release);
    }

    /// Read data from receive buffer
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, i32> {
        loop {
            // Check for error
            let err = self.error.load(Ordering::Acquire);
            if err != 0 {
                return Err(err);
            }

            // Try to read
            {
                let mut rx = self.rx_buffer.lock();
                if !rx.is_empty() {
                    let n = buf.len().min(rx.len());
                    for byte in buf[..n].iter_mut() {
                        *byte = rx.pop_front().unwrap();
                    }
                    return Ok(n);
                }
            }

            // Check for EOF
            if self.is_eof() {
                return Ok(0);
            }

            // Non-blocking?
            if self.is_nonblocking() {
                return Err(crate::error::KernelError::WouldBlock.to_errno_neg());
            }

            // Block
            self.rx_wait.wait();
        }
    }

    /// Check if data is available for reading
    pub fn poll_read(&self) -> bool {
        !self.rx_buffer.lock().is_empty()
            || self.is_eof()
            || self.error.load(Ordering::Acquire) != 0
    }

    /// Check if socket is writable
    pub fn poll_write(&self) -> bool {
        // For TCP, check if send window has space
        if let Some(ref tcp) = self.tcp {
            tcp.snd_wnd.load(Ordering::Acquire) > 0
        } else {
            true
        }
    }

    /// Deliver data to the receive buffer (called by TCP)
    pub fn deliver_data(&self, data: &[u8]) {
        let mut rx = self.rx_buffer.lock();
        for &byte in data {
            if rx.len() < self.rx_buffer_limit {
                rx.push_back(byte);
            }
        }
    }

    /// Deliver a datagram to the receive queue (called by UDP)
    pub fn deliver_datagram(&self, src_addr: Ipv4Addr, src_port: u16, data: &[u8]) {
        let mut queue = self.dgram_rx_queue.lock();
        // Limit queue depth (max 64 datagrams)
        if queue.len() < 64 {
            queue.push_back((src_addr, src_port, data.to_vec()));
        }
    }

    /// Read a datagram from the receive queue (for UDP)
    ///
    /// Returns (bytes_read, source_addr, source_port)
    pub fn read_datagram(&self, buf: &mut [u8]) -> Result<(usize, Ipv4Addr, u16), i32> {
        loop {
            // Check for error
            let err = self.error.load(Ordering::Acquire);
            if err != 0 {
                return Err(err);
            }

            // Try to read a datagram
            {
                let mut queue = self.dgram_rx_queue.lock();
                if let Some((src_addr, src_port, data)) = queue.pop_front() {
                    let n = buf.len().min(data.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    return Ok((n, src_addr, src_port));
                }
            }

            // Check for EOF
            if self.is_eof() {
                return Ok((0, Ipv4Addr::new(0, 0, 0, 0), 0));
            }

            // Non-blocking?
            if self.is_nonblocking() {
                return Err(crate::error::KernelError::WouldBlock.to_errno_neg());
            }

            // Block
            self.rx_wait.wait();
        }
    }

    /// Check if datagram is available for reading
    pub fn poll_read_dgram(&self) -> bool {
        !self.dgram_rx_queue.lock().is_empty()
            || self.is_eof()
            || self.error.load(Ordering::Acquire) != 0
    }

    /// Wake readers
    pub fn wake_rx(&self) {
        self.rx_wait.wake_all();
    }

    /// Wake writers
    pub fn wake_tx(&self) {
        self.tx_wait.wake_all();
    }

    /// Wake connect waiters
    pub fn wake_connect(&self) {
        self.connect_wait.wake_all();
    }

    /// Wake all waiters
    pub fn wake_all(&self) {
        self.rx_wait.wake_all();
        self.tx_wait.wake_all();
        self.connect_wait.wake_all();
    }

    /// Get RX wait queue
    pub fn rx_wait(&self) -> &WaitQueue {
        &self.rx_wait
    }

    /// Get TX wait queue
    pub fn tx_wait(&self) -> &WaitQueue {
        &self.tx_wait
    }

    /// Get connect wait queue
    pub fn connect_wait(&self) -> &WaitQueue {
        &self.connect_wait
    }

    /// Initialize accept queue for a listening socket
    ///
    /// Called by listen() to set up the accept queue with the given backlog.
    pub fn init_accept_queue(&self, backlog: u32) {
        let mut queue = self.accept_queue.lock();
        if queue.is_none() {
            *queue = Some(RequestSockQueue::new(backlog));
        }
    }

    /// Check if this socket has an accept queue (is listening)
    pub fn has_accept_queue(&self) -> bool {
        self.accept_queue.lock().is_some()
    }

    /// Wait for a connection to be available in accept queue
    ///
    /// Uses the direct accept_wait WaitQueue field to avoid holding
    /// the accept_queue Mutex while blocking (which would deadlock with tcp_rcv).
    pub fn accept_wait_block(&self) {
        self.accept_wait.wait();
    }

    /// Wake up processes waiting on accept()
    pub fn accept_wake(&self) {
        self.accept_wait.wake_one();
    }
}
