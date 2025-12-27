//! Socket System Call Handlers
//!
//! This module implements the socket-related system calls for the network stack.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::sync::Weak;

use crate::error::KernelError;
use crate::fs::dentry::Dentry;
use crate::fs::file::{File, FileOps, flags as file_flags};
use crate::fs::inode::{Inode, InodeMode, NULL_INODE_OPS, Timespec};
use crate::net::ipv4::Ipv4Addr;
use crate::net::socket::{AddressFamily, SockAddrIn, Socket, SocketType, sock_flags};
use crate::net::socket_file::SocketFileOps;
use crate::net::tcp::{self, TcpState};
use crate::net::udp;
use crate::task::fdtable::get_task_fd;
use crate::task::percpu::current_tid;
use crate::uaccess::get_user;

// Architecture-specific uaccess implementation
#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::uaccess::Aarch64Uaccess as Uaccess;
#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::uaccess::X86_64Uaccess as Uaccess;

/// Get RLIMIT_NOFILE limit for fd allocation
#[inline]
fn get_nofile_limit() -> u64 {
    let limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_NOFILE);
    if limit == crate::rlimit::RLIM_INFINITY {
        u64::MAX
    } else {
        limit
    }
}

/// Create a dummy dentry for sockets
///
/// Sockets don't have a real filesystem entry, but our File struct
/// requires a dentry. This creates a minimal anonymous dentry.
fn create_socket_dentry() -> Result<Arc<Dentry>, i64> {
    // Create anonymous inode for socket
    let mode = InodeMode::socket(0o600);
    let inode = Arc::new(Inode::new(
        0, // ino=0 for anonymous
        mode,
        0,                      // uid (root)
        0,                      // gid (root)
        0,                      // size
        Timespec::from_secs(0), // mtime
        Weak::new(),            // no superblock for anonymous inode
        &NULL_INODE_OPS,
    ));

    // Create anonymous dentry
    let dentry = Arc::new(Dentry::new_anonymous(String::from("socket"), Some(inode)));

    Ok(dentry)
}

/// socket(domain, type, protocol) - create a socket
pub fn sys_socket(domain: i32, sock_type: i32, protocol: i32) -> i64 {
    // Parse address family
    let family = match AddressFamily::from_i32(domain) {
        Some(AddressFamily::Inet) => AddressFamily::Inet,
        Some(_) | None => return KernelError::AddressFamilyNotSupported.sysret(),
    };

    // Extract type and flags
    let type_only = sock_type & 0xFF;
    let nonblock = sock_type & sock_flags::SOCK_NONBLOCK != 0;
    let cloexec = sock_type & sock_flags::SOCK_CLOEXEC != 0;

    // Parse socket type
    let stype = match SocketType::from_i32(type_only) {
        Some(SocketType::Stream) => SocketType::Stream,
        Some(SocketType::Dgram) => SocketType::Dgram,
        Some(SocketType::Raw) => return KernelError::SocketTypeNotSupported.sysret(),
        None => return KernelError::SocketTypeNotSupported.sysret(),
    };

    // Protocol: 0 means default for type
    // 6 = IPPROTO_TCP, 17 = IPPROTO_UDP
    if protocol != 0 {
        match (stype, protocol) {
            (SocketType::Stream, 6) => {} // TCP
            (SocketType::Dgram, 17) => {} // UDP
            (SocketType::Stream, _) => return KernelError::ProtocolNotSupported.sysret(),
            (SocketType::Dgram, _) => return KernelError::ProtocolNotSupported.sysret(),
            _ => return KernelError::ProtocolNotSupported.sysret(),
        }
    }

    // Create socket
    let socket = Socket::new(family, stype, protocol);

    // Apply flags
    if nonblock {
        socket.set_nonblocking(true);
    }

    // Create file operations (leaked for 'static lifetime like pipe.rs)
    let ops: &'static dyn FileOps = Box::leak(Box::new(SocketFileOps::new(socket)));

    // Create dummy dentry for socket
    let dentry = match create_socket_dentry() {
        Ok(d) => d,
        Err(_) => return KernelError::OutOfMemory.sysret(),
    };

    // Determine file flags
    let mut flags = file_flags::O_RDWR;
    if nonblock {
        flags |= file_flags::O_NONBLOCK;
    }
    if cloexec {
        flags |= file_flags::O_CLOEXEC;
    }
    let file = Arc::new(File::new(dentry, flags, ops));

    // Allocate fd
    let fd_table = match get_task_fd(current_tid()) {
        Some(t) => t,
        None => return KernelError::OutOfMemory.sysret(),
    };
    match fd_table.lock().alloc(file, get_nofile_limit()) {
        Ok(fd) => fd as i64,
        Err(_) => KernelError::OutOfMemory.sysret(),
    }
}

/// connect(fd, addr, addrlen) - connect to remote address
pub fn sys_connect(fd: i32, addr: u64, addrlen: u64) -> i64 {
    if addrlen < core::mem::size_of::<SockAddrIn>() as u64 {
        return KernelError::InvalidArgument.sysret();
    }

    // Get socket from fd
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    // Read sockaddr_in from user
    let sockaddr = match read_sockaddr_in(addr) {
        Ok(s) => s,
        Err(e) => return e,
    };

    // Verify address family
    if sockaddr.sin_family != AddressFamily::Inet as u16 {
        return KernelError::AddressFamilyNotSupported.sysret();
    }

    let remote_addr = sockaddr.addr();
    let remote_port = sockaddr.port();

    // Check TCP state
    if let Some(ref tcp) = socket.tcp {
        match tcp.state() {
            TcpState::Established => return KernelError::AlreadyConnected.sysret(),
            TcpState::SynSent | TcpState::SynReceived => {
                if socket.is_nonblocking() {
                    return KernelError::AlreadyInProgress.sysret();
                }
            }
            _ => {}
        }
    }

    // Initiate connection
    if let Err(e) = tcp::tcp_connect(&socket, remote_addr, remote_port) {
        return e.sysret();
    }

    // Non-blocking: return EINPROGRESS
    if socket.is_nonblocking() {
        return KernelError::InProgress.sysret();
    }

    // Blocking: wait for connection
    loop {
        if let Some(ref tcp) = socket.tcp {
            match tcp.state() {
                TcpState::Established => return 0,
                TcpState::Closed => {
                    let err = socket.get_error();
                    if err != 0 {
                        return err as i64;
                    }
                    return KernelError::NotConnected.sysret();
                }
                _ => {}
            }
        }
        socket.connect_wait().wait();
    }
}

/// bind(fd, addr, addrlen) - bind to local address
pub fn sys_bind(fd: i32, addr: u64, addrlen: u64) -> i64 {
    if addrlen < core::mem::size_of::<SockAddrIn>() as u64 {
        return KernelError::InvalidArgument.sysret();
    }

    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let sockaddr = match read_sockaddr_in(addr) {
        Ok(s) => s,
        Err(e) => return e,
    };

    if sockaddr.sin_family != AddressFamily::Inet as u16 {
        return KernelError::AddressFamilyNotSupported.sysret();
    }

    let mut local_addr = sockaddr.addr();
    let mut local_port = sockaddr.port();

    // Allocate ephemeral port if port is 0
    if local_port == 0 {
        local_port = crate::net::current_net_ns().alloc_port();
    }

    // Use configured IP if addr is 0.0.0.0
    if local_addr.is_unspecified()
        && let Some(config) = crate::net::get_config()
    {
        local_addr = config.ipv4_addr;
    }

    socket.set_local(local_addr, local_port);

    // For UDP sockets, register in the UDP socket table
    if socket.sock_type == SocketType::Dgram {
        let tuple = udp::UdpTwoTuple {
            local_addr,
            local_port,
        };
        udp::udp_register_socket(tuple, Arc::clone(&socket));
    }

    0
}

/// listen(fd, backlog) - start listening for connections
///
/// Following Linux's inet_listen() -> inet_csk_listen_start():
/// 1. Check socket is bound
/// 2. Initialize accept queue with backlog
/// 3. Set TCP state to Listen
/// 4. Register in listener hash table
pub fn sys_listen(fd: i32, backlog: i32) -> i64 {
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    // Must be TCP socket
    let tcp = match socket.tcp.as_ref() {
        Some(t) => t,
        None => return KernelError::OperationNotSupported.sysret(),
    };

    // Must be bound (have local address)
    if socket.local_addr().is_none() {
        return KernelError::InvalidArgument.sysret();
    }

    // Can only listen from Closed state
    if tcp.state() != TcpState::Closed {
        return KernelError::InvalidArgument.sysret();
    }

    // Initialize accept queue with backlog (like inet_csk_listen_start)
    // Linux clamps backlog to somaxconn, we use a simpler approach
    let backlog = (backlog as u32).clamp(1, 128);
    socket.init_accept_queue(backlog);

    // Set TCP state to Listen
    tcp.set_state(TcpState::Listen);

    // Register in listener hash table (like inet_csk_listen_start)
    let (_, local_port) = socket.local_addr().unwrap();
    crate::net::current_net_ns().tcp_listen_register(local_port, Arc::clone(&socket));

    0
}

/// accept(fd, addr, addrlen) - accept incoming connection
///
/// Following Linux's inet_accept() -> inet_csk_accept():
/// 1. Check socket is listening
/// 2. Wait for connection in accept queue (or return EAGAIN if non-blocking)
/// 3. Dequeue child socket
/// 4. Create new fd for child socket
/// 5. Copy peer address to user if requested
pub fn sys_accept(fd: i32, addr: u64, addrlen: u64) -> i64 {
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    // Must be TCP socket
    let tcp = match socket.tcp.as_ref() {
        Some(t) => t,
        None => return KernelError::OperationNotSupported.sysret(),
    };

    // Must be in Listen state
    if tcp.state() != TcpState::Listen {
        return KernelError::InvalidArgument.sysret();
    }

    // Get accept queue
    loop {
        // Try to get a connection from accept queue
        {
            let accept_queue_guard = socket.accept_queue.lock();
            let accept_queue = match accept_queue_guard.as_ref() {
                Some(q) => q,
                None => return KernelError::InvalidArgument.sysret(),
            };

            if let Some(child) = accept_queue.accept_queue_remove() {
                // Got a connection - create fd for it
                drop(accept_queue_guard);

                // Create file descriptor for child socket
                let child_fd = match create_socket_fd(child.clone()) {
                    Ok(fd) => fd,
                    Err(e) => return e,
                };

                // Write peer address if requested
                if addr != 0
                    && addrlen != 0
                    && let Some((remote_addr, remote_port)) = child.remote_addr()
                {
                    // Read addrlen from user
                    let user_addrlen = unsafe { core::ptr::read_volatile(addrlen as *const u32) };

                    if user_addrlen >= 16 {
                        // Write sockaddr_in
                        let sockaddr = SockAddrIn::new(remote_addr, remote_port);
                        unsafe {
                            core::ptr::write_volatile(addr as *mut SockAddrIn, sockaddr);
                            core::ptr::write_volatile(addrlen as *mut u32, 16);
                        }
                    }
                }

                return child_fd;
            }
        }

        // Queue is empty
        if socket.is_nonblocking() {
            return KernelError::WouldBlock.sysret();
        }

        // Block waiting for connection
        // Use socket's accept_wait_block() which doesn't hold the accept_queue lock
        socket.accept_wait_block();
    }
}

/// Create a file descriptor for a socket
fn create_socket_fd(socket: Arc<Socket>) -> Result<i64, i64> {
    // Create socket file operations (leaked for 'static lifetime like in sys_socket)
    let ops: &'static dyn crate::fs::file::FileOps =
        Box::leak(Box::new(SocketFileOps::new(socket)));

    // Create dummy dentry for socket
    let dentry = create_socket_dentry()?;

    // Create file
    let file = Arc::new(File::new(dentry, file_flags::O_RDWR, ops));

    // Allocate fd
    let fd_table = get_task_fd(current_tid()).ok_or(KernelError::BadFd.sysret())?;
    let fd = fd_table
        .lock()
        .alloc(file, get_nofile_limit())
        .map_err(|_| KernelError::ProcessFileLimit.sysret())?;

    Ok(fd as i64)
}

/// accept4(fd, addr, addrlen, flags) - accept with flags
pub fn sys_accept4(fd: i32, addr: u64, addrlen: u64, _flags: i32) -> i64 {
    sys_accept(fd, addr, addrlen)
}

/// socketpair(domain, type, protocol, sv) - create pair of connected sockets
///
/// For AF_INET, creates two UDP sockets connected to each other.
pub fn sys_socketpair(domain: i32, sock_type: i32, protocol: i32, sv: u64) -> i64 {
    if sv == 0 {
        return KernelError::BadAddress.sysret();
    }

    // Only support AF_INET for now
    let family = match AddressFamily::from_i32(domain) {
        Some(AddressFamily::Inet) => AddressFamily::Inet,
        Some(AddressFamily::Unix) => return KernelError::AddressFamilyNotSupported.sysret(), // AF_UNIX not implemented
        _ => return KernelError::AddressFamilyNotSupported.sysret(),
    };

    // Extract type and flags
    let type_only = sock_type & 0xFF;
    let nonblock = sock_type & sock_flags::SOCK_NONBLOCK != 0;
    let cloexec = sock_type & sock_flags::SOCK_CLOEXEC != 0;

    // Parse socket type - only SOCK_DGRAM makes sense for socketpair with AF_INET
    let stype = match SocketType::from_i32(type_only) {
        Some(SocketType::Dgram) => SocketType::Dgram,
        Some(SocketType::Stream) => return KernelError::OperationNotSupported.sysret(), // TCP socketpair needs more work
        _ => return KernelError::SocketTypeNotSupported.sysret(),
    };

    // Validate protocol
    if protocol != 0 && protocol != 17 {
        // 17 = IPPROTO_UDP
        return KernelError::ProtocolNotSupported.sysret();
    }

    // Create two sockets
    let socket1 = Socket::new(family, stype, protocol);
    let socket2 = Socket::new(family, stype, protocol);

    if nonblock {
        socket1.set_nonblocking(true);
        socket2.set_nonblocking(true);
    }

    // Get local address (use loopback 127.0.0.1)
    let local_addr = Ipv4Addr::new(127, 0, 0, 1);

    // Allocate ports
    let port1 = crate::net::current_net_ns().alloc_port();
    let port2 = crate::net::current_net_ns().alloc_port();

    // Bind sockets
    socket1.set_local(local_addr, port1);
    socket1.set_remote(local_addr, port2);
    socket2.set_local(local_addr, port2);
    socket2.set_remote(local_addr, port1);

    // Register in UDP socket table
    let tuple1 = udp::UdpTwoTuple {
        local_addr,
        local_port: port1,
    };
    let tuple2 = udp::UdpTwoTuple {
        local_addr,
        local_port: port2,
    };
    udp::udp_register_socket(tuple1, Arc::clone(&socket1));
    udp::udp_register_socket(tuple2, Arc::clone(&socket2));

    // Create file operations
    let ops1: &'static dyn FileOps = Box::leak(Box::new(SocketFileOps::new(socket1)));
    let ops2: &'static dyn FileOps = Box::leak(Box::new(SocketFileOps::new(socket2)));

    // Create dentries
    let dentry1 = match create_socket_dentry() {
        Ok(d) => d,
        Err(_) => return KernelError::OutOfMemory.sysret(),
    };
    let dentry2 = match create_socket_dentry() {
        Ok(d) => d,
        Err(_) => return KernelError::OutOfMemory.sysret(),
    };

    // Determine file flags
    let mut flags = file_flags::O_RDWR;
    if nonblock {
        flags |= file_flags::O_NONBLOCK;
    }
    if cloexec {
        flags |= file_flags::O_CLOEXEC;
    }

    let file1 = Arc::new(File::new(dentry1, flags, ops1));
    let file2 = Arc::new(File::new(dentry2, flags, ops2));

    // Allocate file descriptors
    let fd_table = match get_task_fd(current_tid()) {
        Some(t) => t,
        None => return KernelError::OutOfMemory.sysret(),
    };

    let nofile = get_nofile_limit();
    let fd1 = match fd_table.lock().alloc(file1, nofile) {
        Ok(fd) => fd,
        Err(_) => return KernelError::OutOfMemory.sysret(),
    };
    let fd2 = match fd_table.lock().alloc(file2, nofile) {
        Ok(fd) => fd,
        Err(_) => {
            // Clean up fd1
            let _ = fd_table.lock().close(fd1);
            return KernelError::OutOfMemory.sysret();
        }
    };

    // Write file descriptors to user space
    unsafe {
        let sv_ptr = sv as *mut [i32; 2];
        (*sv_ptr)[0] = fd1 as i32;
        (*sv_ptr)[1] = fd2 as i32;
    }

    0
}

// ============================================================================
// Message-based send/receive syscalls
// ============================================================================

/// msghdr structure from userspace
#[repr(C)]
pub struct UserMsgHdr {
    /// Optional address
    pub msg_name: u64,
    /// Size of address
    pub msg_namelen: u32,
    /// Padding for alignment
    _pad1: u32,
    /// Scatter/gather array
    pub msg_iov: u64,
    /// Number of elements in iov
    pub msg_iovlen: usize,
    /// Ancillary data
    pub msg_control: u64,
    /// Ancillary data length
    pub msg_controllen: usize,
    /// Flags on received message
    pub msg_flags: i32,
    /// Padding for alignment
    _pad2: i32,
}

/// iovec structure
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoVec {
    /// Base address
    pub iov_base: u64,
    /// Length
    pub iov_len: usize,
}

/// mmsghdr structure for sendmmsg/recvmmsg
#[repr(C)]
pub struct MMsgHdr {
    /// Message header
    pub msg_hdr: UserMsgHdr,
    /// Number of bytes transmitted/received
    pub msg_len: u32,
    /// Padding
    _pad: u32,
}

/// Read msghdr from user space
fn read_msghdr(addr: u64) -> Result<UserMsgHdr, i64> {
    if addr == 0 {
        return Err(KernelError::BadAddress.sysret());
    }
    let ptr = addr as *const UserMsgHdr;
    Ok(unsafe { core::ptr::read(ptr) })
}

/// Gather data from iovec array into a single buffer
fn gather_iovec(iov_ptr: u64, iovlen: usize) -> Result<alloc::vec::Vec<u8>, i64> {
    use alloc::vec::Vec;

    if iovlen == 0 {
        return Ok(Vec::new());
    }
    if iov_ptr == 0 {
        return Err(KernelError::BadAddress.sysret());
    }
    if iovlen > 1024 {
        // UIO_MAXIOV
        return Err(KernelError::InvalidArgument.sysret());
    }

    let iovecs = unsafe { core::slice::from_raw_parts(iov_ptr as *const IoVec, iovlen) };

    // Calculate total size
    let mut total_len = 0usize;
    for iov in iovecs {
        total_len = total_len.saturating_add(iov.iov_len);
    }

    // Gather data
    let mut data = Vec::with_capacity(total_len);
    for iov in iovecs {
        if iov.iov_base != 0 && iov.iov_len > 0 {
            let slice =
                unsafe { core::slice::from_raw_parts(iov.iov_base as *const u8, iov.iov_len) };
            data.extend_from_slice(slice);
        }
    }

    Ok(data)
}

/// Scatter data to iovec array, returns bytes written
fn scatter_iovec(iov_ptr: u64, iovlen: usize, data: &[u8]) -> usize {
    if iovlen == 0 || iov_ptr == 0 || data.is_empty() {
        return 0;
    }

    let iovecs = unsafe { core::slice::from_raw_parts(iov_ptr as *const IoVec, iovlen) };

    let mut offset = 0;
    for iov in iovecs {
        if offset >= data.len() {
            break;
        }
        if iov.iov_base != 0 && iov.iov_len > 0 {
            let to_copy = (data.len() - offset).min(iov.iov_len);
            let dst = unsafe { core::slice::from_raw_parts_mut(iov.iov_base as *mut u8, to_copy) };
            dst.copy_from_slice(&data[offset..offset + to_copy]);
            offset += to_copy;
        }
    }

    offset
}

/// sendmsg(fd, msg, flags) - send a message on a socket
pub fn sys_sendmsg(fd: i32, msg: u64, _flags: i32) -> i64 {
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    // Read msghdr from user
    let msghdr = match read_msghdr(msg) {
        Ok(m) => m,
        Err(e) => return e,
    };

    // Gather data from iovec
    let data = match gather_iovec(msghdr.msg_iov, msghdr.msg_iovlen) {
        Ok(d) => d,
        Err(e) => return e,
    };

    // Get destination address from msg_name (optional for connected sockets)
    let dest = if msghdr.msg_name != 0 && msghdr.msg_namelen >= 16 {
        match read_sockaddr_in(msghdr.msg_name) {
            Ok(addr) => Some((addr.addr(), addr.port())),
            Err(e) => return e,
        }
    } else {
        None
    };

    // Send based on socket type
    match socket.sock_type {
        SocketType::Stream => {
            // For TCP, ignore dest - use connected address
            match tcp::tcp_sendmsg(&socket, &data) {
                Ok(n) => n as i64,
                Err(e) => e.sysret(),
            }
        }
        SocketType::Dgram => {
            // For UDP, use dest if provided, otherwise use connected address
            match udp::udp_sendmsg(&socket, &data, dest) {
                Ok(n) => n as i64,
                Err(e) => e.sysret(),
            }
        }
        _ => KernelError::OperationNotSupported.sysret(),
    }
}

/// recvmsg(fd, msg, flags) - receive a message from a socket
pub fn sys_recvmsg(fd: i32, msg: u64, _flags: i32) -> i64 {
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    // Read msghdr from user
    let mut msghdr = match read_msghdr(msg) {
        Ok(m) => m,
        Err(e) => return e,
    };

    // Calculate total iovec space
    let total_space = if msghdr.msg_iov != 0 && msghdr.msg_iovlen > 0 {
        let iovecs = unsafe {
            core::slice::from_raw_parts(msghdr.msg_iov as *const IoVec, msghdr.msg_iovlen)
        };
        iovecs.iter().map(|iov| iov.iov_len).sum()
    } else {
        0
    };

    // Receive based on socket type
    match socket.sock_type {
        SocketType::Stream => {
            // TCP: read into temporary buffer then scatter
            let mut buf = alloc::vec![0u8; total_space];
            match socket.read(&mut buf) {
                Ok(n) => {
                    let written = scatter_iovec(msghdr.msg_iov, msghdr.msg_iovlen, &buf[..n]);
                    msghdr.msg_flags = 0;
                    // Write back msghdr (mainly msg_flags)
                    unsafe {
                        let ptr = msg as *mut UserMsgHdr;
                        core::ptr::write(ptr, msghdr);
                    }
                    written as i64
                }
                Err(e) => e as i64,
            }
        }
        SocketType::Dgram => {
            // UDP: read datagram and get source address
            let mut buf = alloc::vec![0u8; total_space];
            match socket.read_datagram(&mut buf) {
                Ok((n, src_addr, src_port)) => {
                    let written = scatter_iovec(msghdr.msg_iov, msghdr.msg_iovlen, &buf[..n]);

                    // Write source address to msg_name if provided
                    if msghdr.msg_name != 0 && msghdr.msg_namelen >= 16 {
                        let sockaddr = SockAddrIn::new(src_addr, src_port);
                        unsafe {
                            let ptr = msghdr.msg_name as *mut SockAddrIn;
                            core::ptr::write(ptr, sockaddr);
                        }
                        msghdr.msg_namelen = core::mem::size_of::<SockAddrIn>() as u32;
                    }

                    msghdr.msg_flags = 0;
                    // Write back msghdr
                    unsafe {
                        let ptr = msg as *mut UserMsgHdr;
                        core::ptr::write(ptr, msghdr);
                    }
                    written as i64
                }
                Err(e) => e as i64,
            }
        }
        _ => KernelError::OperationNotSupported.sysret(),
    }
}

/// sendmmsg(fd, msgvec, vlen, flags) - send multiple messages
pub fn sys_sendmmsg(fd: i32, msgvec: u64, vlen: u32, flags: i32) -> i64 {
    if msgvec == 0 || vlen == 0 {
        return 0;
    }
    if vlen > 1024 {
        // UIO_MAXIOV limit
        return KernelError::InvalidArgument.sysret();
    }

    let msgs = unsafe { core::slice::from_raw_parts_mut(msgvec as *mut MMsgHdr, vlen as usize) };

    let mut sent = 0i64;
    for mmsg in msgs.iter_mut() {
        // Get pointer to the embedded UserMsgHdr
        let msg_ptr = &mmsg.msg_hdr as *const UserMsgHdr as u64;
        let result = sys_sendmsg(fd, msg_ptr, flags);
        if result < 0 {
            if sent == 0 {
                return result; // Return error if no messages sent
            }
            break; // Stop on error but return count of successful sends
        }
        mmsg.msg_len = result as u32;
        sent += 1;
    }

    sent
}

/// recvmmsg(fd, msgvec, vlen, flags, timeout) - receive multiple messages
pub fn sys_recvmmsg(fd: i32, msgvec: u64, vlen: u32, flags: i32, _timeout: u64) -> i64 {
    if msgvec == 0 || vlen == 0 {
        return 0;
    }
    if vlen > 1024 {
        return KernelError::InvalidArgument.sysret();
    }

    let msgs = unsafe { core::slice::from_raw_parts_mut(msgvec as *mut MMsgHdr, vlen as usize) };

    let mut received = 0i64;
    for mmsg in msgs.iter_mut() {
        let msg_ptr = &mut mmsg.msg_hdr as *mut UserMsgHdr as u64;
        let result = sys_recvmsg(fd, msg_ptr, flags);
        if result < 0 {
            if received == 0 {
                return result;
            }
            break;
        }
        if result == 0 {
            break; // EOF
        }
        mmsg.msg_len = result as u32;
        received += 1;
    }

    received
}

/// shutdown(fd, how) - shutdown socket
pub fn sys_shutdown(fd: i32, how: i32) -> i64 {
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    // how: 0 = SHUT_RD, 1 = SHUT_WR, 2 = SHUT_RDWR
    match how {
        0 => {
            // SHUT_RD - mark EOF on receive side
            socket.set_eof();
            socket.wake_rx();
        }
        1 | 2 => {
            // SHUT_WR or SHUT_RDWR - close the connection
            if let Err(e) = tcp::tcp_close(&socket) {
                return e.sysret();
            }
            if how == 2 {
                socket.set_eof();
                socket.wake_all();
            }
        }
        _ => return KernelError::InvalidArgument.sysret(),
    }

    0
}

/// getsockname(fd, addr, addrlen) - get local socket address
pub fn sys_getsockname(fd: i32, addr: u64, addrlen: u64) -> i64 {
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let (local_addr, local_port) = match socket.local_addr() {
        Some(a) => a,
        None => (Ipv4Addr::new(0, 0, 0, 0), 0),
    };

    let sockaddr = SockAddrIn::new(local_addr, local_port);
    write_sockaddr_in(addr, addrlen, &sockaddr)
}

/// getpeername(fd, addr, addrlen) - get remote socket address
pub fn sys_getpeername(fd: i32, addr: u64, addrlen: u64) -> i64 {
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let (remote_addr, remote_port) = match socket.remote_addr() {
        Some(a) => a,
        None => return KernelError::NotConnected.sysret(),
    };

    let sockaddr = SockAddrIn::new(remote_addr, remote_port);
    write_sockaddr_in(addr, addrlen, &sockaddr)
}

/// setsockopt(fd, level, optname, optval, optlen) - set socket option
pub fn sys_setsockopt(fd: i32, _level: i32, _optname: i32, _optval: u64, _optlen: u64) -> i64 {
    // Verify it's a socket
    match get_socket(fd) {
        Ok(_) => 0, // Silently accept but ignore options for now
        Err(e) => e,
    }
}

/// getsockopt(fd, level, optname, optval, optlen) - get socket option
pub fn sys_getsockopt(fd: i32, level: i32, optname: i32, optval: u64, optlen: u64) -> i64 {
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    // SOL_SOCKET = 1, SO_ERROR = 4
    if level == 1 && optname == 4 {
        // SO_ERROR - get pending error
        let err = socket.get_error();
        if optval != 0 && optlen != 0 {
            // Write error value
            unsafe {
                let ptr = optval as *mut i32;
                if !ptr.is_null() {
                    *ptr = -err;
                }
                let len_ptr = optlen as *mut u32;
                if !len_ptr.is_null() {
                    *len_ptr = 4;
                }
            }
        }
        return 0;
    }

    // Other options: return 0 with empty result
    0
}

/// sendto(fd, buf, len, flags, dest_addr, addrlen) - send data
pub fn sys_sendto(fd: i32, buf: u64, len: u64, _flags: i32, dest_addr: u64, addrlen: u64) -> i64 {
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let data = unsafe { core::slice::from_raw_parts(buf as *const u8, len as usize) };

    match socket.sock_type {
        SocketType::Stream => {
            // TCP: use tcp_sendmsg (ignores dest_addr)
            match tcp::tcp_sendmsg(&socket, data) {
                Ok(n) => n as i64,
                Err(e) => e.sysret(),
            }
        }
        SocketType::Dgram => {
            // UDP: parse optional destination address
            let dest = if dest_addr != 0 && addrlen >= core::mem::size_of::<SockAddrIn>() as u64 {
                match read_sockaddr_in(dest_addr) {
                    Ok(addr) => Some((addr.addr(), addr.port())),
                    Err(e) => return e,
                }
            } else {
                None
            };

            match udp::udp_sendmsg(&socket, data, dest) {
                Ok(n) => n as i64,
                Err(e) => e.sysret(),
            }
        }
        _ => KernelError::OperationNotSupported.sysret(),
    }
}

/// recvfrom(fd, buf, len, flags, src_addr, addrlen) - receive data
pub fn sys_recvfrom(fd: i32, buf: u64, len: u64, _flags: i32, src_addr: u64, addrlen: u64) -> i64 {
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let buffer = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, len as usize) };

    match socket.sock_type {
        SocketType::Stream => {
            // TCP: use regular read
            match socket.read(buffer) {
                Ok(n) => n as i64,
                Err(e) => e as i64,
            }
        }
        SocketType::Dgram => {
            // UDP: read datagram with source address
            match socket.read_datagram(buffer) {
                Ok((n, src_ip, src_port)) => {
                    // Write source address if requested
                    if src_addr != 0 && addrlen != 0 {
                        let sockaddr = SockAddrIn::new(src_ip, src_port);
                        let _ = write_sockaddr_in(src_addr, addrlen, &sockaddr);
                    }
                    n as i64
                }
                Err(e) => e as i64,
            }
        }
        _ => KernelError::OperationNotSupported.sysret(),
    }
}

// Helper functions

/// Get socket from file descriptor
fn get_socket(fd: i32) -> Result<Arc<Socket>, i64> {
    if fd < 0 {
        return Err(KernelError::BadFd.sysret());
    }

    let fd_table = get_task_fd(current_tid()).ok_or(KernelError::BadFd.sysret())?;
    let file = fd_table.lock().get(fd).ok_or(KernelError::BadFd.sysret())?;

    // Try to downcast FileOps to SocketFileOps
    let ops = file.ops();
    let socket_ops = ops
        .as_any()
        .downcast_ref::<SocketFileOps>()
        .ok_or(KernelError::NotSocket.sysret())?;

    Ok(Arc::clone(socket_ops.socket()))
}

/// Read sockaddr_in from user space
fn read_sockaddr_in(addr: u64) -> Result<SockAddrIn, i64> {
    if addr == 0 {
        return Err(KernelError::BadAddress.sysret());
    }

    // Use get_user to properly access user memory with SMAP protection
    // SockAddrIn layout: sin_family (u16), sin_port (u16), sin_addr (u32), sin_zero ([u8; 8])
    let sin_family: u16 =
        get_user::<Uaccess, u16>(addr).map_err(|_| KernelError::BadAddress.sysret())?;
    let sin_port: u16 =
        get_user::<Uaccess, u16>(addr + 2).map_err(|_| KernelError::BadAddress.sysret())?;
    let sin_addr: u32 =
        get_user::<Uaccess, u32>(addr + 4).map_err(|_| KernelError::BadAddress.sysret())?;

    // sin_zero is padding, we don't need to read it
    Ok(SockAddrIn {
        sin_family,
        sin_port,
        sin_addr,
        sin_zero: [0; 8],
    })
}

/// Write sockaddr_in to user space
fn write_sockaddr_in(addr: u64, addrlen: u64, sockaddr: &SockAddrIn) -> i64 {
    if addr == 0 || addrlen == 0 {
        return KernelError::BadAddress.sysret();
    }

    unsafe {
        let ptr = addr as *mut SockAddrIn;
        *ptr = *sockaddr;

        let len_ptr = addrlen as *mut u32;
        if !len_ptr.is_null() {
            *len_ptr = core::mem::size_of::<SockAddrIn>() as u32;
        }
    }

    0
}
