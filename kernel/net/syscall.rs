//! Socket System Call Handlers
//!
//! This module implements the socket-related system calls for the network stack.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::sync::Weak;

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

/// Error numbers (negative)
mod errno {
    pub const EINVAL: i64 = -22;
    pub const EBADF: i64 = -9;
    pub const ENOTSOCK: i64 = -88;
    pub const EAFNOSUPPORT: i64 = -97;
    pub const ESOCKTNOSUPPORT: i64 = -94;
    pub const EPROTONOSUPPORT: i64 = -93;
    pub const ENOMEM: i64 = -12;
    pub const EOPNOTSUPP: i64 = -95;
    pub const ENOTCONN: i64 = -107;
    pub const EISCONN: i64 = -106;
    pub const EFAULT: i64 = -14;
    #[allow(dead_code)]
    pub const EAGAIN: i64 = -11;
    pub const EINPROGRESS: i64 = -115;
    pub const EALREADY: i64 = -114;
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
        Some(_) | None => return errno::EAFNOSUPPORT,
    };

    // Extract type and flags
    let type_only = sock_type & 0xFF;
    let nonblock = sock_type & sock_flags::SOCK_NONBLOCK != 0;
    let cloexec = sock_type & sock_flags::SOCK_CLOEXEC != 0;

    // Parse socket type
    let stype = match SocketType::from_i32(type_only) {
        Some(SocketType::Stream) => SocketType::Stream,
        Some(SocketType::Dgram) => SocketType::Dgram,
        Some(SocketType::Raw) => return errno::ESOCKTNOSUPPORT,
        None => return errno::ESOCKTNOSUPPORT,
    };

    // Protocol: 0 means default for type
    // 6 = IPPROTO_TCP, 17 = IPPROTO_UDP
    if protocol != 0 {
        match (stype, protocol) {
            (SocketType::Stream, 6) => {} // TCP
            (SocketType::Dgram, 17) => {} // UDP
            (SocketType::Stream, _) => return errno::EPROTONOSUPPORT,
            (SocketType::Dgram, _) => return errno::EPROTONOSUPPORT,
            _ => return errno::EPROTONOSUPPORT,
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
        Err(_) => return errno::ENOMEM,
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
        None => return errno::ENOMEM,
    };
    match fd_table.lock().alloc(file, get_nofile_limit()) {
        Ok(fd) => fd as i64,
        Err(_) => errno::ENOMEM,
    }
}

/// connect(fd, addr, addrlen) - connect to remote address
pub fn sys_connect(fd: i32, addr: u64, addrlen: u64) -> i64 {
    if addrlen < core::mem::size_of::<SockAddrIn>() as u64 {
        return errno::EINVAL;
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
        return errno::EAFNOSUPPORT;
    }

    let remote_addr = sockaddr.addr();
    let remote_port = sockaddr.port();

    // Check TCP state
    if let Some(ref tcp) = socket.tcp {
        match tcp.state() {
            TcpState::Established => return errno::EISCONN,
            TcpState::SynSent | TcpState::SynReceived => {
                if socket.is_nonblocking() {
                    return errno::EALREADY;
                }
            }
            _ => {}
        }
    }

    // Initiate connection
    if let Err(e) = tcp::tcp_connect(&socket, remote_addr, remote_port) {
        return e.to_errno() as i64;
    }

    // Non-blocking: return EINPROGRESS
    if socket.is_nonblocking() {
        return errno::EINPROGRESS;
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
                    return errno::ENOTCONN;
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
        return errno::EINVAL;
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
        return errno::EAFNOSUPPORT;
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
pub fn sys_listen(fd: i32, _backlog: i32) -> i64 {
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    // Set TCP state to Listen
    if let Some(ref tcp) = socket.tcp {
        tcp.set_state(TcpState::Listen);
        0
    } else {
        errno::EOPNOTSUPP
    }
}

/// accept(fd, addr, addrlen) - accept incoming connection
pub fn sys_accept(fd: i32, _addr: u64, _addrlen: u64) -> i64 {
    let _socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    // TODO: Implement accept queue for listening sockets
    // For now, return not supported
    errno::EOPNOTSUPP
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
        return errno::EFAULT;
    }

    // Only support AF_INET for now
    let family = match AddressFamily::from_i32(domain) {
        Some(AddressFamily::Inet) => AddressFamily::Inet,
        Some(AddressFamily::Unix) => return errno::EAFNOSUPPORT, // AF_UNIX not implemented
        _ => return errno::EAFNOSUPPORT,
    };

    // Extract type and flags
    let type_only = sock_type & 0xFF;
    let nonblock = sock_type & sock_flags::SOCK_NONBLOCK != 0;
    let cloexec = sock_type & sock_flags::SOCK_CLOEXEC != 0;

    // Parse socket type - only SOCK_DGRAM makes sense for socketpair with AF_INET
    let stype = match SocketType::from_i32(type_only) {
        Some(SocketType::Dgram) => SocketType::Dgram,
        Some(SocketType::Stream) => return errno::EOPNOTSUPP, // TCP socketpair needs more work
        _ => return errno::ESOCKTNOSUPPORT,
    };

    // Validate protocol
    if protocol != 0 && protocol != 17 {
        // 17 = IPPROTO_UDP
        return errno::EPROTONOSUPPORT;
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
        Err(_) => return errno::ENOMEM,
    };
    let dentry2 = match create_socket_dentry() {
        Ok(d) => d,
        Err(_) => return errno::ENOMEM,
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
        None => return errno::ENOMEM,
    };

    let nofile = get_nofile_limit();
    let fd1 = match fd_table.lock().alloc(file1, nofile) {
        Ok(fd) => fd,
        Err(_) => return errno::ENOMEM,
    };
    let fd2 = match fd_table.lock().alloc(file2, nofile) {
        Ok(fd) => fd,
        Err(_) => {
            // Clean up fd1
            let _ = fd_table.lock().close(fd1);
            return errno::ENOMEM;
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
        return Err(errno::EFAULT);
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
        return Err(errno::EFAULT);
    }
    if iovlen > 1024 {
        // UIO_MAXIOV
        return Err(errno::EINVAL);
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
                Err(e) => e.to_errno() as i64,
            }
        }
        SocketType::Dgram => {
            // For UDP, use dest if provided, otherwise use connected address
            match udp::udp_sendmsg(&socket, &data, dest) {
                Ok(n) => n as i64,
                Err(e) => e.to_errno() as i64,
            }
        }
        _ => errno::EOPNOTSUPP,
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
        _ => errno::EOPNOTSUPP,
    }
}

/// sendmmsg(fd, msgvec, vlen, flags) - send multiple messages
pub fn sys_sendmmsg(fd: i32, msgvec: u64, vlen: u32, flags: i32) -> i64 {
    if msgvec == 0 || vlen == 0 {
        return 0;
    }
    if vlen > 1024 {
        // UIO_MAXIOV limit
        return errno::EINVAL;
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
        return errno::EINVAL;
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
                return e.to_errno() as i64;
            }
            if how == 2 {
                socket.set_eof();
                socket.wake_all();
            }
        }
        _ => return errno::EINVAL,
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
        None => return errno::ENOTCONN,
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
                Err(e) => e.to_errno() as i64,
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
                Err(e) => e.to_errno() as i64,
            }
        }
        _ => errno::EOPNOTSUPP,
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
        _ => errno::EOPNOTSUPP,
    }
}

// Helper functions

/// Get socket from file descriptor
fn get_socket(fd: i32) -> Result<Arc<Socket>, i64> {
    if fd < 0 {
        return Err(errno::EBADF);
    }

    let fd_table = get_task_fd(current_tid()).ok_or(errno::EBADF)?;
    let file = fd_table.lock().get(fd).ok_or(errno::EBADF)?;

    // Try to downcast FileOps to SocketFileOps
    let ops = file.ops();
    let socket_ops = ops
        .as_any()
        .downcast_ref::<SocketFileOps>()
        .ok_or(errno::ENOTSOCK)?;

    Ok(Arc::clone(socket_ops.socket()))
}

/// Read sockaddr_in from user space
fn read_sockaddr_in(addr: u64) -> Result<SockAddrIn, i64> {
    if addr == 0 {
        return Err(errno::EFAULT);
    }

    let ptr = addr as *const SockAddrIn;
    let sockaddr = unsafe { *ptr };
    Ok(sockaddr)
}

/// Write sockaddr_in to user space
fn write_sockaddr_in(addr: u64, addrlen: u64, sockaddr: &SockAddrIn) -> i64 {
    if addr == 0 || addrlen == 0 {
        return errno::EFAULT;
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
