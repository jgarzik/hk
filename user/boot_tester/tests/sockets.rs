//! Socket Tests
//!
//! Tests for the network socket syscalls.

use hk_syscall::{
    sys_close, sys_socket, sys_bind, sys_listen, sys_shutdown,
    sys_getsockname, sys_socketpair, sys_sendmsg, sys_sendto, sys_recvfrom,
    sys_fork, sys_wait4, sys_exit, sys_nanosleep,
    SockAddrIn, MsgHdr, IoVec, Timespec, AF_INET, SOCK_STREAM, SOCK_DGRAM, SOCK_NONBLOCK,
    SHUT_RD, SHUT_WR, SHUT_RDWR, htons, htonl, make_ipv4,
};
use super::helpers::{print, println, print_num};

/// Run all socket tests
pub fn run_tests() {
    println(b"=== Socket Tests ===");

    test_socket_create();
    test_socket_create_nonblock();
    test_socket_invalid_domain();
    test_bind_any();
    test_getsockname();
    test_listen();
    test_shutdown();
    test_socket_close();

    // UDP socket tests
    test_socket_dgram();
    test_udp_bind();

    // New syscall tests
    test_socketpair();
    test_sendmsg_recvmsg();

    // UDP data transfer tests
    test_udp_loopback();
}

/// Test basic socket creation
fn test_socket_create() {
    // Create AF_INET, SOCK_STREAM socket
    let fd = sys_socket(AF_INET, SOCK_STREAM, 0);

    print(b"socket(AF_INET, SOCK_STREAM, 0) returned ");
    print_num(fd);

    if fd >= 0 {
        // Clean up
        sys_close(fd as u64);
        println(b"SOCKET_CREATE:OK");
    } else {
        println(b"SOCKET_CREATE:FAIL");
    }
}

/// Test socket creation with SOCK_NONBLOCK flag
fn test_socket_create_nonblock() {
    // Create AF_INET, SOCK_STREAM with SOCK_NONBLOCK
    let fd = sys_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);

    print(b"socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0) returned ");
    print_num(fd);

    if fd >= 0 {
        sys_close(fd as u64);
        println(b"SOCKET_NONBLOCK:OK");
    } else {
        println(b"SOCKET_NONBLOCK:FAIL");
    }
}

/// Test socket creation with invalid domain
fn test_socket_invalid_domain() {
    // AF_UNIX = 1, should return -EAFNOSUPPORT (-97)
    let fd = sys_socket(1, SOCK_STREAM, 0);

    print(b"socket(AF_UNIX, SOCK_STREAM, 0) returned ");
    print_num(fd);

    // Should fail with -97 (EAFNOSUPPORT)
    if fd == -97 {
        println(b"SOCKET_INVALID:OK");
    } else {
        println(b"SOCKET_INVALID:FAIL");
    }
}

/// Test bind to INADDR_ANY:0 (let kernel assign port)
fn test_bind_any() {
    let fd = sys_socket(AF_INET, SOCK_STREAM, 0);
    if fd < 0 {
        print(b"socket() failed: ");
        print_num(fd);
        println(b"SOCKET_BIND:FAIL");
        return;
    }

    // Bind to 0.0.0.0:0
    let addr = SockAddrIn::new(AF_INET as u16, 0, 0);
    let ret = sys_bind(
        fd as i32,
        &addr as *const SockAddrIn as *const u8,
        core::mem::size_of::<SockAddrIn>() as u32,
    );

    print(b"bind(0.0.0.0:0) returned ");
    print_num(ret);

    sys_close(fd as u64);

    if ret == 0 {
        println(b"SOCKET_BIND:OK");
    } else {
        println(b"SOCKET_BIND:FAIL");
    }
}

/// Test getsockname after bind
fn test_getsockname() {
    let fd = sys_socket(AF_INET, SOCK_STREAM, 0);
    if fd < 0 {
        println(b"SOCKET_GETSOCKNAME:FAIL");
        return;
    }

    // Bind to a specific port
    let port: u16 = 12345;
    let addr = SockAddrIn::new(AF_INET as u16, htons(port), 0);
    let ret = sys_bind(
        fd as i32,
        &addr as *const SockAddrIn as *const u8,
        core::mem::size_of::<SockAddrIn>() as u32,
    );

    if ret != 0 {
        print(b"bind() failed: ");
        print_num(ret);
        sys_close(fd as u64);
        println(b"SOCKET_GETSOCKNAME:FAIL");
        return;
    }

    // Get the bound address
    let mut out_addr = SockAddrIn::new(0, 0, 0);
    let mut addrlen: u32 = core::mem::size_of::<SockAddrIn>() as u32;
    let ret = sys_getsockname(
        fd as i32,
        &mut out_addr as *mut SockAddrIn as *mut u8,
        &mut addrlen,
    );

    print(b"getsockname() returned ");
    print_num(ret);
    print(b", port=");
    // Convert back from network order
    print_num(u16::from_be(out_addr.sin_port) as i64);

    sys_close(fd as u64);

    // Verify we got back the port we bound to
    if ret == 0 && u16::from_be(out_addr.sin_port) == port {
        println(b"SOCKET_GETSOCKNAME:OK");
    } else {
        println(b"SOCKET_GETSOCKNAME:FAIL");
    }
}

/// Test listen on a bound socket
fn test_listen() {
    let fd = sys_socket(AF_INET, SOCK_STREAM, 0);
    if fd < 0 {
        println(b"SOCKET_LISTEN:FAIL");
        return;
    }

    // Bind first
    let addr = SockAddrIn::new(AF_INET as u16, htons(12346), 0);
    let ret = sys_bind(
        fd as i32,
        &addr as *const SockAddrIn as *const u8,
        core::mem::size_of::<SockAddrIn>() as u32,
    );

    if ret != 0 {
        print(b"bind() failed: ");
        print_num(ret);
        sys_close(fd as u64);
        println(b"SOCKET_LISTEN:FAIL");
        return;
    }

    // Listen
    let ret = sys_listen(fd as i32, 5);

    print(b"listen() returned ");
    print_num(ret);

    sys_close(fd as u64);

    if ret == 0 {
        println(b"SOCKET_LISTEN:OK");
    } else {
        println(b"SOCKET_LISTEN:FAIL");
    }
}

/// Test shutdown operations
fn test_shutdown() {
    let fd = sys_socket(AF_INET, SOCK_STREAM, 0);
    if fd < 0 {
        println(b"SOCKET_SHUTDOWN:FAIL");
        return;
    }

    // Test SHUT_RD
    let ret_rd = sys_shutdown(fd as i32, SHUT_RD);
    print(b"shutdown(SHUT_RD) returned ");
    print_num(ret_rd);

    sys_close(fd as u64);

    // Create another socket to test SHUT_WR
    let fd2 = sys_socket(AF_INET, SOCK_STREAM, 0);
    if fd2 < 0 {
        println(b"SOCKET_SHUTDOWN:FAIL");
        return;
    }

    let ret_wr = sys_shutdown(fd2 as i32, SHUT_WR);
    print(b"shutdown(SHUT_WR) returned ");
    print_num(ret_wr);

    sys_close(fd2 as u64);

    // Create another socket to test SHUT_RDWR
    let fd3 = sys_socket(AF_INET, SOCK_STREAM, 0);
    if fd3 < 0 {
        println(b"SOCKET_SHUTDOWN:FAIL");
        return;
    }

    let ret_rdwr = sys_shutdown(fd3 as i32, SHUT_RDWR);
    print(b"shutdown(SHUT_RDWR) returned ");
    print_num(ret_rdwr);

    sys_close(fd3 as u64);

    // All shutdown calls should succeed (returns 0)
    if ret_rd == 0 && ret_wr == 0 && ret_rdwr == 0 {
        println(b"SOCKET_SHUTDOWN:OK");
    } else {
        println(b"SOCKET_SHUTDOWN:FAIL");
    }
}

/// Test socket close returns EBADF on second close
fn test_socket_close() {
    let fd = sys_socket(AF_INET, SOCK_STREAM, 0);
    if fd < 0 {
        println(b"SOCKET_CLOSE:FAIL");
        return;
    }

    // First close should succeed
    let ret1 = sys_close(fd as u64);
    print(b"first close() returned ");
    print_num(ret1);

    // Second close should return EBADF (-9)
    let ret2 = sys_close(fd as u64);
    print(b"second close() returned ");
    print_num(ret2);

    if ret1 == 0 && ret2 == -9 {
        println(b"SOCKET_CLOSE:OK");
    } else {
        println(b"SOCKET_CLOSE:FAIL");
    }
}

/// Test UDP socket creation
fn test_socket_dgram() {
    let fd = sys_socket(AF_INET, SOCK_DGRAM, 0);

    print(b"socket(AF_INET, SOCK_DGRAM, 0) returned ");
    print_num(fd);

    if fd >= 0 {
        sys_close(fd as u64);
        println(b"SOCKET_DGRAM:OK");
    } else {
        println(b"SOCKET_DGRAM:FAIL");
    }
}

/// Test UDP socket bind
fn test_udp_bind() {
    let fd = sys_socket(AF_INET, SOCK_DGRAM, 0);
    if fd < 0 {
        print(b"socket() failed: ");
        print_num(fd);
        println(b"UDP_BIND:FAIL");
        return;
    }

    // Bind to a specific port
    let port: u16 = 54321;
    let addr = SockAddrIn::new(AF_INET as u16, htons(port), 0);
    let ret = sys_bind(
        fd as i32,
        &addr as *const SockAddrIn as *const u8,
        core::mem::size_of::<SockAddrIn>() as u32,
    );

    print(b"UDP bind() returned ");
    print_num(ret);

    // Verify with getsockname
    let mut out_addr = SockAddrIn::new(0, 0, 0);
    let mut addrlen: u32 = core::mem::size_of::<SockAddrIn>() as u32;
    let ret2 = sys_getsockname(
        fd as i32,
        &mut out_addr as *mut SockAddrIn as *mut u8,
        &mut addrlen,
    );

    let bound_port = u16::from_be(out_addr.sin_port);
    print(b", getsockname port=");
    print_num(bound_port as i64);

    sys_close(fd as u64);

    if ret == 0 && ret2 == 0 && bound_port == port {
        println(b"UDP_BIND:OK");
    } else {
        println(b"UDP_BIND:FAIL");
    }
}

/// Test socketpair syscall
fn test_socketpair() {
    let mut sv: [i32; 2] = [-1, -1];

    let ret = sys_socketpair(AF_INET, SOCK_DGRAM, 0, &mut sv as *mut [i32; 2]);

    print(b"socketpair(AF_INET, SOCK_DGRAM) returned ");
    print_num(ret);
    print(b", fds=[");
    print_num(sv[0] as i64);
    print(b",");
    print_num(sv[1] as i64);
    print(b"]");

    if ret == 0 && sv[0] >= 0 && sv[1] >= 0 && sv[0] != sv[1] {
        sys_close(sv[0] as u64);
        sys_close(sv[1] as u64);
        println(b"SOCKETPAIR:OK");
    } else {
        if sv[0] >= 0 {
            sys_close(sv[0] as u64);
        }
        if sv[1] >= 0 {
            sys_close(sv[1] as u64);
        }
        println(b"SOCKETPAIR:FAIL");
    }
}

/// Test sendmsg/recvmsg on TCP socket
fn test_sendmsg_recvmsg() {
    // Create a TCP socket
    let fd = sys_socket(AF_INET, SOCK_STREAM, 0);
    if fd < 0 {
        print(b"socket() failed: ");
        print_num(fd);
        println(b"SENDMSG_RECVMSG:FAIL");
        return;
    }

    // Prepare a message with iovec
    let data: [u8; 5] = [b'H', b'e', b'l', b'l', b'o'];
    let mut iov = IoVec {
        iov_base: data.as_ptr(),
        iov_len: data.len(),
    };

    let msg = MsgHdr::new(&mut iov as *mut IoVec, 1);

    // sendmsg on unconnected TCP socket should fail with ENOTCONN (-107)
    // or EPIPE (-32) depending on implementation
    let ret = sys_sendmsg(fd as i32, &msg as *const MsgHdr, 0);

    print(b"sendmsg on unconnected socket returned ");
    print_num(ret);

    sys_close(fd as u64);

    // We expect an error (negative) since socket is not connected
    if ret < 0 {
        println(b"SENDMSG_RECVMSG:OK");
    } else {
        println(b"SENDMSG_RECVMSG:FAIL");
    }
}

/// Fork-based UDP loopback test - client/server exchange
fn test_udp_loopback() {
    const PORT: u16 = 8899;

    // Create server socket first (before fork)
    let server_fd = sys_socket(AF_INET, SOCK_DGRAM, 0);
    if server_fd < 0 {
        println(b"UDP_LOOPBACK:FAIL");
        return;
    }

    // Bind server socket to loopback address
    let server_addr = SockAddrIn::new(
        AF_INET as u16,
        htons(PORT),
        htonl(make_ipv4(127, 0, 0, 1)),
    );
    let ret = sys_bind(
        server_fd as i32,
        &server_addr as *const SockAddrIn as *const u8,
        core::mem::size_of::<SockAddrIn>() as u32,
    );
    if ret < 0 {
        sys_close(server_fd as u64);
        println(b"UDP_LOOPBACK:FAIL");
        return;
    }

    let pid = sys_fork();
    if pid < 0 {
        sys_close(server_fd as u64);
        println(b"UDP_LOOPBACK:FAIL (fork failed)");
        return;
    }

    if pid == 0 {
        // Child process - client
        sys_close(server_fd as u64);

        // Create client socket
        let client_fd = sys_socket(AF_INET, SOCK_DGRAM, 0);
        if client_fd < 0 {
            sys_exit(1);
        }

        // Destination address
        let dest_addr = SockAddrIn::new(
            AF_INET as u16,
            htons(PORT),
            htonl(make_ipv4(127, 0, 0, 1)),
        );

        // Send data to server
        let msg = b"Hello UDP";
        let sent = sys_sendto(
            client_fd as i32,
            msg.as_ptr(),
            msg.len(),
            0,
            &dest_addr as *const SockAddrIn as *const u8,
            core::mem::size_of::<SockAddrIn>() as u32,
        );

        if sent as usize != msg.len() {
            sys_close(client_fd as u64);
            sys_exit(1);
        }

        // Receive response from server
        let mut buf = [0u8; 64];
        let n = sys_recvfrom(
            client_fd as i32,
            buf.as_mut_ptr(),
            buf.len(),
            0,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );

        sys_close(client_fd as u64);

        // Check response
        let expected = b"UDP reply";
        if n as usize == expected.len() && &buf[..n as usize] == expected {
            sys_exit(0);
        } else {
            sys_exit(1);
        }
    } else {
        // Parent process - server

        // Brief delay to let child start
        let delay = Timespec { tv_sec: 0, tv_nsec: 10_000_000 }; // 10ms
        sys_nanosleep(&delay, core::ptr::null_mut());

        // Receive data from client
        let mut buf = [0u8; 64];
        let mut client_addr = SockAddrIn::new(0, 0, 0);
        let mut addrlen: u32 = core::mem::size_of::<SockAddrIn>() as u32;

        let n = sys_recvfrom(
            server_fd as i32,
            buf.as_mut_ptr(),
            buf.len(),
            0,
            &mut client_addr as *mut SockAddrIn as *mut u8,
            &mut addrlen,
        );

        if n > 0 {
            // Verify received message
            let expected = b"Hello UDP";
            if n as usize == expected.len() && &buf[..n as usize] == expected {
                // Send response back to client
                let response = b"UDP reply";
                sys_sendto(
                    server_fd as i32,
                    response.as_ptr(),
                    response.len(),
                    0,
                    &client_addr as *const SockAddrIn as *const u8,
                    core::mem::size_of::<SockAddrIn>() as u32,
                );
            }
        }

        sys_close(server_fd as u64);

        // Wait for child and check status
        let mut status: i32 = 0;
        sys_wait4(-1, &mut status, 0, 0);

        if (status >> 8) == 0 {
            println(b"UDP_LOOPBACK:OK");
        } else {
            println(b"UDP_LOOPBACK:FAIL");
        }
    }
}
