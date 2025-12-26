//! TCP Tests
//!
//! Tests for the TCP protocol implementation using fork()-based server/client.

use hk_syscall::{
    sys_accept, sys_bind, sys_close, sys_connect, sys_fork, sys_listen,
    sys_recvfrom, sys_sendto, sys_socket, sys_wait4,
    AF_INET, SOCK_STREAM, SockAddrIn, htons, htonl, make_ipv4,
};
use super::helpers::{print, println, print_num};

/// Run all TCP tests
pub fn run_tests() {
    println(b"=== TCP Tests ===");

    test_tcp_loopback();
}

/// Full TCP server-client test using fork()
///
/// This test creates a listening socket, forks, and then:
/// - Parent: accepts connection, receives data, sends response
/// - Child: connects, sends data, receives response
fn test_tcp_loopback() {
    // Create listening socket
    let server_fd = sys_socket(AF_INET, SOCK_STREAM, 0);
    if server_fd < 0 {
        print(b"socket() failed: ");
        print_num(server_fd);
        println(b"TCP_LOOPBACK:FAIL");
        return;
    }

    // Bind to loopback:9999
    let port: u16 = 9999;
    let addr = SockAddrIn::new(AF_INET as u16, htons(port), htonl(make_ipv4(127, 0, 0, 1)));
    let ret = sys_bind(
        server_fd as i32,
        &addr as *const SockAddrIn as *const u8,
        core::mem::size_of::<SockAddrIn>() as u32,
    );
    if ret != 0 {
        print(b"bind() failed: ");
        print_num(ret);
        sys_close(server_fd as u64);
        println(b"TCP_LOOPBACK:FAIL");
        return;
    }

    // Listen
    let ret = sys_listen(server_fd as i32, 5);
    if ret != 0 {
        print(b"listen() failed: ");
        print_num(ret);
        sys_close(server_fd as u64);
        println(b"TCP_LOOPBACK:FAIL");
        return;
    }

    // Fork
    let pid = sys_fork();
    if pid < 0 {
        print(b"fork() failed: ");
        print_num(pid);
        sys_close(server_fd as u64);
        println(b"TCP_LOOPBACK:FAIL");
        return;
    }

    if pid == 0 {
        // Child: client
        sys_close(server_fd as u64);
        run_tcp_client(port);
    } else {
        // Parent: server
        run_tcp_server(server_fd);

        // Wait for child
        let mut status: i32 = 0;
        sys_wait4(-1, &mut status, 0, 0);

        println(b"TCP_LOOPBACK:OK");
    }
}

/// Server side of TCP loopback test
fn run_tcp_server(server_fd: i64) {
    // Accept connection
    let mut client_addr = SockAddrIn::new(0, 0, 0);
    let mut addrlen: u32 = core::mem::size_of::<SockAddrIn>() as u32;

    let conn_fd = sys_accept(
        server_fd as i32,
        &mut client_addr as *mut SockAddrIn as *mut u8,
        &mut addrlen,
    );

    if conn_fd < 0 {
        print(b"accept() failed: ");
        print_num(conn_fd);
        sys_close(server_fd as u64);
        return;
    }

    print(b"SERVER: accept() returned fd=");
    print_num(conn_fd);
    print(b"\n");

    // Receive data from client
    let mut buf = [0u8; 64];
    let n = sys_recvfrom(
        conn_fd as i32,
        buf.as_mut_ptr(),
        buf.len(),
        0,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    );

    if n > 0 {
        print(b"SERVER: received ");
        print_num(n);
        print(b" bytes: ");
        print(&buf[..n as usize]);
        print(b"\n");

        // Check if it matches expected message
        let expected = b"Hello from client";
        if n as usize == expected.len() && &buf[..n as usize] == expected {
            println(b"SERVER_RECV:OK");
        } else {
            println(b"SERVER_RECV:FAIL");
        }

        // Send response
        let response = b"Hello from server";
        let sent = sys_sendto(
            conn_fd as i32,
            response.as_ptr(),
            response.len(),
            0,
            core::ptr::null(),
            0,
        );

        if sent as usize == response.len() {
            print(b"SERVER: sent ");
            print_num(sent);
            print(b" bytes\n");
        } else {
            print(b"SERVER: sendto() failed: ");
            print_num(sent);
            print(b"\n");
        }
    } else {
        print(b"SERVER: recvfrom() failed: ");
        print_num(n);
        print(b"\n");
        println(b"SERVER_RECV:FAIL");
    }

    sys_close(conn_fd as u64);
    sys_close(server_fd as u64);
}

/// Client side of TCP loopback test
fn run_tcp_client(port: u16) {
    // Create socket
    let client_fd = sys_socket(AF_INET, SOCK_STREAM, 0);
    if client_fd < 0 {
        print(b"CLIENT: socket() failed: ");
        print_num(client_fd);
        print(b"\n");
        sys_exit_helper(1);
        return;
    }
    print(b"CLIENT: socket() returned ");
    print_num(client_fd);
    print(b"\n");

    // Connect to server
    let server_addr = SockAddrIn::new(
        AF_INET as u16,
        htons(port),
        htonl(make_ipv4(127, 0, 0, 1)),
    );

    // Debug: print address family
    print(b"CLIENT: sin_family=");
    print_num(server_addr.sin_family as i64);
    print(b" port=");
    print_num(port as i64);
    print(b"\n");

    let ret = sys_connect(
        client_fd as i32,
        &server_addr as *const SockAddrIn as *const u8,
        core::mem::size_of::<SockAddrIn>() as u32,
    );

    if ret != 0 {
        print(b"CLIENT: connect() failed: ");
        print_num(ret);
        print(b"\n");
        sys_close(client_fd as u64);
        sys_exit_helper(1);
        return;
    }

    println(b"CLIENT: connected");

    // Send data
    let msg = b"Hello from client";
    let sent = sys_sendto(
        client_fd as i32,
        msg.as_ptr(),
        msg.len(),
        0,
        core::ptr::null(),
        0,
    );

    if sent as usize != msg.len() {
        print(b"CLIENT: sendto() failed: ");
        print_num(sent);
        print(b"\n");
        sys_close(client_fd as u64);
        sys_exit_helper(1);
        return;
    }

    print(b"CLIENT: sent ");
    print_num(sent);
    print(b" bytes\n");

    // Receive response
    let mut buf = [0u8; 64];
    let n = sys_recvfrom(
        client_fd as i32,
        buf.as_mut_ptr(),
        buf.len(),
        0,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    );

    if n > 0 {
        print(b"CLIENT: received ");
        print_num(n);
        print(b" bytes: ");
        print(&buf[..n as usize]);
        print(b"\n");

        // Check if it matches expected response
        let expected = b"Hello from server";
        if n as usize == expected.len() && &buf[..n as usize] == expected {
            println(b"CLIENT_RECV:OK");
        } else {
            println(b"CLIENT_RECV:FAIL");
        }
    } else {
        print(b"CLIENT: recvfrom() failed: ");
        print_num(n);
        print(b"\n");
        println(b"CLIENT_RECV:FAIL");
    }

    sys_close(client_fd as u64);
    sys_exit_helper(0);
}

/// Helper to exit (child process)
fn sys_exit_helper(status: i32) {
    hk_syscall::sys_exit(status as u64);
}
