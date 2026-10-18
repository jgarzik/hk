//! busybox end-to-end tests (Ubuntu busybox-static, static glibc)
//!
//! Each test forks and execs /bin/busybox with an applet, captures its
//! stdout+stderr through a pipe and checks the exit status and output:
//! shell basics, then the network tools against QEMU's slirp network
//! (`ip`, DHCP with `udhcpc` over AF_PACKET, `nslookup`, `wget` from
//! the HTTP peer, `ping`, `nc` to the echo peer and over lo). Runs
//! unchanged on hk and on real Linux (tools/linux-boot-tester.sh), both
//! architectures.

use super::helpers::{print, print_num, println, skip};
use super::nl::{
    AF_INET, IFA_LOCAL, Nl, RT_TABLE_MAIN, RTA_GATEWAY, RTA_OIF, RTM_GETADDR, RTM_GETROUTE,
    RTM_NEWADDR, RTM_NEWROUTE, Req, addr as nl_addr, ifaddr, net_setup_eth0, rtmsg,
};
use hk_syscall::{
    O_CLOEXEC, POLLIN, PollFd, SIG_IGN, SIGKILL, SIGPIPE, sys_close, sys_dup3, sys_execve,
    sys_exit, sys_fork, sys_kill, sys_pipe2, sys_poll, sys_read, sys_rt_sigaction, sys_wait4,
    sys_write,
};

/// struct sigaction (kernel layout)
#[repr(C)]
#[derive(Default)]
struct SigAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

/// Write `buf` to `fd` with SIGPIPE ignored: a child that exits before
/// reading its input (EPIPE) must not kill the test process
fn write_nopipe(fd: i32, buf: &[u8]) {
    let ign = SigAction {
        handler: SIG_IGN,
        ..Default::default()
    };
    let mut old = SigAction::default();
    let (a, o) = (&ign as *const _ as u64, &mut old as *mut _ as u64);
    sys_rt_sigaction(SIGPIPE, a, o, 8);
    sys_write(fd as u64, buf.as_ptr(), buf.len() as u64);
    sys_rt_sigaction(SIGPIPE, o, 0, 8);
}

/// Captured output size
const OUT_MAX: usize = 8192;

/// Result of one busybox run
pub struct Run {
    /// wait4 status (-1 if the child could not be started or timed out)
    pub status: i32,
    pub out: [u8; OUT_MAX],
    pub len: usize,
}

impl Run {
    pub fn output(&self) -> &[u8] {
        &self.out[..self.len]
    }

    /// Exited normally with status 0
    pub fn ok(&self) -> bool {
        self.status == 0
    }

    pub fn has(&self, needle: &[u8]) -> bool {
        contains(self.output(), needle)
    }
}

pub fn contains(hay: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || hay.windows(needle.len()).any(|w| w == needle)
}

/// Monotonic milliseconds
fn now_ms() -> i64 {
    let mut ts = hk_syscall::Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    hk_syscall::sys_clock_gettime(1, &mut ts);
    ts.tv_sec * 1000 + ts.tv_nsec / 1_000_000
}

const ENVP_PATH: &[u8] = b"PATH=/bin\0";
const ENVP_HOME: &[u8] = b"HOME=/\0";
/// Printed by the child when execve fails (followed by the errno)
const EXEC_FAILED: &[u8] = b"execve failed: ";

/// Child side: stdin from `inp`, stdout/stderr to `outw`, exec
fn child(args: &[&[u8]], inp: i32, outw: i32) -> ! {
    sys_dup3(inp, 0, 0);
    sys_dup3(outw, 1, 0);
    sys_dup3(outw, 2, 0);
    let mut argv: [*const u8; 16] = [core::ptr::null(); 16];
    argv[0] = b"busybox\0".as_ptr();
    for (i, a) in args.iter().take(14).enumerate() {
        argv[i + 1] = a.as_ptr();
    }
    let envp: [*const u8; 3] = [ENVP_PATH.as_ptr(), ENVP_HOME.as_ptr(), core::ptr::null()];
    let e = sys_execve(b"/bin/busybox\0".as_ptr(), argv.as_ptr(), envp.as_ptr());
    print(EXEC_FAILED);
    print_num(e);
    sys_exit(127)
}

/// A running busybox: its pid and the read end of its output pipe
pub struct Child {
    pid: i64,
    fd: i32,
}

/// Start `busybox args...` (each arg NUL-terminated) with `stdin` as
/// its input
pub fn spawn(args: &[&[u8]], stdin: &[u8]) -> Option<Child> {
    let mut outp = [0i32; 2];
    let mut inp = [0i32; 2];
    if sys_pipe2(outp.as_mut_ptr(), O_CLOEXEC) < 0 {
        return None;
    }
    if sys_pipe2(inp.as_mut_ptr(), O_CLOEXEC) < 0 {
        sys_close(outp[0] as u64);
        sys_close(outp[1] as u64);
        return None;
    }
    let pid = sys_fork();
    if pid == 0 {
        child(args, inp[0], outp[1]);
    }
    sys_close(outp[1] as u64);
    sys_close(inp[0] as u64);
    // Small inputs fit the pipe buffer: write all, then EOF
    if pid > 0 && !stdin.is_empty() {
        write_nopipe(inp[1], stdin);
    }
    sys_close(inp[1] as u64);
    if pid < 0 {
        sys_close(outp[0] as u64);
        return None;
    }
    Some(Child { pid, fd: outp[0] })
}

/// Collect a child's output until it exits, killing it after
/// `timeout_ms`
pub fn finish(c: Child, timeout_ms: i64) -> Run {
    let mut r = Run {
        status: -1,
        out: [0; OUT_MAX],
        len: 0,
    };
    let killed = collect(&mut r, c.fd, c.pid, timeout_ms);
    sys_close(c.fd as u64);
    let mut st = 0i32;
    sys_wait4(c.pid, &mut st, 0, 0);
    r.status = if killed { -1 } else { st };
    r
}

/// Run `busybox args...` with `stdin` as input
pub fn bb_input(args: &[&[u8]], stdin: &[u8], timeout_ms: i64) -> Run {
    match spawn(args, stdin) {
        Some(c) => finish(c, timeout_ms),
        None => Run {
            status: -1,
            out: [0; OUT_MAX],
            len: 0,
        },
    }
}

/// Run `busybox args...` with empty stdin
pub fn bb(args: &[&[u8]], timeout_ms: i64) -> Run {
    bb_input(args, b"", timeout_ms)
}

/// Read the child's output until EOF or the deadline; true if killed
fn collect(r: &mut Run, fd: i32, pid: i64, timeout_ms: i64) -> bool {
    let deadline = now_ms() + timeout_ms;
    let mut scratch = [0u8; 512];
    loop {
        let left = deadline - now_ms();
        if left <= 0 {
            sys_kill(pid, SIGKILL);
            return true;
        }
        let mut p = PollFd {
            fd,
            events: POLLIN,
            revents: 0,
        };
        if sys_poll(&mut p, 1, left.min(1000) as i32) <= 0 {
            continue;
        }
        let room = OUT_MAX - r.len;
        let n = if room > 0 {
            sys_read(fd as u64, r.out[r.len..].as_mut_ptr(), room as u64)
        } else {
            sys_read(fd as u64, scratch.as_mut_ptr(), scratch.len() as u64)
        };
        if n <= 0 {
            return false;
        }
        if room > 0 {
            r.len += n as usize;
        }
    }
}

/// Print a verdict; on failure also the status and captured output
fn report(name: &[u8], pass: bool, r: &Run) {
    print(name);
    if pass {
        println(b":OK");
        return;
    }
    print(b":FAIL status=");
    print_num(r.status as i64);
    println(b"");
    print(b"  output: ");
    println(r.output());
}

/// busybox can be executed at all
fn available() -> bool {
    let r = bb(&[b"true\0"], 10_000);
    if !r.ok() {
        report(b"BUSYBOX_EXEC", false, &r);
    }
    r.ok()
}

pub fn run_tests() {
    println(b"=== busybox Tests ===");
    if !available() {
        return;
    }
    test_true();
    test_false();
    test_echo();
    test_sh_c();
    test_sh_pipe();
    test_stdin();
    let eth = match net_setup_eth0() {
        Ok(i) => i,
        Err(e) => {
            skip(b"BUSYBOX_NET", e.as_bytes());
            return;
        }
    };
    test_ip();
    test_udhcpc(eth);
    let _ = net_setup_eth0();
    test_nslookup();
    test_wget();
    test_ping();
    test_nc_echo();
    test_nc_lo();
}

// ============================================================================
// Smoke tests: process basics a static-glibc program needs
// ============================================================================

fn test_true() {
    let r = bb(&[b"true\0"], 10_000);
    report(b"BUSYBOX_TRUE", r.ok() && r.len == 0, &r);
}

fn test_false() {
    let r = bb(&[b"false\0"], 10_000);
    // WEXITSTATUS 1
    report(b"BUSYBOX_FALSE", r.status == 1 << 8, &r);
}

fn test_echo() {
    let r = bb(&[b"echo\0", b"hello\0", b"world\0"], 10_000);
    report(
        b"BUSYBOX_ECHO",
        r.ok() && r.output() == b"hello world\n",
        &r,
    );
}

fn test_sh_c() {
    let r = bb(&[b"sh\0", b"-c\0", b"echo hi; exit 3\0"], 10_000);
    report(
        b"BUSYBOX_SH_C",
        r.status == 3 << 8 && r.output() == b"hi\n",
        &r,
    );
}

fn test_sh_pipe() {
    let r = bb(
        &[b"sh\0", b"-c\0", b"echo a | cat; ls / | grep -c etc\0"],
        10_000,
    );
    report(b"BUSYBOX_SH_PIPE", r.ok() && r.output() == b"a\n1\n", &r);
}

fn test_stdin() {
    let r = bb_input(&[b"cat\0"], b"from stdin\n", 10_000);
    report(
        b"BUSYBOX_STDIN",
        r.ok() && r.output() == b"from stdin\n",
        &r,
    );
}

// ============================================================================
// Network tools
// ============================================================================

/// `ip link/addr/route` show eth0, 10.0.2.15/24 and the default route
fn test_ip() {
    let r = bb(&[b"ip\0", b"link\0"], 10_000);
    report(
        b"BUSYBOX_IP_LINK",
        r.ok() && r.has(b"lo:") && r.has(b"eth0:") && r.has(b"UP"),
        &r,
    );
    let r = bb(
        &[b"ip\0", b"addr\0", b"show\0", b"dev\0", b"eth0\0"],
        10_000,
    );
    report(
        b"BUSYBOX_IP_ADDR",
        r.ok() && r.has(b"inet 10.0.2.15/24"),
        &r,
    );
    let r = bb(&[b"ip\0", b"route\0"], 10_000);
    report(
        b"BUSYBOX_IP_ROUTE",
        r.ok() && r.has(b"default via 10.0.2.2 dev eth0"),
        &r,
    );
}

/// Prefix length of `ip` on link `index`, from an address dump
fn addr_plen(nl: &mut Nl, index: u32, ip: [u8; 4]) -> Option<u8> {
    let mut plen = None;
    let mut r = Req::new(RTM_GETADDR, 0, &ifaddr(AF_INET, 0, 0));
    nl.dump(&mut r, &mut |m| {
        if m.ty == RTM_NEWADDR && m.u32_at(4) == index && m.attr_ip(8, IFA_LOCAL) == Some(ip) {
            plen = Some(m.body[1]);
        }
    });
    plen
}

/// Gateway of the main-table default route on link `index`
fn default_gw(nl: &mut Nl, index: u32) -> Option<[u8; 4]> {
    let mut gw = None;
    let mut r = Req::new(RTM_GETROUTE, 0, &rtmsg(0, 0, 0, 0, 0));
    nl.dump(&mut r, &mut |m| {
        let main = m.body[4] == RT_TABLE_MAIN;
        if m.ty == RTM_NEWROUTE && m.body[1] == 0 && main && m.attr_u32(12, RTA_OIF) == Some(index)
        {
            gw = m.attr_ip(12, RTA_GATEWAY);
        }
    });
    gw
}

/// DHCP from scratch: with eth0's address (and so its routes) removed,
/// `udhcpc` gets slirp's lease and /etc/udhcpc.sh configures it
fn test_udhcpc(eth: u32) {
    const N: &[u8] = b"BUSYBOX_UDHCPC";
    let Some(mut nl) = Nl::open() else {
        skip(N, b"netlink socket");
        return;
    };
    nl_addr(&mut nl, false, eth, [10, 0, 2, 15], 24, 0);
    if addr_plen(&mut nl, eth, [10, 0, 2, 15]).is_some() || default_gw(&mut nl, eth).is_some() {
        print(N);
        println(b":FAIL eth0 still configured after flush");
        return;
    }
    let r = bb(
        &[
            b"udhcpc\0",
            b"-f\0",
            b"-n\0",
            b"-q\0",
            b"-i\0",
            b"eth0\0",
            b"-s\0",
            b"/etc/udhcpc.sh\0",
        ],
        30_000,
    );
    let plen = addr_plen(&mut nl, eth, [10, 0, 2, 15]);
    let gw = default_gw(&mut nl, eth);
    let pass = r.ok() && plen == Some(24) && gw == Some([10, 0, 2, 2]);
    report(N, pass, &r);
    let r = bb(&[b"cat\0", b"/etc/resolv.conf\0"], 10_000);
    report(b"BUSYBOX_RESOLV_CONF", r.has(b"nameserver 10.0.2.3"), &r);
}

/// DNS through slirp's resolver at 10.0.2.3: any answer (even NXDOMAIN)
/// passes; no reply at all needs the host's network: skipped
fn test_nslookup() {
    const N: &[u8] = b"BUSYBOX_NSLOOKUP";
    let r = bb(&[b"nslookup\0", b"localhost\0", b"10.0.2.3\0"], 30_000);
    let answered = r.has(b"Name:") || r.has(b"NXDOMAIN") || r.has(b"can't find");
    if !answered && (r.has(b"timed out") || r.has(b"no servers")) {
        skip(N, b"no reply from slirp DNS (host resolver unreachable)");
        return;
    }
    report(N, r.has(b"10.0.2.3") && answered, &r);
}

/// HTTP GET from the slirp HTTP peer (tools/netpeer/http.py)
fn test_wget() {
    let r = bb(
        &[b"wget\0", b"-q\0", b"-O\0", b"-\0", b"http://10.0.2.100/\0"],
        30_000,
    );
    report(
        b"BUSYBOX_WGET",
        r.ok() && r.output() == b"hk netpeer ok\n",
        &r,
    );
}

/// ICMP echo to the slirp gateway; slirp without ICMP support (no host
/// ping permission) is a skip
fn test_ping() {
    const N: &[u8] = b"BUSYBOX_PING";
    let r = bb(
        &[b"ping\0", b"-c\0", b"1\0", b"-W\0", b"3\0", b"10.0.2.2\0"],
        20_000,
    );
    if r.has(b"0 packets received") {
        skip(N, b"no echo reply from slirp (host ICMP unavailable)");
        return;
    }
    report(N, r.ok() && r.has(b"1 packets received"), &r);
}

/// `echo hi | nc 10.0.2.100 7` through the slirp echo peer
fn test_nc_echo() {
    let r = bb_input(&[b"nc\0", b"10.0.2.100\0", b"7\0"], b"hi\n", 20_000);
    report(b"BUSYBOX_NC_ECHO", r.ok() && r.output() == b"hi\n", &r);
}

/// `nc -l` on lo and an `nc` client: the server prints what it got
fn test_nc_lo() {
    const N: &[u8] = b"BUSYBOX_NC_LO";
    let Some(server) = spawn(&[b"nc\0", b"-l\0", b"-p\0", b"5577\0"], b"") else {
        print(N);
        println(b":FAIL spawn");
        return;
    };
    // Start the client once the server listens (then retry a little)
    let listening = wait_listen(5577);
    let mut client = bb_input(&[b"nc\0", b"127.0.0.1\0", b"5577\0"], b"over lo\n", 10_000);
    for _ in 0..20 {
        if client.ok() {
            break;
        }
        super::nl::msleep(100);
        client = bb_input(&[b"nc\0", b"127.0.0.1\0", b"5577\0"], b"over lo\n", 10_000);
    }
    let s = finish(server, 10_000);
    report(
        N,
        listening && client.ok() && s.ok() && s.output() == b"over lo\n",
        &s,
    );
}

/// A TCP socket listens on `port` (/proc/net/tcp or tcp6: local
/// address `*:PORT`, state 0A; busybox nc listens on IPv6 where it
/// can), waiting up to 5 s
fn wait_listen(port: u16) -> bool {
    let hex = |v: u16, i: usize| b"0123456789ABCDEF"[((v >> (12 - 4 * i)) & 0xf) as usize];
    let want = [b':', hex(port, 0), hex(port, 1), hex(port, 2), hex(port, 3)];
    let listens = |l: &[u8]| {
        let mut f = l.split(|&c| c == b' ').filter(|t| !t.is_empty());
        let (local, st) = (f.nth(1), f.nth(1));
        local.is_some_and(|a| a.ends_with(&want)) && st == Some(b"0A")
    };
    for _ in 0..50 {
        for path in [&b"/proc/net/tcp\0"[..], b"/proc/net/tcp6\0"] {
            let mut b = [0u8; 4096];
            let n = super::helpers::read_file(path, &mut b);
            if b[..n.max(0) as usize].split(|&c| c == b'\n').any(listens) {
                return true;
            }
        }
        super::nl::msleep(100);
    }
    false
}
