//! Signal queue (Linux struct sigqueue) tests
//!
//! - /proc/self/status SigQ is queued/RLIMIT_SIGPENDING, the limit set
//!   at boot (half of max_threads) and inherited

use super::helpers::{print, print_num, println, read_file};
use hk_syscall::{RLIMIT_SIGPENDING, RLimit, sys_getrlimit};

pub fn run_tests() {
    test_sigq_limit();
}

/// Parse a decimal number at the start of `s`
fn num(s: &[u8]) -> (i64, usize) {
    let mut v = 0i64;
    let mut n = 0;
    for &c in s {
        if !c.is_ascii_digit() {
            break;
        }
        v = v * 10 + (c - b'0') as i64;
        n += 1;
    }
    (v, n)
}

/// /proc/self/status SigQ: (queued, limit), or (-1, -1)
fn sigq() -> (i64, i64) {
    let mut buf = [0u8; 2048];
    let n = read_file(b"/proc/self/status\0", &mut buf);
    if n <= 0 {
        return (-1, -1);
    }
    let s = &buf[..n as usize];
    let key = b"SigQ:\t";
    let Some(at) = s.windows(key.len()).position(|w| w == key) else {
        return (-1, -1);
    };
    let s = &s[at + key.len()..];
    let (q, len) = num(s);
    if s.get(len) != Some(&b'/') {
        return (-1, -1);
    }
    (q, num(&s[len + 1..]).0)
}

/// RLIMIT_SIGPENDING is set (soft = hard, non-zero) and SigQ shows it
fn test_sigq_limit() {
    let mut r = RLimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = sys_getrlimit(RLIMIT_SIGPENDING, &mut r);
    let (q, lim) = sigq();
    if rc == 0 && r.rlim_cur > 0 && r.rlim_cur == r.rlim_max && lim == r.rlim_cur as i64 && q >= 0
    {
        println(b"SIGQUEUE_LIMIT:OK");
    } else {
        print(b"SIGQUEUE_LIMIT:FAIL rlim=");
        print_num(r.rlim_cur as i64);
        print(b"/");
        print_num(r.rlim_max as i64);
        print(b" sigq=");
        print_num(q);
        print(b"/");
        print_num(lim);
        println(b"");
    }
}
