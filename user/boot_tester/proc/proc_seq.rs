//! Chunked reads of a generated /proc file (Linux seq_file): a read
//! that continues the last one reads the same generation, so no record
//! is torn between two generations
//!
//! - PROC_READ_CHUNKS: /proc/self/maps read 16 bytes at a time while a
//!   page is mapped below every other mapping before each read: every
//!   line that comes out is whole, and only the page mapped before the
//!   first read shows (Linux: the walk goes on past the last address
//!   shown)

use crate::helpers::{print, print_num, println};
use hk_syscall::{
    MAP_ANONYMOUS, MAP_FIXED_NOREPLACE, MAP_PRIVATE, O_RDONLY, PROT_READ, sys_close, sys_mmap,
    sys_munmap, sys_open, sys_read,
};

/// Below the program image (0x200000 or higher on both arches)
const BASE: u64 = 0x4_0000;
const PAGES: u64 = 64;

pub fn run_tests() {
    let fd = sys_open(b"/proc/self/maps\0".as_ptr(), O_RDONLY, 0);
    let mut out = [0u8; 16384];
    let mut len = 0;
    let mut k = 0;
    let mut mapped = [false; PAGES as usize];
    loop {
        if k < PAGES {
            // Lower than anything else, and a page apart so it is its own
            // line (adjacent ones merge): shifts every byte offset after it
            let at = BASE + (PAGES - 1 - k) * 8192;
            let r = sys_mmap(
                at,
                4096,
                PROT_READ,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                -1,
                0,
            );
            mapped[(PAGES - 1 - k) as usize] = r as u64 == at;
            k += 1;
        }
        if len + 16 > out.len() {
            break;
        }
        let n = sys_read(fd as u64, out[len..].as_mut_ptr(), 16);
        if n <= 0 {
            break;
        }
        len += n as usize;
    }
    sys_close(fd as u64);
    for (i, m) in mapped.iter().enumerate() {
        if *m {
            sys_munmap(BASE + i as u64 * 8192, 4096);
        }
    }
    let lines = || out[..len].split(|&c| c == b'\n').filter(|l| !l.is_empty());
    let bad = lines().position(|l| !whole_line(l));
    // One generation holds only the page mapped before the first read
    let ours = lines()
        .filter(|l| start_of(l).is_some_and(|a| (BASE..BASE + PAGES * 8192).contains(&a)))
        .count();
    print(b"PROC_READ_CHUNKS");
    match bad {
        None if len > 0 && ours == 1 => println(b":OK"),
        _ => {
            print(b":FAIL torn line ");
            print_num(bad.map_or(-1, |i| i as i64));
            print(b", test pages shown ");
            print_num(ours as i64);
            println(b"");
        }
    }
}

/// The start address of a maps line
fn start_of(l: &[u8]) -> Option<u64> {
    let dash = l.iter().position(|&c| c == b'-')?;
    let s = core::str::from_utf8(&l[..dash]).ok()?;
    u64::from_str_radix(s, 16).ok()
}

/// "start-end perms offset dev inode [path]": hex, '-', hex, a space,
/// [r-][w-][x-][ps], then 8+ hex digits
fn whole_line(l: &[u8]) -> bool {
    let hex = |b: &u8| b.is_ascii_hexdigit();
    let Some(dash) = l.iter().position(|&c| c == b'-') else {
        return false;
    };
    let Some(sp) = l.iter().position(|&c| c == b' ') else {
        return false;
    };
    if dash == 0 || sp <= dash + 1 || l.len() < sp + 14 {
        return false;
    }
    let p = &l[sp + 1..sp + 5];
    l[..dash].iter().all(hex)
        && l[dash + 1..sp].iter().all(hex)
        && matches!(p[0], b'r' | b'-')
        && matches!(p[1], b'w' | b'-')
        && matches!(p[2], b'x' | b'-')
        && matches!(p[3], b'p' | b's')
        && l[sp + 5] == b' '
        && l[sp + 6..sp + 14].iter().all(hex)
}
