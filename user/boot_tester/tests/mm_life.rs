//! Address-space lifecycle: /proc/meminfo, and memory handed back when
//! processes exit or exec (Linux mmput/exit_mmap, exec_mmap)

use super::helpers::{print, print_num, println};
use hk_syscall::{
    sys_clone, sys_close, sys_exit, sys_open, sys_read, sys_sched_yield, CLONE_SIGHAND, CLONE_VM,
    O_RDONLY,
};

const CLONE_THREAD: u64 = 0x0001_0000;
const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;

pub fn run_tests() {
    meminfo_format();
    // An exiting thread clears and wakes its CLONE_CHILD_CLEARTID word
    // (Linux mm_release), before it leaves the address space
    report(b"MM_LIFE_CLEARTID", thread(), 0);
}

/// Read /proc/meminfo into `buf`; its length (0 on error)
fn read_meminfo(buf: &mut [u8]) -> usize {
    let fd = sys_open(b"/proc/meminfo\0".as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        return 0;
    }
    let mut len = 0;
    while len < buf.len() {
        let n = sys_read(fd as u64, buf[len..].as_mut_ptr(), (buf.len() - len) as u64);
        if n <= 0 {
            break;
        }
        len += n as usize;
    }
    sys_close(fd as u64);
    len
}

/// The line of /proc/meminfo starting with `key` (e.g. b"MemFree:")
fn line<'a>(text: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    text.split(|&b| b == b'\n').find(|l| l.starts_with(key))
}

/// Value in kB of a /proc/meminfo field, -1 if missing
pub fn meminfo(key: &[u8]) -> i64 {
    let mut buf = [0u8; 4096];
    let len = read_meminfo(&mut buf);
    let Some(l) = line(&buf[..len], key) else {
        return -1;
    };
    let mut v: i64 = -1;
    for &b in &l[key.len()..] {
        if b.is_ascii_digit() {
            v = v.max(0) * 10 + (b - b'0') as i64;
        } else if v >= 0 {
            break;
        }
    }
    v
}

fn report(name: &[u8], ok: bool, detail: i64) {
    print(name);
    if ok {
        println(b":OK");
    } else {
        print(b":FAIL ");
        print_num(detail);
        println(b"");
    }
}

/// Linux layout: a 16-column label, the value, " kB"; free <= total
fn meminfo_format() {
    let mut buf = [0u8; 4096];
    let len = read_meminfo(&mut buf);
    let text = &buf[..len];
    let keys: [&[u8]; 3] = [b"MemTotal:", b"MemFree:", b"MemAvailable:"];
    let mut bad = 0;
    for (i, k) in keys.iter().enumerate() {
        let ok = line(text, k).is_some_and(|l| {
            l.len() > 19 && l[k.len()..16].iter().all(|&b| b == b' ') && l.ends_with(b" kB")
        });
        if !ok {
            bad = i as i64 + 1;
        }
    }
    let total = meminfo(b"MemTotal:");
    let free = meminfo(b"MemFree:");
    if bad == 0 && !(total > 0 && free > 0 && free <= total) {
        bad = 10;
    }
    report(b"MEMINFO_FORMAT", bad == 0, bad);
}

/// A thread is created and exits; its user stack is reused only after
/// CLONE_CHILD_CLEARTID shows it gone
fn thread() -> bool {
    #[repr(C, align(16))]
    struct Stack([u8; 8192]);
    static mut STACK: Stack = Stack([0; 8192]);
    static mut CTID: u32 = 0;
    let top = unsafe { (&raw mut STACK as *mut u8).add(8192) } as u64;
    let ctid = &raw mut CTID;
    unsafe { core::ptr::write_volatile(ctid, 1) };
    let flags = CLONE_VM | CLONE_SIGHAND | CLONE_THREAD | CLONE_CHILD_CLEARTID;
    let r = sys_clone(flags, top, 0, ctid as u64, 0);
    if r == 0 {
        sys_exit(0); // exit(2): this thread only
    }
    if r < 0 {
        return false;
    }
    let mut spins = 0u32;
    while unsafe { core::ptr::read_volatile(ctid) } != 0 {
        spins += 1;
        if spins > 1_000_000 {
            return false;
        }
        sys_sched_yield();
    }
    true
}
