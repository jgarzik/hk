//! Inode attribute changes as one step under i_rwsem (Linux
//! chmod_common/chown_common: inode_lock around notify_change).
//!
//! - CHMOD_CHOWN_RACE: a user chmods its file to 04755 while root
//!   chowns it to uid 0, at the same moment, many times. Either the
//!   chmod comes first and chown's set-id kill clears S_ISUID, or the
//!   chown comes first and the user's chmod fails (no longer the
//!   owner): never a setuid-root file with contents the user chose.
//! - SIZE_PUBLISH: while a writer appends a pattern, a reader that sees
//!   a size never reads stale bytes below it (Linux i_size_write and
//!   i_size_read are release and acquire).

use core::sync::atomic::{AtomicI32, Ordering};

use super::helpers::{print, print_num, println};
use hk_syscall::{
    MAP_ANONYMOUS, MAP_SHARED, O_CREAT, O_RDONLY, O_WRONLY, PROT_READ, PROT_WRITE, Stat, sys_chmod,
    sys_chown, sys_close, sys_exit, sys_fork, sys_fstat, sys_mkdir, sys_mmap, sys_munmap, sys_open,
    sys_pread64, sys_pwrite64, sys_sched_yield, sys_setuid, sys_stat, sys_unlink, sys_wait4,
};

const S_ISUID: u32 = 0o4000;
const ROUNDS: i32 = 300;

pub fn run_tests() {
    report(b"CHMOD_CHOWN_RACE", chmod_chown_race());
    report(b"SIZE_PUBLISH", size_publish());
}

type R = Result<(), (&'static [u8], i64)>;

fn report(name: &[u8], r: R) {
    print(name);
    match r {
        Ok(()) => println(b":OK"),
        Err((why, got)) => {
            print(b":FAIL ");
            print(why);
            print(b" got ");
            print_num(got);
            println(b"");
        }
    }
}

fn check(what: &'static [u8], ok: bool, got: i64) -> R {
    if ok { Ok(()) } else { Err((what, got)) }
}

fn stat(path: &[u8]) -> Option<Stat> {
    // SAFETY: Stat is plain integers, valid all-zero
    let mut st: Stat = unsafe { core::mem::zeroed() };
    (sys_stat(path.as_ptr(), &mut st) == 0).then_some(st)
}

/// Spin (yielding) until `w` reads `v`
fn wait_for(w: &AtomicI32, v: i32) {
    while w.load(Ordering::Acquire) != v {
        sys_sched_yield();
    }
}

const FILE: &[u8] = b"/tmp/attr_race\0";

fn chmod_chown_race() -> R {
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777);
    let fd = sys_open(FILE.as_ptr(), O_CREAT | O_WRONLY, 0o755);
    check(b"create", fd >= 0, fd)?;
    sys_close(fd as u64);
    // [0]: round the parent started; [1]: round the child finished
    let p = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0,
    );
    check(b"mmap", p > 0, p)?;
    // SAFETY: a fresh MAP_SHARED page, unmapped only below
    let sh = unsafe { core::slice::from_raw_parts(p as *const AtomicI32, 2) };
    let r = (|| {
        let mut bad = None;
        let pid = sys_fork();
        if pid == 0 {
            if sys_setuid(1000) != 0 {
                sys_exit(1);
            }
            for round in 1..=ROUNDS {
                wait_for(&sh[0], round);
                sys_chmod(FILE.as_ptr(), 0o4755);
                sh[1].store(round, Ordering::Release);
            }
            sys_exit(0);
        }
        for round in 1..=ROUNDS {
            // The user's file, not set-id
            sys_chown(FILE.as_ptr(), 1000, 1000);
            sys_chmod(FILE.as_ptr(), 0o755);
            sh[0].store(round, Ordering::Release);
            sys_chown(FILE.as_ptr(), 0, u32::MAX);
            wait_for(&sh[1], round);
            let st = stat(FILE).ok_or((&b"stat"[..], 0))?;
            if st.st_uid == 0 && st.st_mode & S_ISUID != 0 {
                bad = Some(round);
                break;
            }
        }
        if bad.is_some() {
            // Let the child run out its rounds
            for round in bad.unwrap_or(0) + 1..=ROUNDS {
                sh[0].store(round, Ordering::Release);
                wait_for(&sh[1], round);
            }
        }
        let mut ws = 0;
        sys_wait4(pid, &mut ws, 0, 0);
        check(b"child", ws == 0, (ws >> 8) as i64)?;
        check(b"setuid root", bad.is_none(), bad.unwrap_or(0) as i64)
    })();
    sys_munmap(p as u64, 4096);
    sys_unlink(FILE.as_ptr());
    r
}

const CHUNK: usize = 64;
const CHUNKS: u64 = 4000;
const SIZE_FILE: &[u8] = b"/tmp/size_publish\0";

fn size_publish() -> R {
    let fd = sys_open(
        SIZE_FILE.as_ptr(),
        O_CREAT | O_WRONLY | hk_syscall::O_TRUNC,
        0o644,
    );
    check(b"create", fd >= 0, fd)?;
    let pid = sys_fork();
    if pid == 0 {
        let buf = [0xABu8; CHUNK];
        for i in 0..CHUNKS {
            sys_pwrite64(
                fd as i32,
                buf.as_ptr(),
                CHUNK as u64,
                (i * CHUNK as u64) as i64,
            );
        }
        sys_exit(0);
    }
    let rd = sys_open(SIZE_FILE.as_ptr(), O_RDONLY, 0);
    let mut bad = None;
    let end = CHUNKS * CHUNK as u64;
    loop {
        // SAFETY: Stat is plain integers, valid all-zero
        let mut st: Stat = unsafe { core::mem::zeroed() };
        sys_fstat(rd as i32, &mut st);
        let size = st.st_size as u64;
        if size >= CHUNK as u64 {
            let mut b = [0u8; CHUNK];
            let n = sys_pread64(
                rd as i32,
                b.as_mut_ptr(),
                CHUNK as u64,
                (size - CHUNK as u64) as i64,
            );
            if n != CHUNK as i64 || b.iter().any(|&c| c != 0xAB) {
                bad = Some(size as i64);
                break;
            }
        }
        if size >= end {
            break;
        }
    }
    let mut ws = 0;
    sys_wait4(pid, &mut ws, 0, 0);
    sys_close(rd as u64);
    sys_close(fd as u64);
    sys_unlink(SIZE_FILE.as_ptr());
    check(b"stale bytes", bad.is_none(), bad.unwrap_or(0))
}
