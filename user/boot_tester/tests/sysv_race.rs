//! SysV IPC creation and control (Linux ipc/util.c ipcget, ipcctl):
//! the lookup, the checks and the insert are one step under the ids
//! rwsem; an existing object is checked against the caller's request.
//!
//! - IPC_GET_RACE: four processes semget(IPC_CREAT) the same keys at
//!   once and all get the same id per key; with IPC_EXCL exactly one
//!   per key succeeds and the rest see EEXIST.
//! - IPC_MORE_CHECKS: semget of an existing key with more semaphores,
//!   or shmget with a larger size, is EINVAL (Linux sem_more_checks,
//!   shm_more_checks); a smaller request finds the object.
//! - IPC_SET_EFAULT: IPC_SET copies the buffer in before looking the id
//!   up, so a bad buffer is EFAULT even for a bad id.

use core::sync::atomic::{AtomicI32, Ordering};

use super::helpers::{print, print_num, println};
use hk_syscall::{
    IPC_CREAT, IPC_EXCL, IPC_RMID, IPC_SET, MAP_ANONYMOUS, MAP_SHARED, PROT_READ, PROT_WRITE,
    sys_exit, sys_fork, sys_mmap, sys_msgctl, sys_munmap, sys_semctl, sys_semget, sys_shmctl,
    sys_shmget, sys_wait4,
};

const EINVAL: i64 = -22;
const EEXIST: i64 = -17;
const EFAULT: i64 = -14;
const PROCS: usize = 4;
const KEYS: usize = 100;
const KEY_BASE: i32 = 0x4c00_0000;

pub fn run_tests() {
    report(b"IPC_GET_RACE", get_race());
    report(b"IPC_MORE_CHECKS", more_checks());
    report(b"IPC_SET_EFAULT", set_efault());
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

/// A shared anonymous array of `n` i32s, zeroed
fn shared(n: usize) -> &'static [AtomicI32] {
    let len = (n * 4).next_multiple_of(4096) as u64;
    let p = sys_mmap(
        0,
        len,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0,
    );
    assert!(p > 0, "mmap");
    // SAFETY: a fresh zeroed MAP_SHARED mapping of at least n i32s,
    // never unmapped while the slice is used (see `unshare`)
    unsafe { core::slice::from_raw_parts(p as *const AtomicI32, n) }
}

fn unshare(s: &[AtomicI32]) {
    let len = (s.len() * 4).next_multiple_of(4096) as u64;
    sys_munmap(s.as_ptr() as u64, len);
}

/// Run `f(i)` in `PROCS` children at once; true if all exited 0
fn in_children(f: fn(usize, &[AtomicI32]), out: &[AtomicI32]) -> bool {
    let mut pids = [0i64; PROCS];
    for (i, p) in pids.iter_mut().enumerate() {
        *p = sys_fork();
        if *p == 0 {
            f(i, out);
            sys_exit(0);
        }
    }
    let mut ok = true;
    for p in pids {
        let mut ws = 0;
        ok &= p > 0 && sys_wait4(p, &mut ws, 0, 0) == p && ws == 0;
    }
    ok
}

fn create(i: usize, out: &[AtomicI32]) {
    for k in 0..KEYS {
        let id = sys_semget(KEY_BASE + k as i32, 1, IPC_CREAT | 0o600);
        out[i * KEYS + k].store(id as i32, Ordering::Relaxed);
    }
}

/// Each child's result per key in its own slot (no atomic RMW in the
/// tester: arm64's outlined atomics need getauxval)
fn create_excl(i: usize, out: &[AtomicI32]) {
    for k in 0..KEYS {
        let r = sys_semget(
            KEY_BASE + KEYS as i32 + k as i32,
            1,
            IPC_CREAT | IPC_EXCL | 0o600,
        );
        out[i * KEYS + k].store(r as i32, Ordering::Relaxed);
    }
}

fn rmid_keys(base: i32) {
    for k in 0..KEYS {
        let id = sys_semget(base + k as i32, 0, 0);
        if id >= 0 {
            sys_semctl(id as i32, 0, IPC_RMID, 0);
        }
    }
}

fn get_race() -> R {
    let ids = shared(PROCS * KEYS);
    let ran = in_children(create, ids);
    rmid_keys(KEY_BASE);
    let r = (|| {
        check(b"children", ran, 0)?;
        for k in 0..KEYS {
            let first = ids[k].load(Ordering::Relaxed);
            check(b"semget", first >= 0, first as i64)?;
            for i in 1..PROCS {
                let id = ids[i * KEYS + k].load(Ordering::Relaxed);
                check(b"same id", id == first, k as i64)?;
            }
        }
        Ok(())
    })();
    unshare(ids);
    r?;
    let res = shared(PROCS * KEYS);
    let ran = in_children(create_excl, res);
    rmid_keys(KEY_BASE + KEYS as i32);
    let r = (|| {
        check(b"excl children", ran, 0)?;
        for k in 0..KEYS {
            let rs = (0..PROCS).map(|i| res[i * KEYS + k].load(Ordering::Relaxed) as i64);
            let won = rs.clone().filter(|&r| r >= 0).count();
            let lost = rs.filter(|&r| r == EEXIST).count();
            check(b"one creator", won == 1, won as i64)?;
            check(b"EEXIST", lost == PROCS - 1, lost as i64)?;
        }
        Ok(())
    })();
    unshare(res);
    r
}

fn more_checks() -> R {
    let key = KEY_BASE + 2 * KEYS as i32;
    let id = sys_semget(key, 2, IPC_CREAT | 0o600);
    check(b"semget", id >= 0, id)?;
    let more = sys_semget(key, 3, 0);
    let same = sys_semget(key, 1, 0);
    sys_semctl(id as i32, 0, IPC_RMID, 0);
    check(b"more sems", more == EINVAL, more)?;
    check(b"fewer sems", same == id, same)?;
    let shm = sys_shmget(key, 4096, IPC_CREAT | 0o600);
    check(b"shmget", shm >= 0, shm)?;
    let bigger = sys_shmget(key, 8192, 0);
    let smaller = sys_shmget(key, 100, 0);
    sys_shmctl(shm as i32, IPC_RMID, 0);
    check(b"bigger shm", bigger == EINVAL, bigger)?;
    check(b"smaller shm", smaller == shm, smaller)
}

fn set_efault() -> R {
    // An id nothing has; the buffer is checked first
    let bad = 0x7fff_fff0;
    let r = sys_msgctl(bad, IPC_SET, 8);
    check(b"msgctl", r == EFAULT, r)?;
    let r = sys_semctl(bad, 0, IPC_SET, 8);
    check(b"semctl", r == EFAULT, r)?;
    let r = sys_shmctl(bad, IPC_SET, 8);
    check(b"shmctl", r == EFAULT, r)
}
