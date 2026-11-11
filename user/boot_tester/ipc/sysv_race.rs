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
//!
//! semop under the array lock (Linux ipc/sem.c perform_atomic_semop):
//! - SEM_DUPSOP: two -1s on one semaphore at 1 would block (EAGAIN with
//!   IPC_NOWAIT) and leave it at 1: repeated operations add up.
//! - SEM_NOWAIT_PER_OP: IPC_NOWAIT belongs to the operation that would
//!   block; on another one it does not stop the wait.
//! - SEM_ERRNO_ORDER: no operations or a negative semid is EINVAL.
//! - SEM_MUTEX_STRESS: four processes use a semaphore as a mutex around
//!   a shared counter; no increment is lost and the value ends at 1.
//! - SEM_GETALL_SUM: units move between two semaphores in atomic
//!   two-operation semops; every GETALL snapshot keeps their sum.
//!
//! SEM_UNDO (Linux struct sem_undo, exit_sem):
//! - SEM_UNDO_EXIT: a child's +3 with SEM_UNDO is undone when it exits.
//! - SEM_UNDO_SETVAL: SETVAL clears every adjustment of that semaphore,
//!   so the exit undoes nothing.
//! - SEM_UNDO_ERANGE: an adjustment past -32768 is ERANGE and changes
//!   nothing.
//! - SEM_UNDO_RMID: arrays with adjustments removed before the exit
//!   take their undo structures along (freeary): the removed id is
//!   EINVAL, a new array gets its own, and the exit undoes only the
//!   array still there.
//! - SEM_UNDO_WAKE: a SEM_UNDO decrement that slept and was completed
//!   by another process's increment records its adjustment: the exit
//!   gives the unit back.
//! - SEM_NCNT: GETNCNT and GETZCNT count the waiters blocked on that
//!   semaphore (Linux count_semcnt); IPC_RMID wakes them with EIDRM.
//! - SEM_MIXED_STRESS: single-operation semops on one semaphore (the
//!   per-semaphore fast path) run while blocking two-operation semops
//!   on others keep switching the array into complex mode: the mutex
//!   loses no increment, no waiter misses its wakeup (2 s timeouts),
//!   and the moved units are all there.
//!
//! Message queues (Linux ipc/msg.c, one lock over the queue's state):
//! - MSGCTL_QBYTES: an unprivileged owner may lower and raise qbytes up
//!   to MSGMNB; above it needs CAP_SYS_RESOURCE (EPERM), as
//!   msgctl_down.
//! - MSG_STAT_STRESS: while one process sends and another receives
//!   fixed-size messages, every IPC_STAT shows cbytes = qnum * size.

use core::sync::atomic::{AtomicI32, Ordering};

use crate::harness::{R, check, report_r};
use hk_syscall::{
    GETALL, GETNCNT, GETVAL, GETZCNT, IPC_CREAT, IPC_EXCL, IPC_NOWAIT, IPC_PRIVATE, IPC_RMID,
    IPC_SET, IPC_STAT, MAP_ANONYMOUS, MAP_SHARED, PROT_READ, PROT_WRITE, SETVAL, Sembuf, Timespec,
    sys_clock_gettime, sys_exit, sys_fork, sys_mmap, sys_msgctl, sys_msgget, sys_msgrcv,
    sys_msgsnd, sys_munmap, sys_semctl, sys_semget, sys_semop, sys_semtimedop, sys_setuid,
    sys_shmctl, sys_shmget, sys_wait4,
};

const EINVAL: i64 = -22;
const EEXIST: i64 = -17;
const EFAULT: i64 = -14;
const EAGAIN: i64 = -11;
const PROCS: usize = 4;
const KEYS: usize = 100;
const KEY_BASE: i32 = 0x4c00_0000;

pub fn run_tests() {
    report_r(b"IPC_GET_RACE", get_race());
    report_r(b"IPC_MORE_CHECKS", more_checks());
    report_r(b"IPC_SET_EFAULT", set_efault());
    report_r(b"SEM_DUPSOP", sem_dupsop());
    report_r(b"SEM_NOWAIT_PER_OP", sem_nowait_per_op());
    report_r(b"SEM_ERRNO_ORDER", sem_errno_order());
    report_r(b"SEM_MUTEX_STRESS", sem_mutex_stress());
    report_r(b"SEM_GETALL_SUM", sem_getall_sum());
    report_r(b"SEM_UNDO_EXIT", sem_undo(undo_exit_child, 0));
    report_r(b"SEM_UNDO_SETVAL", sem_undo(undo_setval_child, 5));
    report_r(b"SEM_UNDO_ERANGE", sem_undo(undo_erange_child, 0));
    report_r(b"SEM_UNDO_RMID", sem_undo(undo_rmid_child, 1));
    report_r(b"SEM_UNDO_WAKE", sem_undo_wake());
    report_r(b"SEM_NCNT", sem_ncnt());
    report_r(b"SEM_MIXED_STRESS", sem_mixed_stress());
    report_r(b"MSGCTL_QBYTES", msgctl_qbytes());
    report_r(b"MSG_STAT_STRESS", msg_stat_stress());
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

/// A private semaphore set of `n`, removed by the guard
struct Set(i32);

impl Set {
    fn new(n: i32) -> Self {
        Set(sys_semget(IPC_PRIVATE, n, IPC_CREAT | 0o600) as i32)
    }
    fn set(&self, num: i32, v: u64) -> i64 {
        sys_semctl(self.0, num, SETVAL, v)
    }
    fn get(&self, num: i32) -> i64 {
        sys_semctl(self.0, num, GETVAL, 0)
    }
    fn op(&self, sops: &[Sembuf]) -> i64 {
        sys_semop(self.0, sops.as_ptr(), sops.len())
    }
}

impl Drop for Set {
    fn drop(&mut self) {
        sys_semctl(self.0, 0, IPC_RMID, 0);
    }
}

fn mono_ms() -> i64 {
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    sys_clock_gettime(1, &mut ts);
    ts.tv_sec * 1000 + ts.tv_nsec / 1_000_000
}

fn sem_dupsop() -> R {
    let set = Set::new(1);
    check(b"semget", set.0 >= 0, set.0 as i64)?;
    set.set(0, 1);
    let nw = IPC_NOWAIT as i16;
    let r = set.op(&[Sembuf::new(0, -1, nw), Sembuf::new(0, -1, nw)]);
    check(b"two -1", r == EAGAIN, r)?;
    check(b"value kept", set.get(0) == 1, set.get(0))?;
    let r = set.op(&[Sembuf::new(0, 2, 0), Sembuf::new(0, -3, 0)]);
    check(b"+2 -3", r == 0, r)?;
    check(b"value 0", set.get(0) == 0, set.get(0))
}

fn sem_nowait_per_op() -> R {
    let set = Set::new(2);
    check(b"semget", set.0 >= 0, set.0 as i64)?;
    // sem 0 is 0: its -1 blocks; IPC_NOWAIT is only on sem 1's +1
    let sops = [Sembuf::new(0, -1, 0), Sembuf::new(1, 1, IPC_NOWAIT as i16)];
    let ts = Timespec {
        tv_sec: 0,
        tv_nsec: 60_000_000,
    };
    let t0 = mono_ms();
    let r = sys_semtimedop(set.0, sops.as_ptr(), 2, &ts);
    let waited = mono_ms() - t0;
    check(b"timed out", r == EAGAIN, r)?;
    check(b"waited", waited >= 40, waited)?;
    check(b"sem 1 unchanged", set.get(1) == 0, set.get(1))
}

fn sem_errno_order() -> R {
    let set = Set::new(1);
    let sop = [Sembuf::new(0, 1, 0)];
    let r = sys_semop(set.0, sop.as_ptr(), 0);
    check(b"nsops 0", r == EINVAL, r)?;
    let r = sys_semop(-1, sop.as_ptr(), 1);
    check(b"semid -1", r == EINVAL, r)
}

const ROUNDS: usize = 2000;

fn mutex_child(i: usize, out: &[AtomicI32]) {
    let id = out[0].load(Ordering::Relaxed);
    let p = [Sembuf::new(0, -1, 0)];
    let v = [Sembuf::new(0, 1, 0)];
    for _ in 0..ROUNDS {
        if sys_semop(id, p.as_ptr(), 1) != 0 {
            out[2 + i].store(1, Ordering::Relaxed);
            return;
        }
        // A plain read-modify-write: only the semaphore orders it
        let c = out[1].load(Ordering::Relaxed);
        out[1].store(c + 1, Ordering::Relaxed);
        sys_semop(id, v.as_ptr(), 1);
    }
}

fn sem_mutex_stress() -> R {
    let set = Set::new(1);
    check(b"semget", set.0 >= 0, set.0 as i64)?;
    set.set(0, 1);
    let sh = shared(2 + PROCS);
    sh[0].store(set.0, Ordering::Relaxed);
    let ran = in_children(mutex_child, sh);
    let count = sh[1].load(Ordering::Relaxed) as i64;
    let failed = (0..PROCS).any(|i| sh[2 + i].load(Ordering::Relaxed) != 0);
    unshare(sh);
    check(b"children", ran && !failed, 0)?;
    check(b"count", count == (PROCS * ROUNDS) as i64, count)?;
    check(b"value 1", set.get(0) == 1, set.get(0))
}

const UNITS: i32 = 100;

fn transfer_child(i: usize, out: &[AtomicI32]) {
    let id = out[0].load(Ordering::Relaxed);
    let (a, b) = if i % 2 == 0 { (0, 1) } else { (1, 0) };
    let mv = [Sembuf::new(a, -1, IPC_NOWAIT as i16), Sembuf::new(b, 1, 0)];
    for _ in 0..ROUNDS {
        sys_semop(id, mv.as_ptr(), 2);
    }
}

fn sem_getall_sum() -> R {
    let set = Set::new(2);
    check(b"semget", set.0 >= 0, set.0 as i64)?;
    set.set(0, UNITS as u64);
    let sh = shared(1);
    sh[0].store(set.0, Ordering::Relaxed);
    let mut pids = [0i64; 2];
    for (i, p) in pids.iter_mut().enumerate() {
        *p = sys_fork();
        if *p == 0 {
            transfer_child(i, sh);
            sys_exit(0);
        }
    }
    let mut bad = None;
    for _ in 0..ROUNDS {
        let mut v = [0u16; 2];
        sys_semctl(set.0, 0, GETALL, v.as_mut_ptr() as u64);
        let sum = v[0] as i32 + v[1] as i32;
        if sum != UNITS {
            bad = Some(sum);
            break;
        }
    }
    for p in pids {
        let mut ws = 0;
        sys_wait4(p, &mut ws, 0, 0);
    }
    unshare(sh);
    check(b"sum", bad.is_none(), bad.unwrap_or(0) as i64)
}

const UNDO: i16 = hk_syscall::SEM_UNDO;

/// Run `child(semid)` in a child (its exit status is its verdict), then
/// expect the semaphore at `want` after its exit undo
fn sem_undo(child: fn(i32) -> u64, want: i64) -> R {
    let set = Set::new(1);
    check(b"semget", set.0 >= 0, set.0 as i64)?;
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(child(set.0));
    }
    let mut ws = 0;
    sys_wait4(pid, &mut ws, 0, 0);
    check(b"child", ws == 0, (ws >> 8) as i64)?;
    check(b"value", set.get(0) == want, set.get(0))
}

fn undo_exit_child(id: i32) -> u64 {
    let op = [Sembuf::new(0, 3, UNDO)];
    (sys_semop(id, op.as_ptr(), 1) != 0) as u64
}

fn undo_setval_child(id: i32) -> u64 {
    let op = [Sembuf::new(0, 1, UNDO)];
    if sys_semop(id, op.as_ptr(), 1) != 0 {
        return 1;
    }
    (sys_semctl(id, 0, SETVAL, 5) != 0) as u64 * 2
}

fn undo_erange_child(id: i32) -> u64 {
    // Adjustment -32767, then the value back to 0 without undo
    let up = [Sembuf::new(0, 32767, UNDO)];
    let down = [Sembuf::new(0, -32767, 0)];
    let one = [Sembuf::new(0, 1, UNDO)];
    if sys_semop(id, up.as_ptr(), 1) != 0 || sys_semop(id, down.as_ptr(), 1) != 0 {
        return 1;
    }
    // -32768 is the last adjustment allowed
    if sys_semop(id, one.as_ptr(), 1) != 0 {
        return 2;
    }
    if sys_semop(id, one.as_ptr(), 1) != -34 {
        return 3;
    }
    // The failed semop changed nothing: value 1; the exit adds -32768
    // and clamps at 0
    (sys_semctl(id, 0, GETVAL, 0) != 1) as u64 * 4
}

fn undo_rmid_child(id: i32) -> u64 {
    let one = |n| [Sembuf::new(n, 1, UNDO)];
    let a = Set::new(2);
    if a.0 < 0 || a.op(&one(1)) != 0 {
        return 1;
    }
    // +2 with SEM_UNDO and +1 without on the parent's array
    let two = [Sembuf::new(0, 2, UNDO)];
    let plain = [Sembuf::new(0, 1, 0)];
    if sys_semop(id, two.as_ptr(), 1) != 0 || sys_semop(id, plain.as_ptr(), 1) != 0 {
        return 2;
    }
    if sys_semctl(a.0, 0, IPC_RMID, 0) != 0 {
        return 3;
    }
    if a.op(&one(1)) != EINVAL {
        return 4;
    }
    // A new array gets its own undo structure; removed (its drop)
    // before the exit too
    let b = Set::new(1);
    if b.0 < 0 || b.op(&one(0)) != 0 || b.get(0) != 1 {
        return 5;
    }
    0
}

fn sem_undo_wake() -> R {
    let set = Set::new(1);
    check(b"semget", set.0 >= 0, set.0 as i64)?;
    let pid = sys_fork();
    if pid == 0 {
        let down = [Sembuf::new(0, -1, UNDO)];
        sys_exit((timed(set.0, &down) != 0) as u64);
    }
    let t0 = mono_ms();
    while sys_semctl(set.0, 0, GETNCNT, 0) != 1 && mono_ms() - t0 < 2000 {
        let ts = Timespec {
            tv_sec: 0,
            tv_nsec: 5_000_000,
        };
        hk_syscall::sys_nanosleep(&ts, core::ptr::null_mut());
    }
    let r = set.op(&[Sembuf::new(0, 1, 0)]);
    let mut ws = 0;
    sys_wait4(pid, &mut ws, 0, 0);
    check(b"up", r == 0, r)?;
    check(b"child", ws == 0, (ws >> 8) as i64)?;
    // Taken by the child, given back by its exit
    check(b"value", set.get(0) == 1, set.get(0))
}

/// Block in semop(`sem_op` on `num`); exit 0 on EIDRM
fn ncnt_child(id: i32, num: u16, sem_op: i16) -> ! {
    let op = [Sembuf::new(num, sem_op, 0)];
    let r = sys_semop(id, op.as_ptr(), 1);
    sys_exit(if r == -43 { 0 } else { 1 })
}

fn sem_ncnt() -> R {
    let set = Set::new(2);
    check(b"semget", set.0 >= 0, set.0 as i64)?;
    set.set(1, 1);
    let a = sys_fork();
    if a == 0 {
        ncnt_child(set.0, 0, -1);
    }
    let b = sys_fork();
    if b == 0 {
        ncnt_child(set.0, 1, 0);
    }
    let cnt = |cmd, num| sys_semctl(set.0, num, cmd, 0);
    // Both children asleep: wait (bounded) until they are counted
    let t0 = mono_ms();
    while (cnt(GETNCNT, 0) != 1 || cnt(GETZCNT, 1) != 1) && mono_ms() - t0 < 2000 {
        let ts = Timespec {
            tv_sec: 0,
            tv_nsec: 5_000_000,
        };
        hk_syscall::sys_nanosleep(&ts, core::ptr::null_mut());
    }
    let r = (|| {
        check(b"ncnt 0", cnt(GETNCNT, 0) == 1, cnt(GETNCNT, 0))?;
        check(b"zcnt 1", cnt(GETZCNT, 1) == 1, cnt(GETZCNT, 1))?;
        check(b"zcnt 0", cnt(GETZCNT, 0) == 0, cnt(GETZCNT, 0))?;
        check(b"ncnt 1", cnt(GETNCNT, 1) == 0, cnt(GETNCNT, 1))?;
        check(b"semnum", cnt(GETNCNT, 2) == EINVAL, cnt(GETNCNT, 2))
    })();
    sys_semctl(set.0, 0, IPC_RMID, 0);
    let mut ok = true;
    for p in [a, b] {
        let mut ws = 0;
        ok &= sys_wait4(p, &mut ws, 0, 0) == p && ws == 0;
    }
    r?;
    check(b"EIDRM", ok, 0)
}

const MIXED_ROUNDS: usize = 1000;

fn timed(id: i32, sops: &[Sembuf]) -> i64 {
    let ts = Timespec {
        tv_sec: 2,
        tv_nsec: 0,
    };
    sys_semtimedop(id, sops.as_ptr(), sops.len(), &ts)
}

/// Children 0 and 1: semaphore 0 as a mutex around out[1]; children 2
/// and 3: move units 2 -> 3 and 3 -> 2. A failed semop marks out[2+i].
fn mixed_child(i: usize, out: &[AtomicI32]) {
    let id = out[0].load(Ordering::Relaxed);
    let fail = |r: i64| {
        if r != 0 {
            out[2 + i].store(r as i32, Ordering::Relaxed);
        }
        r != 0
    };
    for _ in 0..MIXED_ROUNDS {
        if i < 2 {
            if fail(timed(id, &[Sembuf::new(0, -1, 0)])) {
                return;
            }
            let c = out[1].load(Ordering::Relaxed);
            out[1].store(c + 1, Ordering::Relaxed);
            if fail(timed(id, &[Sembuf::new(0, 1, 0)])) {
                return;
            }
        } else {
            let (a, b) = if i == 2 { (2, 3) } else { (3, 2) };
            if fail(timed(id, &[Sembuf::new(a, -1, 0), Sembuf::new(b, 1, 0)])) {
                return;
            }
        }
    }
}

fn sem_mixed_stress() -> R {
    let set = Set::new(4);
    check(b"semget", set.0 >= 0, set.0 as i64)?;
    set.set(0, 1);
    set.set(2, 50);
    let sh = shared(2 + PROCS);
    sh[0].store(set.0, Ordering::Relaxed);
    let ran = in_children(mixed_child, sh);
    let count = sh[1].load(Ordering::Relaxed) as i64;
    let failed = (0..PROCS)
        .map(|i| sh[2 + i].load(Ordering::Relaxed) as i64)
        .find(|&r| r != 0);
    unshare(sh);
    check(b"children", ran, 0)?;
    check(b"semop", failed.is_none(), failed.unwrap_or(0))?;
    check(b"count", count == (2 * MIXED_ROUNDS) as i64, count)?;
    check(b"mutex 1", set.get(0) == 1, set.get(0))?;
    let units = set.get(2) + set.get(3);
    check(b"units", units == 50, units)
}

/// struct msqid64_ds (120 bytes on x86-64 and arm64) as u64 words:
/// msg_cbytes, msg_qnum and msg_qbytes are words 9, 10 and 11
const MSQ_WORDS: usize = 15;
const MSG_CBYTES: usize = 9;
const MSG_QNUM: usize = 10;
const MSG_QBYTES: usize = 11;
const MSGMNB: u64 = 16384;
const EPERM: i64 = -1;

fn msq_stat(id: i32) -> Result<[u64; MSQ_WORDS], i64> {
    let mut ds = [0u64; MSQ_WORDS];
    let r = sys_msgctl(id, IPC_STAT, ds.as_mut_ptr() as u64);
    if r != 0 { Err(r) } else { Ok(ds) }
}

fn msq_set_qbytes(id: i32, qbytes: u64) -> i64 {
    let Ok(mut ds) = msq_stat(id) else {
        return -999;
    };
    ds[MSG_QBYTES] = qbytes;
    sys_msgctl(id, IPC_SET, ds.as_ptr() as u64)
}

/// As uid 1000, the owner of its own queue: lower, raise to MSGMNB,
/// past MSGMNB (EPERM)
fn qbytes_child() -> u64 {
    if sys_setuid(1000) != 0 {
        return 1;
    }
    let id = sys_msgget(IPC_PRIVATE, IPC_CREAT | 0o600) as i32;
    if id < 0 {
        return 2;
    }
    let verdict = (|| {
        if msq_set_qbytes(id, 100) != 0 || msq_stat(id).map(|d| d[MSG_QBYTES]) != Ok(100) {
            return 3;
        }
        if msq_set_qbytes(id, MSGMNB) != 0 {
            return 4;
        }
        if msq_set_qbytes(id, MSGMNB + 1) != EPERM {
            return 5;
        }
        if msq_stat(id).map(|d| d[MSG_QBYTES]) != Ok(MSGMNB) {
            return 6;
        }
        0
    })();
    sys_msgctl(id, IPC_RMID, 0);
    verdict
}

fn msgctl_qbytes() -> R {
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(qbytes_child());
    }
    let mut ws = 0;
    sys_wait4(pid, &mut ws, 0, 0);
    check(b"step", ws == 0, (ws >> 8) as i64)
}

const MSG_SIZE: usize = 32;

fn msg_child(i: usize, out: &[AtomicI32]) {
    let id = out[0].load(Ordering::Relaxed);
    let mut buf = [0u8; 8 + MSG_SIZE];
    buf[0] = 1; // mtype 1
    for _ in 0..ROUNDS {
        let r = if i == 0 {
            sys_msgsnd(id, buf.as_ptr(), MSG_SIZE, 0)
        } else {
            sys_msgrcv(id, buf.as_mut_ptr(), MSG_SIZE, 0, 0)
        };
        if r < 0 {
            out[1 + i].store(r as i32, Ordering::Relaxed);
            return;
        }
    }
}

fn msg_stat_stress() -> R {
    let id = sys_msgget(IPC_PRIVATE, IPC_CREAT | 0o600) as i32;
    check(b"msgget", id >= 0, id as i64)?;
    let sh = shared(3);
    sh[0].store(id, Ordering::Relaxed);
    let mut pids = [0i64; 2];
    for (i, p) in pids.iter_mut().enumerate() {
        *p = sys_fork();
        if *p == 0 {
            msg_child(i, sh);
            sys_exit(0);
        }
    }
    let mut bad = None;
    for _ in 0..ROUNDS {
        match msq_stat(id) {
            Ok(d) if d[MSG_CBYTES] == d[MSG_QNUM] * MSG_SIZE as u64 => {}
            Ok(d) => {
                bad = Some(d[MSG_CBYTES] as i64);
                break;
            }
            Err(e) => {
                bad = Some(e);
                break;
            }
        }
    }
    for p in pids {
        let mut ws = 0;
        sys_wait4(p, &mut ws, 0, 0);
    }
    let failed = (1..3)
        .map(|i| sh[i].load(Ordering::Relaxed))
        .find(|&r| r != 0);
    unshare(sh);
    sys_msgctl(id, IPC_RMID, 0);
    check(b"children", failed.is_none(), failed.unwrap_or(0) as i64)?;
    check(b"snapshot", bad.is_none(), bad.unwrap_or(0))
}
