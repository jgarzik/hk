//! Making a file system or mount read-only holds new writers off and
//! fails, changing nothing, while one holds write access (Linux
//! mnt_hold_writers, sb_prepare_remount_readonly, mnt_make_readonly).
//!
//! - REMOUNT_RO_BUSY: a writer open through a bind mount makes the read-only
//!   remount of the file system EBUSY; the file system stays writable;
//!   once it closes, the remount works and a write open is EROFS. A
//!   read-only bind remount of one mount needs only its own writers gone.
//! - REMOUNT_RO_RACE: while a writer kept open makes every read-only
//!   remount fail, a process opening files for writing never sees EROFS
//!   (no window where the file system looks read-only).

use core::sync::atomic::{AtomicI32, Ordering};

use crate::harness::{fail_num, report_step};
use hk_syscall::{
    LinuxStatFs, MAP_ANONYMOUS, MAP_SHARED, O_CREAT, O_WRONLY, PROT_READ, PROT_WRITE, sys_close,
    sys_exit, sys_fork, sys_mkdir, sys_mmap, sys_mount, sys_munmap, sys_open, sys_rmdir,
    sys_sched_yield, sys_statfs, sys_umount2, sys_unlink, sys_wait4, sys_write,
};

const MS_RDONLY: u64 = 1;
const MS_REMOUNT: u64 = 32;
const MS_BIND: u64 = 4096;
const ST_RDONLY: i64 = 1;
const EBUSY: i64 = -16;
const EROFS: i64 = -30;
const A: &[u8] = b"/tmp/rmro\0";
const B: &[u8] = b"/tmp/rmro_b\0";

pub fn run_tests() {
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777);
    sys_mkdir(A.as_ptr(), 0o755);
    sys_mkdir(B.as_ptr(), 0o755);
    let m = sys_mount(b"none\0".as_ptr(), A.as_ptr(), b"tmpfs\0".as_ptr(), 0, 0);
    let m = if m == 0 {
        m
    } else {
        sys_mount(b"none\0".as_ptr(), A.as_ptr(), b"ramfs\0".as_ptr(), 0, 0)
    };
    let b = sys_mount(A.as_ptr(), B.as_ptr(), core::ptr::null(), MS_BIND, 0);
    if m == 0 && b == 0 {
        report_step(b"REMOUNT_RO_BUSY", remount_ro_busy());
        report_step(b"REMOUNT_RO_RACE", remount_ro_race());
    } else {
        fail_num(b"REMOUNT_RO_BUSY:FAIL mount got ", m.min(b));
    }
    sys_umount2(B.as_ptr(), 0);
    sys_umount2(A.as_ptr(), 0);
    sys_rmdir(B.as_ptr());
    sys_rmdir(A.as_ptr());
}

fn remount(target: &[u8], flags: u64) -> i64 {
    sys_mount(
        core::ptr::null(),
        target.as_ptr(),
        core::ptr::null(),
        MS_REMOUNT | flags,
        0,
    )
}

fn rdonly(target: &[u8]) -> bool {
    // SAFETY: LinuxStatFs is plain integers, valid all-zero
    let mut st: LinuxStatFs = unsafe { core::mem::zeroed() };
    sys_statfs(target.as_ptr(), &mut st) == 0 && st.f_flags & ST_RDONLY != 0
}

fn open_w(path: &[u8]) -> i64 {
    sys_open(path.as_ptr(), O_CREAT | O_WRONLY, 0o644)
}

fn remount_ro_busy() -> i64 {
    let fa = b"/tmp/rmro/f\0";
    let fb = b"/tmp/rmro_b/f\0";
    // A writer through the bind mount
    let w = open_w(fb);
    if w < 0 {
        return 1;
    }
    if remount(A, MS_RDONLY) != EBUSY {
        return 2;
    }
    if rdonly(A) || sys_write(w as u64, b"x".as_ptr(), 1) != 1 {
        return 3;
    }
    // Only B's own writers matter to a read-only bind remount of A
    if remount(A, MS_BIND | MS_RDONLY) != 0 {
        return 4;
    }
    if open_w(fa) != EROFS {
        return 5;
    }
    remount(A, MS_BIND);
    sys_close(w as u64);
    if remount(A, MS_RDONLY) != 0 {
        return 6;
    }
    if open_w(fb) != EROFS {
        return 7;
    }
    if remount(A, 0) != 0 {
        return 8;
    }
    sys_unlink(fa.as_ptr());
    0
}

const RACE_OPENS: i32 = 2000;

fn remount_ro_race() -> i64 {
    let keep = open_w(b"/tmp/rmro/keep\0");
    let p = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0,
    );
    if keep < 0 || p <= 0 {
        return 90;
    }
    // [0]: the opener is done; [1]: a bad open's result
    // SAFETY: a fresh MAP_SHARED page of 2 i32s, unmapped below
    let sh = unsafe { core::slice::from_raw_parts(p as *const AtomicI32, 2) };
    let pid = sys_fork();
    if pid == 0 {
        for _ in 0..RACE_OPENS {
            let fd = open_w(b"/tmp/rmro_b/race\0");
            if fd < 0 {
                sh[1].store(fd as i32, Ordering::Relaxed);
                break;
            }
            sys_close(fd as u64);
        }
        sh[0].store(1, Ordering::Release);
        sys_exit(0);
    }
    let mut remount_ok = 0;
    while sh[0].load(Ordering::Acquire) == 0 {
        if remount(A, MS_RDONLY) == 0 {
            remount_ok += 1;
            remount(A, 0);
        }
        sys_sched_yield();
    }
    let mut ws = 0;
    sys_wait4(pid, &mut ws, 0, 0);
    let bad = sh[1].load(Ordering::Relaxed) as i64;
    sys_munmap(p as u64, 4096);
    sys_close(keep as u64);
    sys_unlink(b"/tmp/rmro/keep\0".as_ptr());
    sys_unlink(b"/tmp/rmro/race\0".as_ptr());
    if remount_ok != 0 {
        return 1;
    }
    if bad != 0 {
        return 10 - bad;
    }
    0
}
