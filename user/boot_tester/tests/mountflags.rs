//! mount(2) permission and per-mount flags (Linux path_mount):
//! CAP_SYS_ADMIN for mount/umount, MS_RDONLY (EROFS) and MS_REMOUNT,
//! MS_NOEXEC (execve EACCES), MS_NODEV (device open EACCES), statfs
//! f_flags

use super::helpers::{host_mode, print, print_num, println};
use hk_syscall::{
    sys_chown, sys_link, sys_mmap, sys_mprotect, sys_munmap, sys_removexattr, sys_rename, sys_setxattr,
    sys_symlink, sys_utimensat, MAP_PRIVATE, O_TRUNC, PROT_READ, AT_FDCWD,
    sys_chmod, sys_close, sys_execve, sys_exit, sys_fork, sys_mkdir, sys_mknod, sys_mount,
    sys_open, sys_read, sys_rmdir, sys_setresgid, sys_setresuid, sys_statfs, sys_truncate,
    sys_umount2, sys_unlink, sys_wait4, sys_write, LinuxStatFs, O_CREAT, O_RDONLY, O_WRONLY,
};

const EPERM: i64 = -1;
const EACCES: i64 = -13;
const EINVAL: i64 = -22;
const EROFS: i64 = -30;
const EBUSY: i64 = -16;
const PROT_EXEC: u32 = 4;

const MS_RDONLY: u64 = 1;
const MS_NODEV: u64 = 4;
const MS_NOEXEC: u64 = 8;
const MS_REMOUNT: u64 = 32;
const MS_MOVE: u64 = 8192;
const ST_RDONLY: i64 = 1;
const ST_NODEV: i64 = 4;
const ST_NOEXEC: i64 = 8;
const S_IFCHR: u32 = 0o020000;

pub fn run_tests() {
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777);
    test_eperm();
    test_rdonly();
    test_noexec();
    test_nodev();
    test_unsupported();
    test_ro_ops();
    test_remount_busy();
    test_noexec_mmap();
}

/// Every modifying syscall on a read-only mount is EROFS
fn test_ro_ops() {
    let n = b"MOUNT_RO_OPS";
    let mp = b"/tmp/mnt_rops\0";
    sys_mkdir(mp.as_ptr(), 0o755);
    let mut f = chk(n, b"mount", ramfs(mp, 0), 0);
    let fd = sys_open(b"/tmp/mnt_rops/f\0".as_ptr(), O_CREAT | O_WRONLY, 0o644);
    sys_close(fd as u64);
    sys_mkdir(b"/tmp/mnt_rops/d\0".as_ptr(), 0o755);
    f += chk(n, b"remount ro", remount(mp, MS_RDONLY), 0);
    let p = |s: &'static [u8]| s.as_ptr();
    let ops: [(&[u8], i64); 15] = [
        (b"creat", sys_open(p(b"/tmp/mnt_rops/g\0"), O_CREAT | O_WRONLY, 0o644)),
        (b"rdonly trunc", sys_open(p(b"/tmp/mnt_rops/f\0"), O_RDONLY | O_TRUNC, 0)),
        (b"rdwr", sys_open(p(b"/tmp/mnt_rops/f\0"), hk_syscall::O_RDWR, 0)),
        (b"mkdir", sys_mkdir(p(b"/tmp/mnt_rops/e\0"), 0o755)),
        (b"mknod", sys_mknod(p(b"/tmp/mnt_rops/n\0"), 0o100644, 0)),
        (b"symlink", sys_symlink(p(b"f\0"), p(b"/tmp/mnt_rops/s\0"))),
        (b"link", sys_link(p(b"/tmp/mnt_rops/f\0"), p(b"/tmp/mnt_rops/h\0"))),
        (b"unlink", sys_unlink(p(b"/tmp/mnt_rops/f\0"))),
        (b"rmdir", sys_rmdir(p(b"/tmp/mnt_rops/d\0"))),
        (b"rename", sys_rename(p(b"/tmp/mnt_rops/f\0"), p(b"/tmp/mnt_rops/r\0"))),
        (b"chmod", sys_chmod(p(b"/tmp/mnt_rops/f\0"), 0o600)),
        (b"chown", sys_chown(p(b"/tmp/mnt_rops/f\0"), 0, 0)),
        (b"utimens", sys_utimensat(AT_FDCWD, p(b"/tmp/mnt_rops/f\0"), core::ptr::null(), 0)),
        (b"setxattr", sys_setxattr(p(b"/tmp/mnt_rops/f\0"), p(b"user.x\0"), p(b"v"), 1, 0)),
        (b"removexattr", sys_removexattr(p(b"/tmp/mnt_rops/f\0"), p(b"user.x\0"))),
    ];
    for (why, got) in ops {
        f += chk(n, why, got, EROFS);
    }
    f += chk(n, b"truncate", sys_truncate(p(b"/tmp/mnt_rops/f\0"), 0), EROFS);
    remount(mp, 0);
    sys_unlink(p(b"/tmp/mnt_rops/f\0"));
    sys_rmdir(p(b"/tmp/mnt_rops/d\0"));
    sys_umount2(mp.as_ptr(), 0);
    sys_rmdir(mp.as_ptr());
    done(n, f);
}

/// rw -> ro remount fails with EBUSY (nothing changed) while a file is
/// open for writing; succeeds after it is closed
fn test_remount_busy() {
    let n = b"MOUNT_REMOUNT_BUSY";
    let mp = b"/tmp/mnt_busy\0";
    sys_mkdir(mp.as_ptr(), 0o755);
    let mut f = chk(n, b"mount", ramfs(mp, 0), 0);
    let fd = sys_open(b"/tmp/mnt_busy/f\0".as_ptr(), O_CREAT | O_WRONLY, 0o644);
    f += chk(n, b"remount ro busy", remount(mp, MS_RDONLY), EBUSY);
    f += chk(n, b"still rw", st_flags(mp) & ST_RDONLY, 0);
    f += chk(n, b"write", sys_write(fd as u64, b"x".as_ptr(), 1), 1);
    sys_close(fd as u64);
    f += chk(n, b"remount ro", remount(mp, MS_RDONLY), 0);
    remount(mp, 0);
    sys_unlink(b"/tmp/mnt_busy/f\0".as_ptr());
    sys_umount2(mp.as_ptr(), 0);
    sys_rmdir(mp.as_ptr());
    done(n, f);
}

/// PROT_EXEC of a file on a noexec mount: mmap EPERM, mprotect EACCES
fn test_noexec_mmap() {
    let n = b"MOUNT_NOEXEC_MMAP";
    let mp = b"/tmp/mnt_nxm\0";
    let file = b"/tmp/mnt_nxm/f\0";
    sys_mkdir(mp.as_ptr(), 0o755);
    let mut f = chk(n, b"mount", ramfs(mp, MS_NOEXEC), 0);
    let fd = sys_open(file.as_ptr(), O_CREAT | O_WRONLY, 0o755);
    let page = [0u8; 4096];
    sys_write(fd as u64, page.as_ptr(), 4096);
    sys_close(fd as u64);
    let fd = sys_open(file.as_ptr(), O_RDONLY, 0);
    let r = sys_mmap(0, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd as i32, 0);
    f += chk(n, b"mmap exec", r, EPERM);
    let a = sys_mmap(0, 4096, PROT_READ, MAP_PRIVATE, fd as i32, 0);
    f += chk(n, b"mmap read", (a > 0) as i64, 1);
    if a > 0 {
        f += chk(n, b"mprotect exec", sys_mprotect(a as u64, 4096, PROT_READ | PROT_EXEC), EACCES);
        sys_munmap(a as u64, 4096);
    }
    sys_close(fd as u64);
    sys_unlink(file.as_ptr());
    sys_umount2(mp.as_ptr(), 0);
    sys_rmdir(mp.as_ptr());
    done(n, f);
}

/// Child-side check: prints the mismatch, returns 1 on failure
fn chk(name: &[u8], why: &[u8], got: i64, want: i64) -> u32 {
    if got == want {
        return 0;
    }
    print(name);
    print(b":FAIL ");
    print(why);
    print(b" got ");
    print_num(got);
    print(b" want ");
    print_num(want);
    println(b"");
    1
}

fn done(name: &[u8], fails: u32) {
    if fails == 0 {
        print(name);
        println(b":OK");
    }
}

fn ramfs(target: &[u8], flags: u64) -> i64 {
    sys_mount(b"none\0".as_ptr(), target.as_ptr(), b"ramfs\0".as_ptr(), flags, 0)
}

fn remount(target: &[u8], flags: u64) -> i64 {
    sys_mount(core::ptr::null(), target.as_ptr(), core::ptr::null(), MS_REMOUNT | flags, 0)
}

fn st_flags(path: &[u8]) -> i64 {
    let mut st: LinuxStatFs = unsafe { core::mem::zeroed() };
    if sys_statfs(path.as_ptr(), &mut st) != 0 {
        return -1;
    }
    st.f_flags
}

/// mount/umount2 without CAP_SYS_ADMIN: EPERM (after the lookup)
fn test_eperm() {
    sys_mkdir(b"/tmp/mnt_perm\0".as_ptr(), 0o755);
    let pid = sys_fork();
    if pid == 0 {
        if sys_setresgid(2000, 2000, 2000) != 0 || sys_setresuid(2000, 2000, 2000) != 0 {
            sys_exit(90);
        }
        let n = b"MOUNT_EPERM";
        let mut f = chk(n, b"mount", ramfs(b"/tmp/mnt_perm\0", 0), EPERM);
        f += chk(n, b"umount", sys_umount2(b"/proc\0".as_ptr(), 0), EPERM);
        sys_exit(f as u64);
    }
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    sys_rmdir(b"/tmp/mnt_perm\0".as_ptr());
    if st == 0 {
        println(b"MOUNT_EPERM:OK");
    } else if st >> 8 == 90 {
        println(b"MOUNT_EPERM:FAIL setresuid");
    }
}

/// MS_RDONLY: every change is EROFS, reads work; MS_REMOUNT switches
fn test_rdonly() {
    let n = b"MOUNT_RDONLY";
    let mp = b"/tmp/mnt_ro\0";
    sys_mkdir(mp.as_ptr(), 0o755);
    let mut f = chk(n, b"mount rw", ramfs(mp, 0), 0);
    let fd = sys_open(b"/tmp/mnt_ro/f\0".as_ptr(), O_CREAT | O_WRONLY, 0o644);
    sys_write(fd as u64, b"data".as_ptr(), 4);
    sys_close(fd as u64);
    f += chk(n, b"remount ro", remount(mp, MS_RDONLY), 0);
    f += chk(n, b"statfs ro", st_flags(mp) & ST_RDONLY, ST_RDONLY);
    let c = sys_open(b"/tmp/mnt_ro/new\0".as_ptr(), O_CREAT | O_WRONLY, 0o644);
    f += chk(n, b"create", c, EROFS);
    f += chk(n, b"mkdir", sys_mkdir(b"/tmp/mnt_ro/d\0".as_ptr(), 0o755), EROFS);
    f += chk(n, b"open wr", sys_open(b"/tmp/mnt_ro/f\0".as_ptr(), O_WRONLY, 0), EROFS);
    f += chk(n, b"unlink", sys_unlink(b"/tmp/mnt_ro/f\0".as_ptr()), EROFS);
    f += chk(n, b"chmod", sys_chmod(b"/tmp/mnt_ro/f\0".as_ptr(), 0o600), EROFS);
    f += chk(n, b"truncate", sys_truncate(b"/tmp/mnt_ro/f\0".as_ptr(), 0), EROFS);
    let r = sys_open(b"/tmp/mnt_ro/f\0".as_ptr(), O_RDONLY, 0);
    let mut buf = [0u8; 8];
    f += chk(n, b"read", sys_read(r as u64, buf.as_mut_ptr(), 8), 4);
    sys_close(r as u64);
    f += chk(n, b"remount rw", remount(mp, 0), 0);
    f += chk(n, b"statfs rw", st_flags(mp) & ST_RDONLY, 0);
    let c = sys_open(b"/tmp/mnt_ro/new\0".as_ptr(), O_CREAT | O_WRONLY, 0o644);
    f += chk(n, b"create rw", (c >= 0) as i64, 1);
    sys_close(c as u64);
    sys_unlink(b"/tmp/mnt_ro/new\0".as_ptr());
    sys_unlink(b"/tmp/mnt_ro/f\0".as_ptr());
    f += chk(n, b"umount", sys_umount2(mp.as_ptr(), 0), 0);
    sys_rmdir(mp.as_ptr());
    // A fresh read-only mount: creation fails from the start
    sys_mkdir(mp.as_ptr(), 0o755);
    f += chk(n, b"mount ro", ramfs(mp, MS_RDONLY), 0);
    f += chk(n, b"mkdir ro", sys_mkdir(b"/tmp/mnt_ro/d\0".as_ptr(), 0o755), EROFS);
    sys_umount2(mp.as_ptr(), 0);
    sys_rmdir(mp.as_ptr());
    done(n, f);
}

/// Copy /bin/boot_tester2 to `dst` (mode 0755)
fn copy_exe(dst: &[u8]) -> bool {
    let src = sys_open(b"/bin/boot_tester2\0".as_ptr(), O_RDONLY, 0);
    let out = sys_open(dst.as_ptr(), O_CREAT | O_WRONLY, 0o755);
    if src < 0 || out < 0 {
        return false;
    }
    let mut buf = [0u8; 512];
    loop {
        let r = sys_read(src as u64, buf.as_mut_ptr(), buf.len() as u64);
        if r <= 0 {
            break;
        }
        sys_write(out as u64, buf.as_ptr(), r as u64);
    }
    sys_close(src as u64);
    sys_close(out as u64);
    true
}

/// Exit status of a child that execs `path` (the exec errno if it fails)
fn exec_status(path: &[u8]) -> i64 {
    let pid = sys_fork();
    if pid == 0 {
        let argv: [*const u8; 2] = [b"boot_tester2\0".as_ptr(), core::ptr::null()];
        let envp: [*const u8; 1] = [core::ptr::null()];
        let r = sys_execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
        sys_exit((-r) as u64);
    }
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    ((st >> 8) & 0xff) as i64
}

/// MS_NOEXEC: execve EACCES; after remount without it the binary runs
fn test_noexec() {
    let n = b"MOUNT_NOEXEC";
    let mp = b"/tmp/mnt_nx\0";
    let exe = b"/tmp/mnt_nx/prog\0";
    sys_mkdir(mp.as_ptr(), 0o755);
    let mut f = chk(n, b"mount", ramfs(mp, 0), 0);
    f += chk(n, b"copy", copy_exe(exe) as i64, 1);
    f += chk(n, b"remount noexec", remount(mp, MS_NOEXEC), 0);
    f += chk(n, b"statfs", st_flags(mp) & ST_NOEXEC, ST_NOEXEC);
    f += chk(n, b"exec noexec", exec_status(exe), -EACCES);
    f += chk(n, b"remount exec", remount(mp, 0), 0);
    f += chk(n, b"exec", exec_status(exe), 123);
    sys_unlink(exe.as_ptr());
    sys_umount2(mp.as_ptr(), 0);
    sys_rmdir(mp.as_ptr());
    done(n, f);
}

/// MS_NODEV: opening a device node is EACCES; without it, it works
fn test_nodev() {
    let n = b"MOUNT_NODEV";
    let mp = b"/tmp/mnt_nd\0";
    let dev = b"/tmp/mnt_nd/null\0";
    sys_mkdir(mp.as_ptr(), 0o755);
    let mut f = chk(n, b"mount", ramfs(mp, MS_NODEV), 0);
    f += chk(n, b"statfs", st_flags(mp) & ST_NODEV, ST_NODEV);
    // /dev/null: major 1, minor 3
    f += chk(n, b"mknod", sys_mknod(dev.as_ptr(), S_IFCHR | 0o666, (1 << 8) | 3), 0);
    f += chk(n, b"open nodev", sys_open(dev.as_ptr(), O_WRONLY, 0), EACCES);
    f += chk(n, b"remount dev", remount(mp, 0), 0);
    let fd = sys_open(dev.as_ptr(), O_WRONLY, 0);
    f += chk(n, b"open dev", (fd >= 0) as i64, 1);
    sys_close(fd as u64);
    sys_unlink(dev.as_ptr());
    sys_umount2(mp.as_ptr(), 0);
    sys_rmdir(mp.as_ptr());
    done(n, f);
}

/// hk rejects flags it cannot honor instead of ignoring them (Linux
/// implements MS_MOVE, so this is hk-only)
fn test_unsupported() {
    if host_mode() {
        return;
    }
    let n = b"MOUNT_UNSUPPORTED";
    let mut f = chk(n, b"MS_MOVE", ramfs(b"/tmp\0", MS_MOVE), EINVAL);
    // A rejected remount changes nothing
    let mp = b"/tmp/mnt_uns\0";
    sys_mkdir(mp.as_ptr(), 0o755);
    f += chk(n, b"mount", ramfs(mp, MS_RDONLY | MS_NOEXEC), 0);
    f += chk(n, b"remount move", remount(mp, MS_MOVE), EINVAL);
    f += chk(n, b"flags kept", st_flags(mp) & (ST_RDONLY | ST_NOEXEC), ST_RDONLY | ST_NOEXEC);
    sys_umount2(mp.as_ptr(), 0);
    sys_rmdir(mp.as_ptr());
    done(n, f);
}
