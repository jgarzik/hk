//! mount(2) permission and per-mount flags (Linux path_mount):
//! CAP_SYS_ADMIN for mount/umount, MS_RDONLY (EROFS) and MS_REMOUNT,
//! MS_NOEXEC (execve EACCES), MS_NODEV (device open EACCES), statfs
//! f_flags

use crate::tests::harness::pass;
use crate::tests::helpers::{print, print_num, println};
use hk_syscall::{
    AT_FDCWD, LinuxStatFs, MAP_PRIVATE, O_CREAT, O_RDONLY, O_TRUNC, O_WRONLY, PROT_READ, sys_chmod,
    sys_chown, sys_close, sys_execve, sys_exit, sys_fork, sys_link, sys_mkdir, sys_mknod, sys_mmap,
    sys_mount, sys_mprotect, sys_munmap, sys_open, sys_read, sys_removexattr, sys_rename,
    sys_rmdir, sys_setresgid, sys_setresuid, sys_setxattr, sys_statfs, sys_symlink, sys_truncate,
    sys_umount2, sys_unlink, sys_utimensat, sys_wait4, sys_write,
};

const EPERM: i64 = -1;
const EACCES: i64 = -13;
const EROFS: i64 = -30;
const EBUSY: i64 = -16;
const PROT_EXEC: u32 = 4;

const MS_RDONLY: u64 = 1;
const MS_NODEV: u64 = 4;
const MS_NOEXEC: u64 = 8;
const MS_REMOUNT: u64 = 32;
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
    test_sync_nosymfollow();
    test_ro_ops();
    test_remount_busy();
    test_noexec_mmap();
    test_mountpoint_busy();
    test_noexec_mayexec();
    test_noexec_fd_passed();
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
        (
            b"creat",
            sys_open(p(b"/tmp/mnt_rops/g\0"), O_CREAT | O_WRONLY, 0o644),
        ),
        (
            b"rdonly trunc",
            sys_open(p(b"/tmp/mnt_rops/f\0"), O_RDONLY | O_TRUNC, 0),
        ),
        (
            b"rdwr",
            sys_open(p(b"/tmp/mnt_rops/f\0"), hk_syscall::O_RDWR, 0),
        ),
        (b"mkdir", sys_mkdir(p(b"/tmp/mnt_rops/e\0"), 0o755)),
        (b"mknod", sys_mknod(p(b"/tmp/mnt_rops/n\0"), 0o100644, 0)),
        (b"symlink", sys_symlink(p(b"f\0"), p(b"/tmp/mnt_rops/s\0"))),
        (
            b"link",
            sys_link(p(b"/tmp/mnt_rops/f\0"), p(b"/tmp/mnt_rops/h\0")),
        ),
        (b"unlink", sys_unlink(p(b"/tmp/mnt_rops/f\0"))),
        (b"rmdir", sys_rmdir(p(b"/tmp/mnt_rops/d\0"))),
        (
            b"rename",
            sys_rename(p(b"/tmp/mnt_rops/f\0"), p(b"/tmp/mnt_rops/r\0")),
        ),
        (b"chmod", sys_chmod(p(b"/tmp/mnt_rops/f\0"), 0o600)),
        (b"chown", sys_chown(p(b"/tmp/mnt_rops/f\0"), 0, 0)),
        (
            b"utimens",
            sys_utimensat(AT_FDCWD, p(b"/tmp/mnt_rops/f\0"), core::ptr::null(), 0),
        ),
        (
            b"setxattr",
            sys_setxattr(p(b"/tmp/mnt_rops/f\0"), p(b"user.x\0"), p(b"v"), 1, 0),
        ),
        (
            b"removexattr",
            sys_removexattr(p(b"/tmp/mnt_rops/f\0"), p(b"user.x\0")),
        ),
    ];
    for (why, got) in ops {
        f += chk(n, why, got, EROFS);
    }
    f += chk(
        n,
        b"truncate",
        sys_truncate(p(b"/tmp/mnt_rops/f\0"), 0),
        EROFS,
    );
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

/// A directory something is mounted on cannot be removed, renamed or
/// renamed over (Linux vfs_rmdir / vfs_rename is_local_mountpoint:
/// EBUSY); after the umount it can
fn test_mountpoint_busy() {
    let n = b"MOUNT_MOUNTPOINT_BUSY";
    let mp = b"/tmp/mnt_mp\0";
    let other = b"/tmp/mnt_mp_other\0";
    sys_mkdir(mp.as_ptr(), 0o755);
    sys_mkdir(other.as_ptr(), 0o755);
    let mut f = chk(n, b"mount", ramfs(mp, 0), 0);
    f += chk(n, b"rmdir", sys_rmdir(mp.as_ptr()), EBUSY);
    f += chk(
        n,
        b"rename away",
        sys_rename(mp.as_ptr(), b"/tmp/mnt_mp2\0".as_ptr()),
        EBUSY,
    );
    f += chk(
        n,
        b"rename over",
        sys_rename(other.as_ptr(), mp.as_ptr()),
        EBUSY,
    );
    f += chk(n, b"umount", sys_umount2(mp.as_ptr(), 0), 0);
    f += chk(
        n,
        b"rename over after",
        sys_rename(other.as_ptr(), mp.as_ptr()),
        0,
    );
    f += chk(n, b"rmdir after", sys_rmdir(mp.as_ptr()), 0);
    sys_rmdir(other.as_ptr());
    sys_rmdir(b"/tmp/mnt_mp2\0".as_ptr());
    // Still busy after a rename of its parent directory
    let pa = b"/tmp/mnt_pa\0";
    let pb = b"/tmp/mnt_pb\0";
    let m = b"/tmp/mnt_pb/m\0";
    sys_mkdir(pa.as_ptr(), 0o755);
    sys_mkdir(b"/tmp/mnt_pa/m\0".as_ptr(), 0o755);
    f += chk(n, b"mount in parent", ramfs(b"/tmp/mnt_pa/m\0", 0), 0);
    f += chk(n, b"rename parent", sys_rename(pa.as_ptr(), pb.as_ptr()), 0);
    f += chk(
        n,
        b"rmdir after parent rename",
        sys_rmdir(m.as_ptr()),
        EBUSY,
    );
    // The mount moved with its parent: unmounted at the new path
    f += chk(
        n,
        b"umount after parent rename",
        sys_umount2(m.as_ptr(), 0),
        0,
    );
    f += chk(n, b"rmdir after umount", sys_rmdir(m.as_ptr()), 0);
    sys_rmdir(pb.as_ptr());
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
        f += chk(
            n,
            b"mprotect exec",
            sys_mprotect(a as u64, 4096, PROT_READ | PROT_EXEC),
            EACCES,
        );
        sys_munmap(a as u64, 4096);
    }
    sys_close(fd as u64);
    sys_unlink(file.as_ptr());
    sys_umount2(mp.as_ptr(), 0);
    sys_rmdir(mp.as_ptr());
    done(n, f);
}

/// A file mapping made on a noexec mount never gets PROT_EXEC, even
/// after the mount is remounted exec (Linux do_mmap clears VM_MAYEXEC)
fn test_noexec_mayexec() {
    let n = b"MOUNT_NOEXEC_MAYEXEC";
    let mp = b"/tmp/mnt_may\0";
    let file = b"/tmp/mnt_may/f\0";
    sys_mkdir(mp.as_ptr(), 0o755);
    let mut f = chk(n, b"mount", ramfs(mp, MS_NOEXEC), 0);
    let fd = sys_open(file.as_ptr(), O_CREAT | O_WRONLY, 0o755);
    let page = [0u8; 4096];
    sys_write(fd as u64, page.as_ptr(), 4096);
    sys_close(fd as u64);
    let fd = sys_open(file.as_ptr(), O_RDONLY, 0);
    let a = sys_mmap(0, 4096, PROT_READ, MAP_PRIVATE, fd as i32, 0);
    f += chk(n, b"remount exec", remount(mp, 0), 0);
    if a > 0 {
        f += chk(
            n,
            b"mprotect exec",
            sys_mprotect(a as u64, 4096, PROT_READ | PROT_EXEC),
            EACCES,
        );
        sys_munmap(a as u64, 4096);
    } else {
        f += chk(n, b"mmap read", a, 0);
    }
    sys_close(fd as u64);
    sys_unlink(file.as_ptr());
    sys_umount2(mp.as_ptr(), 0);
    sys_rmdir(mp.as_ptr());
    done(n, f);
}

/// A file opened on a noexec mount in another mount namespace and
/// passed over SCM_RIGHTS keeps that mount's noexec: mmap PROT_EXEC of
/// it is EPERM here, where its directory is no mount at all (Linux
/// path_noexec on f_path.mnt)
fn test_noexec_fd_passed() {
    use crate::tests::net::sk::recv_msg;
    use crate::tests::net::unix::{got_fds, send_fds};
    const CLONE_NEWNS: u64 = 0x20000;
    let n = b"MOUNT_NOEXEC_FD_PASSED";
    let mp = b"/tmp/mnt_nxp\0";
    sys_mkdir(mp.as_ptr(), 0o755);
    let mut sv = [-1i32; 2];
    hk_syscall::sys_socketpair(1, 1, 0, &mut sv);
    let pid = sys_fork();
    if pid == 0 {
        if hk_syscall::sys_unshare(CLONE_NEWNS) != 0 || ramfs(mp, MS_NOEXEC) != 0 {
            sys_exit(2);
        }
        let file = b"/tmp/mnt_nxp/f\0";
        let fd = sys_open(file.as_ptr(), O_CREAT | O_WRONLY, 0o755);
        let page = [0u8; 4096];
        sys_write(fd as u64, page.as_ptr(), 4096);
        sys_close(fd as u64);
        let fd = sys_open(file.as_ptr(), O_RDONLY, 0);
        send_fds(sv[1], b"f", &[fd as i32]);
        // Keep the namespace until the parent is done
        let mut c = [0u8; 1];
        sys_read(sv[1] as u64, c.as_mut_ptr(), 1);
        sys_exit(0);
    }
    let mut buf = [0u8; 8];
    let mut ctl = [0u8; 64];
    let (r, _, clen) = recv_msg(sv[0], &mut buf, &mut ctl, 0);
    let (fd, _) = got_fds(&ctl, clen);
    let mut f = chk(n, b"recv fd", (r == 1 && fd >= 0) as i64, 1);
    if fd >= 0 {
        let m = sys_mmap(0, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
        f += chk(n, b"mmap exec", m, EPERM);
        if m > 0 {
            sys_munmap(m as u64, 4096);
        }
        sys_close(fd as u64);
    }
    sys_write(sv[0] as u64, b"x".as_ptr(), 1);
    let mut st = 0i32;
    sys_wait4(pid, &mut st, 0, 0);
    f += chk(n, b"child", st as i64, 0);
    sys_close(sv[0] as u64);
    sys_close(sv[1] as u64);
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
    sys_mount(
        b"none\0".as_ptr(),
        target.as_ptr(),
        b"ramfs\0".as_ptr(),
        flags,
        0,
    )
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
        pass(b"MOUNT_EPERM");
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
    f += chk(
        n,
        b"mkdir",
        sys_mkdir(b"/tmp/mnt_ro/d\0".as_ptr(), 0o755),
        EROFS,
    );
    f += chk(
        n,
        b"open wr",
        sys_open(b"/tmp/mnt_ro/f\0".as_ptr(), O_WRONLY, 0),
        EROFS,
    );
    f += chk(n, b"unlink", sys_unlink(b"/tmp/mnt_ro/f\0".as_ptr()), EROFS);
    f += chk(
        n,
        b"chmod",
        sys_chmod(b"/tmp/mnt_ro/f\0".as_ptr(), 0o600),
        EROFS,
    );
    f += chk(
        n,
        b"truncate",
        sys_truncate(b"/tmp/mnt_ro/f\0".as_ptr(), 0),
        EROFS,
    );
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
    f += chk(
        n,
        b"mkdir ro",
        sys_mkdir(b"/tmp/mnt_ro/d\0".as_ptr(), 0o755),
        EROFS,
    );
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
    f += chk(
        n,
        b"mknod",
        sys_mknod(dev.as_ptr(), S_IFCHR | 0o666, (1 << 8) | 3),
        0,
    );
    f += chk(
        n,
        b"open nodev",
        sys_open(dev.as_ptr(), O_WRONLY, 0),
        EACCES,
    );
    f += chk(n, b"remount dev", remount(mp, 0), 0);
    let fd = sys_open(dev.as_ptr(), O_WRONLY, 0);
    f += chk(n, b"open dev", (fd >= 0) as i64, 1);
    sys_close(fd as u64);
    sys_unlink(dev.as_ptr());
    sys_umount2(mp.as_ptr(), 0);
    sys_rmdir(mp.as_ptr());
    done(n, f);
}

/// MOUNT_SYNC_NOSYMFOLLOW: MS_SYNCHRONOUS, MS_DIRSYNC and MS_NOSYMFOLLOW
/// mount (Linux SB_SYNCHRONOUS, SB_DIRSYNC, MNT_NOSYMFOLLOW) and show in
/// statfs (ST_SYNCHRONOUS, ST_NOSYMFOLLOW) and /proc/self/mounts; a
/// symlink on a nosymfollow mount is ELOOP to follow but still readable
fn test_sync_nosymfollow() {
    const MS_SYNCHRONOUS: u64 = 16;
    const MS_DIRSYNC: u64 = 128;
    const MS_NOSYMFOLLOW: u64 = 256;
    const ST_SYNCHRONOUS: i64 = 16;
    const ST_NOSYMFOLLOW: i64 = 0x2000;
    const ELOOP: i64 = -40;
    let n = b"MOUNT_SYNC_NOSYMFOLLOW";
    let mp = b"/tmp/mnt_uns\0";
    sys_mkdir(mp.as_ptr(), 0o755);
    let mut f = chk(n, b"MS_SYNCHRONOUS", ramfs(mp, MS_SYNCHRONOUS), 0);
    f += chk(
        n,
        b"statfs sync",
        st_flags(mp) & ST_SYNCHRONOUS,
        ST_SYNCHRONOUS,
    );
    f += chk(n, b"mounts sync", mounts_opt(b"/tmp/mnt_uns", b",sync"), 1);
    sys_umount2(mp.as_ptr(), 0);
    // A second mount of a superblock already mounted (sysfs) leaves its
    // flags alone (Linux applies them to a new superblock only)
    let r = sys_mount(
        b"sysfs\0".as_ptr(),
        mp.as_ptr(),
        b"sysfs\0".as_ptr(),
        MS_SYNCHRONOUS,
        0,
    );
    f += chk(n, b"sysfs again", r, 0);
    f += chk(n, b"sysfs kept", st_flags(b"/sys\0") & ST_SYNCHRONOUS, 0);
    sys_umount2(mp.as_ptr(), 0);
    f += chk(n, b"MS_DIRSYNC", ramfs(mp, MS_DIRSYNC), 0);
    f += chk(
        n,
        b"mounts dirsync",
        mounts_opt(b"/tmp/mnt_uns", b",dirsync"),
        1,
    );
    sys_umount2(mp.as_ptr(), 0);
    f += chk(n, b"MS_NOSYMFOLLOW", ramfs(mp, MS_NOSYMFOLLOW), 0);
    f += chk(
        n,
        b"mounts nosymfollow",
        mounts_opt(b"/tmp/mnt_uns", b",nosymfollow"),
        1,
    );
    f += chk(
        n,
        b"statfs nosymfollow",
        st_flags(mp) & ST_NOSYMFOLLOW,
        ST_NOSYMFOLLOW,
    );
    let target = b"/tmp/mnt_uns/t\0";
    let fd = sys_open(target.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    sys_close(fd as u64);
    sys_symlink(target.as_ptr(), b"/tmp/mnt_uns/l\0".as_ptr());
    let o = sys_open(b"/tmp/mnt_uns/l\0".as_ptr(), O_RDONLY, 0);
    if o >= 0 {
        sys_close(o as u64);
    }
    f += chk(n, b"follow", o, ELOOP);
    // fs.protected_symlinks decides before nosymfollow (Linux pick_link):
    // another user's link in a sticky directory is EACCES, not ELOOP
    sys_chmod(mp.as_ptr(), 0o1777);
    hk_syscall::sys_lchown(b"/tmp/mnt_uns/l\0".as_ptr(), 3000, 3000);
    f += chk(n, b"protected before nosymfollow", protected_follow(), -13);
    hk_syscall::sys_lchown(b"/tmp/mnt_uns/l\0".as_ptr(), 0, 0);
    let mut buf = [0u8; 64];
    let r = hk_syscall::sys_readlink(b"/tmp/mnt_uns/l\0".as_ptr(), buf.as_mut_ptr(), 64);
    f += chk(n, b"readlink", r, target.len() as i64 - 1);
    // Remount without it: following works again
    f += chk(n, b"remount", remount(mp, 0), 0);
    let o = sys_open(b"/tmp/mnt_uns/l\0".as_ptr(), O_RDONLY, 0);
    if o >= 0 {
        sys_close(o as u64);
    }
    f += chk(n, b"follow after remount", i64::from(o >= 0), 1);
    sys_umount2(mp.as_ptr(), 0);
    sys_rmdir(mp.as_ptr());
    done(n, f);
}

/// 1 if the /proc/self/mounts line of mount point `mp` has `opt` in its
/// options, 0 if not, -1 if there is no such line
fn mounts_opt(mp: &[u8], opt: &[u8]) -> i64 {
    let mut b = [0u8; 8192];
    let len = crate::tests::helpers::read_file(b"/proc/self/mounts\0", &mut b);
    let mut r = -1;
    for line in b[..len.max(0) as usize].split(|&c| c == b'\n') {
        let mut fields = line.split(|&c| c == b' ');
        if fields.nth(1) != Some(mp) {
            continue;
        }
        let opts = fields.nth(1).unwrap_or(&[]);
        r = i64::from(opts.windows(opt.len()).any(|w| w == opt));
    }
    r
}

/// With fs.protected_symlinks=1, uid 1000 follows /tmp/mnt_uns/l: the
/// errno
fn protected_follow() -> i64 {
    let knob = b"/proc/sys/fs/protected_symlinks\0";
    let set = |v: &[u8]| {
        let fd = sys_open(knob.as_ptr(), O_WRONLY, 0);
        sys_write(fd as u64, v.as_ptr(), 1);
        sys_close(fd as u64);
    };
    set(b"1");
    let pid = sys_fork();
    if pid == 0 {
        sys_setresgid(1000, 1000, 1000);
        sys_setresuid(1000, 1000, 1000);
        let o = sys_open(b"/tmp/mnt_uns/l\0".as_ptr(), O_RDONLY, 0);
        sys_exit(o.unsigned_abs() & 0xff);
    }
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    set(b"0");
    -i64::from((st >> 8) & 0xff)
}
