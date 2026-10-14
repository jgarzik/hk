//! Discretionary access control (Linux generic_permission, may_open,
//! may_create, may_delete, setattr_prepare, capability overrides)
//!
//! Root sets up a tree under /tmp/dac; most checks run in a forked child
//! that switched to uid/gid 2000 (setresuid drops every capability).

use super::helpers::{print, print_num, println};
use hk_syscall::{
    sys_chdir, sys_chmod, sys_chown, sys_close, sys_execve, sys_exit, sys_faccessat, sys_fchmod,
    sys_fchown, sys_fork, sys_fstat, sys_link, sys_mkdir, sys_open, sys_rename, sys_rmdir, sys_setfsuid,
    sys_setresgid, sys_setresuid, sys_setxattr, sys_stat, sys_symlink, sys_truncate, sys_umask,
    sys_unlink, sys_utimensat, sys_wait4, sys_write, Stat, Timespec, AT_FDCWD, O_CREAT,
    O_DIRECTORY, O_EXCL, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY, UTIME_NOW, UTIME_OMIT,
};

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const ENOEXEC: i64 = -8;
const EACCES: i64 = -13;
const EEXIST: i64 = -17;
const EISDIR: i64 = -21;
const O_NOATIME: u32 = 0o1000000;
const R_OK: i32 = 4;
const W_OK: i32 = 2;
const X_OK: i32 = 1;

/// Unprivileged test identity (not the initramfs owner)
const USER: u32 = 2000;

pub fn run_tests() {
    setup();
    run(b"DAC_OPEN", t_open);
    run(b"DAC_SEARCH", t_search);
    run(b"DAC_CREATE", t_create);
    run(b"DAC_STICKY", t_sticky);
    run(b"DAC_EXEC", t_exec);
    run(b"DAC_CHMOD", t_chmod);
    run(b"DAC_CHOWN", t_chown);
    run(b"DAC_UTIMES", t_utimes);
    run(b"DAC_TRUNCATE", t_truncate);
    run(b"DAC_RENAME_DIR", t_rename_dir);
    run(b"DAC_OWNER_NEW", t_owner_new);
    run(b"DAC_XATTR", t_xattr);
    run(b"DAC_SUID_WRITE", t_suid_write);
    run_root(b"DAC_ROOT_OVERRIDE", t_root);
    run_root(b"DAC_FSUID", t_fsuid);
    run_root(b"DAC_CHOWN_KILL_SUID", t_root_chown);
    creat_race();
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// Child-side check: prints `NAME:FAIL why got X` on mismatch
fn chk(name: &[u8], why: &[u8], got: i64, want: i64) -> u64 {
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

fn wait_ok(name: &[u8], pid: i64) {
    let mut st = 0;
    sys_wait4(pid, &mut st, 0, 0);
    print(name);
    if st == 0 {
        println(b":OK");
    } else {
        print(b":FAIL child status ");
        print_num(st as i64);
        println(b"");
    }
}

/// Run `f` in a child that dropped to uid/gid USER (no capabilities)
fn run(name: &'static [u8], f: fn(&[u8]) -> u64) {
    let pid = sys_fork();
    if pid == 0 {
        if sys_setresgid(USER, USER, USER) != 0 || sys_setresuid(USER, USER, USER) != 0 {
            sys_exit(90);
        }
        sys_exit(f(name));
    }
    wait_ok(name, pid);
}

/// Run `f` in a child that stays root
fn run_root(name: &'static [u8], f: fn(&[u8]) -> u64) {
    let pid = sys_fork();
    if pid == 0 {
        sys_exit(f(name));
    }
    wait_ok(name, pid);
}

/// Create (or truncate) `path` with `data`, then force `mode` and owner
fn mkfile(path: &[u8], data: &[u8], mode: u32, uid: u32) {
    let fd = sys_open(path.as_ptr(), O_CREAT | O_WRONLY | O_TRUNC, 0o600);
    if fd >= 0 {
        sys_write(fd as u64, data.as_ptr(), data.len() as u64);
        sys_close(fd as u64);
    }
    sys_chown(path.as_ptr(), uid, uid);
    sys_chmod(path.as_ptr(), mode);
}

fn mkdirm(path: &[u8], mode: u32, uid: u32) {
    sys_mkdir(path.as_ptr(), 0o700);
    sys_chown(path.as_ptr(), uid, uid);
    sys_chmod(path.as_ptr(), mode);
}

fn mode_of(path: &[u8]) -> i64 {
    let mut st: Stat = unsafe { core::mem::zeroed() };
    if sys_stat(path.as_ptr(), &mut st) != 0 {
        return -1;
    }
    (st.st_mode & 0o7777) as i64
}

fn owner_of(path: &[u8]) -> (i64, i64) {
    let mut st: Stat = unsafe { core::mem::zeroed() };
    if sys_stat(path.as_ptr(), &mut st) != 0 {
        return (-1, -1);
    }
    (st.st_uid as i64, st.st_gid as i64)
}

/// open + close; returns the open result (fd >= 0 mapped to 0)
fn try_open(path: &[u8], flags: u32) -> i64 {
    let fd = sys_open(path.as_ptr(), flags, 0o666);
    if fd >= 0 {
        sys_close(fd as u64);
        return 0;
    }
    fd
}

fn exec(path: &[u8]) -> i64 {
    let argv: [*const u8; 2] = [path.as_ptr(), core::ptr::null()];
    let envp: [*const u8; 1] = [core::ptr::null()];
    sys_execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr())
}

fn setup() {
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777);
    mkdirm(b"/tmp/dac\0", 0o755, 0);
    mkfile(b"/tmp/dac/f600\0", b"secret", 0o600, 0);
    mkfile(b"/tmp/dac/f644\0", b"public", 0o644, 0);
    mkfile(b"/tmp/dac/f666\0", b"shared", 0o666, 0);
    mkfile(b"/tmp/dac/f000\0", b"locked", 0o000, 0);
    mkfile(b"/tmp/dac/x100\0", b"junk junk junk\n", 0o100, USER);
    mkfile(b"/tmp/dac/x755\0", b"junk junk junk\n", 0o755, 0);
    mkdirm(b"/tmp/dac/d700\0", 0o700, 0);
    mkfile(b"/tmp/dac/d700/in\0", b"x", 0o644, 0);
    mkdirm(b"/tmp/dac/sticky\0", 0o1777, 0);
    mkfile(b"/tmp/dac/sticky/rootf\0", b"r", 0o666, 0);
    mkdirm(b"/tmp/dac/sgid\0", 0o2777, 0);
    sys_chown(b"/tmp/dac/sgid\0".as_ptr(), 0, 3000);
    sys_chmod(b"/tmp/dac/sgid\0".as_ptr(), 0o2777);
    mkdirm(b"/tmp/dac/rn\0", 0o755, USER);
    mkdirm(b"/tmp/dac/rn/a\0", 0o755, USER);
    mkdirm(b"/tmp/dac/rn/b\0", 0o755, USER);
    mkdirm(b"/tmp/dac/rn/a/rootsub\0", 0o755, 0);
    mkfile(b"/tmp/dac/suid\0", b"0123456789", 0o6777, 0);
}

// ---------------------------------------------------------------------------
// Unprivileged child tests
// ---------------------------------------------------------------------------

/// open() access modes against the mode bits (may_open)
fn t_open(n: &[u8]) -> u64 {
    let mut f = 0;
    f += chk(n, b"0600 read", try_open(b"/tmp/dac/f600\0", O_RDONLY), EACCES);
    f += chk(n, b"0600 write", try_open(b"/tmp/dac/f600\0", O_WRONLY), EACCES);
    f += chk(n, b"0644 read", try_open(b"/tmp/dac/f644\0", O_RDONLY), 0);
    f += chk(n, b"0644 write", try_open(b"/tmp/dac/f644\0", O_WRONLY), EACCES);
    f += chk(n, b"0644 rdwr", try_open(b"/tmp/dac/f644\0", O_RDWR), EACCES);
    f += chk(n, b"0644 trunc", try_open(b"/tmp/dac/f644\0", O_RDONLY | O_TRUNC), EACCES);
    f += chk(n, b"0666 rdwr", try_open(b"/tmp/dac/f666\0", O_RDWR), 0);
    f += chk(n, b"dir write", try_open(b"/tmp/dac\0", O_WRONLY), EISDIR);
    f += chk(n, b"noatime", try_open(b"/tmp/dac/f644\0", O_RDONLY | O_NOATIME), EPERM);
    f += chk(n, b"access r", sys_faccessat(AT_FDCWD, b"/tmp/dac/f600\0".as_ptr(), R_OK), EACCES);
    f += chk(n, b"access w", sys_faccessat(AT_FDCWD, b"/tmp/dac/f666\0".as_ptr(), W_OK), 0);
    f
}

/// Path walk needs search (x) on every directory
fn t_search(n: &[u8]) -> u64 {
    let mut st: Stat = unsafe { core::mem::zeroed() };
    let mut f = 0;
    f += chk(n, b"stat", sys_stat(b"/tmp/dac/d700/in\0".as_ptr(), &mut st), EACCES);
    f += chk(n, b"open", try_open(b"/tmp/dac/d700/in\0", O_RDONLY), EACCES);
    f += chk(n, b"missing", try_open(b"/tmp/dac/d700/none\0", O_RDONLY), EACCES);
    f += chk(n, b"dotdot", try_open(b"/tmp/dac/d700/../f644\0", O_RDONLY), EACCES);
    f += chk(n, b"opendir", try_open(b"/tmp/dac/d700\0", O_RDONLY | O_DIRECTORY), EACCES);
    f += chk(n, b"stat dir", sys_stat(b"/tmp/dac/d700\0".as_ptr(), &mut st), 0);
    f += chk(n, b"chdir", sys_chdir(b"/tmp/dac/d700\0".as_ptr()), EACCES);
    f
}

/// Creating or removing names needs write+search on the parent
fn t_create(n: &[u8]) -> u64 {
    let mut f = 0;
    f += chk(n, b"creat", try_open(b"/tmp/dac/new\0", O_CREAT | O_WRONLY), EACCES);
    f += chk(n, b"mkdir", sys_mkdir(b"/tmp/dac/newd\0".as_ptr(), 0o755), EACCES);
    f += chk(n, b"mkdir exist", sys_mkdir(b"/tmp/dac/d700\0".as_ptr(), 0o755), EEXIST);
    f += chk(n, b"symlink", sys_symlink(b"x\0".as_ptr(), b"/tmp/dac/sl\0".as_ptr()), EACCES);
    // Own source file: protected_hardlinks (1 on Ubuntu, 0 upstream) allows it
    let r = sys_link(b"/tmp/dac/x100\0".as_ptr(), b"/tmp/dac/ln\0".as_ptr());
    f += chk(n, b"link", r, EACCES);
    f += chk(n, b"unlink", sys_unlink(b"/tmp/dac/f644\0".as_ptr()), EACCES);
    f += chk(n, b"rmdir", sys_rmdir(b"/tmp/dac/d700\0".as_ptr()), EACCES);
    let r = sys_rename(b"/tmp/dac/f644\0".as_ptr(), b"/tmp/dac/sticky/x\0".as_ptr());
    f += chk(n, b"rename", r, EACCES);
    f += chk(n, b"still", try_open(b"/tmp/dac/f644\0", O_RDONLY), 0);
    f
}

/// Sticky directory: only the file's or directory's owner may remove
fn t_sticky(n: &[u8]) -> u64 {
    let mut f = 0;
    let mine = b"/tmp/dac/sticky/mine\0";
    f += chk(n, b"create", try_open(mine, O_CREAT | O_WRONLY), 0);
    f += chk(n, b"unlink other", sys_unlink(b"/tmp/dac/sticky/rootf\0".as_ptr()), EPERM);
    let r = sys_rename(b"/tmp/dac/sticky/rootf\0".as_ptr(), b"/tmp/dac/sticky/y\0".as_ptr());
    f += chk(n, b"rename other", r, EPERM);
    let r = sys_rename(mine.as_ptr(), b"/tmp/dac/sticky/rootf\0".as_ptr());
    f += chk(n, b"replace other", r, EPERM);
    f += chk(n, b"unlink own", sys_unlink(mine.as_ptr()), 0);
    f
}

/// execve needs x permission on a regular file
fn t_exec(n: &[u8]) -> u64 {
    let mut f = 0;
    f += chk(n, b"0644", exec(b"/tmp/dac/f644\0"), EACCES);
    f += chk(n, b"dir", exec(b"/tmp/dac\0"), EACCES);
    f += chk(n, b"search", exec(b"/tmp/dac/d700/in\0"), EACCES);
    f += chk(n, b"x100 own", exec(b"/tmp/dac/x100\0"), ENOEXEC);
    f
}

/// chmod is owner-only (CAP_FOWNER); SGID dropped outside the group
fn t_chmod(n: &[u8]) -> u64 {
    let mut f = 0;
    f += chk(n, b"other", sys_chmod(b"/tmp/dac/f666\0".as_ptr(), 0o777), EPERM);
    let p = b"/tmp/dac/sticky/cm\0";
    let fd = sys_open(p.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    f += chk(n, b"create", (fd >= 0) as i64, 1);
    f += chk(n, b"fchmod own", sys_fchmod(fd as i32, 0o2755), 0);
    f += chk(n, b"own mode", mode_of(p), 0o2755);
    sys_close(fd as u64);
    f += chk(n, b"fchown grp", sys_chown(p.as_ptr(), u32::MAX, 0), EPERM);
    sys_unlink(p.as_ptr());
    f
}

/// chown needs CAP_CHOWN except an owner "changing" to its own ids
fn t_chown(n: &[u8]) -> u64 {
    let mut f = 0;
    f += chk(n, b"other", sys_chown(b"/tmp/dac/f666\0".as_ptr(), USER, USER), EPERM);
    let p = b"/tmp/dac/sticky/co\0";
    let fd = sys_open(p.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    f += chk(n, b"give away", sys_fchown(fd as i32, 0, u32::MAX), EPERM);
    f += chk(n, b"to group 0", sys_fchown(fd as i32, u32::MAX, 0), EPERM);
    f += chk(n, b"to self", sys_fchown(fd as i32, USER, USER), 0);
    f += chk(n, b"noop", sys_fchown(fd as i32, u32::MAX, u32::MAX), 0);
    sys_close(fd as u64);
    sys_unlink(p.as_ptr());
    f
}

/// utimensat: explicit times need ownership, "now" needs write access
fn t_utimes(n: &[u8]) -> u64 {
    let set = [Timespec { tv_sec: 1, tv_nsec: 0 }, Timespec { tv_sec: 2, tv_nsec: 0 }];
    let now = [Timespec { tv_sec: 0, tv_nsec: UTIME_NOW }, Timespec { tv_sec: 0, tv_nsec: UTIME_NOW }];
    let omit = [Timespec { tv_sec: 0, tv_nsec: UTIME_OMIT }, Timespec { tv_sec: 0, tv_nsec: UTIME_OMIT }];
    let rw = b"/tmp/dac/f666\0".as_ptr();
    let ro = b"/tmp/dac/f644\0".as_ptr();
    let mut f = 0;
    f += chk(n, b"explicit", sys_utimensat(AT_FDCWD, rw, set.as_ptr(), 0), EPERM);
    f += chk(n, b"null rw", sys_utimensat(AT_FDCWD, rw, core::ptr::null(), 0), 0);
    f += chk(n, b"now rw", sys_utimensat(AT_FDCWD, rw, now.as_ptr(), 0), 0);
    f += chk(n, b"null ro", sys_utimensat(AT_FDCWD, ro, core::ptr::null(), 0), EACCES);
    f += chk(n, b"omit", sys_utimensat(AT_FDCWD, ro, omit.as_ptr(), 0), 0);
    f
}

/// truncate needs write access
fn t_truncate(n: &[u8]) -> u64 {
    let mut f = 0;
    f += chk(n, b"0644", sys_truncate(b"/tmp/dac/f644\0".as_ptr(), 0), EACCES);
    f += chk(n, b"0666", sys_truncate(b"/tmp/dac/f666\0".as_ptr(), 6), 0);
    f += chk(n, b"dir", sys_truncate(b"/tmp/dac/sticky\0".as_ptr(), 0), EISDIR);
    f
}

/// Moving a directory to another parent needs write on it (its "..")
fn t_rename_dir(n: &[u8]) -> u64 {
    let mut f = 0;
    let a = b"/tmp/dac/rn/a/rootsub\0";
    let r = sys_rename(a.as_ptr(), b"/tmp/dac/rn/b/rootsub\0".as_ptr());
    f += chk(n, b"cross", r, EACCES);
    f += chk(n, b"same dir", sys_rename(a.as_ptr(), b"/tmp/dac/rn/a/r2\0".as_ptr()), 0);
    f += chk(n, b"back", sys_rename(b"/tmp/dac/rn/a/r2\0".as_ptr(), a.as_ptr()), 0);
    f
}

/// New inodes: owner = fsuid, group = fsgid or SGID parent's, umask applied
fn t_owner_new(n: &[u8]) -> u64 {
    let mut f = 0;
    sys_umask(0o077);
    let p = b"/tmp/dac/sticky/own\0";
    f += chk(n, b"create", try_open(p, O_CREAT | O_WRONLY), 0);
    let (u, g) = owner_of(p);
    f += chk(n, b"uid", u, USER as i64);
    f += chk(n, b"gid", g, USER as i64);
    f += chk(n, b"umask", mode_of(p), 0o600);
    sys_unlink(p.as_ptr());
    let q = b"/tmp/dac/sgid/f\0";
    f += chk(n, b"sgid create", try_open(q, O_CREAT | O_WRONLY), 0);
    f += chk(n, b"sgid gid", owner_of(q).1, 3000);
    let d = b"/tmp/dac/sgid/d\0";
    f += chk(n, b"sgid mkdir", sys_mkdir(d.as_ptr(), 0o777), 0);
    f += chk(n, b"sgid dir mode", mode_of(d), 0o2700);
    f += chk(n, b"sgid dir gid", owner_of(d).1, 3000);
    sys_unlink(q.as_ptr());
    sys_rmdir(d.as_ptr());
    f
}

/// user.* xattrs need write access, trusted.* CAP_SYS_ADMIN
fn t_xattr(n: &[u8]) -> u64 {
    let v = b"v";
    let mut f = 0;
    let r = sys_setxattr(b"/tmp/dac/f644\0".as_ptr(), b"user.x\0".as_ptr(), v.as_ptr(), 1, 0);
    f += chk(n, b"user ro", r, EACCES);
    let r = sys_setxattr(b"/tmp/dac/f666\0".as_ptr(), b"trusted.x\0".as_ptr(), v.as_ptr(), 1, 0);
    f += chk(n, b"trusted", r, EPERM);
    f
}

/// A write by an unprivileged process clears SUID and (group-exec) SGID
fn t_suid_write(n: &[u8]) -> u64 {
    let mut f = 0;
    let p = b"/tmp/dac/suid\0";
    let fd = sys_open(p.as_ptr(), O_WRONLY, 0);
    f += chk(n, b"open", (fd >= 0) as i64, 1);
    f += chk(n, b"write", sys_write(fd as u64, b"x".as_ptr(), 1), 1);
    sys_close(fd as u64);
    f += chk(n, b"mode", mode_of(p), 0o777);
    f
}

// ---------------------------------------------------------------------------
// Root child tests
// ---------------------------------------------------------------------------

/// CAP_DAC_OVERRIDE: read/write anything, exec only with some x bit
fn t_root(n: &[u8]) -> u64 {
    let mut f = 0;
    f += chk(n, b"read 0000", try_open(b"/tmp/dac/f000\0", O_RDONLY), 0);
    f += chk(n, b"write 0000", try_open(b"/tmp/dac/f000\0", O_WRONLY), 0);
    f += chk(n, b"search 0700", try_open(b"/tmp/dac/d700/in\0", O_RDONLY), 0);
    f += chk(n, b"exec 0644", exec(b"/tmp/dac/f644\0"), EACCES);
    f += chk(n, b"exec 0100", exec(b"/tmp/dac/x100\0"), ENOEXEC);
    let x = sys_faccessat(AT_FDCWD, b"/tmp/dac/f644\0".as_ptr(), X_OK);
    f += chk(n, b"access x 0644", x, EACCES);
    let x = sys_faccessat(AT_FDCWD, b"/tmp/dac/x755\0".as_ptr(), X_OK);
    f += chk(n, b"access x 0755", x, 0);
    f += chk(n, b"dir write", try_open(b"/tmp/dac\0", O_RDWR), EISDIR);
    f += chk(n, b"missing", try_open(b"/tmp/dac/none\0", O_RDONLY), ENOENT);
    // Root keeps SUID on its own writes (CAP_FSETID)
    mkfile(b"/tmp/dac/rsuid\0", b"abc", 0o4755, USER);
    let fd = sys_open(b"/tmp/dac/rsuid\0".as_ptr(), O_WRONLY, 0);
    sys_write(fd as u64, b"x".as_ptr(), 1);
    sys_close(fd as u64);
    f += chk(n, b"root write keeps suid", mode_of(b"/tmp/dac/rsuid\0"), 0o4755);
    f
}

/// setfsuid switches the identity used for checks (and the fs capabilities)
fn t_fsuid(n: &[u8]) -> u64 {
    let mut f = 0;
    sys_setfsuid(USER);
    f += chk(n, b"fsuid 0600", try_open(b"/tmp/dac/f600\0", O_RDONLY), EACCES);
    f += chk(n, b"fsuid 0644", try_open(b"/tmp/dac/f644\0", O_RDONLY), 0);
    // access() checks with the real uid (0), not the fsuid
    let r = sys_faccessat(AT_FDCWD, b"/tmp/dac/f600\0".as_ptr(), R_OK);
    f += chk(n, b"access real", r, 0);
    sys_setfsuid(0);
    f += chk(n, b"fsuid back", try_open(b"/tmp/dac/f600\0", O_RDONLY), 0);
    f
}

/// chown clears SUID even when root does it
fn t_root_chown(n: &[u8]) -> u64 {
    let p = b"/tmp/dac/csuid\0";
    mkfile(p, b"abc", 0o4755, USER);
    let mut f = 0;
    f += chk(n, b"chown", sys_chown(p.as_ptr(), 0, 0), 0);
    f += chk(n, b"mode", mode_of(p), 0o755);
    f
}

/// O_CREAT racing another creator: root keeps creating and removing a
/// 0600 file under a name the unprivileged child opens with O_CREAT|O_RDWR;
/// the child may only ever get a file it created itself
fn creat_race() {
    const N: u32 = 2000;
    let p = b"/tmp/dac/sticky/race\0";
    let pid = sys_fork();
    if pid == 0 {
        if sys_setresgid(USER, USER, USER) != 0 || sys_setresuid(USER, USER, USER) != 0 {
            sys_exit(90);
        }
        for _ in 0..N {
            let fd = sys_open(p.as_ptr(), O_CREAT | O_RDWR, 0o600);
            if fd < 0 {
                continue;
            }
            let mut st: Stat = unsafe { core::mem::zeroed() };
            sys_fstat(fd as i32, &mut st);
            sys_close(fd as u64);
            if st.st_uid != USER {
                sys_exit(1);
            }
            sys_unlink(p.as_ptr());
        }
        sys_exit(0);
    }
    for _ in 0..N {
        let fd = sys_open(p.as_ptr(), O_CREAT | O_EXCL | O_WRONLY, 0o600);
        if fd >= 0 {
            sys_close(fd as u64);
            sys_unlink(p.as_ptr());
        }
    }
    wait_ok(b"DAC_CREAT_RACE", pid);
    sys_unlink(p.as_ptr());
}
