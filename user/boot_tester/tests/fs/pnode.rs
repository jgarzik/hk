//! Mount propagation (Linux fs/pnode.c, Documentation/filesystems/
//! sharedsubtree.rst): peers see each other's mounts and umounts, a
//! slave receives but does not send, private and unbindable mounts
//! take no part, an unshared namespace's copies stay peers; mountinfo
//! shows shared:N / master:N. Test mounts are ramfs on both kernels.

use crate::tests::harness::{R, check, report_r};
use hk_syscall::{
    CLONE_NEWNS, O_RDONLY, Stat, sys_chdir, sys_chroot, sys_close, sys_exit, sys_fork, sys_mkdir,
    sys_mount, sys_open, sys_pivot_root, sys_read, sys_rmdir, sys_stat, sys_umount2, sys_unshare,
    sys_wait4,
};

const ENOENT: i64 = -2;
const EINVAL: i64 = -22;
const MS_BIND: u64 = 4096;
const MS_REC: u64 = 1 << 14;
const MS_UNBINDABLE: u64 = 1 << 17;
const MS_PRIVATE: u64 = 1 << 18;
const MS_SLAVE: u64 = 1 << 19;
const MS_SHARED: u64 = 1 << 20;
const MNT_DETACH: u64 = 2;

pub fn run_tests() {
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777); // hk boots without /tmp
    report_r(b"PROPAG_SHARED_BIND", shared_bind());
    report_r(b"PROPAG_SLAVE_ONEWAY", slave_oneway());
    report_r(b"PROPAG_PRIVATE", private());
    report_r(b"PROPAG_UNBINDABLE", unbindable());
    report_r(b"PROPAG_UNSHARE_PEER", unshare_peer());
    // Linux 6.17..7.2 lost it (406fea799925; fixed by 1ab8904ae61b)
    if crate::tests::helpers::linux_at_least(7, 3) {
        report_r(b"PROPAG_UNSHARE_UNBINDABLE", unshare_unbindable());
    } else {
        crate::tests::helpers::skip(b"PROPAG_UNSHARE_UNBINDABLE", b"Linux 7.3 fix");
    }
    report_r(b"PROPAG_SLAVE_GROUPS", slave_groups());
    report_r(b"PROPAG_UNBIND_THEN_SHARED", unbind_then_shared());
    report_r(b"PIVOT_ROOT_SHARED", pivot_shared());
}

fn ramfs(t: &[u8]) -> i64 {
    sys_mount(b"none\0".as_ptr(), t.as_ptr(), b"ramfs\0".as_ptr(), 0, 0)
}

fn bind(s: &[u8], t: &[u8]) -> i64 {
    sys_mount(s.as_ptr(), t.as_ptr(), core::ptr::null(), MS_BIND, 0)
}

fn set(t: &[u8], flags: u64) -> i64 {
    sys_mount(core::ptr::null(), t.as_ptr(), core::ptr::null(), flags, 0)
}

fn dev(p: &[u8]) -> Result<u64, i64> {
    // SAFETY: Stat is plain integers
    let mut st: Stat = unsafe { core::mem::zeroed() };
    match sys_stat(p.as_ptr(), &mut st) {
        0 => Ok(st.st_dev),
        e => Err(e),
    }
}

/// `p` is a mountpoint: its st_dev differs from its parent directory's
fn mounted(p: &[u8], parent: &[u8]) -> bool {
    matches!((dev(p), dev(parent)), (Ok(a), Ok(b)) if a != b)
}

fn mkdirs(ps: &[&[u8]]) {
    for p in ps {
        sys_mkdir(p.as_ptr(), 0o755);
    }
}

fn rmdirs(ps: &[&[u8]]) {
    for p in ps.iter().rev() {
        sys_rmdir(p.as_ptr());
    }
}

/// The value of optional field `key` ("shared" or "master") on the
/// mountinfo line of mountpoint `mp`, 0 if absent
fn opt(mp: &[u8], key: &[u8]) -> u64 {
    let mut buf = [0u8; 8192];
    let fd = sys_open(b"/proc/self/mountinfo\0".as_ptr(), O_RDONLY, 0);
    let mut n = 0usize;
    while fd >= 0 && n < buf.len() {
        let r = sys_read(fd as u64, buf[n..].as_mut_ptr(), (buf.len() - n) as u64);
        if r <= 0 {
            break;
        }
        n += r as usize;
    }
    sys_close(fd as u64);
    let Some(line) = buf[..n]
        .split(|&c| c == b'\n')
        .find(|l| l.split(|&c| c == b' ').nth(4) == Some(mp))
    else {
        return 0;
    };
    for f in line.split(|&c| c == b' ').skip(6) {
        if f == b"-" {
            break;
        }
        if f.len() > key.len() && f.starts_with(key) && f[key.len()] == b':' {
            let mut v = 0u64;
            for &c in &f[key.len() + 1..] {
                v = v * 10 + (c - b'0') as u64;
            }
            return v;
        }
    }
    0
}

/// Peers: a mount under one shows under the other (and back), an
/// umount goes to both (PROPAG_UMOUNT); mountinfo gives both the same
/// shared:N (MOUNTINFO_OPTIONAL)
fn shared_bind() -> R {
    let dirs: [&[u8]; 2] = [b"/tmp/ps_a\0", b"/tmp/ps_b\0"];
    mkdirs(&dirs);
    let r = (|| {
        check(b"mount", ramfs(b"/tmp/ps_a\0") == 0, -1)?;
        check(b"make shared", set(b"/tmp/ps_a\0", MS_SHARED) == 0, -1)?;
        check(b"bind", bind(b"/tmp/ps_a\0", b"/tmp/ps_b\0") == 0, -1)?;
        let (ga, gb) = (opt(b"/tmp/ps_a", b"shared"), opt(b"/tmp/ps_b", b"shared"));
        check(b"same group", ga != 0 && ga == gb, (ga * 1000 + gb) as i64)?;
        mkdirs(&[b"/tmp/ps_a/x\0", b"/tmp/ps_a/y\0"]);
        check(b"mount x", ramfs(b"/tmp/ps_a/x\0") == 0, -1)?;
        check(b"x at b", mounted(b"/tmp/ps_b/x\0", b"/tmp/ps_b\0"), -1)?;
        check(b"mount y via b", ramfs(b"/tmp/ps_b/y\0") == 0, -1)?;
        check(b"y at a", mounted(b"/tmp/ps_a/y\0", b"/tmp/ps_a\0"), -1)?;
        // PROPAG_UMOUNT
        check(
            b"umount x",
            sys_umount2(b"/tmp/ps_a/x\0".as_ptr(), 0) == 0,
            -1,
        )?;
        check(
            b"x gone at b",
            !mounted(b"/tmp/ps_b/x\0", b"/tmp/ps_b\0"),
            -1,
        )
    })();
    for p in [&b"/tmp/ps_a/y\0"[..], b"/tmp/ps_b/x\0", b"/tmp/ps_a/x\0"] {
        sys_umount2(p.as_ptr(), MNT_DETACH);
    }
    rmdirs(&[b"/tmp/ps_a/x\0", b"/tmp/ps_a/y\0"]);
    sys_umount2(b"/tmp/ps_b\0".as_ptr(), 0);
    sys_umount2(b"/tmp/ps_a\0".as_ptr(), 0);
    rmdirs(&dirs);
    r
}

/// A slave receives its master's mounts, not the other way; mountinfo
/// says master:N with the master's shared:N
fn slave_oneway() -> R {
    let dirs: [&[u8]; 2] = [b"/tmp/sl_a\0", b"/tmp/sl_b\0"];
    mkdirs(&dirs);
    let r = (|| {
        check(b"mount", ramfs(b"/tmp/sl_a\0") == 0, -1)?;
        check(b"make shared", set(b"/tmp/sl_a\0", MS_SHARED) == 0, -1)?;
        check(b"bind", bind(b"/tmp/sl_a\0", b"/tmp/sl_b\0") == 0, -1)?;
        check(b"make slave", set(b"/tmp/sl_b\0", MS_SLAVE) == 0, -1)?;
        let (ga, mb) = (opt(b"/tmp/sl_a", b"shared"), opt(b"/tmp/sl_b", b"master"));
        check(b"master:N", ga != 0 && mb == ga, mb as i64)?;
        check(b"slave not shared", opt(b"/tmp/sl_b", b"shared") == 0, -1)?;
        mkdirs(&[b"/tmp/sl_a/x\0", b"/tmp/sl_a/y\0"]);
        check(b"mount x", ramfs(b"/tmp/sl_a/x\0") == 0, -1)?;
        check(b"x at slave", mounted(b"/tmp/sl_b/x\0", b"/tmp/sl_b\0"), -1)?;
        check(b"mount y in slave", ramfs(b"/tmp/sl_b/y\0") == 0, -1)?;
        check(
            b"y not at master",
            !mounted(b"/tmp/sl_a/y\0", b"/tmp/sl_a\0"),
            -1,
        )
    })();
    for p in [&b"/tmp/sl_b/y\0"[..], b"/tmp/sl_a/x\0", b"/tmp/sl_b/x\0"] {
        sys_umount2(p.as_ptr(), MNT_DETACH);
    }
    rmdirs(&[b"/tmp/sl_a/x\0", b"/tmp/sl_a/y\0"]);
    sys_umount2(b"/tmp/sl_b\0".as_ptr(), 0);
    sys_umount2(b"/tmp/sl_a\0".as_ptr(), 0);
    rmdirs(&dirs);
    r
}

/// A peer made private leaves the group: it gets nothing more
fn private() -> R {
    let dirs: [&[u8]; 2] = [b"/tmp/pp_a\0", b"/tmp/pp_b\0"];
    mkdirs(&dirs);
    let r = (|| {
        check(b"mount", ramfs(b"/tmp/pp_a\0") == 0, -1)?;
        check(b"make shared", set(b"/tmp/pp_a\0", MS_SHARED) == 0, -1)?;
        check(b"bind", bind(b"/tmp/pp_a\0", b"/tmp/pp_b\0") == 0, -1)?;
        check(b"make private", set(b"/tmp/pp_b\0", MS_PRIVATE) == 0, -1)?;
        check(b"no group", opt(b"/tmp/pp_b", b"shared") == 0, -1)?;
        sys_mkdir(b"/tmp/pp_a/x\0".as_ptr(), 0o755);
        check(b"mount x", ramfs(b"/tmp/pp_a/x\0") == 0, -1)?;
        check(b"not at b", !mounted(b"/tmp/pp_b/x\0", b"/tmp/pp_b\0"), -1)
    })();
    sys_umount2(b"/tmp/pp_a/x\0".as_ptr(), 0);
    sys_rmdir(b"/tmp/pp_a/x\0".as_ptr());
    sys_umount2(b"/tmp/pp_b\0".as_ptr(), 0);
    sys_umount2(b"/tmp/pp_a\0".as_ptr(), 0);
    rmdirs(&dirs);
    r
}

/// Exactly one propagation type per call (EINVAL); a shared mount made
/// unbindable leaves its group and cannot be bound
fn unbindable() -> R {
    let dirs: [&[u8]; 2] = [b"/tmp/pu_a\0", b"/tmp/pu_b\0"];
    mkdirs(&dirs);
    let r = (|| {
        check(b"mount", ramfs(b"/tmp/pu_a\0") == 0, -1)?;
        let r = set(b"/tmp/pu_a\0", MS_SHARED | MS_PRIVATE);
        check(b"two types", r == EINVAL, r)?;
        check(
            b"make shared",
            set(b"/tmp/pu_a\0", MS_SHARED | MS_REC) == 0,
            -1,
        )?;
        check(b"unbindable", set(b"/tmp/pu_a\0", MS_UNBINDABLE) == 0, -1)?;
        check(b"left group", opt(b"/tmp/pu_a", b"shared") == 0, -1)?;
        let r = bind(b"/tmp/pu_a\0", b"/tmp/pu_b\0");
        check(b"bind", r == EINVAL, r)
    })();
    sys_umount2(b"/tmp/pu_b\0".as_ptr(), 0);
    sys_umount2(b"/tmp/pu_a\0".as_ptr(), 0);
    rmdirs(&dirs);
    r
}

/// unshare(CLONE_NEWNS) copies an unbindable mount unbindable (Linux
/// 7.3+ clone_mnt keeps T_UNBINDABLE): binding it in the new namespace
/// is EINVAL
fn unshare_unbindable() -> R {
    let dirs: [&[u8]; 2] = [b"/tmp/puu_a\0", b"/tmp/puu_b\0"];
    mkdirs(&dirs);
    let r = (|| {
        check(b"mount", ramfs(b"/tmp/puu_a\0") == 0, -1)?;
        check(b"unbindable", set(b"/tmp/puu_a\0", MS_UNBINDABLE) == 0, -1)?;
        let pid = sys_fork();
        if pid == 0 {
            let code = if sys_unshare(CLONE_NEWNS) != 0 {
                1
            } else if bind(b"/tmp/puu_a\0", b"/tmp/puu_b\0") != EINVAL {
                2
            } else {
                0
            };
            sys_exit(code);
        }
        let mut st = 0i32;
        sys_wait4(pid, &mut st, 0, 0);
        check(b"child", st == 0, (st >> 8) as i64)
    })();
    sys_umount2(b"/tmp/puu_b\0".as_ptr(), 0);
    sys_umount2(b"/tmp/puu_a\0".as_ptr(), 0);
    rmdirs(&dirs);
    r
}

/// unshare(CLONE_NEWNS) keeps peerage: a mount the child makes under
/// a shared mount shows in the parent's namespace too
fn unshare_peer() -> R {
    let d: &[u8] = b"/tmp/pn\0";
    sys_mkdir(d.as_ptr(), 0o755);
    let r = (|| {
        check(b"mount", ramfs(d) == 0, -1)?;
        check(b"make shared", set(d, MS_SHARED) == 0, -1)?;
        sys_mkdir(b"/tmp/pn/c\0".as_ptr(), 0o755);
        let pid = sys_fork();
        if pid == 0 {
            let code = if sys_unshare(CLONE_NEWNS) != 0 {
                1
            } else if ramfs(b"/tmp/pn/c\0") != 0 {
                2
            } else {
                0
            };
            sys_exit(code);
        }
        let mut ws = 0i32;
        sys_wait4(pid, &mut ws, 0, 0);
        check(b"child", ws == 0, (ws >> 8) as i64)?;
        check(b"seen here", mounted(b"/tmp/pn/c\0", d), -1)?;
        check(b"umount", sys_umount2(b"/tmp/pn/c\0".as_ptr(), 0) == 0, -1)?;
        check(b"gone", dev(b"/tmp/pn/c/x\0") == Err(ENOENT), -1)
    })();
    sys_umount2(b"/tmp/pn/c\0".as_ptr(), MNT_DETACH);
    sys_rmdir(b"/tmp/pn/c\0".as_ptr());
    sys_umount2(d.as_ptr(), 0);
    sys_rmdir(d.as_ptr());
    r
}

/// An rbind of a two-mount tree under a shared master reaches a group
/// of shared slaves as slaves that are peers of one another: each
/// source mount's copies form their own peer group
fn slave_groups() -> R {
    let dirs: [&[u8]; 4] = [
        b"/tmp/pg_a\0",
        b"/tmp/pg_b\0",
        b"/tmp/pg_c\0",
        b"/tmp/pg_t\0",
    ];
    mkdirs(&dirs);
    let r = (|| {
        check(b"mount a", ramfs(b"/tmp/pg_a\0") == 0, -1)?;
        check(b"a shared", set(b"/tmp/pg_a\0", MS_SHARED) == 0, -1)?;
        check(b"bind b", bind(b"/tmp/pg_a\0", b"/tmp/pg_b\0") == 0, -1)?;
        check(b"b slave", set(b"/tmp/pg_b\0", MS_SLAVE) == 0, -1)?;
        check(b"b shared", set(b"/tmp/pg_b\0", MS_SHARED) == 0, -1)?;
        check(b"bind c", bind(b"/tmp/pg_b\0", b"/tmp/pg_c\0") == 0, -1)?;
        check(b"mount t", ramfs(b"/tmp/pg_t\0") == 0, -1)?;
        sys_mkdir(b"/tmp/pg_t/s\0".as_ptr(), 0o755);
        check(b"mount t/s", ramfs(b"/tmp/pg_t/s\0") == 0, -1)?;
        sys_mkdir(b"/tmp/pg_a/x\0".as_ptr(), 0o755);
        let r = sys_mount(
            b"/tmp/pg_t\0".as_ptr(),
            b"/tmp/pg_a/x\0".as_ptr(),
            core::ptr::null(),
            MS_BIND | MS_REC,
            0,
        );
        check(b"rbind", r == 0, r)?;
        let (p, q) = (
            opt(b"/tmp/pg_b/x", b"shared"),
            opt(b"/tmp/pg_b/x/s", b"shared"),
        );
        check(
            b"two groups",
            p != 0 && q != 0 && p != q,
            (p * 1000 + q) as i64,
        )?;
        check(b"peers in c", opt(b"/tmp/pg_c/x", b"shared") == p, -1)?;
        check(
            b"slaves",
            opt(b"/tmp/pg_b/x", b"master") == opt(b"/tmp/pg_a/x", b"shared"),
            -1,
        )
    })();
    for p in [
        &b"/tmp/pg_c/x/s\0"[..],
        b"/tmp/pg_c/x\0",
        b"/tmp/pg_b/x/s\0",
        b"/tmp/pg_b/x\0",
        b"/tmp/pg_a/x/s\0",
        b"/tmp/pg_a/x\0",
        b"/tmp/pg_c\0",
        b"/tmp/pg_b\0",
        b"/tmp/pg_t/s\0",
    ] {
        sys_umount2(p.as_ptr(), MNT_DETACH);
    }
    sys_rmdir(b"/tmp/pg_a/x\0".as_ptr());
    sys_umount2(b"/tmp/pg_a\0".as_ptr(), MNT_DETACH);
    sys_rmdir(b"/tmp/pg_t/s\0".as_ptr());
    sys_umount2(b"/tmp/pg_t\0".as_ptr(), MNT_DETACH);
    rmdirs(&dirs);
    r
}

/// Making an unbindable mount shared ends unbindable (Linux
/// set_mnt_shared clears T_UNBINDABLE): it can then be bound
fn unbind_then_shared() -> R {
    let dirs: [&[u8]; 2] = [b"/tmp/ub_s\0", b"/tmp/ub_t\0"];
    mkdirs(&dirs);
    let r = (|| {
        check(b"mount", ramfs(b"/tmp/ub_s\0") == 0, -1)?;
        check(b"unbindable", set(b"/tmp/ub_s\0", MS_UNBINDABLE) == 0, -1)?;
        check(b"shared", set(b"/tmp/ub_s\0", MS_SHARED) == 0, -1)?;
        let r = bind(b"/tmp/ub_s\0", b"/tmp/ub_t\0");
        check(b"bind", r == 0, r)
    })();
    sys_umount2(b"/tmp/ub_t\0".as_ptr(), 0);
    sys_umount2(b"/tmp/ub_s\0".as_ptr(), 0);
    rmdirs(&dirs);
    r
}

/// pivot_root with put_old on a shared mount is EINVAL (Linux: no
/// mount may move under a shared one without propagating)
fn pivot_shared() -> R {
    let pid = sys_fork();
    if pid == 0 {
        let code = if sys_unshare(CLONE_NEWNS) != 0 {
            1
        } else {
            sys_mkdir(b"/tmp/psh\0".as_ptr(), 0o755);
            if ramfs(b"/tmp/psh\0") != 0 || sys_chdir(b"/tmp/psh\0".as_ptr()) != 0 {
                2
            } else if sys_mount(b".\0".as_ptr(), b"/\0".as_ptr(), core::ptr::null(), 8192, 0) != 0
                || sys_chroot(b".\0".as_ptr()) != 0
            {
                3
            } else {
                sys_mkdir(b"/new\0".as_ptr(), 0o755);
                if ramfs(b"/new\0") != 0 || set(b"/new\0", MS_SHARED) != 0 {
                    4
                } else {
                    sys_mkdir(b"/new/old\0".as_ptr(), 0o755);
                    let r = sys_pivot_root(b"/new\0".as_ptr(), b"/new/old\0".as_ptr());
                    if r == EINVAL { 0 } else { 5 }
                }
            }
        };
        sys_exit(code);
    }
    let mut ws = 0i32;
    sys_wait4(pid, &mut ws, 0, 0);
    check(b"child", ws == 0, (ws >> 8) as i64)
}
