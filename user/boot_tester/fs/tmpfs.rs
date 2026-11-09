//! tmpfs limits and options (Linux mm/shmem.c)
//!
//! - TMPFS_LIMITS: size=8k,nr_inodes=4: statfs shows 2 blocks and 4
//!   inodes (the root holds one); a write past two pages is short, the
//!   next ENOSPC; files, directories and hard links each take an inode
//!   (ENOSPC once out), an unlink of an extra link gives it back; a hole
//!   reads as zeros on a full tmpfs; the root has the mode and owner
//!   asked for; /proc/mounts shows the options
//! - TMPFS_REMOUNT: a remount grows the size (more writes fit), cannot
//!   shrink it or the inodes below what is in use (EINVAL); fallocate
//!   past the space is ENOSPC, a truncate gives the pages back, then it
//!   fits
//! - TMPFS_DEFAULTS: a plain mount gets half of RAM (no size= shown),
//!   size=0,nr_inodes=0 is unlimited (statfs zeros), bad options EINVAL
//! - ROOTFS_TMPFS: the initramfs root is tmpfs (Linux rootfs with
//!   CONFIG_TMPFS and no root=) limited to about half of RAM (Linux
//!   sizes it before the initrd and init memory are freed); ramfs, which
//!   it no longer is, has no xattrs or fallocate (EOPNOTSUPP)
//! - TMPFILE_LINK: O_TMPFILE makes an unnamed file (nlink 0, "/tmp/#N
//!   (deleted)" in /proc/self/fd) that linkat(AT_EMPTY_PATH) names,
//!   unless opened O_EXCL (ENOENT); read-only, without O_DIRECTORY or
//!   with O_CREAT is EINVAL, a file ENOTDIR, a missing one ENOENT, procfs
//!   EOPNOTSUPP; on tmpfs it takes an inode (ENOSPC), its first link none
//! - DEVTMPFS_TMPFS: devtmpfs is a tmpfs with mode=755 (Linux
//!   devtmpfs_init); another mount shows the same superblock; a bad
//!   option is EINVAL, size= is parsed and dropped (Linux 6.15+; up to
//!   6.14 reconfigure_single applied it to /dev too)

use crate::exec::busybox::contains;
use crate::harness::T;
use crate::helpers::read_file;
use crate::mm::mm_life::{SI_TOTALRAM, sysinfo_ram};
use hk_syscall::{
    LinuxStatFs, O_CREAT, O_RDWR, O_WRONLY, Stat, sys_close, sys_fallocate, sys_ftruncate,
    sys_link, sys_mkdir, sys_mount, sys_open, sys_pread64, sys_rmdir, sys_stat, sys_statfs,
    sys_umount2, sys_unlink, sys_write,
};

const TMPFS_MAGIC: i64 = 0x0102_1994;
const ENOSPC: i64 = -28;
const EINVAL: i64 = -22;
const MS_REMOUNT: u64 = 32;
const MP: &[u8] = b"/tmp/tmpfs_lim\0";

pub fn run_tests() {
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777);
    sys_mkdir(MP.as_ptr(), 0o755);
    limits();
    remount();
    defaults();
    rootfs();
    devtmpfs();
    tmpfile();
    sys_rmdir(MP.as_ptr());
}

/// Mount tmpfs on MP with options `opts` (NUL-terminated)
fn mount(opts: &[u8]) -> i64 {
    sys_mount(
        b"tmpfs\0".as_ptr(),
        MP.as_ptr(),
        b"tmpfs\0".as_ptr(),
        0,
        opts.as_ptr() as u64,
    )
}

fn statfs() -> LinuxStatFs {
    let mut st = LinuxStatFs::default();
    sys_statfs(MP.as_ptr(), &mut st);
    st
}

/// Create (and close) `p`: 0 or the errno
fn touch(p: &[u8]) -> i64 {
    let fd = sys_open(p.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    if fd >= 0 {
        sys_close(fd as u64);
        return 0;
    }
    fd
}

fn limits() {
    let mut t = T::new(b"TMPFS_LIMITS");
    if !t.eq(
        b"mount",
        mount(b"size=8k,nr_inodes=4,mode=750,uid=12,gid=34\0"),
        0,
    ) {
        return t.done();
    }
    let st = statfs();
    t.eq(b"f_type", st.f_type, TMPFS_MAGIC);
    t.eq(b"f_bsize", st.f_bsize, 4096);
    t.eq(b"f_blocks", st.f_blocks, 2);
    t.eq(b"f_bfree", st.f_bfree, 2);
    t.eq(b"f_files", st.f_files, 4);
    t.eq(b"f_ffree", st.f_ffree, 3);
    let mut s = Stat::default();
    sys_stat(MP.as_ptr(), &mut s);
    t.eq(b"root mode", i64::from(s.st_mode), 0o40750);
    t.eq(b"root uid", i64::from(s.st_uid), 12);
    t.eq(b"root gid", i64::from(s.st_gid), 34);

    // Blocks: three pages fit two, then nothing
    let fd = sys_open(b"/tmp/tmpfs_lim/f\0".as_ptr(), O_CREAT | O_RDWR, 0o644);
    t.ok(b"open", fd >= 0, fd);
    let buf = [0x5au8; 3 * 4096];
    t.eq(
        b"short write",
        sys_write(fd as u64, buf.as_ptr(), 3 * 4096),
        2 * 4096,
    );
    t.eq(b"full write", sys_write(fd as u64, buf.as_ptr(), 1), ENOSPC);
    t.eq(b"bfree full", statfs().f_bfree, 0);
    // A hole reads as zeros without needing a page
    t.eq(b"truncate up", sys_ftruncate(fd as i32, 65536), 0);
    let mut rd = [1u8; 4096];
    let n = sys_pread64(fd as i32, rd.as_mut_ptr(), 4096, 40960);
    t.ok(b"hole read", n == 4096 && rd.iter().all(|&b| b == 0), n);
    sys_close(fd as u64);

    // Inodes: root and f hold two of four; a hard link takes one
    t.eq(b"ffree", statfs().f_ffree, 2);
    t.eq(b"create g", touch(b"/tmp/tmpfs_lim/g\0"), 0);
    let link = sys_link(
        b"/tmp/tmpfs_lim/f\0".as_ptr(),
        b"/tmp/tmpfs_lim/f2\0".as_ptr(),
    );
    t.eq(b"link", link, 0);
    t.eq(b"ffree 0", statfs().f_ffree, 0);
    t.eq(b"create full", touch(b"/tmp/tmpfs_lim/h\0"), ENOSPC);
    t.eq(
        b"mkdir full",
        sys_mkdir(b"/tmp/tmpfs_lim/d\0".as_ptr(), 0o755),
        ENOSPC,
    );
    let link = sys_link(
        b"/tmp/tmpfs_lim/f\0".as_ptr(),
        b"/tmp/tmpfs_lim/f3\0".as_ptr(),
    );
    t.eq(b"link full", link, ENOSPC);
    t.eq(
        b"unlink link",
        sys_unlink(b"/tmp/tmpfs_lim/f2\0".as_ptr()),
        0,
    );
    t.eq(b"ffree back", statfs().f_ffree, 1);
    t.eq(b"create h", touch(b"/tmp/tmpfs_lim/h\0"), 0);

    // The options in /proc/mounts (Linux shmem_show_options)
    let mut m = [0u8; 8192];
    let n = read_file(b"/proc/mounts\0", &mut m).max(0) as usize;
    let want = b"tmpfs /tmp/tmpfs_lim tmpfs rw";
    t.ok(b"mounts line", contains(&m[..n], want), n as i64);
    let opts = b",size=8k,nr_inodes=4,mode=750,uid=12,gid=34,inode64 0 0\n";
    t.ok(b"mounts opts", contains(&m[..n], opts), n as i64);
    t.eq(b"umount", sys_umount2(MP.as_ptr(), 0), 0);
    t.done();
}

fn remount() {
    let mut t = T::new(b"TMPFS_REMOUNT");
    if !t.eq(b"mount", mount(b"size=8k,nr_inodes=8\0"), 0) {
        return t.done();
    }
    let fd = sys_open(b"/tmp/tmpfs_lim/f\0".as_ptr(), O_CREAT | O_RDWR, 0o644);
    let buf = [0x5au8; 2 * 4096];
    t.eq(
        b"fill",
        sys_write(fd as u64, buf.as_ptr(), 2 * 4096),
        2 * 4096,
    );
    let re = |opts: &[u8]| {
        sys_mount(
            core::ptr::null(),
            MP.as_ptr(),
            core::ptr::null(),
            MS_REMOUNT,
            opts.as_ptr() as u64,
        )
    };
    t.eq(b"grow", re(b"size=16k\0"), 0);
    let st = statfs();
    t.eq(b"f_blocks", st.f_blocks, 4);
    t.eq(b"f_bfree", st.f_bfree, 2);
    t.eq(b"shrink", re(b"size=4k\0"), EINVAL);
    // Root and f use two inodes
    t.eq(b"inodes below use", re(b"nr_inodes=1\0"), EINVAL);
    t.eq(b"inodes", re(b"nr_inodes=2\0"), 0);
    t.eq(b"f_ffree", statfs().f_ffree, 0);
    t.eq(
        b"more",
        sys_write(fd as u64, buf.as_ptr(), 2 * 4096),
        2 * 4096,
    );
    t.eq(
        b"falloc full",
        sys_fallocate(fd as i32, 0, 16384, 4096),
        ENOSPC,
    );
    t.eq(b"truncate", sys_ftruncate(fd as i32, 0), 0);
    t.eq(b"freed", statfs().f_bfree, 4);
    t.eq(b"falloc", sys_fallocate(fd as i32, 0, 0, 3 * 4096), 0);
    t.eq(b"falloc used", statfs().f_bfree, 1);
    let mut s = Stat::default();
    sys_stat(b"/tmp/tmpfs_lim/f\0".as_ptr(), &mut s);
    t.eq(b"falloc size", s.st_size, 3 * 4096);
    sys_close(fd as u64);
    t.eq(b"umount", sys_umount2(MP.as_ptr(), 0), 0);
    t.done();
}

fn defaults() {
    let mut t = T::new(b"TMPFS_DEFAULTS");
    if !t.eq(b"mount", mount(b"\0"), 0) {
        return t.done();
    }
    let half = (sysinfo_ram(SI_TOTALRAM) / 4096 / 2) as i64;
    let st = statfs();
    t.ok(
        b"half of RAM",
        (st.f_blocks - half).abs() <= half / 100,
        st.f_blocks,
    );
    t.ok(
        b"inodes",
        (st.f_files - half).abs() <= half / 100,
        st.f_files,
    );
    let mut m = [0u8; 8192];
    let n = read_file(b"/proc/mounts\0", &mut m).max(0) as usize;
    let want = b"tmpfs /tmp/tmpfs_lim tmpfs rw,relatime,inode64 0 0\n";
    t.ok(b"mounts line", contains(&m[..n], want), n as i64);
    t.eq(b"umount", sys_umount2(MP.as_ptr(), 0), 0);
    if t.eq(b"unlimited", mount(b"size=0,nr_inodes=0\0"), 0) {
        let st = statfs();
        t.ok(b"zeros", st.f_blocks == 0 && st.f_files == 0, st.f_blocks);
        sys_umount2(MP.as_ptr(), 0);
    }
    t.eq(b"bad size", mount(b"size=12q\0"), EINVAL);
    t.eq(b"unknown", mount(b"bogus=1\0"), EINVAL);
    t.eq(b"empty", mount(b"nr_inodes=\0"), EINVAL);
    t.done();
}

fn rootfs() {
    const EOPNOTSUPP: i64 = -95;
    let mut t = T::new(b"ROOTFS_TMPFS");
    let mut st = LinuxStatFs::default();
    t.eq(b"statfs", sys_statfs(b"/\0".as_ptr(), &mut st), 0);
    t.eq(b"f_type", st.f_type, TMPFS_MAGIC);
    let ram = sysinfo_ram(SI_TOTALRAM) as i64;
    let size = st.f_blocks * 4096;
    t.ok(
        b"half of RAM",
        size > ram * 2 / 5 && size <= ram * 11 / 20,
        st.f_blocks,
    );
    t.ok(b"files", st.f_files > 0 && st.f_ffree > 0, st.f_files);
    // ramfs keeps Linux ramfs's: no xattrs, no fallocate
    if t.eq(
        b"ramfs",
        sys_mount(b"none\0".as_ptr(), MP.as_ptr(), b"ramfs\0".as_ptr(), 0, 0),
        0,
    ) {
        let fd = sys_open(b"/tmp/tmpfs_lim/f\0".as_ptr(), O_CREAT | O_RDWR, 0o644);
        t.eq(
            b"ramfs fallocate",
            sys_fallocate(fd as i32, 0, 0, 4096),
            EOPNOTSUPP,
        );
        let x = hk_syscall::sys_fsetxattr(fd as i32, b"user.x\0".as_ptr(), b"v".as_ptr(), 1, 0);
        t.eq(b"ramfs setxattr", x, EOPNOTSUPP);
        sys_close(fd as u64);
        sys_unlink(b"/tmp/tmpfs_lim/f\0".as_ptr());
        sys_umount2(MP.as_ptr(), 0);
    }
    t.done();
}

fn devtmpfs() {
    let mut t = T::new(b"DEVTMPFS_TMPFS");
    let mut dev = LinuxStatFs::default();
    t.eq(b"statfs", sys_statfs(b"/dev\0".as_ptr(), &mut dev), 0);
    t.eq(b"f_type", dev.f_type, TMPFS_MAGIC);
    t.ok(
        b"limited",
        dev.f_blocks > 0 && dev.f_files > 0,
        dev.f_blocks,
    );
    let mut s = Stat::default();
    sys_stat(b"/dev\0".as_ptr(), &mut s);
    t.eq(b"root mode", i64::from(s.st_mode), 0o40755);
    let mut m = [0u8; 8192];
    let n = read_file(b"/proc/mounts\0", &mut m).max(0) as usize;
    t.ok(
        b"mounts",
        contains(&m[..n], b"devtmpfs /dev devtmpfs rw"),
        n as i64,
    );
    t.ok(
        b"mounts mode",
        contains(&m[..n], b",mode=755,inode64"),
        n as i64,
    );
    let dt = |opts: &[u8]| {
        sys_mount(
            b"devtmpfs\0".as_ptr(),
            MP.as_ptr(),
            b"devtmpfs\0".as_ptr(),
            0,
            opts.as_ptr() as u64,
        )
    };
    t.eq(b"bad option", dt(b"bogus\0"), EINVAL);
    if t.eq(b"mount", dt(b"size=1m\0"), 0) {
        let mut s2 = Stat::default();
        sys_stat(b"/tmp/tmpfs_lim/null\0".as_ptr(), &mut s2);
        t.eq(b"null", s2.st_rdev as i64, 0x103);
        let mut now = LinuxStatFs::default();
        sys_statfs(b"/dev\0".as_ptr(), &mut now);
        if crate::helpers::linux_at_least(6, 15) {
            t.eq(b"size dropped", now.f_blocks, dev.f_blocks);
            sys_umount2(MP.as_ptr(), 0);
        } else {
            t.eq(b"size applied", now.f_blocks, 256);
            sys_umount2(MP.as_ptr(), 0);
            restore_dev(&mut t, dev.f_blocks);
        }
    }
    t.done();
}

/// /dev's block limit back to `blocks` after a pre-6.15 devtmpfs mount
/// changed it
fn restore_dev(t: &mut T, blocks: i64) {
    let mut opt = [0u8; 40];
    opt[..10].copy_from_slice(b"nr_blocks=");
    let (mut digits, mut n, mut v) = ([0u8; 20], 0, blocks as u64);
    loop {
        digits[n] = b'0' + (v % 10) as u8;
        n += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for i in 0..n {
        opt[10 + i] = digits[n - 1 - i];
    }
    let r = sys_mount(
        b"devtmpfs\0".as_ptr(),
        MP.as_ptr(),
        b"devtmpfs\0".as_ptr(),
        0,
        opt.as_ptr() as u64,
    );
    t.eq(b"restore", r, 0);
    sys_umount2(MP.as_ptr(), 0);
    let mut now = LinuxStatFs::default();
    sys_statfs(b"/dev\0".as_ptr(), &mut now);
    t.eq(b"restored", now.f_blocks, blocks);
}

/// O_TMPFILE | `acc`, in `dir`
fn tmpf(dir: &[u8], acc: u32) -> i64 {
    let tmp = hk_syscall::__O_TMPFILE | hk_syscall::O_DIRECTORY;
    sys_open(dir.as_ptr(), tmp | acc, 0o600)
}

fn tmpfile() {
    use hk_syscall::{
        AT_EMPTY_PATH, O_EXCL, O_RDONLY, sys_fstat, sys_linkat, sys_read, sys_readlink,
    };
    const AT_FDCWD: i32 = -100;
    const ENOENT: i64 = -2;
    const ENOTDIR: i64 = -20;
    const EOPNOTSUPP: i64 = -95;
    let mut t = T::new(b"TMPFILE_LINK");
    let fd = tmpf(b"/tmp\0", O_RDWR);
    if !t.ok(b"open", fd >= 0, fd) {
        return t.done();
    }
    let mut s = Stat::default();
    sys_fstat(fd as i32, &mut s);
    t.eq(b"nlink", s.st_nlink as i64, 0);
    t.eq(b"mode", i64::from(s.st_mode), 0o100600);
    t.eq(b"write", sys_write(fd as u64, b"hello".as_ptr(), 5), 5);
    let mut buf = [0u8; 128];
    let mut lp = *b"/proc/self/fd/\0\0\0\0";
    let mut n = fd;
    let mut digits = [0u8; 4];
    let mut k = 0;
    loop {
        digits[k] = b'0' + (n % 10) as u8;
        k += 1;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    for i in 0..k {
        lp[14 + i] = digits[k - 1 - i];
    }
    let r = sys_readlink(lp.as_ptr(), buf.as_mut_ptr(), 128);
    let name = &buf[..r.max(0) as usize];
    t.ok(
        b"fd link",
        name.starts_with(b"/tmp/#") && name.ends_with(b" (deleted)"),
        r,
    );
    let named = b"/tmp/tmpf_named\0";
    let l = sys_linkat(
        fd as i32,
        b"\0".as_ptr(),
        AT_FDCWD,
        named.as_ptr(),
        AT_EMPTY_PATH,
    );
    t.eq(b"linkat", l, 0);
    sys_close(fd as u64);
    let mut s = Stat::default();
    sys_stat(named.as_ptr(), &mut s);
    t.eq(b"linked nlink", s.st_nlink as i64, 1);
    let rfd = sys_open(named.as_ptr(), O_RDONLY, 0);
    let mut rb = [0u8; 8];
    t.eq(b"content", sys_read(rfd as u64, rb.as_mut_ptr(), 8), 5);
    t.ok(b"bytes", &rb[..5] == b"hello", 0);
    sys_close(rfd as u64);
    sys_unlink(named.as_ptr());

    // O_EXCL: never linkable
    let fd = tmpf(b"/tmp\0", O_RDWR | O_EXCL);
    let l = sys_linkat(
        fd as i32,
        b"\0".as_ptr(),
        AT_FDCWD,
        named.as_ptr(),
        AT_EMPTY_PATH,
    );
    t.eq(b"excl linkat", l, ENOENT);
    sys_close(fd as u64);

    t.eq(b"rdonly", tmpf(b"/tmp\0", O_RDONLY), EINVAL);
    let no_dir = sys_open(b"/tmp\0".as_ptr(), hk_syscall::__O_TMPFILE | O_RDWR, 0o600);
    t.eq(b"no O_DIRECTORY", no_dir, EINVAL);
    t.eq(b"O_CREAT", tmpf(b"/tmp\0", O_RDWR | O_CREAT), EINVAL);
    touch(b"/tmp/tmpf_file\0");
    t.eq(b"file", tmpf(b"/tmp/tmpf_file\0", O_RDWR), ENOTDIR);
    sys_unlink(b"/tmp/tmpf_file\0".as_ptr());
    t.eq(b"missing", tmpf(b"/tmp/tmpf_none\0", O_RDWR), ENOENT);
    t.eq(b"procfs", tmpf(b"/proc\0", O_RDWR), EOPNOTSUPP);

    // tmpfs: the root and the tmpfile use both inodes; linking it takes none
    if t.eq(b"mount", mount(b"nr_inodes=2\0"), 0) {
        let fd = tmpf(MP, O_RDWR);
        t.ok(b"tmpfs open", fd >= 0, fd);
        t.eq(b"tmpfs full", tmpf(MP, O_RDWR), ENOSPC);
        let p = b"/tmp/tmpfs_lim/n\0";
        let l = sys_linkat(
            fd as i32,
            b"\0".as_ptr(),
            AT_FDCWD,
            p.as_ptr(),
            AT_EMPTY_PATH,
        );
        t.eq(b"tmpfs link", l, 0);
        t.eq(b"ffree", statfs().f_ffree, 0);
        sys_close(fd as u64);
        sys_unlink(p.as_ptr());
        sys_umount2(MP.as_ptr(), 0);
    }
    t.done();
}
