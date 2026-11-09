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
