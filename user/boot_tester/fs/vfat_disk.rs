//! vfat's on-disk directory entries, read raw from the device after an
//! unmount (Linux fs/fat; the FAT spec)
//!
//! - VFAT_DOTDOT: a directory made in the root has ".." pointing at
//!   cluster 0 (Linux fat_alloc_new_dir: the root's i_logstart is 0);
//!   one made below it points at its parent's first cluster.
//! - VFAT_NLINK: a directory's st_nlink is 2 + its subdirectories
//!   (Linux fat_subdirs, counting "." and ".."; the root's + 2), kept by
//!   mkdir, rmdir and a rename across directories, and the same when
//!   read again after a remount.
//! - VFAT_TIMES: FAT's times (Linux fs/fat/misc.c): the root's are 0;
//!   a new file's mtime is now in 2 s steps with ctime the same and its
//!   atime the day; utimensat truncates the same way (ctime follows
//!   mtime); a rename keeps the moved file's times; all of it reads the
//!   same after a remount, and a time_offset=60 mount shows the stored
//!   local times an hour earlier
//! - VFAT_ATIME_RO: after a read-only remount a read updates no atime
//!   (Linux touch_atime: mnt_get_write_access refused) and still reads;
//!   the atime on disk is the one before
//! - VFAT_UNLINK_RACE: a file unlinked while another process keeps
//!   reading it (each read's atime update writes its entry back: Linux
//!   __fat_write_inode) stays deleted on disk: after a remount none of
//!   the names is there (Linux fat_remove_entries then fat_detach, the
//!   entry's write-back rechecking i_pos)
//! - VFAT_DIR_GROW: a long name whose slots do not fit in a full
//!   directory's free slots at its end starts there and goes on into a
//!   new cluster (Linux fat_add_entries): after a remount it is found,
//!   with no end-of-directory slot before it
//! - VFAT_HOLE_REUSE: a long name whose slots fit a hole that unlinks
//!   left in a directory takes that hole (Linux fat_add_entries: the
//!   first free run long enough, before any new cluster): after an
//!   unmount its long-name slots and short entry are there on the
//!   device, the directory still has one cluster, and it is found
//! - VFAT_FSYNC_TIMES: utimensat marks the inode dirty (Linux
//!   fat_setattr: mark_inode_dirty); fsync writes its entry (Linux
//!   fat_file_fsync -> sync_inode_metadata -> fat_write_inode): the
//!   device then holds the new date and time
//! - VFAT_FDATASYNC_TIMES: an in-place overwrite (no size or cluster
//!   change) dirties only the times (Linux fat_update_time:
//!   I_DIRTY_SYNC); fdatasync skips them (Linux simple_fsync_noflush:
//!   no I_DIRTY_DATASYNC), so the entry keeps its old time; fsync then
//!   writes the new one
//! - VFAT_ODSYNC_TIMES: the same for a synchronous write: O_DSYNC syncs
//!   the data alone (Linux generic_write_sync: datasync unless
//!   IOCB_SYNC), O_SYNC the times too
//! - VFAT_REMOUNT_RO: a read-only remount writes the dirty inodes
//!   back first (Linux fat_reconfigure: sync_filesystem): utimensat
//!   just before it is in the entry on the device right after it, and
//!   a sync of the read-only filesystem changes nothing
//! - VFAT_DIRTY_EXPIRE: an inode's dirtied time is when it as a whole
//!   went dirty (Linux __mark_inode_dirty: dirtied_when only if it was
//!   clean): a size change waits in memory while its pages are written
//!   (sync_file_range) and dirtied again and again, and the periodic
//!   writeback still writes its entry once it expires
//! - VFAT_DIRSYNC: on a dirsync mount, mkdir, create, rename, unlink
//!   and rmdir work, and a create writes its directory's new times to
//!   its entry at once (Linux vfat_add_entry: sync_inode_metadata)
//! - VFAT_BAD_DIR: a directory whose "." and ".." are gone on disk is
//!   EIO (Linux fat_validate_dir: fewer than 2 subdirectory entries),
//!   and on hk its cluster stays allocated. Linux frees it: the refused
//!   inode is iput with i_nlink 0 and fat_evict_inode truncates it, so
//!   a crafted image loses a live directory's data there; hk checks
//!   before any inode exists.

use crate::harness::T;
use crate::helpers::{find_blkdev, host_mode};
use crate::proc::sysfs::each_entry;
use core::sync::atomic::{AtomicI32, Ordering};
use hk_syscall::sys_fsync;
use hk_syscall::{
    MAP_ANONYMOUS, MAP_SHARED, O_CREAT, O_RDONLY, O_RDWR, O_WRONLY, PROT_READ, PROT_WRITE, Stat,
    Timespec, UTIME_OMIT, sys_clock_gettime, sys_close, sys_exit, sys_fork, sys_mkdir, sys_mmap,
    sys_mount, sys_munmap, sys_open, sys_pread64, sys_pwrite64, sys_read, sys_rename, sys_rmdir,
    sys_sched_yield, sys_stat, sys_sync, sys_umount2, sys_unlink, sys_utimensat, sys_wait4,
    sys_write,
};

const MNT: &[u8] = b"/tmp/vdk\0";

/// The FAT32 geometry of a device (its boot sector)
struct Fat {
    fd: i32,
    bps: u64,
    spc: u64,
    /// First data sector
    data: u64,
    /// First FAT sector
    fat: u64,
    root: u32,
}

/// A raw 32-byte directory entry
type Ent = [u8; 32];

impl Fat {
    fn open(dev: &[u8]) -> Option<Self> {
        let fd = sys_open(dev.as_ptr(), O_RDONLY, 0);
        if fd < 0 {
            return None;
        }
        let mut b = [0u8; 512];
        if sys_pread64(fd as i32, b.as_mut_ptr(), 512, 0) != 512 {
            sys_close(fd as u64);
            return None;
        }
        let u16_at = |o: usize| u64::from(u16::from_le_bytes([b[o], b[o + 1]]));
        let u32_at = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let (bps, spc, rsv, nfats) = (u16_at(11), u64::from(b[13]), u16_at(14), u64::from(b[16]));
        let fatsz = u64::from(u32_at(36));
        Some(Self {
            fd: fd as i32,
            bps,
            spc,
            data: rsv + nfats * fatsz,
            fat: rsv,
            root: u32_at(44),
        })
    }

    fn read(&self, off: u64, buf: &mut [u8]) -> bool {
        sys_pread64(self.fd, buf.as_mut_ptr(), buf.len() as u64, off as i64) == buf.len() as i64
    }

    /// Byte offset of cluster `c`
    fn cl_off(&self, c: u32) -> u64 {
        (self.data + u64::from(c - 2) * self.spc) * self.bps
    }

    /// The cluster after `c`, None at the chain's end
    fn next(&self, c: u32) -> Option<u32> {
        let mut b = [0u8; 4];
        if !self.read(self.fat * self.bps + u64::from(c) * 4, &mut b) {
            return None;
        }
        let n = u32::from_le_bytes(b) & 0x0fff_ffff;
        (2..0x0fff_fff8).contains(&n).then_some(n)
    }

    /// The `i`th entry of the directory starting at cluster `dir`
    fn entry(&self, dir: u32, i: u64) -> Option<Ent> {
        let per = self.spc * self.bps / 32;
        let mut c = dir;
        for _ in 0..i / per {
            c = self.next(c)?;
        }
        let mut e = [0u8; 32];
        self.read(self.cl_off(c) + i % per * 32, &mut e)
            .then_some(e)
    }

    /// The short entry named `short` (11 bytes, 8.3 padded) in `dir`
    fn find(&self, dir: u32, short: &[u8; 11]) -> Option<Ent> {
        let mut i = 0;
        loop {
            let e = self.entry(dir, i)?;
            i += 1;
            match e[0] {
                0 => return None,
                0xe5 => {}
                _ if e[11] == 0x0f => {}
                _ if &e[..11] == short => return Some(e),
                _ => {}
            }
        }
    }
}

impl Drop for Fat {
    fn drop(&mut self) {
        sys_close(self.fd as u64);
    }
}

/// An entry's first cluster
fn start(e: &Ent) -> u32 {
    u32::from(u16::from_le_bytes([e[20], e[21]])) << 16
        | u32::from(u16::from_le_bytes([e[26], e[27]]))
}

/// Mount the vfat of `dev` on MNT
fn mount(dev: &[u8]) -> i64 {
    sys_mount(
        dev.as_ptr(),
        MNT.as_ptr(),
        b"vfat\0".as_ptr(),
        0,
        b"iocharset=cp437\0".as_ptr() as u64,
    )
}

pub fn run_tests() {
    let mut t = T::new(b"VFAT_DOTDOT");
    let Some(d) = find_blkdev(b"vd", 32768) else {
        t.ok(b"no vda1", false, 0);
        t.done();
        return;
    };
    let mut p = [0u8; 48];
    let dev = d.path(&mut p);
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777);
    sys_mkdir(MNT.as_ptr(), 0o755);
    if !t.eq(b"mount", mount(dev), 0) {
        sys_rmdir(MNT.as_ptr());
        t.done();
        return;
    }
    dotdot(&mut t, dev);
    nlink(dev);
    times(dev);
    atime_ro(dev);
    unlink_race(dev);
    dir_grow(dev);
    hole_reuse(dev);
    fsync_times(dev);
    fdatasync_times(dev);
    odsync_times(dev);
    remount_ro(dev);
    dirty_expire(dev);
    dirsync(dev);
    bad_dir(dev);
    sys_umount2(MNT.as_ptr(), 0);
    sys_rmdir(MNT.as_ptr());
    t.done();
}

/// VFAT_DOTDOT: D1 in the root, D1/D2 below it
fn dotdot(t: &mut T, dev: &[u8]) {
    let (d1, d2) = (b"/tmp/vdk/D1\0", b"/tmp/vdk/D1/D2\0");
    t.eq(b"mkdir D1", sys_mkdir(d1.as_ptr(), 0o755), 0);
    t.eq(b"mkdir D2", sys_mkdir(d2.as_ptr(), 0o755), 0);
    t.eq(b"umount", sys_umount2(MNT.as_ptr(), 0), 0);
    match Fat::open(dev) {
        Some(f) => {
            let e1 = f.find(f.root, b"D1         ");
            t.ok(b"D1 entry", e1.is_some(), 0);
            if let Some(e1) = e1 {
                let c1 = start(&e1);
                let up1 = f.entry(c1, 1).map_or(u32::MAX, |e| start(&e));
                t.eq(b"D1 .. is 0", i64::from(up1), 0);
                let up2 = f
                    .find(c1, b"D2         ")
                    .and_then(|e2| f.entry(start(&e2), 1))
                    .map_or(u32::MAX, |e| start(&e));
                t.eq(b"D2 .. is D1", i64::from(up2), i64::from(c1));
            }
        }
        None => {
            t.ok(b"open device", false, 0);
        }
    }
    t.eq(b"remount", mount(dev), 0);
    sys_rmdir(d2.as_ptr());
    sys_rmdir(d1.as_ptr());
}

/// st_nlink of `p`, or -1
fn links(p: &[u8]) -> i64 {
    let mut st = Stat::default();
    if sys_stat(p.as_ptr(), &mut st) == 0 {
        st.st_nlink as i64
    } else {
        -1
    }
}

/// 2 + the directories `dir` lists
fn want(dir: &[u8]) -> i64 {
    const DT_DIR: u8 = 4;
    let mut n = 2;
    each_entry(dir, &mut |_, ty| n += i64::from(ty == DT_DIR));
    n
}

/// VFAT_NLINK: N with subdirectories a and b and a file f
fn nlink(dev: &[u8]) {
    let mut t = T::new(b"VFAT_NLINK");
    let (n, a, b, f) = (
        b"/tmp/vdk/N\0",
        b"/tmp/vdk/N/a\0",
        b"/tmp/vdk/N/b\0",
        b"/tmp/vdk/N/f\0",
    );
    let moved = b"/tmp/vdk/Nb\0";
    t.eq(b"mkdir N", sys_mkdir(n.as_ptr(), 0o755), 0);
    t.eq(b"new dir", links(n), 2);
    t.eq(b"mkdir a", sys_mkdir(a.as_ptr(), 0o755), 0);
    t.eq(b"mkdir b", sys_mkdir(b.as_ptr(), 0o755), 0);
    let fd = sys_open(f.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    if fd >= 0 {
        sys_close(fd as u64);
    }
    t.eq(b"N: a, b", links(n), 4);
    t.eq(b"a", links(a), 2);
    t.eq(b"f", links(f), 1);
    t.eq(b"root", links(MNT), want(MNT));
    t.eq(b"rmdir a", sys_rmdir(a.as_ptr()), 0);
    t.eq(b"N: b", links(n), 3);
    t.eq(b"move b out", sys_rename(b.as_ptr(), moved.as_ptr()), 0);
    t.eq(b"N: none", links(n), 2);
    t.eq(b"root after move", links(MNT), want(MNT));
    t.eq(b"mkdir a again", sys_mkdir(a.as_ptr(), 0o755), 0);
    t.eq(b"umount", sys_umount2(MNT.as_ptr(), 0), 0);
    t.eq(b"remount", mount(dev), 0);
    t.eq(b"N read again", links(n), 3);
    t.eq(b"root read again", links(MNT), want(MNT));
    sys_unlink(f.as_ptr());
    sys_rmdir(a.as_ptr());
    sys_rmdir(n.as_ptr());
    sys_rmdir(moved.as_ptr());
    t.done();
}

/// Write `buf` at `off` of the device `dev`
fn poke(dev: &[u8], off: u64, buf: &[u8]) -> bool {
    let fd = sys_open(dev.as_ptr(), O_RDWR, 0);
    if fd < 0 {
        return false;
    }
    let n = sys_pwrite64(fd as i32, buf.as_ptr(), buf.len() as u64, off as i64);
    sys_close(fd as u64);
    n == buf.len() as i64
}

/// The FAT entry of cluster `c`, or u32::MAX
fn fat_of(f: &Fat, c: u32) -> u32 {
    let mut b = [0u8; 4];
    if !f.read(f.fat * f.bps + u64::from(c) * 4, &mut b) {
        return u32::MAX;
    }
    u32::from_le_bytes(b) & 0x0fff_ffff
}

/// VFAT_BAD_DIR: BAD's "." and ".." marked deleted on disk
fn bad_dir(dev: &[u8]) {
    const EIO: i64 = -5;
    let mut t = T::new(b"VFAT_BAD_DIR");
    let bad = b"/tmp/vdk/BAD\0";
    t.eq(b"mkdir", sys_mkdir(bad.as_ptr(), 0o755), 0);
    t.eq(b"umount", sys_umount2(MNT.as_ptr(), 0), 0);
    let mut saved = [0u8; 64];
    let mut at = None;
    if let Some(f) = Fat::open(dev)
        && let Some(e) = f.find(f.root, b"BAD        ")
    {
        let c = start(&e);
        let off = f.cl_off(c);
        if f.read(off, &mut saved) {
            at = Some((c, off, fat_of(&f, c)));
        }
    }
    let Some((c, off, before)) = at else {
        t.ok(b"BAD on disk", false, 0);
        mount(dev);
        sys_rmdir(bad.as_ptr());
        t.done();
        return;
    };
    let mut gone = saved;
    gone[0] = 0xe5;
    gone[32] = 0xe5;
    t.ok(b"poke", poke(dev, off, &gone), 0);
    t.eq(b"remount", mount(dev), 0);
    t.eq(
        b"stat BAD",
        sys_stat(bad.as_ptr(), &mut Stat::default()),
        EIO,
    );
    t.eq(b"umount again", sys_umount2(MNT.as_ptr(), 0), 0);
    let fat = Fat::open(dev);
    let after = fat.as_ref().map_or(u32::MAX, |f| fat_of(f, c));
    let kept = before != 0 && after == before;
    if !host_mode() {
        t.ok(b"cluster kept", kept, i64::from(after));
    } else if !kept && let Some(f) = &fat {
        // A Linux bug: fat_build_inode iputs the refused inode (i_nlink 0)
        // and fat_evict_inode frees a live directory's cluster; put back
        // in the first FAT for the cleanup
        poke(dev, f.fat * f.bps + u64::from(c) * 4, &before.to_le_bytes());
    }
    drop(fat);
    t.ok(b"restore", poke(dev, off, &saved), 0);
    t.eq(b"mount restored", mount(dev), 0);
    t.eq(b"rmdir", sys_rmdir(bad.as_ptr()), 0);
    t.done();
}

/// (atime, mtime, ctime) of `p` as (seconds, nanoseconds)
fn stimes(p: &[u8]) -> [(i64, i64); 3] {
    let mut st = Stat::default();
    sys_stat(p.as_ptr(), &mut st);
    [
        (st.st_atime, st.st_atime_nsec as i64),
        (st.st_mtime, st.st_mtime_nsec as i64),
        (st.st_ctime, st.st_ctime_nsec as i64),
    ]
}

/// Mount the vfat of `dev` on MNT with options `opts`
fn mount_with(dev: &[u8], opts: &[u8]) -> i64 {
    sys_mount(
        dev.as_ptr(),
        MNT.as_ptr(),
        b"vfat\0".as_ptr(),
        0,
        opts.as_ptr() as u64,
    )
}

/// VFAT_TIMES on TD/F, renamed TD/G
fn times(dev: &[u8]) {
    const DAY: i64 = 86_400;
    let mut t = T::new(b"VFAT_TIMES");
    let (d, f, g) = (b"/tmp/vdk/TD\0", b"/tmp/vdk/TD/F\0", b"/tmp/vdk/TD/G\0");
    let root = stimes(MNT);
    t.ok(b"root times 0", root == [(0, 0); 3], root[1].0);
    t.eq(b"mkdir", sys_mkdir(d.as_ptr(), 0o755), 0);
    let mut now = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    sys_clock_gettime(0, &mut now);
    let fd = sys_open(f.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    t.ok(b"create", fd >= 0, fd);
    if fd >= 0 {
        sys_write(fd as u64, b"x".as_ptr(), 1);
        sys_close(fd as u64);
    }
    let [a, m, c] = stimes(f);
    t.ok(b"mtime 2 s", m.0 % 2 == 0 && m.1 == 0, m.1);
    // FAT holds no time before 1980-01-01 (Linux fat_time_unix2fat
    // clamps to it): a guest whose clock starts at the epoch, as the
    // reference arm64 VM's does, gets that
    const FAT_MIN: i64 = 315_532_800;
    let want = now.tv_sec.max(FAT_MIN);
    t.ok(b"mtime now", (m.0 - want).abs() <= 3, m.0 - want);
    t.ok(b"ctime is mtime", c == m, c.0);
    t.ok(b"atime the day", a.0 % DAY == 0 && a.1 == 0, a.0 % DAY);
    let [_, dm, dc] = stimes(d);
    t.ok(
        b"dir mtime 2 s",
        dm.0 % 2 == 0 && dm.1 == 0 && dc == dm,
        dm.1,
    );
    let ts = [
        Timespec {
            tv_sec: 1_600_000_123,
            tv_nsec: 500_000_000,
        },
        Timespec {
            tv_sec: 1_500_000_001,
            tv_nsec: 700_000_000,
        },
    ];
    t.eq(
        b"utimensat",
        sys_utimensat(-100, f.as_ptr(), ts.as_ptr(), 0),
        0,
    );
    let set = [(1_599_955_200, 0), (1_500_000_000, 0), (1_500_000_000, 0)];
    let got = stimes(f);
    t.ok(b"utimensat truncated", got == set, got[1].0);
    t.eq(b"rename", sys_rename(f.as_ptr(), g.as_ptr()), 0);
    let got = stimes(g);
    t.ok(b"rename keeps", got == set, got[1].0);
    t.eq(b"umount", sys_umount2(MNT.as_ptr(), 0), 0);
    t.eq(b"remount", mount(dev), 0);
    let got = stimes(g);
    t.ok(b"kept on disk", got == set, got[1].0);
    let [_, dm2, _] = stimes(d);
    t.ok(b"dir kept", dm2.0 % 2 == 0 && dm2.0 >= dm.0, dm2.0);
    t.eq(b"umount 2", sys_umount2(MNT.as_ptr(), 0), 0);
    t.eq(
        b"time_offset=60",
        mount_with(dev, b"iocharset=cp437,time_offset=60\0"),
        0,
    );
    let [_, om, _] = stimes(g);
    t.eq(b"an hour earlier", om.0, 1_500_000_000 - 3600);
    t.eq(b"umount 3", sys_umount2(MNT.as_ptr(), 0), 0);
    t.eq(b"mount again", mount(dev), 0);
    sys_unlink(g.as_ptr());
    sys_rmdir(d.as_ptr());
    t.done();
}

/// VFAT_ATIME_RO on R, its atime set to OLD's day before
fn atime_ro(dev: &[u8]) {
    const MS_RDONLY: u64 = 1;
    const MS_REMOUNT: u64 = 32;
    /// 2017-07-14, a day boundary (FAT keeps the atime's date only)
    const OLD: i64 = 1_499_990_400;
    let mut t = T::new(b"VFAT_ATIME_RO");
    let r = b"/tmp/vdk/R\0";
    let fd = sys_open(r.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    t.ok(b"create", fd >= 0, fd);
    if fd >= 0 {
        sys_write(fd as u64, b"data".as_ptr(), 4);
        sys_close(fd as u64);
    }
    let ts = [
        Timespec {
            tv_sec: OLD,
            tv_nsec: 0,
        },
        Timespec {
            tv_sec: 0,
            tv_nsec: UTIME_OMIT,
        },
    ];
    t.eq(
        b"utimensat",
        sys_utimensat(-100, r.as_ptr(), ts.as_ptr(), 0),
        0,
    );
    let remount = |f: u64| {
        sys_mount(
            dev.as_ptr(),
            MNT.as_ptr(),
            core::ptr::null(),
            MS_REMOUNT | f,
            b"iocharset=cp437\0".as_ptr() as u64,
        )
    };
    t.eq(b"remount ro", remount(MS_RDONLY), 0);
    let fd = sys_open(r.as_ptr(), O_RDONLY, 0);
    t.ok(b"open ro", fd >= 0, fd);
    if fd >= 0 {
        let mut b = [0u8; 8];
        let n = sys_read(fd as u64, b.as_mut_ptr(), b.len() as u64);
        t.eq(b"read", n, 4);
        sys_close(fd as u64);
    }
    t.eq(b"atime kept", stimes(r)[0].0, OLD);
    t.eq(b"remount rw", remount(0), 0);
    t.eq(b"umount", sys_umount2(MNT.as_ptr(), 0), 0);
    t.eq(b"mount again", mount(dev), 0);
    t.eq(b"atime on disk", stimes(r)[0].0, OLD);
    sys_unlink(r.as_ptr());
    t.done();
}

/// Rounds of VFAT_UNLINK_RACE
const RACE_ROUNDS: i32 = 200;

/// The path of round `n`'s file, /tmp/vdk/U<n>
fn race_path(n: i32, out: &mut [u8; 24]) -> &[u8] {
    let pre = b"/tmp/vdk/U";
    out[..pre.len()].copy_from_slice(pre);
    let mut i = pre.len();
    let mut digits = [0u8; 10];
    let mut k = 0;
    let mut v = n as u32;
    loop {
        digits[k] = b'0' + (v % 10) as u8;
        k += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    while k > 0 {
        k -= 1;
        out[i] = digits[k];
        i += 1;
    }
    out[i] = 0;
    &out[..=i]
}

/// Spin (yielding) until `w` reads `v`
fn wait_for(w: &AtomicI32, v: i32) {
    while w.load(Ordering::Acquire) != v {
        sys_sched_yield();
    }
}

/// VFAT_UNLINK_RACE: per round the parent makes U<n>, the child opens
/// it and reads it in a loop, the parent unlinks it meanwhile
fn unlink_race(dev: &[u8]) {
    let mut t = T::new(b"VFAT_UNLINK_RACE");
    let p = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0,
    );
    if !t.ok(b"mmap", p > 0, p) {
        t.done();
        return;
    }
    // SAFETY: a fresh MAP_SHARED page, unmapped only below
    // [0]: made; [1]: opened; [2]: unlinked; [3]: closed
    let sh = unsafe { core::slice::from_raw_parts(p as *const AtomicI32, 4) };
    let pid = sys_fork();
    if pid == 0 {
        let mut path = [0u8; 24];
        for n in 1..=RACE_ROUNDS {
            wait_for(&sh[0], n);
            let fd = sys_open(race_path(n, &mut path).as_ptr(), O_RDONLY, 0);
            sh[1].store(n, Ordering::Release);
            let mut b = [0u8; 4];
            while sh[2].load(Ordering::Acquire) != n {
                if fd >= 0 {
                    sys_pread64(fd as i32, b.as_mut_ptr(), 4, 0);
                }
            }
            if fd >= 0 {
                sys_close(fd as u64);
            }
            sh[3].store(n, Ordering::Release);
        }
        sys_exit(0);
    }
    let mut path = [0u8; 24];
    for n in 1..=RACE_ROUNDS {
        let u = race_path(n, &mut path);
        let fd = sys_open(u.as_ptr(), O_CREAT | O_WRONLY, 0o644);
        if fd >= 0 {
            sys_write(fd as u64, b"data".as_ptr(), 4);
            sys_close(fd as u64);
        }
        sh[0].store(n, Ordering::Release);
        wait_for(&sh[1], n);
        sys_sched_yield();
        sys_unlink(u.as_ptr());
        sh[2].store(n, Ordering::Release);
        wait_for(&sh[3], n);
    }
    let mut ws = 0;
    sys_wait4(pid, &mut ws, 0, 0);
    t.eq(b"child", ws as i64, 0);
    sys_munmap(p as u64, 4096);
    t.eq(b"umount", sys_umount2(MNT.as_ptr(), 0), 0);
    t.eq(b"remount", mount(dev), 0);
    let mut live = 0;
    let mut first = 0;
    for n in 1..=RACE_ROUNDS {
        let u = race_path(n, &mut path);
        if sys_stat(u.as_ptr(), &mut Stat::default()) == 0 {
            live += 1;
            if first == 0 {
                first = n;
            }
            sys_unlink(u.as_ptr());
        }
    }
    t.ok(b"all deleted", live == 0, i64::from(live * 1000 + first));
    t.done();
}

/// `/tmp/vdk/GD/F<n>` (8.3 upper case: one slot on Linux and hk)
fn grow_path(n: u64, out: &mut [u8; 32]) -> &[u8] {
    let pre = b"/tmp/vdk/GD/F";
    out[..pre.len()].copy_from_slice(pre);
    let mut i = pre.len();
    let mut digits = [0u8; 20];
    let (mut k, mut v) = (0, n);
    loop {
        digits[k] = b'0' + (v % 10) as u8;
        k += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    while k > 0 {
        k -= 1;
        out[i] = digits[k];
        i += 1;
    }
    out[i] = 0;
    &out[..=i]
}

/// VFAT_DIR_GROW: GD's first cluster filled but for 2 slots, then a
/// name of 3 slots (2 long-name ones and its short entry)
fn dir_grow(dev: &[u8]) {
    let mut t = T::new(b"VFAT_DIR_GROW");
    let gd = b"/tmp/vdk/GD\0";
    let long = b"/tmp/vdk/GD/a long name entry here.txt\0";
    let per = Fat::open(dev).map_or(0, |f| f.spc * f.bps / 32);
    if !t.ok(b"geometry", per >= 8, per as i64) {
        t.done();
        return;
    }
    t.eq(b"mkdir", sys_mkdir(gd.as_ptr(), 0o755), 0);
    // "." and ".." take two slots; leave two free at the end
    let files = per - 4;
    let mut path = [0u8; 32];
    for n in 0..files {
        let fd = sys_open(grow_path(n, &mut path).as_ptr(), O_CREAT | O_WRONLY, 0o644);
        if fd < 0 {
            t.ok(b"create", false, fd);
            break;
        }
        sys_close(fd as u64);
    }
    let fd = sys_open(long.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    t.ok(b"create long", fd >= 0, fd);
    if fd >= 0 {
        sys_close(fd as u64);
    }
    t.eq(b"umount", sys_umount2(MNT.as_ptr(), 0), 0);
    t.eq(b"remount", mount(dev), 0);
    t.eq(
        b"long found",
        sys_stat(long.as_ptr(), &mut Stat::default()),
        0,
    );
    let last = grow_path(files - 1, &mut path);
    t.eq(
        b"last short",
        sys_stat(last.as_ptr(), &mut Stat::default()),
        0,
    );
    sys_unlink(long.as_ptr());
    for n in 0..files {
        sys_unlink(grow_path(n, &mut path).as_ptr());
    }
    t.eq(b"rmdir", sys_rmdir(gd.as_ptr()), 0);
    t.done();
}

/// `/tmp/vdk/HD/F<n>` (one slot, as `grow_path`)
fn hole_path(n: u64, out: &mut [u8; 32]) -> &[u8] {
    let len = grow_path(n, out).len();
    out[b"/tmp/vdk/".len()] = b'H';
    &out[..len]
}

/// VFAT_HOLE_REUSE: HD's first cluster filled but for its last slot
/// with one-slot names F0.., F1..F3 (slots 3..5) unlinked, then a name
/// of 3 slots (2 long-name ones and its short entry)
fn hole_reuse(dev: &[u8]) {
    let mut t = T::new(b"VFAT_HOLE_REUSE");
    let hd = b"/tmp/vdk/HD\0";
    let long = b"/tmp/vdk/HD/a long name entry here.txt\0";
    let per = Fat::open(dev).map_or(0, |f| f.spc * f.bps / 32);
    if !t.ok(b"geometry", per >= 8, per as i64) {
        t.done();
        return;
    }
    t.eq(b"mkdir", sys_mkdir(hd.as_ptr(), 0o755), 0);
    // "." and ".." take slots 0 and 1, F<n> slot n + 2; the last is free
    let files = per - 3;
    let mut path = [0u8; 32];
    for n in 0..files {
        let fd = sys_open(hole_path(n, &mut path).as_ptr(), O_CREAT | O_WRONLY, 0o644);
        if fd < 0 {
            t.ok(b"create", false, fd);
            break;
        }
        sys_close(fd as u64);
    }
    for n in 1..4 {
        t.eq(b"unlink", sys_unlink(hole_path(n, &mut path).as_ptr()), 0);
    }
    let fd = sys_open(long.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    t.ok(b"create long", fd >= 0, fd);
    if fd >= 0 {
        sys_close(fd as u64);
    }
    t.eq(b"umount", sys_umount2(MNT.as_ptr(), 0), 0);
    match Fat::open(dev) {
        Some(f) => match f.find(f.root, b"HD         ") {
            Some(e) => {
                let c = start(&e);
                t.ok(b"one cluster", f.next(c).is_none(), 0);
                let attr = |i| f.entry(c, i).map_or(0xff, |e| e[11]);
                let first = f.entry(c, 3).map_or(0, |e| e[0]);
                t.eq(b"slot 3 last lfn", i64::from(first), 0x42);
                t.eq(b"slot 4 lfn", i64::from(attr(4)), 0x0f);
                let short = f.entry(c, 5).unwrap_or([0; 32]);
                t.ok(
                    b"slot 5 short",
                    short[0] != 0 && short[0] != 0xe5 && short[11] == 0x20,
                    i64::from(short[11]),
                );
            }
            None => {
                t.ok(b"HD entry", false, 0);
            }
        },
        None => {
            t.ok(b"open device", false, 0);
        }
    }
    t.eq(b"remount", mount(dev), 0);
    t.eq(
        b"long found",
        sys_stat(long.as_ptr(), &mut Stat::default()),
        0,
    );
    sys_unlink(long.as_ptr());
    for n in 0..files {
        sys_unlink(hole_path(n, &mut path).as_ptr());
    }
    t.eq(b"rmdir", sys_rmdir(hd.as_ptr()), 0);
    t.done();
}

/// VFAT_FSYNC_TIMES on FS in the root, mounted tz=UTC
fn fsync_times(dev: &[u8]) {
    let mut t = T::new(b"VFAT_FSYNC_TIMES");
    let f = b"/tmp/vdk/FS\0";
    t.eq(b"umount", sys_umount2(MNT.as_ptr(), 0), 0);
    t.eq(
        b"mount tz=UTC",
        mount_with(dev, b"iocharset=cp437,tz=UTC\0"),
        0,
    );
    let fd = sys_open(f.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    t.ok(b"create", fd >= 0, fd);
    // 2017-07-14 02:40:00 UTC (atime 00:00 that day)
    let ts = [
        Timespec {
            tv_sec: 1_499_990_400,
            tv_nsec: 0,
        },
        Timespec {
            tv_sec: 1_500_000_000,
            tv_nsec: 0,
        },
    ];
    t.eq(
        b"utimensat",
        sys_utimensat(-100, f.as_ptr(), ts.as_ptr(), 0),
        0,
    );
    if fd >= 0 {
        t.eq(b"fsync", sys_fsync(fd as i32), 0);
        sys_close(fd as u64);
    }
    // FAT date (year - 1980) << 9 | month << 5 | day; time h << 11 |
    // m << 5 | s / 2
    const DATE: u16 = 37 << 9 | 7 << 5 | 14;
    const TIME: u16 = 2 << 11 | 40 << 5;
    let e = Fat::open(dev).and_then(|d| d.find(d.root, b"FS         "));
    let u16_at = |e: &Ent, o: usize| u16::from_le_bytes([e[o], e[o + 1]]);
    match e {
        Some(e) => {
            t.eq(b"time", i64::from(u16_at(&e, 22)), i64::from(TIME));
            t.eq(b"date", i64::from(u16_at(&e, 24)), i64::from(DATE));
            t.eq(b"adate", i64::from(u16_at(&e, 18)), i64::from(DATE));
        }
        None => {
            t.ok(b"entry", false, 0);
        }
    }
    sys_unlink(f.as_ptr());
    t.eq(b"umount 2", sys_umount2(MNT.as_ptr(), 0), 0);
    t.eq(b"mount again", mount(dev), 0);
    t.done();
}

/// 2017-07-14 02:40:00 UTC as a FAT (time, date): time h << 11 | m << 5
/// | s / 2, date (year - 1980) << 9 | month << 5 | day
const OLD_FAT: (i64, i64) = (2 << 11 | 40 << 5, 37 << 9 | 7 << 5 | 14);

/// Give `f` (root entry `short`) a page of data and the mtime 2017-07-14
/// 02:40:00 UTC, synced (fsync on `fd`): the entry holds that time
fn old_synced(t: &mut T, dev: &[u8], fd: i32, f: &[u8], short: &[u8; 11]) {
    let page = [b'a'; 4096];
    t.eq(b"fill", sys_pwrite64(fd, page.as_ptr(), 4096, 0), 4096);
    t.eq(b"utimensat old", utimes(f, 1_500_000_000), 0);
    t.eq(b"fsync old", sys_fsync(fd), 0);
    let got = disk_time(dev, short);
    t.ok(b"old on disk", got == OLD_FAT, got.0);
}

/// Overwrite `fd`'s first bytes in place: no size or cluster change,
/// only the times (now, unlike the entry's 2017)
fn overwrite(t: &mut T, fd: i32) {
    t.eq(b"overwrite", sys_pwrite64(fd, b"bb".as_ptr(), 2, 0), 2);
}

/// VFAT_FDATASYNC_TIMES on FD in the root, mounted tz=UTC
fn fdatasync_times(dev: &[u8]) {
    use hk_syscall::sys_fdatasync;
    let mut t = T::new(b"VFAT_FDATASYNC_TIMES");
    let (f, short) = (b"/tmp/vdk/FD\0", b"FD         ");
    t.eq(b"umount", sys_umount2(MNT.as_ptr(), 0), 0);
    t.eq(
        b"mount tz=UTC",
        mount_with(dev, b"iocharset=cp437,tz=UTC\0"),
        0,
    );
    let fd = sys_open(f.as_ptr(), O_CREAT | O_RDWR, 0o644);
    t.ok(b"create", fd >= 0, fd);
    if fd >= 0 {
        let fd = fd as i32;
        old_synced(&mut t, dev, fd, f, short);
        overwrite(&mut t, fd);
        t.eq(b"fdatasync", sys_fdatasync(fd), 0);
        let got = disk_time(dev, short);
        t.ok(b"times not synced", got == OLD_FAT, got.0);
        t.eq(b"fsync", sys_fsync(fd), 0);
        let got = disk_time(dev, short);
        t.ok(b"times synced", got.0 >= 0 && got != OLD_FAT, got.0);
        sys_close(fd as u64);
    }
    sys_unlink(f.as_ptr());
    t.eq(b"umount 2", sys_umount2(MNT.as_ptr(), 0), 0);
    t.eq(b"mount again", mount(dev), 0);
    t.done();
}

/// VFAT_ODSYNC_TIMES on OD in the root, mounted tz=UTC
fn odsync_times(dev: &[u8]) {
    const O_DSYNC: u32 = 0o10000;
    const O_SYNC: u32 = 0o4010000;
    let mut t = T::new(b"VFAT_ODSYNC_TIMES");
    let (f, short) = (b"/tmp/vdk/OD\0", b"OD         ");
    t.eq(b"umount", sys_umount2(MNT.as_ptr(), 0), 0);
    t.eq(
        b"mount tz=UTC",
        mount_with(dev, b"iocharset=cp437,tz=UTC\0"),
        0,
    );
    for (flag, name, synced) in [
        (O_DSYNC, &b"O_DSYNC"[..], false),
        (O_SYNC, &b"O_SYNC"[..], true),
    ] {
        let fd = sys_open(f.as_ptr(), O_CREAT | O_RDWR | flag, 0o644);
        t.ok(name, fd >= 0, fd);
        if fd < 0 {
            continue;
        }
        let fd = fd as i32;
        old_synced(&mut t, dev, fd, f, short);
        overwrite(&mut t, fd);
        let got = disk_time(dev, short);
        if synced {
            t.ok(b"O_SYNC: times synced", got.0 >= 0 && got != OLD_FAT, got.0);
        } else {
            t.ok(b"O_DSYNC: times not synced", got == OLD_FAT, got.0);
        }
        sys_close(fd as u64);
    }
    sys_unlink(f.as_ptr());
    t.eq(b"umount 2", sys_umount2(MNT.as_ptr(), 0), 0);
    t.eq(b"mount again", mount(dev), 0);
    t.done();
}

/// Set `p`'s atime and mtime to `s` seconds
fn utimes(p: &[u8], s: i64) -> i64 {
    let ts = [
        Timespec {
            tv_sec: s,
            tv_nsec: 0,
        },
        Timespec {
            tv_sec: s,
            tv_nsec: 0,
        },
    ];
    sys_utimensat(-100, p.as_ptr(), ts.as_ptr(), 0)
}

/// The (time, date) of root entry `short` on the device
fn disk_time(dev: &[u8], short: &[u8; 11]) -> (i64, i64) {
    let e = Fat::open(dev).and_then(|d| d.find(d.root, short));
    e.map_or((-1, -1), |e| {
        let u16_at = |o: usize| i64::from(u16::from_le_bytes([e[o], e[o + 1]]));
        (u16_at(22), u16_at(24))
    })
}

/// VFAT_REMOUNT_RO on RO in the root, mounted tz=UTC
fn remount_ro(dev: &[u8]) {
    const MS_RDONLY: u64 = 1;
    const MS_REMOUNT: u64 = 32;
    // 2017-07-14 02:40:00 UTC, then 2020-09-13 12:26:40 UTC
    const OLD: (i64, i64) = (2 << 11 | 40 << 5, 37 << 9 | 7 << 5 | 14);
    const NEW: (i64, i64) = (12 << 11 | 26 << 5 | 20, 40 << 9 | 9 << 5 | 13);
    let mut t = T::new(b"VFAT_REMOUNT_RO");
    let (f, short) = (b"/tmp/vdk/RO\0", b"RO         ");
    let opts = b"iocharset=cp437,tz=UTC\0";
    t.eq(b"umount", sys_umount2(MNT.as_ptr(), 0), 0);
    t.eq(b"mount tz=UTC", mount_with(dev, opts), 0);
    let fd = sys_open(f.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    t.ok(b"create", fd >= 0, fd);
    if fd >= 0 {
        sys_close(fd as u64);
    }
    t.eq(b"utimensat old", utimes(f, 1_500_000_000), 0);
    sys_sync();
    t.ok(
        b"old on disk",
        disk_time(dev, short) == OLD,
        disk_time(dev, short).0,
    );
    t.eq(b"utimensat new", utimes(f, 1_600_000_000), 0);
    let remount = |fl: u64| {
        sys_mount(
            dev.as_ptr(),
            MNT.as_ptr(),
            core::ptr::null(),
            MS_REMOUNT | fl,
            opts.as_ptr() as u64,
        )
    };
    t.eq(b"remount ro", remount(MS_RDONLY), 0);
    let got = disk_time(dev, short);
    t.ok(b"written by the remount", got == NEW, got.0);
    sys_sync();
    let got = disk_time(dev, short);
    t.ok(b"kept after sync", got == NEW, got.0);
    t.eq(b"remount rw", remount(0), 0);
    sys_unlink(f.as_ptr());
    t.eq(b"umount 2", sys_umount2(MNT.as_ptr(), 0), 0);
    t.eq(b"mount again", mount(dev), 0);
    t.done();
}

/// Write `v` to sysctl file `p`, the old value (up to 16 bytes) kept
/// in `old`; its length
fn sysctl_swap(p: &[u8], v: &[u8], old: &mut [u8; 16]) -> i64 {
    let n = crate::helpers::read_file(p, old);
    let fd = sys_open(p.as_ptr(), O_WRONLY, 0);
    if fd >= 0 {
        sys_write(fd as u64, v.as_ptr(), v.len() as u64);
        sys_close(fd as u64);
    }
    n
}

/// The size in root entry `short` on the device
fn disk_size(dev: &[u8], short: &[u8; 11]) -> i64 {
    let e = Fat::open(dev).and_then(|d| d.find(d.root, short));
    e.map_or(-1, |e| {
        i64::from(u32::from_le_bytes([e[28], e[29], e[30], e[31]]))
    })
}

/// VFAT_DIRTY_EXPIRE on DX in the root: expiry 1 s, writeback every
/// 0.5 s, its page rewritten every 0.1 s for up to 10 s
fn dirty_expire(dev: &[u8]) {
    use hk_syscall::sys_sync_file_range;
    let mut t = T::new(b"VFAT_DIRTY_EXPIRE");
    let (f, short) = (b"/tmp/vdk/DX\0", b"DX         ");
    let exp = b"/proc/sys/vm/dirty_expire_centisecs\0";
    let wb = b"/proc/sys/vm/dirty_writeback_centisecs\0";
    let (mut old_exp, mut old_wb) = ([0u8; 16], [0u8; 16]);
    let ne = sysctl_swap(exp, b"100", &mut old_exp);
    let nw = sysctl_swap(wb, b"50", &mut old_wb);
    let fd = sys_open(f.as_ptr(), O_CREAT | O_RDWR, 0o644);
    t.ok(b"create", fd >= 0, fd);
    sys_sync();
    t.eq(b"empty on disk", disk_size(dev, short), 0);
    t.eq(b"write", sys_pwrite64(fd as i32, b"x".as_ptr(), 1, 0), 1);
    let mut got = -1;
    for _ in 0..100 {
        // SYNC_FILE_RANGE_WAIT_BEFORE | WRITE | WAIT_AFTER: the pages
        // only, the inode stays dirty
        sys_sync_file_range(fd as i32, 0, 0, 7);
        sys_pwrite64(fd as i32, b"y".as_ptr(), 1, 0);
        crate::helpers::msleep(100);
        got = disk_size(dev, short);
        if got == 1 {
            break;
        }
    }
    t.eq(b"size written back", got, 1);
    if fd >= 0 {
        sys_close(fd as u64);
    }
    sys_unlink(f.as_ptr());
    if ne > 0 {
        let mut d = [0u8; 16];
        sysctl_swap(exp, &old_exp[..ne as usize], &mut d);
    }
    if nw > 0 {
        let mut d = [0u8; 16];
        sysctl_swap(wb, &old_wb[..nw as usize], &mut d);
    }
    t.done();
}

/// VFAT_DIRSYNC on DS in the root, mounted dirsync and tz=UTC
fn dirsync(dev: &[u8]) {
    const MS_DIRSYNC: u64 = 128;
    // utimensat's 2017-07-14 02:40:00 UTC as FAT (time, date)
    const OLD: (i64, i64) = (2 << 11 | 40 << 5, 37 << 9 | 7 << 5 | 14);
    let mut t = T::new(b"VFAT_DIRSYNC");
    let (d, short) = (b"/tmp/vdk/DS\0", b"DS         ");
    let (f, g) = (b"/tmp/vdk/DS/F\0", b"/tmp/vdk/DS/G\0");
    t.eq(b"umount", sys_umount2(MNT.as_ptr(), 0), 0);
    let r = sys_mount(
        dev.as_ptr(),
        MNT.as_ptr(),
        b"vfat\0".as_ptr(),
        MS_DIRSYNC,
        b"iocharset=cp437,tz=UTC\0".as_ptr() as u64,
    );
    t.eq(b"mount dirsync", r, 0);
    t.eq(b"mkdir", sys_mkdir(d.as_ptr(), 0o755), 0);
    t.eq(b"utimensat", utimes(d, 1_500_000_000), 0);
    let fd = sys_open(f.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    t.ok(b"create", fd >= 0, fd);
    if fd >= 0 {
        sys_close(fd as u64);
    }
    let got = disk_time(dev, short);
    t.ok(b"dir times written", got != OLD && got.1 > 0, got.1);
    t.eq(b"rename", sys_rename(f.as_ptr(), g.as_ptr()), 0);
    t.eq(b"unlink", sys_unlink(g.as_ptr()), 0);
    t.eq(b"rmdir", sys_rmdir(d.as_ptr()), 0);
    t.eq(b"umount 2", sys_umount2(MNT.as_ptr(), 0), 0);
    t.eq(b"mount again", mount(dev), 0);
    t.done();
}
