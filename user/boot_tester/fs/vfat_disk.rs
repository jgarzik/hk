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
//! - VFAT_BAD_DIR: a directory whose "." and ".." are gone on disk is
//!   EIO (Linux fat_validate_dir: fewer than 2 subdirectory entries),
//!   and on hk its cluster stays allocated. Linux frees it: the refused
//!   inode is iput with i_nlink 0 and fat_evict_inode truncates it, so
//!   a crafted image loses a live directory's data there; hk checks
//!   before any inode exists.

use crate::harness::T;
use crate::helpers::{find_blkdev, host_mode};
use crate::proc::sysfs::each_entry;
use hk_syscall::{
    O_CREAT, O_RDONLY, O_RDWR, O_WRONLY, Stat, Timespec, sys_clock_gettime, sys_close, sys_mkdir,
    sys_mount, sys_open, sys_pread64, sys_pwrite64, sys_rename, sys_rmdir, sys_stat, sys_umount2,
    sys_unlink, sys_utimensat, sys_write,
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
