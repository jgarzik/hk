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

use crate::harness::T;
use crate::helpers::find_blkdev;
use crate::proc::sysfs::each_entry;
use hk_syscall::{
    O_CREAT, O_RDONLY, O_WRONLY, Stat, sys_close, sys_mkdir, sys_mount, sys_open, sys_pread64,
    sys_rename, sys_rmdir, sys_stat, sys_umount2, sys_unlink,
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
