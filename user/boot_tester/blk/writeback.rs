//! Periodic writeback (Linux the bdi flusher: wb_workfn, kupdate-style
//! writeback every vm.dirty_writeback_centisecs of what is older than
//! vm.dirty_expire_centisecs): a buffered write to vda3, with no fsync
//! or sync, reaches the disk by itself. Both intervals are shortened for
//! the test and put back after. Seen
//! through the whole disk vda with O_DIRECT: its page cache is not the
//! partition's, and a direct read there writes nothing of vda3's back.

use crate::blk::dsync::{p3_start, pat};
use crate::harness::{R, check, report_r};
use crate::helpers::{BlkDev, find_blkdev, msleep, read_file};
use hk_syscall::{
    MAP_ANONYMOUS, MAP_PRIVATE, O_RDONLY, O_RDWR, O_WRONLY, PROT_READ, PROT_WRITE, Timespec,
    sys_clock_gettime, sys_close, sys_mmap, sys_munmap, sys_open, sys_pread64, sys_pwrite64,
    sys_write,
};

const O_DIRECT: u32 = hk_syscall::O_DIRECT;
const O_DSYNC: u32 = 0o10000;
/// A page of vda3 (16 MiB) no other test touches
const OFF: i64 = (12 << 20) + 458752;
const MSG: &[u8; 8] = b"FLUSHER!";
const WB: &[u8] = b"/proc/sys/vm/dirty_writeback_centisecs\0";
const EXP: &[u8] = b"/proc/sys/vm/dirty_expire_centisecs\0";
/// How long the write may take to land (the interval is 0.5 s)
const WAIT_MS: u64 = 15000;

pub fn run_tests() {
    report_r(b"BLK_WRITEBACK_PERIODIC", periodic());
}

fn periodic() -> R {
    let (Some(vda), Some(p3), Some(start)) = (
        find_blkdev(b"vd", 131072),
        find_blkdev(b"vd", 16384),
        p3_start(),
    ) else {
        return check(b"no vda3", false, 0);
    };
    let (mut wb, mut exp) = ([0u8; 16], [0u8; 16]);
    let nwb = read_file(WB, &mut wb);
    let nexp = read_file(EXP, &mut exp);
    check(b"read sysctls", nwb > 0 && nexp > 0, nwb.min(nexp))?;
    set(WB, b"50");
    set(EXP, b"0");
    let r = landed(&vda, &p3, start * 512 + OFF);
    set(WB, &wb[..nwb as usize]);
    set(EXP, &exp[..nexp as usize]);
    // Put the pattern back, on the disk before return
    let fd = open_dev(&p3, O_RDWR | O_DSYNC);
    let w = sys_pwrite64(fd as i32, pat(OFF).as_ptr(), 8, OFF);
    sys_close(fd as u64);
    r?;
    check(b"restore", w == 8, w)
}

/// Write `MSG` buffered at `OFF` of vda3 and wait for it at byte
/// `disk_off` of vda (O_DIRECT); vda3 stays open meanwhile
fn landed(vda: &BlkDev, p3: &BlkDev, disk_off: i64) -> R {
    let fd = open_dev(p3, O_RDWR);
    check(b"open vda3", fd >= 0, fd)?;
    let w = sys_pwrite64(fd as i32, MSG.as_ptr(), 8, OFF);
    let r = check(b"write", w == 8, w).and_then(|()| {
        let waited = wait(vda, disk_off, WAIT_MS)?;
        check(b"on disk without sync", waited <= WAIT_MS, waited as i64)
    });
    sys_close(fd as u64);
    r
}

/// Poll the disk's sector holding `disk_off` for `MSG`, up to `limit`
/// ms: the ms waited when it showed, past `limit` if it never did
fn wait(vda: &BlkDev, disk_off: i64, limit: u64) -> Result<u64, (&'static [u8], i64)> {
    let disk = open_dev(vda, O_RDONLY | O_DIRECT);
    check(b"open vda", disk >= 0, disk)?;
    let buf = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    let sector = disk_off & !511;
    let at = (disk_off - sector) as usize;
    let mut seen = false;
    let t0 = now_ms();
    let mut waited = 0;
    while buf > 0 && !seen && waited <= limit {
        let n = sys_pread64(disk as i32, buf as *mut u8, 512, sector);
        // SAFETY: the page just mapped, 512 bytes read into it
        let got = unsafe { core::slice::from_raw_parts((buf as *const u8).add(at), 8) };
        seen = n == 512 && got == MSG;
        // Clock time, not sleeps counted: an emulated guest's sleeps run
        // long
        waited = now_ms() - t0;
        if !seen {
            msleep(100);
        }
    }
    if buf > 0 {
        sys_munmap(buf as u64, 4096);
    }
    sys_close(disk as u64);
    check(b"mmap", buf > 0, buf)?;
    Ok(waited)
}

/// CLOCK_MONOTONIC in ms
fn now_ms() -> u64 {
    let mut t = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    sys_clock_gettime(1, &mut t);
    (t.tv_sec * 1000 + t.tv_nsec / 1_000_000) as u64
}

fn set(path: &[u8], v: &[u8]) {
    let fd = sys_open(path.as_ptr(), O_WRONLY, 0);
    sys_write(fd as u64, v.as_ptr(), v.len() as u64);
    sys_close(fd as u64);
}

fn open_dev(d: &BlkDev, flags: u32) -> i64 {
    let mut p = [0u8; 48];
    sys_open(d.path(&mut p).as_ptr(), flags, 0)
}
