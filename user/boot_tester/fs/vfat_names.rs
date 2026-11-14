//! vfat names match without case or trailing dots in the dcache too
//! (Linux vfat_ci_dentry_ops: d_hash vfat_hashi, d_compare vfat_cmpi),
//! so every spelling of a name reaches the one cached dentry.
//!
//! - VFAT_CI_DENTRY: on vda1's vfat, "dir" is made and looked up; then
//!   a chdir to "DIR." stands in that dentry, which getcwd names by its
//!   cached spelling, and a ramfs mounted on "dir" is crossed into
//!   through "Dir".

use crate::harness::T;
use crate::helpers::find_blkdev;
use hk_syscall::{
    Stat, sys_chdir, sys_getcwd, sys_mkdir, sys_mount, sys_rmdir, sys_stat, sys_umount2,
};

const DIR: &[u8] = b"/tmp/vci\0";

/// st_dev of `p`, or 0
fn dev(p: &[u8]) -> u64 {
    let mut st = Stat::default();
    if sys_stat(p.as_ptr(), &mut st) == 0 {
        st.st_dev
    } else {
        0
    }
}

pub fn run_tests() {
    let mut t = T::new(b"VFAT_CI_DENTRY");
    let Some(dev_) = find_blkdev(b"vd", 32768) else {
        t.ok(b"no vda1", false, 0);
        t.done();
        return;
    };
    sys_mkdir(b"/tmp\0".as_ptr(), 0o1777);
    sys_mkdir(DIR.as_ptr(), 0o755);
    let mut p = [0u8; 48];
    let r = sys_mount(
        dev_.path(&mut p).as_ptr(),
        DIR.as_ptr(),
        b"vfat\0".as_ptr(),
        0,
        b"iocharset=cp437\0".as_ptr() as u64,
    );
    if !t.eq(b"mount vfat", r, 0) {
        sys_rmdir(DIR.as_ptr());
        t.done();
        return;
    }
    sys_rmdir(b"/tmp/vci/dir\0".as_ptr());
    if t.eq(b"mkdir", sys_mkdir(b"/tmp/vci/dir\0".as_ptr(), 0o755), 0) {
        check(&mut t);
        sys_chdir(b"/\0".as_ptr());
        sys_rmdir(b"/tmp/vci/dir\0".as_ptr());
    }
    sys_umount2(DIR.as_ptr(), 0);
    sys_rmdir(DIR.as_ptr());
    t.done();
}

fn check(t: &mut T) {
    let vfat = dev(b"/tmp/vci/dir\0");
    t.ok(b"stat dir", vfat != 0, 0);
    t.eq(b"chdir DIR.", sys_chdir(b"/tmp/vci/DIR.\0".as_ptr()), 0);
    let mut buf = [0u8; 64];
    let r = sys_getcwd(buf.as_mut_ptr(), buf.len());
    let want = b"/tmp/vci/dir\0";
    t.ok(
        b"getcwd",
        r == want.len() as i64 && buf[..want.len()] == want[..],
        r,
    );
    sys_chdir(b"/\0".as_ptr());
    let r = sys_mount(
        b"none\0".as_ptr(),
        b"/tmp/vci/dir\0".as_ptr(),
        b"ramfs\0".as_ptr(),
        0,
        0,
    );
    if t.eq(b"mount ramfs", r, 0) {
        let d = dev(b"/tmp/vci/Dir\0");
        t.ok(b"Dir crosses the mount", d != 0 && d != vfat, d as i64);
        sys_umount2(b"/tmp/vci/dir\0".as_ptr(), 0);
    }
}
