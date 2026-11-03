//! /sys/kernel (Linux kernel/ksysfs.c, mm/mm_init.c mm_sysfs_init)

use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::fs::kernfs;
use crate::fs::sysfs;

/// Sequence number of the last uevent (Linux uevent_seqnum)
pub static UEVENT_SEQNUM: AtomicU64 = AtomicU64::new(0);

/// /sys/kernel/{uevent_seqnum,mm}
pub fn init() {
    let k = sysfs::top_dir(b"kernel");
    let _ = k.create_file(
        b"uevent_seqnum",
        0o444,
        kernfs::show(|o| {
            let _ = writeln!(o, "{}", UEVENT_SEQNUM.load(Ordering::Acquire));
        }),
    );
    let _ = k.create_dir(b"mm", 0o755);
}
