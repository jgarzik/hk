//! /sys/kernel (Linux kernel/ksysfs.c, mm/mm_init.c mm_sysfs_init)

use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::fs::kernfs::sysfs;
use crate::fs::kernfs::{self, Attr, SysBuf};
use crate::sync::spin::Mutex;
use crate::util::error::KernelError;
use crate::util::kalloc::arc_nofail;

/// Sequence number of the last uevent (Linux uevent_seqnum)
pub static UEVENT_SEQNUM: AtomicU64 = AtomicU64::new(0);

/// Linux UEVENT_HELPER_PATH_LEN
const UEVENT_HELPER_PATH_LEN: usize = 256;

/// Program run for each uevent and its length; empty: none (Linux
/// uevent_helper, a fixed char array, CONFIG_UEVENT_HELPER_PATH ""; spin
/// leaf, nothing allocated under it)
static UEVENT_HELPER: Mutex<([u8; UEVENT_HELPER_PATH_LEN], usize)> =
    Mutex::new(([0; UEVENT_HELPER_PATH_LEN], 0));

struct UeventHelper;

impl Attr for UeventHelper {
    fn show(&self, out: &mut SysBuf) -> Result<(), KernelError> {
        // Copied out, then emitted with the lock released
        let (b, n) = *UEVENT_HELPER.lock();
        out.bytes(&b[..n]);
        out.bytes(b"\n");
        Ok(())
    }

    /// Linux uevent_helper_store: ENOENT past the path length, one
    /// trailing newline dropped
    fn store(&self, data: &[u8]) -> Result<usize, KernelError> {
        if data.len() + 1 > UEVENT_HELPER_PATH_LEN {
            return Err(KernelError::NotFound);
        }
        let v = data.strip_suffix(b"\n").unwrap_or(data);
        let mut h = UEVENT_HELPER.lock();
        h.0[..v.len()].copy_from_slice(v);
        h.1 = v.len();
        Ok(data.len())
    }
}

/// /sys/kernel/{uevent_seqnum,uevent_helper,mm}
pub fn init() {
    let k = sysfs::top_dir(b"kernel");
    let _ = k.create_file(
        b"uevent_seqnum",
        0o444,
        kernfs::show(|o| {
            let _ = writeln!(o, "{}", UEVENT_SEQNUM.load(Ordering::Acquire));
        }),
    );
    let _ = k.create_file(b"uevent_helper", 0o644, arc_nofail(UeventHelper));
    let _ = k.create_dir(b"mm", 0o755);
}
