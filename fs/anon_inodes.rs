//! Anonymous inodes and pseudo-filesystem inode numbers
//! (Linux fs/anon_inodes.c, get_next_ino in fs/inode.c)
//!
//! Files with no filesystem object behind them (eventfd, epoll,
//! signalfd, timerfd, inotify, fanotify, pidfd, io_uring, bpf) share
//! one inode, mode 0600 with no file type, like Linux's
//! `anon_inode_inode`; each file's state lives in the File. The name
//! given (`[eventfd]`) is what /proc/<pid>/fd shows as
//! `anon_inode:[eventfd]`.
//!
//! Its attributes never change: chmod, chown and utimes on any of these
//! files are EOPNOTSUPP (Linux anon_inode_setattr), so no file can
//! alter what every other one reports.
//!
//! [`get_next_ino`] numbers inodes of pseudo filesystems (pipes,
//! sockets): each CPU takes a batch of numbers from a shared counter
//! and hands them out without touching it (Linux LAST_INO_BATCH).

use alloc::sync::{Arc, Weak};
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};

use spin::Once;

use crate::cpu::PerCpu;
use crate::fs::dentry::Dentry;
use crate::fs::file::{File, FileOps};
use crate::fs::inode::{Inode, InodeMode, InodeOps, Timespec};
use crate::sync::IrqSpinlock;
use crate::util::error::KernelError;
use crate::util::kalloc::{arc_nofail, try_arc};

/// Numbers one CPU takes from the shared counter at a time
const LAST_INO_BATCH: u64 = 1024;

/// The next batch's start
static SHARED_LAST_INO: AtomicU64 = AtomicU64::new(0);

/// Each CPU's last number handed out (0: take a new batch)
static LAST_INO: PerCpu<IrqSpinlock<u64>> = crate::percpu![IrqSpinlock::new(0)];

/// A new inode number for a pseudo filesystem (Linux get_next_ino):
/// 32 bits wide like Linux's `unsigned int`, never 0
pub fn get_next_ino() -> u64 {
    let mut last = LAST_INO.this().lock();
    let mut res = *last;
    if res.is_multiple_of(LAST_INO_BATCH) {
        res = SHARED_LAST_INO.fetch_add(LAST_INO_BATCH, Ordering::Relaxed);
    }
    res = (res + 1) & 0xffff_ffff;
    if res == 0 {
        res = 1;
    }
    *last = res;
    res
}

/// Operations of the shared inode: no lookup, no attribute changes
struct AnonInodeOps;

impl InodeOps for AnonInodeOps {
    fn lookup(&self, _dir: &Inode, _name: &[u8]) -> Result<Arc<Inode>, KernelError> {
        Err(KernelError::OperationNotSupported)
    }

    fn setattr_ok(&self, _inode: &Inode) -> Result<(), KernelError> {
        Err(KernelError::OperationNotSupported)
    }
}

static ANON_INODE_OPS: AnonInodeOps = AnonInodeOps;

/// The inode every anonymous file shares
static ANON_INODE: Once<Arc<Inode>> = Once::new();

fn anon_inode() -> Arc<Inode> {
    ANON_INODE
        .call_once(|| {
            arc_nofail(Inode::new(
                get_next_ino(),
                InodeMode(0o600),
                0,
                0,
                0,
                Timespec::from_secs(0),
                Weak::new(),
                &ANON_INODE_OPS,
            ))
        })
        .clone()
}

/// A new file on the shared anonymous inode (Linux anon_inode_getfile):
/// `name` is its dentry name (`[eventfd]`), `private` its state
pub fn anon_inode_getfile(
    name: &str,
    f_op: &'static dyn FileOps,
    private: Arc<dyn Any + Send + Sync>,
    flags: u32,
) -> Result<Arc<File>, KernelError> {
    let dentry = try_arc(Dentry::new_anonymous(name.into(), Some(anon_inode())))?;
    try_arc(File::new_anon(dentry, flags, f_op, private))
}
