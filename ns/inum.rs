//! Namespace inode numbers (Linux ns_common.inum, fs/proc/generic.c
//! proc_alloc_inum): what /proc/<pid>/ns/<type> names, "<type>:[<inum>]",
//! and the st_ino of the namespace file it leads to. Two tasks share a
//! namespace exactly when its links show the same number.

use crate::util::error::KernelError;
use crate::util::ida::Ida;

/// The initial namespaces' fixed numbers (Linux uapi nsfs.h
/// *_NS_INIT_INO)
pub const IPC_INIT: u32 = 0xEFFF_FFFF;
pub const UTS_INIT: u32 = 0xEFFF_FFFE;
pub const USER_INIT: u32 = 0xEFFF_FFFD;
pub const PID_INIT: u32 = 0xEFFF_FFFC;
pub const NET_INIT: u32 = 0xEFFF_FFF9;
pub const MNT_INIT: u32 = 0xEFFF_FFF8;

/// The first number handed out (Linux PROC_DYNAMIC_FIRST)
const DYNAMIC_FIRST: u32 = 0xF000_0000;

/// Numbers in use above `DYNAMIC_FIRST`, lowest free first (Linux
/// proc_inum_ida)
static INUMS: Ida = Ida::new();

/// A namespace's number, given back when the namespace goes (Linux
/// ns_free_inum)
pub struct Inum(u32);

impl Inum {
    /// An initial namespace's fixed number
    pub const fn fixed(n: u32) -> Self {
        Self(n)
    }

    /// A new namespace's number (Linux ns_alloc_inum), ENOMEM
    pub fn alloc() -> Result<Self, KernelError> {
        let id = INUMS.try_alloc()?;
        match id.checked_add(DYNAMIC_FIRST) {
            Some(n) => Ok(Self(n)),
            None => {
                INUMS.free(id);
                Err(KernelError::OutOfMemory)
            }
        }
    }

    pub fn get(&self) -> u32 {
        self.0
    }
}

impl Drop for Inum {
    fn drop(&mut self) {
        if self.0 >= DYNAMIC_FIRST {
            INUMS.free(self.0 - DYNAMIC_FIRST);
        }
    }
}
