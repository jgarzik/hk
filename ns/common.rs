//! What every namespace has (Linux include/linux/ns_common.h)

use super::inum::Inum;

/// A namespace's common part (Linux struct ns_common)
pub struct NsCommon {
    /// Its inode number (Linux ns.inum): /proc/<pid>/ns/<type> reads
    /// "<type>:[<inum>]", the st_ino of its nsfs file
    pub inum: Inum,
}

impl NsCommon {
    pub const fn new(inum: Inum) -> Self {
        Self { inum }
    }

    /// Its inode number
    pub fn inum(&self) -> u32 {
        self.inum.get()
    }
}
