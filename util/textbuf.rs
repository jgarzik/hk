//! A text buffer that grows as it is written (Linux sysfs_emit's page,
//! and the files built whole before they are copied out)

use alloc::vec::Vec;
use core::fmt;

/// Text written with `write!` and raw bytes, appended as they come;
/// for a caller that may allocate (no lock held: `fs::proc::seq` is the
/// fixed buffer for one that may not)
#[derive(Default)]
pub struct TextBuf(pub Vec<u8>);

impl TextBuf {
    /// Append raw bytes
    pub fn bytes(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
}

impl fmt::Write for TextBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}
