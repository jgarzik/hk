//! Partition table parsing (Linux block/partitions/)
//!
//! Parsers read sectors through a callback, so they run unchanged on
//! host unit tests. Like Linux check_partition, GPT is tried before
//! MBR (an MBR parser must not mistake a protective MBR for a table).

pub mod efi;
pub mod msdos;

use alloc::vec;
use alloc::vec::Vec;

use crate::error::KernelError;

/// A partition: sectors on the disk (512-byte units)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Part {
    pub start: u64,
    pub size: u64,
}

/// Parse result (Linux struct parsed_partitions): slot `n` is
/// partition `n`; slot 0 is unused
pub struct Parsed {
    pub parts: Vec<Option<Part>>,
    /// Next logical partition number (msdos extended partitions)
    pub next: usize,
}

impl Parsed {
    /// Room for partitions 1..limit-1
    pub fn new(limit: usize) -> Self {
        Self {
            parts: vec![None; limit],
            next: 1,
        }
    }

    pub fn limit(&self) -> usize {
        self.parts.len()
    }

    /// Record partition `n` (ignored past the limit; Linux put_partition)
    pub fn put(&mut self, n: usize, start: u64, size: u64) {
        if n < self.limit() {
            self.parts[n] = Some(Part { start, size });
        }
    }
}

/// Reads one 512-byte sector
pub type ReadSector<'a> = dyn FnMut(u64, &mut [u8; 512]) -> Result<(), KernelError> + 'a;

/// Find the partitions of a disk of `nr_sects` sectors with at most
/// `limit - 1` partitions. Returns (number, partition), clipped to the
/// disk like Linux blk_add_partitions.
pub fn scan(read: &mut ReadSector<'_>, nr_sects: u64, limit: usize) -> Vec<(u16, Part)> {
    let mut st = Parsed::new(limit);
    if !efi::efi_partition(&mut st, read, nr_sects) {
        st = Parsed::new(limit);
        msdos::msdos_partition(&mut st, read);
    }
    st.parts
        .iter()
        .enumerate()
        .filter_map(|(n, p)| {
            let p = (*p)?;
            if p.size == 0 || p.start >= nr_sects {
                return None;
            }
            let size = p.size.min(nr_sects - p.start);
            Some((
                n as u16,
                Part {
                    start: p.start,
                    size,
                },
            ))
        })
        .collect()
}

pub(crate) fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

pub(crate) fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

pub(crate) fn le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    /// A sparse disk image for parser tests
    #[derive(Default)]
    pub struct Img(pub BTreeMap<u64, [u8; 512]>);

    impl Img {
        pub fn sector(&mut self, s: u64) -> &mut [u8; 512] {
            self.0.entry(s).or_insert([0; 512])
        }

        pub fn scan(&self, nr: u64, limit: usize) -> Vec<(u16, Part)> {
            let mut rd = |s: u64, b: &mut [u8; 512]| {
                *b = self.0.get(&s).copied().unwrap_or([0; 512]);
                Ok(())
            };
            scan(&mut rd, nr, limit)
        }
    }

    pub fn mbr_entry(img: &mut Img, sector: u64, slot: usize, sys: u8, start: u32, n: u32) {
        let s = img.sector(sector);
        let o = 0x1be + 16 * slot;
        s[o + 4] = sys;
        s[o + 8..o + 12].copy_from_slice(&start.to_le_bytes());
        s[o + 12..o + 16].copy_from_slice(&n.to_le_bytes());
        s[510] = 0x55;
        s[511] = 0xAA;
    }

    #[test]
    fn clipped_to_disk() {
        let mut img = Img::default();
        mbr_entry(&mut img, 0, 0, 0x83, 2048, 100_000);
        mbr_entry(&mut img, 0, 1, 0x83, 200_000, 10);
        assert_eq!(
            img.scan(50_000, 16),
            [(
                1,
                Part {
                    start: 2048,
                    size: 50_000 - 2048
                }
            )]
        );
    }
}
