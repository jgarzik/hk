//! MBR (DOS) partition tables (Linux block/partitions/msdos.c)
//!
//! Primary partitions 1-4; logical partitions 5+ from the chain of
//! extended boot records. No BSD/Solaris/UnixWare subpartitions, no AIX.

use super::{Parsed, ReadSector, le32};

const TABLE: usize = 0x1be;
/// Protective MBR of a GPT disk: GPT's job
const EFI_GPT: u8 = 0xee;

fn magic(s: &[u8; 512]) -> bool {
    s[510] == 0x55 && s[511] == 0xaa
}

/// Partition record `i` of a sector: (boot indicator, type, start, size)
fn entry(s: &[u8; 512], i: usize) -> (u8, u8, u64, u64) {
    let o = TABLE + 16 * i;
    (
        s[o],
        s[o + 4],
        le32(s, o + 8) as u64,
        le32(s, o + 12) as u64,
    )
}

fn is_extended(sys: u8) -> bool {
    matches!(sys, 0x05 | 0x0f | 0x85)
}

/// FAT media byte (Linux fat_valid_media)
fn fat_media(m: u8) -> bool {
    m >= 0xf8 || m == 0xf0
}

/// A FAT boot sector without a partition table (Linux: `reserved`,
/// `fats` and `media` of struct fat_boot_sector)
fn fat_boot(s: &[u8; 512]) -> bool {
    super::le16(s, 14) != 0 && s[16] != 0 && fat_media(s[21])
}

/// Parse an MBR; true if one was found (possibly a bare FAT boot
/// sector: a table with no partitions, as in Linux)
pub fn msdos_partition(st: &mut Parsed, read: &mut ReadSector<'_>) -> bool {
    let mut s = [0u8; 512];
    if read(0, &mut s).is_err() || !magic(&s) {
        return false;
    }
    for i in 0..4 {
        if !matches!(entry(&s, i).0, 0 | 0x80) {
            return i == 0 && fat_boot(&s);
        }
    }
    if (0..4).any(|i| entry(&s, i).1 == EFI_GPT) {
        return false;
    }
    st.next = 5;
    for i in 0..4 {
        let (_, sys, start, size) = entry(&s, i);
        if size == 0 {
            continue;
        }
        if is_extended(sys) {
            // Two sectors: keeps mkfs off the container (Linux)
            st.put(i + 1, start, size.min(2));
            parse_extended(st, read, start, size);
        } else {
            st.put(i + 1, start, size);
        }
    }
    true
}

/// Follow the chain of extended boot records (Linux parse_extended)
fn parse_extended(st: &mut Parsed, read: &mut ReadSector<'_>, first: u64, first_size: u64) {
    let (mut this, mut this_size) = (first, first_size);
    let mut loops = 0;
    let mut s = [0u8; 512];
    loop {
        loops += 1;
        if loops > 100 || st.next >= st.limit() {
            return;
        }
        if read(this, &mut s).is_err() || !magic(&s) {
            return;
        }
        for i in 0..4 {
            let (_, sys, offs, size) = entry(&s, i);
            if size == 0 || is_extended(sys) {
                continue;
            }
            let next = this + offs;
            // The 3rd and 4th records sometimes hold garbage
            if i >= 2
                && (offs + size > this_size || next < first || next + size > first + first_size)
            {
                continue;
            }
            st.put(st.next, next, size);
            loops = 0;
            st.next += 1;
            if st.next >= st.limit() {
                return;
            }
        }
        let Some(link) = (0..4)
            .map(|i| entry(&s, i))
            .find(|e| e.3 != 0 && is_extended(e.1))
        else {
            return;
        };
        this = first + link.2;
        this_size = link.3;
    }
}

#[cfg(test)]
mod tests {
    use super::super::Part;
    use super::super::tests::{Img, mbr_entry};

    fn p(start: u64, size: u64) -> Part {
        Part { start, size }
    }

    #[test]
    fn primaries() {
        let mut img = Img::default();
        mbr_entry(&mut img, 0, 0, 0x83, 2048, 4096);
        mbr_entry(&mut img, 0, 2, 0x0c, 8192, 100);
        assert_eq!(
            img.scan(1 << 20, 16),
            [(1, p(2048, 4096)), (3, p(8192, 100))]
        );
    }

    #[test]
    fn no_signature_no_table() {
        let mut img = Img::default();
        mbr_entry(&mut img, 0, 0, 0x83, 2048, 4096);
        img.sector(0)[511] = 0;
        assert!(img.scan(1 << 20, 16).is_empty());
    }

    #[test]
    fn bad_boot_indicator_is_not_a_table() {
        let mut img = Img::default();
        mbr_entry(&mut img, 0, 0, 0x83, 2048, 4096);
        img.sector(0)[0x1be] = 0x12;
        assert!(img.scan(1 << 20, 16).is_empty());
    }

    #[test]
    fn protective_mbr_is_left_to_gpt() {
        let mut img = Img::default();
        mbr_entry(&mut img, 0, 0, 0xee, 1, 0xffff_ffff);
        let mut st = super::Parsed::new(16);
        let mut rd = |s: u64, b: &mut [u8; 512]| {
            *b = img.0.get(&s).copied().unwrap_or([0; 512]);
            Ok(())
        };
        assert!(!super::msdos_partition(&mut st, &mut rd));
    }

    #[test]
    fn logical_partitions() {
        let mut img = Img::default();
        mbr_entry(&mut img, 0, 0, 0x83, 2048, 1000);
        // Extended container at 10000, 9000 sectors
        mbr_entry(&mut img, 0, 1, 0x05, 10000, 9000);
        // EBR 1: data at +63 (100 sectors), link to the next EBR at +2000
        mbr_entry(&mut img, 10000, 0, 0x83, 63, 100);
        mbr_entry(&mut img, 10000, 1, 0x05, 2000, 3000);
        // EBR 2: data at +63 of itself (50 sectors), end of chain
        mbr_entry(&mut img, 12000, 0, 0x82, 63, 50);
        assert_eq!(
            img.scan(1 << 20, 16),
            [
                (1, p(2048, 1000)),
                (2, p(10000, 2)),
                (5, p(10063, 100)),
                (6, p(12063, 50))
            ]
        );
    }

    #[test]
    fn extended_loop_terminates() {
        let mut img = Img::default();
        mbr_entry(&mut img, 0, 0, 0x05, 100, 1000);
        // EBR that links to itself with no data partition
        mbr_entry(&mut img, 100, 1, 0x05, 0, 1000);
        assert_eq!(img.scan(1 << 20, 16), [(1, p(100, 2))]);
    }

    #[test]
    fn fat_superfloppy_has_no_partitions() {
        let mut img = Img::default();
        let s = img.sector(0);
        s[14] = 32; // reserved sectors
        s[16] = 2; // FATs
        s[21] = 0xf8; // media
        s[0x1be] = 0x54; // boot code, not a boot indicator
        s[510] = 0x55;
        s[511] = 0xaa;
        assert!(img.scan(1 << 20, 16).is_empty());
    }
}
