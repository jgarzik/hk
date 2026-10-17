//! GUID Partition Tables (Linux block/partitions/efi.c)
//!
//! As Linux without `gpt` on the command line: a valid protective (or
//! hybrid) MBR is required, and the primary header at LBA 1 must be
//! valid (CRCs, bounds); the backup is not used as a fallback.

use alloc::vec;

use super::{Parsed, ReadSector, le32, le64};

const SIG: &[u8; 8] = b"EFI PART";
const PMBR_GPT: u8 = 0xee;
/// struct gpt_header up to the entry array CRC
const HDR_MIN: usize = 92;
const ENTRY: usize = 128;
/// Largest entry array read (Linux bounds it by KMALLOC_MAX_SIZE)
const MAX_ENTRIES: usize = 4096;

/// IEEE CRC-32 (Linux efi_crc32: crc32_le(~0, ...) ^ ~0)
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = (c >> 1) ^ (0xedb8_8320 & (c & 1).wrapping_neg());
        }
    }
    !c
}

/// Protective or hybrid MBR (Linux is_pmbr_valid): a 0xEE record
/// starting at LBA 1; a pure protective one must cover the disk
fn pmbr_valid(s: &[u8; 512], nr_sects: u64) -> bool {
    if s[510] != 0x55 || s[511] != 0xaa {
        return false;
    }
    let rec = |i: usize| 0x1be + 16 * i;
    let Some(g) = (0..4).find(|&i| s[rec(i) + 4] == PMBR_GPT && le32(s, rec(i) + 8) == 1) else {
        return false;
    };
    let hybrid = (0..4).any(|i| !matches!(s[rec(i) + 4], 0 | PMBR_GPT));
    if hybrid {
        return true;
    }
    let sz = le32(s, rec(g) + 12);
    sz == 0xffff_ffff || sz == (nr_sects as u32).wrapping_sub(1)
}

/// The primary header, checked (Linux is_gpt_valid at LBA 1)
fn header(read: &mut ReadSector<'_>, last: u64) -> Option<[u8; 512]> {
    let mut h = [0u8; 512];
    read(1, &mut h).ok()?;
    let hsize = le32(&h, 12) as usize;
    if &h[..8] != SIG || !(HDR_MIN..=512).contains(&hsize) {
        return None;
    }
    let mut c = h;
    c[16..20].fill(0);
    if crc32(&c[..hsize]) != le32(&h, 16) || le64(&h, 24) != 1 {
        return None;
    }
    let (first, lastu) = (le64(&h, 40), le64(&h, 48));
    if first > last || lastu > last || lastu < first {
        return None;
    }
    let n = le32(&h, 80) as usize;
    if le32(&h, 84) as usize != ENTRY || n > MAX_ENTRIES {
        return None;
    }
    Some(h)
}

/// The partition entry array, CRC-checked
fn entries(read: &mut ReadSector<'_>, h: &[u8; 512], last: u64) -> Option<alloc::vec::Vec<u8>> {
    // Bounded by MAX_ENTRIES (header check); the array must lie on the
    // disk, past the header
    let len = le32(h, 80) as usize * ENTRY;
    let lba = le64(h, 72);
    let secs = len.div_ceil(512) as u64;
    if lba < 2 || lba.checked_add(secs).is_none_or(|e| e > last + 1) {
        return None;
    }
    let mut buf = vec![0u8; len.next_multiple_of(512)];
    for (i, s) in buf.chunks_mut(512).enumerate() {
        let mut sec = [0u8; 512];
        read(lba + i as u64, &mut sec).ok()?;
        s.copy_from_slice(&sec);
    }
    buf.truncate(len);
    (crc32(&buf) == le32(h, 88)).then_some(buf)
}

/// Parse a GPT; true if one was found
pub fn efi_partition(st: &mut Parsed, read: &mut ReadSector<'_>, nr_sects: u64) -> bool {
    if nr_sects < 3 {
        return false;
    }
    let last = nr_sects - 1;
    let mut mbr = [0u8; 512];
    if read(0, &mut mbr).is_err() || !pmbr_valid(&mbr, nr_sects) {
        return false;
    }
    let Some(h) = header(read, last) else {
        return false;
    };
    let Some(e) = entries(read, &h, last) else {
        return false;
    };
    let limit = st.limit();
    for (i, p) in e.chunks(ENTRY).enumerate().take(limit.saturating_sub(1)) {
        let (start, end) = (le64(p, 32), le64(p, 40));
        // Linux is_pte_valid: used type GUID, inside the disk
        if p[..16].iter().all(|&b| b == 0) || start > last || end > last || end < start {
            continue;
        }
        st.put(i + 1, start, end - start + 1);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::super::Part;
    use super::super::tests::{Img, mbr_entry};
    use super::*;

    const NR: u64 = 262_144; // 128 MiB

    /// A GPT image like tools/mkdisk.sh makes
    fn gpt(parts: &[(u64, u64)]) -> Img {
        let mut img = Img::default();
        mbr_entry(&mut img, 0, 0, PMBR_GPT, 1, (NR - 1) as u32);
        let mut e = vec![0u8; 128 * ENTRY];
        for (i, &(s, n)) in parts.iter().enumerate() {
            let p = &mut e[i * ENTRY..];
            p[0] = 0xaf; // any non-zero type GUID
            p[32..40].copy_from_slice(&s.to_le_bytes());
            p[40..48].copy_from_slice(&(s + n - 1).to_le_bytes());
        }
        for (i, c) in e.chunks(512).enumerate() {
            img.sector(2 + i as u64).copy_from_slice(c);
        }
        let h = img.sector(1);
        h[..8].copy_from_slice(SIG);
        h[12..16].copy_from_slice(&92u32.to_le_bytes());
        h[24..32].copy_from_slice(&1u64.to_le_bytes());
        h[32..40].copy_from_slice(&(NR - 1).to_le_bytes());
        h[40..48].copy_from_slice(&34u64.to_le_bytes());
        h[48..56].copy_from_slice(&(NR - 34).to_le_bytes());
        h[72..80].copy_from_slice(&2u64.to_le_bytes());
        h[80..84].copy_from_slice(&128u32.to_le_bytes());
        h[84..88].copy_from_slice(&(ENTRY as u32).to_le_bytes());
        h[88..92].copy_from_slice(&crc32(&e).to_le_bytes());
        let c = crc32(&h[..92]);
        h[16..20].copy_from_slice(&c.to_le_bytes());
        img
    }

    #[test]
    fn crc32_known_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn mkdisk_layout() {
        let img = gpt(&[(2048, 65536), (67584, 131072), (198656, 32768)]);
        assert_eq!(
            img.scan(NR, 16),
            [
                (
                    1,
                    Part {
                        start: 2048,
                        size: 65536
                    }
                ),
                (
                    2,
                    Part {
                        start: 67584,
                        size: 131072
                    }
                ),
                (
                    3,
                    Part {
                        start: 198656,
                        size: 32768
                    }
                )
            ]
        );
    }

    #[test]
    fn bad_header_crc_rejected() {
        let mut img = gpt(&[(2048, 100)]);
        img.sector(1)[40] ^= 1;
        assert!(img.scan(NR, 16).is_empty());
    }

    #[test]
    fn bad_entries_crc_rejected() {
        let mut img = gpt(&[(2048, 100)]);
        img.sector(2)[33] ^= 1;
        assert!(img.scan(NR, 16).is_empty());
    }

    #[test]
    fn protective_mbr_required_and_sized() {
        let mut img = gpt(&[(2048, 100)]);
        img.sector(0)[0x1be + 12..0x1be + 16].copy_from_slice(&1000u32.to_le_bytes());
        // Neither GPT (pMBR size wrong) nor MBR (0xEE is left to GPT)
        assert!(img.scan(NR, 16).is_empty());
        img.sector(0)[0x1be + 12..0x1be + 16].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        assert_eq!(img.scan(NR, 16).len(), 1);
    }

    #[test]
    fn entry_array_off_disk_rejected() {
        let mut img = gpt(&[(2048, 100)]);
        let h = img.sector(1);
        h[72..80].copy_from_slice(&u64::MAX.to_le_bytes());
        h[16..20].fill(0);
        let c = crc32(&h[..92]);
        h[16..20].copy_from_slice(&c.to_le_bytes());
        assert!(img.scan(NR, 16).is_empty());
    }

    #[test]
    fn entries_past_limit_or_disk_skipped() {
        let mut parts = alloc::vec::Vec::new();
        for i in 0..20u64 {
            parts.push((2048 + i * 100, 100));
        }
        parts[2] = (NR, 10);
        let img = gpt(&parts);
        let got = img.scan(NR, 16);
        assert_eq!(got.len(), 14);
        assert_eq!(got.last().unwrap().0, 15);
        assert!(got.iter().all(|&(n, _)| n != 3));
    }
}
