//! Sleep type values from AML (Linux acpi_get_sleep_type_data, which
//! evaluates \_Sx through the ACPICA interpreter)
//!
//! hk has no AML interpreter. A sleep state's object is almost always a
//! plain named package, `Name (_S5, Package () { SLP_TYPa, SLP_TYPb, ...
//! })`, which can be found by scanning the DSDT (or an SSDT) for its
//! encoding.

/// The SLP_TYP values for one sleep state (PM1a and PM1b control)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SleepType {
    pub a: u8,
    pub b: u8,
}

const NAME_OP: u8 = 0x08;
const PACKAGE_OP: u8 = 0x12;
const ROOT_CHAR: u8 = b'\\';
const ZERO_OP: u8 = 0x00;
const ONE_OP: u8 = 0x01;
const ONES_OP: u8 = 0xff;
const BYTE_PREFIX: u8 = 0x0a;
const WORD_PREFIX: u8 = 0x0b;
const DWORD_PREFIX: u8 = 0x0c;
const QWORD_PREFIX: u8 = 0x0e;

/// The \_S5 package in an AML table body (the bytes after its header),
/// or None if it is missing or not a plain package of integers
pub fn find_s5(aml: &[u8]) -> Option<SleepType> {
    (0..aml.len()).find_map(|i| name_s5(&aml[i..]))
}

/// `Name ([\]_S5_, Package ...)` at the start of `b`
fn name_s5(b: &[u8]) -> Option<SleepType> {
    let b = b.strip_prefix(&[NAME_OP])?;
    let b = b.strip_prefix(&[ROOT_CHAR]).unwrap_or(b);
    package(b.strip_prefix(b"_S5_")?)
}

/// A package of sleep type integers (ACPICA acpi_get_sleep_type_data):
/// one integer holds a in its low byte and b in the next; two or more
/// give a and b
fn package(b: &[u8]) -> Option<SleepType> {
    let b = b.strip_prefix(&[PACKAGE_OP])?;
    let (len, hdr) = pkg_length(b)?;
    let body = b.get(hdr..len)?;
    let (&count, mut rest) = body.split_first()?;
    let a = integer(&mut rest)?;
    match count {
        0 => None,
        1 => Some(SleepType {
            a: a as u8,
            b: (a >> 8) as u8,
        }),
        _ => Some(SleepType {
            a: a as u8,
            b: integer(&mut rest)? as u8,
        }),
    }
}

/// PkgLength: (the length it encodes, counting itself; its own size)
fn pkg_length(b: &[u8]) -> Option<(usize, usize)> {
    let lead = *b.first()?;
    let extra = (lead >> 6) as usize;
    if extra == 0 {
        return Some(((lead & 0x3f) as usize, 1));
    }
    let mut len = (lead & 0x0f) as usize;
    for (i, &byte) in b.get(1..=extra)?.iter().enumerate() {
        len |= (byte as usize) << (4 + 8 * i);
    }
    Some((len, 1 + extra))
}

/// An integer data object, advancing `b` past it
fn integer(b: &mut &[u8]) -> Option<u64> {
    let (&op, rest) = b.split_first()?;
    let (val, size) = match op {
        ZERO_OP => (0, 0),
        ONE_OP => (1, 0),
        ONES_OP => (u64::MAX, 0),
        BYTE_PREFIX => (le(rest, 1)?, 1),
        WORD_PREFIX => (le(rest, 2)?, 2),
        DWORD_PREFIX => (le(rest, 4)?, 4),
        QWORD_PREFIX => (le(rest, 8)?, 8),
        _ => return None,
    };
    *b = &rest[size..];
    Some(val)
}

/// A little-endian integer of `n` bytes
fn le(b: &[u8], n: usize) -> Option<u64> {
    let bytes = b.get(..n)?;
    Some(bytes.iter().rev().fold(0, |v, &x| (v << 8) | x as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    const S5: SleepType = SleepType { a: 7, b: 7 };

    /// Name (_S5, Package (0x04) { 0x07, 0x07, Zero, Zero }), as on
    /// Intel PCH machines
    const INTEL: &[u8] = &[
        0x08, b'_', b'S', b'5', b'_', 0x12, 0x08, 0x04, 0x0a, 0x07, 0x0a, 0x07, 0x00, 0x00,
    ];

    #[test]
    fn intel_pch() {
        let mut aml = alloc::vec![0x10, 0x20, 0x5b, 0x82];
        aml.extend_from_slice(INTEL);
        aml.extend_from_slice(&[0x14, 0x0f]);
        assert_eq!(find_s5(&aml), Some(S5));
    }

    /// Name (\_S5, ...) with the root prefix
    #[test]
    fn root_prefix() {
        let aml = [
            0x08, b'\\', b'_', b'S', b'5', b'_', 0x12, 0x08, 0x04, 0x0a, 0x05, 0x0a, 0x06, 0x00,
            0x00,
        ];
        assert_eq!(find_s5(&aml), Some(SleepType { a: 5, b: 6 }));
    }

    /// Zero and One opcodes, as in QEMU's DSDT
    #[test]
    fn zero_one_ops() {
        let aml = [
            0x08, b'_', b'S', b'5', b'_', 0x12, 0x06, 0x04, 0x00, 0x01, 0x00, 0x00,
        ];
        assert_eq!(find_s5(&aml), Some(SleepType { a: 0, b: 1 }));
    }

    /// A two-byte PkgLength
    #[test]
    fn long_pkg_length() {
        let aml = [
            0x08, b'_', b'S', b'5', b'_', 0x12, 0x49, 0x00, 0x04, 0x0a, 0x07, 0x0a, 0x07, 0x00,
            0x00,
        ];
        assert_eq!(find_s5(&aml), Some(S5));
    }

    /// "_S5_" that is not a Name (a reference, a string) is skipped
    #[test]
    fn skips_non_name() {
        let mut aml = alloc::vec![
            0x0d, b'_', b'S', b'5', b'_', 0x00, 0x70, b'_', b'S', b'5', b'_'
        ];
        aml.extend_from_slice(INTEL);
        assert_eq!(find_s5(&aml), Some(S5));
    }

    /// Missing, truncated, or a Method instead of a package: None, no
    /// panic
    #[test]
    fn missing_or_bad() {
        assert_eq!(find_s5(&[]), None);
        assert_eq!(find_s5(&[0x10, 0x20, 0x30]), None);
        for n in 0..INTEL.len() - 4 {
            assert_eq!(find_s5(&INTEL[..n]), None, "truncated at {n}");
        }
        let method = [0x14, 0x08, b'_', b'S', b'5', b'_', 0x00, 0xa4, 0x00];
        assert_eq!(find_s5(&method), None);
        let one_elem = [0x08, b'_', b'S', b'5', b'_', 0x12, 0x03, 0x01, 0x0a];
        assert_eq!(find_s5(&one_elem), None);
    }

    /// One integer holds both values, a in its low byte (ACPICA)
    #[test]
    fn one_integer() {
        let aml = [
            0x08, b'_', b'S', b'5', b'_', 0x12, 0x05, 0x01, 0x0b, 0x07, 0x05,
        ];
        assert_eq!(find_s5(&aml), Some(SleepType { a: 7, b: 5 }));
    }
}
