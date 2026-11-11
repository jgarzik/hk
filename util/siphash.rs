//! SipHash-2-4 (Linux lib/siphash.c): a keyed hash for tables whose
//! keys an attacker picks (ports, flows, path names)

/// The four state words, keyed
fn init(key: [u64; 2]) -> [u64; 4] {
    [
        key[0] ^ 0x736f_6d65_7073_6575,
        key[1] ^ 0x646f_7261_6e64_6f6d,
        key[0] ^ 0x6c79_6765_6e65_7261,
        key[1] ^ 0x7465_6462_7974_6573,
    ]
}

fn round(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13) ^ v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16) ^ v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21) ^ v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17) ^ v[2];
    v[2] = v[2].rotate_left(32);
}

/// Two compression rounds over one message word
fn compress(v: &mut [u64; 4], m: u64) {
    v[3] ^= m;
    round(v);
    round(v);
    v[0] ^= m;
}

/// The last word (`tail`, the length's low byte on top) and four
/// finalization rounds
fn finish(mut v: [u64; 4], tail: u64) -> u64 {
    compress(&mut v, tail);
    v[2] ^= 0xff;
    for _ in 0..4 {
        round(&mut v);
    }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

/// SipHash-2-4 of `words` under `key` (Linux siphash over u64s)
pub fn siphash(key: [u64; 2], words: &[u64]) -> u64 {
    let mut v = init(key);
    for &m in words {
        compress(&mut v, m);
    }
    finish(v, ((words.len() as u64 * 8) & 0xff) << 56)
}

/// SipHash-2-4 of the bytes `b` under `key` (Linux siphash(data, len))
pub fn siphash_bytes(key: [u64; 2], b: &[u8]) -> u64 {
    let mut v = init(key);
    let (words, rest) = b.as_chunks::<8>();
    for w in words {
        compress(&mut v, u64::from_le_bytes(*w));
    }
    let mut last = [0u8; 8];
    last[..rest.len()].copy_from_slice(rest);
    // Only the length's low byte goes in (the reference's `b`)
    last[7] = b.len() as u8;
    finish(v, u64::from_le_bytes(last))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u64; 2] {
        [
            u64::from_le_bytes([0, 1, 2, 3, 4, 5, 6, 7]),
            u64::from_le_bytes([8, 9, 10, 11, 12, 13, 14, 15]),
        ]
    }

    /// Reference SipHash-2-4 vectors: key 00..0f, messages 00, 01, ..
    #[test]
    fn reference_vectors() {
        assert_eq!(siphash(key(), &[]), 0x726f_db47_dd0e_0e31);
        assert_eq!(siphash_bytes(key(), &[]), 0x726f_db47_dd0e_0e31);
        let m: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
        assert_eq!(
            siphash_bytes(key(), &m),
            siphash(key(), &[u64::from_le_bytes(m)])
        );
        assert_eq!(siphash_bytes(key(), &m), 0x93f5_f579_9a93_2462);
    }
}
