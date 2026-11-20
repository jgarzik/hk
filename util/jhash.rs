//! Bob Jenkins' lookup3 hash, the one-word form (Linux
//! include/linux/jhash.h jhash_1word)

/// Linux JHASH_INITVAL
const JHASH_INITVAL: u32 = 0xdead_beef;

/// Linux __jhash_final
fn final_mix(mut a: u32, mut b: u32, mut c: u32) -> u32 {
    c ^= b;
    c = c.wrapping_sub(b.rotate_left(14));
    a ^= c;
    a = a.wrapping_sub(c.rotate_left(11));
    b ^= a;
    b = b.wrapping_sub(a.rotate_left(25));
    c ^= b;
    c = c.wrapping_sub(b.rotate_left(16));
    a ^= c;
    a = a.wrapping_sub(c.rotate_left(4));
    b ^= a;
    b = b.wrapping_sub(a.rotate_left(14));
    c ^= b;
    c.wrapping_sub(b.rotate_left(24))
}

/// Linux __jhash_nwords
fn nwords(a: u32, b: u32, c: u32, initval: u32) -> u32 {
    final_mix(
        a.wrapping_add(initval),
        b.wrapping_add(initval),
        c.wrapping_add(initval),
    )
}

/// Linux jhash_1word
pub fn jhash_1word(a: u32, initval: u32) -> u32 {
    nwords(
        a,
        0,
        0,
        initval.wrapping_add(JHASH_INITVAL).wrapping_add(1 << 2),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Values computed with Linux's jhash.h macros
    #[test]
    fn known_values() {
        assert_eq!(jhash_1word(0, 0), 0x0493_96b8);
        assert_eq!(jhash_1word(0x0100_007f, 0x1234_5678), 0x5ec6_1144);
    }
}
