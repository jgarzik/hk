//! Integer parsing (Linux lib/kstrtox.c; simple_strtoull of
//! lib/vsprintf.c and memparse of lib/cmdline.c on the same core):
//! base 0 is `0x` hex (a hex digit must follow), a leading `0` octal,
//! else decimal. The kstrto* functions take a whole string (one
//! trailing newline), the others parse a prefix and return the rest.

use super::error::KernelError;

/// Linux _parse_integer_fixup_radix: base 0 resolved, a `0x` before
/// base 16 skipped
fn fixup_radix(s: &[u8], base: u32) -> (u32, &[u8]) {
    let hex = |s: &[u8]| matches!(s, [b'0', x, ..] if x.eq_ignore_ascii_case(&b'x'));
    let base = match s {
        _ if base != 0 => base,
        [b'0', _, h, ..] if hex(s) && h.is_ascii_hexdigit() => 16,
        [b'0', ..] => 8,
        _ => 10,
    };
    if base == 16 && hex(s) {
        (base, &s[2..])
    } else {
        (base, s)
    }
}

/// Linux _parse_integer: the value of the leading digits of `s` in
/// `base` (wrapping past u64), how many digits there were, and whether
/// it overflowed
fn parse_integer(s: &[u8], base: u32) -> (u64, usize, bool) {
    let mut v = 0u64;
    let mut over = false;
    let mut n = 0;
    while let Some(d) = s.get(n).and_then(|&c| (c as char).to_digit(base)) {
        let (m, o1) = v.overflowing_mul(u64::from(base));
        let (a, o2) = m.overflowing_add(u64::from(d));
        over |= o1 || o2;
        v = a;
        n += 1;
    }
    (v, n, over)
}

/// Linux simple_strtoull: the leading number of `s` in `base` (0: by
/// its prefix), wrapping past u64, and the rest; 0 and all of `s` if
/// there is no digit
pub fn simple_strtoull(s: &[u8], base: u32) -> (u64, &[u8]) {
    let (base, t) = fixup_radix(s, base);
    let (v, n, _) = parse_integer(t, base);
    (v, &t[n..])
}

/// Linux strtoul_lenient (kernel/sysctl.c): as `simple_strtoull`, but
/// ERANGE past u64
pub fn strtoull_lenient(s: &[u8], base: u32) -> Result<(u64, &[u8]), KernelError> {
    let (base, t) = fixup_radix(s, base);
    match parse_integer(t, base) {
        (_, _, true) => Err(KernelError::Range),
        (v, n, false) => Ok((v, &t[n..])),
    }
}

/// Linux _kstrtoull: the number, one trailing newline; EINVAL for no
/// digit or anything else after them, ERANGE past u64 (checked first,
/// as Linux)
fn kstrtoull_raw(s: &[u8], base: u32) -> Result<u64, KernelError> {
    let (base, t) = fixup_radix(s, base);
    let (v, n, over) = parse_integer(t, base);
    if n == 0 {
        return Err(KernelError::InvalidArgument);
    }
    if over {
        return Err(KernelError::Range);
    }
    match &t[n..] {
        [] | [b'\n'] => Ok(v),
        _ => Err(KernelError::InvalidArgument),
    }
}

/// Linux kstrtoull: an optional '+', then `kstrtoull_raw`
pub fn kstrtoull(s: &[u8], base: u32) -> Result<u64, KernelError> {
    kstrtoull_raw(s.strip_prefix(b"+").unwrap_or(s), base)
}

/// Linux kstrtouint: `kstrtoull` within u32
pub fn kstrtouint(s: &[u8], base: u32) -> Result<u32, KernelError> {
    u32::try_from(kstrtoull(s, base)?).map_err(|_| KernelError::Range)
}

/// Linux kstrtoll: a '-' before `kstrtoull_raw`, else `kstrtoull`,
/// within i64
pub fn kstrtoll(s: &[u8], base: u32) -> Result<i64, KernelError> {
    match s.strip_prefix(b"-") {
        Some(b) => 0i64
            .checked_sub_unsigned(kstrtoull_raw(b, base)?)
            .ok_or(KernelError::Range),
        None => i64::try_from(kstrtoull(s, base)?).map_err(|_| KernelError::Range),
    }
}

/// Linux kstrtoint: `kstrtoll` within i32
pub fn kstrtoint(s: &[u8], base: u32) -> Result<i32, KernelError> {
    i32::try_from(kstrtoll(s, base)?).map_err(|_| KernelError::Range)
}

/// Linux memparse (lib/cmdline.c): a base-0 `simple_strtoull` number
/// and an optional K, M, G, T, P or E suffix (either case), shifted
/// with no overflow check, as Linux; the value and the rest
pub fn memparse(s: &[u8]) -> (u64, &[u8]) {
    let (v, rest) = simple_strtoull(s, 0);
    let shift = match rest.first().map(u8::to_ascii_lowercase) {
        Some(b'k') => 10,
        Some(b'm') => 20,
        Some(b'g') => 30,
        Some(b't') => 40,
        Some(b'p') => 50,
        Some(b'e') => 60,
        _ => return (v, rest),
    };
    (v << shift, &rest[1..])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Base 0 as Linux: decimal, 0x hex, leading-0 octal, a sign, one
    /// trailing newline
    #[test]
    fn bases() {
        assert_eq!(kstrtoint(b"60", 0), Ok(60));
        assert_eq!(kstrtoint(b"-60", 0), Ok(-60));
        assert_eq!(kstrtoint(b"+60", 0), Ok(60));
        assert_eq!(kstrtoint(b"0x3c", 0), Ok(60));
        assert_eq!(kstrtoint(b"0X3C", 0), Ok(60));
        assert_eq!(kstrtoint(b"-0x3c", 0), Ok(-60));
        assert_eq!(kstrtoint(b"074", 0), Ok(60));
        assert_eq!(kstrtoint(b"0", 0), Ok(0));
        assert_eq!(kstrtoint(b"-0", 0), Ok(0));
        assert_eq!(kstrtoint(b"60\n", 0), Ok(60));
    }

    /// What Linux refuses: EINVAL when malformed, ERANGE past the type
    #[test]
    fn refused() {
        let inval = Err(KernelError::InvalidArgument);
        for s in [
            &b""[..],
            b"-",
            b"+",
            b"0x",
            b"0xg",
            b"08",
            b"6 0",
            b"60\n\n",
            b"-+6",
            b"+-6",
            b" 6",
            b"\n",
        ] {
            assert_eq!(kstrtoint(s, 0), inval, "{s:?}");
        }
        assert_eq!(kstrtoint(b"2147483648", 0), Err(KernelError::Range));
        assert_eq!(kstrtoint(b"-2147483648", 0), Ok(i32::MIN));
        assert_eq!(kstrtoll(b"-9223372036854775808", 0), Ok(i64::MIN));
        assert_eq!(kstrtoll(b"9223372036854775808", 0), Err(KernelError::Range));
        assert_eq!(
            kstrtoll(b"18446744073709551616", 0),
            Err(KernelError::Range)
        );
        assert_eq!(
            kstrtoll(b"18446744073709551616x", 0),
            Err(KernelError::Range)
        );
    }

    /// An explicit base: no prefix but 16's `0x`; u32 and u64 limits
    #[test]
    fn unsigned() {
        assert_eq!(kstrtouint(b"755", 8), Ok(0o755));
        assert_eq!(kstrtouint(b"0755", 8), Ok(0o755));
        assert_eq!(kstrtouint(b"8", 8), Err(KernelError::InvalidArgument));
        assert_eq!(kstrtouint(b"", 8), Err(KernelError::InvalidArgument));
        assert_eq!(kstrtouint(b"0x10", 8), Err(KernelError::InvalidArgument));
        assert_eq!(kstrtouint(b"0x10", 16), Ok(16));
        assert_eq!(kstrtouint(b"10", 16), Ok(16));
        assert_eq!(kstrtouint(b"+7\n", 10), Ok(7));
        assert_eq!(kstrtouint(b"-7", 10), Err(KernelError::InvalidArgument));
        assert_eq!(kstrtouint(b"4294967295", 0), Ok(u32::MAX));
        assert_eq!(kstrtouint(b"4294967296", 0), Err(KernelError::Range));
        assert_eq!(kstrtoull(b"18446744073709551615", 0), Ok(u64::MAX));
        assert_eq!(
            kstrtoull(b"18446744073709551617", 0),
            Err(KernelError::Range)
        );
    }

    /// simple_strtoull: a prefix, the rest returned, wrapping past u64;
    /// strtoull_lenient refuses that
    #[test]
    fn prefixes() {
        assert_eq!(simple_strtoull(b"12ab", 0), (12, &b"ab"[..]));
        assert_eq!(simple_strtoull(b"0x1fz", 0), (31, &b"z"[..]));
        assert_eq!(simple_strtoull(b"0x", 0), (0, &b"x"[..]));
        assert_eq!(simple_strtoull(b"x", 0), (0, &b"x"[..]));
        assert_eq!(simple_strtoull(b"-1", 0), (0, &b"-1"[..]));
        assert_eq!(simple_strtoull(b"18446744073709551617", 0), (1, &b""[..]));
        assert_eq!(strtoull_lenient(b"0+5", 0), Ok((0, &b"+5"[..])));
        assert_eq!(
            strtoull_lenient(b"18446744073709551616", 0),
            Err(KernelError::Range)
        );
    }

    /// memparse: suffixes either case, shifted with no overflow check
    #[test]
    fn sizes() {
        assert_eq!(memparse(b"8k"), (8192, &b""[..]));
        assert_eq!(memparse(b"0x10M"), (16 << 20, &b""[..]));
        assert_eq!(memparse(b"010"), (8, &b""[..]));
        assert_eq!(memparse(b"5%"), (5, &b"%"[..]));
        assert_eq!(memparse(b"2T"), (2 << 40, &b""[..]));
        assert_eq!(memparse(b"3p"), (3 << 50, &b""[..]));
        assert_eq!(memparse(b"1E"), (1 << 60, &b""[..]));
        assert_eq!(memparse(b"99E"), (3 << 60, &b""[..]));
        assert_eq!(memparse(b"1KB"), (1024, &b"B"[..]));
        assert_eq!(memparse(b""), (0, &b""[..]));
    }
}
