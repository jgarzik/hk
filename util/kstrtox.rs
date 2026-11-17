//! Whole-string integer parsing (Linux lib/kstrtox.c, base 0): an
//! optional sign, then `0x` hex (a hex digit must follow), a leading
//! `0` octal, else decimal; one trailing newline; nothing else

use super::error::KernelError;

/// Linux _parse_integer_fixup_radix for base 0: the radix and the digits
fn radix(s: &[u8]) -> (u32, &[u8]) {
    match s {
        [b'0', x, h, ..] if x.eq_ignore_ascii_case(&b'x') && h.is_ascii_hexdigit() => (16, &s[2..]),
        [b'0', ..] => (8, s),
        _ => (10, s),
    }
}

/// Linux _kstrtoull(s, 0): EINVAL for no digit or anything after them
/// but a newline, ERANGE past u64
fn kstrtoull_raw(s: &[u8]) -> Result<u64, KernelError> {
    let (base, s) = radix(s);
    let n = s
        .iter()
        .take_while(|&&c| (c as char).is_digit(base))
        .count();
    if n == 0 {
        return Err(KernelError::InvalidArgument);
    }
    // Overflow first, then what follows (Linux's order)
    let v = s[..n].iter().try_fold(0u64, |v, &c| {
        v.checked_mul(u64::from(base))
            .and_then(|v| v.checked_add(u64::from((c as char).to_digit(base)?)))
            .ok_or(KernelError::Range)
    })?;
    match &s[n..] {
        [] | [b'\n'] => Ok(v),
        _ => Err(KernelError::InvalidArgument),
    }
}

/// Linux kstrtoll(s, 0)
pub fn kstrtoll(s: &[u8]) -> Result<i64, KernelError> {
    match s.strip_prefix(b"-") {
        Some(b) => 0i64
            .checked_sub_unsigned(kstrtoull_raw(b)?)
            .ok_or(KernelError::Range),
        None => {
            let v = kstrtoull_raw(s.strip_prefix(b"+").unwrap_or(s))?;
            i64::try_from(v).map_err(|_| KernelError::Range)
        }
    }
}

/// Linux kstrtoint(s, 0): `kstrtoll` within i32
pub fn kstrtoint(s: &[u8]) -> Result<i32, KernelError> {
    i32::try_from(kstrtoll(s)?).map_err(|_| KernelError::Range)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Base 0 as Linux: decimal, 0x hex, leading-0 octal, a sign, one
    /// trailing newline
    #[test]
    fn bases() {
        assert_eq!(kstrtoint(b"60"), Ok(60));
        assert_eq!(kstrtoint(b"-60"), Ok(-60));
        assert_eq!(kstrtoint(b"+60"), Ok(60));
        assert_eq!(kstrtoint(b"0x3c"), Ok(60));
        assert_eq!(kstrtoint(b"0X3C"), Ok(60));
        assert_eq!(kstrtoint(b"-0x3c"), Ok(-60));
        assert_eq!(kstrtoint(b"074"), Ok(60));
        assert_eq!(kstrtoint(b"0"), Ok(0));
        assert_eq!(kstrtoint(b"-0"), Ok(0));
        assert_eq!(kstrtoint(b"60\n"), Ok(60));
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
            b" 6",
        ] {
            assert_eq!(kstrtoint(s), inval, "{s:?}");
        }
        assert_eq!(kstrtoint(b"2147483648"), Err(KernelError::Range));
        assert_eq!(kstrtoint(b"-2147483648"), Ok(i32::MIN));
        assert_eq!(kstrtoll(b"-9223372036854775808"), Ok(i64::MIN));
        assert_eq!(kstrtoll(b"9223372036854775808"), Err(KernelError::Range));
        assert_eq!(kstrtoll(b"18446744073709551616"), Err(KernelError::Range));
        assert_eq!(kstrtoll(b"18446744073709551616x"), Err(KernelError::Range));
    }
}
