//! FAT timestamps (Linux fs/fat/misc.c: fat_time_unix2fat,
//! fat_time_fat2unix, fat_truncate_atime, fat_truncate_time)
//!
//! A directory entry keeps local time: the modification time and date
//! (2 s), the access date (a day), the creation time and date with
//! hundredths. The mount's offset from UTC is tz=UTC / time_offset=,
//! else the kernel's timezone (Linux sys_tz, which hk keeps at 0).

use crate::time::Timespec;

const SECS_PER_MIN: i64 = 60;
const SECS_PER_HOUR: i64 = 60 * 60;
const SECS_PER_DAY: i64 = SECS_PER_HOUR * 24;
/// Days from 1970-01-01 to 1980-01-01 (Linux DAYS_DELTA)
const DAYS_DELTA: i64 = 365 * 10 + 2;
/// 2100, which is no leap year, from 1980 (Linux YEAR_2100)
const YEAR_2100: i64 = 120;
/// Days before each month, 1-based, past December 0 (Linux
/// days_in_year)
const DAYS_IN_YEAR: [i64; 16] = [
    0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 0, 0, 0,
];

/// The year (from 1980) is a leap year (Linux IS_LEAP_YEAR)
fn is_leap(y: i64) -> bool {
    y & 3 == 0 && y != YEAR_2100
}

/// The offset of the entries' local time from UTC, in seconds (Linux
/// fat_tz_offset): -time_offset minutes when tz= or time_offset= was
/// given, else the kernel's timezone, 0
pub fn tz_offset(tz_set: bool, time_offset: i32) -> i64 {
    if tz_set {
        -i64::from(time_offset) * SECS_PER_MIN
    } else {
        0
    }
}

/// Linux fat_time_fat2unix: an entry's time, date and hundredths as a
/// UNIX time
pub fn fat2unix(off: i64, time: u16, date: u16, cs: u8) -> Timespec {
    let year = i64::from(date >> 9);
    let month = i64::from((date >> 5) & 0xf).max(1);
    let day = i64::from(date & 0x1f).max(1) - 1;
    let mut leap_day = (year + 3) / 4;
    if year > YEAR_2100 {
        leap_day -= 1;
    }
    if is_leap(year) && month > 2 {
        leap_day += 1;
    }
    let mut second = i64::from(time & 0x1f) << 1;
    second += i64::from((time >> 5) & 0x3f) * SECS_PER_MIN;
    second += i64::from(time >> 11) * SECS_PER_HOUR;
    second +=
        (year * 365 + leap_day + DAYS_IN_YEAR[month as usize] + day + DAYS_DELTA) * SECS_PER_DAY;
    second += off;
    if cs != 0 {
        Timespec {
            sec: second + i64::from(cs / 100),
            nsec: u32::from(cs % 100) * 10_000_000,
        }
    } else {
        Timespec {
            sec: second,
            nsec: 0,
        }
    }
}

/// Linux time64_to_tm(t, offset): (years since 1900, month 0..11, day
/// of month, hour, minute, second)
fn to_tm(t: i64, offset: i64) -> (i64, i64, i64, i64, i64, i64) {
    let mut days = t.div_euclid(SECS_PER_DAY);
    let mut rem = t.rem_euclid(SECS_PER_DAY) + offset;
    while rem < 0 {
        rem += SECS_PER_DAY;
        days -= 1;
    }
    while rem >= SECS_PER_DAY {
        rem -= SECS_PER_DAY;
        days += 1;
    }
    // Days since 1970-01-01 to a civil date (proleptic Gregorian)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let mday = doy - (153 * mp + 2) / 5 + 1;
    let mon = if mp < 10 { mp + 2 } else { mp - 10 };
    let year = yoe + era * 400 + i64::from(mon < 2);
    (
        year - 1900,
        mon,
        mday,
        rem / SECS_PER_HOUR,
        rem % SECS_PER_HOUR / SECS_PER_MIN,
        rem % SECS_PER_MIN,
    )
}

/// Linux fat_time_unix2fat: a UNIX time as an entry's (time, date,
/// hundredths), clamped to 1980..2107
pub fn unix2fat(off: i64, ts: Timespec) -> (u16, u16, u8) {
    let (year, mon, mday, hour, min, sec) = to_tm(ts.sec, -off);
    if year < 1980 - 1900 {
        return (0, (1 << 5) | 1, 0);
    }
    if year > 2107 - 1900 {
        return (
            (23 << 11) | (59 << 5) | 29,
            (127 << 9) | (12 << 5) | 31,
            199,
        );
    }
    let time = (hour << 11 | min << 5 | sec >> 1) as u16;
    let date = ((year - 80) << 9 | (mon + 1) << 5 | mday) as u16;
    let cs = ((ts.sec & 1) * 100 + i64::from(ts.nsec) / 10_000_000) as u8;
    (time, date, cs)
}

/// Linux fat_timespec64_trunc_2secs
pub fn trunc_2secs(ts: Timespec) -> Timespec {
    Timespec {
        sec: ts.sec & !1,
        nsec: 0,
    }
}

/// Linux fat_truncate_atime: to the day (00:00:00 local time)
pub fn trunc_atime(off: i64, ts: Timespec) -> Timespec {
    let seconds = ts.sec - off;
    // div_s64_rem: the remainder takes the dividend's sign
    let rem = seconds % SECS_PER_DAY;
    Timespec {
        sec: seconds + off - rem,
        nsec: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(sec: i64, nsec: u32) -> Timespec {
        Timespec { sec, nsec }
    }

    /// Round trips at 2 s granularity, the clamps, leap days, the
    /// hundredths and the offset (Linux fat_test's cases in spirit)
    #[test]
    fn conversions() {
        // 1980-01-01 00:00:00 UTC
        assert_eq!(unix2fat(0, ts(315_532_800, 0)), (0, (1 << 5) | 1, 0));
        assert_eq!(fat2unix(0, 0, (1 << 5) | 1, 0).sec, 315_532_800);
        // 2017-09-14 18:28:21 (an odd second: 2 s field, 100 cs)
        let t = ts(1_505_413_701, 500_000_000);
        let (time, date, cs) = unix2fat(0, t);
        assert_eq!(cs, 150);
        assert_eq!(fat2unix(0, time, date, 0).sec, 1_505_413_700);
        assert_eq!(fat2unix(0, time, date, cs), t);
        // 2000-02-29 and 2004-03-01 (leap years)
        for s in [951_782_400, 1_078_099_200] {
            let (time, date, _) = unix2fat(0, ts(s, 0));
            assert_eq!(fat2unix(0, time, date, 0).sec, s);
        }
        // Before 1980 and past 2107 clamp
        assert_eq!(unix2fat(0, ts(0, 0)), (0, (1 << 5) | 1, 0));
        let far = unix2fat(0, ts(5_000_000_000, 0));
        assert_eq!(
            far,
            (
                (23 << 11) | (59 << 5) | 29,
                (127 << 9) | (12 << 5) | 31,
                199
            )
        );
        // time_offset=60: local is an hour ahead of UTC
        let off = tz_offset(true, 60);
        let (time, date, _) = unix2fat(off, ts(1_500_000_000, 0));
        assert_eq!(fat2unix(0, time, date, 0).sec, 1_500_003_600);
        assert_eq!(fat2unix(off, time, date, 0).sec, 1_500_000_000);
        // A day boundary, local
        assert_eq!(trunc_atime(0, ts(1_600_000_123, 5)).sec, 1_599_955_200);
        assert_eq!(trunc_2secs(ts(1_500_000_001, 7)), ts(1_500_000_000, 0));
    }
}
