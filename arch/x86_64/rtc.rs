//! CMOS Real-Time Clock (RTC) driver
//!
//! The RTC is a battery-backed clock that maintains wall-clock time when
//! the system is powered off. This driver reads the RTC at boot to seed
//! the kernel's wall-clock time.
//!
//! The RTC is accessed via CMOS ports 0x70 (address) and 0x71 (data).

use super::io;

/// CMOS port addresses
const CMOS_ADDR: u16 = 0x70;
const CMOS_DATA: u16 = 0x71;

/// RTC register addresses
const RTC_SECONDS: u8 = 0x00;
const RTC_MINUTES: u8 = 0x02;
const RTC_HOURS: u8 = 0x04;
const RTC_DAY: u8 = 0x07;
const RTC_MONTH: u8 = 0x08;
const RTC_YEAR: u8 = 0x09;
const RTC_STATUS_A: u8 = 0x0A;
const RTC_STATUS_B: u8 = 0x0B;

/// Read a CMOS register
fn cmos_read(reg: u8) -> u8 {
    // Disable NMI by setting bit 7, then select register
    io::outb(CMOS_ADDR, reg | 0x80);
    io::inb(CMOS_DATA)
}

/// Check if RTC update is in progress
fn update_in_progress() -> bool {
    cmos_read(RTC_STATUS_A) & 0x80 != 0
}

/// Convert BCD to binary
fn bcd_to_bin(bcd: u8) -> u8 {
    (bcd >> 4) * 10 + (bcd & 0x0F)
}

/// Read current time from RTC
///
/// Returns seconds since Unix epoch (1970-01-01 00:00:00 UTC)
pub fn read_rtc() -> i64 {
    // Wait for update-in-progress to clear
    // The RTC may be updating its registers, so we need to wait
    while update_in_progress() {
        core::hint::spin_loop();
    }

    // Read all time registers
    let mut sec = cmos_read(RTC_SECONDS);
    let mut min = cmos_read(RTC_MINUTES);
    let mut hour = cmos_read(RTC_HOURS);
    let day = cmos_read(RTC_DAY);
    let month = cmos_read(RTC_MONTH);
    let mut year = cmos_read(RTC_YEAR);

    // Read again and verify (in case update started during read)
    while update_in_progress() {
        core::hint::spin_loop();
    }

    let sec2 = cmos_read(RTC_SECONDS);
    let min2 = cmos_read(RTC_MINUTES);
    let hour2 = cmos_read(RTC_HOURS);

    // If values changed, read again
    if sec != sec2 || min != min2 || hour != hour2 {
        sec = cmos_read(RTC_SECONDS);
        min = cmos_read(RTC_MINUTES);
        hour = cmos_read(RTC_HOURS);
    }

    // Check if BCD mode (bit 2 of status B = 0 means BCD)
    let status_b = cmos_read(RTC_STATUS_B);
    let is_bcd = status_b & 0x04 == 0;
    let is_24hour = status_b & 0x02 != 0;

    if is_bcd {
        sec = bcd_to_bin(sec);
        min = bcd_to_bin(min);
        // Handle AM/PM bit in 12-hour mode before BCD conversion
        let pm = hour & 0x80 != 0;
        hour = bcd_to_bin(hour & 0x7F);
        if !is_24hour {
            hour = hour12(hour, pm);
        }
        year = bcd_to_bin(year);
    } else if !is_24hour {
        let pm = hour & 0x80 != 0;
        hour = hour12(hour & 0x7F, pm);
    }

    // Convert to binary values
    let day = if is_bcd { bcd_to_bin(day) } else { day };
    let month = if is_bcd { bcd_to_bin(month) } else { month };

    // Assume 21st century (year 00-99 -> 2000-2099)
    let year_full = 2000 + i64::from(year);

    // A time the clock cannot hold starts the system at 0 (Linux
    // rtc_valid_tm, then mach_get_cmos_time)
    let (month, day, hour, min, sec) = (
        i64::from(month),
        i64::from(day),
        i64::from(hour),
        i64::from(min),
        i64::from(sec),
    );
    if !valid(year_full, month, day, hour, min, sec) {
        return 0;
    }
    date_to_unix(year_full, month, day, hour, min, sec)
}

/// A 12-hour clock's hour in 24 hours: 12 AM is 0, 12 PM is 12
fn hour12(hour: u8, pm: bool) -> u8 {
    hour % 12 + if pm { 12 } else { 0 }
}

/// A real date and time (Linux rtc_valid_tm; month 1-based here)
fn valid(year: i64, month: i64, day: i64, hour: i64, min: i64, sec: i64) -> bool {
    const DAYS_IN_MONTH: [i64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if !(1..=12).contains(&month) || year < 1970 {
        return false;
    }
    let mdays = DAYS_IN_MONTH[(month - 1) as usize] + i64::from(month == 2 && is_leap_year(year));
    (1..=mdays).contains(&day) && hour < 24 && min < 60 && sec < 60 && hour >= 0
}

/// Convert date/time to Unix timestamp (seconds since 1970-01-01 00:00:00 UTC)
fn date_to_unix(year: i64, month: i64, day: i64, hour: i64, min: i64, sec: i64) -> i64 {
    // Days in each month (non-leap year)
    const DAYS_IN_MONTH: [i64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

    let mut days = 0i64;

    // Count days from 1970 to year-1
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }

    // Count days from January to month-1 in the current year
    for m in 1..month {
        days += DAYS_IN_MONTH[(m - 1) as usize];
        // Add leap day if February and leap year
        if m == 2 && is_leap_year(year) {
            days += 1;
        }
    }

    // Add days in current month (day is 1-indexed)
    days += day - 1;

    // Convert to seconds and add time
    days * 86400 + hour * 3600 + min * 60 + sec
}

/// Check if a year is a leap year
fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hours_and_dates() {
        assert_eq!(hour12(12, false), 0);
        assert_eq!(hour12(12, true), 12);
        assert_eq!(hour12(1, true), 13);
        assert_eq!(hour12(11, false), 11);
        assert!(valid(2026, 2, 28, 23, 59, 59));
        assert!(!valid(2026, 2, 29, 0, 0, 0));
        assert!(valid(2028, 2, 29, 0, 0, 0));
        assert!(!valid(2026, 13, 1, 0, 0, 0));
        assert!(!valid(2026, 14, 1, 0, 0, 0));
        assert!(!valid(2026, 0, 1, 0, 0, 0));
        assert!(!valid(2026, 1, 32, 0, 0, 0));
        assert!(!valid(2026, 1, 1, 24, 0, 0));
        assert_eq!(date_to_unix(1970, 1, 1, 0, 0, 0), 0);
        assert_eq!(date_to_unix(2000, 3, 1, 0, 0, 0), 951_868_800);
    }
}
