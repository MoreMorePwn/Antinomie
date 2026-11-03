// SPDX-License-Identifier: GPL-3.0-only
//! Civil (proleptic Gregorian, UTC) dates without a time library.
//!
//! Core has no chrono, so every day-count to year/month/day conversion and
//! every `YYYY-MM-DD[ HH:MM:SS]` text lives here (Howard Hinnant's
//! `civil_from_days` / `days_from_civil`). Day 0 is 1970-01-01; negative day
//! counts are dates before it.

const SECONDS_PER_DAY: i64 = 86_400;

/// The zone the app displays times in, set by the UI (Settings > Appearance):
/// seconds east of UTC at a Unix second. Stored data stays UTC; only the
/// human-readable text of a report or export uses this.
static DISPLAY_OFFSET: std::sync::RwLock<fn(i64) -> i32> = std::sync::RwLock::new(|_| 0);

pub fn set_display_offset(offset: fn(i64) -> i32) {
    *DISPLAY_OFFSET.write().unwrap_or_else(|e| e.into_inner()) = offset;
}

fn display_offset(seconds: i64) -> i32 {
    (*DISPLAY_OFFSET.read().unwrap_or_else(|e| e.into_inner()))(seconds)
}

/// A zone offset in seconds as `UTC+7`, `UTC+5:30`, `UTC-3`, `UTC` for zero.
pub fn zone_text(offset: i32) -> String {
    if offset == 0 {
        return "UTC".into();
    }
    let (sign, minutes) = (if offset < 0 { '-' } else { '+' }, offset.abs() / 60);
    if minutes % 60 == 0 {
        format!("UTC{sign}{}", minutes / 60)
    } else {
        format!("UTC{sign}{}:{:02}", minutes / 60, minutes % 60)
    }
}

/// `YYYY-MM-DD HH:MM:SS (UTC+7)` of Unix seconds in the display zone.
pub fn display_date_time_text(seconds: i64) -> String {
    let offset = display_offset(seconds);
    format!(
        "{} ({})",
        date_time_text(seconds + i64::from(offset)),
        zone_text(offset)
    )
}

/// Year, month (1..=12) and day (1..=31) of a day count since 1970-01-01.
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// The day count since 1970-01-01 of a real calendar date in years 1..=9999,
/// or None when the month or day does not exist (29 February only in leap
/// years).
pub fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if !(1..=9999).contains(&year) || !(1..=month_days).contains(&day) {
        return None;
    }
    let year = i64::from(year) - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400) as u64;
    let mp = u64::from(if month > 2 { month - 3 } else { month + 9 });
    let doy = (153 * mp + 2) / 5 + u64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe as i64 - 719_468)
}

/// `YYYY-MM-DD` of a day count since 1970-01-01.
pub fn day_text(days: i64) -> String {
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}")
}

/// `YYYY-MM-DD` (UTC) of Unix seconds.
pub fn date_text(seconds: i64) -> String {
    day_text(seconds.div_euclid(SECONDS_PER_DAY))
}

/// `YYYY-MM-DD HH:MM:SS` (UTC) of Unix seconds.
pub fn date_time_text(seconds: i64) -> String {
    let rest = seconds.rem_euclid(SECONDS_PER_DAY);
    format!(
        "{} {:02}:{:02}:{:02}",
        date_text(seconds),
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// The year and month (1..=12) of Unix seconds, in UTC.
pub fn year_month(seconds: i64) -> (i64, u32) {
    let (year, month, _) = civil_from_days(seconds.div_euclid(SECONDS_PER_DAY));
    (year, month)
}
