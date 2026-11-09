// SPDX-License-Identifier: GPL-3.0-only
//! The calendar date of a Unix time in UTC, for the result folders.

/// `yyyy-mm-dd` of `ms` (Unix milliseconds), UTC.
pub fn date_of(ms: u64) -> String {
    let days = (ms / 86_400_000) as i64;
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use super::date_of;

    #[test]
    fn known_dates() {
        assert_eq!(date_of(0), "1970-01-01");
        assert_eq!(date_of(951_782_400_000), "2000-02-29");
        assert_eq!(date_of(1_794_000_000_000), "2026-11-06");
        assert_eq!(date_of(4_102_444_799_999), "2099-12-31");
        assert_eq!(date_of(4_102_444_800_000), "2100-01-01");
    }
}
