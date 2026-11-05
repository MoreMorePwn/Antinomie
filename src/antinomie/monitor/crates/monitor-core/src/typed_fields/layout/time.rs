// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Times as people read them: a `timespec` or `timeval` as a duration (`1.5 s`,
//! `250 ms`, `2 min 5 s`), a wall-clock time as a UTC date, a reading on
//! another clock as seconds since that clock started.

/// What a time structure means in the call that passed it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum TimeKind {
    /// How long: a sleep, a timeout, an interval.
    #[default]
    Duration,
    /// A point on CLOCK_REALTIME (or TAI): a date.
    Wall,
    /// A point on another clock (monotonic, boot): seconds on that clock.
    Clock,
}

/// `utimensat`'s "set to the current time" and "leave alone" sentinels in
/// `tv_nsec`.
const UTIME_NOW: i64 = (1 << 30) - 1;
const UTIME_OMIT: i64 = (1 << 30) - 2;

/// `whole.frac` of `total / unit`, the fraction without trailing zeros.
fn scaled(total: u128, unit: u128, digits: usize) -> String {
    let (whole, rest) = (total / unit, total % unit);
    if rest == 0 {
        return whole.to_string();
    }
    let fraction = format!("{rest:0digits$}");
    format!("{whole}.{}", fraction.trim_end_matches('0'))
}

/// A length of time: `0 s`, `20 ns`, `250 us`, `100 ms`, `1.5 s`, and past a
/// minute the same in larger units (`125 s (2 min 5 s)`).
pub(crate) fn duration(total_ns: u128) -> String {
    match total_ns {
        0 => "0 s".into(),
        1..=999 => format!("{total_ns} ns"),
        1_000..=999_999 => format!("{} us", scaled(total_ns, 1_000, 3)),
        1_000_000..=999_999_999 => format!("{} ms", scaled(total_ns, 1_000_000, 6)),
        _ => {
            let text = format!("{} s", scaled(total_ns, 1_000_000_000, 9));
            let seconds = u64::try_from(total_ns / 1_000_000_000).unwrap_or(u64::MAX);
            if seconds < 60 {
                return text;
            }
            let mut parts = Vec::new();
            let mut rest = seconds;
            for (unit, name) in [(86_400, "d"), (3_600, "h"), (60, "min"), (1, "s")] {
                let count = rest / unit;
                rest %= unit;
                if count != 0 {
                    parts.push(format!("{count} {name}"));
                }
            }
            if parts.is_empty() {
                text
            } else {
                format!("{text} ({})", parts.join(" "))
            }
        }
    }
}

/// A time from its seconds and sub-second part (`nanoseconds` of a timespec,
/// microseconds of a timeval, in `fraction` with `unit` nanoseconds each).
/// None when the parts cannot be a time: the view then keeps the members.
pub(crate) fn time(seconds: i64, fraction: i64, unit: i64, kind: TimeKind) -> Option<String> {
    if unit == 1 && (fraction == UTIME_NOW || fraction == UTIME_OMIT) {
        return Some(
            if fraction == UTIME_NOW {
                "UTIME_NOW"
            } else {
                "UTIME_OMIT"
            }
            .into(),
        );
    }
    let per_second = 1_000_000_000 / unit;
    if !(0..per_second).contains(&fraction) {
        return None;
    }
    if seconds < 0 {
        return match kind {
            // A date before 1970 is a program's zero or garbage, not a duration.
            TimeKind::Wall => Some(format!("{} s before 1970", seconds.unsigned_abs())),
            _ => None,
        };
    }
    let nanos = u128::from(seconds.unsigned_abs()) * 1_000_000_000
        + u128::try_from(fraction * unit).ok()?;
    Some(match kind {
        TimeKind::Duration => duration(nanos),
        TimeKind::Clock => format!("at {}", scaled(nanos, 1_000_000_000, 9) + " s"),
        TimeKind::Wall => {
            let date = crate::date::date_time_text(seconds);
            if fraction == 0 {
                format!("{date} UTC")
            } else {
                let digits = (1_000_000_000 / unit).to_string().len() - 1;
                let fraction = format!("{fraction:0digits$}");
                format!("{date}.{} UTC", fraction.trim_end_matches('0'))
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_read_in_the_largest_fitting_unit() {
        assert_eq!(duration(0), "0 s");
        assert_eq!(duration(20), "20 ns");
        assert_eq!(duration(250_000), "250 us");
        assert_eq!(duration(100_000_000), "100 ms");
        assert_eq!(duration(1_500_000_000), "1.5 s");
        assert_eq!(duration(125_000_000_000), "125 s (2 min 5 s)");
        assert_eq!(duration(3_600_000_000_000), "3600 s (1 h)");
        assert_eq!(duration(90_061_000_000_000), "90061 s (1 d 1 h 1 min 1 s)");
    }

    #[test]
    fn times_check_their_parts() {
        assert_eq!(
            time(1, 500_000_000, 1, TimeKind::Duration).unwrap(),
            "1.5 s"
        );
        assert_eq!(
            time(0, 250_000, 1_000, TimeKind::Duration).unwrap(),
            "250 ms"
        );
        assert_eq!(time(0, 1_000_000_000, 1, TimeKind::Duration), None);
        assert_eq!(time(-1, 0, 1, TimeKind::Duration), None);
        assert_eq!(
            time(5, UTIME_OMIT, 1, TimeKind::Wall).unwrap(),
            "UTIME_OMIT"
        );
        assert_eq!(
            time(1_700_000_000, 500_000_000, 1, TimeKind::Wall).unwrap(),
            "2023-11-14 22:13:20.5 UTC"
        );
        assert_eq!(time(12, 0, 1, TimeKind::Clock).unwrap(), "at 12 s");
    }
}
