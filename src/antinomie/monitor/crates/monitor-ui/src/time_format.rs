// SPDX-License-Identifier: GPL-3.0-only
//! Host wall-clock presentation shared by histories and triage.
use antinomie_monitor_core::HostClockAnchor;
use chrono::{DateTime, FixedOffset, Local, Utc};

pub(crate) fn unix_us(value: u64) -> String {
    i64::try_from(value)
        .ok()
        .and_then(DateTime::<Utc>::from_timestamp_micros)
        .map(|time| {
            let time = time.with_timezone(&Local);
            format!(
                "{} (UTC{})",
                time.format("%Y-%m-%d %H:%M:%S%.3f"),
                compact_zone(time.offset().local_minus_utc())
            )
        })
        .unwrap_or_else(|| "Unavailable".into())
}

/// A zone offset in seconds as `+7`, `+5:30`, `-3`, `+0`.
fn compact_zone(offset: i32) -> String {
    let (sign, minutes) = (if offset < 0 { '-' } else { '+' }, offset.abs() / 60);
    if minutes % 60 == 0 {
        format!("{sign}{}", minutes / 60)
    } else {
        format!("{sign}{}:{:02}", minutes / 60, minutes % 60)
    }
}

/// Whole seconds in the host zone, the offset compact: `2026-10-19 14:05:12
/// (UTC+7)`, `(UTC+5:30)`, `(UTC+0)`.
pub(crate) fn local_seconds(seconds: u64) -> String {
    local_seconds_at(seconds, |time| time.with_timezone(&Local).fixed_offset())
}

/// [`local_seconds`] with the zone chosen by `zone`, so tests can fix it.
fn local_seconds_at(seconds: u64, zone: impl Fn(DateTime<Utc>) -> DateTime<FixedOffset>) -> String {
    i64::try_from(seconds)
        .ok()
        .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, 0))
        .map(|time| {
            let time = zone(time);
            let zone = compact_zone(time.offset().local_minus_utc());
            format!("{} (UTC{zone})", time.format("%Y-%m-%d %H:%M:%S"))
        })
        .unwrap_or_else(|| "Unavailable".into())
}

/// Whole seconds as a UTC date and time: `2026-10-09 14:09:03 UTC`.
pub(crate) fn utc_seconds(seconds: u64) -> String {
    i64::try_from(seconds)
        .ok()
        .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, 0))
        .map(|time| time.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "Unavailable".into())
}

/// A duration as `m:ss`, or `h:mm:ss` from an hour.
pub(crate) fn elapsed(milliseconds: u64) -> String {
    let seconds = milliseconds / 1000;
    let (hours, minutes, seconds) = (seconds / 3600, seconds / 60 % 60, seconds % 60);
    if hours > 0 {
        format!("{hours}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes}:{seconds:02}")
    }
}

/// A duration in its largest useful unit: `640 ms`, `6 s`, `2 min 5 s`,
/// `1 h 3 min`.
pub(crate) fn duration_ms(ms: u64) -> String {
    let seconds = ms / 1000;
    match seconds {
        0 => format!("{ms} ms"),
        1..=59 => format!("{seconds} s"),
        60..=3599 => format!("{} min {} s", seconds / 60, seconds % 60),
        _ => format!("{} h {} min", seconds / 3600, seconds / 60 % 60),
    }
}

/// Machine uptime: `3 h 05 m 09 s`.
pub(crate) fn uptime(milliseconds: u64) -> String {
    let seconds = milliseconds / 1000;
    format!(
        "{} h {:02} m {:02} s",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    )
}

/// How long ago an instant was: `12 s ago`, `3 m ago`.
pub(crate) fn age(time: std::time::Instant) -> String {
    let seconds = time.elapsed().as_secs();
    if seconds < 60 {
        format!("{seconds} s ago")
    } else {
        format!("{} m ago", seconds / 60)
    }
}

/// `14:05:12` in the host zone, from epoch seconds.
pub(crate) fn time_of_day(seconds: u64) -> String {
    i64::try_from(seconds)
        .ok()
        .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, 0))
        .map(|time| time.with_timezone(&Local).format("%H:%M:%S").to_string())
        .unwrap_or_else(|| "—".into())
}

/// The time of day in UTC of a Unix-millisecond time: `14:09:03`.
pub(crate) fn utc_time_of_day(ms: u64) -> String {
    let date = utc_seconds(ms / 1000);
    date.split_whitespace().nth(1).unwrap_or(&date).to_owned()
}

/// The host clock, Unix milliseconds.
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |time| time.as_millis() as u64)
}

pub(crate) fn unix_ms(value: Option<u64>) -> String {
    value
        .and_then(|value| value.checked_mul(1000))
        .map(unix_us)
        .unwrap_or_else(|| "Unavailable".into())
}

pub(crate) fn short_time_us(value: u64) -> String {
    i64::try_from(value)
        .ok()
        .and_then(DateTime::<Utc>::from_timestamp_micros)
        .map(|time| {
            time.with_timezone(&Local)
                .format("%H:%M:%S%.3f")
                .to_string()
                + &format!(
                    " (UTC{})",
                    compact_zone(time.with_timezone(&Local).offset().local_minus_utc())
                )
        })
        .unwrap_or_else(|| "Unavailable".into())
}

/// A tick on the activity graph's axis: the local time of day, with
/// milliseconds when the ticks are closer than a second and microseconds when
/// they are closer than a millisecond.
pub(crate) fn axis_time(value: u64, step_ns: f64) -> String {
    let format = if step_ns >= 1e9 {
        "%H:%M:%S"
    } else if step_ns >= 1e6 {
        "%H:%M:%S%.3f"
    } else {
        "%H:%M:%S%.6f"
    };
    i64::try_from(value)
        .ok()
        .and_then(DateTime::<Utc>::from_timestamp_micros)
        .map(|time| time.with_timezone(&Local).format(format).to_string())
        .unwrap_or_else(|| "Unavailable".into())
}

/// The host zone as the axis names it: `UTC+07:00`.
pub(crate) fn zone_label() -> String {
    format!("UTC{}", Local::now().format("%:z"))
}

pub(crate) fn guest_ns(anchor: Option<HostClockAnchor>, value: Option<u64>) -> String {
    anchor
        .zip(value)
        .and_then(|(anchor, ns)| anchor.host_us(ns))
        .map(|value| format!("~{}", short_time_us(value)))
        .unwrap_or_else(|| "Unavailable".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn guest_clock_handles_events_before_anchor_and_missing_history() {
        let clock = HostClockAnchor {
            guest_ns: 2_000_000,
            host_us: 1_700_000_000_000_000,
        };
        assert_eq!(clock.host_us(1_000_000), Some(1_699_999_999_999_000));
        assert_eq!(guest_ns(None, Some(2)), "Unavailable");
        assert!(guest_ns(Some(clock), Some(1_000_000)).contains("UTC"));
        assert!(guest_ns(Some(clock), Some(1_000_000)).starts_with('~'));
        assert_eq!(
            HostClockAnchor {
                guest_ns: 2_000_000,
                host_us: 0
            }
            .host_us(0),
            None
        );
        assert_eq!(unix_ms(Some(u64::MAX)), "Unavailable");
    }

    #[test]
    fn local_seconds_append_a_compact_utc_offset() {
        let at = |minutes: i32| {
            local_seconds_at(1_700_000_000, |time| {
                time.with_timezone(&FixedOffset::east_opt(minutes * 60).unwrap())
            })
        };
        assert_eq!(at(420), "2023-11-15 05:13:20 (UTC+7)");
        assert_eq!(at(330), "2023-11-15 03:43:20 (UTC+5:30)");
        assert_eq!(at(0), "2023-11-14 22:13:20 (UTC+0)");
        assert_eq!(at(-180), "2023-11-14 19:13:20 (UTC-3)");
    }
}
