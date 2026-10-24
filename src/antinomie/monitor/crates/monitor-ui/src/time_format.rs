// SPDX-License-Identifier: GPL-3.0-only
//! Host wall-clock presentation shared by histories and triage.
use antinomie_monitor_core::HostClockAnchor;
use chrono::{DateTime, FixedOffset, Local, Utc};

pub(crate) fn unix_us(value: u64) -> String {
    i64::try_from(value)
        .ok()
        .and_then(DateTime::<Utc>::from_timestamp_micros)
        .map(|time| {
            time.with_timezone(&Local)
                .format("%Y-%m-%d %H:%M:%S%.3f (UTC%:z)")
                .to_string()
        })
        .unwrap_or_else(|| "Unavailable".into())
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
            let offset = time.offset().local_minus_utc();
            let (sign, minutes) = (if offset < 0 { '-' } else { '+' }, offset.abs() / 60);
            let zone = if minutes % 60 == 0 {
                format!("{sign}{}", minutes / 60)
            } else {
                format!("{sign}{}:{:02}", minutes / 60, minutes % 60)
            };
            format!("{} (UTC{zone})", time.format("%Y-%m-%d %H:%M:%S"))
        })
        .unwrap_or_else(|| "Unavailable".into())
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
                .format("%H:%M:%S%.3f (UTC%:z)")
                .to_string()
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
