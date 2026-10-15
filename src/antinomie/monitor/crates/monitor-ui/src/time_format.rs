// SPDX-License-Identifier: MIT
//! Host wall-clock presentation shared by histories and triage.
use antinomie_monitor_core::HostClockAnchor;
use chrono::{DateTime, Local, Utc};

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
}
