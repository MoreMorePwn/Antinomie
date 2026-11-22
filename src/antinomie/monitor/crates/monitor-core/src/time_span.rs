// SPDX-License-Identifier: GPL-3.0-only
//! Run-relative times and spans in their largest useful unit: `+0.281 s`,
//! `+42.1 s`, `+3 min 05 s`, `+1 h 02 min`. One place for every screen and
//! export, so a long run never shows only a count of seconds.

/// Nanoseconds as a span: under a second `0.281 s` (or `281 ms` with
/// `milliseconds`), under a minute `42.1 s`, under an hour `3 min 05 s`, then
/// `1 h 02 min`. Cut, never rounded up into the next unit.
pub fn span_ns(ns: u64, milliseconds: bool) -> String {
    let ms = ns / 1_000_000;
    if ms < 1_000 {
        return if milliseconds {
            format!("{ms} ms")
        } else {
            format!("0.{ms:03} s")
        };
    }
    let seconds = ns / 1_000_000_000;
    match seconds {
        0..=59 => {
            let tenths = ns / 100_000_000;
            format!("{}.{} s", tenths / 10, tenths % 10)
        }
        60..=3599 => format!("{} min {:02} s", seconds / 60, seconds % 60),
        _ => format!("{} h {:02} min", seconds / 3600, seconds / 60 % 60),
    }
}

/// [`span_ns`] after a plus sign: where something happened from the start of
/// the run. Under a second it is `+0.281 s`.
pub fn relative_ns(ns: u64) -> String {
    format!("+{}", span_ns(ns, false))
}

/// [`relative_ns`] with milliseconds under a second: `+340 ms`.
pub fn relative_ns_ms(ns: u64) -> String {
    format!("+{}", span_ns(ns, true))
}

/// The exact value for a tooltip, to the microsecond: `+176.699883 s`.
pub fn exact_ns(ns: u64) -> String {
    format!(
        "+{}.{:06} s",
        ns / 1_000_000_000,
        ns % 1_000_000_000 / 1_000
    )
}

/// A span that keeps its milliseconds at every size, for a table that must
/// stay exact: `42.123 s`, `3 min 05.123 s`, `49 h 05 min 00.883 s`.
pub fn precise_ns(ns: u64) -> String {
    let ms = ns / 1_000_000;
    let (seconds, rest) = (ms / 1000, ms % 1000);
    match seconds {
        0..=59 => format!("{seconds}.{rest:03} s"),
        60..=3599 => format!("{} min {:02}.{rest:03} s", seconds / 60, seconds % 60),
        _ => format!(
            "{} h {:02} min {:02}.{rest:03} s",
            seconds / 3600,
            seconds / 60 % 60,
            seconds % 60
        ),
    }
}

/// [`precise_ns`] after a plus sign, from milliseconds: a document's
/// `+5.463 s`, `+3 min 05.463 s`.
pub fn relative_precise_ms(ms: u64) -> String {
    format!("+{}", precise_ns(ms.saturating_mul(1_000_000)))
}

/// Whole seconds as `42 s`, `3 min 05 s`, `1 h 02 min`.
pub fn seconds(seconds: u64) -> String {
    match seconds {
        0..=59 => format!("{seconds} s"),
        60..=3599 => format!("{} min {:02} s", seconds / 60, seconds % 60),
        _ => format!("{} h {:02} min", seconds / 3600, seconds / 60 % 60),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000_000;

    #[test]
    fn a_span_moves_to_minutes_at_sixty_seconds_and_to_hours_at_an_hour() {
        assert_eq!(relative_ns(281_000_000), "+0.281 s");
        assert_eq!(relative_ns_ms(340_000_000), "+340 ms");
        assert_eq!(relative_ns(42 * S + 130_000_000), "+42.1 s");
        // Cut, not rounded: 59.96 s is not "60.0 s".
        assert_eq!(relative_ns(59 * S + 960_000_000), "+59.9 s");
        assert_eq!(relative_ns(60 * S), "+1 min 00 s");
        assert_eq!(relative_ns(185 * S), "+3 min 05 s");
        assert_eq!(relative_ns(3599 * S), "+59 min 59 s");
        assert_eq!(relative_ns(3600 * S), "+1 h 00 min");
        assert_eq!(relative_ns(3725 * S), "+1 h 02 min");
        assert_eq!(relative_ns_ms(3725 * S), "+1 h 02 min");
    }

    #[test]
    fn the_exact_and_precise_forms_keep_the_milliseconds() {
        assert_eq!(exact_ns(176_699_883_001_000), "+176699.883001 s");
        assert_eq!(precise_ns(59 * S + 900_000_000), "59.900 s");
        assert_eq!(precise_ns(60 * S), "1 min 00.000 s");
        assert_eq!(precise_ns(176_699_883_000_000), "49 h 04 min 59.883 s");
        assert_eq!(relative_precise_ms(5_463), "+5.463 s");
        assert_eq!(relative_precise_ms(185_463), "+3 min 05.463 s");
    }

    #[test]
    fn whole_seconds_use_the_same_boundaries() {
        assert_eq!(seconds(59), "59 s");
        assert_eq!(seconds(60), "1 min 00 s");
        assert_eq!(seconds(3599), "59 min 59 s");
        assert_eq!(seconds(3600), "1 h 00 min");
    }
}
