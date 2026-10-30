// SPDX-License-Identifier: GPL-3.0-only
//! The bounds a category can meet, said plainly: the time a tool may run, and
//! the sentences that name which bound cut a result short.
use super::*;
use std::cell::Cell;

/// Most bounds one category reports.
const LIMIT_MAX_COUNT: usize = 8;

thread_local! {
    /// Seconds the run allows each tool; 0 leaves every tool its own limit.
    static TIME_LIMIT: Cell<u64> = const { Cell::new(0) };
}

/// Take the run's time limit (`report.time_limit_seconds`) for the checks
/// that follow on this thread.
pub(super) fn set_time_limit(seconds: Option<u64>) {
    TIME_LIMIT.set(seconds.unwrap_or(0));
}

/// Seconds a tool whose own limit is `default` may run.
pub(super) fn seconds(default: u64) -> u64 {
    match TIME_LIMIT.get() {
        0 => default,
        limit => limit,
    }
}

/// `seconds` for a report that has not been through [`set_time_limit`]: the
/// host sizes its own deadlines from the report alone.
pub(super) fn seconds_in(report: &AnalysisReport, default: u64) -> u64 {
    report
        .time_limit_seconds
        .filter(|&s| s > 0)
        .unwrap_or(default)
}

/// "4 minutes", "90 seconds" or "1 minute 30 seconds".
pub(crate) fn duration_text(seconds: u64) -> String {
    let (minutes, rest) = (seconds / 60, seconds % 60);
    let plural =
        |count: u64, unit: &str| format!("{count} {unit}{}", if count == 1 { "" } else { "s" });
    match (minutes, rest) {
        (0, rest) => plural(rest, "second"),
        (minutes, 0) => plural(minutes, "minute"),
        (minutes, rest) => format!("{} {}", plural(minutes, "minute"), plural(rest, "second")),
    }
}

/// The bounds of a check that no setting changes, said for Settings > Analysis
/// and for the warning that names one of them.
pub fn fixed_limits_text() -> String {
    format!(
        "Fixed bounds: a check keeps its first {} rows in the report (the whole list stays in its listing, up to {}); a local tool's output is read up to {}; one value is kept up to {}.",
        super::detection::group_digits(super::worker::ENTRY_MAX_COUNT as u64),
        crate::byte_size::short_size(super::listing::LISTING_MAX_SIZE),
        crate::byte_size::short_size(super::worker::TOOL_OUTPUT_MAX_SIZE as u64),
        crate::byte_size::short_size(super::bounds::VALUE_MAX_SIZE as u64),
    )
}

/// Note a bound `section` met. The same sentence is kept once.
pub(super) fn add(
    section: &mut AnalysisSection,
    kind: AnalysisLimitKind,
    text: impl Into<String>,
    seconds: Option<u64>,
) {
    let text = text.into();
    if section.limits.len() < LIMIT_MAX_COUNT && !section.limits.iter().any(|l| l.text == text) {
        section.limits.push(AnalysisLimit {
            kind,
            text,
            seconds,
        });
    }
}

/// `tool` was stopped after `seconds`. The section is `Timeout` (what the tool
/// had found by then stays in it) and `summary` says what that means.
pub(super) fn time_out(
    section: &mut AnalysisSection,
    tool: &str,
    seconds: u64,
    summary: impl Into<String>,
) {
    section.state = AnalysisSectionState::Timeout;
    section.summary = summary.into();
    add(
        section,
        AnalysisLimitKind::Time,
        format!(
            "{tool} ran out of time: its limit was {}.",
            duration_text(seconds)
        ),
        Some(seconds),
    );
}

/// The worker reached its overall deadline: the check that was running is
/// stopped, out of time, and says so.
pub(super) fn stop_running(report: &mut AnalysisReport, overall: std::time::Duration) {
    for section in &mut report.sections {
        if section.state == AnalysisSectionState::Running {
            section.state = AnalysisSectionState::Timeout;
            section.summary =
                "This check was running when the analysis reached its overall time limit and was stopped.".into();
            add(
                section,
                AnalysisLimitKind::Time,
                format!(
                    "The analysis as a whole ran out of time: its limit was {}.",
                    duration_text(overall.as_secs())
                ),
                None,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_read_as_minutes_and_seconds() {
        assert_eq!(duration_text(240), "4 minutes");
        assert_eq!(duration_text(60), "1 minute");
        assert_eq!(duration_text(90), "1 minute 30 seconds");
        assert_eq!(duration_text(1), "1 second");
    }

    #[test]
    fn a_run_limit_replaces_every_tools_own() {
        set_time_limit(None);
        assert_eq!(seconds(240), 240);
        set_time_limit(Some(600));
        assert_eq!(seconds(240), 600);
        assert_eq!(seconds(60), 600);
        set_time_limit(None);
    }

    #[test]
    fn a_timeout_is_its_own_state_with_the_limit_that_was_hit() {
        let mut section = AnalysisSection::new(AnalysisKind::Capabilities);
        time_out(
            &mut section,
            "capa",
            240,
            "capa found nothing before it was stopped",
        );
        time_out(&mut section, "capa", 240, "again");
        assert_eq!(section.state, AnalysisSectionState::Timeout);
        assert_eq!(section.limits.len(), 1);
        assert_eq!(section.limits[0].kind, AnalysisLimitKind::Time);
        assert_eq!(section.limits[0].seconds, Some(240));
        assert!(section.limits[0].text.contains("4 minutes"));
    }

    #[test]
    fn reports_saved_before_timeouts_and_limits_still_load() {
        let old = r#"{"kind":"capabilities","state":"unavailable","summary":"capa ran out of time","entries":[]}"#;
        let section: AnalysisSection = serde_json::from_str(old).unwrap();
        assert_eq!(section.state, AnalysisSectionState::Unavailable);
        assert!(section.limits.is_empty());
        let saved = serde_json::to_string(&section).unwrap();
        assert!(!saved.contains("limits"));
        let new = r#"{"kind":"capabilities","state":"timeout","summary":"","entries":[],"limits":[{"kind":"time","text":"x","seconds":240}]}"#;
        let section: AnalysisSection = serde_json::from_str(new).unwrap();
        assert_eq!(section.state, AnalysisSectionState::Timeout);
        assert_eq!(section.limits[0].seconds, Some(240));
    }
}
