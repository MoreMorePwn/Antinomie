// SPDX-License-Identifier: GPL-3.0-only
//! The bounds a category can meet, said plainly: the time a tool may run, the
//! sizes and counts the person may raise in Settings, and the sentences that
//! name which bound cut a result short.
use super::*;
use serde::{Deserialize, Serialize};
use std::cell::Cell;

/// Most bounds one category reports.
const LIMIT_MAX_COUNT: usize = 8;

thread_local! {
    /// Seconds the run allows each tool; 0 leaves every tool its own limit.
    static TIME_LIMIT: Cell<u64> = const { Cell::new(0) };
    /// The sizes and counts the report being made was asked for.
    static ACTIVE: Cell<AnalysisLimits> = const { Cell::new(AnalysisLimits::DEFAULT) };
}

/// Which setting raises a bound. A warning that names one leads to its field
/// in Settings > Analysis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitSetting {
    /// Rows a check keeps in the report (and signatures binwalk lists).
    Rows,
    /// The size of one check's listing.
    Listing,
    /// Bytes of one value or string kept in a row.
    Value,
    /// Bytes read from a local tool's output (binwalk reads four times this).
    ToolOutput,
    /// Bytes read from capa's and FLOSS's output.
    LargeOutput,
    /// Strings FLOSS may list.
    FlossStrings,
    /// The largest file FLOSS is given.
    FlossFile,
}

/// One setting as Settings shows it.
#[derive(Clone, Copy, Debug)]
pub struct LimitField {
    pub setting: LimitSetting,
    pub label: &'static str,
    /// What the number counts: "rows", "MiB", "bytes", "strings".
    pub unit: &'static str,
    pub default: u32,
    pub min: u32,
    pub max: u32,
    pub help: &'static str,
}

/// Every setting, in the order Settings lists them.
pub const LIMIT_FIELDS: [LimitField; 7] = [
    LimitField {
        setting: LimitSetting::Rows,
        label: "Rows per check",
        unit: "rows",
        default: 2048,
        min: 256,
        max: 8192,
        help: "Rows a check keeps in its report (and signatures binwalk lists). A check with a listing holds every row there; the report shows the first ones. The report itself grows with this number.",
    },
    LimitField {
        setting: LimitSetting::Listing,
        label: "Listing size per check",
        unit: "MiB",
        default: 64,
        min: 16,
        max: 512,
        help: "Largest listing one check may write (strings, disassembly, decompilation, FLOSS strings). All the listings of a report may take twice this, at least 128 MiB, of disk.",
    },
    LimitField {
        setting: LimitSetting::Value,
        label: "Text kept per value",
        unit: "bytes",
        default: 4096,
        min: 1024,
        max: 16384,
        help: "Bytes of one string or value kept in a row; a longer one keeps only its start.",
    },
    LimitField {
        setting: LimitSetting::ToolOutput,
        label: "Local tool output",
        unit: "MiB",
        default: 1,
        min: 1,
        max: 16,
        help: "Bytes read from a local tool's output (binwalk reads four times this).",
    },
    LimitField {
        setting: LimitSetting::LargeOutput,
        label: "capa and FLOSS output",
        unit: "MiB",
        default: 32,
        min: 32,
        max: 256,
        help: "Bytes read from capa's and FLOSS's output. A bigger result needs more memory.",
    },
    LimitField {
        setting: LimitSetting::FlossStrings,
        label: "FLOSS strings listed",
        unit: "strings",
        default: 50_000,
        min: 10_000,
        max: 500_000,
        help: "Strings the FLOSS listing keeps when the tool finds more.",
    },
    LimitField {
        setting: LimitSetting::FlossFile,
        label: "Largest file for FLOSS",
        unit: "MiB",
        default: 16,
        min: 16,
        max: 64,
        help: "FLOSS is not given a file bigger than this. It needs more time and memory on a big one.",
    },
];

/// The sizes and counts of one analysis. A report records the ones it was
/// made with; a field missing from a saved report is its default.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AnalysisLimits {
    pub rows: u32,
    pub listing_mib: u32,
    pub value_bytes: u32,
    pub tool_output_mib: u32,
    pub large_output_mib: u32,
    pub floss_strings: u32,
    pub floss_file_mib: u32,
}

impl Default for AnalysisLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl AnalysisLimits {
    pub const DEFAULT: Self = Self {
        rows: 2048,
        listing_mib: 64,
        value_bytes: 4096,
        tool_output_mib: 1,
        large_output_mib: 32,
        floss_strings: 50_000,
        floss_file_mib: 16,
    };

    /// The value of one setting.
    pub fn get(&self, setting: LimitSetting) -> u32 {
        match setting {
            LimitSetting::Rows => self.rows,
            LimitSetting::Listing => self.listing_mib,
            LimitSetting::Value => self.value_bytes,
            LimitSetting::ToolOutput => self.tool_output_mib,
            LimitSetting::LargeOutput => self.large_output_mib,
            LimitSetting::FlossStrings => self.floss_strings,
            LimitSetting::FlossFile => self.floss_file_mib,
        }
    }

    /// Set one setting, kept within its range.
    pub fn set(&mut self, setting: LimitSetting, value: u32) {
        let field = LIMIT_FIELDS
            .iter()
            .find(|field| field.setting == setting)
            .expect("every setting is listed");
        let value = value.clamp(field.min, field.max);
        match setting {
            LimitSetting::Rows => self.rows = value,
            LimitSetting::Listing => self.listing_mib = value,
            LimitSetting::Value => self.value_bytes = value,
            LimitSetting::ToolOutput => self.tool_output_mib = value,
            LimitSetting::LargeOutput => self.large_output_mib = value,
            LimitSetting::FlossStrings => self.floss_strings = value,
            LimitSetting::FlossFile => self.floss_file_mib = value,
        }
    }

    /// Every setting within its range (a value from a hand-edited file).
    pub fn clamped(mut self) -> Self {
        for field in &LIMIT_FIELDS {
            self.set(field.setting, self.get(field.setting));
        }
        self
    }

    pub fn is_default(&self) -> bool {
        *self == Self::DEFAULT
    }

    /// `None` for the defaults, so a report made with them stays as it was.
    pub fn for_report(self) -> Option<Self> {
        let limits = self.clamped();
        (!limits.is_default()).then_some(limits)
    }

    /// Bytes of disk all the listings of one report may take.
    pub fn listings_total(&self) -> u64 {
        (u64::from(self.listing_mib) * 2).max(128) << 20
    }

    /// The report size the worker aims for: 128 KiB at the default row count,
    /// growing with it.
    pub fn report_target(&self) -> usize {
        (128 * 1024 * self.rows.max(1) as usize / 2048).clamp(128 * 1024, REPORT_CEILING)
    }
}

/// Largest report the host accepts, whatever the settings: 128 KiB at 2,048
/// rows, scaled to the most rows a setting allows.
pub(crate) const REPORT_CEILING: usize = 512 * 1024;
/// Largest listing the host accepts, whatever the settings.
pub(crate) const LISTING_CEILING: u64 = 512 << 20;
/// Most rows a report may hold, whatever the settings.
pub(crate) const ROWS_CEILING: usize = 8192;
/// Longest value the host accepts in a row, whatever the settings.
pub(crate) const VALUE_CEILING: usize = 16384;

/// Take the sizes and counts of the report being made for the checks that
/// follow on this thread.
pub(super) fn set_limits(limits: Option<AnalysisLimits>) {
    ACTIVE.set(limits.unwrap_or_default().clamped());
}

pub(super) fn active() -> AnalysisLimits {
    ACTIVE.get()
}

/// Rows a check keeps in its report.
pub(super) fn rows() -> usize {
    active().rows as usize
}

/// Largest listing one check may write, in octets.
pub(super) fn listing_bytes() -> u64 {
    u64::from(active().listing_mib) << 20
}

/// Bytes of one value kept in a row.
pub(super) fn value_bytes() -> usize {
    active().value_bytes as usize
}

/// Bytes read from a local tool's output.
pub(super) fn tool_output() -> usize {
    (active().tool_output_mib as usize) << 20
}

/// Bytes read from capa's and FLOSS's output.
pub(super) fn large_output() -> usize {
    (active().large_output_mib as usize) << 20
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

/// The bounds of a check that no setting changes, said for Settings > Analysis.
pub fn fixed_limits_text() -> String {
    format!(
        "Fixed bounds: a report keeps at most {} limit notes per check; Strings keeps its first {} strings in the report (the listing holds all of them); an unpacked layer is read up to {} and at most {} levels deep.",
        LIMIT_MAX_COUNT,
        super::strings::REPORT_STRINGS,
        crate::byte_size::short_size(super::unpack::LAYER_MAX_SIZE),
        super::unpack::LAYER_MAX_COUNT,
    )
}

/// Note a bound `section` met. The same sentence is kept once.
pub(super) fn add(
    section: &mut AnalysisSection,
    kind: AnalysisLimitKind,
    text: impl Into<String>,
    seconds: Option<u64>,
) {
    push(section, kind, text.into(), seconds, None);
}

/// [`add`] for a bound a setting raises.
pub(super) fn add_for(
    section: &mut AnalysisSection,
    kind: AnalysisLimitKind,
    setting: LimitSetting,
    text: impl Into<String>,
) {
    push(section, kind, text.into(), None, Some(setting));
}

fn push(
    section: &mut AnalysisSection,
    kind: AnalysisLimitKind,
    text: String,
    seconds: Option<u64>,
    setting: Option<LimitSetting>,
) {
    if section.limits.len() < LIMIT_MAX_COUNT && !section.limits.iter().any(|l| l.text == text) {
        section.limits.push(AnalysisLimit {
            kind,
            text,
            seconds,
            setting,
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
    fn every_setting_has_a_field_inside_its_range_and_the_defaults_match() {
        let defaults = AnalysisLimits::default();
        for field in &LIMIT_FIELDS {
            assert!(field.min <= field.default && field.default <= field.max);
            assert_eq!(defaults.get(field.setting), field.default);
            let mut limits = defaults;
            limits.set(field.setting, u32::MAX);
            assert_eq!(limits.get(field.setting), field.max);
            limits.set(field.setting, 0);
            assert_eq!(limits.get(field.setting), field.min);
        }
        assert!(defaults.is_default() && defaults.for_report().is_none());
        assert_eq!(defaults.report_target(), 128 * 1024);
        assert_eq!(defaults.listings_total(), 128 << 20);
        let mut most = defaults;
        most.set(LimitSetting::Rows, u32::MAX);
        most.set(LimitSetting::Listing, u32::MAX);
        assert_eq!(most.report_target(), REPORT_CEILING);
        assert!(most.listings_total() <= 1024 << 20);
        assert_eq!(most.rows as usize, ROWS_CEILING);
        assert!(u64::from(most.listing_mib) << 20 <= LISTING_CEILING);
        assert!(most.value_bytes as usize <= VALUE_CEILING);
    }

    #[test]
    fn a_saved_selection_or_report_without_limits_reads_as_the_defaults() {
        let selection: AnalysisSelection = serde_json::from_str(r#"{"enabled":true}"#).unwrap();
        assert!(selection.limits.is_default());
        let out_of_range: AnalysisSelection =
            serde_json::from_str(r#"{"limits":{"rows":1,"listing_mib":9999}}"#).unwrap();
        assert_eq!(out_of_range.limits.rows, 256);
        assert_eq!(out_of_range.limits.listing_mib, 512);
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
