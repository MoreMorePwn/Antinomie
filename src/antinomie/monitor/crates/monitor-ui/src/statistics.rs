// SPDX-License-Identifier: GPL-3.0-only
//! The Statistics window (ANT-T0477): the numbers behind one recorded run or
//! Capture all recording, modelled on Wireshark's Statistics menu. It floats
//! over the main window and pops out into its own window, as the Activity
//! graph does. The counting is `antinomie_triage::statistics`; this module is
//! the window, the worker thread that runs the walk, and the click-through
//! into the Syscall Trace.
//!
//! The tabs are drawn by [`StatisticsWindow::tab_body`]; a new tab is a new
//! [`Tab`] variant, its module and one arm there.
use antinomie_monitor_core::syscall_groups::SyscallGroup;
use std::path::{Path, PathBuf};

mod hierarchy;
mod latency;
mod navigate;
mod properties;
mod rate;
mod rate_lines;
mod rate_paint;
mod toolbar;
mod window;
mod worker;

pub(crate) use navigate::Navigate;
pub(crate) use properties::Facts;
pub(crate) use window::{StatisticsWindow, DEFAULT_SIZE};

#[cfg(test)]
mod tests;

/// The tabs of the window.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) enum Tab {
    #[default]
    Properties,
    Hierarchy,
    CallRate,
    Latency,
}

impl Tab {
    pub(crate) const ALL: [Self; 4] = [
        Self::Properties,
        Self::Hierarchy,
        Self::CallRate,
        Self::Latency,
    ];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Properties => "Properties",
            Self::Hierarchy => "Hierarchy",
            Self::CallRate => "Call rate",
            Self::Latency => "Latency",
        }
    }

    pub(crate) fn hint(self) -> &'static str {
        match self {
            Self::Properties => {
                "What the run was, what the recording holds and how far it can be trusted"
            }
            Self::Hierarchy => "Calls by group, call and result, with the failures",
            Self::CallRate => "Calls per interval over the run, with up to four lines",
            Self::Latency => "How long calls took, and the slowest ones",
        }
    }
}

/// What a tab asks the window to do.
#[derive(Clone, Debug, PartialEq)]
enum Pick {
    /// Open the calls behind a number.
    Count(hierarchy::Click),
    /// Open exactly this call.
    Call((u64, u64, u64)),
}

/// How times are written (design 7).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum TimeBase {
    /// 0 is the first call in the view.
    #[default]
    RunTime,
    /// Guest monotonic seconds since its boot: what `event.time_ns` uses.
    Guest,
    /// Local time through the run's clock anchor; an estimate.
    Host,
}

impl TimeBase {
    pub(crate) const ALL: [Self; 3] = [Self::RunTime, Self::Guest, Self::Host];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::RunTime => "Run time",
            Self::Guest => "Guest clock",
            Self::Host => "Host time ≈",
        }
    }

    /// The word the JSON export names it with.
    pub(crate) fn export_name(self) -> &'static str {
        match self {
            Self::RunTime => "since start",
            Self::Guest => "guest",
            Self::Host => "host clock",
        }
    }
}

/// The run or capture the window shows, as the app describes it.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Target {
    /// Run or capture id: the window follows it.
    pub id: String,
    /// "run 4c1e9a72" or "capture 9b02d4e1".
    pub label: String,
    pub vm: String,
    pub boot: String,
    pub directory: PathBuf,
    pub capture: bool,
    pub root_cookie: u64,
    /// The run is still recording.
    pub live: bool,
    pub facts: Facts,
}

/// What the app tells the window each frame.
pub(crate) struct AppView<'a> {
    pub target: Option<Target>,
    /// The Trace's applied filter, for Use Trace filter.
    pub trace_filter: &'a str,
    /// Categories the Trace hides.
    pub hidden: &'a [SyscallGroup],
    /// Where exports go (`<data>/exports/statistics`).
    pub data_dir: &'a Path,
}

/// The question "X is hidden in the Syscall Trace. Show it there and open these calls?"
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Question {
    pub group: SyscallGroup,
    pub filter: String,
}

/// 1234567 as `1,234,567`.
pub(crate) fn int(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// A large count short: `2.1 M`.
pub(crate) fn count_short(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1} M", n as f64 / 1e6)
    } else {
        int(n)
    }
}

/// A duration with its unit: `830 ns`, `12.4 µs`, `3.20 ms`, `4.1 s`, `2 min 5 s`.
pub(crate) fn duration_ns(ns: u64) -> String {
    match ns {
        0..=999 => format!("{ns} ns"),
        1_000..=999_999 => format!("{:.1} µs", ns as f64 / 1e3),
        1_000_000..=999_999_999 => format!("{:.2} ms", ns as f64 / 1e6),
        1_000_000_000..=59_999_999_999 => format!("{:.2} s", ns as f64 / 1e9),
        _ => {
            let seconds = ns / 1_000_000_000;
            if seconds >= 3600 {
                format!("{} h {} min", seconds / 3600, seconds % 3600 / 60)
            } else {
                format!("{} min {} s", seconds / 60, seconds % 60)
            }
        }
    }
}

/// `+m:ss.mmm` from a start.
pub(crate) fn run_time(ns: u64) -> String {
    let millis = ns / 1_000_000;
    format!(
        "+{}:{:02}.{:03}",
        millis / 60_000,
        millis / 1000 % 60,
        millis % 1000
    )
}

/// A guest timestamp in the chosen base. `first_ns` is the origin of Run time.
pub(crate) fn time_text(
    base: TimeBase,
    ns: u64,
    first_ns: Option<u64>,
    anchor: Option<antinomie_monitor_core::api::HostClockAnchor>,
) -> String {
    match base {
        TimeBase::RunTime => run_time(ns.saturating_sub(first_ns.unwrap_or(0))),
        TimeBase::Guest => format!("{:.3} s", ns as f64 / 1e9),
        TimeBase::Host => match anchor.and_then(|anchor| anchor.host_us(ns)) {
            Some(us) => format!("≈ {}", crate::time_format::local_seconds(us / 1_000_000)),
            None => format!("{:.3} s (no host clock for this run)", ns as f64 / 1e9),
        },
    }
}
