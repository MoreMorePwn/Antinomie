// SPDX-License-Identifier: GPL-3.0-only
//! The counting engine of the Statistics window (ANT-T0477, design 4).
//!
//! One walk through the recording, the same read the Syscall Trace's "page N of
//! M" count makes (`Recording::matching_totals_cancellable`), counts every call
//! that passes the run's scope and the window's filter into bounded tables:
//! the group, call and result hierarchy, per-call latency, calls per interval
//! and the processes and threads seen. The memory the counts take does not grow
//! with the number of calls. UI-free: the desktop window calls it in 0.9.0, the
//! command line and the query API may in 0.9.1.
//!
//! **The count equals the Trace's.** For any filter, `calls + out_of_scope` is
//! the number of calls `matching_totals_cancellable` accepts with that filter's
//! `Compiled::keep` (no hidden category, no selected process). `out_of_scope`
//! counts the calls of another launched program that pass the filter and are
//! left out, as Triage leaves them out.
use crate::query::{self, Compiled};
use crate::trace;
use antinomie_monitor_core::recording::{self, Recording, RecordingError};
use antinomie_monitor_core::{capture, InvocationSummary};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub mod aggregate;
pub mod blocking;
pub mod export;
#[cfg(any(test, feature = "test-support"))]
pub mod fixture;
pub mod latency;
pub mod quality;
pub mod rate;
pub mod views;

#[cfg(test)]
mod bench;
#[cfg(test)]
mod tests;

use aggregate::{Aggregator, Capped, GroupRow};
use latency::{LatencyRow, SlowCall};
use quality::Quality;
use rate::{Peak, Rate};

/// The `schema` of every JSON the engine and its exports write.
pub const SCHEMA: &str = "antinomie.statistics/1";
/// Most custom Call rate lines a request may carry.
pub const MAX_LINES: usize = 3;
/// Most issues kept from the walk.
pub const MAX_ISSUES: usize = 32;
/// Calls between two checks of the clock.
const CHECK_EVERY: u64 = 4096;
/// Time between two partial results.
const PARTIAL_EVERY: Duration = Duration::from_secs(2);

/// What to count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Parts {
    /// Everything: hierarchy, latency, rate bins of the base series, processes.
    All,
    /// Only the rate bins of the custom lines (one more walk for a custom line).
    RateOnly,
}

#[derive(Clone, Debug)]
pub struct StatsRequest {
    /// The run or capture folder.
    pub directory: PathBuf,
    /// Open it as a Capture all recording.
    pub capture: bool,
    /// The run's root task cookie; 0 for a capture (every task).
    pub root_cookie: u64,
    /// The window's filter, in the Trace's language; empty for every call.
    pub filter: String,
    /// 0..=`MAX_LINES` custom Call rate filters, each added to `filter`.
    pub lines: Vec<String>,
    pub parts: Parts,
}

impl StatsRequest {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            capture: false,
            root_cookie: 0,
            filter: String::new(),
            lines: Vec::new(),
            parts: Parts::All,
        }
    }
}

/// How far the walk is. Sent from the walking thread.
#[derive(Clone, Debug)]
pub enum Progress {
    /// Building or extending the packet index: bytes done of bytes in all.
    Indexing { done: u64, total: u64 },
    /// Calls read of calls in the recording.
    Reading { read: u64, total: u64 },
    /// The counts so far, about every 2 s.
    Partial(Box<RunStatistics>),
}

/// The archive a result was read from: valid while the recording still has this
/// identity and length.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stamp {
    pub identity: String,
    pub length: u64,
}

/// Why no result could be made. `Display` is the text the window shows
/// (design 10).
#[derive(Debug)]
pub enum StatsError {
    /// There is no `telemetry.raw`: the run failed before recording.
    NoTelemetry,
    /// The filter or a line does not compile; the parser's message.
    InvalidFilter(String),
    TooManyLines,
    /// The recording was replaced or shrunk while it was read.
    Changed,
    /// Stopped before anything was read.
    Cancelled,
    /// The core error text.
    Unreadable(String),
}

impl std::fmt::Display for StatsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoTelemetry => f.write_str(
                "This run saved no telemetry: it failed before recording. Its launch record is in Run History.",
            ),
            Self::InvalidFilter(message) => f.write_str(message),
            Self::TooManyLines => write!(f, "At most {MAX_LINES} extra lines."),
            Self::Changed => f.write_str("The recording changed while it was read."),
            Self::Cancelled => f.write_str("Stopped."),
            Self::Unreadable(message) => write!(f, "{message}. The Syscall Trace may show more about it."),
        }
    }
}

impl std::error::Error for StatsError {}

/// The result of a walk (design 4.2, Appendix A).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RunStatistics {
    pub schema: String,
    /// The archive prefix read; `None` in a partial or stopped result.
    pub stamp: Option<Stamp>,
    pub filter: String,
    /// `false` when stopped or cancelled: the numbers cover the calls read so far.
    pub complete: bool,
    /// Calls in the view (scope and filter).
    pub calls: u64,
    /// Calls read, before scope and filter.
    pub read: u64,
    /// Calls that pass the filter but belong to another launched program.
    pub out_of_scope: u64,
    pub first_ns: Option<u64>,
    pub last_ns: Option<u64>,
    pub processes: Capped,
    pub threads: Capped,
    /// Some call had no process id (a recording saved before 0.3.0).
    pub pid_not_recorded: bool,
    /// Calls with no result recorded, and of those the ones that ended their task.
    pub no_result: u64,
    pub ended_task: u64,
    /// Calls without both an entry and an exit: no duration.
    pub not_timed: u64,
    /// Calls whose name was past the 1,024 kept (counted in their group).
    pub other_names: u64,
    pub hierarchy: Vec<GroupRow>,
    pub latency: Vec<LatencyRow>,
    /// Timed calls of names past the kept ones.
    pub latency_other: u64,
    /// The 20 slowest calls that do not wait by design, and the 20 longest waits.
    pub slowest: Vec<SlowCall>,
    pub longest_waits: Vec<SlowCall>,
    pub rate: Rate,
    pub peak_per_s: Option<Peak>,
    pub quality: Quality,
    /// At most `MAX_ISSUES`, as the page reads keep them.
    pub issues: Vec<String>,
}

impl RunStatistics {
    fn from_counts(request: &StatsRequest, counts: aggregate::Counts, state: &Walk) -> Self {
        Self {
            schema: SCHEMA.to_owned(),
            stamp: None,
            filter: request.filter.clone(),
            complete: false,
            calls: counts.calls,
            read: state.read,
            out_of_scope: state.out_of_scope,
            first_ns: counts.first_ns,
            last_ns: counts.last_ns,
            processes: counts.processes,
            threads: counts.threads,
            pid_not_recorded: counts.pid_not_recorded,
            no_result: counts.no_result,
            ended_task: counts.ended_task,
            not_timed: counts.not_timed,
            other_names: counts.other_names,
            hierarchy: counts.hierarchy,
            latency: counts.latency,
            latency_other: counts.latency_other,
            slowest: counts.slowest,
            longest_waits: counts.longest_waits,
            rate: counts.rate,
            peak_per_s: counts.peak,
            quality: state.quality.clone(),
            issues: Vec::new(),
        }
    }
}

/// What the walk keeps besides the aggregator.
struct Walk {
    read: u64,
    out_of_scope: u64,
    quality: Quality,
}

/// The calls of the root being counted, or of every task when there is none
/// (the rule of Triage's `archive_scan::stages::in_scope`).
pub fn in_scope(root_cookie: u64, call: &InvocationSummary) -> bool {
    root_cookie == 0
        || trace::representative(call)
            .or(call.task_exit.as_ref())
            .is_some_and(|event| event.root_task_cookie == root_cookie)
}

fn compile(filter: &str, what: &str) -> Result<Compiled, StatsError> {
    let compiled = query::compile_note(filter);
    match compiled.error {
        Some(error) if what.is_empty() => Err(StatsError::InvalidFilter(error)),
        Some(error) => Err(StatsError::InvalidFilter(format!("{what}: {error}"))),
        None => Ok(compiled),
    }
}

fn open(request: &StatsRequest, cancel: &AtomicBool) -> Result<Recording, RecordingError> {
    if request.capture {
        capture::open_capture_recording_cancellable(&request.directory, cancel)
    } else {
        recording::open_recording_cancellable(&request.directory, cancel)
    }
}

fn map_error(error: RecordingError, cancel: &AtomicBool) -> StatsError {
    if cancel.load(Ordering::Relaxed) {
        return StatsError::Cancelled;
    }
    let text = error.to_string();
    if text.contains("replaced or shrunk") {
        StatsError::Changed
    } else {
        StatsError::Unreadable(text)
    }
}

fn has_telemetry(directory: &Path) -> bool {
    std::fs::metadata(directory.join("telemetry.raw")).is_ok_and(|meta| meta.is_file())
}

/// Count the calls of a recording. Blocks until done, stopped or failed: run it
/// on a worker thread. `cancel` stops it within `CHECK_EVERY` calls and returns
/// the counts so far with `complete == false`. `progress` is told how far the
/// walk is; it runs on the walking thread and must not block.
pub fn compute(
    request: &StatsRequest,
    cancel: &AtomicBool,
    progress: &Arc<dyn Fn(Progress) + Send + Sync>,
) -> Result<RunStatistics, StatsError> {
    compute_every(request, cancel, progress, PARTIAL_EVERY)
}

/// [`compute`] with the time between partial results chosen (tests use zero).
pub fn compute_every(
    request: &StatsRequest,
    cancel: &AtomicBool,
    progress: &Arc<dyn Fn(Progress) + Send + Sync>,
    partial_every: Duration,
) -> Result<RunStatistics, StatsError> {
    if request.lines.len() > MAX_LINES {
        return Err(StatsError::TooManyLines);
    }
    let filter = compile(&request.filter, "")?;
    let lines = request
        .lines
        .iter()
        .enumerate()
        .map(|(i, line)| compile(line, &format!("line {}", i + 1)))
        .collect::<Result<Vec<_>, _>>()?;
    if !has_telemetry(&request.directory) {
        return Err(StatsError::NoTelemetry);
    }
    let report = Arc::clone(progress);
    recording::with_index_progress(
        move |done, total| report(Progress::Indexing { done, total }),
        || walk(request, cancel, progress, &filter, &lines, partial_every),
    )
}

fn walk(
    request: &StatsRequest,
    cancel: &AtomicBool,
    progress: &Arc<dyn Fn(Progress) + Send + Sync>,
    filter: &Compiled,
    lines: &[Compiled],
    partial_every: Duration,
) -> Result<RunStatistics, StatsError> {
    let recording = open(request, cancel).map_err(|e| map_error(e, cancel))?;
    let total = recording
        .invocation_count_cancellable(None, cancel)
        .map_err(|e| map_error(e, cancel))?;
    let base = request.parts == Parts::All;
    let mut aggregate = Aggregator::new(base, request.lines.clone());
    let mut state = Walk {
        read: 0,
        out_of_scope: 0,
        quality: Quality::from_manifest(&recording.manifest),
    };
    let mut last_partial = Instant::now();
    progress(Progress::Reading { read: 0, total });
    let outcome = recording.matching_totals_cancellable(None, cancel, |call| {
        state.read += 1;
        if state.read.is_multiple_of(CHECK_EVERY) && last_partial.elapsed() >= partial_every {
            last_partial = Instant::now();
            progress(Progress::Reading {
                read: state.read,
                total,
            });
            let counts = aggregate.finish();
            progress(Progress::Partial(Box::new(RunStatistics::from_counts(
                request, counts, &state,
            ))));
        }
        if !filter.keep(call) {
            return false;
        }
        if !in_scope(request.root_cookie, call) {
            state.out_of_scope += 1;
            return false;
        }
        let mut hits = 0_u32;
        for (i, line) in lines.iter().enumerate() {
            if line.keep(call) {
                hits |= 1 << i;
            }
        }
        if base || hits != 0 {
            aggregate.feed(call, hits);
        }
        false
    });
    let mut result = RunStatistics::from_counts(request, aggregate.finish(), &state);
    match outcome {
        Ok(totals) => {
            result.complete = true;
            result.read = totals.source_total;
            result.stamp = Some(Stamp {
                identity: totals.stamp.identity,
                length: totals.stamp.length,
            });
        }
        Err(error) => match map_error(error, cancel) {
            StatsError::Cancelled => {}
            other => return Err(other),
        },
    }
    Ok(result)
}
