// SPDX-License-Identifier: GPL-3.0-only
//! The per-call counting (design 4.3): hierarchy, latency, rate bins, processes.
//!
//! The aggregator sees calls that already passed the scope and the filter. Its
//! memory does not grow with the number of calls: call names are capped at
//! `MAX_NAMES`, results per call at `MAX_RESULTS`, the process and thread sets
//! at `MAX_IDS`, and the rate bins at `rate::MAX_BINS`.
use super::blocking::{self, BlockClass};
use super::latency::{Histogram, LatencyRow, SlowCall, Slowest};
use super::rate::{Peak, Rate, RateBins};
use crate::trace;
use antinomie_monitor_core::errno::errno_name;
use antinomie_monitor_core::syscall_groups::SyscallGroup;
use antinomie_monitor_core::{EventSummary, InvocationSummary};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{HashMap, HashSet};

/// Distinct call names kept; further names are counted in `other_names`.
pub const MAX_NAMES: usize = 1024;
/// Distinct results kept per call; further ones are counted in `other_results`.
pub const MAX_RESULTS: usize = 64;
/// Distinct process ids, and thread ids, kept (the process tree's own bound).
pub const MAX_IDS: usize = 262_144;
/// Slots in the group tables: the 11 groups and `Other`.
const GROUPS: usize = 12;
/// Series of the rate bins before the custom lines: all, failed, the groups, Other.
pub const BASE_SERIES: usize = 2 + GROUPS;
/// The label of calls outside the native table.
pub const OTHER_GROUP: &str = "Other";
/// The name given to a call with no event at all.
pub const NO_EVENT_NAME: &str = "(no event)";

/// How a call ended, by the filter language's rule: the exit's result, else
/// the entry's; `-4095..=-1` is an error number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ResultKey {
    Returned,
    Errno(u16),
    NoResult,
}

impl ResultKey {
    pub const NO_RESULT_LABEL: &'static str = "no result recorded";

    pub fn of(result: Option<i64>) -> Self {
        match result {
            None => Self::NoResult,
            Some(value @ -4095..=-1) => Self::Errno((-value) as u16),
            Some(_) => Self::Returned,
        }
    }

    pub fn is_error(self) -> bool {
        matches!(self, Self::Errno(_))
    }

    pub fn label(self) -> String {
        match self {
            Self::Returned => "returned".into(),
            Self::NoResult => Self::NO_RESULT_LABEL.into(),
            Self::Errno(n) => {
                errno_name(u64::from(n)).map_or_else(|| format!("errno {n}"), str::to_owned)
            }
        }
    }

    pub fn parse(label: &str) -> Option<Self> {
        match label {
            "returned" => Some(Self::Returned),
            Self::NO_RESULT_LABEL => Some(Self::NoResult),
            _ => {
                if let Some(n) = label.strip_prefix("errno ") {
                    return n.parse().ok().map(Self::Errno);
                }
                (1..=4095_u16)
                    .find(|&n| errno_name(u64::from(n)) == Some(label))
                    .map(Self::Errno)
            }
        }
    }
}

impl Serialize for ResultKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.label())
    }
}

impl<'de> Deserialize<'de> for ResultKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let label = String::deserialize(deserializer)?;
        Self::parse(&label)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown result {label}")))
    }
}

/// One call name of the hierarchy.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallRow {
    pub name: String,
    pub calls: u64,
    /// Calls whose result is an error number (harmless ones such as `EAGAIN` too).
    pub failed: u64,
    /// Most numerous first.
    pub results: Vec<(ResultKey, u64)>,
    /// Calls whose result was past the `MAX_RESULTS` kept for this name.
    pub other_results: u64,
}

/// One group of the hierarchy.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupRow {
    /// The group's label (`File & filesystem`), or `Other`.
    pub group: String,
    pub calls: u64,
    pub failed: u64,
    pub calls_by_name: Vec<CallRow>,
}

impl GroupRow {
    /// The group, `None` for `Other`.
    pub fn syscall_group(&self) -> Option<SyscallGroup> {
        SyscallGroup::ALL
            .into_iter()
            .find(|g| g.label() == self.group)
    }
}

/// A count that stops at a bound.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capped {
    pub count: u64,
    /// The set was full: the true number is at least `count`.
    pub at_least: bool,
}

#[derive(Default)]
struct NameStats {
    group: usize,
    calls: u64,
    failed: u64,
    results: Vec<(ResultKey, u64)>,
    other_results: u64,
    latency: [Option<Box<Histogram>>; 3],
}

/// The finished counts of a walk (everything but the request and the quality).
pub struct Counts {
    pub calls: u64,
    pub first_ns: Option<u64>,
    pub last_ns: Option<u64>,
    pub processes: Capped,
    pub threads: Capped,
    /// Some call had no process id (a recording saved before 0.3.0).
    pub pid_not_recorded: bool,
    pub no_result: u64,
    pub ended_task: u64,
    pub not_timed: u64,
    pub other_names: u64,
    pub hierarchy: Vec<GroupRow>,
    pub latency: Vec<LatencyRow>,
    /// Timed calls past the latency rows' own name bound.
    pub latency_other: u64,
    pub slowest: Vec<SlowCall>,
    pub longest_waits: Vec<SlowCall>,
    pub rate: Rate,
    pub peak: Option<Peak>,
}

pub struct Aggregator {
    names: HashMap<Box<str>, NameStats>,
    group_calls: [u64; GROUPS],
    group_failed: [u64; GROUPS],
    calls: u64,
    other_names: u64,
    no_result: u64,
    ended_task: u64,
    not_timed: u64,
    latency_other: u64,
    first_ns: Option<u64>,
    last_ns: Option<u64>,
    pids: HashSet<u32>,
    tids: HashSet<u32>,
    pids_full: bool,
    tids_full: bool,
    pid_not_recorded: bool,
    slowest: Slowest,
    waits: Slowest,
    bins: RateBins,
    lines: Vec<String>,
    base: bool,
}

impl Aggregator {
    /// `base`: count everything; otherwise only the rate bins of the `lines`.
    pub fn new(base: bool, lines: Vec<String>) -> Self {
        let mut active = vec![base; BASE_SERIES];
        active.extend(std::iter::repeat_n(true, lines.len()));
        Self {
            names: HashMap::new(),
            group_calls: [0; GROUPS],
            group_failed: [0; GROUPS],
            calls: 0,
            other_names: 0,
            no_result: 0,
            ended_task: 0,
            not_timed: 0,
            latency_other: 0,
            first_ns: None,
            last_ns: None,
            pids: HashSet::new(),
            tids: HashSet::new(),
            pids_full: false,
            tids_full: false,
            pid_not_recorded: false,
            slowest: Slowest::default(),
            waits: Slowest::default(),
            bins: RateBins::new(active),
            lines,
            base,
        }
    }

    pub fn calls(&self) -> u64 {
        self.calls
    }

    /// Bytes the counts hold, estimated; independent of the number of calls.
    pub fn heap_bytes(&self) -> usize {
        let names: usize = self
            .names
            .iter()
            .map(|(name, stats)| {
                name.len()
                    + std::mem::size_of::<NameStats>()
                    + stats.results.capacity() * std::mem::size_of::<(ResultKey, u64)>()
                    + stats
                        .latency
                        .iter()
                        .flatten()
                        .map(|h| h.heap_bytes())
                        .sum::<usize>()
            })
            .sum();
        let set = |s: &HashSet<u32>| s.capacity() * 5;
        names
            + set(&self.pids)
            + set(&self.tids)
            + self.bins.heap_bytes()
            + self.slowest.heap_bytes()
            + self.waits.heap_bytes()
    }

    /// Count one call. `line_hits` has bit `i` set when the call also matches
    /// the custom line `i`.
    pub fn feed(&mut self, call: &InvocationSummary, line_hits: u32) {
        self.calls += 1;
        let event = trace::representative(call);
        let mut ids = [0_usize; BASE_SERIES + 3];
        let mut ids_len = 0;
        if let Some(event) = event
            && self.base
        {
            self.note_process(event);
        }
        let outcome =
            event.map(|event| call.exit.as_ref().map_or(event.result, |exit| exit.result));
        let key = ResultKey::of(outcome.flatten());
        let name = event.map_or(NO_EVENT_NAME, |event| event.syscall_name.as_str());
        let group = if self.base {
            self.count_name(call, name, key, event)
        } else {
            0
        };
        if self.base {
            ids[0] = 0;
            ids_len = 1;
            if key.is_error() {
                ids[ids_len] = 1;
                ids_len += 1;
            }
            ids[ids_len] = 2 + group;
            ids_len += 1;
        }
        for line in 0..self.lines.len().min(3) {
            if line_hits & (1 << line) != 0 {
                ids[ids_len] = BASE_SERIES + line;
                ids_len += 1;
            }
        }
        if let Some(event) = event {
            let ts = event.timestamp_ns;
            self.first_ns = Some(self.first_ns.map_or(ts, |first| first.min(ts)));
            self.last_ns = Some(self.last_ns.map_or(ts, |last| last.max(ts)));
            self.bins.add(ts, &ids[..ids_len]);
        }
    }

    fn note_process(&mut self, event: &EventSummary) {
        if event.pid == 0 {
            self.pid_not_recorded = true;
        } else if self.pids.len() < MAX_IDS {
            self.pids.insert(event.pid);
        } else if !self.pids.contains(&event.pid) {
            self.pids_full = true;
        }
        if self.tids.len() < MAX_IDS {
            self.tids.insert(event.tid);
        } else if !self.tids.contains(&event.tid) {
            self.tids_full = true;
        }
    }

    /// Hierarchy and latency; returns the group slot of the call.
    fn count_name(
        &mut self,
        call: &InvocationSummary,
        name: &str,
        key: ResultKey,
        event: Option<&EventSummary>,
    ) -> usize {
        let failed = u64::from(key.is_error());
        if key == ResultKey::NoResult {
            self.no_result += 1;
            if call.task_exit.is_some() {
                self.ended_task += 1;
            }
        }
        let class = event.map_or(BlockClass::Ordinary, |event| {
            let args = call
                .entry
                .as_ref()
                .and_then(|e| e.args.as_ref())
                .or(event.args.as_ref());
            blocking::classify(name, event.syscall_nr, args)
        });
        let duration = call
            .entry
            .as_ref()
            .zip(call.exit.as_ref())
            .and_then(|(entry, exit)| exit.timestamp_ns.checked_sub(entry.timestamp_ns));
        if duration.is_none() {
            self.not_timed += 1;
        }
        let group = if let Some(stats) = self.names.get_mut(name) {
            Self::count(stats, key, failed);
            stats.group
        } else if self.names.len() < MAX_NAMES {
            let group = SyscallGroup::of(name).map_or(GROUPS - 1, |g| g as usize);
            let mut stats = NameStats {
                group,
                ..NameStats::default()
            };
            Self::count(&mut stats, key, failed);
            self.names.insert(name.into(), stats);
            group
        } else {
            self.other_names += 1;
            SyscallGroup::of(name).map_or(GROUPS - 1, |g| g as usize)
        };
        self.group_calls[group] += 1;
        self.group_failed[group] += failed;
        if let Some(duration) = duration {
            self.time(call, name, class, duration);
        }
        group
    }

    fn count(stats: &mut NameStats, key: ResultKey, failed: u64) {
        stats.calls += 1;
        stats.failed += failed;
        if let Some(slot) = stats.results.iter_mut().find(|(k, _)| *k == key) {
            slot.1 += 1;
        } else if stats.results.len() < MAX_RESULTS {
            stats.results.push((key, 1));
        } else {
            stats.other_results += 1;
        }
    }

    fn time(&mut self, call: &InvocationSummary, name: &str, class: BlockClass, duration: u64) {
        match self.names.get_mut(name) {
            Some(stats) => stats.latency[class.index()]
                .get_or_insert_with(Default::default)
                .add(duration),
            None => self.latency_other += 1,
        }
        let list = if class == BlockClass::Waits {
            &mut self.waits
        } else {
            &mut self.slowest
        };
        let key = trace::key(call);
        list.offer(duration, key, || {
            let (pid, tid, start_ns) = call
                .entry
                .as_ref()
                .map_or((0, 0, 0), |e| (e.pid, e.tid, e.timestamp_ns));
            SlowCall {
                key,
                name: name.to_owned(),
                pid,
                tid,
                start_ns,
                duration_ns: duration,
            }
        });
    }

    /// The counts so far, sorted for display. Cheap enough to take every 2 s.
    pub fn finish(&self) -> Counts {
        let mut groups: Vec<GroupRow> = (0..GROUPS)
            .filter(|&g| self.group_calls[g] > 0)
            .map(|g| GroupRow {
                group: SyscallGroup::ALL
                    .get(g)
                    .map_or(OTHER_GROUP, |group| group.label())
                    .to_owned(),
                calls: self.group_calls[g],
                failed: self.group_failed[g],
                calls_by_name: Vec::new(),
            })
            .collect();
        let mut latency = Vec::new();
        for (name, stats) in &self.names {
            let label = SyscallGroup::ALL
                .get(stats.group)
                .map_or(OTHER_GROUP, |group| group.label());
            let mut results = stats.results.clone();
            results.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            if let Some(row) = groups.iter_mut().find(|row| row.group == label) {
                row.calls_by_name.push(CallRow {
                    name: name.to_string(),
                    calls: stats.calls,
                    failed: stats.failed,
                    results,
                    other_results: stats.other_results,
                });
            }
            for class in BlockClass::ALL {
                if let Some(h) = &stats.latency[class.index()] {
                    latency.push(LatencyRow::from_histogram(name, class, h));
                }
            }
        }
        for row in &mut groups {
            row.calls_by_name
                .sort_by(|a, b| b.calls.cmp(&a.calls).then_with(|| a.name.cmp(&b.name)));
        }
        groups.sort_by(|a, b| b.calls.cmp(&a.calls).then_with(|| a.group.cmp(&b.group)));
        latency.sort_by(|a, b| {
            b.total_ns
                .cmp(&a.total_ns)
                .then_with(|| a.name.cmp(&b.name))
        });
        let rate = self.bins.finish(&self.series_names(), |i| i < 2);
        Counts {
            calls: self.calls,
            first_ns: self.first_ns,
            last_ns: self.last_ns,
            processes: Capped {
                count: self.pids.len() as u64,
                at_least: self.pids_full,
            },
            threads: Capped {
                count: self.tids.len() as u64,
                at_least: self.tids_full,
            },
            pid_not_recorded: self.pid_not_recorded,
            no_result: self.no_result,
            ended_task: self.ended_task,
            not_timed: self.not_timed,
            other_names: self.other_names,
            hierarchy: groups,
            latency,
            latency_other: self.latency_other,
            slowest: self.slowest.sorted(),
            longest_waits: self.waits.sorted(),
            rate,
            peak: if self.base { self.bins.peak(0) } else { None },
        }
    }

    fn series_names(&self) -> Vec<String> {
        let mut names = vec!["all".to_owned(), "failed".to_owned()];
        names.extend(SyscallGroup::ALL.iter().map(|g| g.label().to_owned()));
        names.push(OTHER_GROUP.to_owned());
        names.extend(self.lines.iter().cloned());
        names
    }
}
