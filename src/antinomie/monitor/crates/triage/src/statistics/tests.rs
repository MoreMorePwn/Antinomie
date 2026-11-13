// SPDX-License-Identifier: GPL-3.0-only
//! Tests of the counting engine on synthetic recordings (design 14, A1-A13).
use super::aggregate::{Aggregator, ResultKey, MAX_IDS, MAX_NAMES, MAX_RESULTS};
use super::blocking::{self, BlockClass};
use super::export::{self, Cell, ExportContext, Table};
use super::fixture::{self, nr, Call, Fixture, ROOT};
use super::latency::Histogram;
use super::quality::{Quality, QualitySource};
use super::rate::{RateBins, MAX_BINS};
use super::{
    compute, compute_every, views, Parts, Progress, RunStatistics, StatsError, StatsRequest,
};
use crate::query::compile_note;
use antinomie_monitor_core::recording::open_recording_cancellable;
use antinomie_monitor_core::syscall_groups::SyscallGroup;
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn silent() -> Arc<dyn Fn(Progress) + Send + Sync> {
    Arc::new(|_| {})
}

fn request(fixture: &Fixture, filter: &str) -> StatsRequest {
    StatsRequest {
        root_cookie: ROOT,
        filter: filter.to_owned(),
        ..StatsRequest::new(&fixture.directory)
    }
}

fn run(fixture: &Fixture, filter: &str) -> RunStatistics {
    compute(
        &request(fixture, filter),
        &AtomicBool::new(false),
        &silent(),
    )
    .unwrap()
}

/// 39 calls of ten kinds in thread 2..=4, with errors and missing exits, and
/// two calls of another root (thread 9) among them.
fn kinds() -> Vec<Call> {
    let mut calls = Vec::new();
    let mut t = 10_000_u64;
    let mut add = |call: Call, n: usize, calls: &mut Vec<Call>| {
        for i in 0..n {
            t += 1_000;
            calls.push(call.clone().at(t, 50 + (i as u64) * 10));
        }
    };
    add(Call::new(nr::OPENAT, 2).returns(3), 4, &mut calls);
    add(Call::new(nr::OPENAT, 2).fails(2), 3, &mut calls);
    add(Call::new(nr::OPENAT, 3).fails(13), 1, &mut calls);
    add(Call::new(nr::NEWFSTATAT, 3).fails(2), 5, &mut calls);
    add(Call::new(nr::NEWFSTATAT, 3).returns(0), 2, &mut calls);
    add(Call::new(nr::READ, 4).returns(10), 6, &mut calls);
    add(Call::new(nr::READ, 4).fails(11), 1, &mut calls);
    add(Call::new(nr::READ, 4).unfinished(), 1, &mut calls);
    add(Call::new(nr::WRITE, 4).returns(10), 3, &mut calls);
    add(Call::new(nr::CLOSE, 2).returns(0), 4, &mut calls);
    add(Call::new(nr::MMAP, 2).returns(4096), 3, &mut calls);
    add(Call::new(nr::GETPID, 2).returns(7), 2, &mut calls);
    add(Call::new(nr::FUTEX, 4).returns(0), 2, &mut calls);
    add(Call::new(nr::CONNECT, 3).fails(115), 1, &mut calls);
    add(Call::new(nr::EXECVE, 2).unfinished(), 1, &mut calls);
    // Another launched program in the same recording.
    add(Call::new(nr::OPENAT, 9).root(99).fails(2), 2, &mut calls);
    calls
}

fn hierarchy_call<'a>(stats: &'a RunStatistics, name: &str) -> &'a super::aggregate::CallRow {
    stats
        .hierarchy
        .iter()
        .flat_map(|g| &g.calls_by_name)
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("no row for {name}"))
}

fn count_of(row: &super::aggregate::CallRow, key: ResultKey) -> u64 {
    row.results
        .iter()
        .find(|(k, _)| *k == key)
        .map_or(0, |(_, n)| *n)
}

#[test]
fn a1_group_call_and_result_counts() {
    let fixture = Fixture::new(&kinds());
    let stats = run(&fixture, "");
    assert!(stats.complete);
    assert_eq!(stats.read, 41);
    assert_eq!(stats.calls, 39);
    assert_eq!(stats.out_of_scope, 2);
    let openat = hierarchy_call(&stats, "openat");
    assert_eq!((openat.calls, openat.failed), (8, 4));
    assert_eq!(count_of(openat, ResultKey::Returned), 4);
    assert_eq!(count_of(openat, ResultKey::Errno(2)), 3);
    assert_eq!(count_of(openat, ResultKey::Errno(13)), 1);
    let read = hierarchy_call(&stats, "read");
    assert_eq!((read.calls, read.failed), (8, 1));
    assert_eq!(count_of(read, ResultKey::NoResult), 1);
    assert_eq!(count_of(read, ResultKey::Errno(11)), 1);
    assert_eq!(
        hierarchy_call(&stats, "execve").results,
        [(ResultKey::NoResult, 1)]
    );
    assert_eq!(stats.no_result, 2);
    assert_eq!(stats.ended_task, 0);
    assert_eq!(stats.not_timed, 2);
    // The groups add up to the calls, and each name sits in its own group.
    assert_eq!(stats.hierarchy.iter().map(|g| g.calls).sum::<u64>(), 39);
    for group in &stats.hierarchy {
        assert_eq!(
            group.calls_by_name.iter().map(|c| c.calls).sum::<u64>(),
            group.calls
        );
        assert_eq!(
            group.calls_by_name.iter().map(|c| c.failed).sum::<u64>(),
            group.failed
        );
        for call in &group.calls_by_name {
            let expect = SyscallGroup::of(&call.name).map_or("Other", SyscallGroup::label);
            assert_eq!(group.group, expect, "{}", call.name);
            assert_eq!(
                call.results.iter().map(|(_, n)| n).sum::<u64>() + call.other_results,
                call.calls
            );
        }
    }
    let label = |name: &str| {
        stats
            .hierarchy
            .iter()
            .find(|g| g.calls_by_name.iter().any(|c| c.name == name))
            .unwrap()
            .group
            .as_str()
    };
    assert_eq!(label("connect"), "Network");
    assert_eq!(label("mmap"), "Memory");
    assert_eq!(label("execve"), "Process & threads");
    assert_eq!(stats.processes.count, 3);
    assert_eq!(stats.threads.count, 3);
    assert!(!stats.processes.at_least && !stats.pid_not_recorded);
    assert_eq!(stats.first_ns, Some(11_000));
    assert_eq!(stats.rate.series[0].name, "all");
    assert_eq!(
        stats.rate.series[0]
            .bins
            .iter()
            .map(|&n| u64::from(n))
            .sum::<u64>(),
        39
    );
    assert!(stats.hierarchy.windows(2).all(|w| w[0].calls >= w[1].calls));
}

#[test]
fn a2_failed_only_and_by_error_add_up_to_the_plain_counts() {
    let fixture = Fixture::new(&kinds());
    let stats = run(&fixture, "");
    let failed: u64 = stats.hierarchy.iter().map(|g| g.failed).sum();
    assert_eq!(failed, 4 + 5 + 1 + 1);
    let only = views::failed_only(&stats.hierarchy);
    assert_eq!(only.iter().map(|g| g.calls).sum::<u64>(), failed);
    assert!(only
        .iter()
        .flat_map(|g| &g.calls_by_name)
        .all(|c| c.calls == c.failed && c.failed > 0));
    for group in &only {
        assert_eq!(
            group.calls_by_name.iter().map(|c| c.calls).sum::<u64>(),
            group.calls
        );
    }
    let pivot = views::by_error(&stats.hierarchy, true);
    assert_eq!(pivot.total(), failed);
    let enoent = pivot
        .rows
        .iter()
        .find(|r| r.result == ResultKey::Errno(2))
        .unwrap();
    assert_eq!(
        enoent.by_call,
        [("newfstatat".to_owned(), 5), ("openat".to_owned(), 3)]
    );
    // All results: every call is somewhere.
    assert_eq!(views::by_error(&stats.hierarchy, false).total(), 39);
}

/// The Trace's own count for `filter`: what `matching_totals_cancellable` accepts.
fn trace_count(fixture: &Fixture, filter: &str) -> u64 {
    let cancel = AtomicBool::new(false);
    let recording = open_recording_cancellable(&fixture.directory, &cancel).unwrap();
    let compiled = compile_note(filter);
    assert!(compiled.error.is_none(), "{filter}: {:?}", compiled.error);
    recording
        .matching_totals_cancellable(None, &cancel, |call| compiled.keep(call))
        .unwrap()
        .total
}

#[test]
fn a3_the_count_equals_the_traces_count_for_the_same_filter() {
    let fixture = Fixture::new(&kinds());
    for filter in [
        "",
        "syscall.name == openat",
        "syscall.success == false",
        "process.pid == 2",
        "event.time_ns >= 30000",
        "newfstatat",
    ] {
        let stats = run(&fixture, filter);
        let trace = trace_count(&fixture, filter);
        assert_eq!(stats.calls + stats.out_of_scope, trace, "filter {filter:?}");
        assert_eq!(
            stats.hierarchy.iter().map(|g| g.calls).sum::<u64>(),
            stats.calls,
            "{filter:?}"
        );
        assert!(stats.complete);
    }
    // Spot values, so the equality is not between two zeros.
    assert_eq!(trace_count(&fixture, "syscall.name == openat"), 10);
    assert_eq!(run(&fixture, "syscall.name == openat").calls, 8);
    assert_eq!(
        trace_count(&fixture, "process.pid == 2"),
        4 + 3 + 4 + 3 + 2 + 1
    );
}

#[test]
fn a4_calls_of_another_root_are_counted_apart() {
    let fixture = Fixture::new(&kinds());
    let stats = run(&fixture, "");
    assert_eq!((stats.calls, stats.out_of_scope), (39, 2));
    assert_eq!(
        hierarchy_call(&stats, "openat").calls,
        8,
        "the other root's openat is left out"
    );
    // A capture (root 0) counts every task.
    let mut all = request(&fixture, "");
    all.root_cookie = 0;
    let stats = compute(&all, &AtomicBool::new(false), &silent()).unwrap();
    assert_eq!((stats.calls, stats.out_of_scope), (41, 0));
    // Another root's view is the two calls.
    let mut other = request(&fixture, "");
    other.root_cookie = 99;
    let stats = compute(&other, &AtomicBool::new(false), &silent()).unwrap();
    assert_eq!((stats.calls, stats.out_of_scope), (2, 39));
}

#[test]
fn a5_latency_min_max_total_are_exact_and_percentiles_close() {
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut durations: Vec<u64> = (0..10_000).map(|_| 1 + next() % 5_000_000).collect();
    durations.extend([1, 7, 15, 16, 17, 3_000_000_000_000]);
    let mut histogram = Histogram::default();
    for &d in &durations {
        histogram.add(d);
    }
    durations.sort_unstable();
    let n = durations.len();
    assert_eq!((histogram.min, histogram.max), (1, 3_000_000_000_000));
    assert_eq!(
        histogram.total,
        durations.iter().map(|&d| u128::from(d)).sum::<u128>()
    );
    for p in [0.5, 0.95, 0.99] {
        let exact = durations[((p * n as f64).ceil() as usize).clamp(1, n) - 1];
        let got = histogram.percentile(p);
        let error = (got as f64 - exact as f64).abs() / exact as f64;
        assert!(
            got >= exact && error <= 1.0 / 16.0 + 1e-9,
            "p{p}: {got} vs exact {exact}"
        );
    }
    // Tiny values are exact.
    let mut small = Histogram::default();
    for d in 1..=10 {
        small.add(d);
    }
    assert_eq!(small.percentile(0.5), 5);
}

#[test]
fn a5_slowest_lists_and_blocking_classes() {
    let mut calls = Vec::new();
    // 30 ordinary getpid calls of increasing duration (ties at 100 and 101).
    for i in 0..30_u64 {
        calls.push(Call::new(nr::GETPID, 2).at(1_000 + i * 10, 100 + i.min(28)));
    }
    // futex WAIT (op 0) and WAKE (op 1), a private wait (128), flock, io_uring.
    let futex = |op: u64| Call::new(nr::FUTEX, 3).args([0, op, 0, 0, 0, 0]);
    calls.push(futex(0).at(5_000, 9_000));
    calls.push(futex(1).at(6_000, 40));
    calls.push(futex(128 | 9).at(7_000, 8_000));
    calls.push(
        Call::new(nr::FLOCK, 3)
            .args([3, 2, 0, 0, 0, 0])
            .at(8_000, 7_000),
    );
    calls.push(
        Call::new(nr::FLOCK, 3)
            .args([3, 2 | 4, 0, 0, 0, 0])
            .at(8_100, 70),
    );
    calls.push(
        Call::new(nr::IO_URING_ENTER, 3)
            .args([3, 0, 0, 1, 0, 0])
            .at(9_000, 6_000),
    );
    calls.push(
        Call::new(nr::IO_URING_ENTER, 3)
            .args([3, 4, 0, 0, 0, 0])
            .at(9_500, 90),
    );
    calls.push(Call::new(nr::NANOSLEEP, 3).at(10_000, 100_000));
    calls.push(Call::new(nr::READ, 3).at(11_000, 5_000));
    let fixture = Fixture::new(&calls);
    let stats = run(&fixture, "");
    let row = |name: &str, class: BlockClass| {
        stats
            .latency
            .iter()
            .find(|r| r.name == name && r.class == class)
    };
    let futex_waits = row("futex", BlockClass::Waits).unwrap();
    assert_eq!(
        (futex_waits.timed, futex_waits.min_ns, futex_waits.max_ns),
        (2, 8_000, 9_000)
    );
    assert_eq!(row("futex", BlockClass::Ordinary).unwrap().max_ns, 40);
    assert_eq!(row("flock", BlockClass::Waits).unwrap().timed, 1);
    assert_eq!(row("flock", BlockClass::Ordinary).unwrap().timed, 1);
    assert_eq!(
        row("io_uring_enter", BlockClass::Waits).unwrap().max_ns,
        6_000
    );
    assert_eq!(
        row("io_uring_enter", BlockClass::Ordinary).unwrap().max_ns,
        90
    );
    assert_eq!(row("read", BlockClass::MayBlock).unwrap().timed, 1);
    assert_eq!(row("nanosleep", BlockClass::Waits).unwrap().max_ns, 100_000);
    // Waits are apart: the 20 longest waits hold the sleep and the three futex/flock/uring waits.
    let waits: Vec<_> = stats
        .longest_waits
        .iter()
        .map(|c| (c.name.as_str(), c.duration_ns))
        .collect();
    assert_eq!(
        waits,
        [
            ("nanosleep", 100_000),
            ("futex", 9_000),
            ("futex", 8_000),
            ("flock", 7_000),
            ("io_uring_enter", 6_000)
        ]
    );
    // The slowest 20 are ordinary calls: 5,000 read (may block), then the getpid calls.
    assert_eq!(stats.slowest.len(), 20);
    assert_eq!(stats.slowest[0].name, "read");
    let durations: Vec<u64> = stats.slowest.iter().map(|c| c.duration_ns).collect();
    assert!(durations.windows(2).all(|w| w[0] >= w[1]));
    assert_eq!(
        durations[1], 128,
        "the getpid calls at 128 are the longest ordinary ones"
    );
    assert!(stats.slowest.iter().all(|c| c.name != "nanosleep"));
    let top = &stats.slowest[0];
    assert_eq!((top.pid, top.tid, top.start_ns), (3, 3, 11_000));
    // The key names the call the Trace can open: (stream, task cookie, call id).
    assert_eq!(top.key.0, 1);
    assert_eq!(top.key.1, 3);
    // Classification by name and argument on its own.
    assert_eq!(
        blocking::classify("futex", nr::FUTEX, Some(&[0, 6, 0, 0, 0, 0])),
        BlockClass::Waits
    );
    assert_eq!(
        blocking::classify("futex", nr::FUTEX, Some(&[0, 5, 0, 0, 0, 0])),
        BlockClass::Ordinary
    );
    assert_eq!(
        blocking::classify("futex", nr::FUTEX, None),
        BlockClass::Ordinary
    );
    assert_eq!(
        blocking::classify("flock", nr::FLOCK, Some(&[3, 8, 0, 0, 0, 0])),
        BlockClass::Ordinary
    );
    assert_eq!(
        blocking::classify("getpid", nr::GETPID, None),
        BlockClass::Ordinary
    );
}

#[test]
fn a6_rate_bins_sum_double_and_peak() {
    let mut bins = RateBins::new(vec![true, true]);
    // 3 calls in the first millisecond, 2 in the next, then one far away.
    for ts in [5_000_100, 5_000_200, 5_900_000, 6_000_000, 6_100_000] {
        bins.add(ts, &[0]);
    }
    assert_eq!((bins.width_ns(), bins.used()), (1_000_000, 2));
    assert_eq!(bins.total(0), 5);
    // A call earlier than the first bin moves the start back by whole bins.
    bins.add(2_500_000, &[0, 1]);
    assert_eq!(bins.total(0), 6);
    assert_eq!(bins.total(1), 1);
    assert_eq!(bins.used(), 5);
    // A call far past the last bin doubles the width until it fits; sums stay.
    bins.add(100_000_000_000, &[0]);
    assert!(bins.width_ns() > 1_000_000 && bins.used() <= MAX_BINS);
    assert_eq!(bins.total(0), 7);
    assert_eq!(bins.total(1), 1);
    let rate = bins.finish(&["a".into(), "b".into()], |_| true);
    assert_eq!(rate.start_ns % rate.bin_ns, 0);
    assert!(rate
        .series
        .iter()
        .all(|s| s.bins.len() == rate.series[0].bins.len()));
    // Every call lands in the bin that covers its time.
    let bin_of = |ts: u64| ((ts - rate.start_ns) / rate.bin_ns) as usize;
    let a = &rate.series[0].bins;
    for ts in [5_000_100_u64, 2_500_000, 100_000_000_000] {
        assert!(a[bin_of(ts)] > 0, "ts {ts}");
    }
    // Peak: 1,500 calls in one second, 10 in the next.
    let mut bins = RateBins::new(vec![true]);
    for i in 0..1_500_u64 {
        bins.add(3_000_000_000 + i * 600_000, &[0]);
    }
    for i in 0..10_u64 {
        bins.add(5_000_000_000 + i, &[0]);
    }
    let peak = bins.peak(0).unwrap();
    assert!(peak.calls >= 1_500 - 10 && peak.calls <= 1_500, "{peak:?}");
    assert!(peak.span_ns <= 1_000_000_000 && peak.span_ns >= 990_000_000);
    assert!(peak.start_ns >= 3_000_000_000 && peak.start_ns < 3_000_000_000 + 1_000_000);
    // Wide bins: the peak is one bin.
    let mut bins = RateBins::new(vec![true]);
    bins.add(0, &[0]);
    bins.add(70_000_000_000_000, &[0]);
    assert!(bins.width_ns() > 1_000_000_000);
    let peak = bins.peak(0).unwrap();
    assert_eq!((peak.calls, peak.span_ns), (1, bins.width_ns()));
}

#[test]
fn a6_rate_through_the_walk_with_a_call_before_the_first_bin() {
    // The archive order is not time order: the third call is the earliest.
    let calls = [
        Call::new(nr::GETPID, 2).at(50_000_000, 10),
        Call::new(nr::GETPID, 2).at(52_000_000, 10),
        Call::new(nr::GETPID, 2).at(10_000_000, 10),
        Call::new(nr::OPENAT, 2).fails(2).at(10_000_100, 10),
    ];
    let fixture = Fixture::new(&calls);
    let stats = run(&fixture, "");
    let all = &stats.rate.series[0];
    assert_eq!(all.name, "all");
    assert_eq!(all.bins.iter().map(|&n| u64::from(n)).sum::<u64>(), 4);
    assert_eq!(stats.rate.start_ns, 10_000_000);
    assert_eq!(all.bins[0], 2);
    let failed = stats
        .rate
        .series
        .iter()
        .find(|s| s.name == "failed")
        .unwrap();
    assert_eq!(failed.bins.iter().map(|&n| u64::from(n)).sum::<u64>(), 1);
    assert!(stats.peak_per_s.is_some_and(|p| p.calls == 4));
    assert_eq!(
        (stats.first_ns, stats.last_ns),
        (Some(10_000_000), Some(52_000_000))
    );
}

#[test]
fn a6_custom_lines_count_their_own_calls() {
    let fixture = Fixture::new(&kinds());
    let mut req = request(&fixture, "");
    req.lines = vec!["syscall.name == openat".into(), "process.pid == 3".into()];
    let stats = compute(&req, &AtomicBool::new(false), &silent()).unwrap();
    let line = |name: &str| -> u64 {
        stats
            .rate
            .series
            .iter()
            .find(|s| s.name == name)
            .map_or(0, |s| s.bins.iter().map(|&n| u64::from(n)).sum())
    };
    assert_eq!(line("syscall.name == openat"), 8);
    assert_eq!(line("process.pid == 3"), 5 + 2 + 1 + 1);
    // The rate-only walk makes just the lines.
    req.parts = Parts::RateOnly;
    let only = compute(&req, &AtomicBool::new(false), &silent()).unwrap();
    assert_eq!(only.rate.series.len(), 2);
    assert!(only.hierarchy.is_empty() && only.latency.is_empty());
    assert_eq!(
        only.rate.series[0].bins,
        stats
            .rate
            .series
            .iter()
            .find(|s| s.name == "syscall.name == openat")
            .unwrap()
            .bins
    );
    req.lines = vec!["a".into(); 4];
    assert!(matches!(
        compute(&req, &AtomicBool::new(false), &silent()),
        Err(StatsError::TooManyLines)
    ));
    req.lines = vec!["syscall.bogus == 1".into()];
    let error = compute(&req, &AtomicBool::new(false), &silent()).unwrap_err();
    assert!(
        matches!(&error, StatsError::InvalidFilter(m) if m.starts_with("line 1:")),
        "{error}"
    );
}

#[test]
fn a7_caps_send_the_rest_to_other_names_and_other_results() {
    let mut aggregate = Aggregator::new(true, Vec::new());
    for i in 0..1_100_u32 {
        let call = fixture::summary(
            &format!("call{i:04}"),
            9999,
            2,
            1_000 + u64::from(i),
            Some(10),
            Some(0),
        );
        aggregate.feed(&call, 0);
    }
    let counts = aggregate.finish();
    let rows: usize = counts.hierarchy.iter().map(|g| g.calls_by_name.len()).sum();
    assert_eq!(rows, MAX_NAMES);
    assert_eq!(counts.other_names, 1_100 - MAX_NAMES as u64);
    assert_eq!(
        counts.hierarchy.iter().map(|g| g.calls).sum::<u64>(),
        1_100,
        "the group still counts them"
    );
    assert_eq!(counts.latency_other, 1_100 - MAX_NAMES as u64);
    let mut aggregate = Aggregator::new(true, Vec::new());
    for errno in 1..=70_i64 {
        aggregate.feed(
            &fixture::summary("openat", 257, 2, 1_000, Some(10), Some(-errno)),
            0,
        );
    }
    let counts = aggregate.finish();
    let call = &counts.hierarchy[0].calls_by_name[0];
    assert_eq!(call.results.len(), MAX_RESULTS);
    assert_eq!((call.calls, call.failed, call.other_results), (70, 70, 6));
}

#[test]
fn a7_a_task_that_ended_inside_a_call_is_counted_apart() {
    let mut aggregate = Aggregator::new(true, Vec::new());
    let mut call = fixture::summary("exit_group", 231, 2, 1_000, None, None);
    call.task_exit = call.entry.clone();
    aggregate.feed(&call, 0);
    aggregate.feed(&fixture::summary("execve", 59, 2, 2_000, None, None), 0);
    let counts = aggregate.finish();
    assert_eq!(
        (counts.no_result, counts.ended_task, counts.not_timed),
        (2, 1, 2)
    );
}

#[test]
fn a8_memory_stays_bounded_with_a_million_threads() {
    let mut aggregate = Aggregator::new(true, vec!["x".into()]);
    for i in 0..1_000_000_u32 {
        let name = format!("c{}", i % 1_500);
        let call = fixture::summary(
            &name,
            9999,
            i + 1,
            1_000 + u64::from(i) * 700,
            Some(5 + u64::from(i % 90_000)),
            Some(-i64::from(i % 80)),
        );
        aggregate.feed(&call, 1);
    }
    let counts = aggregate.finish();
    assert!(counts.threads.at_least && counts.threads.count == MAX_IDS as u64);
    assert!(counts.processes.at_least);
    let bytes = aggregate.heap_bytes();
    assert!(bytes <= 16 * 1024 * 1024, "{bytes} bytes");
}

#[test]
fn a10_a_stopped_walk_returns_the_counts_so_far() {
    let calls: Vec<Call> = (0..10_000_u64)
        .map(|i| Call::new(nr::GETPID, 2).at(1_000 + i * 10, 5))
        .collect();
    let fixture = Fixture::new(&calls);
    let cancel = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let progress: Arc<dyn Fn(Progress) + Send + Sync> = {
        let (cancel, seen) = (Arc::clone(&cancel), Arc::clone(&seen));
        Arc::new(move |event| {
            if let Progress::Partial(partial) = &event {
                assert!(!partial.complete);
                cancel.store(true, Ordering::Relaxed);
            }
            seen.lock()
                .unwrap()
                .push(format!("{event:?}").chars().take(7).collect::<String>());
        })
    };
    let stats = compute_every(&request(&fixture, ""), &cancel, &progress, Duration::ZERO).unwrap();
    assert!(!stats.complete && stats.stamp.is_none());
    assert!(stats.read >= 4_096 && stats.read < 10_000, "{}", stats.read);
    assert_eq!(stats.calls, stats.read);
    let events = seen.lock().unwrap();
    assert!(events.iter().any(|e| e == "Reading") && events.iter().any(|e| e == "Partial"));
    // Stopped before anything: an empty partial result, no error.
    let flag = AtomicBool::new(true);
    let early = compute(&request(&fixture, ""), &flag, &silent());
    assert!(matches!(early, Err(StatsError::Cancelled)), "{early:?}");
}

#[test]
fn a11_errors_and_empty_recordings() {
    // No telemetry.raw at all: the run failed before recording.
    let none = Fixture::empty();
    none.write_manifest(&json!({}));
    let error = compute(&request(&none, ""), &AtomicBool::new(false), &silent()).unwrap_err();
    assert!(matches!(error, StatsError::NoTelemetry));
    assert!(error.to_string().starts_with("This run saved no telemetry"));
    // An empty telemetry.raw: no calls, no error.
    let empty = Fixture::new(&[]);
    let stats = run(&empty, "");
    assert!(stats.complete && stats.calls == 0 && stats.read == 0);
    assert!(
        stats.hierarchy.is_empty() && stats.rate.series.is_empty() && stats.peak_per_s.is_none()
    );
    // A bad packet length: the walk does not invent counts.
    let bad = Fixture::new(&[Call::new(nr::GETPID, 2)]);
    {
        use std::io::Write;
        let mut raw = std::fs::OpenOptions::new()
            .append(true)
            .open(bad.raw_path())
            .unwrap();
        raw.write_all(&16_u32.to_le_bytes()).unwrap();
        raw.write_all(&[0; 16]).unwrap();
    }
    let outcome = compute(&request(&bad, ""), &AtomicBool::new(false), &silent());
    match outcome {
        Ok(stats) => assert_eq!(stats.calls, 1),
        Err(error) => assert!(matches!(error, StatsError::Unreadable(_)), "{error}"),
    }
    // An invalid filter gives the parser's message.
    let error = compute(
        &request(&empty, "syscall.bogus == 1"),
        &AtomicBool::new(false),
        &silent(),
    )
    .unwrap_err();
    assert!(
        matches!(&error, StatsError::InvalidFilter(m) if !m.is_empty()),
        "{error}"
    );
    // A missing folder is unreadable, not a panic.
    let gone = StatsRequest::new("/nonexistent/antinomie-stats-test");
    assert!(matches!(
        compute(&gone, &AtomicBool::new(false), &silent()),
        Err(StatsError::NoTelemetry)
    ));
}

#[test]
fn a12_quality_from_three_manifests() {
    let finalized = json!({
        "packets": 1000, "bytes": 5_000_000,
        "health": {"dropped": 3, "storage_dropped_packets": 0, "ui_dropped": 12, "guest_note_lost": 1,
                   "transport_waits": 4113, "transport_wait_ns": 2_100_000_000_u64, "ring_size": 1048576,
                   "send_wait_us": 500, "writer_held_ns": 7, "writer_held_longest_ns": 5,
                   "read_gaps": {"count": 3, "total_ns": 1_900_000_000_u64, "longest_ns": 1_200_000_000_u64}},
        "telemetry_loss": {"received_packets": 990, "lost_packets": 10, "untracked_packets": 0},
        "run": {"notes": ["a note"], "execution": {"async_loss_count": 6},
                "environment": {"accelerator": "kvm"},
                "reduced": {"at_ms": 5, "at_guest_ns": 77, "quota_bytes": 100, "dropped_calls": {"read": 4}}},
    });
    let quality = Quality::from_manifest(&finalized);
    assert_eq!(quality.source, QualitySource::Finalized);
    assert_eq!(quality.transport_dropped, Some(3));
    assert_eq!(quality.storage_dropped, Some(0));
    assert_eq!(quality.ui_dropped, Some(12));
    assert_eq!(quality.telemetry_lost.unwrap().lost_packets, 10);
    assert_eq!(quality.guest_send_waits.unwrap().count, 4113);
    assert_eq!(quality.read_gaps.as_ref().unwrap().count, 3);
    assert_eq!(
        (quality.packets, quality.bytes),
        (Some(1000), Some(5_000_000))
    );
    assert_eq!(quality.async_lost, Some(6));
    assert_eq!(quality.accelerator.as_deref(), Some("kvm"));
    assert_eq!(quality.reduced.as_ref().unwrap().dropped_total(), 4);
    assert_eq!(quality.notes, ["a note"]);
    assert!(quality.incomplete());
    // Sealed early: the loss totals alone.
    let sealed =
        json!({"saved": true, "telemetry_loss": {"received_packets": 5, "lost_packets": 0}});
    let quality = Quality::from_manifest(&sealed);
    assert_eq!(quality.source, QualitySource::SealedEarly);
    assert!(quality.transport_dropped.is_none() && quality.read_gaps.is_none());
    assert!(!quality.incomplete() && quality.accelerator.is_none());
    // Missing: nothing known.
    for manifest in [
        json!(null),
        json!({"run": {"environment": {"accelerator": ""}}}),
    ] {
        let quality = Quality::from_manifest(&manifest);
        assert_eq!(quality.source, QualitySource::Missing);
        assert!(
            quality.telemetry_lost.is_none()
                && quality.accelerator.is_none()
                && !quality.incomplete()
        );
    }
    // The walk reads the manifest of the fixture.
    let fixture = Fixture::with_manifest(&[Call::new(nr::GETPID, 2)], finalized);
    assert_eq!(run(&fixture, "").quality.transport_dropped, Some(3));
}

fn sample(fixture: &Fixture) -> RunStatistics {
    run(fixture, "")
}

#[test]
fn a13_export_quotes_fields_and_the_result_round_trips() {
    let table = Table {
        name: "hierarchy",
        columns: vec!["call".into(), "calls".into()],
        rows: vec![
            vec![Cell::Text("a,b".into()), Cell::Num(1)],
            vec![Cell::Text("say \"hi\"".into()), Cell::Num(2)],
            vec![Cell::Text("two\nlines\ttab".into()), Cell::Empty],
        ],
    };
    assert_eq!(
        table.to_csv(),
        "call,calls\r\n\"a,b\",1\r\n\"say \"\"hi\"\"\",2\r\n\"two\nlines\ttab\",\r\n"
    );
    assert_eq!(
        table.to_tsv(),
        "call\tcalls\na,b\t1\nsay \"hi\"\t2\ntwo lines tab\t\n"
    );
    let fixture = Fixture::new(&kinds());
    let stats = sample(&fixture);
    let json = export::all_json(&stats);
    let back: RunStatistics = serde_json::from_str(&json).unwrap();
    assert_eq!(back, stats);
    assert_eq!(back.schema, "antinomie.statistics/1");
    // Result keys write as names, as in the design's appendix.
    assert!(
        json.contains("\"ENOENT\"")
            && json.contains("\"returned\"")
            && json.contains("no result recorded")
    );
    // A table's JSON names the run, filter and stamp.
    let latency = export::latency_table(&stats, false);
    let context = ExportContext {
        run_id: "run-1".into(),
        vm: "vm".into(),
        boot: "b".into(),
        time_base: "guest".into(),
    };
    let document: serde_json::Value =
        serde_json::from_str(&export::table_json(&context, &stats, &latency)).unwrap();
    assert_eq!(document["table"], "latency");
    assert_eq!(document["run"]["id"], "run-1");
    assert_eq!(
        document["rows"].as_array().unwrap().len(),
        latency.rows.len()
    );
    assert!(document["rows"][0]["median_ns"].is_u64());
    assert!(document["stamp"]["length"].as_u64().unwrap() > 0);
    // The hierarchy and error tables carry the counts.
    let hierarchy = export::hierarchy_table(&stats, false, false);
    assert!(hierarchy
        .rows
        .iter()
        .any(|r| r[1] == Cell::Text("openat".into())
            && r[2] == Cell::Text("ENOENT".into())
            && r[3] == Cell::Num(3)));
    let errors = export::hierarchy_table(&stats, true, true);
    assert_eq!(errors.rows[0][0], Cell::Text("ENOENT".into()));
    assert_eq!(errors.rows[0][2], Cell::Num(8));
    assert!(export::rate_table(&stats)
        .columns
        .contains(&"calls_all".to_owned()));
    assert_eq!(
        export::slowest_table(&stats, false).rows.len(),
        stats.slowest.len()
    );
    for key in ["returned", "no result recorded", "ENOENT", "errno 4000"] {
        assert_eq!(ResultKey::parse(key).unwrap().label(), key);
    }
}
