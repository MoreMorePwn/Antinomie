// SPDX-License-Identifier: GPL-3.0-only
//! Timings of the counting engine (A9). The bounds are of a release build; a
//! debug build runs the same code and checks only its shape, as the Activity
//! graph's bench does.
use super::aggregate::Aggregator;
use super::fixture::{self, nr, Call, Fixture, ROOT};
use super::{compute, Progress, StatsRequest};
use antinomie_monitor_core::recording::open_recording_cancellable;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Instant;

const RELEASE: bool = !cfg!(debug_assertions);

#[test]
fn a9_the_aggregator_counts_two_million_calls_a_second() {
    const POOL: u64 = 4096;
    const ROUNDS: u64 = if RELEASE { 1000 } else { 4 };
    let names = [
        ("openat", nr::OPENAT),
        ("read", nr::READ),
        ("write", nr::WRITE),
        ("futex", nr::FUTEX),
        ("newfstatat", nr::NEWFSTATAT),
        ("mmap", nr::MMAP),
        ("close", nr::CLOSE),
        ("getpid", nr::GETPID),
    ];
    let mut pool: Vec<_> = (0..POOL)
        .map(|i| {
            let (name, number) = names[(i % 8) as usize];
            let result = if i % 5 == 0 { -2 } else { 0 };
            fixture::summary(
                name,
                number,
                2 + (i % 40) as u32,
                1_000 + i * 700,
                Some(100 + i % 900),
                Some(result),
            )
        })
        .collect();
    let mut aggregate = Aggregator::new(true, Vec::new());
    let started = Instant::now();
    for round in 0..ROUNDS {
        for call in &mut pool {
            if round > 0 {
                let step = POOL * 700;
                for event in [call.entry.as_mut(), call.exit.as_mut()]
                    .into_iter()
                    .flatten()
                {
                    event.timestamp_ns += step;
                }
            }
            aggregate.feed(call, 0);
        }
    }
    let seconds = started.elapsed().as_secs_f64();
    let calls = POOL * ROUNDS;
    let rate = calls as f64 / seconds;
    println!(
        "aggregator: {calls} calls in {seconds:.3} s = {:.2} M calls/s",
        rate / 1e6
    );
    assert_eq!(aggregate.calls(), calls);
    if RELEASE {
        assert!(rate >= 2e6, "{rate:.0} calls/s");
    }
}

#[test]
fn a9_the_walk_costs_at_most_a_quarter_more_than_the_traces_count() {
    const CALLS: u64 = if RELEASE { 200_000 } else { 2_000 };
    let kinds = [
        nr::OPENAT,
        nr::READ,
        nr::WRITE,
        nr::NEWFSTATAT,
        nr::CLOSE,
        nr::MMAP,
    ];
    let calls: Vec<Call> = (0..CALLS)
        .map(|i| {
            let call = Call::new(kinds[(i % 6) as usize], 2 + (i % 8) as u32)
                .at(1_000 + i * 900, 80 + i % 500);
            if i % 7 == 0 {
                call.fails(2)
            } else {
                call.returns(3)
            }
        })
        .collect();
    let fixture = Fixture::new(&calls);
    let cancel = AtomicBool::new(false);
    let silent: Arc<dyn Fn(Progress) + Send + Sync> = Arc::new(|_| {});
    let request = StatsRequest {
        root_cookie: ROOT,
        ..StatsRequest::new(&fixture.directory)
    };
    // Build the packet index once, outside the timings.
    let warm = compute(&request, &cancel, &silent).unwrap();
    assert_eq!(warm.calls, CALLS);
    let (mut plain, mut stats) = (f64::MAX, f64::MAX);
    for _ in 0..3 {
        let recording = open_recording_cancellable(&fixture.directory, &cancel).unwrap();
        let started = Instant::now();
        let totals = recording
            .matching_totals_cancellable(None, &cancel, |_| true)
            .unwrap();
        plain = plain.min(started.elapsed().as_secs_f64());
        assert_eq!(totals.total, CALLS);
        let started = Instant::now();
        let result = compute(&request, &cancel, &silent).unwrap();
        stats = stats.min(started.elapsed().as_secs_f64());
        assert_eq!(result.calls, CALLS);
    }
    println!(
        "walk of {CALLS} calls: trace count {plain:.3} s = {:.0} calls/s; statistics {stats:.3} s = {:.0} calls/s",
        CALLS as f64 / plain,
        CALLS as f64 / stats
    );
    if RELEASE {
        assert!(
            stats <= plain * 1.25 + 0.1,
            "statistics {stats:.3} s vs count {plain:.3} s"
        );
    }
}
