// SPDX-License-Identifier: GPL-3.0-only
//! Card D, Call rate: the lines, the extra walk, the click-through, the gaps and
//! the paint bound.
use super::*;
use crate::statistics::navigate::with_window_filter;
use crate::statistics::rate::{self, bands, click_of, plot, LineProgress, Plot};
use crate::statistics::rate_lines::{LineKind, Lines, MAX_LINES};
use crate::statistics::rate_paint::{self, Marks};
use antinomie_triage::statistics::rate::{Peak, Rate, RateSeries};
use antinomie_triage::statistics::{compute, Parts, StatsRequest};
use serde_json::json;
use std::sync::atomic::AtomicBool;

const MS: u64 = 1_000_000;

/// Four seconds of calls: openat every 100 ms from 1 s, failing reads between,
/// some failing connects, and three openat of another program at 2.5 s.
pub(super) fn spread() -> Vec<Call> {
    let mut calls = Vec::new();
    for i in 0..30_u64 {
        calls.push(
            Call::new(nr::OPENAT, 2)
                .pid(2)
                .returns(3)
                .at(1_000 * MS + i * 100 * MS, 20_000),
        );
    }
    for i in 0..10_u64 {
        calls.push(
            Call::new(nr::READ, 3)
                .pid(2)
                .fails(11)
                .at(1_050 * MS + i * 100 * MS, 5_000),
        );
    }
    for i in 0..6_u64 {
        calls.push(
            Call::new(nr::CONNECT, 3)
                .pid(2)
                .fails(115)
                .at(2_000 * MS + i * 3 * MS, 9_000),
        );
    }
    for i in 0..3_u64 {
        calls.push(
            Call::new(nr::OPENAT, 9)
                .root(99)
                .fails(2)
                .at(2_500 * MS + i, 100),
        );
    }
    calls
}

fn manifest_with_gaps() -> serde_json::Value {
    json!({
        "format": "ANTT run raw LE32",
        "health": {
            "read_gaps": {
                "count": 3, "total_ns": 1_000_000_000_u64, "longest_ns": 400_000_000_u64,
                "gaps": [
                    {"guest_ns": 2_000 * MS, "len_ns": 600 * MS},
                    {"guest_ns": 900_000 * MS, "len_ns": 200 * MS},
                    {"guest_ns": 3_500 * MS, "len_ns": 600 * MS}
                ],
                "full_spell_count": 1, "full_spell_total_ns": 100 * MS, "full_spell_longest_ns": 100 * MS,
                "full_spells": [{"guest_ns": 1_500 * MS, "len_ns": 100 * MS, "ring": 0}]
            }
        },
        "run": {"reduced": {"at_ms": 5, "at_guest_ns": 2_800 * MS, "quota_bytes": 100}}
    })
}

fn custom_rate(
    fixture: &Fixture,
    filter: &str,
    line: &str,
) -> antinomie_triage::statistics::RunStatistics {
    let request = StatsRequest {
        root_cookie: ROOT,
        filter: filter.to_owned(),
        lines: vec![line.to_owned()],
        parts: Parts::RateOnly,
        ..StatsRequest::new(&fixture.directory)
    };
    compute(&request, &AtomicBool::new(false), &silent()).expect("the extra walk reads")
}

fn kinds() -> Vec<LineKind> {
    vec![
        LineKind::All,
        LineKind::Failed,
        LineKind::Group("File & filesystem".into()),
        LineKind::Custom("syscall.name == connect".into()),
    ]
}

#[test]
fn d1_lines_add_and_remove_and_a_fifth_is_refused_with_a_message() {
    let mut lines = Lines::default();
    assert_eq!(lines.list, [LineKind::All]);
    assert!(lines.add(LineKind::Failed).is_ok());
    assert!(lines.add(LineKind::Group("Network".into())).is_ok());
    assert!(lines
        .add(LineKind::Custom("syscall.name == connect".into()))
        .is_ok());
    assert_eq!(lines.list.len(), MAX_LINES);
    let refused = lines.add(LineKind::Group("Process".into())).unwrap_err();
    assert!(refused.contains("At most 4 lines"), "{refused}");
    assert_eq!(lines.message.as_deref(), Some(refused.as_str()));
    assert_eq!(lines.list.len(), MAX_LINES);
    lines.remove(1);
    assert_eq!(lines.list.len(), 3);
    assert!(lines.message.is_none());
    assert_eq!(lines.customs(), ["syscall.name == connect"]);
    // A repeat and a filter that does not compile are refused too.
    assert!(lines.add(LineKind::All).is_err());
    let mut lines = Lines::default();
    assert!(lines
        .add(LineKind::Custom("syscall.name ==".into()))
        .is_err());
    assert!(lines.add(LineKind::Custom("  ".into())).is_err());
    assert_eq!(lines.list.len(), 1);
}

#[test]
fn d2_a_custom_line_starts_one_walk_shows_its_progress_and_a_change_cancels_it() {
    let fixture = Fixture::new(&spread());
    let mut rig = Rig::new(Some(target(&fixture, "run-a")));
    rig.window.request_open(Some(Tab::CallRate));
    rig.settle();
    assert_eq!(
        rig.window.rate_worker.started, 0,
        "the base lines need no extra walk"
    );
    // One custom line: one walk, after the main read.
    rig.window
        .rate
        .lines
        .add(LineKind::Custom("syscall.name == connect".into()))
        .unwrap();
    rig.frame(vec![]);
    assert_eq!(rig.window.rate_worker.started, 1);
    assert!(rig.window.rate_worker.running() || rig.window.rate_worker.shown().is_some());
    // A second change before the first is read starts a second walk that replaces it.
    rig.window
        .rate
        .lines
        .add(LineKind::Custom("syscall.name == read".into()))
        .unwrap();
    rig.frame(vec![]);
    assert_eq!(rig.window.rate_worker.started, 2);
    let begin = Instant::now();
    while rig.window.rate_worker.running() {
        rig.frame(vec![]);
        assert!(begin.elapsed() < Duration::from_secs(60));
        std::thread::sleep(Duration::from_millis(5));
    }
    rig.frame(vec![]);
    let (key, result) = rig.window.rate_worker.shown().expect("the extra result");
    assert_eq!(
        key.lines,
        ["syscall.name == connect", "syscall.name == read"]
    );
    let names: Vec<&str> = result.rate.series.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["syscall.name == connect", "syscall.name == read"]);
    let total = |name: &str| -> u64 {
        result
            .rate
            .series
            .iter()
            .find(|s| s.name == name)
            .unwrap()
            .bins
            .iter()
            .map(|n| u64::from(*n))
            .sum()
    };
    assert_eq!(total("syscall.name == connect"), 6);
    assert_eq!(total("syscall.name == read"), 10);
    // Removing the custom lines stops asking for walks and forgets the result.
    rig.window.rate.lines.remove(2);
    rig.window.rate.lines.remove(1);
    rig.frame(vec![]);
    assert!(rig.window.rate_worker.shown().is_none());
    assert_eq!(rig.window.rate_worker.started, 2);
    // The chip words follow the phase.
    use crate::statistics::worker::{Phase, Where};
    assert_eq!(
        LineProgress::of(
            &Phase::Running(Where::Reading { read: 5, total: 10 }),
            false,
            false
        ),
        LineProgress::Reading(Some(50))
    );
    assert_eq!(
        LineProgress::of(&Phase::Idle, true, false),
        LineProgress::Waiting
    );
}

#[test]
fn d3_a_click_sends_the_line_and_the_interval_and_the_trace_total_equals_the_bin() {
    let fixture = Fixture::new(&spread());
    let stats = stats_of(&fixture, "");
    let custom = custom_rate(&fixture, "", "syscall.name == connect");
    let lines = kinds();
    let built = plot(
        &lines,
        &stats.rate,
        Some(&custom.rate),
        &LineProgress::Ready,
        None,
    );
    assert!(built.intervals > 100, "{}", built.intervals);
    // Every line counts the same calls whatever the interval.
    let total = |line: usize| built.lines[line].counts.iter().sum::<u64>();
    assert_eq!(total(0), 46, "all calls of the run's program");
    assert_eq!(total(1), 16, "failed calls");
    assert_eq!(total(3), 6, "the custom line");
    let mut checked = 0;
    for (l, line) in built.lines.iter().enumerate() {
        for (i, &n) in line.counts.iter().enumerate().filter(|(_, n)| **n > 0) {
            let click = click_of(&built, &line.kind, i);
            let filter = with_window_filter("", &click.clause);
            let behind = stats_of(&fixture, &filter);
            assert_eq!(behind.calls, n, "line {l} interval {i}: {filter}");
            assert_eq!(
                super::hierarchy::trace_count(&fixture, &filter),
                behind.calls + behind.out_of_scope,
                "{filter}"
            );
            checked += 1;
        }
    }
    assert!(checked > 30, "{checked}");
    // The clause shapes of design 6.
    let click = click_of(&built, &LineKind::Failed, 0);
    assert!(
        click
            .clause
            .starts_with("syscall.success == false && event.time_ns >= "),
        "{}",
        click.clause
    );
    let group = click_of(&built, &lines[2], 0);
    assert_eq!(group.group, SyscallGroup::of("openat"));
    assert!(click_of(&built, &LineKind::All, 3)
        .clause
        .starts_with("event.time_ns >= "));
    assert!(click_of(&built, &lines[3], 3)
        .clause
        .starts_with("(syscall.name == connect) && event.time_ns"));
    // The window filter stays in front.
    let filter = with_window_filter("tid == 2", &click_of(&built, &LineKind::All, 0).clause);
    assert!(
        filter.starts_with("(tid == 2) && event.time_ns >= "),
        "{filter}"
    );
}

#[test]
fn d3_a_click_on_the_graph_opens_the_calls_of_the_nearest_line_in_that_interval() {
    let fixture = Fixture::new(&spread());
    let mut rig = Rig::new(Some(target(&fixture, "run-a")));
    rig.window.request_open(Some(Tab::CallRate));
    rig.settle();
    rig.frame(vec![]);
    let stats = stats_of(&fixture, "");
    let built = plot(
        &[LineKind::All],
        &stats.rate,
        None,
        &LineProgress::Ready,
        None,
    );
    let shape = rig.window.rate.shape.expect("the graph was drawn");
    // The busiest interval, in the middle of the graph's height.
    let (index, &count) = built.lines[0]
        .counts
        .iter()
        .enumerate()
        .max_by_key(|(_, n)| **n)
        .unwrap();
    assert!(count > 0);
    let centre = built.start_ns as f64 + (index as f64 + 0.5) * built.width_ns as f64;
    let at = egui::pos2(shape.x_of(centre), shape.rect.center().y);
    rig.press_at(at);
    let expected = click_of(&built, &LineKind::All, index).clause;
    assert_eq!(rig.navigated, [Navigate::Filter(expected)]);
}

#[test]
fn d4_gaps_and_spells_show_only_inside_the_runs_span_and_are_labelled() {
    let fixture = Fixture::with_manifest(&spread(), manifest_with_gaps());
    let stats = stats_of(&fixture, "");
    let (first, last) = (stats.first_ns.unwrap(), stats.last_ns.unwrap());
    assert_eq!((first, last), (1_000 * MS, 3_900 * MS));
    let found = bands(&stats);
    // The gap at 900 s is outside; the one at 3.5 s is clipped to the last call.
    assert_eq!(found.len(), 3, "{found:?}");
    assert!(found
        .iter()
        .all(|b| b.start_ns >= first && b.end_ns <= last));
    let spell = found.iter().find(|b| b.full_ring).unwrap();
    assert_eq!((spell.start_ns, spell.end_ns), (1_500 * MS, 1_600 * MS));
    assert!(spell.label.contains("ring full"), "{}", spell.label);
    let gap = found.iter().find(|b| b.start_ns == 2_000 * MS).unwrap();
    assert!(
        gap.label.starts_with("no telemetry read here"),
        "{}",
        gap.label
    );
    assert_eq!(found.last().unwrap().end_ns, last);
    // A hover over the gap names it; a stretch with no calls is not "idle".
    let built = plot(
        &[LineKind::All],
        &stats.rate,
        None,
        &LineProgress::Ready,
        None,
    );
    let input = rate::Inputs {
        stats: &stats,
        custom: None,
        progress: LineProgress::Ready,
        base: TimeBase::RunTime,
        anchor: None,
        partial: false,
    };
    let index = built.index_of(2_200.0 * MS as f64).unwrap();
    let hover = rate_paint::hover_lines(&built, &found, &input, index);
    assert!(
        hover
            .iter()
            .any(|l| l.starts_with("no telemetry read here")),
        "{hover:?}"
    );
    // The reduced switch is a marker at its guest time.
    assert_eq!(
        stats.quality.reduced.as_ref().unwrap().at_guest_ns,
        2_800 * MS
    );
    // The graph and its notes are on screen.
    let mut rig = Rig::new(Some(target(&fixture, "run-g")));
    rig.window.request_open(Some(Tab::CallRate));
    rig.settle();
    let shown = rig.texts();
    let has = |needle: &str| shown.iter().any(|(t, _)| t.contains(needle));
    assert!(has("hatched bands"), "{shown:?}");
    assert!(has("no telemetry read here"), "{shown:?}");
    assert!(has("reduced recording from here"), "{shown:?}");
    // The table toggle gives the numbers, with the gap named in its row.
    let table = rate::table(&built, &found);
    assert!(table.rows.iter().any(|r| matches!(r.last(), Some(antinomie_triage::statistics::export::Cell::Text(t)) if t.contains("no telemetry"))));
}

#[test]
fn d_the_interval_is_a_whole_number_of_bins_and_zoom_stays_inside_the_run() {
    assert_eq!(rate::interval_width(Some(10 * MS), MS, 0), 10 * MS);
    assert_eq!(
        rate::interval_width(Some(MS), 4 * MS, 0),
        4 * MS,
        "never finer than the bins"
    );
    assert_eq!(rate::interval_width(Some(10 * MS), 4 * MS, 0), 12 * MS);
    assert_eq!(rate::interval_width(None, MS, 4_000 * MS), 10 * MS);
    let full = (0.0, 1000.0);
    assert_eq!(rate_paint::clamp_view((0.0, 1000.0), full, 10.0), None);
    assert_eq!(
        rate_paint::clamp_view((-50.0, 150.0), full, 10.0),
        Some((0.0, 200.0))
    );
    assert_eq!(
        rate_paint::clamp_view((950.0, 1100.0), full, 10.0),
        Some((850.0, 1000.0))
    );
    assert_eq!(
        rate_paint::clamp_view((400.0, 401.0), full, 10.0),
        Some((395.5, 405.5))
    );
    assert_eq!(rate_paint::nice_max(0.0), 1.0);
    assert_eq!(rate_paint::nice_max(46.0), 50.0);
    assert_eq!(rate_paint::nice_max(1234.0), 2000.0);
    // The tab, its table toggle and the exported table follow the plot.
    let fixture = Fixture::new(&spread());
    let mut rig = Rig::new(Some(target(&fixture, "run-a")));
    rig.window.request_open(Some(Tab::CallRate));
    rig.settle();
    let shown = rig.texts();
    assert!(
        shown.iter().any(|(t, _)| t.starts_with("Peak ")),
        "{shown:?}"
    );
    rig.window.rate.table = true;
    let shown = rig.texts();
    assert!(
        shown.iter().any(|(t, _)| t == "Interval start"),
        "{shown:?}"
    );
}

/// A plot of `lines` lines of 65,536 intervals with a rise and some noise.
fn synthetic(lines: usize) -> Plot {
    let intervals = 65_536;
    let mut seed = 7_u64;
    let mut next = move || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        seed >> 33
    };
    Plot {
        start_ns: 0,
        width_ns: MS,
        intervals,
        lines: (0..lines)
            .map(|i| rate::PlotLine {
                kind: kinds()[i % 4].clone(),
                counts: (0..intervals)
                    .map(|t| (t as u64 / 64 + next() % 500) * (i as u64 + 1))
                    .collect(),
                progress: LineProgress::Ready,
            })
            .collect(),
    }
}

fn thread_cpu() -> Option<Duration> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::ThreadCPUTime);
    Some(Duration::new(
        u64::try_from(now.tv_sec).ok()?,
        u32::try_from(now.tv_nsec).ok()?,
    ))
}

fn timed(work: impl FnOnce()) -> Duration {
    let (started, cpu) = (Instant::now(), thread_cpu());
    work();
    match (cpu, thread_cpu()) {
        (Some(before), Some(after)) => after.saturating_sub(before),
        _ => started.elapsed(),
    }
}

fn paint_frame(
    ctx: &egui::Context,
    plot: &Plot,
    bands: &[rate::Band],
    view: (f64, f64),
) -> Duration {
    timed(|| {
        let output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1280.0, 800.0),
                )),
                ..Default::default()
            },
            |root| {
                egui::CentralPanel::default().show(root, |ui| {
                    let rect = egui::Rect::from_min_size(
                        egui::pos2(60.0, 20.0),
                        egui::vec2(1180.0, 740.0),
                    );
                    let peak = Peak {
                        calls: 1,
                        start_ns: 30_000 * MS,
                        span_ns: 1_000 * MS,
                    };
                    rate_paint::paint(
                        ui.painter(),
                        rect,
                        plot,
                        view,
                        &Marks {
                            bands,
                            reduced_ns: Some(40_000 * MS),
                            peak: Some(&peak),
                            base: TimeBase::RunTime,
                            first_ns: Some(0),
                            anchor: None,
                        },
                    );
                });
            },
        );
        let meshes = ctx.tessellate(output.shapes, output.pixels_per_point);
        std::hint::black_box(meshes.len());
    })
}

#[test]
fn d5_four_lines_of_65536_intervals_paint_within_4_ms_and_an_idle_graph_does_not_repaint() {
    const BUDGET: Duration = Duration::from_millis(4);
    let plot = synthetic(4);
    assert_eq!(
        plot.lines.iter().map(|l| l.counts.len()).sum::<usize>(),
        4 * 65_536
    );
    let bands: Vec<rate::Band> = (0..200)
        .map(|i| rate::Band {
            start_ns: i * 300 * MS,
            end_ns: i * 300 * MS + 120 * MS,
            label: "no telemetry read here".into(),
            full_ring: i % 7 == 0,
        })
        .collect();
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let end = plot.end_ns() as f64;
    paint_frame(&ctx, &plot, &bands, (0.0, end));
    let mut worst = Duration::ZERO;
    for (name, view) in [
        ("whole run", (0.0, end)),
        ("a tenth", (end * 0.4, end * 0.5)),
        ("a hundredth", (end * 0.4, end * 0.41)),
    ] {
        let mut best = Duration::MAX;
        for _ in 0..5 {
            let mut times: Vec<Duration> = (0..15)
                .map(|_| paint_frame(&ctx, &plot, &bands, view))
                .collect();
            times.sort();
            best = best.min(times[times.len() / 2]);
            if best <= BUDGET || cfg!(debug_assertions) {
                break;
            }
        }
        eprintln!("call rate paint, 4 lines x 65,536 intervals, {name}: {best:?}");
        worst = worst.max(best);
    }
    if !cfg!(debug_assertions) {
        assert!(
            worst <= BUDGET,
            "the slowest view took {worst:?}; the budget is 4 ms"
        );
    }
    // No repaint when nothing changes.
    let fixture = Fixture::new(&spread());
    let mut rig = Rig::new(Some(target(&fixture, "run-a")));
    rig.window.request_open(Some(Tab::CallRate));
    rig.settle();
    for _ in 0..5 {
        rig.frame(vec![]);
    }
    let output = rig.frame(vec![]);
    let delay = output
        .viewport_output
        .values()
        .map(|v| v.repaint_delay)
        .min()
        .unwrap_or(Duration::MAX);
    assert!(
        delay >= Duration::from_secs(1),
        "an idle Call rate tab asked to repaint in {delay:?}"
    );
}

#[test]
fn d_a_custom_line_waits_for_its_walk_and_has_no_counts_until_then() {
    let fixture = Fixture::new(&spread());
    let stats = stats_of(&fixture, "");
    let built = plot(
        &kinds(),
        &stats.rate,
        None,
        &LineProgress::Reading(Some(10)),
        None,
    );
    assert_eq!(built.lines[3].counts.len(), 0, "no result yet");
    assert_eq!(built.lines[3].progress, LineProgress::Reading(Some(10)));
    assert_eq!(built.lines[0].progress, LineProgress::Ready);
    // Series of another grid are summed into whole intervals.
    let base = Rate {
        start_ns: 0,
        bin_ns: MS,
        series: vec![RateSeries {
            name: "all".into(),
            bins: vec![1, 2, 3, 4],
        }],
    };
    let coarse = Rate {
        start_ns: 0,
        bin_ns: 2 * MS,
        series: vec![RateSeries {
            name: "x".into(),
            bins: vec![5, 6],
        }],
    };
    let mixed = plot(
        &[LineKind::All, LineKind::Custom("x".into())],
        &base,
        Some(&coarse),
        &LineProgress::Ready,
        None,
    );
    assert_eq!(mixed.width_ns, 2 * MS);
    assert_eq!(mixed.lines[0].counts, [3, 7]);
    assert_eq!(mixed.lines[1].counts, [5, 6]);
}
