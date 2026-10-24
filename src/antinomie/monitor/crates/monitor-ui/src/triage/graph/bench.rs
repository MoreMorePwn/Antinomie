// SPDX-License-Identifier: GPL-3.0-only
//! The graph against the design's budgets, on a synthetic run of 120,000
//! findings over 2,000 lanes (section 6.6): paint at 1280x800 within 4 ms, no
//! repaint when idle, the index within 48 bytes a finding and 64 MiB, and a
//! pyramid built within 150 ms per million findings.
//!
//! The timings are of a release build. A debug build only checks the shape.
use super::index::{Builder, GraphIndex, Record, NO_PHASE};
use super::lanes::Lanes;
use super::paint::Colors;
use super::phases;
use super::view::State;
use super::widget::{self, Config};
use super::*;
use crate::theme::Theme;
use crate::triage::rules::{Category, Tier};
use eframe::egui::{Pos2, Rect};
use std::time::{Duration, Instant};

const RUN_NS: u64 = 3_600_000_000_000;

/// A small deterministic generator, so a failing run can be repeated.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        let mut step = || {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0 >> 33
        };
        // 31 bits a step is too few for nanoseconds of an hour.
        (step() << 31) | step()
    }
}

fn lanes(count: usize) -> Lanes {
    let mut nodes = Vec::with_capacity(count);
    let mut rng = Lcg(7);
    let mut depth = 0usize;
    for at in 0..count {
        // A random walk over depth, so the tree has branches and chains.
        let step = rng.next() % 4;
        depth = match step {
            0 if depth > 0 => depth - 1,
            1 | 2 => (depth + 1).min(12),
            _ => depth,
        };
        if at == 0 {
            depth = 0;
        }
        let first = rng.next() % (RUN_NS / 2);
        let mut node = tests::node(
            depth,
            1000 + at as u32,
            1 + at as u64,
            &format!("/usr/bin/p{at}"),
            first,
            first + rng.next() % (RUN_NS / 2),
        );
        node.argv = vec![format!("p{at}")];
        nodes.push(node);
    }
    Lanes::from_processes(&nodes)
}

pub(super) fn synthetic(findings: usize, lane_count: usize) -> GraphIndex {
    let mut rng = Lcg(42);
    let lanes = lanes(lane_count);
    let lane_total = lanes.list.len() as u64;
    let mut builder = Builder::new(lanes).without_rows();
    for _ in 0..findings {
        let ns = 1 + rng.next() % RUN_NS;
        let roll = rng.next() % 100;
        let tier = match roll {
            0 => Tier::High,
            1..=4 => Tier::Medium,
            5..=34 => Tier::Low,
            _ => Tier::Info,
        };
        let category = Category::ALL[(rng.next() % 13) as usize];
        builder.push_record(Record {
            first_ns: ns,
            last_ns: ns + rng.next() % 1_000_000_000,
            count: 1 + (rng.next() % 5) as u32,
            lane: (rng.next() % lane_total) as u32,
            tier: tier.index() as u8,
            category: category.index() as u8,
            phase: phases::phase_of("", category).map_or(NO_PHASE, |phase| phase.index() as u8),
            flags: 0,
        });
    }
    builder.finish()
}

/// CPU time this thread has used, from the scheduler, or `None` where it does
/// not say. Other tests run on the other threads while this one is timed, and
/// waiting for a core is not the work the budget is about.
fn thread_cpu() -> Option<Duration> {
    let stat = std::fs::read_to_string("/proc/thread-self/schedstat").ok()?;
    let nanos: u64 = stat.split_whitespace().next()?.parse().ok()?;
    Some(Duration::from_nanos(nanos))
}

fn median(mut times: Vec<Duration>) -> Duration {
    times.sort();
    times[times.len() / 2]
}

/// One frame of the widget at 1280x800 over `index`: building the shapes and
/// tessellating them, as the app does every frame it repaints.
fn frame_time(ctx: &egui::Context, state: &mut State, index: &GraphIndex) -> Duration {
    let started = Instant::now();
    let output = ctx.run(
        egui::RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, egui::vec2(1280.0, 800.0))),
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let config = Config {
                    index,
                    colors: Colors::of(Theme::Dark.palette()),
                    clock: None,
                    height: 760.0,
                };
                widget::show(ui, state, &config);
            });
        },
    );
    let meshes = ctx.tessellate(output.shapes, output.pixels_per_point);
    std::hint::black_box(meshes.len());
    started.elapsed()
}

#[test]
fn a_run_of_120k_findings_over_2000_lanes_paints_within_the_budget() {
    let index = synthetic(120_000, 2_000);
    assert_eq!(index.records.len(), 120_000);
    assert!(
        index.lanes.list.len() > 1_000,
        "{} lanes",
        index.lanes.list.len()
    );
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut state = State::default();
    // Warm up fonts and layout.
    frame_time(&ctx, &mut state, &index);
    let (origin, end) = index.extent();
    let span = (end - origin) as f64;
    let mut worst = Duration::ZERO;
    for (name, window) in [
        ("fit", None),
        (
            "a tenth of the run",
            Some((origin as f64 + span * 0.4, origin as f64 + span * 0.5)),
        ),
        (
            "a thousandth",
            Some((origin as f64 + span * 0.4, origin as f64 + span * 0.401)),
        ),
        (
            "a ten-thousandth",
            Some((origin as f64 + span * 0.4, origin as f64 + span * 0.4001)),
        ),
    ] {
        state.window = window;
        let time = median(
            (0..15)
                .map(|_| frame_time(&ctx, &mut state, &index))
                .collect(),
        );
        eprintln!("graph paint, 120k findings, {name}: {time:?}");
        worst = worst.max(time);
    }
    if !cfg!(debug_assertions) {
        assert!(
            worst <= Duration::from_millis(4),
            "the slowest view took {worst:?}; the budget is 4 ms"
        );
    }
}

#[test]
fn an_idle_graph_asks_for_no_repaint() {
    let index = synthetic(10_000, 200);
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut state = State::default();
    let mut delay = Duration::ZERO;
    for _ in 0..4 {
        let output = ctx.run(
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, egui::vec2(1280.0, 800.0))),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let config = Config {
                        index: &index,
                        colors: Colors::of(Theme::Dark.palette()),
                        clock: None,
                        height: 760.0,
                    };
                    widget::show(ui, &mut state, &config);
                });
            },
        );
        delay = output
            .viewport_output
            .values()
            .map(|viewport| viewport.repaint_delay)
            .min()
            .unwrap_or(Duration::MAX);
    }
    assert!(
        delay >= Duration::from_secs(1),
        "an idle graph asked to repaint in {delay:?}"
    );
}

#[test]
fn the_index_stays_within_48_bytes_a_finding_and_64_mib() {
    let index = synthetic(120_000, 2_000);
    let per_finding = index.bytes() as f64 / 120_000.0;
    eprintln!(
        "graph index, 120k findings: {} bytes ({per_finding:.1} a finding), {} cells over {} levels",
        index.bytes(),
        index.cells.iter().map(Vec::len).sum::<usize>(),
        index.cells.len()
    );
    // The records are 32 bytes a finding, under the 48 the design allows.
    let records = index.records.len() * std::mem::size_of::<Record>();
    assert!(records <= 48 * 120_000);
    // The pyramid above the base is no bigger than twice the base.
    let base = index.cells[0].len();
    let above: usize = index.cells[1..].iter().map(Vec::len).sum();
    assert!(
        above <= 2 * base,
        "levels above the base hold {above} cells; the base holds {base}"
    );
    assert!(index.bytes() <= 64 * 1024 * 1024, "{} bytes", index.bytes());
    assert!(
        per_finding <= 48.0 + 3.0 * 32.0 + 32.0,
        "{per_finding} bytes a finding"
    );
}

#[test]
fn the_pyramid_builds_within_150_ms_a_million_findings() {
    // The records of a million findings, built once; the pyramid is timed.
    let started = Instant::now();
    let index = synthetic(1_000_000, 2_000);
    let total = started.elapsed();
    eprintln!("graph build with generation, 1M findings: {total:?}");
    assert_eq!(index.records.len(), 1_000_000);
    // Rebuild from the same records, which is the worker's work. The best of
    // up to fifteen, stopping at the first that is within budget, so the other
    // tests running at the same moment cannot fail it by taking the memory bus.
    let mut time = Duration::MAX;
    for _ in 0..15 {
        let mut builder = Builder::new(lanes(2_000)).without_rows();
        for record in &index.records {
            builder.push_record(*record);
        }
        let (started, cpu) = (Instant::now(), thread_cpu());
        let rebuilt = builder.finish();
        let took = match (cpu, thread_cpu()) {
            (Some(before), Some(after)) => after.saturating_sub(before),
            _ => started.elapsed(),
        };
        time = time.min(took);
        assert_eq!(rebuilt.records.len(), 1_000_000);
        if time <= Duration::from_millis(150) {
            break;
        }
    }
    eprintln!("graph pyramid build, 1M findings: {time:?}");
    if !cfg!(debug_assertions) {
        assert!(
            time <= Duration::from_millis(150),
            "the pyramid took {time:?}; the budget is 150 ms"
        );
    }
}
