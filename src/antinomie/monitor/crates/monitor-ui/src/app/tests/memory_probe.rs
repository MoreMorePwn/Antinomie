// SPDX-License-Identifier: MIT
//! Ignored memory probes for the window. Run one at a time, for example
//! `cargo test --release -p antinomie-monitor-ui memory_probe -- --ignored --exact
//! --test-threads=1 app::tests::memory_probe::idle_frames_do_not_grow`.
use super::*;
use crate::memory_probe::{anon_kib, peak_kib, report};

const SIZE: egui::Vec2 = egui::vec2(1400.0, 900.0);

/// One frame as the window runs it: layout, then tessellation.
fn frame(app: &mut MonitorApp, ctx: &egui::Context, index: u64, events: Vec<egui::Event>) {
    let output = ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
            time: Some(index as f64 / 60.0),
            events,
            ..Default::default()
        },
        |ctx| app.draw(ctx),
    );
    let _ = ctx.tessellate(output.shapes, output.pixels_per_point);
}

fn context() -> egui::Context {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    ctx
}

#[test]
#[ignore = "memory probe; run explicitly with --test-threads=1"]
fn idle_frames_do_not_grow() {
    let ctx = context();
    let mut app = app();
    for index in 0..30 {
        frame(&mut app, &ctx, index, Vec::new());
    }
    report("idle_frames", "start_anon_kib", anon_kib());
    let mut pointer = 0.0_f32;
    for index in 30..40_030_u64 {
        pointer = (pointer + 37.0) % 1300.0;
        let events = if index % 3 == 0 {
            vec![egui::Event::PointerMoved(egui::pos2(
                pointer,
                pointer * 0.6,
            ))]
        } else {
            Vec::new()
        };
        frame(&mut app, &ctx, index, events);
        if (index - 30) % 5_000 == 4_999 {
            report(
                "idle_frames",
                &format!("anon_kib_after_{}", index - 29),
                anon_kib(),
            );
        }
    }
    report("idle_frames", "peak_rss_kib", peak_kib());
    report(
        "idle_frames",
        "galleys_in_cache",
        ctx.fonts(|fonts| fonts.num_galleys_in_cache()),
    );
    report(
        "idle_frames",
        "font_atlas_px",
        format!("{:?}", ctx.fonts(|fonts| fonts.font_image_size())),
    );
}

#[test]
#[ignore = "memory probe; run explicitly with --test-threads=1"]
fn every_panel_in_its_empty_state() {
    for panel in [
        Panel::Summary,
        Panel::Trace,
        Panel::Network,
        Panel::Memory,
        Panel::CoreDump,
        Panel::Triage,
        Panel::StaticAnalysis,
        Panel::RunHistory,
        Panel::Details,
        Panel::Activity,
    ] {
        let ctx = context();
        let mut app = app();
        app.focus_panel = Some(panel.clone());
        for index in 0..10 {
            frame(&mut app, &ctx, index, Vec::new());
        }
        let before = anon_kib();
        let started = Instant::now();
        for index in 10..510 {
            frame(&mut app, &ctx, index, Vec::new());
        }
        let name = format!("{panel:?}");
        report(
            "panels",
            &format!("{name}_ms_per_frame"),
            format!("{:.3}", started.elapsed().as_secs_f64() * 2.0),
        );
        report(
            "panels",
            &format!("{name}_anon_kib_growth"),
            anon_kib() as i64 - before as i64,
        );
    }
}

#[test]
#[ignore = "memory probe; run explicitly with --test-threads=1"]
fn dialog_churn_does_not_grow() {
    let ctx = context();
    let mut app = app();
    for index in 0..10 {
        frame(&mut app, &ctx, index, Vec::new());
    }
    let mut index = 10;
    let mut round =
        |app: &mut MonitorApp, open: &dyn Fn(&mut MonitorApp), close: &dyn Fn(&mut MonitorApp)| {
            open(app);
            for _ in 0..3 {
                frame(app, &ctx, index, Vec::new());
                index += 1;
            }
            close(app);
            frame(app, &ctx, index, Vec::new());
            index += 1;
        };
    for _ in 0..20 {
        round(&mut app, &|a| a.settings_open = true, &|a| {
            a.settings_open = false
        });
        round(&mut app, &|a| a.about_open = true, &|a| {
            a.about_open = false
        });
        round(&mut app, &|a| a.launch_open = true, &|a| {
            a.launch_open = false
        });
    }
    let before = anon_kib();
    let areas = ctx.memory(|memory| memory.areas().visible_layer_ids().len());
    for _ in 0..300 {
        round(&mut app, &|a| a.settings_open = true, &|a| {
            a.settings_open = false
        });
        round(&mut app, &|a| a.about_open = true, &|a| {
            a.about_open = false
        });
        round(&mut app, &|a| a.launch_open = true, &|a| {
            a.launch_open = false
        });
    }
    report(
        "dialog_churn",
        "anon_kib_growth_900_open_close",
        anon_kib() as i64 - before as i64,
    );
    report(
        "dialog_churn",
        "areas_before_after",
        format!(
            "{areas} -> {}",
            ctx.memory(|memory| memory.areas().visible_layer_ids().len())
        ),
    );
}

#[test]
#[ignore = "memory probe; run explicitly with --test-threads=1"]
fn terminal_scrollback_cost() {
    for (cols, rows) in [(80_u16, 24_u16), (120, 40), (256, 60)] {
        let before = anon_kib();
        let mut terminals = Vec::new();
        for _ in 0..4 {
            let mut terminal = crate::terminal::Terminal::default();
            terminal.replay_resize(rows, cols);
            let line = format!("\x1b[32m{}\x1b[0m\r\n", "x".repeat(usize::from(cols) - 1));
            for _ in 0..12_000 {
                terminal.process(line.as_bytes());
            }
            terminals.push(terminal);
        }
        report(
            "terminal",
            &format!("{cols}x{rows}_full_scrollback_kib_each"),
            (anon_kib() as i64 - before as i64) / 4,
        );
        drop(terminals);
    }
}

#[test]
#[ignore = "memory probe; run explicitly with --test-threads=1"]
fn run_history_with_analysis_reports() {
    let ctx = context();
    let mut app = app();
    observer_fixture(&mut app);
    let before = anon_kib();
    let runs: Vec<_> = (0..500)
        .map(|index| {
            let mut summary = run(&format!("run-{index}"));
            summary.state = RunState::Finalized;
            summary.analysis = Some(section_report(
                &format!("run-{index}"),
                &format!("sample {index}"),
            ));
            summary
        })
        .collect();
    let one_copy = anon_kib() as i64 - before as i64;
    report(
        "history",
        "kib_per_run_with_2048_row_report",
        one_copy / 500,
    );
    app.history = runs.clone();
    app.snapshot.runs = runs.clone();
    report(
        "history",
        "kib_for_ui_history_and_snapshot_copies",
        anon_kib() as i64 - before as i64 - one_copy,
    );
    // The frame loop clones the selected run once per frame.
    app.selected_run = Some("run-7".into());
    let started = Instant::now();
    for _ in 0..1000 {
        let copy = app.run("run-7").cloned();
        std::hint::black_box(&copy);
    }
    report(
        "history",
        "selected_run_clone_us",
        format!("{:.1}", started.elapsed().as_secs_f64() * 1000.0),
    );
    app.focus_panel = Some(Panel::RunHistory);
    for index in 0..5 {
        frame(&mut app, &ctx, index, Vec::new());
    }
    let (steady, peak) = (anon_kib(), peak_kib());
    let started = Instant::now();
    for index in 5..205 {
        frame(&mut app, &ctx, index, Vec::new());
    }
    report("history", "peak_rss_kib_before_panel_frames", peak);
    report("history", "peak_rss_kib_after_panel_frames", peak_kib());
    report(
        "history",
        "anon_kib_after_panel_frames",
        anon_kib() as i64 - steady as i64,
    );
    report(
        "history",
        "run_history_panel_ms_per_frame",
        format!("{:.3}", started.elapsed().as_secs_f64() * 5.0),
    );
    drop(runs);
}
