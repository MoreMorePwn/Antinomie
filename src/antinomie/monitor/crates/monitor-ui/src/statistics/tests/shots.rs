// SPDX-License-Identifier: GPL-3.0-only
//! A native fixture for screenshots of the Statistics window under Xvfb, on
//! made-up calls only. It is ignored in a normal test run; it needs an X11
//! display and exits by itself.
//!
//! `ANTINOMIE_QA_TAB` = properties | hierarchy | rate | latency,
//! `ANTINOMIE_QA_POPPED=1` pops the window out, `ANTINOMIE_QA_THEME` = dark |
//! light | blue, `ANTINOMIE_QA_SIZE` = 1300x860, `ANTINOMIE_QA_SECONDS`,
//! `ANTINOMIE_QA_DATA` a throwaway folder (exports would go there).
use super::*;
use crate::statistics::rate_lines::LineKind;
use serde_json::json;

const MS: u64 = 1_000_000;

/// Two minutes of a made-up program: a startup burst, steady reads and writes,
/// failing lookups, a connect loop, sleeps, and a slow read.
fn calls() -> Vec<Call> {
    let mut calls = Vec::new();
    let mut seed = 11_u64;
    let mut next = move |n: u64| {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (seed >> 33) % n
    };
    for i in 0..400_u64 {
        calls.push(
            Call::new(nr::OPENAT, 2)
                .pid(2)
                .returns(3)
                .at(2_000 * MS + i * 3 * MS, 2_000 + next(9_000)),
        );
    }
    for i in 0..1_200_u64 {
        let t = 5_000 * MS + i * 90 * MS + next(40) * MS;
        calls.push(
            Call::new(nr::READ, 3)
                .pid(2)
                .returns(64)
                .at(t, 800 + next(30_000)),
        );
        calls.push(
            Call::new(nr::WRITE, 3)
                .pid(2)
                .returns(64)
                .at(t + 2 * MS, 1_500 + next(60_000)),
        );
    }
    for i in 0..500_u64 {
        calls.push(
            Call::new(nr::NEWFSTATAT, 4)
                .pid(2)
                .fails(2)
                .at(6_000 * MS + i * 190 * MS, 1_000 + next(8_000)),
        );
    }
    for i in 0..80_u64 {
        calls.push(
            Call::new(nr::CONNECT, 4)
                .pid(2)
                .fails(111)
                .at(30_000 * MS + i * 400 * MS, 20_000 + next(900_000)),
        );
    }
    for i in 0..60_u64 {
        calls.push(
            Call::new(nr::NANOSLEEP, 3)
                .pid(2)
                .returns(0)
                .at(10_000 * MS + i * 1_700 * MS, 50 * MS + next(40) * MS),
        );
    }
    calls.push(
        Call::new(nr::READ, 3)
            .pid(2)
            .returns(1)
            .at(70_000 * MS, 310 * MS),
    );
    calls.push(
        Call::new(nr::CONNECT, 4)
            .pid(2)
            .returns(0)
            .at(75_000 * MS, 1_020 * MS),
    );
    calls.push(
        Call::new(nr::READ, 3)
            .pid(2)
            .unfinished()
            .at(118_000 * MS, 0),
    );
    for i in 0..5_u64 {
        calls.push(
            Call::new(nr::OPENAT, 9)
                .root(99)
                .fails(2)
                .at(40_000 * MS + i, 100),
        );
    }
    calls.sort_by_key(|call| call.entry_ns);
    calls
}

fn manifest() -> serde_json::Value {
    let mut manifest = super::properties::manifest();
    manifest["run"]["environment"]["accelerator"] = json!("kvm");
    manifest["run"]["reduced"] = json!({
        "at_ms": 5, "at_guest_ns": 90_000 * MS, "quota_bytes": 100, "dropped_calls": {"openat": 40, "read": 12}
    });
    manifest["health"]["read_gaps"]["gaps"] = json!([
        {"guest_ns": 25_000 * MS, "len_ns": 4_000 * MS},
        {"guest_ns": 62_000 * MS, "len_ns": 2_500 * MS},
        {"guest_ns": 101_000 * MS, "len_ns": 1_200 * MS}
    ]);
    manifest["health"]["read_gaps"]["full_spells"] =
        json!([{"guest_ns": 45_000 * MS, "len_ns": 3_000 * MS, "ring": 0}]);
    manifest
}

#[test]
#[ignore = "requires X11 native rendering; exits after the given seconds"]
fn native_statistics_fixture() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct QaApp {
        window: StatisticsWindow,
        target: Target,
        data: PathBuf,
        _fixture: Fixture,
        deadline: Instant,
    }
    impl eframe::App for QaApp {
        fn ui(&mut self, root: &mut egui::Ui, _frame: &mut eframe::Frame) {
            let ctx = &root.ctx().clone();
            if Instant::now() >= self.deadline {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            egui::CentralPanel::default().show(root, |_| {});
            let view = AppView {
                target: Some(self.target.clone()),
                trace_filter: "",
                hidden: &[],
                data_dir: &self.data,
            };
            self.window.show(ctx, &view);
            ctx.request_repaint_after(Duration::from_millis(200));
            ctx.request_repaint_of(super::super::window::viewport_id());
        }
    }
    let var = |name: &str| std::env::var(name).unwrap_or_default();
    let theme_choice = match var("ANTINOMIE_QA_THEME").as_str() {
        "light" => crate::theme::Theme::Light,
        "blue" => crate::theme::Theme::Blue,
        _ => crate::theme::Theme::Dark,
    };
    let (width, height) = var("ANTINOMIE_QA_SIZE")
        .split_once('x')
        .and_then(|(w, h)| Some((w.parse::<f32>().ok()?, h.parse::<f32>().ok()?)))
        .unwrap_or((1300.0, 860.0));
    let seconds = var("ANTINOMIE_QA_SECONDS").parse::<u64>().unwrap_or(25);
    let tab = match var("ANTINOMIE_QA_TAB").as_str() {
        "hierarchy" => Tab::Hierarchy,
        "rate" => Tab::CallRate,
        "latency" => Tab::Latency,
        _ => Tab::Properties,
    };
    let data = PathBuf::from(var("ANTINOMIE_QA_DATA"));
    assert!(
        !data.as_os_str().is_empty(),
        "set ANTINOMIE_QA_DATA to a throwaway folder"
    );
    std::fs::create_dir_all(&data).unwrap();
    let fixture = Fixture::with_manifest(&calls(), manifest());
    let mut target = target(&fixture, "4c1e9a72");
    target.facts = Facts::of_run(&super::properties::run_summary(), "Finished, exit 0");
    eframe::run_native(
        "Antinomie Statistics QA",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size([width, height]),
            persist_window: false,
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_x11();
                builder.with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            crate::theme::install(&cc.egui_ctx);
            crate::theme::apply_theme(&cc.egui_ctx, theme_choice);
            let mut window = StatisticsWindow::default();
            window.size = [(width - 80.0).max(640.0), (height - 80.0).max(480.0)];
            window.request_open(Some(tab));
            window.set_popped(var("ANTINOMIE_QA_POPPED") == "1");
            if tab == Tab::CallRate {
                for line in [
                    LineKind::Failed,
                    LineKind::Group("File & filesystem".into()),
                    LineKind::Custom("syscall.name == connect".into()),
                ] {
                    let _ = window.rate.lines.add(line);
                }
            }
            Ok(Box::new(QaApp {
                window,
                target,
                data,
                _fixture: fixture,
                deadline: Instant::now() + Duration::from_secs(seconds),
            }))
        }),
    )
    .unwrap();
}
