// SPDX-License-Identifier: GPL-3.0-only
//! Tests of the Statistics window (ANT-T0477 cards B and C): synthetic
//! recordings, a window drawn without an app around it.
//!
//! Run with `XDG_CACHE_HOME` set to a scratch folder: a walk builds the
//! recording's packet index in the cache folder.
use super::*;
use crate::app::tests::texts;
use antinomie_triage::statistics::fixture::{nr, Call, Fixture, ROOT};
use eframe::egui;
use std::time::{Duration, Instant};

mod hierarchy;
mod properties;
mod window;

pub(super) const SCREEN: egui::Vec2 = egui::vec2(1280.0, 820.0);

/// 15 calls of the run's program (thread 2 to 4) and 2 of another program.
pub(super) fn calls() -> Vec<Call> {
    let mut calls = Vec::new();
    let mut t = 10_000_u64;
    let mut add = |call: Call, n: usize| {
        for i in 0..n {
            t += 1_000;
            calls.push(call.clone().at(t, 50 + i as u64 * 10));
        }
    };
    add(Call::new(nr::OPENAT, 2).pid(2).returns(3), 3);
    add(Call::new(nr::OPENAT, 2).pid(2).fails(2), 2);
    add(Call::new(nr::NEWFSTATAT, 3).pid(2).fails(2), 2);
    add(Call::new(nr::READ, 4).pid(2).returns(10), 4);
    add(Call::new(nr::READ, 4).pid(2).unfinished(), 1);
    add(Call::new(nr::WRITE, 4).pid(2).returns(10), 2);
    add(Call::new(nr::CONNECT, 3).pid(2).fails(115), 1);
    add(Call::new(nr::OPENAT, 9).root(99).fails(2), 2);
    calls
}

pub(super) fn target(fixture: &Fixture, id: &str) -> Target {
    Target {
        id: id.into(),
        label: format!("run {id}"),
        vm: "vm".into(),
        boot: "boot".into(),
        directory: fixture.directory.clone(),
        capture: false,
        root_cookie: ROOT,
        live: false,
        facts: Facts::default(),
    }
}

/// A window, its context and what the app would tell it.
pub(super) struct Rig {
    pub ctx: egui::Context,
    pub window: StatisticsWindow,
    pub target: Option<Target>,
    pub hidden: Vec<SyscallGroup>,
    pub trace_filter: String,
    pub data: PathBuf,
    pub navigated: Vec<Navigate>,
}

impl Rig {
    pub fn new(target: Option<Target>) -> Self {
        let ctx = egui::Context::default();
        crate::theme::install(&ctx);
        let data = std::env::temp_dir().join(format!(
            "antinomie-stats-ui-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&data);
        std::fs::create_dir_all(&data).unwrap();
        Self {
            ctx,
            window: StatisticsWindow::default(),
            target,
            hidden: Vec::new(),
            trace_filter: String::new(),
            data,
            navigated: Vec::new(),
        }
    }

    pub fn frame(&mut self, events: Vec<egui::Event>) -> egui::FullOutput {
        let view = AppView {
            target: self.target.clone(),
            trace_filter: &self.trace_filter,
            hidden: &self.hidden,
            data_dir: &self.data,
        };
        let window = &mut self.window;
        let navigated = &mut self.navigated;
        self.ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SCREEN)),
                events,
                ..Default::default()
            },
            |root| {
                let ctx = root.ctx().clone();
                navigated.extend(window.show(&ctx, &view));
            },
        )
    }

    /// Frames until the walk is over (done, stopped or failed).
    pub fn settle(&mut self) -> egui::FullOutput {
        let begin = Instant::now();
        loop {
            self.frame(vec![]);
            if !self.window.worker.running() {
                // Two more frames for the layout to follow the result.
                self.frame(vec![]);
                return self.frame(vec![]);
            }
            assert!(
                begin.elapsed() < Duration::from_secs(60),
                "the walk did not end"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    pub fn texts(&mut self) -> Vec<(String, egui::Rect)> {
        // A window is not drawn on its first frame, while egui measures it.
        self.frame(vec![]);
        self.frame(vec![]);
        let output = self.frame(vec![]);
        texts(&output)
    }

    /// Click the painted text equal to `label`.
    pub fn click(&mut self, label: &str) {
        let visible = self.texts();
        let pos = visible
            .iter()
            .find(|(text, _)| text == label)
            .unwrap_or_else(|| panic!("missing or clipped {label}: {visible:?}"))
            .1
            .center();
        self.press_at(pos);
    }

    pub fn press_at(&mut self, pos: egui::Pos2) {
        self.frame(vec![egui::Event::PointerMoved(pos)]);
        for pressed in [true, false] {
            self.frame(vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                },
            ]);
        }
        self.frame(vec![]);
    }

    pub fn key(&mut self, key: egui::Key) {
        self.frame(vec![egui::Event::Key {
            key,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        }]);
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.window.worker.cancel();
        let _ = std::fs::remove_dir_all(&self.data);
    }
}

pub(super) fn silent(
) -> std::sync::Arc<dyn Fn(antinomie_triage::statistics::Progress) + Send + Sync> {
    std::sync::Arc::new(|_| {})
}

/// The engine's result for the fixture, read on this thread.
pub(super) fn stats_of(
    fixture: &Fixture,
    filter: &str,
) -> antinomie_triage::statistics::RunStatistics {
    let request = antinomie_triage::statistics::StatsRequest {
        root_cookie: ROOT,
        filter: filter.to_owned(),
        ..antinomie_triage::statistics::StatsRequest::new(&fixture.directory)
    };
    antinomie_triage::statistics::compute(
        &request,
        &std::sync::atomic::AtomicBool::new(false),
        &silent(),
    )
    .expect("the fixture reads")
}
