// SPDX-License-Identifier: MIT
//! The Details panel scrolls: long content, a deep and wide process tree, an
//! offset that stays put across repaints and resets for another run.
use super::*;
use antinomie_monitor_core::capture_processes::CaptureProcess;

const SIZE: egui::Vec2 = egui::vec2(700.0, 300.0);

fn process(pid: u32, parent: u32, name: String) -> CaptureProcess {
    CaptureProcess {
        pid,
        parent_pid: parent,
        exe: Some(format!("/usr/lib/{name}/bin/{name}")),
        name,
        at_start: false,
        first_ns: 0,
        last_ns: 1,
        calls: 10,
        packets: 20,
        exited: true,
        exit_code: Some(0),
    }
}

/// A chain `depth` deep with long names: taller and wider than the panel.
fn chain(depth: u32) -> Vec<CaptureProcess> {
    (1..=depth)
        .map(|pid| process(pid, pid - 1, format!("proc{pid}-with-a-rather-long-name")))
        .collect()
}

struct Panel {
    ctx: egui::Context,
    app: MonitorApp,
    time: f64,
}

impl Panel {
    fn new(processes: Vec<CaptureProcess>) -> Self {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut app = app();
        app.selected = Some("vm".into());
        for id in ["first", "second"] {
            let mut finished = run(id);
            finished.state = RunState::Finished;
            app.history.push(finished);
        }
        app.select_run(Some("first".into()));
        app.run_tree = Some(("first".into(), Ok((processes, Vec::new()))));
        Self {
            ctx,
            app,
            time: 0.0,
        }
    }

    fn select(&mut self, id: &str, processes: Vec<CaptureProcess>) {
        self.app.select_run(Some(id.into()));
        self.app.run_tree = Some((id.into(), Ok((processes, Vec::new()))));
    }

    fn draw(&mut self, events: Vec<egui::Event>) -> Vec<(String, egui::Rect)> {
        self.time += 0.05;
        let app = &mut self.app;
        texts(&self.ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
                events,
                time: Some(self.time),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| app.history_detail(ui));
            },
        ))
    }

    /// Repaints with the pointer at `at`, as a mouse does between wheel turns.
    fn settle(&mut self, at: egui::Pos2) -> Vec<(String, egui::Rect)> {
        let mut shown = Vec::new();
        for _ in 0..6 {
            shown = self.draw(vec![egui::Event::PointerMoved(at)]);
        }
        shown
    }

    fn wheel(&mut self, at: egui::Pos2, delta: egui::Vec2) -> Vec<(String, egui::Rect)> {
        self.draw(vec![
            egui::Event::PointerMoved(at),
            egui::Event::MouseWheel {
                unit: egui::MouseWheelUnit::Point,
                delta,
                modifiers: egui::Modifiers::NONE,
            },
        ]);
        self.settle(at)
    }
}

fn find<'a>(shown: &'a [(String, egui::Rect)], label: &str) -> Option<&'a egui::Rect> {
    shown
        .iter()
        .find(|(text, _)| text.contains(label))
        .map(|(_, rect)| rect)
}

/// Whether a label with exactly this text is in view (a tooltip can mention it).
fn has(shown: &[(String, egui::Rect)], label: &str) -> bool {
    shown.iter().any(|(text, _)| text == label)
}

fn top(shown: &[(String, egui::Rect)], label: &str) -> f32 {
    find(shown, label)
        .unwrap_or_else(|| panic!("{label} missing from {shown:?}"))
        .top()
}

/// Over the heading line: the tree is below it.
const OUTSIDE_TREE: egui::Pos2 = egui::pos2(350.0, 12.0);
const INSIDE_TREE: egui::Pos2 = egui::pos2(300.0, 200.0);

#[test]
fn long_details_content_can_be_reached_by_scrolling() {
    let mut panel = Panel::new(chain(3));
    let before = panel.settle(OUTSIDE_TREE);
    assert!(find(&before, "Analysis enabled").is_none(), "{before:?}");
    let after = panel.wheel(OUTSIDE_TREE, egui::vec2(0.0, -400.0));
    assert!(find(&after, "Analysis enabled").is_some(), "{after:?}");
}

#[test]
fn a_deep_and_wide_process_tree_scrolls_both_ways_before_the_details() {
    let mut panel = Panel::new(chain(80));
    let before = panel.settle(INSIDE_TREE);
    assert!(find(&before, "proc1-with").is_some(), "{before:?}");
    assert!(!has(&before, "PID"), "{before:?}");
    let heading = top(&before, "Recorded process tree");
    // Down: the first rows leave the tree and the Details do not move.
    let down = panel.wheel(INSIDE_TREE, egui::vec2(0.0, -400.0));
    assert!(find(&down, "proc1-with").is_none(), "{down:?}");
    assert_eq!(top(&down, "Recorded process tree"), heading);
    // Right: the number columns come into view.
    let right = panel.wheel(INSIDE_TREE, egui::vec2(-4000.0, 0.0));
    assert!(has(&right, "PID"), "{right:?}");
    assert_eq!(top(&right, "Recorded process tree"), heading);
}

#[test]
fn scroll_offsets_survive_repaints_without_jumping_back() {
    let mut panel = Panel::new(chain(80));
    panel.settle(OUTSIDE_TREE);
    let scrolled = panel.wheel(OUTSIDE_TREE, egui::vec2(0.0, -400.0));
    let analysis = top(&scrolled, "Analysis enabled");
    let tree = panel.wheel(INSIDE_TREE, egui::vec2(0.0, -400.0));
    let first_row = tree
        .iter()
        .find(|(text, _)| text.starts_with("proc"))
        .cloned()
        .expect("a row in view");
    for _ in 0..10 {
        let shown = panel.settle(INSIDE_TREE);
        assert_eq!(top(&shown, "Analysis enabled"), analysis);
        assert_eq!(
            shown.iter().find(|(text, _)| text.starts_with("proc")),
            Some(&first_row)
        );
    }
}

#[test]
fn the_offset_resets_when_another_run_is_selected() {
    let mut panel = Panel::new(chain(3));
    let before = panel.settle(OUTSIDE_TREE);
    let scrolled = panel.wheel(OUTSIDE_TREE, egui::vec2(0.0, -400.0));
    assert!(
        find(&scrolled, "Recorded process tree").is_none(),
        "{scrolled:?}"
    );
    panel.select("second", chain(3));
    let other = panel.settle(OUTSIDE_TREE);
    assert_eq!(
        top(&other, "Recorded process tree"),
        top(&before, "Recorded process tree")
    );
}
