// SPDX-License-Identifier: GPL-3.0-only
//! The plain wheel scrolls the Summary page wherever the pointer is; only
//! Ctrl and the wheel zoom the graph.
use super::*;

/// A window on the Summary with a clock that only moves forward, as the wheel
/// smoothing of egui needs.
struct Rig {
    ctx: egui::Context,
    view: TriageView,
    size: egui::Vec2,
    time: f64,
    _files: PacketSpool,
}

impl Rig {
    fn new() -> Self {
        let (files, view) = fixture();
        let mut rig = Self {
            ctx: context(16.0),
            view,
            size: egui::vec2(1280.0, 700.0),
            time: 0.0,
            _files: files,
        };
        rig.frames(4, vec![]);
        rig
    }

    fn frames(&mut self, count: usize, mut events: Vec<egui::Event>) -> egui::FullOutput {
        let mut out = egui::FullOutput::default();
        for _ in 0..count {
            self.time += 0.02;
            out = draw_at(
                &self.ctx,
                &mut self.view,
                self.size,
                std::mem::take(&mut events),
                self.time,
                None,
            );
        }
        out
    }

    /// The wheel turned by `dy` with the pointer at `at`, and the frames after.
    fn spin(&mut self, at: egui::Pos2, dy: f32, modifiers: egui::Modifiers) -> egui::FullOutput {
        let events = vec![
            egui::Event::PointerMoved(at),
            egui::Event::MouseWheel {
                phase: egui::TouchPhase::Move,
                unit: egui::MouseWheelUnit::Point,
                delta: egui::vec2(0.0, dy),
                modifiers,
            },
        ];
        self.frames(1, events);
        self.frames(30, vec![])
    }

    /// The page scrolled, with the pointer at its right edge, until `text`
    /// is drawn between 100 points from the top and 100 from the bottom.
    fn bring(&mut self, text: &str) -> egui::FullOutput {
        let mut out = self.frames(1, vec![]);
        for _ in 0..80 {
            let size = self.size;
            if texts(&out)
                .iter()
                .any(|(t, r)| t == text && r.min.y > 100.0 && r.max.y < size.y - 100.0)
            {
                return out;
            }
            let at = egui::pos2(size.x - 14.0, 200.0);
            out = self.spin(at, -60.0, egui::Modifiers::NONE);
        }
        panic!("{text:?} never came into view");
    }
}

fn percent(out: &egui::FullOutput) -> String {
    texts(out)
        .into_iter()
        .map(|(text, _)| text)
        .find(|text| {
            text.ends_with('%') && text[..text.len() - 1].chars().all(|c| c.is_ascii_digit())
        })
        .expect("the zoom percentage")
}

#[test]
fn the_wheel_over_the_graph_scrolls_the_page_and_ctrl_wheel_zooms() {
    let mut rig = Rig::new();
    let out = rig.bring("Fit");
    let fit = find(&out, "Fit");
    let over = egui::pos2(fit.min.x - 300.0, fit.max.y + 60.0);
    let (zoom, mark) = (percent(&out), fit.min.y);
    let out = rig.spin(over, -40.0, egui::Modifiers::NONE);
    assert_eq!(percent(&out), zoom, "the plain wheel leaves the zoom");
    assert!(
        find(&out, "Fit").min.y < mark - 10.0,
        "the page scrolled over the graph"
    );
    let out = rig.spin(over, 120.0, egui::Modifiers::COMMAND);
    assert_ne!(percent(&out), zoom, "Ctrl and the wheel zoom");
}

#[test]
fn the_wheel_over_a_closed_key_findings_list_scrolls_the_page() {
    let mut rig = Rig::new();
    let title = rules::rule_title("persistence.cron");
    let out = rig.bring(title);
    // The pointer on a row of the findings.
    let row = find(&out, title);
    let out = rig.spin(row.center(), -40.0, egui::Modifiers::NONE);
    assert!(
        find(&out, title).min.y < row.min.y - 8.0,
        "the page scrolled over the list"
    );
}

#[test]
fn the_wheel_over_the_main_activity_graph_scrolls_the_page() {
    let mut rig = Rig::new();
    rig.size = egui::vec2(1280.0, 450.0);
    let out = rig.bring("Main activity graph");
    let title = find(&out, "Main activity graph");
    let over = egui::pos2(600.0, title.max.y + 60.0);
    let out = rig.spin(over, -40.0, egui::Modifiers::NONE);
    assert!(
        find(&out, "Main activity graph").min.y < title.min.y - 8.0,
        "the page scrolled over the strip"
    );
}

impl Rig {
    fn press(&mut self, at: egui::Pos2, pressed: bool) {
        let events = vec![
            egui::Event::PointerMoved(at),
            egui::Event::PointerButton {
                pos: at,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: egui::Modifiers::NONE,
            },
        ];
        self.frames(1, events);
    }

    fn glide(&mut self, to: egui::Pos2) {
        self.frames(1, vec![egui::Event::PointerMoved(to)]);
    }

    fn click(&mut self, at: egui::Pos2) {
        self.press(at, true);
        self.press(at, false);
        self.frames(3, vec![]);
    }

    /// The plain wheel at `at` scrolls the page: `text` moves up.
    fn page_scrolls(&mut self, at: egui::Pos2, text: &str, why: &str) {
        let out = self.frames(2, vec![]);
        let before = find(&out, text).min.y;
        let out = self.spin(at, -40.0, egui::Modifiers::NONE);
        let after = find(&out, text).min.y;
        assert!(after < before - 8.0, "{why}: {text} {before} -> {after}");
    }
}

#[test]
fn the_page_still_scrolls_after_every_way_of_using_the_graph() {
    let mut rig = Rig::new();
    let out = rig.bring("Fit");
    let fit = find(&out, "Fit");
    let over = egui::pos2(fit.min.x - 300.0, fit.max.y + 60.0);
    let outside = egui::pos2(over.x, fit.min.y - 200.0);
    let edge = egui::pos2(1270.0, 200.0);
    // Drag to pan, released inside, then outside the box.
    rig.glide(over);
    rig.press(over, true);
    rig.glide(over + egui::vec2(40.0, 10.0));
    rig.press(over + egui::vec2(40.0, 10.0), false);
    rig.page_scrolls(over, "Fit", "after a drag released inside");
    rig.press(over, true);
    rig.glide(over + egui::vec2(40.0, 10.0));
    rig.glide(outside);
    rig.press(outside, false);
    rig.frames(3, vec![]);
    rig.page_scrolls(over, "Fit", "after a drag released outside");
    rig.page_scrolls(edge, "Fit", "at the page edge after a drag");
    // Ctrl+wheel zoom.
    rig.spin(over, 120.0, egui::Modifiers::COMMAND);
    rig.page_scrolls(over, "Fit", "after Ctrl+wheel");
    // Fit, then Fit all.
    let out = rig.frames(2, vec![]);
    let fit = find(&out, "Fit");
    rig.click(fit.center());
    rig.page_scrolls(over, "Fit", "after Fit");
    let out = rig.frames(2, vec![]);
    let all = find(&out, "Fit all");
    rig.click(all.center());
    rig.page_scrolls(over, "Fit", "after Fit all");
    // The zoom buttons.
    let out = rig.frames(2, vec![]);
    let plus = find(&out, "+");
    rig.click(plus.center());
    rig.page_scrolls(over, "Fit", "after the zoom button");
    // A click on the graph.
    rig.click(over);
    rig.page_scrolls(over, "Fit", "after a click");
    rig.page_scrolls(edge, "Fit", "away from the graph");
}

#[test]
fn the_page_scrolls_after_the_graph_is_dragged_out_of_the_window_and_let_go_outside() {
    // egui-winit drops a button release that happens outside the window, so
    // egui never sees the drag end.
    let mut rig = Rig::new();
    let out = rig.bring("Fit");
    let fit = find(&out, "Fit");
    let over = egui::pos2(fit.min.x - 300.0, fit.max.y + 60.0);
    rig.glide(over);
    rig.press(over, true);
    rig.glide(over + egui::vec2(40.0, 10.0));
    rig.glide(over + egui::vec2(80.0, 20.0));
    rig.frames(1, vec![egui::Event::PointerGone]);
    rig.frames(3, vec![]);
    rig.glide(over);
    rig.page_scrolls(over, "Fit", "after a drag out of the window");
    rig.page_scrolls(egui::pos2(1270.0, 200.0), "Fit", "away from the graph");
}
