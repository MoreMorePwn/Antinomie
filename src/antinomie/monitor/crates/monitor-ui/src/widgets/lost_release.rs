// SPDX-License-Identifier: GPL-3.0-only
//! A drag whose button release never reached egui.
//!
//! egui-winit drops a mouse release that happens while the pointer is outside
//! the window (it has no pointer position then). egui keeps a drag alive until
//! it sees the release, so a graph dragged out of the window and let go
//! outside stays "being dragged" for good, and a `ScrollArea` does not turn
//! the wheel while any widget is being dragged: the whole page stops
//! scrolling until the next click. A pointer that leaves the window therefore
//! ends the drag in progress; the next press starts a new one.

use eframe::egui;
use std::sync::Arc;

/// End a drag when the pointer leaves the window. Call once per context.
pub(crate) fn install(ctx: &egui::Context) {
    ctx.on_begin_pass(
        "lost_release",
        Arc::new(|ui: &mut egui::Ui| {
            let gone = ui.input(|input| {
                input
                    .raw
                    .events
                    .iter()
                    .any(|event| matches!(event, egui::Event::PointerGone))
            });
            if gone && ui.ctx().dragged_id().is_some() {
                ui.ctx().stop_dragging();
            }
        }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A page with a draggable box and a long scroll area; the offset of a
    /// marker inside it says whether the wheel scrolled.
    fn frame(ctx: &egui::Context, time: f64, events: Vec<egui::Event>) -> f32 {
        let mut marker = 0.0;
        let _ = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(400.0, 300.0),
                )),
                time: Some(time),
                events,
                ..Default::default()
            },
            |root| {
                egui::CentralPanel::default().show(root, |ui| {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        let (rect, _) = ui.allocate_exact_size(
                            egui::vec2(300.0, 100.0),
                            egui::Sense::click_and_drag(),
                        );
                        marker = rect.min.y;
                        ui.allocate_space(egui::vec2(10.0, 2000.0));
                    });
                });
            },
        );
        marker
    }

    fn pointer(at: egui::Pos2, pressed: bool) -> Vec<egui::Event> {
        vec![
            egui::Event::PointerMoved(at),
            egui::Event::PointerButton {
                pos: at,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: egui::Modifiers::NONE,
            },
        ]
    }

    /// Drag the box, leave the window with the button down (the release is
    /// lost), come back and turn the wheel: how far the page moved.
    fn wheel_after_a_lost_release(ctx: &egui::Context) -> f32 {
        let at = egui::pos2(100.0, 50.0);
        let mut time = 0.0;
        let mut step = |events| {
            time += 0.02;
            frame(ctx, time, events)
        };
        step(vec![]);
        step(pointer(at, true));
        step(vec![egui::Event::PointerMoved(at + egui::vec2(30.0, 10.0))]);
        step(vec![egui::Event::PointerMoved(at + egui::vec2(60.0, 20.0))]);
        step(vec![egui::Event::PointerGone]);
        step(vec![]);
        let before = step(vec![egui::Event::PointerMoved(at)]);
        let mut after = before;
        for n in 0..30 {
            let events = if n == 0 {
                vec![egui::Event::MouseWheel {
                    phase: egui::TouchPhase::Move,
                    unit: egui::MouseWheelUnit::Point,
                    delta: egui::vec2(0.0, -60.0),
                    modifiers: egui::Modifiers::NONE,
                }]
            } else {
                vec![]
            };
            after = step(events);
        }
        before - after
    }

    #[test]
    fn without_the_guard_a_lost_release_freezes_the_wheel() {
        let ctx = egui::Context::default();
        assert!(wheel_after_a_lost_release(&ctx) < 1.0);
    }

    #[test]
    fn a_pointer_leaving_the_window_ends_the_drag_and_the_wheel_scrolls() {
        let ctx = egui::Context::default();
        install(&ctx);
        let moved = wheel_after_a_lost_release(&ctx);
        assert!(moved > 20.0, "the page moved {moved}");
    }
}
