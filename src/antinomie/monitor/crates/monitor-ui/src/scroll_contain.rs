// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Scroll areas that keep the wheel to themselves. egui hands the wheel to the
//! parent scroll area as soon as a child reaches its top or bottom, so a list
//! in a scrollable window makes the whole window jump. A contained area keeps
//! the wheel while the pointer is over it and it has content to scroll: the
//! parent only scrolls when the pointer is outside the child, or the child has
//! nothing to scroll.
use eframe::egui::{self, scroll_area::ScrollAreaOutput, Ui, Vec2};

/// Take the wheel left over by a scroll area that holds the pointer.
pub(crate) fn contain<R>(ui: &Ui, output: &ScrollAreaOutput<R>) {
    let scrollable = Vec2::new(
        f32::from(output.content_size.x.ceil() > output.inner_rect.width().ceil()),
        f32::from(output.content_size.y.ceil() > output.inner_rect.height().ceil()),
    );
    if (scrollable.x == 0.0 && scrollable.y == 0.0) || !ui.rect_contains_pointer(output.inner_rect)
    {
        return;
    }
    ui.input_mut(|input| {
        if scrollable.x > 0.0 {
            input.smooth_scroll_delta.x = 0.0;
        }
        if scrollable.y > 0.0 {
            input.smooth_scroll_delta.y = 0.0;
        }
    });
}

/// `show` and `show_rows` of a scroll area that is contained.
pub(crate) trait ScrollContained: Sized {
    fn show_contained<R>(
        self,
        ui: &mut Ui,
        add_contents: impl FnOnce(&mut Ui) -> R,
    ) -> ScrollAreaOutput<R>;
    fn show_rows_contained<R>(
        self,
        ui: &mut Ui,
        row_height_sans_spacing: f32,
        total_rows: usize,
        add_contents: impl FnOnce(&mut Ui, std::ops::Range<usize>) -> R,
    ) -> ScrollAreaOutput<R>;
}

impl ScrollContained for egui::ScrollArea {
    fn show_contained<R>(
        self,
        ui: &mut Ui,
        add_contents: impl FnOnce(&mut Ui) -> R,
    ) -> ScrollAreaOutput<R> {
        let output = self.show(ui, add_contents);
        contain(ui, &output);
        output
    }

    fn show_rows_contained<R>(
        self,
        ui: &mut Ui,
        row_height_sans_spacing: f32,
        total_rows: usize,
        add_contents: impl FnOnce(&mut Ui, std::ops::Range<usize>) -> R,
    ) -> ScrollAreaOutput<R> {
        let output = self.show_rows(ui, row_height_sans_spacing, total_rows, add_contents);
        contain(ui, &output);
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A short scroll area with `rows` rows, scrolled to its end, under the
    /// pointer while the wheel turns. Returns how much of the wheel is left
    /// after it, which a parent scroll area would take.
    fn wheel_left_after_child(contained: bool, rows: usize) -> f32 {
        let ctx = egui::Context::default();
        let size = egui::vec2(400.0, 400.0);
        let mut left = 0.0_f32;
        for frame in 0..6 {
            let mut input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                ..Default::default()
            };
            input
                .events
                .push(egui::Event::PointerMoved(egui::pos2(100.0, 100.0)));
            if frame >= 3 {
                input.events.push(egui::Event::MouseWheel {
                    unit: egui::MouseWheelUnit::Point,
                    delta: egui::vec2(0.0, -40.0),
                    phase: egui::TouchPhase::Move,
                    modifiers: Default::default(),
                });
            }
            let _ = ctx.run_ui(input, |root| {
                egui::CentralPanel::default().show(root, |ui| {
                    let area = egui::ScrollArea::vertical()
                        .id_salt("child")
                        .max_height(120.0)
                        .vertical_scroll_offset(10_000.0);
                    let show = |ui: &mut Ui| {
                        for row in 0..rows {
                            ui.label(format!("row {row}"));
                        }
                    };
                    if contained {
                        area.show_contained(ui, show);
                    } else {
                        area.show(ui, show);
                    }
                    if frame >= 3 {
                        left = left.max(ui.input(|input| input.smooth_scroll_delta.y.abs()));
                    }
                });
            });
        }
        left
    }

    #[test]
    fn a_plain_child_at_its_end_leaves_the_wheel_for_the_parent() {
        assert!(wheel_left_after_child(false, 30) > 1.0);
    }

    #[test]
    fn a_contained_child_at_its_end_keeps_the_wheel() {
        assert_eq!(wheel_left_after_child(true, 30), 0.0);
    }

    #[test]
    fn a_contained_area_with_nothing_to_scroll_leaves_the_wheel() {
        assert!(wheel_left_after_child(true, 2) > 1.0);
    }
}
