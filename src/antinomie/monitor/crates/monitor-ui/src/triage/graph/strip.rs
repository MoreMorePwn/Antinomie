// SPDX-License-Identifier: GPL-3.0-only
//! The strip on Triage › Summary: the severity curve, the phase band and the
//! category heat strip of the whole run, with no lanes. It shows on every run;
//! when nothing is above LOW it is one line, and a click opens the full graph.
use super::axis::{Axis, Spacing};
use super::index::GraphIndex;
use super::paint::{self, Colors};
use super::view::{Frame, Metrics};
use super::*;
use eframe::egui::{Align2, Pos2, Rect, Sense};

/// Zoom limits and the step of the buttons. Ctrl+wheel moves in finer steps.
pub(in crate::triage) const ZOOM_MIN: f32 = 0.6;
pub(in crate::triage) const ZOOM_MAX: f32 = 3.0;
const ZOOM_STEP: f32 = 1.25;

/// What the strip remembers for the session.
pub(in crate::triage) struct Strip {
    /// The user's choice. `None` follows the data: open when there is
    /// something above LOW, one line when there is not.
    pub open: Option<bool>,
    /// How much larger than its normal size the strip is drawn: its bands,
    /// labels and text grow together. 1 is the normal size.
    pub zoom: f32,
}

impl Default for Strip {
    fn default() -> Self {
        Self {
            open: None,
            zoom: 1.0,
        }
    }
}

/// `zoom` kept between the limits; a value that is not a number is 1.
pub(in crate::triage) fn clamp_zoom(zoom: f32) -> f32 {
    if zoom.is_finite() {
        zoom.clamp(ZOOM_MIN, ZOOM_MAX)
    } else {
        1.0
    }
}

/// What the user did to the strip this frame.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::triage) struct Outcome {
    /// The strip was clicked: show the full graph.
    pub open_graph: bool,
    /// The pop-out icon was clicked: show the graph in its own window.
    pub open_window: bool,
}

/// The collapsed line: `No medium or high activity · 11 low · 340 info`.
pub(in crate::triage) fn summary_line(tiers: [u64; 4]) -> String {
    let [high, medium, low, info] = tiers;
    if high + medium == 0 {
        format!("No medium or high activity · {low} low · {info} info")
    } else {
        format!("{high} high · {medium} medium · {low} low · {info} info")
    }
}

/// The strip's frame in `rect`: the findings fill the plot, spaced as the
/// graph spaces them (one slot per moment by default), so a few of them are
/// spread over the width instead of bunched in a long run.
pub(super) fn frame(
    rect: Rect,
    overview: &GraphIndex,
    heat_rows: usize,
    spacing: Spacing,
    zoom: f32,
) -> Frame {
    let map = Axis::new(spacing, &overview.slots);
    let window = map.all(overview.extent());
    // The label column grows with the zoom but never takes the plot's room.
    let mut metrics = Metrics::zoomed(zoom);
    metrics.label_w = metrics.label_w.min(rect.width() * 0.4);
    Frame::new(rect, window, heat_rows, metrics, map)
}

impl Strip {
    fn is_open(&self, tiers: [u64; 4]) -> bool {
        self.open.unwrap_or(tiers[0] + tiers[1] > 0)
    }

    /// One button step in (`1`) or out (`-1`).
    pub(in crate::triage) fn step_zoom(&mut self, direction: i32) {
        let factor = if direction >= 0 {
            ZOOM_STEP
        } else {
            1.0 / ZOOM_STEP
        };
        self.zoom = clamp_zoom((self.zoom * factor * 100.0).round() / 100.0);
    }

    /// Back to the normal size.
    pub(in crate::triage) fn reset_zoom(&mut self) {
        self.zoom = 1.0;
    }

    /// The zoom buttons: out, the size (a click goes back to 100%), in.
    fn zoom_buttons(&mut self, ui: &mut egui::Ui) {
        let out = ui
            .add_enabled(
                self.zoom > ZOOM_MIN + 1e-3,
                egui::Button::new(egui_phosphor::regular::MAGNIFYING_GLASS_MINUS).frame(false),
            )
            .on_hover_text("Zoom out (Ctrl+wheel over the graph)");
        if out.clicked() {
            self.step_zoom(-1);
        }
        let normal = (self.zoom - 1.0).abs() < 1e-3;
        let reset = ui
            .add_enabled(
                !normal,
                egui::Button::new(
                    RichText::new(format!("{:.0}%", self.zoom * 100.0))
                        .small()
                        .color(theme::muted()),
                )
                .frame(false),
            )
            .on_hover_text("Back to 100%");
        if reset.clicked() {
            self.reset_zoom();
        }
        let zoom_in = ui
            .add_enabled(
                self.zoom < ZOOM_MAX - 1e-3,
                egui::Button::new(egui_phosphor::regular::MAGNIFYING_GLASS_PLUS).frame(false),
            )
            .on_hover_text("Zoom in (Ctrl+wheel over the graph)");
        if zoom_in.clicked() {
            self.step_zoom(1);
        }
    }

    pub(in crate::triage) fn show(
        &mut self,
        ui: &mut egui::Ui,
        overview: &GraphIndex,
        tiers: [u64; 4],
        clock: Option<antinomie_monitor_core::HostClockAnchor>,
        busy: bool,
        spacing: Spacing,
    ) -> Outcome {
        let mut outcome = Outcome::default();
        let open = self.is_open(tiers);
        ui.horizontal_wrapped(|ui| {
            let arrow = if open { "▾" } else { "▸" };
            if ui
                .add(egui::Button::new(arrow).frame(false))
                .on_hover_text(if open {
                    "Collapse to one line"
                } else {
                    "Show the activity graph"
                })
                .clicked()
            {
                self.open = Some(!open);
            }
            ui.label(
                RichText::new("Main activity graph")
                    .strong()
                    .color(theme::heading()),
            );
            if busy {
                theme::spinner(ui);
            }
            outcome.open_window = ui
                .add(egui::Button::new(egui_phosphor::regular::ARROW_SQUARE_OUT).frame(false))
                .on_hover_text("Open the activity graph in its own window")
                .clicked();
            if open {
                self.zoom_buttons(ui);
            }
            let line = summary_line(tiers);
            if open {
                ui.label(RichText::new(line).small().color(theme::muted()));
            } else if ui
                .add(
                    egui::Label::new(RichText::new(line).color(theme::text()))
                        .sense(Sense::click()),
                )
                .on_hover_text("Click to expand")
                .clicked()
            {
                self.open = Some(true);
            }
        });
        if !open {
            return outcome;
        }
        let categories: Vec<usize> = (0..13)
            .filter(|bit| overview.categories & (1 << bit) != 0)
            .collect();
        let height = Metrics::strip_height(categories.len(), self.zoom);
        let (rect, response) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), height), Sense::click());
        if overview.is_empty() && overview.geometry.is_none() {
            ui.painter().text(
                rect.left_center(),
                Align2::LEFT_CENTER,
                "Nothing to chart for this run.",
                egui::TextStyle::Small.resolve(ui.style()),
                theme::muted(),
            );
            return outcome;
        }
        // Ctrl+wheel over the strip zooms it, as it does in the full graph.
        if response.hovered() {
            let wheel = ui.input(|input| input.zoom_delta());
            if wheel != 1.0 {
                self.zoom = clamp_zoom(self.zoom * wheel);
                ui.ctx().request_repaint();
            }
        }
        let colors = Colors::current();
        let frame = frame(rect, overview, categories.len(), spacing, self.zoom);
        let text = frame.m.text;
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 0.0, colors.panel);
        paint::phase_band(&painter, &frame, overview, &colors);
        let tallest = paint::severity_curve(&painter, &frame, overview, &colors, None);
        paint::heat_strip(&painter, &frame, overview, &colors, &categories, None);
        paint::axis(
            &painter,
            &frame,
            overview.extent().0,
            clock,
            &colors,
            rect.right(),
        );
        let left = frame.labels.left() + 4.0;
        paint::label(
            &painter,
            Pos2::new(left, frame.phases.center().y),
            Align2::LEFT_CENTER,
            "phases",
            11.0 * text,
            colors.muted,
        );
        paint::label(
            &painter,
            Pos2::new(left, frame.curve.top() + 8.0 * text),
            Align2::LEFT_CENTER,
            "severity",
            11.0 * text,
            colors.muted,
        );
        if tallest > 0 {
            paint::label(
                &painter,
                Pos2::new(left, frame.curve.top() + 22.0 * text),
                Align2::LEFT_CENTER,
                &format!("max {tallest}"),
                10.0 * text,
                colors.muted,
            );
        }
        for (row, category) in categories.iter().enumerate() {
            let y = frame.heat.top() + row as f32 * frame.m.heat_h + frame.m.heat_h / 2.0;
            paint::label(
                &painter,
                Pos2::new(left, y),
                Align2::LEFT_CENTER,
                &format!(
                    "{} {}",
                    paint::icon(*category as u8),
                    rules::Category::ALL[*category].chip()
                ),
                9.5 * text,
                colors.muted,
            );
        }
        let response = response.on_hover_text("Open the activity graph");
        outcome.open_graph = response.clicked();
        outcome
    }
}
