// SPDX-License-Identifier: GPL-3.0-only
//! The strip on Triage › Summary: the severity curve, the phase band and the
//! category heat strip of the whole run, with no lanes. It shows on every run;
//! when nothing is above LOW it is one line, and a click opens the full graph.
use super::index::GraphIndex;
use super::paint::{self, Colors};
use super::view::{self, Frame, AXIS_H, CURVE_H, GAP, HEAT_ROW_H, PHASE_H};
use super::*;
use eframe::egui::{Align2, Pos2, Sense};

/// What the strip remembers for the session.
#[derive(Default)]
pub(in crate::triage) struct Strip {
    /// The user's choice. `None` follows the data: open when there is
    /// something above LOW, one line when there is not.
    pub open: Option<bool>,
}

/// What the user did to the strip this frame.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::triage) struct Outcome {
    /// The strip was clicked: show the full graph.
    pub open_graph: bool,
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

impl Strip {
    fn is_open(&self, tiers: [u64; 4]) -> bool {
        self.open.unwrap_or(tiers[0] + tiers[1] > 0)
    }

    pub(in crate::triage) fn show(
        &mut self,
        ui: &mut egui::Ui,
        overview: &GraphIndex,
        tiers: [u64; 4],
        clock: Option<antinomie_monitor_core::HostClockAnchor>,
        busy: bool,
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
        let height =
            PHASE_H + GAP + CURVE_H + GAP + HEAT_ROW_H * categories.len() as f32 + GAP + AXIS_H;
        let (rect, response) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), height), Sense::click());
        if overview.is_empty() && overview.geometry.is_none() {
            ui.painter().text(
                rect.left_center(),
                Align2::LEFT_CENTER,
                "Nothing to chart for this run.",
                egui::FontId::proportional(12.0),
                theme::muted(),
            );
            return outcome;
        }
        let colors = Colors::current();
        let frame = Frame::new(rect, view::fitted(overview.extent()), categories.len());
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 0.0, colors.panel);
        paint::phase_band(&painter, &frame, overview, &colors);
        let tallest = paint::severity_curve(&painter, &frame, overview, &colors);
        paint::heat_strip(&painter, &frame, overview, &colors, &categories);
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
            11.0,
            colors.muted,
        );
        paint::label(
            &painter,
            Pos2::new(left, frame.curve.top() + 8.0),
            Align2::LEFT_CENTER,
            "severity",
            11.0,
            colors.muted,
        );
        if tallest > 0 {
            paint::label(
                &painter,
                Pos2::new(left, frame.curve.top() + 22.0),
                Align2::LEFT_CENTER,
                &format!("max {tallest}"),
                10.0,
                colors.muted,
            );
        }
        for (row, category) in categories.iter().enumerate() {
            let y = frame.heat.top() + row as f32 * HEAT_ROW_H + HEAT_ROW_H / 2.0;
            paint::label(
                &painter,
                Pos2::new(left, y),
                Align2::LEFT_CENTER,
                rules::Category::ALL[*category].chip(),
                9.5,
                colors.muted,
            );
        }
        let response = response.on_hover_text("Open the activity graph");
        outcome.open_graph = response.clicked();
        outcome
    }
}
