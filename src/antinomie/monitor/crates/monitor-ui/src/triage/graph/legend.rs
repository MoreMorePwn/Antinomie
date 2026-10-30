// SPDX-License-Identifier: GPL-3.0-only
//! The graph's legend: what the colours, icons, edges and bands mean. One
//! button on the toolbar of the tab and of the window opens it.
use super::paint::{self, Colors};
use super::*;
use eframe::egui::{Pos2, Sense, Stroke, Vec2};

/// The Legend button; its menu is the legend.
pub(in crate::triage) fn button(ui: &mut egui::Ui) {
    ui.menu_button(format!("{} Legend", egui_phosphor::regular::INFO), |ui| {
        ui.set_max_width(460.0);
        body(ui);
    });
}

/// A marker sample of `size` points, drawn as the graph draws it.
fn sample(ui: &mut egui::Ui, category: u8, color: egui::Color32, hollow: bool) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(22.0), Sense::hover());
    let painter = ui.painter_at(rect);
    let mut shapes = Vec::new();
    paint::marker(
        &painter,
        &mut shapes,
        category,
        rect.center(),
        8.0,
        color,
        hollow,
    );
    painter.extend(shapes);
}

fn dot(ui: &mut egui::Ui, color: egui::Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(22.0), Sense::hover());
    let mut shapes = Vec::new();
    paint::dot(&mut shapes, rect.center(), 5.0, color);
    ui.painter_at(rect).extend(shapes);
}

fn row(ui: &mut egui::Ui, text: &str) {
    ui.add(egui::Label::new(RichText::new(text).color(theme::text())).wrap());
}

fn heading(ui: &mut egui::Ui, text: &str) {
    ui.add_space(4.0);
    ui.label(theme::section_title(ui, text));
}

pub(in crate::triage) fn body(ui: &mut egui::Ui) {
    let colors = Colors::current();
    heading(ui, "Tier colours");
    ui.horizontal_wrapped(|ui| {
        for (tier, color) in rules::Tier::ALL.iter().zip(colors.tier) {
            dot(ui, color);
            ui.label(tier.tag().to_uppercase());
        }
    });
    heading(ui, "Category icons");
    egui::Grid::new("graph-legend-categories")
        .num_columns(4)
        .show(ui, |ui| {
            for (at, category) in rules::Category::ALL.iter().enumerate() {
                sample(ui, at as u8, colors.tier[2], false);
                ui.label(category.chip());
                if at % 2 == 1 || at + 1 == rules::Category::ALL.len() {
                    ui.end_row();
                }
            }
        });
    heading(ui, "Markers");
    ui.horizontal(|ui| {
        sample(ui, 0, colors.tier[1], true);
        row(ui, "Hollow: packets only, no system call.");
    });
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(22.0), Sense::hover());
        ui.painter_at(rect)
            .circle_stroke(rect.center(), 10.0, Stroke::new(2.0_f32, colors.text));
        row(ui, "Ring: the selected finding.");
    });
    ui.horizontal(|ui| {
        ui.label(RichText::new("×3").small().color(colors.text));
        row(ui, "Repeats folded, with count.");
    });
    ui.horizontal(|ui| {
        dot(ui, colors.tier[1]);
        row(ui, "Crowded: tier dots; a small dot is several findings.");
    });
    heading(ui, "Edges and breaks");
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::new(22.0, 22.0), Sense::hover());
        let x = rect.center().x;
        let painter = ui.painter_at(rect);
        painter.line_segment(
            [
                Pos2::new(x, rect.top() + 3.0),
                Pos2::new(x, rect.bottom() - 3.0),
            ],
            Stroke::new(1.0_f32, colors.muted),
        );
        painter.circle_filled(Pos2::new(x, rect.bottom() - 3.0), 1.8, colors.muted);
        row(ui, "Spawn: parent lane to child lane.");
    });
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::new(22.0, 22.0), Sense::hover());
        ui.painter_at(rect).line_segment(
            [rect.left_bottom(), rect.right_top()],
            Stroke::new(1.5_f32, colors.injection),
        );
        row(ui, "Injection: red arrow, injector to target.");
    });
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::new(22.0, 22.0), Sense::hover());
        let painter = ui.painter_at(rect);
        for shift in [-2.0_f32, 2.0] {
            painter.line_segment(
                [
                    Pos2::new(rect.center().x + shift - 3.0, rect.center().y + 6.0),
                    Pos2::new(rect.center().x + shift + 3.0, rect.center().y - 6.0),
                ],
                Stroke::new(1.6_f32, colors.tier[1]),
            );
        }
        row(
            ui,
            "Break: quiet stretch squeezed into one slot; the number is its length.",
        );
    });
    heading(ui, "Bands");
    row(ui, "Phases: run stages");
    row(ui, "Severity curve: findings per tier over time");
    row(ui, "Heat strip: findings per category; brighter is more");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::tests::texts;

    #[test]
    fn every_category_has_its_own_icon() {
        let icons: std::collections::BTreeSet<&str> = (0..13u8).map(paint::icon).collect();
        assert_eq!(icons.len(), 13);
    }

    #[test]
    fn the_legend_names_every_category_and_the_marker_kinds() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut output = egui::FullOutput::default();
        for time in 0..3 {
            output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(900.0, 1200.0),
                    )),
                    time: Some(f64::from(time) * 0.02),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, body);
                },
            );
        }
        let shown: Vec<String> = texts(&output).into_iter().map(|(text, _)| text).collect();
        for category in rules::Category::ALL {
            assert!(
                shown.iter().any(|text| text == category.chip()),
                "{}",
                category.chip()
            );
        }
        for needle in [
            "HIGH",
            "Hollow:",
            "Spawn:",
            "Break:",
            "Phases:",
            "Heat strip:",
        ] {
            assert!(
                shown.iter().any(|text| text.starts_with(needle)),
                "{needle}: {shown:?}"
            );
        }
    }
}
