// SPDX-License-Identifier: GPL-3.0-only
//! Paints the Relationships Timeline: a lane per process with its markers.
use super::model::Key;
use super::timeline::{MarkKind, Timeline};
use crate::theme;
use eframe::egui::{self, Color32, Pos2, Rect, RichText, Sense, Shape, Stroke};

const LANE_H: f32 = 26.0;
const AXIS_H: f32 = 22.0;

fn color_of(kind: MarkKind) -> Color32 {
    match kind {
        MarkKind::Fork => theme::muted(),
        MarkKind::Exec => theme::blue(),
        MarkKind::FileWrite => theme::identity(),
        MarkKind::Connect => theme::good(),
        MarkKind::Finding(tier) => tier.color(),
    }
}

/// The time of `ns` after the run's start, as the axis says it.
pub(in crate::triage) fn after(ns: u64, start: u64) -> String {
    format!("+{:.1} s", ns.saturating_sub(start) as f64 / 1e9)
}

/// Draw the timeline; returns the process of the lane or marker clicked.
pub(in crate::triage) fn show(ui: &mut egui::Ui, id: egui::Id, timeline: &Timeline) -> Option<Key> {
    if timeline.lanes.is_empty() {
        ui.weak("No processes in this run.");
        return None;
    }
    let label_w = (ui.available_width() * 0.28).clamp(110.0, 190.0);
    let height = AXIS_H + LANE_H * timeline.lanes.len() as f32;
    let (rect, _) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), height), Sense::hover());
    let response = ui.interact(rect, id, Sense::click());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 4.0, theme::panel());
    painter.rect_stroke(
        rect,
        4.0,
        Stroke::new(1.0, theme::line()),
        egui::StrokeKind::Inside,
    );
    let track = Rect::from_min_max(
        Pos2::new(rect.left() + label_w, rect.top() + AXIS_H),
        Pos2::new(rect.right() - 12.0, rect.bottom()),
    );
    let x_of = |ns: u64| track.left() + timeline.fraction(ns) * track.width();
    let lane_y = |lane: usize| track.top() + (lane as f32 + 0.5) * LANE_H;
    // The axis: five ticks.
    for step in 0..=4 {
        let ns = timeline.start_ns + (timeline.end_ns - timeline.start_ns) * step / 4;
        let x = x_of(ns);
        painter.line_segment(
            [Pos2::new(x, track.top()), Pos2::new(x, rect.bottom())],
            Stroke::new(1.0, theme::line().gamma_multiply(0.35)),
        );
        let align = if step == 4 {
            egui::Align2::RIGHT_CENTER
        } else {
            egui::Align2::LEFT_CENTER
        };
        painter.text(
            Pos2::new(x, rect.top() + AXIS_H / 2.0),
            align,
            after(ns, timeline.start_ns),
            egui::FontId::proportional(11.0),
            theme::muted(),
        );
    }
    for (i, lane) in timeline.lanes.iter().enumerate() {
        let y = lane_y(i);
        painter.line_segment(
            [Pos2::new(track.left(), y), Pos2::new(track.right(), y)],
            Stroke::new(1.0, theme::line().gamma_multiply(0.6)),
        );
        let clip = painter.with_clip_rect(Rect::from_min_max(
            Pos2::new(rect.left() + 6.0, y - LANE_H / 2.0),
            Pos2::new(track.left() - 6.0, y + LANE_H / 2.0),
        ));
        let mut text = lane.label.clone();
        if lane.warn {
            text.push_str(" \u{26a0}");
        }
        clip.text(
            Pos2::new(rect.left() + 8.0, y),
            egui::Align2::LEFT_CENTER,
            text,
            egui::FontId::proportional(12.0),
            theme::text(),
        );
    }
    for link in &timeline.links {
        let x = x_of(link.ns);
        let color = if link.exec {
            theme::blue()
        } else {
            theme::muted()
        };
        painter.line_segment(
            [
                Pos2::new(x, lane_y(link.from)),
                Pos2::new(x, lane_y(link.to)),
            ],
            Stroke::new(1.2, color),
        );
    }
    let pointer = response.hover_pos();
    let mut hit: Option<(usize, f32)> = None;
    for (at, mark) in timeline.marks.iter().enumerate() {
        let centre = Pos2::new(x_of(mark.ns), lane_y(mark.lane));
        let color = color_of(mark.kind);
        let r = if matches!(mark.kind, MarkKind::Finding(_)) {
            5.0
        } else {
            3.5
        };
        match mark.kind {
            MarkKind::Finding(_) | MarkKind::Connect => {
                painter.circle_filled(centre, r, color);
            }
            MarkKind::Exec => {
                painter.rect_filled(
                    Rect::from_center_size(centre, egui::vec2(r * 2.0, r * 2.0)),
                    1.0,
                    color,
                );
            }
            MarkKind::Fork => {
                painter.add(Shape::convex_polygon(
                    vec![
                        centre + egui::vec2(0.0, -r - 1.0),
                        centre + egui::vec2(r + 1.0, 0.0),
                        centre + egui::vec2(0.0, r + 1.0),
                        centre + egui::vec2(-r - 1.0, 0.0),
                    ],
                    color,
                    Stroke::NONE,
                ));
            }
            MarkKind::FileWrite => {
                painter.add(Shape::convex_polygon(
                    vec![
                        centre + egui::vec2(0.0, -r - 1.0),
                        centre + egui::vec2(r + 1.0, r),
                        centre + egui::vec2(-r - 1.0, r),
                    ],
                    color,
                    Stroke::NONE,
                ));
            }
        }
        if let Some(p) = pointer {
            let d = p.distance(centre);
            if d <= 8.0 && hit.is_none_or(|(_, best)| d < best) {
                hit = Some((at, d));
            }
        }
    }
    let mut clicked = None;
    if let Some((at, _)) = hit {
        let mark = &timeline.marks[at];
        response.clone().on_hover_ui_at_pointer(|ui| {
            ui.label(RichText::new(&mark.label).strong());
            ui.weak(after(mark.ns, timeline.start_ns));
        });
        if response.clicked() {
            clicked = Some(timeline.lanes[mark.lane].key);
        }
    } else if response.clicked() {
        if let Some(p) = pointer {
            let lane = ((p.y - track.top()) / LANE_H).floor();
            if lane >= 0.0 && (lane as usize) < timeline.lanes.len() {
                clicked = Some(timeline.lanes[lane as usize].key);
            }
        }
    }
    clicked
}
