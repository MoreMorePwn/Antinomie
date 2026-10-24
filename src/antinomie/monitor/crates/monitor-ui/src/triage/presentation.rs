// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Native report structure; semantic color follows evidence state, not a verdict.
use super::*;

pub(super) fn frame() -> egui::Frame {
    egui::Frame::new()
        .fill(theme::bg())
        .stroke(egui::Stroke::new(1.0_f32, theme::line()))
        .corner_radius(6)
        .inner_margin(12)
}

pub(super) fn badge(ui: &mut egui::Ui, text: &str, color: egui::Color32) {
    egui::Frame::new()
        .fill(color.gamma_multiply(0.12))
        .corner_radius(4)
        .inner_margin(egui::Margin::symmetric(7, 3))
        .show(ui, |ui| {
            ui.label(RichText::new(text).color(color).small().strong());
        });
}

pub(super) fn heading(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    heading_busy(ui, title, subtitle, false);
}

/// `heading` with a spinner left of the title while `busy`.
pub(super) fn heading_busy(ui: &mut egui::Ui, title: &str, subtitle: &str, busy: bool) {
    // `.strong()` alone uses the active-widget color, which is white in both palettes.
    let title = RichText::new(title)
        .strong()
        .color(theme::heading())
        .size(ui.text_style_height(&egui::TextStyle::Body) + 1.0);
    if busy {
        ui.horizontal(|ui| {
            theme::spinner(ui);
            ui.label(title);
        });
    } else {
        ui.label(title);
    }
    if !subtitle.is_empty() {
        ui.add(egui::Label::new(RichText::new(subtitle).small().color(theme::muted())).wrap());
    }
    ui.add_space(8.0);
}

pub(super) fn navigation(view: &mut TriageView, ui: &mut egui::Ui, input: &TriageInput<'_>) {
    // Process, Files and Network keep their refresh status at the right of
    // the bar; the other sections have none or their own row.
    let trail = matches!(
        view.section,
        Section::Process | Section::Files | Section::Network
    );
    let mut fits = true;
    crate::widgets::tab_row(ui, |ui| {
        let first_line = ui.cursor().min.y;
        for (section, label) in [
            (Section::Summary, "Summary"),
            (Section::Properties, "Properties"),
            (Section::Detection, "Detection"),
            (Section::Process, "Process"),
            (Section::Files, "Files"),
            (Section::Network, "Network"),
            (Section::Bpf, "eBPF"),
        ] {
            if crate::widgets::tab(ui, view.section == section, &label.into()).clicked() {
                view.section = section;
            }
        }
        // The IOC tab counts the run's indicators, red when one matched.
        let ioc = match view.ioc_headline() {
            Some((matched, total, _)) => crate::widgets::TabItem::new("IOC").badge(
                total.to_string(),
                if matched > 0 {
                    crate::widgets::Tone::Error
                } else {
                    crate::widgets::Tone::Plain
                },
            ),
            None => crate::widgets::TabItem::new("IOC"),
        };
        if crate::widgets::tab(ui, view.section == Section::Ioc, &ioc).clicked() {
            view.section = Section::Ioc;
        }
        // `available_width` of a wrapping row is the whole row, not what the tabs left.
        let room = ui.max_rect().right() - ui.cursor().min.x;
        // Tabs that wrapped leave the status no line of its own to share.
        let wrapped = ui.cursor().min.y - first_line > 1.0;
        if trail && !wrapped && room >= 120.0 {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                fits = view.refresh_trail(ui, input, Some(room));
            });
        } else {
            fits = !trail;
        }
    });
    // A narrow pane puts the status under the bar instead.
    if !fits {
        // A line tall enough for the status; a right-to-left layout otherwise
        // takes the whole pane and the section below is pushed out of sight.
        let height = ui.spacing().interact_size.y;
        ui.allocate_ui_with_layout(
            egui::vec2(ui.available_width(), height),
            egui::Layout::right_to_left(egui::Align::Center),
            |ui| {
                view.refresh_trail(ui, input, None);
            },
        );
    }
}

/// Render complementary sections with a shared height, or stack in narrow panes.
pub(super) fn pair(
    ui: &mut egui::Ui,
    left: impl FnOnce(&mut egui::Ui),
    right: impl FnOnce(&mut egui::Ui),
) {
    if ui.available_width() < 740.0 {
        frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            left(ui);
        });
        ui.add_space(10.0);
        frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            right(ui);
        });
        return;
    }
    ui.columns(2, |columns| {
        let backgrounds = columns
            .iter()
            .map(|column| {
                (
                    column.painter().add(egui::Shape::Noop),
                    column.painter().add(egui::Shape::Noop),
                )
            })
            .collect::<Vec<_>>();
        let first = egui::Frame::new()
            .inner_margin(12)
            .show(&mut columns[0], |ui| {
                ui.set_width(ui.available_width());
                left(ui);
            })
            .response
            .rect;
        let second = egui::Frame::new()
            .inner_margin(12)
            .show(&mut columns[1], |ui| {
                ui.set_width(ui.available_width());
                right(ui);
            })
            .response
            .rect;
        let height = first.height().max(second.height());
        for ((column, (fill, stroke)), mut rect) in
            columns.iter().zip(backgrounds).zip([first, second])
        {
            let painter = column.painter();
            rect.max.y = rect.min.y + height;
            painter.set(fill, egui::Shape::rect_filled(rect, 6, theme::bg()));
            painter.set(
                stroke,
                egui::Shape::rect_stroke(
                    rect,
                    6,
                    egui::Stroke::new(1.0_f32, theme::line()),
                    egui::StrokeKind::Inside,
                ),
            );
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn light_theme_emphasis_uses_heading_and_body_colors() {
        let ctx = egui::Context::default();
        theme::apply(&ctx, true);
        let output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(800.0, 400.0),
                )),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    heading(ui, "Detection evidence", "Rule matches");
                    ui.label(
                        RichText::new("triage-sample")
                            .strong()
                            .color(theme::text())
                            .size(22.0),
                    );
                });
            },
        );
        let mut saw_heading = false;
        let mut saw_name = false;
        for clipped in &output.shapes {
            let egui::Shape::Text(text) = &clipped.shape else {
                continue;
            };
            let content = text.galley.text();
            let color = text
                .galley
                .job
                .sections
                .first()
                .map(|section| section.format.color);
            if content.contains("Detection evidence") {
                assert_eq!(color, Some(theme::heading()));
                assert_ne!(color, Some(egui::Color32::WHITE));
                saw_heading = true;
            }
            if content.contains("triage-sample") {
                assert_eq!(color, Some(theme::text()));
                assert_ne!(color, Some(egui::Color32::WHITE));
                saw_name = true;
            }
        }
        assert!(saw_heading && saw_name);
        theme::apply(&ctx, false);
    }

    #[test]
    fn unequal_section_contents_align_in_wide_panes_and_stack_without_overflow() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        for width in [900.0, 480.0] {
            for _ in 0..2 {
                let output = ctx.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(width, 600.0),
                        )),
                        ..Default::default()
                    },
                    |ctx| {
                        egui::CentralPanel::default().show(ctx, |ui| {
                            pair(
                                ui,
                                |ui| {
                                    ui.label("Short section");
                                },
                                |ui| {
                                    for _ in 0..6 {
                                        ui.label("A longer section with more evidence rows");
                                    }
                                },
                            );
                        });
                    },
                );
                let panels: Vec<_> = output
                    .shapes
                    .iter()
                    .filter_map(|shape| match &shape.shape {
                        egui::Shape::Rect(rect)
                            if rect.corner_radius.nw == 6 && rect.fill.a() != 0 =>
                        {
                            Some(rect.rect)
                        }
                        _ => None,
                    })
                    .collect();
                assert_eq!(panels.len(), 2);
                assert!(panels.iter().all(|rect| rect.right() <= width + 1.0));
                if width >= 740.0 {
                    assert!((panels[0].height() - panels[1].height()).abs() < 1.0);
                    assert!((panels[0].top() - panels[1].top()).abs() < 1.0);
                } else {
                    assert!(panels[1].top() >= panels[0].bottom());
                }
            }
        }
    }
}
