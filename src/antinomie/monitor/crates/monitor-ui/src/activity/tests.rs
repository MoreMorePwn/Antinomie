// SPDX-License-Identifier: MIT
use super::*;
use std::collections::BTreeMap;

#[derive(Default)]
struct Storage(BTreeMap<String, String>);
impl eframe::Storage for Storage {
    fn get_string(&self, key: &str) -> Option<String> {
        self.0.get(key).cloned()
    }
    fn set_string(&mut self, key: &str, value: String) {
        self.0.insert(key.into(), value);
    }
    fn flush(&mut self) {}
}

#[test]
fn levels_default_on_filter_independently_and_keep_total_counts() {
    let mut journal = Journal::default();
    journal.log("INFO", "Started".into());
    journal.log("WARN", "Partial capture".into());
    journal.log("ERROR", "Disk write failed".into());
    for mask in 0..8 {
        journal.info = mask & 1 != 0;
        journal.warn = mask & 2 != 0;
        journal.error = mask & 4 != 0;
        for (bit, level) in [(1, Level::Info), (2, Level::Warn), (4, Level::Error)] {
            assert_eq!(journal.visible(level), mask & bit != 0);
        }
        assert_eq!(journal.counts(), (1, 1));
    }
    let defaults = Journal::default();
    assert!(defaults.info && defaults.warn && defaults.error);
}

#[test]
fn saved_log_restores_levels_timestamps_and_clear_removes_filtered_entries() {
    let mut journal = Journal::default();
    journal.log("WARN", "Capture gap".into());
    journal.log("ERROR", "Failed to save".into());
    journal.warn = false;
    let mut storage = Storage::default();
    journal.save(&mut storage);
    let mut restored = Journal::restore(Some(&storage));
    assert_eq!(restored.counts(), (1, 1));
    assert!(!restored.warn);
    assert!(restored.entries.front().unwrap().unix_ms > 0);
    restored.entries.clear();
    restored.save(&mut storage);
    assert_eq!(Journal::restore(Some(&storage)).counts(), (0, 0));
}

#[test]
fn warnings_are_logged_once_per_notice_and_dismissal_preserves_log() {
    let ctx = egui::Context::default();
    let mut journal = Journal::default();
    let (id, dismissed) = register(&ctx, Level::Warn, "Bad filter".into());
    assert!(!dismissed);
    register(&ctx, Level::Warn, "Bad filter".into());
    journal.ingest(&ctx);
    assert_eq!(journal.counts(), (1, 0));
    ctx.data_mut(|data| {
        data.get_temp_mut_or_default::<NoticeHub>(egui::Id::new(HUB))
            .dismissed
            .insert(id)
    });
    assert!(register(&ctx, Level::Warn, "Bad filter".into()).1);
    assert!(!register(&ctx, Level::Warn, "Another error".into()).1);
    journal.ingest(&ctx);
    assert_eq!(journal.counts(), (2, 0));
    journal.entries.clear();
    register(&ctx, Level::Warn, "Bad filter".into());
    journal.ingest(&ctx);
    assert_eq!(
        journal.counts(),
        (0, 0),
        "Clear must not re-add unchanged notices"
    );
}

#[test]
fn journal_and_notice_buffers_are_bounded_without_breaking_unicode() {
    let mut journal = Journal::default();
    for index in 0..ENTRY_LIMIT + 10 {
        journal.log("ERROR", format!("{index} {}", "界".repeat(MESSAGE_SIZE)));
    }
    assert!(journal.entries.len() <= ENTRY_LIMIT);
    assert!(
        journal
            .entries
            .iter()
            .map(|entry| entry.message.len())
            .sum::<usize>()
            <= JOURNAL_SIZE
    );
    assert!(journal
        .entries
        .iter()
        .all(|entry| entry.message.len() <= MESSAGE_SIZE));
    let ctx = egui::Context::default();
    for index in 0..INBOX_LIMIT + 10 {
        report(&ctx, Level::Warn, format!("warning {index}"));
    }
    journal.ingest(&ctx);
    assert!(journal
        .entries
        .back()
        .unwrap()
        .message
        .contains("10 additional notices omitted"));
}

#[test]
fn activity_tab_has_separate_warning_and_error_colors() {
    let mut journal = Journal::default();
    journal.log("WARN", "Warning".into());
    journal.log("ERROR", "Error".into());
    let egui::WidgetText::LayoutJob(job) = journal.title(16.0) else {
        panic!("rich activity title")
    };
    assert!(job.text.contains("Activity"));
    let chip = |index: usize| &job.sections[index].format;
    assert_eq!(chip(2).color, theme::warn());
    assert_eq!(chip(2).background, theme::palette().warn_bg);
    assert_eq!(chip(4).color, theme::error());
    assert_eq!(chip(4).background, theme::palette().error_bg);
}

fn frame(
    ctx: &egui::Context,
    journal: &mut Journal,
    width: f32,
    events: Vec<egui::Event>,
) -> Vec<(String, egui::Rect)> {
    let output = ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(width, 400.0),
            )),
            events,
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| journal.show(ui));
        },
    );
    fn collect(shape: &egui::Shape, texts: &mut Vec<(String, egui::Rect)>) {
        match shape {
            egui::Shape::Text(text) => {
                texts.push((text.galley.text().into(), text.visual_bounding_rect()))
            }
            egui::Shape::Vec(shapes) => {
                for shape in shapes {
                    collect(shape, texts);
                }
            }
            _ => {}
        }
    }
    let mut texts = Vec::new();
    for shape in &output.shapes {
        collect(&shape.shape, &mut texts);
    }
    texts
}
fn click(ctx: &egui::Context, journal: &mut Journal, pos: egui::Pos2) {
    for pressed in [true, false] {
        frame(
            ctx,
            journal,
            800.0,
            vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: Default::default(),
                },
            ],
        );
    }
}

#[test]
fn native_activity_controls_filter_rows_and_clear_all_levels() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut journal = Journal::default();
    journal.log("INFO", "Information row".into());
    journal.log("WARN", "Warning row".into());
    journal.log("ERROR", "Error row".into());
    for _ in 0..3 {
        frame(&ctx, &mut journal, 800.0, vec![]);
    }
    let texts = frame(&ctx, &mut journal, 800.0, vec![]);
    let rect = |label: &str| texts.iter().find(|(text, _)| text == label).unwrap().1;
    assert!(rect("Info").left() < rect("Warn").left());
    assert!(rect("Warn").left() < rect("Error").left());
    assert!(rect("Error").left() < rect("Clear").left());
    click(&ctx, &mut journal, rect("Warn").center());
    let filtered = frame(&ctx, &mut journal, 800.0, vec![]);
    assert!(!filtered.iter().any(|(text, _)| text == "Warning row"));
    assert!(filtered.iter().any(|(text, _)| text == "Error row"));
    assert_eq!(journal.counts(), (1, 1));
    click(&ctx, &mut journal, rect("Clear").center());
    assert!(journal.entries.is_empty());
    assert_eq!(journal.counts(), (0, 0));
    for (width, font) in [(320.0, 16.0), (320.0, 24.0)] {
        theme::text_size(&ctx, font);
        for _ in 0..3 {
            frame(&ctx, &mut journal, width, vec![]);
        }
        let texts = frame(&ctx, &mut journal, width, vec![]);
        for label in ["Info", "Warn", "Error", "Clear"] {
            let rect = texts.iter().find(|(text, _)| text == label).unwrap().1;
            assert!(
                rect.left() >= 0.0 && rect.right() <= width,
                "{label} outside {width}: {rect:?}"
            );
        }
    }
}

#[test]
fn compact_notice_keeps_dismiss_button_inside_a_single_status_row() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let message = "A long backend failure must leave its dismiss control reachable";
    let mut dismiss_rect = egui::Rect::NOTHING;
    for _ in 0..3 {
        let output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(220.0, 40.0),
                )),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    compact(ui, Level::Error, message);
                });
            },
        );
        for shape in &output.shapes {
            if let egui::Shape::Text(text) = &shape.shape {
                if text.galley.text() == "×" {
                    dismiss_rect = text.visual_bounding_rect();
                }
            }
        }
    }
    assert!(dismiss_rect.is_positive(), "dismiss control is visible");
    assert!(
        dismiss_rect.right() <= 220.0 && dismiss_rect.bottom() <= 40.0,
        "{dismiss_rect:?}"
    );
}

#[test]
fn a_disabled_form_still_allows_its_notice_to_be_dismissed() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut rect = egui::Rect::NOTHING;
    let message = "Stop the VM to change these settings";
    let mut draw = |events| {
        let output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(600.0, 200.0),
                )),
                events,
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.add_enabled_ui(false, |ui| {
                        warning(ui, message);
                    });
                });
            },
        );
        for shape in &output.shapes {
            if let egui::Shape::Text(text) = &shape.shape {
                if text.galley.text() == "×" {
                    rect = text.visual_bounding_rect();
                }
            }
        }
        rect
    };
    for _ in 0..3 {
        draw(vec![]);
    }
    let pos = draw(vec![]).center();
    for pressed in [true, false] {
        draw(vec![
            egui::Event::PointerMoved(pos),
            egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: Default::default(),
            },
        ]);
    }
    assert!(register(&ctx, Level::Warn, message.into()).1);
}

#[test]
fn the_activity_table_sorts_by_a_clicked_header() {
    use crate::table_sort::testing::{click, column_order};
    let ctx = egui::Context::default();
    let mut journal = Journal::default();
    journal.log("ERROR", "bravo".into());
    journal.log("INFO", "charlie".into());
    journal.log("WARN", "alpha".into());
    let mut show = |ui: &mut egui::Ui| journal.show(ui);
    let names = ["alpha", "bravo", "charlie"];
    let texts = click(&ctx, "Message", &mut show);
    assert_eq!(column_order(&texts, &names), ["alpha", "bravo", "charlie"]);
    let texts = click(&ctx, "Message", &mut show);
    assert_eq!(column_order(&texts, &names), ["charlie", "bravo", "alpha"]);
    // Level sorts Info, Warn, Error.
    let texts = click(&ctx, "Level", &mut show);
    assert_eq!(column_order(&texts, &names), ["charlie", "alpha", "bravo"]);
}
