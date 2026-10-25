// SPDX-License-Identifier: GPL-3.0-only
//! Match cards: one designed card per matched rule, with a severity stripe, a
//! short summary, a facts row and a Details button.
use super::finding::{pack_name, parse_details};
use super::*;

/// Widest MITRE chip list on a card; the rest is counted.
const CHIP_LIMIT: usize = 6;
/// Room the Details button and the severity badge take beside the title.
const TITLE_RESERVE: f32 = 190.0;

/// Filtered matches stay in a bounded list. A click opens Details; a double
/// click opens the same exact evidence as the table row. A card's Details
/// button returns the finding to open in its own window.
pub(super) fn match_cards(
    ui: &mut egui::Ui,
    report: &Report,
    table_id: &str,
    rows: &[Vec<Cell>],
) -> Option<WindowKey> {
    if report.findings.is_empty() {
        return None;
    }
    presentation::heading(ui, "Matches", "");
    if rows.is_empty() {
        ui.weak("No matches.");
        return None;
    }
    let mut opened = None;
    egui::ScrollArea::vertical()
        .id_salt("detection-matches")
        .max_height(320.0)
        .auto_shrink([false, true])
        .show(ui, |ui| {
            for (index, row) in rows.iter().enumerate() {
                let Some(finding) = finding_for(report, row) else {
                    continue;
                };
                if let Some(next) = card(ui, report, finding, table_id, index, row) {
                    opened = Some(next);
                }
                ui.add_space(6.0);
            }
        });
    opened
}

fn card(
    ui: &mut egui::Ui,
    report: &Report,
    finding: &Finding,
    table_id: &str,
    index: usize,
    row: &[Cell],
) -> Option<WindowKey> {
    let tint = severity_color(&finding.severity);
    // Alternate two surfaces so a long list keeps its rhythm in both themes.
    let fill = if index.is_multiple_of(2) {
        theme::panel()
    } else {
        theme::raised()
    };
    let mut details = None;
    let shown = egui::Frame::new()
        .fill(fill)
        .stroke(egui::Stroke::new(1.0_f32, theme::line()))
        .corner_radius(6)
        .inner_margin(egui::Margin {
            left: 16,
            right: 12,
            top: 10,
            bottom: 10,
        })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            egui::Sides::new().show(
                ui,
                |ui| {
                    ui.set_max_width((ui.available_width() - TITLE_RESERVE).max(80.0));
                    ui.add(
                        egui::Label::new(
                            RichText::new(&finding.title).strong().color(theme::text()),
                        )
                        .truncate(),
                    )
                    .on_hover_text(&finding.title);
                    if !finding.severity.is_empty() {
                        presentation::badge(ui, &finding.severity, tint);
                    }
                },
                |ui| {
                    details = Some(ui.button("Details…"));
                },
            );
            let summary = card_summary(report.engine, finding);
            clipped(ui, &summary, 2);
            ui.add(
                egui::Label::new(
                    RichText::new(facts_line(report, finding))
                        .small()
                        .color(theme::muted()),
                )
                .wrap(),
            );
            if !finding.mitre.is_empty() {
                ui.horizontal_wrapped(|ui| {
                    for reference in finding.mitre.iter().take(CHIP_LIMIT) {
                        presentation::badge(ui, reference, theme::blue());
                    }
                    if finding.mitre.len() > CHIP_LIMIT {
                        ui.label(
                            RichText::new(format!("+{}", finding.mitre.len() - CHIP_LIMIT))
                                .small()
                                .color(theme::muted()),
                        );
                    }
                });
            }
        });
    let rect = shown.response.rect;
    ui.painter().rect_filled(
        egui::Rect::from_min_max(rect.min, egui::pos2(rect.min.x + 5.0, rect.max.y)),
        egui::CornerRadius {
            nw: 6,
            sw: 6,
            ne: 0,
            se: 0,
        },
        tint,
    );
    // The card is one click target except for its Details button, which keeps
    // its own click.
    let over_button = details
        .as_ref()
        .is_some_and(|button| button.hovered() || button.clicked());
    if details.as_ref().is_some_and(|button| button.clicked()) {
        return Some(WindowKey {
            engine: ENGINES
                .iter()
                .position(|engine| *engine == report.engine)
                .unwrap_or(0),
            rule_id: finding.rule_id.clone(),
            title: finding.title.clone(),
        });
    }
    if ui.rect_contains_pointer(rect) && !over_button {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
        ui.painter().rect_stroke(
            rect,
            6.0,
            egui::Stroke::new(1.0_f32, theme::blue()),
            egui::StrokeKind::Inside,
        );
        let (double, single) = ui.input(|input| {
            (
                input
                    .pointer
                    .button_double_clicked(egui::PointerButton::Primary),
                input.pointer.button_clicked(egui::PointerButton::Primary),
            )
        });
        if double {
            request_evidence_jump(
                ui.ctx(),
                row.first()
                    .map(|cell| cell.values.as_slice())
                    .unwrap_or_default(),
            );
        } else if single {
            details::select(ui.ctx(), table_id, HEADERS, row);
            details::clicked(ui.ctx(), table_id);
        }
    }
    None
}

/// Wrapped to `rows` lines and cut with an ellipsis; the whole text is the hover.
fn clipped(ui: &mut egui::Ui, text: &str, rows: usize) {
    let mut job = egui::text::LayoutJob::simple(
        text.to_owned(),
        egui::TextStyle::Body.resolve(ui.style()),
        theme::text(),
        ui.available_width(),
    );
    job.wrap.max_rows = rows;
    ui.add(egui::Label::new(job)).on_hover_text(text);
}

/// The rule's own explanation for people, never the engine's key/value text.
pub(super) fn card_summary(engine: Engine, finding: &Finding) -> String {
    let summary = parse_details(engine, &finding.details).summary;
    if summary.is_empty() {
        "The rule matched, but it did not record an explanation.".into()
    } else {
        summary
    }
}

/// Hit count, first location, rule pack and a short author, in one muted line.
fn facts_line(report: &Report, finding: &Finding) -> String {
    let mut facts = vec![
        format!(
            "{} {}",
            finding.count,
            if finding.count == 1 { "hit" } else { "hits" }
        ),
        match_location(finding),
    ];
    let pack = pack_name(report, finding);
    if !pack.is_empty() {
        facts.push(pack);
    }
    if !finding.author.trim().is_empty() {
        facts.push(format!("by {}", short_author(&finding.author)));
    }
    facts.join(" · ")
}

/// The first author, with the number of others.
pub(super) fn short_author(author: &str) -> String {
    let names: Vec<&str> = author
        .split([',', ';', '&'])
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect();
    let first = names.first().copied().unwrap_or(author.trim());
    let first: String = if first.chars().count() > 28 {
        first.chars().take(27).chain(['…']).collect()
    } else {
        first.to_owned()
    };
    match names.len() {
        0 | 1 => first,
        more => format!("{first} +{}", more - 1),
    }
}

pub(super) fn finding_for<'a>(report: &'a Report, row: &[Cell]) -> Option<&'a Finding> {
    let rule = row_text(row, "finding.rule")?;
    let title = row_text(row, "finding.title");
    report
        .findings
        .iter()
        .find(|finding| finding.rule_id == rule && title.is_none_or(|title| title == finding.title))
}

fn row_text<'a>(row: &'a [Cell], key: &str) -> Option<&'a str> {
    row.first()?.values.iter().find_map(|(name, value)| {
        if *name == key {
            if let RowValue::Text(text) = value {
                Some(text.as_str())
            } else {
                None
            }
        } else {
            None
        }
    })
}

pub(super) fn severity_color(severity: &str) -> egui::Color32 {
    match severity.trim().to_ascii_lowercase().as_str() {
        "1" | "critical" | "high" => theme::error(),
        "2" | "medium" | "indicator" => theme::warn(),
        "3" | "4" | "low" | "informational" | "info" => theme::blue(),
        _ => theme::muted(),
    }
}

pub(super) fn match_location(finding: &Finding) -> String {
    let Some(evidence) = finding.evidence.first() else {
        return format!(
            "{} occurrence{}; no recorded location",
            finding.count,
            if finding.count == 1 { "" } else { "s" }
        );
    };
    let first = match evidence {
        Evidence::Call { call, .. } => format!("syscall {call}"),
        Evidence::Packet { frame, .. } => format!("packet #{frame}"),
        Evidence::Bytes { path, offset, .. } => {
            let name = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| "bytes".into());
            offset.map_or_else(
                || format!("file {name}"),
                |offset| format!("{name} at 0x{offset:x}"),
            )
        }
    };
    if finding.evidence.len() == 1 {
        format!("Matched {first}")
    } else {
        format!(
            "Matched {first} and {} more locations",
            finding.evidence.len() - 1
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{finding, frames, rendered_text, report};
    use super::*;

    fn bytes_at(offset: u64) -> Evidence {
        Evidence::Bytes {
            path: PathBuf::from("/tmp/specimen"),
            offset: Some(offset),
            address: None,
            report_id: None,
            block: None,
        }
    }

    #[test]
    fn match_location_names_the_recorded_byte_and_counts_the_rest() {
        let mut sample = finding("sample", "Sample", vec![bytes_at(0x10), bytes_at(0x20)]);
        sample.details = "marker".into();
        assert_eq!(card_summary(Engine::Yara, &sample), "marker");
        assert_eq!(
            super::super::finding::evidence_label(&sample.evidence[0]),
            "specimen — open bytes at 0x10"
        );
        assert_eq!(
            match_location(&sample),
            "Matched specimen at 0x10 and 1 more locations"
        );
        sample.details = String::new();
        assert!(card_summary(Engine::Yara, &sample).contains("did not record"));
    }

    #[test]
    fn numeric_and_named_severities_share_one_scale() {
        assert_eq!(severity_color("1"), theme::error());
        assert_eq!(severity_color("high"), theme::error());
        assert_eq!(severity_color("2"), theme::warn());
        assert_eq!(severity_color("medium"), theme::warn());
        assert_eq!(severity_color("3"), theme::blue());
        assert_eq!(severity_color("4"), theme::blue());
        assert_eq!(severity_color("informational"), theme::blue());
        assert_eq!(severity_color("unspecified"), theme::muted());
    }

    #[test]
    fn short_author_keeps_the_first_name_and_counts_the_others() {
        assert_eq!(short_author("Ann"), "Ann");
        assert_eq!(short_author("Ann, Bob & Cy"), "Ann +2");
        assert!(short_author(&"x".repeat(60)).ends_with('…'));
    }

    #[test]
    fn cards_read_as_text_not_as_a_key_value_dump() {
        let mut yara = finding(
            "loader",
            "Loader family",
            vec![bytes_at(0x10), bytes_at(0x20)],
        );
        yara.count = 4;
        yara.author = "Ann Lee, Bob".into();
        yara.source = "s0".into();
        yara.mitre = vec!["T1059.004".into(), "T1105".into()];
        yara.details =
            "Detects the loader stage; author: Ann Lee, Bob; tags: MALWARE loader".into();
        let mut report = report(vec![yara]);
        report.sources.push(engine::Source {
            name: "Forge Core".into(),
            version: String::new(),
            license: String::new(),
            sha256: String::new(),
            data: String::new(),
        });
        let mut view = View::default();
        view.results[0] = Some(Ok(report));
        view.rows(0);
        let Some(Ok(report)) = &view.results[0] else {
            unreachable!()
        };
        let ctx = egui::Context::default();
        let shapes = frames(&ctx, 2, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let _ = match_cards(ui, report, TABLES[0], &view.rows[0]);
            });
        });
        let joined = rendered_text(&shapes);
        assert!(joined.contains("Loader family"), "{joined}");
        assert!(joined.contains("Detects the loader stage"), "{joined}");
        assert!(joined.contains("Details…"), "{joined}");
        assert!(joined.contains("4 hits"), "{joined}");
        assert!(joined.contains("Forge Core"), "{joined}");
        assert!(joined.contains("by Ann Lee +1"), "{joined}");
        assert!(joined.contains("T1059.004"), "{joined}");
        assert!(!joined.contains("author:"), "{joined}");
        assert!(!joined.contains("tags:"), "{joined}");
        assert!(!joined.contains('='), "{joined}");
    }

    #[test]
    fn a_long_summary_is_cut_to_two_lines() {
        let mut long = finding("long", "Long", vec![bytes_at(1)]);
        long.details = format!("{}; author: A; tags: t", "word ".repeat(200));
        let mut view = View::default();
        view.results[0] = Some(Ok(report(vec![long])));
        view.rows(0);
        let Some(Ok(report)) = &view.results[0] else {
            unreachable!()
        };
        let ctx = egui::Context::default();
        let shapes = frames(&ctx, 2, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let _ = match_cards(ui, report, TABLES[0], &view.rows[0]);
            });
        });
        let mut longest_rows = 0;
        for shape in &shapes {
            super::super::tests::each_galley(&shape.shape, &mut |galley| {
                if galley.text().starts_with("word word") {
                    longest_rows = longest_rows.max(galley.rows.len());
                }
            });
        }
        assert!((1..=2).contains(&longest_rows), "{longest_rows}");
    }

    fn text_center(shape: &egui::epaint::Shape, wanted: &str) -> Option<egui::Pos2> {
        match shape {
            egui::epaint::Shape::Text(text) if text.galley.text() == wanted => {
                Some(text.pos + text.galley.rect.center().to_vec2())
            }
            egui::epaint::Shape::Vec(shapes) => {
                shapes.iter().find_map(|shape| text_center(shape, wanted))
            }
            _ => None,
        }
    }

    #[test]
    fn the_details_button_opens_its_window_and_a_card_click_still_selects() {
        let mut view = View::default();
        view.results[0] = Some(Ok(report(vec![finding(
            "rule",
            "Title",
            vec![bytes_at(1)],
        )])));
        view.rows(0);
        let Some(Ok(report)) = &view.results[0] else {
            unreachable!()
        };
        let ctx = egui::Context::default();
        let draw = |ctx: &egui::Context, events: Vec<egui::Event>| {
            let mut opened = None;
            let output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(800.0, 600.0),
                    )),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        if let Some(key) = match_cards(ui, report, TABLES[0], &view.rows[0]) {
                            opened = Some(key);
                        }
                    });
                },
            );
            (output.shapes, opened)
        };
        draw(&ctx, vec![]);
        let (shapes, _) = draw(&ctx, vec![]);
        let button = shapes
            .iter()
            .find_map(|shape| text_center(&shape.shape, "Details…"))
            .expect("Details button is drawn");
        let click = |pressed| egui::Event::PointerButton {
            pos: button,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: Default::default(),
        };
        draw(&ctx, vec![egui::Event::PointerMoved(button)]);
        draw(&ctx, vec![click(true)]);
        let (_, opened) = draw(&ctx, vec![click(false)]);
        let key = opened.expect("the click opened the window");
        assert_eq!((key.engine, key.rule_id.as_str()), (0, "rule"));
        // The button click did not also select the row into shared Details.
        let focus = egui::Id::new("triage-details-focus");
        assert!(ctx.data(|data| data.get_temp::<bool>(focus)).is_none());
        // A click on the card body still does.
        let body = shapes
            .iter()
            .find_map(|shape| text_center(&shape.shape, "readable summary"))
            .expect("summary is drawn");
        let at = |pressed| egui::Event::PointerButton {
            pos: body,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: Default::default(),
        };
        draw(&ctx, vec![egui::Event::PointerMoved(body)]);
        draw(&ctx, vec![at(true)]);
        draw(&ctx, vec![at(false)]);
        assert_eq!(ctx.data(|data| data.get_temp::<bool>(focus)), Some(true));
    }
}
